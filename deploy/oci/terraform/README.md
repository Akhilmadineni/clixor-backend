# OCI Always Free Terraform foundation

This stack creates the Clixor production foundation in OCI's Phoenix home
region through **OCI Resource Manager**. It does not create any public ingress,
load balancer, managed database, or application secret.

## What the stack creates

- optional dedicated `ClixorProd` compartment;
- private VCN/subnet, NAT gateway, OCI service gateway, explicit route table,
  security list, and application NSG;
- one private `VM.Standard.A1.Flex` Ubuntu 24.04 ARM64 instance with 2 OCPUs and
  12 GB RAM;
- 50 GB balanced boot volume and 100 GB balanced data volume;
- OCI Bastion restricted to a required administrator IPv4 `/32`;
- private Object Storage media bucket for the native OCI API and short-lived,
  object-specific pre-authenticated requests (PARs), with versioning disabled so
  application deletion permanently removes a uniquely named media object;
- private, versioned Object Storage backup bucket with bounded 14/21-day
  lifecycle retention and automatic cleanup of incomplete multipart uploads;
- default OCI Vault and one software-protected AES key;
- the regional `mail.atlanteanz.com` Email Delivery domain, an OCI-generated
  DKIM key, and a gated `no-reply@mail.atlanteanz.com` approved sender;
- a dedicated classic IAM SMTP user and group whose only enabled credential
  capability is SMTP and whose policy grants `use approved-senders` only for
  the exact `no-reply@mail.atlanteanz.com` address in the mail compartment;
- an instance-principal dynamic group and scoped policy for secret-bundle reads,
  bucket-scoped media/PAR access, and create/inspect/read-only backup access for
  immutable uploads and isolated restore drills (the VM cannot overwrite or
  delete off-site backup objects);
- a regional, bucket-scoped service policy required to execute the Object
  Storage lifecycle rules.

The instance has no public IP. Cloudflare Tunnel remains the only application
ingress and is configured only after the runtime secrets are installed.

The stack deliberately waits 90 seconds after a new Vault becomes active before
creating its first key. OCI can briefly publish the Vault management endpoint
before its unique hostname is resolvable, which otherwise makes a clean
Resource Manager apply fail and succeed only on retry.

The compute image is deliberately pinned in `locals.tf` to the exact Phoenix
Ubuntu 24.04 ARM64 image already used by `clixor-prod-1`:
`ocid1.image.oc1.phx.aaaaaaaa2xgl5y6skitgkee2aiprxzydi3nnxlqojrxtcifdb5d6a3djexuq`.
Do not replace it with a "latest image" lookup: a newly published Canonical
image would change the instance boot source during an otherwise unrelated plan.
Treat an image upgrade as a separate, reviewed host-replacement operation with
verified backups and rollback capacity. With existing Resource Manager state,
this literal must plan as the same `source_id`; reject any plan that replaces or
updates the compute instance or boot volume.

## Cost guardrails

The variables reject non-A1 shapes, more than 2 OCPUs, more than 12 GB RAM, and
more than 200 GB combined boot/data block storage. Defaults consume 150 GB and
leave 50 GB of block-volume allowance for recovery work. OCI still controls
eligibility and capacity, so inspect the Resource Manager plan and the account's
Limits, Quotas and Usage page before apply.

## Run from GitHub through Resource Manager (recommended)

1. Use an existing SSH public key and determine the current administrator public
   IPv4 as a `/32`. Never paste a private key.
2. Push the reviewed Terraform revision to GitHub. In OCI Resource Manager,
   create a GitHub configuration source provider using a dedicated, revocable
   repository-read credential. Never reuse a personal token that can write code,
   and never place the credential in this repository or Terraform variables.
3. Create the stack with **Source code control system** as its origin, select the
   reviewed branch and repository, and set the Terraform working directory to:

   ```text
   deploy/oci/terraform
   ```

4. Select Terraform 1.5.x, choose the tenancy root as the parent when
   `create_compartment=true`, enter the SSH public key and administrator `/32`,
   then run **Plan**. Resource Manager prepopulates `tenancy_ocid`,
   `compartment_ocid`, and `region`, and keeps Terraform state in OCI. No OCI API
   signing key belongs on the workstation or in GitHub.
5. Apply only after the plan contains the intended private A1 resources and no
   paid load balancer, database, or public IP.

Terraform `prevent_destroy` guards the primary media bucket, backup bucket, and
attached data volume. Removing one requires an explicit reviewed configuration
change; do not bypass that guard during routine updates.

## Email Delivery: two-phase DNS activation

Email Delivery is regional, so this stack provisions the sending domain and IAM
principal in Phoenix. It cannot safely create the approved sender on the first
apply: Oracle must observe the DKIM record in public DNS and report the DKIM as
`ACTIVE` first. Keep `create_mail_approved_sender=false` for the first plan and
apply.

After that apply, copy these non-sensitive Resource Manager outputs:

- `mail_dkim_cname_name` and `mail_dkim_cname_value`;
- `mail_spf_txt_name` and `mail_spf_txt_value`;
- `mail_smtp_endpoint`; and
- `mail_smtp_user_id`.

In the Cloudflare DNS zone for `atlanteanz.com`:

1. Create a **CNAME** whose name is `mail_dkim_cname_name` and target is
   `mail_dkim_cname_value`. Set Proxy status to **DNS only**; DKIM validation
   must not pass through the Cloudflare HTTP proxy.
2. Create one **TXT** record at `mail_spf_txt_name` with
   `mail_spf_txt_value`. For Phoenix/Americas, Terraform outputs
   `v=spf1 include:rp.oracleemaildelivery.com ~all`. A DNS name must have only
   one SPF record; merge mechanisms instead of publishing a second `v=spf1`
   record if mail for this subdomain is ever delegated to another sender.
3. Wait for both records to resolve publicly, then wait for the OCI Email
   Delivery DKIM state to become `ACTIVE`. Cloudflare SSL/TLS settings do not
   affect these DNS-only mail records.

Verify from an independent resolver without copying any credential:

```sh
dig +short CNAME "<mail_dkim_cname_name output>"
dig +short TXT mail.atlanteanz.com
```

Only after OCI reports DKIM `ACTIVE`, set
`create_mail_approved_sender=true`, run a fresh plan, and apply. The sender
resource has an apply-time precondition that refuses to proceed earlier. It
creates only `no-reply@mail.atlanteanz.com`, not a domain-wide wildcard sender.
Treat this switch as one-way in production: the sender is protected by
`prevent_destroy`. Rotate DKIM by adding and activating a second selector before
retiring the old selector rather than changing the protected resource in place.

### Manual SMTP credential issuance

Terraform creates the dedicated IAM user but **must never create any**
`oci_identity_smtp_credential`, `oci_identity_domains_smtp_credential`, or
`oci_identity_domains_my_smtp_credential` resource. Those resources return an
Oracle-generated password and would persist it in Terraform/Resource Manager
state. Likewise, the DKIM resource deliberately omits `private_key`; OCI
generates and retains the signing key while Terraform records only public DNS
metadata.

After DNS activation and approved-sender creation, locate the IAM user by the
`mail_smtp_user_id` output and generate one SMTP credential interactively in the
OCI Console. Copy the one-time username/password directly into the approved
secret-management path; never paste them into Terraform variables, outputs,
Cloudflare, GitHub Actions, shell history, tickets, or this repository. Terraform
does not create, read, rotate, or destroy that credential. Rotate it manually,
with an overlap canary, and retain no more than the two OCI credentials allowed
per user.

Configure the application for mandatory implicit TLS using the
`mail_smtp_endpoint` output (port 465), `CLUSTER_SMTP_TRANSPORT=implicit_tls`,
and `no-reply@mail.atlanteanz.com`. Keep outbound mail disabled until an
external mailbox receives a complete password-reset canary and DKIM/SPF headers
pass. Add DMARC only after a monitored reporting mailbox exists; OCI Email
Delivery does not provide an inbox for DMARC reports.

For an audited break-glass import when GitHub is unavailable, generate the
equivalent upload bundle locally and verify its checksum before upload:

```bash
./package-stack.sh
sha256sum clixor-oci-resource-manager.zip
unzip -t clixor-oci-resource-manager.zip
```

If Oracle reports A1 host-capacity exhaustion, change
`availability_domain_index` and re-plan. Do not substitute a paid shape.

## Secret boundary

Do not add credential resources or secret values to this Terraform
configuration: Terraform would retain them in state. In particular, the locked
OCI provider exposes the generated SMTP password as a computed, state-bearing
attribute, so SMTP credential resources are forbidden. A `sensitive` marker, if
added by a future provider, would only redact CLI display and would not remove a
value from state. The stack creates an empty Vault and key, but deliberately
does not create secret objects or values. The host deployment package provides
the audited boundary: an operator creates the values outside Terraform, installs
only their nonsecret secret OCIDs in a root-only mapping, and the VM instance
principal fetches `CURRENT` bundles into a complete root-owned `/run` tmpfs
generation. Docker and cloudflared are ordered after the boot-time hydration unit
and fail closed when the mapping, Vault, content, ownership, mode, allowlist, or
tmpfs checks fail. See `../README.md` for the exact artifact/import/rotation
procedure. Terraform, Resource Manager state, cloud-init, GitHub, and command
arguments never receive secret content. Required values include the database,
Redis, NATS, JWT, metrics, Telnyx, APNs, Cloudflare Tunnel, and backup-encryption
credentials.

Application media uses the compute instance principal with the native OCI
Object Storage API, so the stack creates no S3 customer secret key. Configure
the backend from the `object_storage_namespace`, `media_bucket_name`,
`object_storage_region`, and `object_storage_native_endpoint` outputs. The
bucket stays private; clients receive only expiring, object-specific PAR URLs.
Write PAR identifiers are persisted before their URLs leave the API, revoked at
completion, and their verified objects are conditionally renamed from staging to
backend-only `published/` names. The existing bucket-scoped `manage objects` and
PAR permissions cover rename and revocation; no additional credential is needed.

The cloud-init template only hardens the host, installs packages, validates and
mounts the attached data volume at `/srv/clixor`, restricts SSH, and prevents
Docker from starting without the data mount. It contains no runtime credentials.
Cloud-init user data is treated as a first-boot contract and ignored for
in-place drift so a template edit cannot unexpectedly replace an existing A1
instance. Reconcile later host-script or unit updates through a reviewed Bastion
maintenance session; newly created instances always receive the current files.
