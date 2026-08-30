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
- an instance-principal dynamic group and scoped policy for secret-bundle reads,
  bucket-scoped media/PAR access, and create/inspect-only backup uploads (the VM
  cannot overwrite or delete off-site backup objects);
- a regional, bucket-scoped service policy required to execute the Object
  Storage lifecycle rules.

The instance has no public IP. Cloudflare Tunnel remains the only application
ingress and is configured only after the runtime secrets are installed.

The stack deliberately waits 90 seconds after a new Vault becomes active before
creating its first key. OCI can briefly publish the Vault management endpoint
before its unique hostname is resolvable, which otherwise makes a clean
Resource Manager apply fail and succeed only on retry.

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

Do not add secret resources or secret values to this Terraform configuration:
Terraform would retain them in state. The stack creates an empty Vault and key,
but deliberately does not create secret values or a hydration service. The
bundled host bootstrap generates a root-only **staging** runtime file. Before a
production promotion, add an audited flow that writes secret values to Vault and
hydrates them through the instance principal into a root-owned tmpfs runtime
path. Until that flow exists, production secret materialization is an explicit
release blocker. Required values include the database, Redis, NATS, JWT,
metrics, Telnyx, APNs, Cloudflare Tunnel, and backup-encryption credentials.

Application media uses the compute instance principal with the native OCI
Object Storage API, so the stack creates no S3 customer secret key. Configure
the backend from the `object_storage_namespace`, `media_bucket_name`,
`object_storage_region`, and `object_storage_native_endpoint` outputs. The
bucket stays private; clients receive only expiring, object-specific PAR URLs.

The cloud-init template only hardens the host, installs packages, validates and
mounts the attached data volume at `/srv/clixor`, restricts SSH, and prevents
Docker from starting without the data mount. It contains no runtime credentials.
