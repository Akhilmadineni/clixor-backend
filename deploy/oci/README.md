# Clixor on Oracle Cloud Always Free ARM64

This package runs the backend on one Ubuntu ARM64 OCI instance at
`/srv/clixor`. It is sized for `VM.Standard.A1.Flex` with 2 OCPUs and 12 GB RAM.
It is a safe beta topology, not a multi-host high-availability design.

Two small API processes sit behind an internal Nginx gateway. PostgreSQL,
Redis, and NATS are single-instance services with no published ports. The API
uses authenticated private-CA TLS for each dependency and accesses a private OCI
Object Storage media bucket with its instance principal. The API gateway has a
connector-authenticated Unix-socket origin boundary: the public API is not
reachable on a host TCP port and only the systemd cloudflared identity belongs
to `clixor-origin`. The TCP listener serves exact health paths, clears
`CF-Connecting-IP`, and returns 404 for every application route.
Systemd tmpfiles creates the dedicated locked `clixor-gateway` (UID 986),
`clixor-origin` (GID 987) boundary before Docker at cold boot;
Compose has `create_host_path: false`, so a missing boundary stops the gateway
instead of silently replacing it with daemon-default permissions.

## Canary-first Cloudflare ownership transfer

Actions always deploys `clixor-oci-canary.atlanteanz.com`; `deploy.sh` rejects a
production stage. The gate runs readiness/association checks and the disposable
`smoke.py` lifecycle: account creation/deletion, WebSocket upgrade and reconnect,
E2EE message delivery, OCI PAR upload/download, authorization, and verified media
cleanup. Root-owned `canary-public-smoke.txt` binds that evidence to the exact
release SHA.

This is a **one-way NAS-to-OCI ownership transfer**. The NAS database is retired
and OCI is authoritative, so there is deliberately no route rollback that could
create split brain. A failure leaves production fenced and resumes the same
forward journal. Do not construct a request until a read-only Cloudflare review
has captured the full old and candidate tunnel configuration documents (including
their outer versions), every active connector ID/version, the complete zone
custom-rules ruleset, and both exact DNS records.

**Hard live prerequisite:** the old/source tunnel must first be dedicated to
Clixor. Its ingress inventory must contain exactly the two production Clixor
hostnames followed by the terminal 404. The currently shared tunnel containing
TradingBot is not eligible: move TradingBot to a separate tunnel in its own
reviewed maintenance change, verify that service independently, and only then
build this request. This controller never edits, preserves, or PUTs a shared
TradingBot tunnel. Any unrelated, wildcard, duplicate, or extra route fails
before a journal, gate transition, WAF mutation, or Cloudflare write. This
runbook does not assert that the prerequisite move has happened.

Use this exact request inventory (objects are examples; substitute the complete
reviewed Cloudflare responses):

```json
{
  "mode": "promote",
  "change_window": "FROZEN-CHANGE-1234",
  "account": "ACCOUNT_ID",
  "zone": "ZONE_ID",
  "controller_release": "/srv/clixor/releases/oci-EXACT-TAG",
  "controller_sha256": "SELECTED_RELEASE_PROMOTER_SHA256",
  "old_tunnel": "OLD_TUNNEL_UUID",
  "candidate_tunnel": "OCI_TUNNEL_UUID",
  "old_config_version": 7,
  "candidate_config_version": 11,
  "old_connector_ids": [],
  "candidate_connector_ids": ["REVIEWED_ACTIVE_CONNECTOR_UUID"],
  "old_target": "OLD_TUNNEL_UUID.cfargotunnel.com",
  "candidate_target": "OCI_TUNNEL_UUID.cfargotunnel.com",
  "revision": "NEW_40_CHAR_SHA",
  "old_config": {"ingress": [{"hostname": "clustr-api.atlanteanz.com", "service": "REVIEWED_OLD_SERVICE"}, {"hostname": "clixor.atlanteanz.com", "service": "REVIEWED_OLD_SERVICE"}, {"service": "http_status:404"}]},
  "old_retired_config": {"ingress": [{"service": "http_status:404"}]},
  "candidate_config": {"ingress": [{"hostname": "clixor-oci-canary.atlanteanz.com", "service": "unix:/run/clixor-origin/gateway.sock"}, {"service": "http_status:404"}]},
  "candidate_live_config": {"ingress": [{"hostname": "clixor-oci-canary.atlanteanz.com", "service": "unix:/run/clixor-origin/gateway.sock"}, {"hostname": "clustr-api.atlanteanz.com", "service": "unix:/run/clixor-origin/gateway.sock"}, {"hostname": "clixor.atlanteanz.com", "service": "unix:/run/clixor-origin/gateway.sock"}, {"service": "http_status:404"}]},
  "evidence": "/srv/clixor/releases/oci-EXACT-TAG/canary-public-smoke.txt",
  "evidence_sha": "EVIDENCE_SHA256",
  "maintenance_ruleset": "CUSTOM_RULESET_ID",
  "maintenance_ruleset_sha": "NORMALIZED_FULL_RULESET_SHA256",
  "maintenance_rule": "PRECREATED_FIRST_RULE_ID",
  "maintenance_rule_sha": "DISABLED_EXCEPTION_RULE_SHA256",
  "probe_source_ip": "TERRAFORM_PROMOTION_PROBE_SOURCE_IPV4",
  "dns": [
    {"id": "API_RECORD_ID", "name": "clustr-api.atlanteanz.com", "type": "CNAME", "content": "OLD_TUNNEL_UUID.cfargotunnel.com", "proxied": true, "ttl": 1},
    {"id": "APP_RECORD_ID", "name": "clixor.atlanteanz.com", "type": "CNAME", "content": "OLD_TUNNEL_UUID.cfargotunnel.com", "proxied": true, "ttl": 1}
  ]
}
```

`maintenance_ruleset_sha` is the canonical SHA-256 of the complete ruleset GET
after recursively omitting provider `version` and `last_updated` fields and
normalizing the first rule to the exact disabled exception rule.
`maintenance_rule_sha` binds that selected six-field projection (ID, action,
expression, description, ref, enabled). The selected rule must be uniquely first
in `http_request_firewall_custom`; the controller never calls a nonexistent
individual-rule GET. Each individual PATCH must return a complete ruleset, which
is validated immediately and then compared with another full GET.
`controller_release` must be the exact immediate target of
`/srv/clixor/releases/current`; its manifest source SHA must equal `revision`,
and either its base runtime manifest or its one-time exact promotion extension
must inventory `controller_sha256`. The installed controller must have that
digest, and the evidence must be a direct child of that release.
The tunnel versions are the outer `version` fields from each configuration GET.
Connector IDs are the complete reviewed active inventory returned by each
`/connections` GET (an empty old inventory is valid only when it is actually
empty). After each config PUT, the controller polls until every and only those
IDs reports the exact new `config_version`, journals the version/ID map, and
times out fenced if convergence is incomplete.

Give the separate control token only **DNS Write**, **Zone WAF Write**, and the
narrowest tunnel-config write permission offered for this account: **Cloudflare
One Connector: cloudflared Write**, **Cloudflare One Connectors Write**, or
**Cloudflare Tunnel Write**. Those are the current documented permission names;
do not broaden the token to account administration. Install the request as
`/run/operator/cloudflare-promotion-request.json` and the token as
`/run/operator/cloudflare-control-token`, both `root:root` mode 0400. They are
systemd credentials, never environment, argv, shell history, logs, persistent
files, or the connector token. The evidence path must name the canonical release
directory directly; mutable or symlinked authority paths are rejected. Run only:

```sh
sudo systemctl start clixor-cloudflare-promote.service
sudo systemctl status clixor-cloudflare-promote.service
```

The gateway independently fails closed when the persistent, empty, root-owned
`/var/lib/clixor/origin-gate-public/public-open` capability is absent. Compose
bind-mounts the always-present parent directory read-only; Nginx and cloudflared
cannot create, delete, or rename the marker. Separate Unix-socket virtual hosts
keep canary available while production returns an exact 503. The marker and its
separate root-only transition journal survive reboot and every mutation is
file-and-directory fsynced.

The forward sequence is:

1. validate the root-owned canary evidence, exact configs, exact proxied DNS
   tuples, full ruleset/order, and disabled exception rule;
2. enable a block-all version of the first custom rule and prove the OCI probe
   sees Cloudflare's 403;
3. close and verify the independent OCI origin gate;
4. retire the two reviewed Clixor routes from the dedicated old tunnel and wait
   for every reviewed old connector to consume the exact outer config version;
5. add the production routes to the candidate and wait for every reviewed OCI
   connector to consume that exact version, so no write boundary ever has both
   tunnels serving them;
6. batch both exact DNS records to the candidate. Cloudflare's batch can be
   partially applied, so a retry accepts only bound old/candidate values and
   reapplies the complete reviewed candidate set;
7. patch block-all to block-except the exact Terraform OCI NAT `/32` and prove
   the OCI probe reaches the closed 503 gate. Both old and new enabled edge rule
   versions block every external client, so safety does not assume global WAF
   propagation timing;
8. reread exact rule order/state, both tunnels, DNS, and the closed local gate;
9. create the local capability, validate the exact API and AASA revision through
   Cloudflare without following redirects, then repeat the complete authority
   read immediately before disabling WAF; and
10. disable the WAF rule last, atomically change the root-owned exact topology
    ownership state from `pre-cutover-old` to `oci-live`, and durably mark the
    transfer terminal.

Every remote mutation has an fsynced before/after journal entry. A SIGKILL after
the final disable is recognized from the exact remote state and finalized without
re-enabling WAF, so restart cannot manufacture a fresh outage. Unknown or mixed
state retains the local gate/fence for operator review and never rewrites an
unbound route. Rerunning a terminal request is read-only. To retain evidence,
change only `mode` to `archive`: a collision-safe authority-hash filename is
created with no overwrite, the active journal is fsynced away, and repeated
archive runs verify the same terminal authority idempotently. That makes the
active slot available for the next separately reviewed change window.
While the active journal exists, including after a terminal promotion but before
archive, both application deploy and explicit bootstrap refuse under the shared
deploy lock. This durable interlock prevents a later release from replacing the
exact controller authority required to resume or archive a crashed transfer.

The topology state is separate from application rollout. Before cutover,
ordinary deploys require the production hostnames *not* to serve the candidate.
After the one-time transfer records `oci-live`, ordinary deploys instead require
both production hostnames to serve the exact candidate revision before commit.
Neither deploy nor rollback changes topology ownership, and no NAS route rollback
exists.

The remotely managed canary route must point to
`unix:/run/clixor-origin/gateway.sock`; the checked-in example is the reviewed
route shape. The connector token exists only in the Vault-selected tmpfs cohort.
The promoter is installed from the authenticated release at mode 0555, checked by
a root-owned checksum, and uses systemd `StateDirectory=clixor`; never execute a
copy from `/srv/clixor/repo` or an Actions checkout with the control credential.
For an existing pre-controller release, run the already documented explicit
root bootstrap transition once from this reviewed source before automated deploy.
That transition extends the selected legacy runtime bundle with the checksummed
promoter, checksum, unit, and gate tmpfiles policy in an exact root-owned
extension manifest bound to the current release SHA and controller SHA, then
reloads systemd. That extension is valid current-release promotion authority;
it is not an Actions-checkout authority. Automated deploys then defer bootstrap
publication, capture the active files before any swap, restore them in the exit
rollback, and let the common-lock watchdog restore the exact
`releases/current` copies after SIGKILL or power loss.

## Security and availability boundaries

- On the bundled private-subnet foundation, allow SSH only from the OCI Bastion
  private endpoint. Do not open 80, 443, 8080, 3000, 5432, 6379, or 4222 in
  the VCN security list, network security group, or Ubuntu firewall.
- Host `cloudflared` connects only through the group-protected Unix socket. The
  fixed bridge address exposes health checks only; the gateway has no egress
  network or published host port.
- The two API replicas survive one API-process failure, but not VM, boot-volume,
  availability-domain, PostgreSQL, Redis, or NATS failure. OCI Object Storage is
  outside the VM failure domain but still depends on regional OCI availability.
- `/srv/clixor/backups` is only local staging. A root-owned timer copies verified
  dumps to the private, versioned Object Storage backup bucket; that still does
  not make the single-VM database highly available.
- Production secrets live in OCI Vault and are materialized only into a
  root-owned, atomically selected generation on `/run` tmpfs outside the
  repository. PostgreSQL, Redis, NATS, backup, Grafana, migration, and the API
  each receive only their allowlisted configuration; only the API receives JWT,
  OTP/Telnyx, APNs, SMTP, reset-HMAC, and mail-queue keys. Never
  use OCI user data, GitHub variables, Compose YAML, shell history, or issue logs
  for production credentials.
- Confirm the OCI VCN does not use `172.30.254.0/29`; that subnet is reserved for
  the fixed internal gateway identity trusted to forward `CF-Connecting-IP`.

## 1. Provision the instance

The recommended path is the bundled `terraform/` Resource Manager stack. It
creates an Ubuntu 24.04 ARM64 instance with:

- shape `VM.Standard.A1.Flex`, 2 OCPUs, 12 GB RAM;
- a 50 GB boot volume and separate 100 GB XFS data volume mounted at
  `/srv/clixor` before Docker starts;
- no public IPv4 address;
- a private subnet with outbound NAT and OCI Service Gateway routes;
- SSH-key authentication only; and
- OCI Bastion restricted to the operator's current public `/32`, with VM TCP/22
  reachable only from the Bastion side of the private subnet.

Take all available OS security updates before deploying. Connect or transfer the
source through a time-limited OCI Bastion session. A Cloudflare Tunnel does not
require an inbound web rule, public VM address, or router port forward.

## 2. Bootstrap the host

Clone the exact backend revision to a source directory such as
`/home/ubuntu/clixor-backend`. From that checkout run:

```sh
sudo sh deploy/oci/bootstrap.sh
```

The script verifies ARM64, 2 OCPUs, and approximately 12 GB RAM; installs Docker,
its Compose plugin, OCI CLI 3.91.0 through a checksum-pinned official installer,
and, on a fresh host with no selected release, exactly cloudflared 2026.7.3 from
Cloudflare's official ARM64 `.deb` pinned
to SHA-256
`d3ea7d22dd337b465da33d6bc1c4b3cfd381407447a2a7d29542c19783430db3`;
creates the
data/runtime tree; resolves Object Storage namespace/region through the instance
principal and OCI metadata; generates an internal CA; and creates root-owned
scoped files under `/srv/clixor/secrets` with random local staging credentials.
It selects those files through
`/run/clixor/secrets/active -> /srv/clixor/secrets`. `runtime.env` is retained
only as a non-consumed migration checkpoint for unknown legacy entries. Staging
bootstrap is not a production-secret source.

On an existing VM, bootstrap performs a one-time safe upgrade from the former
all-service `runtime.env`: it rejects symbolic links and duplicate assignments,
copies exact values without evaluating or printing them, validates every scoped
allowlist, publishes mode-0600 files atomically, and removes scoped assignments
from the legacy file only after every new file is ready. Rerunning it is
idempotent. During this Compose boundary only, application rollback uses the new
scoped model with the prior API image so provider credentials are not re-exposed
to data containers. Existing data, backup, and Grafana containers whose immutable
Docker configuration still contains secret-valued environment entries are force-replaced
once (a stopped Grafana container is removed); persistent data volumes are not
deleted.

Bootstrap is also the explicit transition for an existing pre-runtime-bundle
staging VM (including the staging layout produced by revision `9e41d3b`). While
holding the deployment lock, it requires `releases/current` to select a staging
release whose two live API replicas, immutable image ID/revision label, and
`/srv/clixor/repo` source all agree. It then creates and fsyncs a complete
schema-2 runtime baseline under `releases/pending`, validates it, and atomically
adds only that bundle to the already selected release. The current pointer and
PostgreSQL files are never changed. A partial baseline is renamed into
root-owned quarantine and a retry reconstructs it. Bootstrap refuses this
one-time transition for Vault mode or any source/image/PKI mismatch; resolve the
mismatch instead of bypassing the check.

The stable boot/recovery controller is intentionally operator-managed rather
than replaced by an automated release. Before the first deploy of a revision
that adds a required controller capability, rerun this bootstrap from that exact
reviewed revision. Deploy probes for the pre-migration durability command before
creating a candidate and fails without runtime mutation when the installed
controller is older.

The bootstrap preserves and pins an existing `/srv/clixor/secrets/pki/ca.crt`
trust root. It fails closed if that certificate and its private key are missing
as a pair, do not match, or change after being pinned. The CA signs three
independent P-256 server leaves: HAProxy's Redis endpoint is valid only for
`clixor-tls` and `dependency-tls`, PostgreSQL only for
`postgres.clixor.internal`, and NATS only for `nats.clixor.internal`. Leaves are
valid for 397 days and are replaced inside a 30-day renewal window. Key,
certificate, and combined-PEM generations are published through atomic
same-filesystem symlink changes; private keys are never written to deployment
output.

Each deploy compares the desired leaf digests with the last successfully
applied set. It force-recreates only the TLS-bearing dependency containers whose
leaf changed, waits for dependency health, and records the new set only after
both API replicas pass readiness. This desired/applied record also preserves a
pending restart when bootstrap is run separately or a deployment fails. The CA
is intentionally not rotated automatically: a coordinated trust rollover is
required before it enters the minimum validity window for a full new leaf.

The first configuration is deliberately `CLUSTER_ENV=staging` with Telnyx and
APNs disabled. This does not relax the application's production checks. Changing
`CLUSTER_ENV` to `production` still requires complete TLS dependency, Telnyx,
APNs, native OCI media, metrics, and token configuration or the API refuses to
start.

Do not copy an `*.env.example` file over a generated secret file. The examples
contain placeholders and are references, not secret generators.

## 3. Hydrate production secrets from OCI Vault

Terraform creates the Vault, encryption key, instance dynamic group, and
`read secret-bundles` policy, but intentionally creates no secret objects or
values. Create these seven secrets outside Terraform:

- `api_env`, `postgres_env`, `redis_env`, `nats_env`, and `grafana_env`, whose
  plaintext contents follow the matching checked-in examples;
- `apns_production_p8`, containing the complete PKCS#8 Apple private-key file;
  and
- `cloudflare_token`, containing only the remotely managed tunnel token.

`backup.env`, `migrate.env`, and `metrics.token` are derived by the hydrator;
do not create independent Vault copies that could drift. Add
`apns_sandbox_p8` only when `api_env` sets
`CLUSTER_APNS_SANDBOX_PRIVATE_KEY_FILE=/run/secrets/apns/AuthKey-sandbox.p8`.

Use OCI Console's Vault secret-content upload from a protected operator
workstation, or another audited input mechanism that does not put plaintext in
shell arguments or history. Never add `oci_vault_secret`, secret-content
variables, generated passwords, or provider credentials to Terraform: those
persist in state. Do not put secret payloads in Git, GitHub Actions, cloud-init,
Resource Manager variables, the OCID mapping, or command lines.

After creating the secrets, copy only their nonsecret OCIDs into the mapping:

```sh
sudo install -d -o root -g root -m 0700 /etc/clixor
sudo install -o root -g root -m 0600 \
  deploy/oci/vault-secrets.map.example /etc/clixor/vault-secrets.map
sudoedit /etc/clixor/vault-secrets.map
```

Replace every example OCID; placeholders are rejected. Each artifact must use a
different `ocid1.vaultsecret...` identifier. The mapping accepts no values,
shell syntax, unknown names, duplicate names, duplicate OCIDs, symbolic links,
or group/world access. Do **not** change `/etc/clixor/secret-mode` to `vault`.
That file is only the pre-release staging fallback. A production boot may enter
Vault mode only through an approved release, never through an operator-edited
global switch.

Run bootstrap once more from the reviewed checkout while the current release is
still staging. It installs the boot-time unit and fixed-path hydrator, verifies
that `/run/clixor/secrets` is backed by `tmpfs`, keeps the durable staging cohort
selected, and makes Docker require successful preparation on every boot:

```sh
sudo sh deploy/oci/bootstrap.sh
sudo readlink /run/clixor/secrets/active
```

On a raw pre-controller host, this explicit bootstrap reads the exact revision
label from both live API replicas, fetches that commit from the fixed public
repository into the root-owned mode-0700 bare object store at
`/srv/clixor/runtime/actions-source.git`, verifies the Git object graph, and
archives that exact tree. It never treats the mutable, Git-metadata-free
`/srv/clixor/repo` directory as source. The release-local boot cohort is added
only after that identity check. A custom pre-populated object store may be
selected with an absolute `CLIXOR_LEGACY_GIT_DIR`; missing objects, a drifted
image label, unsafe ownership/mode, or a mismatched tree fail the transition.

The initial staging-to-Vault transition is an explicit manual release. Complete
at least one ordinary staging deployment first so
`/srv/clixor/releases/current` already selects a boot-approved staging release;
the cutover refuses to run from an uncommitted/fallback-only host. GitHub Actions
always forces the cutover flag off and therefore cannot perform it:

```sh
revision="$(git rev-parse HEAD)"
sudo env \
  CLIXOR_REQUIRE_PUBLIC_SMOKE=true \
  CLIXOR_REQUIRE_VAULT_HYDRATION=true \
  CLIXOR_INITIAL_VAULT_CUTOVER=true \
  sh deploy/oci/deploy.sh "$PWD" "$revision" manual-vault-cutover-20260830T120000Z
```

While rollback is armed, deploy authenticates only as the VM instance principal
and requests one `CURRENT` response for every mapped OCID. Each response contains
both the base64 content and its OCI `version-number`; they are captured together
instead of making a racy second version query. The hydrator enforces bounded,
canonical content, exact per-service key allowlists, cross-service dependency
consistency, APNs private-key parsing, and the Cloudflare token format. It also
continues to reject implicit PostgreSQL, Grafana, mail-queue encryption, OTP-HMAC,
and password-reset-HMAC rotations, which require their documented state-aware
procedures.

The candidate release receives mode-0400, root-owned
`vault-approved-cohort.json` and `vault-secrets.map` files. The strict manifest
contains every artifact exactly once, its mapped OCID, the exact OCI secret
version, the mapping SHA-256, the release cohort, and a canonical cohort digest.
Unknown, missing, duplicate, unsorted, reused, mixed, or hash-mismatched records
are rejected. Only after application readiness, public ingress, backup, and
restore gates pass does the same atomic `/srv/clixor/releases/current` pointer
approve the application, `secret-mode=vault`, mapping snapshot, and version
manifest together. A failure or crash before that pointer change leaves the old
staging release boot-authoritative.

On every later boot, the unit reads `secret-mode` from the selected release and
hydrates only the exact `--version-number` values in that release's manifest. It
never requests Vault `CURRENT`. Changing `/etc/clixor/vault-secrets.map` or
promoting a new Vault version affects only a future candidate deployment. Keep
every version referenced by the current and retained rollback releases available
in OCI Vault; deleting an approved version makes that release intentionally fail
closed on reboot. Docker and cloudflared start only after the complete pinned
cohort is reconstructed into tmpfs.

Compose mounts the tmpfs files and stores only nonsecret file paths in container
metadata. API and migration binaries parse their mounted file before loading
configuration; PostgreSQL uses `POSTGRES_PASSWORD_FILE`, Redis uses an ACL file,
NATS and Grafana use generated config files, backup uses `PGPASSFILE`, and
cloudflared uses a systemd credential. No secret-valued `env_file` is used.
Loaded API values are still present in process memory/environment while running,
so host root, the Docker daemon, and code execution inside that container remain
trusted boundaries; tmpfs is an at-rest and metadata hardening boundary, not
protection from root compromise.

The production Actions entrypoint selects a new candidate cohort while holding
the deployment lock before any container, file, backup, or migration mutation.
It requires an existing approved Vault release and explicitly sets
`CLIXOR_INITIAL_VAULT_CUTOVER=false`. Production deployment refuses an unpinned
legacy Vault mode, an unapproved/mixed manifest, a non-tmpfs target, or a
missing/unsafe generation marker. A manual staging deploy may use the explicit
`/run/.../active -> /srv/clixor/secrets` fallback and locally generated
credentials.

An upgraded host may still contain the former persistent production files under
`/srv/clixor/secrets` for a deliberately bounded rollback window. Ordinary
hydration and deployment never retire, quarantine, or delete them. Retirement is
the separate, explicit `quarantine-staging-secrets.sh` maintenance workflow
described below; it requires proof of an approved-manifest reboot, a current-boot
restore drill, and all provider canaries. It moves values to root-only quarantine
and never purges them. Never remove the externally recoverable Vault versions.

### Release-approved boot tooling

Every immutable release contains `boot-secrets/prepare-runtime-secrets.sh`, its
matching `hydrate-vault-secrets.py`, and a strict `SHA256SUMS`. Deploy stages
them root-owned with modes `0500`, stores the checksum manifest at `0400`,
revalidates and fsyncs the files and directories, and only then advances
`releases/current`. The stable systemd service executes only the small
root-owned launcher in `/usr/local/libexec/clixor`. That launcher fails closed
unless `releases/current` is a root-owned symlink to one immediate mode-0700
release, the release-local bundle has the exact expected files and modes, and
every checksum matches. It passes the resolved release path to that release's
worker, so an uncommitted candidate directory cannot affect a reboot. Vault
boot hydration uses only the approved manifest and exact OCI version numbers
from the resolved release; it never resolves provider `CURRENT`.

The `/etc/clixor/secret-mode` fallback is limited to the initial staging boot
before any `oci-*` release history exists. Once history exists, a missing or
unsafe `releases/current` pointer is a hard boot failure rather than a silent
staging downgrade. For a fresh host, run the explicit bootstrap in staging mode
and then commit the first staging release. For a host created before
release-local boot tooling, first deploy one staging release while the legacy
boot unit remains installed. After that release is current, run the explicit
operator bootstrap once to install the stable launcher/unit, reboot, and prove
the pinned staging release before any Vault cutover. Bootstrap refuses the
unsafe reverse order. Automated deploy calls set host-tool activation deferral
and cannot overwrite the launcher, initial fallback worker, unit, or Docker
ordering drop-in.

### Explicit staging-secret quarantine maintenance

This workflow is never called by bootstrap, hydration, Actions, or deploy. Run it
only under an approved change ticket after the path-only production release has
been stable. Before reboot, record the current boot ID in a root-only file:

```sh
sudo install -m 0600 -o 0 -g 0 /proc/sys/kernel/random/boot_id \
  /etc/clixor/pre-retirement-boot-id
```

Reboot the VM. Confirm that the boot ID changed, the `active` link selects a
`vault-generations/...` directory whose schema-2 `.vault-hydrated` marker names
the exact current release cohort and contains the mapping and cohort SHA-256
values from that release's root-owned mapping and approved manifest. Never
attest mutable `/etc` mapping or mode files. During this new boot, run a fresh
offsite backup and isolated restore
drill. Then complete real Telnyx OTP, APNs production/sandbox notification, SMTP
reset-mailbox, OCI media upload/verify/download/delete, and both Cloudflare
hostname canaries. A paper review or local readiness alone is not a provider
canary.

After those checks pass, create
`/etc/clixor/staging-secret-retirement.approval` with `sudoedit`. It must contain
exactly these non-secret fields, be owned by `root:root`, and have mode `0600`:

```text
schema=3
change_ticket=CHANGE-1234
approved_mapping_sha256=<64 lowercase hex characters>
approved_cohort_sha256=<64 lowercase hex characters from the schema-2 marker>
pre_reboot_boot_id=<boot ID recorded before reboot>
approved_boot_id=<current boot ID>
approved_release=/srv/clixor/releases/oci-<approved release tag>
provider_canaries=apns,cloudflare,oci-media,smtp,telnyx
provider_canaries_passed_at=2026-08-30T18:30:00Z
retired_cloudflare_token_revoked_at=2026-08-30T18:35:00Z
```

The canary timestamp must be after the current boot, and the restore success
marker must also be newer than that boot. Recheck the approval, revoke the
retired connector token in Cloudflare, and securely remove both
`/etc/cloudflared/token` and `/srv/clixor/secrets/cloudflare-token`. The script
fails closed while either persistent bearer credential exists; tokens are never
retained as evidence. Then run the only supported retirement entrypoint:

```sh
sudo chmod 0600 /etc/clixor/staging-secret-retirement.approval
sudo sh deploy/oci/quarantine-staging-secrets.sh quarantine \
  /etc/clixor/staging-secret-retirement.approval
```

The script revalidates every precondition, current local API readiness, Docker,
cloudflared, file types, ownership, boot IDs, and the exact current release
pointer. It verifies the release-local boot bundle checksum, mode and mapping,
the approved manifest's calculated cohort digest, and the active schema-2
marker with that release's own checksummed verifier. It never falls back to
mutable `/etc/clixor/secret-mode` or `/etc/clixor/vault-secrets.map`. It
moves non-connector `/srv/clixor/secrets` candidates to a unique mode-0700
directory below `/srv/clixor/quarantine/staging-secrets`. It appends a non-secret,
root-only result to `/var/log/clixor/staging-secret-maintenance.log`. It never
deletes quarantined content and offers no purge mode. Any later secure deletion
requires a second change ticket, quarantine inventory review, confirmed Vault
recovery, and a separately implemented operator procedure.

## 4. Deploy an immutable source revision

From the source checkout:

```sh
revision="$(git rev-parse HEAD)"
sudo sh deploy/oci/deploy.sh "$PWD" "$revision" manual-20260830T120000Z
```

Use a new non-secret run identifier for every attempt. Release directories are
immutable while retained, so the script refuses to overwrite an earlier run.
After a newly verified offsite backup and successful deployment, bounded
retention removes only non-boundary history as described below.

The deploy script:

1. takes an exclusive host lock;
2. requires at least 8 GiB plus three times the live PostgreSQL footprint free
   on `/srv/clixor`, and at least 6 GiB free on Docker's filesystem, before
   creating a release or snapshot; when both paths share one filesystem, the
   requirements are added rather than counted twice;
3. stages the candidate only under `releases/pending`; writes its secret mode;
   snapshots the exact approved source and no-auto-restart Compose model; stages
   and checksums its boot worker, Vault hydrator, backup/restore/health programs,
   systemd units and connector unit; downloads and authenticates the exact
   reviewed cloudflared ARM64 package into the pending candidate without
   changing the host; snapshots that executable into the runtime bundle; and
   captures the previous executable, unit, and service state for the synchronous
   exit-trap rollback;
4. for an upgrade, captures the previous Compose model, API image, release
   pointer, and a mode-0600 PostgreSQL custom dump that passes `pg_restore
   --list` and SHA-256 verification, then fsyncs the dump, checksum, and pending
   candidate directory in that order before changing the active runtime; a
   clean first deployment records an explicit first-deploy marker;
5. creates and fsyncs the schema-2 deployment journal before secrets or active
   runtime can change, then advances it consecutively through secret hydration,
   runtime mutation, migration, candidate validation, publication, and pointer
   commit;
6. for Vault, atomically fetches content and OCI version for every mapped
   artifact, writes and revalidates the strict mapping-bound candidate manifest,
   then selects its complete tmpfs generation while secret rollback is armed;
7. rejects live Redis or NATS credential changes on an existing singleton;
8. builds and verifies an ARM64 API image tagged with the full source revision,
   and arms application rollback before the first active runtime mutation;
9. refreshes the independent dependency TLS leaves, synchronizes that exact
   source to `/srv/clixor/repo`, and restarts dependencies that need a new image,
   scoped secret boundary, or certificate; the small HAProxy TLS edge is always
   replaced because it reads its bind-mounted configuration only at startup;
10. runs the one-shot forward, expand-compatible migration command, verifies the
    previous release still passes readiness, then replaces `api-a` and `api-b`
    one at a time, requiring direct readiness before replacing the next replica;
11. reconciles the gateway only after both replicas are ready, validates its
    reviewed configuration, and handles running observability consumers
    separately;
12. records applied PKI and creates a complete schema-2 runtime bundle containing
    exact source, Compose, immutable image reference and ID, runtime configuration,
    dependency TLS leaves, host tools, connector unit/executable, and intended
    service state; every file, mode, and size is inventoried by SHA-256 and
    fsynced;
13. writes the runtime-ready marker only after validating that bundle and both
    candidate API containers' image IDs; for production, activates the reviewed
    connector and checks both public hostnames against the exact revision;
14. while rollback remains armed, publishes candidate backup/restore tooling,
    creates and uploads a fresh post-migration backup, restores it into an
    isolated PostgreSQL container, runs integrity checks, enables the verified
    timers, and runs backup health;
15. atomically renames the complete pending directory into the release root,
    updates the ready marker, and revalidates both runtime and boot bundles;
16. only then atomically advances and fsyncs `releases/current`, recording the
    pointer phase and atomically archiving the journal before rollback is
    disarmed; the pointer approves application, source/config, boot tooling,
    host tooling, image identity, service state, and Vault cohort together; and
17. after the fresh offsite marker and successful release are durable, retains
    current and previous rollback boundaries plus three audit releases, strips
    non-boundary migration dumps, and removes unused non-boundary API image tags.

A failed upgrade restores the prior Vault selection, the exact captured
cloudflared executable and unit checksums plus enabled/active state, the captured host programs,
systemd units, and timer state, then its Compose model, API image, and captured
startup configuration. The stable reconciler then restores the selected
release's exact source, runtime files, PKI, host tools, Compose model, and service
state. Connector readiness and public ingress are rechecked when
the prior connector was active. Cloudflared or host-tool restoration failures are
part of the final rollback verdict rather than warnings. A failed first
deployment performs the same host restoration, stops the incomplete stack, and
renames its release artifact into quarantine without deleting it or its
bind-mounted data. Database migrations are
forward-only: neither path automatically runs `pg_restore`, reverses migrations,
or deletes database files. The pre-change dump is an operator recovery artifact,
not an automatic rollback mechanism.

### Crash-consistent boot and deployment recovery

Docker is not the boot authority. Every persistent Compose service has
`restart: "no"`, so Docker cannot independently revive whichever candidate
containers happened to exist when the VM lost power.
`clixor-runtime-reconcile.service` stops ingress and known containers, validates
only the absolute immediate child selected by `releases/current`, and verifies
that release's exact staging selection or mapping/cohort-bound Vault generation.
Staging releases contain a root-only manifest of every runtime-consumed secret
file's path, ownership, mode, size, and SHA-256 digest. Vault generations contain
the equivalent release/mapping/cohort-bound integrity inventory, including the
derived service files, APNs keys, Cloudflare token, and hydration marker. A
missing, added, metadata-drifted, or content-drifted required artifact is never
accepted merely because the active symlink and cohort marker still match.
If a pre-pointer candidate had switched the tmpfs secret link, it runs only the
current release's checksummed worker to restore the exact approved versions and
then verifies the selection again before touching runtime files or containers.
A healthy boot/watchdog uses the local marker plus the release-local verifier
and does not perform a duplicate Vault fetch. It then restores the selected
release's complete checksummed runtime bundle,
force-recreates its exact image/Compose selection, restores the release-selected
cloudflared executable, verifies both replicas plus exact local revision
readiness, clears every exact controller-owned nft cut in one transaction,
rechecks the host route while the ready marker and Cloudflare remain closed,
and only then writes `/run/clixor/runtime-ready`. The two recognized nft table
identities are `clixor_fail_closed` and `clixor_fail_closed_candidate`; either
exact input-and-output DROP table is a complete crash-safe cut. Recovery never
renames nft tables, never deletes the sole verified cut while installing one,
and accepts a candidate-only state left after power loss. Unknown lookalike
tables are never cleared automatically. Cloudflared and the
backup/restore/health services are ordered after that reconciler and require the
ready marker. A verified first boot with no cloudflared unit is handled
idempotently; any active or unverifiable ingress state still fails closed. The
reconciler never copies, restores, removes, or rolls back PostgreSQL data files.

The durable journal is `/srv/clixor/runtime/deploy-transaction.json`. Its file
and parent are fsynced on creation and every consecutive phase change.
Before that journal can authorize runtime mutation or migration, the controller
opens the canonical root-owned pending parent and candidate without following
links, verifies and fsyncs the dump and exact checksum through directory file
descriptors, then fsyncs the candidate directory and its pending parent in that
order. Symlinked or group/world-writable recovery ancestors are rejected.
`clixor-runtime-watchdog.timer` runs the stable controller every minute. It tries
the deployment lock without blocking: while a deploy holds the lock it does
nothing; after SIGKILL or power loss it ignores the uncommitted candidate,
reconciles only `current`, atomically archives the journal, and renames any
non-current candidate to `/srv/clixor/releases/quarantine`. If the pointer swap
was already durable, the pointer is the commit record and the watchdog reconciles
the new release. Invalid bundles, unavailable exact image IDs, corrupt journals,
unsafe paths, checksum drift, and inability to stop exposed runtime all fail
closed. A corrupt journal is retained for operator inspection.

Pending and quarantined directories are not committed history and do not prevent
initial staging-secret preparation. A pre-journal SIGKILL leftover with the same
run identity is renamed to quarantine on retry. Recovery never deletes data,
volumes, pre-migration dumps, or quarantined evidence.

Inspect the selection and recovery state with:

```sh
sudo readlink /srv/clixor/releases/current
sudo systemctl status --no-pager clixor-runtime-reconcile.service
sudo systemctl status --no-pager clixor-runtime-watchdog.timer
sudo ls -la /srv/clixor/runtime/deploy-transaction.json \
  /srv/clixor/runtime/deploy-transactions \
  /srv/clixor/releases/quarantine 2>/dev/null
```

Rolling availability requires expand/contract database changes. A release may
add nullable columns, tables, indexes, and behavior understood by both the old
and new binaries. It must not remove or reinterpret a field, or add a constraint
the previous binary can violate, while that binary can still serve traffic.
Ship those contract changes only in a later release after every old replica has
drained. The post-migration old-release readiness check catches gross
incompatibility but does not replace migration review.

Migration 18 has a bounded write-fence budget: relation-lock acquisition fails
after 5 seconds and every validation/backfill/DDL statement fails after 30
seconds. Before deploying it, query the production primary for
`count(*)` on `conversation_members`, `conversation_member_local_ids`, and
`conversation_member_tombstones`, and review `pg_stat_activity` for non-idle
transactions with an old `xact_start` that touch user/conversation membership.
Record those counts with the release evidence. Run the exact migration against
a recently restored, production-sized backup in CI or the release load gate;
every statement must finish within 30 seconds. This repository makes no
untested cardinality claim and operators must not raise or remove these limits
to force a release through.

If either timeout fires, the migration transaction, backfill, functions, and
triggers roll back together and the prior API remains authoritative. Cancel or
drain the identified long transaction, or schedule a maintenance window after
the restored-backup load gate passes, then retry the normal deployment. Do not
manually mark migration 18 applied and do not partially replay its SQL.

The first digest-pinned and per-service-PKI rollout intentionally recreates
PostgreSQL, Redis, NATS, and HAProxy once. Schedule that transition in a
maintenance window because the single-node A1 topology has no redundant
database/cache/event-bus instance. Nginx, HAProxy, the backup worker, Prometheus,
and Grafana read ordinary bind-mounted files rather than Docker Config objects.
Each deployment therefore force-replaces HAProxy and the backup worker. Nginx is
reconciled after both APIs pass readiness, validates the new file, and reloads
gracefully unless an immutable container setting or image change requires
Compose to replace it. Any observability process that was already running is
replaced; stopped optional observability services remain stopped.

Capacity failure is intentionally fail-closed before a dump or image build. The
successful-release retention pass never deletes the current release, its direct
previous rollback boundary, either boundary's pre-migration dump, or either API
image. It runs only after the deployment's new offsite success marker. If an
older installation already exhausted the volume before this policy can run,
stop and perform a reviewed manual cleanup; do not weaken the preflight.

Check local state:

```sh
curl --fail http://172.30.254.2:8080/health/ready
sudo env CLIXOR_IMAGE_TAG="$(basename "$(readlink /srv/clixor/releases/current)")" \
  docker compose --file \
  "$(readlink /srv/clixor/releases/current)/runtime-bundle/compose.yaml" ps
```

The exact SHA argument is the deployment boundary. Deploying `main` does not
silently include features that exist only on another branch.

All third-party GitHub Actions used by CI and deployment are pinned to immutable
40-character commits. Container base images, CI service images, the isolated
restore image, and every OCI runtime dependency image are pinned to reviewed
multi-platform manifest-list digests verified to include `linux/arm64` and
`linux/amd64`. Keep digest upgrades separate from application-only releases and
repeat the architecture and provenance review before changing any pin.

### GitHub Actions production runner

After the first manual deployment and Cloudflare cutover are verified, a
repository-scoped runner can enable `.github/workflows/deploy-oci.yml`. The
workflow accepts only a successful `push`-triggered `CI` run on this repository's
`main`, serializes production deployments, and uses the same snapshot, migration,
readiness, public-ingress, and application-rollback path as a manual deployment.
It requests a short-lived GitHub OIDC token bound to the workflow and run. The
root-owned entrypoint verifies that signature, verifies the completed CI run with
GitHub's public Actions API, fetches the exact current `main` SHA from the pinned
public repository URL into a root-only bare mirror, and runs a root-owned archive.
It never executes a file from the runner-writable checkout and invokes the
verifier, Git transport, archive tools, and deployment under an explicit empty
environment rather than inheriting runner-controlled process settings. No OCI,
GitHub, or application credential belongs in GitHub Actions.
Every production run first fetches and validates all mapped Vault `CURRENT`
bundles through the instance principal while holding the root-owned deployment
lock, binds their returned version numbers to the candidate release manifest, and
does so before any deployment mutation.
The root-owned entrypoint additionally refuses automated deployment unless the
hydrated scoped API configuration is mode `0440`, owned by `root:65532`, the
current release already contains a root-only approved manifest/mapping, and the
API explicitly enables production, Telnyx verification, and durable SMTP reset
delivery. Manual staging deployments remain available for provider canaries
before this gate is enabled.

Before bringing the production runner online, protect `main`: require pull
requests and review, make every CI job a required check, and disallow force pushes
and branch deletion. The root boundary requires a successful CI run and the exact
current main tip, but repository governance must still prevent an unreviewed main
push from becoming an approved production source.

Create a dedicated unprivileged account and fixed runner directory:

```sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends git
sudo useradd --create-home --shell /bin/bash github-runner-clixor
sudo install -d -o github-runner-clixor -g github-runner-clixor -m 0750 \
  /opt/actions-runner-clixor
```

In GitHub, open this repository's **Settings > Actions > Runners > New
self-hosted runner**, select Linux ARM64, and use its current download URL and
SHA-256 checksum to install the runner into `/opt/actions-runner-clixor`. Never
paste its one-time registration token into this repository, shell history, or an
issue. Register from an interactive root shell like this:

```sh
sudo -iu github-runner-clixor
cd /opt/actions-runner-clixor
read -r -s -p 'One-time GitHub runner token: ' ONE_TIME_RUNNER_TOKEN
printf '\n'
./config.sh \
  --url https://github.com/Akhilmadineni/clixor-backend \
  --token "$ONE_TIME_RUNNER_TOKEN" \
  --name clixor-oci-prod-01 \
  --labels clixor-oci-production \
  --work _work \
  --unattended \
  --replace
unset ONE_TIME_RUNNER_TOKEN
exit
```

The runner automatically receives the `self-hosted`, `Linux`, and `ARM64`
labels. The additional `clixor-oci-production` label prevents unrelated
self-hosted runners from taking this job. Install the small root-owned validation
entrypoint and grant only that entrypoint through passwordless sudo:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/clixor
sudo install -o root -g root -m 0755 \
  /home/ubuntu/clixor-backend/deploy/oci/actions-deploy.sh \
  /usr/local/sbin/clixor-actions-deploy
sudo install -o root -g root -m 0755 \
  /home/ubuntu/clixor-backend/deploy/oci/verify_github_deploy.py \
  /usr/local/libexec/clixor/verify-github-deploy
sudo visudo -f /etc/sudoers.d/clixor-actions-deploy
```

The sudoers file must contain exactly this rule and be mode `0440`:

```sudoers
github-runner-clixor ALL=(root) NOPASSWD: /usr/local/sbin/clixor-actions-deploy
```

Then install and start the runner service from its installation directory:

```sh
cd /opt/actions-runner-clixor
sudo ./svc.sh install github-runner-clixor
sudo ./svc.sh start
sudo ./svc.sh status
```

Keep the runner repository-scoped and dedicated to production. Do not add the
custom production label to the retired NAS runner or any shared runner. Leave the
OCI runner offline until the Vault-selected files under `/run/clixor/secrets/active`, native OCI media,
backups, and the Cloudflare tunnel have passed their manual release gates. If the
repository owner/name or workflow path changes, update and reinstall both
root-owned verification files before enabling it.
The unauthenticated source-run verification intentionally depends on this
repository remaining public. If the repository becomes private, disable the
runner until this boundary is replaced with a reviewed GitHub App or equivalent
read-only verifier; never silently fall back to trusting the runner checkout.

API startup creates an OCI instance-principal signer and performs `HeadBucket` on
the configured media bucket. Therefore, successful readiness for both replicas
also proves that their egress bridge can reach OCI IMDS and Object Storage and
that the bucket is readable. A real upload/verify/download/delete test remains a
separate release gate because readiness does not exercise pre-authenticated URLs.

Only `api-a` and `api-b` join the non-internal `clixor_egress` network. No proxy,
database, cache, event bus, monitoring, or backup container can reach OCI IMDS.
Treat code execution inside an API container as equivalent to the narrowly scoped
instance-principal media permissions and keep its dynamic-group policy bucket
specific.

## 5. Move Cloudflare ingress

Do not install a moving cloudflared package manually. Terraform cloud-init and a
fresh-host `bootstrap.sh` install exactly **2026.7.3** by downloading Cloudflare's
official `cloudflared-linux-arm64.deb`, verifying the pinned SHA-256 before
extracting it, checking the package architecture/version, and atomically
publishing only its binary at mode 0555. The deploy path repeats that
authentication into the pending release before rollback is armed, then publishes
the release-local copy inside the transaction. Both deploy and the connector
service reject every other version, including 2026.8.0. A failed deploy restores
the exact captured prior executable; the crash watchdog restores the committed
release's executable. This requires no connector token or other secret and works
for new cloud-init instances. On an existing host with a selected release,
explicit bootstrap deliberately leaves the active executable untouched; the next
normal `deploy.sh` performs the same pinned install inside its shared-lock,
release-bound rollback transaction.

Create a new, remotely managed tunnel for this VM; do not
reuse a NAS connector connected to a different database. Before ownership
transfer its remotely managed configuration must be exactly the canary route
followed by the terminal 404 rule:

- `clixor-oci-canary.atlanteanz.com` -> `unix:/run/clixor-origin/gateway.sock`
- terminal catch-all -> `http_status:404`

Do not add either production hostname manually. The root promotion controller
adds them only after the reviewed old-tunnel rules have been retired under the
edge fence and closed local gate.

After selecting the production Vault generation, run the normal immutable
release. `deploy.sh` checksum-stages and systemd-validates the hardened unit,
captures the exact effective old fragment and state, atomically publishes the
candidate, and reloads systemd. It loads the token from the same atomic `active`
generation. It enables the unit but restarts it only if the reviewed executable,
unit, or token changed, using a bounded 90-second readiness gate:

```sh
revision="$(git rev-parse HEAD)"
sudo sh deploy/oci/deploy.sh "$PWD" "$revision" manual-cloudflare-cutover
sudo systemctl status --no-pager cloudflared.service
```

An executable change requires a restart so the running process matches the
committed bundle. Its four outbound connections re-establish automatically, but
this single-VM topology can have a brief ingress interruption during that
restart; schedule the first pinned-version transition inside the maintenance
window. Exit rollback restarts the captured prior binary, and crash recovery
keeps ingress closed until the committed release is restored.

The token stays root-owned at mode `0600`; systemd exposes it to the dynamic
connector identity only through `LoadCredential`. Do not place it in
`runtime.env`, a cloud-init payload, GitHub Actions, or the `cloudflared` command
line. The unit uses Cloudflare's `auto` transport so it prefers QUIC and can fall
back to HTTP/2 if UDP is unavailable. Verify four outbound tunnel connections,
then validate only the candidate hostname and capture the complete canary
evidence described above:

```sh
curl --fail https://clixor-oci-canary.atlanteanz.com/health/ready
curl --fail --header 'Accept: application/json' \
  https://clixor-oci-canary.atlanteanz.com/.well-known/apple-app-site-association
```

Run the reviewed one-way promotion request only after that evidence is sealed.
After the controller reports a terminal promotion, validate the production
hostnames:

```sh
curl --fail https://clustr-api.atlanteanz.com/health/ready
curl --fail https://clixor.atlanteanz.com/privacy
curl --fail https://clixor.atlanteanz.com/terms
curl --fail --header 'Accept: application/json' \
  https://clixor.atlanteanz.com/.well-known/apple-app-site-association
```

The association document authorizes only `/join` and `/join/*` universal links
for Apple application `H9S3BAQ9U8.com.Clustr.Clustr.Clustr`. It must return
directly with HTTP 200 and `Content-Type: application/json`; do not put a login,
HTML error page, or redirect in front of it.

Password-reset mail is first AES-256-GCM sealed and transactionally inserted in
PostgreSQL with the challenge; request handlers never wait for remote SMTP.
Workers use `FOR UPDATE SKIP LOCKED` leases, bounded exponential retry with
jitter, dead-lettering, and bounded retention. For OCI Email Delivery in
Phoenix, use authenticated implicit TLS at
`smtp.email.us-phoenix-1.oci.oraclecloud.com:465`, or mandatory STARTTLS at port
587. Configure the SMTP credential, approved `no-reply@mail.atlanteanz.com` sender,
distinct reset HMAC, and padded-base64 32-byte queue key only in the `api_env`
Vault bundle. Keep the application in explicit staging mode with
`CLUSTER_MAIL_PROVIDER=disabled` until SPF, DKIM, DMARC, suppression handling,
and real-mailbox reset/change canaries pass; reset endpoints then return 503
instead of offering an unsafe shortcut. The production Vault allowlist requires
`CLUSTER_MAIL_PROVIDER=smtp`, so a production promotion fails closed until those
mail gates and credentials are complete.

The queue currently has one encryption key, not a keyring. Never hot-rotate
`CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY`: old queued ciphertext would become
undecryptable. With the old key/provider still active, first let workers drain
until this query returns zero:

```sql
SELECT status, count(*) FROM mail_deliveries
WHERE status = 'pending' GROUP BY status;
```

Then set the provider to disabled and restart both APIs to prevent new enqueue,
and run the query again. If it is nonzero, restore the old key/provider and drain;
do not rotate. Once the frozen queue is empty, retain the old key in the approved
break-glass secret store, install the new key with SMTP re-enabled, restart both
replicas, and run a real-mailbox reset canary. A key change while pending rows
exist is a cutover stop condition.

Never leave the old NAS and new OCI connectors serving the same hostnames against
different databases. That creates split-brain writes and inconsistent sessions.
Cloudflare must allow WebSockets. Media transfer URLs are short-lived,
object-specific OCI pre-authenticated requests returned by the API; media bytes
do not traverse Cloudflare Tunnel or this VM.

Clients must send every header returned in the upload instructions unchanged.
For OCI that includes `Content-Type`, `Content-Length`,
`opc-checksum-algorithm: SHA256`, and a base64 `opc-content-sha256`. Completion
uses Object Storage `HEAD` metadata to verify all three declarations without
streaming a production-05b-compatible 1 GiB object through an API container. A
missing checksum header is rejected and queued for durable deletion. Before an
upload URL is returned, migration 14 stores its opaque PAR identifier. Completion
revokes it, conditionally renames the verified staging object to a backend-only
`published/` key with source-ETag and destination-create fences, then atomically
stores that key and queues staging cleanup. Migrations 10, 11, and 14 must be
applied before this binary starts; migration 10 adds media
reservations, immutable upload expiry, verification leases, and deletion
scheduling, migration 11 adds the bounded published-outbox retention index,
migration 12 adds encrypted durable mail delivery, migration 13 enforces unique
APNs token ownership, and migration 14 closes write-PAR replay during
publication.

## 6. Provider credentials and production promotion

Keep the first deployment in staging while authentication, group, media,
WebSocket, and account-deletion tests run. Populate the Vault bundles described
above with distinct production values, promote their intended versions to
`CURRENT`, run the explicit manual cutover release above, and then complete all
of these:

- Telnyx sender registration, API/signing credentials, allowed country prefixes,
  and a real-device OTP test;
- Apple team/key/bundle values, the readable `.p8` key, and production plus
  sandbox-device notification tests;
- native OCI media upload/verify/download/delete tests using returned
  pre-authenticated URLs;
- account deletion, refresh-token revocation, WebSocket reconnect, and migration
  tests; and
- a successful off-instance backup and isolated restore drill.

After changing runtime configuration, deploy a new immutable revision. Placeholder
values are rejected by the deploy script, and the application's existing production
validation remains authoritative.

Rotate coordinated bundles during a maintenance window, promote every intended
version to `CURRENT`, then run one candidate deployment; do not invoke boot
hydration directly. A PostgreSQL password is
not rotated by changing `POSTGRES_PASSWORD_FILE` on an initialized database:
change the database role password in the same controlled operation or the API
will be locked out. A normal release rejects a Redis or NATS credential change
when that single-node dependency already exists; silently recreating either one
would violate the zero-downtime release contract. Rotate either credential only
as an explicit maintenance operation: announce a window, drain ingress and both
APIs, preserve the prior Vault generation, update the server and client bundle
together, recreate the affected dependency and both APIs, then prove local
readiness and provider canaries before reopening ingress. On failure, reselect
the prior Vault generation and recreate every affected consumer. Do not bypass
the normal-release rejection because there is no redundant Redis or NATS node in
this topology. APNs and API-provider changes require both API replicas to
restart; a Cloudflare token change requires a connector restart after the new
tunnel token is proven.
JWT rotation invalidates sessions. The mail-queue key has the stricter drain
procedure above. Any inconsistent dependency URL/credential bundle, pending mail
during queue-key rotation, unverified Cloudflare token, or failed real-device
canary is a rotation stop condition. Exact Vault versions referenced by the
current and retained release manifests are the reviewed rollback source; never
copy decrypted tmpfs files back to persistent storage.

## 7. Backups

The default stack performs a six-hourly custom-format PostgreSQL dump with a
SHA-256 checksum and seven-day local retention. OCI Object Storage is already the
primary media store and is not copied into the VM backup directory.

The initial operator bootstrap installs root-owned backup programs in
`/usr/local/libexec/clixor`, a mode-0600 non-secret bucket/prefix file at
`/etc/clixor/offsite-backup.env`, and three hardened timer pairs. During a
deployment, bootstrap explicitly defers changes to those host programs and
units. `deploy.sh` instead stores a checksum-verified version under that
release's mode-0700 directory, captures the installed files and timer state, and
publishes the candidate tooling while rollback is armed and before starting the
offsite or restore gates. Thus both synchronous gates execute the new release's
programs and units. It first stops the three timers and refuses activation while
an old backup, restore, or health job is running, closing the race where a gate
could attach to a pre-release process. Any gate or later release failure restores
the captured files, reloads systemd, restores the exact enabled/active timer
state, and carries any restoration failure into the final rollback verdict.

Once created, that file is the durable backup target. Later bootstraps preserve
it and fail on conflicting transient `CLIXOR_OCI_BACKUP_BUCKET` or
`CLIXOR_OCI_BACKUP_PREFIX` values, so an automated deploy cannot silently switch
to a default or different bucket. To migrate the backup target, use a reviewed
operator procedure that first proves bucket policy and restore access, then
updates the root-owned file explicitly.

- `clixor-offsite-backup.timer` checks for a locally generated dump no more than
  eight hours old and uploads every six hours. It uses only the VM instance
  principal. Both the checksum and dump are single-part, checksum-verified,
  `--no-overwrite` objects; rerunning the service safely confirms an existing
  pair instead of creating a new version.
- `clixor-backup-health.timer` checks hourly after its initial boot delay. It
  fails when the local or offsite success marker is older than eight hours, the
  latest local checksum fails, the previous upload or restore service failed,
  or the last successful isolated restore drill is older than 30 days.
- `clixor-restore-drill.timer` repeats the isolated restore verification weekly.
  It and the health timer remain disabled until `deploy.sh` has passed its first
  restore gate. Every deployment restarts the backup worker after migrations,
  proves that `LAST_SUCCESS` is newer than that gate start, uploads the resulting
  complete immutable pair, and restores it against the checked-out exact
  migration set before recording the release as current. A failure triggers the
  normal application rollback path; forward migrations are never auto-restored
  or reversed.

The Terraform instance policy permits only `OBJECT_CREATE`, `OBJECT_INSPECT`,
and `OBJECT_READ` in the named backup bucket. Read is required to download a
restore candidate. The VM still has no object overwrite, delete, version-delete,
retention-rule, or bucket-management permission. No OCI API key, Object Storage
customer secret key, database credential, or NAS dependency is used by these
host jobs.

Inspect the gates without printing any application secret:

```sh
sudo systemctl start clixor-offsite-backup.service
sudo systemctl status clixor-offsite-backup.service --no-pager
sudo systemctl start clixor-backup-health.service
systemctl list-timers 'clixor-*'
```

Every production deploy runs the drill synchronously against a newly generated
post-migration backup as a release gate. For an operator-requested drill, use
the same root-owned unit during a
low-traffic window after confirming at least four times the compressed dump
size plus 2 GiB is free on `/srv/clixor`:

```sh
sudo systemctl start clixor-restore-drill.service
sudo systemctl status clixor-restore-drill.service --no-pager
```

The drill lists the private bucket through the instance principal, selects the
newest fresh dump with a matching checksum object, downloads both to a unique
mode-0700 workspace under `/srv/clixor/restore-drills`, and validates the strict
one-line SHA-256 manifest. It starts the already-installed
digest-pinned `postgres:17.5-alpine` image with `--network none`, no published port, an
ephemeral random credential, a separate temporary data directory, read-only
root filesystem, dropped capabilities, and CPU/memory/PID limits. It then runs
`pg_restore --exit-on-error`, requires the exact checked-out migration set,
reads core tables, and runs `pg_amcheck`. An exit trap removes the container and
workspace on success, failure, or signal. It never loads the production runtime
environment, joins a production Docker network, mounts
`/srv/clixor/data/postgres`, restores into production, or runs a forward
migration.

The success marker records only timestamp, immutable object name, and migration
versions. Check failures with:

```sh
sudo journalctl -u clixor-offsite-backup.service \
  -u clixor-restore-drill.service -u clixor-backup-health.service
```

Object Storage capacity beyond the account's free allowance is billable, so
keep budget and lifecycle alerts active. This change deliberately creates no
retention lock: review and test a time-bound rule separately because an OCI
retention-rule lock is irreversible. Media retention and deletion recovery are
separate from the PostgreSQL backup policy.

## 8. Optional observability

Prometheus and Grafana are excluded from the default 2-OCPU workload. Enable them
only after observing headroom:

```sh
tag="$(docker inspect clixor-oci-api-a --format '{{.Config.Image}}' | cut -d: -f2-)"
sudo env CLIXOR_IMAGE_TAG="$tag" docker compose \
  --file /srv/clixor/repo/deploy/oci/compose.yaml \
  --profile observability up -d prometheus grafana
```

Grafana binds to `127.0.0.1:13000`; access it through an SSH local forward rather
than exposing it publicly. The default containers have bounded memory, PID, and
rotated JSON logs sized for 2 OCPUs/12 GB, but Docker limits are not capacity
proof. Monitor CPU steal, memory/OOM events, boot-volume latency and fullness,
PostgreSQL connections, Redis rejected writes, NATS storage, API latency, tunnel
health, and backup freshness before increasing traffic.
