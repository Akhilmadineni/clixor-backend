# Clixor on Oracle Cloud Always Free ARM64

This package runs the backend on one Ubuntu ARM64 OCI instance at
`/srv/clixor`. It is sized for `VM.Standard.A1.Flex` with 2 OCPUs and 12 GB RAM.
It is a safe beta topology, not a multi-host high-availability design.

Two small API processes sit behind an internal Nginx gateway. PostgreSQL,
Redis, and NATS are single-instance services with no published ports. The API
uses authenticated private-CA TLS for each dependency and accesses a private OCI
Object Storage media bucket with its instance principal. The API gateway has a
fixed address on an internal Docker bridge; Cloudflare Tunnel is the sole HTTP
ingress and reaches that bridge from the host.

## Security and availability boundaries

- On the bundled private-subnet foundation, allow SSH only from the OCI Bastion
  private endpoint. Do not open 80, 443, 8080, 3000, 5432, 6379, or 4222 in
  the VCN security list, network security group, or Ubuntu firewall.
- Host `cloudflared` connects only to the internal gateway at
  `172.30.254.2:8080`; the gateway has no egress network or published host port.
- The two API replicas survive one API-process failure, but not VM, boot-volume,
  availability-domain, PostgreSQL, Redis, or NATS failure. OCI Object Storage is
  outside the VM failure domain but still depends on regional OCI availability.
- `/srv/clixor/backups` is only local staging. A root-owned timer copies verified
  dumps to the private, versioned Object Storage backup bucket; that still does
  not make the single-VM database highly available.
- Secrets live only in root-owned, per-service environment files outside the
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
its Compose plugin, and OCI CLI 3.91.0 through a checksum-pinned official installer; creates the
data/runtime tree; resolves Object Storage namespace/region through the instance
principal and OCI metadata; generates an internal CA; and creates
root-owned scoped files under `/srv/clixor/secrets` with random local
credentials. `runtime.env` is retained only as a non-consumed migration
checkpoint for unknown legacy entries.

On an existing VM, bootstrap performs a one-time safe upgrade from the former
all-service `runtime.env`: it rejects symbolic links and duplicate assignments,
copies exact values without evaluating or printing them, validates every scoped
allowlist, publishes mode-0600 files atomically, and removes scoped assignments
from the legacy file only after every new file is ready. Rerunning it is
idempotent. During this Compose boundary only, application rollback uses the new
scoped model with the prior API image so provider credentials are not re-exposed
to data containers. Existing data, backup, and Grafana containers whose immutable
Docker configuration still contains legacy `CLUSTER_*` values are force-replaced
once (a stopped Grafana container is removed); persistent data volumes are not
deleted.

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

## 3. Deploy an immutable source revision

From the source checkout:

```sh
revision="$(git rev-parse HEAD)"
sudo sh deploy/oci/deploy.sh "$PWD" "$revision" manual-20260830T120000Z
```

Use a new non-secret run identifier for every attempt. Release directories are
append-only audit records, so the script refuses to overwrite an earlier run.

The deploy script:

1. takes an exclusive host lock;
2. for an upgrade, captures the previous Compose model, API image, release
   pointer, and a mode-0600 PostgreSQL custom dump that passes `pg_restore
   --list` and SHA-256 verification before changing the active runtime; a clean
   first deployment records an explicit first-deploy marker;
3. builds and verifies an ARM64 API image tagged with the source revision;
4. arms application rollback before refreshing runtime configuration,
   synchronizing source, or reconciling containers;
5. refreshes the independent dependency TLS leaves, synchronizes that exact
   source to `/srv/clixor/repo`, and restarts only dependencies that need a new
   image, scoped secret boundary, or certificate before health-checking them;
6. runs the one-shot migration command;
7. starts both API replicas and the internal gateway;
8. requires gateway and per-replica readiness;
9. creates and uploads a fresh post-migration backup, restores it into an
   isolated PostgreSQL container, and runs integrity checks; and
10. records the dependency PKI state and atomically advances the current-release
    pointer before disarming rollback.

A failed upgrade restores the previous Compose model and API image when one
exists. A failed first deployment stops the incomplete Compose stack without
deleting its bind-mounted data and removes only the copied active Compose marker
so a clean retry is possible. Database migrations are forward-only: neither
path automatically runs `pg_restore`, reverses migrations, or deletes database
files. The pre-change dump is an operator recovery artifact, not an automatic
rollback mechanism.

The first digest-pinned and per-service-PKI rollout intentionally recreates
PostgreSQL, Redis, NATS, and HAProxy once. Schedule that transition in a
maintenance window because the single-node A1 topology has no redundant
database/cache/event-bus instance. Later releases restart only services whose
reviewed image, configuration, scoped-secret boundary, or leaf certificate
changed.

Check local state:

```sh
curl --fail http://172.30.254.2:8080/health/ready
sudo env CLIXOR_IMAGE_TAG="$(basename "$(readlink /srv/clixor/releases/current)")" \
  docker compose --file /srv/clixor/repo/deploy/oci/compose.yaml ps
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
`main`, checks out that exact approved SHA, serializes production deployments, and
uses the same snapshot, migration, readiness, and application-rollback path as a
manual deployment. No OCI or application credential belongs in GitHub Actions.
The root-owned entrypoint additionally refuses automated deployment unless the
scoped API configuration is mode `0600`, root-owned, and explicitly enables
production, Telnyx verification, and durable SMTP reset delivery. Manual staging
deployments remain available for provider canaries before this gate is enabled.

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
sudo install -o root -g root -m 0755 \
  /home/ubuntu/clixor-backend/deploy/oci/actions-deploy.sh \
  /usr/local/sbin/clixor-actions-deploy
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
OCI runner offline until all scoped files under `/srv/clixor/secrets`, native OCI media,
backups, and the Cloudflare tunnel have passed their manual release gates. If the
runner installation path, repository name, or work-directory name changes, update
and reinstall the root-owned validation entrypoint before enabling it.

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

## 4. Move Cloudflare ingress

Install cloudflared **2025.4.0 or newer** from Cloudflare's signed package
repository; `--token-file` is unavailable in older releases and the installer
rejects them. Create a new, remotely managed tunnel for this VM; do not reuse a
NAS connector connected to a different database. Configure these public
hostname routes on that tunnel:

- `clustr-api.atlanteanz.com` -> `http://172.30.254.2:8080`
- `clixor.atlanteanz.com` -> `http://172.30.254.2:8080`

Download the tunnel token into a temporary protected file without printing it or
putting it in shell history, then install it and the hardened connector unit:

```sh
sudo install -d -o root -g root -m 0700 /etc/cloudflared
sudo install -o root -g root -m 0600 /secure/input/clixor-cloudflare-token \
  /etc/cloudflared/token
sudo sh deploy/oci/install-cloudflared-service.sh \
  "$PWD/deploy/oci/cloudflared.service"
sudo systemctl status --no-pager cloudflared.service
```

The token stays root-owned at mode `0600`; systemd exposes it to the dynamic
connector identity only through `LoadCredential`. Do not place it in
`runtime.env`, a cloud-init payload, GitHub Actions, or the `cloudflared` command
line. The unit uses Cloudflare's `auto` transport so it prefers QUIC and can fall
back to HTTP/2 if UDP is unavailable. Verify four outbound tunnel connections
and test:

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
distinct reset HMAC, and padded-base64 32-byte queue key only in
`/srv/clixor/secrets/api.env`. Keep `CLUSTER_MAIL_PROVIDER=disabled` until SPF,
DKIM, DMARC, suppression handling, and real-mailbox reset/change canaries pass;
the reset endpoints then return 503 instead of offering an unsafe shortcut.

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

## 5. Provider credentials and production promotion

Keep the first deployment in staging while authentication, group, media,
WebSocket, and account-deletion tests run. To add APNs, install the private key
without displaying it:

```sh
sudo install -o root -g 65532 -m 0440 /secure/input/AuthKey.p8 \
  /srv/clixor/secrets/apns/AuthKey.p8
sudo sh deploy/oci/bootstrap.sh
```

UID/GID 65532 is the distroless API identity. Bootstrap keeps the APNs directory
traversable only by root and that identity and fixes every `.p8` key to
`root:65532` mode `0440`.

Use `sudoedit /srv/clixor/secrets/api.env` to add the Telnyx, Apple, and mail
values described in `api.env.example`. The database/cache/bus/backup/Grafana
examples are separate and must stay separate. Use distinct random secrets. Before setting
`CLUSTER_ENV=production`, complete all of these:

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

## 6. Backups

The default stack performs a six-hourly custom-format PostgreSQL dump with a
SHA-256 checksum and seven-day local retention. OCI Object Storage is already the
primary media store and is not copied into the VM backup directory.

Bootstrap installs root-owned backup programs in `/usr/local/libexec/clixor`, a
mode-0600 non-secret bucket/prefix file at `/etc/clixor/offsite-backup.env`, and
three hardened timer pairs:

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

## 7. Optional observability

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
