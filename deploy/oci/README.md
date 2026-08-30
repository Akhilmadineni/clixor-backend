# Clixor on Oracle Cloud Always Free ARM64

This package runs the backend on one Ubuntu ARM64 OCI instance at
`/srv/clixor`. It is sized for `VM.Standard.A1.Flex` with 2 OCPUs and 12 GB RAM.
It is a safe beta topology, not a multi-host high-availability design.

Two small API processes sit behind an internal Nginx gateway. PostgreSQL,
Redis, and NATS are single-instance services with no published ports. The API
uses authenticated private-CA TLS for each dependency and accesses a private OCI
Object Storage media bucket with its instance principal. Only the API gateway
binds to host loopback; Cloudflare Tunnel is the sole HTTP ingress.

## Security and availability boundaries

- On the bundled private-subnet foundation, allow SSH only from the OCI Bastion
  private endpoint. Do not open 80, 443, 18180, 3000, 5432, 6379, or 4222 in
  the VCN security list, network security group, or Ubuntu firewall.
- Cloudflare Tunnel connects outbound only to `127.0.0.1:18180`.
- The two API replicas survive one API-process failure, but not VM, boot-volume,
  availability-domain, PostgreSQL, Redis, or NATS failure. OCI Object Storage is
  outside the VM failure domain but still depends on regional OCI availability.
- `/srv/clixor/backups` is on the same VM. It is useful for operator mistakes,
  but is not disaster recovery until copied to a versioned off-instance bucket.
- Secrets live only in root-owned runtime paths outside the repository. Never
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
`/srv/clixor/secrets/runtime.env` with random local credentials.

The first configuration is deliberately `CLUSTER_ENV=staging` with Telnyx and
APNs disabled. This does not relax the application's production checks. Changing
`CLUSTER_ENV` to `production` still requires complete TLS dependency, Telnyx,
APNs, native OCI media, metrics, and token configuration or the API refuses to
start.

Do not copy `production.env.example` over the generated runtime file. It is a
field-complete reference containing placeholders, not a secret generator.

## 3. Deploy an immutable source revision

From the source checkout:

```sh
revision="$(git rev-parse HEAD)"
sudo sh deploy/oci/deploy.sh "$PWD" "$revision" manual-1
```

The deploy script:

1. takes an exclusive host lock;
2. builds and verifies an ARM64 API image tagged with the source revision;
3. synchronizes that exact source to `/srv/clixor/repo`;
4. starts and health-checks the internal dependencies;
5. captures a mode-0600 pre-migration PostgreSQL dump;
6. runs the one-shot migration command;
7. starts both API replicas and the loopback gateway; and
8. requires gateway and per-replica readiness before recording success.

A failed application rollout restores the previous Compose model and API image
when one exists. Database migrations are forward-only and are never automatically
reversed. The very first deployment has no previous release to restore.

Check local state:

```sh
curl --fail http://127.0.0.1:18180/health/ready
sudo env CLIXOR_IMAGE_TAG="$(basename "$(readlink /srv/clixor/releases/current)")" \
  docker compose --file /srv/clixor/repo/deploy/oci/compose.yaml ps
```

The exact SHA argument is the deployment boundary. Deploying `main` does not
silently include features that exist only on another branch.

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

Install `cloudflared` from Cloudflare's signed package repository. Create a new,
locally managed tunnel for this VM; do not reuse a NAS connector connected to a
different database.

Copy `cloudflared-config.yml.example` to `/etc/cloudflared/config.yml`, substitute
the new tunnel UUID, and install the generated credentials JSON under
`/etc/cloudflared` as root with mode 0600. Route these names to the new tunnel:

- `clustr-api.atlanteanz.com` -> `http://127.0.0.1:18180`
- `clixor.atlanteanz.com` -> `http://127.0.0.1:18180`

Start and enable the `cloudflared` service, then verify four outbound tunnel
connections and test:

```sh
curl --fail https://clustr-api.atlanteanz.com/health/ready
curl --fail https://clixor.atlanteanz.com/privacy
curl --fail https://clixor.atlanteanz.com/terms
```

Never leave the old NAS and new OCI connectors serving the same hostnames against
different databases. That creates split-brain writes and inconsistent sessions.
Cloudflare must allow WebSockets. Media transfer URLs are short-lived,
object-specific OCI pre-authenticated requests returned by the API; media bytes
do not traverse Cloudflare Tunnel or this VM.

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

Use `sudoedit /srv/clixor/secrets/runtime.env` to add the Telnyx and Apple values
described in `production.env.example`. Use distinct random secrets. Before setting
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

`offsite-backup.sh` is intentionally staged but not scheduled. It uploads the
PostgreSQL copies to OCI Object Storage using the VM's instance-principal identity, so no
static cloud API key is stored on the VM or in this repository.

The instance policy permits create/inspect only in the backup bucket. Timestamped
objects are never overwritten, and the VM cannot delete either current objects or
older versions. Before treating the bucket as ransomware-resistant disaster
recovery, create and test a time-bound retention rule; lock it only after its
mandatory review period because an OCI retention-rule lock is irreversible.

Before enabling it:

1. confirm the Terraform-created private backup bucket exists;
2. enable object versioning and retention appropriate for recovery;
3. put this instance in a narrowly scoped OCI dynamic group;
4. grant that group object access only to the backup bucket;
5. verify the bootstrap-installed OCI CLI can use instance-principal
   authentication; and
6. run an isolated PostgreSQL restore test and a separate native-media lifecycle
   test.

Manual canary:

```sh
sudo env OCI_BACKUP_BUCKET=clixor-prod-backups \
  sh /srv/clixor/repo/deploy/oci/offsite-backup.sh
```

Only schedule that command after the canary and restore drill pass. Alert if
`OFFSITE_LAST_SUCCESS`, the PostgreSQL `LAST_SUCCESS`, disk usage, or certificate
expiry becomes stale. Object Storage capacity beyond the account's free allowance
is billable, so enforce budget alerts and retention. Media retention and deletion
recovery are separate from the PostgreSQL backup policy; test the application’s
intended permanent-deletion behavior before enabling bucket versioning.

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
