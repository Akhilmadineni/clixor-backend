# Clustr NAS deployment

This is the production API deployment contract for the NAS. It intentionally does
not contain credentials and will not start with placeholder values.

## NAS layout

```text
/volume1/docker/clustr/
├── repo/       application source used only to build a release image
├── data/       persistent service data
├── runtime/    generated deployment state
├── backups/    local backup staging (not the only backup copy)
└── secrets/    runtime.env and private keys; mode 0700
```

The API, media gateway, and Grafana bind only to NAS loopback on ports `18180`,
`18181`, and `13000`. PostgreSQL, Redis, NATS, and MinIO have no published host
ports. Dependencies use authenticated private-CA TLS across the internal
`clustr_internal` and `clustr_data` networks. The HAProxy bridge uses Docker's
embedded DNS resolver so a recreated Redis or MinIO container does not require a
bridge restart.

## UGOS boot ordering

UGOS mounts `/volume1` asynchronously, while Docker uses `/volume1/@docker` as its
data root. Install the included systemd drop-in once so Docker waits for the UGOS
storage manager's notify-ready event:

```bash
sudo install -d -m 0755 /etc/systemd/system/docker.service.d
sudo install -o root -g root -m 0644 \
  deploy/nas/systemd/docker-volume-ordering.conf \
  /etc/systemd/system/docker.service.d/ugreen-volume.conf
sudo systemctl daemon-reload
systemctl show docker.service -p After -p Requires
```

The final command must show `storage_serv.service` in both properties. This avoids
the boot race where Docker exhausts its restart limit before `/volume1` mounts.

## Build and deploy

Run from `/volume1/docker/clustr/repo`:

```bash
release_tag="nas-$(find . -type f -not -path './.git/*' -print0 | sort -z |
  xargs -0 sha256sum | sha256sum | cut -c1-12)"
sudo deploy/nas/bootstrap.sh
sudo docker build --pull --tag "clustr-api:${release_tag}" .
sudo docker image inspect "clustr-api:${release_tag}" --format '{{.Id}}'

sudo env CLUSTER_IMAGE_TAG="${release_tag}" docker compose \
  --file deploy/nas/compose.yaml \
  --profile migration run --rm migrate

sudo env CLUSTER_IMAGE_TAG="${release_tag}" docker compose \
  --file deploy/nas/compose.yaml up --detach

curl --fail http://127.0.0.1:18180/health/ready
```

## Automatic deployment

`.github/workflows/deploy-nas.yml` runs only after `CI` succeeds
for `main`. It targets a repository-scoped
NAS runner labelled `self-hosted`, `nas`, and `clixor`. GitHub supplies only a
short-lived checkout token; all application credentials remain in
`/volume1/docker/clustr/secrets` and are never copied into Actions secrets.

The host script builds immutable revision-labelled API and bootstrap images before
rollout, serializes deployments with GitHub concurrency and a NAS file lock,
refreshes root-owned runtime files in a capability-limited local container, and
captures a mode-0600 PostgreSQL custom-format snapshot before migration. Local
readiness gates success; a failed rollout restores the previous API image and
Compose model. Database migrations are intentionally forward-only and must remain
compatible with the previous API release; restoring a database dump is a separate,
operator-approved disaster-recovery action, never an automatic rollback.

The final workflow step verifies the public Cloudflare route independently. Keep
the dedicated runner registered only to this repository and do not reuse the
TradingBot or VerifyCore runner credentials.

For Portainer, create a stack named `clustr` from `compose.yaml`, define
`CLUSTER_IMAGE_TAG` as the already-built release tag, and keep the external network
names unchanged. The migration service is a one-shot release step, not a
long-running container.

## Public ingress

Use `https://clustr-api.atlanteanz.com` for the app. The preferred NAS ingress is a
Cloudflare Tunnel with these rules before its final `http_status:404` catch-all:

```yaml
- hostname: clustr-api.atlanteanz.com
  service: http://localhost:18180
- hostname: clustr-media.atlanteanz.com
  service: http://localhost:18181
```

No inbound router ports or Nginx Proxy Manager changes are required. The two
one-level hostnames are covered by the zone's standard wildcard edge certificate.
Do not replace them with nested names such as `api.clustr.atlanteanz.com` unless a
dedicated nested-host certificate is provisioned.

Cloudflare must allow WebSockets. The API sends WebSocket control pings every 25
seconds, and the Swift client converts the HTTPS API URL to WSS automatically.

Run the public smoke test after every release:

```bash
python3 deploy/nas/smoke.py \
  --base-url https://clustr-api.atlanteanz.com \
  --expected-media-host clustr-media.atlanteanz.com
```

The test creates uniquely prefixed accounts and data. Remove only that reported
prefix and its associated object-store keys after validation.

## Release gates

Before public traffic:

1. Keep phone verification disabled until the Telnyx sender registration is
   approved, the sender is assigned to its messaging profile, the API/signing
   credentials and independent OTP HMAC secret are installed, and a real-device
   delivery/verification canary passes. See `PHONE_VERIFICATION_PLAN.md`.
2. Install a production APNs signing key before enabling push delivery.
3. Replicate PostgreSQL dumps and MinIO data to an independent encrypted backup
   destination; a backup on the same NAS is not a complete disaster-recovery plan.
4. Run a full Xcode/iOS SDK build and device test.
5. Complete load, abuse, privacy, client-cryptography, and external security reviews.
