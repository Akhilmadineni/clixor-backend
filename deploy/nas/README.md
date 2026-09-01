# Clustr NAS deployment

> **Retired production target:** OCI is the active deployment target. The NAS
> package remains only as recovery reference. Its GitHub Actions deployment and
> Cloudflare-hostname mutation workflows have been removed; do not register or
> enable a NAS runner for this repository.

This historical deployment contract intentionally does not contain credentials
and will not start with placeholder values.

## NAS layout

```text
/volume1/docker/clustr/
├── repo/       application source used only to build a release image
├── data/       persistent service data
├── runtime/    generated deployment state
├── backups/    local backup staging (not the only backup copy)
└── secrets/    runtime.env and private keys; mode 0700
```

The API gateway, media gateway, and Grafana bind only to NAS loopback on ports
`18180`, `18181`, and `13000`. Two API replicas sit behind the API gateway on a
dedicated internal ingress network; PostgreSQL, Redis, NATS, and MinIO have no
published host ports. The gateway preserves Cloudflare's `CF-Connecting-IP`
header and the API trusts it only from the gateway's fixed internal address.
Dependencies use authenticated private-CA TLS across the internal
`clustr_internal` and `clustr_data` networks. Both HAProxy and the API gateway
use Docker's embedded DNS resolver so recreated containers are discovered.

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

## Cloudflare connector host limits

Install the checked-in connector capacity settings once on the NAS:

```bash
sudo install -o root -g root -m 0644 \
  deploy/nas/systemd/99-cloudflared-capacity.conf \
  /etc/sysctl.d/99-cloudflared-capacity.conf
sudo sysctl --system
sudo install -d -m 0755 /etc/systemd/system/cloudflared.service.d
sudo install -o root -g root -m 0644 \
  deploy/nas/systemd/cloudflared-limits.conf \
  /etc/systemd/system/cloudflared.service.d/capacity.conf
sudo systemctl daemon-reload
sudo systemctl restart cloudflared
```

Verify `ip_local_port_range` is `11000 60999`, the cloudflared open-file limit is
at least 70,000, and the tunnel returns to four active HA connections. The restart
briefly disconnects WebSockets; clients must reconnect and resume automatically.

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

## Deployment status

Automatic NAS deployment is retired. Main-branch CI has no self-hosted NAS job,
and the former workflow that changed the NAS Cloudflare Tunnel hostname is also
removed. If the old host recovers, keep `github-runner-clixor.service` stopped and
remove its GitHub runner registration so it cannot receive future repository jobs.

The commands above are break-glass reference only. Any deliberate rollback to
this topology requires a separate migration and DNS cutover plan; never operate it
against the OCI production database or tunnel hostnames at the same time.

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
- hostname: clixor.atlanteanz.com
  service: http://localhost:18180
- hostname: clustr-media.atlanteanz.com
  service: http://localhost:18181
```

No inbound router ports or Nginx Proxy Manager changes are required. The three
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

## Clixor legal pages

The API binary embeds the public Clixor Privacy Policy and Terms of Use so they
remain available without authentication or a separate database/service:

- `https://clixor.atlanteanz.com/`
- `https://clixor.atlanteanz.com/privacy`
- `https://clixor.atlanteanz.com/terms`

The branded privacy URL is suitable for App Store Connect. Legal-page requests
to the API hostname redirect permanently to the branded hostname; API and webhook
traffic continue using `clustr-api.atlanteanz.com` for client compatibility.

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
