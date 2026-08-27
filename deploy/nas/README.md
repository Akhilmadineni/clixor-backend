# Clustr NAS deployment

This is the production API deployment contract for the NAS. It intentionally does
not contain credentials and will not start with placeholder values.

## NAS layout

```text
/volume1/docker/clustr/
├── repo/       application source used only to build a release image
├── data/       persistent service data, including the outbound mail queue
├── runtime/    generated deployment state and public DKIM DNS value
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

The release includes a send-only Postfix/OpenDKIM queue on the isolated
`clustr_mail` network, but outbound email is disabled by default and the mail
service stays stopped. After its external delivery gates pass, an operator can
set `CLUSTER_MAIL_PROVIDER=smtp`; the deploy script then activates the `mail`
Compose profile. SMTP has no host port, relays only for the two fixed API
addresses, signs outbound mail with a root-owned DKIM key, and retains deferred
messages under `data/mail-queue`. This is fully NAS-hosted outbound mail; it is
not SES and does not expose a general-purpose email API.

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

The manual command above keeps the optional mail profile stopped. After mail is
explicitly enabled in `secrets/runtime.env`, add `--profile mail` to each Compose
invocation. Automatic deployment selects the profile from that explicit setting.

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

The final workflow step verifies the public Cloudflare route independently. The
repository-scoped runner is installed as `atlanteans-nas-clixor` in
`/volume1/docker/github-runner-clixor` and runs under the enabled
`github-runner-clixor.service` systemd unit. Keep it registered only to this
repository and do not reuse the TradingBot or VerifyCore runner credentials.

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

The `clixor.atlanteanz.com` origin also serves the iOS universal-link association
document directly (without redirects) at both Apple-supported paths:

- `/.well-known/apple-app-site-association`
- `/apple-app-site-association`

Only the exact `/join` path is associated with the production app identifier
`H9S3BAQ9U8.com.Clustr.Clustr.Clustr`. Share invites in this form:

```text
https://clixor.atlanteanz.com/join#cinv_<token>
```

The invite bearer token must remain in the URL fragment. Fragments are handled
locally by the browser/app and are not sent to Cloudflare, the tunnel, Nginx, or
the API. Never move the token into the path or query string. Browsers that do not
open the app receive a static, generic `/join` page that does not inspect or
reflect invite data. After the app extracts the fragment, it submits the bearer
only in the JSON body of the fixed `POST /v1/invites/preview` or
`POST /v1/invites/accept` endpoint; bearer values must never appear in API paths.

Run the public smoke test after every release:

```bash
python3 deploy/nas/smoke.py \
  --base-url https://clustr-api.atlanteanz.com \
  --expected-media-host clustr-media.atlanteanz.com
```

The test creates uniquely prefixed accounts and data. Remove only that reported
prefix and its associated object-store keys after validation.

## Outbound email DNS and reputation

Bootstrap creates the DKIM private key once under `secrets/mail`, writes only its
publishable TXT record to `runtime/mail/dkim-dns.txt`, and leaves
`CLUSTER_MAIL_PROVIDER=disabled`. Never copy the private key into DNS, GitHub
Actions, or the repository. Before enabling password-reset delivery, configure:

1. ISP reverse DNS: `52.124.33.145` must resolve to `mail.atlanteanz.com`.
2. Cloudflare DNS-only A record: `mail.atlanteanz.com` -> `52.124.33.145`.
3. Apex SPF TXT: `v=spf1 ip4:52.124.33.145 -all`.
4. DKIM TXT: publish the exact record from `runtime/mail/dkim-dns.txt`.
5. Initial DMARC TXT at `_dmarc.atlanteanz.com`: `v=DMARC1; p=none; adkim=s; aspf=s`.

Cloudflare Tunnel/proxy does not carry SMTP. The mail container connects directly
outbound on TCP 25; no inbound SMTP or router port-forward is required. Validate
forward/reverse DNS, SPF, DKIM, TLS, queue retry behavior, and delivery to a real
mailbox before calling reset email production-ready. If the ISP cannot delegate
matching PTR or later blocks TCP 25, a reputable SMTP relay is required; software
alone cannot repair receiver reputation policy.

Only after those checks and a real-mailbox delivery canary pass, change the
root-owned `secrets/runtime.env` value to `CLUSTER_MAIL_PROVIDER=smtp` and run a
normal deployment. Revert it to `disabled` to make reset endpoints return 503 and
stop the optional mail profile on the next deployment.

The optional SMTP queue is not part of API `/health/ready`; mail trouble must not
remove otherwise healthy API replicas from load balancing. Treat reset-send error
logs, queue health, and the real-mailbox canary as separate activation/operations
signals. A failed enqueue cancels its challenge so no undelivered code is usable.

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
2. Install a production APNs signing key before enabling push delivery. Apply
   migration 9 first, then verify durable queue metrics, bounded terminal/source
   pruning, one forced transient retry, and production-to-sandbox fallback on
   real devices. Migration 9 deliberately leaves push-token uniqueness to the
   application during the production-05b rolling window. Reserve migration 10
   for media reservations and add the outbox retention index as migration 11 in
   the later coordinated release. Add the push-token database constraint as
   migration 12 after old replicas are drained; never rewrite migration 9.
3. Replicate PostgreSQL dumps and MinIO data to an independent encrypted backup
   destination; a backup on the same NAS is not a complete disaster-recovery plan.
4. Run a full Xcode/iOS SDK build and device test.
5. Complete load, abuse, privacy, client-cryptography, and external security reviews.
