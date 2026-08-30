# Clustr backend operations runbook

This runbook is the minimum operating contract for a production rollout. Replace
example hostnames, image names, secret stores, and paging destinations before use.

## Service objectives

- API availability: 99.95% per calendar month, excluding planned maintenance.
- Authenticated message acknowledgement: p95 under 250 ms and p99 under 750 ms.
- Durable message-to-realtime outbox lag: p99 under 2 seconds.
- Recovery point objective: 5 minutes for PostgreSQL and encrypted media metadata.
- Recovery time objective: 60 minutes for a regional restore.

Page when the five-minute error ratio exceeds 2%, readiness fails on more than one
replica, p99 message acknowledgement exceeds 2 seconds, outbox lag exceeds 10
seconds, or PostgreSQL replication/backup freshness exceeds the RPO. Alert without
paging on sustained rate limiting, a rise in
`clustr_push_delivery_failures_total`, any sustained dead-letter growth, prekey
depletion, or a single replica restart loop.

## Deployment

1. Build and scan one immutable image digest. Never deploy a mutable tag.
2. Snapshot PostgreSQL and confirm the latest continuous-archive restore point.
3. Run `/clustr-migrate` as the one-shot migration job and require success.
4. Roll out one canary API replica. Verify readiness, auth, message replay,
   WebSocket delivery, outbox lag, and media upload/download.
5. Roll out remaining replicas with zero unavailable capacity.
6. Observe error rate, database locks, connection pools, Redis latency, NATS
   reconnects, and outbox lag for at least 30 minutes.

Application rollback uses the previous immutable image. Schema changes are
forward-compatible and forward-only; a destructive schema rollback requires a
tested database restore and an incident declaration.

Migration 9 adds the durable APNs delivery queue without constraining the existing
`devices.push_token` column. This is deliberate: production-05b replicas can keep
serving device updates throughout the rolling deployment. The new store serializes
token transfers with an advisory lock. Deduplication and a database uniqueness
constraint require coordinated migration 12 after all 05b replicas are drained;
do not rewrite already-applied migration 9.

Migration 10 adds bounded media reservations, stored-media quota indexes, pending
expiry, verification leases, and delayed object-deletion scheduling. Migration 11
adds the published-outbox retention index. Migration 14 persists upload-capability
identity and makes legacy account deletion cover both OCI staging and immutable
published keys; 12 and 13 remain reserved for mail and push work. Apply every
available migration in numeric order before rolling out this binary. Never publish
a different migration body under an already-applied version.
The migration's ready-row constraint prevents a production-05b replica from
publishing a capability-bearing upload without revocation. Drain old replicas
before promotion so newly created and legacy in-flight OCI uploads complete on
the immutable-publication code path; old rows with no capability remain readable.

`clustr_messaging_transition_messages_total` counts accepted messages from the
installed production-05b codec. Those payloads are base64-encoded JSON,
plaintext-equivalent at the server, and not E2EE. Track the counter by release;
remove the strict one-field compatibility envelope only after upgraded-client
adoption is verified and a coordinated minimum-version policy is active.

Outbound reset email fails closed while `CLUSTER_MAIL_PROVIDER=disabled`.
The OCI deployment uses an authenticated SMTP submission service over mandatory
STARTTLS; it never sends credentials or reset codes to a plaintext relay. Enable
SMTP only after the approved sender, SPF, DKIM, DMARC, provider suppression
handling, and real-mailbox delivery canaries pass. A successful SMTP handshake
alone does not prove Internet delivery.
SMTP is intentionally not a core `/health/ready` dependency: an email outage must
not eject both API replicas from service. Monitor reset queue failures separately;
activation requires the explicit real-mailbox canary below, and a failed enqueue
causes the just-created challenge to be canceled.

## APNs delivery operations

- `clustr_push_deliveries_total{result="retry_scheduled"}` records durable
  retries; `result="dead_letter"` records jobs that exhausted the configured
  budget or received a permanent APNs rejection.
- `clustr_push_delivery_failures_total{class=...}` uses bounded, token-free
  classes. No device token or provider response body is logged or used as a
  metric label.
- Delivered/invalid/canceled rows are retained for 24 hours by default;
  dead-letter rows are retained for 30 days. Each hourly transaction deletes at
  most 1,000 terminal rows and only after the source realtime outbox event is
  acknowledged; an extended NATS outage therefore cannot erase APNs idempotency
  state and resend old pushes.
- After terminal push rows are pruned, published source outbox rows become
  eligible only when they are older than the longer configured push-retention
  window (30 days by default) and have no remaining `push_deliveries` references.
  The source prune is also capped at 1,000 rows per transaction and uses
  `SKIP LOCKED`, so replicas can make progress without a large blocking delete.
- `clustr_push_deliveries_total{result="pruned"}` and
  `clustr_outbox_events_total{result="pruned"}` count deleted retention rows.
  The corresponding `result="prune_failed"` series count failed hourly attempts;
  alert on sustained failures or unexpected absence of pruning while table sizes
  grow.
- Realtime outbox publication and APNs delivery run in separate loops. Each API
  replica claims at most the configured worker concurrency (16 by default) and
  sends that cohort in parallel, keeping the two-minute database lease ahead of
  the APNs client's bounded request timeout.
- Inspect a suspected backlog with a read-only count grouped by `status` and
  `last_error_class` in `push_deliveries`. Never export notification bodies or
  join device tokens into incident tickets.
- Before replaying dead letters, repair and canary the underlying APNs key,
  topic, payload, or network fault. Replay only the affected bounded cohort by
  changing it back to `pending`, clearing its lease/dead-letter timestamp, and
  setting `next_attempt_at=now()` in an audited transaction. Leave `attempts`
  intact unless incident command explicitly approves a fresh retry budget.
- An `invalid_token` outcome atomically clears only the exact token rejected by
  APNs. A token rotated while a delivery was in flight remains registered.

## Backups and restore

- PostgreSQL: encrypted daily base backup plus continuous WAL archiving to a
  separate account/region. Retain 35 days and test point-in-time recovery monthly.
- OCI Object Storage media: encryption at rest, versioning, lifecycle policy,
  and a tested cross-region recovery plan. Treat payloads as plaintext-sensitive
  until audited client-side encryption is deployed; PARs and metadata are always
  sensitive.
- Alert on `clustr_media_pending_cleanup_total{result="failed"}` and sustained
  media quota/rate-limit rejections. Confirm OCI lifecycle rules abort incomplete
  multipart uploads, stored-object limits match the product plan, the configured
  conversation ceiling remains 1 GiB while production-05b is supported, and a
  missing `opc-content-sha256` can never transition an object to ready.
- Alert on completion failures during PAR revocation or conditional rename. A
  ready OCI row must reference `published/`; investigate pending rows with a
  persisted capability older than their expiry and verify staging cleanup outbox
  work is draining before retrying promotion.
- Redis presence/rate limits and NATS realtime fan-out are rebuildable. PostgreSQL
  messages plus the transactional outbox are the recovery source of truth.
- Export backup success and restore-point age as monitored metrics.

A restore drill is successful only after membership counts, per-conversation
message sequences, receipt watermarks, entity versions, media metadata, and a
sample of stored-payload hashes match the source environment.

## Secret and key rotation

- Store PostgreSQL, Redis, NATS, S3, Telnyx, OTP HMAC, APNs, JWT, and metrics credentials in
  a managed secret store; never commit or place them in ConfigMaps.
- Rotate infrastructure credentials at least every 90 days and immediately after
  suspected exposure.
- JWT signing-key rotation needs an overlapping key ring before public launch; the
  current single HMAC secret cannot rotate without invalidating access tokens.
- Revoke and replace the Gemini key found in this repository's Git history before
  enabling AI features. Gemini calls must be proxied by an authenticated backend.
- Device identity-key changes require a client-visible safety-number/key-change
  workflow and security audit before claiming end-to-end encryption.

## Incident priorities

1. Stop data corruption or unauthorized access; disable writes or isolate a cohort
   if necessary.
2. Preserve database, audit, ingress, and application logs with synchronized time.
3. Identify the first bad message sequence/entity version and affected accounts.
4. Recover using sequence replay, idempotency keys, and the transactional outbox;
   do not manufacture or decrypt message payloads server-side.
5. Communicate scope and remediation, rotate exposed credentials, and complete a
   blameless post-incident review with tracked corrective actions.

## Required launch exercises

- PostgreSQL primary loss and point-in-time restore.
- Redis loss during login and normal authenticated traffic.
- NATS outage/reconnect with outbox replay and duplicate-event client handling.
- APNs outage and invalid-device-token handling.
- Telnyx outage, invalid sender registration, signed-webhook replay, OTP lockout,
  destination spray, and daily SMS cost-cap handling.
- Reconnect storm, hot 1024-member group, media quota, and one-time-prekey
  depletion load tests.
- Concurrent pending-media quota races across both API replicas, expired upload
  cleanup, invalid checksum/content-type rejection, and conversation deletion
  while MinIO is unavailable (the outbox must retry without losing object keys).
- External penetration test, abuse review, privacy review, and client cryptography
  audit.
