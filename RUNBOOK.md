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
paging on sustained rate limiting, push failures, prekey depletion, or a single
replica restart loop.

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

## Backups and restore

- PostgreSQL: encrypted daily base backup plus continuous WAL archiving to a
  separate account/region. Retain 35 days and test point-in-time recovery monthly.
- S3 media: encryption at rest, versioning, lifecycle policy, and cross-region
  replication. Treat payloads as plaintext-sensitive until audited client-side
  encryption is deployed; storage credentials and metadata are always sensitive.
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
- External penetration test, abuse review, privacy review, and client cryptography
  audit.
