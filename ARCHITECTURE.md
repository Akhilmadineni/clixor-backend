# Clustr backend architecture

## Service boundary

The first production deployment is a modular monolith with explicit storage, event,
media, verification, and push interfaces. This keeps transactions simple while
allowing the realtime gateway, media service, and notification worker to be split
into independent services when traffic requires it.

The API is stateless. Durable state lives in PostgreSQL, transient rate-limit and
presence state lives in Redis, realtime fan-out uses NATS, and encrypted media
lives in private S3-compatible object storage.

Phone verification is a Clustr-owned service: cryptographically random OTPs are
HMACed with an independent secret and stored only in Redis with short TTLs. Atomic
scripts enforce cooldowns, send budgets, guess limits, lockout, and single use
across API replicas. Telnyx only transports SMS; signed delivery callbacks feed
low-cardinality operational metrics. Raw phone numbers and codes are excluded from
Redis keys, durable storage, metrics, and logs.

## Messaging guarantees

- Each conversation has a monotonically increasing server sequence.
- `(conversation_id, sender_id, client_message_id)` makes retries idempotent.
- Clients replay from `after_seq` after reconnecting.
- Delivery and read watermarks are monotonic.
- A transactional outbox prevents committed messages from being lost between
  PostgreSQL and the event/push pipeline.
- WebSocket events are at-least-once; clients deduplicate by event/message ID.
- Eligible APNs deliveries are materialized idempotently per outbox event and
  device before realtime publication. APNs failures therefore retry from a
  separate durable queue without republishing the realtime event. Exponential
  backoff is bounded; exhausted and permanent failures enter a retained dead
  letter state, while invalid/unregistered tokens are removed transactionally.
- A nonempty APNs token has exactly one device owner. Registration transfers
  token ownership atomically across accounts, and delivery resolves the current
  token from that authenticated device instead of persisting a stale token copy.
- Published outbox rows are transport replay state, not an unbounded audit log.
  Hourly bounded retention removes terminal per-device rows first, then removes
  source rows older than the longest push retention window only when no delivery
  still references them. Partial indexes and `SKIP LOCKED` keep concurrent
  retention scans bounded across API replicas.
- The API and database are designed to treat message bodies and media as opaque
  ciphertext and never require server-side decryption.
- The current Swift transition codec base64-encodes JSON message data and uploads
  raw media bytes. Until audited client cryptography replaces that codec, the
  deployed system does receive plaintext-equivalent content and is not E2EE.
- The compatibility API accepts that codec only with the exact one-field
  `{protocol: clustr-transition-v1}` envelope. It does not apply the E2EE device
  identity or recipient checks because production 05b never published those
  keys. `clustr_messaging_transition_messages_total` measures remaining use; do
  not remove the compatibility path until upgraded-client adoption is verified.
- APNs acceptance and final user presentation are not exactly-once guarantees.
  A worker crash after APNs accepts a request but before PostgreSQL records the
  acknowledgement can resend the same collapse/notification ID.

## End-to-end encryption boundary

Devices publish identity keys, signed prekeys, and one-time prekeys. The server
atomically claims one-time prekeys but does not perform session cryptography.
Clients should use an audited Signal-compatible implementation covering
asynchronous key agreement, ratcheting, skipped-message keys, multi-device session
management, key verification, and secure deletion.

Do not implement a custom Double Ratchet from this repository's server code. A
cryptography review and cross-device protocol test suite are release gates.

## Data layout

Message rows are hash-partitioned by conversation ID. The partition count is an
initial operational choice, not a claim of WhatsApp-scale capacity. At very high
volume, conversations can be sharded by a stable conversation hash while user and
conversation metadata remain in a directory service.

Clustr product data—expenses, tasks, files, chores, settlements, trip plans, and
settings—uses versioned conversation entities. This gives mobile clients one
incremental sync protocol while preserving per-entity authorization.

## Production gates

Before public launch:

1. Add audited client E2EE and encrypted backup recovery.
2. Run PostgreSQL/NATS/Redis failure and restore drills.
3. Add OpenTelemetry traces and SLO-based alerts.
4. Load-test reconnect storms, hot groups, large fan-out, and media uploads.
5. Add abuse prevention, block/report workflows, account recovery, and moderation
   of public metadata.
6. Complete an external penetration test and cryptography review.
7. Preserve and verify any required legacy export before the remote Firebase
   project is decommissioned.
