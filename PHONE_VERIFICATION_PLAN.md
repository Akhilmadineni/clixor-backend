# Production phone verification plan

Last updated: 2026-08-30 (America/Chicago)

This is the durable, secret-free checkpoint for replacing Twilio Verify with a
Clixor-owned OTP service on the private OCI production VM and Telnyx SMS
delivery. The former Atlanteans NAS deployment is retired.

## Architecture

`iOS -> Cloudflare edge/Tunnel -> OCI Clixor API -> Redis OTP/fraud engine -> Telnyx SMS`

- The existing `/v1/auth/phone/start` and `/v1/auth/phone/verify` contracts stay
  stable, so the Swift application does not need a provider-specific SDK.
- Codes are generated with `crypto/rand`, HMACed with a dedicated production
  secret, and held only in Redis with short TTLs. Plaintext codes must never be
  stored in PostgreSQL, Redis, metrics, or application logs.
- Atomic Redis scripts enforce resend cooldown, per-destination and global send
  budgets, attempt limits, lockout, single-use verification, and challenge
  replacement across every API replica.
- Telnyx is isolated behind an SMS sender interface. Provider errors never expose
  credentials, message contents, or destination numbers.
- Signed Telnyx delivery webhooks are verified with Ed25519 and a five-minute
  replay window before status metrics are accepted.

## Default fraud policy

- Six numeric digits; ten-minute lifetime.
- Sixty-second resend cooldown.
- Five guesses per challenge, followed by a fifteen-minute destination lockout.
- Five sends per destination per hour and ten per destination per day.
- Sixty sends globally per minute and ten thousand globally per day.
- Existing API source throttling remains an additional independent control.

All thresholds are explicit environment settings. Raising them requires an
operational review because the global limits are also cost-containment controls.

## Production prerequisites outside the repository

1. Create a Telnyx account and a least-privilege API key.
2. Buy an SMS-capable sender number and assign it to a messaging profile.
3. Complete the appropriate sender registration before off-net traffic. U.S.
   local-number A2P traffic requires an approved 10DLC brand/campaign and the
   number assigned to that active campaign.
4. Configure the messaging webhook as
   `https://clustr-api.atlanteanz.com/v1/webhooks/telnyx/messaging`.
5. Install the API key, sender number, Telnyx public signing key, and a new
   independent OTP HMAC secret in the OCI root-only
   `/srv/clixor/secrets/api.env`. Never commit populated values. The retained
   `runtime.env` is only a non-consumed migration checkpoint and must not contain
   `CLUSTER_*` credentials.
6. Deploy an immutable API image, verify readiness, run a real-device delivery
   canary, and monitor send/verify/delivery outcome metrics before enabling the
   phone-auth UI for all users.

## Rollout gates

- [x] Backend implementation and automated tests pass.
- [x] OCI secret template and deployment runbook are updated.
- [ ] Telnyx account, sender registration, balance alerts, and webhook exist.
- [ ] Staging real-device start/verify/replay/lockout tests pass.
- [ ] Delivery-rate and spend alerts are configured.
- [ ] Production provider is enabled only after the previous gates pass.

## Implementation checkpoint (2026-08-06)

- Implemented provider-neutral SMS transport and Telnyx Messaging API adapter.
- Implemented atomic Redis issue/check/rollback/delivery scripts with HMAC-only
  destination/code identifiers, independent limits, single use, and lockout.
- Added Ed25519 webhook verification, five-minute replay rejection, event
  deduplication, delivery status metrics, readiness checks, safe provider errors,
  and explicit production configuration validation.
- Replaced Twilio configuration in Compose, Kubernetes examples, OCI production
  references, secret templates, OpenAPI, architecture, and runbooks. The retired
  NAS package is not a production deployment path.
- Go formatting, full unit suite, full race-detector suite against Redis 8.0.3,
  vet, static builds, and `govulncheck` passed at the implementation checkpoint.
  Earlier public-endpoint validation occurred during the NAS phase; OCI requires
  a new real-device start/verify/replay/lockout canary before enabling Telnyx.
- A local API smoke run passed `/v1/auth/phone/start` and single-device token
  issuance through `/v1/auth/phone/verify` without logging the phone or code.
- No PostgreSQL migration is needed: challenges, fraud counters, webhook dedupe,
  and short-lived delivery state are intentionally transient Redis data.
