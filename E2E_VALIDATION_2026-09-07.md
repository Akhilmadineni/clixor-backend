# End-to-end validation — 2026-09-07

**Overall: not a complete end-to-end pass. Do not use this report to approve
a production rollout.** Backend checks passed; the live simulator suite still
has unresolved failures. No backend deployment or APNs configuration was changed.

## Revisions and environments

- Cleanup code: `d28c117851f1d8c28541fcf0d2d0995aa3802411`,
  [backend PR 17](https://github.com/Akhilmadineni/clixor-backend/pull/17).
- iOS base: `954c24de3398832621b7bec608df7a23b977d2e6`, plus test-only repairs on
  `feature/akhil/e2e-current-ui-validation` in `Uthejmopathi/Clustr`, pushed head
  `90c02bbd18260f3a6004398aa71977b573d0ccc0`, [draft UI PR 19](https://github.com/Uthejmopathi/Clustr/pull/19).
- Public API: `https://clustr-api.atlanteanz.com`, readiness reports
  **bb86518d57b03690c991d0fda5fd0db0dc449e90**, not the cleanup branch.
- Simulator: iPhone 17 Pro, iOS 26.5, arm64; ad-hoc signed test build.

## Backend results

1. `go test -race -count=1 -json ./internal/httpapi`: **77 top-level tests passed**
   (89 including subtests), zero failures/skips. These tests make actual HTTP
   requests to ephemeral servers with memory adapters. They are not a durable-
   database or deployed-container certification.
2. Cleanup PR CI: **all three checks passed** — verification with PostgreSQL,
   Redis and NATS, OCI Terraform/deployment tests, and amd64/arm64 container build.
   [CI run](https://github.com/Akhilmadineni/clixor-backend/actions/runs/34090358560).
3. Live `deploy/oci/smoke.py` groups `verify_unauthenticated_contract`,
   `verify_auth_lifecycle_and_rate_limit`, `verify_group_realtime_and_media`:
   **24 explicit checks passed**, in addition to required HTTP status/error
   assertions. Covered registration, authentication, refresh/logout/deletion,
   unauthorized access, group isolation, opaque message persistence,
   idempotency, WebSocket delivery/reconnect, entities and media round trips.
   Disposable smoke-account cleanup returned no failures.
4. Full edge/legal smoke **failed** on the API legal redirect's cache policy.
   Live GET `/privacy` returns 308 to the right hostname but `Cache-Control:
   no-store`. That behavior matches the deployed bb86518 code. Current source
   already sets `public, max-age=300`; no test expectation was weakened.

## Simulator results

The original environment-variable-only invocation skipped all eight tests.
This was identified and **not counted as success**. The new runner injects the
origin into the generated `.xctestrun` and rejects skipped results.

After the first round of fixture repairs, the full rerun executed **9 tests:
2 passed, 7 failed, 0 skipped**:

| Journey | Result / stopping point |
| --- | --- |
| Complete group/profile/chat/expenses journey | Failed: ambiguous username-picker toolbar selector |
| Account switch after logout | Failed: second profile setup did not reach home; cause not established |
| Smart Settle / individual / archive | Smart Settle setup/cancel persisted correctly; later failed at username-picker selector |
| Logout / returning login / restoration | Failed while replacing email text, before login submission |
| Forgot Password | Passed: UI displays deployed disabled-mail error |
| Pilot phone sign-in visibility | Passed: phone entry remains hidden; not an SMS delivery test |
| Roommate entity / settlement lifecycle | Failed at username-picker selector |
| Subscription lifecycle | Failed at username-picker selector |
| Trip photo / chat media | Failed at location-picker navigation; full media journey not verified through UI |

The ambiguous selector was changed to a typed Button query. A focused rerun then
**created the three-member group through the UI and verified its name, type and
membership through the API**. It subsequently failed on the group card's shared
accessibility ID before entering chat. All three fixtures from that focused run
were deleted with session revocation verified. Group navigation now selects the
card's explicit Chat button; its further focused result is recorded below.
The final focused run on 90c02bb **also opened chat through the UI, submitted a
message, retrieved it through the API, verified a positive sequence number and
validated the opaque E2EE envelope without exposed plaintext**. It then failed
at the obsolete `group.tab.expenses` selector, before expense submission. The
single full journey therefore remains failed (0 passed, 1 failed, 0 skipped),
despite those verified preceding steps. All three fixtures in this run were
deleted and their sessions rejected. The remaining journey must be adapted to
the current separate group screens rather than the retired tab navigation.

The table above preserves the full-suite result and must not be rewritten as
all-green based on partial checks within a focused test.

## Fixture and cleanup safeguards

Companions are actual disposable registered users, selected by username, with
valid CryptoKit signed device prekeys. Primary signup enters through UI.
Teardown verifies account deletion and immediate session rejection. The full
rerun logged **13 successful deletions/revocations**. One intended second-account
fixture did not authenticate during teardown, so its absence was not independently
proven. The harness now fails explicitly on that ambiguity. No broad user deletion
or direct production database modification was performed.

Account deletion retains shared-history tombstones by design; successful fixture
cleanup does not mean zero database rows or completed asynchronous media GC.

## Still unverified / unavailable

- Complete passing UI journey matrix, including account switching, returning
  login, expenses/settlements, trip picker and media flows.
- Successful password-reset email delivery/confirmation: live start endpoint
  still returns **503 `password_reset_unavailable`**. Its error UI is tested.
- APNs (explicitly deferred), real SMS delivery and Apple sign-in provider flows.
- Multi-device cryptographic interoperability/security review, restore/failover,
  load capacity and the proposed HA migration. Those are not implied by these tests.
- Running the cleanup branch itself behind the public domain. It is unmerged;
  live smoke validates the older live revision only.

Local result bundles and continuation notes are listed in the workspace
`E2E_VALIDATION_CHECKPOINT_2026-09-07.md`; reusable simulator instructions live in
the UI repository's `docs/LIVE_E2E_TESTING.md`.
