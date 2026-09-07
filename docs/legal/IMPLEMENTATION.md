# Legal and safety implementation

Engineering status: feature-branch implementation, not a compliance certification or production activation.

## Implemented contracts

| Capability | Contract and safeguards |
| --- | --- |
| Published policy metadata | Public `GET /v1/legal/policy`; version and SHA-256 bind the exact approved HTML. Defaults disabled. |
| Acceptance | Authenticated `GET/PUT /v1/me/legal-acceptance`; server-bound identity/time, immutable first receipt per account/version. Email, Apple, and phone **new-account** creation require a valid declaration only when policy is enabled. PostgreSQL user creation and receipt insertion are atomic. |
| Eligibility | Self-declared 13+ minor with guardian permission, or legal adult and at least 13. No date of birth or government ID collected by this new flow. This is not verified age or verified parental consent. |
| Nonuser reporting | Public `PUT /v1/support/cases/{UUID}` creates a durable, rate-limited case. Repeating the same ID, secret, and body is idempotent; conflicting retries cannot overwrite a case. |
| Private case status | `GET` on the same path with a random 256-bit capability in the Authorization header. Only a hash is stored. Status never includes the submission, contact, signature, or internal notes. The capability is not an account token and must not be put in URLs or analytics. |
| Review | Host-local `cmd/compliance` queue/review CLI. Expected-status compare-and-swap with an atomic audit entry. No public admin endpoint. Sensitive details require an explicit CLI flag. |
| Blocking | Authenticated `GET /v1/me/blocks` and `PUT/DELETE /v1/me/blocks/{UUID}`. Bidirectional suppression of message-history queries, chat/typing realtime delivery, and message push delivery. New conversation/member initiation checks block relationships. Shared groups and financial records remain. |
| iOS | Canonical Terms/Privacy links, version-bound onboarding and root account gate, native reporting form and private receipt, chat report/block controls, blocked-user management. Backend IDs, not local member IDs, identify block targets. |

Additive migration `000022_compliance_intake.sql` creates `legal_acceptances`, `compliance_cases`, `compliance_reviews`, and `user_blocks`. Do not deploy the application before migration succeeds. Keep the migration on rollback; older app code can ignore these tables.

## Default-off rollout

No release file is configured by default. Existing authentication remains compatible, no new age popup appears, and intake returns 503 without acknowledging or storing reports. The UI treats an explicit policy-route 404 as a legacy backend; network/5xx failures do not bypass an active policy.

To activate later, mount an operator-reviewed JSON file read-only in the API container and set `CLUSTER_LEGAL_RELEASE_FILE` to its in-container path. Every API replica must use identical contents. The deployment templates intentionally do not enable this setting yet.

Fields are `enabled`, `version`, `document_sha256`, `terms_url`, `privacy_url`, `minimum_age`, `intake_enabled`, `operator`, `state`, `contact_email`, `reviewed`, `monitoring_ready`, and `document_html`. The digest is lowercase SHA-256 of the exact UTF-8 HTML string. URLs must retain the existing `https://clixor.atlanteanz.com/terms` and `/privacy` addresses. Keep an immutable archive of each actual published document/version. A boolean assertion is not legal review or proof of operational readiness.

Public operator/contact: Akhil Madineni; Texas, United States; `akhil19960323@gmail.com`. **Do not include the owner's residential mailing address.** Any needed designated-agent address must be separately supplied and approved.

1. Run database-backed tests on an isolated database, then stage the additive migration and compatible API code with both features disabled.
2. Verify backups/restoration, app compatibility, blocking, and reporting in staging. Deploy the tested iOS build.
3. Finalize truthful policy text and actual effective date, review applicability with counsel, and remove draft markers/placeholders. Test the mailbox and confirm who covers urgent reports, including weekends.
4. Activate intake only with confirmed coverage. The web form is `/support` on the existing API hostname; verify it externally before replacing `[SAFETY_REPORT_URL]` in the draft.
5. Coordinate policy activation with a minimum supported client rollout. Once enabled, older clients lacking declarations cannot create new accounts. Existing users are not globally prohibited from backend activity solely for missing a new receipt; the updated UI checks their receipt at its account root. Do not represent this as universal server-side assent enforcement.

## Operator workflow

Build `go build -o /secure/operator-tools/compliance ./cmd/compliance` on the deployment host/tooling image. The binary is not added to the public API container automatically. Supply the existing database URL through protected `CLUSTER_DATABASE_URL`, never a command-line password. Use a controlled operator host and restricted credentials; DB access is the authority boundary, not the self-reported operator label.

`compliance -action queue` returns up to 50 open cases without raw contact/details; `-limit` accepts 1–100. `-include-sensitive-details` explicitly reveals submission data to the authorized operator. Do not put that output in CI logs or GitHub. Queue pagination/automated alerting are not implemented; a capped listing is not a guaranteed full backlog export.

`compliance -action review` reads one JSON object from stdin with `CaseID`, `ExpectedStatus`, `Status`, `Operator`, `Reason`, and `PublicUpdate`. Status values: `received`, `reviewing`, `awaiting_information`, `resolved`, `declined`. PublicUpdate is visible to the reporter; never put internal evidence or third-party personal information there. An audit status change **does not** remove content, disclose personal data, delete an account, or prove a valid legal notice.

Intimate-imagery reports receive a conservative 48-hour triage deadline from receipt. A timestamp alone does not meet a takedown obligation. Establish human review, secure evidence handling, actual enforcement, known-copy checks, and cache invalidation separately.

## Remaining production work

- Confirm monitored inbox/urgent-report owner and coverage; test inbound/outbound mail. A Gmail address does not configure SMTP or fix password-reset delivery.
- Final legal review, tracking/provider audit, approved retention/holds schedule, data-access permissions, and backup/restore verification for reports and receipts.
- Privacy-request identity verification, secure export/correction/appeal fulfillment, and response deadlines. Intake alone grants no authority to reveal or delete data.
- Applicable DMCA agent registration/public details, copyright notice handling, repeat-infringer procedures, and applicable child-safety reporting/preservation processes.
- End-to-end moderation/removal and duplicate-content handling; no automated scanning/filtering or staffed response service is created here.
- Blocks do not recall recipient copies, rotate group encryption keys, suppress shared expenses, or undo prior membership. Existing cached content is hidden for the current user's local block list; server suppression is bidirectional. Concurrent group/member initiation currently checks before the write, not in a single transaction with blocking; it must not be described as an absolute membership barrier.
- The new root legal check requires network access; offline acceptance and an offline verified-receipt cache are not implemented. Never record success after failed requests.

## Validation record

The iOS simulator build succeeded. All 18 iOS API compatibility tests passed with ad-hoc signing. A focused nonuser reporting UI E2E test passed (1 test, zero failures/skips); the isolated backend independently verified exact persisted fixture fields. Local `go test -race ./...`, `go vet ./...`, and formatting checks passed. HTTP tests cover policy gates, server-bound acceptance, rejection before registration persistence, report idempotency/confidentiality, disabled intake, and history/realtime blocking. Database integration cases are included but skip locally without `TEST_DATABASE_URL`; GitHub PR CI supplies PostgreSQL and must pass before merge/deploy. This is not full-app E2E certification. No production policy publication, real-user report, or production moderation action was used for testing.
