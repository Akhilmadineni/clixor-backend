# Backend dead-code audit — 2026-09-07

Base: `ffb38fc8165521f0b8ef147eac7db5e96b3f47c1`. Scope is this backend repo;
the iOS repo, original dirty worktrees, live NAS and OCI files are not changed.

## Removed

Go reachability analysis (`golang.org/x/tools/cmd/deadcode@v0.44.0 -test ./...`)
reported eight functions unreachable even when tests are included:

- `auth.TokenManager.Issue`: superseded by atomic device/session issuance.
- `httpapi.Server.requireAdultAgeAssurance` and `currentAdultAssurance`: the
  global age middleware was already disconnected; registered age endpoints stay.
- `mediakey.IsPublished`: unused convenience wrapper; validation/publication stay.
- `store.NewMediaDeletePayload`: unused wrapper; callers use explicit deadlines.
- `store.NewConversationMemberTombstone` and `memberIsDeletedTombstone`: unused
  helpers; current store-owned tombstone/identity reservation logic stays.
- `postgres.Store.requireAdmin`: unused pool-level query; active transaction-bound
  authorization and all endpoint access checks stay.

Removed all 17 files in `deploy/nas`, explicitly labeled retired before cleanup.
No active OCI scripts/workflows call them. Recovery material remains in Git at
the base commit above. This does not delete live NAS storage, backups, data,
secrets, or any OCI resources. No history was rewritten.

## Deliberately retained

- All published endpoints, production-05b compatibility envelopes/field aliases,
  immutable database migrations, age endpoints and data-repair bridges.
- APNs provider code and tests (activation deferred by owner), SMTP and Telnyx
  configuration support, S3/MinIO local-development adapter, and memory fixtures.
- OCI boot/recovery/canary/rollback/backup helpers. Python/shell dynamic dispatch,
  bundled historical controllers and failover-only paths are not proven dead
  by ordinary text-reference counts.
- Kubernetes reference scaffolds, now explicitly marked unsupported for direct
  production use; they are design examples, not deployed workloads.

## Regression prevention and limits

`make deadcode` uses pinned reachability and Staticcheck U1000 analyzers, includes
test entry points and fails on findings or tool errors. U1000 also checks unused
private types, fields and constants. CI rejects reintroduction of the NAS tree.
Keep tests in the analysis: test-only utilities are not production waste.

A zero-report Go reachability pass does not prove every runtime configuration,
dynamic Python dispatch or historical deployment path is used. This audit removes
confirmed dead code, not all text containing “legacy”. Do not expand deletion to
those retained paths without production-client telemetry and recovery evidence.

## Local verification

- Go reachability and Staticcheck U1000: zero findings after cleanup.
- `go vet ./...` and `go test -race ./...`: passed. Optional Postgres/Redis/NATS
  service-integration cases require their TEST_* environment variables and may
  skip locally; GitHub CI supplies those services.
- OCI offline Python suite: 230 tests, one Linux-only integration skip, otherwise
  passed. Shallow-checkout legacy-proof regression: passed.
- gofmt and `git diff --check`: clean. OpenAPI, migrations and APNs code unchanged.

No cloud resources or production configuration were modified for this cleanup.
