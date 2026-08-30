# Clixor backend repository checkpoint

Last updated: 2026-08-30 (America/Chicago)

Repository: `https://github.com/Akhilmadineni/clixor-backend`

Active deployment target: OCI Phoenix (`deploy/oci`); NAS automation is retired.

## Account deletion implementation checkpoint

- Authenticated `DELETE /v1/me` returns `204` only after a serializable account-erasure transaction commits.
- Login identifiers, password hash, external identities, sessions, push tokens, encryption prekeys, profile fields, phone, email, avatar, and username are removed. The user/device rows remain inaccessible identity-free tombstones only where shared message/entity foreign keys require them.
- The deleted account is removed from every group and from all lookup paths. Ownership is deterministically transferred to the oldest remaining member.
- Single-member conversations are deleted. Their MinIO object keys are queued in bounded durable outbox batches; the relay retries idempotent MinIO deletion until it succeeds.
- Shared messages, expenses, and settlements remain available to other members. Embedded member identity is rewritten to `Deleted user` while stable accounting IDs remain intact.
- Migration `000004_account_deletion.sql`, OpenAPI documentation, HTTP contract tests, store tests, PostgreSQL integration coverage, and MinIO retry coverage are included.
- Validation on Go 1.26.6 passes `gofmt`, `go vet`, `go test ./...`, and `go test -race ./...`. Migration 000004 and the account-deletion integration suite passed against a fresh PostgreSQL 17 database during the earlier NAS phase; that temporary test database was removed immediately afterward. CI and the production image are pinned to Go 1.26.6, with `golang.org/x/net` v0.55.0, to address the August 2026 Go security advisories caught by `govulncheck`.

## Current state

- The production Go backend was split from the combined Clustr iOS repository
  into this private, backend-only repository. The Go module is now
  `github.com/Akhilmadineni/clixor-backend`.
- The split has been reconciled through combined-repository `main` commit
  `b38233b`. Post-split phone linking, pilot authentication, unique usernames,
  username discovery, persistent chat state, and unread-state changes are all
  present here alongside the backend-owned OTP/fraud engine and Telnyx transport.
- The former Twilio adapter is intentionally not carried forward: Telnyx is the
  production SMS transport and the disabled provider remains the safe fallback.
  No active backend implementation remains owned by the combined iOS repository.
- Existing production runtime identifiers, environment variables, public
  hostnames, containers, data paths, and database schema deliberately retain
  their `clustr` names so this repository split does not interrupt clients or
  migrate live data.
- CI checks formatting, vet, race-enabled PostgreSQL/Redis tests, vulnerability
  scanning, binary builds, and the production Docker image.
- After the OCI workflow is merged to `main` and its dedicated runner is
  registered, a successful push-triggered `CI` run for `main` dispatches the
  serialized runner labelled `self-hosted`, `Linux`, `ARM64`, and
  `clixor-oci-production`. It checks out the exact CI-approved SHA and passes it
  through a root-owned validation wrapper before deployment.
- An OCI upgrade captures the previous Compose model, API image, release pointer,
  and a non-empty PostgreSQL dump before active-runtime mutation. Application
  rollback is armed before source sync, dependency reconciliation, or forward
  migration. Schema migrations are never automatically reversed or restored.
- OCI application secrets belong only in root-owned paths under
  `/srv/clixor/secrets`; the Cloudflare token belongs at
  `/etc/cloudflared/token` with root ownership and mode `0600`. No populated
  credential belongs in this repository or GitHub Actions.
- The former NAS deployment workflows are deleted and CI rejects their return.
  A recovered NAS must not receive the OCI production runner label or serve the
  production Cloudflare hostnames.

## Repository ownership boundary

- This repository owns all backend application code, database migrations,
  OpenAPI definitions, backend tests, production Compose/Kubernetes manifests,
  OCI deployment automation, operational runbooks, and backend CI/CD. The
  checked-in `deploy/nas` package is retired historical material and is not an
  active deployment target.
- The combined `Uthejmopathi/Clustr` repository owns the Swift/iOS client only.
  Its historical backend directory and backend-specific GitHub Actions were
  removed from `main` in commit `610ff55` after this repository's reconciled
  production rollout succeeded.
- Existing `CLUSTER_*` configuration keys, `clustr-*` runtime names, database
  names, and public hostnames are compatibility identifiers, not an indication
  that their source belongs in the iOS repository. References to NAS paths in
  the retired deployment package are historical and must not be used for OCI.

No live credential is stored in this repository.
