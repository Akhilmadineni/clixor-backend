# Clixor backend repository checkpoint

Last updated: 2026-08-19 (America/Chicago)

Repository: `https://github.com/Akhilmadineni/clixor-backend`

Branch: `feature/akhil/delete-account-backend` (production source merged to `main` at `2e35f2a`)

## Account deletion implementation checkpoint

- Authenticated `DELETE /v1/me` returns `204` only after a serializable account-erasure transaction commits.
- Login identifiers, password hash, external identities, sessions, push tokens, encryption prekeys, profile fields, phone, email, avatar, and username are removed. The user/device rows remain inaccessible identity-free tombstones only where shared message/entity foreign keys require them.
- The deleted account is removed from every group and from all lookup paths. Ownership is deterministically transferred to the oldest remaining member.
- Single-member conversations are deleted. Their MinIO object keys are queued in bounded durable outbox batches; the relay retries idempotent MinIO deletion until it succeeds.
- Shared messages, expenses, and settlements remain available to other members. Embedded member identity is rewritten to `Deleted user` while stable accounting IDs remain intact.
- Migration `000004_account_deletion.sql`, OpenAPI documentation, HTTP contract tests, store tests, PostgreSQL integration coverage, and MinIO retry coverage are included.
- Validation on Go 1.26.6 passes `gofmt`, `go vet`, `go test ./...`, and `go test -race ./...`. Migration 000004 and the account-deletion integration suite also pass against a fresh PostgreSQL 17 database on the NAS; the temporary test database was removed immediately afterward. CI and the production image are pinned to Go 1.26.6, with `golang.org/x/net` v0.55.0, to address the August 2026 Go security advisories caught by `govulncheck`.
- GitHub Actions CI run `32298576923` and NAS deployment run `32298831529` completed successfully for revision `2e35f2a`. Public readiness returned 200. A disposable production account verified register 201, delete 204, revoked access/refresh/login 401, released-identifier registration 201, and cleanup delete 204.

## Current state

- The production Go backend was split from the combined Clustr iOS repository
  into this private, backend-only repository. The Go module is now
  `github.com/Akhilmadineni/clixor-backend`.
- The split has been reconciled through combined-repository `main` commit
  `b38233b`. Post-split phone linking, pilot authentication, unique usernames,
  username discovery, persistent chat state, and unread-state changes are all
  present here alongside the NAS-owned OTP/fraud engine and Telnyx transport.
- The former Twilio adapter is intentionally not carried forward: Telnyx is the
  production SMS transport and the disabled provider remains the safe fallback.
  No active backend implementation remains owned by the combined iOS repository.
- Existing production runtime identifiers, environment variables, public
  hostnames, containers, data paths, and database schema deliberately retain
  their `clustr` names so this repository split does not interrupt clients or
  migrate live data.
- CI checks formatting, vet, race-enabled PostgreSQL/Redis tests, vulnerability
  scanning, binary builds, and the production Docker image.
- A successful CI run for `main` triggers the dedicated NAS runner labelled
  `self-hosted`, `nas`, and `clixor`. Deployment is serialized, builds an
  immutable revision-labelled image, refreshes runtime configuration without
  exporting NAS secrets, captures a private pre-migration PostgreSQL snapshot,
  applies transactional migrations, gates on readiness, and rolls back the API
  image and Compose model on unhealthy rollout.
- Application secrets remain only under `/volume1/docker/clustr/secrets` on the
  NAS. No populated credential belongs in this repository or GitHub Actions.
- The repository-scoped runner `atlanteans-nas-clixor` is registered with
  `self-hosted`, `Linux`, `X64`, `nas`, and `clixor` labels. Its
  `github-runner-clixor.service` systemd unit is enabled, active, and listening
  for jobs on runner version 2.336.0.
- This implementation is merged into `main`. Every future push or merge to
  `main` starts CI; a successful CI run then dispatches the serialized NAS
  deployment workflow.
- The first main-branch deployment hardened the runtime privilege boundary:
  root-owned material is validated inside the capability-limited bootstrap
  container; the dedicated deployment group gets traverse-only access to the
  secret directory and read access only to Compose's `runtime.env`; PKI private
  material remains root-only.

## Repository ownership boundary

- This repository owns all backend application code, database migrations,
  OpenAPI definitions, backend tests, production Compose/Kubernetes manifests,
  NAS deployment automation, operational runbooks, and backend CI/CD.
- The combined `Uthejmopathi/Clustr` repository owns the Swift/iOS client only.
  Its historical backend directory and backend-specific GitHub Actions were
  removed from `main` in commit `610ff55` after this repository's reconciled
  production rollout succeeded.
- Existing `CLUSTER_*` configuration keys, `clustr-*` runtime names, database
  names, public hostnames, and NAS paths are compatibility identifiers, not an
  indication that their source belongs in the iOS repository.

No live credential is stored in this repository.
