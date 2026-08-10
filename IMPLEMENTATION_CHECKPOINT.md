# Clixor backend repository checkpoint

Last updated: 2026-08-10 (America/Chicago)

Repository: `https://github.com/Akhilmadineni/clixor-backend`

Branch: `feature/akhil/nas-cicd`

## Current state

- The production Go backend was split from the combined Clustr iOS repository
  into this private, backend-only repository. The Go module is now
  `github.com/Akhilmadineni/clixor-backend`.
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

## Remaining installation step

- Register and enable the repository-scoped NAS runner. This creates persistent
  GitHub access and therefore requires operator confirmation at action time.
- Merge this branch to `main`; the first deploy can then run after CI succeeds.

No live credential is stored in this repository.
