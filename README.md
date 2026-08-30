# Clixor production backend

Go backend for Clustr messaging and shared-group data. The OCI production topology
uses PostgreSQL, Redis, NATS, native private OCI Object Storage, a Redis-backed OTP
service with Telnyx SMS transport, OCI Email Delivery, and APNs.

This is the sole source repository for the backend. The
`Uthejmopathi/Clustr` repository contains the Swift/iOS client; retained `clustr`
runtime names and `CLUSTER_*` environment keys are compatibility identifiers for
the retired NAS deployment package. OCI is the active production target; see
`deploy/oci/README.md`.

## Contributors

- [Uthej Mopathi](https://github.com/Uthejmopathi) — original author of the
  Clixor Privacy Policy and Terms of Use page.

## Run a smoke environment

The repository includes a non-durable mode for API development and automated tests:

```bash
make run
curl http://127.0.0.1:8080/health/ready
```

Development phone verification uses code `000000`. Media is intentionally disabled
in the smoke mode because production media uses private object storage.

## Run the production topology locally

Install Docker Desktop or another Compose-compatible runtime, then:

```bash
cp .env.docker.example .env
# Replace every value in .env with a generated secret.
docker compose up --build
```

The local-only Compose stack uses MinIO for development compatibility. The API
listens on `http://127.0.0.1:8080`; its MinIO administration console is at
`http://127.0.0.1:9001`. OCI production does not deploy MinIO or S3 credentials.

## Verify

```bash
make test-race
make vet
```

The API exposes `/health/live`, `/health/ready`, and `/metrics`. See
`ARCHITECTURE.md` for delivery guarantees, encryption boundaries, scaling choices,
and launch gates.

Operational SLOs, deployment sequencing, backup/restore requirements, and incident
steps are in `RUNBOOK.md`.

Phone authentication keeps its challenge and fraud-control state in Redis. See
`PHONE_VERIFICATION_PLAN.md` for its security policy, Telnyx sender-registration
prerequisites, secret contract, and rollout gates.

Production API processes require `CLUSTER_AUTO_MIGRATE=false`. Run the immutable
release image's `/clustr-migrate` command as a one-shot deployment job before
rolling out `/clustr-api`; the Kubernetes examples keep these lifecycle steps
separate.
