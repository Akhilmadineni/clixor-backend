#!/bin/sh
set -eu
umask 077

script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "${test_root}"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'secret split test failed: %s\n' "$*" >&2
  exit 1
}

runtime_env="${test_root}/runtime.env"
reset_secret='test-reset-secret-that-must-never-be-printed'
smtp_secret='test-smtp-secret-that-must-never-be-printed'
queue_key='dGVzdC1vbmx5LTMya2V5LWJ5dGVzLTAwMDAwMDAwMDA='

{
  printf 'POSTGRES_DB=clixor\nPOSTGRES_USER=clixor\nPOSTGRES_PASSWORD=postgres-secret\n'
  printf 'REDIS_PASSWORD=redis-secret\nNATS_AUTH_TOKEN=nats-secret\n'
  printf 'GF_SECURITY_ADMIN_USER=admin\nGF_SECURITY_ADMIN_PASSWORD=grafana-secret\n'
  printf 'CLUSTER_ENV=production\nCLUSTER_STORE=postgres\n'
  printf 'CLUSTER_DATABASE_URL=postgres://clixor:postgres-secret@postgres/db\n'
  printf 'CLUSTER_DATABASE_MAX_CONNS=12\nCLUSTER_DATABASE_MIN_CONNS=2\n'
  printf 'CLUSTER_TLS_CA_FILE=/run/pki/ca.crt\n'
  printf 'CLUSTER_REDIS_URL=rediss://:redis-secret@redis/0\n'
  printf 'CLUSTER_NATS_URL=tls://nats-secret@nats:4222\n'
  printf 'CLUSTER_JWT_ACCESS_SECRET=jwt-secret\nCLUSTER_METRICS_TOKEN=metrics-secret\n'
  printf 'CLUSTER_MEDIA_PROVIDER=oci\nCLUSTER_VERIFICATION_PROVIDER=telnyx\n'
  printf 'CLUSTER_TELNYX_API_KEY=telnyx-secret\nCLUSTER_APNS_KEY_ID=apple-key\n'
  printf 'CLUSTER_MAIL_PROVIDER=smtp\nCLUSTER_SMTP_TRANSPORT=implicit_tls\n'
  printf '%s\n' 'CLUSTER_SMTP_USERNAME=$(printf must-not-execute)'
  printf 'CLUSTER_SMTP_PASSWORD=%s\n' "${smtp_secret}"
  printf 'CLUSTER_PASSWORD_RESET_HMAC_SECRET=%s\n' "${reset_secret}"
  printf 'CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY=%s\n' "${queue_key}"
} > "${runtime_env}"

output="$(sh "${script_root}/split-runtime-secrets.sh" "${runtime_env}" "${test_root}" 2>&1)"
[ -z "${output}" ] || fail "successful migration emitted output"

assert_keys() {
  file=$1
  expected=$2
  actual="$(awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ { print $1 }' "${file}" | sort | tr '\n' ' ')"
  [ "${actual}" = "${expected}" ] || fail "$(basename -- "${file}") keys were ${actual}"
  [ "$(stat -f '%Lp' "${file}" 2>/dev/null || stat -c '%a' "${file}")" = 600 ] || \
    fail "$(basename -- "${file}") mode is not 0600"
}

assert_keys "${test_root}/postgres.env" 'POSTGRES_DB POSTGRES_PASSWORD POSTGRES_USER '
assert_keys "${test_root}/redis.env" 'REDIS_PASSWORD '
assert_keys "${test_root}/nats.env" 'NATS_AUTH_TOKEN '
assert_keys "${test_root}/grafana.env" 'GF_SECURITY_ADMIN_PASSWORD GF_SECURITY_ADMIN_USER '
assert_keys "${test_root}/backup.env" 'POSTGRES_DB POSTGRES_PASSWORD POSTGRES_USER '
assert_keys "${test_root}/migrate.env" 'CLUSTER_DATABASE_MAX_CONNS CLUSTER_DATABASE_MIN_CONNS CLUSTER_DATABASE_URL CLUSTER_TLS_CA_FILE '
if awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ && $1 !~ /^CLUSTER_[A-Z0-9_]+$/ { exit 1 }' \
  "${test_root}/api.env"; then :; else
  fail "api.env contains a non-API key"
fi
grep -q "^CLUSTER_SMTP_PASSWORD=${smtp_secret}$" "${test_root}/api.env" || fail "SMTP secret changed"
grep -Fq 'CLUSTER_SMTP_USERNAME=$(printf must-not-execute)' "${test_root}/api.env" || \
  fail "legacy value was evaluated or changed"
grep -q "^CLUSTER_PASSWORD_RESET_HMAC_SECRET=${reset_secret}$" "${test_root}/api.env" || fail "reset secret changed"
grep -q "^CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY=${queue_key}$" "${test_root}/api.env" || fail "queue key changed"
grep -q '^CLUSTER_SMTP_TRANSPORT=implicit_tls$' "${test_root}/api.env" || fail "OCI TLS mode default changed"
grep -q '^CLUSTER_MAIL_FROM=Clixor <no-reply@mail.atlanteanz.com>$' "${test_root}/api.env" || \
  fail "OCI approved sender default changed"
if awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ { exit 1 }' "${runtime_env}"; then :; else
  fail "legacy runtime.env retained scoped assignments"
fi

before="$(cksum "${test_root}"/*.env | sort)"
sh "${script_root}/split-runtime-secrets.sh" "${runtime_env}" "${test_root}"
after="$(cksum "${test_root}"/*.env | sort)"
[ "${before}" = "${after}" ] || fail "secret split is not idempotent"

# Assert Compose receives only tmpfs file paths, never secret-valued env_file
# content. No checked-in service may consume the persistent staging root.
compose_map="$(awk '
  /^  [A-Za-z0-9_-]+:$/ { service=$1; sub(/:$/, "", service) }
  /\/run\/clixor\/secrets\/active\/[A-Za-z0-9._-]+/ {
    path=$0; sub(/^.*\/active\//, "", path); sub(/:.*/, "", path)
    print service "=" path
  }
' "${script_root}/compose.yaml" | sort)"
expected_map='api-a=api.env
api-a=apns
api-b=api.env
api-b=apns
grafana=grafana.ini
migrate=migrate.env
nats=nats.conf
postgres-backup=postgres.pgpass
postgres=postgres.password
postgres=postgres.pgpass
prometheus=metrics.token
redis=redis.acl
redis=redis.password'
[ "${compose_map}" = "${expected_map}" ] || fail "Compose env exposure map is not allowlisted"
grep -q '^[[:space:]]*env_file:' "${script_root}/compose.yaml" && \
  fail "Compose persists secret values in container environment metadata"
grep -q '/srv/clixor/secrets/active' "${script_root}/compose.yaml" && \
  fail "Compose consumes persistent active secrets instead of tmpfs"
grep -q '/run/clixor/secrets/active/runtime.env' "${script_root}/compose.yaml" && \
  fail "Compose still consumes legacy runtime.env"
grep -Fq "grep -Eq '^(CLUSTER_|POSTGRES_PASSWORD=|REDIS_PASSWORD=|NATS_AUTH_TOKEN=|GF_SECURITY_ADMIN_PASSWORD=)'" \
  "${script_root}/deploy.sh" || \
  fail "deploy does not detect immutable containers with legacy secrets"
grep -q '\[ "${legacy_dependency_scope}" = "true" \]' "${script_root}/deploy.sh" || \
  fail "deploy does not route legacy containers through forced reconciliation"
grep -q -- '--force-recreate "${dependency_service}"' "${script_root}/deploy.sh" || \
  fail "deploy does not replace legacy data containers"
grep -Fq 'trusted_env CLIXOR_REQUIRE_PUBLIC_SMOKE=true CLIXOR_REQUIRE_VAULT_HYDRATION=true' \
  "${script_root}/actions-deploy.sh" || \
  fail "production Actions do not require Vault hydration"
grep -Fq 'CLIXOR_INITIAL_VAULT_CUTOVER=false' \
  "${script_root}/actions-deploy.sh" || \
  fail "production Actions can implicitly perform the initial Vault cutover"
grep -Fq 'staging-to-Vault promotion requires CLIXOR_INITIAL_VAULT_CUTOVER=true' \
  "${script_root}/deploy.sh" || \
  fail "deploy does not require the explicit initial Vault cutover flag"
grep -Fq 'initial Vault cutover requires an existing boot-approved staging release' \
  "${script_root}/deploy.sh" || \
  fail "initial Vault cutover can run without a prior staging rollback boundary"
grep -Fq -- '--candidate-manifest "${candidate_manifest}"' \
  "${script_root}/deploy.sh" || \
  fail "deploy does not record a release candidate Vault manifest"
grep -Fq -- '--commit-candidate-release "${candidate_manifest}"' \
  "${script_root}/deploy.sh" || \
  fail "deploy does not atomically approve the release-local Vault cohort"
grep -Fq -- '--approved-release-manifest "${approved_manifest}"' \
  "${script_root}/prepare-runtime-secrets.sh" || \
  fail "boot-time hydration does not require the resolved release manifest"
grep -Fq 'Candidate and orphan directories are never boot authority' \
  "${script_root}/prepare-runtime-secrets-launcher.py" || \
  fail "boot secret selection does not exclude uncommitted candidates"
grep -Fq 'raise ReconcileError("no committed release is selected")' \
  "${script_root}/runtime-reconciler.py" || \
  fail "runtime can start without a committed current release"
grep -Fq 'command.extend(("--version-number", str(version_number)))' \
  "${script_root}/hydrate-vault-secrets.py" || \
  fail "approved boot hydration does not pin OCI secret versions"
grep -q 'runtime secrets must be materialized on tmpfs' "${script_root}/hydrate-vault-secrets.py" || \
  fail "Vault hydration does not fail closed outside tmpfs"
grep -q '^Requires=clixor-runtime-secrets.service$' "${script_root}/docker-runtime-secrets.conf" || \
  fail "Docker is not ordered after boot-time secret hydration"
grep -q '^RuntimeDirectory=clixor$' "${script_root}/clixor-runtime-secrets.service" || \
  fail "boot-time hydration does not create its tmpfs runtime parent"
grep -Fq 'prepare-runtime-secrets-launcher.py' \
  "${script_root}/clixor-runtime-secrets.service" || \
  fail "boot service does not select release-local tooling through the stable launcher"
grep -Fq 'if [ "${defer_host_tool_activation}" = "false" ]; then' \
  "${script_root}/bootstrap.sh" || \
  fail "normal deferred bootstrap can overwrite boot-critical host artifacts"
grep -q 'LoadCredential=cloudflare-token:/run/clixor/secrets/active/cloudflare-token' \
  "${script_root}/cloudflared.service" || fail "cloudflared does not use the tmpfs generation"
sh -n "${script_root}/prepare-runtime-secrets.sh" \
  "${script_root}/prepare-initial-staging-secrets.sh"
python3 "${script_root}/test_boot_secret_launcher.py"

duplicate_root="${test_root}/duplicate"
mkdir "${duplicate_root}"
printf 'POSTGRES_DB=one\nPOSTGRES_DB=two\n' > "${duplicate_root}/runtime.env"
if sh "${script_root}/split-runtime-secrets.sh" \
  "${duplicate_root}/runtime.env" "${duplicate_root}" >"${duplicate_root}/stdout" 2>"${duplicate_root}/stderr"; then
  fail "duplicate legacy keys were accepted"
fi
grep -q 'one\|two' "${duplicate_root}/stderr" && fail "duplicate failure leaked a value"

target_duplicate_root="${test_root}/target-duplicate"
mkdir "${target_duplicate_root}"
cp "${runtime_env}" "${target_duplicate_root}/runtime.env"
cp "${test_root}/api.env" "${target_duplicate_root}/api.env"
printf 'CLUSTER_MAIL_PROVIDER=disabled\n' >> "${target_duplicate_root}/api.env"
if sh "${script_root}/split-runtime-secrets.sh" \
  "${target_duplicate_root}/runtime.env" "${target_duplicate_root}" >/dev/null 2>&1; then
  fail "duplicate scoped keys were accepted"
fi

link_root="${test_root}/symlink"
mkdir "${link_root}"
printf 'safe=value\n' > "${link_root}/source"
ln -s "${link_root}/source" "${link_root}/runtime.env"
if sh "${script_root}/split-runtime-secrets.sh" \
  "${link_root}/runtime.env" "${link_root}" >/dev/null 2>&1; then
  fail "symlinked legacy file was accepted"
fi
