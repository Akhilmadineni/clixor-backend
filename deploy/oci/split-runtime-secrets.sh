#!/bin/sh
set -eu
umask 077

runtime_env=${1:-}
secret_root=${2:-}

fail() {
  printf 'Runtime secret split failed: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "expected runtime.env and protected secret directory paths"
[ -f "${runtime_env}" ] && [ ! -L "${runtime_env}" ] || \
  fail "legacy runtime configuration must be a regular file"
[ -d "${secret_root}" ] && [ ! -L "${secret_root}" ] || \
  fail "secret root must be a regular directory"
[ "$(dirname -- "${runtime_env}")" = "${secret_root}" ] || \
  fail "legacy runtime configuration must be inside the secret root"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"

for name in api postgres redis nats grafana backup migrate; do
  target="${secret_root}/${name}.env"
  if [ -L "${target}" ] || { [ -e "${target}" ] && [ ! -f "${target}" ]; }; then
    fail "${name}.env must be a regular file"
  fi
done

stage="$(mktemp -d "${secret_root}/.split-runtime.XXXXXX")"
cleanup() {
  rm -rf -- "${stage}"
}
trap cleanup EXIT HUP INT TERM

if awk -F= '
  /^[A-Za-z_][A-Za-z0-9_]*=/ { if (seen[$1]++) exit 1 }
' "${runtime_env}"; then :; else
  fail "legacy runtime configuration has duplicate keys"
fi

validate_env() {
  file=$1
  allowlist=$2
  awk -F= -v allowlist="${allowlist}" '
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    !/^[A-Za-z_][A-Za-z0-9_]*=/ { exit 40 }
    {
      if (seen[$1]++) exit 41
      if ($1 !~ allowlist) exit 42
    }
  ' "${file}" || fail "$(basename -- "${file}") has invalid, duplicate, or disallowed keys"
}

extract_env() {
  source_file=$1
  key_pattern=$2
  destination=$3
  awk -F= -v key_pattern="${key_pattern}" '
    /^[A-Za-z_][A-Za-z0-9_]*=/ && $1 ~ key_pattern {
      if (seen[$1]++) exit 41
      print
    }
  ' "${source_file}" > "${destination}" || \
    fail "legacy runtime configuration has duplicate keys"
}

prepare_from_legacy() {
  name=$1
  key_pattern=$2
  target="${secret_root}/${name}.env"
  staged="${stage}/${name}.env"
  if [ -f "${target}" ]; then
    awk '{ print }' "${target}" > "${staged}"
  else
    extract_env "${runtime_env}" "${key_pattern}" "${staged}"
  fi
}

ensure_value() {
  file=$1
  key=$2
  value=$3
  grep -q "^${key}=" "${file}" || printf '%s=%s\n' "${key}" "${value}" >> "${file}"
}

require_value() {
  file=$1
  key=$2
  grep -Eq "^${key}=.+" "${file}" || \
    fail "$(basename -- "${file}") is missing ${key}"
}

prepare_from_legacy api '^CLUSTER_[A-Z0-9_]+$'
ensure_value "${stage}/api.env" CLUSTER_MAIL_PROVIDER disabled
ensure_value "${stage}/api.env" CLUSTER_MAIL_FROM 'Clixor <no-reply@mail.atlanteanz.com>'
ensure_value "${stage}/api.env" CLUSTER_SMTP_TRANSPORT implicit_tls
ensure_value "${stage}/api.env" CLUSTER_PASSWORD_RESET_TTL 10m
ensure_value "${stage}/api.env" CLUSTER_PASSWORD_RESET_CODE_LENGTH 8
ensure_value "${stage}/api.env" CLUSTER_PASSWORD_RESET_MAX_ATTEMPTS 5
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_BATCH_SIZE 50
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_WORKER_CONCURRENCY 4
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_MAX_ATTEMPTS 8
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_RETRY_BASE_DELAY 5s
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_RETRY_MAX_DELAY 30m
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_DELIVERED_RETENTION 24h
ensure_value "${stage}/api.env" CLUSTER_MAIL_QUEUE_DEAD_LETTER_RETENTION 720h
if ! grep -q '^CLUSTER_PASSWORD_RESET_HMAC_SECRET=' "${stage}/api.env"; then
  printf 'CLUSTER_PASSWORD_RESET_HMAC_SECRET=%s\n' "$(openssl rand -hex 48)" >> "${stage}/api.env"
fi
if ! grep -q '^CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY=' "${stage}/api.env"; then
  printf 'CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32)" >> "${stage}/api.env"
fi
validate_env "${stage}/api.env" '^CLUSTER_[A-Z0-9_]+$'
for key in \
  CLUSTER_ENV CLUSTER_STORE CLUSTER_DATABASE_URL CLUSTER_REDIS_URL CLUSTER_NATS_URL \
  CLUSTER_JWT_ACCESS_SECRET CLUSTER_METRICS_TOKEN CLUSTER_MEDIA_PROVIDER \
  CLUSTER_VERIFICATION_PROVIDER CLUSTER_MAIL_PROVIDER \
  CLUSTER_PASSWORD_RESET_HMAC_SECRET CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY
do
  require_value "${stage}/api.env" "${key}"
done

prepare_from_legacy postgres '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD)$'
validate_env "${stage}/postgres.env" '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD)$'
for key in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD; do
  require_value "${stage}/postgres.env" "${key}"
done

prepare_from_legacy redis '^REDIS_PASSWORD$'
validate_env "${stage}/redis.env" '^REDIS_PASSWORD$'
require_value "${stage}/redis.env" REDIS_PASSWORD

prepare_from_legacy nats '^NATS_AUTH_TOKEN$'
validate_env "${stage}/nats.env" '^NATS_AUTH_TOKEN$'
require_value "${stage}/nats.env" NATS_AUTH_TOKEN

prepare_from_legacy grafana '^(GF_SECURITY_ADMIN_USER|GF_SECURITY_ADMIN_PASSWORD)$'
validate_env "${stage}/grafana.env" '^(GF_SECURITY_ADMIN_USER|GF_SECURITY_ADMIN_PASSWORD)$'
require_value "${stage}/grafana.env" GF_SECURITY_ADMIN_USER
require_value "${stage}/grafana.env" GF_SECURITY_ADMIN_PASSWORD

# Backup intentionally receives only its three PostgreSQL client values. Keep it
# derived from postgres.env so credentials cannot drift across two operator files.
extract_env "${stage}/postgres.env" '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD)$' \
  "${stage}/backup.env"
validate_env "${stage}/backup.env" '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD)$'

# The schema command uses config.LoadMigration and receives only database pool
# configuration. It no longer requires API/provider validation or credentials.
extract_env "${stage}/api.env" \
  '^(CLUSTER_DATABASE_URL|CLUSTER_DATABASE_MAX_CONNS|CLUSTER_DATABASE_MIN_CONNS|CLUSTER_TLS_CA_FILE)$' \
  "${stage}/migrate.env"
validate_env "${stage}/migrate.env" \
  '^(CLUSTER_DATABASE_URL|CLUSTER_DATABASE_MAX_CONNS|CLUSTER_DATABASE_MIN_CONNS|CLUSTER_TLS_CA_FILE)$'
for key in CLUSTER_DATABASE_URL CLUSTER_DATABASE_MAX_CONNS CLUSTER_DATABASE_MIN_CONNS; do
  require_value "${stage}/migrate.env" "${key}"
done

# Preserve comments and unknown legacy entries for operator review, but remove
# every value now owned by a scoped file. No Compose service reads runtime.env.
awk -F= '
  /^[A-Za-z_][A-Za-z0-9_]*=/ &&
    ($1 ~ /^CLUSTER_[A-Z0-9_]+$/ ||
     $1 ~ /^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|REDIS_PASSWORD|NATS_AUTH_TOKEN|GF_SECURITY_ADMIN_USER|GF_SECURITY_ADMIN_PASSWORD)$/) { next }
  { print }
' "${runtime_env}" > "${stage}/runtime.env"
if [ ! -s "${stage}/runtime.env" ]; then
  printf '# Scoped values migrated; no Compose service consumes this file.\n' > \
    "${stage}/runtime.env"
fi

install_scoped_file() {
  name=$1
  staged="${stage}/${name}.env"
  target="${secret_root}/${name}.env"
  chmod 0600 "${staged}"
  [ "$(id -u)" -ne 0 ] || chown 0:0 "${staged}"
  mv -f -- "${staged}" "${target}"
}

# Build and validate every file before publishing any of them. runtime.env is
# replaced last, so interruption is safely recoverable by rerunning this script.
for name in api postgres redis nats grafana backup migrate; do
  install_scoped_file "${name}"
done
install_scoped_file runtime
