#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root so host packages and runtime permissions can be enforced." >&2
  exit 1
fi

architecture="$(uname -m)"
case "${architecture}" in
  aarch64|arm64) ;;
  *)
    echo "This deployment package targets an OCI ARM64 instance; found ${architecture}." >&2
    exit 1
    ;;
esac

if [ ! -r /etc/os-release ] || ! grep -q '^ID=ubuntu$' /etc/os-release; then
  echo "This bootstrap is supported on Ubuntu ARM64 only." >&2
  exit 1
fi

cpu_count="$(getconf _NPROCESSORS_ONLN)"
memory_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
if [ "${cpu_count}" -lt 2 ] || [ "${memory_kb}" -lt 10000000 ]; then
  echo "Use VM.Standard.A1.Flex with 2 OCPUs and 12 GB RAM or larger." >&2
  exit 1
fi

if [ "${CLIXOR_SKIP_PACKAGES:-false}" != "true" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install --yes --no-install-recommends \
    ca-certificates curl docker.io docker-buildx docker-compose-v2 openssl python3 rsync unzip util-linux
  unset DEBIAN_FRONTEND
fi
systemctl enable --now docker
docker compose version >/dev/null
docker buildx version >/dev/null

script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if ! command -v oci >/dev/null 2>&1; then
  [ "${CLIXOR_SKIP_PACKAGES:-false}" != "true" ] || {
    echo "OCI CLI is missing; run ${script_root}/install-oci-cli.sh before deploying." >&2
    exit 1
  }
  sh "${script_root}/install-oci-cli.sh"
fi

oci_backup_bucket=${CLIXOR_OCI_BACKUP_BUCKET:-clixor-prod-backups}
oci_backup_prefix=${CLIXOR_OCI_BACKUP_PREFIX:-clixor}
case "${oci_backup_bucket}" in
  ''|*[!A-Za-z0-9._-]*)
    echo "CLIXOR_OCI_BACKUP_BUCKET contains unsupported characters." >&2
    exit 1
    ;;
esac
case "${oci_backup_prefix}" in
  ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*)
    echo "CLIXOR_OCI_BACKUP_PREFIX contains unsupported characters." >&2
    exit 1
    ;;
esac
if [ "${#oci_backup_prefix}" -gt 63 ]; then
  echo "CLIXOR_OCI_BACKUP_PREFIX is longer than 63 characters." >&2
  exit 1
fi
backup_namespace="$(OCI_CLI_AUTH=instance_principal oci os ns get \
  --query data --raw-output)"
[ -n "${backup_namespace}" ] || {
  echo "Could not resolve the OCI Object Storage namespace for backups." >&2
  exit 1
}
OCI_CLI_AUTH=instance_principal oci os bucket get \
  --namespace-name "${backup_namespace}" \
  --name "${oci_backup_bucket}" >/dev/null || {
  echo "Instance principal cannot read OCI backup bucket ${oci_backup_bucket}." >&2
  exit 1
}

project_root=/srv/clixor
secret_root="${project_root}/secrets"
pki_root="${secret_root}/pki"
apns_root="${secret_root}/apns"
runtime_env="${secret_root}/runtime.env"
api_env="${secret_root}/api.env"
runtime_root="${project_root}/runtime"
backup_tool_root=/usr/local/libexec/clixor
backup_config_root=/etc/clixor
backup_config="${backup_config_root}/offsite-backup.env"
systemd_unit_root=/etc/systemd/system

install -d -m 0750 "${project_root}" "${project_root}/repo" \
  "${project_root}/releases" "${project_root}/data" "${runtime_root}" \
  "${project_root}/backups"
install -d -m 0700 -o 0 -g 0 "${project_root}/restore-drills"
install -d -m 0755 -o 0 -g 0 "${backup_tool_root}" "${backup_config_root}"
install -d -m 0700 -o 0 -g 0 "${secret_root}" "${pki_root}"
# The API image is distroless nonroot (UID/GID 65532). The mount root must be
# traversable and each installed key readable by that identity, but not by other
# host users.
install -d -m 0750 -o 0 -g 65532 "${apns_root}"

install -d -m 0750 -o 99 -g 99 "${runtime_root}/dependency-tls"
install -d -m 0750 -o 70 -g 70 "${runtime_root}/postgres-tls"
install -d -m 0750 -o 1000 -g 1000 "${runtime_root}/nats-tls"
install -d -m 0750 -o 101 -g 101 "${runtime_root}/api-gateway"
install -d -m 0750 -o 0 -g 0 "${runtime_root}/postgres-backup"
install -d -m 0750 -o 65534 -g 65534 "${runtime_root}/prometheus"
install -d -m 0750 -o 472 -g 472 "${runtime_root}/grafana"

for directory in postgres redis nats prometheus grafana; do
  install -d -m 0750 "${project_root}/data/${directory}"
done
install -d -m 0700 "${project_root}/backups/postgres"

if [ ! -s "${pki_root}/ca.crt" ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${pki_root}/ca.key"
  openssl req -x509 -new -sha256 -days 3650 \
    -key "${pki_root}/ca.key" \
    -subj "/CN=Clixor OCI Internal CA" \
    -out "${pki_root}/ca.crt"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${pki_root}/server.key"
  openssl req -new -sha256 \
    -key "${pki_root}/server.key" \
    -subj "/CN=clixor-tls" \
    -out "${pki_root}/server.csr"
  printf '%s\n' \
    "subjectAltName=DNS:clixor-tls,DNS:dependency-tls,DNS:postgres.clixor.internal,DNS:nats.clixor.internal" \
    "extendedKeyUsage=serverAuth" \
    "keyUsage=digitalSignature,keyEncipherment" > "${pki_root}/server.ext"
  openssl x509 -req -sha256 -days 825 \
    -in "${pki_root}/server.csr" \
    -CA "${pki_root}/ca.crt" \
    -CAkey "${pki_root}/ca.key" \
    -CAcreateserial \
    -extfile "${pki_root}/server.ext" \
    -out "${pki_root}/server.crt"
  {
    sed -n '1,$p' "${pki_root}/server.key"
    sed -n '1,$p' "${pki_root}/server.crt"
  } > "${pki_root}/server.pem"
  chmod 0600 "${pki_root}/ca.key" "${pki_root}/server.key" \
    "${pki_root}/server.pem"
  chmod 0644 "${pki_root}/ca.crt" "${pki_root}/server.crt"
fi

if [ ! -f "${runtime_env}" ]; then
  oci_namespace="$(OCI_CLI_AUTH=instance_principal oci os ns get --query data --raw-output)"
  oci_region="$(curl --fail --silent --show-error \
    --connect-timeout 5 --max-time 30 --retry 3 --retry-all-errors --retry-delay 1 \
    --header 'Authorization: Bearer Oracle' \
    http://169.254.169.254/opc/v2/instance/canonicalRegionName)"
  oci_region="$(printf '%s' "${oci_region}" | tr -d '[:space:]')"
  oci_media_bucket=${CLIXOR_OCI_MEDIA_BUCKET:-clixor-prod-media}
  [ -n "${oci_namespace}" ] || {
    echo "Could not resolve the OCI Object Storage namespace with instance principal." >&2
    exit 1
  }
  case "${oci_region}" in
    [a-z][a-z]-[a-z]*-[1-9]) ;;
    *)
      echo "Could not resolve the OCI region from instance metadata." >&2
      exit 1
      ;;
  esac
  case "${oci_media_bucket}" in
    ''|*[!A-Za-z0-9._-]*)
      echo "CLIXOR_OCI_MEDIA_BUCKET contains unsupported characters." >&2
      exit 1
      ;;
  esac
  OCI_CLI_AUTH=instance_principal oci os bucket get \
    --namespace-name "${oci_namespace}" \
    --name "${oci_media_bucket}" >/dev/null || {
    echo "Instance principal cannot read OCI media bucket ${oci_media_bucket}." >&2
    exit 1
  }

  postgres_password="$(openssl rand -hex 32)"
  redis_password="$(openssl rand -hex 32)"
  nats_token="$(openssl rand -hex 32)"
  jwt_secret="$(openssl rand -hex 48)"
  metrics_token="$(openssl rand -hex 48)"
  otp_hmac_secret="$(openssl rand -hex 48)"
  grafana_password="$(openssl rand -hex 24)"

  {
    printf 'POSTGRES_DB=clixor\n'
    printf 'POSTGRES_USER=clixor\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
    printf 'REDIS_PASSWORD=%s\n' "${redis_password}"
    printf 'NATS_AUTH_TOKEN=%s\n' "${nats_token}"
    printf 'GF_SECURITY_ADMIN_USER=clixoradmin\n'
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "${grafana_password}"
    printf 'CLUSTER_ENV=staging\n'
    printf 'CLUSTER_HTTP_ADDR=:8080\n'
    printf 'CLUSTER_PUBLIC_BASE_URL=https://clustr-api.atlanteanz.com\n'
    printf 'CLUSTER_TLS_CA_FILE=/run/pki/ca.crt\n'
    printf 'CLUSTER_STORE=postgres\n'
    printf 'CLUSTER_AUTO_MIGRATE=false\n'
    printf 'CLUSTER_DATABASE_URL=postgres://clixor:%s@postgres.clixor.internal:5432/clixor?sslmode=verify-full&sslrootcert=/run/pki/ca.crt\n' "${postgres_password}"
    printf 'CLUSTER_DATABASE_MAX_CONNS=12\n'
    printf 'CLUSTER_DATABASE_MIN_CONNS=2\n'
    printf 'CLUSTER_REDIS_URL=rediss://:%s@clixor-tls:6379/0\n' "${redis_password}"
    printf 'CLUSTER_NATS_URL=tls://%s@nats.clixor.internal:4222\n' "${nats_token}"
    printf 'CLUSTER_JWT_ACCESS_SECRET=%s\n' "${jwt_secret}"
    printf 'CLUSTER_METRICS_TOKEN=%s\n' "${metrics_token}"
    printf 'CLUSTER_OTP_HMAC_SECRET=%s\n' "${otp_hmac_secret}"
    printf 'CLUSTER_JWT_ISSUER=clixor-api\n'
    printf 'CLUSTER_ACCESS_TTL=15m\n'
    printf 'CLUSTER_REFRESH_TTL=720h\n'
    printf 'CLUSTER_MEDIA_PROVIDER=oci\n'
    printf 'CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE=%s\n' "${oci_namespace}"
    printf 'CLUSTER_OCI_OBJECT_STORAGE_BUCKET=%s\n' "${oci_media_bucket}"
    printf 'CLUSTER_OCI_OBJECT_STORAGE_REGION=%s\n' "${oci_region}"
    printf 'CLUSTER_VERIFICATION_PROVIDER=disabled\n'
    printf 'CLUSTER_OTP_CODE_LENGTH=6\n'
    printf 'CLUSTER_OTP_CHALLENGE_TTL=10m\n'
    printf 'CLUSTER_OTP_RESEND_COOLDOWN=1m\n'
    printf 'CLUSTER_OTP_LOCKOUT_TTL=15m\n'
    printf 'CLUSTER_OTP_MAX_ATTEMPTS=5\n'
    printf 'CLUSTER_OTP_PHONE_SEND_HOURLY=5\n'
    printf 'CLUSTER_OTP_PHONE_SEND_DAILY=10\n'
    printf 'CLUSTER_OTP_GLOBAL_SEND_MINUTE=60\n'
    printf 'CLUSTER_OTP_GLOBAL_SEND_DAILY=10000\n'
    printf 'CLUSTER_APPLE_CLIENT_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APNS_BUNDLE_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APNS_ENVIRONMENT=production\n'
  } > "${runtime_env}"
  chmod 0600 "${runtime_env}"
fi

# Split the legacy all-service environment into least-privilege service files.
# The helper publishes files atomically, is idempotent, and never evaluates or
# prints their values. runtime.env remains only as a non-consumed migration
# checkpoint for unknown legacy entries.
sh "${script_root}/split-runtime-secrets.sh" "${runtime_env}" "${secret_root}"

metrics_token="$(sed -n 's/^CLUSTER_METRICS_TOKEN=//p' "${api_env}" | tail -n 1)"
[ -n "${metrics_token}" ] || {
  echo "CLUSTER_METRICS_TOKEN is missing from ${api_env}." >&2
  exit 1
}
printf '%s' "${metrics_token}" > "${runtime_root}/prometheus/metrics.token"

install -m 0400 -o 99 -g 99 "${pki_root}/server.pem" \
  "${runtime_root}/dependency-tls/server.pem"
install -m 0400 -o 99 -g 99 "${script_root}/haproxy.cfg" \
  "${runtime_root}/dependency-tls/haproxy.cfg"
install -m 0400 -o 70 -g 70 "${pki_root}/server.key" \
  "${runtime_root}/postgres-tls/server.key"
install -m 0444 -o 70 -g 70 "${pki_root}/server.crt" \
  "${runtime_root}/postgres-tls/server.crt"
install -m 0400 -o 1000 -g 1000 "${pki_root}/server.key" \
  "${runtime_root}/nats-tls/server.key"
install -m 0444 -o 1000 -g 1000 "${pki_root}/server.crt" \
  "${runtime_root}/nats-tls/server.crt"
install -m 0400 -o 101 -g 101 "${script_root}/api-gateway-nginx.conf" \
  "${runtime_root}/api-gateway/nginx.conf"
install -m 0500 -o 0 -g 0 "${script_root}/backup.sh" \
  "${runtime_root}/postgres-backup/backup.sh"
install -m 0500 -o 0 -g 0 "${script_root}/offsite-backup.sh" \
  "${backup_tool_root}/offsite-backup.sh"
install -m 0500 -o 0 -g 0 "${script_root}/backup-health.sh" \
  "${backup_tool_root}/backup-health.sh"
install -m 0500 -o 0 -g 0 "${script_root}/restore-drill.sh" \
  "${backup_tool_root}/restore-drill.sh"
install -m 0500 -o 0 -g 0 "${script_root}/backup_manifest.py" \
  "${backup_tool_root}/backup_manifest.py"
for unit_name in \
  clixor-offsite-backup.service \
  clixor-offsite-backup.timer \
  clixor-backup-health.service \
  clixor-backup-health.timer \
  clixor-restore-drill.service \
  clixor-restore-drill.timer
do
  install -m 0644 -o 0 -g 0 "${script_root}/${unit_name}" \
    "${systemd_unit_root}/${unit_name}"
done
backup_config_partial="$(mktemp "${backup_config_root}/offsite-backup.env.XXXXXXXX")"
{
  printf 'OCI_BACKUP_BUCKET=%s\n' "${oci_backup_bucket}"
  printf 'OCI_BACKUP_PREFIX=%s\n' "${oci_backup_prefix}"
} > "${backup_config_partial}"
chmod 0600 "${backup_config_partial}"
chown 0:0 "${backup_config_partial}"
mv "${backup_config_partial}" "${backup_config}"
install -m 0400 -o 65534 -g 65534 "${script_root}/prometheus.yml" \
  "${runtime_root}/prometheus/prometheus.yml"
chown 65534:65534 "${runtime_root}/prometheus/metrics.token"
chmod 0400 "${runtime_root}/prometheus/metrics.token"
install -m 0400 -o 472 -g 472 "${script_root}/grafana-datasource.yml" \
  "${runtime_root}/grafana/datasource.yml"

for apns_key in "${apns_root}"/*.p8; do
  [ -f "${apns_key}" ] || continue
  chown 0:65532 "${apns_key}"
  chmod 0440 "${apns_key}"
done

# Only establish mount-root ownership. Recursively walking a live database
# during every release is both slow and unnecessary.
chown 70:70 "${project_root}/data/postgres"
chown 999:1000 "${project_root}/data/redis"
chown 1000:1000 "${project_root}/data/nats"
chown 65534:65534 "${project_root}/data/prometheus"
chown 472:472 "${project_root}/data/grafana"
chmod 0600 "${runtime_env}"
for scoped_env in api postgres redis nats grafana backup migrate; do
  chmod 0600 "${secret_root}/${scoped_env}.env"
done
chmod 0750 "${apns_root}"

for required_path in \
  "${runtime_env}" \
  "${api_env}" \
  "${secret_root}/postgres.env" \
  "${secret_root}/redis.env" \
  "${secret_root}/nats.env" \
  "${secret_root}/grafana.env" \
  "${secret_root}/backup.env" \
  "${secret_root}/migrate.env" \
  "${pki_root}/ca.crt" \
  "${runtime_root}/dependency-tls/haproxy.cfg" \
  "${runtime_root}/api-gateway/nginx.conf"
do
  [ -s "${required_path}" ] || {
    echo "Missing OCI runtime file: ${required_path}" >&2
    exit 1
  }
done

systemctl daemon-reload
systemctl enable --now clixor-offsite-backup.timer
if [ -s "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" ]; then
  systemctl enable --now clixor-restore-drill.timer clixor-backup-health.timer
else
  # deploy.sh performs the first offsite restore drill as a release gate. Never
  # report backup health or schedule later drills before that gate has passed.
  systemctl disable --now clixor-restore-drill.timer clixor-backup-health.timer \
    >/dev/null 2>&1 || true
fi

echo "Clixor OCI ARM64 directories, staging secrets, and internal PKI are ready."
echo "Telnyx and APNs remain disabled until production credentials are installed."
