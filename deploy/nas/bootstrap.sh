#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root so secret and data permissions can be enforced." >&2
  exit 1
fi

project_root=/volume1/docker/clustr
secret_root="${project_root}/secrets"
pki_root="${secret_root}/pki"
runtime_env="${secret_root}/runtime.env"
runtime_tls_root="${project_root}/runtime/dependency-tls"
runtime_postgres_root="${project_root}/runtime/postgres-tls"
runtime_nats_root="${project_root}/runtime/nats-tls"
deployment_source="${project_root}/repo/deploy/nas"
runtime_media_root="${project_root}/runtime/media"
runtime_backup_root="${project_root}/runtime/postgres-backup"
runtime_prometheus_root="${project_root}/runtime/prometheus"
runtime_grafana_root="${project_root}/runtime/grafana"

install -d -m 0750 "${project_root}/data" "${project_root}/runtime" "${project_root}/backups"
install -d -m 0700 "${secret_root}" "${pki_root}" "${secret_root}/apns"
install -d -m 0750 -o 99 -g 99 "${runtime_tls_root}"
install -d -m 0750 -o 70 -g 70 "${runtime_postgres_root}"
install -d -m 0750 -o 1000 -g 1000 "${runtime_nats_root}"
install -d -m 0750 -o 101 -g 101 "${runtime_media_root}"
install -d -m 0750 -o 0 -g 0 "${runtime_backup_root}"
install -d -m 0750 -o 65534 -g 65534 "${runtime_prometheus_root}"
install -d -m 0750 -o 472 -g 472 "${runtime_grafana_root}"
for directory in postgres redis nats minio prometheus grafana; do
  install -d -m 0750 "${project_root}/data/${directory}"
done
install -d -m 0750 "${project_root}/backups/postgres"

umask 077

if [ ! -f "${pki_root}/ca.crt" ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${pki_root}/ca.key"
  openssl req -x509 -new -sha256 -days 3650 \
    -key "${pki_root}/ca.key" \
    -subj "/CN=Clustr NAS Internal CA" \
    -out "${pki_root}/ca.crt"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${pki_root}/server.key"
  openssl req -new -sha256 \
    -key "${pki_root}/server.key" \
    -subj "/CN=clustr-tls" \
    -out "${pki_root}/server.csr"
  printf '%s\n' \
    "subjectAltName=DNS:clustr-tls,DNS:clustr-dependency-tls,DNS:postgres.clustr.internal,DNS:redis.clustr.internal,DNS:nats.clustr.internal,DNS:minio.clustr.internal" \
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
  chmod 0600 "${pki_root}/ca.key" "${pki_root}/server.key" "${pki_root}/server.pem"
  chmod 0644 "${pki_root}/ca.crt" "${pki_root}/server.crt"
fi

if [ ! -f "${runtime_env}" ]; then
  postgres_password="$(openssl rand -hex 32)"
  redis_password="$(openssl rand -hex 32)"
  nats_token="$(openssl rand -hex 32)"
  minio_password="$(openssl rand -hex 32)"
  jwt_secret="$(openssl rand -hex 48)"
  metrics_token="$(openssl rand -hex 48)"
  otp_hmac_secret="$(openssl rand -hex 48)"
  grafana_password="$(openssl rand -hex 24)"

  {
    printf 'POSTGRES_DB=clustr\n'
    printf 'POSTGRES_USER=clustr\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
    printf 'REDIS_PASSWORD=%s\n' "${redis_password}"
    printf 'NATS_AUTH_TOKEN=%s\n' "${nats_token}"
    printf 'MINIO_ROOT_USER=clustradmin\n'
    printf 'MINIO_ROOT_PASSWORD=%s\n' "${minio_password}"
    printf 'GF_SECURITY_ADMIN_USER=clustradmin\n'
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "${grafana_password}"
    printf 'CLUSTER_ENV=staging\n'
    printf 'CLUSTER_HTTP_ADDR=:8080\n'
    printf 'CLUSTER_PUBLIC_BASE_URL=https://clustr-api.atlanteanz.com\n'
    printf 'CLUSTER_TLS_CA_FILE=/run/pki/ca.crt\n'
    printf 'CLUSTER_STORE=postgres\n'
    printf 'CLUSTER_AUTO_MIGRATE=false\n'
    printf 'CLUSTER_DATABASE_URL=postgres://clustr:%s@postgres.clustr.internal:5432/clustr?sslmode=verify-full&sslrootcert=/run/pki/ca.crt\n' "${postgres_password}"
    printf 'CLUSTER_REDIS_URL=rediss://:%s@clustr-tls:6379/0\n' "${redis_password}"
    printf 'CLUSTER_NATS_URL=tls://%s@nats.clustr.internal:4222\n' "${nats_token}"
    printf 'CLUSTER_JWT_ACCESS_SECRET=%s\n' "${jwt_secret}"
    printf 'CLUSTER_METRICS_TOKEN=%s\n' "${metrics_token}"
    printf 'CLUSTER_OTP_HMAC_SECRET=%s\n' "${otp_hmac_secret}"
    printf 'CLUSTER_JWT_ISSUER=clustr-api\n'
    printf 'CLUSTER_ACCESS_TTL=15m\n'
    printf 'CLUSTER_REFRESH_TTL=720h\n'
    printf 'CLUSTER_S3_ENDPOINT=clustr-tls:9000\n'
    printf 'CLUSTER_S3_PUBLIC_ENDPOINT=clustr-media.atlanteanz.com\n'
    printf 'CLUSTER_S3_ACCESS_KEY=clustradmin\n'
    printf 'CLUSTER_S3_SECRET_KEY=%s\n' "${minio_password}"
    printf 'CLUSTER_S3_BUCKET=clustr-media\n'
    printf 'CLUSTER_S3_USE_TLS=true\n'
    printf 'CLUSTER_VERIFICATION_PROVIDER=disabled\n'
    printf 'CLUSTER_APNS_BUNDLE_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APPLE_CLIENT_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APNS_ENVIRONMENT=production\n'
  } > "${runtime_env}"
  printf '%s' "${metrics_token}" > "${secret_root}/metrics.token"
  chmod 0600 "${runtime_env}" "${secret_root}/metrics.token"
fi

# Existing installations predate the self-hosted OTP engine. Add its independent
# HMAC key without changing the disabled provider or printing the generated value.
if ! grep -q '^CLUSTER_OTP_HMAC_SECRET=' "${runtime_env}"; then
  otp_hmac_secret="$(openssl rand -hex 48)"
  printf 'CLUSTER_OTP_HMAC_SECRET=%s\n' "${otp_hmac_secret}" >> "${runtime_env}"
  chmod 0600 "${runtime_env}"
fi

sed -i 's/@clustr-tls:5432/@postgres.clustr.internal:5432/' "${runtime_env}"
sed -i 's/@clustr-tls:4222/@nats.clustr.internal:4222/' "${runtime_env}"
install -m 0400 -o 99 -g 99 "${pki_root}/server.pem" "${runtime_tls_root}/server.pem"
install -m 0400 -o 99 -g 99 "${deployment_source}/haproxy.cfg" "${runtime_tls_root}/haproxy.cfg"
install -m 0400 -o 70 -g 70 "${pki_root}/server.key" "${runtime_postgres_root}/server.key"
install -m 0444 -o 70 -g 70 "${pki_root}/server.crt" "${runtime_postgres_root}/server.crt"
install -m 0400 -o 1000 -g 1000 "${pki_root}/server.key" "${runtime_nats_root}/server.key"
install -m 0444 -o 1000 -g 1000 "${pki_root}/server.crt" "${runtime_nats_root}/server.crt"
install -m 0400 -o 101 -g 101 "${deployment_source}/media-nginx.conf" "${runtime_media_root}/nginx.conf"
install -m 0500 -o 0 -g 0 "${deployment_source}/backup.sh" "${runtime_backup_root}/backup.sh"
install -m 0400 -o 65534 -g 65534 "${deployment_source}/prometheus.yml" "${runtime_prometheus_root}/prometheus.yml"
install -m 0400 -o 65534 -g 65534 "${secret_root}/metrics.token" "${runtime_prometheus_root}/metrics.token"
install -m 0400 -o 472 -g 472 "${deployment_source}/grafana-datasource.yml" "${runtime_grafana_root}/datasource.yml"

chown -R 70:70 "${project_root}/data/postgres"
chown -R 999:1000 "${project_root}/data/redis"
chown -R 1000:1000 "${project_root}/data/nats" "${project_root}/data/minio"
chown -R 65534:65534 "${project_root}/data/prometheus"
chown -R 472:472 "${project_root}/data/grafana"
chmod 0700 "${secret_root}"

echo "Clustr NAS directories, internal PKI, and runtime secrets are ready."
