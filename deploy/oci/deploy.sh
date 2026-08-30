#!/bin/sh
set -eu
umask 077

project_root=/srv/clixor
stable_root="${project_root}/repo"
release_root="${project_root}/releases"
runtime_env="${project_root}/secrets/runtime.env"
api_env="${project_root}/secrets/api.env"
postgres_env="${project_root}/secrets/postgres.env"
redis_env="${project_root}/secrets/redis.env"
nats_env="${project_root}/secrets/nats.env"
grafana_env="${project_root}/secrets/grafana.env"
backup_env="${project_root}/secrets/backup.env"
migrate_env="${project_root}/secrets/migrate.env"
lock_file="${project_root}/runtime/deploy.lock"
compose_file="${stable_root}/deploy/oci/compose.yaml"
pki_desired="${project_root}/runtime/dependency-pki.desired"
pki_applied="${project_root}/runtime/dependency-pki.applied"
gateway_readiness_url=http://172.30.254.2:8080/health/ready
public_api_readiness_url=https://clustr-api.atlanteanz.com/health/ready
public_association_url=https://clixor.atlanteanz.com/.well-known/apple-app-site-association
public_smoke_mode=${CLIXOR_REQUIRE_PUBLIC_SMOKE:-auto}
source_root=${1:-}
source_sha=${2:-}
run_id=${3:-manual}

log() {
  printf '[clixor-oci-deploy] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

case "${public_smoke_mode}" in
  auto|true|false) ;;
  *) fail "CLIXOR_REQUIRE_PUBLIC_SMOKE must be auto, true, or false" ;;
esac
public_smoke_required=false
[ "${public_smoke_mode}" = "true" ] && public_smoke_required=true

verify_public_ingress() {
  log "verifying public Cloudflare ingress before release finalization"
  curl --fail --silent --show-error --retry 12 --retry-all-errors \
    --retry-delay 5 --max-time 10 "${public_api_readiness_url}" >/dev/null
  curl --fail --silent --show-error --retry 6 --retry-all-errors \
    --retry-delay 5 --max-time 10 --header 'Cache-Control: no-cache' \
    "${public_association_url}" >/dev/null
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "${source_root}" ] || fail "source workspace argument is required"
[ -f "${source_root}/go.mod" ] || fail "source workspace does not contain go.mod"
[ -f "${source_root}/deploy/oci/compose.yaml" ] || fail "source workspace does not contain the OCI Compose model"
grep -q '^module github.com/Akhilmadineni/clixor-backend$' "${source_root}/go.mod" || \
  fail "unexpected Go module"

case "${source_sha}" in
  ''|*[!0-9a-f]*) fail "source revision must be a lowercase Git object ID" ;;
esac
[ "${#source_sha}" -ge 12 ] || fail "source revision is too short"
case "${run_id}" in
  *[!A-Za-z0-9._-]*) fail "run ID contains unsupported characters" ;;
esac

for command_name in cmp curl docker find flock install python3 rsync sha256sum systemctl touch; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done
docker buildx version >/dev/null 2>&1 || fail "missing Docker Buildx plugin"

mkdir -p "${project_root}/runtime"
exec 9>"${lock_file}"
flock -n 9 || fail "another deployment holds ${lock_file}"

# Detect containers created by the retired all-secrets Compose model without
# printing their environments. Docker stores container configuration immutably,
# so changing files alone is insufficient: affected containers must be replaced
# once to remove API/provider credentials from docker inspect.
legacy_dependency_scope=false
legacy_grafana_scope=false
prometheus_was_running=false
grafana_was_running=false
[ "$(docker inspect clixor-oci-prometheus --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] && \
  prometheus_was_running=true
[ "$(docker inspect clixor-oci-grafana --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] && \
  grafana_was_running=true
for container_name in \
  clixor-oci-postgres clixor-oci-redis clixor-oci-nats \
  clixor-oci-grafana
do
  if docker inspect "${container_name}" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | \
    grep -q '^CLUSTER_'; then
    case "${container_name}" in
      clixor-oci-postgres|clixor-oci-redis|clixor-oci-nats)
        legacy_dependency_scope=true
        ;;
      clixor-oci-grafana)
        legacy_grafana_scope=true
        ;;
    esac
  fi
done

release_tag="oci-$(printf '%s' "${source_sha}" | cut -c1-12)-${run_id}"
release_dir="${release_root}/${release_tag}"
previous_compose="${release_dir}/previous-compose.yaml"
rollback_compose="${previous_compose}"
scoped_rollback_compose="${release_dir}/scoped-rollback-compose.yaml"
previous_runtime_root="${release_dir}/previous-runtime"
pre_migration_dump="${release_dir}/pre-migration.dump"
new_image="clixor-api:${release_tag}"

mkdir -p "${stable_root}" "${release_root}" "${project_root}/runtime"
[ ! -e "${release_dir}" ] || fail "release directory already exists: ${release_dir}"
mkdir "${release_dir}"
chmod 0700 "${release_dir}"

previous_image="$(docker inspect clixor-oci-api-a --format '{{.Config.Image}}' 2>/dev/null || true)"
previous_postgres_id="$(docker inspect clixor-oci-postgres --format '{{.Id}}' 2>/dev/null || true)"
previous_release="$(readlink "${release_root}/current" 2>/dev/null || true)"
first_deploy=false
previous_compose_uses_scoped=false

if [ -z "${previous_image}" ] && [ ! -e "${compose_file}" ] && [ -z "${previous_postgres_id}" ]; then
  first_deploy=true
  log "no previous OCI application state found; preparing a first deployment"
else
  [ -n "${previous_image}" ] || \
    fail "partial previous deployment: clixor-oci-api-a has no image"
  case "${previous_image}" in
    clixor-api:*) ;;
    *) fail "previous API image is outside the clixor-api repository" ;;
  esac
  docker image inspect "${previous_image}" >/dev/null 2>&1 || \
    fail "previous API image is unavailable for rollback: ${previous_image}"
  [ -s "${compose_file}" ] || \
    fail "partial previous deployment: stable Compose model is missing"
  [ -n "${previous_postgres_id}" ] || \
    fail "partial previous deployment: PostgreSQL container is missing"
  [ "$(docker inspect clixor-oci-postgres --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] || \
    fail "existing PostgreSQL is not running; repair it before deployment"

  cp "${compose_file}" "${previous_compose}"
  [ -s "${previous_compose}" ] || fail "captured previous Compose model is empty"
  if grep -q '/srv/clixor/secrets/api.env' "${previous_compose}"; then
    previous_compose_uses_scoped=true
  fi

  log "capturing a pre-change PostgreSQL snapshot"
  docker exec clixor-oci-postgres sh -ec \
    'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
    > "${pre_migration_dump}.partial"
  [ -s "${pre_migration_dump}.partial" ] || fail "pre-change PostgreSQL snapshot is empty"
  docker exec -i clixor-oci-postgres pg_restore --list \
    < "${pre_migration_dump}.partial" >/dev/null || \
    fail "pre-change PostgreSQL snapshot failed archive validation"
  chmod 0600 "${pre_migration_dump}.partial"
  mv "${pre_migration_dump}.partial" "${pre_migration_dump}"
  (
    cd "${release_dir}"
    sha256sum "$(basename -- "${pre_migration_dump}")" > \
      "$(basename -- "${pre_migration_dump}").sha256.partial"
    sha256sum --check "$(basename -- "${pre_migration_dump}").sha256.partial" \
      >/dev/null
    chmod 0600 "$(basename -- "${pre_migration_dump}").sha256.partial"
    mv "$(basename -- "${pre_migration_dump}").sha256.partial" \
      "$(basename -- "${pre_migration_dump}").sha256"
  )

  # If bootstrap completes the one-time least-privilege secret split, rollback
  # must use this reviewed, digest-pinned Compose model with the prior API image.
  # Until the split commits, the captured prior Compose remains authoritative.
  cp "${source_root}/deploy/oci/compose.yaml" "${scoped_rollback_compose}"
  [ -s "${scoped_rollback_compose}" ] || \
    fail "scoped rollback Compose model is empty"

  # Ordinary bind-mounted file contents are outside Compose's state model. Keep
  # the exact active copies so a public-smoke or later gate failure can restore
  # both the prior image and the configuration processes parsed at startup.
  install -d -m 0700 -o 0 -g 0 \
    "${previous_runtime_root}/dependency-tls" \
    "${previous_runtime_root}/api-gateway" \
    "${previous_runtime_root}/postgres-backup"
  for runtime_config in \
    dependency-tls/haproxy.cfg \
    api-gateway/nginx.conf \
    postgres-backup/backup.sh
  do
    [ -s "${project_root}/runtime/${runtime_config}" ] || \
      fail "active runtime configuration is missing: ${runtime_config}"
    install -m 0600 -o 0 -g 0 \
      "${project_root}/runtime/${runtime_config}" \
      "${previous_runtime_root}/${runtime_config}"
  done
  if [ "${prometheus_was_running}" = "true" ]; then
    install -d -m 0700 -o 0 -g 0 "${previous_runtime_root}/prometheus"
    install -m 0600 -o 0 -g 0 \
      "${project_root}/runtime/prometheus/prometheus.yml" \
      "${previous_runtime_root}/prometheus/prometheus.yml"
  fi
  if [ "${grafana_was_running}" = "true" ]; then
    install -d -m 0700 -o 0 -g 0 "${previous_runtime_root}/grafana"
    install -m 0600 -o 0 -g 0 \
      "${project_root}/runtime/grafana/datasource.yml" \
      "${previous_runtime_root}/grafana/datasource.yml"
  fi
fi
printf '%s\n' "${source_sha}" > "${release_dir}/source-sha"
if [ "${first_deploy}" = "true" ]; then
  printf 'first-deploy\n' > "${release_dir}/deployment-kind"
  printf 'none\n' > "${release_dir}/previous-image"
  printf 'none\n' > "${release_dir}/previous-release"
else
  printf 'upgrade\n' > "${release_dir}/deployment-kind"
  printf '%s\n' "${previous_image}" > "${release_dir}/previous-image"
  printf '%s\n' "${previous_release:-unrecorded}" > "${release_dir}/previous-release"
fi

rollback_needed=0
scoped_runtime_ready() {
  [ -f "${runtime_env}" ] && [ ! -L "${runtime_env}" ] || return 1
  for scoped_env in \
    "${api_env}" "${postgres_env}" "${redis_env}" "${nats_env}" \
    "${grafana_env}" "${backup_env}" "${migrate_env}"
  do
    [ -f "${scoped_env}" ] && [ ! -L "${scoped_env}" ] && [ -s "${scoped_env}" ] || \
      return 1
  done
  ! grep -Eq '^(CLUSTER_[A-Z0-9_]+|POSTGRES_(DB|USER|PASSWORD)|REDIS_PASSWORD|NATS_AUTH_TOKEN|GF_SECURITY_ADMIN_(USER|PASSWORD))=' \
    "${runtime_env}"
}

rollback() {
  status=$?
  trap - 0
  if [ "${status}" -ne 0 ] && [ "${rollback_needed}" -eq 1 ]; then
    set +e
    if [ "${first_deploy}" = "false" ]; then
      log "deployment failed; attempting application rollback to ${previous_image}"
      selected_rollback_compose="${rollback_compose}"
      if [ "${previous_compose_uses_scoped}" = "false" ] && scoped_runtime_ready; then
        selected_rollback_compose="${scoped_rollback_compose}"
      fi
      rollback_failed=0
      if [ ! -s "${selected_rollback_compose}" ]; then
        log "ERROR: rollback Compose model is unavailable" >&2
        rollback_failed=1
      fi
      if [ "${rollback_failed}" -eq 0 ]; then
        if ! install -m 0400 -o 99 -g 99 \
          "${previous_runtime_root}/dependency-tls/haproxy.cfg" \
          "${project_root}/runtime/dependency-tls/haproxy.cfg" || \
          ! install -m 0400 -o 101 -g 101 \
          "${previous_runtime_root}/api-gateway/nginx.conf" \
          "${project_root}/runtime/api-gateway/nginx.conf" || \
          ! install -m 0500 -o 0 -g 0 \
          "${previous_runtime_root}/postgres-backup/backup.sh" \
          "${project_root}/runtime/postgres-backup/backup.sh"; then
          log "ERROR: could not restore prior runtime configuration" >&2
          rollback_failed=1
        fi
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${prometheus_was_running}" = "true" ] && \
        ! install -m 0400 -o 65534 -g 65534 \
          "${previous_runtime_root}/prometheus/prometheus.yml" \
          "${project_root}/runtime/prometheus/prometheus.yml"; then
        log "ERROR: could not restore prior Prometheus configuration" >&2
        rollback_failed=1
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${grafana_was_running}" = "true" ] && \
        ! install -m 0400 -o 472 -g 472 \
          "${previous_runtime_root}/grafana/datasource.yml" \
          "${project_root}/runtime/grafana/datasource.yml"; then
        log "ERROR: could not restore prior Grafana configuration" >&2
        rollback_failed=1
      fi
      previous_tag=${previous_image#clixor-api:}
      if [ "${rollback_failed}" -eq 0 ]; then
        if ! cp "${selected_rollback_compose}" "${compose_file}" || \
          ! cmp -s "${selected_rollback_compose}" "${compose_file}"; then
          log "ERROR: could not restore the rollback Compose model" >&2
          rollback_failed=1
        fi
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        ! CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
          --file "${compose_file}" up -d --no-build --remove-orphans; then
        log "ERROR: rollback Compose reconciliation failed" >&2
        rollback_failed=1
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        ! CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
          --file "${compose_file}" up -d --no-build --no-deps --force-recreate \
          dependency-tls api-gateway postgres-backup; then
        log "ERROR: rollback configuration consumers did not restart" >&2
        rollback_failed=1
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${prometheus_was_running}" = "true" ] && \
        ! CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
          --file "${compose_file}" --profile observability up -d --no-build \
          --no-deps --force-recreate prometheus; then
        log "ERROR: rollback Prometheus did not restart" >&2
        rollback_failed=1
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${grafana_was_running}" = "true" ] && \
        ! CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
          --file "${compose_file}" --profile observability up -d --no-build \
          --no-deps --force-recreate grafana; then
        log "ERROR: rollback Grafana did not restart" >&2
        rollback_failed=1
      fi

      for replica in clixor-oci-api-a clixor-oci-api-b; do
        actual_image="$(docker inspect "${replica}" \
          --format '{{.Config.Image}}' 2>/dev/null || true)"
        if [ "${actual_image}" != "${previous_image}" ]; then
          log "ERROR: ${replica} did not restore the prior API image" >&2
          rollback_failed=1
        fi
      done

      rollback_attempt=1
      rollback_ready=false
      if [ "${rollback_failed}" -eq 0 ]; then
        until curl --fail --silent --show-error --max-time 5 \
          "${gateway_readiness_url}" >/dev/null; do
          if [ "${rollback_attempt}" -ge 30 ]; then
            break
          fi
          rollback_attempt=$((rollback_attempt + 1))
          sleep 2
        done
        if curl --fail --silent --show-error --max-time 5 \
          "${gateway_readiness_url}" >/dev/null; then
          rollback_ready=true
        fi
      fi
      if [ "${rollback_failed}" -eq 0 ] && [ "${rollback_ready}" = "true" ]; then
        log "application rollback completed; database migrations were not reversed"
      else
        log "ERROR: application rollback did not restore and verify the prior release" >&2
      fi
    else
      log "first deployment failed; stopping the incomplete application stack"
      if [ -s "${compose_file}" ]; then
        CLIXOR_IMAGE_TAG="${release_tag}" docker compose \
          --file "${compose_file}" down --remove-orphans
        rm -f -- "${compose_file}"
      fi
      log "first-deploy cleanup completed; database files and forward migrations were not restored or deleted"
    fi
  fi
  exit "${status}"
}
trap rollback 0
trap 'exit 130' INT
trap 'exit 143' TERM

log "building ARM64 release ${new_image}"
docker buildx build --load \
  --pull \
  --label "org.opencontainers.image.revision=${source_sha}" \
  --label "org.opencontainers.image.source=https://github.com/Akhilmadineni/clixor-backend" \
  --tag "${new_image}" \
  "${source_root}"
image_architecture="$(docker image inspect "${new_image}" --format '{{.Architecture}}')"
[ "${image_architecture}" = "arm64" ] || fail "built ${image_architecture}, expected arm64"

# Everything below can mutate the active runtime. Arm application rollback
# before refreshing configuration, syncing Compose, reconciling dependencies,
# or running a forward migration. The captured dump is for operator recovery;
# this script never restores it automatically.
rollback_needed=1

# Idempotently refresh permissions, certificates and checked-in runtime config.
# Package installation belongs to the explicit first bootstrap, not every deploy.
CLIXOR_SKIP_PACKAGES=true sh "${source_root}/deploy/oci/bootstrap.sh"
for scoped_env in \
  "${api_env}" "${postgres_env}" "${redis_env}" "${nats_env}" \
  "${grafana_env}" "${backup_env}" "${migrate_env}"
do
  [ -s "${scoped_env}" ] || fail "scoped configuration is missing"
done
if grep -Eiq 'REPLACE_(WITH|ME)|replace-with' \
  "${api_env}" "${postgres_env}" "${redis_env}" "${nats_env}" \
  "${grafana_env}" "${backup_env}" "${migrate_env}"; then
  fail "runtime configuration still contains a placeholder"
fi
if grep -Eq '^(CLUSTER_[A-Z0-9_]+|POSTGRES_(DB|USER|PASSWORD)|REDIS_PASSWORD|NATS_AUTH_TOKEN|GF_SECURITY_ADMIN_(USER|PASSWORD))=' "${runtime_env}"; then
  fail "legacy runtime.env still contains a scoped credential"
fi
for required_key in \
  CLUSTER_MAIL_PROVIDER \
  CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY \
  CLUSTER_PASSWORD_RESET_HMAC_SECRET
do
  grep -Eq "^${required_key}=.+" "${api_env}" || \
    fail "API-only configuration is missing ${required_key}"
done
grep -q '^CLUSTER_MEDIA_PROVIDER=oci$' "${api_env}" || \
  fail "OCI deployment requires CLUSTER_MEDIA_PROVIDER=oci"
for required_key in \
  CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE \
  CLUSTER_OCI_OBJECT_STORAGE_BUCKET \
  CLUSTER_OCI_OBJECT_STORAGE_REGION
do
  grep -Eq "^${required_key}=.+" "${api_env}" || \
    fail "runtime configuration is missing ${required_key}"
done
if [ "${public_smoke_mode}" = "auto" ] && \
  grep -qx 'CLUSTER_ENV=production' "${api_env}"; then
  public_smoke_required=true
fi
[ -s "${pki_desired}" ] || fail "desired dependency PKI state is missing"
install -m 0600 -o 0 -g 0 "${pki_desired}" \
  "${release_dir}/dependency-pki.desired"
pki_restart_services="$(python3 "${source_root}/deploy/oci/dependency_pki.py" \
  pending-restarts \
  --desired "${release_dir}/dependency-pki.desired" \
  --applied "${pki_applied}")"

log "syncing the approved revision into ${stable_root}"
rsync -a --delete \
  --exclude='/.git/' \
  --exclude='/.DS_Store' \
  --exclude='/.build/' \
  --exclude='/coverage.out' \
  "${source_root}/" "${stable_root}/"

CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" config --quiet
for dependency_service in ${pki_restart_services}; do
  case "${dependency_service}" in
    postgres|nats|dependency-tls) ;;
    *) fail "dependency PKI requested an unexpected service restart" ;;
  esac
done

for dependency_service in postgres redis nats; do
  recreate_dependency=false
  if [ "${legacy_dependency_scope}" = "true" ]; then
    recreate_dependency=true
  fi
  case " ${pki_restart_services} " in
    *" ${dependency_service} "*) recreate_dependency=true ;;
  esac
  if [ "${recreate_dependency}" = "true" ]; then
    log "recreating ${dependency_service} for scoped secrets or its new TLS leaf"
    CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
      up -d --no-build --no-deps --force-recreate "${dependency_service}"
  else
    CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
      up -d --no-build --no-deps "${dependency_service}"
  fi
done

for dependency_container in clixor-oci-postgres clixor-oci-redis clixor-oci-nats; do
  attempt=1
  while :; do
    health_status="$(docker inspect "${dependency_container}" \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      2>/dev/null || true)"
    [ "${health_status}" = "healthy" ] && break
    case "${health_status}" in
      exited|dead) fail "${dependency_container} stopped while waiting for health" ;;
    esac
    [ "${attempt}" -lt 60 ] || fail "${dependency_container} did not become healthy"
    attempt=$((attempt + 1))
    sleep 2
  done
done

# HAProxy reads both its mounted configuration and certificate only at process
# start. Compose tracks the bind path, not file contents, so every release must
# replace this small stateless proxy even when the leaf digest is unchanged.
log "recreating dependency-tls to apply its reviewed configuration and Redis TLS leaf"
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
  up -d --no-build --no-deps --force-recreate dependency-tls

attempt=1
while :; do
  health_status="$(docker inspect clixor-oci-dependency-tls \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
    2>/dev/null || true)"
  [ "${health_status}" = "healthy" ] && break
  case "${health_status}" in
    exited|dead) fail "dependency-tls stopped while waiting for health" ;;
  esac
  [ "${attempt}" -lt 60 ] || fail "dependency-tls did not become healthy"
  attempt=$((attempt + 1))
  sleep 2
done

if [ "${first_deploy}" = "true" ]; then
  [ "$(docker inspect clixor-oci-postgres --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] || \
    fail "first-deploy PostgreSQL did not become healthy"
else
  [ -s "${pre_migration_dump}" ] || \
    fail "pre-change PostgreSQL snapshot disappeared before migration"
fi

log "applying transactional forward migrations"
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
  --profile migration run --rm migrate

CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" up -d --no-build \
  api-a api-b
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" up -d --no-build \
  --remove-orphans

# Nginx, Prometheus, and Grafana read their bind-mounted configuration only at
# process start. Preserve the operator's observability run/stop state while
# guaranteeing that every running consumer uses this exact release's files.
log "recreating api-gateway to apply the reviewed ingress configuration"
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
  up -d --no-build --no-deps --force-recreate api-gateway
if [ "${prometheus_was_running}" = "true" ]; then
  log "recreating running Prometheus to apply the reviewed scrape configuration"
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
    --profile observability up -d --no-build --no-deps --force-recreate prometheus
fi
if [ "${grafana_was_running}" = "true" ]; then
  log "recreating running Grafana to apply its reviewed provisioning configuration"
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
    --profile observability up -d --no-build --no-deps --force-recreate grafana
elif [ "${legacy_grafana_scope}" = "true" ] && \
  docker inspect clixor-oci-grafana >/dev/null 2>&1; then
  # The persistent Grafana data directory is untouched; only the stopped
  # immutable container configuration containing old secrets is removed.
  docker rm clixor-oci-grafana >/dev/null
fi

attempt=1
until curl --fail --silent --show-error --max-time 5 \
  "${gateway_readiness_url}" >/dev/null; do
  if [ "${attempt}" -ge 60 ]; then
    CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" ps
    CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
      logs --tail=100 api-a api-b api-gateway
    fail "local API readiness did not pass within 120 seconds"
  fi
  attempt=$((attempt + 1))
  sleep 2
done

for replica in api-a api-b; do
  docker exec clixor-oci-api-gateway wget --quiet --output-document=/dev/null \
    "http://${replica}:8080/health/ready" || fail "${replica} readiness failed through the gateway"
done
log "both API replicas completed native OCI media-provider startup and readiness"
if [ "${public_smoke_required}" = "true" ]; then
  verify_public_ingress
else
  log "public ingress smoke is deferred for this non-production staging deployment"
fi

log "forcing a fresh post-migration backup for the isolated restore release gate"
backup_gate_start="${release_dir}/post-migration-backup-gate-start"
touch "${backup_gate_start}"
# The long-running backup worker creates a dump immediately at startup. Restart
# it after the gate timestamp so a pre-migration LAST_SUCCESS can never satisfy
# this release, even when the application schema did not change. Force-recreate
# also makes the long-running shell consume this release's mounted backup script
# and removes any credentials retained by the retired all-secrets container.
sleep 1
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
  up -d --no-build --no-deps --force-recreate postgres-backup
backup_attempt=1
while :; do
  if [ -s "${project_root}/backups/postgres/LAST_SUCCESS" ] && \
    [ -n "$(find "${project_root}/backups/postgres/LAST_SUCCESS" \
      -newer "${backup_gate_start}" -print 2>/dev/null)" ]; then
    break
  fi
  [ "$(docker inspect clixor-oci-postgres-backup \
    --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] || \
    fail "the PostgreSQL backup container exited during the release gate"
  [ "${backup_attempt}" -lt 120 ] || \
    fail "the PostgreSQL backup container did not produce a fresh backup within 10 minutes"
  backup_attempt=$((backup_attempt + 1))
  sleep 5
done
systemctl start clixor-offsite-backup.service
[ -s "${project_root}/backups/OFFSITE_LAST_SUCCESS" ] && \
  [ -n "$(find "${project_root}/backups/OFFSITE_LAST_SUCCESS" \
    -newer "${backup_gate_start}" -print 2>/dev/null)" ] || \
  fail "the offsite upload did not produce a fresh success marker"
systemctl start clixor-restore-drill.service
[ -s "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" ] && \
  [ -n "$(find "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" \
    -newer "${backup_gate_start}" -print 2>/dev/null)" ] || \
  fail "the isolated restore drill did not produce a fresh success marker"
systemctl enable --now clixor-restore-drill.timer clixor-backup-health.timer
systemctl start clixor-backup-health.service

python3 "${source_root}/deploy/oci/dependency_pki.py" mark-applied \
  --desired "${release_dir}/dependency-pki.desired" \
  --applied "${pki_applied}"

ln -s "${release_dir}" "${release_dir}/current-link.pending"
mv -Tf "${release_dir}/current-link.pending" "${release_root}/current"
[ "$(readlink "${release_root}/current")" = "${release_dir}" ] || \
  fail "current release pointer did not update atomically"
rollback_needed=0
log "deployed ${new_image}; API readiness passed"
