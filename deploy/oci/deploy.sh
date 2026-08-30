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
gateway_readiness_url=http://172.30.254.2:8080/health/ready
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

for command_name in curl docker find flock rsync systemctl touch; do
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
legacy_backup_scope=false
legacy_grafana_scope=false
legacy_grafana_running=false
for container_name in \
  clixor-oci-postgres clixor-oci-redis clixor-oci-nats \
  clixor-oci-postgres-backup clixor-oci-grafana
do
  if docker inspect "${container_name}" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | \
    grep -q '^CLUSTER_'; then
    case "${container_name}" in
      clixor-oci-postgres|clixor-oci-redis|clixor-oci-nats)
        legacy_dependency_scope=true
        ;;
      clixor-oci-postgres-backup)
        legacy_backup_scope=true
        ;;
      clixor-oci-grafana)
        legacy_grafana_scope=true
        if [ "$(docker inspect "${container_name}" --format '{{.State.Running}}')" = "true" ]; then
          legacy_grafana_running=true
        fi
        ;;
    esac
  fi
done

release_tag="oci-$(printf '%s' "${source_sha}" | cut -c1-12)-${run_id}"
release_dir="${release_root}/${release_tag}"
previous_compose="${release_dir}/previous-compose.yaml"
rollback_compose="${previous_compose}"
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

  log "capturing a pre-change PostgreSQL snapshot"
  docker exec clixor-oci-postgres sh -ec \
    'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
    > "${pre_migration_dump}.partial"
  [ -s "${pre_migration_dump}.partial" ] || fail "pre-change PostgreSQL snapshot is empty"
  chmod 0600 "${pre_migration_dump}.partial"
  mv "${pre_migration_dump}.partial" "${pre_migration_dump}"
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
rollback() {
  status=$?
  trap - 0
  if [ "${status}" -ne 0 ] && [ "${rollback_needed}" -eq 1 ]; then
    set +e
    if [ "${first_deploy}" = "false" ]; then
      log "deployment failed; attempting application rollback to ${previous_image}"
      [ -s "${rollback_compose}" ] || \
        log "ERROR: rollback Compose model is unavailable" >&2
      previous_tag=${previous_image#clixor-api:}
      cp "${rollback_compose}" "${compose_file}"
      CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
        --file "${compose_file}" up -d --no-build --remove-orphans

      rollback_attempt=1
      rollback_ready=false
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
      if [ "${rollback_ready}" = "true" ]; then
        log "application rollback completed; database migrations were not reversed"
      else
        log "ERROR: previous application did not become ready after rollback" >&2
      fi
    else
      log "first deployment failed; stopping the incomplete application stack"
      if [ -s "${compose_file}" ]; then
        CLIXOR_IMAGE_TAG="${release_tag}" docker compose \
          --file "${compose_file}" down --remove-orphans
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

# The one-time secret split makes the retired all-secrets Compose model
# unusable for rollback. Capture the new scoped model before bootstrap mutates
# runtime.env, so even an early failure can keep the previous API image on
# least-privilege service files.
if [ "${first_deploy}" = "false" ] && \
  ! grep -q '/srv/clixor/secrets/api.env' "${previous_compose}"; then
  rollback_compose="${release_dir}/rollback-compose.yaml"
  cp "${source_root}/deploy/oci/compose.yaml" "${rollback_compose}"
  [ -s "${rollback_compose}" ] || fail "scoped rollback Compose model is empty"
fi

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

log "syncing the approved revision into ${stable_root}"
rsync -a --delete \
  --exclude='/.git/' \
  --exclude='/.DS_Store' \
  --exclude='/.build/' \
  --exclude='/coverage.out' \
  "${source_root}/" "${stable_root}/"

CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" config --quiet
if [ "${legacy_dependency_scope}" = "true" ]; then
  log "replacing legacy data containers to remove inherited API credentials"
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
    up -d --no-build --force-recreate postgres redis nats dependency-tls
else
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" up -d --no-build \
    postgres redis nats dependency-tls
fi

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

if [ "${legacy_backup_scope}" = "true" ]; then
  log "replacing legacy backup container to remove inherited API credentials"
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
    up -d --no-build --no-deps --force-recreate postgres-backup
fi
if [ "${legacy_grafana_scope}" = "true" ]; then
  if [ "${legacy_grafana_running}" = "true" ]; then
    log "replacing legacy Grafana container to remove inherited API credentials"
    CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
      --profile observability up -d --no-build --no-deps --force-recreate grafana
  else
    # The persistent Grafana data directory is untouched; only the stopped
    # immutable container configuration containing old secrets is removed.
    docker rm clixor-oci-grafana >/dev/null
  fi
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

log "forcing a fresh post-migration backup for the isolated restore release gate"
backup_gate_start="${release_dir}/post-migration-backup-gate-start"
touch "${backup_gate_start}"
# The long-running backup worker creates a dump immediately at startup. Restart
# it after the gate timestamp so a pre-migration LAST_SUCCESS can never satisfy
# this release, even when the application schema did not change.
sleep 1
docker restart clixor-oci-postgres-backup >/dev/null
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

rollback_needed=0
ln -sfn "${release_dir}" "${release_root}/current"
log "deployed ${new_image}; API readiness passed"
