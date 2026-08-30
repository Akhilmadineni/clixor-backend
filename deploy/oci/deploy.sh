#!/bin/sh
set -eu
umask 077

project_root=/srv/clixor
stable_root="${project_root}/repo"
release_root="${project_root}/releases"
runtime_env="${project_root}/secrets/runtime.env"
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

for command_name in curl docker flock rsync; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done
docker buildx version >/dev/null 2>&1 || fail "missing Docker Buildx plugin"

mkdir -p "${project_root}/runtime"
exec 9>"${lock_file}"
flock -n 9 || fail "another deployment holds ${lock_file}"

release_tag="oci-$(printf '%s' "${source_sha}" | cut -c1-12)-${run_id}"
release_dir="${release_root}/${release_tag}"
previous_compose="${release_dir}/previous-compose.yaml"
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
      previous_tag=${previous_image#clixor-api:}
      cp "${previous_compose}" "${compose_file}"
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

# Everything below can mutate the active runtime. Arm application rollback
# before refreshing configuration, syncing Compose, reconciling dependencies,
# or running a forward migration. The captured dump is for operator recovery;
# this script never restores it automatically.
rollback_needed=1

# Idempotently refresh permissions, certificates and checked-in runtime config.
# Package installation belongs to the explicit first bootstrap, not every deploy.
CLIXOR_SKIP_PACKAGES=true sh "${source_root}/deploy/oci/bootstrap.sh"
[ -s "${runtime_env}" ] || fail "runtime configuration is missing"
if grep -Eiq 'REPLACE_(WITH|ME)|replace-with' "${runtime_env}"; then
  fail "runtime configuration still contains a placeholder"
fi
grep -q '^CLUSTER_MEDIA_PROVIDER=oci$' "${runtime_env}" || \
  fail "OCI deployment requires CLUSTER_MEDIA_PROVIDER=oci"
for required_key in \
  CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE \
  CLUSTER_OCI_OBJECT_STORAGE_BUCKET \
  CLUSTER_OCI_OBJECT_STORAGE_REGION
do
  grep -Eq "^${required_key}=.+" "${runtime_env}" || \
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
CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" up -d --no-build \
  postgres redis nats dependency-tls

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
rollback_needed=0
ln -sfn "${release_dir}" "${release_root}/current"
log "deployed ${new_image}; API readiness passed"
