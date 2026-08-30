#!/bin/sh
set -eu
umask 077
ulimit -c 0

project_root=/srv/clixor
stable_root="${project_root}/repo"
release_root="${project_root}/releases"
runtime_env="${project_root}/secrets/runtime.env"
runtime_secret_root=/run/clixor/secrets
active_secret_root="${runtime_secret_root}/active"
api_env="${active_secret_root}/api.env"
postgres_env="${active_secret_root}/postgres.env"
redis_env="${active_secret_root}/redis.env"
nats_env="${active_secret_root}/nats.env"
grafana_env="${active_secret_root}/grafana.env"
backup_env="${active_secret_root}/backup.env"
migrate_env="${active_secret_root}/migrate.env"
lock_file="${project_root}/runtime/deploy.lock"
compose_file="${stable_root}/deploy/oci/compose.yaml"
pki_desired="${project_root}/runtime/dependency-pki.desired"
pki_applied="${project_root}/runtime/dependency-pki.applied"
gateway_readiness_url=http://172.30.254.2:8080/health/ready
public_api_readiness_url=${CLIXOR_PUBLIC_API_READINESS_URL:-https://clustr-api.atlanteanz.com/health/ready}
public_association_url=${CLIXOR_PUBLIC_ASSOCIATION_URL:-https://clixor.atlanteanz.com/.well-known/apple-app-site-association}
public_smoke_mode=${CLIXOR_REQUIRE_PUBLIC_SMOKE:-auto}
vault_hydration_mode=${CLIXOR_REQUIRE_VAULT_HYDRATION:-false}
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
case "${vault_hydration_mode}" in
  true|false) ;;
  *) fail "CLIXOR_REQUIRE_VAULT_HYDRATION must be true or false" ;;
esac
case "${public_api_readiness_url}" in
  https://*) ;;
  *) fail "public API readiness URL must use HTTPS" ;;
esac
case "${public_association_url}" in
  https://*) ;;
  *) fail "public association URL must use HTTPS" ;;
esac
public_smoke_required=false
[ "${public_smoke_mode}" = "true" ] && public_smoke_required=true

verify_public_ingress() {
  log "verifying public Cloudflare ingress before release finalization"
  curl --fail --silent --show-error --retry 12 --retry-all-errors \
    --retry-delay 5 --max-time 10 "${public_api_readiness_url}" >/dev/null || \
    return 1
  curl --fail --silent --show-error --retry 6 --retry-all-errors \
    --retry-delay 5 --max-time 10 --header 'Cache-Control: no-cache' \
    "${public_association_url}" >/dev/null || return 1
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

for command_name in \
  cmp curl docker find findmnt flock install python3 rsync sha256sum systemctl touch
do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done
docker buildx version >/dev/null 2>&1 || fail "missing Docker Buildx plugin"

mkdir -p "${project_root}/runtime"
exec 9>"${lock_file}"
flock -n 9 || fail "another deployment holds ${lock_file}"

if [ -s "${compose_file}" ] && \
  ! grep -Eq '(/srv/clixor/secrets/(active/)?api.env|/run/clixor/secrets/active/api.env)' \
    "${compose_file}"; then
  fail "path-only secret migration requires a reviewed manual maintenance release"
fi

vault_generation_changed=false
cloudflare_secret_changed=false
cloudflare_secret_activated=false
vault_postgres_secret_changed=false
vault_postgres_secret_activated=false
vault_redis_secret_changed=false
vault_redis_secret_activated=false
vault_nats_secret_changed=false
vault_nats_secret_activated=false
previous_vault_target=
current_vault_target=

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
    grep -Eq '^(CLUSTER_|POSTGRES_PASSWORD=|REDIS_PASSWORD=|NATS_AUTH_TOKEN=|GF_SECURITY_ADMIN_PASSWORD=)'; then
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
  if grep -Eq '(/srv/clixor/secrets/(active/)?api.env|/run/clixor/secrets/active/api.env|CLUSTER_CONFIG_FILE:[[:space:]]*/run/secrets/api.env)' \
    "${previous_compose}"; then
    previous_compose_uses_scoped=true
  fi
  log "capturing a pre-change PostgreSQL snapshot"
  if docker inspect clixor-oci-postgres \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | \
    grep -q '^POSTGRES_PASSWORD='; then
    # One-time transition from the retired env-secret container model.
    docker exec clixor-oci-postgres sh -ec \
      'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
      > "${pre_migration_dump}.partial"
  else
    # Current containers mount their credential from tmpfs; Docker metadata
    # contains only the path and nonsecret database identity.
    docker exec clixor-oci-postgres sh -ec \
      'PGPASSFILE=/run/secrets/postgres.pgpass pg_dump --host=postgres.clixor.internal --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
      > "${pre_migration_dump}.partial"
  fi
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
restore_previous_vault_target() {
  [ "${vault_generation_changed}" = "true" ] || return 0
  if [ -n "${current_vault_target}" ]; then
    [ -L "${runtime_secret_root}/active" ] && \
      [ "$(readlink -- "${runtime_secret_root}/active")" = "${current_vault_target}" ] || \
      return 1
  else
    [ ! -e "${runtime_secret_root}/active" ] && \
      [ ! -L "${runtime_secret_root}/active" ] || return 1
  fi
  case "${previous_vault_target}" in
    '')
      rm -f -- "${runtime_secret_root}/active" || return 1
      vault_generation_changed=false
      return 0
      ;;
    /srv/clixor/secrets)
      [ -d "${previous_vault_target}" ] && [ ! -L "${previous_vault_target}" ] || \
        return 1
      ;;
    vault-generations/gen-[0-9]*-[0-9a-f]*)
      [ -d "${runtime_secret_root}/${previous_vault_target}" ] && \
        [ ! -L "${runtime_secret_root}/${previous_vault_target}" ] || return 1
      ;;
    *) return 1 ;;
  esac
  temporary_vault_link="${runtime_secret_root}/.active.rollback.$$"
  rm -f -- "${temporary_vault_link}"
  ln -s "${previous_vault_target}" "${temporary_vault_link}" || return 1
  if ! mv -Tf -- "${temporary_vault_link}" "${runtime_secret_root}/active"; then
    rm -f -- "${temporary_vault_link}"
    return 1
  fi
  vault_generation_changed=false
}

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

retire_persistent_staging_secrets() {
  for persistent_name in \
    api.env postgres.env redis.env nats.env grafana.env backup.env migrate.env \
    metrics.token postgres.password postgres.pgpass redis.password redis.acl \
    nats.conf grafana.ini cloudflare-token
  do
    persistent_path="${project_root}/secrets/${persistent_name}"
    if [ -e "${persistent_path}" ] || [ -L "${persistent_path}" ]; then
      [ -f "${persistent_path}" ] && [ ! -L "${persistent_path}" ] || return 1
      rm -f -- "${persistent_path}" || return 1
    fi
  done
  for persistent_apns_key in "${project_root}/secrets/apns"/*.p8; do
    [ -e "${persistent_apns_key}" ] || continue
    [ -f "${persistent_apns_key}" ] && [ ! -L "${persistent_apns_key}" ] || \
      return 1
    rm -f -- "${persistent_apns_key}" || return 1
  done
  legacy_cloudflare_token=/etc/cloudflared/token
  if [ -e "${legacy_cloudflare_token}" ] || [ -L "${legacy_cloudflare_token}" ]; then
    [ -f "${legacy_cloudflare_token}" ] && \
      [ ! -L "${legacy_cloudflare_token}" ] && \
      [ "$(stat -c '%u:%g:%a' "${legacy_cloudflare_token}")" = "0:0:600" ] || \
      return 1
    rm -f -- "${legacy_cloudflare_token}" || return 1
  fi
  for residual_secret_dir in \
    "${project_root}/secrets"/.split-runtime.* \
    "${project_root}/secrets"/.staging-runtime-*
  do
    [ -e "${residual_secret_dir}" ] || continue
    [ -d "${residual_secret_dir}" ] && [ ! -L "${residual_secret_dir}" ] && \
      [ "$(stat -c '%u:%g:%a' "${residual_secret_dir}")" = "0:0:700" ] || \
      return 1
    case "${residual_secret_dir}" in
      "${project_root}/secrets"/.split-runtime.*|\
      "${project_root}/secrets"/.staging-runtime-*) ;;
      *) return 1 ;;
    esac
    rm -rf -- "${residual_secret_dir}" || return 1
  done
}

rollback() {
  status=$?
  trap - 0
  secret_rollback_failed=0
  cloudflare_rollback_failed=0
  if [ "${status}" -ne 0 ] && [ "${vault_generation_changed}" = "true" ]; then
    set +e
    if restore_previous_vault_target; then
      log "restored the previous runtime-secret generation after deployment failure"
      if [ "${cloudflare_secret_activated}" = "true" ]; then
        if [ -n "${previous_vault_target}" ]; then
          if systemctl restart cloudflared.service && \
            systemctl is-active --quiet cloudflared.service; then
            log "restored cloudflared with the previous credential"
          else
            log "ERROR: cloudflared did not recover with the previous credential" >&2
            cloudflare_rollback_failed=1
          fi
        else
          if systemctl stop cloudflared.service; then
            log "stopped cloudflared because no prior credential existed"
          else
            log "ERROR: cloudflared did not stop after first-deploy failure" >&2
            cloudflare_rollback_failed=1
          fi
        fi
      fi
    else
      log "ERROR: could not restore the previous runtime-secret generation" >&2
      secret_rollback_failed=1
    fi
  fi
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
      rollback_secret_services=
      rollback_secret_containers=
      [ "${vault_postgres_secret_activated}" = "true" ] && {
        rollback_secret_services="${rollback_secret_services} postgres"
        rollback_secret_containers="${rollback_secret_containers} clixor-oci-postgres"
      }
      [ "${vault_redis_secret_activated}" = "true" ] && {
        rollback_secret_services="${rollback_secret_services} redis"
        rollback_secret_containers="${rollback_secret_containers} clixor-oci-redis"
      }
      [ "${vault_nats_secret_activated}" = "true" ] && {
        rollback_secret_services="${rollback_secret_services} nats"
        rollback_secret_containers="${rollback_secret_containers} clixor-oci-nats"
      }
      if [ "${rollback_failed}" -eq 0 ] && \
        [ -n "${rollback_secret_services}" ]; then
        if ! CLIXOR_IMAGE_TAG="${previous_tag}" docker compose \
          --file "${compose_file}" up -d --no-build --no-deps --force-recreate \
          ${rollback_secret_services}; then
          log "ERROR: rollback secret consumers did not restart" >&2
          rollback_failed=1
        fi
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ -n "${rollback_secret_containers}" ]; then
        for rollback_dependency in ${rollback_secret_containers}
        do
          rollback_dependency_attempt=1
          while :; do
            rollback_dependency_health="$(docker inspect "${rollback_dependency}" \
              --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
              2>/dev/null || true)"
            [ "${rollback_dependency_health}" = "healthy" ] && break
            case "${rollback_dependency_health}" in
              exited|dead) break ;;
            esac
            [ "${rollback_dependency_attempt}" -lt 60 ] || break
            rollback_dependency_attempt=$((rollback_dependency_attempt + 1))
            sleep 2
          done
          if [ "${rollback_dependency_health}" != "healthy" ]; then
            log "ERROR: ${rollback_dependency} did not recover with the previous secrets" >&2
            rollback_failed=1
          fi
        done
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
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${rollback_ready}" = "true" ] && \
        [ "${cloudflare_secret_activated}" = "true" ] && \
        [ -n "${previous_vault_target}" ]; then
        if verify_public_ingress; then
          cloudflare_rollback_failed=0
        else
          log "ERROR: public ingress did not recover after connector rollback" >&2
          cloudflare_rollback_failed=1
        fi
      fi
      if [ "${rollback_failed}" -eq 0 ] && \
        [ "${secret_rollback_failed}" -eq 0 ] && \
        [ "${cloudflare_rollback_failed}" -eq 0 ] && \
        [ "${rollback_ready}" = "true" ]; then
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

# Hydrate only after the exit trap is armed. From this point onward, every
# failure restores the exact previously selected generation before attempting
# an application rollback. The pre-change database snapshot above deliberately
# uses the still-running containers' prior mounted credentials.
if [ "${vault_hydration_mode}" = "true" ]; then
  [ -x /usr/bin/python3 ] || fail "Python 3 is required for OCI Vault hydration"
  previous_vault_target="$(readlink -- "${runtime_secret_root}/active" 2>/dev/null || true)"
  hydration_status=0
  /usr/bin/python3 "${source_root}/deploy/oci/hydrate-vault-secrets.py" || \
    hydration_status=$?
  current_vault_target="$(readlink -- "${runtime_secret_root}/active" 2>/dev/null || true)"
  if [ "${previous_vault_target}" != "${current_vault_target}" ]; then
    vault_generation_changed=true
  fi
  if [ "${hydration_status}" -eq 0 ] && \
    [ "${vault_generation_changed}" = "true" ]; then
    previous_secret_generation_root=
    case "${previous_vault_target}" in
      /srv/clixor/secrets)
        previous_secret_generation_root="${previous_vault_target}"
        ;;
      vault-generations/gen-[0-9]*-[0-9a-f]*)
        previous_secret_generation_root="${runtime_secret_root}/${previous_vault_target}"
        ;;
    esac
    current_secret_generation_root="${runtime_secret_root}/${current_vault_target}"
    for secret_consumer in \
      postgres:postgres.password redis:redis.acl nats:nats.conf \
      cloudflare:cloudflare-token
    do
      consumer_name=${secret_consumer%%:*}
      consumer_file=${secret_consumer#*:}
      consumer_changed=false
      if [ -z "${previous_secret_generation_root}" ] || \
        [ ! -f "${previous_secret_generation_root}/${consumer_file}" ] || \
        [ -L "${previous_secret_generation_root}/${consumer_file}" ] || \
        ! cmp -s "${previous_secret_generation_root}/${consumer_file}" \
          "${current_secret_generation_root}/${consumer_file}"; then
        consumer_changed=true
      fi
      case "${consumer_name}:${consumer_changed}" in
        postgres:true) vault_postgres_secret_changed=true ;;
        redis:true) vault_redis_secret_changed=true ;;
        nats:true) vault_nats_secret_changed=true ;;
        cloudflare:true) cloudflare_secret_changed=true ;;
      esac
    done
  fi
  [ "${hydration_status}" -eq 0 ] || fail "OCI Vault hydration failed before deployment"
fi

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
CLIXOR_SKIP_PACKAGES=true CLIXOR_SKIP_SECRET_PREPARATION=true \
  sh "${source_root}/deploy/oci/bootstrap.sh"
for scoped_env in \
  "${api_env}" "${postgres_env}" "${redis_env}" "${nats_env}" \
  "${grafana_env}" "${backup_env}" "${migrate_env}"
do
  [ -s "${scoped_env}" ] || fail "scoped configuration is missing"
done
if [ "${vault_hydration_mode}" = "true" ]; then
  [ -L "${runtime_secret_root}/active" ] && \
    [ "$(readlink -- "${runtime_secret_root}/active")" = "${current_vault_target}" ] || \
    fail "the active Vault generation changed during deployment"
  grep -qx 'CLUSTER_ENV=production' "${api_env}" || \
    fail "Vault-backed deployments require CLUSTER_ENV=production"
  grep -qx 'CLUSTER_VERIFICATION_PROVIDER=telnyx' "${api_env}" || \
    fail "Vault-backed deployments require the Telnyx verification provider"
  grep -qx 'CLUSTER_MAIL_PROVIDER=smtp' "${api_env}" || \
    fail "Vault-backed deployments require durable SMTP password-reset delivery"
fi
if grep -q '^CLUSTER_ENV=production$' "${api_env}"; then
  [ -f /etc/clixor/secret-mode ] && [ ! -L /etc/clixor/secret-mode ] && \
    [ "$(stat -c '%u:%g:%a' /etc/clixor/secret-mode)" = "0:0:600" ] && \
    [ "$(sed -n '1p' /etc/clixor/secret-mode)" = "vault" ] || \
    fail "production requires root-owned OCI Vault secret mode"
  [ "$(findmnt --noheadings --output FSTYPE --target "${runtime_secret_root}" | tr -d '[:space:]')" = "tmpfs" ] || \
    fail "production runtime secrets are not on tmpfs"
  active_target="$(readlink -- "${runtime_secret_root}/active")"
  case "${active_target}" in
    vault-generations/gen-[0-9]*-[0-9a-f]*) ;;
    *) fail "production requires an atomically selected OCI Vault generation" ;;
  esac
  marker="${runtime_secret_root}/${active_target}/.vault-hydrated"
  [ -f "${marker}" ] && [ ! -L "${marker}" ] || \
    fail "production Vault hydration marker is missing"
  [ "$(stat -c '%u:%g:%a' "${marker}")" = "0:0:400" ] || \
    fail "production Vault hydration marker has unsafe ownership or mode"
  grep -q '^schema=1$' "${marker}" || fail "production Vault hydration marker is invalid"
  if grep -Eq '^[[:space:]]*[^#[:space:]]' "${runtime_env}"; then
    fail "production requires an empty legacy runtime.env marker"
  fi
fi
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
if [ "${vault_postgres_secret_changed}" = "true" ] && \
  [ "$(docker inspect clixor-oci-postgres --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ]; then
  log "verifying hydrated PostgreSQL credentials before replacing dependencies"
  CLIXOR_IMAGE_TAG="${release_tag}" docker compose --file "${compose_file}" \
    run --rm --no-deps --entrypoint psql postgres-backup \
    --host postgres.clixor.internal --username clixor --dbname clixor \
    --command 'SELECT 1' >/dev/null || \
    fail "Vault PostgreSQL credential does not match the initialized database"
fi
for dependency_service in ${pki_restart_services}; do
  case "${dependency_service}" in
    postgres|nats|dependency-tls) ;;
    *) fail "dependency PKI requested an unexpected service restart" ;;
  esac
done

for dependency_service in postgres redis nats; do
  recreate_dependency=false
  vault_dependency_secret_changed=false
  if [ "${legacy_dependency_scope}" = "true" ]; then
    recreate_dependency=true
  fi
  case "${dependency_service}" in
    postgres) vault_dependency_secret_changed=${vault_postgres_secret_changed} ;;
    redis) vault_dependency_secret_changed=${vault_redis_secret_changed} ;;
    nats) vault_dependency_secret_changed=${vault_nats_secret_changed} ;;
  esac
  [ "${vault_dependency_secret_changed}" = "true" ] && recreate_dependency=true
  case " ${pki_restart_services} " in
    *" ${dependency_service} "*) recreate_dependency=true ;;
  esac
  if [ "${recreate_dependency}" = "true" ]; then
    log "recreating ${dependency_service} for scoped secrets or its new TLS leaf"
    if [ "${vault_dependency_secret_changed}" = "true" ]; then
      case "${dependency_service}" in
        postgres) vault_postgres_secret_activated=true ;;
        redis) vault_redis_secret_activated=true ;;
        nats) vault_nats_secret_activated=true ;;
      esac
    fi
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
if [ "${cloudflare_secret_changed}" = "true" ]; then
  log "restarting cloudflared to activate the rotated tmpfs credential"
  cloudflare_secret_activated=true
  systemctl restart cloudflared.service
  systemctl is-active --quiet cloudflared.service || \
    fail "cloudflared did not become active with the rotated credential"
fi
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
vault_generation_changed=false

# Retire durable staging copies only after the release is committed and its
# rollback trap is disarmed. A staging-to-Vault cutover deliberately retains
# the prior files for one full release; the next successful Vault-to-Vault
# release removes them after proving both the application and connector.
retire_staging_copies=false
if [ "${first_deploy}" = "true" ]; then
  retire_staging_copies=true
else
  case "${previous_vault_target}" in
    vault-generations/gen-[0-9]*-[0-9a-f]*) retire_staging_copies=true ;;
  esac
fi
if grep -qx 'CLUSTER_ENV=production' "${api_env}" && \
  [ "${retire_staging_copies}" = "true" ]; then
  retire_persistent_staging_secrets || \
    fail "release is live but persistent staging credential retirement failed"
fi
log "deployed ${new_image}; API readiness passed"
