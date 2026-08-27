#!/bin/sh
set -eu
umask 077

project_root=${CLUSTER_DEPLOY_PROJECT_ROOT:-/volume1/docker/clustr}
stable_root=$project_root/repo
release_root=$project_root/releases
lock_file=$project_root/runtime/deploy.lock
compose_file=$stable_root/deploy/nas/compose.yaml
runtime_env=$project_root/secrets/runtime.env
source_root=${1:-}
source_sha=${2:-}
run_id=${3:-manual}

log() {
  printf '[clustr-deploy] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

for command_name in cmp curl docker flock rsync sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done

[ -n "$source_root" ] || fail "source workspace argument is required"
[ -f "$source_root/go.mod" ] || fail "source workspace does not contain go.mod"
[ -f "$source_root/deploy/nas/compose.yaml" ] || fail "source workspace does not contain the NAS Compose model"
[ -f "$source_root/internal/httpapi/universal-links/apple-app-site-association" ] ||
  fail "source workspace does not contain the Apple association document"
[ -f "$source_root/internal/httpapi/universal-links/join.html" ] ||
  fail "source workspace does not contain the invite landing page"
grep -q '^module github.com/Akhilmadineni/clixor-backend$' "$source_root/go.mod" || fail "unexpected Go module"

case "$source_sha" in
  ''|*[!0-9a-f]*) fail "source revision must be a lowercase Git object ID" ;;
esac
[ "${#source_sha}" -ge 12 ] || fail "source revision is too short"
case "$run_id" in
  *[!A-Za-z0-9._-]*) fail "run ID contains unsupported characters" ;;
esac

release_tag="nas-$(printf '%s' "$source_sha" | cut -c1-12)-$run_id"
release_dir=$release_root/$release_tag
previous_compose=$release_dir/previous-compose.yaml
new_image=clustr-api:$release_tag
mail_image=clustr-mail:$release_tag
bootstrap_image=clustr-bootstrap:$release_tag
previous_repo=$release_dir/previous-repo
empty_repo=$release_dir/empty-repo
runtime_config_snapshot=$release_dir/previous-runtime-config

directory_has_entries() {
  directory=$1
  [ -d "$directory" ] || return 1
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    if [ -e "$entry" ] || [ -L "$entry" ]; then
      return 0
    fi
  done
  return 1
}

replica_image() {
  docker inspect "clustr-$1" --format '{{.Config.Image}}' 2>/dev/null || true
}

gateway_running() {
  [ "$(docker inspect clustr-api-gateway --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ]
}

wait_replica_ready() {
  replica=$1
  probe_mode=${2:-gateway}
  attempt=1
  while :; do
    if gateway_running; then
      if docker exec clustr-api-gateway wget --quiet --output-document=/dev/null \
        "http://${replica}:8080/health/ready" >/dev/null 2>&1; then
        return 0
      fi
    elif [ "$probe_mode" = bootstrap ]; then
      # Only a legacy-to-HA or empty first installation may lack the gateway.
      # dependency-tls shares clustr_internal and can validate each candidate
      # before the gateway is created. It is never a steady-state fallback.
      if docker exec clustr-dependency-tls wget --quiet --output-document=/dev/null \
        "http://${replica}:8080/health/ready" >/dev/null 2>&1; then
        return 0
      fi
    fi
    [ "$attempt" -lt 60 ] || return 1
    attempt=$((attempt + 1))
    sleep 2
  done
}

assert_replica_ready() {
  wait_replica_ready "$1" gateway ||
    fail "$1 gateway-specific readiness did not pass within 120 seconds"
}

assert_bootstrap_replica_ready() {
  wait_replica_ready "$1" bootstrap ||
    fail "$1 bootstrap readiness did not pass within 120 seconds"
}

assert_replica_image() {
  replica=$1
  expected=$2
  actual=$(replica_image "$replica")
  [ "$actual" = "$expected" ] ||
    fail "$replica runs image ${actual:-missing}; expected $expected"
}

wait_gateway_ready() {
  attempt=1
  until curl --fail --silent --show-error --max-time 5 \
    http://127.0.0.1:18180/health/ready >/dev/null; do
    [ "$attempt" -lt 60 ] || return 1
    attempt=$((attempt + 1))
    sleep 2
  done
}

assert_gateway_ready() {
  wait_gateway_ready || fail "local gateway readiness did not pass within 120 seconds"
}

snapshot_runtime_configs() {
  log "snapshotting release-derived runtime configuration"
  docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:size=32m,mode=1777 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --volume "$project_root:$project_root" \
    --entrypoint /bin/sh \
    "$bootstrap_image" -ec '
      project_root=$1
      snapshot_root=$2
      umask 077
      mkdir -p "$snapshot_root"
      : >"$snapshot_root/missing-files"
      snapshot_file() {
        relative_path=$1
        source_path=$project_root/$relative_path
        destination_path=$snapshot_root/$relative_path
        if [ -f "$source_path" ]; then
          mkdir -p "$(dirname "$destination_path")"
          cp -p "$source_path" "$destination_path"
        else
          printf "%s\n" "$relative_path" >>"$snapshot_root/missing-files"
        fi
      }
      snapshot_file runtime/dependency-tls/haproxy.cfg
      snapshot_file runtime/api-gateway/nginx.conf
      snapshot_file runtime/media/nginx.conf
      snapshot_file runtime/postgres-backup/backup.sh
      snapshot_file runtime/prometheus/prometheus.yml
      snapshot_file runtime/grafana/datasource.yml
    ' clustr-snapshot-runtime-config "$project_root" "$runtime_config_snapshot"
}

restore_runtime_configs() {
  log "restoring release-derived runtime configuration"
  docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:size=32m,mode=1777 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --volume "$project_root:$project_root" \
    --entrypoint /bin/sh \
    "$bootstrap_image" -ec '
      project_root=$1
      snapshot_root=$2
      restore_file() {
        relative_path=$1
        source_path=$snapshot_root/$relative_path
        destination_path=$project_root/$relative_path
        if [ -f "$source_path" ]; then
          mkdir -p "$(dirname "$destination_path")"
          cp -p "$source_path" "$destination_path"
        elif grep -Fqx "$relative_path" "$snapshot_root/missing-files"; then
          rm -f "$destination_path"
        else
          printf "runtime snapshot is incomplete for %s\n" "$relative_path" >&2
          exit 1
        fi
      }
      restore_file runtime/dependency-tls/haproxy.cfg
      restore_file runtime/api-gateway/nginx.conf
      restore_file runtime/media/nginx.conf
      restore_file runtime/postgres-backup/backup.sh
      restore_file runtime/prometheus/prometheus.yml
      restore_file runtime/grafana/datasource.yml
    ' clustr-restore-runtime-config "$project_root" "$runtime_config_snapshot"
}

snapshot_stable_repo() {
  mkdir -p "$previous_repo" "$empty_repo"
  chmod 700 "$previous_repo" "$empty_repo"
  if directory_has_entries "$stable_root"; then
    stable_repo_had_content=1
    rsync -a "$stable_root/" "$previous_repo/"
  else
    stable_repo_had_content=0
  fi
}

restore_stable_repo() {
  log "restoring the previous stable repository snapshot"
  if [ "$stable_repo_had_content" -eq 1 ]; then
    rsync -a --delete "$previous_repo/" "$stable_root/"
  else
    rsync -a --delete "$empty_repo/" "$stable_root/"
  fi
}

[ ! -e "$release_dir" ] && [ ! -L "$release_dir" ] ||
  fail "release directory already exists; use a unique run ID: $release_dir"
mkdir -p "$stable_root" "$release_dir" "$project_root/runtime"
chmod 700 "$release_dir"
exec 9>"$lock_file"
flock -n 9 || fail "another Clustr deployment holds $lock_file"

previous_a_image=$(replica_image api-a)
previous_b_image=$(replica_image api-b)
previous_ha=0
if [ -n "$previous_a_image" ] || [ -n "$previous_b_image" ]; then
  [ -n "$previous_a_image" ] && [ -n "$previous_b_image" ] ||
    fail "existing HA release is missing one API replica"
  [ "$previous_a_image" = "$previous_b_image" ] ||
    fail "existing API replicas do not run the same image"
  previous_ha=1
  previous_image=$previous_a_image
else
  previous_image=$(docker inspect clustr-api --format '{{.Config.Image}}' 2>/dev/null || true)
fi
case "$previous_image" in
  ''|clustr-api:*) ;;
  *) fail "existing API image is not an immutable clustr-api tag" ;;
esac
if [ -f "$compose_file" ]; then
  cp "$compose_file" "$previous_compose"
fi
if [ -n "$previous_image" ] && [ ! -s "$previous_compose" ]; then
  fail "a live API exists but its rollback Compose model is unavailable"
fi
printf '%s\n' "$source_sha" >"$release_dir/source-sha"
printf '%s\n' "$previous_image" >"$release_dir/previous-image"

if [ "$previous_ha" -eq 1 ]; then
  assert_replica_ready api-a
  assert_replica_ready api-b
  assert_gateway_ready
elif [ -n "$previous_image" ]; then
  # The legacy single API owns the same loopback endpoint before HA migration.
  assert_gateway_ready
fi

rollback_needed=0
touched_api_a=0
touched_api_b=0
mail_enabled=0
stable_repo_restore_needed=0
runtime_config_restore_needed=0

restore_replica() {
  replica=$1
  previous_tag=$2
  log "restoring $replica to $previous_image"
  CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$previous_compose" \
    up -d --no-build --no-deps "$replica"
  if wait_replica_ready "$replica" && [ "$(replica_image "$replica")" = "$previous_image" ]; then
    log "$replica rollback readiness passed"
    return 0
  fi
  log "ERROR: $replica did not return to the previous ready image" >&2
  return 1
}

remove_candidate_container() {
  candidate_container=$1
  if ! matching_containers=$(docker ps -a \
    --filter "name=^/${candidate_container}$" \
    --format '{{.Names}}'); then
    log "ERROR: could not query candidate container $candidate_container" >&2
    return 1
  fi
  case "$matching_containers" in
    '') return 0 ;;
    "$candidate_container") ;;
    *)
      log "ERROR: candidate container query returned an unexpected result for $candidate_container" >&2
      return 1
      ;;
  esac
  if ! docker rm -f "$candidate_container" >/dev/null 2>&1; then
    log "ERROR: could not remove candidate container $candidate_container" >&2
    return 1
  fi
  if ! matching_containers=$(docker ps -a \
    --filter "name=^/${candidate_container}$" \
    --format '{{.Names}}'); then
    log "ERROR: could not verify candidate container removal: $candidate_container" >&2
    return 1
  fi
  if [ -n "$matching_containers" ]; then
    log "ERROR: candidate container still exists after removal: $candidate_container" >&2
    return 1
  fi
  return 0
}

rollback() {
  status=$?
  trap - 0
  if [ "$status" -ne 0 ]; then
    set +e
    rollback_incomplete=0

    # Source and generated runtime files are changed before migrations and API
    # replacement. Restore them on every later failure, even if application
    # rollback was not armed yet. Persistent runtime.env values and generated
    # keys/certificates are deliberately excluded: bootstrap changes to them are
    # additive/backward-compatible and secret material must never roll backward.
    if [ "$runtime_config_restore_needed" -eq 1 ]; then
      restore_runtime_configs || rollback_incomplete=1
    fi
    if [ "$stable_repo_restore_needed" -eq 1 ]; then
      restore_stable_repo || rollback_incomplete=1
    fi

    if [ "$rollback_needed" -eq 1 ]; then
      log "deployment failed; attempting serial application rollback to $previous_image"
    fi
    if [ "$rollback_needed" -eq 1 ] && [ -n "$previous_image" ] && [ -s "$previous_compose" ]; then
      previous_tag=${previous_image#clustr-api:}

      # Recreate only previous non-API services first. This reloads the restored
      # gateway configuration while candidate replicas are still ready, and the
      # explicit --no-deps service list cannot recreate api-a and api-b together.
      cp "$previous_compose" "$compose_file"
      rollback_services=
      for service in $(CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$compose_file" config --services); do
        case "$service" in
          api-a|api-b|mail|migrate) ;;
          *) rollback_services="$rollback_services $service" ;;
        esac
      done
      if [ -z "$rollback_services" ]; then
        log "ERROR: previous Compose model has no rollback services" >&2
        rollback_incomplete=1
      elif [ "$mail_enabled" -eq 1 ] && grep -q 'profiles:.*mail' "$compose_file"; then
        CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$compose_file" --profile mail \
          up -d --no-build --no-deps --remove-orphans $rollback_services mail ||
          rollback_incomplete=1
      else
        CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$compose_file" \
          up -d --no-build --no-deps --remove-orphans $rollback_services ||
          rollback_incomplete=1
      fi

      if [ "$previous_ha" -eq 1 ]; then
        # Reverse rollout order so one known-ready replica remains in service.
        can_restore_api_a=1
        if [ "$touched_api_b" -eq 1 ]; then
          if ! restore_replica api-b "$previous_tag"; then
            can_restore_api_a=0
            rollback_incomplete=1
            log "ERROR: leaving ready candidate api-a in service because api-b rollback failed" >&2
          fi
        fi
        if [ "$touched_api_a" -eq 1 ] && [ "$can_restore_api_a" -eq 1 ]; then
          restore_replica api-a "$previous_tag" || rollback_incomplete=1
        fi
      else
        # The previous service list above starts the legacy single API before
        # candidate HA replicas are removed.
        if [ "$touched_api_b" -eq 1 ]; then
          remove_candidate_container clustr-api-b || rollback_incomplete=1
        fi
        if [ "$touched_api_a" -eq 1 ]; then
          remove_candidate_container clustr-api-a || rollback_incomplete=1
        fi
      fi
      if wait_gateway_ready && [ "$rollback_incomplete" -eq 0 ]; then
        log "application rollback completed; forward database migrations were not reversed"
      else
        log "ERROR: automatic rollback is incomplete; operator intervention is required" >&2
      fi
    elif [ "$rollback_needed" -eq 1 ] && [ -z "$previous_image" ]; then
      # A failed first installation has no application image to restore. Remove
      # every candidate public/application container, but leave PostgreSQL and
      # its forward migrations running so a retry can first take a valid dump.
      for candidate_container in \
        clustr-api-b clustr-api-a clustr-api-gateway clustr-media clustr-mail \
        clustr-postgres-backup clustr-prometheus clustr-grafana \
        clustr-dependency-tls clustr-redis clustr-nats clustr-minio; do
        remove_candidate_container "$candidate_container" || rollback_incomplete=1
      done
      if [ "$rollback_incomplete" -eq 0 ]; then
        log "first-install application containers removed; PostgreSQL was retained for recoverable retry"
      else
        log "ERROR: first-install cleanup is incomplete; operator intervention is required" >&2
      fi
    elif [ "$rollback_needed" -eq 1 ]; then
      rollback_incomplete=1
      log "ERROR: no previous release was available for automatic rollback" >&2
    fi
  fi
  exit "$status"
}
trap rollback 0
trap 'exit 130' INT
trap 'exit 143' TERM

log "building immutable API and bootstrap images for $source_sha"
docker build \
  --pull \
  --label "org.opencontainers.image.revision=$source_sha" \
  --label "org.opencontainers.image.source=https://github.com/Akhilmadineni/clixor-backend" \
  --tag "$new_image" \
  "$source_root"
docker build \
  --pull \
  --tag "$bootstrap_image" \
  --file "$source_root/deploy/nas/bootstrap.Dockerfile" \
  "$source_root/deploy/nas"
built_revision=$(docker image inspect "$new_image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
[ "$built_revision" = "$source_sha" ] || fail "API image revision label does not match the approved source"

snapshot_file=$release_dir/pre-migration.dump
snapshot_checksum=$release_dir/pre-migration.dump.sha256
snapshot_catalog=$release_dir/pre-migration.catalog
postgres_running=$(docker inspect clustr-postgres --format '{{.State.Running}}' 2>/dev/null || true)
if [ "$postgres_running" = "true" ]; then
  log "capturing and validating the live pre-migration PostgreSQL snapshot"
  docker exec clustr-postgres sh -ec \
    'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
    >"$snapshot_file"
  [ -s "$snapshot_file" ] || fail "pre-migration PostgreSQL snapshot is empty"
  (cd "$release_dir" && sha256sum pre-migration.dump >pre-migration.dump.sha256)
  if ! (cd "$release_dir" && sha256sum -c pre-migration.dump.sha256 >/dev/null); then
    fail "pre-migration PostgreSQL snapshot checksum validation failed"
  fi
  pg_restore_version=$(docker exec clustr-postgres pg_restore --version)
  case "$pg_restore_version" in
    'pg_restore (PostgreSQL) 17.'*) ;;
    *) fail "pre-migration snapshot requires PostgreSQL 17 pg_restore; found: $pg_restore_version" ;;
  esac
  if ! docker exec -i clustr-postgres pg_restore --list \
    <"$snapshot_file" >"$snapshot_catalog"; then
    fail "pre-migration PostgreSQL snapshot catalog validation failed"
  fi
  [ -s "$snapshot_catalog" ] || fail "pre-migration PostgreSQL snapshot catalog is empty"
  chmod 600 "$snapshot_file" "$snapshot_checksum" "$snapshot_catalog"
else
  # The runner cannot normally enumerate PostgreSQL's mode-0750, uid-70 data
  # directory. Probe it through the already-built bootstrap image with a
  # read-only bind and only DAC_READ_SEARCH. Treat every probe error or
  # unexpected result as existing data so a recovery state can never be
  # mistaken for an empty installation.
  if ! postgres_data_state=$(docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true \
    --volume "$project_root:$project_root:ro" \
    --entrypoint /bin/sh \
    "$bootstrap_image" -ec '
      postgres_data_dir=$1/data/postgres
      if [ ! -e "$postgres_data_dir" ]; then
        printf "absent\n"
      elif [ ! -d "$postgres_data_dir" ]; then
        printf "invalid\n"
        exit 2
      elif ! first_entry=$(find "$postgres_data_dir" -mindepth 1 -maxdepth 1 -print -quit); then
        printf "invalid\n"
        exit 2
      elif [ -n "$first_entry" ]; then
        printf "present\n"
      else
        printf "empty\n"
      fi
    ' clustr-probe-postgres-data "$project_root"); then
    fail "could not safely determine whether PostgreSQL data exists"
  fi
  case "$postgres_data_state" in
    absent|empty) postgres_data_present=0 ;;
    present) postgres_data_present=1 ;;
    *) fail "PostgreSQL data probe returned an unsafe state: $postgres_data_state" ;;
  esac
  if [ -n "$previous_image" ] || [ "$postgres_data_present" -eq 1 ]; then
    fail "live PostgreSQL is unavailable; refusing to touch an existing installation before its snapshot"
  fi
  log "no prior API or PostgreSQL data exists; proceeding as an explicit first installation"
fi

# Capture both the prior source tree and the root-owned release-derived runtime
# files before rsync/bootstrap can alter them. The exit trap restores either
# snapshot on every subsequent failure, including failures before migration.
snapshot_stable_repo
snapshot_runtime_configs
stable_repo_restore_needed=1

log "syncing the CI-approved revision into $stable_root"
rsync -a --delete \
  --exclude='/.git/' \
  --exclude='/.DS_Store' \
  --exclude='/.build/' \
  --exclude='/coverage.out' \
  "$source_root/" "$stable_root/"

log "refreshing root-owned runtime configuration without exporting secrets"
runtime_config_restore_needed=1
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:size=32m,mode=1777 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --volume "$project_root:$project_root" \
  "$bootstrap_image"

if grep -q '^CLUSTER_MAIL_PROVIDER=smtp$' "$runtime_env"; then
  mail_enabled=1
  log "mail provider is enabled; building its immutable release image"
  docker build \
    --pull \
    --label "org.opencontainers.image.revision=$source_sha" \
    --label "org.opencontainers.image.source=https://github.com/Akhilmadineni/clixor-backend" \
    --tag "$mail_image" \
    --file "$source_root/deploy/nas/mail/Dockerfile" \
    "$source_root/deploy/nas/mail"
else
  log "mail provider is disabled; skipping mail image build and startup"
fi

compose_release() {
  if [ "$mail_enabled" -eq 1 ]; then
    CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" --profile mail "$@"
  else
    CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" "$@"
  fi
}

reconcile_non_api_services() {
  non_api_services="postgres redis nats minio dependency-tls api-gateway media postgres-backup prometheus grafana"
  if [ "$mail_enabled" -eq 1 ]; then
    compose_release up -d --no-build --no-deps --remove-orphans $non_api_services mail
  else
    compose_release up -d --no-build --no-deps --remove-orphans $non_api_services
  fi
}

for network_name in clustr_internal homelab_proxy; do
  docker network inspect "$network_name" >/dev/null 2>&1 || fail "required external Docker network is missing: $network_name"
done

compose_release config --quiet
# From this point onward Compose may recreate persistent dependencies or load
# candidate runtime configuration, so every failure must reconcile the previous
# release even if migrations or API replacement have not started yet.
rollback_needed=1
if [ "$mail_enabled" -eq 1 ]; then
  compose_release up -d --no-build postgres redis nats minio dependency-tls mail
else
  compose_release up -d --no-build postgres redis nats minio dependency-tls
  CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" --profile mail \
    stop mail >/dev/null 2>&1 || true
fi
[ "$(docker inspect clustr-postgres --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ] ||
  fail "PostgreSQL did not start; refusing to run migrations"

log "applying transactional, forward-compatible database migrations"
compose_release --profile migration run --rm migrate

if [ "$previous_ha" -eq 1 ]; then
  # B remains old and ready while A is replaced.
  assert_replica_image api-b "$previous_image"
  assert_replica_ready api-b
  touched_api_a=1
  compose_release up -d --no-build --no-deps api-a
  assert_replica_image api-a "$new_image"
  assert_replica_ready api-a
  assert_replica_image api-b "$previous_image"
  assert_replica_ready api-b
  assert_gateway_ready

  # A remains new and ready while B is replaced.
  touched_api_b=1
  compose_release up -d --no-build --no-deps api-b
  assert_replica_image api-b "$new_image"
  assert_replica_ready api-b
  assert_replica_image api-a "$new_image"
  assert_replica_ready api-a
  assert_gateway_ready
else
  # A first installation or legacy-to-HA transition still starts each replica
  # separately. The legacy API retains the public port until both are ready.
  touched_api_a=1
  compose_release up -d --no-build --no-deps api-a
  assert_replica_image api-a "$new_image"
  assert_bootstrap_replica_ready api-a
  touched_api_b=1
  compose_release up -d --no-build --no-deps api-b
  assert_replica_image api-b "$new_image"
  assert_bootstrap_replica_ready api-b
  assert_bootstrap_replica_ready api-a
  if [ "$(docker inspect clustr-api --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ]; then
    docker stop --time 30 clustr-api
  fi
fi

# The explicit list and --no-deps structurally exclude both API replicas while
# bringing up the gateway for a first HA transition and reconciling sidecars.
reconcile_non_api_services
assert_replica_image api-a "$new_image"
assert_replica_ready api-a
assert_replica_image api-b "$new_image"
assert_replica_ready api-b
assert_gateway_ready

public_health=$release_dir/public-health.json
public_aasa=$release_dir/public-aasa.json
public_join=$release_dir/public-join.html
public_me=$release_dir/public-me.json
public_query="deploy=$release_tag"

log "validating public ingress while automatic rollback remains armed"
if ! health_metadata=$(curl --fail --silent --show-error --retry 6 --retry-all-errors \
  --retry-delay 5 --max-time 10 --output "$public_health" \
  --write-out '%{http_code}|%{content_type}|%{num_redirects}' \
  "https://clustr-api.atlanteanz.com/health/ready?$public_query"); then
  fail "public API readiness failed"
fi
[ "$health_metadata" = '200|application/json|0' ] ||
  fail "public API readiness returned unexpected metadata: $health_metadata"
grep -Eq '"status"[[:space:]]*:[[:space:]]*"ready"' "$public_health" ||
  fail "public API readiness returned an unexpected body"

if ! aasa_metadata=$(curl --fail --silent --show-error --retry 6 --retry-all-errors \
  --retry-delay 5 --max-time 10 --output "$public_aasa" \
  --write-out '%{http_code}|%{content_type}|%{num_redirects}' \
  "https://clixor.atlanteanz.com/.well-known/apple-app-site-association?$public_query"); then
  fail "public Apple association document failed"
fi
[ "$aasa_metadata" = '200|application/json|0' ] ||
  fail "public Apple association document returned unexpected metadata: $aasa_metadata"
cmp -s "$stable_root/internal/httpapi/universal-links/apple-app-site-association" "$public_aasa" ||
  fail "public Apple association document did not exactly match the approved release"

if ! join_metadata=$(curl --fail --silent --show-error --retry 6 --retry-all-errors \
  --retry-delay 5 --max-time 10 --output "$public_join" \
  --write-out '%{http_code}|%{content_type}|%{num_redirects}' \
  "https://clixor.atlanteanz.com/join?$public_query"); then
  fail "public invite landing page failed"
fi
[ "$join_metadata" = '200|text/html; charset=utf-8|0' ] ||
  fail "public invite landing page returned unexpected metadata: $join_metadata"
cmp -s "$stable_root/internal/httpapi/universal-links/join.html" "$public_join" ||
  fail "public invite landing page was not the approved generic no-token page"

if ! me_metadata=$(curl --silent --show-error --retry 6 --retry-all-errors \
  --retry-delay 5 --max-time 10 --output "$public_me" \
  --write-out '%{http_code}|%{content_type}|%{num_redirects}' \
  "https://clustr-api.atlanteanz.com/v1/me?$public_query"); then
  fail "public unauthenticated account boundary probe failed"
fi
[ "$me_metadata" = '401|application/json|0' ] ||
  fail "public unauthenticated account boundary returned unexpected metadata: $me_metadata"

ln -sfn "$release_dir" "$release_root/current"
rollback_needed=0
runtime_config_restore_needed=0
stable_repo_restore_needed=0
log "deployed $new_image; replica, gateway, and public readiness gates passed"
