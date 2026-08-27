#!/bin/sh
set -eu
umask 077

project_root=/volume1/docker/clustr
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

for command_name in curl docker flock rsync; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done

[ -n "$source_root" ] || fail "source workspace argument is required"
[ -f "$source_root/go.mod" ] || fail "source workspace does not contain go.mod"
[ -f "$source_root/deploy/nas/compose.yaml" ] || fail "source workspace does not contain the NAS Compose model"
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

mkdir -p "$stable_root" "$release_dir" "$project_root/runtime"
chmod 700 "$release_dir"
exec 9>"$lock_file"
flock -n 9 || fail "another Clustr deployment holds $lock_file"

previous_image=$(docker inspect clustr-api-a --format '{{.Config.Image}}' 2>/dev/null || true)
if [ -z "$previous_image" ]; then
  previous_image=$(docker inspect clustr-api --format '{{.Config.Image}}' 2>/dev/null || true)
fi
if [ -f "$compose_file" ]; then
  cp "$compose_file" "$previous_compose"
fi
printf '%s\n' "$source_sha" >"$release_dir/source-sha"
printf '%s\n' "$previous_image" >"$release_dir/previous-image"

rollback_needed=0
rollback() {
  status=$?
  trap - 0
  if [ "$status" -ne 0 ] && [ "$rollback_needed" -eq 1 ]; then
    set +e
    log "deployment failed; attempting application rollback to $previous_image"
    if [ -n "$previous_image" ] && [ -s "$previous_compose" ]; then
      previous_tag=${previous_image#clustr-api:}
      cp "$previous_compose" "$compose_file"
      if grep -q '^CLUSTER_MAIL_PROVIDER=smtp$' "$runtime_env"; then
        CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$compose_file" --profile mail \
          up -d --no-build --remove-orphans
      else
        CLUSTER_IMAGE_TAG="$previous_tag" docker compose --file "$compose_file" \
          up -d --no-build --remove-orphans
      fi
      curl --fail --silent --show-error --max-time 10 http://127.0.0.1:18180/health/ready >/dev/null
      log "application rollback command completed; forward database migrations were not reversed"
    else
      log "no previous release was available for automatic rollback"
    fi
  fi
  exit "$status"
}
trap rollback 0
trap 'exit 130' INT
trap 'exit 143' TERM

log "building immutable release images for $source_sha"
docker build \
  --pull \
  --label "org.opencontainers.image.revision=$source_sha" \
  --label "org.opencontainers.image.source=https://github.com/Akhilmadineni/clixor-backend" \
  --tag "$new_image" \
  "$source_root"
docker build \
  --pull \
  --label "org.opencontainers.image.revision=$source_sha" \
  --label "org.opencontainers.image.source=https://github.com/Akhilmadineni/clixor-backend" \
  --tag "$mail_image" \
  --file "$source_root/deploy/nas/mail/Dockerfile" \
  "$source_root/deploy/nas/mail"
docker build \
  --pull \
  --tag "$bootstrap_image" \
  --file "$source_root/deploy/nas/bootstrap.Dockerfile" \
  "$source_root/deploy/nas"
docker image inspect "$new_image" --format '{{.Id}}'

log "syncing the CI-approved revision into $stable_root"
rsync -a --delete \
  --exclude='/.git/' \
  --exclude='/.DS_Store' \
  --exclude='/.build/' \
  --exclude='/coverage.out' \
  "$source_root/" "$stable_root/"

log "refreshing root-owned runtime configuration without exporting secrets"
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

mail_enabled=0
if grep -q '^CLUSTER_MAIL_PROVIDER=smtp$' "$runtime_env"; then
  mail_enabled=1
fi

compose_release() {
  if [ "$mail_enabled" -eq 1 ]; then
    CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" --profile mail "$@"
  else
    CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" "$@"
  fi
}

for network_name in clustr_internal homelab_proxy; do
  docker network inspect "$network_name" >/dev/null 2>&1 || fail "required external Docker network is missing: $network_name"
done

compose_release config --quiet
if [ "$mail_enabled" -eq 1 ]; then
  compose_release up -d --no-build postgres redis nats minio dependency-tls mail
else
  compose_release up -d --no-build postgres redis nats minio dependency-tls
  CLUSTER_IMAGE_TAG="$release_tag" docker compose --file "$compose_file" --profile mail stop mail >/dev/null 2>&1 || true
fi

if [ "$(docker inspect clustr-postgres --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ]; then
  log "capturing a pre-migration PostgreSQL snapshot"
  docker exec clustr-postgres sh -ec \
    'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
    >"$release_dir/pre-migration.dump"
  [ -s "$release_dir/pre-migration.dump" ] || fail "pre-migration PostgreSQL snapshot is empty"
  chmod 600 "$release_dir/pre-migration.dump"
else
  fail "PostgreSQL did not start; refusing to run migrations without a snapshot"
fi

log "applying transactional, forward-compatible database migrations"
compose_release --profile migration run --rm migrate

rollback_needed=1
compose_release up -d --no-build api-a api-b

# The original single API owns the public loopback port on the first HA rollout.
# Both replacement replicas are started before releasing that port so the
# gateway transition is the only interruption.
if [ "$(docker inspect clustr-api --format '{{.State.Running}}' 2>/dev/null || true)" = "true" ]; then
  docker stop --time 30 clustr-api
fi
compose_release up -d --no-build --remove-orphans

attempt=1
until curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18180/health/ready >/dev/null; do
  if [ "$attempt" -ge 60 ]; then
    compose_release ps
    if [ "$mail_enabled" -eq 1 ]; then
      compose_release logs --tail=100 mail api-a api-b api-gateway
    else
      compose_release logs --tail=100 api-a api-b api-gateway
    fi
    fail "local readiness did not pass within 120 seconds"
  fi
  attempt=$((attempt + 1))
  sleep 2
done

for replica in api-a api-b; do
  docker exec clustr-api-gateway wget --quiet --output-document=/dev/null \
    "http://${replica}:8080/health/ready" || fail "${replica} readiness failed through the ingress network"
done
rollback_needed=0

ln -sfn "$release_dir" "$release_root/current"
log "deployed $new_image; local readiness passed"
