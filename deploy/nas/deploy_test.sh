#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
deploy_script=$script_dir/deploy.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/clustr-deploy-test.XXXXXX")

cleanup() {
  status=$?
  trap - 0
  case "$test_root" in
    "${TMPDIR:-/tmp}"/clustr-deploy-test.*) rm -rf -- "$test_root" ;;
    *) printf 'refusing to remove unexpected test path: %s\n' "$test_root" >&2 ;;
  esac
  exit "$status"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM

fake_bin=$test_root/bin
mkdir -p "$fake_bin"

cat >"$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu

log_file=${DEPLOY_TEST_LOG:?}
state_dir=${DEPLOY_TEST_STATE_DIR:?}
failure=${DEPLOY_TEST_FAILURE:-none}
topology=${DEPLOY_TEST_TOPOLOGY:-ha}
project_root=${DEPLOY_TEST_PROJECT_ROOT:?}
printf 'docker tag=%s %s\n' "${CLUSTER_IMAGE_TAG:-none}" "$*" >>"$log_file"

write_runtime_candidate() {
  candidate=$project_root/runtime/api-gateway/nginx.conf
  mkdir -p "$(dirname "$candidate")"
  printf 'candidate gateway configuration\n' >"$candidate"
}

snapshot_runtime() {
  snapshot_root=$1
  mkdir -p "$snapshot_root/runtime/api-gateway"
  : >"$snapshot_root/missing-files"
  source_path=$project_root/runtime/api-gateway/nginx.conf
  if [ -f "$source_path" ]; then
    cp -p "$source_path" "$snapshot_root/runtime/api-gateway/nginx.conf"
  else
    printf '%s\n' runtime/api-gateway/nginx.conf >"$snapshot_root/missing-files"
  fi
}

restore_runtime() {
  snapshot_root=$1
  destination=$project_root/runtime/api-gateway/nginx.conf
  if [ -f "$snapshot_root/runtime/api-gateway/nginx.conf" ]; then
    mkdir -p "$(dirname "$destination")"
    cp -p "$snapshot_root/runtime/api-gateway/nginx.conf" "$destination"
  elif grep -Fqx runtime/api-gateway/nginx.conf "$snapshot_root/missing-files"; then
    rm -f "$destination"
  else
    exit 1
  fi
}

command_name=${1:-}
[ "$#" -eq 0 ] || shift
case "$command_name" in
  inspect)
    target=${1:-}
    case "$target" in
      clustr-api-a)
        [ -s "$state_dir/api-a.image" ] || exit 1
        cat "$state_dir/api-a.image"
        ;;
      clustr-api-b)
        [ -s "$state_dir/api-b.image" ] || exit 1
        cat "$state_dir/api-b.image"
        ;;
      clustr-postgres)
        [ -f "$state_dir/postgres.running" ] || exit 1
        printf 'true\n'
        ;;
      clustr-api-gateway)
        [ -f "$state_dir/gateway.running" ] || exit 1
        printf 'true\n'
        ;;
      clustr-api)
        if [ -f "$state_dir/legacy.running" ]; then
          case " $* " in
            *State.Running*) printf 'true\n' ;;
            *) cat "$state_dir/legacy.image" ;;
          esac
        else
          exit 1
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  image)
    [ "${1:-}" = inspect ] || exit 1
    printf '%s\n' "${DEPLOY_TEST_SOURCE_SHA:?}"
    ;;
  ps)
    target=
    for argument in "$@"; do
      case "$argument" in
        'name=^/clustr-api-a$') target=clustr-api-a ;;
        'name=^/clustr-api-b$') target=clustr-api-b ;;
        'name=^/clustr-api-gateway$') target=clustr-api-gateway ;;
        'name=^/clustr-media$') target=clustr-media ;;
        'name=^/clustr-mail$') target=clustr-mail ;;
        'name=^/clustr-postgres-backup$') target=clustr-postgres-backup ;;
        'name=^/clustr-prometheus$') target=clustr-prometheus ;;
        'name=^/clustr-grafana$') target=clustr-grafana ;;
        'name=^/clustr-dependency-tls$') target=clustr-dependency-tls ;;
        'name=^/clustr-redis$') target=clustr-redis ;;
        'name=^/clustr-nats$') target=clustr-nats ;;
        'name=^/clustr-minio$') target=clustr-minio ;;
      esac
    done
    [ -n "$target" ] || exit 1
    case "$failure:$target" in
      legacy-query-api-a:clustr-api-a|empty-query-gateway:clustr-api-gateway) exit 1 ;;
    esac
    case "$target" in
      clustr-api-a) [ ! -s "$state_dir/api-a.image" ] || printf '%s\n' "$target" ;;
      clustr-api-b) [ ! -s "$state_dir/api-b.image" ] || printf '%s\n' "$target" ;;
      clustr-api-gateway) [ ! -f "$state_dir/gateway.running" ] || printf '%s\n' "$target" ;;
    esac
    ;;
  build|network)
    exit 0
    ;;
  run)
    case " $* " in
      *" clustr-probe-postgres-data "*)
        printf 'postgres-data root probe\n' >>"$log_file"
        [ "$failure" != data-probe ] || exit 2
        case "$topology" in
          data-only|existing-down) printf 'present\n' ;;
          *) printf 'absent\n' ;;
        esac
        ;;
      *" clustr-snapshot-runtime-config "*)
        printf 'runtime-config snapshot\n' >>"$log_file"
        while [ "${1:-}" != clustr-snapshot-runtime-config ]; do shift; done
        shift
        ignored_project_root=${1:?}
        shift
        snapshot_runtime "${1:?}"
        ;;
      *" clustr-restore-runtime-config "*)
        printf 'runtime-config restore\n' >>"$log_file"
        while [ "${1:-}" != clustr-restore-runtime-config ]; do shift; done
        shift
        ignored_project_root=${1:?}
        shift
        restore_runtime "${1:?}"
        ;;
      *)
        printf 'runtime-config bootstrap\n' >>"$log_file"
        write_runtime_candidate
        [ "$failure" != bootstrap ] || exit 1
        ;;
    esac
    ;;
  stop)
    case " $* " in
      *" clustr-api"*) rm -f "$state_dir/legacy.running" ;;
    esac
    ;;
  rm)
    for target in "$@"; do
      case "$failure:$target" in
        legacy-rm-api-a:clustr-api-a|empty-rm-gateway:clustr-api-gateway) exit 1 ;;
      esac
    done
    for target in "$@"; do
      case "$target" in
        clustr-api-a) rm -f "$state_dir/api-a.image" ;;
        clustr-api-b) rm -f "$state_dir/api-b.image" ;;
        clustr-api-gateway) rm -f "$state_dir/gateway.running" ;;
        clustr-api) rm -f "$state_dir/legacy.running" ;;
        clustr-postgres) rm -f "$state_dir/postgres.running" ;;
      esac
    done
    ;;
  compose)
    action=
    update_a=0
    update_b=0
    service_seen=0
    list_services=0
    for argument in "$@"; do
      [ "$argument" != --services ] || list_services=1
      if [ -z "$action" ]; then
        case "$argument" in
          config|up|run|ps|logs|stop) action=$argument ;;
        esac
        continue
      fi
      case "$argument" in
        postgres|redis|nats|minio|dependency-tls|mail|migrate|api|api-gateway|media|postgres-backup|prometheus|grafana)
          service_seen=1
          ;;
        api-a)
          service_seen=1
          update_a=1
          ;;
        api-b)
          service_seen=1
          update_b=1
          ;;
      esac
    done
    if [ "$action" = config ] && [ "$list_services" -eq 1 ]; then
      if [ "$topology" = legacy ]; then
        printf '%s\n' postgres redis nats minio dependency-tls api media postgres-backup prometheus grafana
      else
        printf '%s\n' postgres redis nats minio dependency-tls mail migrate api-a api-b api-gateway media postgres-backup prometheus grafana
      fi
    fi
    if [ "$action" = up ]; then
      [ "$service_seen" -eq 1 ] || exit 91
      if [ "$update_a" -eq 1 ]; then
        printf 'clustr-api:%s\n' "${CLUSTER_IMAGE_TAG:?}" >"$state_dir/api-a.image"
        if [ "${CLUSTER_IMAGE_TAG:?}" != nas-old ]; then : >"$state_dir/rollout.started"; fi
      fi
      if [ "$update_b" -eq 1 ]; then
        printf 'clustr-api:%s\n' "${CLUSTER_IMAGE_TAG:?}" >"$state_dir/api-b.image"
        if [ "${CLUSTER_IMAGE_TAG:?}" != nas-old ]; then : >"$state_dir/rollout.started"; fi
      fi
      for argument in "$@"; do
        case "$argument" in
          postgres) : >"$state_dir/postgres.running" ;;
          api-gateway) : >"$state_dir/gateway.running" ;;
          api)
            printf 'clustr-api:%s\n' "${CLUSTER_IMAGE_TAG:?}" >"$state_dir/legacy.image"
            : >"$state_dir/legacy.running"
            ;;
        esac
      done
    fi
    if [ "$action" = run ] && [ "$failure" = migration ]; then
      exit 1
    fi
    exit 0
    ;;
  exec)
    if [ "${1:-}" = -i ]; then shift; fi
    container=${1:-}
    [ "$#" -eq 0 ] || shift
    case "$container:$*" in
      clustr-postgres:*pg_dump*) printf 'PGDMP deterministic test archive\n' ;;
      clustr-postgres:*pg_restore*--version*)
        if [ "$failure" = pg-version ]; then
          printf 'pg_restore (PostgreSQL) 16.9\n'
        else
          printf 'pg_restore (PostgreSQL) 17.5\n'
        fi
        ;;
      clustr-postgres:*pg_restore*--list*)
        [ "$failure" != catalog ] || exit 1
        printf '; deterministic PostgreSQL archive catalog\n'
        ;;
      clustr-api-gateway:*api-a*)
        [ -f "$state_dir/gateway.running" ] || exit 1
        image=$(cat "$state_dir/api-a.image")
        if { [ "$failure" = api-a ] || [ "$failure" = gateway-api-a ]; } &&
          [ "$image" != 'clustr-api:nas-old' ]; then exit 1; fi
        if [ -f "$state_dir/rollback.failure-triggered" ] &&
          [ "$failure" = public-health-rollback-a ] &&
          [ "$image" = 'clustr-api:nas-old' ]; then exit 1; fi
        ;;
      clustr-dependency-tls:*api-a*)
        image=$(cat "$state_dir/api-a.image")
        if [ "$failure" = api-a ] && [ "$image" != 'clustr-api:nas-old' ]; then exit 1; fi
        ;;
      clustr-api-gateway:*api-b*)
        [ -f "$state_dir/gateway.running" ] || exit 1
        image=$(cat "$state_dir/api-b.image")
        if [ "$failure" = api-b ] && [ "$image" != 'clustr-api:nas-old' ]; then exit 1; fi
        if [ -f "$state_dir/rollback.failure-triggered" ] &&
          [ "$failure" = public-health-rollback-b ] &&
          [ "$image" = 'clustr-api:nas-old' ]; then exit 1; fi
        ;;
      clustr-dependency-tls:*api-b*)
        image=$(cat "$state_dir/api-b.image")
        if [ "$failure" = api-b ] && [ "$image" != 'clustr-api:nas-old' ]; then exit 1; fi
        ;;
    esac
    ;;
  *)
    printf 'unexpected fake docker command: %s\n' "$command_name" >&2
    exit 1
    ;;
esac
EOF

cat >"$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu

output=
write_out=
url=
state_dir=${DEPLOY_TEST_STATE_DIR:?}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      output=$2
      shift 2
      ;;
    --write-out)
      write_out=$2
      shift 2
      ;;
    http://*|https://*)
      url=$1
      shift
      ;;
    --retry|--retry-delay|--max-time)
      shift 2
      ;;
    *) shift ;;
  esac
done
printf 'curl %s\n' "$url" >>"${DEPLOY_TEST_LOG:?}"

failure=${DEPLOY_TEST_FAILURE:-none}
case "$url:$failure" in
  *clustr-api.atlanteanz.com/health/ready*:public-health|\
  *clustr-api.atlanteanz.com/health/ready*:public-health-rollback-a|\
  *clustr-api.atlanteanz.com/health/ready*:public-health-rollback-b|\
  *clustr-api.atlanteanz.com/health/ready*:legacy-rm-api-a|\
  *clustr-api.atlanteanz.com/health/ready*:empty-rm-gateway|\
  *clustr-api.atlanteanz.com/health/ready*:legacy-query-api-a|\
  *clustr-api.atlanteanz.com/health/ready*:empty-query-gateway|\
  *clixor.atlanteanz.com/.well-known/apple-app-site-association*:public-aasa|\
  *clixor.atlanteanz.com/join*:public-join|\
  *clustr-api.atlanteanz.com/v1/me*:public-me)
    : >"$state_dir/rollback.failure-triggered"
    exit 22
    ;;
esac

metadata=
case "$url" in
  http://127.0.0.1:18180/health/ready*) metadata='200|application/json|0' ;;
  https://clustr-api.atlanteanz.com/health/ready*)
    metadata='200|application/json|0'
    [ -z "$output" ] || printf '{"status":"ready"}\n' >"$output"
    ;;
  https://clixor.atlanteanz.com/.well-known/apple-app-site-association*)
    metadata='200|application/json|0'
    [ -z "$output" ] || cp "${DEPLOY_TEST_EXPECTED_AASA:?}" "$output"
    ;;
  https://clixor.atlanteanz.com/join*)
    metadata='200|text/html; charset=utf-8|0'
    [ -z "$output" ] || cp "${DEPLOY_TEST_EXPECTED_JOIN:?}" "$output"
    ;;
  https://clustr-api.atlanteanz.com/v1/me*)
    metadata='401|application/json|0'
    [ -z "$output" ] || printf '{"error":{"code":"unauthenticated"}}\n' >"$output"
    ;;
  *)
    printf 'unexpected fake curl URL: %s\n' "$url" >&2
    exit 1
    ;;
esac
[ -z "$write_out" ] || printf '%s' "$metadata"
EOF

cat >"$fake_bin/flock" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$fake_bin/rsync" <<'EOF'
#!/bin/sh
set -eu
printf 'rsync %s\n' "$*" >>"${DEPLOY_TEST_LOG:?}"
delete_destination=0
for argument in "$@"; do
  [ "$argument" != --delete ] || delete_destination=1
done
while [ "$#" -gt 2 ]; do shift; done
source_path=${1%/}
destination=$2
case "$destination" in
  "${DEPLOY_TEST_PROJECT_ROOT:?}"/*) ;;
  *) printf 'refusing fake rsync destination: %s\n' "$destination" >&2; exit 1 ;;
esac
mkdir -p "$destination"
if [ "$delete_destination" -eq 1 ]; then
  for existing in "$destination"/* "$destination"/.[!.]* "$destination"/..?*; do
    if [ -e "$existing" ] || [ -L "$existing" ]; then
      rm -rf -- "$existing"
    fi
  done
fi
cp -R "$source_path/." "$destination/"
EOF

cat >"$fake_bin/sha256sum" <<'EOF'
#!/bin/sh
set -eu
printf 'sha256sum %s\n' "$*" >>"${DEPLOY_TEST_LOG:?}"
if [ "${1:-}" = -c ]; then
  [ "${DEPLOY_TEST_FAILURE:-none}" != checksum ] || exit 1
  exit 0
fi
printf '0123456789abcdef  %s\n' "${1:?}"
EOF

cat >"$fake_bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF

chmod 755 "$fake_bin"/*

source_sha=0123456789abcdef0123456789abcdef01234567
new_tag=nas-0123456789ab-test
new_image=clustr-api:$new_tag
old_image=clustr-api:nas-old

fail_test() {
  printf 'deploy harness failure: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  file=$1
  pattern=$2
  grep -Fq -- "$pattern" "$file" || fail_test "missing '$pattern' in $file"
}

assert_not_contains() {
  file=$1
  pattern=$2
  if grep -Fq -- "$pattern" "$file"; then
    fail_test "unexpected '$pattern' in $file"
  fi
}

first_line() {
  file=$1
  pattern=$2
  grep -n -F -m 1 -- "$pattern" "$file" | cut -d: -f1
}

assert_before() {
  file=$1
  first=$2
  second=$3
  first_number=$(first_line "$file" "$first")
  second_number=$(first_line "$file" "$second")
  [ "$first_number" -lt "$second_number" ] ||
    fail_test "'$first' did not occur before '$second'"
}

assert_file_equals() {
  file=$1
  expected=$2
  [ -f "$file" ] || fail_test "missing expected file: $file"
  actual=$(cat "$file")
  [ "$actual" = "$expected" ] ||
    fail_test "$file contained '$actual', expected '$expected'"
}

prepare_case() {
  case_name=$1
  provider=$2
  topology=$3
  case_dir=$test_root/$case_name
  source_dir=$case_dir/source
  project_dir=$case_dir/project
  state_dir=$case_dir/state
  mkdir -p \
    "$source_dir/deploy/nas" \
    "$source_dir/internal/httpapi/universal-links" \
    "$project_dir/secrets" \
    "$state_dir"
  printf 'module github.com/Akhilmadineni/clixor-backend\n' >"$source_dir/go.mod"
  printf 'candidate source tree\n' >"$source_dir/release-marker"
  cp "$repository_root/deploy/nas/compose.yaml" "$source_dir/deploy/nas/compose.yaml"
  cp "$repository_root/internal/httpapi/universal-links/apple-app-site-association" \
    "$source_dir/internal/httpapi/universal-links/apple-app-site-association"
  cp "$repository_root/internal/httpapi/universal-links/join.html" \
    "$source_dir/internal/httpapi/universal-links/join.html"
  printf 'CLUSTER_MAIL_PROVIDER=%s\n' "$provider" >"$project_dir/secrets/runtime.env"
  case "$topology" in
    ha|existing-down)
      mkdir -p "$project_dir/repo/deploy/nas" "$project_dir/runtime/api-gateway"
      cp "$repository_root/deploy/nas/compose.yaml" "$project_dir/repo/deploy/nas/compose.yaml"
      printf 'previous source tree\n' >"$project_dir/repo/release-marker"
      printf 'previous gateway configuration\n' >"$project_dir/runtime/api-gateway/nginx.conf"
      printf '%s\n' "$old_image" >"$state_dir/api-a.image"
      printf '%s\n' "$old_image" >"$state_dir/api-b.image"
      : >"$state_dir/gateway.running"
      [ "$topology" != ha ] || : >"$state_dir/postgres.running"
      if [ "$topology" = existing-down ]; then
        mkdir -p "$project_dir/data/postgres"
        printf 'existing database bytes\n' >"$project_dir/data/postgres/PG_VERSION"
      fi
      ;;
    legacy)
      mkdir -p "$project_dir/repo/deploy/nas" "$project_dir/runtime/api-gateway"
      printf 'services:\n  api:\n    image: clustr-api:${CLUSTER_IMAGE_TAG}\n' \
        >"$project_dir/repo/deploy/nas/compose.yaml"
      printf 'previous source tree\n' >"$project_dir/repo/release-marker"
      printf 'previous gateway configuration\n' >"$project_dir/runtime/api-gateway/nginx.conf"
      printf '%s\n' "$old_image" >"$state_dir/legacy.image"
      : >"$state_dir/legacy.running"
      : >"$state_dir/postgres.running"
      ;;
    empty) ;;
    data-only)
      # This deliberately has no API image and no running PostgreSQL
      # container. The fake root-in-container probe reports the retained data,
      # exercising the recovery state that an unprivileged runner cannot
      # safely enumerate itself.
      mkdir -p "$project_dir/data/postgres"
      printf 'existing database bytes\n' >"$project_dir/data/postgres/PG_VERSION"
      ;;
    *) fail_test "unknown test topology: $topology" ;;
  esac
  : >"$case_dir/commands.log"
}

run_case() {
  case_name=$1
  provider=$2
  failure=$3
  expected=$4
  topology=${5:-ha}
  prepare_case "$case_name" "$provider" "$topology"
  case_dir=$test_root/$case_name
  if [ "$failure" = release-collision ]; then
    mkdir -p "$case_dir/project/releases/$new_tag"
    printf 'prior attempt artifact\n' >"$case_dir/project/releases/$new_tag/sentinel"
  fi
  if PATH="$fake_bin:$PATH" \
    CLUSTER_DEPLOY_PROJECT_ROOT="$case_dir/project" \
    DEPLOY_TEST_LOG="$case_dir/commands.log" \
    DEPLOY_TEST_STATE_DIR="$case_dir/state" \
    DEPLOY_TEST_PROJECT_ROOT="$case_dir/project" \
    DEPLOY_TEST_TOPOLOGY="$topology" \
    DEPLOY_TEST_SOURCE_SHA="$source_sha" \
    DEPLOY_TEST_FAILURE="$failure" \
    DEPLOY_TEST_EXPECTED_AASA="$case_dir/source/internal/httpapi/universal-links/apple-app-site-association" \
    DEPLOY_TEST_EXPECTED_JOIN="$case_dir/source/internal/httpapi/universal-links/join.html" \
    sh "$deploy_script" "$case_dir/source" "$source_sha" test \
    >"$case_dir/output.log" 2>&1; then
    actual=success
  else
    actual=failure
  fi
  [ "$actual" = "$expected" ] ||
    fail_test "$case_name returned $actual, expected $expected; see $case_dir/output.log"
  if grep -E "tag=$new_tag .* up .*api-a .*api-b|tag=$new_tag .* up .*api-b .*api-a" \
    "$case_dir/commands.log" >/dev/null; then
    fail_test "$case_name updated both API replicas in one command"
  fi
}

run_case success disabled none success
success_log=$test_root/success/commands.log
assert_not_contains "$success_log" "--tag clustr-mail:$new_tag"
if grep -E ' compose .* up .* mail([[:space:]]|$)' "$success_log" >/dev/null; then
  fail_test "disabled mail provider was started"
fi
assert_before "$success_log" "sha256sum -c pre-migration.dump.sha256" "run --rm migrate"
assert_before "$success_log" "pg_restore --version" "pg_restore --list"
assert_before "$success_log" "sha256sum -c pre-migration.dump.sha256" "pg_restore --list"
assert_before "$success_log" "pg_restore --list" "rsync -a "
assert_before "$success_log" "runtime-config snapshot" "rsync -a --delete"
assert_before "$success_log" "rsync -a --delete" "runtime-config bootstrap"
assert_before "$success_log" "runtime-config bootstrap" "compose --file $test_root/success/project/repo/deploy/nas/compose.yaml up -d --no-build postgres"
assert_before "$success_log" "pg_restore --list" "run --rm migrate"
assert_before "$success_log" "run --rm migrate" "up -d --no-build --no-deps api-a"
assert_before "$success_log" "up -d --no-build --no-deps api-a" "up -d --no-build --no-deps api-b"
assert_before "$success_log" "clustr-api.atlanteanz.com/health/ready" "clixor.atlanteanz.com/.well-known/apple-app-site-association"
assert_before "$success_log" "clixor.atlanteanz.com/.well-known/apple-app-site-association" "clixor.atlanteanz.com/join"
assert_before "$success_log" "clixor.atlanteanz.com/join" "clustr-api.atlanteanz.com/v1/me"
[ -L "$test_root/success/project/releases/current" ] || fail_test "successful release was not marked current"
assert_file_equals "$test_root/success/project/repo/release-marker" "candidate source tree"
assert_file_equals "$test_root/success/project/runtime/api-gateway/nginx.conf" "candidate gateway configuration"

run_case mail-enabled smtp none success
mail_log=$test_root/mail-enabled/commands.log
assert_contains "$mail_log" "--tag clustr-mail:$new_tag"
if ! grep -E ' compose .* up .* mail([[:space:]]|$)' "$mail_log" >/dev/null; then
  fail_test "enabled mail provider was not started"
fi

for snapshot_failure in checksum pg-version catalog; do
  run_case "$snapshot_failure" disabled "$snapshot_failure" failure
  failure_log=$test_root/$snapshot_failure/commands.log
  assert_not_contains "$failure_log" "run --rm migrate"
  assert_not_contains "$failure_log" "up -d --no-build --no-deps api-a"
  assert_not_contains "$failure_log" "up -d --no-build --no-deps api-b"
done

run_case existing-database-down disabled none failure existing-down
database_down_log=$test_root/existing-database-down/commands.log
assert_not_contains "$database_down_log" "rsync "
assert_not_contains "$database_down_log" "runtime-config bootstrap"
assert_not_contains "$database_down_log" "run --rm migrate"

run_case data-only-database-down disabled none failure data-only
data_only_down_log=$test_root/data-only-database-down/commands.log
assert_contains "$data_only_down_log" "postgres-data root probe"
assert_not_contains "$data_only_down_log" "rsync "
assert_not_contains "$data_only_down_log" "runtime-config bootstrap"
assert_not_contains "$data_only_down_log" "run --rm migrate"

run_case data-probe-error disabled data-probe failure empty
data_probe_error_log=$test_root/data-probe-error/commands.log
assert_contains "$data_probe_error_log" "postgres-data root probe"
assert_not_contains "$data_probe_error_log" "rsync "
assert_not_contains "$data_probe_error_log" "runtime-config bootstrap"
assert_not_contains "$data_probe_error_log" "run --rm migrate"

run_case release-collision disabled release-collision failure
release_collision_log=$test_root/release-collision/commands.log
assert_not_contains "$release_collision_log" " build "
assert_file_equals "$test_root/release-collision/project/releases/$new_tag/sentinel" "prior attempt artifact"

run_case bootstrap-failure disabled bootstrap failure
bootstrap_log=$test_root/bootstrap-failure/commands.log
assert_before "$bootstrap_log" "runtime-config bootstrap" "runtime-config restore"
assert_file_equals "$test_root/bootstrap-failure/project/repo/release-marker" "previous source tree"
assert_file_equals "$test_root/bootstrap-failure/project/runtime/api-gateway/nginx.conf" "previous gateway configuration"
assert_not_contains "$bootstrap_log" "run --rm migrate"

run_case migration-failure disabled migration failure
migration_failure_log=$test_root/migration-failure/commands.log
assert_contains "$migration_failure_log" "run --rm migrate"
assert_not_contains "$migration_failure_log" "tag=$new_tag compose --file $test_root/migration-failure/project/repo/deploy/nas/compose.yaml up -d --no-build --no-deps api-a"
assert_file_equals "$test_root/migration-failure/project/repo/release-marker" "previous source tree"
assert_file_equals "$test_root/migration-failure/project/runtime/api-gateway/nginx.conf" "previous gateway configuration"
assert_contains "$test_root/migration-failure/output.log" "application rollback completed"

run_case gateway-route-failure disabled gateway-api-a failure
gateway_failure_log=$test_root/gateway-route-failure/commands.log
assert_not_contains "$gateway_failure_log" "exec clustr-dependency-tls wget --quiet --output-document=/dev/null http://api-a:8080/health/ready"
assert_not_contains "$gateway_failure_log" "tag=$new_tag compose --file $test_root/gateway-route-failure/project/repo/deploy/nas/compose.yaml up -d --no-build --no-deps api-b"

run_case api-a-failure disabled api-a failure
api_a_log=$test_root/api-a-failure/commands.log
assert_contains "$api_a_log" "tag=nas-old compose"
assert_not_contains "$api_a_log" "tag=$new_tag compose --file $test_root/api-a-failure/project/repo/deploy/nas/compose.yaml up -d --no-build --no-deps api-b"
[ ! -e "$test_root/api-a-failure/project/releases/current" ] || fail_test "failed A rollout became current"

run_case api-b-failure disabled api-b failure
api_b_log=$test_root/api-b-failure/commands.log
assert_before "$api_b_log" "tag=nas-old compose --file $test_root/api-b-failure/project/releases/nas-0123456789ab-test/previous-compose.yaml up -d --no-build --no-deps api-b" \
  "tag=nas-old compose --file $test_root/api-b-failure/project/releases/nas-0123456789ab-test/previous-compose.yaml up -d --no-build --no-deps api-a"
[ ! -e "$test_root/api-b-failure/project/releases/current" ] || fail_test "failed B rollout became current"

for public_failure in public-health public-aasa public-join public-me; do
  run_case "$public_failure" disabled "$public_failure" failure
  public_log=$test_root/$public_failure/commands.log
  assert_before "$public_log" "tag=nas-old compose --file $test_root/$public_failure/project/releases/nas-0123456789ab-test/previous-compose.yaml up -d --no-build --no-deps api-b" \
    "tag=nas-old compose --file $test_root/$public_failure/project/releases/nas-0123456789ab-test/previous-compose.yaml up -d --no-build --no-deps api-a"
  [ ! -e "$test_root/$public_failure/project/releases/current" ] ||
    fail_test "$public_failure release became current"
  assert_file_equals "$test_root/$public_failure/project/repo/release-marker" "previous source tree"
  assert_file_equals "$test_root/$public_failure/project/runtime/api-gateway/nginx.conf" "previous gateway configuration"
  assert_before "$public_log" "runtime-config restore" "tag=nas-old compose"
done

run_case rollback-api-a-failure disabled public-health-rollback-a failure
rollback_a_output=$test_root/rollback-api-a-failure/output.log
assert_contains "$rollback_a_output" "automatic rollback is incomplete; operator intervention is required"
assert_not_contains "$rollback_a_output" "application rollback completed"

run_case rollback-api-b-failure disabled public-health-rollback-b failure
rollback_b_output=$test_root/rollback-api-b-failure/output.log
assert_contains "$rollback_b_output" "leaving ready candidate api-a in service because api-b rollback failed"
assert_contains "$rollback_b_output" "automatic rollback is incomplete; operator intervention is required"
assert_file_equals "$test_root/rollback-api-b-failure/state/api-a.image" "$new_image"

run_case legacy-success disabled none success legacy
legacy_success_log=$test_root/legacy-success/commands.log
assert_contains "$legacy_success_log" "exec clustr-dependency-tls wget --quiet --output-document=/dev/null http://api-a:8080/health/ready"
assert_file_equals "$test_root/legacy-success/state/api-a.image" "$new_image"
assert_file_equals "$test_root/legacy-success/state/api-b.image" "$new_image"
[ ! -e "$test_root/legacy-success/state/legacy.running" ] ||
  fail_test "legacy API remained running after successful HA transition"

run_case legacy-public-failure disabled public-health failure legacy
legacy_failure_log=$test_root/legacy-public-failure/commands.log
[ -f "$test_root/legacy-public-failure/state/legacy.running" ] ||
  fail_test "legacy API was not restored"
[ ! -e "$test_root/legacy-public-failure/state/api-a.image" ] ||
  fail_test "legacy rollback left api-a running"
[ ! -e "$test_root/legacy-public-failure/state/api-b.image" ] ||
  fail_test "legacy rollback left api-b running"
assert_file_equals "$test_root/legacy-public-failure/project/repo/release-marker" "previous source tree"
assert_file_equals "$test_root/legacy-public-failure/project/runtime/api-gateway/nginx.conf" "previous gateway configuration"
[ ! -e "$test_root/legacy-public-failure/project/releases/current" ] ||
  fail_test "failed legacy transition became current"

run_case legacy-cleanup-failure disabled legacy-rm-api-a failure legacy
legacy_cleanup_output=$test_root/legacy-cleanup-failure/output.log
assert_contains "$legacy_cleanup_output" "could not remove candidate container clustr-api-a"
assert_contains "$legacy_cleanup_output" "automatic rollback is incomplete; operator intervention is required"
assert_file_equals "$test_root/legacy-cleanup-failure/state/api-a.image" "$new_image"

run_case legacy-cleanup-query-failure disabled legacy-query-api-a failure legacy
legacy_query_output=$test_root/legacy-cleanup-query-failure/output.log
assert_contains "$legacy_query_output" "could not query candidate container clustr-api-a"
assert_contains "$legacy_query_output" "automatic rollback is incomplete; operator intervention is required"
assert_file_equals "$test_root/legacy-cleanup-query-failure/state/api-a.image" "$new_image"

run_case empty-success disabled none success empty
assert_file_equals "$test_root/empty-success/project/repo/release-marker" "candidate source tree"
assert_file_equals "$test_root/empty-success/project/runtime/api-gateway/nginx.conf" "candidate gateway configuration"

run_case empty-public-failure disabled public-health failure empty
empty_failure_dir=$test_root/empty-public-failure
[ ! -e "$empty_failure_dir/state/api-a.image" ] || fail_test "first-install rollback left api-a"
[ ! -e "$empty_failure_dir/state/api-b.image" ] || fail_test "first-install rollback left api-b"
[ ! -e "$empty_failure_dir/state/gateway.running" ] || fail_test "first-install rollback left the gateway"
[ -e "$empty_failure_dir/state/postgres.running" ] || fail_test "first-install rollback did not retain PostgreSQL"
[ ! -e "$empty_failure_dir/project/repo/release-marker" ] || fail_test "first-install rollback left candidate source"
[ ! -e "$empty_failure_dir/project/runtime/api-gateway/nginx.conf" ] || fail_test "first-install rollback left candidate gateway config"
[ ! -e "$empty_failure_dir/project/releases/current" ] || fail_test "failed first install became current"

run_case empty-cleanup-failure disabled empty-rm-gateway failure empty
empty_cleanup_output=$test_root/empty-cleanup-failure/output.log
assert_contains "$empty_cleanup_output" "could not remove candidate container clustr-api-gateway"
assert_contains "$empty_cleanup_output" "first-install cleanup is incomplete; operator intervention is required"
[ -e "$test_root/empty-cleanup-failure/state/gateway.running" ] ||
  fail_test "forced first-install cleanup failure did not leave the modeled gateway"

run_case empty-cleanup-query-failure disabled empty-query-gateway failure empty
empty_query_output=$test_root/empty-cleanup-query-failure/output.log
assert_contains "$empty_query_output" "could not query candidate container clustr-api-gateway"
assert_contains "$empty_query_output" "first-install cleanup is incomplete; operator intervention is required"
[ -e "$test_root/empty-cleanup-query-failure/state/gateway.running" ] ||
  fail_test "forced first-install query failure did not leave the modeled gateway"

printf 'deploy harness passed: HA/legacy/empty rollout, rollback, snapshot, runtime, mail, and public gates\n'
