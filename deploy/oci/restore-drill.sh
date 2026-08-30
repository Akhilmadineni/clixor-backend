#!/bin/sh
set -eu
umask 077

fail() {
  echo "Clixor isolated restore drill failed: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"

config_file=/etc/clixor/offsite-backup.env
[ -f "${config_file}" ] || fail "backup environment file is missing"
[ "$(stat -c %u "${config_file}")" -eq 0 ] || fail "backup environment file is not root-owned"
[ "$(stat -c %a "${config_file}")" = "600" ] || fail "backup environment file must have mode 0600"
# The bootstrap writes only validated, non-secret bucket and prefix values.
# shellcheck disable=SC1090
. "${config_file}"

bucket=${OCI_BACKUP_BUCKET:?backup environment is missing OCI_BACKUP_BUCKET}
prefix=${OCI_BACKUP_PREFIX:-clixor}
max_age=${CLIXOR_RESTORE_SOURCE_MAX_AGE_MINUTES:-1440}
restore_root=/srv/clixor/restore-drills
backup_root=/srv/clixor/backups
repo_root=/srv/clixor/repo
helper=/usr/local/libexec/clixor/backup_manifest.py
lock_root=/run/clixor-backup
postgres_image=postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa

case "${bucket}" in
  ''|*[!A-Za-z0-9._-]*) fail "OCI_BACKUP_BUCKET contains unsupported characters" ;;
esac
case "${prefix}" in
  ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) fail "OCI_BACKUP_PREFIX contains unsupported characters" ;;
esac
[ "${#prefix}" -le 63 ] || fail "OCI_BACKUP_PREFIX is longer than 63 characters"
case "${max_age}" in
  ''|*[!0-9]*) fail "CLIXOR_RESTORE_SOURCE_MAX_AGE_MINUTES must be a positive integer" ;;
esac
[ "${max_age}" -gt 0 ] || fail "CLIXOR_RESTORE_SOURCE_MAX_AGE_MINUTES must be greater than zero"
[ -x "${helper}" ] || fail "backup manifest helper is missing"

for command_name in awk df docker flock mktemp oci openssl python3 stat; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done
docker image inspect "${postgres_image}" >/dev/null 2>&1 || \
  fail "${postgres_image} is not installed; refusing an unreviewed pull"

install -d -m 0700 -o 0 -g 0 "${restore_root}" "${lock_root}"
exec 9>"${lock_root}/restore-drill.lock"
flock -n 9 || fail "another restore drill is already running"

container_name=
work_dir=
cleanup() {
  original_status=$?
  cleanup_status=0
  trap - EXIT HUP INT TERM
  set +e
  if [ -n "${container_name}" ]; then
    if ! docker rm --force "${container_name}" >/dev/null 2>&1; then
      echo "Could not remove restore container; retaining its isolated workspace." >&2
      cleanup_status=1
    else
      container_name=
    fi
  fi
  if [ -n "${work_dir}" ] && [ -z "${container_name}" ]; then
    case "${work_dir}" in
      "${restore_root}"/run.*) rm -rf -- "${work_dir}" || cleanup_status=1 ;;
      *) echo "Refusing to remove unexpected restore path: ${work_dir}" >&2; cleanup_status=1 ;;
    esac
  fi
  if [ "${original_status}" -ne 0 ]; then
    exit "${original_status}"
  fi
  exit "${cleanup_status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

work_dir="$(mktemp -d "${restore_root}/run.XXXXXXXX")"
input_root="${work_dir}/input"
pgdata_root="${work_dir}/pgdata"
install -d -m 0750 -o 0 -g 70 "${input_root}"
install -d -m 0700 -o 70 -g 70 "${pgdata_root}"

export OCI_CLI_AUTH=instance_principal
export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
namespace="$(oci os ns get --query data --raw-output)"
[ -n "${namespace}" ] || fail "could not resolve the Object Storage namespace"

listing="${work_dir}/objects.json"
oci os object list \
  --namespace-name "${namespace}" \
  --bucket-name "${bucket}" \
  --prefix "${prefix}/postgres/" \
  --fields name,size,timeCreated \
  --all > "${listing}"
latest_object="$(python3 "${helper}" select --prefix "${prefix}" \
  --max-age-minutes "${max_age}" --field name < "${listing}")"
object_size="$(python3 "${helper}" select --prefix "${prefix}" \
  --max-age-minutes "${max_age}" --field size < "${listing}")"
case "${object_size}" in
  ''|*[!0-9]*) fail "selected backup has an invalid size" ;;
esac
[ "${object_size}" -gt 0 ] || fail "selected backup is empty"

available_kb="$(df -Pk "${restore_root}" | awk 'NR == 2 {print $4}')"
case "${available_kb}" in
  ''|*[!0-9]*) fail "could not determine restore workspace free space" ;;
esac
# Reserve four compressed-dump sizes plus 2 GiB before attempting a restore.
# This is a preflight guard, not a substitute for filesystem capacity alerts.
required_kb=$((object_size / 1024 * 4 + 2097152))
[ "${available_kb}" -gt "${required_kb}" ] || \
  fail "insufficient isolated restore workspace capacity"

dump_name=${latest_object##*/}
dump_path="${input_root}/${dump_name}"
checksum_path="${dump_path}.sha256"
oci os object get \
  --namespace-name "${namespace}" \
  --bucket-name "${bucket}" \
  --name "${latest_object}.sha256" \
  --file "${checksum_path}.partial"
mv "${checksum_path}.partial" "${checksum_path}"
oci os object get \
  --namespace-name "${namespace}" \
  --bucket-name "${bucket}" \
  --name "${latest_object}" \
  --file "${dump_path}.partial"
mv "${dump_path}.partial" "${dump_path}"
python3 "${helper}" verify --dump "${dump_path}" --checksum "${checksum_path}"
chown 0:70 "${dump_path}" "${checksum_path}"
chmod 0440 "${dump_path}" "${checksum_path}"

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
container_name="clixor-restore-drill-${run_id}"
ephemeral_password="$(openssl rand -hex 32)"
env_file="${work_dir}/postgres.env"
{
  printf 'POSTGRES_DB=restore_drill\n'
  printf 'POSTGRES_USER=restore_admin\n'
  printf 'POSTGRES_PASSWORD=%s\n' "${ephemeral_password}"
} > "${env_file}"
chmod 0600 "${env_file}"

docker run --detach \
  --pull=never \
  --name "${container_name}" \
  --network none \
  --user 70:70 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 2g \
  --memory-swap 2g \
  --cpus 0.75 \
  --env-file "${env_file}" \
  --mount "type=bind,src=${pgdata_root},dst=/var/lib/postgresql/data" \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,size=16m,uid=70,gid=70,mode=0750 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,uid=70,gid=70,mode=1770 \
  "${postgres_image}" >/dev/null
rm -f -- "${env_file}"
# PostgreSQL retains its generated password in the isolated container
# environment. Do not retain it in this process or put it in docker-exec argv.
ephemeral_password=

attempt=1
until docker exec "${container_name}" sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_isready --username restore_admin --dbname restore_drill' \
  >/dev/null 2>&1; do
  [ "$(docker inspect "${container_name}" --format '{{.State.Running}}')" = "true" ] || \
    fail "ephemeral PostgreSQL exited during startup"
  [ "${attempt}" -lt 60 ] || fail "ephemeral PostgreSQL did not become ready"
  attempt=$((attempt + 1))
  sleep 2
done

docker exec -i "${container_name}" pg_restore --list < "${dump_path}" >/dev/null
docker exec -i "${container_name}" sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_restore --username restore_admin --dbname restore_drill --no-owner --no-privileges --exit-on-error' \
  < "${dump_path}"

expected_migrations="$(python3 "${helper}" migrations \
  --directory "${repo_root}/internal/store/postgres/migrations")"
actual_migrations="$(docker exec "${container_name}" sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec psql --username restore_admin --dbname restore_drill --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 --command "SELECT string_agg(version::text, chr(44) ORDER BY version) FROM schema_migrations;"')"
[ "${actual_migrations}" = "${expected_migrations}" ] || \
  fail "restored schema migration set does not match the checked-out release"

for table_name in users conversations conversation_members messages schema_migrations; do
  docker exec "${container_name}" sh -ec \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql --username restore_admin --dbname restore_drill --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 --command "$1"' \
    sh "SELECT count(*) FROM ${table_name};" >/dev/null
done
docker exec "${container_name}" sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_amcheck --username restore_admin --database restore_drill' \
  >/dev/null

marker="${backup_root}/RESTORE_DRILL_LAST_SUCCESS"
marker_partial="${marker}.partial.$$"
{
  printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'object=%s\n' "${latest_object}"
  printf 'migrations=%s\n' "${actual_migrations}"
} > "${marker_partial}"
chmod 0600 "${marker_partial}"
mv "${marker_partial}" "${marker}"
echo "Isolated PostgreSQL 17 restore drill passed; production data was not mounted or modified."
