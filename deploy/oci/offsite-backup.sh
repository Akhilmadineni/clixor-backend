#!/bin/sh
set -eu
umask 077

backup_root=${CLIXOR_BACKUP_ROOT:-/srv/clixor/backups}
bucket=${OCI_BACKUP_BUCKET:?set OCI_BACKUP_BUCKET to the private versioned backup bucket}
prefix=${OCI_BACKUP_PREFIX:-clixor}
local_max_age=${CLIXOR_LOCAL_BACKUP_MAX_AGE_MINUTES:-480}
lock_root=${CLIXOR_BACKUP_LOCK_ROOT:-/run/clixor-backup}

fail() {
  echo "Clixor offsite backup failed: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
case "${bucket}" in
  ''|*[!A-Za-z0-9._-]*) fail "OCI_BACKUP_BUCKET contains unsupported characters" ;;
esac
case "${prefix}" in
  ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) fail "OCI_BACKUP_PREFIX contains unsupported characters" ;;
esac
[ "${#prefix}" -le 63 ] || fail "OCI_BACKUP_PREFIX is longer than 63 characters"
case "${local_max_age}" in
  ''|*[!0-9]*) fail "CLIXOR_LOCAL_BACKUP_MAX_AGE_MINUTES must be a positive integer" ;;
esac
[ "${local_max_age}" -gt 0 ] || fail "CLIXOR_LOCAL_BACKUP_MAX_AGE_MINUTES must be greater than zero"

for command_name in cmp find flock grep mktemp oci sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done

mkdir -p "${lock_root}"
chmod 0700 "${lock_root}"
exec 9>"${lock_root}/offsite.lock"
flock -n 9 || fail "another offsite backup is already running"

verify_root="$(mktemp -d "${backup_root}/.offsite-verify.XXXXXXXX")"
cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  case "${verify_root}" in
    "${backup_root}"/.offsite-verify.*) rm -rf -- "${verify_root}" ;;
    *) echo "Refusing to remove unexpected verification path: ${verify_root}" >&2; exit 1 ;;
  esac
  exit "${original_status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

postgres_root="${backup_root}/postgres"
[ -d "${postgres_root}" ] || fail "PostgreSQL backup directory is missing"
latest_dump="$(find "${postgres_root}" -type f -name 'clixor-*.dump' \
  -mmin "-${local_max_age}" -print | sort | tail -n 1)"
[ -n "${latest_dump}" ] || fail "no fresh PostgreSQL dump is available"
[ "$(basename "${latest_dump}" | grep -Ec '^clixor-[0-9]{8}T[0-9]{6}Z\.dump$')" -eq 1 ] || \
  fail "latest PostgreSQL dump has an invalid filename"
[ -s "${latest_dump}.sha256" ] || fail "latest PostgreSQL dump has no checksum sidecar"
(
  cd "$(dirname "${latest_dump}")"
  sha256sum --check "$(basename "${latest_dump}").sha256" >/dev/null
) || fail "latest PostgreSQL dump checksum validation failed"

# Instance-principal authentication is the only supported cloud credential.
export OCI_CLI_AUTH=instance_principal
export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
namespace="$(oci os ns get --query data --raw-output)"
[ -n "${namespace}" ] || fail "could not resolve the Object Storage namespace"

object_prefix="${prefix}/postgres/$(basename "${latest_dump}")"
upload_immutable() {
  local_path=$1
  object_name=$2
  remote_copy="${verify_root}/$(basename "${object_name}").existing"
  if oci os object head \
    --namespace-name "${namespace}" \
    --bucket-name "${bucket}" \
    --name "${object_name}" >/dev/null 2>&1; then
    oci os object get \
      --namespace-name "${namespace}" \
      --bucket-name "${bucket}" \
      --name "${object_name}" \
      --file "${remote_copy}"
    cmp "${local_path}" "${remote_copy}" >/dev/null || \
      fail "existing immutable object does not match the local backup"
    rm -f -- "${remote_copy}"
    return
  fi
  if ! oci os object put \
    --namespace-name "${namespace}" \
    --bucket-name "${bucket}" \
    --file "${local_path}" \
    --name "${object_name}" \
    --no-multipart \
    --no-overwrite \
    --opc-checksum-algorithm SHA256 \
    --verify-checksum >/dev/null; then
    # A competing immutable creator can win after the HEAD. Accept it only if
    # downloading proves it is byte-for-byte identical to the local artifact.
    oci os object get \
      --namespace-name "${namespace}" \
      --bucket-name "${bucket}" \
      --name "${object_name}" \
      --file "${remote_copy}" || return 1
    cmp "${local_path}" "${remote_copy}" >/dev/null || \
      fail "concurrently created immutable object does not match the local backup"
    rm -f -- "${remote_copy}"
  fi
  oci os object head \
    --namespace-name "${namespace}" \
    --bucket-name "${bucket}" \
    --name "${object_name}" >/dev/null
}

# Publish the checksum first. A failed second upload leaves no dump candidate;
# rerunning is safe because both immutable object puts use --no-overwrite.
upload_immutable "${latest_dump}.sha256" "${object_prefix}.sha256"
upload_immutable "${latest_dump}" "${object_prefix}"

marker="${backup_root}/OFFSITE_LAST_SUCCESS"
marker_partial="${marker}.partial.$$"
{
  printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'object=%s\n' "${object_prefix}"
} > "${marker_partial}"
chmod 0600 "${marker_partial}"
mv "${marker_partial}" "${marker}"
echo "Offsite PostgreSQL backup is present in the private backup bucket."
