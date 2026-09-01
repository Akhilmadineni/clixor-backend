#!/bin/sh
set -eu
umask 077

backup_root=${CLIXOR_BACKUP_ROOT:-/srv/clixor/backups}
local_max_age=${CLIXOR_LOCAL_BACKUP_MAX_AGE_MINUTES:-480}
offsite_max_age=${CLIXOR_OFFSITE_BACKUP_MAX_AGE_MINUTES:-480}
restore_max_age=${CLIXOR_RESTORE_DRILL_MAX_AGE_MINUTES:-43200}

fail() {
  echo "Clixor backup health check failed: $*" >&2
  exit 1
}

validate_minutes() {
  case "$2" in
    ''|*[!0-9]*) fail "$1 must be a positive integer" ;;
  esac
  [ "$2" -gt 0 ] || fail "$1 must be greater than zero"
}

is_fresh_file() {
  [ -f "$1" ] || return 1
  [ -n "$(find "$1" -prune -type f -mmin "-$2" -print 2>/dev/null)" ]
}

validate_minutes CLIXOR_LOCAL_BACKUP_MAX_AGE_MINUTES "${local_max_age}"
validate_minutes CLIXOR_OFFSITE_BACKUP_MAX_AGE_MINUTES "${offsite_max_age}"
validate_minutes CLIXOR_RESTORE_DRILL_MAX_AGE_MINUTES "${restore_max_age}"

for command_name in find sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing command: ${command_name}"
done

postgres_root="${backup_root}/postgres"
[ -d "${postgres_root}" ] || fail "local PostgreSQL backup directory is missing"
is_fresh_file "${postgres_root}/LAST_SUCCESS" "${local_max_age}" || \
  fail "local PostgreSQL backup success marker is stale or missing"

latest_dump="$(find "${postgres_root}" -type f -name 'clixor-*.dump' \
  -mmin "-${local_max_age}" -print | sort | tail -n 1)"
[ -n "${latest_dump}" ] || fail "no fresh local PostgreSQL dump exists"
[ -s "${latest_dump}.sha256" ] || fail "latest local dump has no checksum sidecar"
(
  cd "$(dirname "${latest_dump}")"
  sha256sum --check "$(basename "${latest_dump}").sha256" >/dev/null
) || fail "latest local dump checksum validation failed"

is_fresh_file "${backup_root}/OFFSITE_LAST_SUCCESS" "${offsite_max_age}" || \
  fail "offsite backup success marker is stale or missing"
is_fresh_file "${backup_root}/RESTORE_DRILL_LAST_SUCCESS" "${restore_max_age}" || \
  fail "isolated restore-drill success marker is stale or missing"

if [ "${CLIXOR_CHECK_SYSTEMD_RESULT:-true}" = "true" ] && \
  command -v systemctl >/dev/null 2>&1; then
  for service_name in clixor-offsite-backup.service clixor-restore-drill.service; do
    systemctl cat "${service_name}" >/dev/null 2>&1 || continue
    service_result="$(systemctl show "${service_name}" --property=Result --value)"
    [ "${service_result}" = "success" ] || \
      fail "${service_name} result is ${service_result:-unknown}"
  done
fi

echo "Clixor local backup, offsite backup, and isolated restore-drill markers are fresh."
