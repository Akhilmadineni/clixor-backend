#!/bin/sh
set -eu
umask 077

backup_root=/backups/postgres
mkdir -p "${backup_root}"

export PGHOST=postgres.clixor.internal
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/run/pki/ca.crt

while true; do
  until pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; do
    sleep 5
  done

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  partial="${backup_root}/.clixor-${timestamp}.dump.partial"
  destination="${backup_root}/clixor-${timestamp}.dump"
  pg_dump \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --format custom \
    --compress 9 \
    --file "${partial}"
  pg_restore --list "${partial}" >/dev/null
  mv "${partial}" "${destination}"
  (
    cd "${backup_root}"
    sha256sum "$(basename "${destination}")" > "$(basename "${destination}").sha256"
  )
  date -u +%Y-%m-%dT%H:%M:%SZ > "${backup_root}/LAST_SUCCESS"

  # Local backups protect against operator error, not VM or availability-domain
  # loss. Seven days keeps the Always Free boot volume from filling silently.
  find "${backup_root}" -type f -mtime +7 -delete
  sleep 21600
done
