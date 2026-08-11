#!/bin/sh
set -eu

backup_root=/backups/postgres
mkdir -p "${backup_root}"

export PGHOST=postgres.clustr.internal
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/run/pki/ca.crt

while true; do
  until pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; do
    sleep 5
  done

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  destination="${backup_root}/clustr-${timestamp}.dump"
  PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --format custom \
    --compress 9 \
    --file "${destination}"
  sha256sum "${destination}" > "${destination}.sha256"

  find "${backup_root}" -type f -mtime +35 -delete
  sleep 86400
done
