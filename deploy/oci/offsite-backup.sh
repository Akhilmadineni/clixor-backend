#!/bin/sh
set -eu

backup_root=${CLIXOR_BACKUP_ROOT:-/srv/clixor/backups}
bucket=${OCI_BACKUP_BUCKET:?set OCI_BACKUP_BUCKET to the versioned Object Storage bucket}
prefix=${OCI_BACKUP_PREFIX:-clixor}

for command_name in find oci sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "Missing required command: ${command_name}" >&2
    exit 1
  }
done

[ -d "${backup_root}/postgres" ] || {
  echo "PostgreSQL backup directory is missing: ${backup_root}/postgres" >&2
  exit 1
}
latest_dump="$(find "${backup_root}/postgres" -type f -name 'clixor-*.dump' -mmin -480 -print | sort | tail -n 1)"
[ -n "${latest_dump}" ] || {
  echo "No PostgreSQL dump newer than eight hours; refusing a stale off-instance upload." >&2
  exit 1
}
(
  cd "$(dirname "${latest_dump}")"
  sha256sum --check "$(basename "${latest_dump}").sha256"
)
# OCI_CLI_AUTH avoids static cloud access keys. The instance must belong to a
# dynamic group whose policy permits object management in only this bucket.
export OCI_CLI_AUTH=instance_principal
namespace="$(oci os ns get --query data --raw-output)"
[ -n "${namespace}" ] || {
  echo "Could not resolve the Object Storage namespace with instance principal." >&2
  exit 1
}

object_prefix="${prefix}/postgres/$(basename "${latest_dump}")"
oci os object put \
  --namespace-name "${namespace}" \
  --bucket-name "${bucket}" \
  --file "${latest_dump}" \
  --name "${object_prefix}"
oci os object put \
  --namespace-name "${namespace}" \
  --bucket-name "${bucket}" \
  --file "${latest_dump}.sha256" \
  --name "${object_prefix}.sha256"

date -u +%Y-%m-%dT%H:%M:%SZ > "${backup_root}/OFFSITE_LAST_SUCCESS"
echo "Off-instance PostgreSQL backup upload completed to ${bucket}/${prefix}/postgres/."
