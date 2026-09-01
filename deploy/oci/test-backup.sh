#!/bin/sh
set -eu

script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/clixor-backup-test.XXXXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT HUP INT TERM

postgres_root="${test_root}/postgres"
mkdir -p "${postgres_root}"
dump="${postgres_root}/clixor-20260830T120000Z.dump"
printf 'safe disposable backup fixture\n' > "${dump}"
(
  cd "${postgres_root}"
  sha256sum "$(basename "${dump}")" > "$(basename "${dump}").sha256"
)
printf '2026-08-30T12:00:00Z\n' > "${postgres_root}/LAST_SUCCESS"
printf 'timestamp=2026-08-30T12:05:00Z\n' > "${test_root}/OFFSITE_LAST_SUCCESS"
printf 'timestamp=2026-08-30T12:10:00Z\n' > "${test_root}/RESTORE_DRILL_LAST_SUCCESS"

CLIXOR_BACKUP_ROOT="${test_root}" \
CLIXOR_CHECK_SYSTEMD_RESULT=false \
  sh "${script_root}/backup-health.sh" >/dev/null

printf 'corruption\n' >> "${dump}"
if CLIXOR_BACKUP_ROOT="${test_root}" \
  CLIXOR_CHECK_SYSTEMD_RESULT=false \
  sh "${script_root}/backup-health.sh" >/dev/null 2>&1; then
  echo "backup health check accepted a corrupted dump" >&2
  exit 1
fi

printf 'safe disposable backup fixture\n' > "${dump}"
(
  cd "${postgres_root}"
  sha256sum "$(basename "${dump}")" > "$(basename "${dump}").sha256"
)
touch -t 202001010000 "${test_root}/OFFSITE_LAST_SUCCESS"
if CLIXOR_BACKUP_ROOT="${test_root}" \
  CLIXOR_CHECK_SYSTEMD_RESULT=false \
  sh "${script_root}/backup-health.sh" >/dev/null 2>&1; then
  echo "backup health check accepted a stale offsite marker" >&2
  exit 1
fi

touch "${test_root}/OFFSITE_LAST_SUCCESS"
fake_bin="${test_root}/bin"
object_root="${test_root}/objects"
lock_root="${test_root}/locks"
mkdir -p "${fake_bin}" "${object_root}"
cat > "${fake_bin}/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat > "${fake_bin}/flock" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "${fake_bin}/oci" <<'EOF'
#!/bin/sh
set -eu
[ "$1" = os ] || exit 2
case "$2:$3" in
  ns:get)
    printf 'testnamespace\n'
    ;;
  object:put)
    shift 3
    source_file=
    object_name=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --file) source_file=$2; shift 2 ;;
        --name) object_name=$2; shift 2 ;;
        --namespace-name|--bucket-name|--opc-checksum-algorithm) shift 2 ;;
        --no-multipart|--no-overwrite|--verify-checksum) shift ;;
        *) exit 2 ;;
      esac
    done
    [ -f "${source_file}" ] && [ -n "${object_name}" ] || exit 2
    destination="${OCI_TEST_OBJECT_ROOT}/${object_name}"
    [ ! -e "${destination}" ] || exit 1
    mkdir -p "$(dirname "${destination}")"
    cp "${source_file}" "${destination}"
    ;;
  object:head)
    shift 3
    object_name=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --name) object_name=$2; shift 2 ;;
        --namespace-name|--bucket-name) shift 2 ;;
        *) exit 2 ;;
      esac
    done
    [ -s "${OCI_TEST_OBJECT_ROOT}/${object_name}" ]
    ;;
  object:get)
    shift 3
    destination_file=
    object_name=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --file) destination_file=$2; shift 2 ;;
        --name) object_name=$2; shift 2 ;;
        --namespace-name|--bucket-name) shift 2 ;;
        *) exit 2 ;;
      esac
    done
    [ -s "${OCI_TEST_OBJECT_ROOT}/${object_name}" ] || exit 1
    [ -n "${destination_file}" ] || exit 2
    cp "${OCI_TEST_OBJECT_ROOT}/${object_name}" "${destination_file}"
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "${fake_bin}/id" "${fake_bin}/flock" "${fake_bin}/oci"

# Simulate an interrupted first run: the immutable checksum exists, but the
# matching dump does not. The next run must verify the checksum and continue.
object_prefix="${object_root}/clixor/postgres/$(basename "${dump}")"
mkdir -p "$(dirname "${object_prefix}")"
cp "${dump}.sha256" "${object_prefix}.sha256"

for run in 1 2; do
  PATH="${fake_bin}:${PATH}" \
  OCI_TEST_OBJECT_ROOT="${object_root}" \
  OCI_BACKUP_BUCKET=clixor-prod-backups \
  OCI_BACKUP_PREFIX=clixor \
  CLIXOR_BACKUP_ROOT="${test_root}" \
  CLIXOR_BACKUP_LOCK_ROOT="${lock_root}" \
    sh "${script_root}/offsite-backup.sh" >/dev/null
done
[ "$(find "${object_root}" -type f | wc -l | tr -d ' ')" -eq 2 ] || {
  echo "idempotent offsite upload did not retain exactly one immutable pair" >&2
  exit 1
}
cmp "${dump}" "${object_root}/clixor/postgres/$(basename "${dump}")"
cmp "${dump}.sha256" "${object_root}/clixor/postgres/$(basename "${dump}").sha256"

# Existing objects are accepted only when their bytes match. A collision must
# fail closed and must never replace the immutable remote object.
printf 'remote collision\n' > "${object_prefix}"
if PATH="${fake_bin}:${PATH}" \
  OCI_TEST_OBJECT_ROOT="${object_root}" \
  OCI_BACKUP_BUCKET=clixor-prod-backups \
  OCI_BACKUP_PREFIX=clixor \
  CLIXOR_BACKUP_ROOT="${test_root}" \
  CLIXOR_BACKUP_LOCK_ROOT="${lock_root}" \
    sh "${script_root}/offsite-backup.sh" >/dev/null 2>&1; then
  echo "offsite upload accepted a conflicting immutable object" >&2
  exit 1
fi
[ "$(cat "${object_prefix}")" = "remote collision" ] || {
  echo "offsite upload overwrote a conflicting immutable object" >&2
  exit 1
}

printf 'shell backup regression tests passed\n'
