#!/bin/sh
set -eu
umask 077

expected_source_root=/opt/actions-runner-clixor/_work/clixor-backend/clixor-backend
source_root=${1:-}
source_sha=${2:-}
run_id=${3:-}

fail() {
  printf '[clixor-oci-actions] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run through the root-owned sudo entrypoint"
[ "$#" -eq 3 ] || fail "expected source workspace, revision, and run ID"

[ -x /usr/bin/git ] || fail "git is not installed at /usr/bin/git"
canonical_source_root="$(/usr/bin/readlink -f -- "${source_root}")"
[ "${canonical_source_root}" = "${expected_source_root}" ] || \
  fail "unexpected Actions workspace"
[ -d "${canonical_source_root}/.git" ] || fail "Actions workspace is not a Git checkout"

case "${source_sha}" in
  ''|*[!0-9a-f]*) fail "revision is not a lowercase Git object ID" ;;
esac
[ "${#source_sha}" -eq 40 ] || fail "revision must be a full 40-character Git object ID"
case "${run_id}" in
  ''|*[!A-Za-z0-9._-]*) fail "run ID contains unsupported characters" ;;
esac

actual_sha="$(/usr/bin/git -c safe.directory="${canonical_source_root}" \
  -C "${canonical_source_root}" rev-parse HEAD)"
[ "${actual_sha}" = "${source_sha}" ] || fail "checkout does not match approved revision"
[ -z "$(/usr/bin/git -c safe.directory="${canonical_source_root}" \
  -C "${canonical_source_root}" status --porcelain --untracked-files=all)" ] || \
  fail "checkout contains uncommitted or untracked files"

api_env=/srv/clixor/secrets/api.env
[ -f "${api_env}" ] && [ ! -L "${api_env}" ] || \
  fail "production API configuration is missing or unsafe"
[ "$(stat -c %u "${api_env}")" -eq 0 ] || \
  fail "production API configuration is not root-owned"
[ "$(stat -c %a "${api_env}")" = "600" ] || \
  fail "production API configuration must have mode 0600"
grep -qx 'CLUSTER_ENV=production' "${api_env}" || \
  fail "Actions deploys require CLUSTER_ENV=production"
grep -qx 'CLUSTER_VERIFICATION_PROVIDER=telnyx' "${api_env}" || \
  fail "Actions deploys require the Telnyx verification provider"
grep -qx 'CLUSTER_MAIL_PROVIDER=smtp' "${api_env}" || \
  fail "Actions deploys require durable SMTP password-reset delivery"

exec /bin/sh "${canonical_source_root}/deploy/oci/deploy.sh" \
  "${canonical_source_root}" "${source_sha}" "${run_id}"
