#!/bin/sh
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
LC_ALL=C
IFS="$(printf ' \t\n_')"
IFS=${IFS%_}
export PATH HOME LC_ALL
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH XDG_CONFIG_HOME \
  GIT_DIR GIT_WORK_TREE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_COUNT GIT_PROXY_COMMAND GIT_SSH GIT_SSH_COMMAND GIT_ASKPASS \
  SSH_ASKPASS http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  LD_PRELOAD LD_LIBRARY_PATH

repository=Akhilmadineni/clixor-backend
trusted_remote=https://github.com/Akhilmadineni/clixor-backend.git
trusted_workflow_ref="${repository}/.github/workflows/deploy-oci.yml@refs/heads/main"
approval_helper=/usr/local/libexec/clixor/verify-github-deploy
mirror_root=/srv/clixor/runtime/actions-source.git
source_cache_root=/srv/clixor/runtime
source_sha=${1:-}
source_run_id=${2:-}
deploy_run_id=${3:-}
deploy_run_attempt=${4:-}

fail() {
  printf '[clixor-oci-actions] ERROR: %s\n' "$*" >&2
  exit 1
}

trusted_env() {
  /usr/bin/env -i PATH="${PATH}" HOME="${HOME}" LC_ALL="${LC_ALL}" "$@"
}

[ "$(id -u)" -eq 0 ] || fail "run through the root-owned sudo entrypoint"
[ "$#" -eq 4 ] || \
  fail "expected source revision, source CI run, deploy run, and deploy attempt"

for command_path in \
  /usr/bin/chmod /usr/bin/env /usr/bin/git /usr/bin/install /usr/bin/mktemp \
  /usr/bin/python3 /usr/bin/rm /usr/bin/stat /usr/bin/tar
do
  [ -x "${command_path}" ] || fail "required trusted command is unavailable: ${command_path}"
done
[ -f "${approval_helper}" ] && [ ! -L "${approval_helper}" ] && \
  [ -r "${approval_helper}" ] || fail "root-owned GitHub approval verifier is missing"
[ "$(/usr/bin/stat -c %u "${approval_helper}")" -eq 0 ] || \
  fail "GitHub approval verifier is not root-owned"
case "$(/usr/bin/stat -c %a "${approval_helper}")" in
  500|550|700|750|755) ;;
  *) fail "GitHub approval verifier has unsafe permissions" ;;
esac

case "${source_sha}" in
  ''|*[!0-9a-f]*) fail "revision is not a lowercase Git object ID" ;;
esac
[ "${#source_sha}" -eq 40 ] || fail "revision must be a full 40-character Git object ID"
for numeric_value in "${source_run_id}" "${deploy_run_id}" "${deploy_run_attempt}"; do
  case "${numeric_value}" in
    ''|*[!0-9]*) fail "GitHub run identifiers must contain only digits" ;;
  esac
done

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

approval_audience="clixor-oci-production:${source_sha}:${source_run_id}:${deploy_run_id}:${deploy_run_attempt}"
trusted_env /usr/bin/python3 "${approval_helper}" \
  --repository "${repository}" \
  --workflow-ref "${trusted_workflow_ref}" \
  --source-run-id "${source_run_id}" \
  --source-sha "${source_sha}" \
  --deploy-run-id "${deploy_run_id}" \
  --deploy-run-attempt "${deploy_run_attempt}" \
  --audience "${approval_audience}" >/dev/null || \
  fail "GitHub did not approve this deployment caller and source run"

# The runner account is intentionally outside this trust boundary. Fetch the
# approved public main ref into a root-only bare repository, require the CI SHA
# to remain the exact main tip, and execute only an archive produced from those
# root-owned objects. No script from the writable Actions checkout runs as root.
if [ -e "${mirror_root}" ] || [ -L "${mirror_root}" ]; then
  [ -d "${mirror_root}" ] && [ ! -L "${mirror_root}" ] || \
    fail "trusted source mirror is not a regular directory"
  [ "$(/usr/bin/stat -c %u "${mirror_root}")" -eq 0 ] || \
    fail "trusted source mirror is not root-owned"
else
  /usr/bin/install -d -m 0700 -o 0 -g 0 "${mirror_root}"
  trusted_env /usr/bin/git init --bare --initial-branch=main "${mirror_root}" >/dev/null
fi
/usr/bin/chmod 0700 "${mirror_root}"
trusted_env /usr/bin/git --git-dir="${mirror_root}" remote remove origin >/dev/null 2>&1 || true
trusted_env /usr/bin/git --git-dir="${mirror_root}" remote add origin "${trusted_remote}"
trusted_env /usr/bin/git --git-dir="${mirror_root}" fetch \
  --force --prune --no-tags --depth=1 origin \
  '+refs/heads/main:refs/remotes/origin/main'
trusted_main="$(trusted_env /usr/bin/git --git-dir="${mirror_root}" rev-parse refs/remotes/origin/main)"
[ "${trusted_main}" = "${source_sha}" ] || \
  fail "CI-approved revision is no longer the exact trusted main tip"
trusted_env /usr/bin/git --git-dir="${mirror_root}" fsck --full --strict "${source_sha}" >/dev/null

work_root="$(/usr/bin/mktemp -d "${source_cache_root}/approved-source.${deploy_run_id}.${deploy_run_attempt}.XXXXXXXX")"
approved_source="${work_root}/source"
source_archive="${work_root}/source.tar"
cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  case "${work_root}" in
    "${source_cache_root}"/approved-source.*)
      /usr/bin/rm -rf -- "${work_root}"
      ;;
    *)
      printf '[clixor-oci-actions] ERROR: refusing to remove unexpected source path\n' >&2
      exit 1
      ;;
  esac
  exit "${original_status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

/usr/bin/install -d -m 0700 -o 0 -g 0 "${approved_source}"
trusted_env /usr/bin/git --git-dir="${mirror_root}" archive \
  --format=tar --output="${source_archive}" "${source_sha}"
trusted_env /usr/bin/tar --extract --file="${source_archive}" --directory="${approved_source}" \
  --no-same-owner
/usr/bin/rm -f -- "${source_archive}"
[ -f "${approved_source}/go.mod" ] || fail "approved archive has no Go module"
[ -f "${approved_source}/deploy/oci/deploy.sh" ] || \
  fail "approved archive has no OCI deployment entrypoint"

trusted_env CLIXOR_REQUIRE_PUBLIC_SMOKE=true \
  /bin/sh "${approved_source}/deploy/oci/deploy.sh" \
  "${approved_source}" "${source_sha}" "${deploy_run_id}-${deploy_run_attempt}"
