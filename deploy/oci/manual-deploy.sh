#!/bin/sh
set -eu
umask 077
ulimit -c 0

PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
LC_ALL=C
export PATH HOME LC_ALL
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH XDG_CONFIG_HOME \
  GIT_DIR GIT_WORK_TREE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_COUNT GIT_PROXY_COMMAND GIT_SSH GIT_SSH_COMMAND GIT_ASKPASS \
  SSH_ASKPASS http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  LD_PRELOAD LD_LIBRARY_PATH

trusted_remote=https://github.com/Akhilmadineni/clixor-backend.git
mirror_root=/srv/clixor/runtime/manual-source.git
source_cache_root=/srv/clixor/runtime
stable_source_verifier=/usr/local/libexec/clixor/runtime_bundle.py
revision=${1:-}
run_id=${2:-}

fail() {
  printf '[clixor-manual-deploy] ERROR: %s\n' "$*" >&2
  exit 1
}

trusted_env() {
  /usr/bin/env -i PATH="${PATH}" HOME="${HOME}" LC_ALL="${LC_ALL}" \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 "$@"
}

[ "$(id -u)" -eq 0 ] || fail "run through sudo as root"
[ "$#" -eq 2 ] || fail "expected a full Git commit and non-secret run identifier"
case "${revision}" in
  ''|*[!0-9a-f]*) fail "revision is not a lowercase Git object ID" ;;
esac
[ "${#revision}" -eq 40 ] || fail "revision must be a full 40-character Git object ID"
case "${run_id}" in
  ''|*[!A-Za-z0-9._-]*) fail "run identifier contains unsupported characters" ;;
esac
[ "${#run_id}" -le 160 ] || fail "run identifier is too long"

for command_path in \
  /usr/bin/chmod /usr/bin/env /usr/bin/find /usr/bin/git /usr/bin/install \
  /usr/bin/mktemp /usr/bin/python3 /usr/bin/readlink /usr/bin/rm \
  /usr/bin/stat /usr/bin/tar
do
  [ -x "${command_path}" ] || fail "required trusted command is unavailable: ${command_path}"
done
[ -f "${stable_source_verifier}" ] && [ ! -L "${stable_source_verifier}" ] && \
  [ "$(/usr/bin/stat -c '%u:%g:%a' "${stable_source_verifier}")" = "0:0:500" ] || \
  fail "stable source verifier is missing or unsafe; run explicit bootstrap first"
[ -d "${source_cache_root}" ] && [ ! -L "${source_cache_root}" ] && \
  [ "$(/usr/bin/readlink -f -- "${source_cache_root}")" = "${source_cache_root}" ] && \
  { [ "$(/usr/bin/stat -c '%u:%g:%a' "${source_cache_root}")" = "0:0:700" ] || \
    [ "$(/usr/bin/stat -c '%u:%g:%a' "${source_cache_root}")" = "0:0:750" ]; } || \
  fail "manual source cache is unsafe"

if [ -e "${mirror_root}" ] || [ -L "${mirror_root}" ]; then
  [ -d "${mirror_root}" ] && [ ! -L "${mirror_root}" ] && \
    [ "$(/usr/bin/readlink -f -- "${mirror_root}")" = "${mirror_root}" ] && \
    [ "$(/usr/bin/stat -c %u "${mirror_root}")" -eq 0 ] || \
    fail "trusted source mirror is unsafe"
else
  /usr/bin/install -d -m 0700 -o 0 -g 0 "${mirror_root}"
  trusted_env /usr/bin/git init --bare --initial-branch=main \
    "${mirror_root}" >/dev/null
fi
/usr/bin/chmod 0700 "${mirror_root}"
[ -z "$(/usr/bin/find "${mirror_root}" \
  \( ! -user root -o -perm /022 -o \( ! -type d -a ! -type f \) \) \
  -print -quit)" ] || fail "trusted source mirror contains unsafe state"
trusted_env /usr/bin/git --git-dir="${mirror_root}" remote remove origin \
  >/dev/null 2>&1 || true
trusted_env /usr/bin/git --git-dir="${mirror_root}" remote add origin \
  "${trusted_remote}"
trusted_env /usr/bin/git --git-dir="${mirror_root}" fetch \
  --force --no-tags --depth=1 origin \
  "+${revision}:refs/clixor/manual-approved"
trusted_env /usr/bin/git --git-dir="${mirror_root}" fsck \
  --full --strict "${revision}" >/dev/null
[ "$(trusted_env /usr/bin/git --git-dir="${mirror_root}" rev-parse \
  refs/clixor/manual-approved^{commit})" = "${revision}" ] || \
  fail "fetched source does not match the requested commit"

work_root="$(/usr/bin/mktemp -d \
  "${source_cache_root}/approved-manual.${run_id}.XXXXXXXX")"
approved_source="${work_root}/source"
source_archive="${work_root}/source.tar"
cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  case "${work_root}" in
    "${source_cache_root}"/approved-manual.*)
      /usr/bin/rm -rf -- "${work_root}"
      ;;
    *)
      printf '[clixor-manual-deploy] ERROR: refusing unsafe cleanup path\n' >&2
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
  --format=tar --output="${source_archive}" "${revision}"
trusted_env /usr/bin/tar --extract --file="${source_archive}" \
  --directory="${approved_source}" --no-same-owner
/usr/bin/rm -f -- "${source_archive}"
/usr/bin/find "${approved_source}" -type d -exec /usr/bin/chmod 0500 {} +
/usr/bin/find "${approved_source}" -type f -perm /111 \
  -exec /usr/bin/chmod 0500 {} +
/usr/bin/find "${approved_source}" -type f ! -perm /111 \
  -exec /usr/bin/chmod 0400 {} +

trusted_env /usr/bin/python3 "${stable_source_verifier}" \
  verify-approved-source \
  --source "${approved_source}" \
  --source-sha "${revision}" \
  --git-dir "${mirror_root}" >/dev/null || \
  fail "archived source is not the exact requested Git commit"

# Preserve only deploy.sh's reviewed, non-secret control inputs. The approved
# Git directory is always replaced with this helper's root-owned mirror.
trusted_env \
  CLIXOR_APPROVED_GIT_DIR="${mirror_root}" \
  CLIXOR_ENABLE_CANARY_CONNECTOR="${CLIXOR_ENABLE_CANARY_CONNECTOR:-}" \
  CLIXOR_CANARY_CLOUDFLARE_ACCOUNT_ID="${CLIXOR_CANARY_CLOUDFLARE_ACCOUNT_ID:-}" \
  CLIXOR_CANARY_CLOUDFLARE_TUNNEL_ID="${CLIXOR_CANARY_CLOUDFLARE_TUNNEL_ID:-}" \
  CLIXOR_CANARY_CLOUDFLARE_SECRET_OCID="${CLIXOR_CANARY_CLOUDFLARE_SECRET_OCID:-}" \
  CLIXOR_CANARY_CLOUDFLARE_SECRET_VERSION="${CLIXOR_CANARY_CLOUDFLARE_SECRET_VERSION:-}" \
  CLIXOR_CANARY_CLOUDFLARE_CONFIG_VERSION="${CLIXOR_CANARY_CLOUDFLARE_CONFIG_VERSION:-}" \
  CLIXOR_INGRESS_STAGE="${CLIXOR_INGRESS_STAGE:-}" \
  CLIXOR_INITIAL_VAULT_CUTOVER="${CLIXOR_INITIAL_VAULT_CUTOVER:-}" \
  CLIXOR_PUBLIC_API_READINESS_URL="${CLIXOR_PUBLIC_API_READINESS_URL:-}" \
  CLIXOR_PUBLIC_ASSOCIATION_URL="${CLIXOR_PUBLIC_ASSOCIATION_URL:-}" \
  CLIXOR_PUBLIC_SMOKE_BASE_URL="${CLIXOR_PUBLIC_SMOKE_BASE_URL:-}" \
  CLIXOR_PUBLIC_SMOKE_LEGAL_URL="${CLIXOR_PUBLIC_SMOKE_LEGAL_URL:-}" \
  CLIXOR_REQUIRE_PUBLIC_SMOKE="${CLIXOR_REQUIRE_PUBLIC_SMOKE:-}" \
  CLIXOR_REQUIRE_VAULT_HYDRATION="${CLIXOR_REQUIRE_VAULT_HYDRATION:-}" \
  /bin/sh "${approved_source}/deploy/oci/deploy.sh" \
    "${approved_source}" "${revision}" "${run_id}"
