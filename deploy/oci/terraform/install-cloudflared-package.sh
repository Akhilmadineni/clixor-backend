#!/bin/sh
set -eu
umask 077
ulimit -c 0

# This is deliberately an exact reviewed release, not a moving "latest" URL.
# 2026.8.0 is intentionally excluded because of its reported path regression.
reviewed_cloudflared_version=2026.7.3
reviewed_cloudflared_package_url=https://github.com/cloudflare/cloudflared/releases/download/2026.7.3/cloudflared-linux-arm64.deb
reviewed_cloudflared_package_sha256=d3ea7d22dd337b465da33d6bc1c4b3cfd381407447a2a7d29542c19783430db3

fail() {
  printf '[clixor-cloudflared-package] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  [ -z "${pending_path:-}" ] || /usr/bin/rm -f -- "${pending_path}" || true
  [ -z "${package_work_root:-}" ] || \
    /usr/bin/rm -rf -- "${package_work_root}" || true
  [ -z "${install_work_root:-}" ] || \
    /usr/bin/rm -rf -- "${install_work_root}" || true
  exit "${status}"
}
trap cleanup 0 HUP INT TERM

[ "$(/usr/bin/id -u)" -eq 0 ] || fail "run as root"
case "$(/usr/bin/uname -m)" in
  aarch64|arm64) ;;
  *) fail "the reviewed package is for ARM64 only" ;;
esac
for required_program in \
  /usr/bin/curl /usr/bin/dpkg-deb /usr/bin/sha256sum \
  /usr/bin/cmp /usr/bin/id /usr/bin/install /usr/bin/mktemp /usr/bin/mv \
  /usr/bin/readlink /usr/bin/rm /usr/bin/sed /usr/bin/stat /usr/bin/sync \
  /usr/bin/uname
do
  [ -x "${required_program}" ] || fail "required program is unavailable: ${required_program}"
done

validate_binary() {
  binary_path=$1
  [ -f "${binary_path}" ] && [ ! -L "${binary_path}" ] || \
    fail "cloudflared candidate must be a regular file"
  [ "$(/usr/bin/readlink -f -- "${binary_path}")" = "${binary_path}" ] || \
    fail "cloudflared candidate path must be canonical"
  binary_metadata="$(/usr/bin/stat -c '%u:%a' "${binary_path}")"
  [ "${binary_metadata%%:*}" = "0" ] || \
    fail "cloudflared candidate must be root-owned"
  case "${binary_metadata##*:}" in
    *[2367][0-7]|*[0-7][2367]) \
      fail "cloudflared candidate must not be group/world writable" ;;
  esac
  candidate_version="$(LC_ALL=C "${binary_path}" --version 2>/dev/null | \
    /usr/bin/sed -n 's/^cloudflared version \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
  [ "${candidate_version}" = "${reviewed_cloudflared_version}" ] || \
    fail "cloudflared must be exactly ${reviewed_cloudflared_version} (found ${candidate_version:-unparseable})"
}

validate_target_parent() {
  target_path=$1
  case "${target_path}" in
    /*) ;;
    *) fail "target path must be absolute" ;;
  esac
  target_parent=${target_path%/*}
  [ -n "${target_parent}" ] || target_parent=/
  [ -d "${target_parent}" ] && [ ! -L "${target_parent}" ] || \
    fail "target parent must be a real directory"
  [ "$(/usr/bin/readlink -f -- "${target_parent}")" = "${target_parent}" ] || \
    fail "target parent path must be canonical"
  target_parent_metadata="$(/usr/bin/stat -c '%u:%g:%a' "${target_parent}")"
  target_parent_owner=${target_parent_metadata%%:*}
  target_parent_mode=${target_parent_metadata##*:}
  [ "${target_parent_owner}" = "0" ] || fail "target parent must be root-owned"
  case "${target_parent_mode}" in
    *[2367][0-7]|*[0-7][2367]) fail "target parent must not be group/world writable" ;;
  esac
  if [ -e "${target_path}" ] || [ -L "${target_path}" ]; then
    [ -f "${target_path}" ] && [ ! -L "${target_path}" ] || \
      fail "target must be absent or a regular file"
  fi
}

publish_binary() {
  binary_source=$1
  binary_target=$2
  validate_binary "${binary_source}"
  validate_target_parent "${binary_target}"
  if [ -f "${binary_target}" ] && [ ! -L "${binary_target}" ] && \
    [ "$(/usr/bin/stat -c '%u:%g:%a' "${binary_target}")" = "0:0:555" ] && \
    /usr/bin/cmp -s "${binary_source}" "${binary_target}"
  then
    return
  fi
  pending_path="${binary_target}.pending.$$"
  /usr/bin/rm -f -- "${pending_path}"
  /usr/bin/install -m 0555 -o 0 -g 0 "${binary_source}" "${pending_path}"
  /usr/bin/mv -Tf "${pending_path}" "${binary_target}"
  pending_path=
  /usr/bin/sync -f "${binary_target}"
  /usr/bin/sync -f "${binary_target%/*}"
  [ "$(/usr/bin/stat -c '%u:%g:%a' "${binary_target}")" = "0:0:555" ] || \
    fail "installed cloudflared metadata is unsafe"
  /usr/bin/cmp -s "${binary_source}" "${binary_target}" || \
    fail "installed cloudflared content changed"
  validate_binary "${binary_target}"
}

stage_reviewed_binary() {
  stage_target=$1
  validate_target_parent "${stage_target}"
  package_work_root="$(/usr/bin/mktemp -d /tmp/clixor-cloudflared.XXXXXXXX)"
  [ -d "${package_work_root}" ] && [ ! -L "${package_work_root}" ] && \
    [ "$(/usr/bin/stat -c '%u:%g:%a' "${package_work_root}")" = "0:0:700" ] || \
    fail "could not create a safe package workspace"
  package_path="${package_work_root}/cloudflared-linux-arm64.deb"
  /usr/bin/curl \
    --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 \
    --output "${package_path}" "${reviewed_cloudflared_package_url}"
  printf '%s  %s\n' \
    "${reviewed_cloudflared_package_sha256}" \
    'cloudflared-linux-arm64.deb' > "${package_work_root}/SHA256SUMS"
  (
    cd "${package_work_root}"
    /usr/bin/sha256sum --check --strict SHA256SUMS >/dev/null
  ) || fail "reviewed cloudflared package checksum is invalid"
  package_architecture="$(/usr/bin/dpkg-deb --field "${package_path}" Architecture)"
  package_version="$(/usr/bin/dpkg-deb --field "${package_path}" Version)"
  [ "${package_architecture}" = "arm64" ] || \
    fail "reviewed package architecture changed"
  [ "${package_version}" = "${reviewed_cloudflared_version}" ] || \
    fail "reviewed package version changed"
  /usr/bin/dpkg-deb --extract \
    "${package_path}" "${package_work_root}/extracted"
  publish_binary \
    "${package_work_root}/extracted/usr/bin/cloudflared" "${stage_target}"
  /usr/bin/rm -rf -- "${package_work_root}"
  package_work_root=
}

command=${1:-install}
case "${command}" in
  install)
    [ "$#" -eq 1 ] || fail "usage: $0 install"
    install_work_root="$(/usr/bin/mktemp -d /tmp/clixor-cloudflared-install.XXXXXXXX)"
    [ "$(/usr/bin/stat -c '%u:%g:%a' "${install_work_root}")" = "0:0:700" ] || \
      fail "could not create a safe install workspace"
    staged_binary="${install_work_root}/cloudflared"
    stage_reviewed_binary "${staged_binary}"
    publish_binary "${staged_binary}" /usr/bin/cloudflared
    ;;
  install-from)
    [ "$#" -eq 2 ] || fail "usage: $0 install-from ABSOLUTE_BINARY"
    case "$2" in
      /*) ;;
      *) fail "trusted source path must be absolute" ;;
    esac
    publish_binary "$2" /usr/bin/cloudflared
    ;;
  stage)
    [ "$#" -eq 2 ] || fail "usage: $0 stage ABSOLUTE_TARGET"
    stage_reviewed_binary "$2"
    ;;
  *) fail "command must be install, install-from, or stage" ;;
esac

printf '[clixor-cloudflared-package] cloudflared %s is ready\n' \
  "${reviewed_cloudflared_version}"
