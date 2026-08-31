#!/bin/sh
set -eu
umask 077

token_file=/run/clixor/cloudflare-connector/current/token
unit_source=${1:-}
reviewed_cloudflared_version=2026.7.3
release_root=/srv/clixor/releases
current_release=

fail() {
  printf '[clixor-cloudflared] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "${unit_source}" ] || fail "cloudflared service unit path is required"
[ -f "${unit_source}" ] || fail "service unit does not exist: ${unit_source}"
[ -x /usr/bin/cloudflared ] || fail "install the signed cloudflared package first"
[ -L "${release_root}/current" ] || \
  fail "a committed release must be selected before connector installation"
current_release="$(readlink -- "${release_root}/current")"
case "${current_release}" in
  "${release_root}"/oci-*) ;;
  *) fail "current release pointer is unsafe" ;;
esac
[ "${current_release%/*}" = "${release_root}" ] && \
  [ "$(readlink -f -- "${release_root}/current")" = "${current_release}" ] || \
  fail "current release must select an immediate release child"
connector_controller="${current_release}/runtime-bundle/host-tools/bin/cloudflare-canary-credential.py"
[ -f "${connector_controller}" ] && [ ! -L "${connector_controller}" ] || \
  fail "selected release has no connector credential controller"
/usr/bin/python3 /usr/local/libexec/clixor/runtime-reconciler.py validate-release \
  --release "${current_release}" >/dev/null || \
  fail "selected release runtime bundle is invalid"
/usr/bin/python3 "${connector_controller}" verify \
  --release "${current_release}" >/dev/null || \
  fail "selected release connector credential is invalid"

cloudflared_version="$(LC_ALL=C /usr/bin/cloudflared --version 2>/dev/null | \
  sed -n 's/^cloudflared version \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
[ "${cloudflared_version}" = "${reviewed_cloudflared_version}" ] || \
  fail "cloudflared must be exactly ${reviewed_cloudflared_version} (found ${cloudflared_version:-unparseable})"

[ -s "${token_file}" ] || fail "install the tunnel token at ${token_file} first"
[ -f "${token_file}" ] && [ ! -L "${token_file}" ] || \
  fail "${token_file} must resolve to a regular file"

token_owner="$(stat -c '%u:%g' "${token_file}")"
token_mode="$(stat -c '%a' "${token_file}")"
[ "${token_owner}" = "0:0" ] || fail "${token_file} must be owned by root:root"
[ "${token_mode}" = "600" ] || fail "${token_file} must have mode 0600"
[ -s /run/clixor/cloudflare-connector/current/selection.json ] && \
  [ -f /run/clixor/cloudflare-connector/current/selection.json ] && \
  [ ! -L /run/clixor/cloudflare-connector/current/selection.json ] || \
  fail "release-bound connector selection is missing"
[ -d /run/clixor-origin ] && [ ! -L /run/clixor-origin ] && \
  [ "$(stat -c '%u:%g:%a' /run/clixor-origin)" = "986:987:750" ] || \
  fail "connector-only origin boundary is missing or unsafe"

install -m 0644 -o 0 -g 0 "${unit_source}" /etc/systemd/system/cloudflared.service
systemctl daemon-reload

connector_authority_is_current() {
  /usr/bin/python3 "${connector_controller}" verify \
    --release "${current_release}" >/dev/null || return 1
  canary_metadata="${current_release}/runtime-bundle/cloudflare-canary-connector.json"
  if [ -f "${canary_metadata}" ] && [ ! -L "${canary_metadata}" ]; then
    /usr/bin/python3 "${connector_controller}" verify-remote \
      --release "${current_release}" >/dev/null || return 1
  elif [ -e "${canary_metadata}" ] || [ -L "${canary_metadata}" ]; then
    return 1
  fi
  return 0
}

if ! systemctl enable --now cloudflared.service || \
  ! systemctl is-active --quiet cloudflared.service || \
  ! connector_authority_is_current
then
  # A started process is not a successful installation until its local
  # credential and, for a canary, complete effective remote configuration are
  # synchronously bound to the selected release.
  rm -f -- /run/clixor/runtime-ready
  systemctl stop cloudflared.service >/dev/null 2>&1 || true
  systemctl disable cloudflared.service >/dev/null 2>&1 || true
  fail "cloudflared did not start with the selected release authority"
fi

printf '[clixor-cloudflared] connector service is active\n'
