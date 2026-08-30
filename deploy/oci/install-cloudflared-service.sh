#!/bin/sh
set -eu
umask 077

token_file=/run/clixor/secrets/active/cloudflare-token
legacy_token_file=/etc/cloudflared/token
unit_source=${1:-}
minimum_cloudflared_version=2025.4.0

fail() {
  printf '[clixor-cloudflared] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "${unit_source}" ] || fail "cloudflared service unit path is required"
[ -f "${unit_source}" ] || fail "service unit does not exist: ${unit_source}"
[ -x /usr/bin/cloudflared ] || fail "install the signed cloudflared package first"
[ -x /usr/bin/dpkg ] || fail "dpkg is required to validate the cloudflared version"

cloudflared_version="$(LC_ALL=C /usr/bin/cloudflared --version 2>/dev/null | \
  sed -n 's/^cloudflared version \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
[ -n "${cloudflared_version}" ] || fail "could not parse cloudflared --version"
/usr/bin/dpkg --compare-versions \
  "${cloudflared_version}" ge "${minimum_cloudflared_version}" || \
  fail "cloudflared ${minimum_cloudflared_version} or newer is required for --token-file (found ${cloudflared_version})"

if [ ! -e "${token_file}" ] && [ -f "${legacy_token_file}" ] && \
  [ ! -L "${legacy_token_file}" ]; then
  [ "$(stat -c '%u:%g:%a' "${legacy_token_file}")" = "0:0:600" ] || \
    fail "legacy tunnel token has unsafe ownership or mode"
  [ "$(readlink -- /run/clixor/secrets/active)" = "/srv/clixor/secrets" ] || \
    fail "refusing to copy a legacy token into a Vault-selected generation"
  install -m 0600 -o 0 -g 0 "${legacy_token_file}" \
    /srv/clixor/secrets/cloudflare-token
fi
[ -s "${token_file}" ] || fail "install the tunnel token at ${token_file} first"
[ -f "${token_file}" ] && [ ! -L "${token_file}" ] || \
  fail "${token_file} must resolve to a regular file"

token_owner="$(stat -c '%u:%g' "${token_file}")"
token_mode="$(stat -c '%a' "${token_file}")"
[ "${token_owner}" = "0:0" ] || fail "${token_file} must be owned by root:root"
[ "${token_mode}" = "600" ] || fail "${token_file} must have mode 0600"

install -m 0644 -o 0 -g 0 "${unit_source}" /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable --now cloudflared.service
systemctl is-active --quiet cloudflared.service || fail "cloudflared did not become active"

printf '[clixor-cloudflared] connector service is active\n'
