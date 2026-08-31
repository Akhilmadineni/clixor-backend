#!/bin/sh
set -eu
umask 077

token_file=/run/clixor/secrets/active/cloudflare-token
unit_source=${1:-}
reviewed_cloudflared_version=2026.7.3

fail() {
  printf '[clixor-cloudflared] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "${unit_source}" ] || fail "cloudflared service unit path is required"
[ -f "${unit_source}" ] || fail "service unit does not exist: ${unit_source}"
[ -x /usr/bin/cloudflared ] || fail "install the signed cloudflared package first"

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
[ "$(readlink -- /run/clixor/secrets/active)" != "/srv/clixor/secrets" ] || \
  fail "production connector credentials must be selected from a Vault tmpfs generation"
[ -d /run/clixor-origin ] && [ ! -L /run/clixor-origin ] && \
  [ "$(stat -c '%u:%g:%a' /run/clixor-origin)" = "986:987:750" ] || \
  fail "connector-only origin boundary is missing or unsafe"

install -m 0644 -o 0 -g 0 "${unit_source}" /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable --now cloudflared.service
systemctl is-active --quiet cloudflared.service || fail "cloudflared did not become active"

printf '[clixor-cloudflared] connector service is active\n'
