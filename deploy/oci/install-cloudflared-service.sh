#!/bin/sh
set -eu
umask 077

token_file=/etc/cloudflared/token
unit_source=${1:-}

fail() {
  printf '[clixor-cloudflared] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "${unit_source}" ] || fail "cloudflared service unit path is required"
[ -f "${unit_source}" ] || fail "service unit does not exist: ${unit_source}"
[ -x /usr/bin/cloudflared ] || fail "install the signed cloudflared package first"
[ -s "${token_file}" ] || fail "install the tunnel token at ${token_file} first"

token_owner="$(stat -c '%u:%g' "${token_file}")"
token_mode="$(stat -c '%a' "${token_file}")"
[ "${token_owner}" = "0:0" ] || fail "${token_file} must be owned by root:root"
[ "${token_mode}" = "600" ] || fail "${token_file} must have mode 0600"

install -m 0644 -o 0 -g 0 "${unit_source}" /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable --now cloudflared.service
systemctl is-active --quiet cloudflared.service || fail "cloudflared did not become active"

printf '[clixor-cloudflared] connector service is active\n'
