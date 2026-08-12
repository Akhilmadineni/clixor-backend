#!/bin/sh
set -eu
umask 077

config=/etc/cloudflared/config.yml
hostname=clixor.atlanteanz.com
origin=http://localhost:18180

log() {
  printf '[clixor-hostname] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v cloudflared >/dev/null 2>&1 || fail "cloudflared is not installed"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is not installed"
command -v curl >/dev/null 2>&1 || fail "curl is not installed"
[ -f "$config" ] || fail "$config does not exist"

if grep -Fq "hostname: $hostname" "$config"; then
  cloudflared tunnel --config "$config" ingress validate
  systemctl is-active --quiet cloudflared || fail "cloudflared is not active"
  log "$hostname is already configured"
  exit 0
fi

catch_all_count=$(grep -Ec '^[[:space:]]*-[[:space:]]*service:[[:space:]]*http_status:404[[:space:]]*$' "$config" || true)
[ "$catch_all_count" -eq 1 ] || fail "expected exactly one http_status:404 catch-all"

candidate="${config}.clixor-candidate.$$"
backup="${config}.before-clixor.$(date -u +%Y%m%dT%H%M%SZ).$$"
installed=0

rollback() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "$installed" -eq 1 ]; then
    log "configuration failed; restoring $backup"
    cp -p "$backup" "$config"
    systemctl restart cloudflared || true
  fi
  [ ! -e "$candidate" ] || unlink "$candidate"
  exit "$status"
}
trap rollback EXIT

awk -v host="$hostname" -v service="$origin" '
  /^[[:space:]]*-[[:space:]]*service:[[:space:]]*http_status:404[[:space:]]*$/ && !inserted {
    print "  - hostname: " host
    print "    service: " service
    inserted = 1
  }
  { print }
  END { if (!inserted) exit 42 }
' "$config" > "$candidate"

config_mode=$(stat -c '%a' "$config")
config_owner=$(stat -c '%u:%g' "$config")
chmod "$config_mode" "$candidate"
chown "$config_owner" "$candidate"
cloudflared tunnel --config "$candidate" ingress validate
cp -p "$config" "$backup"
mv "$candidate" "$config"
installed=1

systemctl restart cloudflared
systemctl is-active --quiet cloudflared || fail "cloudflared did not restart successfully"
cloudflared tunnel --config "$config" ingress validate
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:18180/health/ready >/dev/null

installed=0
log "configured $hostname -> $origin; backup retained at $backup"
