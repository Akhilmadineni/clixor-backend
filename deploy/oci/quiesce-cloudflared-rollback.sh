#!/bin/sh
set -eu
umask 077

fail() {
  printf '[clixor-cloudflared-rollback] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 3 ] || fail "expected saved fragment, enabled state, and active state"
saved_fragment=$1
saved_enabled=$2
saved_active=$3

case "${saved_fragment}" in
  absent|/*) ;;
  *) fail "saved unit fragment is invalid" ;;
esac
case "${saved_enabled}" in
  enabled|disabled|static|indirect|not-found) ;;
  *) fail "saved enabled state is invalid" ;;
esac
case "${saved_active}" in
  active|inactive) ;;
  *) fail "saved active state is invalid" ;;
esac

systemctl_binary=/usr/bin/systemctl
if [ -n "${CLIXOR_ROLLBACK_SYSTEMCTL_TEST_PATH:-}" ]; then
  [ "$(id -u)" -ne 0 ] || fail "test systemctl override is forbidden for root"
  case "${CLIXOR_ROLLBACK_SYSTEMCTL_TEST_PATH}" in
    /*) systemctl_binary=${CLIXOR_ROLLBACK_SYSTEMCTL_TEST_PATH} ;;
    *) fail "test systemctl override must be absolute" ;;
  esac
fi
[ -x "${systemctl_binary}" ] || fail "systemctl is unavailable"

if ! current_load_state="$("${systemctl_binary}" show cloudflared.service \
  --property=LoadState --value 2>/dev/null)"; then
  fail "cloudflared load state is unavailable"
fi
case "${current_load_state}" in
  loaded)
    "${systemctl_binary}" stop cloudflared.service >/dev/null 2>&1 || \
      fail "cloudflared could not be stopped"
    ;;
  not-found)
    [ "${saved_fragment}:${saved_enabled}:${saved_active}" = \
      "absent:not-found:inactive" ] || \
      fail "missing cloudflared unit conflicts with saved state"
    ;;
  *) fail "cloudflared has an unsafe load state" ;;
esac

current_active_state="$("${systemctl_binary}" is-active cloudflared.service \
  2>/dev/null || true)"
[ "${current_active_state}" = "inactive" ] || \
  fail "cloudflared is not synchronously inactive"

if [ "${saved_enabled}" != "enabled" ]; then
  current_enabled_state="$("${systemctl_binary}" is-enabled cloudflared.service \
    2>/dev/null || true)"
  case "${current_enabled_state}" in
    enabled)
      "${systemctl_binary}" disable cloudflared.service >/dev/null 2>&1 || \
        fail "cloudflared could not be disabled"
      ;;
    disabled|static|indirect|not-found) ;;
    *) fail "cloudflared has an unsafe enabled state" ;;
  esac
fi

current_active_state="$("${systemctl_binary}" is-active cloudflared.service \
  2>/dev/null || true)"
[ "${current_active_state}" = "inactive" ] || \
  fail "cloudflared became active during rollback quiescence"
