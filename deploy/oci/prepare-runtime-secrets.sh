#!/bin/sh
set -eu
umask 077
ulimit -c 0

mode_file=/etc/clixor/secret-mode
runtime_root=/run/clixor/secrets
staging_root=/srv/clixor/secrets
hydrator=/usr/local/libexec/clixor/hydrate-vault-secrets.py

fail() {
  printf '[clixor-runtime-secrets] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ "$(awk 'END { print NR }' /proc/swaps)" = "1" ] || \
  fail "swap must be disabled before preparing runtime secrets"
[ -f "${mode_file}" ] && [ ! -L "${mode_file}" ] || \
  fail "secret mode must be a regular file"
[ "$(stat -c '%u:%g:%a' "${mode_file}")" = "0:0:600" ] || \
  fail "secret mode has unsafe ownership or mode"
mode="$(sed -n '1p' "${mode_file}")"
[ "$(wc -l < "${mode_file}" | tr -d '[:space:]')" = "1" ] || \
  fail "secret mode file is invalid"
case "${mode}" in
  staging|vault) ;;
  *) fail "secret mode must be staging or vault" ;;
esac

install -d -m 0700 -o 0 -g 0 /run/clixor
install -d -m 0700 -o 0 -g 0 "${runtime_root}"
[ "$(findmnt --noheadings --output FSTYPE --target "${runtime_root}" | tr -d '[:space:]')" = "tmpfs" ] || \
  fail "runtime secret root is not on tmpfs"

if [ "${mode}" = "vault" ]; then
  [ -f "${hydrator}" ] && [ ! -L "${hydrator}" ] || \
    fail "installed Vault hydrator is unavailable"
  [ "$(stat -c '%u:%g:%a' "${hydrator}")" = "0:0:755" ] || \
    fail "installed Vault hydrator has unsafe ownership or mode"
  exec /usr/bin/python3 "${hydrator}"
fi

[ -d "${staging_root}" ] && [ ! -L "${staging_root}" ] || \
  fail "staging secret root is unavailable"
[ "$(stat -c '%u:%g:%a' "${staging_root}")" = "0:0:700" ] || \
  fail "staging secret root has unsafe ownership or mode"
temporary_link="${runtime_root}/.active.$$"
rm -f -- "${temporary_link}"
ln -s "${staging_root}" "${temporary_link}"
mv -Tf -- "${temporary_link}" "${runtime_root}/active"
