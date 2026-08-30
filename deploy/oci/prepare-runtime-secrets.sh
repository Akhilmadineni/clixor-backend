#!/bin/sh
set -eu
umask 077
ulimit -c 0

fallback_mode_file=/etc/clixor/secret-mode
release_root=/srv/clixor/releases
release_mode_file="${release_root}/current/secret-mode"
approved_manifest="${release_root}/current/vault-approved-cohort.json"
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
if [ -e "${release_mode_file}" ] || [ -L "${release_mode_file}" ]; then
  [ -L "${release_root}/current" ] || \
    fail "current release must be selected by a symbolic link"
  current_release_target="$(readlink -- "${release_root}/current")"
  case "${current_release_target}" in
    "${release_root}"/oci-*) ;;
    *) fail "current release pointer targets an unexpected location" ;;
  esac
  [ "${current_release_target%/*}" = "${release_root}" ] && \
    [ "$(readlink -f -- "${release_root}/current")" = "${current_release_target}" ] && \
    [ -d "${current_release_target}" ] && [ ! -L "${current_release_target}" ] && \
    [ "$(stat -c '%u:%g:%a' "${current_release_target}")" = "0:0:700" ] || \
    fail "current release pointer does not select an immediate release child"
  [ -f "${release_mode_file}" ] && [ ! -L "${release_mode_file}" ] || \
    fail "approved release secret mode must be a regular file"
  [ "$(stat -c '%u:%g:%a' "${release_mode_file}")" = "0:0:400" ] || \
    fail "approved release secret mode has unsafe ownership or mode"
  mode_file=${release_mode_file}
else
  if [ -d "${release_root}" ] && \
    [ -n "$(find "${release_root}" -mindepth 1 -maxdepth 1 -type d -name 'oci-*' -print -quit)" ]; then
    fail "release history exists but the boot approval pointer is unavailable"
  fi
  [ -f "${fallback_mode_file}" ] && [ ! -L "${fallback_mode_file}" ] || \
    fail "fallback secret mode must be a regular file"
  [ "$(stat -c '%u:%g:%a' "${fallback_mode_file}")" = "0:0:600" ] || \
    fail "fallback secret mode has unsafe ownership or mode"
  mode_file=${fallback_mode_file}
fi
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
  [ -f "${approved_manifest}" ] && [ ! -L "${approved_manifest}" ] || \
    fail "approved Vault cohort is unavailable from the current release"
  exec /usr/bin/python3 "${hydrator}" \
    --approved-manifest "${approved_manifest}"
fi

if [ -e "${approved_manifest}" ] || [ -L "${approved_manifest}" ]; then
  fail "a staging release must not contain an approved Vault cohort"
fi

[ -d "${staging_root}" ] && [ ! -L "${staging_root}" ] || \
  fail "staging secret root is unavailable"
[ "$(stat -c '%u:%g:%a' "${staging_root}")" = "0:0:700" ] || \
  fail "staging secret root has unsafe ownership or mode"
temporary_link="${runtime_root}/.active.$$"
rm -f -- "${temporary_link}"
ln -s "${staging_root}" "${temporary_link}"
mv -Tf -- "${temporary_link}" "${runtime_root}/active"
