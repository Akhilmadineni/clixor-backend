#!/bin/sh
set -eu
umask 077
ulimit -c 0

project_root=/srv/clixor
release_root="${project_root}/releases"
fallback_mode_file=/etc/clixor/secret-mode
runtime_root=/run/clixor/secrets
staging_root="${project_root}/secrets"

fail() {
  printf '[clixor-initial-staging-secrets] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 0 ] || fail "initial staging worker does not accept arguments"
[ "$(id -u)" -eq 0 ] || fail "run as root"
# Only releases/current is authority. Pending or orphaned candidate directories
# are deliberately ignored; the runtime reconciler will not start application
# containers or ingress without a committed current pointer.
[ ! -e "${release_root}/current" ] && [ ! -L "${release_root}/current" ] || \
  fail "initial staging fallback is forbidden after a release is approved"
[ -f "${fallback_mode_file}" ] && [ ! -L "${fallback_mode_file}" ] || \
  fail "fallback secret mode must be a regular file"
[ "$(stat -c '%u:%g:%a' "${fallback_mode_file}")" = "0:0:600" ] || \
  fail "fallback secret mode has unsafe ownership or mode"
[ "$(wc -l < "${fallback_mode_file}" | tr -d '[:space:]')" = "1" ] && \
  [ "$(sed -n '1p' "${fallback_mode_file}")" = "staging" ] || \
  fail "initial fallback secret mode must be exactly staging"
[ "$(awk 'END { print NR }' /proc/swaps)" = "1" ] || \
  fail "swap must be disabled before preparing runtime secrets"

install -d -m 0700 -o 0 -g 0 /run/clixor "${runtime_root}"
[ "$(findmnt --noheadings --output FSTYPE --target "${runtime_root}" | tr -d '[:space:]')" = "tmpfs" ] || \
  fail "runtime secret root is not on tmpfs"
[ -d "${staging_root}" ] && [ ! -L "${staging_root}" ] && \
  [ "$(stat -c '%u:%g:%a' "${staging_root}")" = "0:0:700" ] || \
  fail "staging secret root is unavailable or unsafe"

temporary_link="${runtime_root}/.active.$$"
trap 'rm -f -- "${temporary_link}"' EXIT HUP INT TERM
ln -s "${staging_root}" "${temporary_link}"
mv -Tf -- "${temporary_link}" "${runtime_root}/active"
trap - EXIT HUP INT TERM
