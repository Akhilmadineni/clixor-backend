#!/bin/sh
set -eu
umask 077
ulimit -c 0

release_root=/srv/clixor/releases
runtime_root=/run/clixor/secrets
staging_root=/srv/clixor/secrets

fail() {
  printf '[clixor-release-runtime-secrets] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ "$#" -eq 1 ] || fail "usage: prepare-runtime-secrets.sh /srv/clixor/releases/oci-<release>"
release=$1
case "${release}" in
  "${release_root}"/oci-*) ;;
  *) fail "release path is invalid" ;;
esac
[ "${release%/*}" = "${release_root}" ] && \
  [ -d "${release}" ] && [ ! -L "${release}" ] && \
  [ "$(readlink -f -- "${release}")" = "${release}" ] && \
  [ "$(stat -c '%u:%g:%a' "${release}")" = "0:0:700" ] || \
  fail "release must be an immediate root-owned mode-0700 child"

boot_root="${release}/boot-secrets"
hydrator="${boot_root}/hydrate-vault-secrets.py"
mode_file="${release}/secret-mode"
approved_mapping="${release}/vault-secrets.map"
approved_manifest="${release}/vault-approved-cohort.json"
release_cohort=${release##*/}

[ -d "${boot_root}" ] && [ ! -L "${boot_root}" ] && \
  [ "$(stat -c '%u:%g:%a' "${boot_root}")" = "0:0:700" ] || \
  fail "release boot-tool directory is unavailable or unsafe"
[ -f "${hydrator}" ] && [ ! -L "${hydrator}" ] && \
  [ "$(stat -c '%u:%g:%a' "${hydrator}")" = "0:0:500" ] || \
  fail "release-local Vault hydrator is unavailable or unsafe"
[ -f "${mode_file}" ] && [ ! -L "${mode_file}" ] && \
  [ "$(stat -c '%u:%g:%a' "${mode_file}")" = "0:0:400" ] || \
  fail "release secret mode is unavailable or unsafe"
[ "$(wc -l < "${mode_file}" | tr -d '[:space:]')" = "1" ] || \
  fail "release secret mode is invalid"
mode="$(sed -n '1p' "${mode_file}")"
case "${mode}" in
  staging|vault) ;;
  *) fail "release secret mode must be staging or vault" ;;
esac

[ "$(awk 'END { print NR }' /proc/swaps)" = "1" ] || \
  fail "swap must be disabled before preparing runtime secrets"
install -d -m 0700 -o 0 -g 0 /run/clixor "${runtime_root}"
[ "$(findmnt --noheadings --output FSTYPE --target "${runtime_root}" | tr -d '[:space:]')" = "tmpfs" ] || \
  fail "runtime secret root is not on tmpfs"

if [ "${mode}" = "vault" ]; then
  for approved_file in "${approved_mapping}" "${approved_manifest}"; do
    [ -f "${approved_file}" ] && [ ! -L "${approved_file}" ] && \
      [ "$(stat -c '%u:%g:%a' "${approved_file}")" = "0:0:400" ] || \
      fail "approved Vault release metadata is unavailable or unsafe"
  done
  exec /usr/bin/python3 "${hydrator}" \
    --approved-release-manifest "${approved_manifest}" \
    --release-cohort "${release_cohort}"
fi

for forbidden_vault_file in "${approved_mapping}" "${approved_manifest}"; do
  [ ! -e "${forbidden_vault_file}" ] && [ ! -L "${forbidden_vault_file}" ] || \
    fail "a staging release must not contain approved Vault metadata"
done
[ -d "${staging_root}" ] && [ ! -L "${staging_root}" ] && \
  [ "$(stat -c '%u:%g:%a' "${staging_root}")" = "0:0:700" ] || \
  fail "staging secret root is unavailable or unsafe"
temporary_link="${runtime_root}/.active.$$"
trap 'rm -f -- "${temporary_link}"' EXIT HUP INT TERM
ln -s "${staging_root}" "${temporary_link}"
mv -Tf -- "${temporary_link}" "${runtime_root}/active"
trap - EXIT HUP INT TERM
