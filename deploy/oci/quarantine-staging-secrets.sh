#!/bin/sh
set -eu
umask 077
ulimit -c 0

project_root=/srv/clixor
secret_root="${project_root}/secrets"
runtime_secret_root=/run/clixor/secrets
pre_reboot_boot_id_file=/etc/clixor/pre-retirement-boot-id
release_link="${project_root}/releases/current"
restore_marker="${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS"
audit_root=/var/log/clixor
audit_log="${audit_root}/staging-secret-maintenance.log"
lock_file="${project_root}/runtime/staging-secret-maintenance.lock"
action=${1:-}
approval_file=${2:-}

log() {
  printf '[clixor-secret-quarantine] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

approval_value() {
  sed -n "s/^$1=//p" "${approval_file}"
}

marker_value() {
  sed -n "s/^$1=//p" "${hydration_marker}"
}

audit() {
  audit_result=$1
  audit_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '%s action=quarantine result=%s ticket=%s boot_id=%s release=%s release_cohort=%s mapping_sha256=%s cohort_sha256=%s approval_sha256=%s item_count=%s\n' \
    "${audit_time}" "${audit_result}" "${change_ticket}" \
    "${approved_boot_id}" "${approved_release}" "${release_cohort:-unverified}" \
    "${approved_mapping_sha256}" "${approved_cohort_sha256}" \
    "${approval_sha256}" "${item_count}" \
    >> "${audit_log}"
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ "$#" -eq 2 ] && [ "${action}" = "quarantine" ] || \
  fail "usage: $0 quarantine /etc/clixor/staging-secret-retirement.approval"

for command_name in \
  awk chmod curl date docker find flock grep id install mkdir mktemp mv \
  python3 readlink sed sha256sum stat systemctl uptime wc
do
  command -v "${command_name}" >/dev/null 2>&1 || \
    fail "missing command: ${command_name}"
done

install -d -m 0700 -o 0 -g 0 "${project_root}/runtime" "${audit_root}"
exec 9>"${lock_file}"
flock -n 9 || fail "another staging-secret maintenance operation is running"

[ -f "${approval_file}" ] && [ ! -L "${approval_file}" ] || \
  fail "approval must be a regular file"
[ "$(stat -c '%u:%g:%a' "${approval_file}")" = "0:0:600" ] || \
  fail "approval must be root-owned with mode 0600"
awk -F= '
  !/^(schema|change_ticket|approved_mapping_sha256|approved_cohort_sha256|pre_reboot_boot_id|approved_boot_id|approved_release|provider_canaries|provider_canaries_passed_at)=/ { exit 1 }
  { if (seen[$1]++) exit 1 }
  END {
    if (seen["schema"] != 1 || seen["change_ticket"] != 1 ||
        seen["approved_mapping_sha256"] != 1 ||
        seen["approved_cohort_sha256"] != 1 ||
        seen["pre_reboot_boot_id"] != 1 ||
        seen["approved_boot_id"] != 1 || seen["approved_release"] != 1 ||
        seen["provider_canaries"] != 1 ||
        seen["provider_canaries_passed_at"] != 1) exit 1
  }
' "${approval_file}" || fail "approval has unknown, missing, or duplicate fields"

approval_schema="$(approval_value schema)"
change_ticket="$(approval_value change_ticket)"
approved_mapping_sha256="$(approval_value approved_mapping_sha256)"
approved_cohort_sha256="$(approval_value approved_cohort_sha256)"
pre_reboot_boot_id="$(approval_value pre_reboot_boot_id)"
approved_boot_id="$(approval_value approved_boot_id)"
approved_release="$(approval_value approved_release)"
provider_canaries="$(approval_value provider_canaries)"
provider_canaries_passed_at="$(approval_value provider_canaries_passed_at)"
approval_sha256="$(sha256sum "${approval_file}" | awk '{print $1}')"

[ "${approval_schema}" = "2" ] || fail "approval schema must be 2"
case "${change_ticket}" in
  ''|*[!A-Za-z0-9._-]*) fail "approval change ticket is invalid" ;;
esac
case "${approved_mapping_sha256}" in
  *[!0-9a-f]*|'') fail "approved mapping checksum is invalid" ;;
esac
[ "${#approved_mapping_sha256}" -eq 64 ] || \
  fail "approved mapping checksum must be SHA-256"
case "${approved_cohort_sha256}" in
  *[!0-9a-f]*|'') fail "approved cohort checksum is invalid" ;;
esac
[ "${#approved_cohort_sha256}" -eq 64 ] || \
  fail "approved cohort checksum must be SHA-256"
for recorded_boot_id in "${pre_reboot_boot_id}" "${approved_boot_id}"; do
  case "${recorded_boot_id}" in
    ????????-????-????-????-????????????) ;;
    *) fail "approval contains an invalid boot ID" ;;
  esac
  case "${recorded_boot_id}" in
    *[!0-9a-f-]*) fail "approval contains an invalid boot ID" ;;
  esac
done
[ "${pre_reboot_boot_id}" != "${approved_boot_id}" ] || \
  fail "approval does not prove a reboot"
[ -f "${pre_reboot_boot_id_file}" ] && \
  [ ! -L "${pre_reboot_boot_id_file}" ] && \
  [ "$(stat -c '%u:%g:%a' "${pre_reboot_boot_id_file}")" = "0:0:600" ] && \
  [ "$(sed -n '1p' "${pre_reboot_boot_id_file}")" = \
    "${pre_reboot_boot_id}" ] || \
  fail "approval does not match the root-owned pre-reboot boot ID record"
case "${approved_release}" in
  /srv/clixor/releases/oci-*) ;;
  *) fail "approved release is invalid" ;;
esac
[ "${provider_canaries}" = "apns,cloudflare,oci-media,smtp,telnyx" ] || \
  fail "approval must attest every required provider canary"
case "${provider_canaries_passed_at}" in
  ????-??-??T??:??:??Z) ;;
  *) fail "provider canary timestamp must be UTC RFC3339" ;;
esac
if [ -e "${audit_log}" ] || [ -L "${audit_log}" ]; then
  [ -f "${audit_log}" ] && [ ! -L "${audit_log}" ] && \
    [ "$(stat -c '%u:%g:%a' "${audit_log}")" = "0:0:600" ] || \
    fail "maintenance audit log is unsafe"
else
  install -m 0600 -o 0 -g 0 /dev/null "${audit_log}"
fi
item_count=0
trap 'status=$?; if [ "${status}" -ne 0 ]; then audit failed || true; fi; exit "${status}"' 0

[ -L "${release_link}" ] && \
  [ "$(stat -c '%u:%g' "${release_link}")" = "0:0" ] || \
  fail "current release must be selected by a root-owned symbolic link"
current_release="$(readlink -- "${release_link}")"
case "${current_release}" in
  /srv/clixor/releases/oci-*) ;;
  *) fail "current release pointer targets an unexpected location" ;;
esac
[ "${current_release%/*}" = "${project_root}/releases" ] && \
  [ "$(readlink -f -- "${release_link}")" = "${current_release}" ] && \
  [ -d "${current_release}" ] && [ ! -L "${current_release}" ] && \
  [ "$(stat -c '%u:%g:%a' "${current_release}")" = "0:0:700" ] || \
  fail "current release is not an immediate root-owned mode-0700 child"
[ "${approved_release}" = "${current_release}" ] || \
  fail "approval does not match the current release"
release_cohort=${current_release##*/}
case "${release_cohort}" in
  oci-????????????-*) ;;
  *) fail "current release cohort name is invalid" ;;
esac
case "${release_cohort}" in
  *[!A-Za-z0-9._-]*) fail "current release cohort name is invalid" ;;
esac
release_hash=${release_cohort#oci-}
release_hash=${release_hash%%-*}
case "${release_hash}" in
  *[!0-9a-f]*|'') fail "current release cohort hash is invalid" ;;
esac
[ "${#release_hash}" -eq 12 ] || fail "current release cohort hash is invalid"

release_secret_mode="${current_release}/secret-mode"
approved_mapping="${current_release}/vault-secrets.map"
approved_manifest="${current_release}/vault-approved-cohort.json"
release_boot_root="${current_release}/boot-secrets"
release_boot_checksums="${release_boot_root}/SHA256SUMS"
release_hydrator="${release_boot_root}/hydrate-vault-secrets.py"
release_worker="${release_boot_root}/prepare-runtime-secrets.sh"
for release_metadata in \
  "${release_secret_mode}" "${approved_mapping}" "${approved_manifest}"
do
  [ -f "${release_metadata}" ] && [ ! -L "${release_metadata}" ] && \
    [ "$(stat -c '%u:%g:%a' "${release_metadata}")" = "0:0:400" ] || \
    fail "current release Vault metadata is missing or unsafe"
done
[ "$(wc -l < "${release_secret_mode}" | tr -d '[:space:]')" = "1" ] && \
  [ "$(sed -n '1p' "${release_secret_mode}")" = "vault" ] || \
  fail "current release is not approved for Vault secret mode"
actual_mapping_sha256="$(sha256sum "${approved_mapping}" | awk '{print $1}')"
[ "${actual_mapping_sha256}" = "${approved_mapping_sha256}" ] || \
  fail "current release mapping does not match the approved checksum"

[ -d "${release_boot_root}" ] && [ ! -L "${release_boot_root}" ] && \
  [ "$(stat -c '%u:%g:%a' "${release_boot_root}")" = "0:0:700" ] || \
  fail "current release boot-tool root is missing or unsafe"
[ -f "${release_boot_checksums}" ] && [ ! -L "${release_boot_checksums}" ] && \
  [ "$(stat -c '%u:%g:%a' "${release_boot_checksums}")" = "0:0:400" ] || \
  fail "current release boot checksum manifest is missing or unsafe"
awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ { exit 1 }
  $2 != "hydrate-vault-secrets.py" && $2 != "prepare-runtime-secrets.sh" { exit 1 }
  { if (seen[$2]++) exit 1 }
  END {
    if (seen["hydrate-vault-secrets.py"] != 1 ||
        seen["prepare-runtime-secrets.sh"] != 1) exit 1
  }
' "${release_boot_checksums}" || \
  fail "current release boot checksum manifest is malformed"
for release_boot_file in "${release_hydrator}" "${release_worker}"; do
  [ -f "${release_boot_file}" ] && [ ! -L "${release_boot_file}" ] && \
    [ "$(stat -c '%u:%g:%a' "${release_boot_file}")" = "0:0:500" ] || \
    fail "current release boot file is missing or unsafe"
done
(
  cd "${release_boot_root}"
  sha256sum --check SHA256SUMS >/dev/null
) || fail "current release boot-tool checksum verification failed"

[ -L "${runtime_secret_root}/active" ] || \
  fail "runtime Vault generation is not selected"
active_target="$(readlink -- "${runtime_secret_root}/active")"
case "${active_target}" in
  vault-generations/gen-[0-9]*-[0-9a-f]*) ;;
  *) fail "active runtime secrets are not a hydrated Vault generation" ;;
esac
hydration_marker="${runtime_secret_root}/${active_target}/.vault-hydrated"
[ -f "${hydration_marker}" ] && [ ! -L "${hydration_marker}" ] && \
  [ "$(stat -c '%u:%g:%a' "${hydration_marker}")" = "0:0:400" ] || \
  fail "current-boot Vault hydration marker is missing or unsafe"
awk -F= '
  !/^(schema|release_cohort|mapping_sha256|cohort_sha256)=/ { exit 1 }
  { if (seen[$1]++) exit 1 }
  END {
    if (seen["schema"] != 1 || seen["release_cohort"] != 1 ||
        seen["mapping_sha256"] != 1 || seen["cohort_sha256"] != 1) exit 1
  }
' "${hydration_marker}" || \
  fail "current-boot Vault hydration marker has unknown, missing, or duplicate fields"
[ "$(marker_value schema)" = "2" ] && \
  [ "$(marker_value release_cohort)" = "${release_cohort}" ] && \
  [ "$(marker_value mapping_sha256)" = "${approved_mapping_sha256}" ] && \
  [ "$(marker_value cohort_sha256)" = "${approved_cohort_sha256}" ] || \
  fail "hydrated generation does not match the approved release cohort"
/usr/bin/python3 "${release_hydrator}" \
  --verify-candidate-manifest "${approved_manifest}" \
  --release-cohort "${release_cohort}" || \
  fail "release manifest, mapping, and active Vault cohort are not identical"

current_boot_id="$(sed -n '1p' /proc/sys/kernel/random/boot_id)"
[ "${approved_boot_id}" = "${current_boot_id}" ] || \
  fail "approval was not issued for the current successful reboot"
boot_epoch="$(date --date="$(uptime -s)" '+%s')"
canary_epoch="$(date --date="${provider_canaries_passed_at}" '+%s')"
now_epoch="$(date -u '+%s')"
[ "${canary_epoch}" -ge "${boot_epoch}" ] && \
  [ "${canary_epoch}" -le "${now_epoch}" ] || \
  fail "provider canaries were not attested during the current boot"
[ -s "${restore_marker}" ] && [ ! -L "${restore_marker}" ] && \
  [ "$(stat -c '%Y' "${restore_marker}")" -ge "${boot_epoch}" ] || \
  fail "a successful restore drill from the current boot is required"
systemctl is-active --quiet docker.service || fail "Docker is not active"
systemctl is-active --quiet cloudflared.service || fail "cloudflared is not active"
for container_name in clixor-oci-api-a clixor-oci-api-b; do
  [ "$(docker inspect "${container_name}" --format '{{.State.Running}}' \
    2>/dev/null || true)" = "true" ] || \
    fail "${container_name} is not running"
done
curl --fail --silent --show-error --max-time 5 \
  http://172.30.254.2:8080/health/ready >/dev/null || \
  fail "local API readiness is not passing"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
quarantine_id="${timestamp}-${change_ticket}"
srv_quarantine="${project_root}/quarantine/staging-secrets/${quarantine_id}"
cloudflare_quarantine="/etc/cloudflared/quarantine/${quarantine_id}"
[ ! -e "${srv_quarantine}" ] && [ ! -e "${cloudflare_quarantine}" ] || \
  fail "quarantine destination already exists"

inventory="$(mktemp "${project_root}/runtime/staging-secret-inventory.XXXXXXXX")"
: > "${inventory}"
for persistent_name in \
  api.env postgres.env redis.env nats.env grafana.env backup.env migrate.env \
  metrics.token postgres.password postgres.pgpass redis.password redis.acl \
  nats.conf grafana.ini cloudflare-token
do
  persistent_path="${secret_root}/${persistent_name}"
  [ -e "${persistent_path}" ] || continue
  [ -f "${persistent_path}" ] && [ ! -L "${persistent_path}" ] || \
    fail "unsafe persistent staging file: ${persistent_name}"
  printf 'srv-file|%s|%s\n' "${persistent_path}" "${persistent_name}" >> "${inventory}"
done
for persistent_apns_key in "${secret_root}/apns"/*.p8; do
  [ -e "${persistent_apns_key}" ] || continue
  [ -f "${persistent_apns_key}" ] && [ ! -L "${persistent_apns_key}" ] || \
    fail "unsafe persistent APNs staging key"
  apns_name=${persistent_apns_key##*/}
  case "${apns_name}" in
    *[!A-Za-z0-9._-]*|'') fail "unsafe persistent APNs staging filename" ;;
  esac
  printf 'srv-apns|%s|%s\n' "${persistent_apns_key}" "${apns_name}" >> "${inventory}"
done
for residual_secret_dir in \
  "${secret_root}"/.split-runtime.* \
  "${secret_root}"/.staging-runtime-*
do
  [ -e "${residual_secret_dir}" ] || continue
  [ -d "${residual_secret_dir}" ] && [ ! -L "${residual_secret_dir}" ] && \
    [ "$(stat -c '%u:%g:%a' "${residual_secret_dir}")" = "0:0:700" ] || \
    fail "unsafe residual staging directory"
  [ -z "$(find "${residual_secret_dir}" -xdev -type l -print -quit)" ] || \
    fail "residual staging directory contains a symbolic link"
  [ -z "$(find "${residual_secret_dir}" -xdev ! -type d ! -type f \
    -print -quit)" ] || \
    fail "residual staging directory contains a special file"
  residual_name=${residual_secret_dir##*/}
  printf 'srv-dir|%s|%s\n' "${residual_secret_dir}" "${residual_name}" >> "${inventory}"
done
legacy_cloudflare_token=/etc/cloudflared/token
if [ -e "${legacy_cloudflare_token}" ] || [ -L "${legacy_cloudflare_token}" ]; then
  [ -f "${legacy_cloudflare_token}" ] && \
    [ ! -L "${legacy_cloudflare_token}" ] && \
    [ "$(stat -c '%u:%g:%a' "${legacy_cloudflare_token}")" = "0:0:600" ] || \
    fail "legacy Cloudflare token is unsafe"
  printf 'cloudflare-file|%s|token\n' "${legacy_cloudflare_token}" >> "${inventory}"
fi

item_count="$(awk 'END {print NR + 0}' "${inventory}")"
[ "${item_count}" -gt 0 ] || fail "no persistent staging secrets require quarantine"
install -d -m 0700 -o 0 -g 0 \
  "${srv_quarantine}" "${srv_quarantine}/apns" \
  "${srv_quarantine}/residual" "${cloudflare_quarantine}"
install -m 0600 -o 0 -g 0 "${approval_file}" \
  "${srv_quarantine}/maintenance.approval"
sha256sum "${srv_quarantine}/maintenance.approval" > \
  "${srv_quarantine}/maintenance.approval.sha256"

while IFS='|' read -r item_type source_path item_name; do
  case "${item_type}" in
    srv-file) destination="${srv_quarantine}/${item_name}" ;;
    srv-apns) destination="${srv_quarantine}/apns/${item_name}" ;;
    srv-dir) destination="${srv_quarantine}/residual/${item_name}" ;;
    cloudflare-file) destination="${cloudflare_quarantine}/${item_name}" ;;
    *) fail "internal inventory contains an unknown item type" ;;
  esac
  [ ! -e "${destination}" ] && [ ! -L "${destination}" ] || \
    fail "quarantine destination collision"
  mv -- "${source_path}" "${destination}"
done < "${inventory}"
mv -- "${inventory}" "${srv_quarantine}/inventory"
chmod 0600 "${srv_quarantine}/inventory" \
  "${srv_quarantine}/maintenance.approval.sha256"
audit succeeded
trap - 0
log "quarantined ${item_count} staging-secret artifacts under audited root-only storage"
log "no quarantined data was deleted; purge requires a separate reviewed operation"
