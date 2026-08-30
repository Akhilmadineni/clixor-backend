#!/bin/sh
set -eu
umask 077
ulimit -c 0

case "${CLIXOR_SKIP_SECRET_PREPARATION:-false}" in
  true|false) ;;
  *)
    echo "CLIXOR_SKIP_SECRET_PREPARATION must be true or false." >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root so host packages and runtime permissions can be enforced." >&2
  exit 1
fi

defer_host_tool_activation=${CLIXOR_DEFER_HOST_TOOL_ACTIVATION:-false}
case "${defer_host_tool_activation}" in
  true|false) ;;
  *)
    echo "CLIXOR_DEFER_HOST_TOOL_ACTIVATION must be true or false." >&2
    exit 1
    ;;
esac

architecture="$(uname -m)"
case "${architecture}" in
  aarch64|arm64) ;;
  *)
    echo "This deployment package targets an OCI ARM64 instance; found ${architecture}." >&2
    exit 1
    ;;
esac

if [ ! -r /etc/os-release ] || ! grep -q '^ID=ubuntu$' /etc/os-release; then
  echo "This bootstrap is supported on Ubuntu ARM64 only." >&2
  exit 1
fi

cpu_count="$(getconf _NPROCESSORS_ONLN)"
memory_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
if [ "${cpu_count}" -lt 2 ] || [ "${memory_kb}" -lt 10000000 ]; then
  echo "Use VM.Standard.A1.Flex with 2 OCPUs and 12 GB RAM or larger." >&2
  exit 1
fi

if [ "${CLIXOR_SKIP_PACKAGES:-false}" != "true" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install --yes --no-install-recommends \
    ca-certificates curl docker.io docker-buildx docker-compose-v2 git nftables openssl python3 rsync unzip util-linux
  unset DEBIAN_FRONTEND
fi
systemctl enable --now docker
docker compose version >/dev/null
docker buildx version >/dev/null

script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if ! command -v oci >/dev/null 2>&1; then
  [ "${CLIXOR_SKIP_PACKAGES:-false}" != "true" ] || {
    echo "OCI CLI is missing; run ${script_root}/install-oci-cli.sh before deploying." >&2
    exit 1
  }
  sh "${script_root}/install-oci-cli.sh"
fi

backup_config_root=/etc/clixor
backup_config="${backup_config_root}/offsite-backup.env"
existing_backup_bucket=
existing_backup_prefix=
if [ -e "${backup_config}" ] || [ -L "${backup_config}" ]; then
  [ -f "${backup_config}" ] && [ ! -L "${backup_config}" ] || {
    echo "Existing backup configuration must be a regular file." >&2
    exit 1
  }
  [ "$(stat -c %u "${backup_config}")" -eq 0 ] && \
    [ "$(stat -c %a "${backup_config}")" = "600" ] || {
    echo "Existing backup configuration must be root-owned with mode 0600." >&2
    exit 1
  }
  awk -F= '
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    !/^(OCI_BACKUP_BUCKET|OCI_BACKUP_PREFIX)=[A-Za-z0-9._-]+$/ { exit 1 }
    { if (seen[$1]++) exit 1 }
    END {
      if (seen["OCI_BACKUP_BUCKET"] != 1 || seen["OCI_BACKUP_PREFIX"] != 1) exit 1
    }
  ' "${backup_config}" || {
    echo "Existing backup configuration is malformed or contains unsupported keys." >&2
    exit 1
  }
  existing_backup_bucket="$(sed -n 's/^OCI_BACKUP_BUCKET=//p' "${backup_config}")"
  existing_backup_prefix="$(sed -n 's/^OCI_BACKUP_PREFIX=//p' "${backup_config}")"
fi

if [ -n "${CLIXOR_OCI_BACKUP_BUCKET:-}" ] && \
  [ -n "${existing_backup_bucket}" ] && \
  [ "${CLIXOR_OCI_BACKUP_BUCKET}" != "${existing_backup_bucket}" ]; then
  echo "CLIXOR_OCI_BACKUP_BUCKET conflicts with the durable backup configuration." >&2
  exit 1
fi
if [ -n "${CLIXOR_OCI_BACKUP_PREFIX:-}" ] && \
  [ -n "${existing_backup_prefix}" ] && \
  [ "${CLIXOR_OCI_BACKUP_PREFIX}" != "${existing_backup_prefix}" ]; then
  echo "CLIXOR_OCI_BACKUP_PREFIX conflicts with the durable backup configuration." >&2
  exit 1
fi
oci_backup_bucket=${existing_backup_bucket:-${CLIXOR_OCI_BACKUP_BUCKET:-clixor-prod-backups}}
oci_backup_prefix=${existing_backup_prefix:-${CLIXOR_OCI_BACKUP_PREFIX:-clixor}}
case "${oci_backup_bucket}" in
  ''|*[!A-Za-z0-9._-]*)
    echo "CLIXOR_OCI_BACKUP_BUCKET contains unsupported characters." >&2
    exit 1
    ;;
esac
case "${oci_backup_prefix}" in
  ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*)
    echo "CLIXOR_OCI_BACKUP_PREFIX contains unsupported characters." >&2
    exit 1
    ;;
esac
if [ "${#oci_backup_prefix}" -gt 63 ]; then
  echo "CLIXOR_OCI_BACKUP_PREFIX is longer than 63 characters." >&2
  exit 1
fi
backup_namespace="$(OCI_CLI_AUTH=instance_principal oci os ns get \
  --query data --raw-output)"
[ -n "${backup_namespace}" ] || {
  echo "Could not resolve the OCI Object Storage namespace for backups." >&2
  exit 1
}
OCI_CLI_AUTH=instance_principal oci os bucket get \
  --namespace-name "${backup_namespace}" \
  --name "${oci_backup_bucket}" >/dev/null || {
  echo "Instance principal cannot read OCI backup bucket ${oci_backup_bucket}." >&2
  exit 1
}

project_root=/srv/clixor
secret_root="${project_root}/secrets"
pki_root="${secret_root}/pki"
apns_root="${secret_root}/apns"
runtime_env="${secret_root}/runtime.env"
runtime_root="${project_root}/runtime"
backup_tool_root=/usr/local/libexec/clixor
systemd_unit_root=/etc/systemd/system

install -d -m 0750 "${project_root}" "${project_root}/repo" \
  "${project_root}/releases" "${project_root}/data" "${runtime_root}" \
  "${project_root}/backups"
install -d -m 0700 -o 0 -g 0 "${project_root}/restore-drills"
install -d -m 0755 -o 0 -g 0 "${backup_tool_root}" "${backup_config_root}"
install -d -m 0700 -o 0 -g 0 "${secret_root}" "${pki_root}"
secret_mode=/etc/clixor/secret-mode
if [ ! -e "${secret_mode}" ] && [ ! -L "${secret_mode}" ]; then
  temporary_mode="/etc/clixor/.secret-mode.$$"
  printf 'staging\n' > "${temporary_mode}"
  chmod 0600 "${temporary_mode}"
  chown 0:0 "${temporary_mode}"
  mv -Tf -- "${temporary_mode}" "${secret_mode}"
fi
[ -f "${secret_mode}" ] && [ ! -L "${secret_mode}" ] && \
  [ "$(stat -c '%u:%g:%a' "${secret_mode}")" = "0:0:600" ] || {
  echo "${secret_mode} has unsafe type, ownership, or mode." >&2
  exit 1
}
[ "$(wc -l < "${secret_mode}" | tr -d '[:space:]')" = "1" ] || {
  echo "${secret_mode} must contain exactly one line." >&2
  exit 1
}
case "$(sed -n '1p' "${secret_mode}")" in
  staging|vault) ;;
  *)
    echo "${secret_mode} must contain exactly staging or vault." >&2
    exit 1
    ;;
esac
selected_secret_mode="$(sed -n '1p' "${secret_mode}")"
release_secret_mode="${project_root}/releases/current/secret-mode"
if [ -e "${release_secret_mode}" ] || [ -L "${release_secret_mode}" ]; then
  current_release_link="${project_root}/releases/current"
  [ -L "${current_release_link}" ] || {
    echo "${current_release_link} must be a symbolic link." >&2
    exit 1
  }
  current_release_target="$(readlink -- "${current_release_link}")"
  case "${current_release_target}" in
    "${project_root}/releases"/oci-*) ;;
    *)
      echo "${current_release_link} targets an unexpected location." >&2
      exit 1
      ;;
  esac
  [ "${current_release_target%/*}" = "${project_root}/releases" ] && \
    [ "$(readlink -f -- "${current_release_link}")" = "${current_release_target}" ] && \
    [ -d "${current_release_target}" ] && [ ! -L "${current_release_target}" ] && \
    [ "$(stat -c '%u:%g:%a' "${current_release_target}")" = "0:0:700" ] && \
    [ -f "${release_secret_mode}" ] && [ ! -L "${release_secret_mode}" ] && \
    [ "$(stat -c '%u:%g:%a' "${release_secret_mode}")" = "0:0:400" ] || {
    echo "${release_secret_mode} has unsafe type, ownership, or mode." >&2
    exit 1
  }
  [ "$(wc -l < "${release_secret_mode}" | tr -d '[:space:]')" = "1" ] || {
    echo "${release_secret_mode} must contain exactly one line." >&2
    exit 1
  }
  selected_secret_mode="$(sed -n '1p' "${release_secret_mode}")"
  case "${selected_secret_mode}" in
    staging|vault) ;;
    *)
      echo "${release_secret_mode} must contain exactly staging or vault." >&2
      exit 1
      ;;
  esac
fi
# The API image is distroless nonroot (UID/GID 65532). The mount root must be
# traversable and each installed key readable by that identity, but not by other
# host users.
install -d -m 0750 -o 0 -g 65532 "${apns_root}"

install -d -m 0750 -o 0 -g 99 "${runtime_root}/dependency-tls"
install -d -m 0750 -o 0 -g 70 "${runtime_root}/postgres-tls"
install -d -m 0750 -o 0 -g 1000 "${runtime_root}/nats-tls"
install -d -m 0750 -o 101 -g 101 "${runtime_root}/api-gateway"
if getent group 987 >/dev/null 2>&1; then
  [ "$(getent group 987 | cut -d: -f1)" = "clixor-origin" ] || {
    echo "Host GID 987 is already assigned outside the connector boundary." >&2
    exit 1
  }
elif getent group clixor-origin >/dev/null 2>&1; then
  [ "$(getent group clixor-origin | cut -d: -f3)" = "987" ] || {
    echo "clixor-origin must use reviewed GID 987." >&2
    exit 1
  }
else
  groupadd --system --gid 987 clixor-origin
fi
install -m 0644 -o 0 -g 0 "${script_root}/clixor-origin.conf" \
  /etc/tmpfiles.d/clixor-origin.conf
systemd-tmpfiles --create /etc/tmpfiles.d/clixor-origin.conf
[ -d /run/clixor-origin ] && [ ! -L /run/clixor-origin ] && \
  [ "$(stat -c '%u:%g:%a' /run/clixor-origin)" = "0:987:750" ] || {
  echo "Connector origin tmpfs boundary is unsafe." >&2
  exit 1
}
install -d -m 0750 -o 0 -g 0 "${runtime_root}/postgres-backup"
install -d -m 0750 -o 65534 -g 65534 "${runtime_root}/prometheus"
install -d -m 0750 -o 472 -g 472 "${runtime_root}/grafana"

for directory in postgres redis nats prometheus grafana; do
  install -d -m 0750 "${project_root}/data/${directory}"
done
install -d -m 0700 "${project_root}/backups/postgres"

python3 "${script_root}/dependency_pki.py" ensure \
  --pki-root "${pki_root}" \
  --runtime-root "${runtime_root}"

if [ ! -f "${runtime_env}" ] && [ "${selected_secret_mode}" = "vault" ]; then
  printf '# Production values are hydrated from OCI Vault into /run only.\n' > \
    "${runtime_env}"
  chmod 0600 "${runtime_env}"
elif [ ! -f "${runtime_env}" ]; then
  oci_namespace="$(OCI_CLI_AUTH=instance_principal oci os ns get --query data --raw-output)"
  oci_region="$(curl --fail --silent --show-error \
    --connect-timeout 5 --max-time 30 --retry 3 --retry-all-errors --retry-delay 1 \
    --header 'Authorization: Bearer Oracle' \
    http://169.254.169.254/opc/v2/instance/canonicalRegionName)"
  oci_region="$(printf '%s' "${oci_region}" | tr -d '[:space:]')"
  oci_media_bucket=${CLIXOR_OCI_MEDIA_BUCKET:-clixor-prod-media}
  [ -n "${oci_namespace}" ] || {
    echo "Could not resolve the OCI Object Storage namespace with instance principal." >&2
    exit 1
  }
  case "${oci_region}" in
    [a-z][a-z]-[a-z]*-[1-9]) ;;
    *)
      echo "Could not resolve the OCI region from instance metadata." >&2
      exit 1
      ;;
  esac
  case "${oci_media_bucket}" in
    ''|*[!A-Za-z0-9._-]*)
      echo "CLIXOR_OCI_MEDIA_BUCKET contains unsupported characters." >&2
      exit 1
      ;;
  esac
  OCI_CLI_AUTH=instance_principal oci os bucket get \
    --namespace-name "${oci_namespace}" \
    --name "${oci_media_bucket}" >/dev/null || {
    echo "Instance principal cannot read OCI media bucket ${oci_media_bucket}." >&2
    exit 1
  }

  postgres_password="$(openssl rand -hex 32)"
  redis_password="$(openssl rand -hex 32)"
  nats_token="$(openssl rand -hex 32)"
  jwt_secret="$(openssl rand -hex 48)"
  metrics_token="$(openssl rand -hex 48)"
  otp_hmac_secret="$(openssl rand -hex 48)"
  grafana_password="$(openssl rand -hex 24)"

  {
    printf 'POSTGRES_DB=clixor\n'
    printf 'POSTGRES_USER=clixor\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
    printf 'REDIS_PASSWORD=%s\n' "${redis_password}"
    printf 'NATS_AUTH_TOKEN=%s\n' "${nats_token}"
    printf 'GF_SECURITY_ADMIN_USER=clixoradmin\n'
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "${grafana_password}"
    printf 'CLUSTER_ENV=staging\n'
    printf 'CLUSTER_HTTP_ADDR=:8080\n'
    printf 'CLUSTER_PUBLIC_BASE_URL=https://clustr-api.atlanteanz.com\n'
    printf 'CLUSTER_TLS_CA_FILE=/run/pki/ca.crt\n'
    printf 'CLUSTER_STORE=postgres\n'
    printf 'CLUSTER_AUTO_MIGRATE=false\n'
    printf 'CLUSTER_DATABASE_URL=postgres://clixor:%s@postgres.clixor.internal:5432/clixor?sslmode=verify-full&sslrootcert=/run/pki/ca.crt\n' "${postgres_password}"
    printf 'CLUSTER_DATABASE_MAX_CONNS=12\n'
    printf 'CLUSTER_DATABASE_MIN_CONNS=2\n'
    printf 'CLUSTER_REDIS_URL=rediss://:%s@clixor-tls:6379/0\n' "${redis_password}"
    printf 'CLUSTER_NATS_URL=tls://%s@nats.clixor.internal:4222\n' "${nats_token}"
    printf 'CLUSTER_JWT_ACCESS_SECRET=%s\n' "${jwt_secret}"
    printf 'CLUSTER_METRICS_TOKEN=%s\n' "${metrics_token}"
    printf 'CLUSTER_OTP_HMAC_SECRET=%s\n' "${otp_hmac_secret}"
    printf 'CLUSTER_JWT_ISSUER=clixor-api\n'
    printf 'CLUSTER_ACCESS_TTL=15m\n'
    printf 'CLUSTER_REFRESH_TTL=720h\n'
    printf 'CLUSTER_MEDIA_PROVIDER=oci\n'
    printf 'CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE=%s\n' "${oci_namespace}"
    printf 'CLUSTER_OCI_OBJECT_STORAGE_BUCKET=%s\n' "${oci_media_bucket}"
    printf 'CLUSTER_OCI_OBJECT_STORAGE_REGION=%s\n' "${oci_region}"
    printf 'CLUSTER_VERIFICATION_PROVIDER=disabled\n'
    printf 'CLUSTER_OTP_CODE_LENGTH=6\n'
    printf 'CLUSTER_OTP_CHALLENGE_TTL=10m\n'
    printf 'CLUSTER_OTP_RESEND_COOLDOWN=1m\n'
    printf 'CLUSTER_OTP_LOCKOUT_TTL=15m\n'
    printf 'CLUSTER_OTP_MAX_ATTEMPTS=5\n'
    printf 'CLUSTER_OTP_PHONE_SEND_HOURLY=5\n'
    printf 'CLUSTER_OTP_PHONE_SEND_DAILY=10\n'
    printf 'CLUSTER_OTP_GLOBAL_SEND_MINUTE=60\n'
    printf 'CLUSTER_OTP_GLOBAL_SEND_DAILY=10000\n'
    printf 'CLUSTER_APPLE_CLIENT_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APNS_BUNDLE_ID=com.Clustr.Clustr.Clustr\n'
    printf 'CLUSTER_APNS_ENVIRONMENT=production\n'
  } > "${runtime_env}"
  chmod 0600 "${runtime_env}"
fi

# Split the legacy all-service environment into least-privilege service files.
# The helper publishes files atomically, is idempotent, and never evaluates or
# prints their values. runtime.env remains only as a non-consumed migration
# checkpoint for unknown legacy entries.
if [ "${selected_secret_mode}" = "staging" ]; then
  sh "${script_root}/split-runtime-secrets.sh" "${runtime_env}" "${secret_root}"
fi

if [ "${defer_host_tool_activation}" = "false" ]; then
  # Existing hosts must first commit one release containing boot-secrets while
  # the legacy unit is still active. Only an explicit operator bootstrap may
  # then replace these stable boot-critical host artifacts. Automated deploys
  # set deferral and cannot overwrite the launcher, unit, drop-in, or fallback.
  stable_secret_launcher=/usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py
  stable_initial_worker=/usr/local/libexec/clixor/prepare-initial-staging-secrets.sh
  stable_secret_unit=/etc/systemd/system/clixor-runtime-secrets.service
  stable_docker_dropin=/etc/systemd/system/docker.service.d/clixor-runtime-secrets.conf
  stable_launcher_installed=false
  if [ -e "${stable_docker_dropin}" ] || [ -L "${stable_docker_dropin}" ]; then
    [ -f "${stable_docker_dropin}" ] && [ ! -L "${stable_docker_dropin}" ] && \
      [ "$(stat -c '%u:%g:%a' "${stable_docker_dropin}")" = "0:0:644" ] || {
      echo "Existing Docker runtime-secret ordering drop-in is unsafe." >&2
      exit 1
    }
  fi
  if [ -e "${stable_secret_launcher}" ] || [ -L "${stable_secret_launcher}" ]; then
    [ -f "${stable_secret_launcher}" ] && [ ! -L "${stable_secret_launcher}" ] && \
      [ "$(stat -c '%u:%g:%a' "${stable_secret_launcher}")" = "0:0:755" ] && \
      [ -f "${stable_initial_worker}" ] && [ ! -L "${stable_initial_worker}" ] && \
      [ "$(stat -c '%u:%g:%a' "${stable_initial_worker}")" = "0:0:500" ] && \
      [ -f "${stable_secret_unit}" ] && [ ! -L "${stable_secret_unit}" ] && \
      [ "$(stat -c '%u:%g:%a' "${stable_secret_unit}")" = "0:0:644" ] && \
      grep -Fxq \
        'ExecStart=/usr/bin/python3 /usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py' \
        "${stable_secret_unit}" || {
      echo "Existing stable runtime-secret launcher installation is incomplete or unsafe." >&2
      exit 1
    }
    stable_launcher_installed=true
  else
    if [ -e "${stable_initial_worker}" ] || [ -L "${stable_initial_worker}" ]; then
      echo "Stable initial-staging worker exists without its validated launcher." >&2
      exit 1
    fi
    if [ -e "${stable_secret_unit}" ] || [ -L "${stable_secret_unit}" ]; then
      [ -f "${stable_secret_unit}" ] && [ ! -L "${stable_secret_unit}" ] && \
        [ "$(stat -c '%u:%g:%a' "${stable_secret_unit}")" = "0:0:644" ] || {
        echo "Existing runtime-secret unit is unsafe." >&2
        exit 1
      }
      if grep -Fq 'prepare-runtime-secrets-launcher.py' "${stable_secret_unit}"; then
        echo "Stable runtime-secret unit exists without its validated launcher." >&2
        exit 1
      fi
    fi
  fi

  legacy_release_needs_bootstrap=false
  if [ -L "${project_root}/releases/current" ]; then
    selected_boot_release="$(readlink -- "${project_root}/releases/current")"
    selected_boot_mode="${selected_boot_release}/secret-mode"
    selected_boot_root="${selected_boot_release}/boot-secrets"
    if [ -e "${selected_boot_mode}" ] || [ -L "${selected_boot_mode}" ] || \
      [ -e "${selected_boot_root}" ] || [ -L "${selected_boot_root}" ]; then
      /usr/bin/python3 "${script_root}/prepare-runtime-secrets-launcher.py" \
        --verify-release-bundle "${selected_boot_release}"
    elif [ "${selected_secret_mode}" = "staging" ]; then
      # Raw pre-controller releases have neither marker. The reconciler may
      # extend this exact current release only after it verifies the live image
      # commit in the root-owned Git object store.
      legacy_release_needs_bootstrap=true
    else
      echo "Current release lacks its stable boot-secret cohort." >&2
      exit 1
    fi
    if [ "${stable_launcher_installed}" = "false" ]; then
      [ "${legacy_release_needs_bootstrap}" = "true" ] || { \
        [ -f "${selected_boot_release}/secret-mode" ] && \
          [ ! -L "${selected_boot_release}/secret-mode" ] && \
          [ "$(stat -c '%u:%g:%a' "${selected_boot_release}/secret-mode")" = "0:0:400" ] && \
          [ "$(wc -l < "${selected_boot_release}/secret-mode" | tr -d '[:space:]')" = "1" ] && \
          [ "$(sed -n '1p' "${selected_boot_release}/secret-mode")" = "staging" ]; \
      } || {
        echo "Initial stable-launcher transition requires a current staging release; reboot-prove it before Vault cutover." >&2
        exit 1
      }
    fi
  elif [ "${stable_launcher_installed}" = "false" ] && \
    [ "${selected_secret_mode}" != "staging" ]; then
    echo "Initial stable-launcher bootstrap requires staging secret mode." >&2
    exit 1
  fi
  install -m 0755 -o 0 -g 0 \
    "${script_root}/prepare-runtime-secrets-launcher.py" \
    /usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py
  install -m 0500 -o 0 -g 0 \
    "${script_root}/prepare-initial-staging-secrets.sh" \
    /usr/local/libexec/clixor/prepare-initial-staging-secrets.sh
  install -m 0500 -o 0 -g 0 "${script_root}/hydrate-vault-secrets.py" \
    /usr/local/libexec/clixor/staging-secret-validation.py
  install -m 0755 -o 0 -g 0 "${script_root}/prepare-staging-secrets.py" \
    /usr/local/libexec/clixor/prepare-staging-secrets.py
  install -d -m 0755 -o 0 -g 0 /etc/systemd/system/docker.service.d
  install -m 0644 -o 0 -g 0 "${script_root}/clixor-runtime-secrets.service" \
    /etc/systemd/system/clixor-runtime-secrets.service
  install -m 0644 -o 0 -g 0 "${script_root}/docker-runtime-secrets.conf" \
    /etc/systemd/system/docker.service.d/clixor-runtime-secrets.conf
  # The legacy baseline hashes the complete staging cohort. Render derived
  # files and select that cohort before attempting the one-time transition.
  if [ "${CLIXOR_SKIP_SECRET_PREPARATION:-false}" = "false" ]; then
    if [ "${selected_secret_mode}" = "staging" ]; then
      /usr/bin/python3 /usr/local/libexec/clixor/prepare-staging-secrets.py
    fi
    if [ "${legacy_release_needs_bootstrap}" = "false" ]; then
      /usr/bin/python3 \
        /usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py
    fi
  fi
  # Existing 9e41-style staging releases contain only the boot-secret cohort.
  # Before installing the new boot authority, atomically extend the selected
  # staging release with a complete schema-2 runtime baseline. This explicit
  # transition holds the same lock as deployments and fails closed on any
  # source/image/PKI mismatch.
  install -d -m 0700 -o 0 -g 0 "${project_root}/releases/pending"
  if [ -L "${project_root}/releases/current" ]; then
    exec 8>"${project_root}/runtime/deploy.lock"
    flock -n 8 || {
      echo "A deployment is active; refusing the runtime-controller transition." >&2
      exit 1
    }
    controller_source_root="$(CDPATH= cd -- "${script_root}/../.." && pwd)"
    legacy_git_directory=${CLIXOR_LEGACY_GIT_DIR:-${project_root}/runtime/actions-source.git}
    case "${legacy_git_directory}" in
      /*) ;;
      *)
        echo "CLIXOR_LEGACY_GIT_DIR must be an absolute path." >&2
        exit 1
        ;;
    esac
    if [ "${legacy_release_needs_bootstrap}" = "true" ]; then
      [ -x /usr/bin/git ] || {
        echo "Git is required for the raw legacy source transition." >&2
        exit 1
      }
      if [ -e "${legacy_git_directory}" ] || [ -L "${legacy_git_directory}" ]; then
        [ -d "${legacy_git_directory}" ] && [ ! -L "${legacy_git_directory}" ] && \
          [ "$(readlink -f -- "${legacy_git_directory}")" = "${legacy_git_directory}" ] && \
          [ "$(stat -c '%u:%g:%a' "${legacy_git_directory}")" = "0:0:700" ] || {
          echo "Legacy Git object directory is unsafe." >&2
          exit 1
        }
      else
        install -d -m 0700 -o 0 -g 0 "${legacy_git_directory}"
        /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root LC_ALL=C \
          GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
          /usr/bin/git init --bare --initial-branch=main \
          "${legacy_git_directory}" >/dev/null
      fi
      legacy_image="clixor-api:${selected_boot_release##*/}"
      legacy_source_sha="$(docker image inspect "${legacy_image}" \
        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
      case "${legacy_source_sha}" in
        ''|*[!0-9a-f]*)
          echo "Legacy image revision is not a lowercase Git object ID." >&2
          exit 1
          ;;
      esac
      [ "${#legacy_source_sha}" -eq 40 ] && \
        [ "$(printf '%s' "${legacy_source_sha}" | cut -c1-12)" = \
          "$(printf '%s' "${selected_boot_release##*/}" | cut -c5-16)" ] || {
        echo "Legacy image revision does not match the current release." >&2
        exit 1
      }
      trusted_git() {
        /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root LC_ALL=C \
          GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
          /usr/bin/git --git-dir="${legacy_git_directory}" "$@"
      }
      trusted_git remote remove origin >/dev/null 2>&1 || true
      trusted_git remote add origin \
        https://github.com/Akhilmadineni/clixor-backend.git
      trusted_git fetch --force --no-tags origin \
        "+${legacy_source_sha}:refs/clixor/legacy-baseline"
      trusted_git fsck --full --strict "${legacy_source_sha}" >/dev/null
    fi
    /usr/bin/python3 "${script_root}/runtime-reconciler.py" \
      establish-legacy-baseline \
      --controller-source "${controller_source_root}" \
      --legacy-git-dir "${legacy_git_directory}"
    if [ "${legacy_release_needs_bootstrap}" = "true" ] && \
      [ "${CLIXOR_SKIP_SECRET_PREPARATION:-false}" = "false" ]; then
      /usr/bin/python3 \
        /usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py
    fi
  fi
  install -m 0500 -o 0 -g 0 "${script_root}/runtime_bundle.py" \
    /usr/local/libexec/clixor/runtime_bundle.py
  install -m 0500 -o 0 -g 0 "${script_root}/runtime-reconciler.py" \
    /usr/local/libexec/clixor/runtime-reconciler.py
  for runtime_unit in \
    clixor-runtime-reconcile.service \
    clixor-runtime-watchdog.service \
    clixor-runtime-watchdog.timer
  do
    install -m 0644 -o 0 -g 0 "${script_root}/${runtime_unit}" \
      "/etc/systemd/system/${runtime_unit}"
  done
  systemctl daemon-reload
  systemctl enable \
    clixor-runtime-secrets.service \
    clixor-runtime-reconcile.service \
    clixor-runtime-watchdog.timer
  if [ -L "${project_root}/releases/current" ]; then
    systemctl restart clixor-runtime-reconcile.service
    systemctl start clixor-runtime-watchdog.timer
    systemctl try-restart cloudflared.service >/dev/null 2>&1 || true
  fi
fi

runtime_secret_root=/run/clixor/secrets
active_link="${runtime_secret_root}/active"
[ -L "${active_link}" ] || {
  echo "${active_link} must be a symbolic link." >&2
  exit 1
}
active_target="$(readlink -- "${active_link}")"
case "${active_target}" in
  /srv/clixor/secrets) ;;
  vault-generations/gen-[0-9]*-[0-9a-f]*)
    [ -d "${runtime_secret_root}/${active_target}" ] && \
      [ ! -L "${runtime_secret_root}/${active_target}" ] || {
      echo "${active_link} selects an unavailable Vault generation." >&2
      exit 1
    }
    ;;
  *)
    echo "${active_link} selects an unsupported secret location." >&2
    exit 1
    ;;
esac

active_secret_root="${runtime_secret_root}/active"
api_env="${active_secret_root}/api.env"
active_apns_root="${active_secret_root}/apns"
metrics_secret="${active_secret_root}/metrics.token"
metrics_token="$(sed -n 's/^CLUSTER_METRICS_TOKEN=//p' "${api_env}" | tail -n 1)"
[ -n "${metrics_token}" ] || {
  echo "CLUSTER_METRICS_TOKEN is missing from ${api_env}." >&2
  exit 1
}
if [ "${active_target}" = "/srv/clixor/secrets" ]; then
  printf '%s' "${metrics_token}" > "${secret_root}/metrics.token"
  chown 0:65534 "${secret_root}/metrics.token"
  chmod 0440 "${secret_root}/metrics.token"
else
  [ -s "${metrics_secret}" ] && [ ! -L "${metrics_secret}" ] || {
    echo "Hydrated metrics token is missing." >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a' "${metrics_secret}")" = "0:65534:440" ] || {
    echo "Hydrated metrics token has unsafe ownership or mode." >&2
    exit 1
  }
fi

install -m 0400 -o 99 -g 99 "${script_root}/haproxy.cfg" \
  "${runtime_root}/dependency-tls/haproxy.cfg"
install -m 0400 -o 101 -g 101 "${script_root}/api-gateway-nginx.conf" \
  "${runtime_root}/api-gateway/nginx.conf"
install -m 0500 -o 0 -g 0 "${script_root}/backup.sh" \
  "${runtime_root}/postgres-backup/backup.sh"
if [ "${defer_host_tool_activation}" = "false" ]; then
  install -m 0500 -o 0 -g 0 "${script_root}/offsite-backup.sh" \
    "${backup_tool_root}/offsite-backup.sh"
  install -m 0500 -o 0 -g 0 "${script_root}/backup-health.sh" \
    "${backup_tool_root}/backup-health.sh"
  install -m 0500 -o 0 -g 0 "${script_root}/restore-drill.sh" \
    "${backup_tool_root}/restore-drill.sh"
  install -m 0500 -o 0 -g 0 "${script_root}/backup_manifest.py" \
    "${backup_tool_root}/backup_manifest.py"
  for unit_name in \
    clixor-offsite-backup.service \
    clixor-offsite-backup.timer \
    clixor-backup-health.service \
    clixor-backup-health.timer \
    clixor-restore-drill.service \
    clixor-restore-drill.timer
  do
    install -m 0644 -o 0 -g 0 "${script_root}/${unit_name}" \
      "${systemd_unit_root}/${unit_name}"
  done
fi
if [ ! -f "${backup_config}" ]; then
  backup_config_partial="$(mktemp "${backup_config_root}/offsite-backup.env.XXXXXXXX")"
  {
    printf 'OCI_BACKUP_BUCKET=%s\n' "${oci_backup_bucket}"
    printf 'OCI_BACKUP_PREFIX=%s\n' "${oci_backup_prefix}"
  } > "${backup_config_partial}"
  chmod 0600 "${backup_config_partial}"
  chown 0:0 "${backup_config_partial}"
  mv "${backup_config_partial}" "${backup_config}"
fi
install -m 0400 -o 65534 -g 65534 "${script_root}/prometheus.yml" \
  "${runtime_root}/prometheus/prometheus.yml"
install -m 0400 -o 472 -g 472 "${script_root}/grafana-datasource.yml" \
  "${runtime_root}/grafana/datasource.yml"

for apns_key in "${active_apns_root}"/*.p8; do
  [ -f "${apns_key}" ] || continue
  [ ! -L "${apns_key}" ] || {
    echo "APNs key must not be a symbolic link: ${apns_key}" >&2
    exit 1
  }
  if [ "${active_target}" = "/srv/clixor/secrets" ]; then
    chown 0:65532 "${apns_key}"
    chmod 0440 "${apns_key}"
  elif [ "$(stat -c '%u:%g:%a' "${apns_key}")" != "0:65532:440" ]; then
    echo "Hydrated APNs key has unsafe ownership or mode." >&2
    exit 1
  fi
done

# Only establish mount-root ownership. Recursively walking a live database
# during every release is both slow and unnecessary.
chown 70:70 "${project_root}/data/postgres"
chown 999:1000 "${project_root}/data/redis"
chown 1000:1000 "${project_root}/data/nats"
chown 65534:65534 "${project_root}/data/prometheus"
chown 472:472 "${project_root}/data/grafana"
chmod 0600 "${runtime_env}"
chmod 0750 "${active_apns_root}"

for file_spec in \
  'api.env:0:65532:440' \
  'migrate.env:0:65532:440' \
  'postgres.password:0:70:440' \
  'postgres.pgpass:0:0:400' \
  'redis.password:0:1000:440' \
  'redis.acl:0:1000:440' \
  'nats.conf:0:1000:440' \
  'grafana.ini:0:472:440' \
  'metrics.token:0:65534:440'
do
  file_name=${file_spec%%:*}
  expected_metadata=${file_spec#*:}
  file_path="${active_secret_root}/${file_name}"
  [ -f "${file_path}" ] && [ ! -L "${file_path}" ] || {
    echo "Runtime secret file is unsafe: ${file_name}" >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a' "${file_path}")" = "${expected_metadata}" ] || {
    echo "Runtime secret file has unsafe ownership or mode: ${file_name}" >&2
    exit 1
  }
done

for required_path in \
  "${runtime_env}" \
  "${api_env}" \
  "${active_secret_root}/postgres.env" \
  "${active_secret_root}/redis.env" \
  "${active_secret_root}/nats.env" \
  "${active_secret_root}/grafana.env" \
  "${active_secret_root}/backup.env" \
  "${active_secret_root}/migrate.env" \
  "${active_secret_root}/postgres.password" \
  "${active_secret_root}/postgres.pgpass" \
  "${active_secret_root}/redis.password" \
  "${active_secret_root}/redis.acl" \
  "${active_secret_root}/nats.conf" \
  "${active_secret_root}/grafana.ini" \
  "${metrics_secret}" \
  "${pki_root}/ca.crt" \
  "${runtime_root}/dependency-pki.desired" \
  "${runtime_root}/dependency-tls/current/server.pem" \
  "${runtime_root}/postgres-tls/current/server.key" \
  "${runtime_root}/postgres-tls/current/server.crt" \
  "${runtime_root}/nats-tls/current/server.key" \
  "${runtime_root}/nats-tls/current/server.crt" \
  "${runtime_root}/dependency-tls/haproxy.cfg" \
  "${runtime_root}/api-gateway/nginx.conf"
do
  [ -s "${required_path}" ] || {
    echo "Missing OCI runtime file: ${required_path}" >&2
    exit 1
  }
done

if [ "${defer_host_tool_activation}" = "false" ]; then
  systemctl daemon-reload
  systemctl enable --now clixor-offsite-backup.timer
  if [ -s "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" ]; then
    systemctl enable --now clixor-restore-drill.timer clixor-backup-health.timer
  else
    # deploy.sh performs the first offsite restore drill as a release gate. Never
    # report backup health or schedule later drills before that gate has passed.
    systemctl disable --now clixor-restore-drill.timer clixor-backup-health.timer \
      >/dev/null 2>&1 || true
  fi
fi

echo "Clixor OCI ARM64 directories, runtime secrets, and internal PKI are ready."
if [ "${selected_secret_mode}" = "staging" ]; then
  echo "Telnyx and APNs remain disabled until production Vault credentials are installed."
fi
