#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root to install OCI CLI under /opt and /usr/local/bin." >&2
  exit 1
fi

installer_commit=fbff93ae6744ed23671b974fd876adb239545cea
installer_sha256=079dcc9a3e2a61ec692400e30169c9996b2998ac8c4e205198ed5863283fcb76
installer_url="https://raw.githubusercontent.com/oracle/oci-cli/${installer_commit}/scripts/install/install.sh"
temporary_installer="$(mktemp /tmp/oci-cli-install.XXXXXX)"
trap 'rm -f "${temporary_installer}"' 0 HUP INT TERM

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "${installer_url}" --output "${temporary_installer}"
printf '%s  %s\n' "${installer_sha256}" "${temporary_installer}" | sha256sum --check --status

bash "${temporary_installer}" \
  --accept-all-defaults \
  --oci-cli-version 3.91.0 \
  --install-dir /opt/oci-cli \
  --exec-dir /usr/local/bin \
  --script-dir /opt/oci-cli/scripts

/usr/local/bin/oci --version
