#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_file="${1:-$script_dir/clixor-oci-resource-manager.zip}"

if [[ "$output_file" != /* ]]; then
  output_file="$PWD/$output_file"
fi

rm -f -- "$output_file"
(
  cd "$script_dir"
  zip -q "$output_file" \
    .terraform.lock.hcl \
    clixor-data-volume.service \
    clixor-mount-data.sh \
    cloud-init.yaml.tftpl \
    compute.tf \
    identity.tf \
    locals.tf \
    network.tf \
    outputs.tf \
    providers.tf \
    schema.yaml \
    storage.tf \
    variables.tf \
    vault.tf \
    versions.tf
)

printf '%s\n' "$output_file"
