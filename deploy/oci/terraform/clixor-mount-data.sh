#!/usr/bin/env bash
set -euo pipefail

device=${CLIXOR_DATA_DEVICE:-/dev/oracleoci/oraclevdb}
expected_size_gbs=${CLIXOR_DATA_VOLUME_SIZE_GBS:-100}
mount_point=/srv/clixor

case "$device" in
  /dev/oracleoci/oraclevd[b-z]) ;;
  *)
    echo "refusing unsafe OCI data device path: $device" >&2
    exit 2
    ;;
esac

case "$expected_size_gbs" in
  '' | *[!0-9]*)
    echo "expected data volume size must be a whole number of GiB" >&2
    exit 2
    ;;
esac
if ((expected_size_gbs < 50 || expected_size_gbs > 150)); then
  echo "expected data volume size is outside the supported range" >&2
  exit 2
fi
expected_size_bytes=$((expected_size_gbs * 1024 * 1024 * 1024))

udevadm settle --timeout=30 || true
for _attempt in $(seq 1 120); do
  [[ -b "$device" ]] && break
  sleep 5
done
if [[ ! -b "$device" ]]; then
  lsblk -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS >&2
  echo "configured OCI data device did not appear: $device" >&2
  exit 1
fi

resolved_device=$(readlink -f "$device")
read -r device_type device_read_only device_maj_min < <(
  lsblk -dn -o TYPE,RO,MAJ:MIN "$resolved_device"
)
if [[ "$device_type" != disk || "$device_read_only" != 0 || -z "$device_maj_min" ]]; then
  echo "refusing non-writable whole-disk data device: $resolved_device" >&2
  exit 2
fi

actual_size_bytes=$(blockdev --getsize64 "$resolved_device")
if [[ "$actual_size_bytes" -ne "$expected_size_bytes" ]]; then
  echo "refusing data device with unexpected size: $resolved_device ($actual_size_bytes bytes)" >&2
  exit 2
fi

root_source=$(findmnt -n -o SOURCE --target /)
root_source=$(readlink -f "$root_source")
if [[ ! -b "$root_source" ]]; then
  echo "unable to prove the root filesystem block-device ancestry" >&2
  exit 2
fi
mapfile -t root_maj_min < <(lsblk -s -nr -o MAJ:MIN "$root_source" | awk 'NF { print $1 }')
if ((${#root_maj_min[@]} == 0)); then
  echo "unable to enumerate the root filesystem block-device ancestry" >&2
  exit 2
fi
for ancestor in "${root_maj_min[@]}"; do
  if [[ "$device_maj_min" == "$ancestor" ]]; then
    echo "refusing a device in the root filesystem ancestry: $resolved_device" >&2
    exit 2
  fi
done

mapfile -t device_nodes < <(lsblk -nrpo NAME "$resolved_device")
if ((${#device_nodes[@]} != 1)); then
  echo "refusing data device that already has child block devices: $resolved_device" >&2
  exit 3
fi

mapfile -t device_mounts < <(
  findmnt -rn -o MAJ:MIN,TARGET |
    awk -v device_maj_min="$device_maj_min" '$1 == device_maj_min { print $2 }'
)
for existing_mount in "${device_mounts[@]}"; do
  if [[ "$existing_mount" != "$mount_point" ]]; then
    echo "refusing data device already mounted at $existing_mount" >&2
    exit 3
  fi
done

target_is_mounted=false
if mountpoint -q "$mount_point"; then
  target_is_mounted=true
  mounted_maj_min=$(findmnt -n -o MAJ:MIN --target "$mount_point" | tr -d '[:space:]')
  if [[ "$mounted_maj_min" != "$device_maj_min" ]]; then
    echo "refusing unexpected device already mounted at $mount_point" >&2
    exit 3
  fi
elif [[ -d "$mount_point" ]] && [[ -n "$(find "$mount_point" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "refusing to hide existing unmounted content at $mount_point" >&2
  exit 3
fi

mapfile -t fstab_entries < <(
  awk -v target="$mount_point" \
    '$1 !~ /^#/ && $2 == target { print $1, $2, $3, $4, $5, $6 }' \
    /etc/fstab
)
if ((${#fstab_entries[@]} > 1)); then
  echo "refusing duplicate fstab entries for $mount_point" >&2
  exit 4
fi

filesystem=$(blkid -p -o value -s TYPE "$resolved_device" || true)
if [[ -z "$filesystem" ]]; then
  if [[ "$target_is_mounted" == true || ${#fstab_entries[@]} -ne 0 ]]; then
    echo "refusing to format a blank device with existing mount state" >&2
    exit 4
  fi
  signatures=$(wipefs --no-act --output TYPE "$resolved_device" | awk 'NR > 1 && NF { print $1 }')
  if [[ -n "$signatures" ]]; then
    echo "refusing data device with existing signatures: $resolved_device" >&2
    exit 4
  fi
  mkfs.xfs -L CLIXOR_DATA "$resolved_device"
elif [[ "$filesystem" != xfs ]]; then
  echo "refusing unexpected filesystem type: $filesystem" >&2
  exit 4
fi

uuid=$(blkid -p -o value -s UUID "$resolved_device")
if [[ -z "$uuid" ]]; then
  echo "unable to resolve the XFS filesystem UUID" >&2
  exit 5
fi
mapfile -t uuid_devices < <(blkid -t "UUID=$uuid" -o device)
if ((${#uuid_devices[@]} != 1)); then
  echo "refusing non-unique or mismatched filesystem UUID" >&2
  exit 5
fi
uuid_device=$(readlink -f "${uuid_devices[0]}")
uuid_device_maj_min=$(lsblk -dn -o MAJ:MIN "$uuid_device" | tr -d '[:space:]')
if [[ "$uuid_device_maj_min" != "$device_maj_min" ]]; then
  echo "refusing non-unique or mismatched filesystem UUID" >&2
  exit 5
fi

if ((${#fstab_entries[@]} == 1)); then
  read -r fstab_source fstab_target fstab_filesystem fstab_options fstab_dump fstab_pass <<<"${fstab_entries[0]}"
  if [[ "$fstab_source" != "UUID=$uuid" || "$fstab_target" != "$mount_point" || "$fstab_filesystem" != xfs || "$fstab_dump" != 0 || "$fstab_pass" != 2 ]]; then
    echo "refusing conflicting fstab entry for $mount_point" >&2
    exit 5
  fi
  wrapped_options=",$fstab_options,"
  for required_option in defaults nofail _netdev x-systemd.device-timeout=5min; do
    if [[ "$wrapped_options" != *",$required_option,"* ]]; then
      echo "refusing fstab entry missing required option: $required_option" >&2
      exit 5
    fi
  done
else
  printf 'UUID=%s %s xfs defaults,nofail,_netdev,x-systemd.device-timeout=5min 0 2\n' \
    "$uuid" "$mount_point" >>/etc/fstab
fi

mkdir -p "$mount_point"
if [[ "$target_is_mounted" == false ]]; then
  mount "$mount_point"
fi

read -r mounted_maj_min mounted_filesystem mounted_uuid < <(
  findmnt -n -o MAJ:MIN,FSTYPE,UUID --target "$mount_point"
)
if [[ "$mounted_maj_min" != "$device_maj_min" || "$mounted_filesystem" != xfs || "$mounted_uuid" != "$uuid" ]]; then
  echo "refusing unexpected filesystem mounted at $mount_point" >&2
  exit 6
fi

install -d -m 0750 -o root -g docker \
  "$mount_point" \
  "$mount_point/app" \
  "$mount_point/data" \
  "$mount_point/backups" \
  "$mount_point/releases"
