#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "SKIP: root required"; exit 77; }
[ -d /run/systemd/system ] || { echo "SKIP: systemd is not PID 1"; exit 77; }
unit="clixor-promotion-state-test-$$"
directory="clixor-promotion-state-test-$$"
script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
cleanup() { rm -rf -- "/var/lib/${directory}"; }
trap cleanup EXIT HUP INT TERM
# This exercises systemd's real StateDirectory setup ordering on an initially
# absent path: the ExecStart assertion cannot pass unless PID 1 created it first.
systemd-run --quiet --wait --collect --unit="${unit}" \
  --property=Type=oneshot \
  --property="StateDirectory=${directory}" \
  --property=StateDirectoryMode=0700 \
  /usr/bin/python3 "${script_root}/cloudflare-promote.py" initialize-gate \
    --gate-directory "/var/lib/${directory}/origin-gate-public" \
    --gate-state "/var/lib/${directory}/cloudflare-origin-gate.json"
[ "$(stat -c '%u:%g:%a' "/var/lib/${directory}")" = "0:0:700" ]
[ "$(stat -c '%u:%g:%a' "/var/lib/${directory}/origin-gate-public")" = "0:0:755" ]
[ "$(stat -c '%u:%g:%a' "/var/lib/${directory}/cloudflare-origin-gate.json")" = "0:0:400" ]
[ ! -e "/var/lib/${directory}/origin-gate-public/public-open" ]
# A second real oneshot proves cold-start reconciliation does not invent an
# opening capability or replace the stable journal.
systemd-run --quiet --wait --collect --unit="${unit}-again" \
  --property=Type=oneshot \
  --property="StateDirectory=${directory}" \
  --property=StateDirectoryMode=0700 \
  /usr/bin/python3 "${script_root}/cloudflare-promote.py" initialize-gate \
    --gate-directory "/var/lib/${directory}/origin-gate-public" \
    --gate-state "/var/lib/${directory}/cloudflare-origin-gate.json"
[ ! -e "/var/lib/${directory}/origin-gate-public/public-open" ]
echo "promotion-state-directory=passed"
