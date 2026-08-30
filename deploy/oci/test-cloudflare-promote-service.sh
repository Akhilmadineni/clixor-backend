#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "SKIP: root required"; exit 77; }
[ -d /run/systemd/system ] || { echo "SKIP: systemd is not PID 1"; exit 77; }
unit="clixor-promotion-state-test-$$"
directory="clixor-promotion-state-test-$$"
# This exercises systemd's real StateDirectory setup ordering on an initially
# absent path: the ExecStart assertion cannot pass unless PID 1 created it first.
systemd-run --quiet --wait --collect --unit="${unit}" \
  --property=Type=oneshot \
  --property="StateDirectory=${directory}" \
  --property=StateDirectoryMode=0700 \
  /usr/bin/test -d "/var/lib/${directory}"
[ "$(stat -c '%u:%g:%a' "/var/lib/${directory}")" = "0:0:700" ]
echo "promotion-state-directory=passed"
