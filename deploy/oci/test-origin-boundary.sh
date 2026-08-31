#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "SKIP: root required"; exit 77; }
root="$(mktemp -d /tmp/clixor-origin-test.XXXXXX)"
chmod 0711 "${root}"
cleanup() { kill "${server_pid:-0}" 2>/dev/null || true; rm -rf -- "${root}"; }
trap cleanup EXIT HUP INT TERM
install -d -m 0750 -o 986 -g 987 "${root}/origin"
install -d -m 0755 -o 0 -g 0 "${root}/origin-gate-public"
install -m 0400 -o 0 -g 0 /dev/null "${root}/origin-gate-public/public-open"

# Faithful kernel boundary: the gateway owner creates a 0770 Unix socket; only
# a process carrying connector GID 987 can connect. Other host/runner identities
# cannot traverse the directory or replace the socket entry.
setpriv --reuid=986 --regid=987 --clear-groups python3 - "${root}/origin/gateway.sock" <<'PY' &
import os, socket, sys
os.umask(0o007)
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1]); s.listen(4)
for _ in range(2):
    c, _ = s.accept(); c.sendall(b"connector-only\n"); c.close()
PY
server_pid=$!
for _ in $(seq 1 50); do [ -S "${root}/origin/gateway.sock" ] && break; sleep .05; done
[ "$(stat -c '%u:%g:%a' "${root}/origin")" = "986:987:750" ]
[ "$(stat -c '%u:%g:%a' "${root}/origin/gateway.sock")" = "986:987:770" ]
[ "$(setpriv --reuid=65530 --regid=65530 --groups=987 python3 - "${root}/origin/gateway.sock" <<'PY'
import socket, sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print(s.recv(64).decode().strip())
PY
)" = "connector-only" ]

if setpriv --reuid=65531 --regid=65531 --clear-groups \
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' \
  "${root}/origin/gateway.sock" 2>/dev/null; then
  echo "non-connector identity reached the origin" >&2; exit 1
fi
# The denial above is meaningful only while the same server is still listening.
kill -0 "${server_pid}"
[ "$(setpriv --reuid=65530 --regid=65530 --groups=987 python3 - "${root}/origin/gateway.sock" <<'PY'
import socket, sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print(s.recv(64).decode().strip())
PY
)" = "connector-only" ]
wait "${server_pid}"
if setpriv --reuid=65530 --regid=65530 --groups=987 \
  rm -f -- "${root}/origin/gateway.sock" 2>/dev/null; then
  echo "connector group could replace the gateway socket" >&2; exit 1
fi
setpriv --reuid=986 --regid=987 --clear-groups rm -f -- "${root}/origin/gateway.sock"
[ ! -e "${root}/origin/gateway.sock" ]

# The gateway and connector may stat the persistent capability through their
# read-only bind mount, but neither numeric identity can create, remove, or
# rename host gate artifacts. Missing public-open is therefore fail-closed.
for identity in '986 987' '65530 987'; do
  set -- ${identity}
  setpriv --reuid="$1" --regid="$2" --clear-groups \
    test -f "${root}/origin-gate-public/public-open"
  if setpriv --reuid="$1" --regid="$2" --clear-groups \
    touch "${root}/origin-gate-public/created" 2>/dev/null; then
    echo "non-root identity created an origin gate artifact" >&2; exit 1
  fi
  if setpriv --reuid="$1" --regid="$2" --clear-groups \
    rm -f "${root}/origin-gate-public/public-open" 2>/dev/null; then
    echo "non-root identity removed the origin gate capability" >&2; exit 1
  fi
  if setpriv --reuid="$1" --regid="$2" --clear-groups \
    mv "${root}/origin-gate-public/public-open" \
       "${root}/origin-gate-public/replaced" 2>/dev/null; then
    echo "non-root identity renamed the origin gate capability" >&2; exit 1
  fi
done
[ "$(stat -c '%u:%g:%a:%s' "${root}/origin-gate-public/public-open")" = "0:0:400:0" ]

# The bootstrap's collision guard is exact: any pre-existing numeric owner with
# another name is a terminal condition, never silently adopted.
python3 - "$(dirname "$0")/bootstrap.sh" <<'PY'
import pathlib, sys
raw=pathlib.Path(sys.argv[1]).read_text()
assert 'getent passwd "${gateway_uid}"' in raw
assert 'already assigned outside the gateway boundary' in raw
assert 'passwd --lock "${gateway_user}"' in raw
assert '/usr/sbin/nologin' in raw and '/nonexistent' in raw
PY
if python3 "$(dirname "$0")/validate-origin-identity.py" \
  --passwd-record 'occupied:x:986:987::/nonexistent:/usr/sbin/nologin' \
  --group-record 'clixor-origin:x:987:' --shadow-status 'clixor-gateway L' \
  >/dev/null 2>&1; then
  echo "pre-existing UID collision was accepted" >&2; exit 1
fi

# The checked-in TCP server is health-only and cannot pass a forged identity.
python3 - "$(dirname "$0")/api-gateway-nginx.conf" <<'PY'
import pathlib, sys
raw=pathlib.Path(sys.argv[1]).read_text()
health=raw[raw.index("listen 8080;")-200:]
assert "listen 8080;" in health
assert 'proxy_set_header CF-Connecting-IP "";' in health
assert "location / { return 404; }" in health
PY
echo "origin-boundary=passed"
