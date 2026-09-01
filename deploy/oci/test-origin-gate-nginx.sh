#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "SKIP: root required"; exit 77; }
command -v docker >/dev/null 2>&1 || { echo "SKIP: docker required"; exit 77; }

image='nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de'
script_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
prefix="clixor-origin-gate-test-$$"
root="$(mktemp -d /tmp/clixor-origin-gate-nginx.XXXXXX)"
network="${prefix}-network"
cleanup() {
  docker rm -f "${prefix}-gateway" "${prefix}-api-a" "${prefix}-api-b" \
    >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf -- "${root}"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0750 -o 986 -g 987 "${root}/origin"
install -d -m 0755 -o 0 -g 0 "${root}/gate"
docker network create "${network}" >/dev/null

start_api() {
  name="$1"
  docker run --detach --name "${prefix}-${name}" --network "${network}" \
    --network-alias "${name}" \
    --mount "type=bind,src=${script_root}/test-origin-gate-upstream.conf,dst=/etc/nginx/conf.d/default.conf,readonly" \
    "${image}" \
    >/dev/null
}
start_api api-a
start_api api-b

docker run --detach --name "${prefix}-gateway" --network "${network}" \
  --user 986:987 --read-only \
  --tmpfs /var/cache/nginx:uid=986,gid=987,mode=0750,size=32m \
  --tmpfs /var/run:uid=986,gid=987,mode=0750,size=4m \
  --tmpfs /tmp:size=16m \
  --mount "type=bind,src=${script_root}/api-gateway-nginx.conf,dst=/etc/nginx/nginx.conf,readonly" \
  --mount "type=bind,src=${root}/origin,dst=/run/clixor-origin" \
  --mount "type=bind,src=${root}/gate,dst=/run/clixor-origin-gate,readonly" \
  "${image}" /bin/sh -c "umask 007 && exec nginx -g 'daemon off;'" >/dev/null

for _ in $(seq 1 80); do
  [ -S "${root}/origin/gateway.sock" ] && break
  sleep .1
done
[ -S "${root}/origin/gateway.sock" ] || {
  docker logs "${prefix}-gateway" >&2
  echo "gateway Unix socket was not created" >&2
  exit 1
}

request() {
  python3 - "${root}/origin/gateway.sock" "$1" <<'PY'
import http.client, socket, sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(("GET /health/ready HTTP/1.1\r\nHost: "+sys.argv[2]+"\r\nConnection: close\r\n\r\n").encode())
r=http.client.HTTPResponse(s); r.begin(); body=r.read().decode().strip()
print(f"{r.status}|{body}")
PY
}

[ "$(request clustr-api.atlanteanz.com)" = '503|clixor-origin-gate-closed' ]
[ "$(request clixor-oci-canary.atlanteanz.com)" = \
  '200|{"status":"ready","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ]
unknown_result="$(request attacker.invalid)"
[ "${unknown_result%%|*}" = '421' ]
install -m 0400 -o 0 -g 0 /dev/null "${root}/gate/public-open"
[ "$(request clustr-api.atlanteanz.com)" = \
  '200|{"status":"ready","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ]
echo "origin-gate-nginx=passed"
