#!/bin/sh
set -eu

postfix status >/dev/null 2>&1
test -s /run/opendkim/opendkim.pid
kill -0 "$(cat /run/opendkim/opendkim.pid)" 2>/dev/null
banner="$(printf 'QUIT\r\n' | nc -w 3 127.0.0.1 25 | head -1)"
case "$banner" in
  220*) exit 0 ;;
  *) exit 1 ;;
esac
