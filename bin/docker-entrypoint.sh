#!/bin/bash

set -eo pipefail
shopt -s nullglob

supervisord -c /etc/supervisord.conf &

until grep -q "^Ready.$" /tmp/localstack_infra.log >/dev/null 2>&1 ; do
  echo "waiting for localstack"
  sleep 2
done

for f in /docker-entrypoint-initaws.d/*; do
  case "$f" in
    *.sh)     echo "$0: running $f"; . "$f" ;;
    *)        echo "$0: ignoring $f" ;;
  esac
  echo
done

tail -f /tmp/localstack_infra.log
