#!/bin/bash

set -eo pipefail
shopt -s nullglob

# Strip `LOCALSTACK_` prefix in environment variables name (except LOCALSTACK_HOSTNAME)
source <(
  env |
  grep -v -e '^LOCALSTACK_HOSTNAME' |
  grep -v -e '^LOCALSTACK_[[:digit:]]' | # See issue #1387
  sed -ne 's/^LOCALSTACK_\([^=]\+\)=.*/export \1=${LOCALSTACK_\1}/p'
)

cat /dev/null > /tmp/localstack_infra.log
cat /dev/null > /tmp/localstack_infra.err

supervisord -c /etc/supervisord.conf &

function run_startup_scripts {
  until grep -q "^Ready.$" /tmp/localstack_infra.log >/dev/null 2>&1 ; do
    echo "Waiting for all LocalStack services to be ready"
    sleep 7
  done

  for f in /docker-entrypoint-initaws.d/*; do
    case "$f" in
      *.sh)     echo "$0: running $f"; . "$f" ;;
      *)        echo "$0: ignoring $f" ;;
    esac
    echo
  done
}

run_startup_scripts &

tail -qF /tmp/localstack_infra.log /tmp/localstack_infra.err
