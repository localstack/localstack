#!/bin/bash

set -eo pipefail
shopt -s nullglob

if [[ ! $INIT_SCRIPTS_PATH ]]
then
  INIT_SCRIPTS_PATH=/docker-entrypoint-initaws.d
fi

# This stores the PID of supervisord for us after forking
suppid=0

# Setup the SIGTERM-handler function
term_handler() {
  send_sig="-$1"
  if [ $suppid -ne 0 ]; then
    echo "Sending $send_sig to supervisord"
    kill ${send_sig} "$suppid"
    wait "$suppid"
  fi
  exit 143; # 128 + 15 -- SIGTERM
}

# Strip `LOCALSTACK_` prefix in environment variables name (except LOCALSTACK_HOSTNAME)
source <(
  env |
  grep -v -e '^LOCALSTACK_HOSTNAME' |
  grep -v -e '^LOCALSTACK_[[:digit:]]' | # See issue #1387
  sed -ne 's/^LOCALSTACK_\([^=]\+\)=.*/export \1=${LOCALSTACK_\1}/p'
)

# Setup trap handler(s)
if [ "$SET_TERM_HANDLER" != "" ]; then
  # Catch all the main 
  trap 'kill -1 ${!}; term_handler 1' SIGHUP
  trap 'kill -2 ${!}; term_handler 2' SIGINT
  trap 'kill -3 ${!}; term_handler 3' SIGQUIT
  trap 'kill -15 ${!}; term_handler 15' SIGTERM
  trap 'kill -31 ${!}; term_handler 31' SIGUSR2
fi

cat /dev/null > /tmp/localstack_infra.log
cat /dev/null > /tmp/localstack_infra.err

supervisord -c /etc/supervisord.conf &
suppid="$!"

function run_startup_scripts {
  until grep -q '^Ready.' /tmp/localstack_infra.log >/dev/null 2>&1 ; do
    echo "Waiting for all LocalStack services to be ready"
    sleep 7
  done

  for f in $INIT_SCRIPTS_PATH/*; do
    case "$f" in
      *.sh)     echo "$0: running $f"; . "$f" ;;
      *)        echo "$0: ignoring $f" ;;
    esac
    echo
  done
}

run_startup_scripts &

# Run tail on the localstack log files forever until we are told to terminate
if [ "$SET_TERM_HANDLER" != "" ]; then
  while true; do
    tail -qF /tmp/localstack_infra.log /tmp/localstack_infra.err & wait ${!}
  done
else
  tail -qF /tmp/localstack_infra.log /tmp/localstack_infra.err
fi
