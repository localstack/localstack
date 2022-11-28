#!/bin/bash

set -eo pipefail
shopt -s nullglob

if [[ ! $INIT_SCRIPTS_PATH ]]
then
  # FIXME: deprecate and use /etc/localstack/init/ready.d
  INIT_SCRIPTS_PATH=/docker-entrypoint-initaws.d
fi
if [[ ! $EDGE_PORT ]]
then
  EDGE_PORT=4566
fi

# FIXME: deprecation path for legacy directories
# the Dockerfile creates .marker file that will be overwritten if a volume is mounted into /tmp/localstack
if [ ! -f /tmp/localstack/.marker ]; then
    # unless LEGACY_DIRECTORIES is explicitly set to 1, print an error message and exit with a non-zero exit code
    if [[ -z ${LEGACY_DIRECTORIES} ]] || [[ ${LEGACY_DIRECTORIES} == "0" ]]; then
        echo "ERROR"
        echo "============================================================================"
        echo "  It seems you are mounting the LocalStack volume into /tmp/localstack."
        echo "  This will break the LocalStack container! Please update your volume mount"
        echo "  destination to /var/lib/localstack."
        echo "  You can suppress this error by setting LEGACY_DIRECTORIES=1."
        echo ""
        echo "  See: https://github.com/localstack/localstack/issues/6398"
        echo "============================================================================"
        echo ""
        exit 1
    fi
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
  exit 0; # 128 + 15 = 143 -- SIGTERM, but 0 is expected if proper shutdown takes place
}

# Strip `LOCALSTACK_` prefix in environment variables name (except LOCALSTACK_HOSTNAME)
source <(
  env |
  grep -v -e '^LOCALSTACK_HOSTNAME' |
  grep -v -e '^LOCALSTACK_[[:digit:]]' | # See issue #1387
  sed -ne 's/^LOCALSTACK_\([^=]\+\)=.*/export \1=${LOCALSTACK_\1}/p'
)

# Setup trap handler(s)
if [ "$DISABLE_TERM_HANDLER" == "" ]; then
  # Catch all the main
  trap 'kill -1 ${!}; term_handler 1' SIGHUP
  trap 'kill -2 ${!}; term_handler 2' SIGINT
  trap 'kill -3 ${!}; term_handler 3' SIGQUIT
  trap 'kill -15 ${!}; term_handler 15' SIGTERM
  trap 'kill -31 ${!}; term_handler 31' SIGUSR2
fi

LOG_DIR=/var/lib/localstack/logs
test -d ${LOG_DIR} || mkdir -p ${LOG_DIR}

cat /dev/null > ${LOG_DIR}/localstack_infra.log
cat /dev/null > ${LOG_DIR}/localstack_infra.err

# FIXME for backwards compatibility with LEGACY_DIRECTORIES=1
test -f /tmp/localstack_infra.log || ln -s ${LOG_DIR}/localstack_infra.log /tmp/localstack_infra.log
test -f /tmp/localstack_infra.err || ln -s ${LOG_DIR}/localstack_infra.err /tmp/localstack_infra.err

# run modern runtime init scripts before starting localstack
test -d /etc/localstack/init/boot.d && /opt/code/localstack/.venv/bin/python -m localstack.runtime.init BOOT

supervisord -c /etc/supervisord.conf &
suppid="$!"

function run_startup_scripts {
  until grep -q '^Ready.' ${LOG_DIR}/localstack_infra.log >/dev/null 2>&1 ; do
    echo "Waiting for all LocalStack services to be ready"
    sleep 7
  done

  curl -XPUT -s -H "Content-Type: application/json" -d '{"features:initScripts":"initializing"}' "http://localhost:$EDGE_PORT/_localstack/health" > /dev/null
  for f in $INIT_SCRIPTS_PATH/*; do
    case "$f" in
      *.sh)     echo "$0: running $f"; . "$f" ;;
      *)        echo "$0: ignoring $f" ;;
    esac
    echo
  done
  curl -XPUT -s -H "Content-Type: application/json" -d '{"features:initScripts":"initialized"}' "http://localhost:$EDGE_PORT/_localstack/health" > /dev/null
}

run_startup_scripts &

# Run tail on the localstack log files forever until we are told to terminate
if [ "$DISABLE_TERM_HANDLER" == "" ]; then
  while true; do
    tail -qF ${LOG_DIR}/localstack_infra.log ${LOG_DIR}/localstack_infra.err & wait ${!}
  done
else
  tail -qF ${LOG_DIR}/localstack_infra.log ${LOG_DIR}/localstack_infra.err
fi
