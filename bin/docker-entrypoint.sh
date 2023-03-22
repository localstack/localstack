#!/bin/bash

set -eo pipefail
shopt -s nullglob
if [[ ! $EDGE_PORT ]]
then
  EDGE_PORT=4566
fi

# the Dockerfile creates .pro-version file for the pro image and .bigdata-pro-version for the bigdata image.
# When trying to activate pro features with any other version, a warning is printed.
if [[ $LOCALSTACK_API_KEY ]] && ! compgen -G /usr/lib/localstack/.*pro-version >/dev/null; then
    echo "WARNING"
    echo "============================================================================"
    echo "  It seems you are trying to use the LocalStack Pro version without using "
    echo "  the dedicated Pro image."
    echo "  LocalStack will only start with community services enabled."
    echo "  To fix this warning, use localstack/localstack-pro instead."
    echo ""
    echo "  See: https://github.com/localstack/localstack/issues/7882"
    echo "============================================================================"
    echo ""
elif [[ -f /usr/lib/localstack/.light-version ]] || [[ -f /usr/lib/localstack/.full-version ]]; then
    echo "WARNING"
    echo "============================================================================"
    echo "  It seems you are using a deprecated image (localstack/localstack-light"
    echo "  or localstack/localstack-full)."
    echo "  These images are deprecated and will be removed in the future."
    echo "  To fix this warning, use localstack/localstack instead."
    echo ""
    echo "  See: https://github.com/localstack/localstack/issues/7257"
    echo "============================================================================"
    echo ""
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

# run modern runtime init scripts before starting localstack
test -d /etc/localstack/init/boot.d && /opt/code/localstack/.venv/bin/python -m localstack.runtime.init BOOT

# TODO: maybe we can simplify this by making supervisord block the main process?
supervisord -c /etc/supervisord.conf &
suppid="$!"

# Run tail on the localstack log files forever until we are told to terminate
if [ "$DISABLE_TERM_HANDLER" == "" ]; then
  while true; do
    tail -qF ${LOG_DIR}/localstack_infra.log ${LOG_DIR}/localstack_infra.err & wait ${!}
  done
else
  tail -qF ${LOG_DIR}/localstack_infra.log ${LOG_DIR}/localstack_infra.err
fi
