#!/bin/bash

set -eo pipefail
shopt -s nullglob

if [ -z $LOCALSTACK_AUTH_TOKEN ]; then
    echo "WARNING"
    echo "================================================================================"
    echo "  You are starting the LocalStack Community Docker image."
    echo "  We move towards a unified LocalStack for AWS image in March 2026."
    echo "  Go to this page for more infos: https://localstack.cloud/2026-updates"
    echo "================================================================================"
    echo ""
fi

# When trying to activate pro features in the community version, raise a warning
if [[ -n $LOCALSTACK_API_KEY || -n $LOCALSTACK_AUTH_TOKEN ]]; then
    echo "WARNING"
    echo "================================================================================"
    echo "  It seems you are trying to use the LocalStack Pro version without using the"
    echo "  dedicated Pro image."
    echo "  LocalStack will only start with community services enabled."
    echo "  To fix this warning, use localstack/localstack-pro instead."
    echo ""
    echo "  See: https://github.com/localstack/localstack/issues/7882"
    echo "================================================================================"
    echo ""
fi

# Strip `LOCALSTACK_` prefix in environment variables name; except LOCALSTACK_HOST and LOCALSTACK_HOSTNAME (deprecated)
source <(
  env |
  grep -v -e '^LOCALSTACK_HOSTNAME' |
  grep -v -e '^LOCALSTACK_HOST' |
  grep -v -e '^LOCALSTACK_[[:digit:]]' | # See issue #1387
  sed -ne 's/^LOCALSTACK_\([^=]\+\)=.*/export \1=${LOCALSTACK_\1}/p'
)

LOG_DIR=/var/lib/localstack/logs
test -d ${LOG_DIR} || mkdir -p ${LOG_DIR}

# activate the virtual environment
source /opt/code/localstack/.venv/bin/activate

# run runtime init hooks BOOT stage before starting localstack
test -d /etc/localstack/init/boot.d && python3 -m localstack.runtime.init BOOT

# run the localstack supervisor. it's important to run with `exec` and don't use pipes so signals are handled correctly
exec localstack-supervisor
