#!/bin/bash

set -eo pipefail
shopt -s nullglob

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
fi

# Strip `LOCALSTACK_` prefix in environment variables name (except LOCALSTACK_HOST)
source <(
  env |
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
