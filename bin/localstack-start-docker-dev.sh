#!/usr/bin/env bash

source ${VENV_DIR=.venv}/bin/activate

export LOCALSTACK_VOLUME_DIR=$(pwd)/.filesystem/var/lib/localstack
export DOCKER_FLAGS="${DOCKER_FLAGS}
-v $(pwd)/localstack:/opt/code/localstack/localstack
-v $(pwd)/localstack_core.egg-info:/opt/code/localstack/localstack_core.egg-info
-v $(pwd)/.filesystem/etc/localstack:/etc/localstack
-v $(pwd)/bin/localstack-supervisor:/opt/code/localstack/bin/localstack-supervisor
-v $(pwd)/bin/docker-entrypoint.sh:/usr/local/bin/docker-entrypoint.sh"

exec python -m localstack.cli.main start "$@"
