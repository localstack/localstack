#!/bin/bash
set -euo pipefail

mkdir -p /tmp/localstack
rm -rf /tmp/localstack/*.lock

source .venv/bin/activate
SQS_DISABLE_CLOUDWATCH_METRICS=1 PROVIDER_OVERRIDE_DYNAMODBSTREAMS=v2 DYNAMODB_IN_MEMORY=1 DYNAMODB_LOCAL_PORT=31456 python -m gunicorn --bind 0.0.0.0:4566 -w 10 --threads=10 'localstack.aws.serving.granian:create_app()'
