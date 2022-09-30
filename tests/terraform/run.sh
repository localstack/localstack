#!/bin/bash
set -euo pipefail

export TF_ACC=1
export TF_LOG=DEBUG
export TF_LOG_CORE=DEBUG
export TF_LOG_PROVIDER=DEBUG

export AWS_ALTERNATE_ACCESS_KEY_ID=test
export AWS_ALTERNATE_SECRET_ACCESS_KEY=test
export AWS_ALTERNATE_REGION=us-east-2
export AWS_DEFAULT_REGION=eu-west-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# in some services we can only create certain endpoints before quota updation
# so we need restrict no of tests that can run in parallel
PARALLELISM_MAPPING=( "route53resolver:4")
# example to extend the mapping:
# PARALLELISM_MAPPING=( "route53resolver:4"
#         "s3:2"
#         "ec2:10" )

PARALLEL=0
for service in "${PARALLELISM_MAPPING[@]}" ; do
    KEY="${service%%:*}"
    if [ $KEY == $1 ]; then
        VALUE="${service##*:}"
        PARALLEL=1
    fi
done

cd terraform-provider-aws

LOGS_DIR=`pwd`/terraformlogs
mkdir -p "${LOGS_DIR}"
export TF_LOG_PATH_MASK="${LOGS_DIR}/%s.log"

if [ $# == 2 ]; then
    echo "Service: $1 | Test: $2"
    if [ $PARALLEL == 1 ]; then
        echo "Parallelism: $VALUE"
        go test ./internal/service/$1 -test.count 1 -test.v -test.timeout 60m -parallel $VALUE -run $2
    else
        echo "Parallelism: Auto"
        go test ./internal/service/$1 -test.count 1 -test.v -test.timeout 60m -run $2
    fi
elif [ $# == 1 ]; then
    echo "Service: $1 | Test: All"
    if [ $PARALLEL == 1 ]; then
        echo "Parallelism: $VALUE"
        go test ./internal/service/$1 -test.count 1 -test.v -test.timeout 60m -parallel $VALUE
    else
        echo "Parallelism: Auto"
        go test ./internal/service/$1 -test.count 1 -test.v -test.timeout 60m
    fi
else
    echo "usage: ./run.sh service_name [test_case_pattern]"
    exit 1
fi

if [ $CI == "false" ]; then
    python -m http.server
fi
