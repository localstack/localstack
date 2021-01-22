#!/bin/bash
#
# usage: ./example/run.sh

export AWS_ACCESS_KEY_ID=fake
export AWS_SECRET_ACCESS_KEY=fake
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint http://localhost:4566 dynamodb create-table --cli-input-yaml file://example/table.yaml
aws --endpoint http://localhost:4566 dynamodb get-item --cli-input-yaml file://example/get-item.yaml
