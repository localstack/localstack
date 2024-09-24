import os

import boto3


def handler(event, context):
    aws_endpoint_url = os.environ.get("AWS_ENDPOINT_URL")
    if aws_endpoint_url:
        sts_client = boto3.client("sts", endpoint_url=aws_endpoint_url)
    else:
        sts_client = boto3.client("sts")

    return sts_client.get_caller_identity()
