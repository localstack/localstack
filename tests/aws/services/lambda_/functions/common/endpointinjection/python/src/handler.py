import os

import boto3

sqs_client = boto3.client("sqs", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))


def handler(event, context):
    queues = sqs_client.list_queues()
    print(f"{queues=}")
    return "ok"
