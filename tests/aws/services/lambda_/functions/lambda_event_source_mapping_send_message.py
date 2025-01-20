import json
import os

import boto3


def handler(event, context):
    endpoint_url = os.environ.get("AWS_ENDPOINT_URL")

    region_name = (
        os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
    )

    sqs = boto3.client("sqs", endpoint_url=endpoint_url, verify=False, region_name=region_name)

    queue_url = os.environ.get("SQS_QUEUE_URL")

    records = event.get("Records", [])
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(records))

    return {"count": len(records)}
