import datetime
import json
import os
import time

import boto3

SQS_QUEUE_URL = os.environ["SQS_QUEUE_URL"]
sqs_client = boto3.client("sqs", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))


def handler(event, context):
    if event.get("notify", True):
        message = {
            "request_id": context.aws_request_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        print(f"Notify message: {message}")
        sqs_client.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=json.dumps(message))

    if wait_time := event.get("wait"):
        print(f"Sleeping for {wait_time} seconds ...")
        time.sleep(wait_time)
