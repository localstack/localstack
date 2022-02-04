import os

import boto3

EDGE_PORT = 4566


def handler(event, context):
    protocol = "https" if os.environ.get("USE_SSL") else "http"
    endpoint_url = "{}://{}:{}".format(protocol, os.environ["LOCALSTACK_HOSTNAME"], EDGE_PORT)
    sqs = boto3.client(
        "sqs", endpoint_url=endpoint_url, region_name=event["region_name"], verify=False
    )

    queue_url = sqs.get_queue_url(QueueName=event["queue_name"])["QueueUrl"]
    rs = sqs.send_message(QueueUrl=queue_url, MessageBody=event["message"])

    return rs["MessageId"]
