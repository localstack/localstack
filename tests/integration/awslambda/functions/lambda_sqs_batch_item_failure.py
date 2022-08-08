"""This lambda is used for lambda/sqs integration tests. Since SQS event source mappings don't allow
DestinationConfigurations that send lambda results to other source (like SQS queues), that can be used to verify
invocations, this lambda does this manually. You can pass in an event that looks like this::

    {
        "destination": "<queue_url>",
        "fail_attempts": 2
    }

Which will cause the lambda to mark that record as failure twice (comparing the "ApproximateReceiveCount" of the SQS
event triggering the lambda). The lambda returns a batchItemFailures list that contains every failed record. All
other records are sent to the destination queue as successfully processed."""
import json
import os

import boto3


def handler(event, context):
    sqs = create_external_boto_client("sqs")

    print("incoming event:")
    print(json.dumps(event))

    # this lambda expects inputs from an SQS event source mapping
    if not event.get("Records"):
        raise ValueError("no records passed to event")

    batch_item_failures_ids = []

    for record in event["Records"]:
        message = json.loads(record["body"])

        if message.get("fail_attempts") is None:
            raise ValueError("no fail_attempts for the event given")

        if message["fail_attempts"] >= int(record["attributes"]["ApproximateReceiveCount"]):
            batch_item_failures_ids.append(record["messageId"])

    result = {
        "batchItemFailures": [
            {"itemIdentifier": message_id} for message_id in batch_item_failures_ids
        ]
    }

    destination_queue_url = os.environ.get("DESTINATION_QUEUE_URL")
    if destination_queue_url:
        sqs.send_message(
            QueueUrl=destination_queue_url,
            MessageBody=json.dumps({"event": event, "result": result}),
        )

    return result


def create_external_boto_client(service):
    endpoint_url = None
    if os.environ.get("LOCALSTACK_HOSTNAME"):
        endpoint_url = (
            f"http://{os.environ['LOCALSTACK_HOSTNAME']}:{os.environ.get('EDGE_PORT', 4566)}"
        )
    region_name = (
        os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
    )
    return boto3.client(service, endpoint_url=endpoint_url, region_name=region_name)
