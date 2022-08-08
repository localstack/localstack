"""This lambda is used for lambda/sqs integration tests. Since SQS event source mappings don't allow
DestinationConfigurations that send lambda results to other source (like SQS queues), that can be used to verify
invocations, this lambda does this manually. You can pass in an event that looks like this::

    {
        "destination": "<queue_url>",
        "fail_attempts": 2
    }

Which will cause the lambda to fail twice (comparing the "ApproximateReceiveCount" of the SQS event triggering
the lambda), and send either an error or success result to the SQS queue passed in the destination key.
"""
import json
import os

import boto3


def handler(event, context):
    # this lambda expects inputs from an SQS event source mapping
    if len(event.get("Records", [])) != 1:
        raise ValueError("the payload must consist of exactly one record")

    # it expects exactly one record where the message body is '{"destination": "<queue_url>"}' that mimics a
    # DestinationConfig (which is not possible with SQS event source mappings).
    record = event["Records"][0]
    message = json.loads(record["body"])

    if not message.get("destination"):
        raise ValueError("no destination for the event given")

    error = None
    try:
        if message["fail_attempts"] >= int(record["attributes"]["ApproximateReceiveCount"]):
            raise ValueError("failed attempt")
    except Exception as e:
        error = e
        raise
    finally:
        # we then send a message to the destination queue
        result = {"error": None if not error else str(error), "event": event}
        sqs = create_external_boto_client("sqs")
        sqs.send_message(QueueUrl=message.get("destination"), MessageBody=json.dumps(result))


def create_external_boto_client(service):
    endpoint_url = None
    if os.environ.get("LOCALSTACK_HOSTNAME"):
        endpoint_url = (
            f"http://{os.environ['LOCALSTACK_HOSTNAME']}:{os.environ.get('EDGE_PORT', 4566)}"
        )
    return boto3.client(service, endpoint_url=endpoint_url)
