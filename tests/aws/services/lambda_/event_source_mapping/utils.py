from localstack.config import LAMBDA_EVENT_SOURCE_MAPPING
from localstack.testing.aws.util import is_aws_cloud

# For DynamoDB Streams and Kinesis:
# If the batchItemFailures array contains multiple items, Lambda uses the record with the lowest sequence number as the checkpoint.
# Lambda then retries all records starting from that checkpoint.
LAMBDA_DYNAMODB_BATCH_ITEM_FAILURE = """
import json

def handler(event, context):
    batch_item_failures = []
    print(json.dumps(event))

    for record in event.get("Records", []):
        new_image = record["dynamodb"].get("NewImage", {})

        # Only 1 record allowed
        if new_image.get("should_fail", {}).get("BOOL", False):
            batch_item_failures.append({"itemIdentifier": record["dynamodb"]["SequenceNumber"]})

    return {"batchItemFailures": batch_item_failures}
"""


LAMBDA_KINESIS_BATCH_ITEM_FAILURE = """
import json
import base64

def handler(event, context):
    batch_item_failures = []
    print(json.dumps(event))

    for record in event.get("Records", []):
        payload = json.loads(base64.b64decode(record["kinesis"]["data"]))

        if payload.get("should_fail", False):
            batch_item_failures.append({"itemIdentifier": record["kinesis"]["sequenceNumber"]})

    return {"batchItemFailures" : batch_item_failures}
"""

_LAMBDA_WITH_RESPONSE = """
import json

def handler(event, context):
    print(json.dumps(event))
    return {response}
"""


def create_lambda_with_response(response: str) -> str:
    """Creates a lambda with pre-defined response"""
    return _LAMBDA_WITH_RESPONSE.format(response=response)


def is_v2_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v2" and not is_aws_cloud()


def is_old_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v1" and not is_aws_cloud()
