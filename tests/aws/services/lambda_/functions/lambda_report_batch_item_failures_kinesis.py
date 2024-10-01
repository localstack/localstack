# For DynamoDB Streams and Kinesis:
# If the batchItemFailures array contains multiple items, Lambda uses the record with the lowest sequence number as the checkpoint.
# Lambda then retries all records starting from that checkpoint.

import base64
import json


def handler(event, context):
    batch_item_failures = []
    print(json.dumps(event))

    for record in event.get("Records", []):
        payload = json.loads(base64.b64decode(record["kinesis"]["data"]))

        # If multiple items, the lowest sequence number is selected
        if payload.get("should_fail", False):
            batch_item_failures.append({"itemIdentifier": record["kinesis"]["sequenceNumber"]})

    return {"batchItemFailures": batch_item_failures}
