# For DynamoDB Streams and Kinesis:
# If the batchItemFailures array contains multiple items, Lambda uses the record with the lowest sequence number as the checkpoint.
# Lambda then retries all records starting from that checkpoint.

import json


def handler(event, context):
    batch_item_failures = []
    print(json.dumps(event))

    for record in event.get("Records", []):
        new_image = record["dynamodb"].get("NewImage", {})

        # If multiple items, the lowest sequence number is selected
        if new_image.get("should_fail", {}).get("BOOL", False):
            batch_item_failures.append({"itemIdentifier": record["dynamodb"]["SequenceNumber"]})

    return {"batchItemFailures": batch_item_failures}
