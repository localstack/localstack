import json
import os
import time

import boto3


def handler(event, context):
    endpoint_url = os.environ.get("AWS_ENDPOINT_URL")

    region_name = (
        os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
    )

    sqs = boto3.client("sqs", endpoint_url=endpoint_url, verify=False, region_name=region_name)

    queue_url = os.environ.get("SQS_QUEUE_URL")

    records = event.get("Records", [])
    if records:
        is_aws_cloud = int(os.environ.get("AWS_CLOUD", "0"))
        if (kinesis_record := records[0]) and kinesis_record["eventSource"].endswith("kinesis"):
            if kinesis_record["kinesis"]["partitionKey"] == "long_processing":
                # sleep for 120s in AWS to simulate some long processing event. Else sleep for 20s in Localstack.
                sleep = 120 if is_aws_cloud else 20
                time.sleep(sleep)

    attributes = {
        "lambda_execution_id": {"StringValue": context.aws_request_id, "DataType": "String"}
    }
    sqs.send_message(
        QueueUrl=queue_url, MessageBody=json.dumps(records), MessageAttributes=attributes
    )

    return {"count": len(records)}
