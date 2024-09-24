import json
import os

import boto3

# TODO - merge this file with lambda_send_message.py, to avoid duplication


def handler(event, context):
    endpoint_url = None
    if os.environ.get("AWS_ENDPOINT_URL"):
        endpoint_url = os.environ["AWS_ENDPOINT_URL"]
    sf = boto3.client(
        "stepfunctions",
        endpoint_url=endpoint_url,
        region_name=event["region_name"],
        verify=False,
    )

    sf.start_execution(stateMachineArn=event["state_machine_arn"], input=json.dumps(event["input"]))

    return 0
