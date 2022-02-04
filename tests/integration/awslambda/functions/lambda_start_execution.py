import json
import os

import boto3

# TODO - merge this file with lambda_send_message.py, to avoid duplication

EDGE_PORT = 4566


def handler(event, context):
    protocol = "https" if os.environ.get("USE_SSL") else "http"
    endpoint_url = "{}://{}:{}".format(protocol, os.environ["LOCALSTACK_HOSTNAME"], EDGE_PORT)
    sf = boto3.client(
        "stepfunctions",
        endpoint_url=endpoint_url,
        region_name=event["region_name"],
        verify=False,
    )

    sf.start_execution(stateMachineArn=event["state_machine_arn"], input=json.dumps(event["input"]))

    return 0
