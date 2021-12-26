import os

import boto3

# TODO - merge this file with lambda_send_message.py, to avoid duplication

EDGE_PORT = 4566


def handler(event, context):
    protocol = "https" if os.environ.get("USE_SSL") else "http"
    endpoint_url = "{}://{}:{}".format(protocol, os.environ["LOCALSTACK_HOSTNAME"], EDGE_PORT)
    ddb = boto3.resource(
        "dynamodb",
        endpoint_url=endpoint_url,
        region_name=event["region_name"],
        verify=False,
    )

    table_name = event["table_name"]
    table = ddb.Table(table_name)
    for item in event["items"]:
        table.put_item(Item=item)
