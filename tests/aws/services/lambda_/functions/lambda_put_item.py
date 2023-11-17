import os

import boto3

# TODO - merge this file with lambda_send_message.py, to avoid duplication


def handler(event, context):
    endpoint_url = None
    if os.environ.get("AWS_ENDPOINT_URL"):
        endpoint_url = os.environ["AWS_ENDPOINT_URL"]
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
