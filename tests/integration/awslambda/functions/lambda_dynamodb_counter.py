import os
import time

import boto3


def create_client():
    if "LOCALSTACK_HOSTNAME" in os.environ:
        endpoint_url = "{}://{}:{}".format("http", os.environ["LOCALSTACK_HOSTNAME"], 4566)
        return boto3.client("dynamodb", endpoint_url=endpoint_url)
    else:
        return boto3.client("dynamodb")


dynamodb_client = create_client()
table_name = os.environ["TABLE_NAME"]
wait_s = int(os.environ["TEST_WAIT_TIME_S"])


def handler(event, context):
    dynamodb_client.update_item(
        TableName=table_name,
        Key={"Id": {"S": "testcountid"}},
        UpdateExpression="SET TestCounterStart = TestCounterStart + :incr",
        ExpressionAttributeValues={":incr": {"N": "1"}},
        ReturnValues="ALL_NEW",
    )

    print(f"Sleeping for {wait_s} seconds.")
    time.sleep(wait_s)

    update_response = dynamodb_client.update_item(
        TableName=table_name,
        Key={"Id": {"S": "testcountid"}},
        UpdateExpression="SET TestCounterStop = TestCounterStop + :incr",
        ExpressionAttributeValues={":incr": {"N": "1"}},
        ReturnValues="ALL_NEW",
    )

    return update_response["Attributes"]
