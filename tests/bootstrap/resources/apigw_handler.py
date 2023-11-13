import json
import os
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from mypy_boto3_sns import SNSClient


client: "SNSClient" = boto3.client("sns", endpoint_url=os.environ["AWS_ENDPOINT_URL"])

TOPIC_ARN = os.environ["TOPIC_ARN"]


def handler(event, context):
    print(f"API Gateway handler {context.function_name} invoked ({event=})")

    message = json.loads(event["body"])

    try:
        client.publish(
            TopicArn=TOPIC_ARN,
            Message=json.dumps(message),
        )
        print("Publish successful")
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": json.dumps(
                {
                    "status": "ok",
                }
            ),
        }
    except Exception as e:
        return {
            "isBase64Encoded": False,
            "statusCode": 500,
            "headers": {},
            "body": json.dumps(
                {
                    "status": "error",
                    "error": str(e),
                }
            ),
        }
