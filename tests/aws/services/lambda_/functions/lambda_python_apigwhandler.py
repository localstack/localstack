import json


def handler(event, context):
    return {
        "isBase64Encoded": False,
        "headers": {},
        "body": json.dumps({"test": "hello world"}),
        "statusCode": 200,
    }
