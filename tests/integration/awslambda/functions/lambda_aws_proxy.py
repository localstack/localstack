import json


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(json.dumps(event))
    return {
        "statusCode": 200,
        "body": json.dumps(event),
        "isBase64Encoded": False,
    }
