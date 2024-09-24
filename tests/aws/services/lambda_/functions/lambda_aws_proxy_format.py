import json


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(json.dumps(event))
    if event["path"] == "/no-body":
        return {"statusCode": 200}
    elif event["path"] == "/only-headers":
        return {"statusCode": 200, "headers": {"test-header": "value"}}
    elif event["path"] == "/wrong-format":
        return {"statusCode": 200, "wrongValue": "value"}

    elif event["path"] == "/empty-response":
        return {}

    else:
        return {
            "statusCode": 200,
            "body": json.dumps(event),
            "isBase64Encoded": False,
        }
