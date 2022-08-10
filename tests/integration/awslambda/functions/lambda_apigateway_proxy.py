import json


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(json.dumps(event))
    # return the event so we can make assertions about it
    return {"statusCode": 200, "headers": {}, "isBase64Encoded": False, "body": json.dumps(event)}
