"""
Interprets the body of the lambda event as a JSON document and returns it. This allows you to
dynamically simulate functions that look like::

    def handler(event, context):
        return {
           "statusCode": 201,
            "headers": {
                "Content-Type": "application/json",
                "My-Custom-Header": "Custom Value"
            },
            "body": json.dumps({
                "message": "Hello, world!"
            }),
            "isBase64Encoded": False,
        }
"""

import json


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(json.dumps(event))
    return json.loads(event["body"])
