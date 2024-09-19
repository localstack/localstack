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
    print(f"Received event: {json.dumps(event)}")

    response_body = {
        "message": "Hello from Lambda!",
        "input": event
    }
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(response_body)
    }
