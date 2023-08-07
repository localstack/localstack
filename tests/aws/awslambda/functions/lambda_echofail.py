import json


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(json.dumps({"event": event, "aws_request_id": context.aws_request_id}))
    raise Exception("intentional failure")
