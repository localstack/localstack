import json


def handler(event, context):
    # Just print the event thar was passed to the Lambda
    print(json.dumps(event))
    return event
