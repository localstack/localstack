import json


def handler(event, context):
    # Just print the event that was passed to the Lambda and return nothing
    print(json.dumps(event))
    return
