import json


def handler(event, context):
    # Just print the event was passed to lambda
    print(json.dumps(event))
    return 0
