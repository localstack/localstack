import json


def handler(event, ctx):
    print(json.dumps(event))
    return event
