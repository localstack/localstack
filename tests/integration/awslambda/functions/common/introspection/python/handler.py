import json
import os


def handler(event, ctx):
    print(json.dumps(event))
    return {
        "environment": dict(os.environ),
        "ctx": "tbd",
        "packages": [],
    }
