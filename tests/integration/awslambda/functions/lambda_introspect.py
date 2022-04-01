import os
import time


def handler(event, context):

    if event.get("wait"):
        time.sleep(event["wait"])

    return {
        "env": {k: v for k, v in os.environ.items()},
        "event": event,
    }
