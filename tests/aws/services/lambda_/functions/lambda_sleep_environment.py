import os
import time


def handler(event, context):
    if event.get("sleep"):
        time.sleep(event.get("sleep"))
    return {"environment": dict(os.environ)}
