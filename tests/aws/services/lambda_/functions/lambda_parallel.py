import json
import time


def handler(event, context):
    result = {"executionStart": time.time(), "event": event}
    time.sleep(5)
    # Just print the event was passed to lambda
    print(json.dumps(result))
    return result
