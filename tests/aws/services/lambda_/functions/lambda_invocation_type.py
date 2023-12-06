import os
import time


def handler(event, context):
    if event.get("wait"):
        time.sleep(event["wait"])
    init_type = os.environ["AWS_LAMBDA_INITIALIZATION_TYPE"]
    print(f"{init_type=}")
    return init_type
