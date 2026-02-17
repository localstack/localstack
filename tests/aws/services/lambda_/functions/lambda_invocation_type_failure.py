import os
import time

init_type = os.environ["AWS_LAMBDA_INITIALIZATION_TYPE"]

if init_type == "provisioned-concurrency":
    raise Exception("Intentional failure upon provisioned concurrency initialization")


def handler(event, context):
    if event.get("wait"):
        time.sleep(event["wait"])
    print(f"{init_type=}")
    return init_type
