import os
import time

sleep_duration = int(os.getenv("TEST_SLEEP_S", "0"))


def handler(event, context):
    print(f"sleeping for {sleep_duration}")
    time.sleep(sleep_duration)
    print("done sleeping")
    return {"status": "ok"}
