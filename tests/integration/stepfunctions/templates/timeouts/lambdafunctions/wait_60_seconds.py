import time


def handler(event, context):
    time.sleep(60)
    return event
