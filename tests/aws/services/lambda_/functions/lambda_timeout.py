import logging
import time


def handler(event, context):
    try:
        print("starting wait")
        time.sleep(event["wait"])
        print("done waiting")
    except Exception as e:
        print("exception while waiting")
        logging.error(e)
