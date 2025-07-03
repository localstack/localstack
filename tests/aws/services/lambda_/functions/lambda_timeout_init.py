import logging
import time

# From https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html#runtimes-lifecycle-ib
# The Init phase is limited to 10 seconds. If all three init tasks (for Extension, Runtime, Function) do not complete within 10 seconds,
# Lambda retries the Init phase at the time of the first function invocation with the configured function timeout.
time.sleep(15)


def handler(event, context):
    try:
        print("starting wait")
        time.sleep(event["wait"])
        print("done waiting")
    except Exception as e:
        print("exception while waiting")
        logging.error(e)
