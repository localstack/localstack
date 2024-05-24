import json
import os
import time

import boto3

s3 = boto3.client("s3", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
# Configurable identifier to test function updates
FUNCTION_VARIANT = os.environ.get("FUNCTION_VARIANT")


def handler(event, context):
    sleep_duration = int(event.get("sleep_seconds", 0))
    if sleep_duration > 0:
        print(f"Sleeping for {sleep_duration} seconds ...")
        time.sleep(sleep_duration)
        print("... done sleeping")

    request_prefix = event.get("request_prefix")
    response = {
        "function_version": context.function_version,
        "request_id": context.aws_request_id,
        "request_prefix": request_prefix,
        "function_variant": FUNCTION_VARIANT,
    }

    # The side effect is required to test async invokes
    if S3_BUCKET_NAME:
        s3_key = f"{request_prefix}--{FUNCTION_VARIANT}"
        response["s3_key"] = s3_key
        s3.put_object(Bucket=S3_BUCKET_NAME, Key=s3_key, Body=json.dumps(response))

    return response
