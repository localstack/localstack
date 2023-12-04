import os

import boto3


def handler(event, context):
    endpoint_url = None
    if os.environ.get("AWS_ENDPOINT_URL"):
        endpoint_url = os.environ["AWS_ENDPOINT_URL"]
    s3 = boto3.client("s3", endpoint_url=endpoint_url, verify=False)
    s3.download_file(
        os.environ["BUCKET_NAME"],
        os.environ["OBJECT_NAME"],
        os.environ["LOCAL_FILE_NAME"],
    )
    print("success")
    return
