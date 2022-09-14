import os

import boto3

EDGE_PORT = 4566


def handler(event, context):
    endpoint_url = None
    if os.environ.get("LOCALSTACK_HOSTNAME"):
        protocol = "https" if os.environ.get("USE_SSL") else "http"
        endpoint_url = "{}://{}:{}".format(protocol, os.environ["LOCALSTACK_HOSTNAME"], EDGE_PORT)
    s3 = boto3.client("s3", endpoint_url=endpoint_url, verify=False)
    s3.download_file(
        os.environ["BUCKET_NAME"],
        os.environ["OBJECT_NAME"],
        os.environ["LOCAL_FILE_NAME"],
    )
    print("success")
    return
