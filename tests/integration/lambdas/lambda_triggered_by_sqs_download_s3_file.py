import os

import boto3

EDGE_PORT = 4566


def handler(event, context):
    protocol = "https" if os.environ.get("USE_SSL") else "http"
    endpoint_url = "{}://{}:{}".format(protocol, os.environ["LOCALSTACK_HOSTNAME"], EDGE_PORT)
    s3 = boto3.client("s3", endpoint_url=endpoint_url, region_name="us-east-1", verify=False)
    s3.download_file(
        os.environ["BUCKET_NAME"],
        os.environ["OBJECT_NAME"],
        os.environ["LOCAL_FILE_NAME"],
    )
    print("success")
    return
