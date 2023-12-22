import os

import boto3

s3 = boto3.client("s3", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))
BUCKET_NAME = os.environ["S3_BUCKET_NAME"]


def handler(event, context):
    file_size_bytes = event.get("file_size_bytes", 1)
    file_name = "/tmp/outfile"
    with open(file_name, "wb") as out:
        out.write(os.urandom(file_size_bytes))

    s3_key = context.aws_request_id
    s3.upload_file(file_name, BUCKET_NAME, s3_key)
    return {"s3_key": s3_key}
