import json
import os
import tempfile

import boto3

s3 = boto3.client("s3", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))
BUCKET_NAME = os.environ["S3_BUCKET_NAME"]


def handler(event, context):
    s3_key = context.aws_request_id
    file_size_bytes = event.get("file_size_bytes")
    if file_size_bytes is not None:
        # Upload random file if file_size_bytes is present in the event
        with tempfile.SpooledTemporaryFile() as tmpfile:
            tmpfile.write(os.urandom(file_size_bytes))
            s3.upload_fileobj(tmpfile, BUCKET_NAME, s3_key)
    else:
        # Upload the event otherwise
        s3.put_object(Bucket=BUCKET_NAME, Key=s3_key, Body=json.dumps(event))

    function_version = os.environ["AWS_LAMBDA_FUNCTION_VERSION"]
    return {"s3_key": s3_key, "function_version": function_version}
