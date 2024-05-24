"""Test utils for Lambda."""

from localstack.aws.connect import ServiceLevelClientFactory


def get_s3_keys(aws_client: ServiceLevelClientFactory, s3_bucket: str) -> list[str]:
    s3_keys_output = []
    paginator = aws_client.s3.get_paginator("list_objects_v2")
    page_iterator = paginator.paginate(Bucket=s3_bucket)
    for page in page_iterator:
        for obj in page.get("Contents", []):
            s3_keys_output.append(obj["Key"])
    return s3_keys_output
