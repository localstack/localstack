import contextlib

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.validated
def test_create_list_delete_bucket(aws_client, region_name, snapshot, s3_empty_bucket):
    # transformers for dynamic values
    snapshot.add_transformer(snapshot.transform.key_value("Name"))
    snapshot.add_transformer(snapshot.transform.key_value("Location"))
    snapshot.add_transformer(snapshot.transform.key_value("x-amz-id-2"))
    snapshot.add_transformer(snapshot.transform.key_value("x-amz-request-id"))
    snapshot.add_transformer(snapshot.transform.key_value("date"))
    snapshot.add_transformer(
        snapshot.transform.jsonpath(
            jsonpath="$..Location", value_replacement="<location>", reference_replacement=False
        )
    )

    bucket_name = f"test-bucket-{short_uid()}"

    create_kwargs: dict[str, object] = {"Bucket": bucket_name}
    if region_name != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region_name}

    delete_attempted = False

    try:
        # create bucket
        create_resp = aws_client.s3.create_bucket(**create_kwargs)
        snapshot.match("create_response", create_resp)

        # list objects (should be empty)
        list_resp = aws_client.s3.list_objects_v2(Bucket=bucket_name)
        snapshot.match("list_objects_v2_empty", list_resp)

        # delete bucket
        delete_resp = aws_client.s3.delete_bucket(Bucket=bucket_name)
        delete_attempted = True
        snapshot.match("delete_response", delete_resp)
    finally:
        # best-effort cleanup in case the test fails before deletion
        if not delete_attempted:
            with contextlib.suppress(Exception):
                s3_empty_bucket(bucket_name)
                aws_client.s3.delete_bucket(Bucket=bucket_name)
