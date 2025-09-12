import contextlib
import hashlib

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.fixture
def create_bucket(aws_client):
    buckets: list[str] = []

    def _create_bucket(**kwargs):
        if "Bucket" not in kwargs:
            kwargs["Bucket"] = f"test-bucket-{short_uid()}"
        if (
            "CreateBucketConfiguration" not in kwargs
            and aws_client.s3.meta.region_name != "us-east-1"
        ):
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": aws_client.s3.meta.region_name
            }
        response = aws_client.s3.create_bucket(**kwargs)
        buckets.append(kwargs["Bucket"])
        return response

    yield _create_bucket

    for bucket in reversed(buckets):
        # best-effort cleanup
        with contextlib.suppress(Exception):
            extra = {}
            try:
                aws_client.s3.get_object_lock_configuration(Bucket=bucket)
                extra["BypassGovernanceRetention"] = True
            except Exception:
                pass
            try:
                resp = aws_client.s3.list_objects_v2(Bucket=bucket)
                objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
                if objs:
                    aws_client.s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}, **extra)
            except Exception:
                pass
            try:
                resp = aws_client.s3.list_object_versions(Bucket=bucket)
                versions = resp.get("Versions", [])
                versions.extend(resp.get("DeleteMarkers", []))
                ov = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions]
                if ov:
                    aws_client.s3.delete_objects(Bucket=bucket, Delete={"Objects": ov}, **extra)
            except Exception:
                pass
            with contextlib.suppress(Exception):
                aws_client.s3.delete_bucket(Bucket=bucket)


@markers.aws.validated
def test_create_list_delete_bucket(aws_client, region_name, snapshot, create_bucket):
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

    # create bucket using fixture factory to ensure cleanup; capture response
    create_resp = create_bucket(**create_kwargs)
    snapshot.match("create_response", create_resp)

    # list objects (should be empty)
    list_resp = aws_client.s3.list_objects_v2(Bucket=bucket_name)
    snapshot.match("list_objects_v2_empty", list_resp)

    # delete bucket and snapshot response
    delete_resp = aws_client.s3.delete_bucket(Bucket=bucket_name)
    snapshot.match("delete_response", delete_resp)


@markers.aws.validated
def test_put_and_get_object_md5(aws_client, snapshot, create_bucket):
    snapshot.add_transformer(snapshot.transform.key_value("x-amz-id-2"))
    snapshot.add_transformer(snapshot.transform.key_value("x-amz-request-id"))
    snapshot.add_transformer(snapshot.transform.key_value("date"))

    bucket_name = f"test-bucket-{short_uid()}"
    object_key = f"obj-{short_uid()}"
    content = b"hello-localstack-s3-put-object"
    uploaded_md5 = hashlib.md5(content).hexdigest()

    create_bucket(Bucket=bucket_name)

    put_resp = aws_client.s3.put_object(Bucket=bucket_name, Key=object_key, Body=content)
    snapshot.match("put_object_response", put_resp)

    get_resp = aws_client.s3.get_object(Bucket=bucket_name, Key=object_key)
    body = get_resp["Body"].read()
    downloaded_md5 = hashlib.md5(body).hexdigest()

    assert downloaded_md5 == uploaded_md5

    meta = dict(get_resp)
    meta.pop("Body", None)
    snapshot.match("get_object_response_meta", meta)
