import json
import os
import uuid
from datetime import datetime, timezone

import boto3
import pytest
from moto import mock_cloudtrail, mock_s3
from mypy_boto3_s3 import S3Client


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
@pytest.mark.usefixtures("aws_credentials")
def s3_client():
    with mock_s3():
        yield boto3.client("s3", region_name="us-east-1")


@pytest.fixture
@pytest.mark.usefixtures("aws_credentials")
def cloudtrail_client():
    with mock_cloudtrail():
        yield boto3.client("cloudtrail", region_name="us-east-1")


def short_uid():
    return str(uuid.uuid4())[:8]


@pytest.fixture
def s3_bucket(s3_client: S3Client, monkeypatch):
    bucket_name = f"bucket-{short_uid()}"
    monkeypatch.setenv("BUCKET", bucket_name)
    s3_client.create_bucket(Bucket=bucket_name)
    return bucket_name


def test_save_to_s3(s3_bucket, s3_client: S3Client):
    import sys

    sys.path.insert(0, "cloudtrail_tracking/handler")
    from index import compute_s3_key, save_to_s3

    event = {
        "test_name": "foobar",
        "role_arn": "role-arn",
        "start_time": datetime(2023, 1, 1, tzinfo=timezone.utc).isoformat(),
        "end_time": datetime(2023, 1, 2, tzinfo=timezone.utc).isoformat(),
    }

    s3_key = compute_s3_key(event["test_name"], event["start_time"])
    assert s3_key == "foobar/2023-01-01T00:00:00+00:00/events.json"

    save_to_s3([{"foo": "bar"}], s3_key)

    res = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
    events = json.load(res["Body"])
    assert events == [{"foo": "bar"}]


@pytest.mark.skip(reason="cloudtrail is not implemented in moto")
def test_handler(s3_bucket, cloudtrail_client):
    import sys

    sys.path.insert(0, "lib/handler")
    from index import handler

    event = {
        "test_name": "foobar",
        "role_arn": "role-arn",
        "start_time": datetime(2023, 1, 1, tzinfo=timezone.utc).isoformat(),
        "end_time": datetime(2023, 1, 2, tzinfo=timezone.utc).isoformat(),
    }
    context = {}

    handler(event, context)
