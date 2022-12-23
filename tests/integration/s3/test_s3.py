import base64
import datetime
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import time
from io import BytesIO
from operator import itemgetter
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, parse_qs, quote, urlencode, urlparse, urlunsplit
from zoneinfo import ZoneInfo

import boto3 as boto3
import pytest
import requests
import xmltodict
from boto3.s3.transfer import KB, TransferConfig
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError

from localstack import config, constants
from localstack.config import LEGACY_S3_PROVIDER
from localstack.constants import (
    LOCALHOST_HOSTNAME,
    S3_VIRTUAL_HOSTNAME,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_NODEJS14X,
    LAMBDA_RUNTIME_PYTHON39,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest.fixtures import _client
from localstack.testing.snapshots.transformer_utility import TransformerUtility
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.collections import is_sub_dict
from localstack.utils.files import load_file
from localstack.utils.run import run
from localstack.utils.server import http2_server
from localstack.utils.strings import (
    checksum_crc32,
    checksum_crc32c,
    hash_sha1,
    hash_sha256,
    short_uid,
    to_bytes,
    to_str,
)
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

LOG = logging.getLogger(__name__)

# transformer list to transform headers, that will be validated for some specific s3-tests
HEADER_TRANSFORMER = [
    TransformerUtility.jsonpath("$..HTTPHeaders.date", "date", reference_replacement=False),
    TransformerUtility.jsonpath(
        "$..HTTPHeaders.last-modified", "last-modified", reference_replacement=False
    ),
    TransformerUtility.jsonpath("$..HTTPHeaders.server", "server", reference_replacement=False),
    TransformerUtility.jsonpath("$..HTTPHeaders.x-amz-id-2", "id-2", reference_replacement=False),
    TransformerUtility.jsonpath(
        "$..HTTPHeaders.x-amz-request-id", "request-id", reference_replacement=False
    ),
    TransformerUtility.key_value("HostId", reference_replacement=False),
    TransformerUtility.key_value("RequestId", reference_replacement=False),
]

S3_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

S3_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*",
            ],
            "Resource": "*",
        }
    ],
}


def is_old_provider():
    return LEGACY_S3_PROVIDER


def is_asf_provider():
    return not LEGACY_S3_PROVIDER


@pytest.fixture(scope="function")
def patch_s3_skip_signature_validation_false(monkeypatch):
    monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", False)


@pytest.fixture(scope="class")
def s3_client_for_region():
    def _s3_client(
        region_name: str = None,
    ):
        return _client("s3", region_name=region_name)

    return _s3_client


@pytest.fixture
def s3_create_bucket_with_client(s3_resource):
    buckets = []

    def factory(s3_client, **kwargs) -> str:
        if "Bucket" not in kwargs:
            kwargs["Bucket"] = f"test-bucket-{short_uid()}"

        response = s3_client.create_bucket(**kwargs)
        buckets.append(kwargs["Bucket"])
        return response

    yield factory

    # cleanup
    for bucket in buckets:
        try:
            bucket = s3_resource.Bucket(bucket)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            bucket.delete()
        except Exception as e:
            LOG.debug(f"error cleaning up bucket {bucket}: {e}")


@pytest.fixture
def s3_multipart_upload(s3_client):
    def perform_multipart_upload(bucket, key, data=None, zipped=False, acl=None, parts: int = 1):
        # beware, the last part can be under 5 MiB, but previous parts needs to be between 5MiB and 5GiB
        kwargs = {"ACL": acl} if acl else {}
        multipart_upload_dict = s3_client.create_multipart_upload(Bucket=bucket, Key=key, **kwargs)
        upload_id = multipart_upload_dict["UploadId"]
        data = data or (5 * short_uid())
        multipart_upload_parts = []
        for part in range(parts):
            # Write contents to memory rather than a file.
            part_number = part + 1

            part_data = data or (5 * short_uid())
            if part_number < parts and ((len_data := len(part_data)) < 5_242_880):
                # data must be at least 5MiB
                multiple = 5_242_880 // len_data
                part_data = part_data * (multiple + 1)

            part_data = to_bytes(part_data)
            upload_file_object = BytesIO(part_data)
            if zipped:
                upload_file_object = BytesIO()
                with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
                    filestream.write(part_data)

            response = s3_client.upload_part(
                Bucket=bucket,
                Key=key,
                Body=upload_file_object,
                PartNumber=part_number,
                UploadId=upload_id,
            )

            multipart_upload_parts.append({"ETag": response["ETag"], "PartNumber": part_number})
            # multiple parts won't work with zip, stop at one
            if zipped:
                break

        return s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

    return perform_multipart_upload


@pytest.fixture
def create_tmp_folder_lambda():
    cleanup_folders = []

    def prepare_folder(path_to_lambda, run_command=None):
        tmp_dir = tempfile.mkdtemp()
        shutil.copy(path_to_lambda, tmp_dir)
        if run_command:
            run(f"cd {tmp_dir}; {run_command}")
        cleanup_folders.append(tmp_dir)
        return tmp_dir

    yield prepare_folder

    for folder in cleanup_folders:
        try:
            shutil.rmtree(folder)
        except Exception:
            LOG.warning(f"could not delete folder {folder}")


def _filter_header(param: dict) -> dict:
    return {k: v for k, v in param.items() if k.startswith("x-amz") or k in ["content-type"]}


class TestS3:
    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER,
        reason="exceptions not raised",
    )
    def test_replication_config_without_filter(
        self, s3_client, s3_create_bucket, create_iam_role_with_policy, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..ReplicationConfiguration.Role", "role", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..Destination.Bucket", "dest-bucket", reference_replacement=False
            )
        )
        bucket_src = f"src-{short_uid()}"
        bucket_dst = f"dst-{short_uid()}"
        role_name = f"replication_role_{short_uid()}"
        policy_name = f"replication_policy_{short_uid()}"

        role_arn = create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=S3_ASSUME_ROLE_POLICY,
            PolicyDefinition=S3_POLICY,
        )
        s3_create_bucket(Bucket=bucket_src)
        # enable versioning on src
        s3_client.put_bucket_versioning(
            Bucket=bucket_src, VersioningConfiguration={"Status": "Enabled"}
        )

        s3_create_bucket(Bucket=bucket_dst)

        replication_config = {
            "Role": role_arn,
            "Rules": [
                {
                    "ID": "rtc",
                    "Priority": 0,
                    "Filter": {},
                    "Status": "Disabled",
                    "Destination": {
                        "Bucket": "arn:aws:s3:::does-not-exist",
                        "StorageClass": "STANDARD",
                        "ReplicationTime": {"Status": "Enabled", "Time": {"Minutes": 15}},
                        "Metrics": {"Status": "Enabled", "EventThreshold": {"Minutes": 15}},
                    },
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                }
            ],
        }
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_replication(
                ReplicationConfiguration=replication_config, Bucket=bucket_src
            )
        snapshot.match("expected_error_dest_does_not_exist", e.value.response)

        # set correct destination
        replication_config["Rules"][0]["Destination"]["Bucket"] = f"arn:aws:s3:::{bucket_dst}"

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_replication(
                ReplicationConfiguration=replication_config, Bucket=bucket_src
            )
        snapshot.match("expected_error_dest_versioning_disabled", e.value.response)

        # enable versioning on destination bucket
        s3_client.put_bucket_versioning(
            Bucket=bucket_dst, VersioningConfiguration={"Status": "Enabled"}
        )

        response = s3_client.put_bucket_replication(
            ReplicationConfiguration=replication_config, Bucket=bucket_src
        )
        snapshot.match("put-bucket-replication", response)

        response = s3_client.get_bucket_replication(Bucket=bucket_src)
        snapshot.match("get-bucket-replication", response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER,
        reason="exceptions not raised",
    )
    def test_replication_config(
        self, s3_client, s3_create_bucket, create_iam_role_with_policy, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..ReplicationConfiguration.Role", "role", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..Destination.Bucket", "dest-bucket", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("ID", "id", reference_replacement=False)
        )
        bucket_src = f"src-{short_uid()}"
        bucket_dst = f"dst-{short_uid()}"
        role_name = f"replication_role_{short_uid()}"
        policy_name = f"replication_policy_{short_uid()}"

        role_arn = create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=S3_ASSUME_ROLE_POLICY,
            PolicyDefinition=S3_POLICY,
        )
        s3_create_bucket(Bucket=bucket_src)

        s3_create_bucket(
            Bucket=bucket_dst, CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
        )
        s3_client.put_bucket_versioning(
            Bucket=bucket_dst, VersioningConfiguration={"Status": "Enabled"}
        )

        # expect error if versioning is disabled on src-bucket
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_replication(Bucket=bucket_src)
        snapshot.match("expected_error_no_replication_set", e.value.response)

        replication_config = {
            "Role": role_arn,
            "Rules": [
                {
                    "Status": "Enabled",
                    "Priority": 1,
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {"Prefix": "Tax"},
                    "Destination": {"Bucket": f"arn:aws:s3:::{bucket_dst}"},
                }
            ],
        }
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_replication(
                ReplicationConfiguration=replication_config, Bucket=bucket_src
            )
        snapshot.match("expected_error_versioning_not_enabled", e.value.response)

        # enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_src, VersioningConfiguration={"Status": "Enabled"}
        )

        response = s3_client.put_bucket_replication(
            ReplicationConfiguration=replication_config, Bucket=bucket_src
        )
        snapshot.match("put-bucket-replication", response)

        response = s3_client.get_bucket_replication(Bucket=bucket_src)
        snapshot.match("get-bucket-replication", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=["$..VersionId", "$..ContentLanguage", "$..BucketKeyEnabled"],
    )
    def test_copy_object_kms(self, s3_client, s3_bucket, kms_create_key, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # because of the kms-key, the etag will be different on AWS
        # FIXME there is currently no server side encryption is place and thus the etag is the same for the copied objects in LS
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..CopyObjectResult.ETag", "copy-etag", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..get-copied-object.ETag", "etag", reference_replacement=False
            )
        )
        snapshot.add_transformer(snapshot.transform.key_value("SSEKMSKeyId", "key-id"))
        key_id = kms_create_key()["KeyId"]
        body = "hello world"
        s3_client.put_object(Bucket=s3_bucket, Key="mykey", Body=body)

        response = s3_client.get_object(Bucket=s3_bucket, Key="mykey")
        snapshot.match("get-object", response)
        response = s3_client.copy_object(
            Bucket=s3_bucket,
            CopySource=f"{s3_bucket}/mykey",
            Key="copiedkey",
            BucketKeyEnabled=True,
            SSEKMSKeyId=key_id,
            ServerSideEncryption="aws:kms",
        )
        snapshot.match("copy-object", response)

        response = s3_client.get_object(Bucket=s3_bucket, Key="copiedkey")
        snapshot.match("get-copied-object", response)

    @pytest.mark.aws_validated
    def test_region_header_exists(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = s3_create_bucket(
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
        )
        response = s3_client.head_bucket(Bucket=bucket_name)
        assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-bucket-region"] == "eu-west-1"
        snapshot.match("head_bucket", response)
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-bucket-region"] == "eu-west-1"
        snapshot.match("list_objects_v2", response)

    @pytest.mark.aws_validated
    # TODO list-buckets contains other buckets when running in CI
    @pytest.mark.skip_snapshot_verify(paths=["$..Prefix", "$..list-buckets.Buckets"])
    def test_delete_bucket_with_content(self, s3_client, s3_resource, s3_bucket, snapshot):

        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = s3_bucket

        for i in range(0, 10, 1):
            body = "test-" + str(i)
            key = "test-key-" + str(i)
            s3_client.put_object(Bucket=bucket_name, Key=key, Body=body)

        resp = s3_client.list_objects(Bucket=bucket_name, MaxKeys=100)
        snapshot.match("list-objects", resp)
        assert 10 == len(resp["Contents"])

        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.all().delete()
        bucket.delete()

        resp = s3_client.list_buckets()
        # TODO - this fails in the CI pipeline and is currently skipped from verification
        snapshot.match("list-buckets", resp)
        assert bucket_name not in [b["Name"] for b in resp["Buckets"]]

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage"]
    )
    def test_put_and_get_object_with_utf8_key(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        response = s3_client.put_object(Bucket=s3_bucket, Key="Ā0Ä", Body=b"abc123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        snapshot.match("put-object", response)

        response = s3_client.get_object(Bucket=s3_bucket, Key="Ā0Ä")
        snapshot.match("get-object", response)
        assert response["Body"].read() == b"abc123"

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_asf_provider,
        paths=[
            "$..HTTPHeaders.connection",
            # TODO content-length and type is wrong, skipping for now
            "$..HTTPHeaders.content-length",  # 58, but should be 0
            "$..HTTPHeaders.content-type",  # application/xml but should not be set
        ],
    )  # for ASF we currently always set 'close'
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..HTTPHeaders.access-control-allow-origin",
            "$..HTTPHeaders.access-control-allow-headers",
            "$..HTTPHeaders.access-control-allow-methods",
            "$..HTTPHeaders.access-control-expose-headers",
            "$..HTTPHeaders.connection",
            "$..HTTPHeaders.content-md5",
            "$..HTTPHeaders.x-amz-version-id",
            "$..HTTPHeaders.x-amzn-requestid",
            "$..HostId",
            "$..VersionId",
            "$..HTTPHeaders.content-type",
            "$..HTTPHeaders.last-modified",
            "$..HTTPHeaders.location",
            "$..MaxAttemptsReached",
        ],
    )
    def test_put_and_get_object_with_content_language_disposition(
        self, s3_client, s3_bucket, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(HEADER_TRANSFORMER)

        response = s3_client.put_object(
            Bucket=s3_bucket,
            Key="test",
            Body=b"abc123",
            ContentLanguage="de",
            ContentDisposition='attachment; filename="foo.jpg"',
            CacheControl="no-cache",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        snapshot.match("put-object", response)
        snapshot.match("put-object-headers", response["ResponseMetadata"])

        response = s3_client.get_object(Bucket=s3_bucket, Key="test")
        snapshot.match("get-object", response)
        snapshot.match("get-object-headers", response["ResponseMetadata"])
        assert response["Body"].read() == b"abc123"

    @pytest.mark.aws_validated
    def test_resource_object_with_slashes_in_key(self, s3_resource, s3_bucket):
        s3_resource.Object(s3_bucket, "/foo").put(Body="foobar")
        s3_resource.Object(s3_bucket, "bar").put(Body="barfoo")
        s3_resource.Object(s3_bucket, "/bar/foo/").put(Body="test")

        with pytest.raises(ClientError) as e:
            s3_resource.Object(s3_bucket, "foo").get()
        e.match("NoSuchKey")

        with pytest.raises(ClientError) as e:
            s3_resource.Object(s3_bucket, "/bar").get()
        e.match("NoSuchKey")

        response = s3_resource.Object(s3_bucket, "/foo").get()
        assert response["Body"].read() == b"foobar"
        response = s3_resource.Object(s3_bucket, "bar").get()
        assert response["Body"].read() == b"barfoo"
        response = s3_resource.Object(s3_bucket, "/bar/foo/").get()
        assert response["Body"].read() == b"test"

    @pytest.mark.aws_validated
    def test_metadata_header_character_decoding(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # Object metadata keys should accept keys with underscores
        # https://github.com/localstack/localstack/issues/1790
        # put object
        object_key = "key-with-metadata"
        metadata = {"TEST_META_1": "foo", "__meta_2": "bar"}
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Metadata=metadata, Body="foo")
        metadata_saved = s3_client.head_object(Bucket=s3_bucket, Key=object_key)["Metadata"]
        snapshot.match("head-object", metadata_saved)

        # note that casing is removed (since headers are case-insensitive)
        assert metadata_saved == {"test_meta_1": "foo", "__meta_2": "bar"}

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage"]
    )
    def test_upload_file_multipart(self, s3_client, s3_bucket, tmpdir, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        key = "my-key"
        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html#multipart-transfers
        tranfer_config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        file = tmpdir / "test-file.bin"
        data = b"1" * (6 * KB)  # create 6 kilobytes of ones
        file.write(data=data, mode="w")
        s3_client.upload_file(
            Bucket=s3_bucket, Key=key, Filename=str(file.realpath()), Config=tranfer_config
        )

        obj = s3_client.get_object(Bucket=s3_bucket, Key=key)
        assert obj["Body"].read() == data, f"body did not contain expected data {obj}"
        snapshot.match("get_object", obj)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("delimiter", ["/", "%2F"])
    def test_list_objects_with_prefix(self, s3_client, s3_create_bucket, delimiter, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = s3_create_bucket()
        key = "test/foo/bar/123"
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=b"content 123")

        response = s3_client.list_objects(
            Bucket=bucket_name, Prefix="test/", Delimiter=delimiter, MaxKeys=1, EncodingType="url"
        )
        snapshot.match("list-objects", response)
        sub_dict = {
            "Delimiter": delimiter,
            "EncodingType": "url",
            "IsTruncated": False,
            "Marker": "",
            "MaxKeys": 1,
            "Name": bucket_name,
            "Prefix": "test/",
        }

        if delimiter == "/":
            # if delimiter is "/", then common prefixes are returned
            sub_dict["CommonPrefixes"] = [{"Prefix": "test/foo/"}]
        else:
            # if delimiter is "%2F" (or other non-contained character), then the actual keys are returned in Contents
            assert len(response["Contents"]) == 1
            assert response["Contents"][0]["Key"] == key
            sub_dict["Delimiter"] = "%252F"

        assert is_sub_dict(sub_dict, response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, path="$..Error.BucketName")
    def test_get_object_no_such_bucket(self, s3_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=f"does-not-exist-{short_uid()}", Key="foobar")

        snapshot.match("expected_error", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(path="$..RequestID")
    def test_delete_bucket_no_such_bucket(self, s3_client, snapshot):
        with pytest.raises(ClientError) as e:
            s3_client.delete_bucket(Bucket=f"does-not-exist-{short_uid()}")

        snapshot.match("expected_error", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, path="$..Error.BucketName")
    def test_get_bucket_notification_configuration_no_such_bucket(self, s3_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_notification_configuration(Bucket=f"doesnotexist-{short_uid()}")

        snapshot.match("expected_error", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER,
        reason="currently not implemented in moto, see https://github.com/localstack/localstack/issues/6217",
    )
    # parser issue in https://github.com/localstack/localstack/issues/6422 because moto returns wrong response
    # TODO test versioned KEY
    def test_get_object_attributes(self, s3_client, s3_bucket, snapshot, s3_multipart_upload):
        s3_client.put_object(Bucket=s3_bucket, Key="data.txt", Body=b"69\n420\n")
        response = s3_client.get_object_attributes(
            Bucket=s3_bucket,
            Key="data.txt",
            ObjectAttributes=["StorageClass", "ETag", "ObjectSize", "ObjectParts"],
        )
        snapshot.match("object-attrs", response)

        multipart_key = "test-get-obj-attrs-multipart"
        s3_multipart_upload(bucket=s3_bucket, key=multipart_key, data="upload-part-1" * 5)
        response = s3_client.get_object_attributes(
            Bucket=s3_bucket,
            Key=multipart_key,
            ObjectAttributes=["StorageClass", "ETag", "ObjectSize", "ObjectParts"],
        )
        snapshot.match("object-attrs-multiparts-1-part", response)

        multipart_key = "test-get-obj-attrs-multipart-2"
        s3_multipart_upload(bucket=s3_bucket, key=multipart_key, data="upload-part-1" * 5, parts=2)
        response = s3_client.get_object_attributes(
            Bucket=s3_bucket,
            Key=multipart_key,
            ObjectAttributes=["StorageClass", "ETag", "ObjectSize", "ObjectParts"],
            MaxParts=3,
        )
        snapshot.match("object-attrs-multiparts-2-parts", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..Error.RequestID"]
    )
    def test_multipart_and_list_parts(self, s3_client, s3_bucket, s3_multipart_upload, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value(
                    "ID", value_replacement="owner-id", reference_replacement=False
                ),
            ]
        )

        key_name = "test-list-parts"
        response = s3_client.create_multipart_upload(Bucket=s3_bucket, Key=key_name)
        snapshot.match("create-multipart", response)
        upload_id = response["UploadId"]

        list_part = s3_client.list_parts(Bucket=s3_bucket, Key=key_name, UploadId=upload_id)
        snapshot.match("list-part-after-created", list_part)

        # Write contents to memory rather than a file.
        data = "upload-part-1" * 5
        data = to_bytes(data)
        upload_file_object = BytesIO(data)

        response = s3_client.upload_part(
            Bucket=s3_bucket,
            Key=key_name,
            Body=upload_file_object,
            PartNumber=1,
            UploadId=upload_id,
        )
        snapshot.match("upload-part", response)
        list_part = s3_client.list_parts(Bucket=s3_bucket, Key=key_name, UploadId=upload_id)
        snapshot.match("list-part-after-upload", list_part)

        multipart_upload_parts = [{"ETag": response["ETag"], "PartNumber": 1}]

        response = s3_client.complete_multipart_upload(
            Bucket=s3_bucket,
            Key=key_name,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )
        snapshot.match("complete-multipart", response)
        with pytest.raises(ClientError) as e:
            s3_client.list_parts(Bucket=s3_bucket, Key=key_name, UploadId=upload_id)
        snapshot.match("list-part-after-complete-exc", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage"]
    )
    def test_put_and_get_object_with_hash_prefix(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        key_name = "#key-with-hash-prefix"
        content = b"test 123"
        response = s3_client.put_object(Bucket=s3_bucket, Key=key_name, Body=content)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        snapshot.match("put-object", response)

        response = s3_client.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-object", response)
        assert response["Body"].read() == content

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=["$..Error.ActualObjectSize", "$..Error.RangeRequested", "$..Error.Message"],
    )
    def test_invalid_range_error(self, s3_client, s3_bucket, snapshot):
        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")

        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1024-4096")
        snapshot.match("exc", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Error.Key", "$..Error.RequestID"])
    def test_range_key_not_exists(self, s3_client, s3_bucket, snapshot):
        key = "my-key"
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1024-4096")

        snapshot.match("exc", e.value.response)

    @pytest.mark.aws_validated
    def test_create_bucket_via_host_name(self, s3_vhost_client):
        # TODO check redirection (happens in AWS because of region name), should it happen in LS?
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingBackwardsCompatibility
        bucket_name = f"test-{short_uid()}"
        try:
            response = s3_vhost_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
            )
            assert "Location" in response
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
            response = s3_vhost_client.get_bucket_location(Bucket=bucket_name)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
            assert response["LocationConstraint"] == "eu-central-1"
        finally:
            s3_vhost_client.delete_bucket(Bucket=bucket_name)

    @pytest.mark.aws_validated
    def test_put_and_get_bucket_policy(self, s3_client, s3_bucket, snapshot):
        # just for the joke: Response syntax HTTP/1.1 200
        # sample response: HTTP/1.1 204 No Content
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
        snapshot.add_transformer(snapshot.transform.key_value("Resource"))
        # put bucket policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "s3:GetObject",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{s3_bucket}/*",
                    "Principal": {"AWS": "*"},
                }
            ],
        }
        response = s3_client.put_bucket_policy(Bucket=s3_bucket, Policy=json.dumps(policy))
        # assert response["ResponseMetadata"]["HTTPStatusCode"] == 204
        snapshot.match("put-bucket-policy", response)

        # retrieve and check policy config
        response = s3_client.get_bucket_policy(Bucket=s3_bucket)
        snapshot.match("get-bucket-policy", response)
        assert policy == json.loads(response["Policy"])

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER,
        reason="see https://github.com/localstack/localstack/issues/5769",
    )
    def test_put_object_tagging_empty_list(self, s3_client, s3_bucket, snapshot):
        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")

        object_tags = s3_client.get_object_tagging(Bucket=s3_bucket, Key=key)
        snapshot.match("created-object-tags", object_tags)

        tag_set = {"TagSet": [{"Key": "tag1", "Value": "tag1"}]}
        s3_client.put_object_tagging(Bucket=s3_bucket, Key=key, Tagging=tag_set)

        object_tags = s3_client.get_object_tagging(Bucket=s3_bucket, Key=key)
        snapshot.match("updated-object-tags", object_tags)

        s3_client.put_object_tagging(Bucket=s3_bucket, Key=key, Tagging={"TagSet": []})

        object_tags = s3_client.get_object_tagging(Bucket=s3_bucket, Key=key)
        snapshot.match("deleted-object-tags", object_tags)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER,
        reason="see https://github.com/localstack/localstack/issues/6218",
    )
    def test_head_object_fields(self, s3_client, s3_bucket, snapshot):
        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")
        response = s3_client.head_object(Bucket=s3_bucket, Key=key)
        snapshot.match("head-object", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..ContentLanguage", "$..Error.RequestID"]
    )
    def test_get_object_after_deleted_in_versioned_bucket(
        self, s3_client, s3_bucket, s3_resource, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.key_value("VersionId"))
        bucket = s3_resource.Bucket(s3_bucket)
        bucket.Versioning().enable()

        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")

        s3_obj = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-object", s3_obj)

        s3_client.delete_object(Bucket=s3_bucket, Key=key)

        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=s3_bucket, Key=key)

        snapshot.match("get-object-after-delete", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("algorithm", ["CRC32", "CRC32C", "SHA1", "SHA256"])
    def test_put_object_checksum(self, s3_client, s3_create_bucket, algorithm, snapshot):
        bucket = s3_create_bucket()
        key = f"file-{short_uid()}"
        data = b"test data.."

        params = {
            "Bucket": bucket,
            "Key": key,
            "Body": data,
            "ChecksumAlgorithm": algorithm,
            f"Checksum{algorithm}": short_uid(),
        }

        with pytest.raises(ClientError) as e:
            s3_client.put_object(**params)
        snapshot.match("put-wrong-checksum", e.value.response)

        error = e.value.response["Error"]
        assert error["Code"] == "InvalidRequest"

        checksum_header = f"x-amz-checksum-{algorithm.lower()}"
        assert error["Message"] == f"Value for {checksum_header} header is invalid."

        # Test our generated checksums
        match algorithm:
            case "CRC32":
                checksum = checksum_crc32(data)
            case "CRC32C":
                checksum = checksum_crc32c(data)
            case "SHA1":
                checksum = hash_sha1(data)
            case "SHA256":
                checksum = hash_sha256(data)
            case _:
                checksum = ""
        params.update({f"Checksum{algorithm}": checksum})
        response = s3_client.put_object(**params)
        snapshot.match("put-object-generated", response)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # Test the autogenerated checksums
        params.pop(f"Checksum{algorithm}")
        response = s3_client.put_object(**params)
        snapshot.match("put-object-autogenerated", response)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..AcceptRanges"])
    def test_s3_copy_metadata_replace(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        object_key = "source-object"
        bucket_name = s3_create_bucket()
        resp = s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body='{"key": "value"}',
            ContentType="application/json",
            Metadata={"key": "value"},
        )
        snapshot.match("put_object", resp)

        head_object = s3_client.head_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("head_object", head_object)

        object_key_copy = f"{object_key}-copy"
        resp = s3_client.copy_object(
            Bucket=bucket_name,
            CopySource=f"{bucket_name}/{object_key}",
            Key=object_key_copy,
            Metadata={"another-key": "value"},
            ContentType="application/javascript",
            MetadataDirective="REPLACE",
        )
        snapshot.match("copy_object", resp)

        head_object = s3_client.head_object(Bucket=bucket_name, Key=object_key_copy)
        snapshot.match("head_object_copy", head_object)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..AcceptRanges"])
    def test_s3_copy_content_type_and_metadata(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        object_key = "source-object"
        bucket_name = s3_create_bucket()
        resp = s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body='{"key": "value"}',
            ContentType="application/json",
            Metadata={"key": "value"},
        )
        snapshot.match("put_object", resp)

        head_object = s3_client.head_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("head_object", head_object)

        object_key_copy = f"{object_key}-copy"
        resp = s3_client.copy_object(
            Bucket=bucket_name, CopySource=f"{bucket_name}/{object_key}", Key=object_key_copy
        )
        snapshot.match("copy_object", resp)

        head_object = s3_client.head_object(Bucket=bucket_name, Key=object_key_copy)
        snapshot.match("head_object_copy", head_object)

        s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": object_key_copy}]})

        # does not set MetadataDirective=REPLACE, so the original metadata should be kept
        object_key_copy = f"{object_key}-second-copy"
        resp = s3_client.copy_object(
            Bucket=bucket_name,
            CopySource=f"{bucket_name}/{object_key}",
            Key=object_key_copy,
            Metadata={"another-key": "value"},
            ContentType="application/javascript",
        )
        snapshot.match("copy_object_second", resp)

        head_object = s3_client.head_object(Bucket=bucket_name, Key=object_key_copy)
        snapshot.match("head_object_second_copy", head_object)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="wrong behaviour, see https://docs.aws.amazon.com/AmazonS3/latest/userguide/managing-acls.html"
    )
    def test_s3_multipart_upload_acls(
        self, s3_client, s3_create_bucket, s3_multipart_upload, snapshot
    ):
        # The basis for this test is wrong - see:
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/managing-acls.html
        # > Bucket and object permissions are independent of each other. An object does not inherit the permissions
        # > from its bucket. For example, if you create a bucket and grant write access to a user, you can't access
        # > that user’s objects unless the user explicitly grants you access.
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("DisplayName"),
                snapshot.transform.key_value("ID", value_replacement="owner-id"),
            ]
        )
        bucket_name = f"test-bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        snapshot.match("bucket-acl", response)

        def check_permissions(key):
            acl_response = s3_client.get_object_acl(Bucket=bucket_name, Key=key)
            snapshot.match(f"permission-{key}", acl_response)

        # perform uploads (multipart and regular) and check ACLs
        s3_client.put_object(Bucket=bucket_name, Key="acl-key0", Body="something")
        check_permissions("acl-key0")
        s3_multipart_upload(bucket=bucket_name, key="acl-key1")
        check_permissions("acl-key1")
        s3_multipart_upload(bucket=bucket_name, key="acl-key2", acl="public-read-write")
        check_permissions("acl-key2")

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Grants..Grantee.DisplayName", "$..Grants..Grantee.ID"]
    )
    def test_s3_bucket_acl(self, s3_client, s3_create_bucket, snapshot):
        # loosely based on
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("DisplayName"),
                snapshot.transform.key_value("ID", value_replacement="owner-id"),
            ]
        )
        list_bucket_output = s3_client.list_buckets()
        owner = list_bucket_output["Owner"]

        bucket_name = s3_create_bucket(ACL="public-read")
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        snapshot.match("get-bucket-acl", response)

        s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")

        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        snapshot.match("get-bucket-canned-acl", response)

        s3_client.put_bucket_acl(
            Bucket=bucket_name, GrantRead='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"'
        )

        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        snapshot.match("get-bucket-grant-acl", response)

        # Owner is mandatory, otherwise raise MalformedXML
        acp = {
            "Owner": owner,
            "Grants": [
                {
                    "Grantee": {"ID": owner["ID"], "Type": "CanonicalUser"},
                    "Permission": "FULL_CONTROL",
                },
                {
                    "Grantee": {
                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                        "Type": "Group",
                    },
                    "Permission": "WRITE",
                },
            ],
        }
        s3_client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=acp)

        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        snapshot.match("get-bucket-acp-acl", response)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(LEGACY_S3_PROVIDER, reason="Behaviour not implemented in legacy provider")
    def test_s3_bucket_acl_exceptions(self, s3_client, s3_bucket, snapshot):
        list_bucket_output = s3_client.list_buckets()
        owner = list_bucket_output["Owner"]

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, ACL="fake-acl")

        snapshot.match("put-bucket-canned-acl", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(
                Bucket=s3_bucket, GrantWrite='uri="http://acs.amazonaws.com/groups/s3/FakeGroup"'
            )

        snapshot.match("put-bucket-grant-acl-fake-uri", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, GrantWrite='fakekey="1234"')

        snapshot.match("put-bucket-grant-acl-fake-key", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, GrantWrite='id="wrong-id"')

        snapshot.match("put-bucket-grant-acl-wrong-id", e.value.response)

        acp = {
            "Grants": [
                {
                    "Grantee": {
                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                        "Type": "Group",
                    },
                    "Permission": "WRITE",
                }
            ]
        }
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-1", e.value.response)

        # add Owner, but modify the permission
        acp["Owner"] = owner
        acp["Grants"][0]["Permission"] = "WRONG-PERMISSION"

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-2", e.value.response)

        # restore good permission, but put bad format Owner ID
        acp["Owner"] = {"ID": "wrong-id"}
        acp["Grants"][0]["Permission"] = "FULL_CONTROL"

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-3", e.value.response)

        # restore owner, but wrong URI
        acp["Owner"] = owner
        acp["Grants"][0]["Grantee"]["URI"] = "http://acs.amazonaws.com/groups/s3/FakeGroup"

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-4", e.value.response)

        # different type of failing grantee (CanonicalUser/ID)
        acp["Grants"][0]["Grantee"]["Type"] = "CanonicalUser"
        acp["Grants"][0]["Grantee"]["ID"] = "wrong-id"
        acp["Grants"][0]["Grantee"].pop("URI")

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-5", e.value.response)

        # different type of failing grantee (Wrong type)
        acp["Grants"][0]["Grantee"]["Type"] = "BadType"

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_acl(Bucket=s3_bucket, AccessControlPolicy=acp)
        snapshot.match("put-bucket-acp-acl-6", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Restore"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..AcceptRanges",
            "$..ContentLanguage",
            "$..VersionId",
        ],
    )
    def test_s3_object_expiry(self, s3_client, s3_bucket, snapshot):
        # AWS only cleans up S3 expired object once a day usually
        # the object stays accessible for quite a while after being expired
        # https://stackoverflow.com/questions/38851456/aws-s3-object-expiration-less-than-24-hours
        # handle s3 object expiry
        # https://github.com/localstack/localstack/issues/1685
        # TODO: should we have a config var to not deleted immediately in the new provider? and schedule it?
        snapshot.add_transformer(snapshot.transform.s3_api())
        # put object
        short_expire = datetime.datetime.now(ZoneInfo("GMT")) + datetime.timedelta(seconds=1)
        object_key_expired = "key-object-expired"
        object_key_not_expired = "key-object-not-expired"

        s3_client.put_object(
            Bucket=s3_bucket,
            Key=object_key_expired,
            Body="foo",
            Expires=short_expire,
        )
        # sleep so it expires
        time.sleep(3)
        # head_object does not raise an error for now in LS
        response = s3_client.head_object(Bucket=s3_bucket, Key=object_key_expired)
        assert response["Expires"] < datetime.datetime.now(ZoneInfo("GMT"))
        snapshot.match("head-object-expired", response)

        # try to fetch an object which is already expired
        if not is_aws_cloud():  # fixme for now behaviour differs, have a look at it and discuss
            with pytest.raises(Exception) as e:  # this does not raise in AWS
                s3_client.get_object(Bucket=s3_bucket, Key=object_key_expired)

            e.match("NoSuchKey")

        s3_client.put_object(
            Bucket=s3_bucket,
            Key=object_key_not_expired,
            Body="foo",
            Expires=datetime.datetime.now(ZoneInfo("GMT")) + datetime.timedelta(hours=1),
        )

        # try to fetch has not been expired yet.
        resp = s3_client.get_object(Bucket=s3_bucket, Key=object_key_not_expired)
        assert "Expires" in resp
        assert resp["Expires"] > datetime.datetime.now(ZoneInfo("GMT"))
        snapshot.match("get-object-not-yet-expired", resp)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
        ],
    )
    def test_upload_file_with_xml_preamble(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        object_key = f"key-{short_uid()}"
        body = '<?xml version="1.0" encoding="UTF-8"?><test/>'

        s3_create_bucket(Bucket=bucket_name)
        s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=body)

        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("get_object", response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER, reason="Get 404 Not Found instead of NoSuchBucket"
    )
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..Error.BucketName"])
    def test_bucket_availability(self, s3_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        # make sure to have a non created bucket, got some AccessDenied against AWS
        bucket_name = f"test-bucket-lifecycle-{short_uid()}-{short_uid()}"
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle(Bucket=bucket_name)
        snapshot.match("bucket-lifecycle", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_replication(Bucket=bucket_name)
        snapshot.match("bucket-replication", e.value.response)

    @pytest.mark.aws_validated
    def test_location_path_url(self, s3_client, s3_create_bucket, account_id, snapshot):
        region = "us-east-2"
        bucket_name = s3_create_bucket(
            CreateBucketConfiguration={"LocationConstraint": region}, ACL="public-read"
        )
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        assert region == response["LocationConstraint"]

        url = _bucket_url(bucket_name, region)
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
        # make raw request, assert that newline is contained after XML preamble: <?xml ...>\n
        response = requests.get(f"{url}?location?x-amz-expected-bucket-owner={account_id}")
        assert response.ok

        content = to_str(response.content)
        assert re.match(r"^<\?xml [^>]+>\n<.*", content, flags=re.MULTILINE)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..Error.RequestID"])
    def test_different_location_constraint(
        self,
        s3_client,
        s3_create_bucket,
        s3_client_for_region,
        s3_create_bucket_with_client,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(
            snapshot.transform.key_value("Location", "<location>", reference_replacement=False)
        )
        bucket_1_name = f"bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_1_name)
        response = s3_client.get_bucket_location(Bucket=bucket_1_name)
        snapshot.match("get_bucket_location_bucket_1", response)

        region_2 = "us-east-2"
        client_2 = s3_client_for_region(region_name=region_2)
        bucket_2_name = f"bucket-{short_uid()}"
        s3_create_bucket_with_client(
            client_2,
            Bucket=bucket_2_name,
            CreateBucketConfiguration={"LocationConstraint": region_2},
        )
        response = client_2.get_bucket_location(Bucket=bucket_2_name)
        snapshot.match("get_bucket_location_bucket_2", response)

        # assert creation fails without location constraint for us-east-2 region
        with pytest.raises(Exception) as exc:
            client_2.create_bucket(Bucket=f"bucket-{short_uid()}")
        snapshot.match("create_bucket_constraint_exc", exc.value.response)

        bucket_3_name = f"bucket-{short_uid()}"
        response = s3_create_bucket_with_client(
            client_2,
            Bucket=bucket_3_name,
            CreateBucketConfiguration={"LocationConstraint": region_2},
        )
        snapshot.match("create_bucket_bucket_3", response)

        response = client_2.get_bucket_location(Bucket=bucket_3_name)
        snapshot.match("get_bucket_location_bucket_3", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
        ],
    )
    def test_get_object_with_anon_credentials(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = f"bucket-{short_uid()}"
        object_key = f"key-{short_uid()}"
        body = "body data"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")

        s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=body,
        )
        s3_client.put_object_acl(Bucket=bucket_name, Key=object_key, ACL="public-read")
        s3_anon_client = _anon_client("s3")

        response = s3_anon_client.get_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("get_object", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..ContentLanguage", "$..VersionId", "$..AcceptRanges"]
    )
    def test_putobject_with_multiple_keys(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket = f"bucket-{short_uid()}"
        key_by_path = "aws/key1/key2/key3"

        s3_create_bucket(Bucket=bucket)
        s3_client.put_object(Body=b"test", Bucket=bucket, Key=key_by_path)
        result = s3_client.get_object(Bucket=bucket, Key=key_by_path)
        snapshot.match("get_object", result)

    @pytest.mark.aws_validated
    def test_delete_bucket_lifecycle_configuration(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-lifecycle-exc-1", e.value.response)

        resp = s3_client.delete_bucket_lifecycle(Bucket=s3_bucket)
        snapshot.match("delete-bucket-lifecycle-no-bucket", resp)

        lfc = {
            "Rules": [
                {
                    "Expiration": {"Days": 7},
                    "ID": "wholebucket",
                    "Filter": {"Prefix": ""},
                    "Status": "Enabled",
                }
            ]
        }
        s3_client.put_bucket_lifecycle_configuration(Bucket=s3_bucket, LifecycleConfiguration=lfc)
        result = retry(
            s3_client.get_bucket_lifecycle_configuration, retries=3, sleep=1, Bucket=s3_bucket
        )
        snapshot.match("get-bucket-lifecycle-conf", result)
        s3_client.delete_bucket_lifecycle(Bucket=s3_bucket)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-lifecycle-exc-2", e.value.response)

    @pytest.mark.aws_validated
    def test_delete_lifecycle_configuration_on_bucket_deletion(
        self, s3_client, s3_create_bucket, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        bucket_name = f"test-bucket-{short_uid()}"  # keep the same name for both bucket
        s3_create_bucket(Bucket=bucket_name)
        lfc = {
            "Rules": [
                {
                    "Expiration": {"Days": 7},
                    "ID": "wholebucket",
                    "Filter": {"Prefix": ""},
                    "Status": "Enabled",
                }
            ]
        }
        s3_client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lfc)
        result = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        snapshot.match("get-bucket-lifecycle-conf", result)
        s3_client.delete_bucket(Bucket=bucket_name)
        s3_create_bucket(Bucket=bucket_name)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        snapshot.match("get-bucket-lifecycle-exc", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="Bucket lifecycle doesn't affect object expiration in both providers for now"
    )
    def test_bucket_lifecycle_configuration_object_expiry(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("BucketName"),
                snapshot.transform.key_value(
                    "Expiration", reference_replacement=False, value_replacement="<expiration>"
                ),
            ]
        )

        lfc = {
            "Rules": [
                {
                    "Expiration": {"Days": 7},
                    "ID": "wholebucket",
                    "Filter": {"Prefix": ""},
                    "Status": "Enabled",
                }
            ]
        }
        s3_client.put_bucket_lifecycle_configuration(Bucket=s3_bucket, LifecycleConfiguration=lfc)
        result = s3_client.get_bucket_lifecycle_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-lifecycle-conf", result)

        key = "test-object-expiry"
        s3_client.put_object(Body=b"test", Bucket=s3_bucket, Key=key)

        response = s3_client.head_object(Bucket=s3_bucket, Key=key)
        snapshot.match("head-object-expiry", response)
        response = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-object-expiry", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
        ],
    )
    def test_range_header_body_length(self, s3_client, s3_bucket, snapshot):
        # Test for https://github.com/localstack/localstack/issues/1952
        # object created is random, ETag will be as well
        snapshot.add_transformer(snapshot.transform.key_value("ETag"))
        object_key = "sample.bin"
        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            s3_client.upload_fileobj(data, s3_bucket, object_key)

        range_header = f"bytes=0-{(chunk_size - 1)}"
        resp = s3_client.get_object(Bucket=s3_bucket, Key=object_key, Range=range_header)
        content = resp["Body"].read()
        assert chunk_size == len(content)
        snapshot.match("get-object", resp)

    @pytest.mark.aws_validated
    def test_get_range_object_headers(self, s3_client, s3_bucket):
        object_key = "sample.bin"
        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            s3_client.upload_fileobj(data, s3_bucket, object_key)

        range_header = f"bytes=0-{(chunk_size - 1)}"
        resp = s3_client.get_object(Bucket=s3_bucket, Key=object_key, Range=range_header)
        assert resp.get("AcceptRanges") == "bytes"
        resp_headers = resp["ResponseMetadata"]["HTTPHeaders"]
        assert "x-amz-request-id" in resp_headers
        assert "x-amz-id-2" in resp_headers
        # `content-language` should not be in the response
        if is_aws_cloud():  # fixme parity issue
            assert "content-language" not in resp_headers
        # We used to return `cache-control: no-cache` if the header wasn't set
        # by the client, but this was a bug because s3 doesn't do that. It simply
        # omits it.
        assert "cache-control" not in resp_headers
        # Do not send a content-encoding header as discussed in Issue #3608
        assert "content-encoding" not in resp_headers

    @pytest.mark.only_localstack
    def test_put_object_chunked_newlines(self, s3_client, s3_bucket):
        # Boto still does not support chunk encoding, which means we can't test with the client nor
        # aws_http_client_factory. See open issue: https://github.com/boto/boto3/issues/751
        # Test for https://github.com/localstack/localstack/issues/1571
        object_key = "data"
        body = "Hello\r\n\r\n\r\n\r\n"
        headers = {
            "Authorization": aws_stack.mock_aws_request_headers("s3")["Authorization"],
            "Content-Type": "audio/mpeg",
            "X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "X-Amz-Date": "20190918T051509Z",
            "X-Amz-Decoded-Content-Length": str(len(body)),
        }
        data = (
            "d;chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n"
            f"{body}\r\n0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n"
        )
        # put object
        url = f"{config.service_url('s3')}/{s3_bucket}/{object_key}"
        requests.put(url, data, headers=headers, verify=False)
        # get object and assert content length
        downloaded_object = s3_client.get_object(Bucket=s3_bucket, Key=object_key)
        download_file_object = to_str(downloaded_object["Body"].read())
        assert len(body) == len(str(download_file_object))
        assert body == str(download_file_object)

    @pytest.mark.only_localstack
    def test_put_object_with_md5_and_chunk_signature(self, s3_client, s3_bucket):
        # Boto still does not support chunk encoding, which means we can't test with the client nor
        # aws_http_client_factory. See open issue: https://github.com/boto/boto3/issues/751
        # Test for https://github.com/localstack/localstack/issues/4987
        object_key = "test-runtime.properties"
        object_data = (
            "#20211122+0100\n"
            "#Mon Nov 22 20:10:44 CET 2021\n"
            "last.sync.url.test-space-key=2822a50f-4992-425a-b8fb-923735a9ddff317e3479-5907-46cf-b33a-60da9709274f\n"
        )
        object_data_chunked = (
            "93;chunk-signature=5be6b2d473e96bb9f297444da60bdf0ff8f5d2e211e1d551b3cf3646c0946641\r\n"
            f"{object_data}"
            "\r\n0;chunk-signature=bd5c830b94346b57ddc8805ba26c44a122256c207014433bf6579b0985f21df7\r\n\r\n"
        )
        content_md5 = base64.b64encode(hashlib.md5(object_data.encode()).digest()).decode()
        headers = {
            "Content-Md5": content_md5,
            "Content-Type": "application/octet-stream",
            "User-Agent": (
                "aws-sdk-java/1.11.951 Mac_OS_X/10.15.7 OpenJDK_64-Bit_Server_VM/11.0.11+9-LTS "
                "java/11.0.11 scala/2.13.6 kotlin/1.5.31 vendor/Amazon.com_Inc."
            ),
            "X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "X-Amz-Date": "20211122T191045Z",
            "X-Amz-Decoded-Content-Length": str(len(object_data)),
            "Content-Length": str(len(object_data_chunked)),
            "Connection": "Keep-Alive",
            "Expect": "100-continue",
        }

        url = s3_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": s3_bucket,
                "Key": object_key,
                "ContentType": "application/octet-stream",
                "ContentMD5": content_md5,
            },
        )
        result = requests.put(url, data=object_data_chunked, headers=headers)
        assert result.status_code == 200, (result, result.content)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage"]
    )
    def test_delete_object_tagging(self, s3_client, s3_bucket, snapshot):
        object_key = "test-key-tagging"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        # get object and assert response
        s3_obj = s3_client.get_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-obj", s3_obj)
        # delete object tagging
        s3_client.delete_object_tagging(Bucket=s3_bucket, Key=object_key)
        # assert that the object still exists
        s3_obj = s3_client.get_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-obj-after-tag-deletion", s3_obj)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="Not implemented in old provider")
    def test_delete_non_existing_keys_quiet(self, s3_client, s3_bucket, snapshot):
        object_key = "test-key-nonexistent"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        response = s3_client.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [{"Key": object_key}, {"Key": "dummy1"}, {"Key": "dummy2"}],
                "Quiet": True,
            },
        )
        snapshot.match("deleted-resp", response)
        assert "Deleted" not in response
        assert "Errors" not in response

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..VersionId"])
    def test_delete_non_existing_keys(self, s3_client, s3_bucket, snapshot):
        object_key = "test-key-nonexistent"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        response = s3_client.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [{"Key": object_key}, {"Key": "dummy1"}, {"Key": "dummy2"}],
            },
        )
        response["Deleted"].sort(key=itemgetter("Key"))
        snapshot.match("deleted-resp", response)
        assert len(response["Deleted"]) == 3
        assert "Errors" not in response

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Error.RequestID"]
    )  # fixme RequestID not in AWS response
    def test_delete_non_existing_keys_in_non_existing_bucket(self, s3_client, snapshot):
        with pytest.raises(ClientError) as e:
            s3_client.delete_objects(
                Bucket="non-existent-bucket",
                Delete={"Objects": [{"Key": "dummy1"}, {"Key": "dummy2"}]},
            )
        assert "NoSuchBucket" == e.value.response["Error"]["Code"]
        snapshot.match("error-non-existent-bucket", e.value.response)

    @pytest.mark.aws_validated
    def test_s3_request_payer(self, s3_client, s3_bucket, snapshot):
        response = s3_client.put_bucket_request_payment(
            Bucket=s3_bucket, RequestPaymentConfiguration={"Payer": "Requester"}
        )
        snapshot.match("put-bucket-request-payment", response)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        response = s3_client.get_bucket_request_payment(Bucket=s3_bucket)
        snapshot.match("get-bucket-request-payment", response)
        assert "Requester" == response["Payer"]

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, path="$..Error.BucketName")
    def test_s3_request_payer_exceptions(self, s3_client, s3_bucket, snapshot):
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_request_payment(
                Bucket=s3_bucket, RequestPaymentConfiguration={"Payer": "Random"}
            )
        snapshot.match("wrong-payer-type", e.value.response)

        # TODO: check if no luck or AccessDenied is normal?
        # with pytest.raises(ClientError) as e:
        #     s3_client.put_bucket_request_payment(
        #         Bucket="fake_bucket", RequestPaymentConfiguration={"Payer": "Requester"}
        #     )
        # snapshot.match("wrong-bucket-name", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Error.RequestID", "$..Grants..Grantee.DisplayName"]
    )
    def test_bucket_exists(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("DisplayName"),
                snapshot.transform.key_value("ID", value_replacement="owner-id"),
            ]
        )
        s3_client.put_bucket_cors(
            Bucket=s3_bucket,
            CORSConfiguration={
                "CORSRules": [
                    {
                        "AllowedMethods": ["GET", "POST", "PUT", "DELETE"],
                        "AllowedOrigins": ["localhost"],
                    }
                ]
            },
        )

        response = s3_client.get_bucket_cors(Bucket=s3_bucket)
        snapshot.match("get-bucket-cors", response)

        result = s3_client.get_bucket_acl(Bucket=s3_bucket)
        snapshot.match("get-bucket-acl", result)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_acl(Bucket="bucket-not-exists")
        snapshot.match("get-bucket-not-exists", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=["$..VersionId", "$..ContentLanguage", "$..Error.RequestID"],
    )
    def test_s3_uppercase_key_names(self, s3_client, s3_create_bucket, snapshot):
        # bucket name should be case-sensitive
        bucket_name = f"testuppercase-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)

        # key name should be case-sensitive
        object_key = "camelCaseKey"
        s3_client.put_object(Bucket=bucket_name, Key=object_key, Body="something")
        res = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("response", res)
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=bucket_name, Key="camelcasekey")
        snapshot.match("wrong-case-key", e.value.response)

    @pytest.mark.aws_validated
    def test_s3_download_object_with_lambda(
        self,
        s3_client,
        s3_create_bucket,
        create_lambda_function,
        lambda_client,
        lambda_su_role,
        logs_client,
    ):

        bucket_name = f"bucket-{short_uid()}"
        function_name = f"func-{short_uid()}"
        key = f"key-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name)
        s3_client.put_object(Bucket=bucket_name, Key=key, Body="something..")

        create_lambda_function(
            handler_file=os.path.join(
                os.path.dirname(__file__),
                "../awslambda",
                "functions",
                "lambda_triggered_by_sqs_download_s3_file.py",
            ),
            func_name=function_name,
            role=lambda_su_role,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            envvars=dict(
                {
                    "BUCKET_NAME": bucket_name,
                    "OBJECT_NAME": key,
                    "LOCAL_FILE_NAME": "/tmp/" + key,
                }
            ),
        )
        lambda_client.invoke(FunctionName=function_name, InvocationType="Event")

        # TODO maybe this check can be improved (do not rely on logs)
        retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            regex_filter="success",
            expected_length=1,
            logs_client=logs_client,
        )

    @pytest.mark.aws_validated
    # TODO LocalStack adds this RequestID to the error response
    @pytest.mark.skip_snapshot_verify(paths=["$..Error.RequestID"])
    def test_precondition_failed_error(self, s3_client, s3_create_bucket, snapshot):
        bucket = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket)
        s3_client.put_object(Bucket=bucket, Key="foo", Body=b'{"foo": "bar"}')

        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=bucket, Key="foo", IfMatch='"not good etag"')

        snapshot.match("get-object-if-match", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(reason="Error format is wrong and missing keys")
    def test_s3_invalid_content_md5(self, s3_client, s3_bucket, snapshot):
        # put object with invalid content MD5
        # TODO: implement ContentMD5 in ASF
        hashes = ["__invalid__", "000", "not base64 encoded checksum", "MTIz"]
        for index, md5hash in enumerate(hashes):
            with pytest.raises(ClientError) as e:
                s3_client.put_object(
                    Bucket=s3_bucket,
                    Key="test-key",
                    Body="something",
                    ContentMD5=md5hash,
                )
            snapshot.match(f"md5-error-{index}", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..ETag"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage"]
    )
    def test_s3_upload_download_gzip(self, s3_client, s3_bucket, snapshot):
        data = "1234567890 " * 100

        # Write contents to memory rather than a file.
        upload_file_object = BytesIO()
        with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
            filestream.write(data.encode("utf-8"))

        # Upload gzip
        response = s3_client.put_object(
            Bucket=s3_bucket,
            Key="test.gz",
            ContentEncoding="gzip",
            Body=upload_file_object.getvalue(),
        )
        snapshot.match("put-object", response)
        # TODO: check why ETag is different

        # Download gzip
        downloaded_object = s3_client.get_object(Bucket=s3_bucket, Key="test.gz")
        snapshot.match("get-object", downloaded_object)
        download_file_object = BytesIO(downloaded_object["Body"].read())
        with gzip.GzipFile(fileobj=download_file_object, mode="rb") as filestream:
            downloaded_data = filestream.read().decode("utf-8")

        assert downloaded_data == data

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..VersionId"])
    def test_multipart_copy_object_etag(self, s3_client, s3_bucket, s3_multipart_upload, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("Bucket"),
            ]
        )
        key = "test.file"
        copy_key = "copy.file"
        src_object_path = f"{s3_bucket}/{key}"
        content = "test content 123"

        response = s3_multipart_upload(bucket=s3_bucket, key=key, data=content)
        snapshot.match("multipart-upload", response)
        multipart_etag = response["ETag"]

        response = s3_client.copy_object(Bucket=s3_bucket, CopySource=src_object_path, Key=copy_key)
        snapshot.match("copy-object", response)
        copy_etag = response["CopyObjectResult"]["ETag"]
        # etags should be different
        assert copy_etag != multipart_etag

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..VersionId"])
    def test_set_external_hostname(
        self, s3_client, s3_bucket, s3_multipart_upload, monkeypatch, snapshot
    ):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("Bucket"),
            ]
        )
        monkeypatch.setattr(config, "HOSTNAME_EXTERNAL", "foobar")
        key = "test.file"
        content = "test content 123"
        acl = "public-read"
        # upload file
        response = s3_multipart_upload(bucket=s3_bucket, key=key, data=content, acl=acl)
        snapshot.match("multipart-upload", response)

        if is_aws_cloud():  # TODO: default addressing is vhost for AWS
            expected_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{key}"
        else:  # LS default is path addressing
            expected_url = f"{_bucket_url(bucket_name=s3_bucket, localstack_host=config.HOSTNAME_EXTERNAL)}/{key}"
        assert response["Location"] == expected_url

        # download object via API
        downloaded_object = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-object", response)
        assert content == to_str(downloaded_object["Body"].read())

        # download object directly from download link
        download_url = response["Location"].replace(f"{config.HOSTNAME_EXTERNAL}:", "localhost:")
        response = requests.get(download_url)
        assert response.status_code == 200
        assert to_str(response.content) == content

    @pytest.mark.skip_offline
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..AcceptRanges"])
    def test_s3_lambda_integration(
        self,
        lambda_client,
        create_lambda_function,
        lambda_su_role,
        s3_client,
        s3_create_bucket,
        create_tmp_folder_lambda,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        handler_file = os.path.join(
            os.path.dirname(__file__), "../awslambda/functions/lambda_s3_integration.js"
        )
        temp_folder = create_tmp_folder_lambda(
            handler_file,
            run_command="npm i @aws-sdk/util-endpoints @aws-sdk/client-s3 @aws-sdk/s3-request-presigner @aws-sdk/middleware-endpoint",
        )

        function_name = f"func-integration-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(temp_folder, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS14X,
            handler="lambda_s3_integration.handler",
            role=lambda_su_role,
        )
        s3_create_bucket(Bucket=function_name)

        response = lambda_client.invoke(FunctionName=function_name)
        presigned_url = response["Payload"].read()
        presigned_url = json.loads(to_str(presigned_url))["body"].strip('"')

        response = requests.put(presigned_url, verify=False)
        assert 200 == response.status_code

        response = s3_client.head_object(Bucket=function_name, Key="key.png")
        snapshot.match("head_object", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, path="$..Error.BucketName")
    def test_s3_uppercase_bucket_name(self, s3_client, s3_create_bucket, snapshot):
        # bucket name should be lower-case
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"TESTUPPERCASE-{short_uid()}"
        with pytest.raises(ClientError) as e:
            s3_create_bucket(Bucket=bucket_name)
        snapshot.match("uppercase-bucket", e.value.response)

    @pytest.mark.aws_validated
    def test_create_bucket_with_existing_name(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        s3_create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "us-west-1"},
        )

        for loc_constraint in ["us-west-1", "us-east-2"]:
            with pytest.raises(ClientError) as e:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": loc_constraint},
                )
            e.match("BucketAlreadyOwnedByYou")
            snapshot.match(f"create-bucket-{loc_constraint}", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="asf provider: routing for region-path style not working; "
        "both provider: return 200 for other regions (no redirects)"
    )
    def test_access_bucket_different_region(self, s3_create_bucket, s3_vhost_client):
        bucket_name = f"my-bucket-{short_uid()}"

        s3_create_bucket(
            Bucket=bucket_name,
            ACL="public-read",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        s3_vhost_client.list_objects(Bucket=bucket_name)
        bucket_vhost_url = _bucket_url_vhost(bucket_name, region="us-west-2")
        response = requests.get(bucket_vhost_url)
        assert response.status_code == 200

        bucket_url = _bucket_url(bucket_name, region="us-west-2")
        response = requests.get(bucket_url)
        assert response.status_code == 200

        bucket_vhost_url = _bucket_url_vhost(bucket_name, region="us-east-2")
        response = requests.get(bucket_vhost_url)
        assert response.status_code == 301

        bucket_vhost_url = _bucket_url_vhost(bucket_name, region="us-east-1")
        response = requests.get(bucket_vhost_url)
        assert response.status_code == 200
        assert response.history[0].status_code == 307

    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..Error.RequestID"]
    )
    def test_bucket_does_not_exist(self, s3_client, s3_vhost_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-does-not-exist-{short_uid()}"

        with pytest.raises(ClientError) as e:
            response = s3_client.list_objects(Bucket=bucket_name)
        e.match("NoSuchBucket")
        snapshot.match("list_object", e.value.response)

        with pytest.raises(ClientError) as e:
            response = s3_vhost_client.list_objects(Bucket=bucket_name)
        e.match("NoSuchBucket")
        snapshot.match("list_object_vhost", e.value.response)

        bucket_vhost_url = _bucket_url_vhost(bucket_name, region="us-east-1")
        assert "us-east-1" not in bucket_vhost_url

        response = requests.get(bucket_vhost_url)
        assert response.status_code == 404

        bucket_url = _bucket_url(bucket_name, region="us-east-1")
        assert "us-east-1" not in bucket_url
        response = requests.get(bucket_url)
        assert response.status_code == 404

        bucket_vhost_url = _bucket_url_vhost(bucket_name, region="us-west-2")
        assert "us-west-2" in bucket_vhost_url
        response = requests.get(bucket_vhost_url)
        assert response.status_code == 404

        bucket_url = _bucket_url(bucket_name, region="us-west-2")
        assert "us-west-2" in bucket_url
        response = requests.get(bucket_url)
        assert response.status_code == 404

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: not LEGACY_S3_PROVIDER,
        paths=["$..x-amz-access-point-alias", "$..x-amz-id-2"],
    )
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=[
            "$..x-amz-access-point-alias",
            "$..x-amz-id-2",
            "$..create_bucket_location_constraint.Location",
            "$..content-type",
            "$..x-amzn-requestid",
        ],
    )
    def test_create_bucket_head_bucket(self, s3_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_1 = f"my-bucket-1{short_uid()}"
        bucket_2 = f"my-bucket-2{short_uid()}"

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(rf"{bucket_1}", "<bucket-name:1>"),
                snapshot.transform.regex(rf"{bucket_2}", "<bucket-name:2>"),
                snapshot.transform.key_value("x-amz-id-2", reference_replacement=False),
                snapshot.transform.key_value("x-amz-request-id", reference_replacement=False),
                snapshot.transform.regex(r"s3\.amazonaws\.com", "host"),
                snapshot.transform.regex(r"s3\.localhost\.localstack\.cloud:4566", "host"),
            ]
        )

        try:
            response = s3_client.create_bucket(Bucket=bucket_1)
            snapshot.match("create_bucket", response)

            response = s3_client.create_bucket(
                Bucket=bucket_2,
                CreateBucketConfiguration={"LocationConstraint": "us-west-1"},
            )
            snapshot.match("create_bucket_location_constraint", response)

            response = s3_client.head_bucket(Bucket=bucket_1)
            snapshot.match("head_bucket", response)
            snapshot.match(
                "head_bucket_filtered_header",
                _filter_header(response["ResponseMetadata"]["HTTPHeaders"]),
            )

            response = s3_client.head_bucket(Bucket=bucket_2)
            snapshot.match("head_bucket_2", response)
            snapshot.match(
                "head_bucket_2_filtered_header",
                _filter_header(response["ResponseMetadata"]["HTTPHeaders"]),
            )

            # TODO aws returns 403, LocalStack 404
            # with pytest.raises(ClientError) as e:
            #     response = s3_client.head_bucket(Bucket="does-not-exist")
            # snapshot.match("head_bucket_not_exist", e.value.response)
        finally:
            s3_client.delete_bucket(Bucket=bucket_1)
            s3_client.delete_bucket(Bucket=bucket_2)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER, reason="virtual-host url for bucket with dots not supported"
    )
    def test_bucket_name_with_dots(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("Date", reference_replacement=False))
        snapshot.add_transformer(snapshot.transform.key_value("date", reference_replacement=False))
        snapshot.add_transformer(
            snapshot.transform.key_value("x-amz-id-2", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("x-amz-request-id", reference_replacement=False)
        )

        bucket_name = f"my.bucket.name.{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(Bucket=bucket_name, Key="my-content", Body="something")
        response = s3_client.list_objects(Bucket=bucket_name)
        assert response["Contents"][0]["Key"] == "my-content"
        assert response["Contents"][0]["ETag"] == '"437b930db84b8079c2dd804a71936b5f"'
        assert response["Contents"][0]["Size"] == 9

        snapshot.match("list_objects", response)
        snapshot.match("list_objects_headers", response["ResponseMetadata"]["HTTPHeaders"])

        # will result in a host-name-match if we use https, as the bucket contains dots
        response_vhost = requests.get(_bucket_url_vhost(bucket_name).replace("https://", "http://"))
        content_vhost = response_vhost.content.decode("utf-8")
        assert "<Key>my-content</Key>" in content_vhost
        # TODO aws contains <ETag>&quot;437b930db84b8079c2dd804a71936b5f&quot;</ETag>
        # assert '<ETag>"437b930db84b8079c2dd804a71936b5f"</ETag>' in content_vhost
        assert "<Size>9</Size>" in content_vhost

        snapshot.match("request_vhost_url_content", content_vhost)
        # TODO headers different; raw response on AWS returns 'ListBucketResult', on LS 'ListObjectsOutput'
        snapshot.match("request_vhost_headers", dict(response_vhost.headers))

        response_path_style = requests.get(_bucket_url(bucket_name))
        content_path_style = response_path_style.content.decode("utf-8")

        assert "<Key>my-content</Key>" in content_path_style
        # TODO aws contains <ETag>&quot;437b930db84b8079c2dd804a71936b5f&quot;</ETag>
        # assert '<ETag>"437b930db84b8079c2dd804a71936b5f"</ETag>' in content_path_style
        assert "<Size>9</Size>" in content_path_style

        snapshot.match("request_path_url_content", content_path_style)
        snapshot.match("request_path_headers", dict(response_path_style.headers))
        assert content_vhost == content_path_style

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Prefix"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..ContentLanguage", "$..VersionId"]
    )
    def test_s3_put_more_than_1000_items(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = "test" + short_uid()
        s3_create_bucket(Bucket=bucket_name)
        for i in range(0, 1010, 1):
            body = "test-" + str(i)
            key = "test-key-" + str(i)
            s3_client.put_object(Bucket=bucket_name, Key=key, Body=body)

        # trying to get the last item of 1010 items added.
        resp = s3_client.get_object(Bucket=bucket_name, Key="test-key-1009")
        snapshot.match("get_object-1009", resp)

        # trying to get the first item of 1010 items added.
        resp = s3_client.get_object(Bucket=bucket_name, Key="test-key-0")
        snapshot.match("get_object-0", resp)

        # according docs for MaxKeys: the response might contain fewer keys but will never contain more.
        # AWS returns less during testing
        resp = s3_client.list_objects(Bucket=bucket_name, MaxKeys=1010)
        assert 1010 >= len(resp["Contents"])

        resp = s3_client.list_objects(Bucket=bucket_name, Delimiter="/")
        assert 1000 == len(resp["Contents"])
        # way too much content, remove it from this match
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..list-objects.Contents", "<content>", reference_replacement=False
            )
        )
        snapshot.match("list-objects", resp)
        next_marker = resp["NextMarker"]

        # Second list
        resp = s3_client.list_objects(Bucket=bucket_name, Marker=next_marker)
        snapshot.match("list-objects-next_marker", resp)
        assert 10 == len(resp["Contents"])

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Prefix"])
    def test_s3_list_objects_empty_marker(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = "test" + short_uid()
        s3_create_bucket(Bucket=bucket_name)
        resp = s3_client.list_objects(Bucket=bucket_name, Marker="")
        snapshot.match("list-objects", resp)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..AcceptRanges"])
    def test_upload_big_file(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        key1 = "test_key1"
        key2 = "test_key1"

        s3_create_bucket(Bucket=bucket_name)

        body1 = "\x01" * 10000000
        rs = s3_client.put_object(Bucket=bucket_name, Key=key1, Body=body1)
        snapshot.match("put_object_key1", rs)

        body2 = "a" * 10000000
        rs = s3_client.put_object(Bucket=bucket_name, Key=key2, Body=body2)
        snapshot.match("put_object_key2", rs)

        rs = s3_client.head_object(Bucket=bucket_name, Key=key1)
        snapshot.match("head_object_key1", rs)

        rs = s3_client.head_object(Bucket=bucket_name, Key=key2)
        snapshot.match("head_object_key2", rs)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Delimiter", "$..EncodingType", "$..VersionIdMarker"]
    )
    def test_get_bucket_versioning_order(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = f"bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)
        rs = s3_client.list_object_versions(Bucket=bucket_name, EncodingType="url")
        snapshot.match("list_object_versions_before", rs)

        rs = s3_client.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
        snapshot.match("put_bucket_versioning", rs)

        rs = s3_client.get_bucket_versioning(Bucket=bucket_name)
        snapshot.match("get_bucket_versioning", rs)

        s3_client.put_object(Bucket=bucket_name, Key="test", Body="body")
        s3_client.put_object(Bucket=bucket_name, Key="test", Body="body")
        s3_client.put_object(Bucket=bucket_name, Key="test2", Body="body")
        rs = s3_client.list_object_versions(
            Bucket=bucket_name,
        )

        snapshot.match("list_object_versions", rs)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..ContentLanguage", "$..VersionId"]
    )
    def test_etag_on_get_object_call(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        object_key = "my-key"
        s3_create_bucket(Bucket=bucket_name)

        body = "Lorem ipsum dolor sit amet, ... " * 30
        rs = s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=body)

        rs = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        snapshot.match("get_object", rs)

        range_content = 17
        rs = s3_client.get_object(
            Bucket=bucket_name,
            Key=object_key,
            Range=f"bytes=0-{range_content-1}",
        )
        snapshot.match("get_object_range", rs)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Delimiter", "$..EncodingType", "$..VersionIdMarker"]
    )
    def test_s3_delete_object_with_version_id(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"

        test_1st_key = "aws/s3/testkey1.txt"
        test_2nd_key = "aws/s3/testkey2.txt"

        body = "Lorem ipsum dolor sit amet, ... " * 30

        s3_create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        rs = s3_client.get_bucket_versioning(Bucket=bucket_name)
        snapshot.match("get_bucket_versioning", rs)

        # put 2 objects
        rs = s3_client.put_object(Bucket=bucket_name, Key=test_1st_key, Body=body)
        s3_client.put_object(Bucket=bucket_name, Key=test_2nd_key, Body=body)
        version_id = rs["VersionId"]

        # delete 1st object with version
        rs = s3_client.delete_objects(
            Bucket=bucket_name,
            Delete={"Objects": [{"Key": test_1st_key, "VersionId": version_id}]},
        )

        deleted = rs["Deleted"][0]
        assert test_1st_key == deleted["Key"]
        assert version_id == deleted["VersionId"]
        snapshot.match("delete_objects", rs)

        rs = s3_client.list_object_versions(Bucket=bucket_name)
        object_versions = [object["VersionId"] for object in rs["Versions"]]
        snapshot.match("list_object_versions_after_delete", rs)

        assert version_id not in object_versions

        # disable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Suspended"},
        )
        rs = s3_client.get_bucket_versioning(Bucket=bucket_name)
        snapshot.match("get_bucket_versioning_suspended", rs)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Delimiter", "$..EncodingType", "$..VersionIdMarker"]
    )
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=["$..ContentLanguage", "$..VersionId"],
    )
    def test_s3_put_object_versioned(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        # this object is put before the bucket is versioned, its internal versionId is `null`
        key = "non-version-bucket-key"
        put_obj_pre_versioned = s3_client.put_object(
            Bucket=s3_bucket, Key=key, Body="non-versioned-key"
        )
        snapshot.match("put-pre-versioned", put_obj_pre_versioned)
        get_obj_pre_versioned = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-pre-versioned", get_obj_pre_versioned)

        list_obj_pre_versioned = s3_client.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-object-pre-versioned", list_obj_pre_versioned)

        # we activate the bucket versioning then check if the object has a versionId
        s3_client.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        get_obj_non_versioned = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-post-versioned", get_obj_non_versioned)

        # create versioned key, then update it, and check we got the last versionId
        key_2 = "versioned-bucket-key"
        put_obj_versioned_1 = s3_client.put_object(
            Bucket=s3_bucket, Key=key_2, Body="versioned-key"
        )
        snapshot.match("put-obj-versioned-1", put_obj_versioned_1)
        put_obj_versioned_2 = s3_client.put_object(
            Bucket=s3_bucket, Key=key_2, Body="versioned-key-updated"
        )
        snapshot.match("put-obj-versioned-2", put_obj_versioned_2)

        get_obj_versioned = s3_client.get_object(Bucket=s3_bucket, Key=key_2)
        snapshot.match("get-obj-versioned", get_obj_versioned)

        list_obj_post_versioned = s3_client.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-object-versioned", list_obj_post_versioned)

        # disable versioning to check behaviour after getting keys
        # all keys will now have versionId when getting them, even non-versioned ones
        s3_client.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Suspended"},
        )
        list_obj_post_versioned_disabled = s3_client.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-bucket-suspended", list_obj_post_versioned_disabled)

        get_obj_versioned_disabled = s3_client.get_object(Bucket=s3_bucket, Key=key_2)
        snapshot.match("get-obj-versioned-disabled", get_obj_versioned_disabled)

        get_obj_non_versioned_disabled = s3_client.get_object(Bucket=s3_bucket, Key=key)
        snapshot.match("get-obj-non-versioned-disabled", get_obj_non_versioned_disabled)

        # won't return the versionId from put
        key_3 = "non-version-bucket-key-after-disable"
        put_obj_non_version_post_disable = s3_client.put_object(
            Bucket=s3_bucket, Key=key_3, Body="non-versioned-key-post"
        )
        snapshot.match("put-non-versioned-post-disable", put_obj_non_version_post_disable)
        # will return the versionId now, when it didn't before setting the BucketVersioning to `Enabled`
        get_obj_non_version_post_disable = s3_client.get_object(Bucket=s3_bucket, Key=key_3)
        snapshot.match("get-non-versioned-post-disable", get_obj_non_version_post_disable)

        # manually assert all VersionId, as it's hard to do in snapshots
        if is_aws_cloud() or not LEGACY_S3_PROVIDER:
            assert "VersionId" not in get_obj_pre_versioned
            assert get_obj_non_versioned["VersionId"] == "null"
            assert list_obj_pre_versioned["Versions"][0]["VersionId"] == "null"
            assert get_obj_versioned["VersionId"] is not None
            assert list_obj_post_versioned["Versions"][0]["VersionId"] == "null"
            assert list_obj_post_versioned["Versions"][1]["VersionId"] is not None
            assert list_obj_post_versioned["Versions"][2]["VersionId"] is not None

    @pytest.mark.aws_validated
    @pytest.mark.xfail(reason="ACL behaviour is not implemented, see comments")
    def test_s3_batch_delete_objects_using_requests_with_acl(
        self, s3_client, s3_create_bucket, snapshot
    ):
        # If an object is created in a public bucket by the owner, it can't be deleted by anonymous clients
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee-predefined-groups
        # only "public" created objects can be deleted by anonymous clients
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        object_key_1 = "key-created-by-owner"
        object_key_2 = "key-created-by-anonymous"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read-write")
        s3_client.put_object(
            Bucket=bucket_name, Key=object_key_1, Body="This body document", ACL="public-read-write"
        )
        anon = _anon_client("s3")
        anon.put_object(
            Bucket=bucket_name,
            Key=object_key_2,
            Body="This body document #2",
            ACL="public-read-write",
        )

        url = f"{_bucket_url(bucket_name, localstack_host=config.LOCALSTACK_HOSTNAME)}?delete"

        data = f"""
        <Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Object>
            <Key>{object_key_1}</Key>
          </Object>
          <Object>
            <Key>{object_key_2}</Key>
          </Object>
        </Delete>
        """

        md = hashlib.md5(data.encode("utf-8")).digest()
        contents_md5 = base64.b64encode(md).decode("utf-8")
        header = {"content-md5": contents_md5, "x-amz-request-payer": "requester"}
        r = requests.post(url=url, data=data, headers=header)

        assert 200 == r.status_code
        response = xmltodict.parse(r.content)
        response["DeleteResult"].pop("@xmlns", None)
        assert response["DeleteResult"]["Error"]["Key"] == object_key_1
        assert response["DeleteResult"]["Error"]["Code"] == "AccessDenied"
        assert response["DeleteResult"]["Deleted"]["Key"] == object_key_2
        snapshot.match("multi-delete-with-requests", response)

        response = s3_client.list_objects(Bucket=bucket_name)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        assert len(response["Contents"]) == 1
        snapshot.match("list-remaining-objects", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..DeleteResult.Deleted..VersionId",
            "$..Prefix",
        ]
    )
    def test_s3_batch_delete_public_objects_using_requests(
        self, s3_client, s3_create_bucket, snapshot
    ):
        # only "public" created objects can be deleted by anonymous clients
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee-predefined-groups
        snapshot.add_transformer(snapshot.transform.s3_api())
        bucket_name = f"bucket-{short_uid()}"
        object_key_1 = "key-created-by-anonymous-1"
        object_key_2 = "key-created-by-anonymous-2"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read-write")
        anon = _anon_client("s3")
        anon.put_object(
            Bucket=bucket_name, Key=object_key_1, Body="This body document", ACL="public-read-write"
        )
        anon.put_object(
            Bucket=bucket_name,
            Key=object_key_2,
            Body="This body document #2",
            ACL="public-read-write",
        )

        # TODO delete does currently not work with S3_VIRTUAL_HOSTNAME
        url = f"{_bucket_url(bucket_name, localstack_host=config.LOCALSTACK_HOSTNAME)}?delete"

        data = f"""
            <Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Object>
                <Key>{object_key_1}</Key>
              </Object>
              <Object>
                <Key>{object_key_2}</Key>
              </Object>
            </Delete>
            """

        md = hashlib.md5(data.encode("utf-8")).digest()
        contents_md5 = base64.b64encode(md).decode("utf-8")
        header = {"content-md5": contents_md5, "x-amz-request-payer": "requester"}
        r = requests.post(url=url, data=data, headers=header)

        assert 200 == r.status_code
        response = xmltodict.parse(r.content)
        # TODO: why is that under??
        if LEGACY_S3_PROVIDER:
            response["DeleteResult"].pop("@xmlns")

        snapshot.match("multi-delete-with-requests", response)

        response = s3_client.list_objects(Bucket=bucket_name)
        snapshot.match("list-remaining-objects", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Prefix",
        ]
    )
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, path="$..Deleted..VersionId")
    def test_s3_batch_delete_objects(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("Key"))
        delete_object = []
        for _ in range(5):
            key_name = f"key-batch-delete-{short_uid()}"
            s3_client.put_object(Bucket=s3_bucket, Key=key_name, Body="This body document")
            delete_object.append({"Key": key_name})

        response = s3_client.delete_objects(Bucket=s3_bucket, Delete={"Objects": delete_object})
        snapshot.match("batch-delete", response)

        response = s3_client.list_objects(Bucket=s3_bucket)
        snapshot.match("list-remaining-objects", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..VersionId"])
    def test_s3_get_object_header_overrides(self, s3_client, s3_bucket, snapshot):
        # Signed requests may include certain header overrides in the querystring
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
        object_key = "key-header-overrides"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        expiry_date = "Wed, 21 Oct 2015 07:28:00 GMT"
        response = s3_client.get_object(
            Bucket=s3_bucket,
            Key=object_key,
            ResponseCacheControl="max-age=74",
            ResponseContentDisposition='attachment; filename="foo.jpg"',
            ResponseContentEncoding="identity",
            ResponseContentLanguage="de-DE",
            ResponseContentType="image/jpeg",
            ResponseExpires=expiry_date,
        )
        snapshot.match("get-object", response)

    @pytest.mark.only_localstack
    @pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="Testing new ASF handler behaviour")
    def test_virtual_host_proxying_headers(self, s3_client, s3_bucket):
        # forwarding requests from virtual host to path addressed will double add server specific headers
        # (date and server). Verify that those are not double added after a fix to the proxy
        key = "test-double-headers"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body="test-headers", ACL="public-read")

        key_url = f"{_bucket_url(bucket_name=s3_bucket)}/{key}"
        response = requests.get(key_url)
        assert response.headers["server"]

        key_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{key}"
        proxied_response = requests.get(key_url)
        assert proxied_response.headers["server"] == response.headers["server"]
        assert len(proxied_response.headers["server"].split(",")) == 1
        assert len(proxied_response.headers["date"].split(",")) == 2  # coma in the date


class TestS3TerraformRawRequests:
    @pytest.mark.only_localstack
    def test_terraform_request_sequence(self):

        reqs = load_file(os.path.join(os.path.dirname(__file__), "../files", "s3.requests.txt"))
        reqs = reqs.split("---")

        for req in reqs:
            header, _, body = req.strip().partition("\n\n")
            req, _, headers = header.strip().partition("\n")
            headers = {h.split(":")[0]: h.partition(":")[2].strip() for h in headers.split("\n")}
            method, path, _ = req.split(" ")
            url = f"{config.get_edge_url()}{path}"
            result = requests.request(method=method, url=url, data=body, headers=headers)
            assert result.status_code < 400


class TestS3PresignedUrl:
    """
    These tests pertain to S3's presigned URL feature.
    """

    # # Note: This test may have side effects (via `s3_client.meta.events.register(..)`) and
    # # may not be suitable for parallel execution
    @pytest.mark.aws_validated
    def test_presign_with_additional_query_params(
        self, s3_client, s3_bucket, patch_s3_skip_signature_validation_false
    ):
        """related to issue: https://github.com/localstack/localstack/issues/4133"""

        def add_query_param(request, **kwargs):
            request.url += "?requestedBy=abcDEF123"

        s3_client.put_object(Body="test-value", Bucket=s3_bucket, Key="test")
        s3_presigned_client = _s3_client_custom_config(
            Config(signature_version="s3v4"),
            endpoint_url=_endpoint_url(),
        )
        s3_presigned_client.meta.events.register("before-sign.s3.GetObject", add_query_param)
        try:
            presign_url = s3_presigned_client.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": s3_bucket, "Key": "test"},
                ExpiresIn=86400,
            )
            assert "requestedBy=abcDEF123" in presign_url
            response = requests.get(presign_url)
            assert b"test-value" == response._content
        finally:
            s3_presigned_client.meta.events.unregister("before-sign.s3.GetObject", add_query_param)

    @pytest.mark.only_localstack
    @pytest.mark.xfail(
        condition=not LEGACY_S3_PROVIDER,
        reason="failing for ASF provider, will be fixed in separate PR",
    )
    def test_presign_check_signature_validation_for_port_permutation(
        self, s3_client, s3_bucket, patch_s3_skip_signature_validation_false
    ):
        port1 = 443
        port2 = config.EDGE_PORT
        endpoint = (
            f"http://{config.LOCALSTACK_HOSTNAME}:{port1}"  # .replace(f":{port2}", f":{port1}")
        )
        s3_presign = _s3_client_custom_config(
            Config(signature_version="s3v4"),
            endpoint_url=endpoint,
        )

        s3_client.put_object(Body="test-value", Bucket=s3_bucket, Key="test")

        presign_url = s3_presign.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": s3_bucket, "Key": "test"},
            ExpiresIn=86400,
        )
        assert f":{port1}" in presign_url
        presign_url = presign_url.replace(f":{port1}", f":{port2}")

        response = requests.get(presign_url)
        assert b"test-value" == response._content

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..VersionId", "$..ContentLanguage", "$..Expires"]
    )
    def test_put_object(self, s3_client, s3_bucket, snapshot):
        # big bug here in the old provider: PutObject gets the Expires param from the presigned url??
        #  when it's supposed to be in the headers?
        snapshot.add_transformer(snapshot.transform.s3_api())

        key = "my-key"

        url = s3_client.generate_presigned_url(
            "put_object", Params={"Bucket": s3_bucket, "Key": key}
        )
        requests.put(url, data="something", verify=False)

        response = s3_client.get_object(Bucket=s3_bucket, Key=key)
        assert response["Body"].read() == b"something"
        snapshot.match("get_object", response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="failing sporadically with new HTTP gateway (only in CI)",
    )
    def test_post_object_with_files(self, s3_client, s3_bucket):
        object_key = "test-presigned-post-key"

        body = (
            b"0" * 70_000
        )  # make sure the payload size is large to force chunking in our internal implementation

        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket,
            Key=object_key,
            ExpiresIn=60,
            Conditions=[{"bucket": s3_bucket}],
        )
        # put object
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": body},
            verify=False,
        )
        assert response.status_code == 204

        # get object and compare results
        downloaded_object = s3_client.get_object(Bucket=s3_bucket, Key=object_key)
        assert downloaded_object["Body"].read() == body

    @pytest.mark.aws_validated
    # old provider does not raise the right exception
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    def test_post_request_expires(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        # presign a post with a short expiry time
        object_key = "test-presigned-post-key"

        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket, Key=object_key, ExpiresIn=2
        )

        # sleep so it expires
        time.sleep(3)

        # attempt to use the presigned request
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": "file content"},
            verify=False,
        )

        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("exception", exception)
        assert response.status_code in [400, 403]

    @pytest.mark.only_localstack
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER,
        reason="Legacy S3 provider does not skip the signature validation",
    )
    def test_get_request_expires_ignored_if_validation_disabled(
        self, s3_client, s3_bucket, monkeypatch, patch_s3_skip_signature_validation_false
    ):
        s3_client.put_object(Body="test-value", Bucket=s3_bucket, Key="test")

        presigned_request = s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": s3_bucket, "Key": "test"},
            ExpiresIn=2,
        )
        # sleep so it expires
        time.sleep(3)

        # attempt to use the presigned request
        response = requests.get(presigned_request)
        # response should not be successful as it is expired -> signature will not match
        # "SignatureDoesNotMatch" in str(response.content)
        assert response.status_code in [400, 403]

        # set skip signature validation to True -> the request should now work
        monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", True)
        response = requests.get(presigned_request)
        assert response.status_code == 200
        assert b"test-value" == response.content

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER, reason="Policy is not validated in legacy provider"
    )
    @pytest.mark.parametrize(
        "signature_version",
        ["s3", "s3v4"],
    )
    def test_post_request_malformed_policy(
        self,
        s3_client,
        s3_bucket,
        snapshot,
        signature_version,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        object_key = "test-presigned-malformed-policy"

        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )

        presigned_request = presigned_client.generate_presigned_post(
            Bucket=s3_bucket, Key=object_key, ExpiresIn=60
        )

        # modify the base64 string to be wrong
        original_policy = presigned_request["fields"]["policy"]
        presigned_request["fields"]["policy"] = original_policy[:-2]

        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": "file content"},
            verify=False,
        )
        # the policy has been modified, so the signature does not correspond
        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("exception-policy", exception)
        # assert fields that snapshot cannot match
        signature_field = "signature" if signature_version == "s3" else "x-amz-signature"
        assert (
            exception["Error"]["SignatureProvided"] == presigned_request["fields"][signature_field]
        )
        assert exception["Error"]["StringToSign"] == presigned_request["fields"]["policy"]

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER, reason="Signature is not validated in legacy provider"
    )
    @pytest.mark.parametrize(
        "signature_version",
        ["s3", "s3v4"],
    )
    def test_post_request_missing_signature(
        self,
        s3_client,
        s3_bucket,
        snapshot,
        signature_version,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        object_key = "test-presigned-missing-signature"

        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )

        presigned_request = presigned_client.generate_presigned_post(
            Bucket=s3_bucket, Key=object_key, ExpiresIn=60
        )

        # remove the signature field
        signature_field = "signature" if signature_version == "s3" else "x-amz-signature"
        presigned_request["fields"].pop(signature_field)

        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": "file content"},
            verify=False,
        )

        # AWS seems to detected what kind of signature is missing from the policy fields
        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("exception-missing-signature", exception)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        condition=LEGACY_S3_PROVIDER, reason="Policy is not validated in legacy provider"
    )
    @pytest.mark.parametrize(
        "signature_version",
        ["s3", "s3v4"],
    )
    def test_post_request_missing_fields(
        self,
        s3_client,
        s3_bucket,
        snapshot,
        signature_version,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        object_key = "test-presigned-missing-fields"

        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )

        presigned_request = presigned_client.generate_presigned_post(
            Bucket=s3_bucket, Key=object_key, ExpiresIn=60
        )

        # remove some signature related fields
        if signature_version == "s3":
            presigned_request["fields"].pop("AWSAccessKeyId")
        else:
            presigned_request["fields"].pop("x-amz-algorithm")
            presigned_request["fields"].pop("x-amz-credential")

        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": "file content"},
            verify=False,
        )

        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("exception-missing-fields", exception)

        # pop everything else to see what exception comes back
        presigned_request["fields"] = {
            k: v for k, v in presigned_request["fields"].items() if k in ("key", "policy")
        }
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files={"file": "file content"},
            verify=False,
        )

        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("exception-no-sig-related-fields", exception)

    @pytest.mark.aws_validated
    def test_delete_has_empty_content_length_header(self, s3_client, s3_bucket):
        for encoding in None, "gzip":
            # put object
            object_key = "key-by-hostname"
            s3_client.put_object(
                Bucket=s3_bucket,
                Key=object_key,
                Body="something",
                ContentType="text/html; charset=utf-8",
            )
            url = s3_client.generate_presigned_url(
                "delete_object", Params={"Bucket": s3_bucket, "Key": object_key}
            )

            # get object and assert headers
            headers = {}
            if encoding:
                headers["Accept-Encoding"] = encoding
            response = requests.delete(url, headers=headers, verify=False)
            assert not response.content
            assert response.status_code == 204
            # AWS does not send a content-length header at all, legacy localstack sends a 0 length header
            assert response.headers.get("content-length") in [
                "0",
                None,
            ], f"Unexpected content-length in headers {response.headers}"

    @pytest.mark.aws_validated
    def test_head_has_correct_content_length_header(self, s3_client, s3_bucket):
        body = "something body \n \n\r"
        # put object
        object_key = "key-by-hostname"
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=object_key,
            Body=body,
            ContentType="text/html; charset=utf-8",
        )
        url = s3_client.generate_presigned_url(
            "head_object", Params={"Bucket": s3_bucket, "Key": object_key}
        )
        # get object and assert headers
        response = requests.head(url, verify=False)
        assert response.headers.get("content-length") == str(len(body))

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Expires", "$..AcceptRanges"])
    def test_put_url_metadata(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # Object metadata should be passed as query params via presigned URL
        # https://github.com/localstack/localstack/issues/544
        metadata = {"foo": "bar"}
        object_key = "key-by-hostname"

        # put object via presigned URL
        url = s3_client.generate_presigned_url(
            "put_object",
            Params={"Bucket": s3_bucket, "Key": object_key, "Metadata": metadata},
        )
        assert "x-amz-meta-foo=bar" in url

        response = requests.put(url, data="content 123", verify=False)
        assert response.ok, f"response returned {response.status_code}: {response.text}"
        # response body should be empty, see https://github.com/localstack/localstack/issues/1317
        assert not response.text

        # assert metadata is present
        response = s3_client.head_object(Bucket=s3_bucket, Key=object_key)
        assert response.get("Metadata", {}).get("foo") == "bar"
        snapshot.match("head_object", response)

    @pytest.mark.aws_validated
    def test_get_object_ignores_request_body(self, s3_client, s3_bucket):
        key = "foo-key"
        body = "foobar"

        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=body)

        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": key}
        )

        response = requests.get(url, data=b"get body is ignored by AWS")
        assert response.status_code == 200
        assert response.text == body

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "signature_version, verify_signature",
        [
            ("s3", True),
            ("s3", False),
            ("s3v4", True),
            ("s3v4", False),
        ],
    )
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    def test_put_object_with_md5_and_chunk_signature_bad_headers(
        self,
        s3_client,
        s3_create_bucket,
        signature_version,
        verify_signature,
        monkeypatch,
        snapshot,
    ):

        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        snapshotted = False
        if verify_signature:
            monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", False)
            snapshotted = True
        else:
            monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", True)

        bucket_name = f"bucket-{short_uid()}"
        object_key = "test-runtime.properties"
        content_md5 = "pX8KKuGXS1f2VTcuJpqjkw=="
        headers = {
            "Content-Md5": content_md5,
            "Content-Type": "application/octet-stream",
            "X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "X-Amz-Date": "20211122T191045Z",
            "X-Amz-Decoded-Content-Length": "test",  # string instead of int
            "Content-Length": "10",
            "Connection": "Keep-Alive",
            "Expect": "100-continue",
        }

        s3_create_bucket(Bucket=bucket_name)
        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )
        url = presigned_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": "application/octet-stream",
                "ContentMD5": content_md5,
            },
        )
        result = requests.put(url, data="test", headers=headers)
        assert result.status_code == 403
        if snapshotted:
            exception = xmltodict.parse(result.content)
            snapshot.match("with-decoded-content-length", exception)

        # old provider does not raise the right error message
        if LEGACY_S3_PROVIDER or signature_version == "s3":
            assert b"SignatureDoesNotMatch" in result.content
        # we are either using s3v4 with new provider or whichever signature against AWS
        else:
            assert b"AccessDenied" in result.content

        # check also no X-Amz-Decoded-Content-Length
        headers.pop("X-Amz-Decoded-Content-Length")
        result = requests.put(url, data="test", headers=headers)
        assert result.status_code == 403, (result, result.content)
        if snapshotted:
            exception = xmltodict.parse(result.content)
            snapshot.match("without-decoded-content-length", exception)
        if LEGACY_S3_PROVIDER or signature_version == "s3":
            assert b"SignatureDoesNotMatch" in result.content
        else:
            assert b"AccessDenied" in result.content

    @pytest.mark.aws_validated
    def test_s3_get_response_default_content_type(self, s3_client, s3_bucket):
        # When no content type is provided by a PUT request
        # 'binary/octet-stream' should be used
        # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html

        # put object
        object_key = "key-by-hostname"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}
        )
        response = requests.get(url, verify=False)
        assert response.headers["content-type"] == "binary/octet-stream"

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("signature_version", ["s3", "s3v4"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        path=["$..Error.Expires"],
    )
    def test_s3_presigned_url_expired(
        self,
        s3_bucket,
        s3_client,
        signature_version,
        snapshot,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))

        object_key = "key-expires-in-2"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )
        url = presigned_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}, ExpiresIn=2
        )
        # retrieving it before expiry
        resp = requests.get(url, verify=False)
        assert resp.status_code == 200
        assert to_str(resp.content) == "something"

        time.sleep(3)  # wait for the URL to expire
        resp = requests.get(url, verify=False)
        resp_content = to_str(resp.content)
        assert resp.status_code == 403
        exception = xmltodict.parse(resp.content)
        snapshot.match("expired-exception", exception)

        assert "<Code>AccessDenied</Code>" in resp_content
        assert "<Message>Request has expired</Message>" in resp_content

        url = presigned_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": s3_bucket, "Key": object_key},
            ExpiresIn=120,
        )

        resp = requests.get(url, verify=False)
        assert resp.status_code == 200
        assert to_str(resp.content) == "something"

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("signature_version", ["s3", "s3v4"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        path=["$..Error.Message"],
    )
    def test_s3_put_presigned_url_with_different_headers(
        self,
        s3_bucket,
        s3_client,
        signature_version,
        snapshot,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))

        object_key = "key-double-header-param"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )
        # Content-Type, Content-MD5 and Date are specific headers for SigV2 and are checked
        # others are not verified in the signature
        # Manually set the content-type for it to be added to the signature
        presigned_url = presigned_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": s3_bucket,
                "Key": object_key,
                "ContentType": "text/plain",
            },
            ExpiresIn=10,
        )
        # Use the pre-signed URL with the right ContentType
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"Content-Type": "text/plain"},
        )
        assert not response.content
        assert response.status_code == 200

        # Use the pre-signed URL with the wrong ContentType
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"Content-Type": "text/xml"},
        )
        assert response.status_code == 403

        exception = xmltodict.parse(response.content)
        exception["StatusCode"] = response.status_code
        snapshot.match("content-type-exception", exception)

        if signature_version == "s3":
            # we sleep 1 second to allow the StringToSign value in the exception change between both call
            # (timestamped value, to avoid the test being flaky)
            time.sleep(1.1)

        # regenerate a new pre-signed URL with no content-type specified
        presigned_url = presigned_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": s3_bucket,
                "Key": object_key,
                "ContentEncoding": "identity",
            },
            ExpiresIn=10,
        )

        # send the pre-signed URL with the right ContentEncoding
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"Content-Encoding": "identity"},
        )
        assert not response.content
        assert response.status_code == 200

        # send the pre-signed URL with the right ContentEncoding but a new ContentType
        # should fail with SigV2 and succeed with SigV4
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"Content-Encoding": "identity", "Content-Type": "text/xml"},
        )
        if not is_old_provider() and signature_version == "s3":
            assert response.status_code == 403
        else:
            assert response.status_code == 200

        exception = xmltodict.parse(response.content) if response.content else {}
        exception["StatusCode"] = response.status_code
        snapshot.match("content-type-response", exception)

        # now send the pre-signed URL with the wrong ContentEncoding
        # should succeed with SigV2 as only hard coded headers are checked
        # but fail with SigV4 as Content-Encoding was part of the signed headers
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"Content-Encoding": "gzip"},
        )
        if signature_version == "s3":
            assert response.status_code == 200
        else:
            assert response.status_code == 403
        exception = xmltodict.parse(response.content) if response.content else {}
        exception["StatusCode"] = response.status_code
        snapshot.match("wrong-content-encoding-response", exception)

    @pytest.mark.aws_validated
    def test_s3_put_presigned_url_same_header_and_qs_parameter(
        self, s3_bucket, s3_client, snapshot, patch_s3_skip_signature_validation_false
    ):
        # this test tries to check if double query/header values trigger InvalidRequest like said in the documentation
        # spoiler: they do not
        # https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html#query-string-auth-v4-signing
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        if not is_aws_cloud():
            if LEGACY_S3_PROVIDER:
                pytest.xfail(reason="Legacy S3 provider does not implement the right behaviour")

        object_key = "key-double-header-param"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        presigned_client = _s3_client_custom_config(
            Config(signature_version="s3v4"),
            endpoint_url=_endpoint_url(),
        )
        presigned_url = presigned_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": s3_bucket,
                "Key": object_key,
                "RequestPayer": "requester",
            },
            ExpiresIn=10,
        )
        # add the same parameter as a query string parameter as well as header, with different values
        parsed = urlparse(presigned_url)
        query_params = parse_qs(parsed.query)
        # auth params needs to be at the end
        new_query_params = {"x-amz-request-payer": ["non-valid"]}
        for k, v in query_params.items():
            new_query_params[k] = v[0]

        new_query_params = urlencode(new_query_params, quote_via=quote, safe=" ")
        new_url = urlunsplit(
            SplitResult(  # noqa
                parsed.scheme, parsed.netloc, parsed.path, new_query_params, parsed.fragment
            )
        )
        response = requests.put(
            new_url,
            data="test_data",
            headers={"x-amz-request-payer": "requester"},
        )
        exception = xmltodict.parse(response.content) if response.content else {}
        exception["StatusCode"] = response.status_code
        snapshot.match("double-header-query-string", exception)

        # test overriding a signed query parameter
        response = requests.put(
            presigned_url,
            data="test_data",
            headers={"x-amz-expires": "5"},
        )
        exception = xmltodict.parse(response.content) if response.content else {}
        exception["StatusCode"] = response.status_code
        snapshot.match("override-signed-qs", exception)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("signature_version", ["s3", "s3v4"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Error.Code",
            "$..Error.Message",
            "$..StatusCode",
        ],
    )
    def test_s3_put_presigned_url_missing_sig_param(
        self,
        s3_bucket,
        s3_client,
        signature_version,
        snapshot,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))

        object_key = "key-missing-param"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version),
            endpoint_url=_endpoint_url(),
        )
        url = presigned_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}, ExpiresIn=5
        )
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # sig v2
        if "Signature" in query_params:
            query_params.pop("Expires", None)
        else:  # sig v4
            query_params.pop("X-Amz-Date", None)
        new_query_params = urlencode(
            {k: v[0] for k, v in query_params.items()}, quote_via=quote, safe=" "
        )

        invalid_url = urlunsplit(
            SplitResult(  # noqa
                parsed.scheme, parsed.netloc, parsed.path, new_query_params, parsed.fragment
            )
        )

        resp = requests.get(invalid_url, verify=False)
        assert resp.status_code in [
            400,
            403,
        ]  # the snapshot will differentiate between sig v2 and sig v4
        exception = xmltodict.parse(resp.content)
        exception["StatusCode"] = resp.status_code
        snapshot.match("missing-param-exception", exception)

    @pytest.mark.aws_validated
    def test_s3_get_response_content_type_same_as_upload_and_range(self, s3_client, s3_bucket):
        # put object
        object_key = "foo/bar/key-by-hostname"
        content_type = "foo/bar; charset=utf-8"
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=object_key,
            Body="something " * 20,
            ContentType=content_type,
        )

        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}
        )

        # get object and assert headers
        response = requests.get(url, verify=False)
        assert content_type == response.headers["content-type"]

        # get object using range query and assert headers
        response = requests.get(url, headers={"Range": "bytes=0-18"}, verify=False)
        assert content_type == response.headers["content-type"]
        # test we only get the first 18 bytes from the object
        assert "something something" == to_str(response.content)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="sporadically failing in CI: presigned-post does not set the body, and then etag is wrong"
    )
    def test_s3_presigned_post_success_action_status_201_response(self, s3_client, s3_bucket):
        # a security policy is required if the bucket is not publicly writable
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html#RESTObjectPOST-requests-form-fields
        body = "something body"
        # get presigned URL
        object_key = "key-${filename}"
        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket,
            Key=object_key,
            Fields={"success_action_status": "201"},
            Conditions=[{"bucket": s3_bucket}, ["eq", "$success_action_status", "201"]],
            ExpiresIn=60,
        )
        files = {"file": ("my-file", body)}
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files=files,
            verify=False,
        )

        assert response.status_code == 201
        json_response = xmltodict.parse(response.content)
        assert "PostResponse" in json_response
        json_response = json_response["PostResponse"]

        if LEGACY_S3_PROVIDER and not is_aws_cloud():
            # legacy provider is does not manage PostResponse adequately
            location = "http://localhost/key-my-file"
            etag = "d41d8cd98f00b204e9800998ecf8427f"
        else:
            location = f"{_bucket_url_vhost(s3_bucket, aws_stack.get_region())}/key-my-file"
            etag = '"43281e21fce675ac3bcb3524b38ca4ed"'
            assert response.headers["ETag"] == etag
            assert response.headers["Location"] == location

        assert json_response["Location"] == location
        assert json_response["Bucket"] == s3_bucket
        assert json_response["Key"] == "key-my-file"
        assert json_response["ETag"] == etag

    @pytest.mark.aws_validated
    @pytest.mark.xfail(condition=LEGACY_S3_PROVIDER, reason="not supported in legacy provider")
    def test_s3_presigned_post_success_action_redirect(self, s3_client, s3_bucket):
        # a security policy is required if the bucket is not publicly writable
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html#RESTObjectPOST-requests-form-fields
        body = "something body"
        # get presigned URL
        object_key = "key-test"
        redirect_location = "http://localhost.test/random"
        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket,
            Key=object_key,
            Fields={"success_action_redirect": redirect_location},
            Conditions=[
                {"bucket": s3_bucket},
                ["eq", "$success_action_redirect", redirect_location],
            ],
            ExpiresIn=60,
        )
        files = {"file": ("my-file", body)}
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files=files,
            verify=False,
            allow_redirects=False,
        )

        assert response.status_code == 303
        assert not response.text
        location = urlparse(response.headers["Location"])
        location_qs = parse_qs(location.query)
        assert location_qs["key"][0] == object_key
        assert location_qs["bucket"][0] == s3_bucket
        # TODO requests.post has known issues when running in CI -> sometimes the body is empty, etag is therefore different
        #  assert location_qs["etag"][0] == '"43281e21fce675ac3bcb3524b38ca4ed"'

        # If S3 cannot interpret the URL, it acts as if the field is not present.
        wrong_redirect = "/wrong/redirect/relative"
        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket,
            Key=object_key,
            Fields={"success_action_redirect": wrong_redirect},
            Conditions=[
                {"bucket": s3_bucket},
                ["eq", "$success_action_redirect", wrong_redirect],
            ],
            ExpiresIn=60,
        )
        response = requests.post(
            presigned_request["url"],
            data=presigned_request["fields"],
            files=files,
            verify=False,
            allow_redirects=False,
        )
        assert response.status_code == 204

    @pytest.mark.aws_validated
    def test_presigned_url_with_session_token(
        self, sts_client, s3_create_bucket_with_client, patch_s3_skip_signature_validation_false
    ):
        bucket_name = f"bucket-{short_uid()}"
        key_name = "key"
        response = sts_client.get_session_token()
        if not is_aws_cloud():
            # moto does not respect credentials passed, and will always set hard coded values from a template here
            # until this can be used, we are hardcoding the AccessKeyId and SecretAccessKey
            response["Credentials"]["AccessKeyId"] = "test"
            response["Credentials"]["SecretAccessKey"] = "test"

        client = boto3.client(
            "s3",
            config=Config(signature_version="s3v4"),
            endpoint_url=_endpoint_url(),
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        s3_create_bucket_with_client(s3_client=client, Bucket=bucket_name)
        client.put_object(Body="test-value", Bucket=bucket_name, Key=key_name)
        presigned_url = client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket_name, "Key": key_name},
            ExpiresIn=600,
        )
        response = requests.get(presigned_url)
        assert response._content == b"test-value"

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("signature_version", ["s3", "s3v4"])
    def test_s3_get_response_header_overrides(
        self, s3_client, s3_bucket, signature_version, patch_s3_skip_signature_validation_false
    ):
        # Signed requests may include certain header overrides in the querystring
        # https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
        object_key = "key-header-overrides"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        expiry_date = "Wed, 21 Oct 2015 07:28:00 GMT"
        presigned_client = _s3_client_custom_config(
            Config(signature_version=signature_version), endpoint_url=_endpoint_url()
        )

        url = presigned_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": s3_bucket,
                "Key": object_key,
                "ResponseCacheControl": "max-age=74",
                "ResponseContentDisposition": 'attachment; filename="foo.jpg"',
                "ResponseContentEncoding": "identity",
                "ResponseContentLanguage": "de-DE",
                "ResponseContentType": "image/jpeg",
                "ResponseExpires": expiry_date,
            },
        )
        response = requests.get(url, verify=False)
        assert response.status_code == 200
        headers = response.headers
        assert headers["cache-control"] == "max-age=74"
        assert headers["content-disposition"] == 'attachment; filename="foo.jpg"'
        assert headers["content-encoding"] == "identity"
        assert headers["content-language"] == "de-DE"
        assert headers["content-type"] == "image/jpeg"

        # Note: looks like depending on the environment/libraries, we can get different date formats...
        possible_date_formats = ["2015-10-21T07:28:00Z", expiry_date]
        assert headers["expires"] in possible_date_formats

    @pytest.mark.aws_validated
    def test_s3_copy_md5(self, s3_client, s3_bucket, snapshot, s3_presigned_client, monkeypatch):
        if not is_aws_cloud() and not LEGACY_S3_PROVIDER:
            monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", False)
        src_key = "src"
        s3_client.put_object(Bucket=s3_bucket, Key=src_key, Body="something")

        # copy object
        dest_key = "dest"
        response = s3_client.copy_object(
            Bucket=s3_bucket,
            CopySource={"Bucket": s3_bucket, "Key": src_key},
            Key=dest_key,
        )
        snapshot.match("copy-obj", response)

        # Create copy object to try to match s3a setting Content-MD5
        dest_key2 = "dest"
        url = s3_presigned_client.generate_presigned_url(
            "copy_object",
            Params={
                "Bucket": s3_bucket,
                "CopySource": {"Bucket": s3_bucket, "Key": src_key},
                "Key": dest_key2,
            },
        )

        request_response = requests.put(url, verify=False)
        assert request_response.status_code == 200

    @pytest.mark.only_localstack
    @pytest.mark.parametrize("case_sensitive_headers", [True, False])
    def test_s3_get_response_case_sensitive_headers(
        self, s3_client, s3_bucket, case_sensitive_headers
    ):
        # Test that RETURN_CASE_SENSITIVE_HEADERS is respected
        object_key = "key-by-hostname"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        case_sensitive_before = http2_server.RETURN_CASE_SENSITIVE_HEADERS
        try:
            url = s3_client.generate_presigned_url(
                "get_object", Params={"Bucket": s3_bucket, "Key": object_key}
            )
            http2_server.RETURN_CASE_SENSITIVE_HEADERS = case_sensitive_headers
            response = requests.get(url, verify=False)
            # expect that Etag is contained
            header_names = list(response.headers.keys())
            expected_etag = "ETag" if case_sensitive_headers else "etag"
            assert expected_etag in header_names
        finally:
            http2_server.RETURN_CASE_SENSITIVE_HEADERS = case_sensitive_before

    @pytest.mark.parametrize(
        "signature_version, use_virtual_address",
        [
            ("s3", False),
            ("s3", True),
            ("s3v4", False),
            ("s3v4", True),
        ],
    )
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        path=["$..Error.Expires"],
    )
    def test_presigned_url_signature_authentication_expired(
        self,
        s3_client,
        s3_create_bucket,
        signature_version,
        use_virtual_address,
        snapshot,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        bucket_name = f"presign-{short_uid()}"

        s3_endpoint_path_style = _endpoint_url()

        s3_create_bucket(Bucket=bucket_name)
        object_key = "temp.txt"
        s3_client.put_object(Key=object_key, Bucket=bucket_name, Body="123")

        s3_config = {"addressing_style": "virtual"} if use_virtual_address else {}
        client = _s3_client_custom_config(
            Config(signature_version=signature_version, s3=s3_config),
            endpoint_url=s3_endpoint_path_style,
        )

        url = _generate_presigned_url(client, {"Bucket": bucket_name, "Key": object_key}, expires=1)
        time.sleep(2)
        response = requests.get(url)
        assert response.status_code == 403
        exception = xmltodict.parse(response.content)
        snapshot.match("expired", exception)

    @pytest.mark.parametrize(
        "signature_version, use_virtual_address",
        [
            ("s3", False),
            ("s3", True),
            ("s3v4", False),
            ("s3v4", True),
        ],
    )
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        path=["$..Error.Expires"],
    )
    def test_presigned_url_signature_authentication(
        self,
        s3_client,
        s3_create_bucket,
        signature_version,
        use_virtual_address,
        snapshot,
        patch_s3_skip_signature_validation_false,
    ):
        snapshot.add_transformer(self._get_presigned_snapshot_transformers(snapshot))
        bucket_name = f"presign-{short_uid()}"

        s3_endpoint_path_style = _endpoint_url()
        s3_url = _bucket_url_vhost(bucket_name) if use_virtual_address else _bucket_url(bucket_name)

        s3_create_bucket(Bucket=bucket_name)
        object_key = "temp.txt"
        s3_client.put_object(Key=object_key, Bucket=bucket_name, Body="123")

        s3_config = {"addressing_style": "virtual"} if use_virtual_address else {}
        client = _s3_client_custom_config(
            Config(signature_version=signature_version, s3=s3_config),
            endpoint_url=s3_endpoint_path_style,
        )

        expires = 20

        # GET requests
        simple_params = {"Bucket": bucket_name, "Key": object_key}
        url = _generate_presigned_url(client, simple_params, expires)
        response = requests.get(url)
        assert response.status_code == 200
        assert response.content == b"123"

        params = {
            "Bucket": bucket_name,
            "Key": object_key,
            "ResponseContentType": "text/plain",
            "ResponseContentDisposition": "attachment;  filename=test.txt",
        }

        presigned = _generate_presigned_url(client, params, expires)
        response = requests.get(presigned)
        assert response.status_code == 200
        assert response.content == b"123"

        object_data = f"this should be found in when you download {object_key}."

        # invalid requests
        response = requests.get(
            _make_url_invalid(s3_url, object_key, presigned),
            data=object_data,
            headers={"Content-Type": "my-fake-content/type"},
        )
        assert response.status_code == 403
        exception = xmltodict.parse(response.content)
        snapshot.match("invalid-get-1", exception)

        # put object valid
        response = requests.put(
            _generate_presigned_url(client, simple_params, expires, client_method="put_object"),
            data=object_data,
        )
        # body should be empty, and it will show us the exception if it's not
        assert not response.content
        assert response.status_code == 200

        params = {
            "Bucket": bucket_name,
            "Key": object_key,
            "ContentType": "text/plain",
        }
        presigned_put_url = _generate_presigned_url(
            client, params, expires, client_method="put_object"
        )
        response = requests.put(
            presigned_put_url,
            data=object_data,
            headers={"Content-Type": "text/plain"},
        )
        assert not response.content
        assert response.status_code == 200

        # Invalid request
        response = requests.put(
            _make_url_invalid(s3_url, object_key, presigned_put_url),
            data=object_data,
            headers={"Content-Type": "my-fake-content/type"},
        )
        assert response.status_code == 403
        exception = xmltodict.parse(response.content)
        snapshot.match("invalid-put-1", exception)

        # DELETE requests
        presigned_delete_url = _generate_presigned_url(
            client, simple_params, expires, client_method="delete_object"
        )
        response = requests.delete(presigned_delete_url)
        assert response.status_code == 204

    @pytest.mark.parametrize(
        "signature_version, use_virtual_address",
        [
            ("s3", False),
            ("s3", True),
            ("s3v4", False),
            ("s3v4", True),
        ],
    )
    @pytest.mark.aws_validated
    def test_presigned_url_signature_authentication_multi_part(
        self,
        s3_client,
        s3_create_bucket,
        signature_version,
        use_virtual_address,
        patch_s3_skip_signature_validation_false,
    ):
        # it should test if the user is sending wrong signature
        bucket_name = f"presign-{short_uid()}"

        s3_endpoint_path_style = _endpoint_url()

        s3_create_bucket(Bucket=bucket_name)
        object_key = "temp.txt"

        s3_config = {"addressing_style": "virtual"} if use_virtual_address else {}
        client = _s3_client_custom_config(
            Config(signature_version=signature_version, s3=s3_config),
            endpoint_url=s3_endpoint_path_style,
        )
        upload_id = client.create_multipart_upload(
            Bucket=bucket_name,
            Key=object_key,
        )["UploadId"]

        data = to_bytes("hello this is a upload test")
        upload_file_object = BytesIO(data)

        signed_url = _generate_presigned_url(
            client,
            {
                "Bucket": bucket_name,
                "Key": object_key,
                "UploadId": upload_id,
                "PartNumber": 1,
            },
            expires=4,
            client_method="upload_part",
        )

        response = requests.put(signed_url, data=upload_file_object)
        assert response.status_code == 200
        multipart_upload_parts = [{"ETag": response.headers["ETag"], "PartNumber": 1}]

        response = client.complete_multipart_upload(
            Bucket=bucket_name,
            Key=object_key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        simple_params = {"Bucket": bucket_name, "Key": object_key}
        response = requests.get(_generate_presigned_url(client, simple_params, 4))
        assert response.status_code == 200
        assert response.content == data

    @staticmethod
    def _get_presigned_snapshot_transformers(snapshot):
        return [
            snapshot.transform.key_value("AWSAccessKeyId"),
            snapshot.transform.key_value("HostId", reference_replacement=False),
            snapshot.transform.key_value("RequestId"),
            snapshot.transform.key_value("SignatureProvided"),
            snapshot.transform.jsonpath(
                "$..Error.StringToSign",
                value_replacement="<string-to-sign>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value("StringToSignBytes"),
            snapshot.transform.jsonpath(
                "$..Error.CanonicalRequest",
                value_replacement="<canonical-request>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value("CanonicalRequestBytes"),
        ]


@pytest.mark.skipif(
    condition=is_asf_provider(),
    reason="ASF provider is tested in test_s3_cors.py, this will be deprecated",
)
class TestS3Cors:
    @pytest.mark.aws_validated
    # TODO x-amzn-requestid should be 'x-amz-request-id'
    # TODO "Vary" contains more in AWS, other params are added additional in LocalStack
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Access-Control-Allow-Headers",
            "$..Connection",
            "$..Location",
            "$..Vary",
            "$..Content-Type",
            "$..x-amzn-requestid",
            "$..last-modified",
            "$..Last-Modified",
        ]
    )
    def test_cors_with_allowed_origins(self, s3_client, s3_create_bucket, snapshot, monkeypatch):
        monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", False)
        snapshot.add_transformer(self._get_cors_result_header_snapshot_transformer(snapshot))
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["https://localhost:4200"],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        bucket_name = f"bucket-{short_uid()}"
        object_key = "424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf"
        s3_create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        # create signed url
        url = s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": "application/pdf",
                "ACL": "bucket-owner-full-control",
            },
            ExpiresIn=3600,
        )
        result = requests.put(
            url,
            data="something",
            verify=False,
            headers={
                "Origin": "https://localhost:4200",
                "Content-Type": "application/pdf",
            },
        )
        assert result.status_code == 200
        # result.headers is type CaseInsensitiveDict and needs to be converted first
        snapshot.match("raw-response-headers", dict(result.headers))

        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [
                        "https://localhost:4200",
                        "https://localhost:4201",
                    ],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        # create signed url
        url = s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": "application/pdf",
                "ACL": "bucket-owner-full-control",
            },
            ExpiresIn=3600,
        )

        # mimic chrome behavior, sending OPTIONS request first for strict-origin-when-cross-origin
        result = requests.options(
            url,
            headers={
                "Origin": "https://localhost:4200",
                "Access-Control-Request-Method": "PUT",
            },
        )
        snapshot.match("raw-response-headers-2", dict(result.headers))

        result = requests.put(
            url,
            data="something",
            verify=False,
            headers={
                "Origin": "https://localhost:4200",
                "Content-Type": "application/pdf",
            },
        )
        assert result.status_code == 200
        snapshot.match("raw-response-headers-3", dict(result.headers))

        result = requests.put(
            url,
            data="something",
            verify=False,
            headers={
                "Origin": "https://localhost:4201",
                "Content-Type": "application/pdf",
            },
        )
        assert result.status_code == 200
        snapshot.match("raw-response-headers-4", dict(result.headers))

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Access-Control-Allow-Headers",
            "$..Connection",
            "$..Location",
            "$..Vary",
            "$..Content-Type",
            "$..x-amzn-requestid",
            "$..last-modified",
            "$..accept-ranges",
            "$..content-language",
            "$..content-md5",
            "$..content-type",
            "$..x-amz-version-id",
            "$..Last-Modified",
            "$..Accept-Ranges",
            "$..raw-response-headers-2.Access-Control-Allow-Credentials",
        ]
    )
    def test_cors_configurations(self, s3_client, s3_create_bucket, monkeypatch, snapshot):
        monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", False)
        snapshot.add_transformer(self._get_cors_result_header_snapshot_transformer(snapshot))

        bucket = f"test-cors-{short_uid()}"
        object_key = "index.html"

        url = "{}/{}".format(_bucket_url(bucket), object_key)

        BUCKET_CORS_CONFIG = {
            "CORSRules": [
                {
                    "AllowedOrigins": [config.get_edge_url()],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["x-amz-tagging"],
                }
            ]
        }

        s3_create_bucket(Bucket=bucket, ACL="public-read")
        s3_client.put_bucket_cors(Bucket=bucket, CORSConfiguration=BUCKET_CORS_CONFIG)

        s3_client.put_object(
            Bucket=bucket, Key=object_key, Body="<h1>Index</html>", ACL="public-read"
        )

        response = requests.get(
            url, headers={"Origin": config.get_edge_url(), "Content-Type": "text/html"}
        )
        assert 200 == response.status_code

        snapshot.match("raw-response-headers", dict(response.headers))

        BUCKET_CORS_CONFIG = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["https://anydomain.com"],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["x-amz-tagging"],
                }
            ]
        }

        s3_client.put_bucket_cors(Bucket=bucket, CORSConfiguration=BUCKET_CORS_CONFIG)
        response = requests.get(
            url, headers={"Origin": config.get_edge_url(), "Content-Type": "text/html"}
        )
        assert 200 == response.status_code
        snapshot.match("raw-response-headers-2", dict(response.headers))

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="Access-Control-Allow-Origin returns Origin value in LS",
    )
    def test_s3_get_response_headers(self, s3_client, s3_bucket, snapshot):
        # put object and CORS configuration
        object_key = "key-by-hostname"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        s3_client.put_bucket_cors(
            Bucket=s3_bucket,
            CORSConfiguration={
                "CORSRules": [
                    {
                        "AllowedMethods": ["GET", "PUT", "POST"],
                        "AllowedOrigins": ["*"],
                        "ExposeHeaders": ["ETag", "x-amz-version-id"],
                    }
                ]
            },
        )
        bucket_cors_res = s3_client.get_bucket_cors(Bucket=s3_bucket)
        snapshot.match("bucket-cors-response", bucket_cors_res)

        # get object and assert headers
        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}
        )
        # need to add Origin headers for S3 to send back the Access-Control-* headers
        # as CORS is made for browsers
        response = requests.get(url, verify=False, headers={"Origin": "http://localhost"})
        assert response.headers["Access-Control-Expose-Headers"] == "ETag, x-amz-version-id"
        assert response.headers["Access-Control-Allow-Methods"] == "GET, PUT, POST"
        assert (
            response.headers["Access-Control-Allow-Origin"] == "*"
        )  # returns http://localhost in LS

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="Behaviour diverges from AWS, Access-Control-* headers always added",
    )
    def test_s3_get_response_headers_without_origin(self, s3_client, s3_bucket):
        # put object and CORS configuration
        object_key = "key-by-hostname"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        s3_client.put_bucket_cors(
            Bucket=s3_bucket,
            CORSConfiguration={
                "CORSRules": [
                    {
                        "AllowedMethods": ["GET", "PUT", "POST"],
                        "AllowedOrigins": ["*"],
                        "ExposeHeaders": ["ETag", "x-amz-version-id"],
                    }
                ]
            },
        )

        # get object and assert headers
        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": object_key}
        )
        response = requests.get(url, verify=False)
        assert "Access-Control-Expose-Headers" not in response.headers
        assert "Access-Control-Allow-Methods" not in response.headers
        assert "Access-Control-Allow-Origin" not in response.headers

    @staticmethod
    def _get_cors_result_header_snapshot_transformer(snapshot):
        return [
            snapshot.transform.key_value("x-amz-id-2", "<id>", reference_replacement=False),
            snapshot.transform.key_value(
                "x-amz-request-id", "<request-id>", reference_replacement=False
            ),
            snapshot.transform.key_value("Date", "<date>", reference_replacement=False),
            snapshot.transform.key_value("Server", "<server>", reference_replacement=False),
            snapshot.transform.key_value("Last-Modified", "<date>", reference_replacement=False),
        ]


class TestS3DeepArchive:
    """
    Test to cover DEEP_ARCHIVE Storage Class functionality.
    """

    @pytest.mark.aws_validated
    def test_storage_class_deep_archive(self, s3_client, s3_resource, s3_bucket, tmpdir):
        key = "my-key"

        transfer_config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        def upload_file(size_in_kb: int):
            file = tmpdir / f"test-file-{short_uid()}.bin"
            data = b"1" * (size_in_kb * KB)
            file.write(data=data, mode="w")
            s3_client.upload_file(
                Bucket=s3_bucket,
                Key=key,
                Filename=str(file.realpath()),
                ExtraArgs={"StorageClass": "DEEP_ARCHIVE"},
                Config=transfer_config,
            )

        upload_file(1)
        upload_file(9)
        upload_file(15)

        objects = s3_resource.Bucket(s3_bucket).objects.all()
        keys = []
        for obj in objects:
            keys.append(obj.key)
            assert obj.storage_class == "DEEP_ARCHIVE"

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Error.Message",  # TODO AWS does not include dot at the end
            "$..Error.RequestID",  # AWS has no RequestID here
            "$..Error.StorageClass",  # Missing in Localstack
            "$..StorageClass",  # Missing in Localstack
        ],
    )
    def test_s3_get_deep_archive_object_restore(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = f"bucket-{short_uid()}"
        object_key = f"key-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name)

        # put DEEP_ARCHIVE object
        s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body="body data",
            StorageClass="DEEP_ARCHIVE",
        )
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=bucket_name, Key=object_key)
        e.match("InvalidObjectState")

        snapshot.match("get_object_invalid_state", e.value.response)
        response = s3_client.restore_object(
            Bucket=bucket_name,
            Key=object_key,
            RestoreRequest={
                "Days": 30,
                "GlacierJobParameters": {
                    "Tier": "Bulk",
                },
            },
        )
        snapshot.match("restore_object", response)

        # AWS tier is currently configured to retrieve within 48 hours, so we cannot test the get-object here
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
        if 'ongoing-request="false"' in response.get("Restore", ""):
            # if the restoring happens in LocalStack (or was fast in AWS) we can retrieve the object
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            assert "etag" in response.get("ResponseMetadata").get("HTTPHeaders")


class TestS3StaticWebsiteHosting:
    """
    Test to cover StaticWebsiteHosting functionality.
    """

    @pytest.mark.aws_validated
    def test_s3_static_website_index(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            Body="index",
            ContentType="text/html",
            ACL="public-read",
        )

        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        url = _website_bucket_url(bucket_name)

        response = requests.get(url, verify=False)
        assert response.status_code == 200
        assert response.text == "index"

    @pytest.mark.aws_validated
    def test_s3_static_website_hosting(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        index_obj = s3_client.put_object(
            Bucket=bucket_name,
            Key="test/index.html",
            Body="index",
            ContentType="text/html",
            ACL="public-read",
        )
        error_obj = s3_client.put_object(
            Bucket=bucket_name,
            Key="test/error.html",
            Body="error",
            ContentType="text/html",
            ACL="public-read",
        )
        actual_key_obj = s3_client.put_object(
            Bucket=bucket_name,
            Key="actual/key.html",
            Body="key",
            ContentType="text/html",
            ACL="public-read",
        )
        with_content_type_obj = s3_client.put_object(
            Bucket=bucket_name,
            Key="with-content-type/key.js",
            Body="some js",
            ContentType="application/javascript; charset=utf-8",
            ACL="public-read",
        )
        s3_client.put_object(
            Bucket=bucket_name,
            Key="to-be-redirected.html",
            WebsiteRedirectLocation="/actual/key.html",
            ACL="public-read",
        )
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "test/error.html"},
            },
        )
        website_url = _website_bucket_url(bucket_name)
        # actual key
        url = f"{website_url}/actual/key.html"
        response = requests.get(url, verify=False)
        assert 200 == response.status_code
        assert "key" == response.text
        assert "content-type" in response.headers
        assert "text/html" == response.headers["content-type"]
        assert "etag" in response.headers
        assert actual_key_obj["ETag"] in response.headers["etag"]

        # If-None-Match and Etag
        response = requests.get(
            url, headers={"If-None-Match": actual_key_obj["ETag"]}, verify=False
        )
        assert 304 == response.status_code

        # key with specified content-type
        url = f"{website_url}/with-content-type/key.js"
        response = requests.get(url, verify=False)
        assert 200 == response.status_code
        assert "some js" == response.text
        assert "content-type" in response.headers
        assert "application/javascript; charset=utf-8" == response.headers["content-type"]
        assert "etag" in response.headers
        assert with_content_type_obj["ETag"] == response.headers["etag"]

        # index document
        url = f"{website_url}/test"
        response = requests.get(url, verify=False)
        assert 200 == response.status_code
        assert "index" == response.text
        assert "content-type" in response.headers
        assert "text/html" in response.headers["content-type"]
        assert "etag" in response.headers
        assert index_obj["ETag"] == response.headers["etag"]

        # root path test
        url = f"{website_url}/"
        response = requests.get(url, verify=False)
        assert 404 == response.status_code
        assert "error" == response.text
        assert "content-type" in response.headers
        assert "text/html" in response.headers["content-type"]
        assert "etag" in response.headers
        assert error_obj["ETag"] == response.headers["etag"]

        # error document
        url = f"{website_url}/something"
        response = requests.get(url, verify=False)
        assert 404 == response.status_code
        assert "error" == response.text
        assert "content-type" in response.headers
        assert "text/html" in response.headers["content-type"]
        assert "etag" in response.headers
        assert error_obj["ETag"] == response.headers["etag"]

        # redirect object
        url = f"{website_url}/to-be-redirected.html"
        response = requests.get(url, verify=False, allow_redirects=False)
        assert 301 == response.status_code
        assert "location" in response.headers
        assert "actual/key.html" in response.headers["location"]

        response = requests.get(url, verify=False)
        assert response.status_code == 200
        assert response.headers["etag"] == actual_key_obj["ETag"]

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide proper website support",
    )
    def test_website_hosting_no_such_website(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformers_list(self._get_static_hosting_transformers(snapshot))
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")

        random_url = _website_bucket_url(f"non-existent-bucket-{short_uid()}")
        response = requests.get(random_url, verify=False)
        assert response.status_code == 404
        snapshot.match("no-such-bucket", response.text)

        website_url = _website_bucket_url(bucket_name)
        # actual key
        response = requests.get(website_url, verify=False)
        assert response.status_code == 404
        snapshot.match("no-such-website-config", response.text)

        url = f"{website_url}/actual/key.html"
        response = requests.get(url)
        assert response.status_code == 404
        snapshot.match("no-such-website-config-key", response.text)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide proper website support",
    )
    def test_website_hosting_http_methods(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformers_list(self._get_static_hosting_transformers(snapshot))
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )
        website_url = _website_bucket_url(bucket_name)
        req = requests.post(website_url, data="test")
        assert req.status_code == 405
        error_response = req.text
        snapshot.match("not-allowed-post", {"content": error_response})

        req = requests.delete(website_url)
        assert req.status_code == 405
        error_response = req.text
        snapshot.match("not-allowed-delete", {"content": error_response})

        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )
        s3_client.put_object(
            Bucket=bucket_name,
            Key="error.html",
            Body="error",
            ContentType="text/html",
            ACL="public-read",
        )

        # documentation states that error code in the range 4XX are redirected to the ErrorDocument
        # 405 in not concerned by this
        req = requests.post(website_url, data="test")
        assert req.status_code == 405

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide proper website redirection",
    )
    def test_website_hosting_index_lookup(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformers_list(self._get_static_hosting_transformers(snapshot))
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            Body="index",
            ContentType="text/html",
            ACL="public-read",
        )

        website_url = _website_bucket_url(bucket_name)
        # actual key
        response = requests.get(website_url)
        assert response.status_code == 200
        assert response.text == "index"

        s3_client.put_object(
            Bucket=bucket_name,
            Key="directory/index.html",
            Body="index",
            ContentType="text/html",
            ACL="public-read",
        )

        response = requests.get(f"{website_url}/directory", allow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"] == "/directory/"

        response = requests.get(f"{website_url}/directory/", verify=False)
        assert response.status_code == 200
        assert response.text == "index"

        response = requests.get(f"{website_url}/directory-wrong", verify=False)
        assert response.status_code == 404
        snapshot.match("404-no-trailing-slash", response.text)

        response = requests.get(f"{website_url}/directory-wrong/", verify=False)
        assert response.status_code == 404
        snapshot.match("404-with-trailing-slash", response.text)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide proper website support",
    )
    def test_website_hosting_404(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformers_list(self._get_static_hosting_transformers(snapshot))
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        website_url = _website_bucket_url(bucket_name)

        response = requests.get(website_url)
        assert response.status_code == 404
        snapshot.match("404-no-such-key", response.text)

        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )
        response = requests.get(website_url)
        assert response.status_code == 404
        snapshot.match("404-no-such-key-nor-custom", response.text)

        s3_client.put_object(
            Bucket=bucket_name,
            Key="error.html",
            Body="error",
            ContentType="text/html",
            ACL="public-read",
        )

        response = requests.get(website_url)
        assert response.status_code == 404
        assert response.text == "error"

    @pytest.mark.aws_validated
    def test_object_website_redirect_location(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            WebsiteRedirectLocation="/another/index.html",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="error.html",
            Body="error_redirected",
            WebsiteRedirectLocation="/another/error.html",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="another/error.html",
            Body="error",
            ACL="public-read",
        )

        website_url = _website_bucket_url(bucket_name)

        response = requests.get(website_url)
        # losing the status code because of the redirection in the error document
        assert response.status_code == 200
        assert response.text == "error"

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide website routing rules",
    )
    def test_routing_rules_conditions(self, s3_client, s3_create_bucket):
        # https://github.com/localstack/localstack/issues/6308
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
                "RoutingRules": [
                    {
                        "Condition": {
                            "KeyPrefixEquals": "both-prefixed/",
                            "HttpErrorCodeReturnedEquals": "404",
                        },
                        "Redirect": {"ReplaceKeyWith": "redirected-both.html"},
                    },
                    {
                        "Condition": {"KeyPrefixEquals": "prefixed"},
                        "Redirect": {"ReplaceKeyWith": "redirected.html"},
                    },
                    {
                        "Condition": {"HttpErrorCodeReturnedEquals": "404"},
                        "Redirect": {"ReplaceKeyWith": "redirected.html"},
                    },
                ],
            },
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="redirected.html",
            Body="redirected",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="prefixed-key-test",
            Body="prefixed",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="redirected-both.html",
            Body="redirected-both",
            ACL="public-read",
        )

        website_url = _website_bucket_url(bucket_name)

        response = requests.get(f"{website_url}/non-existent-key", allow_redirects=False)
        assert response.status_code == 301
        assert response.headers["Location"] == f"{website_url}/redirected.html"

        # redirects when the custom ErrorDocument is not found
        response = requests.get(f"{website_url}/non-existent-key")
        assert response.status_code == 200
        assert response.text == "redirected"

        s3_client.put_object(
            Bucket=bucket_name,
            Key="error.html",
            Body="error",
            ACL="public-read",
        )

        response = requests.get(f"{website_url}/non-existent-key")
        assert response.status_code == 200
        assert response.text == "redirected"

        response = requests.get(f"{website_url}/prefixed-key-test")
        assert response.status_code == 200
        assert response.text == "redirected"

        response = requests.get(f"{website_url}/both-prefixed/")
        assert response.status_code == 200
        assert response.text == "redirected-both"

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide website routing rules",
    )
    def test_routing_rules_redirects(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
                "RoutingRules": [
                    {
                        "Condition": {
                            "KeyPrefixEquals": "host/",
                        },
                        "Redirect": {"HostName": "random-hostname"},
                    },
                    {
                        "Condition": {
                            "KeyPrefixEquals": "replace-prefix/",
                        },
                        "Redirect": {"ReplaceKeyPrefixWith": "replaced-prefix/"},
                    },
                    {
                        "Condition": {
                            "KeyPrefixEquals": "protocol/",
                        },
                        "Redirect": {"Protocol": "https"},
                    },
                    {
                        "Condition": {
                            "KeyPrefixEquals": "code/",
                        },
                        "Redirect": {"HttpRedirectCode": "307"},
                    },
                ],
            },
        )

        website_url = _website_bucket_url(bucket_name)

        response = requests.get(f"{website_url}/host/key", allow_redirects=False)
        assert response.status_code == 301
        assert response.headers["Location"] == "http://random-hostname/host/key"

        response = requests.get(f"{website_url}/replace-prefix/key", allow_redirects=False)
        assert response.status_code == 301
        assert response.headers["Location"] == f"{website_url}/replaced-prefix/key"

        response = requests.get(f"{website_url}/protocol/key", allow_redirects=False)
        assert response.status_code == 301
        assert not website_url.startswith("https")
        assert response.headers["Location"].startswith("https")

        response = requests.get(f"{website_url}/code/key", allow_redirects=False)
        assert response.status_code == 307

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER,
        reason="Legacy S3 provider does not provide website routing rules",
    )
    def test_routing_rules_empty_replace_prefix(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            Body="index",
            ACL="public-read",
        )
        s3_client.put_object(
            Bucket=bucket_name,
            Key="test.html",
            Body="test",
            ACL="public-read",
        )
        s3_client.put_object(
            Bucket=bucket_name,
            Key="error.html",
            Body="error",
            ACL="public-read",
        )
        s3_client.put_object(
            Bucket=bucket_name,
            Key="mydocs/test.html",
            Body="mydocs",
            ACL="public-read",
        )

        # change configuration
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
                "RoutingRules": [
                    {
                        "Condition": {"KeyPrefixEquals": "docs/"},
                        "Redirect": {"ReplaceKeyPrefixWith": ""},
                    },
                    {
                        "Condition": {"KeyPrefixEquals": "another/path/"},
                        "Redirect": {"ReplaceKeyPrefixWith": ""},
                    },
                ],
            },
        )

        website_url = _website_bucket_url(bucket_name)

        # testing that routing rule redirect correctly (by removing the defined prefix)
        response = requests.get(f"{website_url}/docs/test.html")
        assert response.status_code == 200
        assert response.text == "test"

        response = requests.get(f"{website_url}/another/path/test.html")
        assert response.status_code == 200
        assert response.text == "test"

        response = requests.get(f"{website_url}/docs/mydocs/test.html")
        assert response.status_code == 200
        assert response.text == "mydocs"

        # no routing rule defined -> should result in error
        response = requests.get(f"{website_url}/docs2/test.html")
        assert response.status_code == 404
        assert response.text == "error"

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER,
        reason="Legacy S3 provider does not provide website routing rules",
    )
    def test_routing_rules_order(self, s3_client, s3_create_bucket):
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
                "RoutingRules": [
                    {
                        "Condition": {
                            "KeyPrefixEquals": "prefix",
                        },
                        "Redirect": {"ReplaceKeyWith": "redirected.html"},
                    },
                    {
                        "Condition": {
                            "KeyPrefixEquals": "index",
                        },
                        "Redirect": {"ReplaceKeyWith": "redirected.html"},
                    },
                ],
            },
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            Body="index",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="redirected.html",
            Body="redirected",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="website-redirected.html",
            Body="website-redirected",
            ACL="public-read",
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="prefixed-key-test",
            Body="prefixed",
            ACL="public-read",
            WebsiteRedirectLocation="/website-redirected.html",
        )

        website_url = _website_bucket_url(bucket_name)
        # testing that routing rules have precedence over individual object redirection
        response = requests.get(f"{website_url}/prefixed-key-test")
        assert response.status_code == 200
        assert response.text == "redirected"

        # assert that prefix rules don't apply for root path (internally redirected to index.html)
        response = requests.get(website_url)
        assert response.status_code == 200
        assert response.text == "index"

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide website configuration validation",
    )
    @pytest.mark.skip_snapshot_verify(
        # todo: serializer issue with empty node, very tricky one...
        paths=["$.invalid-website-conf-1.Error.ArgumentValue"]
    )
    def test_validate_website_configuration(self, s3_client, s3_bucket, snapshot):

        website_configurations = [
            # can't have slash in the suffix
            {
                "IndexDocument": {"Suffix": "/index.html"},
            },
            # empty suffix value
            {
                "IndexDocument": {"Suffix": ""},
            },
            # if RedirectAllRequestsTo is set, cannot have other fields
            {
                "RedirectAllRequestsTo": {"HostName": "test"},
                "IndexDocument": {"Suffix": "/index.html"},
            },
            # does not have an IndexDocument field
            {
                "ErrorDocument": {"Key": "/index.html"},
            },
            # wrong protocol, must be http|https
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [{"Redirect": {"Protocol": "protocol"}}],
            },
            # has both ReplaceKeyPrefixWith and ReplaceKeyWith
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Redirect": {
                            "ReplaceKeyPrefixWith": "prefix",
                            "ReplaceKeyWith": "key-name",
                        }
                    }
                ],
            },
            # empty Condition field in Routing Rule
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [
                    {
                        "Redirect": {
                            "ReplaceKeyPrefixWith": "prefix",
                        },
                        "Condition": {},
                    }
                ],
            },
            # empty routing rules
            {
                "IndexDocument": {"Suffix": "index.html"},
                "RoutingRules": [],
            },
        ]

        for index, invalid_configuration in enumerate(website_configurations):
            # not using pytest.raises, to have better debugging value in case of not raising exception
            # because of the loop, we don't know which configuration has not raised the exception
            try:
                s3_client.put_bucket_website(
                    Bucket=s3_bucket,
                    WebsiteConfiguration=invalid_configuration,
                )
                assert False, f"{invalid_configuration} should have raised an exception"
            except ClientError as e:
                snapshot.match(f"invalid-website-conf-{index}", e.response)

    @pytest.mark.aws_validated
    def test_crud_website_configuration(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_website(Bucket=s3_bucket)
        snapshot.match("get-no-such-website-config", e.value.response)

        resp = s3_client.delete_bucket_website(Bucket=s3_bucket)
        snapshot.match("del-no-such-website-config", resp)

        response = s3_client.put_bucket_website(
            Bucket=s3_bucket,
            WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}},
        )
        snapshot.match("put-website-config", response)

        response = s3_client.get_bucket_website(Bucket=s3_bucket)
        snapshot.match("get-website-config", response)

        s3_client.delete_bucket_website(Bucket=s3_bucket)
        with pytest.raises(ClientError):
            s3_client.get_bucket_website(Bucket=s3_bucket)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(
        condition=LEGACY_S3_PROVIDER and not is_aws_cloud(),
        reason="Legacy S3 provider does not provide website redirection",
    )
    def test_website_hosting_redirect_all(self, s3_client, s3_create_bucket):
        bucket_name_redirected = f"bucket-{short_uid()}"
        bucket_name = f"bucket-{short_uid()}"

        s3_create_bucket(Bucket=bucket_name_redirected, ACL="public-read")
        bucket_website_url = _website_bucket_url(bucket_name)
        bucket_website_host = urlparse(bucket_website_url).netloc

        s3_client.put_bucket_website(
            Bucket=bucket_name_redirected,
            WebsiteConfiguration={
                "RedirectAllRequestsTo": {"HostName": bucket_website_host},
            },
        )

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        s3_client.put_object(
            Bucket=bucket_name,
            Key="index.html",
            Body="index",
            ContentType="text/html",
            ACL="public-read",
        )

        redirected_bucket_website = _website_bucket_url(bucket_name_redirected)

        response_no_redirect = requests.get(redirected_bucket_website, allow_redirects=False)
        assert response_no_redirect.status_code == 301
        assert response_no_redirect.content == b""

        response_redirected = requests.get(redirected_bucket_website)
        assert response_redirected.status_code == 200
        assert response_redirected.content == b"index"

        response = requests.get(bucket_website_url)
        assert response.status_code == 200
        assert response.content == b"index"

        assert response.content == response_redirected.content

        response_redirected = requests.get(f"{redirected_bucket_website}/random-key")
        assert response_redirected.status_code == 404

    @staticmethod
    def _get_static_hosting_transformers(snapshot):
        return [
            snapshot.transform.regex(
                "RequestId: (.*?)</li>", replacement="RequestId: <request-id></li>"
            ),
            snapshot.transform.regex("HostId: (.*?)</li>", replacement="HostId: <host-id></li>"),
            snapshot.transform.regex(
                "BucketName: (.*?)</li>", replacement="BucketName: <bucket-name></li>"
            ),
        ]


def _anon_client(service: str):
    conf = Config(signature_version=UNSIGNED)
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client(service, config=conf, region_name=None)
    return aws_stack.create_external_boto_client(service, config=conf)


def _s3_client_custom_config(conf: Config, endpoint_url: str = None):
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client("s3", config=conf, endpoint_url=endpoint_url)

    # TODO in future this should work with aws_stack.create_external_boto_client
    #      currently it doesn't as authenticate_presign_url_signv2 requires the secret_key to be 'test'
    # return aws_stack.create_external_boto_client(
    #     "s3",
    #     config=conf,
    #     endpoint_url=endpoint_url,
    #     aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
    # )
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        config=conf,
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    )


def _endpoint_url(region: str = "", localstack_host: str = None) -> str:
    if not region:
        region = config.AWS_REGION_US_EAST_1
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        if region == "us-east-1":
            return "https://s3.amazonaws.com"
        else:
            return f"http://s3.{region}.amazonaws.com"
    if region == "us-east-1":
        return f"{config.get_edge_url(localstack_hostname=localstack_host or S3_VIRTUAL_HOSTNAME)}"
    return config.get_edge_url(f"s3.{region}.{LOCALHOST_HOSTNAME}")


def _bucket_url(bucket_name: str, region: str = "", localstack_host: str = None) -> str:
    return f"{_endpoint_url(region, localstack_host)}/{bucket_name}"


def _website_bucket_url(bucket_name: str):
    # TODO depending on region the syntax of the website vary (dot vs dash before region)
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        region = config.AWS_REGION_US_EAST_1
        return f"http://{bucket_name}.s3-website-{region}.amazonaws.com"
    return _bucket_url_vhost(bucket_name, localstack_host=constants.S3_STATIC_WEBSITE_HOSTNAME)


def _bucket_url_vhost(bucket_name: str, region: str = "", localstack_host: str = None) -> str:
    if not region:
        region = config.AWS_REGION_US_EAST_1
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        if region == "us-east-1":
            return f"https://{bucket_name}.s3.amazonaws.com"
        else:
            return f"https://{bucket_name}.s3.{region}.amazonaws.com"
    host = localstack_host or (
        f"s3.{region}.{LOCALHOST_HOSTNAME}" if region != "us-east-1" else S3_VIRTUAL_HOSTNAME
    )
    s3_edge_url = config.get_edge_url(localstack_hostname=host)
    # TODO might add the region here
    return s3_edge_url.replace(f"://{host}", f"://{bucket_name}.{host}")


def _generate_presigned_url(
    client: "S3Client", params: dict, expires: int, client_method: str = "get_object"
) -> str:
    return client.generate_presigned_url(
        client_method,
        Params=params,
        ExpiresIn=expires,
    )


def _make_url_invalid(url_prefix: str, object_key: str, url: str) -> str:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if "Signature" in query_params:
        # v2 style
        return "{}/{}?AWSAccessKeyId={}&Signature={}&Expires={}".format(
            url_prefix,
            object_key,
            query_params["AWSAccessKeyId"][0],
            query_params["Signature"][0],
            query_params["Expires"][0],
        )
    else:
        # v4 style
        return (
            "{}/{}?X-Amz-Algorithm=AWS4-HMAC-SHA256&"
            "X-Amz-Credential={}&X-Amz-Date={}&"
            "X-Amz-Expires={}&X-Amz-SignedHeaders=host&"
            "X-Amz-Signature={}"
        ).format(
            url_prefix,
            object_key,
            quote(query_params["X-Amz-Credential"][0]).replace("/", "%2F"),
            query_params["X-Amz-Date"][0],
            query_params["X-Amz-Expires"][0],
            query_params["X-Amz-Signature"][0],
        )
