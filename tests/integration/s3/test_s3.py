import datetime
import gzip
import io
import json
import logging
import os
import re
import time
from io import BytesIO
from operator import itemgetter
from unittest.mock import patch

import boto3 as boto3
import pytest
import requests
import xmltodict
from boto3.s3.transfer import KB, TransferConfig
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError
from pytz import timezone

from localstack import config
from localstack.constants import S3_VIRTUAL_HOSTNAME
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest.fixtures import _client
from localstack.utils.aws import aws_stack
from localstack.utils.collections import is_sub_dict
from localstack.utils.files import load_file
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

LOG = logging.getLogger(__name__)


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
            kwargs["Bucket"] = "test-bucket-%s" % short_uid()

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
            LOG.debug("error cleaning up bucket %s: %s", bucket, e)


@pytest.fixture
def s3_multipart_upload(s3_client):
    def perform_multipart_upload(bucket, key, data=None, zipped=False, acl=None):
        kwargs = {"ACL": acl} if acl else {}
        multipart_upload_dict = s3_client.create_multipart_upload(Bucket=bucket, Key=key, **kwargs)
        upload_id = multipart_upload_dict["UploadId"]

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zipped:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
                filestream.write(data)

        response = s3_client.upload_part(
            Bucket=bucket,
            Key=key,
            Body=upload_file_object,
            PartNumber=1,
            UploadId=upload_id,
        )

        multipart_upload_parts = [{"ETag": response["ETag"], "PartNumber": 1}]

        return s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

    return perform_multipart_upload


class TestS3:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..EncodingType"])
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
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Marker", "$..Prefix", "$..EncodingType", "$..list-buckets.Buckets"]
    )
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
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId", "$..ContentLanguage"])
    def test_put_and_get_object_with_utf8_key(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        response = s3_client.put_object(Bucket=s3_bucket, Key="Ā0Ä", Body=b"abc123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        snapshot.match("put-object", response)

        response = s3_client.get_object(Bucket=s3_bucket, Key="Ā0Ä")
        snapshot.match("get-object", response)
        assert response["Body"].read() == b"abc123"

    @pytest.mark.aws_validated
    def test_resource_object_with_slashes_in_key(self, s3_resource, s3_bucket):
        s3_resource.Object(s3_bucket, "/foo").put(Body="foobar")
        s3_resource.Object(s3_bucket, "bar").put(Body="barfoo")

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
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId", "$..ContentLanguage"])
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
    def test_list_objects_with_prefix(self, s3_client, s3_create_bucket, delimiter):
        bucket_name = s3_create_bucket()
        key = "test/foo/bar/123"
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=b"content 123")

        response = s3_client.list_objects(
            Bucket=bucket_name, Prefix="test/", Delimiter=delimiter, MaxKeys=1, EncodingType="url"
        )
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
    def test_get_object_no_such_bucket(self, s3_client):
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=f"does-not-exist-{short_uid()}", Key="foobar")

        # TODO: simplify with snapshot test once activated
        response = e.value.response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 404
        error = response["Error"]
        assert error["Code"] == "NoSuchBucket"
        assert error["Message"] == "The specified bucket does not exist"

    @pytest.mark.aws_validated
    def test_delete_bucket_no_such_bucket(self, s3_client):
        with pytest.raises(ClientError) as e:
            s3_client.delete_bucket(Bucket=f"does-not-exist-{short_uid()}")

        # TODO: simplify with snapshot test once activated
        response = e.value.response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 404
        error = response["Error"]
        assert error["Code"] == "NoSuchBucket"
        assert error["Message"] == "The specified bucket does not exist"

    @pytest.mark.aws_validated
    def test_get_bucket_notification_configuration_no_such_bucket(self, s3_client):
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_notification_configuration(Bucket=f"doesnotexist-{short_uid()}")

        # TODO: simplify with snapshot test once activated
        response = e.value.response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 404
        error = response["Error"]
        assert error["Code"] == "NoSuchBucket"
        assert error["Message"] == "The specified bucket does not exist"

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="currently not implemented in moto, see https://github.com/localstack/localstack/issues/6422"
    )
    def test_get_object_attributes_object_size(self, s3_client, s3_bucket):
        s3_client.put_object(Bucket=s3_bucket, Key="data.txt", Body=b"69\n420\n")
        response = s3_client.get_object_attributes(
            Bucket=s3_bucket, Key="data.txt", ObjectAttributes=["ObjectSize"]
        )
        assert response["ObjectSize"] == 7

    @pytest.mark.aws_validated
    @pytest.mark.xfail(
        reason="currently not implemented in moto, see https://github.com/localstack/localstack/issues/6217"
    )
    # see also https://github.com/localstack/localstack/issues/6422
    # todo: see XML issue?
    def test_get_object_attributes(self, s3_client, s3_bucket, snapshot):
        s3_client.put_object(Bucket=s3_bucket, Key="data.txt", Body=b"69\n420\n")
        response = s3_client.get_object_attributes(
            Bucket=s3_bucket,
            Key="data.txt",
            ObjectAttributes=["StorageClass", "ETag", "ObjectSize"],
        )
        snapshot.match("object-attrs", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId", "$..ContentLanguage"])
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
    @pytest.mark.xfail(reason="error message is different in current implementation")
    def test_invalid_range_error(self, s3_client, s3_bucket):
        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")

        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1024-4096")

        e.match("InvalidRange")
        e.match("The requested range is not satisfiable")

    @pytest.mark.aws_validated
    def test_range_key_not_exists(self, s3_client, s3_bucket):
        key = "my-key"
        with pytest.raises(ClientError) as e:
            s3_client.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1024-4096")

        e.match("NoSuchKey")
        e.match("The specified key does not exist.")

    @pytest.mark.aws_validated
    def test_create_bucket_via_host_name(self, s3_vhost_client):
        # todo check redirection (happens in AWS because of region name), should it happen in LS?
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingBackwardsCompatibility
        bucket_name = "test-%s" % short_uid()
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
    def test_put_and_get_bucket_policy(self, s3_client, s3_bucket):
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
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 204

        # retrieve and check policy config
        saved_policy = s3_client.get_bucket_policy(Bucket=s3_bucket)["Policy"]
        assert policy == json.loads(saved_policy)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(reason="see https://github.com/localstack/localstack/issues/5769")
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
    @pytest.mark.xfail(reason="see https://github.com/localstack/localstack/issues/6218")
    def test_head_object_fields(self, s3_client, s3_bucket, snapshot):
        key = "my-key"
        s3_client.put_object(Bucket=s3_bucket, Key=key, Body=b"abcdefgh")

        response = s3_client.head_object(Bucket=s3_bucket, Key=key)
        # missing AcceptRanges field
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
        # https://stackoverflow.com/questions/58541696/s3-not-returning-accept-ranges-header
        # https://www.keycdn.com/support/frequently-asked-questions#is-byte-range-not-working-in-combination-with-s3

        snapshot.match("head-object", response)

    @pytest.mark.aws_validated
    @pytest.mark.xfail(reason="see https://github.com/localstack/localstack/issues/6553")
    def test_get_object_after_deleted_in_versioned_bucket(
        self, s3_client, s3_bucket, s3_resource, snapshot
    ):
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
    def test_put_object_checksum(self, s3_client, s3_create_bucket, algorithm):
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
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # Test the autogenerated checksums
        params.pop(f"Checksum{algorithm}")
        response = s3_client.put_object(**params)
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
        bucket_name = "test-bucket-%s" % short_uid()
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..AcceptRanges",
            "$..ContentLanguage",
            "$..VersionId",
            "$..Restore",
        ]
    )
    def test_s3_object_expiry(self, s3_client, s3_bucket, snapshot):
        # AWS only cleans up S3 expired object once a day usually
        # the object stays accessible for quite a while after being expired
        # https://stackoverflow.com/questions/38851456/aws-s3-object-expiration-less-than-24-hours
        # handle s3 object expiry
        # https://github.com/localstack/localstack/issues/1685
        # todo: should we have a config var to not deleted immediately in the new provider? and schedule it?
        snapshot.add_transformer(snapshot.transform.s3_api())
        # put object
        short_expire = datetime.datetime.now(timezone("GMT")) + datetime.timedelta(seconds=1)
        object_key_expired = "key-object-expired"
        object_key_not_expired = "key-object-not-expired"

        s3_client.put_object(
            Bucket=s3_bucket,
            Key=object_key_expired,
            Body="foo",
            Expires=short_expire,
        )
        time.sleep(3)
        # head_object does not raise an error for now in LS
        response = s3_client.head_object(Bucket=s3_bucket, Key=object_key_expired)
        assert response["Expires"] < datetime.datetime.now(timezone("GMT"))
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
            Expires=datetime.datetime.now(timezone("GMT")) + datetime.timedelta(hours=1),
        )

        # try to fetch has not been expired yet.
        resp = s3_client.get_object(Bucket=s3_bucket, Key=object_key_not_expired)
        assert "Expires" in resp
        assert resp["Expires"] > datetime.datetime.now(timezone("GMT"))
        snapshot.match("get-object-not-yet-expired", resp)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
        ]
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
    @pytest.mark.xfail(reason="The error format is wrong in s3_listener (is_bucket_available)")
    def test_bucket_availability(self, s3_client, snapshot):
        bucket_name = "test-bucket-lifecycle"
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle(Bucket=bucket_name)
        snapshot.match("bucket-lifecycle", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_replication(Bucket=bucket_name)
        snapshot.match("bucket-replication", e.value.response)

    @pytest.mark.aws_validated
    def test_location_path_url(
        self,
        s3_client,
        s3_create_bucket,
    ):
        region = "us-east-2"
        bucket_name = s3_create_bucket(
            CreateBucketConfiguration={"LocationConstraint": region}, ACL="public-read"
        )
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        assert region == response["LocationConstraint"]
        # TODO should this also work against AWS?
        # related PR https://github.com/localstack/localstack/pull/5795
        # originally tested this url:
        # url = f"{config.get_edge_url(localstack_hostname=S3_VIRTUAL_HOSTNAME)}/{bucket_name}?location="

        # make raw request, assert that newline is contained after XML preamble: <?xml ...>\n
        url = _bucket_url(bucket_name, region)
        response = requests.get(url)
        assert response.ok
        content = to_str(response.content)
        assert re.match(r"^<\?xml [^>]+>\n<.*", content, flags=re.MULTILINE)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Error.RequestID"])
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
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
        ]
    )
    def test_get_object_with_anon_credentials(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = "bucket-%s" % short_uid()
        object_key = "key-%s" % short_uid()
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
        paths=["$..ContentLanguage", "$..VersionId", "$..AcceptRanges"]
    )
    def test_putobject_with_multiple_keys(self, s3_client, s3_create_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket = "bucket-%s" % short_uid()
        key_by_path = "aws/key1/key2/key3"

        s3_create_bucket(Bucket=bucket)
        s3_client.put_object(Body=b"test", Bucket=bucket, Key=key_by_path)
        result = s3_client.get_object(Bucket=bucket, Key=key_by_path)
        snapshot.match("get_object", result)

    @pytest.mark.aws_validated
    def test_delete_bucket_lifecycle_configuration(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
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
        s3_client.delete_bucket_lifecycle(Bucket=s3_bucket)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_lifecycle_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-lifecycle-exc", e.value.response)

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
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..ContentLanguage",
            "$..VersionId",
            "$..ETag",  # todo ETag should be the same?
        ]
    )
    def test_range_header_body_length(self, s3_client, s3_bucket, snapshot):
        # Test for https://github.com/localstack/localstack/issues/1952

        object_key = "sample.bin"
        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            s3_client.upload_fileobj(data, s3_bucket, object_key)

        range_header = "bytes=0-%s" % (chunk_size - 1)
        resp = s3_client.get_object(Bucket=s3_bucket, Key=object_key, Range=range_header)
        content = resp["Body"].read()
        assert chunk_size == len(content)
        snapshot.match("get-object", resp)

    @pytest.mark.aws_validated
    def test_s3_get_range_object_headers(self, s3_client, s3_bucket):
        object_key = "sample.bin"
        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            s3_client.upload_fileobj(data, s3_bucket, object_key)

        range_header = "bytes=0-%s" % (chunk_size - 1)
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
    def test_s3_put_object_chunked_newlines(self, s3_client, s3_bucket):
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId", "$..ContentLanguage"])
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
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId"])
    def test_delete_non_existing_keys(self, s3_client, s3_bucket, snapshot):
        object_key = "test-key-nonexistent"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")
        response = s3_client.delete_objects(
            Bucket=s3_bucket,
            Delete={"Objects": [{"Key": object_key}, {"Key": "dummy1"}, {"Key": "dummy2"}]},
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
        paths=["$..VersionId", "$..ContentLanguage", "$..Error.RequestID"]
    )
    def test_s3_uppercase_key_names(self, s3_client, s3_create_bucket, snapshot):
        # bucket name should be case-sensitive
        bucket_name = "testuppercase-%s" % short_uid()
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

        bucket_name = "bucket-%s" % short_uid()
        function_name = "func-%s" % short_uid()
        key = "key-%s" % short_uid()

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
            url = "%s%s" % (config.get_edge_url(), path)
            result = getattr(requests, method.lower())(url, data=body, headers=headers)
            assert result.status_code < 400


class TestS3PresignedUrl:
    """
    These tests pertain to S3's presigned URL feature.
    """

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..VersionId", "$..ContentLanguage", "$..Expires"])
    def test_put_object(self, s3_client, s3_bucket, snapshot):
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
        condition=not config.LEGACY_EDGE_PROXY, reason="failing with new HTTP gateway (only in CI)"
    )
    def test_post_object_with_files(self, s3_client, s3_bucket):
        object_key = "test-presigned-post-key"

        body = b"something body"

        presigned_request = s3_client.generate_presigned_post(
            Bucket=s3_bucket, Key=object_key, ExpiresIn=60
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
    def test_post_request_expires(self, s3_client, s3_bucket):
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

        # FIXME: localstack returns 400 but aws returns 403
        assert response.status_code in [400, 403]
        assert "ExpiredToken" in response.text

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
            assert response.status_code == 204
            assert not response.text
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
    def test_put_object_with_md5_and_chunk_signature_bad_headers(
        self,
        s3_client,
        s3_create_bucket,
    ):
        bucket_name = "bucket-%s" % short_uid()
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
        url = s3_client.generate_presigned_url(
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
        assert b"SignatureDoesNotMatch" in result.content

        # check also no X-Amz-Decoded-Content-Length
        headers.pop("X-Amz-Decoded-Content-Length")
        result = requests.put(url, data="test", headers=headers)
        assert result.status_code == 403, (result, result.content)
        assert b"SignatureDoesNotMatch" in result.content

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
    def test_s3_presigned_url_expired(self, s3_presigned_client, s3_bucket, monkeypatch):
        if not is_aws_cloud():
            monkeypatch.setattr(config, "S3_SKIP_SIGNATURE_VALIDATION", False)

        object_key = "key-expires-in-2"
        s3_presigned_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        url = s3_presigned_client.generate_presigned_url(
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
        assert "<Code>AccessDenied</Code>" in resp_content
        assert "<Message>Request has expired</Message>" in resp_content

        url = s3_presigned_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": s3_bucket, "Key": object_key},
            ExpiresIn=120,
        )

        resp = requests.get(url, verify=False)
        assert resp.status_code == 200
        assert to_str(resp.content) == "something"

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
        # test
        assert 201 == response.status_code
        json_response = xmltodict.parse(response.content)
        assert "PostResponse" in json_response
        json_response = json_response["PostResponse"]
        # fixme 201 response is hardcoded
        # see localstack.services.s3.s3_listener.ProxyListenerS3.get_201_response
        if is_aws_cloud():
            location = f"{_bucket_url_vhost(s3_bucket, aws_stack.get_region())}/key-my-file"
            etag = '"43281e21fce675ac3bcb3524b38ca4ed"'  # todo check quoting of etag
        else:
            location = "http://localhost/key-my-file"
            etag = "d41d8cd98f00b204e9800998ecf8427f"
        assert json_response["Location"] == location
        assert json_response["Bucket"] == s3_bucket
        assert json_response["Key"] == "key-my-file"
        assert json_response["ETag"] == etag

    @pytest.mark.aws_validated
    @pytest.mark.xfail(reason="Access-Control-Allow-Origin returns Origin value in LS")
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
    @pytest.mark.xfail(reason="Behaviour diverges from AWS, Access-Control-* headers always added")
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

    @pytest.mark.aws_validated
    def test_s3_get_response_header_overrides(self, s3_client, s3_bucket):
        # Signed requests may include certain header overrides in the querystring
        # https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
        object_key = "key-header-overrides"
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Body="something")

        # get object and assert headers
        expiry_date = "Wed, 21 Oct 2015 07:28:00 GMT"
        url = s3_client.generate_presigned_url(
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
        headers = response.headers
        assert headers["cache-control"] == "max-age=74"
        assert headers["content-disposition"] == 'attachment; filename="foo.jpg"'
        assert headers["content-encoding"] == "identity"
        assert headers["content-language"] == "de-DE"
        assert headers["content-type"] == "image/jpeg"

        # Note: looks like depending on the environment/libraries, we can get different date formats...
        possible_date_formats = ["2015-10-21T07:28:00Z", expiry_date]
        assert headers["expires"] in possible_date_formats

    def test_s3_copy_md5(self, s3_client, s3_bucket, snapshot):
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
        url = s3_client.generate_presigned_url(
            "copy_object",
            Params={
                "Bucket": s3_bucket,
                "CopySource": {"Bucket": s3_bucket, "Key": src_key},
                "Key": dest_key2,
            },
        )

        request_response = requests.put(url, verify=False)
        assert request_response.status_code == 200


class TestS3Cors:
    @patch.object(config, "DISABLE_CUSTOM_CORS_S3", False)
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
    def test_cors_with_allowed_origins(self, s3_client, s3_create_bucket, snapshot):
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

        bucket_name = "bucket-%s" % short_uid()
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

    @patch.object(config, "DISABLE_CUSTOM_CORS_S3", False)
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
    def test_cors_configurations(self, s3_client, s3_create_bucket, snapshot):
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
        # TODO this is not contained in AWS but was asserted for LocalStack
        #  assert "Access-Control-Allow-Headers" in response.headers
        #  assert "x-amz-tagging" == response.headers["Access-Control-Allow-Headers"]
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

    def _get_cors_result_header_snapshot_transformer(self, snapshot):
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


def _anon_client(service: str):
    conf = Config(signature_version=UNSIGNED)
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client(service, config=conf, region_name=None)
    return aws_stack.create_external_boto_client(service, config=conf)


def _bucket_url(bucket_name: str, region: str = "") -> str:
    if not region:
        region = config.DEFAULT_REGION
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        if region == "us-east-1":
            return f"https://s3.amazonaws.com/{bucket_name}"
        else:
            return f"http://s3.{region}.amazonaws.com/{bucket_name}"
    return f"{config.get_edge_url(localstack_hostname=S3_VIRTUAL_HOSTNAME)}/{bucket_name}"


def _bucket_url_vhost(bucket_name: str, region: str = "") -> str:
    if not region:
        region = config.DEFAULT_REGION
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        if region == "us-east-1":
            return f"https://{bucket_name}.s3.amazonaws.com"
        else:
            return f"https://{bucket_name}.s3.{region}.amazonaws.com"
    s3_edge_url = config.get_edge_url(localstack_hostname=S3_VIRTUAL_HOSTNAME)
    # todo might add the region here
    return s3_edge_url.replace("://s3.", f"://{bucket_name}.s3.")
