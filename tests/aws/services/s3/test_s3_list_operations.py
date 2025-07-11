"""
This file is to test specific behaviour of List* operations of S3, especially pagination, which is pretty specific to
each implementation. They all have subtle differences which make it difficult to test.
"""

import datetime
from io import BytesIO

import pytest
import xmltodict
from botocore.auth import SigV4Auth
from botocore.client import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.config import S3_VIRTUAL_HOSTNAME
from localstack.constants import AWS_REGION_US_EAST_1, LOCALHOST_HOSTNAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


def _bucket_url(bucket_name: str, region: str = "", localstack_host: str = None) -> str:
    return f"{_endpoint_url(region, localstack_host)}/{bucket_name}"


def _endpoint_url(region: str = "", localstack_host: str = None) -> str:
    if not region:
        region = AWS_REGION_US_EAST_1
    if is_aws_cloud():
        if region == "us-east-1":
            return "https://s3.amazonaws.com"
        else:
            return f"http://s3.{region}.amazonaws.com"
    if region == "us-east-1":
        return f"{config.internal_service_url(host=localstack_host or S3_VIRTUAL_HOSTNAME)}"
    return config.internal_service_url(host=f"s3.{region}.{LOCALHOST_HOSTNAME}")


def assert_timestamp_is_iso8061_s3_format(timestamp: str):
    # the timestamp should be looking like the following
    # 2023-11-15T12:02:40.000Z
    assert timestamp.endswith(".000Z")
    assert len(timestamp) == 24
    # assert that it follows the right format and it does not raise an exception during parsing
    parsed_ts = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    assert parsed_ts.microsecond == 0


class TestS3ListBuckets:
    @markers.aws.validated
    def test_list_buckets_by_prefix_with_case_sensitivity(
        self, s3_create_bucket, aws_client, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("Prefix"))

        bucket_name = f"test-bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)
        s3_create_bucket(Bucket=f"ignored-bucket-{short_uid()}")

        response = aws_client.s3.list_buckets(Prefix=bucket_name.upper())
        assert len(response["Buckets"]) == 0

        snapshot.match("list-objects-by-prefix-empty", response)

        response = aws_client.s3.list_buckets(Prefix=bucket_name)
        assert len(response["Buckets"]) == 1

        returned_bucket = response["Buckets"][0]
        assert returned_bucket["Name"] == bucket_name

        snapshot.match("list-objects-by-prefix-not-empty", response)

    @markers.aws.validated
    def test_list_buckets_with_max_buckets(self, s3_create_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("ContinuationToken"))

        s3_create_bucket()
        s3_create_bucket()

        response = aws_client.s3.list_buckets(MaxBuckets=1)
        assert len(response["Buckets"]) == 1

        snapshot.match("list-objects-with-max-buckets", response)

    @markers.aws.validated
    def test_list_buckets_when_continuation_token_is_empty(
        self, s3_create_bucket, aws_client, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("ContinuationToken"))

        s3_create_bucket()
        s3_create_bucket()

        response = aws_client.s3.list_buckets(ContinuationToken="", MaxBuckets=1)
        assert len(response["Buckets"]) == 1

        snapshot.match("list-objects-with-empty-continuation-token", response)

    @markers.aws.validated
    # In some regions AWS returns the Owner display name (us-west-2) but in some it doesnt (eu-central-1)
    @markers.snapshot.skip_snapshot_verify(
        paths=["$.list-objects-by-bucket-region-empty..Owner.DisplayName"]
    )
    def test_list_buckets_by_bucket_region(
        self, s3_create_bucket, s3_create_bucket_with_client, aws_client_factory, snapshot
    ):
        region_us_west_2 = "us-west-2"
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.regex(region_us_west_2, "<region>"))

        s3_create_bucket()
        client_us_west_2 = aws_client_factory(region_name=region_us_west_2).s3

        bucket_name = f"test-bucket-{short_uid()}"
        s3_create_bucket_with_client(
            client_us_west_2,
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region_us_west_2},
        )

        region_eu_central_1 = "eu-central-1"
        client_eu_central_1 = aws_client_factory(region_name=region_eu_central_1).s3
        response = client_eu_central_1.list_buckets(
            BucketRegion=region_eu_central_1, Prefix=bucket_name
        )
        assert len(response["Buckets"]) == 0

        snapshot.match("list-objects-by-bucket-region-empty", response)

        response = client_us_west_2.list_buckets(BucketRegion=region_us_west_2, Prefix=bucket_name)
        assert len(response["Buckets"]) == 1

        returned_bucket = response["Buckets"][0]
        assert returned_bucket["BucketRegion"] == region_us_west_2

        snapshot.match("list-objects-by-bucket-region-not-empty", response)

    @markers.aws.validated
    def test_list_buckets_with_continuation_token(self, s3_create_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("ContinuationToken"))

        s3_create_bucket()
        s3_create_bucket()
        s3_create_bucket()
        response = aws_client.s3.list_buckets(MaxBuckets=1)
        assert "ContinuationToken" in response

        first_returned_bucket = response["Buckets"][0]
        continuation_token = response["ContinuationToken"]

        response = aws_client.s3.list_buckets(MaxBuckets=1, ContinuationToken=continuation_token)

        continuation_returned_bucket = response["Buckets"][0]
        assert first_returned_bucket["Name"] != continuation_returned_bucket["Name"]

        snapshot.match("list-objects-with-continuation", response)


class TestS3ListObjects:
    @markers.aws.validated
    @pytest.mark.parametrize("delimiter", ["", "/", "%2F"])
    def test_list_objects_with_prefix(
        self, s3_bucket, delimiter, snapshot, aws_client, aws_http_client_factory
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        key = "test/foo/bar/123"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects(
            Bucket=s3_bucket, Prefix="test/", Delimiter=delimiter, MaxKeys=1, EncodingType="url"
        )
        snapshot.match("list-objects", response)

        # Boto always add `EncodingType=url` in the request, so we need to bypass it to see the proper result, but only
        # if %2F is already encoded
        # change the prefix to `test` because it has a `/` in it which wouldn't work in the URL
        # see https://github.com/boto/boto3/issues/816
        if delimiter == "%2F":
            bucket_url = f"{_bucket_url(s3_bucket)}?prefix=test&delimiter={delimiter}"
            s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
            resp = s3_http_client.get(
                bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
            )
            resp_dict = xmltodict.parse(resp.content)
            resp_dict["ListBucketResult"].pop("@xmlns", None)
            snapshot.match("list-objects-no-encoding", resp_dict)

    @markers.aws.validated
    def test_list_objects_next_marker(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("NextMarker"))
        snapshot.add_transformer(snapshot.transform.key_value("Key"), priority=-1)
        keys = [f"test_{i}" for i in range(3)]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects(Bucket=s3_bucket)
        snapshot.match("list-objects-all", response)

        response = aws_client.s3.list_objects(Bucket=s3_bucket, MaxKeys=1, Delimiter="/")
        snapshot.match("list-objects-max-1", response)
        # next marker is not there by default, you need a delimiter or you need to use the last key
        next_marker = response["NextMarker"]

        response = aws_client.s3.list_objects(Bucket=s3_bucket, Marker=next_marker, MaxKeys=1)
        snapshot.match("list-objects-rest", response)

        resp = aws_client.s3.list_objects(Bucket=s3_bucket, Marker="", MaxKeys=1)
        snapshot.match("list-objects-marker-empty", resp)

    @markers.aws.validated
    def test_s3_list_objects_empty_marker(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        resp = aws_client.s3.list_objects(Bucket=s3_bucket, Marker="")
        snapshot.match("list-objects", resp)

    @markers.aws.validated
    def test_list_objects_marker_common_prefixes(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        keys = [
            "folder/aSubfolder/subFile1",
            "folder/aSubfolder/subFile2",
            "folder/file1",
            "folder/file2",
        ]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects(Bucket=s3_bucket)
        snapshot.match("list-objects-all-keys", response)

        response = aws_client.s3.list_objects(
            Bucket=s3_bucket, Prefix="folder/", Delimiter="/", MaxKeys=1
        )
        snapshot.match("list-objects-start", response)
        marker_1 = response["NextMarker"]

        response = aws_client.s3.list_objects(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            Marker=marker_1,
        )
        snapshot.match("list-objects-next-1", response)
        marker_2 = response["NextMarker"]

        response = aws_client.s3.list_objects(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            Marker=marker_2,
        )
        snapshot.match("list-objects-end", response)
        assert not response["IsTruncated"]

        # try manually with the first key from the list, to assert the skipping of the second key as well
        response = aws_client.s3.list_objects(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            Marker="folder/aSubfolder/subFile1",
        )
        snapshot.match("list-objects-manual-first-file", response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "querystring", ["", "?list-type=2"], ids=["ListObjects", "ListObjectsV2"]
    )
    def test_s3_list_objects_timestamp_precision(
        self, s3_bucket, aws_client, aws_http_client_factory, querystring
    ):
        # behaviour is shared with ListObjectsV2 so we can do it in the same test
        aws_client.s3.put_object(Bucket=s3_bucket, Key="test-key", Body="test-body")
        bucket_url = f"{_bucket_url(s3_bucket)}{querystring}"
        # Boto automatically parses the timestamp to ISO8601 with no precision, but AWS returns a different format
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)
        timestamp: str = resp_dict["ListBucketResult"]["Contents"]["LastModified"]

        # the timestamp should be looking like the following: 2023-11-15T12:02:40.000Z
        assert_timestamp_is_iso8061_s3_format(timestamp)


class TestS3ListObjectsV2:
    @markers.aws.validated
    def test_list_objects_v2_with_prefix(
        self, s3_bucket, snapshot, aws_client, aws_http_client_factory
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        keys = ["test/foo/bar/123", "test/foo/bar/456", "test/bar/foo/123"]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/", EncodingType="url"
        )
        snapshot.match("list-objects-v2-1", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/foo", EncodingType="url"
        )
        snapshot.match("list-objects-v2-2", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/foo/bar", EncodingType="url"
        )
        snapshot.match("list-objects-v2-3", response)

        # test without EncodingUrl, manually encode parameters
        bucket_url = f"{_bucket_url(s3_bucket)}?list-type=2&prefix=test%2Ffoo"
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)
        resp_dict["ListBucketResult"].pop("@xmlns", None)
        snapshot.match("list-objects-v2-no-encoding", resp_dict)

    @markers.aws.validated
    def test_list_objects_v2_with_prefix_and_delimiter(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("NextContinuationToken"))
        keys = ["test/foo/bar/123", "test/foo/bar/456", "test/bar/foo/123"]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/", EncodingType="url", Delimiter="/"
        )
        snapshot.match("list-objects-v2-1", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket,
            Prefix="test/",
            EncodingType="url",
            Delimiter="/",
            MaxKeys=1,
        )
        snapshot.match("list-objects-v2-1-with-max-keys", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/foo", EncodingType="url", Delimiter="/"
        )
        snapshot.match("list-objects-v2-2", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="test/foo/bar", EncodingType="url", Delimiter="/"
        )
        snapshot.match("list-objects-v2-3", response)

    @markers.aws.validated
    def test_list_objects_v2_continuation_start_after(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("NextContinuationToken"))
        keys = [f"test_{i}" for i in range(12)]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects_v2(Bucket=s3_bucket, MaxKeys=5)
        snapshot.match("list-objects-v2-max-5", response)

        continuation_token = response["NextContinuationToken"]

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, ContinuationToken=continuation_token
        )
        snapshot.match("list-objects-v2-rest", response)

        # verify isTruncated behaviour
        response = aws_client.s3.list_objects_v2(Bucket=s3_bucket, StartAfter="test_7", MaxKeys=2)
        snapshot.match("list-objects-start-after", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket,
            StartAfter="test_7",
            ContinuationToken=continuation_token,
        )
        snapshot.match("list-objects-start-after-token", response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.list_objects_v2(Bucket=s3_bucket, ContinuationToken="")
        snapshot.match("exc-continuation-token", e.value.response)

    @markers.aws.validated
    def test_list_objects_v2_continuation_common_prefixes(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("NextContinuationToken"))
        keys = [
            "folder/aSubfolder/subFile1",
            "folder/aSubfolder/subFile2",
            "folder/file1",
            "folder/file2",
        ]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_objects_v2(Bucket=s3_bucket)
        snapshot.match("list-objects-v2-all-keys", response)

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket, Prefix="folder/", Delimiter="/", MaxKeys=1
        )
        snapshot.match("list-objects-v2-start", response)
        continuation_token_1 = response["NextContinuationToken"]

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            ContinuationToken=continuation_token_1,
        )
        snapshot.match("list-objects-v2-next-1", response)
        continuation_token_2 = response["NextContinuationToken"]

        response = aws_client.s3.list_objects_v2(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            ContinuationToken=continuation_token_2,
        )
        snapshot.match("list-objects-v2-end", response)
        assert "NextContinuationToken" not in response


class TestS3ListObjectVersions:
    @markers.aws.validated
    def test_list_objects_versions_markers(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        keys = [f"test_{i}" for i in range(3)]
        # we need to snapshot the version ids in order of creation to understand better the ordering in snapshots
        versions_ids = []
        for key in keys:
            resp = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"version 1")
            versions_ids.append(resp["VersionId"])

        # add versions on top
        resp = aws_client.s3.put_object(Bucket=s3_bucket, Key=keys[2], Body=b"version 2")
        versions_ids.append(resp["VersionId"])

        # put DeleteMarkers to change a bit the ordering
        for key in keys:
            resp = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
            versions_ids.append(resp["VersionId"])
        # re-add versions for some
        for key in keys[:2]:
            resp = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"version 2")
            versions_ids.append(resp["VersionId"])

        snapshot.match(
            "version-order",
            {"Versions": [{"VersionId": version_id} for version_id in versions_ids]},
        )
        # get everything to check default order
        response = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-objects-versions-all", response)

        response = aws_client.s3.list_object_versions(Bucket=s3_bucket, MaxKeys=5)
        snapshot.match("list-objects-versions-5", response)

        next_key_marker = response["NextKeyMarker"]
        next_version_id_marker = response["NextVersionIdMarker"]

        # try to see what's next when specifying only one
        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket, MaxKeys=1, KeyMarker=next_key_marker
        )
        snapshot.match("list-objects-next-key-only", response)

        # try with last key
        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket, MaxKeys=1, KeyMarker=keys[-1]
        )
        snapshot.match("list-objects-next-key-last", response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.list_object_versions(
                Bucket=s3_bucket, MaxKeys=1, VersionIdMarker=next_version_id_marker
            )
        snapshot.match("list-objects-next-version-only", e.value.response)

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            MaxKeys=1,
            KeyMarker=next_key_marker,
            VersionIdMarker=next_version_id_marker,
        )
        snapshot.match("list-objects-both-markers", response)

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            MaxKeys=1,
            KeyMarker=keys[-1],
            VersionIdMarker=versions_ids[3],
        )
        snapshot.match("list-objects-last-key-last-version", response)

        response = aws_client.s3.list_object_versions(Bucket=s3_bucket, MaxKeys=1, KeyMarker="")
        snapshot.match("list-objects-next-key-empty", response)

    @markers.aws.validated
    def test_list_object_versions_pagination_common_prefixes(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())

        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        keys = [
            "folder/aSubfolder/subFile1",
            "folder/aSubfolder/subFile2",
            "folder/file1",
            "folder/file2",
        ]
        for key in keys:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"content 123")

        response = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-object-versions-all-keys", response)

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket, Prefix="folder/", Delimiter="/", MaxKeys=1
        )
        snapshot.match("list-object-versions-start", response)
        next_key_marker_1 = response["NextKeyMarker"]

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            KeyMarker=next_key_marker_1,
        )
        snapshot.match("list-object-versions-next-1", response)
        next_key_marker_2 = response["NextKeyMarker"]

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            KeyMarker=next_key_marker_2,
        )
        snapshot.match("list-object-versions-end", response)
        assert not response["IsTruncated"]

        response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxKeys=1,
            KeyMarker="folder/aSubfolder/subFile1",
        )
        snapshot.match("list-object-versions-manual-first-file", response)

    @markers.aws.validated
    def test_list_objects_versions_with_prefix(
        self, s3_bucket, snapshot, aws_client, aws_http_client_factory
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        objects = [
            {"Key": "dir/test", "Content": b"content key1-v1"},
            {"Key": "dir/test", "Content": b"content key-1v2"},
            {"Key": "dir/subdir/test2", "Content": b"content key2-v1"},
            {"Key": "dir/subdir/test2", "Content": b"content key2-v2"},
        ]
        params = [
            {"Prefix": "dir/", "Delimiter": "/", "Id": 1},
            {"Prefix": "dir/s", "Delimiter": "/", "Id": 2},
            {"Prefix": "dir/test", "Delimiter": "/", "Id": 3},
            {"Prefix": "dir/subdir", "Delimiter": "/", "Id": 4},
            {"Prefix": "dir/subdir/", "Delimiter": "/", "Id": 5},
            {"Prefix": "dir/subdir/test2", "Delimiter": "/", "Id": 6},
        ]

        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        for obj in objects:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=obj["Key"], Body=obj["Content"])

        for param in params:
            response = aws_client.s3.list_object_versions(
                Bucket=s3_bucket, Delimiter=param["Delimiter"], Prefix=param["Prefix"]
            )
            snapshot.match(f"list-object-version-{param['Id']}", response)

        # test without EncodingUrl, manually encode parameters
        bucket_url = f"{_bucket_url(s3_bucket)}?versions&prefix=dir%2Fsubdir&delimiter=%2F"
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)
        resp_dict["ListVersionsResult"].pop("@xmlns", None)
        snapshot.match("list-objects-versions-no-encoding", resp_dict)

    @markers.aws.validated
    def test_list_objects_versions_with_prefix_only_and_pagination(
        self,
        s3_bucket,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        for _ in range(5):
            aws_client.s3.put_object(Bucket=s3_bucket, Key="prefixed_key")

        aws_client.s3.put_object(Bucket=s3_bucket, Key="non_prefixed_key")

        prefixed_full = aws_client.s3.list_object_versions(Bucket=s3_bucket, Prefix="prefix")
        snapshot.match("list-object-version-prefix-full", prefixed_full)

        full_response = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        assert len(full_response["Versions"]) == 6

        page_1_response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket, Prefix="prefix", MaxKeys=3
        )
        snapshot.match("list-object-version-prefix-page-1", page_1_response)
        next_version_id_marker = page_1_response["NextVersionIdMarker"]

        page_2_key_marker_only = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="prefix",
            MaxKeys=4,
            KeyMarker=page_1_response["NextKeyMarker"],
        )
        snapshot.match("list-object-version-prefix-key-marker-only", page_2_key_marker_only)

        page_2_response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="prefix",
            MaxKeys=5,
            KeyMarker=page_1_response["NextKeyMarker"],
            VersionIdMarker=page_1_response["NextVersionIdMarker"],
        )
        snapshot.match("list-object-version-prefix-page-2", page_2_response)

        delete_version_id_marker = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {"Key": version["Key"], "VersionId": version["VersionId"]}
                    for version in page_1_response["Versions"]
                ],
            },
        )
        # result is unordered in AWS, pretty hard to snapshot and tested in other places anyway
        assert len(delete_version_id_marker["Deleted"]) == 3
        assert any(
            version["VersionId"] == next_version_id_marker
            for version in delete_version_id_marker["Deleted"]
        )

        page_2_response = aws_client.s3.list_object_versions(
            Bucket=s3_bucket,
            Prefix="prefix",
            MaxKeys=5,
            KeyMarker=page_1_response["NextKeyMarker"],
            VersionIdMarker=next_version_id_marker,
        )
        snapshot.match("list-object-version-prefix-page-2-after-delete", page_2_response)

    @markers.aws.validated
    def test_list_objects_versions_with_prefix_only_and_pagination_many_versions(
        self,
        s3_bucket,
        aws_client,
    ):
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # with our internal pagination system, we use characters from the alphabet (lower and upper) + digits
        # by creating more than 100 objects, we can make sure we circle all the way around our sequencing, and properly
        # paginate over all of them
        for _ in range(101):
            aws_client.s3.put_object(Bucket=s3_bucket, Key="prefixed_key")

        paginator = aws_client.s3.get_paginator("list_object_versions")
        # even if the PageIterator looks like it should be an iterator, it's actually an iterable and needs to be
        # wrapped in `iter`
        page_iterator = iter(
            paginator.paginate(
                Bucket=s3_bucket, Prefix="prefix", PaginationConfig={"PageSize": 100}
            )
        )
        page_1 = next(page_iterator)
        assert len(page_1["Versions"]) == 100

        page_2 = next(page_iterator)
        assert len(page_2["Versions"]) == 1

    @markers.aws.validated
    def test_s3_list_object_versions_timestamp_precision(
        self, s3_bucket, aws_client, aws_http_client_factory
    ):
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # put Objects and DeleteMarker
        aws_client.s3.put_object(Bucket=s3_bucket, Key="test-key", Body="test-body")
        aws_client.s3.delete_object(Bucket=s3_bucket, Key="test-key")

        bucket_url = f"{_bucket_url(s3_bucket)}?versions"
        # Boto automatically parses the timestamp to ISO8601 with no precision, but AWS returns a different format
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)

        timestamp_obj: str = resp_dict["ListVersionsResult"]["Version"]["LastModified"]
        timestamp_marker: str = resp_dict["ListVersionsResult"]["DeleteMarker"]["LastModified"]

        for timestamp in (timestamp_obj, timestamp_marker):
            # the timestamp should be looking like the following: 2023-11-15T12:02:40.000Z
            assert_timestamp_is_iso8061_s3_format(timestamp)


class TestS3ListMultipartUploads:
    @markers.aws.validated
    def test_list_multiparts_next_marker(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("Bucket"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value(
                    "ID", value_replacement="owner-id", reference_replacement=False
                ),
            ]
        )
        snapshot.add_transformer(snapshot.transform.key_value("Key"), priority=-1)

        response = aws_client.s3.list_multipart_uploads(Bucket=s3_bucket)
        snapshot.match("list-multiparts-empty", response)

        keys = ["test_c", "test_b", "test_a"]
        uploads_ids = []
        for key in keys:
            # create 1 upload per key, except for the last one
            resp = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
            uploads_ids.append(resp["UploadId"])
            if key == "test_a":
                for _ in range(2):
                    # add more upload for the last key to test UploadId ordering
                    resp = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
                    uploads_ids.append(resp["UploadId"])

        # snapshot the upload ids ordering to compare with listing
        snapshot.match(
            "upload-ids-order",
            {"UploadIds": [{"UploadId": upload_id} for upload_id in uploads_ids]},
        )

        # AWS is saying on the doc that `UploadId` are sorted lexicographically, however tests shows that it's sorted
        # by the Initiated time of the multipart
        response = aws_client.s3.list_multipart_uploads(Bucket=s3_bucket)
        snapshot.match("list-multiparts-all", response)

        response = aws_client.s3.list_multipart_uploads(Bucket=s3_bucket, MaxUploads=1)
        snapshot.match("list-multiparts-max-1", response)

        next_key_marker = response["NextKeyMarker"]
        next_upload_id_marker = response["NextUploadIdMarker"]

        # try to see what's next when specifying only one
        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket, MaxUploads=1, KeyMarker=next_key_marker
        )
        snapshot.match("list-multiparts-next-key-only", response)

        # try with last key lexicographically
        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket, MaxUploads=1, KeyMarker=keys[0]
        )
        snapshot.match("list-multiparts-next-key-last", response)

        # UploadIdMarker is ignored if KeyMarker is not specified
        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            MaxUploads=1,
            UploadIdMarker=next_upload_id_marker,
        )
        snapshot.match("list-multiparts-next-upload-only", response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            MaxUploads=1,
            KeyMarker=next_key_marker,
            UploadIdMarker=next_upload_id_marker,
        )
        snapshot.match("list-multiparts-both-markers", response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            MaxUploads=1,
            KeyMarker=next_key_marker,
            UploadIdMarker=uploads_ids[-1],
        )
        snapshot.match("list-multiparts-both-markers-2", response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            MaxUploads=1,
            KeyMarker=keys[1],
            UploadIdMarker=uploads_ids[1],
        )
        snapshot.match("list-multiparts-get-last-upload-no-truncate", response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.list_multipart_uploads(
                Bucket=s3_bucket,
                MaxUploads=1,
                KeyMarker=keys[0],
                UploadIdMarker=uploads_ids[1],
            )
        snapshot.match("list-multiparts-wrong-id-for-key", e.value.response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket, MaxUploads=1, KeyMarker=""
        )
        snapshot.match("list-multiparts-next-key-empty", response)

    @markers.aws.validated
    def test_list_multiparts_with_prefix_and_delimiter(
        self, s3_bucket, snapshot, aws_client, aws_http_client_factory
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("Bucket"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value(
                    "ID", value_replacement="owner-id", reference_replacement=False
                ),
            ]
        )
        snapshot.add_transformer(snapshot.transform.key_value("Key"), priority=-1)
        keys = ["test/foo/bar/123", "test/foo/bar/456", "test/bar/foo/123"]
        for key in keys:
            aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            Prefix="test/",
            EncodingType="url",
            Delimiter="/",
        )
        snapshot.match("list-multiparts-1", response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket, Prefix="test/foo/", EncodingType="url", Delimiter="/"
        )
        snapshot.match("list-multiparts-2", response)

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket, Prefix="test/foo/bar", EncodingType="url", Delimiter="/"
        )
        snapshot.match("list-multiparts-3", response)

        # test without EncodingUrl, manually encode parameters
        bucket_url = f"{_bucket_url(s3_bucket)}?uploads&prefix=test%2Ffoo"
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)
        resp_dict["ListMultipartUploadsResult"].pop("@xmlns", None)
        snapshot.match("list-multiparts-no-encoding", resp_dict)

    @markers.aws.validated
    def test_list_multipart_uploads_marker_common_prefixes(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("Bucket"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value(
                    "ID", value_replacement="owner-id", reference_replacement=False
                ),
            ]
        )

        keys = [
            "folder/aSubfolder/subFile1",
            "folder/aSubfolder/subFile2",
            "folder/file1",
            "folder/file2",
        ]
        uploads_ids = []
        for key in keys:
            resp = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
            uploads_ids.append(resp["UploadId"])

        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxUploads=1,
        )
        snapshot.match("list-multiparts-start", response)
        # AWS does not return a NextKeyMarker or a NextUploadIdMarker, so there is no way to paginate from here

        # try manually from previous experience with ListObjectVersions and ListObjects?
        # this is equal of using the last prefix: CommonPrefix[-1]["Prefix"]
        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxUploads=1,
            KeyMarker="folder/aSubfolder/",
        )
        snapshot.match("list-multiparts-manual-prefix", response)

        # try manually with the first key from the list, to assert the skipping of the second key as well
        response = aws_client.s3.list_multipart_uploads(
            Bucket=s3_bucket,
            Prefix="folder/",
            Delimiter="/",
            MaxUploads=1,
            KeyMarker="folder/aSubfolder/subFile1",
        )
        snapshot.match("list-multiparts-manual-first-file", response)

    @markers.aws.validated
    def test_s3_list_multiparts_timestamp_precision(
        self, s3_bucket, aws_client, aws_http_client_factory
    ):
        object_key = "test-list-part-empty-marker"
        response = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=object_key)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        bucket_url = f"{_bucket_url(s3_bucket)}?uploads"
        # Boto automatically parses the timestamp to ISO8601 with no precision, but AWS returns a different format
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)

        timestamp: str = resp_dict["ListMultipartUploadsResult"]["Upload"]["Initiated"]
        # the timestamp should be looking like the following: 2023-11-15T12:02:40.000Z
        assert_timestamp_is_iso8061_s3_format(timestamp)


class TestS3ListParts:
    @markers.aws.validated
    def test_list_parts_pagination(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("ID", reference_replacement=False),
            ]
        )
        object_key = "test-list-part-pagination"
        response = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=object_key)
        upload_id = response["UploadId"]

        response = aws_client.s3.list_parts(Bucket=s3_bucket, UploadId=upload_id, Key=object_key)
        snapshot.match("list-parts-empty", response)

        for i in range(1, 3):
            aws_client.s3.upload_part(
                Bucket=s3_bucket,
                Key=object_key,
                Body=BytesIO(b"data"),
                PartNumber=i,
                UploadId=upload_id,
            )

        response = aws_client.s3.list_parts(Bucket=s3_bucket, UploadId=upload_id, Key=object_key)
        snapshot.match("list-parts-all", response)

        response = aws_client.s3.list_parts(
            Bucket=s3_bucket, UploadId=upload_id, Key=object_key, MaxParts=1
        )
        next_part_number_marker = response["NextPartNumberMarker"]
        snapshot.match("list-parts-1", response)

        response = aws_client.s3.list_parts(
            Bucket=s3_bucket,
            UploadId=upload_id,
            Key=object_key,
            MaxParts=1,
            PartNumberMarker=next_part_number_marker,
        )

        snapshot.match("list-parts-next", response)

        response = aws_client.s3.list_parts(
            Bucket=s3_bucket,
            UploadId=upload_id,
            Key=object_key,
            MaxParts=1,
            PartNumberMarker=10,
        )
        snapshot.match("list-parts-wrong-part", response)

    @markers.aws.validated
    def test_list_parts_empty_part_number_marker(self, s3_bucket, snapshot, aws_client_factory):
        # we need to disable validation for this test
        s3_client = aws_client_factory(config=Config(parameter_validation=False)).s3
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("ID", reference_replacement=False),
            ]
        )
        object_key = "test-list-part-empty-marker"
        response = s3_client.create_multipart_upload(Bucket=s3_bucket, Key=object_key)
        upload_id = response["UploadId"]

        s3_client.upload_part(
            Bucket=s3_bucket,
            Key=object_key,
            Body=BytesIO(b"data"),
            PartNumber=1,
            UploadId=upload_id,
        )
        # it seems S3 does not care about empty string for integer query string parameters
        response = s3_client.list_parts(
            Bucket=s3_bucket, UploadId=upload_id, Key=object_key, PartNumberMarker=""
        )
        snapshot.match("list-parts-empty-marker", response)

        response = s3_client.list_parts(
            Bucket=s3_bucket, UploadId=upload_id, Key=object_key, MaxParts=""
        )
        snapshot.match("list-parts-empty-max-parts", response)

    @markers.aws.validated
    def test_s3_list_parts_timestamp_precision(
        self, s3_bucket, aws_client, aws_http_client_factory
    ):
        object_key = "test-list-part-empty-marker"
        response = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=object_key)
        upload_id = response["UploadId"]

        aws_client.s3.upload_part(
            Bucket=s3_bucket,
            Key=object_key,
            Body=BytesIO(b"data"),
            PartNumber=1,
            UploadId=upload_id,
        )

        bucket_url = f"{_bucket_url(s3_bucket)}/{object_key}?uploadId={upload_id}"
        # Boto automatically parses the timestamp to ISO8601 with no precision, but AWS returns a different format
        s3_http_client = aws_http_client_factory("s3", signer_factory=SigV4Auth)
        resp = s3_http_client.get(bucket_url, headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
        resp_dict = xmltodict.parse(resp.content)

        timestamp: str = resp_dict["ListPartsResult"]["Part"]["LastModified"]
        # the timestamp should be looking like the following: 2023-11-15T12:02:40.000Z
        assert_timestamp_is_iso8061_s3_format(timestamp)

    @markers.aws.validated
    def test_list_parts_via_object_attrs_pagination(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("ID", reference_replacement=False),
            ]
        )
        object_key = "test-object-attrs-pagination"
        response = aws_client.s3.create_multipart_upload(
            Bucket=s3_bucket, Key=object_key, ChecksumAlgorithm="SHA256"
        )
        upload_id = response["UploadId"]

        # data must be at least 5MiB
        part_data = b"a" * (5_242_880 + 1)
        multipart_upload_parts = []

        for i in range(1, 3):
            upload_part = aws_client.s3.upload_part(
                Bucket=s3_bucket,
                Key=object_key,
                Body=part_data,
                PartNumber=i,
                UploadId=upload_id,
                ChecksumAlgorithm="SHA256",
            )
            multipart_upload_parts.append(
                {
                    "ETag": upload_part["ETag"],
                    "PartNumber": i,
                    "ChecksumSHA256": upload_part["ChecksumSHA256"],
                }
            )

        response = aws_client.s3.list_parts(Bucket=s3_bucket, UploadId=upload_id, Key=object_key)
        snapshot.match("list-parts", response)

        complete_multipart = aws_client.s3.complete_multipart_upload(
            Bucket=s3_bucket,
            UploadId=upload_id,
            Key=object_key,
            MultipartUpload={"Parts": multipart_upload_parts},
        )
        snapshot.match("complete-mpu", complete_multipart)

        object_attrs = aws_client.s3.get_object_attributes(
            Bucket=s3_bucket,
            Key=object_key,
            ObjectAttributes=["ObjectParts"],
        )
        snapshot.match("get-object-attrs-all", object_attrs)

        object_attrs_1 = aws_client.s3.get_object_attributes(
            Bucket=s3_bucket, Key=object_key, ObjectAttributes=["ObjectParts"], MaxParts=1
        )
        snapshot.match("get-object-attrs-1", object_attrs)
        next_part_number_marker = object_attrs_1["ObjectParts"]["NextPartNumberMarker"]

        object_attrs_next = aws_client.s3.get_object_attributes(
            Bucket=s3_bucket,
            Key=object_key,
            ObjectAttributes=["ObjectParts"],
            MaxParts=1,
            PartNumberMarker=next_part_number_marker,
        )
        snapshot.match("get-object-attrs-next", object_attrs_next)

        object_attrs_wrong = aws_client.s3.get_object_attributes(
            Bucket=s3_bucket,
            Key=object_key,
            ObjectAttributes=["ObjectParts"],
            MaxParts=1,
            PartNumberMarker=10,
        )
        snapshot.match("get-object-attrs-wrong-part", object_attrs_wrong)
