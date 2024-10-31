import json
import string
from operator import itemgetter
from urllib.parse import urlencode

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid, short_uid
from tests.aws.services.s3.conftest import TEST_S3_IMAGE, is_v2_provider


@markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..ServerSideEncryption"])
class TestS3BucketCRUD:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider, paths=["$.delete-with-obj.Error.BucketName"]
    )
    def test_delete_bucket_with_objects(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        key_name = "test-delete"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_bucket(Bucket=s3_bucket)
        snapshot.match("delete-with-obj", e.value.response)

        delete_object = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-obj", delete_object)

        delete_bucket = aws_client.s3.delete_bucket(Bucket=s3_bucket)
        snapshot.match("delete-bucket", delete_bucket)
        # TODO: write a test with a multipart upload that is not completed?

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider,
        paths=[
            "$..Error.BucketName",
            "$..Error.Message",
            "$.delete-marker-by-version.DeleteMarker",
        ],
    )
    def test_delete_versioned_bucket_with_objects(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # enable versioning on the bucket
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        key_name = "test-delete-versioned"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")
        # try deleting without specifying the object version, it sets a DeleteMarker on top
        put_delete_marker = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_bucket(Bucket=s3_bucket)
        snapshot.match("delete-with-obj-and-delete-marker", e.value.response)

        # delete the object directly by its version, only the delete marker is left
        delete_object_by_version = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=key_name, VersionId=put_object["VersionId"]
        )
        snapshot.match("delete-obj-by-version", delete_object_by_version)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_bucket(Bucket=s3_bucket)
        snapshot.match("delete-with-only-delete-marker", e.value.response)

        # delete the delete marker, the bucket should now be empty
        delete_marker_by_version = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=key_name, VersionId=put_delete_marker["VersionId"]
        )
        snapshot.match("delete-marker-by-version", delete_marker_by_version)

        delete_bucket = aws_client.s3.delete_bucket(Bucket=s3_bucket)
        snapshot.match("success-delete-bucket", delete_bucket)


@markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..ServerSideEncryption"])
class TestS3ObjectCRUD:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not raise exceptions",
    )
    def test_delete_object(self, s3_bucket, aws_client, snapshot):
        key_name = "test-delete"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")
        snapshot.match("put-object", put_object)

        delete_object = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-object", delete_object)

        delete_object_2 = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-nonexistent-object", delete_object_2)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object(
                Bucket=s3_bucket, Key=key_name, VersionId="HPniJFCxqTsMuIH9KX8K8wEjNUgmABCD"
            )
        snapshot.match("delete-nonexistent-object-versionid", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not raise exceptions",
    )
    def test_delete_objects(self, s3_bucket, aws_client, snapshot):
        key_name = "test-delete"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")
        snapshot.match("put-object", put_object)

        delete_objects = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [{"Key": key_name, "VersionId": "HPniJFCxqTsMuIH9KX8K8wEjNUgmABCD"}]
            },
        )

        snapshot.match("delete-object-wrong-version-id", delete_objects)

        delete_objects = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {"Key": key_name},
                    {"Key": "c-wrong-key"},
                    {"Key": "a-wrong-key"},
                ]
            },
        )
        delete_objects["Deleted"].sort(key=itemgetter("Key"))

        snapshot.match("delete-objects", delete_objects)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not return proper headers",
    )
    def test_delete_object_versioned(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("ArgumentValue"))
        # enable versioning on the bucket
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )

        key_name = "test-delete"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")
        snapshot.match("put-object", put_object)
        object_version_id = put_object["VersionId"]

        # try deleting the last version of the object, it sets a DeleteMarker on top
        delete_object = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-object", delete_object)
        delete_marker_version_id = delete_object["VersionId"]

        # try GetObject without VersionId
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-deleted-object", e.value.response)

        # Boto does not parse those headers in the exception, but they are present
        response_headers = e.value.response["ResponseMetadata"]["HTTPHeaders"]
        assert response_headers["x-amz-delete-marker"] == "true"
        assert response_headers["x-amz-version-id"] == delete_marker_version_id

        # try GetObject with VersionId
        get_object_with_version = aws_client.s3.get_object(
            Bucket=s3_bucket, Key=key_name, VersionId=object_version_id
        )
        snapshot.match("get-object-with-version", get_object_with_version)

        # try GetObject on a DeleteMarker
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(
                Bucket=s3_bucket, Key=key_name, VersionId=delete_marker_version_id
            )
        snapshot.match("get-delete-marker", e.value.response)

        # Boto does not parse those headers in the exception, but they are present
        response_headers = e.value.response["ResponseMetadata"]["HTTPHeaders"]
        assert response_headers["x-amz-delete-marker"] == "true"
        assert response_headers["x-amz-version-id"] == delete_marker_version_id
        assert response_headers["allow"] == "DELETE"

        # delete again without specifying a VersionId, this will just pile another DeleteMarker onto the stack
        delete_object_2 = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-object-2", delete_object_2)

        list_object_version = aws_client.s3.list_object_versions(Bucket=s3_bucket, Prefix=key_name)
        snapshot.match("list-object-versions", list_object_version)

        # delete a DeleteMarker directly
        delete_marker = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=key_name, VersionId=delete_marker_version_id
        )
        snapshot.match("delete-delete-marker", delete_marker)
        # assert that the returned VersionId is the same as the DeleteMarker, indicating that the DeleteMarker
        # was deleted
        assert delete_object["VersionId"] == delete_marker_version_id

        # delete the object directly, without setting a DeleteMarker
        delete_object_version = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=key_name, VersionId=object_version_id
        )
        snapshot.match("delete-object-version", delete_object_version)
        # assert that we properly deleted an object and did not set a DeleteMarker or deleted One
        assert "DeleteMarker" not in delete_object_version

        # try GetObject with VersionId on the now delete ObjectVersion
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name, VersionId=object_version_id)
        snapshot.match("get-deleted-object-with-version", e.value.response)

        response_headers = e.value.response["ResponseMetadata"]["HTTPHeaders"]
        assert "x-amz-delete-marker" not in response_headers
        assert "x-amz-version-id" not in response_headers

        # try to delete with a wrong VersionId
        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object(
                Bucket=s3_bucket,
                Key=key_name,
                VersionId=object_version_id[:-4] + "ABCD",
            )
        snapshot.match("delete-with-bad-version", e.value.response)

        response_headers = e.value.response["ResponseMetadata"]["HTTPHeaders"]
        assert "x-amz-delete-marker" not in response_headers
        assert "x-amz-version-id" not in response_headers

        # try deleting a never existing object
        delete_wrong_key = aws_client.s3.delete_object(Bucket=s3_bucket, Key="wrong-key")
        snapshot.match("delete-wrong-key", delete_wrong_key)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not return right values",
    )
    def test_delete_objects_versioned(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("DeleteMarkerVersionId"))
        snapshot.add_transformer(SortingTransformer("Deleted", itemgetter("Key")))
        snapshot.add_transformer(SortingTransformer("Errors", itemgetter("Key")))
        # enable versioning on the bucket
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )

        key_name = "test-delete"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-delete")
        snapshot.match("put-object", put_object)
        object_version_id = put_object["VersionId"]

        delete_objects = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {"Key": key_name},
                    {"Key": "wrongkey"},
                    {"Key": "wrongkey-x"},
                ]
            },
        )
        snapshot.match("delete-objects-no-version-id", delete_objects)
        delete_marker_version_id = delete_objects["Deleted"][0]["DeleteMarkerVersionId"]

        # delete a DeleteMarker directly
        delete_objects_marker = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {
                        "Key": key_name,
                        "VersionId": delete_marker_version_id,
                    }
                ]
            },
        )
        snapshot.match("delete-objects-marker", delete_objects_marker)

        # delete with a fake VersionId
        delete_objects = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {
                        "Key": key_name,
                        "VersionId": "HPniJFCxqTsMuIH9KX8K8wEjNUgmABCD",
                    },
                    {
                        "Key": "wrong-key-2",
                        "VersionId": "HPniJFCxqTsMuIH9KX8K8wEjNUgmABCD",
                    },
                ]
            },
        )

        snapshot.match("delete-objects-wrong-version-id", delete_objects)

        # delete the object directly, without setting a DeleteMarker
        delete_objects_marker = aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [
                    {
                        "Key": key_name,
                        "VersionId": object_version_id,
                    }
                ]
            },
        )
        snapshot.match("delete-objects-version-id", delete_objects_marker)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation raises the wrong exception",
    )
    def test_get_object_with_version_unversioned_bucket(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        key_name = "test-version"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-version")
        snapshot.match("put-object", put_object)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(
                Bucket=s3_bucket, Key=key_name, VersionId="HPniJFCxqTsMuIH9KX8K8wEjNUgmABCD"
            )
        snapshot.match("get-obj-with-version", e.value.response)

        get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name, VersionId="null")
        snapshot.match("get-obj-with-null-version", get_obj)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation deletes all versions when suspending versioning, when it should keep it",
    )
    def test_put_object_on_suspended_bucket(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # enable versioning on the bucket
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        key_name = "test-version"
        for i in range(3):
            put_object = aws_client.s3.put_object(
                Bucket=s3_bucket, Key=key_name, Body=f"test-version-{i}"
            )
            snapshot.match(f"put-object-{i}", put_object)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-enabled", list_object_versions)
        assert len(list_object_versions["Versions"]) == 3

        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended", list_object_versions)
        assert len(list_object_versions["Versions"]) == 3

        put_object = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-version-suspended"
        )
        snapshot.match("put-object-suspended", put_object)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended-after-put", list_object_versions)
        assert len(list_object_versions["Versions"]) == 4

        put_object = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-version-suspended"
        )
        snapshot.match("put-object-suspended-overwrite", put_object)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended-after-overwrite", list_object_versions)
        assert len(list_object_versions["Versions"]) == 4

        get_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-object-current", get_object)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation has the wrong behaviour",
    )
    def test_delete_object_on_suspended_bucket(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        # enable versioning on the bucket
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        key_name = "test-delete-suspended"
        for i in range(2):
            put_object = aws_client.s3.put_object(
                Bucket=s3_bucket, Key=key_name, Body=f"test-version-{i}"
            )
            snapshot.match(f"put-object-{i}", put_object)

        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended", list_object_versions)
        assert len(list_object_versions["Versions"]) == 2

        # delete object with no version specified
        delete_object_no_version = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-object-no-version", delete_object_no_version)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended-delete", list_object_versions)
        # assert len(list_object_versions["Versions"]) == 2

        put_object = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-version-suspended-after-delete"
        )
        snapshot.match("put-object-suspended", put_object)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended-put", list_object_versions)

        # delete object with no version specified again, should overwrite the last object
        delete_object_no_version = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("delete-object-no-version-after-put", delete_object_no_version)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-suspended-after-put", list_object_versions)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider,
        paths=[
            "$..Delimiter",
            "$..EncodingType",
            "$..VersionIdMarker",
        ],
    )
    def test_list_object_versions_order_unversioned(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-empty", list_object_versions)

        key_name = "a-test-object-1"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-object-1")
        snapshot.match("put-object", put_object)

        key_name = "c-test-object-3"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-object-3")
        snapshot.match("put-object-3", put_object)

        key_name = "b-test-object-2"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="test-object-2")
        snapshot.match("put-object-2", put_object)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-object-versions", list_object_versions)

    @markers.aws.validated
    def test_get_object_range(self, aws_client, s3_bucket, snapshot):
        content = "0123456789"
        key = "test-key-range"

        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=content)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=0-8")
        snapshot.match("get-0-8", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1-1")
        snapshot.match("get-1-1", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1-0")
        snapshot.match("get-1-0", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=1-")
        snapshot.match("get-1-", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-1-")
        snapshot.match("get--1-", resp)

        # test suffix byte range, returning the 2 last bytes
        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-2")
        snapshot.match("get--2", resp)

        # test suffix byte range, returning the 9 last bytes
        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-9")
        snapshot.match("get--9", resp)

        # test suffix byte range, returning the 15 last bytes, which will return max 0
        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-15")
        snapshot.match("get--15", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=0-100")
        snapshot.match("get-0-100", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=0-0")
        snapshot.match("get-0-0", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=0--1")
        snapshot.match("get-0--1", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=0-1,3-4,7-9")
        snapshot.match("get-multiple-ranges", resp)

        if not config.LEGACY_V2_S3_PROVIDER or is_aws_cloud():
            # FIXME: missing handling in moto for very wrong format of the range header
            resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="0-1")
            snapshot.match("get-wrong-format", resp)

        resp = aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-")
        snapshot.match("get--", resp)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=-0")
        snapshot.match("get--0", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object(Bucket=s3_bucket, Key=key, Range="bytes=100-200")
        snapshot.match("get-100-200", e.value.response)

        # test that we can still put an object on the same key that failed GetObject with range request
        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=content * 2)
        snapshot.match("put-after-failed", put_obj)


@markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..ServerSideEncryption"])
class TestS3Multipart:
    # TODO: write a validated test for UploadPartCopy preconditions

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto does not handle the exceptions properly",
    )
    @markers.snapshot.skip_snapshot_verify(paths=["$..PartNumberMarker"])  # TODO: invetigate this
    def test_upload_part_copy_range(self, aws_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("ID", reference_replacement=False),
            ]
        )
        src_key = "src-key"
        content = "0123456789"
        put_src_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=src_key, Body=content)
        snapshot.match("put-src-object", put_src_object)
        key = "test-upload-part-copy"
        create_multipart = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
        snapshot.match("create-multipart", create_multipart)
        upload_id = create_multipart["UploadId"]

        copy_source_key = f"{s3_bucket}/{src_key}"
        parts = []
        # not using parametrization here as it needs a lot of setup for only one operation tested
        src_ranges_values = [
            "0-8",
            "1-1",
            "0-0",
        ]
        for i, src_range in enumerate(src_ranges_values):
            upload_part_copy = aws_client.s3.upload_part_copy(
                Bucket=s3_bucket,
                UploadId=upload_id,
                Key=key,
                PartNumber=i + 1,
                CopySource=copy_source_key,
                CopySourceRange=f"bytes={src_range}",
            )
            snapshot.match(f"upload-part-copy-{i + 1}", upload_part_copy)
            parts.append({"ETag": upload_part_copy["CopyPartResult"]["ETag"], "PartNumber": i + 1})

        list_parts = aws_client.s3.list_parts(Bucket=s3_bucket, Key=key, UploadId=upload_id)
        snapshot.match("list-parts", list_parts)

        with pytest.raises(ClientError) as e:
            aws_client.s3.upload_part_copy(
                Bucket=s3_bucket,
                UploadId=upload_id,
                Key=key,
                PartNumber=1,
                CopySource=copy_source_key,
                CopySourceRange="0-8",
            )
        snapshot.match("upload-part-copy-wrong-format", e.value.response)

        wrong_src_ranges_values = [
            "1-0",
            "-1-",
            "0--1",
            "0-1,3-4,7-9",
            "-",
            "-0",
            "0-100",
            "100-200",
            "1-",
            "-2",
            "-15",
        ]
        for src_range in wrong_src_ranges_values:
            with pytest.raises(ClientError) as e:
                aws_client.s3.upload_part_copy(
                    Bucket=s3_bucket,
                    UploadId=upload_id,
                    Key=key,
                    PartNumber=1,
                    CopySource=copy_source_key,
                    CopySourceRange=f"bytes={src_range}",
                )
            snapshot.match(f"upload-part-copy-range-exc-{src_range}", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        # Not always present depending on the region
        paths=["$..Owner.DisplayName"],
    )
    def test_upload_part_copy_no_copy_source_range(self, aws_client, s3_bucket, snapshot):
        """
        upload_part_copy should not require CopySourceRange to be populated
        """

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("Bucket", reference_replacement=False),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("DisplayName", reference_replacement=False),
                snapshot.transform.key_value("ID", reference_replacement=False),
            ]
        )

        src_key = "src-key"
        content = "0123456789"
        put_src_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=src_key, Body=content)
        snapshot.match("put-src-object", put_src_object)
        key = "test-upload-part-copy"
        create_multipart = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
        snapshot.match("create-multipart", create_multipart)
        upload_id = create_multipart["UploadId"]

        copy_source_key = f"{s3_bucket}/{src_key}"
        parts = []
        upload_part_copy = aws_client.s3.upload_part_copy(
            Bucket=s3_bucket, UploadId=upload_id, Key=key, PartNumber=1, CopySource=copy_source_key
        )
        snapshot.match("upload-part-copy", upload_part_copy)
        parts.append({"ETag": upload_part_copy["CopyPartResult"]["ETag"], "PartNumber": 1})

        list_parts = aws_client.s3.list_parts(Bucket=s3_bucket, Key=key, UploadId=upload_id)
        snapshot.match("list-parts", list_parts)


class TestS3BucketVersioning:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation not raising exceptions",
    )
    def test_bucket_versioning_crud(self, aws_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        get_versioning_before = aws_client.s3.get_bucket_versioning(Bucket=s3_bucket)
        snapshot.match("get-versioning-before", get_versioning_before)

        put_versioning_suspended_before = aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )
        snapshot.match("put-versioning-suspended-before", put_versioning_suspended_before)

        get_versioning_before = aws_client.s3.get_bucket_versioning(Bucket=s3_bucket)
        snapshot.match("get-versioning-after-suspended", get_versioning_before)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_versioning(
                Bucket=s3_bucket, VersioningConfiguration={"Status": "enabled"}
            )
        snapshot.match("put-versioning-enabled-lowercase", e.value.response)

        put_versioning_enabled = aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        snapshot.match("put-versioning-enabled-capitalized", put_versioning_enabled)

        get_versioning_after = aws_client.s3.get_bucket_versioning(Bucket=s3_bucket)
        snapshot.match("get-versioning-after-enabled", get_versioning_after)

        put_versioning_suspended_after = aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )
        snapshot.match("put-versioning-suspended-after", put_versioning_suspended_after)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_versioning(
                Bucket=s3_bucket, VersioningConfiguration={"Status": "Disabled"}
            )
        snapshot.match("put-versioning-disabled", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_versioning(Bucket=s3_bucket, VersioningConfiguration={})
        snapshot.match("put-versioning-empty", e.value.response)

        fake_bucket = f"myrandombucket{short_uid()}-{short_uid()}"
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_versioning(
                Bucket=fake_bucket, VersioningConfiguration={"Status": "Suspended"}
            )
        snapshot.match("put-versioning-no-bucket", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_versioning(Bucket=fake_bucket)
        snapshot.match("get-versioning-no-bucket", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation is not the right format",
    )
    def test_object_version_id_format(self, aws_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("VersionId"))
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )

        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key="test-version-id")
        snapshot.match("put-object", put_object)
        version_id = put_object["VersionId"]

        # example version id
        # gS53zabD7XTvkrwbjMnXlBylVWetO8ym
        # the conditions under have been tested against more than 100 AWS VersionIds
        assert len(version_id) == 32
        letters_and_digits_and_dot = string.ascii_letters + string.digits + "._"
        assert all(char in letters_and_digits_and_dot for char in version_id)


class TestS3BucketEncryption:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have default encryption",
    )
    def test_s3_default_bucket_encryption(self, s3_bucket, aws_client, snapshot):
        get_default_encryption = aws_client.s3.get_bucket_encryption(Bucket=s3_bucket)
        snapshot.match("default-bucket-encryption", get_default_encryption)

        delete_bucket_encryption = aws_client.s3.delete_bucket_encryption(Bucket=s3_bucket)
        snapshot.match("delete-bucket-encryption", delete_bucket_encryption)

        delete_bucket_encryption_2 = aws_client.s3.delete_bucket_encryption(Bucket=s3_bucket)
        snapshot.match("delete-bucket-encryption-idempotent", delete_bucket_encryption_2)

        bucket_versioning = aws_client.s3.get_bucket_versioning(Bucket=s3_bucket)
        snapshot.match("get-bucket-no-encryption", bucket_versioning)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have proper validation",
    )
    def test_s3_default_bucket_encryption_exc(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.s3_api())
        fake_bucket = f"fakebucket-{short_uid()}-{short_uid()}"
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_encryption(Bucket=fake_bucket)
        snapshot.match("get-bucket-enc-no-bucket", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_bucket_encryption(Bucket=fake_bucket)
        snapshot.match("delete-bucket-enc-no-bucket", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_encryption(
                Bucket=fake_bucket, ServerSideEncryptionConfiguration={"Rules": []}
            )
        snapshot.match("put-bucket-enc-no-bucket", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_encryption(
                Bucket=s3_bucket, ServerSideEncryptionConfiguration={"Rules": []}
            )
        snapshot.match("put-bucket-encryption-no-rules", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_encryption(
                Bucket=s3_bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                            },
                            "BucketKeyEnabled": True,
                        },
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            },
                        },
                    ]
                },
            )
        snapshot.match("put-bucket-encryption-two-rules", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_encryption(
                Bucket=s3_bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                                "KMSMasterKeyID": "randomkeyid",
                            },
                        }
                    ]
                },
            )
        snapshot.match("put-bucket-encryption-kms-with-aes", e.value.response)

    @markers.aws.validated
    def test_s3_bucket_encryption_sse_s3(self, s3_bucket, aws_client, snapshot):
        # AES256 is already the default
        # so set something with the BucketKey, which should only be set for KMS, to see if it returns
        put_bucket_enc = aws_client.s3.put_bucket_encryption(
            Bucket=s3_bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        snapshot.match("put-bucket-enc", put_bucket_enc)

        key_name = "key-encrypted"
        put_object_encrypted = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-encrypted"
        )
        snapshot.match("put-object-encrypted", put_object_encrypted)

        head_object_encrypted = aws_client.s3.head_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("head-object-encrypted", head_object_encrypted)

        get_object_encrypted = aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-object-encrypted", get_object_encrypted)

    @pytest.mark.skipif(condition=TEST_S3_IMAGE, reason="KMS not enabled in S3 image")
    @markers.aws.validated
    # there is currently no server side encryption is place in LS, ETag will be different
    @markers.snapshot.skip_snapshot_verify(paths=["$..ETag"])
    @markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..BucketKeyEnabled"])
    def test_s3_bucket_encryption_sse_kms(self, s3_bucket, kms_key, aws_client, snapshot):
        put_bucket_enc = aws_client.s3.put_bucket_encryption(
            Bucket=s3_bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key["KeyId"],
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        snapshot.match("put-bucket-enc", put_bucket_enc)

        get_bucket_enc = aws_client.s3.get_bucket_encryption(Bucket=s3_bucket)
        snapshot.match("get-bucket-enc", get_bucket_enc)

        key_name = "key-encrypted"
        put_object_encrypted = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-encrypted"
        )
        snapshot.match("put-object-encrypted", put_object_encrypted)

        head_object_encrypted = aws_client.s3.head_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("head-object-encrypted", head_object_encrypted)

        get_object_encrypted = aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-object-encrypted", get_object_encrypted)

        # disable the BucketKeyEnabled
        put_bucket_enc = aws_client.s3.put_bucket_encryption(
            Bucket=s3_bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key["KeyId"],
                        },
                        "BucketKeyEnabled": False,
                    }
                ]
            },
        )
        snapshot.match("put-bucket-enc-bucket-key-disabled", put_bucket_enc)

        # if the BucketKeyEnabled is False, S3 does not return the field from PutObject
        key_name = "key-encrypted-bucket-key-disabled"
        put_object_encrypted = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-encrypted"
        )
        snapshot.match("put-object-encrypted-bucket-key-disabled", put_object_encrypted)

    @pytest.mark.skipif(condition=TEST_S3_IMAGE, reason="KMS not enabled in S3 image")
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have S3 KMS managed key",
    )
    # there is currently no server side encryption is place in LS, ETag will be different
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..ETag",
            "$.managed-kms-key.KeyMetadata.KeyManager",  # TODO: we have no internal way to create KMS key
        ]
    )
    def test_s3_bucket_encryption_sse_kms_aws_managed_key(self, s3_bucket, aws_client, snapshot):
        # if you don't provide a KMS key, AWS will use an AWS managed one.
        put_bucket_enc = aws_client.s3.put_bucket_encryption(
            Bucket=s3_bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        snapshot.match("put-bucket-enc", put_bucket_enc)

        get_bucket_enc = aws_client.s3.get_bucket_encryption(Bucket=s3_bucket)
        snapshot.match("get-bucket-enc", get_bucket_enc)

        key_name = "key-encrypted"
        put_object_encrypted = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="test-encrypted"
        )
        snapshot.match("put-object-encrypted", put_object_encrypted)

        kms_key_id = put_object_encrypted["SSEKMSKeyId"]
        kms_key_data = aws_client.kms.describe_key(KeyId=kms_key_id)
        snapshot.match("managed-kms-key", kms_key_data)

        head_object_encrypted = aws_client.s3.head_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("head-object-encrypted", head_object_encrypted)

        get_object_encrypted = aws_client.s3.get_object(Bucket=s3_bucket, Key=key_name)
        snapshot.match("get-object-encrypted", get_object_encrypted)


@markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..ServerSideEncryption"])
class TestS3BucketObjectTagging:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider, paths=["$.get-bucket-tags.TagSet[1].Value"]
    )
    def test_bucket_tagging_crud(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_tagging(Bucket=s3_bucket)
        snapshot.match("get-bucket-tags-empty", e.value.response)

        tag_set = {"TagSet": [{"Key": "tag1", "Value": "tag1"}, {"Key": "tag2", "Value": ""}]}

        put_bucket_tags = aws_client.s3.put_bucket_tagging(Bucket=s3_bucket, Tagging=tag_set)
        snapshot.match("put-bucket-tags", put_bucket_tags)

        get_bucket_tags = aws_client.s3.get_bucket_tagging(Bucket=s3_bucket)
        snapshot.match("get-bucket-tags", get_bucket_tags)

        tag_set_2 = {"TagSet": [{"Key": "tag3", "Value": "tag3"}]}

        put_bucket_tags = aws_client.s3.put_bucket_tagging(Bucket=s3_bucket, Tagging=tag_set_2)
        snapshot.match("put-bucket-tags-overwrite", put_bucket_tags)

        get_bucket_tags = aws_client.s3.get_bucket_tagging(Bucket=s3_bucket)
        snapshot.match("get-bucket-tags-overwritten", get_bucket_tags)

        delete_bucket_tags = aws_client.s3.delete_bucket_tagging(Bucket=s3_bucket)
        snapshot.match("delete-bucket-tags", delete_bucket_tags)

        # test idempotency of delete
        aws_client.s3.delete_bucket_tagging(Bucket=s3_bucket)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_tagging(Bucket=s3_bucket)
        e.match("NoSuchTagSet")

        # setting an empty tag set is the same as effectively deleting the TagSet
        tag_set_empty = {"TagSet": []}

        put_bucket_tags = aws_client.s3.put_bucket_tagging(Bucket=s3_bucket, Tagging=tag_set_empty)
        snapshot.match("put-bucket-tags-empty", put_bucket_tags)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_tagging(Bucket=s3_bucket)
        e.match("NoSuchTagSet")

    @markers.aws.validated
    def test_bucket_tagging_exc(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        fake_bucket = f"fake-bucket-{short_uid()}-{short_uid()}"
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_tagging(Bucket=fake_bucket)
        snapshot.match("get-no-bucket-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_bucket_tagging(Bucket=fake_bucket)
        snapshot.match("delete-no-bucket-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_tagging(Bucket=fake_bucket, Tagging={"TagSet": []})
        snapshot.match("put-no-bucket-tags", e.value.response)

    @markers.aws.validated
    def test_object_tagging_crud(self, s3_bucket, aws_client, snapshot):
        object_key = "test-object-tagging"
        put_object = aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body="test-tagging")
        snapshot.match("put-object", put_object)

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-empty", get_bucket_tags)

        tag_set = {"TagSet": [{"Key": "tag1", "Value": "tag1"}, {"Key": "tag2", "Value": ""}]}

        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, Tagging=tag_set
        )
        snapshot.match("put-object-tags", put_bucket_tags)

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags", get_bucket_tags)

        tag_set_2 = {"TagSet": [{"Key": "tag3", "Value": "tag3"}]}

        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, Tagging=tag_set_2
        )
        snapshot.match("put-object-tags-overwrite", put_bucket_tags)

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-overwritten", get_bucket_tags)

        get_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-obj-after-tags", get_object)

        delete_bucket_tags = aws_client.s3.delete_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("delete-object-tags", delete_bucket_tags)

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-deleted", get_bucket_tags)

        get_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-obj-after-tags-deleted", get_object)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation do not catch exceptions",
    )
    def test_object_tagging_exc(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, replacement="<bucket:1>"))
        fake_bucket = f"fake-bucket-{short_uid()}-{short_uid()}"
        fake_key = "fake-key"
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_tagging(Bucket=fake_bucket, Key=fake_key)
        snapshot.match("get-no-bucket-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object_tagging(Bucket=fake_bucket, Key=fake_key)
        snapshot.match("delete-no-bucket-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(
                Bucket=fake_bucket, Tagging={"TagSet": []}, Key=fake_key
            )
        snapshot.match("put-no-bucket-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=fake_key)
        snapshot.match("get-no-key-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object_tagging(Bucket=s3_bucket, Key=fake_key)
        snapshot.match("delete-no-key-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(Bucket=s3_bucket, Tagging={"TagSet": []}, Key=fake_key)
        snapshot.match("put-no-key-tags", e.value.response)

        with pytest.raises(ClientError) as e:
            tagging = "key1=val1&key1=val2"
            aws_client.s3.put_object(Bucket=s3_bucket, Key=fake_key, Body="", Tagging=tagging)
        snapshot.match("put-obj-duplicate-tagging", e.value.response)

        with pytest.raises(ClientError) as e:
            tagging = "key1=val1,key2=val2"
            aws_client.s3.put_object(Bucket=s3_bucket, Key=fake_key, Body="", Tagging=tagging)
        snapshot.match("put-obj-wrong-format", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation missing versioning implementation",
    )
    def test_object_tagging_versioned(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("VersionId"))
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        object_key = "test-version-tagging"
        version_ids = []
        v1_tags = {"test_tag": "tagv1"}
        for i in range(2):
            if i == 0:
                put_obj = aws_client.s3.put_object(
                    Bucket=s3_bucket, Key=object_key, Body=f"test-{i}", Tagging=urlencode(v1_tags)
                )
            else:
                put_obj = aws_client.s3.put_object(
                    Bucket=s3_bucket, Key=object_key, Body=f"test-{i}"
                )
            snapshot.match(f"put-obj-{i}", put_obj)
            version_ids.append(put_obj["VersionId"])

        version_id_1, version_id_2 = version_ids

        tag_set_2 = {"TagSet": [{"Key": "tag3", "Value": "tag3"}]}

        # test without specifying a VersionId
        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, Tagging=tag_set_2
        )
        snapshot.match("put-object-tags-current-version", put_bucket_tags)
        assert put_bucket_tags["VersionId"] == version_id_2

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-current-version", get_bucket_tags)

        get_bucket_tags = aws_client.s3.get_object_tagging(
            Bucket=s3_bucket, Key=object_key, VersionId=version_id_1
        )
        snapshot.match("get-object-tags-previous-version", get_bucket_tags)

        tag_set_2 = {"TagSet": [{"Key": "tag1", "Value": "tag1"}]}
        # test by specifying a VersionId to Version1
        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, VersionId=version_id_1, Tagging=tag_set_2
        )
        snapshot.match("put-object-tags-previous-version", put_bucket_tags)
        assert put_bucket_tags["VersionId"] == version_id_1

        get_bucket_tags = aws_client.s3.get_object_tagging(
            Bucket=s3_bucket, Key=object_key, VersionId=version_id_1
        )
        snapshot.match("get-object-tags-previous-version-again", get_bucket_tags)

        # Put a DeleteMarker on top of the stack
        delete_current = aws_client.s3.delete_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("put-delete-marker", delete_current)
        version_id_delete_marker = delete_current["VersionId"]

        # test to put/get tagging on the DeleteMarker
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
                VersionId=version_id_delete_marker,
                Tagging=tag_set_2,
            )
        snapshot.match("put-object-tags-delete-marker-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_tagging(
                Bucket=s3_bucket, Key=object_key, VersionId=version_id_delete_marker
            )
        snapshot.match("get-object-tags-delete-marker-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object_tagging(
                Bucket=s3_bucket, Key=object_key, VersionId=version_id_delete_marker
            )
        snapshot.match("delete-object-tags-delete-marker-id", e.value.response)

        # test to put/get tagging on latest version (DeleteMarker)
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(Bucket=s3_bucket, Key=object_key, Tagging=tag_set_2)
        snapshot.match("put-object-tags-delete-marker-latest", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
            )
        snapshot.match("get-object-tags-delete-marker-latest", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
            )
        snapshot.match("delete-object-tags-delete-marker-latest", e.value.response)

    @markers.aws.validated
    def test_put_object_with_tags(self, s3_bucket, aws_client, snapshot):
        object_key = "test-put-object-tagging"
        # tagging must be a URL encoded string directly
        tag_set = "tag1=tag1&tag2=tag2&tag="
        put_object = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=object_key, Body="test-tagging", Tagging=tag_set
        )
        snapshot.match("put-object", put_object)

        get_object_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        # only TagSet set with the query string format are unordered, so not using the SortingTransformer
        get_object_tags["TagSet"].sort(key=itemgetter("Key"))
        snapshot.match("get-object-tags", get_object_tags)

        tag_set_2 = {"TagSet": [{"Key": "tag3", "Value": "tag3"}]}
        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, Tagging=tag_set_2
        )
        snapshot.match("put-object-tags", put_bucket_tags)

        get_object_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-override", get_object_tags)

        head_object = aws_client.s3.head_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("head-obj", head_object)

        get_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-obj", get_object)

        tagging = "wrongquery&wrongagain"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body="", Tagging=tagging)

        get_object_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        # only TagSet set with the query string format are unordered, so not using the SortingTransformer
        get_object_tags["TagSet"].sort(key=itemgetter("Key"))
        snapshot.match("get-object-tags-wrong-format-qs", get_object_tags)

        tagging = "key1&&&key2"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body="", Tagging=tagging)

        get_object_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-tags-wrong-format-qs-2", get_object_tags)

    @markers.aws.validated
    def test_object_tags_delete_or_overwrite_object(self, s3_bucket, aws_client, snapshot):
        # verify that tags aren't kept after object deletion
        object_key = "test-put-object-tagging-kept"
        aws_client.s3.put_object(
            Bucket=s3_bucket, Key=object_key, Body="create", Tagging="tag1=val1"
        )

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-after-creation", get_bucket_tags)

        aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body="overwrite")

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-after-overwrite", get_bucket_tags)

        # put some tags to verify they won't be kept
        tag_set = {"TagSet": [{"Key": "tag3", "Value": "tag3"}]}
        aws_client.s3.put_object_tagging(Bucket=s3_bucket, Key=object_key, Tagging=tag_set)

        aws_client.s3.delete_object(Bucket=s3_bucket, Key=object_key)
        aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body="recreate")

        get_bucket_tags = aws_client.s3.get_object_tagging(Bucket=s3_bucket, Key=object_key)
        snapshot.match("get-object-after-recreation", get_bucket_tags)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not raise exceptions",
    )
    def test_tagging_validation(self, s3_bucket, aws_client, snapshot):
        object_key = "tagging-validation"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body=b"")

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_tagging(
                Bucket=s3_bucket,
                Tagging={
                    "TagSet": [
                        {"Key": "Key1", "Value": "Val1"},
                        {"Key": "Key1", "Value": "Val1"},
                    ]
                },
            )
        snapshot.match("put-bucket-tags-duplicate-keys", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_tagging(
                Bucket=s3_bucket,
                Tagging={
                    "TagSet": [
                        {"Key": "Key1,Key2", "Value": "Val1"},
                    ]
                },
            )
        snapshot.match("put-bucket-tags-invalid-key", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_tagging(
                Bucket=s3_bucket,
                Tagging={
                    "TagSet": [
                        {"Key": "Key1", "Value": "Val1,Val2"},
                    ]
                },
            )
        snapshot.match("put-bucket-tags-invalid-value", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_tagging(
                Bucket=s3_bucket,
                Tagging={
                    "TagSet": [
                        {"Key": "aws:prefixed", "Value": "Val1"},
                    ]
                },
            )
        snapshot.match("put-bucket-tags-aws-prefixed", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
                Tagging={
                    "TagSet": [
                        {"Key": "Key1", "Value": "Val1"},
                        {"Key": "Key1", "Value": "Val1"},
                    ]
                },
            )

        snapshot.match("put-object-tags-duplicate-keys", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
                Tagging={"TagSet": [{"Key": "Key1,Key2", "Value": "Val1"}]},
            )

        snapshot.match("put-object-tags-invalid-field", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_tagging(
                Bucket=s3_bucket,
                Key=object_key,
                Tagging={"TagSet": [{"Key": "aws:prefixed", "Value": "Val1"}]},
            )
        snapshot.match("put-object-tags-aws-prefixed", e.value.response)


class TestS3ObjectLock:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not catch exception",
    )
    def test_put_object_lock_configuration_on_existing_bucket(
        self, s3_bucket, aws_client, snapshot
    ):
        # this has been updated by AWS:
        # https://aws.amazon.com/about-aws/whats-new/2023/11/amazon-s3-enabling-object-lock-buckets/
        # before, S3 buckets had to be created with a specific config to be able to be use S3 Object Lock
        # however, the bucket needs to be at least versioned
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)

        snapshot.match("get-object-lock-existing-bucket-no-config", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                },
            )
        snapshot.match("put-object-lock-existing-bucket-no-versioning", e.value.response)

        suspend_versioning = aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )
        snapshot.match("suspended-versioning", suspend_versioning)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                },
            )
        snapshot.match("put-object-lock-existing-bucket-versioning-disabled", e.value.response)

        enable_versioning = aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        snapshot.match("enabled-versioning", enable_versioning)

        put_lock_on_existing_bucket = aws_client.s3.put_object_lock_configuration(
            Bucket=s3_bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
            },
        )
        snapshot.match("put-object-lock-existing-bucket-enabled", put_lock_on_existing_bucket)

        get_lock_on_existing_bucket = aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)
        snapshot.match("get-object-lock-existing-bucket-enabled", get_lock_on_existing_bucket)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider,
        paths=["$.get-lock-config.ObjectLockConfiguration.Rule.DefaultRetention.Years"],
    )
    def test_get_put_object_lock_configuration(self, s3_create_bucket, aws_client, snapshot):
        s3_bucket = s3_create_bucket(ObjectLockEnabledForBucket=True)

        get_lock_config = aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)
        snapshot.match("get-lock-config-start", get_lock_config)

        put_lock_config = aws_client.s3.put_object_lock_configuration(
            Bucket=s3_bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "GOVERNANCE",
                        "Days": 1,
                    }
                },
            },
        )
        snapshot.match("put-lock-config", put_lock_config)

        get_lock_config = aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)
        snapshot.match("get-lock-config", get_lock_config)

        put_lock_config_enabled = aws_client.s3.put_object_lock_configuration(
            Bucket=s3_bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
            },
        )
        snapshot.match("put-lock-config-enabled", put_lock_config_enabled)

        get_lock_config = aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)
        snapshot.match("get-lock-config-only-enabled", get_lock_config)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not catch exception",
    )
    def test_put_object_lock_configuration_exc(self, s3_create_bucket, aws_client, snapshot):
        s3_bucket = s3_create_bucket(ObjectLockEnabledForBucket=True)
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "Rule": {
                        "DefaultRetention": {
                            "Mode": "GOVERNANCE",
                            "Days": 1,
                        }
                    }
                },
            )
        snapshot.match("put-lock-config-no-enabled", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket, ObjectLockConfiguration={}
            )
        snapshot.match("put-lock-config-empty", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={"ObjectLockEnabled": "Enabled", "Rule": {}},
            )
        snapshot.match("put-lock-config-empty-rule", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {}},
                },
            )
        snapshot.match("put-lock-config-empty-retention", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {
                        "DefaultRetention": {
                            "Mode": "GOVERNANCE",
                        }
                    },
                },
            )
        snapshot.match("put-lock-config-no-days", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object_lock_configuration(
                Bucket=s3_bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {
                        "DefaultRetention": {
                            "Mode": "GOVERNANCE",
                            "Days": 1,
                            "Years": 1,
                        }
                    },
                },
            )
        snapshot.match("put-lock-config-both-days-years", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(condition=is_v2_provider, paths=["$..Error.BucketName"])
    def test_get_object_lock_configuration_exc(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_lock_configuration(Bucket=s3_bucket)
        snapshot.match("get-lock-config-no-enabled", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_object_lock_configuration(Bucket=f"fake-bucket-ls-{long_uid()}")
        snapshot.match("get-lock-config-bucket-not-exists", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not raise exceptions",
    )
    def test_disable_versioning_on_locked_bucket(self, s3_create_bucket, aws_client, snapshot):
        bucket_name = s3_create_bucket(ObjectLockEnabledForBucket=True)
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    "Status": "Suspended",
                },
            )
        snapshot.match("disable-versioning-on-locked-bucket", e.value.response)

        put_bucket_versioning_again = aws_client.s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                "Status": "Enabled",
            },
        )
        snapshot.match("enable-versioning-again-on-locked-bucket", put_bucket_versioning_again)

    @markers.aws.validated
    def test_delete_object_with_no_locking(self, s3_bucket, aws_client, snapshot):
        key = "test-delete-no-lock"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=b"test")

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object(Bucket=s3_bucket, Key=key, BypassGovernanceRetention=True)
        snapshot.match("delete-object-bypass-no-lock", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_object(Bucket=s3_bucket, Key=key, BypassGovernanceRetention=False)
        snapshot.match("delete-object-bypass-no-lock-false", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.delete_objects(
                Bucket=s3_bucket, Delete={"Objects": [{"Key": key}]}, BypassGovernanceRetention=True
            )
        snapshot.match("delete-objects-bypass-no-lock", e.value.response)


class TestS3BucketOwnershipControls:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have default ownership controls",
    )
    def test_crud_bucket_ownership_controls(self, s3_create_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        default_s3_bucket = s3_create_bucket()
        get_default_ownership = aws_client.s3.get_bucket_ownership_controls(
            Bucket=default_s3_bucket
        )
        snapshot.match("default-ownership", get_default_ownership)

        put_ownership = aws_client.s3.put_bucket_ownership_controls(
            Bucket=default_s3_bucket,
            OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
        )
        snapshot.match("put-ownership", put_ownership)

        get_ownership = aws_client.s3.get_bucket_ownership_controls(Bucket=default_s3_bucket)
        snapshot.match("get-ownership", get_ownership)

        delete_ownership = aws_client.s3.delete_bucket_ownership_controls(Bucket=default_s3_bucket)
        snapshot.match("delete-ownership", delete_ownership)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_ownership_controls(Bucket=default_s3_bucket)
        snapshot.match("get-ownership-after-delete", e.value.response)

        delete_idempotent = aws_client.s3.delete_bucket_ownership_controls(Bucket=default_s3_bucket)
        snapshot.match("delete-ownership-after-delete", delete_idempotent)

        s3_bucket = s3_create_bucket(ObjectOwnership="BucketOwnerPreferred")
        get_ownership_at_creation = aws_client.s3.get_bucket_ownership_controls(Bucket=s3_bucket)
        snapshot.match("get-ownership-at-creation", get_ownership_at_creation)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have default ownership controls",
    )
    def test_bucket_ownership_controls_exc(self, s3_create_bucket, aws_client, snapshot):
        default_s3_bucket = s3_create_bucket()
        get_default_ownership = aws_client.s3.get_bucket_ownership_controls(
            Bucket=default_s3_bucket
        )
        snapshot.match("default-ownership", get_default_ownership)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_ownership_controls(
                Bucket=default_s3_bucket,
                OwnershipControls={
                    "Rules": [
                        {"ObjectOwnership": "BucketOwnerPreferred"},
                        {"ObjectOwnership": "ObjectWriter"},
                    ]
                },
            )
        snapshot.match("put-ownership-multiple-rules", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_ownership_controls(
                Bucket=default_s3_bucket,
                OwnershipControls={"Rules": [{"ObjectOwnership": "RandomValue"}]},
            )
        snapshot.match("put-ownership-wrong-value", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_ownership_controls(
                Bucket=default_s3_bucket, OwnershipControls={"Rules": []}
            )
        snapshot.match("put-ownership-empty-rule", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_create_bucket(ObjectOwnership="RandomValue")
        snapshot.match("ownership-wrong-value-at-creation", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_create_bucket(ObjectOwnership="")
        snapshot.match("ownership-non-value-at-creation", e.value.response)


class TestS3PublicAccessBlock:
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not have default public access block",
    )
    def test_crud_public_access_block(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        get_public_access_block = aws_client.s3.get_public_access_block(Bucket=s3_bucket)
        snapshot.match("get-default-public-access-block", get_public_access_block)

        put_public_access_block = aws_client.s3.put_public_access_block(
            Bucket=s3_bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
            },
        )
        snapshot.match("put-public-access-block", put_public_access_block)

        get_public_access_block = aws_client.s3.get_public_access_block(Bucket=s3_bucket)
        snapshot.match("get-public-access-block", get_public_access_block)

        delete_public_access_block = aws_client.s3.delete_public_access_block(Bucket=s3_bucket)
        snapshot.match("delete-public-access-block", delete_public_access_block)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_public_access_block(Bucket=s3_bucket)
        snapshot.match("get-public-access-block-after-delete", e.value.response)

        delete_public_access_block = aws_client.s3.delete_public_access_block(Bucket=s3_bucket)
        snapshot.match("idempotent-delete-public-access-block", delete_public_access_block)


class TestS3BucketPolicy:
    @markers.aws.validated
    def test_bucket_policy_crud(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.key_value("Resource"))
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        # delete the OwnershipControls so that we can set a Policy
        aws_client.s3.delete_bucket_ownership_controls(Bucket=s3_bucket)
        aws_client.s3.delete_public_access_block(Bucket=s3_bucket)

        # get the default Policy, should raise
        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_policy(Bucket=s3_bucket)
        snapshot.match("get-bucket-default-policy", e.value.response)

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
        response = aws_client.s3.put_bucket_policy(Bucket=s3_bucket, Policy=json.dumps(policy))
        snapshot.match("put-bucket-policy", response)

        # retrieve and check policy config
        response = aws_client.s3.get_bucket_policy(Bucket=s3_bucket)
        snapshot.match("get-bucket-policy", response)
        assert policy == json.loads(response["Policy"])

        response = aws_client.s3.delete_bucket_policy(Bucket=s3_bucket)
        snapshot.match("delete-bucket-policy", response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.get_bucket_policy(Bucket=s3_bucket)
        snapshot.match("get-bucket-policy-after-delete", e.value.response)

        response = aws_client.s3.delete_bucket_policy(Bucket=s3_bucket)
        snapshot.match("delete-bucket-policy-after-delete", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=config.LEGACY_V2_S3_PROVIDER,
        reason="Moto implementation does not raise Exception",
    )
    def test_bucket_policy_exc(self, s3_bucket, snapshot, aws_client):
        # delete the OwnershipControls so that we can set a Policy
        aws_client.s3.delete_bucket_ownership_controls(Bucket=s3_bucket)
        aws_client.s3.delete_public_access_block(Bucket=s3_bucket)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_policy(Bucket=s3_bucket, Policy="")
        snapshot.match("put-empty-bucket-policy", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_policy(Bucket=s3_bucket, Policy="invalid json")
        snapshot.match("put-bucket-policy-randomstring", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_policy(Bucket=s3_bucket, Policy="{}")
        snapshot.match("put-bucket-policy-empty-json", e.value.response)


class TestS3BucketAccelerateConfiguration:
    @markers.aws.validated
    def test_bucket_acceleration_configuration_crud(self, s3_bucket, snapshot, aws_client):
        get_default_config = aws_client.s3.get_bucket_accelerate_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-default-accelerate-config", get_default_config)

        response = aws_client.s3.put_bucket_accelerate_configuration(
            Bucket=s3_bucket,
            AccelerateConfiguration={"Status": "Enabled"},
        )
        snapshot.match("put-bucket-accelerate-config-enabled", response)

        response = aws_client.s3.get_bucket_accelerate_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-accelerate-config-enabled", response)

        response = aws_client.s3.put_bucket_accelerate_configuration(
            Bucket=s3_bucket,
            AccelerateConfiguration={"Status": "Suspended"},
        )
        snapshot.match("put-bucket-accelerate-config-disabled", response)

        response = aws_client.s3.get_bucket_accelerate_configuration(Bucket=s3_bucket)
        snapshot.match("get-bucket-accelerate-config-disabled", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_v2_provider,
        paths=[
            "$.put-bucket-accelerate-config-dot-bucket.Error.Code",
            "$.put-bucket-accelerate-config-dot-bucket.Error.Message",
        ],
    )
    def test_bucket_acceleration_configuration_exc(
        self, s3_bucket, s3_create_bucket, snapshot, aws_client
    ):
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_accelerate_configuration(
                Bucket=s3_bucket,
                AccelerateConfiguration={"Status": "enabled"},
            )
        snapshot.match("put-bucket-accelerate-config-lowercase", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_accelerate_configuration(
                Bucket=s3_bucket,
                AccelerateConfiguration={"Status": "random"},
            )
        snapshot.match("put-bucket-accelerate-config-random", e.value.response)

        bucket_with_name = s3_create_bucket(Bucket=f"test.bucket.{long_uid()}")
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_accelerate_configuration(
                Bucket=bucket_with_name,
                AccelerateConfiguration={"Status": "random"},
            )
        snapshot.match("put-bucket-accelerate-config-dot-bucket", e.value.response)


@pytest.mark.skipif(
    condition=config.LEGACY_V2_S3_PROVIDER,
    reason="Not implemented in legacy",
)
class TestS3ObjectWritePrecondition:
    @pytest.fixture(autouse=True)
    def add_snapshot_transformers(self, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("Bucket"),
                snapshot.transform.key_value("UploadId"),
                snapshot.transform.key_value("VersionId"),
                snapshot.transform.key_value("DisplayName"),
                snapshot.transform.key_value("ID"),
                snapshot.transform.key_value("Name"),
            ]
        )
        snapshot.add_transformer(snapshot.transform.key_value("Location"), priority=-1)

    @markers.aws.validated
    def test_put_object_if_none_match(self, s3_bucket, aws_client, snapshot):
        key = "test-precondition"
        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj", put_obj)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj-if-none-match", e.value.response)

        del_obj = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
        snapshot.match("del-obj", del_obj)

        put_obj_after_del = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj-after-del", put_obj_after_del)

    @markers.aws.validated
    def test_put_object_if_none_match_validation(self, s3_bucket, aws_client, snapshot):
        key = "test-precondition-validation"
        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key)
        snapshot.match("put-obj", put_obj)
        obj_etag = put_obj["ETag"]

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch=obj_etag)
        snapshot.match("put-obj-if-none-match-bad-value", e.value.response)

    @markers.aws.validated
    def test_multipart_if_none_match_with_delete(self, s3_bucket, aws_client, snapshot):
        key = "test-precondition"
        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj", put_obj)

        create_multipart = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
        snapshot.match("create-multipart", create_multipart)
        upload_id = create_multipart["UploadId"]

        upload_part = aws_client.s3.upload_part(
            Bucket=s3_bucket, Key=key, UploadId=upload_id, Body="test", PartNumber=1
        )
        parts = [{"ETag": upload_part["ETag"], "PartNumber": 1}]

        with pytest.raises(ClientError) as e:
            aws_client.s3.complete_multipart_upload(
                Bucket=s3_bucket,
                Key=key,
                MultipartUpload={"Parts": parts},
                UploadId=upload_id,
                IfNoneMatch="*",
            )
        snapshot.match("complete-multipart-if-none-match", e.value.response)

        del_obj = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
        snapshot.match("del-obj", del_obj)

        # the previous DeleteObject request was done between the CreateMultipartUpload and completion, so it takes
        # precedence
        # you need to restart the whole multipart for it to work

        with pytest.raises(ClientError) as e:
            aws_client.s3.complete_multipart_upload(
                Bucket=s3_bucket,
                Key=key,
                MultipartUpload={"Parts": parts},
                UploadId=upload_id,
                IfNoneMatch="*",
            )
        snapshot.match("complete-multipart-after-del", e.value.response)

        create_multipart = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
        upload_id = create_multipart["UploadId"]

        upload_part = aws_client.s3.upload_part(
            Bucket=s3_bucket, Key=key, UploadId=upload_id, Body="test", PartNumber=1
        )
        parts = [{"ETag": upload_part["ETag"], "PartNumber": 1}]
        complete_multipart = aws_client.s3.complete_multipart_upload(
            Bucket=s3_bucket,
            Key=key,
            MultipartUpload={"Parts": parts},
            UploadId=upload_id,
            IfNoneMatch="*",
        )
        snapshot.match("complete-multipart-after-del-restart", complete_multipart)

    @markers.aws.validated
    def test_multipart_if_none_match_with_put(self, s3_bucket, aws_client, snapshot):
        key = "test-precondition"

        create_multipart = aws_client.s3.create_multipart_upload(Bucket=s3_bucket, Key=key)
        snapshot.match("create-multipart", create_multipart)
        upload_id = create_multipart["UploadId"]

        upload_part = aws_client.s3.upload_part(
            Bucket=s3_bucket, Key=key, UploadId=upload_id, Body="test", PartNumber=1
        )
        parts = [{"ETag": upload_part["ETag"], "PartNumber": 1}]

        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj", put_obj)

        with pytest.raises(ClientError) as e:
            aws_client.s3.complete_multipart_upload(
                Bucket=s3_bucket,
                Key=key,
                MultipartUpload={"Parts": parts},
                UploadId=upload_id,
                IfNoneMatch="*",
            )
        snapshot.match("complete-multipart-if-none-match-put-during", e.value.response)

    @markers.aws.validated
    def test_put_object_if_none_match_versioned_bucket(self, s3_bucket, aws_client, snapshot):
        #  For buckets with versioning enabled, S3 checks for the presence of a current object version with the same
        #  name as part of the conditional evaluation. If there is no current object version with the same name, or
        #  if the current object version is a delete marker, then the write operation succeeds.
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        key = "test-precondition"
        put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj", put_obj)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj-if-none-match", e.value.response)

        del_obj = aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
        snapshot.match("del-obj", del_obj)

        # if the last object is a delete marker, then we can use IfNoneMatch
        put_obj_after_del = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, IfNoneMatch="*")
        snapshot.match("put-obj-after-del", put_obj_after_del)

        list_object_versions = aws_client.s3.list_object_versions(Bucket=s3_bucket)
        snapshot.match("list-object-versions", list_object_versions)
