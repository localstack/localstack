from operator import itemgetter

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.strings import short_uid


def is_native_provider():
    return config.NATIVE_S3_PROVIDER


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_native_provider(), paths=["$..ServerSideEncryption"]
)
class TestS3BucketCRUD:
    @markers.aws.validated
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


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_native_provider(), paths=["$..ServerSideEncryption"]
)
class TestS3ObjectCRUD:
    @markers.aws.validated
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

    @markers.aws.unknown
    def test_delete_object_locked(self):
        pass

    @markers.aws.validated
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

        # TODO: test with Next? xxx
        # TODO: test with ListObject/ListObjectV2


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
)
class TestS3BucketVersioning:
    @markers.aws.validated
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


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
)
class TestS3BucketEncryption:
    @markers.aws.validated
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

    @markers.aws.validated
    # there is currently no server side encryption is place in LS, ETag will be different
    @markers.snapshot.skip_snapshot_verify(paths=["$..ETag"])
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

    @markers.aws.validated
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


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
)
class TestS3BucketObjectTagging:
    @markers.aws.validated
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
    def test_object_tagging_versioned(self, s3_bucket, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("VersionId"))
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        object_key = "test-version-tagging"
        version_ids = []
        for i in range(2):
            put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=object_key, Body=f"test-{i}")
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
        snapshot.match("get-object-tags-previous-version", get_bucket_tags)

        # Put a DeleteMarker on top of the stack
        delete_current = aws_client.s3.delete_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("put-delete-marker", delete_current)

        # test to put/get tagging on a DeleteMarker
        put_bucket_tags = aws_client.s3.put_object_tagging(
            Bucket=s3_bucket, Key=object_key, VersionId=version_id_1, Tagging=tag_set_2
        )
        snapshot.match("put-object-tags-delete-marker", put_bucket_tags)

        get_bucket_tags = aws_client.s3.get_object_tagging(
            Bucket=s3_bucket, Key=object_key, VersionId=version_id_1
        )
        snapshot.match("get-object-tags-delete-marker", get_bucket_tags)

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
