from operator import itemgetter

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.testing.pytest import markers


@pytest.mark.skipif(
    condition=not config.NATIVE_S3_PROVIDER,
    reason="These are WIP tests for the new native S3 provider",
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
        # TODO: VALIDATION OF VERSION ID
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

    @markers.aws.unknown
    def test_delete_object_on_suspended_bucket(self):
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
