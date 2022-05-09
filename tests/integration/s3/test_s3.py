import pytest
import requests
from boto3.s3.transfer import KB, TransferConfig
from botocore.exceptions import ClientError

from localstack.utils.strings import short_uid


class TestS3:
    @pytest.mark.aws_validated
    def test_region_header_exists(self, s3_client, s3_create_bucket):
        bucket_name = s3_create_bucket(
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
        )

        response = s3_client.head_bucket(Bucket=bucket_name)
        assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-bucket-region"] == "eu-west-1"

        response = s3_client.list_objects_v2(Bucket=bucket_name)
        assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-bucket-region"] == "eu-west-1"

    @pytest.mark.aws_validated
    def test_delete_bucket_with_content(self, s3_client, s3_resource, s3_bucket):
        bucket_name = s3_bucket

        for i in range(0, 10, 1):
            body = "test-" + str(i)
            key = "test-key-" + str(i)
            s3_client.put_object(Bucket=bucket_name, Key=key, Body=body)

        resp = s3_client.list_objects(Bucket=bucket_name, MaxKeys=100)
        assert 10 == len(resp["Contents"])

        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.all().delete()
        bucket.delete()

        resp = s3_client.list_buckets()
        assert bucket_name not in [b["Name"] for b in resp["Buckets"]]

    @pytest.mark.aws_validated
    def test_put_and_get_object_with_utf8_key(self, s3_client, s3_bucket):
        response = s3_client.put_object(Bucket=s3_bucket, Key="Ā0Ä", Body=b"abc123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        response = s3_client.get_object(Bucket=s3_bucket, Key="Ā0Ä")
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
    def test_metadata_header_character_decoding(self, s3_client, s3_bucket):
        # Object metadata keys should accept keys with underscores
        # https://github.com/localstack/localstack/issues/1790
        # put object
        object_key = "key-with-metadata"
        metadata = {"TEST_META_1": "foo", "__meta_2": "bar"}
        s3_client.put_object(Bucket=s3_bucket, Key=object_key, Metadata=metadata, Body="foo")
        metadata_saved = s3_client.head_object(Bucket=s3_bucket, Key=object_key)["Metadata"]

        # note that casing is removed (since headers are case-insensitive)
        assert metadata_saved == {"test_meta_1": "foo", "__meta_2": "bar"}

    @pytest.mark.aws_validated
    def test_upload_file_multipart(self, s3_client, s3_bucket, tmpdir):
        key = "my-key"
        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html#multipart-transfers
        config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        file = tmpdir / "test-file.bin"
        data = b"1" * (6 * KB)  # create 6 kilobytes of ones
        file.write(data=data, mode="w")
        s3_client.upload_file(
            Bucket=s3_bucket, Key=key, Filename=str(file.realpath()), Config=config
        )

        obj = s3_client.get_object(Bucket=s3_bucket, Key=key)
        assert obj["Body"].read() == data, f"body did not contain expected data {obj}"


class TestS3PresignedUrl:
    """
    These tests pertain to S3's presigned URL feature.
    """

    @pytest.mark.aws_validated
    def test_put_object(self, s3_client, s3_bucket):
        key = "my-key"

        url = s3_client.generate_presigned_url(
            "put_object", Params={"Bucket": s3_bucket, "Key": key}
        )
        requests.put(url, data="something", verify=False)

        response = s3_client.get_object(Bucket=s3_bucket, Key=key)
        assert response["Body"].read() == b"something"

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
    def test_put_url_metadata(self, s3_client, s3_bucket):
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


class TestS3DeepArchive:
    """
    Test to cover DEEP_ARCHIVE Storage Class functionality.
    """

    @pytest.mark.aws_validated
    def test_storage_class_deep_archive(self, s3_client, s3_resource, s3_bucket, tmpdir):
        key = "my-key"

        config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        def upload_file(size_in_kb: int):
            file = tmpdir / f"test-file-{short_uid()}.bin"
            data = b"1" * (size_in_kb * KB)
            file.write(data=data, mode="w")
            s3_client.upload_file(
                Bucket=s3_bucket,
                Key=key,
                Filename=str(file.realpath()),
                ExtraArgs={"StorageClass": "DEEP_ARCHIVE"},
                Config=config,
            )

        upload_file(1)
        upload_file(9)
        upload_file(15)

        objects = s3_resource.Bucket(s3_bucket).objects.all()
        keys = []
        for obj in objects:
            keys.append(obj.key)
            assert obj.storage_class == "DEEP_ARCHIVE"
