import json
import time

import pytest
import requests
from boto3.s3.transfer import KB, TransferConfig
from botocore.exceptions import ClientError

from localstack import config
from localstack.utils.collections import is_sub_dict
from localstack.utils.strings import (
    checksum_crc32,
    checksum_crc32c,
    hash_sha1,
    hash_sha256,
    short_uid,
)


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
        config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        file = tmpdir / "test-file.bin"
        data = b"1" * (6 * KB)  # create 6 kilobytes of ones
        file.write(data=data, mode="w")
        s3_client.upload_file(
            Bucket=s3_bucket, Key=key, Filename=str(file.realpath()), Config=config
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
