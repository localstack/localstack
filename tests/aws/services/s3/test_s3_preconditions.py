import datetime
import time
from zoneinfo import ZoneInfo

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


class TestS3CopySourcePreconditions:
    @markers.aws.validated
    def test_s3_copy_object_preconditions(self, s3_bucket, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.s3_api())
        object_key = "source-object"
        dest_key = "dest-object"
        # create key with no checksum
        put_object = aws_client.s3.put_object(
            Bucket=s3_bucket,
            Key=object_key,
            Body=b"data",
        )
        head_obj = aws_client.s3.head_object(Bucket=s3_bucket, Key=object_key)
        snapshot.match("head-object", head_obj)

        # wait a bit for the `unmodified_since` value so that it's unvalid.
        # S3 compares it the last-modified field, but you can't set the value in the future otherwise it ignores it
        # It needs to be now or less, but the object needs to be a bit more recent than that.
        time.sleep(3)

        # we're testing the order of validation at the same time by validating all of them at once, by elimination
        now = datetime.datetime.now().astimezone(tz=ZoneInfo("GMT"))
        wrong_unmodified_since = now - datetime.timedelta(days=1)

        with pytest.raises(ClientError) as e:
            aws_client.s3.copy_object(
                Bucket=s3_bucket,
                CopySource=f"{s3_bucket}/{object_key}",
                Key=dest_key,
                CopySourceIfModifiedSince=now,
                CopySourceIfUnmodifiedSince=wrong_unmodified_since,
                CopySourceIfMatch="etag123",
                CopySourceIfNoneMatch=put_object["ETag"],
            )
        snapshot.match("copy-precondition-if-match", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.copy_object(
                Bucket=s3_bucket,
                CopySource=f"{s3_bucket}/{object_key}",
                Key=dest_key,
                CopySourceIfModifiedSince=now,
                CopySourceIfUnmodifiedSince=wrong_unmodified_since,
                CopySourceIfNoneMatch=put_object["ETag"],
            )
        snapshot.match("copy-precondition-if-unmodified-since", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.copy_object(
                Bucket=s3_bucket,
                CopySource=f"{s3_bucket}/{object_key}",
                Key=dest_key,
                CopySourceIfModifiedSince=now,
                CopySourceIfNoneMatch=put_object["ETag"],
            )
        snapshot.match("copy-precondition-if-none-match", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.copy_object(
                Bucket=s3_bucket,
                CopySource=f"{s3_bucket}/{object_key}",
                Key=dest_key,
                CopySourceIfModifiedSince=now,
            )
        snapshot.match("copy-precondition-if-modified-since", e.value.response)

        # AWS will ignore the value if it's in the future
        copy_obj = aws_client.s3.copy_object(
            Bucket=s3_bucket,
            CopySource=f"{s3_bucket}/{object_key}",
            Key=dest_key,
            CopySourceIfModifiedSince=now + datetime.timedelta(days=1),
        )
        snapshot.match("copy-ignore-future-modified-since", copy_obj)

        # AWS will ignore the missing quotes around the ETag and still reject the request
        with pytest.raises(ClientError) as e:
            aws_client.s3.copy_object(
                Bucket=s3_bucket,
                CopySource=f"{s3_bucket}/{object_key}",
                Key=dest_key,
                CopySourceIfNoneMatch=put_object["ETag"].strip('"'),
            )
        snapshot.match("copy-etag-missing-quotes", e.value.response)

        # Positive tests with all conditions checked
        copy_obj_all_positive = aws_client.s3.copy_object(
            Bucket=s3_bucket,
            CopySource=f"{s3_bucket}/{object_key}",
            Key=dest_key,
            CopySourceIfMatch=put_object["ETag"].strip('"'),
            CopySourceIfNoneMatch="etag123",
            CopySourceIfModifiedSince=now - datetime.timedelta(days=1),
            CopySourceIfUnmodifiedSince=now,
        )
        snapshot.match("copy-success", copy_obj_all_positive)
