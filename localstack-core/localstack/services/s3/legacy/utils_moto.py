import datetime
from typing import Literal, Union

import moto.s3.models as moto_s3_models
from moto.s3.exceptions import MissingBucket
from moto.s3.models import FakeBucket, FakeDeleteMarker, FakeKey

from localstack.aws.api.s3 import BucketName, MethodNotAllowed, NoSuchBucket, NoSuchKey, ObjectKey


def is_moto_key_expired(key_object: Union[FakeKey, FakeDeleteMarker]) -> bool:
    if not key_object or isinstance(key_object, FakeDeleteMarker) or not key_object._expiry:
        return False
    return key_object._expiry <= datetime.datetime.now(key_object._expiry.tzinfo)


def get_bucket_from_moto(
    moto_backend: moto_s3_models.S3Backend, bucket: BucketName
) -> moto_s3_models.FakeBucket:
    # TODO: check authorization for buckets as well?
    try:
        return moto_backend.get_bucket(bucket_name=bucket)
    except MissingBucket:
        raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)


def get_key_from_moto_bucket(
    moto_bucket: FakeBucket,
    key: ObjectKey,
    version_id: str = None,
    raise_if_delete_marker_method: Literal["GET", "PUT"] = None,
) -> FakeKey | FakeDeleteMarker:
    # TODO: rework the delete marker handling
    # we basically need to re-implement moto `get_object` to account for FakeDeleteMarker
    if version_id is None:
        fake_key = moto_bucket.keys.get(key)
    else:
        for key_version in moto_bucket.keys.getlist(key, default=[]):
            if str(key_version.version_id) == str(version_id):
                fake_key = key_version
                break
        else:
            fake_key = None

    if not fake_key:
        raise NoSuchKey("The specified key does not exist.", Key=key)

    if isinstance(fake_key, FakeDeleteMarker) and raise_if_delete_marker_method:
        # TODO: validate method, but should be PUT in most cases (updating a DeleteMarker)
        match raise_if_delete_marker_method:
            case "GET":
                raise NoSuchKey("The specified key does not exist.", Key=key)
            case "PUT":
                raise MethodNotAllowed(
                    "The specified method is not allowed against this resource.",
                    Method="PUT",
                    ResourceType="DeleteMarker",
                )

    return fake_key
