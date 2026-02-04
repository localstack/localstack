from localstack.aws.api.s3 import InvalidTag
from localstack.aws.api.s3control import Tag, TagList
from localstack.aws.forwarder import NotImplementedAvoidFallbackError
from localstack.services.s3.exceptions import MalformedXML
from localstack.services.s3.models import s3_stores
from localstack.services.s3.utils import TAG_REGEX
from localstack.services.s3control.provider import NoSuchResource


def validate_arn_for_tagging(
    resource_arn: str, partition: str, account_id: str, region: str
) -> None:
    """
    Validates the resource ARN for the resource being tagged.

    :param resource_arn: The ARN of the resource being tagged.
    :param partition: The partition the request is originating from.
    :param account_id: The account ID of the target resource.
    :param region: The region the request is originating from.
    :return: None
    """

    s3_prefix = f"arn:{partition}:s3:::"
    if not resource_arn.startswith(s3_prefix):
        # Moto does not support Tagging operations for S3 Control, so we should not forward those operations back
        # to it
        raise NotImplementedAvoidFallbackError(
            "LocalStack only support Bucket tagging operations for S3Control"
        )

    store = s3_stores[account_id][region]
    bucket_name = resource_arn.removeprefix(s3_prefix)
    if bucket_name not in store.global_bucket_map:
        raise NoSuchResource("The specified resource doesn't exist.")


def validate_tags(tags: TagList):
    """
    Validate the tags provided. This is the same function as S3, but with different error messages
    :param tags: a TagList object
    :raises MalformedXML if the object does not conform to the schema
    :raises InvalidTag if the tag key or value are outside the set of validations defined by S3 and S3Control
    :return: None
    """
    keys = set()
    for tag in tags:
        tag: Tag
        if set(tag) != {"Key", "Value"}:
            raise MalformedXML()

        key = tag["Key"]
        value = tag["Value"]

        if key is None or value is None:
            raise MalformedXML()

        if key in keys:
            raise InvalidTag(
                "There are duplicate tag keys in your request. Remove the duplicate tag keys and try again.",
                TagKey=key,
            )

        if key.startswith("aws:"):
            raise InvalidTag(
                'User-defined tag keys can\'t start with "aws:". This prefix is reserved for system tags. Remove "aws:" from your tag keys and try again.',
            )

        if not TAG_REGEX.match(key):
            raise InvalidTag(
                "This request contains a tag key or value that isn't valid. Valid characters include the following: [a-zA-Z+-=._:/]. Tag keys can contain up to 128 characters. Tag values can contain up to 256 characters.",
                TagKey=key,
            )
        elif not TAG_REGEX.match(value):
            raise InvalidTag(
                "This request contains a tag key or value that isn't valid. Valid characters include the following: [a-zA-Z+-=._:/]. Tag keys can contain up to 128 characters. Tag values can contain up to 256 characters.",
                TagKey=key,
                TagValue=value,
            )

        keys.add(key)
