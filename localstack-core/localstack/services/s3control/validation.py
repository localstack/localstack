from localstack.aws.api.s3 import InvalidTag
from localstack.aws.api.s3control import Tag, TagList
from localstack.services.s3.exceptions import MalformedXML
from localstack.services.s3.utils import TAG_REGEX


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
