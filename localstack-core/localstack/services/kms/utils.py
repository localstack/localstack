import base64
import re
from collections.abc import Callable

from localstack.aws.api.kms import (
    CreateKeyRequest,
    DryRunOperationException,
    Tag,
    TagException,
    TagList,
)
from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.services.kms.exceptions import ValidationException
from localstack.utils.aws.arns import ARN_PARTITION_REGEX

KMS_KEY_ARN_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:kms:(?P<region_name>[^:]+):(?P<account_id>\d{{12}}):((?=key/)key/|(?=alias/))(?P<key_id>[^:]+)$"
)
# special tag name to allow specifying a custom key material for created keys
TAG_KEY_CUSTOM_KEY_MATERIAL = "_custom_key_material_"


def get_hash_algorithm(signing_algorithm: str) -> str:
    """
    Return the hashing algorithm for a given signing algorithm.
    eg. "RSASSA_PSS_SHA_512" -> "SHA_512"
    """
    return "_".join(signing_algorithm.rsplit(sep="_", maxsplit=-2)[-2:])


def parse_key_arn(key_arn: str) -> tuple[str, str, str]:
    """
    Parse a valid KMS key arn into its constituents.

    :param key_arn: KMS key ARN
    :return: Tuple of account ID, region name and key ID
    """
    return KMS_KEY_ARN_PATTERN.match(key_arn).group("account_id", "region_name", "key_id")


def is_valid_key_arn(key_arn: str) -> bool:
    """
    Check if a given string is a valid KMS key ARN.
    """
    return KMS_KEY_ARN_PATTERN.match(key_arn) is not None


def validate_alias_name(alias_name: str) -> None:
    if not alias_name.startswith("alias/"):
        raise ValidationException(
            'Alias must start with the prefix "alias/". Please see '
            "https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html"
        )


def validate_tag(tag_position: int, tag: Tag) -> None:
    tag_key = tag.get("TagKey")
    tag_value = tag.get("TagValue")

    if len(tag_key) > 128:
        raise ValidationException(
            f"1 validation error detected: Value '{tag_key}' at 'tags.{tag_position}.member.tagKey' failed to satisfy constraint: Member must have length less than or equal to 128"
        )
    if len(tag_value) > 256:
        raise ValidationException(
            f"1 validation error detected: Value '{tag_value}' at 'tags.{tag_position}.member.tagValue' failed to satisfy constraint: Member must have length less than or equal to 256"
        )

    if tag_key.lower().startswith("aws:"):
        raise TagException("Tags beginning with aws: are reserved")


def validate_and_filter_tags(tag_list: TagList) -> TagList:
    """
    Validates tags and filters out LocalStack specific tags

    :param tag_list: The list of tags provided to apply to the KMS key.
    :returns: Filtered and validated list of tags to apply to the KMS key.
    """
    unique_tag_keys = {tag["TagKey"] for tag in tag_list}
    if len(unique_tag_keys) < len(tag_list):
        raise TagException("Duplicate tag keys")
    if len(tag_list) > 50:
        raise TagException("Too many tags")

    validated_tags = []
    for i, tag in enumerate(tag_list, start=1):
        if tag["TagKey"] != TAG_KEY_CUSTOM_KEY_MATERIAL:
            validate_tag(i, tag)
            validated_tags.append(tag)

    return validated_tags


def get_custom_key_material(request: CreateKeyRequest | None) -> bytes | None:
    """
    Retrieves custom material which is sent in a CreateKeyRequest via the Tags.

    :param request: The request for creating a KMS key.
    :returns: Custom key material for the KMS key.
    """
    if not request:
        return None

    tags = request.get("Tags", [])
    for tag in tags:
        if tag["TagKey"] == TAG_KEY_CUSTOM_KEY_MATERIAL:
            return base64.b64decode(tag["TagValue"])
    return None


def get_custom_key_id(request: CreateKeyRequest | None) -> bytes | None:
    """
    Retrieves a custom Key ID for the KMS key which is sent in a CreateKeyRequest via the Tags.

    :param request: The request for creating a KMS key.
    :returns: THe custom Key ID for the KMS key.
    """
    if not request:
        return None

    tags = request.get("Tags", [])
    for tag in tags:
        if tag["TagKey"] == TAG_KEY_CUSTOM_ID:
            return tag["TagValue"]
    return None


def execute_dry_run_capable[T](func: Callable[..., T], dry_run: bool, *args, **kwargs) -> T:
    """
    Executes a function unless dry run mode is enabled.

    If ``dry_run`` is ``True``, the function is not executed and a
    ``DryRunOperationException`` is raised. Otherwise, the provided
    function is called with the given positional and keyword arguments.

    :param func: The function to be executed.
    :type func: Callable[..., T]
    :param dry_run: Flag indicating whether the execution is a dry run.
    :type dry_run: bool
    :param args: Positional arguments to pass to the function.
    :param kwargs: Keyword arguments to pass to the function.
    :returns: The result of the function call if ``dry_run`` is ``False``.
    :rtype: T
    :raises DryRunOperationException: If ``dry_run`` is ``True``.
    """
    if dry_run:
        raise DryRunOperationException(
            "The request would have succeeded, but the DryRun option is set."
        )
    return func(*args, **kwargs)
