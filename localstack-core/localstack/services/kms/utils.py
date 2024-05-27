import re
from typing import Tuple

from localstack.services.kms.exceptions import ValidationException
from localstack.utils.aws.arns import ARN_PARTITION_REGEX

KMS_KEY_ARN_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:kms:(?P<region_name>[^:]+):(?P<account_id>\d{{12}}):key\/(?P<key_id>[^:]+)$"
)


def get_hash_algorithm(signing_algorithm: str) -> str:
    """
    Return the hashing algorithm for a given signing algorithm.
    eg. "RSASSA_PSS_SHA_512" -> "SHA_512"
    """
    return "_".join(signing_algorithm.rsplit(sep="_", maxsplit=-2)[-2:])


def parse_key_arn(key_arn: str) -> Tuple[str, str, str]:
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
