import base64
import random

AWS_ROLE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ACCOUNT_OFFSET = (
    549755813888  # int.from_bytes(base64.b32decode(b"QAAAAAAA"), byteorder="big"), start value
)

REQUIRE_RESOURCE_ACCESS_POLICIES_CHECK = ["sts:AssumeRole"]
EXTERNAL_CONDITION_SOURCES = ["sts:ExternalId"]


def _random_uppercase_or_digit_sequence(length: int) -> str:
    return "".join(str(random.choice(AWS_ROLE_ALPHABET)) for _ in range(length))


def generate_iam_identifier(account_id: str, prefix: str, total_length: int = 20) -> str:
    """
    Generates an IAM identifier (e.g. access key id, user ID etc.) for the given account id and prefix

    :param account_id: Account id this key id should belong to
    :param prefix: Prefix, e.g. ASIA for temp credentials or AROA for roles
    :param total_length: Total length of the access key (e.g. 20 for temp access keys, 21 for role ids)
    :return: Generated id
    """
    account_id_nr = int(account_id)
    id_with_offset = account_id_nr // 2 + ACCOUNT_OFFSET
    account_bytes = int.to_bytes(id_with_offset, byteorder="big", length=5)
    account_part = base64.b32encode(account_bytes).decode("utf-8")
    middle_char = (
        random.choice(AWS_ROLE_ALPHABET[16:])
        if account_id_nr % 2
        else random.choice(AWS_ROLE_ALPHABET[:16])
    )
    semi_fixed_part = prefix + account_part + middle_char
    return semi_fixed_part + _random_uppercase_or_digit_sequence(
        total_length - len(semi_fixed_part)
    )


def generate_access_key_id_from_account_id(
    account_id: str, prefix: str, total_length: int = 20
) -> str:
    """
    Generates a key id (e.g. access key id) for the given account id and prefix

    :param account_id: Account id this key id should belong to
    :param prefix: Prefix, e.g. ASIA for temp credentials or AROA for roles
    :param total_length: Total length of the access key (e.g. 20 for temp access keys, 21 for role ids)
    :return: Generated id
    """
    account_id_nr = int(account_id)
    id_with_offset = account_id_nr // 2 + ACCOUNT_OFFSET
    account_bytes = int.to_bytes(id_with_offset, byteorder="big", length=5)
    account_part = base64.b32encode(account_bytes).decode("utf-8")
    middle_char = (
        random.choice(AWS_ROLE_ALPHABET[16:])
        if account_id_nr % 2
        else random.choice(AWS_ROLE_ALPHABET[:16])
    )
    semi_fixed_part = prefix + account_part + middle_char
    return semi_fixed_part + _random_uppercase_or_digit_sequence(
        total_length - len(semi_fixed_part)
    )
