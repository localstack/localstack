import base64
import dataclasses
import random

from localstack.services.iam.models import iam_stores

AWS_ROLE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ACCOUNT_OFFSET = (
    549755813888  # int.from_bytes(base64.b32decode(b"QAAAAAAA"), byteorder="big"), start value
)


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


@dataclasses.dataclass
class AccessKeyInfo:
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


def get_access_key_by_id(account_id: str, region: str, access_key_id: str) -> AccessKeyInfo | None:
    iam_store = iam_stores[account_id][region]
    # sts_store = sts_stores[account_id][region]
    if user_name := iam_store.ACCESS_KEY_INDEX.get(access_key_id):
        user = iam_store.USERS.get(user_name)
        if user and (access_key := user.access_keys.get(access_key_id)):
            return AccessKeyInfo(
                access_key_id=access_key.access_key["AccessKeyId"],
                secret_access_key=access_key.access_key["SecretAccessKey"],
            )
        # store in a non consistent state - maybe access key was deleted in the meantime
        return None
    # TODO sts store lookup
