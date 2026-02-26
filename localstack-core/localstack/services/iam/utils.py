import base64
import dataclasses
import hashlib
import random
import string

from localstack import config
from localstack.aws.api.iam import Tag
from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.services.iam.models import iam_stores
from localstack.utils.aws.arns import get_partition

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


# ------------------------------ ID Generation Functions ------------------------------ #


def get_custom_id_from_tags(tags: list[Tag] | None) -> str | None:
    """
    Check an IAM tag list for a custom id tag, and return the value if present.

    :param tags: List of tags
    :return: Custom Id or None if not present
    """
    if not tags:
        return None
    for tag in tags:
        if tag["Key"] == TAG_KEY_CUSTOM_ID:
            return tag["Value"]
    return None


def generate_policy_id() -> str:
    """Generate a policy ID: 'A' followed by 20 random alphanumeric characters."""
    return "A" + "".join(random.choices(string.ascii_uppercase + string.digits, k=20))


def generate_aws_managed_policy_id(name: str) -> str:
    """Generate a deterministic, stable PolicyId for an AWS managed policy.

    The format mirrors real AWS IDs (``ANPA`` + 17 upper-hex chars).  The value
    is derived from a SHA-256 hash of the policy name so it is consistent across
    restarts without needing to be persisted.
    """
    hash_hex = hashlib.sha256(name.encode()).hexdigest()[:17].upper()
    return f"ANPA{hash_hex}"


def generate_role_id(account_id: str, tags: list[Tag] | None = None) -> str:
    """Generate a role ID: AROA + 17 random chars, or use custom ID from tags."""
    custom_id = get_custom_id_from_tags(tags)
    if custom_id:
        return custom_id
    return generate_iam_identifier(account_id, prefix="AROA", total_length=21)


def generate_user_id(account_id: str, tags: list[Tag] | None = None) -> str:
    """Generate a user ID: AIDA + 17 random chars, or use custom ID from tags."""
    custom_id = get_custom_id_from_tags(tags)
    if custom_id:
        return custom_id
    return generate_iam_identifier(account_id, prefix="AIDA", total_length=21)


def generate_group_id(account_id: str) -> str:
    """Generate a group ID: AGPA + 17 random chars."""
    return generate_iam_identifier(account_id, prefix="AGPA", total_length=21)


def generate_access_key_id(account_id: str) -> str:
    """Generate an access key ID with the appropriate prefix based on config."""
    prefix = "AKIA" if config.PARITY_AWS_ACCESS_KEY_ID else "LKIA"
    return generate_iam_identifier(account_id, prefix=prefix, total_length=20)


def generate_temp_access_key_id(account_id: str) -> str:
    """Generate a temporary access key ID for STS credentials (starts with ASIA)."""
    return generate_iam_identifier(account_id, prefix="ASIA", total_length=20)


def generate_secret_access_key() -> str:
    """Generate a 40-character random secret access key."""
    charset = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(charset, k=40))


def generate_credential_id(account_id: str) -> str:
    """
    Generate a credential ID.
    Credentials have a similar structure as access key ids, and also contain the account id encoded in them.
    Example: `ACCAQAAAAAAAPBAFQJI5W` for account `000000000000`

    :param account_id: Account id
    :return: New credential id.
    """
    return generate_iam_identifier(account_id, prefix="ACCA", total_length=21)


def generate_ssh_public_key_id(account_id: str) -> str:
    """Generate an SSH public key ID with APKA prefix."""
    return generate_iam_identifier(account_id, prefix="APKA", total_length=21)


def generate_ssh_key_fingerprint(ssh_public_key_body: str) -> str:
    """
    Generate a fingerprint for an SSH public key.
    The fingerprint is the MD5 hash of the key body in colon-separated hex format.
    """
    md5_hash = hashlib.md5(ssh_public_key_body.encode("utf-8")).hexdigest()
    return ":".join(md5_hash[i : i + 2] for i in range(0, len(md5_hash), 2))


def generate_server_certificate_id(account_id: str) -> str:
    """Generate a server certificate ID with ASCA prefix."""
    return generate_iam_identifier(account_id, prefix="ASCA", total_length=21)


def generate_signing_certificate_id() -> str:
    """Generate a 24-character signing certificate ID (uppercase alphanumeric)."""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=24))


def generate_instance_profile_id(account_id: str) -> str:
    """Generate an instance profile ID: AIPA + 17 random chars."""
    return generate_iam_identifier(account_id, prefix="AIPA", total_length=21)


def generate_session_token() -> str:
    """Generate a session token for STS temporary credentials."""
    chars = string.ascii_letters + string.digits + "+/="
    prefix = "FQoGZXIvYXdzE"
    body = "".join(random.choices(chars, k=343))
    return f"{prefix}{body}"


# ------------------------------ ARN Building Functions ------------------------------ #


def build_policy_arn(account_id: str, region: str, path: str, policy_name: str) -> str:
    """Build the ARN for a managed policy."""
    partition = get_partition(region)
    # Path has a prefix like /my/path/
    return f"arn:{partition}:iam::{account_id}:policy{path}{policy_name}"


def build_role_arn(account_id: str, region: str, path: str, role_name: str) -> str:
    """Build the ARN for a role."""
    partition = get_partition(region)
    return f"arn:{partition}:iam::{account_id}:role{path}{role_name}"


def build_user_arn(account_id: str, region: str, path: str, user_name: str) -> str:
    """Build the ARN for a user."""
    partition = get_partition(region)
    return f"arn:{partition}:iam::{account_id}:user{path}{user_name}"


def build_group_arn(account_id: str, region: str, path: str, group_name: str) -> str:
    """Build the ARN for a group."""
    partition = get_partition(region)
    # Path for ARN: /path/ becomes /path/ in the ARN resource portion
    if path == "/":
        return f"arn:{partition}:iam::{account_id}:group/{group_name}"
    else:
        # Remove leading slash for ARN construction
        path_part = path[1:] if path.startswith("/") else path
        return f"arn:{partition}:iam::{account_id}:group/{path_part}{group_name}"


def build_server_certificate_arn(account_id: str, partition: str, path: str, cert_name: str) -> str:
    """Build the ARN for a server certificate."""
    return f"arn:{partition}:iam::{account_id}:server-certificate{path}{cert_name}"


def build_instance_profile_arn(account_id: str, region: str, path: str, profile_name: str) -> str:
    """Build the ARN for an instance profile."""
    partition = get_partition(region)
    # Remove leading slash from path if present to avoid double slashes
    path_part = path.rstrip("/")
    if path_part == "":
        return f"arn:{partition}:iam::{account_id}:instance-profile/{profile_name}"
    return f"arn:{partition}:iam::{account_id}:instance-profile{path_part}/{profile_name}"
