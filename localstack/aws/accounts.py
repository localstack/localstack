"""Functionality related to AWS Accounts"""
import base64
import binascii
import logging
import re
import threading
from typing import Optional

import moto.core

from localstack.constants import DEFAULT_AWS_ACCOUNT_ID

# Thread local storage for keeping current request & account related info
REQUEST_CTX_TLS = threading.local()

# Account id offset for id extraction
# generated from int.from_bytes(base64.b32decode(b"QAAAAAAA"), byteorder="big") (user id 000000000000)
ACCOUNT_OFFSET = 549755813888
# Basically the base32 alphabet, for better access as constant here
AWS_ACCESS_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

LOG = logging.getLogger(__name__)
#
# Access Key IDs
#


def get_aws_access_key_id() -> Optional[str]:
    """Return the AWS access key ID for current context."""
    return getattr(REQUEST_CTX_TLS, "access_key_id", None)


def set_aws_access_key_id(access_key_id: str):
    REQUEST_CTX_TLS.access_key_id = access_key_id


#
# Account IDs
#


def get_aws_account_id() -> str:
    """Return the AWS account ID for the current context."""
    return account_id_resolver()


def get_default_account_id() -> str:
    return DEFAULT_AWS_ACCOUNT_ID


def get_moto_default_account_id() -> str:
    return moto.core.DEFAULT_ACCOUNT_ID


account_id_resolver = get_default_account_id

#
# Utils
#


def extract_account_id_from_access_key_id(access_key_id: str) -> str:
    """
    Extract account id from access key id

    Example:
        "ASIAQAAAAAAAGMKEM7X5" => "000000000000"
        "AKIARZPUZDIKGB2VALC4" => "123456789012"
    :param access_key_id: Access key id. Must start with either ASIA or AKIA and has at least 20 characters
    :return: Account ID (as string), 12 digits
    """
    account_id_part = access_key_id[4:12]
    # decode account id part
    try:
        account_id_part_int = int.from_bytes(base64.b32decode(account_id_part), byteorder="big")
    except binascii.Error:
        LOG.warning(
            "Invalid Access Key Id format. Falling back to default id: %s", get_default_account_id()
        )
        return get_default_account_id()

    account_id = 2 * (account_id_part_int - ACCOUNT_OFFSET)
    try:
        if AWS_ACCESS_KEY_ALPHABET.index(access_key_id[12]) >= 16:
            account_id += 1
    except ValueError:
        LOG.warning(
            "Char at index 12 not from base32 alphabet. Falling back to default id: %s",
            get_default_account_id(),
        )
        return get_default_account_id()
    if account_id < 0 or account_id > 999999999999:
        LOG.warning(
            "Extracted account id not between 000000000000 and 999999999999. Falling back to default id: %s",
            get_default_account_id(),
        )
        return get_default_account_id()
    return f"{account_id:012}"


def get_account_id_from_access_key_id(access_key_id: str) -> str:
    """Return the Account ID associated the Access Key ID."""
    # For now, we assume the client sends Account ID or an IAM Access Key ID in Access Key ID field.

    if re.match(r"\d{12}", access_key_id):
        return access_key_id
    else:
        if len(access_key_id) >= 20 and (
            access_key_id.startswith("ASIA") or access_key_id.startswith("AKIA")
        ):
            return extract_account_id_from_access_key_id(access_key_id)
        else:
            return get_default_account_id()
