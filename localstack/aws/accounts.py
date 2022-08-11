"""Functionality related to AWS Accounts"""
import re
import threading
from typing import Optional

import moto.core

from localstack.constants import DEFAULT_AWS_ACCOUNT_ID

# Thread local storage for keeping current request & account related info
REQUEST_CTX_TLS = threading.local()

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


def get_account_id_from_access_key_id(access_key_id: str) -> str:
    """Return the Account ID associated the Access Key ID."""
    # This utility ignores IAM mappings.
    # For now, we assume the client sends Account ID in Access Key ID field.

    if re.match(r"\d{12}", access_key_id):
        return access_key_id
    else:
        return get_default_account_id()
