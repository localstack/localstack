"""Functionality related to AWS Accounts"""
import threading
from typing import Optional

from localstack.constants import _TEST_AWS_ACCOUNT_ID, TEST_AWS_ACCESS_KEY_ID

# Thread local storage for keeping current request & account related info
REQUEST_CTX_TLS = threading.local()


def get_aws_account_id() -> str:
    """Return the AWS account ID for the current context."""
    return account_id_resolver()


def get_default_account_id() -> str:
    return _TEST_AWS_ACCOUNT_ID


account_id_resolver = get_default_account_id


def get_account_id_from_access_key_id(access_key_id: str) -> str:
    """Return the Account ID associated the Access Key ID."""
    # This utility ignores IAM mappings.
    # For now, we assume the client sends Account ID in Access Key ID field.

    if access_key_id == TEST_AWS_ACCESS_KEY_ID:
        # Keep backward compatibilty prior to multi-accounts revamp
        return get_default_account_id()
    else:
        return access_key_id


def get_ctx_aws_access_key_id() -> Optional[str]:
    """Return the AWS access key ID for current context."""
    return getattr(REQUEST_CTX_TLS, "access_key_id", None)


def set_ctx_aws_access_key_id(access_key_id: str):
    REQUEST_CTX_TLS.access_key_id = access_key_id
