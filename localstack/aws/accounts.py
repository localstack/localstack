"""Functionality related to AWS Accounts"""
import re
import threading
from typing import Optional

from localstack.constants import _TEST_AWS_ACCOUNT_ID
from localstack.runtime import hooks

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

    if re.match(r"\d{12}", access_key_id):
        return access_key_id
    else:
        return get_default_account_id()


def get_ctx_aws_access_key_id() -> Optional[str]:
    """Return the AWS access key ID for current context."""
    return getattr(REQUEST_CTX_TLS, "access_key_id", None)


def set_ctx_aws_access_key_id(access_key_id: str):
    REQUEST_CTX_TLS.access_key_id = access_key_id


@hooks.on_infra_start()
def patch_get_account_id():
    """Patch Moto's account ID resolver with our own."""
    from moto import core as moto_core
    from moto.core import models as moto_core_models

    from localstack.aws.accounts import get_default_account_id

    moto_core.account_id_resolver = get_default_account_id
    moto_core.ACCOUNT_ID = moto_core_models.ACCOUNT_ID = get_default_account_id()
