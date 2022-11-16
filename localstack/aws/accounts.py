"""Functionality related to AWS Accounts"""
import logging
import re
import threading

from localstack.constants import DEFAULT_AWS_ACCOUNT_ID, TEST_AWS_ACCESS_KEY_ID

LOG = logging.getLogger(__name__)

# Thread local storage for keeping current request & account related info
REQUEST_CTX_TLS = threading.local()

#
# Access Key IDs
#


def get_aws_access_key_id() -> str:
    """Return the AWS access key ID for current context."""
    return getattr(REQUEST_CTX_TLS, "access_key_id", TEST_AWS_ACCESS_KEY_ID)


def set_aws_access_key_id(access_key_id: str):
    REQUEST_CTX_TLS.access_key_id = access_key_id


#
# Account IDs
#


def get_aws_account_id() -> str:
    """Return the AWS account ID for the current context."""
    try:
        return REQUEST_CTX_TLS.account_id
    except AttributeError:
        LOG.debug(
            "No Account ID in thread-local storage for thread %s",
            threading.current_thread().ident,
        )
        return DEFAULT_AWS_ACCOUNT_ID


def set_aws_account_id(account_id: str) -> None:
    REQUEST_CTX_TLS.account_id = account_id


def get_account_id_from_access_key_id(access_key_id: str) -> str:
    """Return the Account ID associated the Access Key ID."""

    # If AWS_ACCESS_KEY_ID has a 12-digit integer value, use it as the account ID
    if re.match(r"\d{12}", access_key_id):
        return access_key_id

    elif len(access_key_id) >= 20:
        # If AWS_ACCESS_KEY_ID has production AWS credentials, ignore them
        if access_key_id.startswith("ASIA") or access_key_id.startswith("AKIA"):
            LOG.warning(
                "Ignoring production AWS credentials provided to LocalStack. Falling back to default account ID."
            )

        elif access_key_id.startswith("LSIA") or access_key_id.startswith("LKIA"):
            # TODO Add IAM mapping logic here
            pass

    return DEFAULT_AWS_ACCOUNT_ID
