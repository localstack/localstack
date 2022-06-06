"""Functionality related to AWS Account IDs"""
from localstack.constants import _TEST_AWS_ACCOUNT_ID


def get_aws_account_id() -> str:
    """Return the AWS account ID."""
    return account_id_resolver()


def get_default_account_id() -> str:
    return _TEST_AWS_ACCOUNT_ID


account_id_resolver = get_default_account_id
