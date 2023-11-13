"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging

from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
    set_aws_access_key_id,
    set_aws_account_id,
)
from localstack.constants import TEST_AWS_ACCESS_KEY_ID
from localstack.http import Request
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header
from localstack.utils.aws.request_context import extract_region_from_headers

LOG = logging.getLogger(__name__)


def get_region(request: Request) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id_from_request(request: Request) -> str:
    access_key_id = (
        extract_access_key_id_from_auth_header(request.headers) or TEST_AWS_ACCESS_KEY_ID
    )
    set_aws_access_key_id(access_key_id)

    account_id = get_account_id_from_access_key_id(access_key_id)
    set_aws_account_id(account_id)

    return account_id
