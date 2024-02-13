"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging

from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
)
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)


# TODO: consider moving this to `localstack.utils.aws.request_context`
def get_account_id_from_request(request: Request) -> str:
    access_key_id = (
        extract_access_key_id_from_auth_header(request.headers) or DEFAULT_AWS_ACCOUNT_ID
    )

    return get_account_id_from_access_key_id(access_key_id)
