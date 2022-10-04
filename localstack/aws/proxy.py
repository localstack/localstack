"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging
from typing import Any

from botocore.model import ServiceModel

from localstack.aws.accounts import get_account_id_from_access_key_id, set_aws_access_key_id
from localstack.aws.api import RequestContext
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.constants import TEST_AWS_ACCESS_KEY_ID
from localstack.http import Request, Response
from localstack.http.adapters import ProxyListenerAdapter
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
    return get_account_id_from_access_key_id(access_key_id)


class AwsApiListener(ProxyListenerAdapter):
    service: ServiceModel

    def __init__(self, api: str, delegate: Any):
        self.service = load_service(api)
        self.skeleton = Skeleton(self.service, delegate)

    def request(self, request: Request) -> Response:
        context = self.create_request_context(request)
        return self.skeleton.invoke(context)

    def create_request_context(self, request: Request) -> RequestContext:
        context = RequestContext()
        context.service = self.service
        context.request = request
        context.region = get_region(request)
        context.account_id = get_account_id_from_request(request)
        return context
