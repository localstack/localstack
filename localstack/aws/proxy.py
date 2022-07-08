"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging
from typing import Any, Optional

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers

from localstack.aws.accounts import get_account_id_from_access_key_id, set_ctx_aws_access_key_id
from localstack.aws.api import RequestContext
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.constants import TEST_AWS_ACCESS_KEY_ID
from localstack.http import Request, Response
from localstack.http.adapters import ProxyListenerAdapter
from localstack.services.generic_proxy import ProxyListener
from localstack.services.messages import MessagePayload
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header
from localstack.utils.aws.request_context import extract_region_from_headers

LOG = logging.getLogger(__name__)


def get_region(request: Request) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id_from_request(request: Request) -> str:
    access_key_id = (
        extract_access_key_id_from_auth_header(request.headers) or TEST_AWS_ACCESS_KEY_ID
    )
    set_ctx_aws_access_key_id(access_key_id)
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


def _raise_not_implemented_error(*args, **kwargs):
    raise NotImplementedError


class AsfWithFallbackListener(AwsApiListener):
    """
    An AwsApiListener that does not return a default error response if a particular method has not been implemented,
    but instead calls a second ProxyListener. This is useful to migrate service providers to ASF providers.
    """

    api: str
    delegate: Any
    fallback: ProxyListener

    def __init__(self, api: str, delegate: Any, fallback: ProxyListener):
        super().__init__(api, delegate)
        self.fallback = fallback
        self.skeleton.on_not_implemented_error = _raise_not_implemented_error

    def forward_request(self, method, path, data, headers):
        try:
            return super().forward_request(method, path, data, headers)
        except (NotImplementedError):
            LOG.debug("no ASF handler for %s %s, using fallback listener", method, path)
            return self.fallback.forward_request(method, path, data, headers)

    def return_response(
        self, method: str, path: str, data: MessagePayload, headers: Headers, response: Response
    ) -> Optional[Response]:
        return self.fallback.return_response(method, path, data, headers, response)

    def get_forward_url(self, method: str, path: str, data, headers):
        return self.fallback.get_forward_url(method, path, data, headers)
