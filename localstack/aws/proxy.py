import logging
from typing import Any, Optional

from botocore.model import ServiceModel
from requests.models import Response
from werkzeug.datastructures import Headers

from localstack import constants
from localstack.aws.api import HttpRequest, HttpResponse, RequestContext
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.services.generic_proxy import ProxyListener
from localstack.services.messages import MessagePayload
from localstack.utils.aws.request_context import extract_region_from_headers
from localstack.utils.persistence import PersistingProxyListener

LOG = logging.getLogger(__name__)


def get_region(request: HttpRequest) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id(_: HttpRequest) -> str:
    # TODO: at some point we may want to get the account id from credentials
    return constants.TEST_AWS_ACCOUNT_ID


class AwsApiListener(ProxyListener):
    service: ServiceModel

    def __init__(self, api: str, delegate: Any):
        self.service = load_service(api)
        self.skeleton = Skeleton(self.service, delegate)

    def forward_request(self, method, path, data, headers):
        request = HttpRequest(
            method=method,
            path=path,
            headers=headers,
            body=data,
        )

        context = self.create_request_context(request)
        response = self.skeleton.invoke(context)
        return self.to_server_response(response)

    def create_request_context(self, request: HttpRequest) -> RequestContext:
        context = RequestContext()
        context.service = self.service
        context.request = request
        context.region = get_region(request)
        context.account_id = get_account_id(request)
        return context

    def to_server_response(self, response: HttpResponse):
        # TODO: creating response objects in this way (re-using the requests library instead of an HTTP server
        #  framework) is a bit ugly, but it's the way that the edge proxy expects them.
        resp = Response()
        resp._content = response.get_data()
        resp.status_code = response.status_code
        resp.headers.update(response.headers)
        return resp


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
        except (NotImplementedError, KeyError):
            # FIXME: KeyError may be an ASF parser error, that indicates that the request cannot be parsed
            LOG.debug("no ASF handler for %s %s, using fallback listener", method, path)
            return self.fallback.forward_request(method, path, data, headers)

    def return_response(
        self, method: str, path: str, data: MessagePayload, headers: Headers, response: Response
    ) -> Optional[Response]:
        return self.fallback.return_response(method, path, data, headers, response)

    def get_forward_url(self, method: str, path: str, data, headers):
        return self.fallback.get_forward_url(method, path, data, headers)


class AsfWithPersistingFallbackListener(AsfWithFallbackListener, PersistingProxyListener):
    fallback: PersistingProxyListener

    def __init__(self, api: str, delegate: Any, fallback: PersistingProxyListener):
        super().__init__(api, delegate, fallback)

    def api_name(self):
        return self.fallback.api_name()
