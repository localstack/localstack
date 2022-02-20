"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging
from typing import Any, Optional

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers

from localstack import constants
from localstack.http import Request, Response
from localstack.http.adapters import ProxyListenerAdapter
from localstack.services.generic_proxy import ProxyListener, modify_and_forward
from localstack.services.messages import MessagePayload
from localstack.utils.aws.request_context import extract_region_from_headers
from localstack.utils.persistence import PersistingProxyListener

from .api import RequestContext
from .chain import Handler, HandlerChain
from .skeleton import Skeleton
from .spec import load_service

LOG = logging.getLogger(__name__)


def get_region(request: Request) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id(_: Request) -> str:
    # TODO: at some point we may want to get the account id from credentials
    return constants.TEST_AWS_ACCOUNT_ID


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
        context.account_id = get_account_id(request)
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


class AsfWithPersistingFallbackListener(AsfWithFallbackListener, PersistingProxyListener):
    fallback: PersistingProxyListener

    def __init__(self, api: str, delegate: Any, fallback: PersistingProxyListener):
        super().__init__(api, delegate, fallback)

    def api_name(self):
        return self.fallback.api_name()


class _NoHandlerCalled(Exception):
    pass


class _DummyProxyListener(ProxyListener):
    def forward_request(self, method, path, data, headers):
        raise _NoHandlerCalled


class DefaultListenerHandler(Handler):
    """
    Adapter that exposes the ProxyListener.DEFAULT_LISTENERS as a Handler.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not ProxyListener.DEFAULT_LISTENERS:
            return

        req = context.request
        path_with_query = req.full_path if req.query_string else req.path

        try:
            resp = modify_and_forward(
                method=req.method,
                path=path_with_query,
                data_bytes=req.data,
                headers=req.headers,
                forward_base_url=None,
                listeners=[_DummyProxyListener()],
                client_address=req.remote_addr,
                server_address=req.host,
            )
        except _NoHandlerCalled:
            return

        # TODO: replace with util code
        response.status_code = resp.status_code
        response.headers = Headers(dict(resp.headers))
        response.set_response(resp.content)

        chain.stop()
