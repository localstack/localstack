"""
Adapters and other utilities to use ASF together with the edge proxy.
"""
import logging
import re
from typing import Any, Mapping, Optional
from urllib.parse import urlencode

from botocore.model import ServiceModel
from requests import Response as RequestsResponse
from werkzeug.datastructures import Headers, MultiDict
from werkzeug.test import encode_multipart

from localstack import constants
from localstack.constants import HEADER_LOCALSTACK_EDGE_URL, HEADER_LOCALSTACK_REQUEST_URL
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


class GenericProxyHandler(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        request = context.request

        data = request.data
        # a werkzeug Request consumes form/multipart data from the socket stream, so we need to restore the payload here
        if not data:
            if request.method == "POST":
                if request.files:
                    boundary = request.content_type.split("=")[1]

                    fields = MultiDict()
                    fields.update(request.form)
                    fields.update(request.files)

                    _, data = encode_multipart(fields, boundary)
                elif request.form:
                    data = urlencode(list(request.form.items(multi=True))).encode("utf-8")
                else:
                    LOG.debug("the request did not contain any data %s", request)
                    data = b""

        # TODO: rethink whether this proxy handling is necessary
        context.request.headers[HEADER_LOCALSTACK_REQUEST_URL] = context.request.base_url

        result = self.forward_request(
            context,
            method=request.method,
            path=request.full_path if request.query_string else request.path,
            data=data,
            headers=request.headers,
        )

        if type(result) == int:
            chain.respond(status_code=result)
            return

        if isinstance(result, tuple):
            # special case for Kinesis SubscribeToShard
            if len(result) == 2:
                response.status_code = 200
                response.set_response(result[0])
                response.headers.update(dict(result[1]))
                chain.stop()
                return

        if isinstance(result, RequestsResponse):
            response.status_code = result.status_code
            response.set_response(result.content)
            # make sure headers are set after the content, so potential content-length headers are overwritten
            response.headers.update(dict(result.headers))

            # make sure content-length is re-calculated correctly, unless it's a HEAD request
            if request.method != "HEAD":
                length = response.calculate_content_length()
                if length is not None:
                    response.headers["Content-Length"] = length
            chain.stop()
            return

        raise ValueError("cannot create response for result %s" % result)

    def forward_request(
        self, context: RequestContext, method: str, path: str, data: bytes, headers: Mapping
    ):
        raise NotImplementedError


class LegacyPluginHandler(GenericProxyHandler):
    """
    This adapter exposes Services that are developed as ProxyListener as Handler.
    """

    def forward_request(
        self, context: RequestContext, method: str, path: str, data: bytes, headers: Mapping
    ):
        from localstack.services.edge import do_forward_request

        # TODO: rethink whether this proxy handling is necessary
        request = context.request
        orig_req_url = request.headers.pop(HEADER_LOCALSTACK_REQUEST_URL, "")
        request.headers[HEADER_LOCALSTACK_EDGE_URL] = (
            re.sub(r"^([^:]+://[^/]+).*", r"\1", orig_req_url) or request.host_url
        )

        return do_forward_request(
            api=context.service.service_name,
            method=method,
            path=path,
            data=data,
            headers=headers,
            port=None,
        )


class DefaultListenerHandler(GenericProxyHandler):
    """
    Adapter that exposes the ProxyListener.DEFAULT_LISTENERS as a Handler.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not ProxyListener.DEFAULT_LISTENERS:
            return

        try:
            super(DefaultListenerHandler, self).__call__(chain, context, response)
        except _NoHandlerCalled:
            # may be raised by the _DummyProxyListener, which is reached if no other listener is called,
            # in which case we don't want to return a result or stop the chain.
            return

    def forward_request(
        self, context: RequestContext, method: str, path: str, data: bytes, headers: Mapping
    ):
        request = context.request

        return modify_and_forward(
            method=method,
            path=path,
            data_bytes=data,
            headers=headers,
            forward_base_url=None,
            listeners=[_DummyProxyListener()],
            client_address=request.remote_addr,
            server_address=request.host,
        )
