""" Handlers for compatibility with legacy edge proxy and the quart http framework."""

import logging
import re
from typing import Mapping

from requests import Response as RequestsResponse

from localstack.constants import HEADER_LOCALSTACK_EDGE_URL, HEADER_LOCALSTACK_REQUEST_URL
from localstack.http import Response
from localstack.http.request import restore_payload
from localstack.services.generic_proxy import ProxyListener, modify_and_forward

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from .routes import RouterHandler

LOG = logging.getLogger(__name__)


def push_request_context(_chain: HandlerChain, context: RequestContext, _response: Response):
    # hack for legacy compatibility. various parts of localstack access the global flask/quart/our own request
    # context. since we're neither in a flask nor a quart context, we're pushing our own context object into their
    # proxy objects, which is terrible, but works because mostly code just accesses "context.request", so we don't
    # have to bother pushing a real quart/flask context.
    import flask.globals
    import quart.globals

    from localstack.utils.aws import request_context

    quart.globals._request_ctx_stack.push(context)
    flask.globals._request_ctx_stack.push(context)
    request_context.THREAD_LOCAL.request_context = context.request


def pop_request_context(_chain: HandlerChain, _context: RequestContext, _response: Response):
    # hack for legacy compatibility
    import flask.globals
    import quart.globals

    from localstack.utils.aws import request_context

    quart.globals._request_ctx_stack.pop()
    flask.globals._request_ctx_stack.pop()
    request_context.THREAD_LOCAL.request_context = None


class EdgeRouterHandler(RouterHandler):
    def __init__(self, respond_not_found=False) -> None:
        from localstack.services.edge import ROUTER

        super().__init__(ROUTER, respond_not_found)


class GenericProxyHandler(Handler):
    """
    This handler maps HandlerChain requests to the generic proxy ProxyListener interface `forward_request`.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        request = context.request

        # a werkzeug Request consumes form/multipart data from the socket stream, so we need to restore the payload here
        data = restore_payload(request)

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
                    response.headers["Content-Length"] = str(length)
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


class _NoHandlerCalled(Exception):
    pass


class _DummyProxyListener(ProxyListener):
    def forward_request(self, method, path, data, headers):
        raise _NoHandlerCalled


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
