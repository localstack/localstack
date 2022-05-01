from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment, StartResponse

from werkzeug.datastructures import Headers
from werkzeug.wrappers import Request

from localstack.http import Response

from ..gateway import Gateway


class WsgiGateway:
    """
    Exposes a Gateway as a WSGI application.
    """

    gateway: Gateway

    def __init__(self, gateway: Gateway) -> None:
        super().__init__()
        self.gateway = gateway

    def __call__(
        self, environ: "WSGIEnvironment", start_response: "StartResponse"
    ) -> Iterable[bytes]:
        # create request from environment
        request = Request(environ)
        # by default, werkzeug requests from environ are immutable
        request.headers = Headers(request.headers)

        # prepare response
        response = Response()

        self.gateway.process(request, response)

        return response(environ, start_response)
