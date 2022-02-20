from werkzeug import run_simple
from werkzeug.datastructures import Headers
from werkzeug.wrappers import Request

from localstack.aws.gateway import Gateway
from localstack.http import Response


class WsgiGateway:
    """
    Exposes a Gateway as a WSGI application.
    """

    gateway: Gateway

    def __init__(self, gateway) -> None:
        super().__init__()
        self.gateway = gateway

    def __call__(self, environ, start_response):
        http_request = Request(environ)
        http_request.headers = Headers(http_request.headers)
        http_response = Response()

        # Request is a drop-in replacement for HttpRequest
        # noinspection PyTypeChecker
        self.gateway.process(http_request, http_response)

        return http_response(environ, start_response)


def serve(gateway: Gateway, host="localhost", port=4566, use_reloader=True, **kwargs):
    run_simple(host, port, WsgiGateway(gateway), use_reloader=use_reloader, **kwargs)
