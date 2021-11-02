from werkzeug import run_simple
from werkzeug.datastructures import Headers
from werkzeug.wrappers import Request, Response

from localstack.aws.api import HttpRequest, HttpResponse
from localstack.aws.gateway import Gateway


class WsgiGateway:
    """
    Exposes a Gateway as a WSGI application.
    """

    gateway: Gateway

    def __init__(self, gateway) -> None:
        super().__init__()
        self.gateway = gateway

    def __call__(self, environ, start_response):
        request = Request(environ)

        http_request = HttpRequest(
            method=request.method,
            path=request.path,
            headers=Headers(request.headers),
            body=request.get_data(),
        )
        http_response: HttpResponse = dict()
        http_response["headers"] = Headers()
        self.gateway.process(http_request, http_response)

        response = Response(
            http_response.get("body", b""),
            status=http_response.get("status_code", 200),
            headers=http_response["headers"],
        )

        return response(environ, start_response)


def serve(gateway: Gateway, host="localhost", port=4566, use_reloader=True, **kwargs):
    run_simple(host, port, WsgiGateway(gateway), use_reloader=use_reloader, **kwargs)
