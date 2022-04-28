from requests import Response as RequestsResponse

from localstack.aws.gateway import Gateway
from localstack.http import Request, Response
from localstack.utils.run import FuncThread
from localstack.utils.server import http2_server


def to_server_response(response: Response):
    # TODO: creating response objects in this way (re-using the requests library instead of an HTTP server
    #  framework) is a bit ugly, but it's the way that the edge proxy expects them.
    resp = RequestsResponse()
    resp._content = response.data
    resp.status_code = response.status_code
    resp.headers.update(response.headers)
    resp.headers["Content-Length"] = response.content_length
    return resp


class GatewayHandler:
    """
    A handler to serve a gateway through LocalStack's http2_server utility that wraps Quart.
    """

    gateway: Gateway

    def __init__(self, gateway: Gateway):
        self.gateway = gateway

    def __call__(self, request, data):
        request = Request(
            method=request.method,
            path=request.path,
            query_string=request.query_string,
            headers=request.headers,
            body=data,
            remote_addr=request.remote_addr,
        )
        response = Response()

        self.gateway.process(request, response)

        return to_server_response(response)


def serve_threaded(gateway: Gateway, host="localhost", port=4566, ssl_creds=None) -> FuncThread:
    return http2_server.run_server(
        port, [host], handler=GatewayHandler(gateway), ssl_creds=ssl_creds
    )
