import asyncio

from botocore.model import ServiceModel
from requests.models import Response as RequestsResponse
from werkzeug.datastructures import Headers

from localstack import constants
from localstack.aws.api import RequestContext
from localstack.aws.gateway import Gateway
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.http import Request, Response
from localstack.services.generic_proxy import ProxyListener
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.utils.aws.request_context import extract_region_from_headers


def get_region(request: Request) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id(_: Request) -> str:
    # TODO: at some point we may want to get the account id from credentials
    return constants.TEST_AWS_ACCOUNT_ID


def to_server_response(response: Response):
    # TODO: creating response objects in this way (re-using the requests library instead of an HTTP server
    #  framework) is a bit ugly, but it's the way that the edge proxy expects them.
    resp = RequestsResponse()
    resp._content = response.data
    resp.status_code = response.status_code
    resp.headers.update(response.headers)
    resp.headers["Content-Length"] = response.content_length
    return resp


class GatewayListener(ProxyListener):
    """
    An edge proxy listener that delegates requests to a Gateway.
    """

    gateway: Gateway

    def __init__(self, gateway: Gateway):
        self.gateway = gateway

    def forward_request(self, method, path, data, headers):
        request = Request(
            method=method,
            path=path,
            headers=headers,
            body=data,
        )
        response = Response()

        self.gateway.process(request, response)

        return to_server_response(response)


class ServiceListener(ProxyListener):
    """
    A proxy listener for an individual service API and its remote object.
    """

    service: ServiceModel

    def __init__(self, api, delegate):
        self.service = load_service(api)
        self.skeleton = Skeleton(self.service, delegate)

    def forward_request(self, method, path, data, headers):
        request = Request(
            method=method,
            path=path,
            headers=Headers(headers),
            body=data,
        )

        context = self.create_request_context(request)
        response = self.skeleton.invoke(context)
        return to_server_response(response)

    def create_request_context(self, request: Request) -> RequestContext:
        context = RequestContext()
        context.service = self.service
        context.request = request
        context.region = get_region(request)
        context.account_id = get_account_id(request)
        return context


def serve_gateway(bind_address, port, use_ssl, asynchronous=False):
    from hypercorn import Config

    from localstack.aws.app import LocalstackAwsGateway
    from localstack.aws.serving.asgi import AsgiGateway
    from localstack.http.hypercorn import HypercornServer
    from localstack.services.generic_proxy import GenericProxy, install_predefined_cert_if_available

    # build server config
    config = Config()

    if isinstance(bind_address, str):
        bind_address = [bind_address]
    config.bind = [f"{addr}:{port}" for addr in bind_address]

    if use_ssl:
        install_predefined_cert_if_available()
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        config.certfile = cert_file_name
        config.keyfile = key_file_name

    # build gateway
    loop = asyncio.new_event_loop()
    app = AsgiGateway(LocalstackAwsGateway(SERVICE_PLUGINS), event_loop=loop)

    # start serving gateway
    server = HypercornServer(app, config, loop)
    server.start()

    if not asynchronous:
        server.join()

    return server._thread
