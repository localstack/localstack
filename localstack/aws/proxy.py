from botocore.model import ServiceModel
from requests.models import Response
from werkzeug.datastructures import Headers

from localstack import constants
from localstack.aws.api import HttpRequest, HttpResponse, RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.services.generic_proxy import ProxyListener, modify_and_forward
from localstack.utils.aws.request_context import extract_region_from_headers


def get_region(request: HttpRequest) -> str:
    return extract_region_from_headers(request.headers)


def get_account_id(_: HttpRequest) -> str:
    # TODO: at some point we may want to get the account id from credentials
    return constants.TEST_AWS_ACCOUNT_ID


class AwsApiListener(ProxyListener):
    service: ServiceModel

    def __init__(self, api, delegate):
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


class _NoHandlerCalled(Exception):
    pass


class _DummyProxyListener(ProxyListener):
    def forward_request(self, method, path, data, headers):
        raise _NoHandlerCalled


class DefaultListenerHandler(Handler):
    """
    Adapter that exposes the ProxyListener.DEFAULT_LISTENERS as a Handler.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        if not ProxyListener.DEFAULT_LISTENERS:
            return

        req = context.request

        try:
            resp = modify_and_forward(
                method=req.method,
                path=req.path,  # TODO: should have parameters
                data_bytes=req.data,
                headers=req.headers,
                forward_base_url=None,
                listeners=[_DummyProxyListener()],
                request_handler=None,
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
