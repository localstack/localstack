from botocore.model import ServiceModel
from requests.models import Response
from werkzeug.datastructures import Headers

from localstack import constants
from localstack.aws.api import HttpRequest, HttpResponse, RequestContext
from localstack.aws.gateway import Gateway
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.request_context import extract_region_from_headers


def to_server_response(response: HttpResponse):
    # TODO: creating response objects in this way (re-using the requests library instead of an HTTP server
    #  framework) is a bit ugly, but it's the way that the edge proxy expects them.
    resp = Response()
    resp._content = response["body"]
    resp.status_code = response["status_code"]
    resp.headers.update(response["headers"])
    resp.headers["Content-Length"] = str(len(response["body"]))
    return resp


class GatewayListener(ProxyListener):
    """
    An edge proxy listener that delegates requests to a Gateway.
    """

    gateway: Gateway

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
        response: HttpResponse = dict()

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
        request = HttpRequest(
            method=method,
            path=path,
            headers=Headers(headers),
            body=data,
        )

        context = self.create_request_context(request)
        response = self.skeleton.invoke(context)
        return to_server_response(response)

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
        resp._content = response["body"]
        resp.status_code = response["status_code"]
        resp.headers.update(response["headers"])
        resp.headers["Content-Length"] = str(len(response["body"]))
        return resp


def get_region(request: HttpRequest) -> str:
    return extract_region_from_headers(request["headers"])


def get_account_id(_: HttpRequest) -> str:
    # TODO: at some point we may want to get the account id from credentials
    return constants.TEST_AWS_ACCOUNT_ID
