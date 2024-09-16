import logging

from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import IntegrationType
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationResponse, RestApiInvocationContext
from ..header_utils import drop_headers

LOG = logging.getLogger(__name__)

# These are dropped after the templates override were applied. they will never make it to the requests.
DROPPED_FROM_INTEGRATION_RESPONSES_COMMON = ["Transfer-Encoding"]
DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY = [
    *DROPPED_FROM_INTEGRATION_RESPONSES_COMMON,
    "Content-Encoding",
    "Via",
]


# Headers that will receive a remap
REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON = [
    "Connection",
    "Content-Length",
    "Date",
    "Server",
]
REMAPPED_FROM_INTEGRATION_RESPONSE_NON_PROXY = [
    *REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON,
    "Authorization",
    "Content-MD5",
    "Expect",
    "Host",
    "Max-Forwards",
    "Proxy-Authenticate",
    "Trailer",
    "Upgrade",
    "User-Agent",
    "WWW-Authenticate",
]


class MethodResponseHandler(RestApiGatewayHandler):
    """
    Last handler of the chain, responsible for serializing the Response object
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        invocation_response = context.invocation_response
        integration_type = context.integration["type"]
        headers = invocation_response["headers"]

        self._transform_headers(headers, integration_type)

        method_response = self.serialize_invocation_response(invocation_response)
        response.update_from(method_response)

    @staticmethod
    def serialize_invocation_response(invocation_response: InvocationResponse) -> Response:
        is_content_type_set = invocation_response["headers"].get("content-type") is not None
        response = Response(
            response=invocation_response["body"],
            headers=invocation_response["headers"],
            status=invocation_response["status_code"],
        )
        if not is_content_type_set:
            # Response sets a content-type by default. This will always be ignored.
            response.headers.remove("content-type")
        return response

    @staticmethod
    def _transform_headers(headers: Headers, integration_type: IntegrationType):
        """Remaps the provided headers in-place. Adding new `x-amzn-Remapped-` headers and dropping the original headers"""
        to_remap = REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON
        to_drop = DROPPED_FROM_INTEGRATION_RESPONSES_COMMON

        match integration_type:
            case IntegrationType.HTTP | IntegrationType.AWS:
                to_remap = REMAPPED_FROM_INTEGRATION_RESPONSE_NON_PROXY
            case IntegrationType.HTTP_PROXY:
                to_drop = DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY

        for header in to_remap:
            if headers.get(header):
                LOG.debug("Remapping header: %s", header)
                remapped = headers.pop(header)
                headers[f"x-amzn-Remapped-{header}"] = remapped

        drop_headers(headers, to_drop)
