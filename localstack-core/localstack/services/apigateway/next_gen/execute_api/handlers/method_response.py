import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationResponse, RestApiInvocationContext
from ..header_utils import (
    drop_response_headers,
    remap_response_headers,
    set_default_response_headers,
)

LOG = logging.getLogger(__name__)


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

        remap_response_headers(headers, integration_type)
        drop_response_headers(headers, integration_type)

        set_default_response_headers(headers, context, integration_type)
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
