import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationResponse, RestApiInvocationContext

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
        method_response = self.serialize_invocation_response(context.invocation_response)
        response.update_from(method_response)

    @staticmethod
    def serialize_invocation_response(invocation_response: InvocationResponse) -> Response:
        return Response(
            response=invocation_response["body"],
            headers=invocation_response["headers"],
            status=invocation_response["status_code"],
        )
