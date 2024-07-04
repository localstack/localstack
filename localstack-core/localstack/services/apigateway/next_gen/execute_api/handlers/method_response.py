import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class MethodResponseHandler(RestApiGatewayHandler):
    """
    Currently, it seems the `MethodResponse` APIGW resource might not add logic/data to the returning
    IntegrationResponse. We will need to investigate if this handler is needed.
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        return
