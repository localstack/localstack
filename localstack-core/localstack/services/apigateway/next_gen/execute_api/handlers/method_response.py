import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class MethodResponseHandler(RestApiGatewayHandler):
    """
    This class might not too much, we still need to investigate but from a first look, does not have much impact
    on the HTTP response
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        return
