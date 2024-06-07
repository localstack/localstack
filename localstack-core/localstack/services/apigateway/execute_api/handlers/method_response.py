import logging

from localstack.http import Response

from ..api import ApiGatewayHandler, ApiGatewayHandlerChain
from ..context import InvocationContext

LOG = logging.getLogger(__name__)


class MethodResponseHandler(ApiGatewayHandler):
    """
    This class might not too much, we still need to investigate but from a first look, does not have much impact
    on the HTTP response
    """

    def __call__(
        self, chain: ApiGatewayHandlerChain, context: InvocationContext, response: Response
    ):
        return
