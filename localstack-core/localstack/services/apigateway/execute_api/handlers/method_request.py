import logging

from localstack.http import Response

from ..api import ApiGatewayHandler, ApiGatewayHandlerChain
from ..context import InvocationContext

LOG = logging.getLogger(__name__)


class MethodRequestHandler(ApiGatewayHandler):
    """
    This class will mostly take care of Request validation with Models
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html
    """

    def __call__(
        self, chain: ApiGatewayHandlerChain, context: InvocationContext, response: Response
    ):
        return
