import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class MethodRequestHandler(RestApiGatewayHandler):
    """
    This class will mostly take care of Request validation with Models
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        return
