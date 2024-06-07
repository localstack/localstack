import logging

from localstack.http import Response

from ..api import ApiGatewayHandler, ApiGatewayHandlerChain
from ..context import InvocationContext

LOG = logging.getLogger(__name__)


class IntegrationRequestHandler(ApiGatewayHandler):
    """
    This class will take care of the Integration Request part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-request.html
    """

    def __call__(
        self, chain: ApiGatewayHandlerChain, context: InvocationContext, response: Response
    ):
        return
