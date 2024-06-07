import logging

from localstack.http import Response

from ..api import ApiGatewayHandler, ApiGatewayHandlerChain
from ..context import InvocationContext

LOG = logging.getLogger(__name__)


# TODO: this will need to use ApiGatewayIntegration class, using Plugin for discoverability and a PluginManager,
#  in order to automatically have access to defined Integrations that we can extend
# this might be a bit closer to our AWS Skeleton in a way
class IntegrationHandler(ApiGatewayHandler):
    def __call__(
        self, chain: ApiGatewayHandlerChain, context: InvocationContext, response: Response
    ):
        return
