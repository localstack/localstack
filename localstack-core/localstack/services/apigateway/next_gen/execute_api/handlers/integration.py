import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


# TODO: this will need to use ApiGatewayIntegration class, using Plugin for discoverability and a PluginManager,
#  in order to automatically have access to defined Integrations that we can extend
# this might be a bit closer to our AWS Skeleton in a way
class IntegrationHandler(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        return
