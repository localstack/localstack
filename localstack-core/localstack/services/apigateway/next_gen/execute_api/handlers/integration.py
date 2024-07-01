import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..integrations import REST_API_INTEGRATIONS

LOG = logging.getLogger(__name__)


# TODO: this will need to use ApiGatewayIntegration class, using Plugin for discoverability and a PluginManager,
#  in order to automatically have access to defined Integrations that we can extend
class IntegrationHandler(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        integration_type = context.resource_method["methodIntegration"]["type"]

        integration = REST_API_INTEGRATIONS.get(integration_type)

        if not integration:
            # TODO: raise proper exception?
            raise NotImplementedError(
                f"This integration type is not yet supported: {integration_type}"
            )

        integration_response = integration.invoke(context)
        response.update_from(integration_response)
