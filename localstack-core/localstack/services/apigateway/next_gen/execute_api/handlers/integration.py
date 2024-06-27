import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..integrations import RestApiPluginManager

LOG = logging.getLogger(__name__)


# TODO: this will need to use ApiGatewayIntegration class, using Plugin for discoverability and a PluginManager,
#  in order to automatically have access to defined Integrations that we can extend
class IntegrationHandler(RestApiGatewayHandler):
    def __init__(self):
        self._plugin_manager: RestApiPluginManager = RestApiPluginManager.get()

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        integration_type = context.resource_method["methodIntegration"]["type"].lower()

        integration_plugin = self._plugin_manager.get_plugin(
            integration_type=integration_type.lower()
        )
        if not integration_plugin:
            # TODO: raise proper exception?
            raise NotImplementedError(
                f"This integration type is not yet supported: {integration_type}"
            )

        integration_response = integration_plugin.invoke(context)
        response.update_from(integration_response)
