import logging

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import EndpointResponse, RestApiInvocationContext
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
        integration_type = context.integration["type"]
        is_proxy = "PROXY" in integration_type

        integration = REST_API_INTEGRATIONS.get(integration_type)

        if not integration:
            # TODO: raise proper exception?
            raise NotImplementedError(
                f"This integration type is not yet supported: {integration_type}"
            )

        endpoint_response: EndpointResponse = integration.invoke(context)
        context.endpoint_response = endpoint_response
        if is_proxy:
            context.invocation_response = endpoint_response
