import logging

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class IntegrationRequestHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Request part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-request.html
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        integration: Integration = context.resource_method["methodIntegration"]
        integration_type = integration["type"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration mapping templates
            # TODO: check if PROXY can still parameters mapping and substitution in URI for example?
            # See
            return

        if integration_type == IntegrationType.MOCK:
            # TODO: only apply partial rendering of the VTL context
            return

        # TODO: apply rendering, and attach the Integration Request needed for the Integration to construct its HTTP
        #  request to send

        return
