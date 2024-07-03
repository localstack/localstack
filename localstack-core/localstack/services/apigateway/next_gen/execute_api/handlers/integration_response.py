import logging

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class IntegrationResponseHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Response part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-response.html
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        # TODO: we should log the response coming in from the Integration, either in Integration or here.
        #  before modification / after?
        integration: Integration = context.resource_method["methodIntegration"]
        integration_type = integration["type"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration response mapping templates
            # TODO: verify assumptions against AWS
            return

        # we then need to apply Integration Response parameters mapping, to only return select headers

        # we can also apply the Response Templates, they will depend on status code + accept header?

        # then responseOverride

        # here we update the `Response`. We basically need to remove all headers and replace them with the mapping, then
        # override them if there are overrides.
        # for the body, it will maybe depend on configuration?
