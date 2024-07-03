import logging

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import IntegrationRequest, RestApiInvocationContext
from ..parameters_mapping import ParametersMapper, RequestDataMapping

LOG = logging.getLogger(__name__)


class IntegrationRequestHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Request part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-request.html
    """

    def __init__(self):
        self._param_mapper = ParametersMapper()

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
            # TODO: check if PROXY can still parameters mapping and substitution in URI for example? normally not
            # See
            return

        # TODO: maybe first do the `passthroughBehavior` and determine if there's a mapping template?

        # TODO: this handler might not be tested yet until `TemplateMappings` are implemented, as overall behavior will
        #  change
        integration_request_parameters = integration["requestParameters"] or {}
        request_data_mapping = self.get_integration_request_data(
            context, integration_request_parameters
        )

        # TODO: work on TemplateMappings with VTL to render the body of the request
        #  it might populate the context requestOverride too, maybe deepcopy the ContextVariables because it will
        #  get mutated, or pop it directly? might just be better!

        # TODO: extract the code under into its own method

        # TODO: create helper method to render the different URI with stageVariables and parameters
        rendered_integration_uri = integration["uri"]  # use request_data_mapping["path"]

        # TODO: verify the assumptions about the method with an AWS validated test
        # if the integration method is defined and is not ANY, we can use it for the integration
        if not (integration_method := integration["httpMethod"]) or integration_method == "ANY":
            # otherwise, fallback to the request's method
            integration_method = context.invocation_request["method"]

        integration_request = IntegrationRequest(
            http_method=integration_method,
            uri=rendered_integration_uri,
            query_string_parameters=request_data_mapping["querystring"],
            headers=request_data_mapping["header"],
            body=b"",  # TODO: from MappingTemplates or passthrough
        )
        # TODO: log every override that happens afterwards

        # This is the data that downstream integrations might use if they are not of `PROXY_` type
        # LOG.debug("Created integration request from xxx")
        context.integration_request = integration_request

    def get_integration_request_data(
        self, context: RestApiInvocationContext, request_parameters: dict[str, str]
    ) -> RequestDataMapping:
        return self._param_mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=context.invocation_request,
            context_variables=context.context_variables,
            stage_variables=context.stage_variables,
        )
