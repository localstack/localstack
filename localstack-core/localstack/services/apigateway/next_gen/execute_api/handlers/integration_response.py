import logging
import re

from localstack.aws.api.apigateway import Integration, IntegrationResponse, IntegrationType
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..gateway_response import ApiConfigurationError
from ..parameters_mapping import ParametersMapper, ResponseDataMapping

LOG = logging.getLogger(__name__)


class IntegrationResponseHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Response part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-response.html
    """

    def __init__(self):
        self._param_mapper = ParametersMapper()

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

        # we first need to find the right IntegrationResponse based on their selection template, linked to the status
        # code of the Response
        # TODO: create util to get the AWS integration type from the URI
        #  maybe we could cache the result in the context? in an IntegrationDetails field?
        is_lambda = False
        if integration_type == IntegrationType.AWS and is_lambda:
            # TODO: fetch errorMessage
            selection_value = ""
        else:
            selection_value = str(response.status_code)

        integration_response: IntegrationResponse = self.select_integration_response(
            selection_value,
            integration["integrationResponses"],
        )

        # we then need to apply Integration Response parameters mapping, to only return select headers
        response_parameters = integration_response["responseParameters"] or {}
        response_data_mapping = self.get_method_response_data(
            context=context,
            response=response,
            response_parameters=response_parameters,
        )

        # we can also apply the Response Templates, they will depend on status code + accept header?

        # then responseOverride

        # here we update the `Response`. We basically need to remove all headers and replace them with the mapping, then
        # override them if there are overrides.
        # for the body, it will maybe depend on configuration?

        response.headers.clear()
        # there must be some default headers set, snapshot those?
        if mapped_headers := response_data_mapping.get("header"):
            response.headers.update(mapped_headers)

    def get_method_response_data(
        self,
        context: RestApiInvocationContext,
        response: Response,
        response_parameters: dict[str, str],
    ) -> ResponseDataMapping:
        return self._param_mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=response,
            context_variables=context.context_variables,
            stage_variables=context.stage_variables,
        )

    @staticmethod
    def select_integration_response(
        selection_value: str, integration_responses: dict[str, IntegrationResponse]
    ) -> IntegrationResponse:
        if select_by_pattern := [
            response
            for response in integration_responses.values()
            if (selectionPatten := response.get("selectionPattern"))
            and re.match(selectionPatten, selection_value)
        ]:
            selected_response = select_by_pattern[0]
            if len(select_by_pattern) > 1:
                LOG.warning(
                    "Multiple integration responses matching '%s' statuscode. Choosing '%s' (first).",
                    selection_value,
                    selected_response["statusCode"],
                )
        else:
            # choose default return code
            # TODO: the provider should check this, as we should only have one default with no value in selectionPattern
            default_responses = [
                response
                for response in integration_responses.values()
                if not response.get("selectionPattern")
            ]
            if not default_responses:
                # TODO: verify log message when the selection_value is a lambda errorMessage
                LOG.warning(
                    "Configuration error: No match for output mapping and no default output mapping configured. "
                    "Endpoint Response Status Code: %s",
                    selection_value,
                )
                raise ApiConfigurationError("Internal server error")

            selected_response = default_responses[0]
            if len(default_responses) > 1:
                LOG.warning(
                    "Multiple default integration responses. Choosing %s (first).",
                    selected_response["statusCode"],
                )
        return selected_response
