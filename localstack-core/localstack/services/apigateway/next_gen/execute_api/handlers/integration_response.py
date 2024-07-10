import logging
import re

from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, IntegrationResponse, IntegrationType
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.utils.strings import to_bytes, to_str

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext
from ..gateway_response import ApiConfigurationError
from ..parameters_mapping import ParametersMapper, ResponseDataMapping
from ..template_mapping import (
    ApiGatewayVtlTemplate,
    MappingTemplateInput,
    MappingTemplateParams,
    MappingTemplateVariables,
)
from ..variables import ContextVarsResponseOverride

LOG = logging.getLogger(__name__)


class IntegrationResponseHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Response part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-response.html
    """

    def __init__(self):
        self._param_mapper = ParametersMapper()
        self._vtl_template = ApiGatewayVtlTemplate()

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
        response_parameters = integration_response.get("responseParameters") or {}
        response_data_mapping = self.get_method_response_data(
            context=context,
            response=response,
            response_parameters=response_parameters,
        )

        # We then fetch a response templates and apply the template mapping
        response_template = self.get_response_template(
            integration_response=integration_response, request=context.invocation_request
        )
        body, response_override = self.render_request_template_mapping(
            context=context, template=response_template, response=response
        )

        # here we update the `Response`. We basically need to remove all headers and replace them with the mapping, then
        # override them if there are overrides.
        # The status code is pretty straight forward. By default, it would be set by the integration response,
        # unless there was an override
        response.status_code = int(integration_response["statusCode"])
        if response_status_override := response_override["status"]:
            # maybe make a better error message format, same for the overrides for request too
            LOG.debug("Overriding response status code: '%s'", response_status_override)
            response.status_code = response_status_override

        # Create a new headers object that we can manipulate before overriding the original response headers
        headers = Headers(response_data_mapping.get("header"))
        if header_override := response_override["header"]:
            LOG.debug("Response header overrides: %s", header_override)
            headers.update(header_override)

        # When trying to override certain headers, they will instead be remapped
        # There may be other headers, but these have been confirmed on aws
        remapped_headers = (
            "connection",
            "content-length",
            "date",
            "x-amzn-requestid",
            "content-type",
        )
        for header in remapped_headers:
            if value := headers.get(header):
                headers[f"x-amzn-remapped-{header}"] = value
                headers.remove(header)

        # Those headers are passed through from the response headers, there might be more?
        passthrough_headers = ("connection", "content-type", "content-length")
        for header in passthrough_headers:
            if values := response.headers.getlist(header):
                headers.setlist(header, values)

        # We replace the old response with the newly created one
        response.headers = headers

        # Body is updated last to make sure the content-length is reset if needed
        if response_template:
            LOG.debug("Method response body after transformations: %s", body)
            response.data = body

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

    @staticmethod
    def get_response_template(
        integration_response: IntegrationResponse, request: InvocationRequest
    ) -> str:
        """The Response Template is selected from the response templates.
        If there are no templates defined, the body will pass through.
        Apigateway looks at the integration request `Accept` header and defaults to `application/json`.
        If no template is matched, Apigateway will use the "first" existing template and use it as default.
        https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html#transforming-request-response-body
        """
        if not (response_templates := integration_response["responseTemplates"]):
            return ""

        # Aws seems to ignore the integration request headers and uses the invocation request header
        accept = request["headers"].get("accept", APPLICATION_JSON)
        if template := response_templates.get(accept):
            return template
        # TODO aws seemed to favor application/json as default when unmatched regardless of "first"
        if template := response_templates.get(APPLICATION_JSON):
            return template
        # TODO What is first? do we need to keep an order as to when they were added/modified?
        template = next(iter(response_templates.values()))
        LOG.warning("No templates were matched, Using template: %s", template)
        return template

    def render_request_template_mapping(
        self, context: RestApiInvocationContext, template: str, response: Response
    ) -> tuple[bytes, ContextVarsResponseOverride]:
        body = response.data

        if not template:
            return body, ContextVarsResponseOverride(status=0, header={})

        body, response_override = self._vtl_template.render_response(
            template=template,
            variables=MappingTemplateVariables(
                context=context.context_variables,
                stageVariables=context.stage_variables or {},
                input=MappingTemplateInput(
                    body=to_str(body),
                    params=MappingTemplateParams(
                        path=context.invocation_request.get("path_parameters"),
                        querystring=context.invocation_request.get("query_string_parameters", {}),
                        header=context.invocation_request.get("headers", {}),
                    ),
                ),
            ),
        )

        # AWS ignores the status if the override isn't an integer between 100 and 599
        if (status := response_override["status"]) and not (
            isinstance(status, int) and 100 <= status < 600
        ):
            response_override["status"] = 0
        return to_bytes(body), response_override
