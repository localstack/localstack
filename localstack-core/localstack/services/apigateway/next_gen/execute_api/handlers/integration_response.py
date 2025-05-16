import base64
import json
import logging
import re

from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import (
    ContentHandlingStrategy,
    Integration,
    IntegrationResponse,
    IntegrationType,
)
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.utils.strings import to_bytes

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import (
    EndpointResponse,
    InvocationRequest,
    InvocationResponse,
    RestApiInvocationContext,
)
from ..gateway_response import ApiConfigurationError, InternalServerError
from ..helpers import mime_type_matches_binary_media_types
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
        integration: Integration = context.integration
        integration_type = integration["type"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration response mapping templates
            # TODO: verify assumptions against AWS
            return

        endpoint_response: EndpointResponse = context.endpoint_response
        status_code = endpoint_response["status_code"]
        body = endpoint_response["body"]

        # we first need to find the right IntegrationResponse based on their selection template, linked to the status
        # code of the Response
        if integration_type == IntegrationType.AWS and "lambda:path/" in integration["uri"]:
            selection_value = self.parse_error_message_from_lambda(body)
        else:
            selection_value = str(status_code)

        integration_response: IntegrationResponse = self.select_integration_response(
            selection_value,
            integration["integrationResponses"],
        )

        # we then need to apply Integration Response parameters mapping, to only return select headers
        response_parameters = integration_response.get("responseParameters") or {}
        response_data_mapping = self.get_method_response_data(
            context=context,
            response=endpoint_response,
            response_parameters=response_parameters,
        )

        # We then fetch a response templates and apply the template mapping
        response_template = self.get_response_template(
            integration_response=integration_response, request=context.invocation_request
        )
        # binary support
        converted_body = self.convert_body(
            context,
            body=body,
            content_handling=integration_response.get("contentHandling"),
        )

        body, response_override = self.render_response_template_mapping(
            context=context, template=response_template, body=converted_body
        )

        # We basically need to remove all headers and replace them with the mapping, then
        # override them if there are overrides.
        # The status code is pretty straight forward. By default, it would be set by the integration response,
        # unless there was an override
        response_status_code = int(integration_response["statusCode"])
        if response_status_override := response_override["status"]:
            # maybe make a better error message format, same for the overrides for request too
            LOG.debug("Overriding response status code: '%s'", response_status_override)
            response_status_code = response_status_override

        # Create a new headers object that we can manipulate before overriding the original response headers
        response_headers = Headers(response_data_mapping.get("header"))
        if header_override := response_override["header"]:
            LOG.debug("Response header overrides: %s", header_override)
            response_headers.update(header_override)

        LOG.debug("Method response body after transformations: %s", body)
        context.invocation_response = InvocationResponse(
            body=body,
            headers=response_headers,
            status_code=response_status_code,
        )

    def get_method_response_data(
        self,
        context: RestApiInvocationContext,
        response: EndpointResponse,
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
        if not integration_responses:
            LOG.warning(
                "Configuration error: No match for output mapping and no default output mapping configured. "
                "Endpoint Response Status Code: %s",
                selection_value,
            )
            raise ApiConfigurationError("Internal server error")

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

        # The invocation request header is used to find the right response templated
        accepts = request["headers"].getlist("accept")
        if accepts and (template := response_templates.get(accepts[-1])):
            return template
        # TODO aws seemed to favor application/json as default when unmatched regardless of "first"
        if template := response_templates.get(APPLICATION_JSON):
            return template
        # TODO What is first? do we need to keep an order as to when they were added/modified?
        template = next(iter(response_templates.values()))
        LOG.warning("No templates were matched, Using template: %s", template)
        return template

    @staticmethod
    def convert_body(
        context: RestApiInvocationContext,
        body: bytes,
        content_handling: ContentHandlingStrategy | None,
    ) -> bytes | str:
        """
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings.html
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings-workflow.html
        :param context: RestApiInvocationContext
        :param body: the endpoint response body
        :param content_handling: the contentHandling of the IntegrationResponse
        :return: the body, either as is, or converted depending on the table in the second link
        """

        request: InvocationRequest = context.invocation_request
        response: EndpointResponse = context.endpoint_response
        binary_media_types = context.deployment.rest_api.rest_api.get("binaryMediaTypes", [])

        is_binary_payload = mime_type_matches_binary_media_types(
            mime_type=response["headers"].get("Content-Type"),
            binary_media_types=binary_media_types,
        )
        is_binary_accept = mime_type_matches_binary_media_types(
            mime_type=request["headers"].get("Accept"),
            binary_media_types=binary_media_types,
        )

        if is_binary_payload:
            if (
                content_handling and content_handling == ContentHandlingStrategy.CONVERT_TO_TEXT
            ) or (not content_handling and not is_binary_accept):
                body = base64.b64encode(body)
        else:
            # this means the Payload is of type `Text` in AWS terms for the table
            if (
                content_handling and content_handling == ContentHandlingStrategy.CONVERT_TO_TEXT
            ) or (not content_handling and not is_binary_accept):
                body = body.decode(encoding="UTF-8", errors="replace")
            else:
                try:
                    body = base64.b64decode(body)
                except ValueError:
                    raise InternalServerError("Internal server error")

        return body

    def render_response_template_mapping(
        self, context: RestApiInvocationContext, template: str, body: bytes | str
    ) -> tuple[bytes, ContextVarsResponseOverride]:
        if not template:
            return to_bytes(body), context.context_variable_overrides["responseOverride"]

        # if there are no template, we can pass binary data through
        if not isinstance(body, str):
            # TODO: check, this might be ApiConfigurationError
            raise InternalServerError("Internal server error")

        body, response_override = self._vtl_template.render_response(
            template=template,
            variables=MappingTemplateVariables(
                context=context.context_variables,
                stageVariables=context.stage_variables or {},
                input=MappingTemplateInput(
                    body=body,
                    params=MappingTemplateParams(
                        path=context.invocation_request.get("path_parameters"),
                        querystring=context.invocation_request.get("query_string_parameters", {}),
                        header=context.invocation_request.get("headers", {}),
                    ),
                ),
            ),
            context_overrides=context.context_variable_overrides,
        )

        # AWS ignores the status if the override isn't an integer between 100 and 599
        if (status := response_override["status"]) and not (
            isinstance(status, int) and 100 <= status < 600
        ):
            response_override["status"] = 0
        return to_bytes(body), response_override

    @staticmethod
    def parse_error_message_from_lambda(payload: bytes) -> str:
        try:
            lambda_response = json.loads(payload)
            if not isinstance(lambda_response, dict):
                return ""

            # very weird case, but AWS will not return the Error from Lambda in AWS integration, where it does for
            # Kinesis and such. The AWS Lambda only behavior is concentrated in this method
            if lambda_response.get("__type") == "AccessDeniedException":
                raise InternalServerError("Internal server error")

            return lambda_response.get("errorMessage", "")

        except json.JSONDecodeError:
            return ""
