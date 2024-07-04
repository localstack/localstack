import logging

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Response
from localstack.utils.collections import merge_recursive
from localstack.utils.strings import to_bytes, to_str

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..gateway_response import UnsupportedMediaTypeError
from ..parameters_mapping import ParametersMapper, RequestDataMapping
from ..template_mapping import (
    ApiGatewayVtlTemplate,
    MappingTemplateInput,
    MappingTemplateParams,
    MappingTemplateVariables,
)
from ..variables import ContextVarsRequestOverride

LOG = logging.getLogger(__name__)


class PassthroughBehavior(str):
    # TODO maybe this class should be moved where it can also be used for validation in
    #  the provider when we switch out of moto
    WHEN_NO_MATCH = "WHEN_NO_MATCH"
    WHEN_NO_TEMPLATES = "WHEN_NO_TEMPLATES"
    NEVER = "NEVER"


class IntegrationRequestHandler(RestApiGatewayHandler):
    """
    This class will take care of the Integration Request part, which is mostly linked to template mapping
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-request.html
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
        integration: Integration = context.resource_method["methodIntegration"]
        integration_type = integration["type"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration mapping templates
            # TODO: check if PROXY can still parameters mapping and substitution in URI for example? normally not
            # See
            return

        # find request template to raise UnsupportedMediaTypeError early
        request_template = self.get_request_template(
            integration=integration, request=context.invocation_request
        )

        integration_request_parameters = integration["requestParameters"] or {}
        request_data_mapping = self.get_integration_request_data(
            context, integration_request_parameters
        )

        body, request_override = self.render_request_template_mapping(
            context=context, template=request_template
        )
        merge_recursive(request_override, request_data_mapping, overwrite=True)

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
            body=body,
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

    def render_request_template_mapping(
        self,
        context: RestApiInvocationContext,
        template: str,
    ) -> tuple[bytes, ContextVarsRequestOverride]:
        request: InvocationRequest = context.invocation_request
        body = request["body"]

        if not template:
            return body, {}

        body, request_override = self._vtl_template.render_request(
            template=template.strip(),
            variables=MappingTemplateVariables(
                context=context.context_variables,
                stageVariables=context.stage_variables or {},
                input=MappingTemplateInput(
                    body=to_str(body),
                    params=MappingTemplateParams(
                        path=request.get("path_parameters"),
                        querystring=request.get("query_string_parameters", {}),
                        header=request.get("headers", {}),
                    ),
                ),
            ),
        )
        return to_bytes(body), request_override

    def get_request_template(self, integration: Integration, request: InvocationRequest) -> str:
        """
        Attempts to return the request template.
        Will raise UnsupportedMediaTypeError if there are no match according to passthrough behavior.
        """
        request_templates = integration.get("requestTemplates", {})
        passthrough_behavior = integration.get("passthroughBehavior")
        # If content-type is not provided aws assumes application/json
        content_type = request["raw_headers"].get("Content-Type", "application/json")
        # first look to for a template associated to the content-type, otherwise look for the $default template
        request_template = request_templates.get(content_type) or request_templates.get("$default")

        if request_template or passthrough_behavior == PassthroughBehavior.WHEN_NO_MATCH:
            return request_template

        match passthrough_behavior:
            case PassthroughBehavior.NEVER:
                LOG.debug(
                    "No request template found for '%s' and passthrough behavior set to NEVER",
                    content_type,
                )
                raise UnsupportedMediaTypeError("Unsupported Media Type")
            case PassthroughBehavior.WHEN_NO_TEMPLATES:
                if request_templates:
                    LOG.debug(
                        "No request template found for '%s' and passthrough behavior set to WHEN_NO_TEMPLATES",
                        content_type,
                    )
                    raise UnsupportedMediaTypeError("Unsupported Media Type")
            case _:
                LOG.debug("Unknown passthrough behavior: '%s'", passthrough_behavior)

        return request_template
