import logging

from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.utils.collections import merge_recursive
from localstack.utils.strings import to_bytes, to_str

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..gateway_response import UnsupportedMediaTypeError
from ..helpers import render_integration_uri
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

        integration_request_parameters = integration["requestParameters"] or {}
        request_data_mapping = self.get_integration_request_data(
            context, integration_request_parameters
        )
        path_parameters = request_data_mapping["path"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration mapping templates, they pass most of the data straight
            headers = context.invocation_request["headers"]
            query_string_parameters: dict[str, list[str]] = context.invocation_request[
                "multi_value_query_string_parameters"
            ]
            body = context.invocation_request["body"]

            # HTTP_PROXY still make uses of the request data mappings, and merges it with the invocation request
            # this is undocumented but validated behavior
            if integration_type == IntegrationType.HTTP_PROXY:
                headers = headers.copy()
                to_merge = {
                    k: v
                    for k, v in request_data_mapping["header"].items()
                    if k not in ("Content-Type", "Accept")
                }
                headers.update(to_merge)

                query_string_parameters = self._merge_http_proxy_query_string(
                    query_string_parameters, request_data_mapping["querystring"]
                )

            else:
                # AWS_PROXY does not allow URI path rendering
                # TODO: verify this
                path_parameters = {}

        else:
            # default values, can be overridden with right casing
            default_headers = {
                "Content-Type": APPLICATION_JSON,
                "Accept": APPLICATION_JSON,
            }
            request_data_mapping["header"] = default_headers | request_data_mapping["header"]

            # find request template to raise UnsupportedMediaTypeError early
            request_template = self.get_request_template(
                integration=integration, request=context.invocation_request
            )

            body, request_override = self.render_request_template_mapping(
                context=context, template=request_template
            )
            # TODO: log every override that happens afterwards (in a loop on `request_override`)
            merge_recursive(request_override, request_data_mapping, overwrite=True)

            headers = Headers(request_data_mapping["header"])
            query_string_parameters = request_data_mapping["querystring"]

        # looks like the stageVariables rendering part is done in the Integration part in AWS
        # but we can avoid duplication by doing it here for now
        # TODO: if the integration if of AWS Lambda type and the Lambda is in another account, we cannot render
        #  stageVariables. Work on that special case later (we can add a quick check for the URI region and set the
        #  stage variables to an empty dict)
        rendered_integration_uri = render_integration_uri(
            uri=integration["uri"],
            path_parameters=path_parameters,
            stage_variables=context.stage_variables,
        )

        # if the integration method is defined and is not ANY, we can use it for the integration
        if not (integration_method := integration["httpMethod"]) or integration_method == "ANY":
            # otherwise, fallback to the request's method
            integration_method = context.invocation_request["http_method"]

        integration_request = IntegrationRequest(
            http_method=integration_method,
            uri=rendered_integration_uri,
            query_string_parameters=query_string_parameters,
            headers=headers,
            body=body,
        )

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
            template=template,
            variables=MappingTemplateVariables(
                context=context.context_variables,
                stageVariables=context.stage_variables or {},
                input=MappingTemplateInput(
                    body=to_str(body),
                    params=MappingTemplateParams(
                        path=request.get("path_parameters"),
                        querystring=request.get("query_string_parameters", {}),
                        header=request.get("headers"),
                    ),
                ),
            ),
        )
        return to_bytes(body), request_override

    @staticmethod
    def get_request_template(integration: Integration, request: InvocationRequest) -> str:
        """
        Attempts to return the request template.
        Will raise UnsupportedMediaTypeError if there are no match according to passthrough behavior.
        """
        request_templates = integration.get("requestTemplates") or {}
        passthrough_behavior = integration.get("passthroughBehavior")
        # If content-type is not provided aws assumes application/json
        content_type = request["headers"].get("Content-Type", APPLICATION_JSON)
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

    @staticmethod
    def _merge_http_proxy_query_string(
        query_string_parameters: dict[str, list[str]],
        mapped_query_string: dict[str, str | list[str]],
    ):
        new_query_string_parameters = {k: v.copy() for k, v in query_string_parameters.items()}
        for param, value in mapped_query_string.items():
            if existing := new_query_string_parameters.get(param):
                if isinstance(value, list):
                    existing.extend(value)
                else:
                    existing.append(value)
            else:
                new_query_string_parameters[param] = value

        return new_query_string_parameters
