import logging
from http import HTTPMethod

from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.constants import APPLICATION_JSON
from localstack.http import Request, Response
from localstack.utils.collections import merge_recursive
from localstack.utils.strings import to_bytes, to_str

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..gateway_response import InternalServerError, UnsupportedMediaTypeError
from ..header_utils import drop_headers, set_default_headers
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

# Illegal headers to include in transformation
ILLEGAL_INTEGRATION_REQUESTS_COMMON = [
    "content-length",
    "transfer-encoding",
    "x-amzn-trace-id",
    "X-Amzn-Apigateway-Api-Id",
]
ILLEGAL_INTEGRATION_REQUESTS_AWS = [
    *ILLEGAL_INTEGRATION_REQUESTS_COMMON,
    "authorization",
    "connection",
    "expect",
    "proxy-authenticate",
    "te",
]

# These are dropped after the templates override were applied. they will never make it to the requests.
DROPPED_FROM_INTEGRATION_REQUESTS_COMMON = ["Expect", "Proxy-Authenticate", "TE"]
DROPPED_FROM_INTEGRATION_REQUESTS_AWS = [*DROPPED_FROM_INTEGRATION_REQUESTS_COMMON, "Referer"]
DROPPED_FROM_INTEGRATION_REQUESTS_HTTP = [*DROPPED_FROM_INTEGRATION_REQUESTS_COMMON, "Via"]

# Default headers
DEFAULT_REQUEST_HEADERS = {"Accept": APPLICATION_JSON, "Connection": "keep-alive"}


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
        integration: Integration = context.integration
        integration_type = integration["type"]

        integration_request_parameters = integration["requestParameters"] or {}
        request_data_mapping = self.get_integration_request_data(
            context, integration_request_parameters
        )
        path_parameters = request_data_mapping["path"]

        if integration_type in (IntegrationType.AWS_PROXY, IntegrationType.HTTP_PROXY):
            # `PROXY` types cannot use integration mapping templates, they pass most of the data straight
            # We make a copy to avoid modifying the invocation headers and keep a cleaner history
            headers = context.invocation_request["headers"].copy()
            query_string_parameters: dict[str, list[str]] = context.invocation_request[
                "multi_value_query_string_parameters"
            ]
            body = context.invocation_request["body"]

            # HTTP_PROXY still make uses of the request data mappings, and merges it with the invocation request
            # this is undocumented but validated behavior
            if integration_type == IntegrationType.HTTP_PROXY:
                # These headers won't be passed through by default from the invocation.
                # They can however be added through request mappings.
                drop_headers(headers, ["Host", "Content-Encoding"])
                headers.update(request_data_mapping["header"])

                query_string_parameters = self._merge_http_proxy_query_string(
                    query_string_parameters, request_data_mapping["querystring"]
                )

            else:
                self._set_proxy_headers(headers, context.request)
                # AWS_PROXY does not allow URI path rendering
                # TODO: verify this
                path_parameters = {}

        else:
            # find request template to raise UnsupportedMediaTypeError early
            request_template = self.get_request_template(
                integration=integration, request=context.invocation_request
            )

            body, request_override = self.render_request_template_mapping(
                context=context, template=request_template
            )
            # mutate the ContextVariables with the requestOverride result, as we copy the context when rendering the
            # template to avoid mutation on other fields
            # the VTL responseTemplate can access the requestOverride
            context.context_variables["requestOverride"] = request_override
            # TODO: log every override that happens afterwards (in a loop on `request_override`)
            merge_recursive(request_override, request_data_mapping, overwrite=True)

            headers = Headers(request_data_mapping["header"])
            query_string_parameters = request_data_mapping["querystring"]

        # Some headers can't be modified by parameter mappings or mapping templates.
        # Aws will raise in those were present. Even for AWS_PROXY, where it is not applying them.
        if header_mappings := request_data_mapping["header"]:
            self._validate_headers_mapping(header_mappings, integration_type)

        self._apply_header_transforms(headers, integration_type, context)

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

    @staticmethod
    def _set_proxy_headers(headers: Headers, request: Request):
        headers.set("X-Forwarded-For", request.remote_addr)
        headers.set("X-Forwarded-Port", request.environ.get("SERVER_PORT"))
        headers.set(
            "X-Forwarded-Proto",
            request.environ.get("SERVER_PROTOCOL", "").split("/")[0],
        )

    @staticmethod
    def _apply_header_transforms(
        headers: Headers, integration_type: IntegrationType, context: RestApiInvocationContext
    ):
        # Dropping matching headers for the provided integration type
        match integration_type:
            case IntegrationType.AWS:
                drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_AWS)
            case IntegrationType.HTTP | IntegrationType.HTTP_PROXY:
                drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_HTTP)
            case _:
                drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_COMMON)

        # Adding default headers to the requests headers
        default_headers = {
            **DEFAULT_REQUEST_HEADERS,
            "User-Agent": f"AmazonAPIGateway_{context.api_id}",
        }
        if (
            content_type := context.request.headers.get("Content-Type")
        ) and context.request.method not in {HTTPMethod.OPTIONS, HTTPMethod.GET, HTTPMethod.HEAD}:
            default_headers["Content-Type"] = content_type

        set_default_headers(headers, default_headers)
        headers.set("X-Amzn-Trace-Id", context.trace_id)
        if integration_type not in (IntegrationType.AWS_PROXY, IntegrationType.AWS):
            headers.set("X-Amzn-Apigateway-Api-Id", context.api_id)

    @staticmethod
    def _validate_headers_mapping(headers: dict[str, str], integration_type: IntegrationType):
        """Validates and raises an error when attempting to set an illegal header"""
        to_validate = ILLEGAL_INTEGRATION_REQUESTS_COMMON
        if integration_type in {IntegrationType.AWS, IntegrationType.AWS_PROXY}:
            to_validate = ILLEGAL_INTEGRATION_REQUESTS_AWS

        for header in headers:
            if header.lower() in to_validate:
                LOG.debug(
                    "Execution failed due to configuration error: %s header already present", header
                )
                raise InternalServerError("Internal server error")
