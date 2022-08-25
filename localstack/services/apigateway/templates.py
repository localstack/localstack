import base64
import json
import logging
from enum import Enum
from typing import Any, Dict, Union
from urllib.parse import quote_plus, unquote_plus

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.utils.aws.templating import VelocityUtil, VtlTemplate
from localstack.utils.json import extract_jsonpath, json_safe
from localstack.utils.numbers import is_number, to_number
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


class PassthroughBehavior(Enum):
    WHEN_NO_MATCH = "WHEN_NO_MATCH"
    WHEN_NO_TEMPLATES = "WHEN_NO_TEMPLATES"
    NEVER = "NEVER"


class MappingTemplates:
    """
    API Gateway uses mapping templates to transform incoming requests before they are sent to the
    integration back end. With API Gateway, you can define one mapping template for each possible
    content type. The content type selection is based on the Content-Type header of the incoming
    request. If no content type is specified in the request, API Gateway uses an application/json
    mapping template. By default, mapping templates are configured to simply pass through the
    request input. Mapping templates use Apache Velocity to generate a request to your back end.
    """

    passthrough_behavior: PassthroughBehavior

    class UnsupportedMediaType(Exception):
        pass

    def __init__(self, passthrough_behaviour: str):
        self.passthrough_behavior = self.get_passthrough_behavior(passthrough_behaviour)

    def check_passthrough_behavior(self, request_template):
        """
        Specifies how the method request body of an unmapped content type will be passed through
        the integration request to the back end without transformation.
        A content type is unmapped if no mapping template is defined in the integration or the
        content type does not match any of the mapped content types, as specified in requestTemplates
        """
        if not request_template and self.passthrough_behavior in {
            PassthroughBehavior.NEVER,
            PassthroughBehavior.WHEN_NO_TEMPLATES,
        }:
            raise MappingTemplates.UnsupportedMediaType()

    @staticmethod
    def get_passthrough_behavior(passthrough_behaviour: str):
        return getattr(PassthroughBehavior, passthrough_behaviour, None)


class VelocityUtilApiGateway(VelocityUtil):
    """
    Simple class to mimic the behavior of variable '$util' in AWS API Gateway integration
    velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    """

    def base64Encode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        encoded_str = s.encode(config.DEFAULT_ENCODING)
        encoded_b64_str = base64.b64encode(encoded_str)
        return encoded_b64_str.decode(config.DEFAULT_ENCODING)

    def base64Decode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        return base64.b64decode(s)

    def toJson(self, obj):
        return obj and json.dumps(obj)

    def urlEncode(self, s):
        return quote_plus(s)

    def urlDecode(self, s):
        return unquote_plus(s)

    def escapeJavaScript(self, s):
        try:
            return json.dumps(json.loads(s))
        except Exception:
            primitive_types = (str, int, bool, float, type(None))
            s = s if isinstance(s, primitive_types) else str(s)
        if str(s).strip() in {"true", "false"}:
            s = bool(s)
        elif s not in [True, False] and is_number(s):
            s = to_number(s)
        return json.dumps(s)


class VelocityInput:
    """
    Simple class to mimic the behavior of variable '$input' in AWS API Gateway integration
    velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    """

    def __init__(self, body, params):
        self.parameters = params or {}
        self.value = body

    def path(self, path):
        if not self.value:
            return {}
        value = self.value if isinstance(self.value, dict) else json.loads(self.value)
        return extract_jsonpath(value, path)

    def json(self, path):
        path = path or "$"
        matching = self.path(path)
        if isinstance(matching, (list, dict)):
            matching = json_safe(matching)
        return json.dumps(matching)

    @property
    def body(self):
        return self.value

    def params(self, name=None):
        if not name:
            return self.parameters
        for k in ["path", "querystring", "header"]:
            if val := self.parameters.get(k).get(name):
                return val
        return ""

    def __getattr__(self, name):
        return self.value.get(name)

    def __repr__(self):
        return "$input"


class ApiGatewayVtlTemplate(VtlTemplate):
    """Util class for rendering VTL templates with API Gateway specific extensions"""

    def prepare_namespace(self, variables) -> Dict[str, Any]:
        namespace = super().prepare_namespace(variables)
        if stage_var := variables.get("stage_variables") or {}:
            namespace["stageVariables"] = stage_var
        input_var = variables.get("input") or {}
        variables = {
            "input": VelocityInput(input_var.get("body"), input_var.get("params")),
            "util": VelocityUtilApiGateway(),
        }
        namespace.update(variables)
        return namespace


class Templates:
    __slots__ = ["vtl"]

    def __init__(self):
        self.vtl = ApiGatewayVtlTemplate()

    def render(self, api_context: ApiInvocationContext) -> Union[bytes, str]:
        pass

    def render_vtl(self, template, variables):
        return self.vtl.render_vtl(template, variables=variables)

    @staticmethod
    def build_variables_mapping(api_context: ApiInvocationContext):
        # TODO: make this (dict) an object so usages of "render_vtl" variables are defined
        return {
            "context": api_context.context or {},
            "stage_variables": api_context.stage_variables or {},
            "input": {
                "body": api_context.data_as_string(),
                "params": {
                    "path": api_context.path_params,
                    "querystring": api_context.query_params(),
                    "header": api_context.headers,
                },
            },
        }


class RequestTemplates(Templates):
    """
    Handles request template rendering
    """

    def render(self, api_context: ApiInvocationContext) -> Union[bytes, str]:
        LOG.info(
            "Method request body before transformations: %s", to_str(api_context.data_as_string())
        )
        request_templates = api_context.integration.get("requestTemplates", {})
        template = request_templates.get(APPLICATION_JSON, {})
        if not template:
            return api_context.data_as_string()

        variables = self.build_variables_mapping(api_context)
        result = self.render_vtl(template, variables=variables)
        LOG.info(f"Endpoint request body after transformations:\n{result}")
        return result


class ResponseTemplates(Templates):
    """
    Handles response template rendering
    """

    def render(self, api_context: ApiInvocationContext, **kwargs) -> Union[bytes, str]:
        # XXX: keep backwards compatibility until we migrate all integrations to this new classes
        # api_context contains a response object that we want slowly remove from it
        data = kwargs["response"] if "response" in kwargs else ""
        response = data or api_context.response
        integration = api_context.integration
        # we set context data with the response content because later on we use context data as
        # the body field in the template. We need to improve this by using the right source
        # depending on the type of templates.
        api_context.data = response._content

        integration_responses = integration.get("integrationResponses") or {}
        if not integration_responses:
            return response._content
        entries = list(integration_responses.keys())
        return_code = str(response.status_code)
        if return_code not in entries and len(entries) > 1:
            LOG.info("Found multiple integration response status codes: %s", entries)
            return response._content
        return_code = entries[0]

        response_templates = integration_responses[return_code].get("responseTemplates", {})
        template = response_templates.get(APPLICATION_JSON, {})
        if not template:
            return response._content

        variables = self.build_variables_mapping(api_context)
        response._content = self.render_vtl(template, variables=variables)
        LOG.info("Endpoint response body after transformations:\n%s", response._content)
        return response._content
