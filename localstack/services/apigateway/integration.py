import base64
import copy
import json
import logging
import re
from abc import ABC, abstractmethod
from enum import Enum
from urllib.parse import quote_plus, unquote_plus

import airspeed
from requests import Response

from localstack import config
from localstack.constants import APPLICATION_JSON, HEADER_CONTENT_TYPE
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.utils.aws import aws_stack
from localstack.utils.common import make_http_request, to_str
from localstack.utils.json import extract_jsonpath, json_safe
from localstack.utils.numbers import is_number, to_number
from localstack.utils.objects import recurse_object

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
        self.passthrough_behavior = self.passthrough_behavior(passthrough_behaviour)

    def request_body_passthrough(self, request_template):
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
    def passthrough_behavior(passthrough_behaviour: str):
        return getattr(PassthroughBehavior, passthrough_behaviour, None)


class BackendIntegration(ABC):
    """
    Backend integration
    """

    def __init__(self):
        self.request_templates = RequestTemplates()
        self.response_templates = ResponseTemplates()

    @abstractmethod
    def invoke(self, invocation_context: ApiInvocationContext):
        pass


class SnsIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        try:
            payload = self.request_templates.render(invocation_context)
        except Exception as e:
            LOG.warning("Failed to apply template for SNS integration", e)
            raise
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        region_name = uri.split(":")[3]
        headers = aws_stack.mock_aws_request_headers(service="sns", region_name=region_name)
        return make_http_request(
            config.service_url("sns"), method="POST", headers=headers, data=payload
        )


class MockIntegration(BackendIntegration):
    @staticmethod
    def _create_response(status_code, headers, data=""):
        response = Response()
        response.status_code = status_code
        response.headers = headers
        response._content = data
        return response

    @classmethod
    def mapping_templates(cls, passthrough_behavior: str):
        return MappingTemplates(passthrough_behavior)

    def invoke(self, invocation_context: ApiInvocationContext):
        passthrough_behavior = invocation_context.integration.get("passthroughBehavior") or ""
        request_template = invocation_context.integration.get("requestTemplates", {}).get(
            invocation_context.headers.get(HEADER_CONTENT_TYPE)
        )

        try:
            self.mapping_templates(passthrough_behavior).request_body_passthrough(request_template)
        except MappingTemplates.UnsupportedMediaType:
            response = Response()
            response.headers.update({HEADER_CONTENT_TYPE: APPLICATION_JSON})
            response.status_code = 415
            response._content = '{"message": "Unsupported Media Type"}'
            return response

        # request template
        request_payload = self.request_templates.render(invocation_context)

        # mapping is done based on "statusCode" field
        status_code = 200
        if invocation_context.headers.get(HEADER_CONTENT_TYPE) == APPLICATION_JSON:
            try:
                mock_response = json.loads(request_payload)
                status_code = mock_response.get("statusCode", status_code)
            except Exception as e:
                LOG.warning("failed to deserialize request payload after transformation: %s", e)
                return MockIntegration._create_response(
                    500,
                    headers={"Content-Type": APPLICATION_JSON},
                    data='{"message": "Internal server error"}',
                )

        # response template
        response = MockIntegration._create_response(
            status_code, invocation_context.headers, data=request_payload
        )
        response = self.response_templates.render(invocation_context, response=response)
        if isinstance(response, Response):
            return response
        if not invocation_context.headers.get(HEADER_CONTENT_TYPE):
            invocation_context.headers.update({HEADER_CONTENT_TYPE: APPLICATION_JSON})
        return MockIntegration._create_response(status_code, invocation_context.headers, response)


class VelocityUtil(object):
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

        if isinstance(s, str):
            return json.dumps(s)[1:-1]
        return json.dumps(s)


class VelocityInput(object):
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


class VtlTemplate:
    def render_vtl(self, template, variables: dict, as_json=False):
        if variables is None:
            variables = {}

        if not template:
            return template

        # fix "#set" commands
        template = re.sub(r"(^|\n)#\s+set(.*)", r"\1#set\2", template, re.MULTILINE)

        # enable syntax like "test#${foo.bar}"
        empty_placeholder = " __pLaCe-HoLdEr__ "
        template = re.sub(
            r"([^\s]+)#\$({)?(.*)",
            r"\1#%s$\2\3" % empty_placeholder,
            template,
            re.MULTILINE,
        )

        # add extensions for common string functions below

        class ExtendedString(str):
            def trim(self, *args, **kwargs):
                return ExtendedString(self.strip(*args, **kwargs))

            def toLowerCase(self, *args, **kwargs):
                return ExtendedString(self.lower(*args, **kwargs))

            def toUpperCase(self, *args, **kwargs):
                return ExtendedString(self.upper(*args, **kwargs))

        def apply(obj, **kwargs):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        obj[k] = ExtendedString(v)
            return obj

        # loop through the variables and enable certain additional util functions (e.g.,
        # string utils)
        variables = copy.deepcopy(variables or {})
        recurse_object(variables, apply)

        # prepare and render template
        context_var = variables.get("context") or {}
        input_var = variables.get("input") or {}
        stage_var = variables.get("stage_variables") or {}
        t = airspeed.Template(template)
        namespace = {
            "input": VelocityInput(input_var.get("body"), input_var.get("params")),
            "util": VelocityUtil(),
            "context": context_var,
            "stageVariables": stage_var,
        }

        # this steps prepares the namespace for object traversal,
        # e.g, foo.bar.trim().toLowerCase().replace
        dict_pack = input_var.get("body")
        if isinstance(dict_pack, dict):
            for k, v in dict_pack.items():
                namespace.update({k: v})

        rendered_template = t.merge(namespace)

        # revert temporary changes from the fixes above
        rendered_template = rendered_template.replace(empty_placeholder, "")

        if as_json:
            rendered_template = json.loads(rendered_template)
        return rendered_template


class Templates:
    __slots__ = ["vtl"]

    def __init__(self):
        self.vtl = VtlTemplate()

    def render(self, api_context: ApiInvocationContext, **kwargs):
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
                    "header": dict(api_context.headers),
                },
            },
        }


class RequestTemplates(Templates):
    """
    Handles request template rendering
    """

    def render(self, api_context: ApiInvocationContext, **kwargs):
        LOG.info(
            "Method request body before transformations: %s", to_str(api_context.data_as_string())
        )
        request_templates = api_context.integration.get("requestTemplates", {})
        request_template = request_templates.get(api_context.headers.get(HEADER_CONTENT_TYPE))

        # if not template and passthrough_behavior in {PassthroughBehavior.WHEN_NO_MATCH,
        #                                              PassthroughBehavior.WHEN_NO_TEMPLATES}:
        #     return api_context.data_as_string()

        variables = self.build_variables_mapping(api_context)
        result = self.render_vtl(request_template, variables=variables)
        LOG.info(f"Endpoint request body after transformations:\n{result}")
        return result or ""


class ResponseTemplates(Templates):
    """
    Handles response template rendering
    """

    def render(self, api_context: ApiInvocationContext, **kwargs):
        data = kwargs["response"] if "response" in kwargs else ""
        response = data or api_context.response
        integration = api_context.integration
        # we set context data with the response content because later on we use context data as
        # the body field in the template. We need to improve this by using the right source
        # depending on the type of templates.
        api_context.data = response._content
        int_responses = integration.get("integrationResponses") or {}
        if not int_responses:
            return response._content, response.status_code
        entries = list(int_responses.keys())
        return_code = str(response.status_code)
        if return_code not in entries and len(entries) > 1:
            LOG.info("Found multiple integration response status codes: %s", entries)
            return response._content, return_code

        selected_integration = int_responses.get(return_code)
        # select the default, the default integration has an "empty" selection pattern
        if not int_responses.get(return_code) and entries:
            for status_code_entry in int_responses.keys():
                integration_response = int_responses[status_code_entry]
                if "selectionPattern" not in integration_response:
                    selected_integration = integration_response
                    response.status_code = status_code_entry
                    break

        response_templates = selected_integration.get("responseTemplates", {})
        template = response_templates.get(APPLICATION_JSON, {})
        if not template:
            return response

        variables = self.build_variables_mapping(api_context)
        response._content = self.render_vtl(template, variables=variables)
        response.headers.update({HEADER_CONTENT_TYPE: APPLICATION_JSON})
        LOG.info("Endpoint response body after transformations:\n%s", response._content)
        return response
