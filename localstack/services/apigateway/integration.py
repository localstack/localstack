import base64
import json
import logging
import re
from urllib.parse import quote_plus, unquote_plus

import airspeed

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.utils.aws import aws_stack
from localstack.utils.aws.templating import DictWrapper
from localstack.utils.common import make_http_request, to_str
from localstack.utils.json import extract_jsonpath, json_safe
from localstack.utils.numbers import is_number, to_number
from localstack.utils.objects import recurse_object

LOG = logging.getLogger(__name__)


class BackendIntegration:
    """
    Backend integration
    """


class SnsIntegration(BackendIntegration):
    @classmethod
    def invoke(cls, invocation_context: ApiInvocationContext):
        try:
            request_templates = RequestTemplates()
            payload = request_templates.render(invocation_context)
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


class VtlTemplate:
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
            if str(s).strip() in ["true", "false"]:
                s = bool(s)
            elif s not in [True, False] and is_number(s):
                s = to_number(s)
            return json.dumps(s)

    class VelocityInput(object):
        """
        Simple class to mimic the behavior of variable '$input' in AWS API Gateway integration
        velocity templates.
        See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
        """

        def __init__(self, body, params):
            self.parameters = self._attach_missing_functions(params or {})
            self.value = self._attach_missing_functions(body)

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

        @staticmethod
        def _attach_missing_functions(value):
            if value:

                def _fix(obj, **kwargs):
                    return DictWrapper(obj) if isinstance(obj, dict) else obj

                value = recurse_object(value, _fix)
            return value

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
                    if isinstance(v, dict):
                        obj[k] = DictWrapper(v)
                return DictWrapper(obj)
            return obj

        # loop through the variables and enable certain additional util functions (e.g.,
        # string utils)
        variables = variables or {}
        recurse_object(variables, apply)

        # prepare and render template
        context_var = variables.get("context") or {}
        input_var = variables.get("input") or {}
        stage_var = variables.get("stage_variables") or {}
        t = airspeed.Template(template)
        namespace = {
            "input": self.VelocityInput(input_var.get("body"), input_var.get("params")),
            "util": self.VelocityUtil(),
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

    def render(self, api_context: ApiInvocationContext):
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

    def render(self, api_context: ApiInvocationContext):
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

    def render(self, api_context: ApiInvocationContext):
        response = api_context.response
        integration = api_context.integration
        # we set context data with the response content because later on we use context data as
        # the body field in the template. We need to improve this by using the right source
        # depending on the type of templates.
        api_context.data = response._content
        int_responses = integration.get("integrationResponses") or {}
        if not int_responses:
            return response._content
        entries = list(int_responses.keys())
        return_code = str(response.status_code)
        if return_code not in entries and len(entries) > 1:
            LOG.info("Found multiple integration response status codes: %s", entries)
            return response._content
        return_code = entries[0]

        response_templates = int_responses[return_code].get("responseTemplates", {})
        template = response_templates.get(APPLICATION_JSON, {})
        if not template:
            return response

        variables = self.build_variables_mapping(api_context)
        response._content = self.render_vtl(template, variables=variables)
        LOG.info("Endpoint response body after transformations:\n%s", response._content)
        return response._content
