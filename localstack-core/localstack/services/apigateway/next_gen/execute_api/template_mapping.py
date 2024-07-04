# > In API Gateway, an API's method request or response can take a payload in a different format from the integration
# request or response.
#
# You can transform your data to:
# - Match the payload to an API-specified format.
# - Override an API's request and response parameters and status codes.
# - Return client selected response headers.
# - Associate path parameters, query string parameters, or header parameters in the method request of HTTP proxy
#       or AWS service proxy. TODO: this is from the documentation. Can we use requestOverides for proxy integrations?
# - Select which data to send using integration with AWS services, such as Amazon DynamoDB or Lambda functions,
#       or HTTP endpoints.
#
# You can use mapping templates to transform your data. A mapping template is a script expressed in Velocity Template
# Language (VTL) and applied to the payload using JSONPath .
#
# https://docs.aws.amazon.com/apigateway/latest/developerguide/models-mappings.html
import base64
import copy
import json
import logging
from typing import Any, TypedDict
from urllib.parse import quote_plus, unquote_plus

import xmltodict

from localstack import config
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
    ContextVarsRequestOverride,
    ContextVarsResponseOverride,
)
from localstack.utils.aws.templating import VelocityUtil, VtlTemplate
from localstack.utils.json import extract_jsonpath, json_safe

LOG = logging.getLogger(__name__)


class MappingTemplateParams(TypedDict, total=False):
    path: dict[str, str]
    querystring: dict[str, str]
    header: dict[str, str]


class MappingTemplateInput(TypedDict, total=False):
    body: str
    params: MappingTemplateParams


class MappingTemplateVariables(TypedDict, total=False):
    context: ContextVariables
    input: MappingTemplateInput
    stageVariables: dict[str, str]


class AttributeDict(dict):
    """
    Wrapper returned by VelocityUtilApiGateway.parseJson to allow access to dict values as attributes (dot notation),
    e.g.: $util.parseJson('$.foo').bar
    """

    def __init__(self, *args, **kwargs):
        super(AttributeDict, self).__init__(*args, **kwargs)
        for key, value in self.items():
            if isinstance(value, dict):
                self[key] = AttributeDict(value)

    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(f"'AttributeDict' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError(f"'AttributeDict' object has no attribute '{name}'")


class VelocityUtilApiGateway(VelocityUtil):
    """
    Simple class to mimic the behavior of variable '$util' in AWS API Gateway integration
    velocity templates.
    See: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
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

    def escapeJavaScript(self, obj: Any) -> str:
        """
        Converts the given object to a string and escapes any regular single quotes (') into escaped ones (\').
        JSON dumps will escape the single quotes.
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
        """
        if obj is None:
            return "null"
        if isinstance(obj, str):
            # empty string escapes to empty object
            if len(obj.strip()) == 0:
                return "{}"
            return json.dumps(obj)[1:-1]
        if obj in (True, False):
            return str(obj).lower()
        return str(obj)

    def parseJson(self, s: str):
        obj = json.loads(s)
        return AttributeDict(obj) if isinstance(obj, dict) else obj


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

    def prepare_namespace(self, variables) -> dict[str, Any]:
        namespace = super().prepare_namespace(variables)
        input_var = variables.get("input") or {}
        variables = {
            "input": VelocityInput(input_var.get("body"), input_var.get("params")),
            "util": VelocityUtilApiGateway(),
        }
        namespace.update(variables)
        return namespace

    def render_request(
        self, template: str, variables: MappingTemplateVariables
    ) -> tuple[str, ContextVarsRequestOverride]:
        vars: MappingTemplateVariables = copy.deepcopy(variables)
        vars["context"]["requestOverride"] = ContextVarsRequestOverride(
            querystring={}, header={}, path={}
        )
        result = self.render_vtl(template=template.strip(), variables=vars)
        return result, vars["context"]["requestOverride"]

    def render_response(
        self, template: str, variables: MappingTemplateVariables
    ) -> tuple[str, ContextVarsResponseOverride]:
        pass

    # TODO Maybe we don't need those methods and they should belong on the integration response handler?
    #  And we should raise the appropriate exception from the gateway responses.
    def _render_as_text(self, template: str, variables: dict[str, Any]) -> str:
        """
        Render the given Velocity template string + variables into a plain string.
        :return: the template rendering result as a string
        """
        rendered_tpl = self.render_vtl(template, variables=variables)
        return rendered_tpl.strip()

    @staticmethod
    def _validate_json(content: str):
        """
        Checks that the content received is a valid JSON.
        :raise JSONDecodeError: if content is not valid JSON
        """
        try:
            json.loads(content)
        except Exception as e:
            LOG.info("Unable to parse template result as JSON: %s - %s", e, content)
            raise

    @staticmethod
    def _validate_xml(content: str):
        """
        Checks that the content received is a valid XML.
        :raise xml.parsers.expat.ExpatError: if content is not valid XML
        """
        try:
            xmltodict.parse(content)
        except Exception as e:
            LOG.info("Unable to parse template result as XML: %s - %s", e, content)
            raise
