import base64
import copy
import json
import logging
from enum import Enum
from typing import Any, Dict, Union
from urllib.parse import quote_plus, unquote_plus

import xmltodict

from localstack import config
from localstack.constants import APPLICATION_JSON, APPLICATION_XML
from localstack.services.apigateway.legacy.context import ApiInvocationContext
from localstack.services.apigateway.legacy.helpers import select_integration_response
from localstack.utils.aws.templating import VelocityUtil, VtlTemplate
from localstack.utils.json import extract_jsonpath, json_safe, try_json
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
    def build_variables_mapping(api_context: ApiInvocationContext) -> dict[str, Any]:
        # TODO: make this (dict) an object so usages of "render_vtl" variables are defined
        ctx = copy.deepcopy(api_context.context or {})
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-override-request-response-parameters.html
        # create namespace for request override
        ctx["requestOverride"] = {
            "header": {},
            "path": {},
            "querystring": {},
        }

        ctx["responseOverride"] = {
            "header": {},
            "status": 200,
        }

        return {
            "context": ctx,
            "stage_variables": api_context.stage_variables or {},
            "input": {
                "body": api_context.data_as_string(),
                "params": {
                    "path": api_context.path_params,
                    "querystring": api_context.query_params(),
                    # Sometimes we get a werkzeug.datastructures.Headers object, sometimes a dict
                    # depending on the request. We need to convert to a dict to be able to render
                    # the template.
                    "header": dict(api_context.headers),
                },
            },
        }


class RequestTemplates(Templates):
    """
    Handles request template rendering
    """

    def render(
        self, api_context: ApiInvocationContext, template_key: str = APPLICATION_JSON
    ) -> Union[bytes, str]:
        LOG.debug(
            "Method request body before transformations: %s", to_str(api_context.data_as_string())
        )
        request_templates = api_context.integration.get("requestTemplates", {})
        template = request_templates.get(template_key)
        if not template:
            return api_context.data_as_string()

        variables = self.build_variables_mapping(api_context)
        result = self.render_vtl(template.strip(), variables=variables)

        # set the request overrides into context
        api_context.headers.update(
            variables.get("context", {}).get("requestOverride", {}).get("header", {})
        )

        LOG.debug("Endpoint request body after transformations:\n%s", result)
        return result


class ResponseTemplates(Templates):
    """
    Handles response template rendering. The integration response status code is used to select
    the correct template to render, if there is no template for the status code, the default
    template is used.
    """

    def render(self, api_context: ApiInvocationContext, **kwargs) -> Union[bytes, str]:
        # XXX: keep backwards compatibility until we migrate all integrations to this new classes
        # api_context contains a response object that we want slowly remove from it
        data = kwargs.get("response", "")
        response = data or api_context.response
        integration = api_context.integration
        # we set context data with the response content because later on we use context data as
        # the body field in the template. We need to improve this by using the right source
        # depending on the type of templates.
        api_context.data = response._content

        # status code returned by the integration
        status_code = str(response.status_code)

        # get the integration responses configuration from the integration object
        integration_responses = integration.get("integrationResponses")
        if not integration_responses:
            return response._content

        # get the configured integration response status codes,
        # e.g. ["200", "400", "500"]
        integration_status_codes = [str(code) for code in list(integration_responses.keys())]
        # if there are no integration responses, we return the response as is
        if not integration_status_codes:
            return response.content

        # The following code handles two use cases.If there is an integration response for the status code returned
        # by the integration, we use the template configured for that status code (1) or the errorMessage (2) for
        # lambda integrations.
        # For an HTTP integration, API Gateway matches the regex to the HTTP status code to return
        # For a Lambda function, API Gateway matches the regex to the errorMessage header to
        # return a status code.
        # For example, to set a 400 response for any error that starts with Malformed,
        # set the method response status code to 400 and the Lambda error regex to Malformed.*.
        match_resp = status_code
        if isinstance(try_json(response._content), dict):
            resp_dict = try_json(response._content)
            if "errorMessage" in resp_dict:
                match_resp = resp_dict.get("errorMessage")

        selected_integration_response = select_integration_response(match_resp, api_context)
        response.status_code = int(selected_integration_response.get("statusCode", 200))
        response_templates = selected_integration_response.get("responseTemplates", {})

        # we only support JSON and XML templates for now - if there is no template we return the response as is
        # If the content type is not supported we always use application/json as default value
        # TODO - support other content types, besides application/json and application/xml
        # see https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html#selecting-mapping-templates
        accept = api_context.headers.get("accept", APPLICATION_JSON)
        supported_types = [APPLICATION_JSON, APPLICATION_XML]
        media_type = accept if accept in supported_types else APPLICATION_JSON
        if not (template := response_templates.get(media_type, {})):
            return response._content

        # we render the template with the context data and the response content
        variables = self.build_variables_mapping(api_context)
        # update the response body
        response._content = self._render_as_text(template, variables)
        if media_type == APPLICATION_JSON:
            self._validate_json(response.content)
        elif media_type == APPLICATION_XML:
            self._validate_xml(response.content)

        if response_overrides := variables.get("context", {}).get("responseOverride", {}):
            response.headers.update(response_overrides.get("header", {}).items())
            response.status_code = response_overrides.get("status", 200)

        LOG.debug("Endpoint response body after transformations:\n%s", response._content)
        return response._content

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
