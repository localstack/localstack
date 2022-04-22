import base64
import copy
import json
import logging
import re
from abc import ABC, abstractmethod
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict
from urllib.parse import quote_plus, unquote_plus, urljoin

import airspeed
import requests
from flask import Response as FlaskResponse
from requests import Response

from localstack import config
from localstack.constants import APPLICATION_JSON, HEADER_CONTENT_TYPE, TEST_AWS_ACCOUNT_ID
from localstack.services.apigateway import helpers
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import extract_path_params, make_error_response
from localstack.services.awslambda import lambda_api
from localstack.services.kinesis import kinesis_listener
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import (
    LambdaResponse,
    flask_to_requests_response,
    request_response_stream,
)
from localstack.utils.common import make_http_request, to_str
from localstack.utils.http import add_query_params_to_url
from localstack.utils.json import extract_jsonpath, json_safe
from localstack.utils.numbers import is_number, to_number
from localstack.utils.objects import recurse_object
from localstack.utils.strings import to_bytes

LOG = logging.getLogger(__name__)

# target ARN patterns
TARGET_REGEX_PATH_S3_URI = (
    r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:path/(?P<bucket>[^/]+)/(?P<object>.+)$"
)
TARGET_REGEX_ACTION_S3_URI = r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:action/(?:GetObject&Bucket\=(?P<bucket>[^&]+)&Key\=(?P<object>.+))$"


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

    @classmethod
    def _create_response(cls, status_code, headers, data=""):
        response = Response()
        response.status_code = status_code
        response.headers = headers
        response._content = data
        return response

    @classmethod
    def apply_request_parameters(
        cls,
        uri: str,
        integration: Dict[str, Any],
        path_params: Dict[str, str],
        query_params: Dict[str, str],
    ):
        request_parameters = integration.get("requestParameters")
        uri = uri or integration.get("uri") or integration.get("integrationUri") or ""
        if request_parameters:
            for key in path_params:
                # check if path_params is present in the integration request parameters
                request_param_key = f"integration.request.path.{key}"
                request_param_value = f"method.request.path.{key}"
                if request_parameters.get(request_param_key, None) == request_param_value:
                    uri = uri.replace(f"{{{key}}}", path_params[key])

        if integration.get("type") != "HTTP_PROXY" and request_parameters:
            for key in query_params.copy():
                request_query_key = f"integration.request.querystring.{key}"
                request_param_val = f"method.request.querystring.{key}"
                if request_parameters.get(request_query_key, None) != request_param_val:
                    query_params.pop(key)

        return add_query_params_to_url(uri, query_params)


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
    @classmethod
    def evaluate_passthrough_behavior(cls, passthrough_behavior: str, request_template: str):
        return MappingTemplates(passthrough_behavior).request_body_passthrough(request_template)

    def invoke(self, invocation_context: ApiInvocationContext):
        passthrough_behavior = invocation_context.integration.get("passthroughBehavior") or ""
        request_template = invocation_context.integration.get("requestTemplates", {}).get(
            invocation_context.headers.get(HEADER_CONTENT_TYPE)
        )

        # based on the configured passthrough behavior and the existence of template or not,
        # we proceed calling the integration or raise an exception.
        try:
            self.evaluate_passthrough_behavior(passthrough_behavior, request_template)
        except MappingTemplates.UnsupportedMediaType:
            http_status = HTTPStatus(415)
            return MockIntegration._create_response(
                http_status.value,
                headers={"Content-Type": APPLICATION_JSON},
                data=json.dumps({"message": f"{http_status.phrase}"}),
            )

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
                http_status = HTTPStatus(500)
                return MockIntegration._create_response(
                    http_status.value,
                    headers={"Content-Type": APPLICATION_JSON},
                    data=json.dumps({"message": f"{http_status.phrase}"}),
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


class HttpIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        invocation_path = invocation_context.path_with_query_string
        relative_path, query_string_params = helpers.extract_query_string_params(
            path=invocation_context.path_with_query_string
        )

        try:
            path_params = extract_path_params(
                path=relative_path, extracted_path=invocation_context.resource_path
            )
            invocation_context.path_params = path_params
        except Exception:
            path_params = {}

        if ":servicediscovery:" in uri:
            # check if this is a servicediscovery integration URI
            client = aws_stack.connect_to_service("servicediscovery")
            service_id = uri.split("/")[-1]
            instances = client.list_instances(ServiceId=service_id)["Instances"]
            instance = (instances or [None])[0]
            if instance and instance.get("Id"):
                uri = f'http://{instance["Id"]}/{invocation_path.lstrip("/")}'

        # apply custom request template
        payload = self.request_templates.render(invocation_context)

        if isinstance(payload, dict):
            payload = json.dumps(payload)
        relative_path, query_string_params = helpers.extract_query_string_params(
            path=invocation_path
        )
        uri = self.apply_request_parameters(
            uri=uri,
            integration=invocation_context.integration,
            path_params=path_params,
            query_params=query_string_params,
        )
        result = requests.request(
            method=invocation_context.method,
            url=uri,
            data=payload,
            headers=invocation_context.headers,
        )
        # apply custom response template
        invocation_context.response = result
        self.response_templates.render(invocation_context)
        return invocation_context.response


class LambdaIntegration(BackendIntegration):
    @classmethod
    def update_content_length(cls, response: Response):
        if response and response.content is not None:
            response.headers["Content-Length"] = str(len(response.content))

    def invoke(self, invocation_context: ApiInvocationContext):
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        relative_path, query_string_params = helpers.extract_query_string_params(
            path=invocation_context.path_with_query_string
        )
        api_id = invocation_context.api_id
        stage = invocation_context.stage
        headers = invocation_context.headers
        resource_path = invocation_context.resource_path

        try:
            path_params = extract_path_params(path=relative_path, extracted_path=resource_path)
            invocation_context.path_params = path_params
        except Exception:
            path_params = {}

        func_arn = uri
        if ":lambda:path" in uri:
            func_arn = uri.split(":lambda:path")[1].split("functions/")[1].split("/invocations")[0]

        if invocation_context.authorizer_type:
            authorizer_context = {
                invocation_context.authorizer_type: invocation_context.auth_context
            }
            invocation_context.context["authorizer"] = authorizer_context

        payload = self.request_templates.render(invocation_context)

        # TODO: change this signature to InvocationContext as well!
        result = lambda_api.process_apigateway_invocation(
            func_arn,
            relative_path,
            payload,
            stage,
            api_id,
            headers,
            is_base64_encoded=invocation_context.is_data_base64_encoded,
            path_params=path_params,
            query_string_params=query_string_params,
            method=invocation_context.method,
            resource_path=resource_path,
            request_context=invocation_context.context,
            stage_variables=invocation_context.stage_variables,
        )

        if isinstance(result, FlaskResponse):
            response = flask_to_requests_response(result)
        elif isinstance(result, Response):
            response = result
        else:
            response = LambdaResponse()
            parsed_result = result if isinstance(result, dict) else json.loads(str(result or "{}"))
            parsed_result = common.json_safe(parsed_result)
            parsed_result = {} if parsed_result is None else parsed_result
            response.status_code = int(parsed_result.get("statusCode", 200))
            parsed_headers = parsed_result.get("headers", {})
            if parsed_headers is not None:
                response.headers.update(parsed_headers)
            try:
                result_body = parsed_result.get("body")
                if isinstance(result_body, dict):
                    response._content = json.dumps(result_body)
                else:
                    body_bytes = to_bytes(to_str(result_body or ""))
                    if parsed_result.get("isBase64Encoded", False):
                        body_bytes = base64.b64decode(body_bytes)
                    response._content = body_bytes
            except Exception as e:
                LOG.warning("Couldn't set Lambda response content: %s", e)
                response._content = "{}"
            self.update_content_length(response)
            response.multi_value_headers = parsed_result.get("multiValueHeaders") or {}

        # apply custom response template
        invocation_context.response = response

        self.response_templates.render(invocation_context)
        invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))
        return invocation_context.response


class KinesisIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        if uri.endswith("kinesis:action/PutRecord"):
            target = kinesis_listener.ACTION_PUT_RECORD
        elif uri.endswith("kinesis:action/PutRecords"):
            target = kinesis_listener.ACTION_PUT_RECORDS
        elif uri.endswith("kinesis:action/ListStreams"):
            target = kinesis_listener.ACTION_LIST_STREAMS
        else:
            LOG.info(f"Unexpected API Gateway integration URI '{uri}' for integration type")
            target = ""

        try:
            payload = self.request_templates.render(invocation_context)

        except Exception as e:
            LOG.warning("Unable to convert API Gateway payload to str", e)
            raise

        # forward records to target kinesis stream
        headers = aws_stack.mock_aws_request_headers(
            service="kinesis", region_name=invocation_context.region_name
        )
        headers["X-Amz-Target"] = target

        result = common.make_http_request(
            url=config.service_url("kineses"), data=payload, headers=headers, method="POST"
        )

        # apply response template
        invocation_context.response = result
        self.response_templates.render(invocation_context)
        return invocation_context.response


class SqsIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        template = invocation_context.integration["requestTemplates"][APPLICATION_JSON]
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )

        account_id, queue = uri.split("/")[-2:]
        region_name = uri.split(":")[3]
        if "GetQueueUrl" in template or "CreateQueue" in template:
            request_templates = RequestTemplates()
            payload = request_templates.render(invocation_context)
            new_request = f"{payload}&QueueName={queue}"
        else:
            payload = self.request_templates.render(invocation_context)
            queue_url = f"{config.get_edge_url()}/{account_id}/{queue}"
            new_request = f"{payload}&QueueUrl={queue_url}"
        headers = aws_stack.mock_aws_request_headers(service="sqs", region_name=region_name)

        url = urljoin(config.service_url("sqs"), f"{TEST_AWS_ACCOUNT_ID}/{queue}")
        result = common.make_http_request(url, method="POST", headers=headers, data=new_request)
        return result


class S3Integration(BackendIntegration):
    def __init__(self):
        super().__init__()
        self.s3 = aws_stack.connect_to_service("s3")

    def invoke(self, invocation_context: ApiInvocationContext):
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        relative_path, query_string_params = helpers.extract_query_string_params(
            path=invocation_context.path_with_query_string
        )
        resource_path = invocation_context.resource_path

        try:
            path_params = extract_path_params(path=relative_path, extracted_path=resource_path)
            invocation_context.path_params = path_params
        except Exception:
            path_params = {}

        uri = self.apply_request_parameters(
            uri,
            integration=invocation_context.integration,
            path_params=path_params,
            query_params=query_string_params,
        )

        if uri_match := re.match(TARGET_REGEX_PATH_S3_URI, uri) or re.match(
            TARGET_REGEX_ACTION_S3_URI, uri
        ):
            return self._get_s3_object(uri_match)

        msg = "Request URI does not match s3 specifications"
        LOG.warning(msg)
        return make_error_response(msg, 400)

    def _get_s3_object(self, uri_match):
        bucket, object_key = uri_match.group("bucket", "object")
        LOG.debug("Getting request for bucket %s object %s", bucket, object_key)
        try:
            s3_object = self.s3.get_object(Bucket=bucket, Key=object_key)
        except self.s3.exceptions.NoSuchKey:
            msg = f"Object {object_key} not found"
            LOG.debug(msg)
            return make_error_response(msg, 404)

        headers = aws_stack.mock_aws_request_headers(service="s3")

        if s3_object.get("ContentType"):
            headers["Content-Type"] = s3_object["ContentType"]

        return request_response_stream(stream=s3_object["Body"], headers=headers)


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
        request_template = request_templates.get(
            api_context.headers.get(HEADER_CONTENT_TYPE) or APPLICATION_JSON
        )
        # if there is no template we don't need to render anything, we return the incoming input
        if not request_template:
            return api_context.data_as_string()

        result = self.render_vtl(
            request_template, variables=self.build_variables_mapping(api_context)
        )

        LOG.info(f"Endpoint request body after transformations:\n{result}")
        return result


class ResponseTemplates(Templates):
    """
    Handles response template rendering
    """

    def render(self, api_context: ApiInvocationContext, **kwargs):
        # keep backwards compatibility until we migrate all integrations to this new classes
        # api_context contains a response object that we want slowly remove from it
        data = kwargs["response"] if "response" in kwargs else ""
        response = data or api_context.response
        integration = api_context.integration
        # we set context data with the response content because later on we use context data as
        # the body field in the template. We need to improve this by using the right source
        # depending on the type of templates.
        api_context.data = response._content
        int_responses = integration.get("integrationResponses") or {}
        if not int_responses:
            # backwards compatibility
            api_context.response = response
            return response
        entries = list(int_responses.keys())
        return_code = str(response.status_code)
        if return_code not in entries and len(entries) > 1:
            LOG.info("Found multiple integration response status codes: %s", entries)
            # backwards compatibility
            api_context.response = response
            return response

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
            # backwards compatibility
            api_context.response = response
            return response

        variables = self.build_variables_mapping(api_context)
        response._content = self.render_vtl(template, variables=variables)
        response.headers.update({HEADER_CONTENT_TYPE: APPLICATION_JSON})
        LOG.info("Endpoint response body after transformations:\n%s", response._content)
        # backwards compatibility
        api_context.response = response
        return response
