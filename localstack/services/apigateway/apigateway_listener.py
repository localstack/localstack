import datetime
import json
import logging
import re
import time
from http import HTTPStatus
from typing import Dict

import pytz
from jsonschema import ValidationError, validate

from localstack.constants import (
    APPLICATION_JSON,
    HEADER_LOCALSTACK_AUTHORIZATION,
    HEADER_LOCALSTACK_EDGE_URL,
    LOCALHOST_HOSTNAME,
    TEST_AWS_ACCOUNT_ID,
)
from localstack.services.apigateway import helpers
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import (
    API_REGIONS,
    PATH_REGEX_AUTHORIZERS,
    PATH_REGEX_CLIENT_CERTS,
    PATH_REGEX_DOC_PARTS,
    PATH_REGEX_PATH_MAPPINGS,
    PATH_REGEX_RESPONSES,
    PATH_REGEX_TEST_INVOKE_API,
    PATH_REGEX_USER_REQUEST,
    PATH_REGEX_VALIDATORS,
    REQUEST_TIME_DATE_FORMAT,
    UrlParts,
    extract_path_params,
    extract_query_string_params,
    get_api_region,
    get_cors_response,
    handle_accounts,
    handle_authorizers,
    handle_base_path_mappings,
    handle_client_certificates,
    handle_documentation_parts,
    handle_gateway_responses,
    handle_validators,
    handle_vpc_links,
    make_error_response,
)
from localstack.services.apigateway.integration import (
    DynamoDbIntegration,
    HttpIntegration,
    IntegrationError,
    KinesisIntegration,
    LambdaIntegration,
    MockIntegration,
    S3Integration,
    SnsIntegration,
    SqsIntegration,
    StepFunctionsIntegration,
)
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_responses, aws_stack
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.aws.request_context import (
    RequestContextManager,
    get_region_from_request_context,
    mock_request_for_region,
)
from localstack.utils.common import to_str
from localstack.utils.strings import long_uid

# URL pattern for invocations
HOST_REGEX_EXECUTE_API = (
    r"(?:.*://)?([a-zA-Z0-9-]+)\.execute-api\.(%s|([^\.]+)\.amazonaws\.com)(.*)"
    % LOCALHOST_HOSTNAME
)

# set up logger

LOG = logging.getLogger(__name__)


class AuthorizationError(Exception):
    pass


class ProxyListenerApiGateway(ProxyListener):
    def forward_request(self, method, path, data, headers):
        url_parts = UrlParts(method, path, headers)
        invocation_context = ApiInvocationContext(
            method,
            url_parts.invocation_path,
            data,
            headers,
            api_id=url_parts.api_id,
            stage=url_parts.stage,
        )

        forwarded_for = headers.get(HEADER_LOCALSTACK_EDGE_URL, "")
        if re.match(PATH_REGEX_USER_REQUEST, path) or "execute-api" in forwarded_for:
            result = invoke_rest_api_from_request(invocation_context)
            if result is not None:
                return result

        data = data and json.loads(to_str(data))

        if re.match(PATH_REGEX_AUTHORIZERS, path):
            return handle_authorizers(method, path, data, headers)

        if re.match(PATH_REGEX_DOC_PARTS, path):
            return handle_documentation_parts(method, path, data, headers)

        if re.match(PATH_REGEX_VALIDATORS, path):
            return handle_validators(method, path, data, headers)

        if re.match(PATH_REGEX_RESPONSES, path):
            return handle_gateway_responses(method, path, data, headers)

        if re.match(PATH_REGEX_PATH_MAPPINGS, path):
            return handle_base_path_mappings(method, path, data, headers)

        if helpers.is_test_invoke_method(method, path):
            return handle_test_invoke_request(path, invocation_context, data)
        return True

    def return_response(self, method, path, data, headers, response):
        # fix backend issue (missing support for API documentation)
        if (
            re.match(r"/restapis/[^/]+/documentation/versions", path)
            and response.status_code == 404
        ):
            return requests_response({"position": "1", "items": []})

        # add missing implementations
        if response.status_code == 404:
            result = None
            if path == "/account":
                data = data and json.loads(to_str(data))
                result = handle_accounts(method, path, data, headers)
            elif path.startswith("/vpclinks"):
                data = data and json.loads(to_str(data))
                result = handle_vpc_links(method, path, data, headers)
            elif re.match(PATH_REGEX_CLIENT_CERTS, path):
                data = data and json.loads(to_str(data))
                result = handle_client_certificates(method, path, data, headers)

            if result is not None:
                response.status_code = 200
                aws_responses.set_response_content(response, result, getattr(result, "headers", {}))

        # keep track of API regions for faster lookup later on
        if method == "POST" and path == "/restapis":
            content = json.loads(to_str(response.content))
            api_id = content["id"]
            region = aws_stack.extract_region_from_auth_header(headers)
            API_REGIONS[api_id] = region

        # publish event
        if method == "POST" and path == "/restapis":
            content = json.loads(to_str(response.content))
            event_publisher.fire_event(
                event_publisher.EVENT_APIGW_CREATE_API,
                payload={"a": event_publisher.get_hash(content["id"])},
            )
        api_regex = r"^/restapis/([a-zA-Z0-9\-]+)$"
        if method == "DELETE" and re.match(api_regex, path):
            api_id = re.sub(api_regex, r"\1", path)
            event_publisher.fire_event(
                event_publisher.EVENT_APIGW_DELETE_API,
                payload={"a": event_publisher.get_hash(api_id)},
            )


class RequestValidator:
    __slots__ = ["context", "apigateway_client"]

    def __init__(self, context: ApiInvocationContext, apigateway_client):
        self.context = context
        self.apigateway_client = apigateway_client

    def is_request_valid(self) -> bool:
        # make all the positive checks first
        if self.context.resource is None or "resourceMethods" not in self.context.resource:
            return True

        resource_methods = self.context.resource["resourceMethods"]
        if self.context.method not in resource_methods:
            return True

        # check if there is validator for the resource
        resource = resource_methods[self.context.method]
        if not (resource.get("requestValidatorId") or "").strip():
            return True

        # check if there is a validator for this request
        validator = self.apigateway_client.get_request_validator(
            restApiId=self.context.api_id, requestValidatorId=resource["requestValidatorId"]
        )
        if validator is None:
            return True

        # are we validating the body?
        if self.should_validate_body(validator):
            is_body_valid = self.validate_body(resource)
            if not is_body_valid:
                return is_body_valid

        if self.should_validate_request(validator):
            is_valid_parameters = self.validate_parameters_and_headers(resource)
            if not is_valid_parameters:
                return is_valid_parameters

        return True

    def validate_body(self, resource):
        # we need a model to validate the body
        if "requestModels" not in resource or not resource["requestModels"]:
            return False

        schema_name = resource["requestModels"].get(APPLICATION_JSON)
        model = self.apigateway_client.get_model(
            restApiId=self.context.api_id,
            modelName=schema_name,
        )
        if not model:
            return False

        try:
            validate(instance=json.loads(self.context.data), schema=json.loads(model["schema"]))
            return True
        except ValidationError as e:
            LOG.warning("failed to validate request body", e)
            return False

    # TODO implement parameters and headers
    def validate_parameters_and_headers(self, resource):
        return True

    @staticmethod
    def should_validate_body(validator):
        return validator["validateRequestBody"]

    @staticmethod
    def should_validate_request(validator):
        return validator.get("validateRequestParameters")


# ------------
# API METHODS
# ------------
def handle_test_invoke_request(path, invocation_context, data):
    # if call is from test_invoke_api then use http_method to find the integration,
    #   as test_invoke_api makes a POST call to request the test invocation
    match = re.match(PATH_REGEX_TEST_INVOKE_API, path)
    invocation_context.method = match[3]
    if data:
        orig_data = data
        if path_with_query_string := orig_data.get("pathWithQueryString", None):
            invocation_context.path_with_query_string = path_with_query_string
        invocation_context.data = data.get("body")
        invocation_context.headers = orig_data.get("headers", {})
    result = invoke_rest_api_from_request(invocation_context)
    result = {
        "status": result.status_code,
        "body": to_str(result.content),
        "headers": dict(result.headers),
    }
    return result


def run_authorizer(invocation_context: ApiInvocationContext, authorizer: Dict):
    # TODO implement authorizers
    pass


def authorize_invocation(invocation_context: ApiInvocationContext):
    client = aws_stack.connect_to_service("apigateway")
    authorizers = client.get_authorizers(restApiId=invocation_context.api_id, limit=100).get(
        "items", []
    )
    for authorizer in authorizers:
        run_authorizer(invocation_context, authorizer)


def validate_api_key(api_key: str, stage: str):
    usage_plan_ids = []

    client = aws_stack.connect_to_service("apigateway")
    usage_plans = client.get_usage_plans()
    for item in usage_plans.get("items", []):
        api_stages = item.get("apiStages", [])
        usage_plan_ids.extend(
            item.get("id") for api_stage in api_stages if api_stage.get("stage") == stage
        )

    for usage_plan_id in usage_plan_ids:
        usage_plan_keys = client.get_usage_plan_keys(usagePlanId=usage_plan_id)
        for key in usage_plan_keys.get("items", []):
            if key.get("value") == api_key:
                return True

    return False


def is_api_key_valid(is_api_key_required: bool, headers: Dict[str, str], stage: str):
    if not is_api_key_required:
        return True

    api_key = headers.get("X-API-Key")
    if not api_key:
        return False

    return validate_api_key(api_key, stage)


# def apply_response_parameters(invocation_context: ApiInvocationContext):
#     response = invocation_context.response
#     integration = invocation_context.integration
#
#     int_responses = integration.get("integrationResponses") or {}
#     if not int_responses:
#         return response
#     entries = list(int_responses.keys())
#     return_code = str(response.status_code)
#     if return_code not in entries:
#         if len(entries) > 1:
#             LOG.info("Found multiple integration response status codes: %s", entries)
#             return response
#         return_code = entries[0]
#     response_params = int_responses[return_code].get("responseParameters", {})
#     for key, value in response_params.items():
#         # TODO: add support for method.response.body, etc ...
#         if str(key).lower().startswith("method.response.header."):
#             header_name = key[len("method.response.header.") :]
#             response.headers[header_name] = value.strip("'")
#     return response


# def set_api_id_stage_invocation_path(
#     invocation_context: ApiInvocationContext,
# ) -> ApiInvocationContext:
#     # skip if all details are already available
#     values = (
#         invocation_context.api_id,
#         invocation_context.stage,
#         invocation_context.path_with_query_string,
#     )
#     if all(values):
#         return invocation_context
#
#     # skip if this is a websocket request
#     if invocation_context.is_websocket_request():
#         return invocation_context
#
#     path = invocation_context.path
#     headers = invocation_context.headers
#
#     path_match = re.search(PATH_REGEX_USER_REQUEST, path)
#     host_header = headers.get(HEADER_LOCALSTACK_EDGE_URL, "") or headers.get("Host") or ""
#     host_match = re.search(HOST_REGEX_EXECUTE_API, host_header)
#     test_invoke_match = re.search(PATH_REGEX_TEST_INVOKE_API, path)
#     if path_match:
#         api_id = path_match.group(1)
#         stage = path_match.group(2)
#         relative_path_w_query_params = f"/{path_match.group(3)}"
#     elif host_match:
#         api_id = extract_api_id_from_hostname_in_url(host_header)
#         stage = path.strip("/").split("/")[0]
#         relative_path_w_query_params = f'/{path.lstrip("/").partition("/")[2]}'
#     elif test_invoke_match:
#         # special case: fetch the resource details for TestInvokeApi invocations
#         stage = None
#         region_name = invocation_context.region_name
#         api_id = test_invoke_match.group(1)
#         resource_id = test_invoke_match.group(2)
#         query_string = test_invoke_match.group(4) or ""
#         apigateway = aws_stack.connect_to_service(
#             service_name="apigateway", region_name=region_name
#         )
#         resource = apigateway.get_resource(restApiId=api_id, resourceId=resource_id)
#         resource_path = resource.get("path")
#         relative_path_w_query_params = f"{resource_path}{query_string}"
#     else:
#         raise Exception(
#             f"Unable to extract API Gateway details from request: {path} {dict(headers)}"
#         )
#     if api_id and getattr(THREAD_LOCAL, "request_context", None) is not None:
#         THREAD_LOCAL.request_context.headers[MARKER_APIGW_REQUEST_REGION] = API_REGIONS.get(
#             api_id, ""
#         )
#
#     # set details in invocation context
#     invocation_context.api_id = api_id
#     invocation_context.stage = stage
#     invocation_context.path_with_query_string = relative_path_w_query_params
#     return invocation_context


# def extract_api_id_from_hostname_in_url(hostname: str) -> str:
#     """Extract API ID 'id123' from URLs like
#     https://id123.execute-api.localhost.localstack.cloud:4566"""
#     match = re.match(HOST_REGEX_EXECUTE_API, hostname)
#     return match.group(1)


def invoke_rest_api_from_request(invocation_context: ApiInvocationContext):
    # set_api_id_stage_invocation_path(invocation_context)
    try:
        context = mock_request_for_region(
            get_api_region(invocation_context.api_id), service_name="apigateway"
        )
        with RequestContextManager(context):
            return invoke_rest_api(invocation_context)
    except AuthorizationError as e:
        api_id = invocation_context.api_id
        return make_error_response(f"Not authorized to invoke REST API {api_id}: {e}", 403)


def invoke_rest_api(invocation_context: ApiInvocationContext):
    raw_path = invocation_context.path or invocation_context.path_with_query_string
    method = invocation_context.method
    headers = invocation_context.headers

    # run gateway authorizers for this request
    authorize_invocation(invocation_context)

    extracted_path, resource = helpers.get_target_resource_details(invocation_context)
    if not resource:
        return make_error_response(f"Unable to find path {invocation_context.path}", 404)

    # validate request
    validator = RequestValidator(invocation_context, aws_stack.connect_to_service("apigateway"))
    if not validator.is_request_valid():
        return make_error_response("Invalid request body", 400)

    api_key_required = resource.get("resourceMethods", {}).get(method, {}).get("apiKeyRequired")
    if not is_api_key_valid(api_key_required, headers, invocation_context.stage):
        return make_error_response("Access denied - invalid API key", 403)

    integrations = resource.get("resourceMethods", {})
    integration = integrations.get(method, {})
    if not integration:
        # HttpMethod: '*'
        # ResourcePath: '/*' - produces 'X-AMAZON-APIGATEWAY-ANY-METHOD'
        integration = integrations.get("ANY", {}) or integrations.get(
            "X-AMAZON-APIGATEWAY-ANY-METHOD", {}
        )
    integration = integration.get("methodIntegration")
    if not integration:
        if method == "OPTIONS" and "Origin" in headers:
            # default to returning CORS headers if this is an OPTIONS request
            return get_cors_response(headers)
        return make_error_response(
            f"Unable to find integration for: {method} {invocation_context.path_with_query_string} ({raw_path})",
            404,
        )

    res_methods = resource.get("resourceMethods", {})
    meth_integration = res_methods.get(method, {}).get("methodIntegration", {})
    int_responses = meth_integration.get("integrationResponses", {})
    response_templates = int_responses.get("200", {}).get("responseTemplates", {})

    # update fields in invocation context, then forward request to next handler
    invocation_context.resource = resource
    invocation_context.resource_path = extracted_path
    invocation_context.response_templates = response_templates
    invocation_context.integration = integration

    return invoke_rest_api_integration(invocation_context)


def invoke_rest_api_integration(invocation_context: ApiInvocationContext):
    try:
        response = invoke_rest_api_integration_backend(invocation_context)
        if response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE:
            return response
        # invocation_context.response = response
        # response = apply_response_parameters(invocation_context)
        return response
    except Exception as e:
        msg = f"Error invoking integration for API Gateway ID '{invocation_context.api_id}': {e}"
        LOG.exception(msg)
        return make_error_response(msg, 400)


# TODO: refactor this to have a class per integration type to make it easy to
# test the encapsulated logic
def invoke_rest_api_integration_backend(invocation_context: ApiInvocationContext):
    # define local aliases from invocation context
    invocation_path = invocation_context.path_with_query_string
    method = invocation_context.method
    headers = invocation_context.headers

    resource_path = invocation_context.resource_path
    integration = invocation_context.integration
    # extract integration type and path parameters
    relative_path, query_string_params = extract_query_string_params(path=invocation_path)
    integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
    integration_type = integration_type_orig.upper()
    uri = integration.get("uri") or integration.get("integrationUri") or ""
    # XXX we need replace the internal Authorization header with an Authorization header set from
    # the customer, even if it's empty that's what's expected in the integration.
    custom_auth_header = invocation_context.headers.pop(HEADER_LOCALSTACK_AUTHORIZATION, "")
    invocation_context.headers["Authorization"] = custom_auth_header

    # XXX this can be computed inside invocation_context.
    invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)

    try:
        path_params = extract_path_params(path=relative_path, extracted_path=resource_path)
        invocation_context.path_params = path_params
    except Exception:
        invocation_context.path_params = {}

    if (uri.startswith("arn:aws:apigateway:") and ":lambda:path" in uri) or uri.startswith(
        "arn:aws:lambda"
    ):
        if integration_type in ["AWS", "AWS_PROXY"]:
            invocation_context.context = helpers.get_event_request_context(invocation_context)
            integration = LambdaIntegration()
            return integration.invoke(invocation_context)
        raise IntegrationError(
            f'API Gateway integration type "{integration_type}", action "{uri}", method "{method}"'
        )
    elif integration_type == "AWS":
        if "kinesis:action/" in uri:
            invocation_context.context = helpers.get_event_request_context(invocation_context)
            integration = KinesisIntegration()
            return integration.invoke(invocation_context)
        elif "states:action/" in uri:
            integration = StepFunctionsIntegration()
            return integration.invoke(invocation_context)
        # https://docs.aws.amazon.com/apigateway/api-reference/resource/integration/
        elif ("s3:path/" in uri or "s3:action/" in uri) and method == "GET":
            integration = S3Integration()
            return integration.invoke(invocation_context)
        if method == "POST" and uri.startswith("arn:aws:apigateway:"):
            if ":sqs:path" in uri:
                integration = SqsIntegration()
                return integration.invoke(invocation_context)
            elif uri.startswith("arn:aws:apigateway:") and ":sns:path" in uri:
                invocation_context.context = helpers.get_event_request_context(invocation_context)
            elif ":sns:path" in uri:
                integration = SnsIntegration()
                return integration.invoke(invocation_context)
        raise IntegrationError(
            f"API Gateway AWS integration action URI '{uri}', method '{method}' not yet implemented"
        )
    elif integration_type == "AWS_PROXY":
        if not uri.startswith("arn:aws:apigateway:") or ":dynamodb:action" not in uri:
            raise IntegrationError(
                f"API Gateway action uri '{uri}', integration type '{integration_type}' not yet "
                f"implemented"
            )
        integration = DynamoDbIntegration()
        return integration.invoke(invocation_context)
    elif integration_type in ["HTTP_PROXY", "HTTP"]:
        integration = HttpIntegration()
        return integration.invoke(invocation_context=invocation_context)
    elif integration_type == "MOCK":
        integration = MockIntegration()
        return integration.invoke(invocation_context)
    if method == "OPTIONS":
        # fall back to returning CORS headers if this is an OPTIONS request
        return get_cors_response(headers)
    raise IntegrationError(
        f"API Gateway integration type '{integration_type}', method '{method}', URI '{uri}' not "
        f"yet implemented"
    )


def apply_request_response_templates(
    data: Union[Response, bytes],
    templates: Dict[str, str],
    content_type: str = None,
    as_json: bool = False,
):
    """Apply the matching request/response template (if it exists) to the payload data and return the result"""

def get_target_resource_method(invocation_context: ApiInvocationContext) -> Optional[Dict]:
    """Look up and return the API GW resource method for the given invocation context."""
    _, resource = get_target_resource_details(invocation_context)
    if not resource:
        return None
    methods = resource.get("resourceMethods") or {}
    method_name = invocation_context.method.upper()
    return methods.get(method_name) or methods.get("ANY")


def get_event_request_context(invocation_context: ApiInvocationContext):
    method = invocation_context.method
    path = invocation_context.path
    headers = invocation_context.headers
    integration_uri = invocation_context.integration_uri
    resource_path = invocation_context.resource_path
    resource_id = invocation_context.resource_id

    # set_api_id_stage_invocation_path(invocation_context)
    relative_path, query_string_params = extract_query_string_params(
        path=invocation_context.path_with_query_string
    )
    api_id = invocation_context.api_id
    stage = invocation_context.stage

    source_ip = headers.get("X-Forwarded-For", ",").split(",")[-2].strip()
    integration_uri = integration_uri or ""
    account_id = integration_uri.split(":lambda:path")[-1].split(":function:")[0].split(":")[-1]
    account_id = account_id or TEST_AWS_ACCOUNT_ID
    request_context = {
        "accountId": account_id,
        "apiId": api_id,
        "resourcePath": resource_path or relative_path,
        "domainPrefix": invocation_context.domain_prefix,
        "domainName": invocation_context.domain_name,
        "resourceId": resource_id,
        "requestId": long_uid(),
        "identity": {
            "accountId": account_id,
            "sourceIp": source_ip,
            "userAgent": headers.get("User-Agent"),
        },
        "httpMethod": method,
        "protocol": "HTTP/1.1",
        "requestTime": pytz.utc.localize(datetime.datetime.utcnow()).strftime(
            REQUEST_TIME_DATE_FORMAT
        ),
        "requestTimeEpoch": int(time.time() * 1000),
        "authorizer": {},
    }

    # set "authorizer" and "identity" event attributes from request context
    auth_context = invocation_context.auth_context
    if auth_context:
        request_context["authorizer"] = auth_context
    request_context["identity"].update(invocation_context.auth_identity or {})

    if not helpers.is_test_invoke_method(method, path):
        request_context["path"] = (f"/{stage}" if stage else "") + relative_path
        request_context["stage"] = stage
    return request_context


# def apply_request_response_templates(
#     data: Union[Response, bytes],
#     templates: Dict[str, str],
#     content_type: str = None,
#     as_json: bool = False,
# ):
#     """Apply the matching request/response template (if it exists) to the payload data and
#     return the result"""
#
#     content_type = content_type or APPLICATION_JSON
#     is_response = isinstance(data, Response)
#     templates = templates or {}
#     template = templates.get(content_type)
#     if not template:
#         return data
#     content = (data.content if is_response else data) or ""
#     result = VtlTemplate().render_vtl(template, content, as_json=as_json)
#     if is_response:
#         data._content = result
#         update_content_length(data)
#         return data
#     return result
    content_type = content_type or APPLICATION_JSON
    is_response = isinstance(data, Response)
    templates = templates or {}
    template = templates.get(content_type)
    if not template:
        return data
    content = (data.content if is_response else data) or ""
    result = VtlTemplate().render_vtl(template, content, as_json=as_json)
    if is_response:
        data._content = result
        update_content_length(data)
        return data
    return result


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
