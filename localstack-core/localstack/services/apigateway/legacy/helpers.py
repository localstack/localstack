import json
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union
from urllib import parse as urlparse

from botocore.utils import InvalidArnException
from moto.apigateway.models import apigateway_backends
from requests.models import Response

from localstack.aws.connect import connect_to
from localstack.constants import (
    APPLICATION_JSON,
    DEFAULT_AWS_ACCOUNT_ID,
    HEADER_LOCALSTACK_EDGE_URL,
    PATH_USER_REQUEST,
)
from localstack.services.apigateway.helpers import REQUEST_TIME_DATE_FORMAT
from localstack.services.apigateway.legacy.context import ApiInvocationContext
from localstack.utils import common
from localstack.utils.aws import resources as resource_utils
from localstack.utils.aws.arns import get_partition, parse_arn
from localstack.utils.aws.aws_responses import requests_error_response_json, requests_response
from localstack.utils.json import try_json
from localstack.utils.numbers import is_number
from localstack.utils.strings import canonicalize_bool_to_str, long_uid, to_str

LOG = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_MAIN = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+(\?.*)?"
PATH_REGEX_SUB = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*"
PATH_REGEX_TEST_INVOKE_API = r"^\/restapis\/([A-Za-z0-9_\-]+)\/resources\/([A-Za-z0-9_\-]+)\/methods\/([A-Za-z0-9_\-]+)/?(\?.*)?"

# regex path pattern for user requests, handles stages like $default
PATH_REGEX_USER_REQUEST = (
    r"^/restapis/([A-Za-z0-9_\\-]+)(?:/([A-Za-z0-9\_($|%%24)\\-]+))?/%s/(.*)$" % PATH_USER_REQUEST
)
# URL pattern for invocations
HOST_REGEX_EXECUTE_API = r"(?:.*://)?([a-zA-Z0-9]+)(?:(-vpce-[^.]+))?\.execute-api\.(.*)"

# template for SQS inbound data
APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE = (
    "Action=SendMessage&MessageBody=$util.base64Encode($input.json('$'))"
)


class ApiGatewayIntegrationError(Exception):
    """
    Base class for all ApiGateway Integration errors.
    Can be used as is or extended for common error types.
    These exceptions should be handled in one place, and bubble up from all others.
    """

    message: str
    status_code: int

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_response(self):
        return requests_response({"message": self.message}, status_code=self.status_code)


class IntegrationParameters(TypedDict):
    path: dict[str, str]
    querystring: dict[str, str]
    headers: dict[str, str]


class RequestParametersResolver:
    """
    Integration request data mapping expressions
    https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html

    Note: Use on REST APIs only
    """

    def resolve(self, context: ApiInvocationContext) -> IntegrationParameters:
        """
        Resolve method request parameters into integration request parameters.
        Integration request parameters, in the form of path variables, query strings
        or headers, can be mapped from any defined method request parameters
        and the payload.

        :return: IntegrationParameters
        """
        method_request_params: Dict[str, Any] = self.method_request_dict(context)

        # requestParameters: {
        #     "integration.request.path.pathParam": "method.request.header.Content-Type"
        #     "integration.request.querystring.who": "method.request.querystring.who",
        #     "integration.request.header.Content-Type": "'application/json'",
        # }
        request_params = context.integration.get("requestParameters", {})

        # resolve all integration request parameters with the already resolved method request parameters
        integrations_parameters = {}
        for k, v in request_params.items():
            if v.lower() in method_request_params:
                integrations_parameters[k] = method_request_params[v.lower()]
            else:
                # static values
                integrations_parameters[k] = v.replace("'", "")

        # build the integration parameters
        result: IntegrationParameters = IntegrationParameters(path={}, querystring={}, headers={})
        for k, v in integrations_parameters.items():
            # headers
            if k.startswith("integration.request.header."):
                header_name = k.split(".")[-1]
                result["headers"].update({header_name: v})

            # querystring
            if k.startswith("integration.request.querystring."):
                param_name = k.split(".")[-1]
                result["querystring"].update({param_name: v})

            # path
            if k.startswith("integration.request.path."):
                path_name = k.split(".")[-1]
                result["path"].update({path_name: v})

        return result

    def method_request_dict(self, context: ApiInvocationContext) -> Dict[str, Any]:
        """
        Build a dict with all method request parameters and their values.
        :return: dict with all method request parameters and their values,
        and all keys in lowercase
        """
        params: Dict[str, str] = {}

        # TODO: add support for multi-values headers and multi-values querystring

        for k, v in context.query_params().items():
            params[f"method.request.querystring.{k}"] = v

        for k, v in context.headers.items():
            params[f"method.request.header.{k}"] = v

        for k, v in context.path_params.items():
            params[f"method.request.path.{k}"] = v

        for k, v in context.stage_variables.items():
            params[f"stagevariables.{k}"] = v

        # TODO: add support for missing context variables, use `context.context` which contains most of the variables
        #  see https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html#context-variable-reference
        #  - all `context.identity` fields
        #  - protocol
        #  - requestId, extendedRequestId
        #  - all requestOverride, responseOverride
        #  - requestTime, requestTimeEpoch
        #  - resourcePath
        #  - wafResponseCode, webaclArn
        params["context.accountId"] = context.account_id
        params["context.apiId"] = context.api_id
        params["context.domainName"] = context.domain_name
        params["context.httpMethod"] = context.method
        params["context.path"] = context.path
        params["context.resourceId"] = context.resource_id
        params["context.stage"] = context.stage

        auth_context_authorizer = context.auth_context.get("authorizer") or {}
        for k, v in auth_context_authorizer.items():
            if isinstance(v, bool):
                v = canonicalize_bool_to_str(v)
            elif is_number(v):
                v = str(v)

            params[f"context.authorizer.{k.lower()}"] = v

        if context.data:
            params["method.request.body"] = context.data

        return {key.lower(): val for key, val in params.items()}


class ResponseParametersResolver:
    def resolve(self, context: ApiInvocationContext) -> Dict[str, str]:
        """
        Resolve integration response parameters into method response parameters.
        Integration response parameters can map header, body,
        or static values to the header type of the method response.

        :return: dict with all method response parameters and their values
        """
        integration_request_params: Dict[str, Any] = self.integration_request_dict(context)

        # "responseParameters" : {
        #     "method.response.header.Location" : "integration.response.body.redirect.url",
        #     "method.response.header.x-user-id" : "integration.response.header.x-userid"
        # }
        integration_responses = context.integration.get("integrationResponses", {})
        # XXX Fix for other status codes context.response contains a response status code, but response
        # can be a LambdaResponse or Response object and the field is not the same, normalize it or use introspection
        response_params = integration_responses.get("200", {}).get("responseParameters", {})

        # resolve all integration request parameters with the already resolved method
        # request parameters
        method_parameters = {}
        for k, v in response_params.items():
            if v.lower() in integration_request_params:
                method_parameters[k] = integration_request_params[v.lower()]
            else:
                # static values
                method_parameters[k] = v.replace("'", "")

        # build the integration parameters
        result: Dict[str, str] = {}
        for k, v in method_parameters.items():
            # headers
            if k.startswith("method.response.header."):
                header_name = k.split(".")[-1]
                result[header_name] = v

        return result

    def integration_request_dict(self, context: ApiInvocationContext) -> Dict[str, Any]:
        params: Dict[str, str] = {}

        for k, v in context.headers.items():
            params[f"integration.request.header.{k}"] = v

        if context.data:
            params["integration.request.body"] = try_json(context.data)

        return {key.lower(): val for key, val in params.items()}


def make_json_response(message):
    return requests_response(json.dumps(message), headers={"Content-Type": APPLICATION_JSON})


def make_error_response(message, code=400, error_type=None):
    if code == 404 and not error_type:
        error_type = "NotFoundException"
    error_type = error_type or "InvalidRequest"
    return requests_error_response_json(message, code=code, error_type=error_type)


def select_integration_response(matched_part: str, invocation_context: ApiInvocationContext):
    int_responses = invocation_context.integration.get("integrationResponses") or {}
    if select_by_pattern := [
        response
        for response in int_responses.values()
        if response.get("selectionPattern")
        and re.match(response.get("selectionPattern"), matched_part)
    ]:
        selected_response = select_by_pattern[0]
        if len(select_by_pattern) > 1:
            LOG.warning(
                "Multiple integration responses matching '%s' statuscode. Choosing '%s' (first).",
                matched_part,
                selected_response["statusCode"],
            )
    else:
        # choose default return code
        default_responses = [
            response for response in int_responses.values() if not response.get("selectionPattern")
        ]
        if not default_responses:
            raise ApiGatewayIntegrationError("Internal server error", 500)

        selected_response = default_responses[0]
        if len(default_responses) > 1:
            LOG.warning(
                "Multiple default integration responses. Choosing %s (first).",
                selected_response["statusCode"],
            )
    return selected_response


def make_accepted_response():
    response = Response()
    response.status_code = 202
    return response


def get_api_id_from_path(path):
    if match := re.match(PATH_REGEX_SUB, path):
        return match.group(1)
    return re.match(PATH_REGEX_MAIN, path).group(1)


def is_test_invoke_method(method, path):
    return method == "POST" and bool(re.match(PATH_REGEX_TEST_INVOKE_API, path))


def get_stage_variables(context: ApiInvocationContext) -> Optional[Dict[str, str]]:
    if is_test_invoke_method(context.method, context.path):
        return None

    if not context.stage:
        return {}

    account_id, region_name = get_api_account_id_and_region(context.api_id)
    api_gateway_client = connect_to(
        aws_access_key_id=account_id, region_name=region_name
    ).apigateway
    try:
        response = api_gateway_client.get_stage(restApiId=context.api_id, stageName=context.stage)
        return response.get("variables", {})
    except Exception:
        LOG.info("Failed to get stage %s for API id %s", context.stage, context.api_id)
        return {}


def tokenize_path(path):
    return path.lstrip("/").split("/")


def extract_path_params(path: str, extracted_path: str) -> Dict[str, str]:
    tokenized_extracted_path = tokenize_path(extracted_path)
    # Looks for '{' in the tokenized extracted path
    path_params_list = [(i, v) for i, v in enumerate(tokenized_extracted_path) if "{" in v]
    tokenized_path = tokenize_path(path)
    path_params = {}
    for param in path_params_list:
        path_param_name = param[1][1:-1]
        path_param_position = param[0]
        if path_param_name.endswith("+"):
            path_params[path_param_name.rstrip("+")] = "/".join(
                tokenized_path[path_param_position:]
            )
        else:
            path_params[path_param_name] = tokenized_path[path_param_position]
    path_params = common.json_safe(path_params)
    return path_params


def extract_query_string_params(path: str) -> Tuple[str, Dict[str, str]]:
    parsed_path = urlparse.urlparse(path)
    if not path.startswith("//"):
        path = parsed_path.path
    parsed_query_string_params = urlparse.parse_qs(parsed_path.query)

    query_string_params = {}
    for query_param_name, query_param_values in parsed_query_string_params.items():
        if len(query_param_values) == 1:
            query_string_params[query_param_name] = query_param_values[0]
        else:
            query_string_params[query_param_name] = query_param_values

    path = path or "/"
    return path, query_string_params


def get_cors_response(headers):
    # TODO: for now we simply return "allow-all" CORS headers, but in the future
    # we should implement custom headers for CORS rules, as supported by API Gateway:
    # http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html
    response = Response()
    response.status_code = 200
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response._content = ""
    return response


def get_apigateway_path_for_resource(
    api_id, resource_id, path_suffix="", resources=None, region_name=None
):
    if resources is None:
        apigateway = connect_to(region_name=region_name).apigateway
        resources = apigateway.get_resources(restApiId=api_id, limit=100)["items"]
    target_resource = list(filter(lambda res: res["id"] == resource_id, resources))[0]
    path_part = target_resource.get("pathPart", "")
    if path_suffix:
        if path_part:
            path_suffix = "%s/%s" % (path_part, path_suffix)
    else:
        path_suffix = path_part
    parent_id = target_resource.get("parentId")
    if not parent_id:
        return "/%s" % path_suffix
    return get_apigateway_path_for_resource(
        api_id,
        parent_id,
        path_suffix=path_suffix,
        resources=resources,
        region_name=region_name,
    )


def get_rest_api_paths(account_id: str, region_name: str, rest_api_id: str):
    apigateway = connect_to(aws_access_key_id=account_id, region_name=region_name).apigateway
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources["items"]:
        path = resource.get("path")
        # TODO: check if this is still required in the general case (can we rely on "path" being
        #  present?)
        path = path or get_apigateway_path_for_resource(
            rest_api_id, resource["id"], region_name=region_name
        )
        resource_map[path] = resource
    return resource_map


# TODO: Extract this to a set of rules that have precedence and easy to test individually.
#
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings
#  -method-request.html
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html
def get_resource_for_path(
    path: str, method: str, path_map: Dict[str, Dict]
) -> tuple[Optional[str], Optional[dict]]:
    matches = []
    # creates a regex from the input path if there are parameters, e.g /foo/{bar}/baz -> /foo/[
    # ^\]+/baz, otherwise is a direct match.
    for api_path, details in path_map.items():
        api_path_regex = re.sub(r"{[^+]+\+}", r"[^\?#]+", api_path)
        api_path_regex = re.sub(r"{[^}]+}", r"[^/]+", api_path_regex)
        if re.match(r"^%s$" % api_path_regex, path):
            matches.append((api_path, details))

    # if there are no matches, it's not worth to proceed, bail here!
    if not matches:
        LOG.debug("No match found for path: '%s' and method: '%s'", path, method)
        return None, None

    if len(matches) == 1:
        LOG.debug("Match found for path: '%s' and method: '%s'", path, method)
        return matches[0]

    # so we have more than one match
    # /{proxy+} and /api/{proxy+} for inputs like /api/foo/bar
    # /foo/{param1}/baz and /foo/{param1}/{param2} for inputs like /for/bar/baz
    proxy_matches = []
    param_matches = []
    for match in matches:
        match_methods = list(match[1].get("resourceMethods", {}).keys())
        # only look for path matches if the request method is in the resource
        if method.upper() in match_methods or "ANY" in match_methods:
            # check if we have an exact match (exact matches take precedence) if the method is the same
            if match[0] == path:
                return match

            elif path_matches_pattern(path, match[0]):
                # parameters can fit in
                param_matches.append(match)
                continue

            proxy_matches.append(match)

    if param_matches:
        # count the amount of parameters, return the one with the least which is the most precise
        sorted_matches = sorted(param_matches, key=lambda x: x[0].count("{"))
        LOG.debug("Match found for path: '%s' and method: '%s'", path, method)
        return sorted_matches[0]

    if proxy_matches:
        # at this stage, we still have more than one match, but we have an eager example like
        # /{proxy+} or /api/{proxy+}, so we pick the best match by sorting by length, only if they have a method
        # that could match
        sorted_matches = sorted(proxy_matches, key=lambda x: len(x[0]), reverse=True)
        LOG.debug("Match found for path: '%s' and method: '%s'", path, method)
        return sorted_matches[0]

    # if there are no matches with a method that would match, return
    LOG.debug("No match found for method: '%s' for matched path: %s", method, path)
    return None, None


def path_matches_pattern(path, api_path):
    api_paths = api_path.split("/")
    paths = path.split("/")
    reg_check = re.compile(r"{(.*)}")
    if len(api_paths) != len(paths):
        return False
    results = [
        part == paths[indx]
        for indx, part in enumerate(api_paths)
        if reg_check.match(part) is None and part
    ]

    return len(results) > 0 and all(results)


def connect_api_gateway_to_sqs(gateway_name, stage_name, queue_arn, path, account_id, region_name):
    resources = {}
    template = APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE
    resource_path = path.replace("/", "")

    try:
        arn = parse_arn(queue_arn)
        queue_name = arn["resource"]
        sqs_account = arn["account"]
        sqs_region = arn["region"]
    except InvalidArnException:
        queue_name = queue_arn
        sqs_account = account_id
        sqs_region = region_name

    partition = get_partition(region_name)
    resources[resource_path] = [
        {
            "httpMethod": "POST",
            "authorizationType": "NONE",
            "integrations": [
                {
                    "type": "AWS",
                    "uri": "arn:%s:apigateway:%s:sqs:path/%s/%s"
                    % (partition, sqs_region, sqs_account, queue_name),
                    "requestTemplates": {"application/json": template},
                    "requestParameters": {
                        "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"
                    },
                }
            ],
        }
    ]
    return resource_utils.create_api_gateway(
        name=gateway_name,
        resources=resources,
        stage_name=stage_name,
        client=connect_to(aws_access_key_id=sqs_account, region_name=sqs_region).apigateway,
    )


def get_target_resource_details(
    invocation_context: ApiInvocationContext,
) -> Tuple[Optional[str], Optional[dict]]:
    """Look up and return the API GW resource (path pattern + resource dict) for the given invocation context."""
    path_map = get_rest_api_paths(
        account_id=invocation_context.account_id,
        region_name=invocation_context.region_name,
        rest_api_id=invocation_context.api_id,
    )
    relative_path = invocation_context.invocation_path.rstrip("/") or "/"
    try:
        extracted_path, resource = get_resource_for_path(
            path=relative_path, method=invocation_context.method, path_map=path_map
        )
        if not extracted_path:
            return None, None
        invocation_context.resource = resource
        invocation_context.resource_path = extracted_path
        try:
            invocation_context.path_params = extract_path_params(
                path=relative_path, extracted_path=extracted_path
            )
        except Exception:
            invocation_context.path_params = {}

        return extracted_path, resource

    except Exception:
        return None, None


def get_target_resource_method(invocation_context: ApiInvocationContext) -> Optional[Dict]:
    """Look up and return the API GW resource method for the given invocation context."""
    _, resource = get_target_resource_details(invocation_context)
    if not resource:
        return None
    methods = resource.get("resourceMethods") or {}
    return methods.get(invocation_context.method.upper()) or methods.get("ANY")


def event_type_from_route_key(invocation_context):
    action = invocation_context.route["RouteKey"]
    return (
        "CONNECT"
        if action == "$connect"
        else "DISCONNECT"
        if action == "$disconnect"
        else "MESSAGE"
    )


def get_event_request_context(invocation_context: ApiInvocationContext):
    method = invocation_context.method
    path = invocation_context.path
    headers = invocation_context.headers
    integration_uri = invocation_context.integration_uri
    resource_path = invocation_context.resource_path
    resource_id = invocation_context.resource_id

    set_api_id_stage_invocation_path(invocation_context)
    api_id = invocation_context.api_id
    stage = invocation_context.stage

    if "_user_request_" in invocation_context.raw_uri:
        full_path = invocation_context.raw_uri.partition("_user_request_")[2]
    else:
        full_path = invocation_context.raw_uri.removeprefix(f"/{stage}")
    relative_path, query_string_params = extract_query_string_params(path=full_path)

    source_ip = invocation_context.auth_identity.get("sourceIp")
    integration_uri = integration_uri or ""
    account_id = integration_uri.split(":lambda:path")[-1].split(":function:")[0].split(":")[-1]
    account_id = account_id or DEFAULT_AWS_ACCOUNT_ID
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
        "requestTime": datetime.now(timezone.utc).strftime(REQUEST_TIME_DATE_FORMAT),
        "requestTimeEpoch": int(time.time() * 1000),
        "authorizer": {},
    }

    if invocation_context.is_websocket_request():
        request_context["connectionId"] = invocation_context.connection_id

    # set "authorizer" and "identity" event attributes from request context
    authorizer_result = invocation_context.authorizer_result
    if authorizer_result:
        request_context["authorizer"] = authorizer_result
    request_context["identity"].update(invocation_context.auth_identity or {})

    if not is_test_invoke_method(method, path):
        request_context["path"] = (f"/{stage}" if stage else "") + relative_path
        request_context["stage"] = stage
    return request_context


def set_api_id_stage_invocation_path(
    invocation_context: ApiInvocationContext,
) -> ApiInvocationContext:
    # skip if all details are already available
    values = (
        invocation_context.api_id,
        invocation_context.stage,
        invocation_context.path_with_query_string,
    )
    if all(values):
        return invocation_context

    # skip if this is a websocket request
    if invocation_context.is_websocket_request():
        return invocation_context

    path = invocation_context.path
    headers = invocation_context.headers

    path_match = re.search(PATH_REGEX_USER_REQUEST, path)
    host_header = headers.get(HEADER_LOCALSTACK_EDGE_URL, "") or headers.get("Host") or ""
    host_match = re.search(HOST_REGEX_EXECUTE_API, host_header)
    test_invoke_match = re.search(PATH_REGEX_TEST_INVOKE_API, path)
    if path_match:
        api_id = path_match.group(1)
        stage = path_match.group(2)
        relative_path_w_query_params = "/%s" % path_match.group(3)
    elif host_match:
        api_id = extract_api_id_from_hostname_in_url(host_header)
        stage = path.strip("/").split("/")[0]
        relative_path_w_query_params = "/%s" % path.lstrip("/").partition("/")[2]
    elif test_invoke_match:
        stage = invocation_context.stage
        api_id = invocation_context.api_id
        relative_path_w_query_params = invocation_context.path_with_query_string
    else:
        raise Exception(
            f"Unable to extract API Gateway details from request: {path} {dict(headers)}"
        )

    # set details in invocation context
    invocation_context.api_id = api_id
    invocation_context.stage = stage
    invocation_context.path_with_query_string = relative_path_w_query_params
    return invocation_context


def get_api_account_id_and_region(api_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Return the region name for the given REST API ID"""
    for account_id, account in apigateway_backends.items():
        for region_name, region in account.items():
            # compare low case keys to avoid case sensitivity issues
            for key in region.apis.keys():
                if key.lower() == api_id.lower():
                    return account_id, region_name
    return None, None


def extract_api_id_from_hostname_in_url(hostname: str) -> str:
    """Extract API ID 'id123' from URLs like https://id123.execute-api.localhost.localstack.cloud:4566"""
    match = re.match(HOST_REGEX_EXECUTE_API, hostname)
    return match.group(1)


def multi_value_dict_for_list(elements: Union[List, Dict]) -> Dict:
    temp_mv_dict = defaultdict(list)
    for key in elements:
        if isinstance(key, (list, tuple)):
            key, value = key
        else:
            value = elements[key]

        key = to_str(key)
        temp_mv_dict[key].append(value)
    return {k: tuple(v) for k, v in temp_mv_dict.items()}
