import contextlib
import datetime
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib import parse as urlparse

import pytz
from apispec import APISpec
from botocore.utils import InvalidArnException
from jsonpatch import apply_patch
from jsonpointer import JsonPointerException
from moto.apigateway.models import Authorizer, Integration, Resource, RestAPI, apigateway_backends
from moto.apigateway.utils import create_id as create_resource_id
from requests.models import Response

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import (
    APPLICATION_JSON,
    HEADER_LOCALSTACK_EDGE_URL,
    LOCALHOST_HOSTNAME,
    PATH_USER_REQUEST,
)
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.models import ApiGatewayStore, apigateway_stores
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import requests_error_response_json, requests_response
from localstack.utils.aws.aws_stack import parse_arn
from localstack.utils.aws.request_context import MARKER_APIGW_REQUEST_REGION, THREAD_LOCAL
from localstack.utils.strings import long_uid
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp

LOG = logging.getLogger(__name__)

REQUEST_TIME_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# regex path pattern for user requests, handles stages like $default
PATH_REGEX_USER_REQUEST = (
    r"^/restapis/([A-Za-z0-9_\\-]+)(?:/([A-Za-z0-9\_($|%%24)\\-]+))?/%s/(.*)$" % PATH_USER_REQUEST
)
# URL pattern for invocations
HOST_REGEX_EXECUTE_API = r"(?:.*://)?([a-zA-Z0-9-]+)\.execute-api\.(localhost.localstack.cloud|([^\.]+)\.amazonaws\.com)(.*)"

# regex path patterns
PATH_REGEX_MAIN = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+(\?.*)?"
PATH_REGEX_SUB = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*"

# path regex patterns
PATH_REGEX_AUTHORIZERS = r"^/restapis/([A-Za-z0-9_\-]+)/authorizers/?([^?/]+)?(\?.*)?"
PATH_REGEX_VALIDATORS = r"^/restapis/([A-Za-z0-9_\-]+)/requestvalidators/?([^?/]+)?(\?.*)?"
PATH_REGEX_RESPONSES = r"^/restapis/([A-Za-z0-9_\-]+)/gatewayresponses(/[A-Za-z0-9_\-]+)?(\?.*)?"
PATH_REGEX_DOC_PARTS = r"^/restapis/([A-Za-z0-9_\-]+)/documentation/parts/?([^?/]+)?(\?.*)?"
PATH_REGEX_PATH_MAPPINGS = r"/domainnames/([^/]+)/basepathmappings/?(.*)"
PATH_REGEX_CLIENT_CERTS = r"/clientcertificates/?([^/]+)?$"
PATH_REGEX_VPC_LINKS = r"/vpclinks/([^/]+)?(.*)"
PATH_REGEX_TEST_INVOKE_API = r"^\/restapis\/([A-Za-z0-9_\-]+)\/resources\/([A-Za-z0-9_\-]+)\/methods\/([A-Za-z0-9_\-]+)/?(\?.*)?"

# template for SQS inbound data
APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE = (
    "Action=SendMessage&MessageBody=$util.base64Encode($input.json('$'))"
)

# special tag name to allow specifying a custom ID for new REST APIs
TAG_KEY_CUSTOM_ID = "_custom_id_"

# TODO: make the CRUD operations in this file generic for the different model types (authorizes, validators, ...)


def get_apigateway_store(account_id: str = None, region: str = None) -> ApiGatewayStore:
    return apigateway_stores[account_id or get_aws_account_id()][region or aws_stack.get_region()]


class Resolver:
    def __init__(self, document: dict, allow_recursive=True):
        self.document = document
        self.allow_recursive = allow_recursive
        # cache which maps known refs to part of the document
        self._cache = {}
        self._refpaths = ["#"]

    def _is_ref(self, item) -> bool:
        return isinstance(item, dict) and "$ref" in item

    def _is_internal_ref(self, refpath) -> bool:
        return str(refpath).startswith("#/")

    @property
    def current_path(self):
        return self._refpaths[-1]

    @contextlib.contextmanager
    def _pathctx(self, refpath: str):
        if not self._is_internal_ref(refpath):
            refpath = "/".join((self.current_path, refpath))

        self._refpaths.append(refpath)
        yield
        self._refpaths.pop()

    def _resolve_refpath(self, refpath: str) -> dict:
        if refpath in self._refpaths and not self.allow_recursive:
            raise Exception("recursion detected with allow_recursive=False")

        if refpath in self._cache:
            return self._cache.get(refpath)

        with self._pathctx(refpath):
            if self._is_internal_ref(self.current_path):
                cur = self.document
            else:
                raise NotImplementedError("External references not yet supported.")

            for step in self.current_path.split("/")[1:]:
                cur = cur.get(step)

            self._cache[self.current_path] = cur
            return cur

    def _namespaced_resolution(self, namespace: str, data: Union[dict, list]) -> Union[dict, list]:
        with self._pathctx(namespace):
            return self._resolve_references(data)

    def _resolve_references(self, data) -> Union[dict, list]:
        if self._is_ref(data):
            return self._resolve_refpath(data["$ref"])

        if isinstance(data, dict):
            for k, v in data.items():
                data[k] = self._namespaced_resolution(k, v)
        elif isinstance(data, list):
            for i, v in enumerate(data):
                data[i] = self._namespaced_resolution(str(i), v)

        return data

    def resolve_references(self) -> dict:
        return self._resolve_references(self.document)


def resolve_references(data: dict, allow_recursive=True) -> dict:
    resolver = Resolver(data, allow_recursive=allow_recursive)
    return resolver.resolve_references()


def make_json_response(message):
    return requests_response(json.dumps(message), headers={"Content-Type": APPLICATION_JSON})


def make_error_response(message, code=400, error_type=None):
    if code == 404 and not error_type:
        error_type = "NotFoundException"
    error_type = error_type or "InvalidRequest"
    return requests_error_response_json(message, code=code, error_type=error_type)


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

    _, region_name = get_api_account_id_and_region(context.api_id)
    api_gateway_client = aws_stack.connect_to_service("apigateway", region_name=region_name)
    try:
        response = api_gateway_client.get_stage(restApiId=context.api_id, stageName=context.stage)
        return response.get("variables")
    except Exception:
        LOG.info("Failed to get stage %s for API id %s", context.stage, context.api_id)
        return {}


# -----------------------
# GATEWAY RESPONSES APIs
# -----------------------


# TODO: merge with to_response_json(..) above
def gateway_response_to_response_json(item, api_id):
    base_path = "/restapis/%s/gatewayresponses" % api_id
    item["_links"] = {
        "self": {"href": "%s/%s" % (base_path, item["responseType"])},
        "gatewayresponse:put": {
            "href": "%s/{response_type}" % base_path,
            "templated": True,
        },
        "gatewayresponse:update": {"href": "%s/%s" % (base_path, item["responseType"])},
    }
    item["responseParameters"] = item.get("responseParameters", {})
    item["responseTemplates"] = item.get("responseTemplates", {})
    return item


def get_gateway_responses(api_id):
    region_details = get_apigateway_store()
    result = region_details.gateway_responses.get(api_id, [])

    href = "http://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-gatewayresponse-{rel}.html"
    base_path = "/restapis/%s/gatewayresponses" % api_id

    result = {
        "_links": {
            "curies": {"href": href, "name": "gatewayresponse", "templated": True},
            "self": {"href": base_path},
            "first": {"href": base_path},
            "gatewayresponse:by-type": {
                "href": "%s/{response_type}" % base_path,
                "templated": True,
            },
            "item": [{"href": "%s/%s" % (base_path, r["responseType"])} for r in result],
        },
        "_embedded": {"item": [gateway_response_to_response_json(i, api_id) for i in result]},
        # Note: Looks like the format required by aws CLI ("item" at top level) differs from the docs:
        # https://docs.aws.amazon.com/apigateway/api-reference/resource/gateway-responses/
        "item": [gateway_response_to_response_json(i, api_id) for i in result],
    }
    return result


def get_gateway_response(api_id, response_type):
    region_details = get_apigateway_store()
    responses = region_details.gateway_responses.get(api_id, [])
    if result := [r for r in responses if r["responseType"] == response_type]:
        return result[0]
    return make_error_response(
        "Gateway response %s for API Gateway %s not found" % (response_type, api_id),
        code=404,
    )


def put_gateway_response(api_id, response_type, data):
    region_details = get_apigateway_store()
    responses = region_details.gateway_responses.setdefault(api_id, [])
    if existing := ([r for r in responses if r["responseType"] == response_type] or [None])[0]:
        existing.update(data)
    else:
        data["responseType"] = response_type
        responses.append(data)
    return data


def delete_gateway_response(api_id, response_type):
    region_details = get_apigateway_store()
    responses = region_details.gateway_responses.get(api_id) or []
    region_details.gateway_responses[api_id] = [
        r for r in responses if r["responseType"] != response_type
    ]
    return make_accepted_response()


def update_gateway_response(api_id, response_type, data):
    region_details = get_apigateway_store()
    responses = region_details.gateway_responses.setdefault(api_id, [])

    existing = ([r for r in responses if r["responseType"] == response_type] or [None])[0]
    if existing is None:
        return make_error_response(
            "Gateway response %s for API Gateway %s not found" % (response_type, api_id),
            code=404,
        )
    return apply_json_patch_safe(existing, data["patchOperations"])


def handle_gateway_responses(method, path, data, headers):
    search_match = re.search(PATH_REGEX_RESPONSES, path)
    api_id = search_match.group(1)
    response_type = (search_match.group(2) or "").lstrip("/")
    if method == "GET":
        if response_type:
            return get_gateway_response(api_id, response_type)
        return get_gateway_responses(api_id)
    if method == "PUT":
        return put_gateway_response(api_id, response_type, data)
    if method == "PATCH":
        return update_gateway_response(api_id, response_type, data)
    if method == "DELETE":
        return delete_gateway_response(api_id, response_type)
    return make_error_response(
        "Not implemented for API Gateway gateway responses: %s" % method, code=404
    )


# ---------------
# UTIL FUNCTIONS
# ---------------


def find_api_subentity_by_id(api_id, entity_id, map_name):
    region_details = get_apigateway_store()
    auth_list = getattr(region_details, map_name).get(api_id) or []
    return ([a for a in auth_list if a["id"] == entity_id] or [None])[0]


def path_based_url(api_id: str, stage_name: str, path: str) -> str:
    """Return URL for inbound API gateway for given API ID, stage name, and path"""
    pattern = "%s/restapis/{api_id}/{stage_name}/%s{path}" % (
        config.service_url("apigateway"),
        PATH_USER_REQUEST,
    )
    return pattern.format(api_id=api_id, stage_name=stage_name, path=path)


def host_based_url(rest_api_id: str, path: str, stage_name: str = None):
    """Return URL for inbound API gateway for given API ID, stage name, and path with custom dns
    format"""
    pattern = "http://{endpoint}{stage}{path}"
    stage = stage_name and f"/{stage_name}" or ""
    return pattern.format(endpoint=get_execute_api_endpoint(rest_api_id), stage=stage, path=path)


def get_execute_api_endpoint(api_id: str, protocol: str = "") -> str:
    port = config.get_edge_port_http()
    return f"{protocol}{api_id}.execute-api.{LOCALHOST_HOSTNAME}:{port}"


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


def get_rest_api_paths(rest_api_id, region_name=None):
    apigateway = aws_stack.connect_to_service(service_name="apigateway", region_name=region_name)
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources["items"]:
        path = resource.get("path")
        # TODO: check if this is still required in the general case (can we rely on "path" being
        #  present?)
        path = path or aws_stack.get_apigateway_path_for_resource(
            rest_api_id, resource["id"], region_name=region_name
        )
        resource_map[path] = resource
    return resource_map


# TODO: Extract this to a set of rules that have precedence and easy to test individually.
#
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings
#  -method-request.html
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html
def get_resource_for_path(path: str, path_map: Dict[str, Dict]) -> Optional[Tuple[str, dict]]:
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
        return None

    # so we have matches and perhaps more than one, e.g
    # /{proxy+} and /api/{proxy+} for inputs like /api/foo/bar
    # /foo/{param1}/baz and /foo/{param1}/{param2} for inputs like /for/bar/baz
    if len(matches) > 1:
        # check if we have an exact match (exact matches take precedence)
        for match in matches:
            if match[0] == path:
                return match

        # not an exact match but parameters can fit in
        for match in matches:
            if path_matches_pattern(path, match[0]):
                return match

        # at this stage, we have more than one match but we have an eager example like
        # /{proxy+} or /api/{proxy+}, so we pick the best match by sorting by length
        sorted_matches = sorted(matches, key=lambda x: len(x[0]), reverse=True)
        return sorted_matches[0]
    return matches[0]


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


def connect_api_gateway_to_sqs(gateway_name, stage_name, queue_arn, path, region_name=None):
    resources = {}
    template = APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE
    resource_path = path.replace("/", "")
    region_name = region_name or aws_stack.get_region()

    try:
        arn = parse_arn(queue_arn)
        queue_name = arn["resource"]
        sqs_region = arn["region"]
    except InvalidArnException:
        queue_name = queue_arn
        sqs_region = region_name

    resources[resource_path] = [
        {
            "httpMethod": "POST",
            "authorizationType": "NONE",
            "integrations": [
                {
                    "type": "AWS",
                    "uri": "arn:aws:apigateway:%s:sqs:path/%s/%s"
                    % (sqs_region, get_aws_account_id(), queue_name),
                    "requestTemplates": {"application/json": template},
                }
            ],
        }
    ]
    return aws_stack.create_api_gateway(
        name=gateway_name,
        resources=resources,
        stage_name=stage_name,
        region_name=region_name,
    )


def apply_json_patch_safe(subject, patch_operations, in_place=True, return_list=False):
    """Apply JSONPatch operations, using some customizations for compatibility with API GW
    resources."""

    results = []
    patch_operations = (
        [patch_operations] if isinstance(patch_operations, dict) else patch_operations
    )
    for operation in patch_operations:
        try:
            # special case: for "replace" operations, assume "" as the default value
            if operation["op"] == "replace" and operation.get("value") is None:
                operation["value"] = ""

            if operation["op"] != "remove" and operation.get("value") is None:
                LOG.info('Missing "value" in JSONPatch operation for %s: %s', subject, operation)
                continue

            if operation["op"] == "add":
                path = operation["path"]
                target = subject.get(path.strip("/"))
                target = target or common.extract_from_jsonpointer_path(subject, path)
                if not isinstance(target, list):
                    # for "add" operations, we should ensure that the path target is a list instance
                    value = [] if target is None else [target]
                    common.assign_to_path(subject, path, value=value, delimiter="/")
                target = common.extract_from_jsonpointer_path(subject, path)
                if isinstance(target, list) and not path.endswith("/-"):
                    # if "path" is an attribute name pointing to an array in "subject", and we're running
                    # an "add" operation, then we should use the standard-compliant notation "/path/-"
                    operation["path"] = "%s/-" % path

            result = apply_patch(subject, [operation], in_place=in_place)
            if not in_place:
                subject = result
            results.append(result)
        except JsonPointerException:
            pass  # path cannot be found - ignore
        except Exception as e:
            if "non-existent object" in str(e):
                if operation["op"] == "replace":
                    # fall back to an ADD operation if the REPLACE fails
                    operation["op"] = "add"
                    result = apply_patch(subject, [operation], in_place=in_place)
                    results.append(result)
                    continue
                if operation["op"] == "remove" and isinstance(subject, dict):
                    result = subject.pop(operation["path"], None)
                    results.append(result)
                    continue
            raise
    if return_list:
        return results
    return (results or [subject])[-1]


def import_api_from_openapi_spec(rest_api: RestAPI, body: Dict, query_params: Dict) -> RestAPI:
    """Import an API from an OpenAPI spec document"""

    resolved_schema = resolve_references(body)

    # TODO:
    # 1. validate the "mode" property of the spec document, "merge" or "overwrite"
    # 2. validate the document type, "swagger" or "openapi"

    # XXX for some reason this makes cf tests fail that's why is commented.
    # test_cfn_handle_serverless_api_resource
    # rest_api.name = resolved_schema.get("info", {}).get("title")
    rest_api.description = resolved_schema.get("info", {}).get("description")

    # Remove default root, then add paths from API spec
    rest_api.resources = {}

    # authorizers map to avoid duplication
    authorizers = {}

    def create_authorizer(path_payload: dict) -> Authorizer:
        if "security" not in path_payload:
            return None

        security_schemes = path_payload.get("security")
        for security_scheme in security_schemes:
            for security_scheme_name, _ in security_scheme.items():
                if security_scheme_name in body.get("securityDefinitions", []):
                    security_config = body.get("securityDefinitions", {}).get(security_scheme_name)
                    aws_apigateway_authorizer = security_config.get(
                        "x-amazon-apigateway-authorizer", {}
                    )
                    if not aws_apigateway_authorizer:
                        continue

                    if authorizers.get(security_scheme_name):
                        return authorizers.get(security_scheme_name)
                    authorizer = rest_api.create_authorizer(
                        create_resource_id(),
                        name=security_scheme_name,
                        authorizer_type=aws_apigateway_authorizer.get("type"),
                        provider_arns=None,
                        auth_type=security_config.get("x-amazon-apigateway-authtype"),
                        authorizer_uri=aws_apigateway_authorizer.get("authorizerUri"),
                        authorizer_credentials=aws_apigateway_authorizer.get(
                            "authorizerCredentials"
                        ),
                        identity_source=aws_apigateway_authorizer.get("identitySource"),
                        identiy_validation_expression=aws_apigateway_authorizer.get(
                            "identityValidationExpression"
                        ),
                        authorizer_result_ttl=aws_apigateway_authorizer.get(
                            "authorizerResultTtlInSeconds"
                        )
                        or 300,
                    )
                    if authorizer:
                        authorizers.update({security_scheme_name: authorizer})
                    return authorizer

    def get_or_create_path(abs_path: str, base_path: str):
        parts = abs_path.rstrip("/").replace("//", "/").split("/")
        parent_id = ""
        if len(parts) > 1:
            parent_path = "/".join(parts[:-1])
            parent = get_or_create_path(parent_path, base_path=base_path)
            parent_id = parent.id
        if existing := [
            r
            for r in rest_api.resources.values()
            if r.path_part == (parts[-1] or "/") and (r.parent_id or "") == (parent_id or "")
        ]:
            return existing[0]

        # construct relative path (without base path), then add field resources for this path
        rel_path = abs_path.removeprefix(base_path)
        return add_path_methods(rel_path, parts, parent_id=parent_id)

    def add_path_methods(rel_path: str, parts: List[str], parent_id=""):
        child_id = create_resource_id()
        rel_path = rel_path or "/"
        resource = Resource(
            account_id=rest_api.account_id,
            resource_id=child_id,
            region_name=rest_api.region_name,
            api_id=rest_api.id,
            path_part=parts[-1] or "/",
            parent_id=parent_id,
        )

        paths_dict = resolved_schema["paths"]
        method_paths = paths_dict.get(rel_path, {})
        for field, field_schema in method_paths.items():
            if field in [
                "parameters",
                "servers",
                "description",
                "summary",
                "$ref",
            ] or not isinstance(field_schema, dict):
                LOG.warning("Ignoring unsupported field %s in path %s", field, rel_path)
                continue

            field = field.upper()

            method_integration = field_schema.get("x-amazon-apigateway-integration", {})
            method_resource = create_method_resource(resource, field, field_schema)
            method_resource["requestParameters"] = method_integration.get("requestParameters")
            responses = field_schema.get("responses", {})
            for status_code in responses:
                response_model = None
                if model_schema := responses.get(status_code, {}).get("schema", {}):
                    response_model = {APPLICATION_JSON: model_schema}

                response_parameters = (
                    method_integration.get("responses", {})
                    .get("default", {})
                    .get("responseParameters")
                )
                method_resource.create_response(
                    status_code,
                    response_model,
                    response_parameters,
                )

            integration = Integration(
                http_method=field,
                uri=method_integration.get("uri"),
                integration_type=method_integration.get("type"),
                passthrough_behavior=method_integration.get("passthroughBehavior"),
                request_templates=method_integration.get("requestTemplates") or {},
                request_parameters=method_integration.get("requestParameters") or {},
            )
            integration.create_integration_response(
                status_code=method_integration.get("responses", {})
                .get("default", {})
                .get("statusCode", 200),
                selection_pattern=None,
                response_templates=method_integration.get("responses", {})
                .get("default", {})
                .get("responseTemplates", None),
                content_handling=None,
            )
            resource.resource_methods[field]["methodIntegration"] = integration

        rest_api.resources[child_id] = resource
        return resource

    def create_method_resource(child, method, method_schema):
        return (
            child.add_method(
                method,
                authorization_type=authorizer.get("type"),
                api_key_required=None,
                authorizer_id=authorizer.get("id"),
            )
            if (authorizer := create_authorizer(method_schema))
            else child.add_method(method, None, None)
        )

    if definitions := resolved_schema.get("definitions", {}):
        for name, model in definitions.items():
            rest_api.add_model(name=name, schema=model, content_type=APPLICATION_JSON)

    # determine base path
    basepath_mode = (query_params.get("basepath") or ["prepend"])[0]
    base_path = ""
    if basepath_mode == "prepend":
        base_path = resolved_schema.get("basePath") or ""
    if basepath_mode == "split":
        base_path = (resolved_schema.get("basePath") or "").strip("/").split("/")[0]
        base_path = f"/{base_path}" if base_path else ""

    for path in resolved_schema.get("paths", {}):
        get_or_create_path(base_path + path, base_path=base_path)

    policy = resolved_schema.get("x-amazon-apigateway-policy")
    if policy:
        policy = json.dumps(policy) if isinstance(policy, dict) else str(policy)
        rest_api.policy = policy
    minimum_compression_size = resolved_schema.get("x-amazon-apigateway-minimum-compression-size")
    if minimum_compression_size is not None:
        rest_api.minimum_compression_size = int(minimum_compression_size)
    endpoint_config = resolved_schema.get("x-amazon-apigateway-endpoint-configuration")
    if endpoint_config:
        if endpoint_config.get("vpcEndpointIds"):
            endpoint_config.setdefault("types", ["PRIVATE"])
        rest_api.endpoint_configuration = endpoint_config

    return rest_api


def get_target_resource_details(invocation_context: ApiInvocationContext) -> Tuple[str, Dict]:
    """Look up and return the API GW resource (path pattern + resource dict) for the given invocation context."""
    path_map = get_rest_api_paths(
        rest_api_id=invocation_context.api_id, region_name=invocation_context.region_name
    )
    relative_path = invocation_context.invocation_path.rstrip("/") or "/"
    try:
        extracted_path, resource = get_resource_for_path(path=relative_path, path_map=path_map)
        invocation_context.resource = resource
        return extracted_path, resource
    except Exception:
        return None, None


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

    set_api_id_stage_invocation_path(invocation_context)
    relative_path, query_string_params = extract_query_string_params(
        path=invocation_context.path_with_query_string
    )
    api_id = invocation_context.api_id
    stage = invocation_context.stage

    source_ip = headers.get("X-Forwarded-For", ",").split(",")[-2].strip()
    integration_uri = integration_uri or ""
    account_id = integration_uri.split(":lambda:path")[-1].split(":function:")[0].split(":")[-1]
    account_id = account_id or get_aws_account_id()
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
        # special case: fetch the resource details for TestInvokeApi invocations
        stage = None
        region_name = invocation_context.region_name
        api_id = test_invoke_match.group(1)
        resource_id = test_invoke_match.group(2)
        query_string = test_invoke_match.group(4) or ""
        apigateway = aws_stack.connect_to_service(
            service_name="apigateway", region_name=region_name
        )
        resource = apigateway.get_resource(restApiId=api_id, resourceId=resource_id)
        resource_path = resource.get("path")
        relative_path_w_query_params = f"{resource_path}{query_string}"
    else:
        raise Exception(
            f"Unable to extract API Gateway details from request: {path} {dict(headers)}"
        )
    if api_id:
        # set current region in request thread local, to ensure aws_stack.get_region() works properly
        # TODO: replace with RequestContextManager
        if getattr(THREAD_LOCAL, "request_context", None) is not None:
            _, api_region = get_api_account_id_and_region(api_id)
            THREAD_LOCAL.request_context.headers[MARKER_APIGW_REQUEST_REGION] = api_region

    # set details in invocation context
    invocation_context.api_id = api_id
    invocation_context.stage = stage
    invocation_context.path_with_query_string = relative_path_w_query_params
    return invocation_context


def get_api_account_id_and_region(api_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Return the region name for the given REST API ID"""
    for account_id, account in apigateway_backends.items():
        for region_name, region in account.items():
            if api_id in region.apis:
                return (account_id, region_name)

    return (None, None)


def extract_api_id_from_hostname_in_url(hostname: str) -> str:
    """Extract API ID 'id123' from URLs like https://id123.execute-api.localhost.localstack.cloud:4566"""
    match = re.match(HOST_REGEX_EXECUTE_API, hostname)
    return match.group(1)


# This need to be extended to handle mappings and not just literal values.
def create_invocation_headers(invocation_context: ApiInvocationContext) -> Dict[str, Any]:
    headers = invocation_context.headers
    integration = invocation_context.integration

    if request_parameters := integration.get("requestParameters"):
        for req_parameter_key, req_parameter_value in request_parameters.items():
            if (
                header_name := req_parameter_key.lstrip("integration.request.header.")
                if "integration.request.header." in req_parameter_key
                else None
            ):
                headers.update({header_name: req_parameter_value})
    return headers


# TODO:
# - handle extensions
#

TypeExporter = Callable[[str, str, str], str]


class OpenApiExporter:
    SWAGGER_VERSION = "2.0"
    OPENAPI_VERSION = "3.0.1"

    exporters: Dict[str, TypeExporter]

    def __init__(self):
        self.exporters = {"swagger": self._swagger_export, "oas3": self._oas3_export}
        self.export_formats = {"application/json": "to_dict", "application/yaml": "to_yaml"}

    def export_api(
        self, api_id: str, stage: str, export_type: str, export_format: str = "application/json"
    ) -> str:
        return self.exporters.get(export_type)(api_id, stage, export_format)

    @classmethod
    def _add_paths(cls, spec, resources):
        for item in resources.get("items"):
            path = item.get("path")
            for method, method_config in item.get("resourceMethods").items():
                method = method.lower()
                integration_responses = (
                    method_config.get("methodIntegration", {})
                    .get("integrationResponses", {})
                    .keys()
                )
                responses = dict.fromkeys(integration_responses, {})
                spec.path(path=path, operations={method: {"responses": responses}})

    def _swagger_export(self, api_id: str, stage: str, export_format: str) -> str:
        """
        https://github.com/OAI/OpenAPI-Specification/blob/main/versions/2.0.md
        """
        apigateway_client = aws_stack.connect_to_service("apigateway")

        rest_api = apigateway_client.get_rest_api(restApiId=api_id)
        resources = apigateway_client.get_resources(restApiId=api_id)

        spec = APISpec(
            title=rest_api.get("name"),
            version=timestamp(rest_api.get("createdDate"), format=TIMESTAMP_FORMAT_TZ),
            info=dict(description=rest_api.get("description")),
            openapi_version=self.SWAGGER_VERSION,
            basePath=f"/{stage}",
        )

        self._add_paths(spec, resources)

        return getattr(spec, self.export_formats.get(export_format))()

    def _oas3_export(self, api_id: str, stage: str, export_format: str) -> str:
        """
        https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.1.0.md
        """
        apigateway_client = aws_stack.connect_to_service("apigateway")

        rest_api = apigateway_client.get_rest_api(restApiId=api_id)
        resources = apigateway_client.get_resources(restApiId=api_id)

        spec = APISpec(
            title=rest_api.get("name"),
            version=timestamp(rest_api.get("createdDate"), format=TIMESTAMP_FORMAT_TZ),
            info=dict(description=rest_api.get("description")),
            openapi_version=self.OPENAPI_VERSION,
        )

        self._add_paths(spec, resources)

        return getattr(spec, self.export_formats.get(export_format))()
