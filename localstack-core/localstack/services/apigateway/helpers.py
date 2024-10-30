import contextlib
import copy
import hashlib
import json
import logging
from datetime import datetime
from typing import List, Optional, Union
from urllib import parse as urlparse

from jsonpatch import apply_patch
from jsonpointer import JsonPointerException
from moto.apigateway import models as apigw_models
from moto.apigateway.models import APIGatewayBackend, Integration, Resource
from moto.apigateway.models import RestAPI as MotoRestAPI
from moto.apigateway.utils import ApigwAuthorizerIdentifier, ApigwResourceIdentifier

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.apigateway import (
    Authorizer,
    ConnectionType,
    DocumentationPart,
    DocumentationPartLocation,
    IntegrationType,
    Model,
    NotFoundException,
    RequestValidator,
)
from localstack.constants import (
    APPLICATION_JSON,
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
    PATH_USER_REQUEST,
)
from localstack.services.apigateway.legacy.context import ApiInvocationContext
from localstack.services.apigateway.models import (
    ApiGatewayStore,
    RestApiContainer,
    apigateway_stores,
)
from localstack.utils import common
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

REQUEST_TIME_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

INVOKE_TEST_LOG_TEMPLATE = """Execution log for request {request_id}
        {formatted_date} : Starting execution for request: {request_id}
        {formatted_date} : HTTP Method: {http_method}, Resource Path: {resource_path}
        {formatted_date} : Method request path: {request_path}
        {formatted_date} : Method request query string: {query_string}
        {formatted_date} : Method request headers: {request_headers}
        {formatted_date} : Method request body before transformations: {request_body}
        {formatted_date} : Method response body after transformations: {response_body}
        {formatted_date} : Method response headers: {response_headers}
        {formatted_date} : Successfully completed execution
        {formatted_date} : Method completed with status: {status_code}
        """


EMPTY_MODEL = "Empty"
ERROR_MODEL = "Error"


# TODO: we could actually parse the schema to get TypedDicts with the proper schema/types for each properties
class OpenAPIExt:
    """
    Represents the specific OpenAPI extensions for API Gateway
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions.html
    """

    ANY_METHOD = "x-amazon-apigateway-any-method"
    CORS = "x-amazon-apigateway-cors"
    API_KEY_SOURCE = "x-amazon-apigateway-api-key-source"
    AUTH = "x-amazon-apigateway-auth"
    AUTHORIZER = "x-amazon-apigateway-authorizer"
    AUTHTYPE = "x-amazon-apigateway-authtype"
    BINARY_MEDIA_TYPES = "x-amazon-apigateway-binary-media-types"
    DOCUMENTATION = "x-amazon-apigateway-documentation"
    ENDPOINT_CONFIGURATION = "x-amazon-apigateway-endpoint-configuration"
    GATEWAY_RESPONSES = "x-amazon-apigateway-gateway-responses"
    IMPORTEXPORT_VERSION = "x-amazon-apigateway-importexport-version"
    INTEGRATION = "x-amazon-apigateway-integration"
    INTEGRATIONS = "x-amazon-apigateway-integrations"  # used in components
    MINIMUM_COMPRESSION_SIZE = "x-amazon-apigateway-minimum-compression-size"
    POLICY = "x-amazon-apigateway-policy"
    REQUEST_VALIDATOR = "x-amazon-apigateway-request-validator"
    REQUEST_VALIDATORS = "x-amazon-apigateway-request-validators"
    TAG_VALUE = "x-amazon-apigateway-tag-value"


# TODO: make the CRUD operations in this file generic for the different model types (authorizes, validators, ...)


def get_apigateway_store(context: RequestContext) -> ApiGatewayStore:
    return apigateway_stores[context.account_id][context.region]


def get_apigateway_store_for_invocation(context: ApiInvocationContext) -> ApiGatewayStore:
    account_id = context.account_id or DEFAULT_AWS_ACCOUNT_ID
    region_name = context.region_name or AWS_REGION_US_EAST_1
    return apigateway_stores[account_id][region_name]


def get_moto_backend(account_id: str, region: str) -> APIGatewayBackend:
    return apigw_models.apigateway_backends[account_id][region]


def get_moto_rest_api(context: RequestContext, rest_api_id: str) -> MotoRestAPI:
    moto_backend = apigw_models.apigateway_backends[context.account_id][context.region]
    if rest_api := moto_backend.apis.get(rest_api_id):
        return rest_api
    else:
        raise NotFoundException(
            f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
        )


def get_rest_api_container(context: RequestContext, rest_api_id: str) -> RestApiContainer:
    store = get_apigateway_store(context=context)
    if not (rest_api_container := store.rest_apis.get(rest_api_id)):
        raise NotFoundException(
            f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
        )
    return rest_api_container


class OpenAPISpecificationResolver:
    def __init__(self, document: dict, rest_api_id: str, allow_recursive=True):
        self.document = document
        self.allow_recursive = allow_recursive
        # cache which maps known refs to part of the document
        self._cache = {}
        self._refpaths = ["#"]
        host_definition = localstack_host()
        self._base_url = f"{config.get_protocol()}://apigateway.{host_definition.host_and_port()}/restapis/{rest_api_id}/models/"

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

        # We don't resolve the Model definition, we will return a absolute reference to the model like AWS
        # When validating the schema, we will need to resolve the $ref there
        # Because if we resolved all $ref in schema, it can lead to circular references in complex schemas
        if self.current_path.startswith("#/definitions") or self.current_path.startswith(
            "#/components/schemas"
        ):
            return {"$ref": f"{self._base_url}{refpath.rsplit('/', maxsplit=1)[-1]}"}

        # We should not resolve the Model either, because we need its name to set it to the Request/ResponseModels,
        # it just makes our job more difficult to retrieve the Model name
        # We still need to verify that the ref exists
        is_schema = self.current_path.endswith("schema")

        if refpath in self._cache and not is_schema:
            return self._cache.get(refpath)

        with self._pathctx(refpath):
            if self._is_internal_ref(self.current_path):
                cur = self.document
            else:
                raise NotImplementedError("External references not yet supported.")

            for step in self.current_path.split("/")[1:]:
                cur = cur.get(step)

            self._cache[self.current_path] = cur

            if is_schema:
                # If the $ref doesn't exist in our schema, return None, otherwise return the ref
                return {"$ref": refpath} if cur else None

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


class ModelResolver:
    """
    This class allows a Model to use recursive and circular references to other Models.
    To be able to JSON dump Models, AWS will not resolve Models but will use their absolute $ref instead.
    When validating, we need to resolve those references, using JSON schema tricks to allow recursion.
    See: https://json-schema.org/understanding-json-schema/structuring.html#recursion

    To allow a simpler structure, we're not replacing directly the reference with the schema, but instead create
    a map of all used schema in $defs, as advised on JSON schema:
    See: https://json-schema.org/understanding-json-schema/structuring.html#defs

    This allows us to not render every sub schema/models, but instead keep a clean map of used schemas.
    """

    def __init__(self, rest_api_container: RestApiContainer, model_name: str):
        self.rest_api_container = rest_api_container
        self.model_name = model_name
        self._deps = {}
        self._current_resolving_name = None

    @contextlib.contextmanager
    def _resolving_ctx(self, current_resolving_name: str):
        self._current_resolving_name = current_resolving_name
        yield
        self._current_resolving_name = None

    def resolve_model(self, model: dict) -> dict | None:
        resolved_model = copy.deepcopy(model)
        model_names = set()

        def _look_for_ref(sub_model):
            for key, value in sub_model.items():
                if key == "$ref":
                    ref_name = value.rsplit("/", maxsplit=1)[-1]
                    if ref_name == self.model_name:
                        # if we reference our main Model, use the # for recursive access
                        sub_model[key] = "#"
                        continue
                    # otherwise, this Model will be available in $defs
                    sub_model[key] = f"#/$defs/{ref_name}"

                    if ref_name != self._current_resolving_name:
                        # add the ref to the next ref to resolve and to $deps
                        model_names.add(ref_name)

                elif isinstance(value, dict):
                    _look_for_ref(value)
                elif isinstance(value, list):
                    for val in value:
                        if isinstance(val, dict):
                            _look_for_ref(val)

        if isinstance(resolved_model, dict):
            _look_for_ref(resolved_model)

        if model_names:
            for ref_model_name in model_names:
                if ref_model_name in self._deps:
                    continue

                def_resolved, was_resolved = self._get_resolved_submodel(model_name=ref_model_name)

                if not def_resolved:
                    LOG.debug(
                        "Failed to resolve submodel %s for model %s",
                        ref_model_name,
                        self._current_resolving_name,
                    )
                    return
                # if the ref was already resolved, we copy the result to not alter the already resolved schema
                if was_resolved:
                    def_resolved = copy.deepcopy(def_resolved)

                self._remove_self_ref(def_resolved)

                if "$deps" in def_resolved:
                    # this will happen only if the schema was already resolved, otherwise the deps would be in _deps
                    # remove own definition in case of recursive / circular Models
                    def_resolved["$defs"].pop(self.model_name, None)
                    # remove the $defs from the schema, we don't want nested $defs
                    def_resolved_defs = def_resolved.pop("$defs")
                    # merge the resolved sub model $defs to the main schema
                    self._deps.update(def_resolved_defs)

                # add the dependencies to the global $deps
                self._deps[ref_model_name] = def_resolved

        return resolved_model

    def _remove_self_ref(self, resolved_schema: dict):
        for key, value in resolved_schema.items():
            if key == "$ref":
                ref_name = value.rsplit("/", maxsplit=1)[-1]
                if ref_name == self.model_name:
                    resolved_schema[key] = "#"

            elif isinstance(value, dict):
                self._remove_self_ref(value)

    def get_resolved_model(self) -> dict | None:
        if not (resolved_model := self.rest_api_container.resolved_models.get(self.model_name)):
            model = self.rest_api_container.models.get(self.model_name)
            if not model:
                return None
            schema = json.loads(model["schema"])
            resolved_model = self.resolve_model(schema)
            if not resolved_model:
                return None
            # attach the resolved dependencies of the schema
            if self._deps:
                resolved_model["$defs"] = self._deps
            self.rest_api_container.resolved_models[self.model_name] = resolved_model

        return resolved_model

    def _get_resolved_submodel(self, model_name: str) -> tuple[dict | None, bool | None]:
        was_resolved = True
        if not (resolved_model := self.rest_api_container.resolved_models.get(model_name)):
            was_resolved = False
            model = self.rest_api_container.models.get(model_name)
            if not model:
                LOG.warning(
                    "Error while validating the request body, could not the find the Model: '%s'",
                    model_name,
                )
                return None, was_resolved
            schema = json.loads(model["schema"])

            with self._resolving_ctx(model_name):
                resolved_model = self.resolve_model(schema)

        return resolved_model, was_resolved


def resolve_references(data: dict, rest_api_id, allow_recursive=True) -> dict:
    resolver = OpenAPISpecificationResolver(
        data, allow_recursive=allow_recursive, rest_api_id=rest_api_id
    )
    return resolver.resolve_references()


# ---------------
# UTIL FUNCTIONS
# ---------------


def path_based_url(api_id: str, stage_name: str, path: str) -> str:
    """Return URL for inbound API gateway for given API ID, stage name, and path"""
    pattern = "%s/restapis/{api_id}/{stage_name}/%s{path}" % (
        config.external_service_url(),
        PATH_USER_REQUEST,
    )
    return pattern.format(api_id=api_id, stage_name=stage_name, path=path)


def localstack_path_based_url(api_id: str, stage_name: str, path: str) -> str:
    """Return URL for inbound API gateway for given API ID, stage name, and path on the _aws namespace"""
    return f"{config.external_service_url()}/_aws/execute-api/{api_id}/{stage_name}{path}"


def host_based_url(rest_api_id: str, path: str, stage_name: str = None):
    """Return URL for inbound API gateway for given API ID, stage name, and path with custom dns
    format"""
    pattern = "{endpoint}{stage}{path}"
    stage = stage_name and f"/{stage_name}" or ""
    return pattern.format(endpoint=get_execute_api_endpoint(rest_api_id), stage=stage, path=path)


def get_execute_api_endpoint(api_id: str, protocol: str | None = None) -> str:
    host = localstack_host()
    protocol = protocol or config.get_protocol()
    return f"{protocol}://{api_id}.execute-api.{host.host_and_port()}"


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
                    # for `add` operation, if the target does not exist, set it to an empty dict (default behaviour)
                    # previous behaviour was an empty list. Revisit this if issues arise.
                    # TODO: we are assigning a value, even if not `in_place=True`
                    common.assign_to_path(subject, path, value={}, delimiter="/")

                target = common.extract_from_jsonpointer_path(subject, path)
                if isinstance(target, list) and not path.endswith("/-"):
                    # if "path" is an attribute name pointing to an array in "subject", and we're running
                    # an "add" operation, then we should use the standard-compliant notation "/path/-"
                    operation["path"] = f"{path}/-"

            if operation["op"] == "remove":
                path = operation["path"]
                common.assign_to_path(subject, path, value={}, delimiter="/")

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


def add_documentation_parts(rest_api_container, documentation):
    for doc_part in documentation.get("documentationParts", []):
        entity_id = short_uid()[:6]
        location = doc_part["location"]
        rest_api_container.documentation_parts[entity_id] = DocumentationPart(
            id=entity_id,
            location=DocumentationPartLocation(
                type=location.get("type"),
                path=location.get("path", "/")
                if location.get("type") not in ["API", "MODEL"]
                else None,
                method=location.get("method"),
                statusCode=location.get("statusCode"),
                name=location.get("name"),
            ),
            properties=doc_part["properties"],
        )


def import_api_from_openapi_spec(
    rest_api: MotoRestAPI, body: dict, context: RequestContext
) -> Optional[MotoRestAPI]:
    """Import an API from an OpenAPI spec document"""

    query_params: dict = context.request.values.to_dict()
    resolved_schema = resolve_references(copy.deepcopy(body), rest_api_id=rest_api.id)
    account_id = context.account_id
    region_name = context.region

    # TODO:
    # 1. validate the "mode" property of the spec document, "merge" or "overwrite"
    # 2. validate the document type, "swagger" or "openapi"

    rest_api.version = (
        str(version) if (version := resolved_schema.get("info", {}).get("version")) else None
    )
    # XXX for some reason this makes cf tests fail that's why is commented.
    # test_cfn_handle_serverless_api_resource
    # rest_api.name = resolved_schema.get("info", {}).get("title")
    rest_api.description = resolved_schema.get("info", {}).get("description")

    # authorizers map to avoid duplication
    authorizers = {}

    store = get_apigateway_store(context=context)
    rest_api_container = store.rest_apis[rest_api.id]

    def is_api_key_required(path_payload: dict) -> bool:
        # TODO: consolidate and refactor with `create_authorizer`, duplicate logic for now
        if not (security_schemes := path_payload.get("security")):
            return False

        for security_scheme in security_schemes:
            for security_scheme_name in security_scheme.keys():
                # $.securityDefinitions is Swagger 2.0
                # $.components.SecuritySchemes is OpenAPI 3.0
                security_definitions = resolved_schema.get(
                    "securityDefinitions"
                ) or resolved_schema.get("components", {}).get("securitySchemes", {})
                if security_scheme_name in security_definitions:
                    security_config = security_definitions.get(security_scheme_name)
                    if (
                        OpenAPIExt.AUTHORIZER not in security_config
                        and security_config.get("type") == "apiKey"
                        and security_config.get("name", "").lower() == "x-api-key"
                    ):
                        return True
        return False

    def create_authorizers(security_schemes: dict) -> None:
        for security_scheme_name, security_config in security_schemes.items():
            aws_apigateway_authorizer = security_config.get(OpenAPIExt.AUTHORIZER, {})
            if not aws_apigateway_authorizer:
                continue

            if security_scheme_name in authorizers:
                continue

            authorizer_type = aws_apigateway_authorizer.get("type", "").upper()
            # TODO: do we need validation of resources here?
            authorizer = Authorizer(
                id=ApigwAuthorizerIdentifier(
                    account_id, region_name, security_scheme_name
                ).generate(),
                name=security_scheme_name,
                type=authorizer_type,
                authorizerResultTtlInSeconds=aws_apigateway_authorizer.get(
                    "authorizerResultTtlInSeconds", 300
                ),
            )
            if provider_arns := aws_apigateway_authorizer.get("providerARNs"):
                authorizer["providerARNs"] = provider_arns
            if auth_type := security_config.get(OpenAPIExt.AUTHTYPE):
                authorizer["authType"] = auth_type
            if authorizer_uri := aws_apigateway_authorizer.get("authorizerUri"):
                authorizer["authorizerUri"] = authorizer_uri
            if authorizer_credentials := aws_apigateway_authorizer.get("authorizerCredentials"):
                authorizer["authorizerCredentials"] = authorizer_credentials
            if authorizer_type == "TOKEN":
                header_name = security_config.get("name")
                authorizer["identitySource"] = f"method.request.header.{header_name}"
            elif identity_source := aws_apigateway_authorizer.get("identitySource"):
                # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions-authorizer.html
                # Applicable for the authorizer of the request and jwt type only
                authorizer["identitySource"] = identity_source
            if identity_validation_expression := aws_apigateway_authorizer.get(
                "identityValidationExpression"
            ):
                authorizer["identityValidationExpression"] = identity_validation_expression

            rest_api_container.authorizers[authorizer["id"]] = authorizer

            authorizers[security_scheme_name] = authorizer

    def get_authorizer(path_payload: dict) -> Optional[Authorizer]:
        if not (security_schemes := path_payload.get("security")):
            return None

        for security_scheme in security_schemes:
            for security_scheme_name in security_scheme.keys():
                if authorizer := authorizers.get(security_scheme_name):
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
        rel_path = rel_path or "/"
        child_id = ApigwResourceIdentifier(account_id, region_name, parent_id, rel_path).generate()

        # Create a `Resource` for the passed `rel_path`
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
        # Iterate over each field of the `path` to try to find the methods defined
        for field, field_schema in method_paths.items():
            if field in [
                "parameters",
                "servers",
                "description",
                "summary",
                "$ref",
            ] or not isinstance(field_schema, dict):
                LOG.warning("Ignoring unsupported field %s in path %s", field, rel_path)
                # TODO: check if we should skip parameters, those are global parameters applied to every routes but
                #  can be overridden at the operation level
                continue

            method_name = field.upper()
            if method_name == OpenAPIExt.ANY_METHOD.upper():
                method_name = "ANY"

            # Create the `Method` resource for each method path
            method_resource = create_method_resource(resource, method_name, field_schema)

            # Get the `Method` requestParameters and requestModels
            request_parameters_schema = field_schema.get("parameters", [])
            request_parameters = {}
            request_models = {}
            if request_parameters_schema:
                for req_param_data in request_parameters_schema:
                    # For Swagger 2.0, possible values for `in` from the specs are "query", "header", "path",
                    # "formData" or "body".
                    # For OpenAPI 3.0, values are "query", "header", "path" or "cookie".
                    # Only "path", "header" and "query" are supported in API Gateway for requestParameters
                    # "body" is mapped to a requestModel
                    param_location = req_param_data.get("in")
                    param_name = req_param_data.get("name")
                    param_required = req_param_data.get("required", False)
                    if param_location in ("query", "header", "path"):
                        if param_location == "query":
                            param_location = "querystring"

                        request_parameters[f"method.request.{param_location}.{param_name}"] = (
                            param_required
                        )

                    elif param_location == "body":
                        request_models = {APPLICATION_JSON: param_name}

                    else:
                        LOG.warning(
                            "Ignoring unsupported requestParameters/requestModels location value for %s: %s",
                            param_name,
                            param_location,
                        )
                        continue

            # this replaces 'body' in Parameters for OpenAPI 3.0, a requestBody Object
            # https://swagger.io/specification/v3/#request-body-object
            if request_models_schema := field_schema.get("requestBody"):
                model_ref = None
                for content_type, media_type in request_models_schema.get("content", {}).items():
                    # we're iterating over the Media Type object:
                    # https://swagger.io/specification/v3/#media-type-object
                    if content_type == APPLICATION_JSON:
                        model_ref = media_type.get("schema", {}).get("$ref")
                        continue
                    LOG.warning(
                        "Found '%s' content-type for the MethodResponse model for path '%s' and method '%s', not adding the model as currently not supported",
                        content_type,
                        rel_path,
                        method_name,
                    )
                if model_ref:
                    model_schema = model_ref.rsplit("/", maxsplit=1)[-1]
                    request_models = {APPLICATION_JSON: model_schema}

            method_resource.request_models = request_models or None

            # check if there's a request validator set in the method
            request_validator_name = field_schema.get(
                OpenAPIExt.REQUEST_VALIDATOR, default_req_validator_name
            )
            if request_validator_name:
                if not (
                    req_validator_id := request_validator_name_id_map.get(request_validator_name)
                ):
                    # Might raise an exception here if we properly validate the template
                    LOG.warning(
                        "A validator ('%s') was referenced for %s.(%s), but is not defined",
                        request_validator_name,
                        rel_path,
                        method_name,
                    )
                method_resource.request_validator_id = req_validator_id

            # we check if there's a path parameter, AWS adds the requestParameter automatically
            resource_path_part = parts[-1].strip("/")
            if is_variable_path(resource_path_part) and not is_greedy_path(resource_path_part):
                path_parameter = resource_path_part[1:-1]  # remove the curly braces
                request_parameters[f"method.request.path.{path_parameter}"] = True

            method_resource.request_parameters = request_parameters or None

            # Create the `MethodResponse` for the previously created `Method`
            method_responses = field_schema.get("responses", {})
            for method_status_code, method_response in method_responses.items():
                method_response_model = None
                model_ref = None
                # separating the two different versions, Swagger (2.0) and OpenAPI 3.0
                if "schema" in method_response:  # this is Swagger
                    model_ref = method_response["schema"].get("$ref")
                elif "content" in method_response:  # this is OpenAPI 3.0
                    for content_type, media_type in method_response["content"].items():
                        # we're iterating over the Media Type object:
                        # https://swagger.io/specification/v3/#media-type-object
                        if content_type == APPLICATION_JSON:
                            model_ref = media_type.get("schema", {}).get("$ref")
                            continue
                        LOG.warning(
                            "Found '%s' content-type for the MethodResponse model for path '%s' and method '', not adding the model as currently not supported",
                            content_type,
                            rel_path,
                            method_name,
                        )

                if model_ref:
                    model_schema = model_ref.rsplit("/", maxsplit=1)[-1]

                    method_response_model = {APPLICATION_JSON: model_schema}

                method_response_parameters = {}
                if response_param_headers := method_response.get("headers"):
                    for header, header_info in response_param_headers.items():
                        # TODO: make use of `header_info`
                        method_response_parameters[f"method.response.header.{header}"] = False

                method_resource.create_response(
                    method_status_code,
                    method_response_model,
                    method_response_parameters or None,
                )

            # Create the `Integration` for the previously created `Method`
            method_integration = field_schema.get(OpenAPIExt.INTEGRATION, {})

            integration_type = (
                i_type.upper() if (i_type := method_integration.get("type")) else None
            )

            match integration_type:
                case "AWS_PROXY":
                    # if the integration is AWS_PROXY with lambda, the only accepted integration method is POST
                    integration_method = "POST"
                case _:
                    integration_method = (
                        method_integration.get("httpMethod") or method_name
                    ).upper()

            connection_type = (
                ConnectionType.INTERNET
                if integration_type in (IntegrationType.HTTP, IntegrationType.HTTP_PROXY)
                else None
            )

            integration = Integration(
                http_method=integration_method,
                uri=method_integration.get("uri"),
                integration_type=integration_type,
                passthrough_behavior=method_integration.get(
                    "passthroughBehavior", "WHEN_NO_MATCH"
                ).upper(),
                request_templates=method_integration.get("requestTemplates"),
                request_parameters=method_integration.get("requestParameters"),
                cache_namespace=resource.id,
                timeout_in_millis=method_integration.get("timeoutInMillis") or "29000",
                content_handling=method_integration.get("contentHandling"),
                connection_type=connection_type,
            )

            # Create the `IntegrationResponse` for the previously created `Integration`
            if method_integration_responses := method_integration.get("responses"):
                for pattern, integration_responses in method_integration_responses.items():
                    integration_response_templates = integration_responses.get("responseTemplates")
                    integration_response_parameters = integration_responses.get(
                        "responseParameters"
                    )

                    integration_response = integration.create_integration_response(
                        status_code=integration_responses.get("statusCode", 200),
                        selection_pattern=pattern if pattern != "default" else None,
                        response_templates=integration_response_templates,
                        response_parameters=integration_response_parameters,
                        content_handling=None,
                    )
                    # moto set the responseTemplates to an empty dict when it should be None if not defined
                    if integration_response_templates is None:
                        integration_response.response_templates = None

            resource.resource_methods[method_name].method_integration = integration

        rest_api.resources[child_id] = resource
        rest_api_container.resource_children.setdefault(parent_id, []).append(child_id)
        return resource

    def create_method_resource(child, method, method_schema):
        authorization_type = "NONE"
        api_key_required = is_api_key_required(method_schema)
        kwargs = {}

        if authorizer := get_authorizer(method_schema) or default_authorizer:
            method_authorizer = authorizer or default_authorizer
            # override the authorizer_type if it's a TOKEN or REQUEST to CUSTOM
            if (authorizer_type := method_authorizer["type"]) in ("TOKEN", "REQUEST"):
                authorization_type = "CUSTOM"
            else:
                authorization_type = authorizer_type

            kwargs["authorizer_id"] = method_authorizer["id"]

        return child.add_method(
            method,
            api_key_required=api_key_required,
            authorization_type=authorization_type,
            operation_name=method_schema.get("operationId"),
            **kwargs,
        )

    models = resolved_schema.get("definitions") or resolved_schema.get("components", {}).get(
        "schemas", {}
    )
    for name, model_data in models.items():
        model_id = short_uid()[:6]  # length 6 to make TF tests pass
        model = Model(
            id=model_id,
            name=name,
            contentType=APPLICATION_JSON,
            description=model_data.get("description"),
            schema=json.dumps(model_data),
        )
        store.rest_apis[rest_api.id].models[name] = model

    # create the RequestValidators defined at the top-level field `x-amazon-apigateway-request-validators`
    request_validators = resolved_schema.get(OpenAPIExt.REQUEST_VALIDATORS, {})
    request_validator_name_id_map = {}
    for validator_name, validator_schema in request_validators.items():
        validator_id = short_uid()[:6]

        validator = RequestValidator(
            id=validator_id,
            name=validator_name,
            validateRequestBody=validator_schema.get("validateRequestBody") or False,
            validateRequestParameters=validator_schema.get("validateRequestParameters") or False,
        )

        store.rest_apis[rest_api.id].validators[validator_id] = validator
        request_validator_name_id_map[validator_name] = validator_id

    # get default requestValidator if present
    default_req_validator_name = resolved_schema.get(OpenAPIExt.REQUEST_VALIDATOR)

    # $.securityDefinitions is Swagger 2.0
    # $.components.SecuritySchemes is OpenAPI 3.0
    security_data = resolved_schema.get("securityDefinitions") or resolved_schema.get(
        "components", {}
    ).get("securitySchemes", {})
    # create the defined authorizers, even if they're not used by any routes
    if security_data:
        create_authorizers(security_data)

    # create default authorizer if present
    default_authorizer = get_authorizer(resolved_schema)

    # determine base path
    # default basepath mode is "ignore"
    # see https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-import-api-basePath.html
    basepath_mode = query_params.get("basepath") or "ignore"
    base_path = ""

    if basepath_mode != "ignore":
        # in Swagger 2.0, the basePath is a top-level property
        if "basePath" in resolved_schema:
            base_path = resolved_schema["basePath"]

        # in OpenAPI 3.0, the basePath is contained in the server object
        elif "servers" in resolved_schema:
            servers_property = resolved_schema.get("servers", [])
            for server in servers_property:
                # first, we check if there are a basePath variable (1st choice)
                if "basePath" in server.get("variables", {}):
                    base_path = server["variables"]["basePath"].get("default", "")
                    break
                # TODO: this allows both absolute and relative part, but AWS might not manage relative
                url_path = urlparse.urlparse(server.get("url", "")).path
                if url_path:
                    base_path = url_path if url_path != "/" else ""
                    break

    if basepath_mode == "split":
        base_path = base_path.strip("/").partition("/")[-1]
        base_path = f"/{base_path}" if base_path else ""

    api_paths = resolved_schema.get("paths", {})
    if api_paths:
        # Remove default root, then add paths from API spec
        # TODO: the default mode is now `merge`, not `overwrite` if using `PutRestApi`
        # TODO: quick hack for now, but do not remove the rootResource if the OpenAPI file is empty
        rest_api.resources = {}

    for path in api_paths:
        get_or_create_path(base_path + path, base_path=base_path)

    # binary types
    rest_api.binaryMediaTypes = resolved_schema.get(OpenAPIExt.BINARY_MEDIA_TYPES, [])

    policy = resolved_schema.get(OpenAPIExt.POLICY)
    if policy:
        policy = json.dumps(policy) if isinstance(policy, dict) else str(policy)
        rest_api.policy = policy
    minimum_compression_size = resolved_schema.get(OpenAPIExt.MINIMUM_COMPRESSION_SIZE)
    if minimum_compression_size is not None:
        rest_api.minimum_compression_size = int(minimum_compression_size)
    endpoint_config = resolved_schema.get(OpenAPIExt.ENDPOINT_CONFIGURATION)
    if endpoint_config:
        if endpoint_config.get("vpcEndpointIds"):
            endpoint_config.setdefault("types", ["PRIVATE"])
        rest_api.endpoint_configuration = endpoint_config

    api_key_source = resolved_schema.get(OpenAPIExt.API_KEY_SOURCE)
    if api_key_source is not None:
        rest_api.api_key_source = api_key_source.upper()

    documentation = resolved_schema.get(OpenAPIExt.DOCUMENTATION)
    if documentation:
        add_documentation_parts(rest_api_container, documentation)
    return rest_api


def is_greedy_path(path_part: str) -> bool:
    return path_part.startswith("{") and path_part.endswith("+}")


def is_variable_path(path_part: str) -> bool:
    return path_part.startswith("{") and path_part.endswith("}")


def log_template(
    request_id: str,
    date: datetime,
    http_method: str,
    resource_path: str,
    request_path: str,
    query_string: str,
    request_headers: str,
    request_body: str,
    response_body: str,
    response_headers: str,
    status_code: str,
):
    formatted_date = date.strftime("%a %b %d %H:%M:%S %Z %Y")
    return INVOKE_TEST_LOG_TEMPLATE.format(
        request_id=request_id,
        formatted_date=formatted_date,
        http_method=http_method,
        resource_path=resource_path,
        request_path=request_path,
        query_string=query_string,
        request_headers=request_headers,
        request_body=request_body,
        response_body=response_body,
        response_headers=response_headers,
        status_code=status_code,
    )


def get_domain_name_hash(domain_name: str) -> str:
    """
    Return a hash of the given domain name, which help construct regional domain names for APIs.
    TODO: use this in the future to dispatch API Gateway API invocations made to the regional domain name
    """
    return hashlib.shake_128(to_bytes(domain_name)).hexdigest(4)


def get_regional_domain_name(domain_name: str) -> str:
    """
    Return the regional domain name for the given domain name.
    In real AWS, this would look something like: "d-oplm2qchq0.execute-api.us-east-1.amazonaws.com"
    In LocalStack, we're returning this format: "d-<domain_hash>.execute-api.localhost.localstack.cloud"
    """
    domain_name_hash = get_domain_name_hash(domain_name)
    host = localstack_host().host
    return f"d-{domain_name_hash}.execute-api.{host}"
