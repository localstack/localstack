import io
import json
import logging
from copy import deepcopy
from typing import IO, Any

from moto.apigateway import models as apigw_models
from moto.apigateway.models import Resource as MotoResource
from moto.apigateway.models import RestAPI as MotoRestAPI
from moto.core.utils import camelcase_to_underscores

from localstack.aws.api import CommonServiceException, RequestContext, ServiceRequest, handler
from localstack.aws.api.apigateway import (
    Account,
    ApigatewayApi,
    ApiKeys,
    Authorizer,
    Authorizers,
    BadRequestException,
    BasePathMapping,
    BasePathMappings,
    Blob,
    Boolean,
    ClientCertificate,
    ClientCertificates,
    ConflictException,
    CreateAuthorizerRequest,
    CreateRestApiRequest,
    DocumentationPart,
    DocumentationPartLocation,
    DocumentationParts,
    ExportResponse,
    GetDocumentationPartsRequest,
    Integration,
    IntegrationType,
    ListOfPatchOperation,
    ListOfString,
    MapOfStringToBoolean,
    MapOfStringToString,
    Method,
    MethodResponse,
    Model,
    Models,
    NotFoundException,
    NullableBoolean,
    NullableInteger,
    PutIntegrationRequest,
    PutRestApiRequest,
    RequestValidator,
    RequestValidators,
    Resource,
    RestApi,
    RestApis,
    String,
    Tags,
    TestInvokeMethodRequest,
    TestInvokeMethodResponse,
    VpcLink,
    VpcLinks,
)
from localstack.aws.forwarder import NotImplementedAvoidFallbackError, create_aws_request_context
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.helpers import (
    EMPTY_MODEL,
    OpenApiExporter,
    apply_json_patch_safe,
    get_apigateway_store,
    import_api_from_openapi_spec,
)
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.models import RestApiContainer
from localstack.services.apigateway.patches import apply_patches
from localstack.services.apigateway.router_asf import ApigatewayRouter, to_invocation_context
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import (
    DelSafeDict,
    PaginatedList,
    ensure_list,
    select_from_typed_dict,
)
from localstack.utils.json import parse_json_or_yaml
from localstack.utils.strings import short_uid, str_to_bool, to_str
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)


class ApigatewayProvider(ApigatewayApi, ServiceLifecycleHook):
    router: ApigatewayRouter

    def __init__(self, router: ApigatewayRouter = None):
        self.router = router or ApigatewayRouter(ROUTER)

    def on_after_init(self):
        apply_patches()
        self.router.register_routes()

    @handler("TestInvokeMethod", expand=False)
    def test_invoke_method(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> TestInvokeMethodResponse:

        invocation_context = to_invocation_context(context.request)
        invocation_context.method = request["httpMethod"]

        if data := parse_json_or_yaml(to_str(invocation_context.data or b"")):
            orig_data = data
            if path_with_query_string := orig_data.get("pathWithQueryString"):
                invocation_context.path_with_query_string = path_with_query_string
            invocation_context.data = data.get("body")
            invocation_context.headers = orig_data.get("headers", {})

        result = invoke_rest_api_from_request(invocation_context)

        # TODO: implement the other TestInvokeMethodResponse parameters
        #   * multiValueHeaders: Optional[MapOfStringToList]
        #   * log: Optional[String]
        #   * latency: Optional[Long]

        return TestInvokeMethodResponse(
            status=result.status_code,
            headers=dict(result.headers),
            body=to_str(result.content),
        )

    @handler("CreateRestApi", expand=False)
    def create_rest_api(self, context: RequestContext, request: CreateRestApiRequest) -> RestApi:
        if request.get("description") == "":
            raise BadRequestException("Description cannot be an empty string")

        minimum_compression_size = request.get("minimumCompressionSize")
        if minimum_compression_size is not None and (
            minimum_compression_size < 0 or minimum_compression_size > 10485760
        ):
            raise BadRequestException(
                "Invalid minimum compression size, must be between 0 and 10485760"
            )

        result = call_moto(context)
        rest_api = get_moto_rest_api(context, rest_api_id=result["id"])
        rest_api.version = request.get("version")
        response: RestApi = rest_api.to_dict()
        remove_empty_attributes_from_rest_api(response)
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = RestApiContainer(rest_api=response)
        store.rest_apis[result["id"]] = rest_api_container
        # add the 2 default models
        rest_api_container.models[EMPTY_MODEL] = DEFAULT_EMPTY_MODEL
        rest_api_container.models["Error"] = DEFAULT_ERROR_MODEL

        return response

    def get_rest_api(self, context: RequestContext, rest_api_id: String) -> RestApi:
        rest_api: RestApi = call_moto(context)
        remove_empty_attributes_from_rest_api(rest_api)
        return rest_api

    def update_rest_api(
        self,
        context: RequestContext,
        rest_api_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> RestApi:
        rest_api = get_moto_rest_api(context, rest_api_id)

        fixed_patch_ops = []
        binary_media_types_path = "/binaryMediaTypes"
        # TODO: validate a bit more patch operations
        for patch_op in patch_operations:
            patch_op_path = patch_op.get("path", "")
            # binaryMediaTypes has a specific way of being set
            # see https://docs.aws.amazon.com/apigateway/latest/api/API_PatchOperation.html
            # TODO: maybe implement a more generalized way if this happens anywhere else
            if patch_op_path.startswith(binary_media_types_path):
                if patch_op_path == binary_media_types_path:
                    raise BadRequestException(f"Invalid patch path {patch_op_path}")
                value = patch_op_path.rsplit("/", maxsplit=1)[-1]
                path_value = value.replace("~1", "/")
                patch_op["path"] = binary_media_types_path

                if patch_op["op"] == "add":
                    patch_op["value"] = path_value

                elif patch_op["op"] == "remove":
                    remove_index = rest_api.binaryMediaTypes.index(path_value)
                    patch_op["path"] = f"{binary_media_types_path}/{remove_index}"

                elif patch_op["op"] == "replace":
                    # AWS is behaving weirdly, and will actually remove/add instead of replacing in place
                    # it will put the replaced value last in the array
                    replace_index = rest_api.binaryMediaTypes.index(path_value)
                    fixed_patch_ops.append(
                        {"op": "remove", "path": f"{binary_media_types_path}/{replace_index}"}
                    )
                    patch_op["op"] = "add"

            elif patch_op_path == "/minimumCompressionSize":
                if patch_op["op"] != "replace":
                    raise BadRequestException(
                        "Invalid patch operation specified. Must be 'add'|'remove'|'replace'"
                    )

                try:
                    # try to cast the value to integer if truthy, else reject
                    value = int(val) if (val := patch_op.get("value")) else None
                except ValueError:
                    raise BadRequestException(
                        "Invalid minimum compression size, must be between 0 and 10485760"
                    )

                if value is not None and (value < 0 or value > 10485760):
                    raise BadRequestException(
                        "Invalid minimum compression size, must be between 0 and 10485760"
                    )
                patch_op["value"] = value

            fixed_patch_ops.append(patch_op)

        _patch_api_gateway_entity(rest_api, fixed_patch_ops)

        # fix data types after patches have been applied
        endpoint_configs = rest_api.endpoint_configuration or {}
        if isinstance(endpoint_configs.get("vpcEndpointIds"), str):
            endpoint_configs["vpcEndpointIds"] = [endpoint_configs["vpcEndpointIds"]]

        response = rest_api.to_dict()
        remove_empty_attributes_from_rest_api(response, remove_tags=False)
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        store.rest_apis[rest_api_id].rest_api = response
        return response

    @handler("PutRestApi", expand=False)
    def put_rest_api(self, context: RequestContext, request: PutRestApiRequest) -> RestApi:
        body_data = request["body"].read()
        rest_api = get_moto_rest_api(context, request["restApiId"])

        openapi_spec = parse_json_or_yaml(to_str(body_data))
        rest_api = import_api_from_openapi_spec(
            rest_api,
            openapi_spec,
            context.request.values.to_dict(),
            account_id=context.account_id,
            region=context.region,
        )

        response = rest_api.to_dict()
        remove_empty_attributes_from_rest_api(response)
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        store.rest_apis[request["restApiId"]].rest_api = response
        # TODO: verify this
        return to_rest_api_response_json(response)

    def delete_rest_api(self, context: RequestContext, rest_api_id: String) -> None:
        try:
            store = get_apigateway_store(context.account_id, context.region)
            store.rest_apis.pop(rest_api_id, None)
            call_moto(context)
        except KeyError as e:
            # moto raises a key error if we're trying to delete an API that doesn't exist
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            ) from e

    def get_rest_apis(
        self, context: RequestContext, position: String = None, limit: NullableInteger = None
    ) -> RestApis:
        response: RestApis = call_moto(context)
        for rest_api in response["items"]:
            remove_empty_attributes_from_rest_api(rest_api)
        return response

    # resources

    def create_resource(
        self, context: RequestContext, rest_api_id: String, parent_id: String, path_part: String
    ) -> Resource:
        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        parent_moto_resource: MotoResource = moto_rest_api.resources.get(parent_id, None)
        # validate here if the parent exists. Moto would first create then validate, which would lead to the resource
        # being created anyway
        if not parent_moto_resource:
            raise NotFoundException("Invalid Resource identifier specified")

        parent_path = parent_moto_resource.path_part
        if is_greedy_path(parent_path):
            raise BadRequestException(
                f"Cannot create a child of a resource with a greedy path variable: {parent_path}"
            )

        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api = store.rest_apis.get(rest_api_id)
        children = rest_api.resource_children.setdefault(parent_id, [])

        if is_variable_path(path_part):
            for sibling in children:
                sibling_resource: MotoResource = moto_rest_api.resources.get(sibling, None)
                if is_variable_path(sibling_resource.path_part):
                    raise BadRequestException(
                        f"A sibling ({sibling_resource.path_part}) of this resource already has a variable path part -- only one is allowed"
                    )

        response: Resource = call_moto(context)

        # save children to allow easy deletion of all children if we delete a parent route
        children.append(response["id"])

        return response

    def delete_resource(
        self, context: RequestContext, rest_api_id: String, resource_id: String
    ) -> None:
        moto_rest_api = get_moto_rest_api(context, rest_api_id)

        moto_resource: MotoResource = moto_rest_api.resources.pop(resource_id, None)
        if not moto_resource:
            raise NotFoundException("Invalid Resource identifier specified")

        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api = store.rest_apis.get(rest_api_id)
        api_resources = rest_api.resource_children
        # we need to recursively delete all children resources of the resource we're deleting

        def _delete_children(resource_to_delete: str):
            children = api_resources.get(resource_to_delete, [])
            for child in children:
                moto_rest_api.resources.pop(child)
                _delete_children(child)

            api_resources.pop(resource_to_delete, None)

        _delete_children(resource_id)

        # remove the resource as a child from its parent
        parent_id = moto_resource.parent_id
        api_resources[parent_id].remove(resource_id)

    def update_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> Resource:
        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        moto_resource = moto_rest_api.resources.get(resource_id)
        if not moto_resource:
            raise NotFoundException("Invalid Resource identifier specified")

        store = get_apigateway_store(account_id=context.account_id, region=context.region)

        rest_api = store.rest_apis.get(rest_api_id)
        api_resources = rest_api.resource_children

        future_path_part = moto_resource.path_part
        current_parent_id = moto_resource.parent_id

        for patch_operation in patch_operations:
            op = patch_operation.get("op")
            if (path := patch_operation.get("path")) not in ("/pathPart", "/parentId"):
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op '{op}'. Must be one of: [/parentId, /pathPart]"
                )
            if op != "replace":
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op '{op}'. Please choose supported operations"
                )

            if path == "/parentId":
                value = patch_operation.get("value")
                future_parent_resource = moto_rest_api.resources.get(value)
                if not future_parent_resource:
                    raise NotFoundException("Invalid Resource identifier specified")

                children_resources = api_resources.get(resource_id, [])
                if value in children_resources:
                    raise BadRequestException("Resources cannot be cyclical.")

                new_sibling_resources = api_resources.get(value, [])

            else:  # path == "/pathPart"
                future_path_part = patch_operation.get("value")
                new_sibling_resources = api_resources.get(moto_resource.parent_id, [])

            for sibling in new_sibling_resources:
                sibling_resource = moto_rest_api.resources[sibling]
                if sibling_resource.path_part == future_path_part:
                    raise ConflictException(
                        f"Another resource with the same parent already has this name: {future_path_part}"
                    )

        # TODO: test with multiple patch operations which would not be compatible between each other
        _patch_api_gateway_entity(moto_resource, patch_operations)

        # after setting it, mutate the store
        if moto_resource.parent_id != current_parent_id:
            current_sibling_resources = api_resources.get(current_parent_id)
            if current_sibling_resources:
                current_sibling_resources.remove(resource_id)
                # if the parent does not have children anymore, remove from the list
                if not current_sibling_resources:
                    api_resources.pop(current_parent_id)

        # add it to the new parent children
        future_sibling_resources = api_resources[moto_resource.parent_id]
        future_sibling_resources.append(resource_id)

        response = moto_resource.to_dict()
        return response

    # resource method

    def get_method(
        self, context: RequestContext, rest_api_id: String, resource_id: String, http_method: String
    ) -> Method:
        response: Method = call_moto(context)
        remove_empty_attributes_from_method(response)
        return response

    def put_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        authorization_type: String,
        authorizer_id: String = None,
        api_key_required: Boolean = None,
        operation_name: String = None,
        request_parameters: MapOfStringToBoolean = None,
        request_models: MapOfStringToString = None,
        request_validator_id: String = None,
        authorization_scopes: ListOfString = None,
    ) -> Method:
        # TODO: add missing validation? check order of validation as well
        moto_backend = apigw_models.apigateway_backends[context.account_id][context.region]
        moto_rest_api: MotoRestAPI = moto_backend.apis.get(rest_api_id)
        if not moto_rest_api or not moto_rest_api.resources.get(resource_id):
            raise NotFoundException("Invalid Resource identifier specified")

        if http_method not in ("GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY"):
            raise BadRequestException(
                "Invalid HttpMethod specified. "
                "Valid options are GET,PUT,POST,DELETE,PATCH,OPTIONS,HEAD,ANY"
            )

        if request_parameters:
            request_parameters_names = {
                name.rsplit(".", maxsplit=1)[-1] for name in request_parameters.keys()
            }
            if len(request_parameters_names) != len(request_parameters):
                raise BadRequestException(
                    "Parameter names must be unique across querystring, header and path"
                )
        need_authorizer_id = authorization_type in ("CUSTOM", "COGNITO_USER_POOLS")
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis[rest_api_id]
        if need_authorizer_id and (
            not authorizer_id or authorizer_id not in rest_api_container.authorizers
        ):
            # TODO: will be cleaner with https://github.com/localstack/localstack/pull/7750
            raise BadRequestException(
                "Invalid authorizer ID specified. "
                "Setting the authorization type to CUSTOM or COGNITO_USER_POOLS requires a valid authorizer."
            )

        if request_validator_id and request_validator_id not in rest_api_container.validators:
            raise BadRequestException("Invalid Request Validator identifier specified")

        if request_models:
            for content_type, model_name in request_models.items():
                # FIXME: add Empty model to rest api at creation
                if model_name == EMPTY_MODEL:
                    continue
                if model_name not in rest_api_container.models:
                    raise BadRequestException(f"Invalid model identifier specified: {model_name}")

        response: Method = call_moto(context)
        remove_empty_attributes_from_method(response)

        # this is straight from the moto patch, did not test it yet but has the same functionality
        # FIXME: check if still necessary after testing Authorizers
        if need_authorizer_id and "authorizerId" not in response:
            response["authorizerId"] = authorizer_id

        return response

    def update_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> Method:
        # see https://www.linkedin.com/pulse/updating-aws-cli-patch-operations-rest-api-yitzchak-meirovich/
        # for path construction
        moto_backend = apigw_models.apigateway_backends[context.account_id][context.region]
        moto_rest_api: MotoRestAPI = moto_backend.apis.get(rest_api_id)
        if not moto_rest_api or not (moto_resource := moto_rest_api.resources.get(resource_id)):
            raise NotFoundException("Invalid Resource identifier specified")

        if not (moto_method := moto_resource.resource_methods.get(http_method)):
            raise NotFoundException("Invalid Method identifier specified")
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api = store.rest_apis[rest_api_id]
        applicable_patch_operations = []
        modifying_auth_type = False
        modified_authorizer_id = False
        for patch_operation in patch_operations:
            op = patch_operation.get("op")
            path = patch_operation.get("path")
            # if the path is not supported at all, raise an Exception
            if len(path.split("/")) > 3 or not any(
                path.startswith(s_path) for s_path in UPDATE_METHOD_PATCH_PATHS["supported_paths"]
            ):
                raise BadRequestException(f"Invalid patch path {path}")

            # if the path is not supported by the operation, ignore it and skip
            op_supported_path = UPDATE_METHOD_PATCH_PATHS.get(op, [])
            if not any(path.startswith(s_path) for s_path in op_supported_path):
                continue

            value = patch_operation.get("value")
            if op not in ("add", "replace"):
                # skip
                applicable_patch_operations.append(patch_operation)
                continue

            if path == "/authorizationType" and value in ("CUSTOM", "COGNITO_USER_POOLS"):
                modifying_auth_type = True

            elif path == "/authorizerId":
                modified_authorizer_id = value

            if any(
                path.startswith(s_path) for s_path in ("/apiKeyRequired", "/requestParameters/")
            ):
                patch_op = {"op": op, "path": path, "value": str_to_bool(value)}
                applicable_patch_operations.append(patch_op)
                continue

            elif path == "/requestValidatorId" and value not in rest_api.validators:
                if not value:
                    # you can remove a requestValidator by passing an empty string as a value
                    patch_op = {"op": "remove", "path": path, "value": value}
                    applicable_patch_operations.append(patch_op)
                    continue
                raise BadRequestException("Invalid Request Validator identifier specified")

            elif path.startswith("/requestModels/"):
                if value != EMPTY_MODEL and value not in rest_api.models:
                    raise BadRequestException(f"Invalid model identifier specified: {value}")

            applicable_patch_operations.append(patch_operation)

        if modifying_auth_type:
            if not modified_authorizer_id or modified_authorizer_id not in rest_api.authorizers:
                raise BadRequestException(
                    "Invalid authorizer ID specified. "
                    "Setting the authorization type to CUSTOM or COGNITO_USER_POOLS requires a valid authorizer."
                )
        elif modified_authorizer_id:
            if moto_method.authorization_type not in ("CUSTOM", "COGNITO_USER_POOLS"):
                # AWS will ignore this patch if the method does not have a proper authorization type
                # filter the patches to remove the modified authorizerId
                applicable_patch_operations = [
                    op for op in applicable_patch_operations if op.get("path") != "/authorizerId"
                ]

        # TODO: test with multiple patch operations which would not be compatible between each other
        _patch_api_gateway_entity(moto_method, applicable_patch_operations)

        response = moto_method.to_json()
        remove_empty_attributes_from_method(response)
        return response

    def delete_method(
        self, context: RequestContext, rest_api_id: String, resource_id: String, http_method: String
    ) -> None:
        moto_backend = apigw_models.apigateway_backends[context.account_id][context.region]
        moto_rest_api: MotoRestAPI = moto_backend.apis.get(rest_api_id)
        if not moto_rest_api or not (moto_resource := moto_rest_api.resources.get(resource_id)):
            raise NotFoundException("Invalid Resource identifier specified")

        if not (moto_resource.resource_methods.get(http_method)):
            raise NotFoundException("Invalid Method identifier specified")

        call_moto(context)

    # method responses

    @handler("UpdateMethodResponse", expand=False)
    def update_method_response(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> MethodResponse:
        # this operation is not implemented by moto, but raises a 500 error (instead of a 501).
        # avoid a fallback to moto and return the 501 to the client directly instead.
        raise NotImplementedAvoidFallbackError

    # authorizers

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest
    ) -> Authorizer:
        # TODO: add validation
        api_id = request["restApiId"]
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if api_id not in store.rest_apis:
            # this seems like a weird exception to throw, but couldn't get anything different
            # we might need to have a look again
            raise ConflictException(
                "Unable to complete operation due to concurrent modification. Please try again later."
            )

        authorizer_id = short_uid()[:6]  # length 6 to make TF tests pass
        authorizer = deepcopy(select_from_typed_dict(Authorizer, request))
        authorizer["id"] = authorizer_id
        authorizer["authorizerResultTtlInSeconds"] = int(
            authorizer.get("authorizerResultTtlInSeconds", 300)
        )
        store.rest_apis[api_id].authorizers[authorizer_id] = authorizer

        response = to_authorizer_response_json(api_id, authorizer)
        return response

    def get_authorizers(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> Authorizers:
        # TODO add paging, validation
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        result = [
            to_authorizer_response_json(rest_api_id, a)
            for a in rest_api_container.authorizers.values()
        ]
        return Authorizers(items=result)

    def get_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String
    ) -> Authorizer:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        authorizer = (
            rest_api_container.authorizers.get(authorizer_id) if rest_api_container else None
        )

        if authorizer is None:
            raise NotFoundException(f"Authorizer not found: {authorizer_id}")
        return to_authorizer_response_json(rest_api_id, authorizer)

    def delete_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String
    ) -> None:
        # TODO: add validation if authorizer does not exist
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        if rest_api_container:
            rest_api_container.authorizers.pop(authorizer_id, None)

    def update_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        authorizer_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> Authorizer:
        # TODO: add validation
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        authorizer = (
            rest_api_container.authorizers.get(authorizer_id) if rest_api_container else None
        )

        if authorizer is None:
            raise NotFoundException(f"Authorizer not found: {authorizer_id}")

        patched_authorizer = apply_json_patch_safe(authorizer, patch_operations)
        # terraform sends this as a string in patch, so convert to int
        patched_authorizer["authorizerResultTtlInSeconds"] = int(
            patched_authorizer.get("authorizerResultTtlInSeconds", 300)
        )

        # store the updated Authorizer
        rest_api_container.authorizers[authorizer_id] = patched_authorizer

        result = to_authorizer_response_json(rest_api_id, patched_authorizer)
        return result

    # accounts

    def get_account(
        self,
        context: RequestContext,
    ) -> Account:
        region_details = get_apigateway_store()
        result = to_account_response_json(region_details.account)
        return Account(**result)

    def update_account(
        self, context: RequestContext, patch_operations: ListOfPatchOperation = None
    ) -> Account:
        region_details = get_apigateway_store()
        apply_json_patch_safe(region_details.account, patch_operations, in_place=True)
        result = to_account_response_json(region_details.account)
        return Account(**result)

    # documentation parts

    def get_documentation_parts(
        self, context: RequestContext, request: GetDocumentationPartsRequest
    ) -> DocumentationParts:
        # TODO: add validation
        api_id = request["restApiId"]
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{api_id}"
            )

        result = [
            to_documentation_part_response_json(api_id, a)
            for a in rest_api_container.documentation_parts.values()
        ]
        return DocumentationParts(items=result)

    def get_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String
    ) -> DocumentationPart:
        # TODO: add validation
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        documentation_part = (
            rest_api_container.documentation_parts.get(documentation_part_id)
            if rest_api_container
            else None
        )

        if documentation_part is None:
            raise NotFoundException("Invalid Documentation part identifier specified")
        return to_documentation_part_response_json(rest_api_id, documentation_part)

    def create_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        location: DocumentationPartLocation,
        properties: String,
    ) -> DocumentationPart:
        entity_id = short_uid()[:6]  # length 6 for AWS parity / Terraform compatibility
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        # TODO: add complete validation for
        # location parameter: https://docs.aws.amazon.com/apigateway/latest/api/API_DocumentationPartLocation.html
        # As of now we validate only "type"
        location_type = location.get("type")
        valid_location_types = [
            "API",
            "AUTHORIZER",
            "MODEL",
            "RESOURCE",
            "METHOD",
            "PATH_PARAMETER",
            "QUERY_PARAMETER",
            "REQUEST_HEADER",
            "REQUEST_BODY",
            "RESPONSE",
            "RESPONSE_HEADER",
            "RESPONSE_BODY",
        ]
        if location_type not in valid_location_types:
            raise CommonServiceException(
                "ValidationException",
                f"1 validation error detected: Value '{location_type}' at "
                f"'createDocumentationPartInput.location.type' failed to satisfy constraint: "
                f"Member must satisfy enum value set: "
                f"[RESPONSE_BODY, RESPONSE, METHOD, MODEL, AUTHORIZER, RESPONSE_HEADER, "
                f"RESOURCE, PATH_PARAMETER, REQUEST_BODY, QUERY_PARAMETER, API, REQUEST_HEADER]",
            )

        doc_part = DocumentationPart(
            id=entity_id,
            location=location,
            properties=properties,
        )
        rest_api_container.documentation_parts[entity_id] = doc_part

        result = to_documentation_part_response_json(rest_api_id, doc_part)
        return DocumentationPart(**result)

    def update_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_part_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> DocumentationPart:
        # TODO: add validation
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        doc_part = (
            rest_api_container.documentation_parts.get(documentation_part_id)
            if rest_api_container
            else None
        )

        if doc_part is None:
            raise NotFoundException("Invalid Documentation part identifier specified")

        for patch_operation in patch_operations:
            path = patch_operation.get("path")
            operation = patch_operation.get("op")
            if operation != "replace":
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op '{operation}'. "
                    f"Please choose supported operations"
                )

            if path != "/properties":
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op 'replace'. "
                    f"Must be one of: [/properties]"
                )

            key = path[1:]
            if key == "properties" and not patch_operation.get("value"):
                raise BadRequestException("Documentation part properties must be non-empty")

        patched_doc_part = apply_json_patch_safe(doc_part, patch_operations)

        rest_api_container.documentation_parts[documentation_part_id] = patched_doc_part

        result = to_documentation_part_response_json(rest_api_id, patched_doc_part)
        return result

    def delete_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String
    ) -> None:
        # TODO: add validation if document_part does not exist, or rest_api
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        documentation_part = rest_api_container.documentation_parts.get(documentation_part_id)

        if documentation_part is None:
            raise NotFoundException("Invalid Documentation part identifier specified")

        if rest_api_container:
            rest_api_container.documentation_parts.pop(documentation_part_id, None)

    # base path mappings

    def get_base_path_mappings(
        self,
        context: RequestContext,
        domain_name: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> BasePathMappings:
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []

        result = [
            to_base_mapping_response_json(domain_name, m["basePath"], m) for m in mappings_list
        ]
        return BasePathMappings(items=result)

    def get_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String
    ) -> BasePathMapping:
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []
        mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
        if mapping is None:
            raise NotFoundException(f"Base path mapping not found: {domain_name} - {base_path}")

        result = to_base_mapping_response_json(domain_name, base_path, mapping)
        return BasePathMapping(**result)

    def create_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        rest_api_id: String,
        base_path: String = None,
        stage: String = None,
    ) -> BasePathMapping:
        region_details = get_apigateway_store()

        # Note: "(none)" is a special value in API GW:
        # https://docs.aws.amazon.com/apigateway/api-reference/link-relation/basepathmapping-by-base-path
        base_path = base_path or "(none)"

        entry = {
            "domainName": domain_name,
            "restApiId": rest_api_id,
            "basePath": base_path,
            "stage": stage,
        }
        region_details.base_path_mappings.setdefault(domain_name, []).append(entry)

        result = to_base_mapping_response_json(domain_name, base_path, entry)
        return BasePathMapping(**result)

    def update_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> BasePathMapping:
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []

        mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
        if mapping is None:
            raise NotFoundException(
                f"Not found: mapping for domain name {domain_name}, "
                f"base path {base_path} in list {mappings_list}"
            )

        patch_operations = ensure_list(patch_operations)
        for operation in patch_operations:
            if operation["path"] == "/restapiId":
                operation["path"] = "/restApiId"
        result = apply_json_patch_safe(mapping, patch_operations)

        for i in range(len(mappings_list)):
            if mappings_list[i]["basePath"] == base_path:
                mappings_list[i] = result

        result = to_base_mapping_response_json(domain_name, base_path, result)
        return BasePathMapping(**result)

    def delete_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String
    ) -> None:
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []
        for i in range(len(mappings_list)):
            if mappings_list[i]["basePath"] == base_path:
                del mappings_list[i]
                return

        raise NotFoundException(f"Base path mapping {base_path} for domain {domain_name} not found")

    # client certificates

    def get_client_certificate(
        self, context: RequestContext, client_certificate_id: String
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        result = region_details.client_certificates.get(client_certificate_id)
        if result is None:
            raise NotFoundException(f"Client certificate ID {client_certificate_id} not found")
        return ClientCertificate(**result)

    def get_client_certificates(
        self, context: RequestContext, position: String = None, limit: NullableInteger = None
    ) -> ClientCertificates:
        region_details = get_apigateway_store()
        result = list(region_details.client_certificates.values())
        return ClientCertificates(items=result)

    def generate_client_certificate(
        self, context: RequestContext, description: String = None, tags: MapOfStringToString = None
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        cert_id = short_uid()
        creation_time = now_utc()
        entry = {
            "description": description,
            "tags": tags,
            "clientCertificateId": cert_id,
            "createdDate": creation_time,
            "expirationDate": creation_time + 60 * 60 * 24 * 30,  # assume 30 days validity
            "pemEncodedCertificate": "testcert-123",  # TODO return proper certificate!
        }
        region_details.client_certificates[cert_id] = entry
        result = to_client_cert_response_json(entry)
        return ClientCertificate(**result)

    def update_client_certificate(
        self,
        context: RequestContext,
        client_certificate_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        entity = region_details.client_certificates.get(client_certificate_id)
        if entity is None:
            raise NotFoundException(f'Client certificate ID "{client_certificate_id}" not found')
        result = apply_json_patch_safe(entity, patch_operations)
        result = to_client_cert_response_json(result)
        return ClientCertificate(**result)

    def delete_client_certificate(
        self, context: RequestContext, client_certificate_id: String
    ) -> None:
        region_details = get_apigateway_store()
        entity = region_details.client_certificates.pop(client_certificate_id, None)
        if entity is None:
            raise NotFoundException(f'VPC link ID "{client_certificate_id}" not found for deletion')

    # VPC links

    def create_vpc_link(
        self,
        context: RequestContext,
        name: String,
        target_arns: ListOfString,
        description: String = None,
        tags: MapOfStringToString = None,
    ) -> VpcLink:
        region_details = get_apigateway_store()
        link_id = short_uid()
        entry = {"id": link_id, "status": "AVAILABLE"}
        region_details.vpc_links[link_id] = entry
        result = to_vpc_link_response_json(entry)
        return VpcLink(**result)

    def get_vpc_links(
        self, context: RequestContext, position: String = None, limit: NullableInteger = None
    ) -> VpcLinks:
        region_details = get_apigateway_store()
        result = region_details.vpc_links.values()
        result = [to_vpc_link_response_json(r) for r in result]
        result = {"items": result}
        return result

    def get_vpc_link(self, context: RequestContext, vpc_link_id: String) -> VpcLink:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.get(vpc_link_id)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found')
        result = to_vpc_link_response_json(vpc_link)
        return VpcLink(**result)

    def update_vpc_link(
        self,
        context: RequestContext,
        vpc_link_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> VpcLink:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.get(vpc_link_id)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found')
        result = apply_json_patch_safe(vpc_link, patch_operations)
        result = to_vpc_link_response_json(result)
        return VpcLink(**result)

    def delete_vpc_link(self, context: RequestContext, vpc_link_id: String) -> None:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.pop(vpc_link_id, None)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found for deletion')

    # request validators

    def get_request_validators(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> RequestValidators:
        # TODO: add validation and pagination?
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        result = [
            to_validator_response_json(rest_api_id, a)
            for a in rest_api_container.validators.values()
        ]
        return RequestValidators(items=result)

    def get_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String
    ) -> RequestValidator:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        validator = (
            rest_api_container.validators.get(request_validator_id) if rest_api_container else None
        )

        if validator is None:
            raise NotFoundException("Invalid Request Validator identifier specified")

        result = to_validator_response_json(rest_api_id, validator)
        return result

    def create_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String = None,
        validate_request_body: Boolean = None,
        validate_request_parameters: Boolean = None,
    ) -> RequestValidator:
        # TODO: add validation (ex: name cannot be blank)
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise BadRequestException("Invalid REST API identifier specified")
        # length 6 for AWS parity and TF compatibility
        validator_id = short_uid()[:6]

        validator = RequestValidator(
            id=validator_id,
            name=name,
            validateRequestBody=validate_request_body or False,
            validateRequestParameters=validate_request_parameters or False,
        )

        rest_api_container.validators[validator_id] = validator

        # missing to_validator_response_json ?
        return validator

    def update_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        request_validator_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> RequestValidator:
        # TODO: add validation
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        # TODO: validate the restAPI id to remove the conditional
        validator = (
            rest_api_container.validators.get(request_validator_id) if rest_api_container else None
        )

        if validator is None:
            raise NotFoundException(
                f"Validator {request_validator_id} for API Gateway {rest_api_id} not found"
            )

        for patch_operation in patch_operations:
            path = patch_operation.get("path")
            operation = patch_operation.get("op")
            if operation != "replace":
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op '{operation}'. "
                    f"Please choose supported operations"
                )
            if path not in ("/name", "/validateRequestBody", "/validateRequestParameters"):
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op 'replace'. "
                    f"Must be one of: [/name, /validateRequestParameters, /validateRequestBody]"
                )

            key = path[1:]
            value = patch_operation.get("value")
            if key == "name" and not value:
                raise BadRequestException("Request Validator name cannot be blank")

            elif key in ("validateRequestParameters", "validateRequestBody"):
                value = value and value.lower() == "true" or False

            rest_api_container.validators[request_validator_id][key] = value

        return to_validator_response_json(
            rest_api_id, rest_api_container.validators[request_validator_id]
        )

    def delete_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String
    ) -> None:
        # TODO: add validation if rest api does not exist
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        rest_api_container = store.rest_apis.get(rest_api_id)
        if not rest_api_container:
            raise NotFoundException("Invalid Request Validator identifier specified")

        validator = rest_api_container.validators.pop(request_validator_id, None)
        if not validator:
            raise NotFoundException("Invalid Request Validator identifier specified")

    # tags

    def get_tags(
        self,
        context: RequestContext,
        resource_arn: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> Tags:
        result = get_apigateway_store().TAGS.get(resource_arn, {})
        return Tags(tags=result)

    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: MapOfStringToString
    ) -> None:
        resource_tags = get_apigateway_store().TAGS.setdefault(resource_arn, {})
        resource_tags.update(tags)

    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: ListOfString
    ) -> None:
        resource_tags = get_apigateway_store().TAGS.setdefault(resource_arn, {})
        for key in tag_keys:
            resource_tags.pop(key, None)

    def import_rest_api(
        self,
        context: RequestContext,
        body: IO[Blob],
        fail_on_warnings: Boolean = None,
        parameters: MapOfStringToString = None,
    ) -> RestApi:

        body_data = body.read()

        # create rest api
        openapi_spec = parse_json_or_yaml(to_str(body_data))
        create_api_request = CreateRestApiRequest(name=openapi_spec.get("info").get("title"))
        create_api_context = create_custom_context(
            context,
            "CreateRestApi",
            create_api_request,
        )
        response = self.create_rest_api(create_api_context, create_api_request)

        # put rest api
        put_api_request = PutRestApiRequest(
            restApiId=response.get("id"),
            failOnWarnings=str_to_bool(fail_on_warnings) or False,
            parameters=parameters or {},
            body=io.BytesIO(body_data),
        )
        put_api_context = create_custom_context(
            context,
            "PutRestApi",
            put_api_request,
        )
        return self.put_rest_api(put_api_context, put_api_request)

    def put_integration(
        self, context: RequestContext, request: PutIntegrationRequest
    ) -> Integration:
        if request.get("type") == IntegrationType.AWS_PROXY:
            integration_uri = request.get("uri") or ""
            if ":lambda:" not in integration_uri and ":firehose:" not in integration_uri:
                raise BadRequestException(
                    "Integrations of type 'AWS_PROXY' currently only supports "
                    "Lambda function and Firehose stream invocations."
                )
        return call_moto(context)

    def delete_integration(
        self, context: RequestContext, rest_api_id: String, resource_id: String, http_method: String
    ) -> None:
        try:
            call_moto(context)
        except Exception as e:
            raise NotFoundException("Invalid Resource identifier specified") from e

    def get_export(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        export_type: String,
        parameters: MapOfStringToString = None,
        accepts: String = None,
    ) -> ExportResponse:

        openapi_exporter = OpenApiExporter()
        result = openapi_exporter.export_api(
            api_id=rest_api_id, stage=stage_name, export_type=export_type, export_format=accepts
        )

        if accepts == APPLICATION_JSON:
            result = json.dumps(result, indent=2)

        return ExportResponse(contentType=accepts, body=result)

    def get_api_keys(
        self,
        context: RequestContext,
        position: String = None,
        limit: NullableInteger = None,
        name_query: String = None,
        customer_id: String = None,
        include_values: NullableBoolean = None,
    ) -> ApiKeys:
        moto_response: ApiKeys = call_moto(context=context)
        item_list = PaginatedList(moto_response["items"])

        def token_generator(item):
            return item["id"]

        def filter_function(item):
            return item["name"].startswith(name_query)

        paginated_list, next_token = item_list.get_page(
            token_generator=token_generator,
            next_token=position,
            page_size=limit,
            filter_function=filter_function if name_query else None,
        )

        return ApiKeys(
            items=paginated_list, warnings=moto_response.get("warnings"), position=next_token
        )

    def create_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String,
        content_type: String,
        description: String = None,
        schema: String = None,
    ) -> Model:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if rest_api_id not in store.rest_apis:
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        if not name:
            raise BadRequestException("Model name must be non-empty")

        if name in store.rest_apis[rest_api_id].models:
            raise ConflictException("Model name already exists for this REST API")

        if not schema:
            # TODO: maybe add more validation around the schema, valid json string?
            raise BadRequestException(
                "Model schema must have at least 1 property or array items defined"
            )

        model_id = short_uid()[:6]  # length 6 to make TF tests pass
        model = Model(
            id=model_id, name=name, contentType=content_type, description=description, schema=schema
        )
        store.rest_apis[rest_api_id].models[name] = model
        remove_empty_attributes_from_model(model)
        return model

    def get_models(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> Models:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if rest_api_id not in store.rest_apis:
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        models = [
            remove_empty_attributes_from_model(model)
            for model in store.rest_apis[rest_api_id].models.values()
        ]
        return Models(items=models)

    def get_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        model_name: String,
        flatten: Boolean = None,
    ) -> Model:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if rest_api_id not in store.rest_apis or not (
            model := store.rest_apis[rest_api_id].models.get(model_name)
        ):
            raise NotFoundException(f"Invalid model name specified: {model_name}")

        return model

    def update_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        model_name: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> Model:
        # manually update the model, not need for JSON patch, only 2 path supported with replace operation
        # /schema
        # /description
        store = get_apigateway_store(account_id=context.account_id, region=context.region)
        if rest_api_id not in store.rest_apis or not (
            model := store.rest_apis[rest_api_id].models.get(model_name)
        ):
            raise NotFoundException(f"Invalid model name specified: {model_name}")

        for operation in patch_operations:
            path = operation.get("path")
            if operation.get("op") != "replace":
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op 'add'. Please choose supported operations"
                )
            if path not in ("/schema", "/description"):
                raise BadRequestException(
                    f"Invalid patch path  '{path}' specified for op 'replace'. Must be one of: [/description, /schema]"
                )

            key = path[1:]  # remove the leading slash
            value = operation.get("value")
            if key == "schema" and not value:
                raise BadRequestException(
                    "Model schema must have at least 1 property or array items defined"
                )
            model[key] = value
        remove_empty_attributes_from_model(model)
        return model

    def delete_model(
        self, context: RequestContext, rest_api_id: String, model_name: String
    ) -> None:
        store = get_apigateway_store(account_id=context.account_id, region=context.region)

        if (
            rest_api_id not in store.rest_apis
            or model_name not in store.rest_apis[rest_api_id].models
        ):
            raise NotFoundException(f"Invalid model name specified: {model_name}")

        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        validate_model_in_use(moto_rest_api, model_name)

        store.rest_apis[rest_api_id].models.pop(model_name, None)


# ---------------
# UTIL FUNCTIONS
# ---------------


def get_moto_rest_api(context: RequestContext, rest_api_id: str) -> MotoRestAPI:
    moto_backend = apigw_models.apigateway_backends[context.account_id][context.region]
    rest_api = moto_backend.apis.get(rest_api_id)
    if not rest_api:
        raise NotFoundException(
            f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
        )

    return rest_api


def remove_empty_attributes_from_rest_api(rest_api: RestApi, remove_tags=True) -> RestApi:
    if not rest_api.get("binaryMediaTypes"):
        rest_api.pop("binaryMediaTypes", None)

    if not isinstance(rest_api.get("minimumCompressionSize"), int):
        rest_api.pop("minimumCompressionSize", None)

    if not rest_api.get("tags"):
        if remove_tags:
            rest_api.pop("tags", None)
        else:
            # if `tags` is falsy, set it to an empty dict
            rest_api["tags"] = {}

    if not rest_api.get("version"):
        rest_api.pop("version", None)
    if not rest_api.get("description"):
        rest_api.pop("description", None)

    return rest_api


def remove_empty_attributes_from_method(method: Method) -> Method:
    if not method.get("methodResponses"):
        method.pop("methodResponses", None)

    if not method.get("requestModels"):
        method.pop("requestModels", None)

    if not method.get("requestParameters"):
        method.pop("requestParameters", None)

    return method


def remove_empty_attributes_from_model(model: Model) -> Model:
    if not model.get("description"):
        model.pop("description", None)

    return model


def is_greedy_path(path_part: str) -> bool:
    return path_part.startswith("{") and path_part.endswith("+}")


def is_variable_path(path_part: str) -> bool:
    return path_part.startswith("{") and path_part.endswith("}")


def validate_model_in_use(moto_rest_api: MotoRestAPI, model_name: str) -> None:
    for resource in moto_rest_api.resources.values():
        for method in resource.resource_methods.values():
            if model_name in set(method.request_models.values()):
                path = f"{resource.get_path()}/{method.http_method}"
                raise ConflictException(
                    f"Cannot delete model '{model_name}', is referenced in method request: {path}"
                )


def create_custom_context(
    context: RequestContext, action: str, parameters: ServiceRequest
) -> RequestContext:
    ctx = create_aws_request_context(
        service_name=context.service.service_name,
        action=action,
        parameters=parameters,
        region=context.region,
    )
    ctx.request.headers.update(context.request.headers)
    ctx.account_id = context.account_id
    return ctx


def _patch_api_gateway_entity(entity: Any, patch_operations: ListOfPatchOperation):
    if not isinstance(entity.__dict__, DelSafeDict):
        entity.__dict__ = DelSafeDict(entity.__dict__)

    not_supported_attributes = {"/id", "/region_name", "/create_date"}

    model_attributes = list(entity.__dict__.keys())
    for operation in patch_operations:
        path_start = operation["path"].strip("/").split("/")[0]
        path_start_usc = camelcase_to_underscores(path_start)
        if path_start not in model_attributes and path_start_usc in model_attributes:
            operation["path"] = operation["path"].replace(path_start, path_start_usc)
        if operation["path"] in not_supported_attributes:
            raise BadRequestException(f"Invalid patch path {operation['path']}")

    apply_json_patch_safe(entity.__dict__, patch_operations, in_place=True)


def to_authorizer_response_json(api_id, data):
    result = to_response_json("authorizer", data, api_id=api_id)
    result = select_from_typed_dict(Authorizer, result)
    return result


def to_validator_response_json(api_id, data):
    result = to_response_json("validator", data, api_id=api_id)
    result = select_from_typed_dict(RequestValidator, result)
    return result


def to_documentation_part_response_json(api_id, data):
    result = to_response_json("documentationpart", data, api_id=api_id)
    result = select_from_typed_dict(DocumentationPart, result)
    return result


def to_base_mapping_response_json(domain_name, base_path, data):
    self_link = "/domainnames/%s/basepathmappings/%s" % (domain_name, base_path)
    result = to_response_json("basepathmapping", data, self_link=self_link)
    result = select_from_typed_dict(BasePathMapping, result)
    return result


def to_account_response_json(data):
    result = to_response_json("account", data, self_link="/account")
    result = select_from_typed_dict(Account, result)
    return result


def to_vpc_link_response_json(data):
    result = to_response_json("vpclink", data)
    result = select_from_typed_dict(VpcLink, result)
    return result


def to_client_cert_response_json(data):
    result = to_response_json("clientcertificate", data, id_attr="clientCertificateId")
    result = select_from_typed_dict(ClientCertificate, result)
    return result


def to_rest_api_response_json(data):
    result = to_response_json("restapi", data)
    result = select_from_typed_dict(RestApi, result)
    return result


def to_response_json(model_type, data, api_id=None, self_link=None, id_attr=None):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    id_attr = id_attr or "id"
    result = deepcopy(data)
    if not self_link:
        self_link = "/%ss/%s" % (model_type, data[id_attr])
        if api_id:
            self_link = "/restapis/%s/%s" % (api_id, self_link)
    # TODO: check if this is still required - "_links" are listed in the sample responses in the docs, but
    #  recent parity tests indicate that this field is not returned by real AWS...
    # https://docs.aws.amazon.com/apigateway/latest/api/API_GetAuthorizers.html#API_GetAuthorizers_Example_1_Response
    if "_links" not in result:
        result["_links"] = {}
    result["_links"]["self"] = {"href": self_link}
    result["_links"]["curies"] = {
        "href": "https://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-authorizer-latest.html",
        "name": model_type,
        "templated": True,
    }
    result["_links"]["%s:delete" % model_type] = {"href": self_link}
    return result


DEFAULT_EMPTY_MODEL = Model(
    id=short_uid()[:6],
    name=EMPTY_MODEL,
    contentType="application/json",
    description="This is a default empty schema model",
    schema=json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "Empty Schema",
            "type": "object",
        }
    ),
)

DEFAULT_ERROR_MODEL = Model(
    id=short_uid()[:6],
    name="Error",
    contentType="application/json",
    description="This is a default error schema model",
    schema=json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "Error Schema",
            "type": "object",
            "properties": {"message": {"type": "string"}},
        }
    ),
)


# TODO: maybe extract this in its own files, or find a better generalizable way
UPDATE_METHOD_PATCH_PATHS = {
    "supported_paths": [
        "/authorizationScopes",
        "/authorizationType",
        "/authorizerId",
        "/apiKeyRequired",
        "/operationName",
        "/requestParameters/",
        "/requestModels/",
        "/requestValidatorId",
    ],
    "add": [
        "/authorizationScopes",
        "/requestParameters/",
        "/requestModels/",
    ],
    "remove": [
        "/authorizationScopes",
        "/requestParameters/",
        "/requestModels/",
    ],
    "replace": [
        "/authorizationType",
        "/authorizerId",
        "/apiKeyRequired",
        "/operationName",
        "/requestParameters/",
        "/requestModels/",
        "/requestValidatorId",
    ],
}
