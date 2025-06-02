import copy
import datetime
import re

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.apigateway import (
    BadRequestException,
    CacheClusterSize,
    CreateStageRequest,
    Deployment,
    DeploymentCanarySettings,
    GatewayResponse,
    GatewayResponses,
    GatewayResponseType,
    ListOfPatchOperation,
    MapOfStringToString,
    NotFoundException,
    NullableBoolean,
    NullableInteger,
    Stage,
    StatusCode,
    String,
    TestInvokeMethodRequest,
    TestInvokeMethodResponse,
)
from localstack.services.apigateway.helpers import (
    get_apigateway_store,
    get_moto_rest_api,
    get_rest_api_container,
)
from localstack.services.apigateway.legacy.provider import (
    STAGE_UPDATE_PATHS,
    ApigatewayProvider,
    patch_api_gateway_entity,
)
from localstack.services.apigateway.patches import apply_patches
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto

from ..models import apigateway_stores
from .execute_api.gateway_response import (
    DEFAULT_GATEWAY_RESPONSES,
    GatewayResponseCode,
    build_gateway_response,
    get_gateway_response_or_default,
)
from .execute_api.helpers import freeze_rest_api
from .execute_api.router import ApiGatewayEndpoint, ApiGatewayRouter
from .execute_api.test_invoke import run_test_invocation


class ApigatewayNextGenProvider(ApigatewayProvider):
    router: ApiGatewayRouter

    def __init__(self, router: ApiGatewayRouter = None):
        # we initialize the route handler with a global store with default account and region, because it only ever
        # access values with CrossAccount attributes
        if not router:
            route_handler = ApiGatewayEndpoint(store=apigateway_stores)
            router = ApiGatewayRouter(ROUTER, handler=route_handler)

        super().__init__(router=router)

    def on_after_init(self):
        apply_patches()
        self.router.register_routes()

    @handler("DeleteRestApi")
    def delete_rest_api(self, context: RequestContext, rest_api_id: String, **kwargs) -> None:
        super().delete_rest_api(context, rest_api_id, **kwargs)
        store = get_apigateway_store(context=context)
        api_id_lower = rest_api_id.lower()
        store.active_deployments.pop(api_id_lower, None)
        store.internal_deployments.pop(api_id_lower, None)

    @handler("CreateStage", expand=False)
    def create_stage(self, context: RequestContext, request: CreateStageRequest) -> Stage:
        # TODO: we need to internalize Stages and Deployments in LocalStack, we have a lot of split logic
        super().create_stage(context, request)
        rest_api_id = request["restApiId"].lower()
        stage_name = request["stageName"]
        moto_api = get_moto_rest_api(context, rest_api_id)
        stage = moto_api.stages[stage_name]

        if canary_settings := request.get("canarySettings"):
            if (
                deployment_id := canary_settings.get("deploymentId")
            ) and deployment_id not in moto_api.deployments:
                raise BadRequestException("Deployment id does not exist")

            default_settings = {
                "deploymentId": stage.deployment_id,
                "percentTraffic": 0.0,
                "useStageCache": False,
            }
            default_settings.update(canary_settings)
            stage.canary_settings = default_settings
        else:
            stage.canary_settings = None

        store = get_apigateway_store(context=context)

        store.active_deployments.setdefault(rest_api_id, {})
        store.active_deployments[rest_api_id][stage_name] = request["deploymentId"]
        response: Stage = stage.to_json()
        self._patch_stage_response(response)
        return response

    @handler("UpdateStage")
    def update_stage(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Stage:
        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        if not (moto_stage := moto_rest_api.stages.get(stage_name)):
            raise NotFoundException("Invalid Stage identifier specified")

        # construct list of path regexes for validation
        path_regexes = [re.sub("{[^}]+}", ".+", path) for path in STAGE_UPDATE_PATHS]

        # copy the patch operations to not mutate them, so that we're logging the correct input
        patch_operations = copy.deepcopy(patch_operations) or []
        # we are only passing a subset of operations to Moto as it does not handle properly all of them
        moto_patch_operations = []
        moto_stage_copy = copy.deepcopy(moto_stage)
        for patch_operation in patch_operations:
            skip_moto_apply = False
            patch_path = patch_operation["path"]
            patch_op = patch_operation["op"]

            # special case: handle updates (op=remove) for wildcard method settings
            patch_path_stripped = patch_path.strip("/")
            if patch_path_stripped == "*/*" and patch_op == "remove":
                if not moto_stage.method_settings.pop(patch_path_stripped, None):
                    raise BadRequestException(
                        "Cannot remove method setting */* because there is no method setting for this method "
                    )
                response = moto_stage.to_json()
                self._patch_stage_response(response)
                return response

            path_valid = patch_path in STAGE_UPDATE_PATHS or any(
                re.match(regex, patch_path) for regex in path_regexes
            )
            if is_canary := patch_path.startswith("/canarySettings"):
                skip_moto_apply = True
                path_valid = is_canary_settings_update_patch_valid(op=patch_op, path=patch_path)
                # it seems our JSON Patch utility does not handle replace properly if the value does not exists before
                # it seems to maybe be a Stage-only thing, so replacing it here
                if patch_op == "replace":
                    patch_operation["op"] = "add"

            if patch_op == "copy":
                copy_from = patch_operation.get("from")
                if patch_path not in ("/deploymentId", "/variables") or copy_from not in (
                    "/canarySettings/deploymentId",
                    "/canarySettings/stageVariableOverrides",
                ):
                    raise BadRequestException(
                        "Invalid copy operation with path: /canarySettings/stageVariableOverrides and from /variables. Valid copy:path are [/deploymentId, /variables] and valid copy:from are [/canarySettings/deploymentId, /canarySettings/stageVariableOverrides]"
                    )

                if copy_from.startswith("/canarySettings") and not getattr(
                    moto_stage_copy, "canary_settings", None
                ):
                    raise BadRequestException("Promotion not available. Canary does not exist.")

                if patch_path == "/variables":
                    moto_stage_copy.variables.update(
                        moto_stage_copy.canary_settings.get("stageVariableOverrides", {})
                    )
                elif patch_path == "/deploymentId":
                    moto_stage_copy.deployment_id = moto_stage_copy.canary_settings["deploymentId"]

                # we manually assign `copy` ops, no need to apply them
                continue

            if not path_valid:
                valid_paths = f"[{', '.join(STAGE_UPDATE_PATHS)}]"
                # note: weird formatting in AWS - required for snapshot testing
                valid_paths = valid_paths.replace(
                    "/{resourcePath}/{httpMethod}/throttling/burstLimit, /{resourcePath}/{httpMethod}/throttling/rateLimit, /{resourcePath}/{httpMethod}/caching/ttlInSeconds",
                    "/{resourcePath}/{httpMethod}/throttling/burstLimit/{resourcePath}/{httpMethod}/throttling/rateLimit/{resourcePath}/{httpMethod}/caching/ttlInSeconds",
                )
                valid_paths = valid_paths.replace("/burstLimit, /", "/burstLimit /")
                valid_paths = valid_paths.replace("/rateLimit, /", "/rateLimit /")
                raise BadRequestException(
                    f"Invalid method setting path: {patch_operation['path']}. Must be one of: {valid_paths}"
                )

            # TODO: check if there are other boolean, maybe add a global step in _patch_api_gateway_entity
            if patch_path == "/tracingEnabled" and (value := patch_operation.get("value")):
                patch_operation["value"] = value and value.lower() == "true" or False

            elif patch_path in ("/canarySettings/deploymentId", "/deploymentId"):
                if patch_op != "copy" and not moto_rest_api.deployments.get(
                    patch_operation.get("value")
                ):
                    raise BadRequestException("Deployment id does not exist")

            if not skip_moto_apply:
                # we need to copy the patch operation because `_patch_api_gateway_entity` is mutating it in place
                moto_patch_operations.append(dict(patch_operation))

            # we need to apply patch operation individually to be able to validate the logic
            # TODO: rework the patching logic
            patch_api_gateway_entity(moto_stage_copy, [patch_operation])
            if is_canary and (canary_settings := getattr(moto_stage_copy, "canary_settings", None)):
                default_canary_settings = {
                    "deploymentId": moto_stage_copy.deployment_id,
                    "percentTraffic": 0.0,
                    "useStageCache": False,
                }
                default_canary_settings.update(canary_settings)
                moto_stage_copy.canary_settings = default_canary_settings

        moto_rest_api.stages[stage_name] = moto_stage_copy
        moto_stage_copy.apply_operations(moto_patch_operations)
        if moto_stage.deployment_id != moto_stage_copy.deployment_id:
            store = get_apigateway_store(context=context)
            store.active_deployments.setdefault(rest_api_id.lower(), {})[stage_name] = (
                moto_stage_copy.deployment_id
            )

        moto_stage_copy.last_updated_date = datetime.datetime.now(tz=datetime.UTC)

        response = moto_stage_copy.to_json()
        self._patch_stage_response(response)
        return response

    def delete_stage(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> None:
        call_moto(context)
        store = get_apigateway_store(context=context)
        store.active_deployments[rest_api_id.lower()].pop(stage_name, None)

    def create_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String = None,
        stage_description: String = None,
        description: String = None,
        cache_cluster_enabled: NullableBoolean = None,
        cache_cluster_size: CacheClusterSize = None,
        variables: MapOfStringToString = None,
        canary_settings: DeploymentCanarySettings = None,
        tracing_enabled: NullableBoolean = None,
        **kwargs,
    ) -> Deployment:
        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        if canary_settings:
            # TODO: add validation to the canary settings
            if not stage_name:
                error_stage = stage_name if stage_name is not None else "null"
                raise BadRequestException(
                    f"Invalid deployment content specified.Non null and non empty stageName must be provided for canary deployment. Provided value is {error_stage}"
                )
            if stage_name not in moto_rest_api.stages:
                raise BadRequestException(
                    "Invalid deployment content specified.Stage non-existing must already be created before making a canary release deployment"
                )

        # FIXME: moto has an issue and is not handling canarySettings, hence overwriting the current stage with the
        #  canary deployment
        current_stage = None
        if stage_name:
            current_stage = copy.deepcopy(moto_rest_api.stages.get(stage_name))

        # TODO: if the REST API does not contain any method, we should raise an exception
        deployment: Deployment = call_moto(context)
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/updating-api.html
        # TODO: the deployment is not accessible until it is linked to a stage
        # you can combine a stage or later update the deployment with a stage id
        store = get_apigateway_store(context=context)
        rest_api_container = get_rest_api_container(context, rest_api_id=rest_api_id)
        frozen_deployment = freeze_rest_api(
            account_id=context.account_id,
            region=context.region,
            moto_rest_api=moto_rest_api,
            localstack_rest_api=rest_api_container,
        )
        router_api_id = rest_api_id.lower()
        deployment_id = deployment["id"]
        store.internal_deployments.setdefault(router_api_id, {})[deployment_id] = frozen_deployment

        if stage_name:
            moto_stage = moto_rest_api.stages[stage_name]
            store.active_deployments.setdefault(router_api_id, {})[stage_name] = deployment_id
            if canary_settings:
                moto_stage = current_stage
                moto_rest_api.stages[stage_name] = current_stage

                default_settings = {
                    "deploymentId": deployment_id,
                    "percentTraffic": 0.0,
                    "useStageCache": False,
                }
                default_settings.update(canary_settings)
                moto_stage.canary_settings = default_settings
            else:
                moto_stage.canary_settings = None

            if variables:
                moto_stage.variables = variables

            moto_stage.description = stage_description or moto_stage.description or None

            if cache_cluster_enabled is not None:
                moto_stage.cache_cluster_enabled = cache_cluster_enabled

            if cache_cluster_size is not None:
                moto_stage.cache_cluster_size = cache_cluster_size

            if tracing_enabled is not None:
                moto_stage.tracing_enabled = tracing_enabled

        return deployment

    def delete_deployment(
        self, context: RequestContext, rest_api_id: String, deployment_id: String, **kwargs
    ) -> None:
        call_moto(context)
        store = get_apigateway_store(context=context)
        store.internal_deployments.get(rest_api_id.lower(), {}).pop(deployment_id, None)

    def put_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        status_code: StatusCode = None,
        response_parameters: MapOfStringToString = None,
        response_templates: MapOfStringToString = None,
        **kwargs,
    ) -> GatewayResponse:
        store = get_apigateway_store(context=context)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        if response_type not in DEFAULT_GATEWAY_RESPONSES:
            raise CommonServiceException(
                code="ValidationException",
                message=f"1 validation error detected: Value '{response_type}' at 'responseType' failed to satisfy constraint: Member must satisfy enum value set: [{', '.join(DEFAULT_GATEWAY_RESPONSES)}]",
            )

        gateway_response = build_gateway_response(
            status_code=status_code,
            response_parameters=response_parameters,
            response_templates=response_templates,
            response_type=response_type,
            default_response=False,
        )

        rest_api_container.gateway_responses[response_type] = gateway_response

        # The CRUD provider has a weird behavior: for some responses (for now, INTEGRATION_FAILURE), it sets the default
        # status code to `504`. However, in the actual invocation logic, it returns 500. To deal with the inconsistency,
        # we need to set the value to None if not provided by the user, so that the invocation logic can properly return
        # 500, and the CRUD layer can still return 504 even though it is technically wrong.
        response = gateway_response.copy()
        if response.get("statusCode") is None:
            response["statusCode"] = GatewayResponseCode[response_type]

        return response

    def get_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        **kwargs,
    ) -> GatewayResponse:
        store = get_apigateway_store(context=context)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        if response_type not in DEFAULT_GATEWAY_RESPONSES:
            raise CommonServiceException(
                code="ValidationException",
                message=f"1 validation error detected: Value '{response_type}' at 'responseType' failed to satisfy constraint: Member must satisfy enum value set: [{', '.join(DEFAULT_GATEWAY_RESPONSES)}]",
            )

        gateway_response = _get_gateway_response_or_default(
            response_type, rest_api_container.gateway_responses
        )
        # TODO: add validation with the parameters? seems like it validated client side? how to try?
        return gateway_response

    def get_gateway_responses(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> GatewayResponses:
        store = get_apigateway_store(context=context)
        if not (rest_api_container := store.rest_apis.get(rest_api_id)):
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            )

        user_gateway_resp = rest_api_container.gateway_responses
        gateway_responses = [
            _get_gateway_response_or_default(response_type, user_gateway_resp)
            for response_type in DEFAULT_GATEWAY_RESPONSES
        ]
        return GatewayResponses(items=gateway_responses)

    def test_invoke_method(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> TestInvokeMethodResponse:
        rest_api_id = request["restApiId"]
        moto_rest_api = get_moto_rest_api(context=context, rest_api_id=rest_api_id)
        resource = moto_rest_api.resources.get(request["resourceId"])
        if not resource:
            raise NotFoundException("Invalid Resource identifier specified")

        # test httpMethod

        rest_api_container = get_rest_api_container(context, rest_api_id=rest_api_id)
        frozen_deployment = freeze_rest_api(
            account_id=context.account_id,
            region=context.region,
            moto_rest_api=moto_rest_api,
            localstack_rest_api=rest_api_container,
        )

        response = run_test_invocation(
            test_request=request,
            deployment=frozen_deployment,
        )

        return response


def is_canary_settings_update_patch_valid(op: str, path: str) -> bool:
    path_regexes = (
        r"\/canarySettings\/percentTraffic",
        r"\/canarySettings\/deploymentId",
        r"\/canarySettings\/stageVariableOverrides\/.+",
        r"\/canarySettings\/useStageCache",
    )
    if path == "/canarySettings" and op == "remove":
        return True

    matches_path = any(re.match(regex, path) for regex in path_regexes)

    if op not in ("replace", "copy"):
        if matches_path:
            raise BadRequestException(f"Invalid {op} operation with path: {path}")

        raise BadRequestException(
            f"Cannot {op} method setting {path.lstrip('/')} because there is no method setting for this method "
        )

    # stageVariableOverrides is a bit special as it's nested, it doesn't return the same error message
    if not matches_path and path != "/canarySettings/stageVariableOverrides":
        return False

    return True


def _get_gateway_response_or_default(
    response_type: GatewayResponseType,
    gateway_responses: dict[GatewayResponseType, GatewayResponse],
) -> GatewayResponse:
    """
    Utility function that overrides the behavior of `get_gateway_response_or_default` by setting a default status code
    from the `GatewayResponseCode` values. In reality, some default values in the invocation layer are different from
    what the CRUD layer of API Gateway is returning.
    """
    response = get_gateway_response_or_default(response_type, gateway_responses)
    if response.get("statusCode") is None and (status_code := GatewayResponseCode[response_type]):
        response["statusCode"] = status_code

    return response
