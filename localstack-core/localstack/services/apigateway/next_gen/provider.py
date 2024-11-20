from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.apigateway import (
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
from localstack.services.apigateway.legacy.provider import ApigatewayProvider
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
        response = super().create_stage(context, request)
        store = get_apigateway_store(context=context)

        rest_api_id = request["restApiId"].lower()
        store.active_deployments.setdefault(rest_api_id, {})
        store.active_deployments[rest_api_id][request["stageName"]] = request["deploymentId"]

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
        response = super().update_stage(
            context, rest_api_id, stage_name, patch_operations, **kwargs
        )

        for patch_operation in patch_operations:
            patch_path = patch_operation["path"]

            if patch_path == "/deploymentId" and patch_operation["op"] == "replace":
                if deployment_id := patch_operation.get("value"):
                    store = get_apigateway_store(context=context)
                    store.active_deployments.setdefault(rest_api_id.lower(), {})[stage_name] = (
                        deployment_id
                    )

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
        # TODO: if the REST API does not contain any method, we should raise an exception
        deployment: Deployment = call_moto(context)
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/updating-api.html
        # TODO: the deployment is not accessible until it is linked to a stage
        # you can combine a stage or later update the deployment with a stage id
        store = get_apigateway_store(context=context)
        moto_rest_api = get_moto_rest_api(context, rest_api_id)
        rest_api_container = get_rest_api_container(context, rest_api_id=rest_api_id)
        frozen_deployment = freeze_rest_api(
            account_id=context.account_id,
            region=context.region,
            moto_rest_api=moto_rest_api,
            localstack_rest_api=rest_api_container,
        )
        router_api_id = rest_api_id.lower()
        store.internal_deployments.setdefault(router_api_id, {})[deployment["id"]] = (
            frozen_deployment
        )

        if stage_name:
            store.active_deployments.setdefault(router_api_id, {})[stage_name] = deployment["id"]

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
        # TODO: rewrite and migrate to NextGen
        return super().test_invoke_method(context, request)


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
