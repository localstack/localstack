from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import (
    CacheClusterSize,
    CreateStageRequest,
    Deployment,
    DeploymentCanarySettings,
    ListOfPatchOperation,
    MapOfStringToString,
    NullableBoolean,
    Stage,
    String,
)
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.services.apigateway.helpers import (
    get_apigateway_store,
    get_moto_rest_api,
    get_rest_api_container,
)
from localstack.services.apigateway.patches import apply_patches
from localstack.services.apigateway.provider import ApigatewayProvider
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto

from ..models import apigateway_stores
from .execute_api.helpers import freeze_rest_api
from .execute_api.router import ApiGatewayEndpoint, ApiGatewayRouter


class ApigatewayNextGenProvider(ApigatewayProvider):
    router: ApiGatewayRouter
    route_handler: ApiGatewayEndpoint

    def __init__(self, router: ApiGatewayRouter = None):
        # we initialize the route handler with a global store with default account and region, because it only ever
        # access values with CrossAccount attributes
        store = apigateway_stores[DEFAULT_AWS_ACCOUNT_ID][AWS_REGION_US_EAST_1]
        route_handler = ApiGatewayEndpoint(store=store)
        super().__init__(router=router or ApiGatewayRouter(ROUTER, handler=route_handler))
        self.route_handler = route_handler

    def on_after_init(self):
        apply_patches()
        self.router.register_routes()

    @handler("CreateStage", expand=False)
    def create_stage(self, context: RequestContext, request: CreateStageRequest) -> Stage:
        response = super().create_stage(context, request)
        store = get_apigateway_store(context=context)
        store.active_deployments[(request["restApiId"].lower(), request["stageName"])] = request[
            "deploymentId"
        ]
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
                    store.active_deployments[(rest_api_id.lower(), stage_name)] = deployment_id

        return response

    def delete_stage(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> None:
        call_moto(context)
        store = get_apigateway_store(context=context)
        store.active_deployments.pop((rest_api_id.lower(), stage_name), None)

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
        store.internal_deployments[(router_api_id, deployment["id"])] = frozen_deployment

        if stage_name:
            store.active_deployments[(router_api_id, stage_name)] = deployment["id"]

        return deployment

    def delete_deployment(
        self, context: RequestContext, rest_api_id: String, deployment_id: String, **kwargs
    ) -> None:
        call_moto(context)
        store = get_apigateway_store(context=context)
        store.internal_deployments.pop((rest_api_id.lower(), deployment_id), None)
