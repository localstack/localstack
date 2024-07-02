from moto.apigateway.models import APIGatewayBackend, apigateway_backends
from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.aws.api.apigateway import ApiKey, ListOfUsagePlan, ListOfUsagePlanKey, Resource


def get_resources_from_moto_rest_api(moto_rest_api: MotoRestAPI) -> dict[str, Resource]:
    """
    This returns the `Resources` from a Moto REST API
    This allows to decouple the underlying split of resources between Moto and LocalStack, and always return the right
    format.
    """
    moto_resources = moto_rest_api.resources

    resources: dict[str, Resource] = {}
    for moto_resource in moto_resources.values():
        resource = Resource(
            id=moto_resource.id,
            parentId=moto_resource.parent_id,
            pathPart=moto_resource.path_part,
            path=moto_resource.get_path(),
            resourceMethods={
                # TODO: check if resource_methods.to_json() returns everything we need/want
                k: v.to_json()
                for k, v in moto_resource.resource_methods.items()
            },
        )

        resources[moto_resource.id] = resource

    return resources


def get_stage_variables(
    account_id: str, region: str, api_id: str, stage_name: str
) -> dict[str, str]:
    apigateway_backend: APIGatewayBackend = apigateway_backends[account_id][region]
    moto_rest_api = apigateway_backend.apis[api_id]
    stage = moto_rest_api.stages[stage_name]
    return stage.variables


def get_usage_plans(account_id: str, region_name: str) -> ListOfUsagePlan:
    """
    Will return a list of usage plans from the moto store.
    """
    apigateway_backend: APIGatewayBackend = apigateway_backends[account_id][region_name]
    return [usage_plan.to_json() for usage_plan in apigateway_backend.usage_plans.values()]


def get_api_key(api_key_id: str, account_id: str, region_name: str) -> ApiKey:
    """
    Will return an api key from the moto store.
    """
    apigateway_backend: APIGatewayBackend = apigateway_backends[account_id][region_name]
    return apigateway_backend.keys[api_key_id].to_json()


def get_usage_plan_keys(
    usage_plan_id: str, account_id: str, region_name: str
) -> ListOfUsagePlanKey:
    """
    Will return a list of usage plan keys from the moto store.
    """
    apigateway_backend: APIGatewayBackend = apigateway_backends[account_id][region_name]
    return [
        usage_plan_key.to_json()
        for usage_plan_key in apigateway_backend.usage_plan_keys.get(usage_plan_id, {}).values()
    ]
