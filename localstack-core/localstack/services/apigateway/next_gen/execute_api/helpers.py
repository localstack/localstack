import copy

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.aws.api.apigateway import ListOfResource, Resource
from localstack.services.apigateway.models import RestApiContainer, RestApiDeployment


def freeze_rest_api(
    account_id: str, region: str, moto_rest_api: MotoRestAPI, localstack_rest_api: RestApiContainer
) -> RestApiDeployment:
    """Snapshot a REST API in time to create a deployment"""
    return RestApiDeployment(
        account_id=account_id,
        region=region,
        moto_rest_api=copy.deepcopy(moto_rest_api),
        localstack_rest_api=copy.deepcopy(localstack_rest_api),
    )


def get_resources_from_deployment(deployment: RestApiDeployment) -> ListOfResource:
    """
    This returns the `Resources` from a deployment
    This allows to decouple the underlying split of resources between Moto and LocalStack, and always return the right
    format.
    """
    moto_resources = deployment.moto_rest_api.resources

    resources: ListOfResource = []
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

        resources.append(resource)

    return resources
