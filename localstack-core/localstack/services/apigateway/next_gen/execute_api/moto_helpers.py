from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.aws.api.apigateway import Resource


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
