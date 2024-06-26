import copy

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import MergedRestApi, RestApiContainer, RestApiDeployment

from .moto_helpers import get_resources_from_moto_rest_api


def freeze_rest_api(
    account_id: str, region: str, moto_rest_api: MotoRestAPI, localstack_rest_api: RestApiContainer
) -> RestApiDeployment:
    """
    Snapshot a REST API in time to create a deployment
    This will merge the Moto and LocalStack data into one `MergedRestApi`
    """
    moto_resources = get_resources_from_moto_rest_api(moto_rest_api)

    rest_api = MergedRestApi.from_rest_api_container(
        rest_api_container=localstack_rest_api,
        resources=moto_resources,
    )

    return RestApiDeployment(
        account_id=account_id,
        region=region,
        rest_api=copy.deepcopy(rest_api),
    )
