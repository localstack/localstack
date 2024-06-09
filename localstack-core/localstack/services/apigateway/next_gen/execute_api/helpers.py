import copy

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import RestApiContainer, RestApiDeployment


def freeze_rest_api(
    moto_rest_api: MotoRestAPI, localstack_rest_api: RestApiContainer
) -> RestApiDeployment:
    """Snapshot a REST API in time to create a deployment"""
    return RestApiDeployment(
        moto_rest_api=copy.deepcopy(moto_rest_api),
        localstack_rest_api=copy.deepcopy(localstack_rest_api),
    )
