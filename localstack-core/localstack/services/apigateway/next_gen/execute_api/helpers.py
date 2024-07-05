import copy
import logging
import re

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import MergedRestApi, RestApiContainer, RestApiDeployment

from .moto_helpers import get_resources_from_moto_rest_api

LOG = logging.getLogger(__name__)

_stage_variable_pattern = re.compile(r"\${stageVariables\.(?P<varName>.*?)}")


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


def render_uri_with_stage_variables(uri: str, stage_variables: dict[str, str]):
    """
    https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html#stage-variables-in-integration-HTTP-uris
    URI=https://${stageVariables.<variable_name>}
    This format is the same as VTL, but we're using a simplified version to only replace `${stageVariables.<param>}`
    values, as AWS will ignore `${path}` for example
    """

    def replace_match(match_obj: re.Match) -> str:
        return stage_variables.get(match_obj.group("varName"), "")

    return _stage_variable_pattern.sub(replace_match, uri)


def render_uri_with_path_parameters(uri: str, path_parameters: dict[str, str]) -> str:
    for key, value in path_parameters.items():
        uri = uri.replace(f"{{{key}}}", value)

    return uri
