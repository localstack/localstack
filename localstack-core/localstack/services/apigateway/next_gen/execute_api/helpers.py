import copy
import logging

from airspeed.operators import TemplateSyntaxError
from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import MergedRestApi, RestApiContainer, RestApiDeployment
from localstack.utils.aws.templating import VtlTemplate

from .moto_helpers import get_resources_from_moto_rest_api

LOG = logging.getLogger(__name__)

_vtl_template_renderer = VtlTemplate()


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
    This format is the same as VTL, so we're using a simplified version. The provider should validate the input.
    """
    try:
        return _vtl_template_renderer.render_vtl(uri, {"stageVariables": stage_variables})
    except TemplateSyntaxError:
        LOG.warning(
            "The URI provided did not have the right format: the stageVariables could not be rendered: '%s'",
            uri,
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )
        return uri


def render_uri_with_path_parameters(uri: str, path_parameters: dict[str, str]) -> str:
    for key, value in path_parameters.items():
        uri = uri.replace(f"{{{key}}}", value)

    return uri
