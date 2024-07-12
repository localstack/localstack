import copy
import logging
import re
from typing import Type, TypedDict

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import MergedRestApi, RestApiContainer, RestApiDeployment

from .context import RestApiInvocationContext
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


def render_uri_with_stage_variables(uri: str | None, stage_variables: dict[str, str]) -> str | None:
    """
    https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html#stage-variables-in-integration-HTTP-uris
    URI=https://${stageVariables.<variable_name>}
    This format is the same as VTL, but we're using a simplified version to only replace `${stageVariables.<param>}`
    values, as AWS will ignore `${path}` for example
    """
    if not uri:
        return uri

    def replace_match(match_obj: re.Match) -> str:
        return stage_variables.get(match_obj.group("varName"), "")

    return _stage_variable_pattern.sub(replace_match, uri)


def render_uri_with_path_parameters(uri: str, path_parameters: dict[str, str]) -> str:
    for key, value in path_parameters.items():
        uri = uri.replace(f"{{{key}}}", value)

    return uri


def render_integration_uri(
    uri: str, path_parameters: dict[str, str], stage_variables: dict[str, str]
) -> str:
    """
    A URI can contain different value to interpolate / render
    It will have path parameters substitutions with this shape (can also add a querystring).
    URI=http://myhost.test/rootpath/{path}

    It can also have another format, for stage variables, documented here:
    https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html#stage-variables-in-integration-HTTP-uris
    URI=https://${stageVariables.<variable_name>}
    This format is the same as VTL.

    :param uri: the integration URI
    :param path_parameters: the list of path parameters, coming from the parameters mapping and override
    :param stage_variables: -
    :return: the rendered URI
    """
    uri_with_path = render_uri_with_path_parameters(uri, path_parameters)
    return render_uri_with_stage_variables(uri_with_path, stage_variables)


def get_source_arn(context: RestApiInvocationContext):
    method = context.resource_method["httpMethod"]
    path = context.resource["path"]
    return (
        "arn:aws:execute-api"
        f":{context.region}"
        f":{context.account_id}"
        f":{context.api_id}"
        f"/{context.stage}/{method}{path}"
    )


def get_lambda_function_arn_from_invocation_uri(uri: str) -> str:
    """
    "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:SimpleLambda4ProxyResource/invocations",
    :param uri: the integration URI value for a lambda function
    :return: the lambda function ARN
    """
    return uri.split("functions/")[1].removesuffix("/invocations")


def validate_sub_dict_of_typed_dict(typed_dict: Type[TypedDict], obj: dict) -> bool:
    """
    Validate that the object is a subset off the keys of a given `TypedDict`.
    :param typed_dict: the `TypedDict` blueprint
    :param obj: the object to validate
    :return: True if it is a subset, False otherwise
    """
    typed_dict_keys = {*typed_dict.__required_keys__, *typed_dict.__optional_keys__}

    return not bool(set(obj) - typed_dict_keys)
