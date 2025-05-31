import copy
import logging
import random
import re
import time
from secrets import token_hex
from typing import Type, TypedDict

from moto.apigateway.models import RestAPI as MotoRestAPI

from localstack.services.apigateway.models import MergedRestApi, RestApiContainer, RestApiDeployment
from localstack.utils.aws.arns import get_partition

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


def render_uri_with_stage_variables(
    uri: str | None, stage_variables: dict[str, str] | None
) -> str | None:
    """
    https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html#stage-variables-in-integration-HTTP-uris
    URI=https://${stageVariables.<variable_name>}
    This format is the same as VTL, but we're using a simplified version to only replace `${stageVariables.<param>}`
    values, as AWS will ignore `${path}` for example
    """
    if not uri:
        return uri
    stage_vars = stage_variables or {}

    def replace_match(match_obj: re.Match) -> str:
        return stage_vars.get(match_obj.group("varName"), "")

    return _stage_variable_pattern.sub(replace_match, uri)


def render_uri_with_path_parameters(uri: str | None, path_parameters: dict[str, str]) -> str | None:
    if not uri:
        return uri

    for key, value in path_parameters.items():
        uri = uri.replace(f"{{{key}}}", value)

    return uri


def render_integration_uri(
    uri: str | None, path_parameters: dict[str, str], stage_variables: dict[str, str]
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
    if not uri:
        return ""

    uri_with_path = render_uri_with_path_parameters(uri, path_parameters)
    return render_uri_with_stage_variables(uri_with_path, stage_variables)


def get_source_arn(context: RestApiInvocationContext):
    method = context.resource_method["httpMethod"]
    path = context.resource["path"]
    return (
        f"arn:{get_partition(context.region)}:execute-api"
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


def generate_trace_id():
    """https://docs.aws.amazon.com/xray/latest/devguide/xray-api-sendingdata.html#xray-api-traceids"""
    original_request_epoch = int(time.time())
    timestamp_hex = hex(original_request_epoch)[2:]
    version_number = "1"
    unique_id = token_hex(12)
    return f"{version_number}-{timestamp_hex}-{unique_id}"


def generate_trace_parent():
    return token_hex(8)


def parse_trace_id(trace_id: str) -> dict[str, str]:
    split_trace = trace_id.split(";")
    trace_values = {}
    for trace_part in split_trace:
        key_value = trace_part.split("=")
        if len(key_value) == 2:
            trace_values[key_value[0].capitalize()] = key_value[1]

    return trace_values


def mime_type_matches_binary_media_types(mime_type: str | None, binary_media_types: list[str]):
    if not mime_type or not binary_media_types:
        return False

    mime_type_and_subtype = mime_type.split(",")[0].split(";")[0].split("/")
    if len(mime_type_and_subtype) != 2:
        return False
    mime_type, mime_subtype = mime_type_and_subtype

    for bmt in binary_media_types:
        type_and_subtype = bmt.split(";")[0].split("/")
        if len(type_and_subtype) != 2:
            continue
        _type, subtype = type_and_subtype
        if _type == "*":
            continue

        if subtype == "*" and mime_type == _type:
            return True

        if mime_type == _type and mime_subtype == subtype:
            return True

    return False


def should_divert_to_canary(percent_traffic: float) -> bool:
    if int(percent_traffic) == 100:
        return True
    return percent_traffic > random.random() * 100
