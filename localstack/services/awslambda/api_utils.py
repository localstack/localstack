""" some mostly temporary utils that will be refactored and unified with the other utils soon """
import re
from typing import Any, Optional

from localstack.aws.api import lambda_ as api_spec
from localstack.aws.api.lambda_ import FunctionUrlAuthType
from localstack.services.awslambda.invocation.lambda_models import FunctionUrlConfig
from localstack.services.awslambda.invocation.models import LambdaStore

FN_ARN_PATTERN = re.compile(
    r"^arn:aws:lambda:(?P<region_name>[^:]+):(?P<account_id>\d{12}):function:(?P<function_name>[^:]+)(:(?P<qualifier>.*))?$"
)


# def assert_function_exists():
#     ...
#
# def assert_is_alias():
#     ...
#
# def assert_is_function_version():
#     ...
#
# def is_alias():
#     ...
#
# def alias_exists():
#     ...
#
#


# Function URL utils


def map_function_url_config(model: FunctionUrlConfig) -> api_spec.FunctionUrlConfig:
    return api_spec.FunctionUrlConfig(
        FunctionUrl=model.url,
        FunctionArn=model.function_arn,
        CreationTime=model.creation_time,
        LastModifiedTime=model.last_modified_time,
        Cors=model.cors,
        AuthType=model.auth_type,
    )


def get_config_for_url(store: LambdaStore, url_id: str) -> Optional[FunctionUrlConfig]:
    """
    Get a config object when resolving a URL

    :param store: Lambda Store
    :param url_id: unique url ID (prefixed domain when calling the function)
    :return: FunctionUrlConfig that belongs to this ID

    # TODO: quite inefficient: optimize
    """
    for fn_name, fn in store.functions.items():
        for qualifier, fn_url_config in fn.function_url_configs.items():
            if fn_url_config.url_id == url_id:
                return fn_url_config
    return None


VERSION_REGEX = re.compile(r"^[0-9]+$")
ALIAS_REGEX = re.compile(r"(?!^[0-9]+$)([a-zA-Z0-9-_]+)")


def qualifier_is_version(qualifier: str) -> bool:
    return bool(VERSION_REGEX.match(qualifier))


def qualifier_is_alias(qualifier: str) -> bool:
    return bool(ALIAS_REGEX.match(qualifier))


def get_function_name(function_arn_or_name: str) -> str:
    """return name"""
    pattern_match = FN_ARN_PATTERN.search(function_arn_or_name)
    if not pattern_match:
        return function_arn_or_name

    return pattern_match.groupdict().get("function_name")


def build_statement(
    resource_arn: str,
    statement_id: str,
    action: str,
    principal: str,
    source_arn: Optional[str] = None,
    source_account: Optional[str] = None,  # TODO: test & implement
    principal_org_id: Optional[str] = None,  # TODO: test & implement
    event_source_token: Optional[str] = None,  # TODO: test & implement
    auth_type: Optional[FunctionUrlAuthType] = None,  # TODO: test & implement
) -> dict[str, Any]:
    statement = {
        "Sid": statement_id,
        "Effect": "Allow",
        "Action": action,
        "Resource": resource_arn,
    }

    if "." in principal:  # TODO: better matching
        # assuming service principal
        statement["Principal"] = {"Service": principal}
    else:
        statement["Principal"] = principal  # TODO: verify

    if source_arn:
        statement["Condition"] = {"ArnLike": {"AWS:SourceArn": source_arn}}

    return statement

    # if auth_type:
    #     auth_condition = {
    #         "StringEquals": {
    #             "lambda:FunctionUrlAuthType": auth_type
    #         }
    #     }
    #     statement["Condition"] = auth_condition
