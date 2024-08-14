from typing import TYPE_CHECKING

from localstack.aws.api.lambda_ import ResourceNotFoundException
from localstack.services.lambda_.api_utils import (
    function_locators_from_arn,
    lambda_arn,
    qualified_lambda_arn,
    qualifier_is_alias,
    unqualified_lambda_arn,
)
from localstack.services.lambda_.invocation.models import lambda_stores

if TYPE_CHECKING:
    from localstack.services.lambda_.invocation.lambda_models import (
        FunctionVersion,
    )


def get_function_version_from_arn(function_arn: str) -> "FunctionVersion":
    function_name, qualifier, account_id, region = function_locators_from_arn(function_arn)
    fn = lambda_stores[account_id][region].functions.get(function_name)
    if fn is None:
        if qualifier is None:
            raise ResourceNotFoundException(
                f"Function not found: {unqualified_lambda_arn(function_name, account_id, region)}",
                Type="User",
            )
        else:
            raise ResourceNotFoundException(
                f"Function not found: {qualified_lambda_arn(function_name, qualifier, account_id, region)}",
                Type="User",
            )
    if qualifier and qualifier_is_alias(qualifier):
        if qualifier not in fn.aliases:
            alias_arn = qualified_lambda_arn(function_name, qualifier, account_id, region)
            raise ResourceNotFoundException(f"Function not found: {alias_arn}", Type="User")
        alias_name = qualifier
        qualifier = fn.aliases[alias_name].function_version

    version = get_function_version(
        function_name=function_name,
        qualifier=qualifier,
        account_id=account_id,
        region=region,
    )
    return version


def get_function_version(
    function_name: str, qualifier: str | None, account_id: str, region: str
) -> "FunctionVersion":
    state = lambda_stores[account_id][region]
    function = state.functions.get(function_name)
    qualifier_or_latest = qualifier or "$LATEST"
    version = function and function.versions.get(qualifier_or_latest)
    if not function or not version:
        arn = lambda_arn(
            function_name=function_name,
            qualifier=qualifier,
            account=account_id,
            region=region,
        )
        raise ResourceNotFoundException(
            f"Function not found: {arn}",
            Type="User",
        )
    # TODO what if version is missing?
    return version
