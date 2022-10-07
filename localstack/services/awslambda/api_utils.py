""" Utilities for the new Lambda ASF provider. Do not use in the current provider, as ASF specific exceptions might be thrown """
import datetime
import random
import re
import string
from typing import TYPE_CHECKING, Any, Optional

from localstack.aws.api import lambda_ as api_spec
from localstack.aws.api.lambda_ import (
    AliasConfiguration,
    EnvironmentResponse,
    EphemeralStorage,
    FunctionConfiguration,
    FunctionUrlAuthType,
    InvalidParameterValueException,
    ResourceNotFoundException,
    TracingConfig,
)

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_models import (
        CodeSigningConfig,
        Function,
        FunctionUrlConfig,
        FunctionVersion,
        VersionAlias,
    )
    from localstack.services.awslambda.invocation.models import LambdaStore

# Pattern for a full (both with and without qualifier) lambda function ARN
FULL_FN_ARN_PATTERN = re.compile(
    r"^arn:aws:lambda:(?P<region_name>[^:]+):(?P<account_id>\d{12}):function:(?P<function_name>[^:]+)(:(?P<qualifier>.*))?$"
)

# Pattern for a valid destination arn
DESTINATION_ARN_PATTERN = re.compile(
    r"^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)

# Pattern for extracting various attributes from a full or partial ARN or just a function name.
FUNCTION_NAME_REGEX = re.compile(
    r"(arn:(aws[a-zA-Z-]*):lambda:)?((?P<region>[a-z]{2}(-gov)?-[a-z]+-\d{1}):)?(?P<account>\d{12}:)?(function:)?(?P<name>[a-zA-Z0-9-_\.]+)(:(?P<qualifier>\$LATEST|[a-zA-Z0-9-_]+))?"
)  # also length 1-170 incl.
# Pattern for a lambda function handler
HANDLER_REGEX = re.compile(r"[^\s]+")
# Pattern for a valid kms key
KMS_KEY_ARN_REGEX = re.compile(r"(arn:(aws[a-zA-Z-]*)?:[a-z0-9-.]+:.*)|()")
# Pattern for a valid IAM role assumed by a lambda function
ROLE_REGEX = re.compile(r"arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+")
# Pattern for a signing job arn
SIGNING_JOB_ARN_REGEX = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
# Pattern for a signing profiler version arn
SIGNING_PROFILE_VERSION_ARN_REGEX = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
# Pattern for a version qualifier
VERSION_REGEX = re.compile(r"^[0-9]+$")
# Pattern for an alias qualifier
ALIAS_REGEX = re.compile(r"(?!^[0-9]+$)([a-zA-Z0-9-_]+)")


URL_CHAR_SET = string.ascii_lowercase + string.digits
# Date format as returned by the lambda service
LAMBDA_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+0000"


def map_function_url_config(model: "FunctionUrlConfig") -> api_spec.FunctionUrlConfig:
    return api_spec.FunctionUrlConfig(
        FunctionUrl=model.url,
        FunctionArn=model.function_arn,
        CreationTime=model.creation_time,
        LastModifiedTime=model.last_modified_time,
        Cors=model.cors,
        AuthType=model.auth_type,
    )


def map_csc(model: "CodeSigningConfig") -> api_spec.CodeSigningConfig:
    return api_spec.CodeSigningConfig(
        CodeSigningConfigId=model.csc_id,
        CodeSigningConfigArn=model.arn,
        Description=model.description,
        AllowedPublishers=model.allowed_publishers,
        CodeSigningPolicies=model.policies,
        LastModified=model.last_modified,
    )


def get_config_for_url(store: "LambdaStore", url_id: str) -> "Optional[FunctionUrlConfig]":
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


def qualifier_is_version(qualifier: str) -> bool:
    """
    Checks if a given qualifier represents a version

    :param qualifier: Qualifier to check
    :return: True if it matches a version, false otherwise
    """
    return bool(VERSION_REGEX.match(qualifier))


def qualifier_is_alias(qualifier: str) -> bool:
    """
    Checks if a given qualifier represents an alias

    :param qualifier: Qualifier to check
    :return: True if it matches an alias, false otherwise
    """
    return bool(ALIAS_REGEX.match(qualifier))


def get_function_name(function_arn_or_name: str, region: str) -> str:
    """
    Return function name from a given arn. Will check if the region provided matches the region in the arn, if an arn

    :param function_arn_or_name: Function arn or only name
    :param region: Region of the request
    :return: function name
    """
    name, _ = get_name_and_qualifier(function_arn_or_name, qualifier=None, region=region)
    return name


def function_name_qualifier_and_region_from_arn(arn: str) -> tuple[str, str | None, str | None]:
    """
    Takes a full or partial arn, or a name

    :param arn: Given arn (or name)
    :return: tuple with (name, qualifier, region). Qualifier and region are none if missing
    """
    return FUNCTION_NAME_REGEX.match(arn).group("name", "qualifier", "region")


def get_name_and_qualifier(
    function_arn_or_name: str, qualifier: str | None, region: str
) -> tuple[str, str | None]:
    """
    Takes a full or partial arn, or a name and a qualifier
    Will raise exception if a qualified arn is provided and the qualifier does not match (but is given)

    :param function_arn_or_name: Given arn (or name)
    :param qualifier: A qualifier for the function (or None)
    :param region: The region the function lives in
    :return: tuple with (name, qualifier). Qualifier is none if missing
    """
    function_name, arn_qualifier, arn_region = function_name_qualifier_and_region_from_arn(
        function_arn_or_name
    )
    if qualifier and arn_qualifier and arn_qualifier != qualifier:
        raise InvalidParameterValueException(
            "The derived qualifier from the function name does not match the specified qualifier.",
            Type="User",
        )
    if arn_region and arn_region != region:
        raise ResourceNotFoundException(
            f"Functions from '{arn_region}' are not reachable in this region ('{region}')",
            Type="User",
        )
    qualifier = qualifier or arn_qualifier
    return function_name, qualifier


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


def generate_random_url_id() -> str:
    """
    32 characters [0-9a-z] url ID
    """

    return "".join(random.choices(URL_CHAR_SET, k=32))


def unqualified_lambda_arn(function_name: str, account: str, region: str):
    """
    Generate a unqualified lambda arn

    :param function_name: Function name (not an arn!)
    :param account: Account ID
    :param region: Region
    :return: Unqualified lambda arn
    """
    # TODO should get partition here, but current way is too expensive (15-120ms) using aws_stack get_partition
    return f"arn:aws:lambda:{region}:{account}:function:{function_name}"


def qualified_lambda_arn(
    function_name: str, qualifier: Optional[str], account: str, region: str
) -> str:
    """
    Generate a qualified lambda arn

    :param function_name: Function name (not an arn!)
    :param qualifier: qualifier (will be set to $LATEST if not present)
    :param account: Account ID
    :param region: Region
    :return: Qualified lambda arn
    """
    qualifier = qualifier or "$LATEST"
    return f"{unqualified_lambda_arn(function_name=function_name, account=account, region=region)}:{qualifier}"


def lambda_arn(function_name: str, qualifier: Optional[str], account: str, region: str) -> str:
    """
    Return the lambda arn for the given parameters, with a qualifier if supplied, without otherwise

    :param function_name: Function name
    :param qualifier: Qualifier. May be left out, then the returning arn does not have one either
    :param account: Account ID
    :param region: Region of the Lambda
    :return: Lambda Arn with or without qualifier
    """
    if qualifier:
        return qualified_lambda_arn(
            function_name=function_name, qualifier=qualifier, account=account, region=region
        )
    else:
        return unqualified_lambda_arn(function_name=function_name, account=account, region=region)


def is_role_arn(role_arn: str) -> bool:
    """
    Returns true if the provided string is a role arn, false otherwise

    :param role_arn: Potential role arn
    :return: Boolean indicating if input is a role arn
    """
    return bool(ROLE_REGEX.match(role_arn))


def format_lambda_date(date_to_format: datetime.datetime) -> str:
    """Format a given datetime to a string generated with the lambda date format"""
    return date_to_format.strftime(LAMBDA_DATE_FORMAT)


def generate_lambda_date() -> str:
    """Get the current date as string generated with the lambda date format"""
    return format_lambda_date(datetime.datetime.now())


def map_update_status_config(version: "FunctionVersion") -> dict[str, str]:
    """Map version model to dict output"""
    result = {}
    if version.config.last_update:
        if version.config.last_update.status:
            result["LastUpdateStatus"] = version.config.last_update.status
        if version.config.last_update.code:
            result["LastUpdateStatusReasonCode"] = version.config.last_update.code
        if version.config.last_update.reason:
            result["LastUpdateStatusReason"] = version.config.last_update.reason
    return result


def map_state_config(version: "FunctionVersion") -> dict[str, str]:
    """Map version state to dict output"""
    result = {}
    if version_state := version.config.state:
        if version_state.state:
            result["State"] = version_state.state
        if version_state.reason:
            result["StateReason"] = version_state.reason
        if version_state.code:
            result["StateReasonCode"] = version_state.code
    return result


def map_config_out(
    version: "FunctionVersion",
    return_qualified_arn: bool = False,
    return_update_status: bool = True,
) -> FunctionConfiguration:
    """map version config to function configuration"""

    # handle optional entries that shouldn't be rendered at all if not present
    optional_kwargs = {}
    if return_update_status:
        optional_kwargs.update(map_update_status_config(version))
    optional_kwargs.update(map_state_config(version))

    if version.config.architectures:
        optional_kwargs["Architectures"] = version.config.architectures
    if version.config.environment is not None:
        optional_kwargs["Environment"] = EnvironmentResponse(
            Variables=version.config.environment
        )  # TODO: Errors key?

    func_conf = FunctionConfiguration(
        RevisionId=version.config.revision_id,
        FunctionName=version.id.function_name,
        FunctionArn=version.id.qualified_arn()
        if return_qualified_arn
        else version.id.unqualified_arn(),  # qualifier usually not included
        LastModified=version.config.last_modified,
        Version=version.id.qualifier,
        Description=version.config.description,
        Role=version.config.role,
        Timeout=version.config.timeout,
        Runtime=version.config.runtime,
        Handler=version.config.handler,
        CodeSize=version.config.code.code_size,
        CodeSha256=version.config.code.code_sha256,
        MemorySize=version.config.memory_size,
        PackageType=version.config.package_type,
        TracingConfig=TracingConfig(Mode=version.config.tracing_config_mode),
        EphemeralStorage=EphemeralStorage(Size=version.config.ephemeral_storage.size),
        **optional_kwargs,
    )
    return func_conf


def map_to_list_response(config: FunctionConfiguration) -> FunctionConfiguration:
    """remove values not usually presented in list operations from function config output"""
    shallow_copy = config.copy()
    for k in [
        "State",
        "StateReason",
        "StateReasonCode",
        "LastUpdateStatus",
        "LastUpdateStatusReason",
        "LastUpdateStatusReasonCode",
    ]:
        shallow_copy.pop(k, None)
    return shallow_copy


def map_alias_out(alias: "VersionAlias", function: "Function") -> AliasConfiguration:
    """map alias model to alias configuration output"""
    alias_arn = f"{function.latest().id.unqualified_arn()}:{alias.name}"
    optional_kwargs = {}
    if alias.routing_configuration:
        optional_kwargs |= {
            "RoutingConfig": {
                "AdditionalVersionWeights": alias.routing_configuration.version_weights
            }
        }
    return AliasConfiguration(
        AliasArn=alias_arn,
        Description=alias.description,
        FunctionVersion=alias.function_version,
        Name=alias.name,
        RevisionId=alias.revision_id,
        **optional_kwargs,
    )
