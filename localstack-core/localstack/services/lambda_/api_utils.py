"""Utilities related to Lambda API operations such as ARN handling, validations, and output formatting.
Everything related to behavior or implicit functionality goes into `lambda_utils.py`.
"""

import datetime
import random
import re
import string
from typing import TYPE_CHECKING, Any, Optional, Tuple

from localstack.aws.api import RequestContext
from localstack.aws.api import lambda_ as api_spec
from localstack.aws.api.lambda_ import (
    AliasConfiguration,
    Architecture,
    DeadLetterConfig,
    EnvironmentResponse,
    EphemeralStorage,
    FunctionConfiguration,
    FunctionUrlAuthType,
    ImageConfig,
    ImageConfigResponse,
    InvalidParameterValueException,
    LayerVersionContentOutput,
    PublishLayerVersionResponse,
    ResourceNotFoundException,
    TracingConfig,
    VpcConfigResponse,
)
from localstack.services.lambda_.runtimes import ALL_RUNTIMES, VALID_LAYER_RUNTIMES, VALID_RUNTIMES
from localstack.utils.collections import merge_recursive

if TYPE_CHECKING:
    from localstack.services.lambda_.invocation.lambda_models import (
        CodeSigningConfig,
        Function,
        FunctionUrlConfig,
        FunctionVersion,
        LayerVersion,
        VersionAlias,
    )
    from localstack.services.lambda_.invocation.models import LambdaStore


# Pattern for a full (both with and without qualifier) lambda function ARN
FULL_FN_ARN_PATTERN = re.compile(
    r"^arn:aws:lambda:(?P<region_name>[^:]+):(?P<account_id>\d{12}):function:(?P<function_name>[^:]+)(:(?P<qualifier>.*))?$"
)

# Pattern for a full (both with and without qualifier) lambda function ARN
LAYER_VERSION_ARN_PATTERN = re.compile(
    r"^arn:aws:lambda:(?P<region_name>[^:]+):(?P<account_id>\d{12}):layer:(?P<layer_name>[^:]+)(:(?P<layer_version>\d+))?$"
)


# Pattern for a valid destination arn
DESTINATION_ARN_PATTERN = re.compile(
    r"^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)

AWS_FUNCTION_NAME_REGEX = re.compile(
    "^(arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\\d{1}:)?(\\d{12}:)?(function:)?([a-zA-Z0-9-_.]+)(:(\\$LATEST|[a-zA-Z0-9-_]+))?$"
)

# Pattern for extracting various attributes from a full or partial ARN or just a function name.
FUNCTION_NAME_REGEX = re.compile(
    r"(arn:(aws[a-zA-Z-]*):lambda:)?((?P<region>[a-z]{2}(-gov)?-[a-z]+-\d{1}):)?(?:(?P<account>\d{12}):)?(function:)?(?P<name>[a-zA-Z0-9-_\.]+)(:(?P<qualifier>\$LATEST|[a-zA-Z0-9-_]+))?"
)  # also length 1-170 incl.
# Pattern for a lambda function handler
HANDLER_REGEX = re.compile(r"[^\s]+")
# Pattern for a valid kms key
KMS_KEY_ARN_REGEX = re.compile(r"(arn:(aws[a-zA-Z-]*)?:[a-z0-9-.]+:.*)|()")
# Pattern for a valid IAM role assumed by a lambda function
ROLE_REGEX = re.compile(r"arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+")
# Pattern for a valid AWS account
AWS_ACCOUNT_REGEX = re.compile(r"\d{12}")
# Pattern for a signing job arn
SIGNING_JOB_ARN_REGEX = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
# Pattern for a signing profiler version arn
SIGNING_PROFILE_VERSION_ARN_REGEX = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
# Combined pattern for alias and version based on AWS error using "(|[a-zA-Z0-9$_-]+)"
QUALIFIER_REGEX = re.compile(r"(^[a-zA-Z0-9$_-]+$)")
# Pattern for a version qualifier
VERSION_REGEX = re.compile(r"^[0-9]+$")
# Pattern for an alias qualifier
# Rules: https://docs.aws.amazon.com/lambda/latest/dg/API_CreateAlias.html#SSS-CreateAlias-request-Name
# The original regex from AWS misses ^ and $ in the second regex, which allowed for partial substring matches
ALIAS_REGEX = re.compile(r"(?!^[0-9]+$)(^[a-zA-Z0-9-_]+$)")
# Permission statement id
STATEMENT_ID_REGEX = re.compile(r"^[a-zA-Z0-9-_]+$")


URL_CHAR_SET = string.ascii_lowercase + string.digits
# Date format as returned by the lambda service
LAMBDA_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+0000"

# An unordered list of all Lambda CPU architectures supported by LocalStack.
ARCHITECTURES = [Architecture.arm64, Architecture.x86_64]


def map_function_url_config(model: "FunctionUrlConfig") -> api_spec.FunctionUrlConfig:
    return api_spec.FunctionUrlConfig(
        FunctionUrl=model.url,
        FunctionArn=model.function_arn,
        CreationTime=model.creation_time,
        LastModifiedTime=model.last_modified_time,
        Cors=model.cors,
        AuthType=model.auth_type,
        InvokeMode=model.invoke_mode,
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


def is_qualifier_expression(qualifier: str) -> bool:
    """Checks if a given qualifier is a syntactically accepted expression.
    It is not necessarily a valid alias or version.

    :param qualifier: Qualifier to check
    :return True if syntactically accepted qualifier expression, false otherwise
    """
    return bool(QUALIFIER_REGEX.match(qualifier))


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


def get_function_name(function_arn_or_name: str, context: RequestContext) -> str:
    """
    Return function name from a given arn.
    Will check if the context region matches the arn region in the arn, if an arn is provided.

    :param function_arn_or_name: Function arn or only name
    :return: function name
    """
    name, _ = get_name_and_qualifier(function_arn_or_name, qualifier=None, context=context)
    return name


def function_locators_from_arn(arn: str) -> tuple[str, str | None, str | None, str | None]:
    """
    Takes a full or partial arn, or a name

    :param arn: Given arn (or name)
    :return: tuple with (name, qualifier, account, region). Qualifier and region are none if missing
    """
    return FUNCTION_NAME_REGEX.match(arn).group("name", "qualifier", "account", "region")


def get_account_and_region(function_arn_or_name: str, context: RequestContext) -> Tuple[str, str]:
    """
    Takes a full ARN, partial ARN or a name. Returns account ID and region from ARN if available, else
    falls back to context account ID and region.

    Lambda allows cross-account access. This function should be used to resolve the correct Store based on the ARN.
    """
    _, _, account_id, region = function_locators_from_arn(function_arn_or_name)
    return account_id or context.account_id, region or context.region


def get_name_and_qualifier(
    function_arn_or_name: str, qualifier: str | None, context: RequestContext
) -> tuple[str, str | None]:
    """
    Takes a full or partial arn, or a name and a qualifier
    Will raise exception if a qualified arn is provided and the qualifier does not match (but is given)

    :param function_arn_or_name: Given arn (or name)
    :param qualifier: A qualifier for the function (or None)
    :param context: Request context
    :return: tuple with (name, qualifier). Qualifier is none if missing
    """
    function_name, arn_qualifier, _, arn_region = function_locators_from_arn(function_arn_or_name)
    if qualifier and arn_qualifier and arn_qualifier != qualifier:
        raise InvalidParameterValueException(
            "The derived qualifier from the function name does not match the specified qualifier.",
            Type="User",
        )
    if arn_region and arn_region != context.region:
        raise ResourceNotFoundException(
            f"Functions from '{arn_region}' are not reachable in this region ('{context.region}')",
            Type="User",
        )
    qualifier = qualifier or arn_qualifier
    return function_name, qualifier


def get_function_arn(function_name_or_arn, context, state):
    # Can be either a partial arn or a full arn for the version/alias
    function_name, qualifier, account, region = function_locators_from_arn(function_name_or_arn)
    account = account or context.account_id
    region = region or context.region
    fn = state.functions.get(function_name)
    if not fn:
        raise InvalidParameterValueException("Function does not exist", Type="User")
    if qualifier:
        # make sure the function version/alias exists
        if qualifier_is_alias(qualifier):
            fn_alias = fn.aliases.get(qualifier)
            if not fn_alias:
                raise Exception("unknown alias")  # TODO: cover via test
        elif qualifier_is_version(qualifier):
            fn_version = fn.versions.get(qualifier)
            if not fn_version:
                raise Exception("unknown version")  # TODO: cover via test
        elif qualifier == "$LATEST":
            pass
        else:
            raise Exception("invalid functionname")  # TODO: cover via test
        fn_arn = qualified_lambda_arn(function_name, qualifier, account, region)

    else:
        fn_arn = unqualified_lambda_arn(function_name, account, region)
    return fn_arn, function_name


def build_statement(
    resource_arn: str,
    statement_id: str,
    action: str,
    principal: str,
    source_arn: Optional[str] = None,
    source_account: Optional[str] = None,
    principal_org_id: Optional[str] = None,
    event_source_token: Optional[str] = None,
    auth_type: Optional[FunctionUrlAuthType] = None,
) -> dict[str, Any]:
    statement = {
        "Sid": statement_id,
        "Effect": "Allow",
        "Action": action,
        "Resource": resource_arn,
    }

    # See AWS service principals for comprehensive docs:
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
    # TODO: validate against actual list of IAM-supported AWS services (e.g., lambda.amazonaws.com)
    if principal.endswith(".amazonaws.com"):
        statement["Principal"] = {"Service": principal}
    elif is_aws_account(principal):
        statement["Principal"] = {"AWS": f"arn:aws:iam::{principal}:root"}
    # TODO: potentially validate against IAM?
    elif principal.startswith("arn:aws:iam:"):
        statement["Principal"] = {"AWS": principal}
    elif principal == "*":
        statement["Principal"] = principal
    # TODO: unclear whether above matching is complete?
    else:
        raise InvalidParameterValueException(
            "The provided principal was invalid. Please check the principal and try again.",
            Type="User",
        )

    condition = dict()
    if auth_type:
        update = {"StringEquals": {"lambda:FunctionUrlAuthType": auth_type}}
        condition = merge_recursive(condition, update)

    if principal_org_id:
        update = {"StringEquals": {"aws:PrincipalOrgID": principal_org_id}}
        condition = merge_recursive(condition, update)

    if source_account:
        update = {"StringEquals": {"AWS:SourceAccount": source_account}}
        condition = merge_recursive(condition, update)

    if event_source_token:
        update = {"StringEquals": {"lambda:EventSourceToken": event_source_token}}
        condition = merge_recursive(condition, update)

    if source_arn:
        update = {"ArnLike": {"AWS:SourceArn": source_arn}}
        condition = merge_recursive(condition, update)

    if condition:
        statement["Condition"] = condition

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


def is_aws_account(aws_account: str) -> bool:
    """
    Returns true if the provided string is an AWS account, false otherwise

    :param role_arn: Potential AWS account
    :return: Boolean indicating if input is an AWS account
    """
    return bool(AWS_ACCOUNT_REGEX.match(aws_account))


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
    alias_name: str | None = None,
) -> FunctionConfiguration:
    """map function version to function configuration"""

    # handle optional entries that shouldn't be rendered at all if not present
    optional_kwargs = {}
    if return_update_status:
        optional_kwargs.update(map_update_status_config(version))
    optional_kwargs.update(map_state_config(version))

    if version.config.architectures:
        optional_kwargs["Architectures"] = version.config.architectures

    if version.config.dead_letter_arn:
        optional_kwargs["DeadLetterConfig"] = DeadLetterConfig(
            TargetArn=version.config.dead_letter_arn
        )

    if version.config.vpc_config:
        optional_kwargs["VpcConfig"] = VpcConfigResponse(
            VpcId=version.config.vpc_config.vpc_id,
            SubnetIds=version.config.vpc_config.subnet_ids,
            SecurityGroupIds=version.config.vpc_config.security_group_ids,
        )

    if version.config.environment is not None:
        optional_kwargs["Environment"] = EnvironmentResponse(
            Variables=version.config.environment
        )  # TODO: Errors key?

    if version.config.layers:
        optional_kwargs["Layers"] = [
            {"Arn": layer.layer_version_arn, "CodeSize": layer.code.code_size}
            for layer in version.config.layers
        ]
    if version.config.image_config:
        image_config = ImageConfig()
        if version.config.image_config.command:
            image_config["Command"] = version.config.image_config.command
        if version.config.image_config.entrypoint:
            image_config["EntryPoint"] = version.config.image_config.entrypoint
        if version.config.image_config.working_directory:
            image_config["WorkingDirectory"] = version.config.image_config.working_directory
        if image_config:
            optional_kwargs["ImageConfigResponse"] = ImageConfigResponse(ImageConfig=image_config)
    if version.config.code:
        optional_kwargs["CodeSize"] = version.config.code.code_size
        optional_kwargs["CodeSha256"] = version.config.code.code_sha256
    elif version.config.image:
        optional_kwargs["CodeSize"] = 0
        optional_kwargs["CodeSha256"] = version.config.image.code_sha256

    # output for an alias qualifier is completely the same except for the returned ARN
    if alias_name:
        function_arn = f"{':'.join(version.id.qualified_arn().split(':')[:-1])}:{alias_name}"
    else:
        function_arn = (
            version.id.qualified_arn() if return_qualified_arn else version.id.unqualified_arn()
        )

    func_conf = FunctionConfiguration(
        RevisionId=version.config.revision_id,
        FunctionName=version.id.function_name,
        FunctionArn=function_arn,
        LastModified=version.config.last_modified,
        Version=version.id.qualifier,
        Description=version.config.description,
        Role=version.config.role,
        Timeout=version.config.timeout,
        Runtime=version.config.runtime,
        Handler=version.config.handler,
        MemorySize=version.config.memory_size,
        PackageType=version.config.package_type,
        TracingConfig=TracingConfig(Mode=version.config.tracing_config_mode),
        EphemeralStorage=EphemeralStorage(Size=version.config.ephemeral_storage.size),
        SnapStart=version.config.snap_start,
        RuntimeVersionConfig=version.config.runtime_version_config,
        LoggingConfig=version.config.logging_config,
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
        "RuntimeVersionConfig",
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


def validate_and_set_batch_size(event_source_arn: str, batch_size: Optional[int] = None) -> int:
    min_batch_size = 1

    BATCH_SIZE_RANGES = {
        "kafka": (100, 10_000),
        "kinesis": (100, 10_000),
        "dynamodb": (100, 1_000),
        "sqs-fifo": (10, 10),
        "sqs": (10, 10_000),
        "mq": (100, 10_000),
    }
    svc = event_source_arn.split(":")[2]  # arn:<parition>:<svc>:<region>:...
    if svc == "sqs" and "fifo" in event_source_arn:
        svc = "sqs-fifo"
    svc_range = BATCH_SIZE_RANGES.get(svc)

    if svc_range:
        default_batch_size, max_batch_size = svc_range

        if batch_size is None:
            batch_size = default_batch_size

        if batch_size < min_batch_size or batch_size > max_batch_size:
            raise InvalidParameterValueException("out of bounds todo", Type="User")  # TODO: test

    return batch_size


def map_layer_out(layer_version: "LayerVersion") -> PublishLayerVersionResponse:
    return PublishLayerVersionResponse(
        Content=LayerVersionContentOutput(
            Location=layer_version.code.generate_presigned_url(),
            CodeSha256=layer_version.code.code_sha256,
            CodeSize=layer_version.code.code_size,
            # SigningProfileVersionArn="", # same as in function configuration
            # SigningJobArn="" # same as in function configuration
        ),
        LicenseInfo=layer_version.license_info,
        Description=layer_version.description,
        CompatibleArchitectures=layer_version.compatible_architectures,
        CompatibleRuntimes=layer_version.compatible_runtimes,
        CreatedDate=layer_version.created,
        LayerArn=layer_version.layer_arn,
        LayerVersionArn=layer_version.layer_version_arn,
        Version=layer_version.version,
    )


def layer_arn(layer_name: str, account: str, region: str):
    return f"arn:aws:lambda:{region}:{account}:layer:{layer_name}"


def layer_version_arn(layer_name: str, account: str, region: str, version: str):
    return f"arn:aws:lambda:{region}:{account}:layer:{layer_name}:{version}"


def parse_layer_arn(layer_version_arn: str) -> Tuple[str, str, str, str]:
    return LAYER_VERSION_ARN_PATTERN.match(layer_version_arn).group(
        "region_name", "account_id", "layer_name", "layer_version"
    )


def validate_layer_runtime(compatible_runtime: str) -> str | None:
    if compatible_runtime is not None and compatible_runtime not in ALL_RUNTIMES:
        return f"Value '{compatible_runtime}' at 'compatibleRuntime' failed to satisfy constraint: Member must satisfy enum value set: {VALID_LAYER_RUNTIMES}"
    return None


def validate_layer_architecture(compatible_architecture: str) -> str | None:
    if compatible_architecture is not None and compatible_architecture not in ARCHITECTURES:
        return f"Value '{compatible_architecture}' at 'compatibleArchitecture' failed to satisfy constraint: Member must satisfy enum value set: [x86_64, arm64]"
    return None


def validate_layer_runtimes_and_architectures(
    compatible_runtimes: list[str], compatible_architectures: list[str]
):
    validations = []

    if compatible_runtimes and set(compatible_runtimes).difference(ALL_RUNTIMES):
        constraint = f"Member must satisfy enum value set: {VALID_RUNTIMES}"
        validation_msg = f"Value '[{', '.join([s for s in compatible_runtimes])}]' at 'compatibleRuntimes' failed to satisfy constraint: {constraint}"
        validations.append(validation_msg)

    if compatible_architectures and set(compatible_architectures).difference(ARCHITECTURES):
        constraint = "[Member must satisfy enum value set: [x86_64, arm64]]"
        validation_msg = f"Value '[{', '.join([s for s in compatible_architectures])}]' at 'compatibleArchitectures' failed to satisfy constraint: Member must satisfy constraint: {constraint}"
        validations.append(validation_msg)

    return validations


def is_layer_arn(layer_name: str) -> bool:
    return LAYER_VERSION_ARN_PATTERN.match(layer_name) is not None


def validate_function_name(function_name):
    return AWS_FUNCTION_NAME_REGEX.match(function_name)
