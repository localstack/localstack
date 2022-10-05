import base64
import dataclasses
import datetime
import json
import logging
import threading
import time
from typing import IO

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.lambda_ import (
    AccountLimit,
    AccountUsage,
    AddPermissionRequest,
    AddPermissionResponse,
    Alias,
    AliasConfiguration,
    AliasRoutingConfiguration,
    AllowedPublishers,
    Architecture,
    Arn,
    Blob,
    CodeSigningConfigArn,
    CodeSigningConfigNotFoundException,
    CodeSigningPolicies,
    Cors,
    CreateCodeSigningConfigResponse,
    CreateEventSourceMappingRequest,
    CreateFunctionRequest,
    CreateFunctionUrlConfigResponse,
    DeleteCodeSigningConfigResponse,
    Description,
    DestinationConfig,
    EnvironmentResponse,
    EphemeralStorage,
    EventSourceMappingConfiguration,
    FunctionCodeLocation,
    FunctionConfiguration,
    FunctionEventInvokeConfig,
    FunctionName,
    FunctionUrlAuthType,
    FunctionUrlQualifier,
    GetAccountSettingsResponse,
    GetCodeSigningConfigResponse,
    GetFunctionCodeSigningConfigResponse,
    GetFunctionResponse,
    GetFunctionUrlConfigResponse,
    GetPolicyResponse,
    GetProvisionedConcurrencyConfigResponse,
    InvalidParameterValueException,
    InvocationResponse,
    InvocationType,
    LambdaApi,
    LastUpdateStatus,
    ListAliasesResponse,
    ListCodeSigningConfigsResponse,
    ListEventSourceMappingsResponse,
    ListFunctionEventInvokeConfigsResponse,
    ListFunctionsByCodeSigningConfigResponse,
    ListFunctionsResponse,
    ListFunctionUrlConfigsResponse,
    ListProvisionedConcurrencyConfigsResponse,
    ListVersionsByFunctionResponse,
    LogType,
    MasterRegion,
    MaxFunctionEventInvokeConfigListItems,
    MaximumEventAgeInSeconds,
    MaximumRetryAttempts,
    MaxItems,
    MaxListItems,
    MaxProvisionedConcurrencyConfigListItems,
    NamespacedFunctionName,
    NamespacedStatementId,
    PackageType,
    PositiveInteger,
    PreconditionFailedException,
    ProvisionedConcurrencyConfigListItem,
    ProvisionedConcurrencyStatusEnum,
    PutFunctionCodeSigningConfigResponse,
    PutProvisionedConcurrencyConfigResponse,
    Qualifier,
    ResourceConflictException,
    ResourceNotFoundException,
    ServiceException,
    State,
    StateReasonCode,
    String,
    TracingConfig,
    TracingMode,
    UpdateCodeSigningConfigResponse,
    UpdateEventSourceMappingRequest,
    UpdateFunctionCodeRequest,
    UpdateFunctionConfigurationRequest,
    UpdateFunctionUrlConfigResponse,
    Version,
)
from localstack.services.awslambda import api_utils
from localstack.services.awslambda.api_utils import FN_ARN_PATTERN, get_name_and_qualifier
from localstack.services.awslambda.invocation.lambda_models import (
    AliasRoutingConfig,
    CodeSigningConfig,
    EventInvokeConfig,
    Function,
    FunctionResourcePolicy,
    FunctionUrlConfig,
    FunctionVersion,
    InvocationError,
    LambdaEphemeralStorage,
    ResourcePolicy,
    UpdateStatus,
    ValidationException,
    VersionAlias,
    VersionFunctionConfiguration,
    VersionIdentifier,
    VersionState,
)
from localstack.services.awslambda.invocation.lambda_service import (
    LambdaService,
    lambda_stores,
    store_lambda_archive,
    store_s3_bucket_archive,
)
from localstack.services.awslambda.invocation.lambda_util import (
    LAMBDA_DATE_FORMAT,
    format_lambda_date,
    function_name_from_arn,
    generate_lambda_date,
    lambda_arn,
    qualified_lambda_arn,
    unqualified_lambda_arn,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import PaginatedList
from localstack.utils.strings import get_random_hex, long_uid, short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128


class LambdaProvider(LambdaApi, ServiceLifecycleHook):
    lambda_service: LambdaService
    lock: threading.RLock
    create_fn_lock: threading.RLock

    def __init__(self) -> None:
        self.lambda_service = LambdaService()
        self.lock = threading.RLock()
        self.create_fn_lock = threading.RLock()

    def on_before_stop(self) -> None:
        self.lambda_service.stop()

    @staticmethod
    def _get_function(function_name: str, account_id: str, region: str):
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        if not function:
            arn = unqualified_lambda_arn(
                function_name=function_name,
                account=account_id,
                region=region,
            )
            raise ResourceNotFoundException(
                f"Function not found: {arn}",
                Type="User",
            )
        return function

    @staticmethod
    def _get_function_version(
        function_name: str, qualifier: str | None, account_id: str, region: str
    ):
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

    @staticmethod
    def _map_version_config(version: FunctionVersion) -> dict[str, str]:
        result = {}
        if version.config.last_update:
            if version.config.last_update.status:
                result["LastUpdateStatus"] = version.config.last_update.status
            if version.config.last_update.code:
                result["LastUpdateStatusReasonCode"] = version.config.last_update.code
            if version.config.last_update.reason:
                result["LastUpdateStatusReason"] = version.config.last_update.reason
        return result

    @staticmethod
    def _map_state_config(version: FunctionVersion) -> dict[str, str]:
        result = {}
        if version_state := version.config.state:
            if version_state.state:
                result["State"] = version_state.state
            if version_state.reason:
                result["StateReason"] = version_state.reason
            if version_state.code:
                result["StateReasonCode"] = version_state.code
        return result

    def _map_config_out(
        self, version: FunctionVersion, return_qualified_arn: bool = False
    ) -> FunctionConfiguration:

        # handle optional entries that shouldn't be rendered at all if not present
        optional_kwargs = {}
        optional_kwargs |= self._map_version_config(version)
        optional_kwargs |= self._map_state_config(version)

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

    def _map_to_list_response(self, config: FunctionConfiguration) -> FunctionConfiguration:
        shallow_copy = config.copy()
        for k in [
            "State",
            "StateReason",
            "StateReasonCode",
            "LastUpdateStatus",
            "LastUpdateStatusReason",
            "LastUpdateStatusReasonCode",
        ]:
            if shallow_copy.get(k):
                del shallow_copy[k]
        return shallow_copy

    def _publish_version(
        self,
        function_name: str,
        region: str,
        account_id: str,
        description: str | None = None,
        revision_id: str | None = None,
        code_sha256: str | None = None,
    ):
        current_latest_version = self._get_function_version(
            function_name=function_name, qualifier="$LATEST", account_id=account_id, region=region
        )
        if revision_id and current_latest_version.config.revision_id != revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )
        current_hash = current_latest_version.config.code.code_sha256
        if code_sha256 and current_hash != code_sha256:
            raise InvalidParameterValueException(
                f"CodeSHA256 ({code_sha256}) is different from current CodeSHA256 in $LATEST ({current_hash}). Please try again with the CodeSHA256 in $LATEST.",
                Type="User",
            )
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        changes = {}
        if description is not None:
            changes["description"] = description
        with function.lock:
            # TODO check if there was a change since last version
            next_version = str(function.next_version)
            function.next_version += 1
            new_id = VersionIdentifier(
                function_name=function_name,
                qualifier=next_version,
                region=region,
                account=account_id,
            )
            new_version = dataclasses.replace(
                current_latest_version,
                config=dataclasses.replace(current_latest_version.config, **changes),
                id=new_id,
            )
            function.versions[next_version] = new_version
        # TODO state active from the start?
        self.lambda_service.create_function_version(new_version)
        return new_version

    @handler(operation="CreateFunction", expand=False)
    def create_function(
        self,
        context: RequestContext,
        request: CreateFunctionRequest,
    ) -> FunctionConfiguration:

        # publish_version = request.get('Publish', False)

        architectures = request.get("Architectures")
        if architectures and Architecture.arm64 in architectures:
            raise ServiceException("ARM64 is currently not supported by this provider")

        state = lambda_stores[context.account_id][context.region]

        function_name = request["FunctionName"]
        with self.create_fn_lock:
            if function_name in state.functions:
                raise ResourceConflictException(f"Function already exist: {function_name}")
            fn = Function(function_name=function_name)
            arn = VersionIdentifier(
                function_name=function_name,
                qualifier="$LATEST",
                region=context.region,
                account=context.account_id,
            )
            # save function code to s3
            code = None
            if request.get("PackageType", PackageType.Zip) == PackageType.Zip:
                request_code = request["Code"]
                # TODO verify if correct combination of code is set
                if zip_file := request_code.get("ZipFile"):
                    code = store_lambda_archive(
                        archive_file=zip_file,
                        function_name=function_name,
                        region_name=context.region,
                        account_id=context.account_id,
                    )
                elif s3_bucket := request_code.get("S3Bucket"):
                    s3_key = request_code["S3Key"]
                    s3_object_version = request_code.get("S3ObjectVersion")
                    code = store_s3_bucket_archive(
                        archive_bucket=s3_bucket,
                        archive_key=s3_key,
                        archive_version=s3_object_version,
                        function_name=function_name,
                        region_name=context.region,
                        account_id=context.account_id,
                    )
                else:
                    raise ServiceException("Gotta have s3 bucket or zip file")

            version = FunctionVersion(
                id=arn,
                config=VersionFunctionConfiguration(
                    function_arn=arn.qualified_arn(),
                    last_modified=format_lambda_date(datetime.datetime.now()),
                    description=request.get("Description", ""),
                    role=request["Role"],
                    timeout=request.get("Timeout", LAMBDA_DEFAULT_TIMEOUT),
                    runtime=request["Runtime"],
                    memory_size=request.get("MemorySize", LAMBDA_DEFAULT_MEMORY_SIZE),
                    handler=request["Handler"],
                    package_type=PackageType.Zip,  # TODO
                    reserved_concurrent_executions=0,
                    environment=request.get("Environment", {}).get("Variables"),
                    architectures=request.get("Architectures") or ["x86_64"],  # TODO
                    tracing_config_mode=TracingMode.PassThrough,  # TODO
                    image_config=None,  # TODO
                    code=code,
                    layers=[],  # TODO
                    internal_revision=short_uid(),
                    ephemeral_storage=LambdaEphemeralStorage(
                        size=request.get("EphemeralStorage", {}).get("Size", 512)
                    ),
                    state=VersionState(
                        state=State.Pending,
                        code=StateReasonCode.Creating,
                        reason="The function is being created.",
                    ),
                ),
            )
            fn.versions["$LATEST"] = version
            state.functions[function_name] = fn
        self.lambda_service.create_function_version(version)

        if request.get("Publish"):
            version = self._publish_version(
                function_name=function_name, region=context.region, account_id=context.account_id
            )

        return self._map_config_out(version, return_qualified_arn=False)

    @handler(operation="UpdateFunctionConfiguration", expand=False)
    def update_function_configuration(
        self, context: RequestContext, request: UpdateFunctionConfigurationRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        function_name = request.get("FunctionName")  # TODO: can this be an ARN too?
        state = lambda_stores[context.account_id][context.region]

        if function_name not in state.functions:
            raise ResourceNotFoundException(
                f"Function not found: {unqualified_lambda_arn(function_name=function_name, region=context.region, account=context.account_id)}",
                Type="User",
            )
        function = state.functions[function_name]

        # TODO: lock modification of latest version
        # TODO: notify service for changes relevant to re-provisioning of $LATEST
        latest_version = function.latest()
        latest_version_config = latest_version.config

        replace_kwargs = {}
        if "EphemeralStorage" in request:
            replace_kwargs["ephemeral_storage"] = LambdaEphemeralStorage(
                request.get("EphemeralStorage", {}).get("Size", 512)
            )  # TODO: do defaults here apply as well?

        if "Role" in request:
            replace_kwargs["role"] = request["Role"]

        if "Description" in request:
            replace_kwargs["description"] = request["Description"]

        if "Timeout" in request:
            replace_kwargs["timeout"] = request["Timeout"]

        if "MemorySize" in request:
            replace_kwargs["memory_size"] = request["MemorySize"]

        if "Runtime" in request:
            replace_kwargs["runtime"] = request["Runtime"]

        if "Environment" in request:
            replace_kwargs["environment"] = {
                k: v for k, v in request.get("Environment", {}).get("Variables", {}).items()
            }
        new_latest_version = dataclasses.replace(
            latest_version,
            config=dataclasses.replace(
                latest_version_config,
                last_modified=generate_lambda_date(),
                internal_revision=short_uid(),
                last_update=UpdateStatus(
                    status=LastUpdateStatus.InProgress,
                    code="Creating",
                    reason="The function is being created.",
                ),
                **replace_kwargs,
            ),
        )
        function.versions["$LATEST"] = new_latest_version  # TODO: notify
        self.lambda_service.update_version(new_version=new_latest_version)

        return self._map_config_out(new_latest_version)

    @handler(operation="UpdateFunctionCode", expand=False)
    def update_function_code(
        self, context: RequestContext, request: UpdateFunctionCodeRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        # only supports normal zip packaging atm
        # if request.get("Publish"):
        #     self.lambda_service.create_function_version()

        function_name = request.get("FunctionName")
        state = lambda_stores[context.account_id][context.region]
        if function_name not in state.functions:
            raise ResourceNotFoundException(
                f"Function not found: {unqualified_lambda_arn(function_name=function_name, region=context.region, account=context.account_id)}",
                Type="User",
            )
        function = state.functions[function_name]
        # TODO verify if correct combination of code is set
        if zip_file := request.get("ZipFile"):
            code = store_lambda_archive(
                archive_file=zip_file,
                function_name=function_name,
                region_name=context.region,
                account_id=context.account_id,
            )
        elif s3_bucket := request.get("S3Bucket"):
            s3_key = request["S3Key"]
            s3_object_version = request.get("S3ObjectVersion")
            code = store_s3_bucket_archive(
                archive_bucket=s3_bucket,
                archive_key=s3_key,
                archive_version=s3_object_version,
                function_name=function_name,
                region_name=context.region,
                account_id=context.account_id,
            )
        else:
            raise ServiceException("Gotta have s3 bucket or zip file")

        old_function_version = function.versions.get("$LATEST")
        config = dataclasses.replace(
            old_function_version.config,
            code=code,
            internal_revision=short_uid(),
            last_modified=generate_lambda_date(),
            last_update=UpdateStatus(
                status=LastUpdateStatus.InProgress,
                code="Creating",
                reason="The function is being created.",
            ),
        )
        function_version = dataclasses.replace(old_function_version, config=config)
        function.versions["$LATEST"] = function_version

        self.lambda_service.update_version(new_version=function_version)
        if request.get("Publish"):
            function_version = self._publish_version(
                function_name=function_name, region=context.region, account_id=context.account_id
            )
        return self._map_config_out(function_version)

    # TODO: does deleting the latest published version affect the next versions number?
    # TODO: what happens when we call this with a qualifier and a fully qualified ARN? (+ conflicts?)
    # TODO: test different ARN patterns (shorthand ARN?)
    # TODO: test deleting across regions?
    # TODO: test mismatch between context region and region in ARN
    # TODO: test qualifier $LATEST, alias-name and version
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        if qualifier == "$LATEST":
            raise InvalidParameterValueException(
                "$LATEST version cannot be deleted without deleting the function.", Type="User"
            )

        if function_name not in state.functions:
            e = ResourceNotFoundException(
                f"Function not found: {unqualified_lambda_arn(function_name=function_name, region=context.region, account=context.account_id)}",
                Type="User",
            )
            raise e
        function = state.functions.get(function_name)

        if qualifier:
            # delete a version of the function
            version = function.versions.pop(qualifier, None)
            if version:
                self.lambda_service.stop_version(version.qualified_arn())
        else:
            # delete the whole function
            function = state.functions.pop(function_name)
            for version in function.versions.values():
                self.lambda_service.stop_version(qualified_arn=version.id.qualified_arn())
                # we can safely destroy the code here
                version.config.code.destroy()

    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,  # (only relevant for lambda@edge)
        function_version: FunctionVersion = None,  # TODO
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListFunctionsResponse:
        state = lambda_stores[context.account_id][context.region]
        versions = [f.latest() for f in state.functions.values()]  # TODO: qualifier
        return ListFunctionsResponse(
            Functions=[self._map_to_list_response(self._map_config_out(fc)) for fc in versions]
        )

    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,  # TODO
    ) -> GetFunctionResponse:
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        version = self._get_function_version(
            function_name=function_name,
            qualifier=qualifier,
            account_id=context.account_id,
            region=context.region,
        )
        # TODO what if no version?
        code = version.config.code
        return GetFunctionResponse(
            Configuration=self._map_config_out(version, return_qualified_arn=bool(qualifier)),
            Code=FunctionCodeLocation(
                Location=code.generate_presigned_url(), RepositoryType="S3"
            ),  # TODO
            # Tags={},  # TODO
            # Concurrency={},  # TODO
        )

    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> FunctionConfiguration:
        # CAVE: THIS RETURN VALUE IS *NOT* THE SAME AS IN get_function (!) but seems to be only configuration part?
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        version = self._get_function_version(
            function_name=function_name,
            qualifier=qualifier,
            account_id=context.account_id,
            region=context.region,
        )
        return self._map_config_out(version, return_qualified_arn=bool(qualifier))

    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType = None,
        log_type: LogType = None,
        client_context: String = None,
        payload: IO[Blob] = None,
        qualifier: Qualifier = None,
    ) -> InvocationResponse:

        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        time_before = time.perf_counter()
        result = self.lambda_service.invoke(
            function_name=function_name,
            qualifier=qualifier,
            region=context.region,
            account_id=context.account_id,
            invocation_type=invocation_type,
            client_context=client_context,
            payload=payload.read() if payload else None,
        )
        qualifier = qualifier or "$LATEST"
        try:
            invocation_result = result.result()
        except Exception as e:
            LOG.error("Error while invoking lambda", exc_info=e)
            # TODO map to correct exception
            raise ServiceException() from e

        LOG.debug("Type of result: %s", type(invocation_result))

        response = InvocationResponse(
            StatusCode=200,
            Payload=invocation_result.payload,
            ExecutedVersion=qualifier,
            # TODO: should be conditional. Might have to get this from the invoke result as well
        )

        if isinstance(invocation_result, InvocationError):
            response["FunctionError"] = "Unhandled"

        LOG.debug("Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000)

        if log_type == LogType.Tail:
            response["LogResult"] = to_str(
                base64.b64encode(to_bytes(invocation_result.logs)[-4096:])
            )

        return response

    # Version operations
    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String = None,
        description: Description = None,
        revision_id: String = None,
    ) -> FunctionConfiguration:
        function_name = function_name_from_arn(function_name)
        new_version = self._publish_version(
            function_name=function_name,
            description=description,
            account_id=context.account_id,
            region=context.region,
            revision_id=revision_id,
            code_sha256=code_sha256,
        )
        return self._map_config_out(new_version, return_qualified_arn=True)

    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListVersionsByFunctionResponse:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        return ListVersionsByFunctionResponse(
            Versions=[
                self._map_to_list_response(
                    self._map_config_out(version=version, return_qualified_arn=True)
                )
                for version in function.versions.values()
            ]
        )

    # Alias
    def _map_alias_out(self, alias: VersionAlias, function: Function) -> AliasConfiguration:
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

    def _create_routing_config_model(self, routing_config_dict: dict[str, float]):
        if len(routing_config_dict) > 1:
            raise InvalidParameterValueException(
                "Number of items in AdditionalVersionWeights cannot be greater than 1",
                Type="User",
            )
        # should be exactly one item here
        for key, value in routing_config_dict.items():
            if value < 0.0 or value >= 1.0:
                raise ValidationException(
                    f"1 validation error detected: Value '{{{key}={value}}}' at 'routingConfig.additionalVersionWeights' failed to satisfy constraint: Map value must satisfy constraint: [Member must have value less than or equal to 1.0, Member must have value greater than or equal to 0.0]"
                )
        return AliasRoutingConfig(version_weights=routing_config_dict)

    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        # description is always present, if not specified it's an empty string
        description = description or ""
        with function.lock:
            if name in function.aliases:
                raise ValueError("Already present!")  # TODO proper message
            routing_configuration = None
            if routing_config and (
                routing_config_dict := routing_config.get("AdditionalVersionWeights")
            ):
                routing_configuration = self._create_routing_config_model(routing_config_dict)

            alias = VersionAlias(
                name=name,
                function_version=function_version,
                description=description,
                routing_configuration=routing_configuration,
            )
            function.aliases[name] = alias
        return self._map_alias_out(alias=alias, function=function)

    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListAliasesResponse:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        return ListAliasesResponse(
            Aliases=[
                self._map_alias_out(alias, function)
                for alias in function.aliases.values()
                if function_version is None or alias.function_version == function_version
            ]
        )

    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        if name not in function.aliases:
            raise ValueError("Alias not found")  # TODO proper exception
        function.aliases.pop(name, None)

    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        if not (alias := function.aliases.get(name)):
            raise ValueError("Alias not found")  # TODO proper exception
        return self._map_alias_out(alias=alias, function=function)

    def update_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version = None,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
        revision_id: String = None,
    ) -> AliasConfiguration:
        function_name = function_name_from_arn(function_name)
        function = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        if not (alias := function.aliases.get(name)):
            raise ValueError("Alias not found")  # TODO proper exception
        if revision_id and alias.revision_id != revision_id:
            raise ValueError("Wrong revision id")  # TODO proper exception
        changes = {}
        if function_version is not None:
            changes |= {"function_version": function_version}
        if description is not None:
            changes |= {"description": description}
        if routing_config is not None:
            # if it is an empty dict or AdditionalVersionWeights is empty, set routing config to None
            new_routing_config = None
            if routing_config_dict := routing_config.get("AdditionalVersionWeights"):
                new_routing_config = self._create_routing_config_model(routing_config_dict)
            changes |= {"routing_configuration": new_routing_config}
        # even if no changes are done, we have to update revision id for some reason
        alias = dataclasses.replace(alias, **changes)
        function.aliases[name] = alias
        return self._map_alias_out(alias=alias, function=function)

    # =======================================
    # ======= EVENT SOURCE MAPPINGS =========
    # =======================================

    @handler("CreateEventSourceMapping", expand=False)
    def create_event_source_mapping(
        self,
        context: RequestContext,
        request: CreateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:
        if "EventSourceArn" not in request:
            raise InvalidParameterValueException("Unrecognized event source.", Type="User")

        state = lambda_stores[context.account_id][context.region]
        fn_name = request["FunctionName"]
        fn = state.functions.get(fn_name)
        if not fn:
            raise InvalidParameterValueException("Function does not exist", Type="User")

        new_uuid = long_uid()

        # TODO: create domain models and map accordingly
        params = request.copy()
        params.pop("FunctionName")
        params["State"] = "Enabled"  # TODO: should be set asynchronously
        # params["State"] = "Creating"
        params["StateTransitionReason"] = "USER_INITIATED"
        params["UUID"] = new_uuid
        params["BatchSize"] = request.get("BatchSize", 10)
        params["FunctionResponseTypes"] = request.get("FunctionResponseTypes", [])
        params["MaximumBatchingWindowInSeconds"] = request.get("MaximumBatchingWindowInSeconds", 0)
        params["LastModified"] = generate_lambda_date()
        params["FunctionArn"] = unqualified_lambda_arn(
            request["FunctionName"], context.account_id, context.region
        )

        esm_config = EventSourceMappingConfiguration(**params)
        state.event_source_mappings[new_uuid] = esm_config
        return esm_config

    @handler("UpdateEventSourceMapping", expand=False)
    def update_event_source_mapping(
        self,
        context: RequestContext,
        request: UpdateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        uuid = request["UUID"]
        event_source_mapping = state.event_source_mappings.get(uuid)
        if not event_source_mapping:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        return EventSourceMappingConfiguration()  # TODO: implement

    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        event_source_mapping = state.event_source_mappings.get(uuid)
        if not event_source_mapping:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        return state.event_source_mappings.pop(uuid)

    def get_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        event_source_mapping = state.event_source_mappings.get(uuid)
        if not event_source_mapping:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        return event_source_mapping

    def list_event_source_mappings(
        self,
        context: RequestContext,
        event_source_arn: Arn = None,
        function_name: FunctionName = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListEventSourceMappingsResponse:
        state = lambda_stores[context.account_id][context.region]
        esms = PaginatedList(state.event_source_mappings)
        page, token = esms.get_page(
            lambda x: x,  # TODO
            marker,
            max_items,
        )
        return ListEventSourceMappingsResponse(EventSourceMappings=page, NextMarker=token)

    # =======================================
    # ============ FUNCTION URLS ============
    # =======================================

    # TODO: what happens if function state is not active?
    # TODO: qualifier both in function_name as ARN and in qualifier?
    # TODO: test for qualifier being a number (i.e. version)
    # TODO: test for conflicts between function_name as ARN and provided qualifier
    def create_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        auth_type: FunctionUrlAuthType,
        qualifier: FunctionUrlQualifier = None,
        cors: Cors = None,
    ) -> CreateFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        resolved_fn_name = api_utils.get_function_name(function_name)
        fn = state.functions.get(resolved_fn_name)
        if fn is None:
            raise ResourceNotFoundException("Function does not exist", Type="User")

        # check if fn already exists
        url_config = fn.function_url_configs.get(qualifier or "$LATEST")
        if url_config:
            raise ResourceConflictException(
                f"Failed to create function url config for [functionArn = {url_config.function_arn}]. Error message:  FunctionUrlConfig exists for this Lambda function",
                Type="User",
            )

        if qualifier and qualifier != "$LATEST" and qualifier not in fn.aliases:
            raise ResourceNotFoundException("Where Alias?")  # TODO: verify

        normalized_qualifier = qualifier or "$LATEST"

        function_arn = (
            qualified_lambda_arn(resolved_fn_name, qualifier, context.account_id, context.region)
            if qualifier
            else unqualified_lambda_arn(resolved_fn_name, context.account_id, context.region)
        )

        fn.function_url_configs[normalized_qualifier] = FunctionUrlConfig(
            function_arn=function_arn,
            function_name=resolved_fn_name,
            cors=cors,
            url_id="something",  # TODO
            url="something",  # TODO
            auth_type=auth_type,
            creation_time=generate_lambda_date(),
            last_modified_time=generate_lambda_date(),
        )

        # persist and start URL
        api_url_config = api_utils.map_function_url_config(
            fn.function_url_configs[normalized_qualifier]
        )

        return CreateFunctionUrlConfigResponse(
            FunctionUrl=api_url_config["FunctionUrl"],
            FunctionArn=api_url_config["FunctionArn"],
            AuthType=api_url_config["AuthType"],
            Cors=api_url_config["Cors"],
            CreationTime=api_url_config["CreationTime"],
        )

    def get_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> GetFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        fn_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        resolved_fn = state.functions.get(fn_name)
        if not resolved_fn:
            raise ResourceNotFoundException("The resource you requested does not exist.")

        qualifier = qualifier or "$LATEST"
        url_config = resolved_fn.function_url_configs.get(qualifier)
        if not url_config:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        return api_utils.map_function_url_config(url_config)

    def update_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
        auth_type: FunctionUrlAuthType = None,
        cors: Cors = None,
    ) -> UpdateFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        resolved_fn_name = api_utils.get_function_name(function_name)
        fn = state.functions.get(resolved_fn_name)
        if not fn:
            raise ResourceNotFoundException("Function does not exist")
            # raise ResourceNotFoundException("Function does not exist", Type="User")

        normalized_qualifier = qualifier or "$LATEST"
        url_config = fn.function_url_configs.get(normalized_qualifier)
        if not url_config:
            raise ResourceNotFoundException("Config does not exist")

        changes = {
            "last_modified_time": generate_lambda_date(),
            **({"cors": cors} if cors else {}),
            **({"auth_type": auth_type} if auth_type else {}),
        }
        new_url_config = dataclasses.replace(url_config, **changes)
        fn.function_url_configs[normalized_qualifier] = new_url_config

        return UpdateFunctionUrlConfigResponse(
            FunctionUrl=new_url_config.url,
            FunctionArn=new_url_config.function_arn,
            AuthType=new_url_config.auth_type,
            Cors=new_url_config.cors,
            CreationTime=new_url_config.creation_time,
            LastModifiedTime=new_url_config.last_modified_time,
        )

    # TODO: does only specifying the function name, also delete the ones from all related aliases?
    def delete_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> None:
        state = lambda_stores[context.account_id][context.region]

        fn_name = api_utils.get_function_name(function_name)
        resolved_fn = state.functions.get(fn_name)
        if not resolved_fn:
            raise ResourceNotFoundException("???")  # TODO: cover with test

        qualifier = qualifier or "$LATEST"
        url_config = resolved_fn.function_url_configs.get(qualifier)
        if not url_config:
            raise ResourceNotFoundException("???")  # TODO: cover with test

        # TODO: locking
        del resolved_fn.function_url_configs[qualifier]

    def list_function_url_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxItems = None,
    ) -> ListFunctionUrlConfigsResponse:
        state = lambda_stores[context.account_id][context.region]

        fn_name = api_utils.get_function_name(function_name)
        resolved_fn = state.functions.get(fn_name)
        if not resolved_fn:
            raise ResourceNotFoundException("???")

        url_configs = [
            api_utils.map_function_url_config(fn_conf)
            for fn_conf in resolved_fn.function_url_configs
        ]
        url_configs = PaginatedList(url_configs)
        page, token = url_configs.get_page(
            lambda url_config: url_config["FunctionArn"],
            marker,
            max_items,  # TODO: check what these are ordered by
        )
        url_configs = page
        return ListFunctionUrlConfigsResponse(FunctionUrlConfigs=url_configs, NextMarker=token)

    # =======================================
    # ============  Permissions  ============
    # =======================================

    # TODO: add test for event_source_token (alexa smart home) and auth_type
    @handler("AddPermission", expand=False)
    def add_permission(
        self,
        context: RequestContext,
        request: AddPermissionRequest,
    ) -> AddPermissionResponse:
        state = lambda_stores[context.account_id][context.region]

        resolved_fn_name = api_utils.get_function_name(request["FunctionName"])
        resolved_fn = state.functions.get(resolved_fn_name)

        if not resolved_fn:
            raise ResourceNotFoundException("Where Function???")  # TODO: test

        resolved_qualifier = request.get("Qualifier", "$LATEST")

        resource = unqualified_lambda_arn(resolved_fn_name, context.account_id, context.region)
        if api_utils.qualifier_is_alias(resolved_qualifier):
            if resolved_qualifier not in resolved_fn.aliases:
                raise ResourceNotFoundException("Where Alias???")  # TODO: test
            resource = qualified_lambda_arn(
                resolved_fn_name, resolved_qualifier, context.account_id, context.region
            )
        elif api_utils.qualifier_is_version(resolved_qualifier):
            if resolved_qualifier not in resolved_fn.versions:
                raise ResourceNotFoundException("Where Version???")  # TODO: test
            resource = qualified_lambda_arn(
                resolved_fn_name, resolved_qualifier, context.account_id, context.region
            )
        elif resolved_qualifier != "$LATEST":
            raise ResourceNotFoundException("Wrong format for qualifier?")
        # TODO: is there a different int he resulting policy when adding $LATEST manually?

        # check for an already existing policy and any conflicts in existing statements
        existing_policy = resolved_fn.permissions.get(resolved_qualifier)
        if existing_policy:
            if request["StatementId"] in [s["Sid"] for s in existing_policy.policy.Statement]:
                # TODO: is this unique just in the policy or across all policies in region/account/function (?)
                raise ResourceConflictException("Double Statement!")

        permission_statement = api_utils.build_statement(
            resource,
            request["StatementId"],
            request["Action"],
            request["Principal"],
            source_arn=request.get("SourceArn"),
        )
        policy = existing_policy
        if not existing_policy:
            policy = FunctionResourcePolicy(
                long_uid(), policy=ResourcePolicy(Version="2012-10-17", Id="default", Statement=[])
            )
        policy.policy.Statement.append(permission_statement)
        if not existing_policy:
            resolved_fn.permissions[resolved_qualifier] = policy
        return AddPermissionResponse(Statement=json.dumps(permission_statement))

    # TODO: test if get_policy works after removing all permissions
    def remove_permission(
        self,
        context: RequestContext,
        function_name: FunctionName,
        statement_id: NamespacedStatementId,
        qualifier: Qualifier = None,
        revision_id: String = None,  # TODO
    ) -> None:
        state = lambda_stores[context.account_id][context.region]

        resolved_fn = state.functions.get(function_name)
        if resolved_fn is None:
            raise ResourceNotFoundException("Where function???")  # TODO: test

        resolved_qualifier = qualifier or "$LATEST"
        function_permission = resolved_fn.permissions.get(resolved_qualifier)
        if not function_permission:
            raise ResourceNotFoundException("Where permission???")  # TODO: test

        # try to find statement in policy and delete it
        statement = None
        for s in function_permission.policy.Statement:
            if s["Sid"] == statement_id:
                statement = s
                break

        if not statement:
            raise ResourceNotFoundException(
                f"Statement {statement_id} is not found in resource policy.", Type="User"
            )
        function_permission.policy.Statement.remove(statement)

        # remove the policy as a whole when there's no statement left in it
        if len(function_permission.policy.Statement) == 0:
            del resolved_fn.permissions[resolved_qualifier]

    def get_policy(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetPolicyResponse:
        state = lambda_stores[context.account_id][context.region]

        resolved_fn = state.functions.get(function_name)
        if resolved_fn is None:
            raise ResourceNotFoundException("Where function???")  # TODO: test

        resolved_qualifier = qualifier or "$LATEST"
        function_permission = resolved_fn.permissions.get(resolved_qualifier)
        if not function_permission:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        return GetPolicyResponse(
            Policy=json.dumps(dataclasses.asdict(function_permission.policy)),
            RevisionId=function_permission.revision_id,
        )

    # =======================================
    # ========  Code signing config  ========
    # =======================================

    def create_code_signing_config(
        self,
        context: RequestContext,
        allowed_publishers: AllowedPublishers,
        description: Description = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> CreateCodeSigningConfigResponse:

        state = lambda_stores[context.account_id][context.region]
        # TODO: can there be duplicates?
        csc_id = f"csc-{get_random_hex(17)}"  # e.g. 'csc-077c33b4c19e26036'
        csc_arn = (
            f"arn:aws:lambda:{context.region}:{context.account_id}:code-signing-config:{csc_id}"
        )
        csc = CodeSigningConfig(
            csc_id=csc_id,
            arn=csc_arn,
            allowed_publishers=allowed_publishers,
            policies=code_signing_policies,
            last_modified=generate_lambda_date(),
            description=description,
        )
        state.code_signing_configs[csc_arn] = csc
        return CreateCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(csc))

    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: FunctionName,
    ) -> PutFunctionCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name)

        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise CodeSigningConfigNotFoundException(
                f"The code signing configuration cannot be found. Check that the provided configuration is not deleted: {code_signing_config_arn}.",
                Type="User",
            )

        fn = state.functions.get(function_name)
        fn_arn = unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        fn.code_signing_config_arn = code_signing_config_arn
        return PutFunctionCodeSigningConfigResponse(
            CodeSigningConfigArn=code_signing_config_arn, FunctionName=function_name
        )

    def update_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        description: Description = None,
        allowed_publishers: AllowedPublishers = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> UpdateCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        changes = {
            **(
                {"allowed_publishers": allowed_publishers} if allowed_publishers is not None else {}
            ),
            **({"policies": code_signing_policies} if code_signing_policies is not None else {}),
            **({"description": description} if description is not None else {}),
        }
        new_csc = dataclasses.replace(csc, last_modified=generate_lambda_date(), **changes)
        state.code_signing_configs[code_signing_config_arn] = new_csc

        return UpdateCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(new_csc))

    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> GetCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        return GetCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(csc))

    def get_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name)
        fn = state.functions.get(function_name)
        fn_arn = unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        if fn.code_signing_config_arn:
            return GetFunctionCodeSigningConfigResponse(
                CodeSigningConfigArn=fn.code_signing_config_arn, FunctionName=function_name
            )

        return GetFunctionCodeSigningConfigResponse()

    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name)
        fn = state.functions.get(function_name)
        fn_arn = unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        fn.code_signing_config_arn = None

    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> DeleteCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        del state.code_signing_configs[code_signing_config_arn]

        return DeleteCodeSigningConfigResponse()

    def list_code_signing_configs(
        self, context: RequestContext, marker: String = None, max_items: MaxListItems = None
    ) -> ListCodeSigningConfigsResponse:
        state = lambda_stores[context.account_id][context.region]

        cscs = [api_utils.map_csc(csc) for csc in state.code_signing_configs.values()]
        cscs = PaginatedList(cscs)
        page, token = cscs.get_page(
            lambda csc: csc["CodeSigningConfigId"],  # TODO
            marker,
            max_items,
        )
        return ListCodeSigningConfigsResponse(CodeSigningConfigs=page, NextMarker=token)

    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        if code_signing_config_arn not in state.code_signing_configs:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        fn_arns = [
            unqualified_lambda_arn(fn.function_name, context.account_id, context.region)
            for fn in state.functions.values()
            if fn.code_signing_config_arn == code_signing_config_arn
        ]

        cscs = PaginatedList(fn_arns)
        page, token = cscs.get_page(
            lambda x: x,
            marker,
            max_items,
        )
        return ListFunctionsByCodeSigningConfigResponse(FunctionArns=page, NextMarker=token)

    # =======================================
    # =========  Account Settings   =========
    # =======================================

    # TODO: add to store
    # TODO: update these values throughout the provider where applicable
    # CAVE: these settings & usages are *per* region!
    def get_account_settings(
        self,
        context: RequestContext,
    ) -> GetAccountSettingsResponse:
        return GetAccountSettingsResponse(
            AccountLimit=AccountLimit(
                TotalCodeSize=0,
                CodeSizeZipped=0,
                CodeSizeUnzipped=0,
                ConcurrentExecutions=0,
                UnreservedConcurrentExecutions=0,
            ),
            AccountUsage=AccountUsage(
                TotalCodeSize=0,
                FunctionCount=0,
            ),
        )

    # =======================================
    # ==  Provisioned Concurrency Config   ==
    # =======================================

    # TODO: test how th is behaves when both alias and referencing version have conflicting configs
    def put_provisioned_concurrency_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier,
        provisioned_concurrent_executions: PositiveInteger,
    ) -> PutProvisionedConcurrencyConfigResponse:
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        state = lambda_stores[context.account_id][context.region]

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("where function?")  # TODO: test

        if not qualifier:
            raise ServiceException("Why $LATEST")  # TODO: test

        fn_arn = qualified_lambda_arn(function_name, qualifier, context.account_id, context.region)
        ver_manager = self.lambda_service.get_lambda_version_manager(fn_arn)
        if ver_manager.provisioned_state:
            raise ResourceConflictException("double provisioned")
        # TODO: check if it already exists

        provisioned_config = None
        if api_utils.qualifier_is_alias(qualifier):
            fn_alias = fn.aliases.get(qualifier)
            if not fn_alias:
                raise ResourceNotFoundException("Where alias?")  # TODO: test
            provisioned_config = fn_alias.provisioned_concurrency_config
        elif api_utils.qualifier_is_version(qualifier):
            fn_version = fn.versions.get(qualifier)
            if not fn_version:
                raise ResourceNotFoundException("Where version?")  # TODO: test
            provisioned_config = fn_version.provisioned_concurrency_config

        if not provisioned_config:
            raise ResourceNotFoundException("Where provisioned config?")  # TODO: test

        return provisioned_config

    def get_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> GetProvisionedConcurrencyConfigResponse:
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        state = lambda_stores[context.account_id][context.region]

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("where function?")  # TODO: test

        if not qualifier:
            raise ServiceException("Implicit $LATEST")  # TODO: test

        provisioned_config = None
        if api_utils.qualifier_is_alias(qualifier):
            fn_alias = fn.aliases.get(qualifier)
            if not fn_alias:
                raise ResourceNotFoundException("Where alias?")  # TODO: test
            provisioned_config = fn_alias.provisioned_concurrency_config
        elif api_utils.qualifier_is_version(qualifier):
            fn_version = fn.versions.get(qualifier)
            if not fn_version:
                raise ResourceNotFoundException("Where version?")  # TODO: test
            provisioned_config = fn_version.provisioned_concurrency_config

        if not provisioned_config:
            raise ResourceNotFoundException("Where provisioned config?")  # TODO: test

        fn_arn = qualified_lambda_arn(function_name, qualifier, context.account_id, context.region)
        ver_manager = self.lambda_service.get_lambda_version_manager(fn_arn)

        return GetProvisionedConcurrencyConfigResponse(
            RequestedProvisionedConcurrentExecutions=provisioned_config.provisioned_concurrent_executions,
            LastModified=provisioned_config.last_modified,
            AvailableProvisionedConcurrentExecutions=ver_manager.provisioned_state.available,
            AllocatedProvisionedConcurrentExecutions=ver_manager.provisioned_state.allocated,
            Status=ver_manager.provisioned_state.status,
            StatusReason=ver_manager.provisioned_state.status_reason,
        )

    def list_provisioned_concurrency_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxProvisionedConcurrencyConfigListItems = None,
    ) -> ListProvisionedConcurrencyConfigsResponse:

        provisioned_concurrency_configs = [
            # TODO
            ProvisionedConcurrencyConfigListItem(
                FunctionArn="",
                RequestedProvisionedConcurrentExecutions=0,
                AvailableProvisionedConcurrentExecutions=0,
                AllocatedProvisionedConcurrentExecutions=0,
                Status=ProvisionedConcurrencyStatusEnum.IN_PROGRESS,
                StatusReason="?",
                LastModified=generate_lambda_date(),
            )
        ]
        provisioned_concurrency_configs = PaginatedList(provisioned_concurrency_configs)
        page, token = provisioned_concurrency_configs.get_page(
            lambda x: x,
            marker,
            max_items,
        )
        return ListProvisionedConcurrencyConfigsResponse(
            ProvisionedConcurrencyConfigs=page, NextMarker=token
        )

    # TODO: test what happens when alias or function is deleted
    def delete_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> None:
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        state = lambda_stores[context.account_id][context.region]

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("where function?")  # TODO: test

        if not qualifier:
            raise ServiceException("Why $LATEST")  # TODO: test

        provisioned_config = None
        if api_utils.qualifier_is_alias(qualifier):
            fn_alias = fn.aliases.get(qualifier)
            if not fn_alias:
                raise ResourceNotFoundException("Where alias?")  # TODO: test
            provisioned_config = fn_alias.provisioned_concurrency_config
            fn_alias.provisioned_concurrency_configuration = None
        elif api_utils.qualifier_is_version(qualifier):
            fn_version = fn.versions.get(qualifier)
            if not fn_version:
                raise ResourceNotFoundException("Where version?")  # TODO: test
            provisioned_config = fn_version.provisioned_concurrency_config

        if not provisioned_config:
            raise ResourceNotFoundException("Where provisioned config?")  # TODO: test

    # =======================================
    # =======  Event Invoke Config   ========
    # =======================================

    def put_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        """
        Destinations can be:
        * SQS
        * SNS
        * Lambda
        * EventBridge

        Differences between put_ and update_:
            * put overwrites any existing config
            * update allows changes only single values while keeping the rest of existing ones
            * update fails on non-existing configs

        Differences between destination and DLQ

            * "However, a dead-letter queue is part of a function's version-specific configuration, so it is locked in when you publish a version."
            *  On-failure destinations also support additional targets and include details about the function's response in the invocation record.

        """
        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        if ":" in function_name:
            function_name, second_qualifier = function_name.split(":")

        if (
            maximum_event_age_in_seconds is None
            and maximum_retry_attempts is None
            and destination_config is None
        ):
            raise InvalidParameterValueException(
                "You must specify at least one of error handling or destination setting.",
                Type="User",
            )

        # TODO: validate destination config properly
        if destination_config:
            success_destination = destination_config.get("OnSuccess", {}).get("Destination")
            if success_destination:
                fn_parts = FN_ARN_PATTERN.search(success_destination).groupdict()
                if fn_parts:
                    # check if it exists
                    fn = state.functions.get(fn_parts["function_name"])
                    if not fn:
                        raise InvalidParameterValueException(
                            f"The provided destination config DestinationConfig(onSuccess=OnSuccess(destination={success_destination}), onFailure=null) is invalid."
                        )  # TODO generalize / make utils
                    if fn_parts["function_name"] == function_name:
                        raise InvalidParameterValueException(
                            "You can't specify the function as a destination for itself.",
                            Type="User",
                        )

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("Where fn?")  # TODO: verify

        if qualifier and not (qualifier in fn.aliases or qualifier in fn.versions):
            raise ResourceNotFoundException("Where qualifier?")  # TODO: verify

        config = EventInvokeConfig(
            function_name=function_name,
            qualifier=qualifier,
            maximum_event_age_in_seconds=maximum_event_age_in_seconds,
            maximum_retry_attempts=maximum_retry_attempts,
            last_modified=generate_lambda_date(),
        )
        if destination_config:
            if "OnFailure" in destination_config:
                on_failure_destination = destination_config["OnFailure"].get("Destination")
                if not on_failure_destination:
                    raise InvalidParameterValueException("?")  # TODO: add test
                config.destination_config.on_failure = on_failure_destination
            if "OnSuccess" in destination_config:
                on_success_destination = destination_config["OnSuccess"].get("Destination")
                if not on_success_destination:
                    raise InvalidParameterValueException("?")  # TODO: add test
                config.destination_config.on_success = on_success_destination

        fn.event_invoke_configs[qualifier] = config

        fn_arn = qualified_lambda_arn(
            function_name, qualifier or "$LATEST", context.account_id, context.region
        )

        optional_kwargs = {
            **(
                {"MaximumRetryAttempts": config.maximum_retry_attempts}
                if config.maximum_retry_attempts is not None
                else {}
            ),
            **(
                {"MaximumEventAgeInSeconds": config.maximum_event_age_in_seconds}
                if config.maximum_event_age_in_seconds is not None
                else {}
            ),
        }
        return FunctionEventInvokeConfig(
            LastModified=datetime.datetime.strptime(config.last_modified, LAMBDA_DATE_FORMAT),
            FunctionArn=fn_arn,
            DestinationConfig=destination_config,
            **optional_kwargs,
        )

    def get_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> FunctionEventInvokeConfig:
        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        if ":" in function_name:
            function_name, second_qualifier = function_name.split(":")

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("Where fn?")  # TODO: verify

        config = fn.event_invoke_configs.get(qualifier or "$LATEST")
        if not config:
            raise ResourceNotFoundException("Where event invoke config?")  # TODO: verify

        return FunctionEventInvokeConfig(
            LastModified=datetime.datetime.strptime(config.last_modified, LAMBDA_DATE_FORMAT),
            FunctionArn=qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            ),
            DestinationConfig=config.destination_config,
            MaximumEventAgeInSeconds=config.maximum_event_age_in_seconds,
            MaximumRetryAttempts=config.maximum_retry_attempts,
        )

    def list_function_event_invoke_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxFunctionEventInvokeConfigListItems = None,
    ) -> ListFunctionEventInvokeConfigsResponse:
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("Where Function?")  # TODO: verify

        event_invoke_configs = [
            # TODO
            FunctionEventInvokeConfig(
                LastModified="",
                FunctionArn="",
                MaximumEventAgeInSeconds=0,
                MaximumRetryAttempts=0,
                DestinationConfig=DestinationConfig(),
            )
            for c in fn.event_invoke_configs
        ]

        event_invoke_configs = PaginatedList(event_invoke_configs)
        page, token = event_invoke_configs.get_page(
            lambda x: x,  # TODO
            marker,
            max_items,
        )
        return ListFunctionEventInvokeConfigsResponse(
            FunctionEventInvokeConfigs=page, NextMarker=token
        )

    def delete_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> None:
        function_name, qualifier = get_name_and_qualifier(function_name, qualifier)
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("Where fn?")  # TODO: verify

        resolved_qualifier = qualifier or "$LATEST"
        config = fn.event_invoke_configs.get(resolved_qualifier)
        if not config:
            raise ResourceNotFoundException("Where config?")  # TODO: verify

        del fn.event_invoke_configs[resolved_qualifier]

    def update_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        # like put but only update single fields via replace
        # TODO
        ...
