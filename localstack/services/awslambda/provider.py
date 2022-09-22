import base64
import dataclasses
import datetime
import json
import logging
import re
import threading
import time
from typing import IO

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.lambda_ import (
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
    CodeSigningPolicies,
    Cors,
    CreateCodeSigningConfigResponse,
    CreateEventSourceMappingRequest,
    CreateFunctionRequest,
    CreateFunctionUrlConfigResponse,
    DeleteCodeSigningConfigResponse,
    Description,
    EnvironmentResponse,
    EphemeralStorage,
    EventSourceMappingConfiguration,
    FunctionCodeLocation,
    FunctionConfiguration,
    FunctionName,
    FunctionUrlAuthType,
    FunctionUrlQualifier,
    GetCodeSigningConfigResponse,
    GetFunctionCodeSigningConfigResponse,
    GetFunctionResponse,
    GetFunctionUrlConfigResponse,
    GetPolicyResponse,
    InvocationResponse,
    InvocationType,
    LambdaApi,
    LastUpdateStatus,
    ListAliasesResponse,
    ListCodeSigningConfigsResponse,
    ListEventSourceMappingsResponse,
    ListFunctionsByCodeSigningConfigResponse,
    ListFunctionsResponse,
    ListFunctionUrlConfigsResponse,
    ListVersionsByFunctionResponse,
    LogType,
    MasterRegion,
    MaxItems,
    MaxListItems,
    NamespacedFunctionName,
    NamespacedStatementId,
    PackageType,
    PutFunctionCodeSigningConfigResponse,
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
    UpdateFunctionCodeRequest,
    UpdateFunctionConfigurationRequest,
    UpdateFunctionUrlConfigResponse,
    Version,
)
from localstack.services.awslambda import api_utils
from localstack.services.awslambda.invocation.lambda_models import (
    Function,
    FunctionResourcePolicy,
    FunctionUrlConfig,
    FunctionVersion,
    InvocationError,
    LambdaEphemeralStorage,
    ResourcePolicy,
    UpdateStatus,
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
    format_lambda_date,
    generate_lambda_date,
    lambda_arn_without_qualifier,
    qualified_lambda_arn,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import PaginatedList
from localstack.utils.strings import long_uid, short_uid, to_bytes, to_str

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

    def _map_config_out(self, version: FunctionVersion) -> FunctionConfiguration:

        # handle optional entries that shouldn't be rendered at all if not present
        optional_kwargs = {}
        if version.config.last_update:
            if version.config.last_update.status:
                optional_kwargs["LastUpdateStatus"] = version.config.last_update.status
            if version.config.last_update.code:
                optional_kwargs["LastUpdateStatusReasonCode"] = version.config.last_update.code
            if version.config.last_update.reason:
                optional_kwargs["LastUpdateStatusReason"] = version.config.last_update.reason

        if version_state := version.config.state:
            if version_state.state:
                optional_kwargs["State"] = version_state.state
            if version_state.reason:
                optional_kwargs["StateReason"] = version_state.reason
            if version_state.code:
                optional_kwargs["StateReasonCode"] = version_state.code

        if version.config.architectures:
            optional_kwargs["Architectures"] = version.config.architectures

        func_conf = FunctionConfiguration(
            RevisionId=version.config.revision_id,
            FunctionName=version.id.function_name,
            FunctionArn=version.id.unqualified_arn(),  # qualifier usually not included
            LastModified=version.config.last_modified,
            Version=version.id.qualifier,
            Description=version.config.description,
            Role=version.config.role,
            Timeout=version.config.timeout,
            Runtime=version.config.runtime,
            Handler=version.config.handler,
            Environment=EnvironmentResponse(
                Variables=version.config.environment
            ),  # TODO: Errors key?
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
        if function_name in state.functions:
            raise ResourceConflictException(f"Function already exist: {function_name}")
        fn = Function(function_name=function_name)

        with self.create_fn_lock:
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
                qualifier="$LATEST",
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
                    environment={
                        k: v for k, v in request.get("Environment", {}).get("Variables", {}).items()
                    },
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

        # if publish_version:
        #     self.lambda_service.create_function_version(version)
        # TODO: do we now need to return the $LATEST or version 1?

        return self._map_config_out(version)

    @handler(operation="UpdateFunctionConfiguration", expand=False)
    def update_function_configuration(
        self, context: RequestContext, request: UpdateFunctionConfigurationRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        function_name = request.get("FunctionName")  # TODO: can this be an ARN too?
        state = lambda_stores[context.account_id][context.region]

        if function_name not in state.functions:
            raise ResourceNotFoundException(
                f"Function not found: {lambda_arn_without_qualifier(function_name=function_name, region=context.region, account=context.account_id)}",
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
                f"Function not found: {lambda_arn_without_qualifier(function_name=function_name, region=context.region, account=context.account_id)}",
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
        FN_ARN_PATTERN = re.compile(
            r"^arn:aws:lambda:(?P<region_name>[^:]+):(?P<account_id>\d{12}):function:(?P<function_name>[^:]+)(:(?P<qualifier>.*))?$"
        )
        arn_match = re.search(FN_ARN_PATTERN, function_name)
        state = lambda_stores[context.account_id][context.region]

        if arn_match:
            # function_name is actually an ARN, so parse actual name and qualifier
            groups = arn_match.groupdict()
            function_name = groups["function_name"]
            group_qualifier = groups["qualifier"]

            if group_qualifier:
                qualifier = group_qualifier

        # TODO: error message if just the version is not there
        if function_name not in state.functions:
            e = ResourceNotFoundException(
                f"Function not found: {lambda_arn_without_qualifier(function_name=function_name, region=context.region, account=context.account_id)}",
                Type="User",
            )  # TODO: should probably include qualifier if one is available?
            raise e
        function = state.functions.pop(function_name)

        if qualifier:
            # delete a version of the function
            if qualifier not in function.versions:
                raise ResourceNotFoundException(
                    f"Function not found: {lambda_arn_without_qualifier(function_name=function_name, region=context.region, account=context.account_id)}",
                    Type="User",
                )  # TODO: adapt to version?
            version = function.versions.pop(qualifier)
            self.lambda_service.stop_version(version.qualified_arn())
        else:
            # delete the whole function
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
        qualifier = qualifier or "$LATEST"
        state = lambda_stores[context.account_id][context.region]
        version = state.functions[function_name].versions[qualifier]
        code = version.config.code
        return GetFunctionResponse(
            Configuration=self._map_config_out(version),
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
    ) -> FunctionConfiguration:  # CAVE: THIS RETURN VALUE IS *NOT* THE SAME AS IN get_function (!)
        return FunctionConfiguration()

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
        LOG.debug("Lambda function got invoked! Params: %s", dict(locals()))

        # TODO discuss where function data is stored - might need to be passed here
        qualified_arn = qualified_lambda_arn(
            function_name, "$LATEST", context.account_id, context.region
        )
        time_before = time.perf_counter()
        result = self.lambda_service.invoke(
            function_arn_qualified=qualified_arn,
            invocation_type=invocation_type,
            client_context=client_context,
            payload=payload.read() if payload else None,
        )
        try:
            invocation_result = result.result()
        except Exception as e:
            LOG.error("Error while invoking lambda", exc_info=e)
            # TODO map to correct exception
            raise ServiceException()

        LOG.debug("Type of result: %s", type(invocation_result))

        function_error = None
        if isinstance(invocation_result, InvocationError):
            function_error = "Unhandled"

        response = InvocationResponse(
            StatusCode=200,
            Payload=invocation_result.payload,
            ExecutedVersion="$LATEST",  # TODO: should be resolved version from qualifier
            FunctionError=function_error,
            # TODO: should be conditional. Might have to get this from the invoke result as well
        )
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
        ...

    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListVersionsByFunctionResponse:
        ...

    # Alias
    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        ...

    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListAliasesResponse:
        ...

    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        ...

    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        ...

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
        ...

    # Event Source Mappings

    @handler("CreateEventSourceMapping", expand=False)
    def create_event_source_mapping(
        self,
        context: RequestContext,
        request: CreateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:

        ...

    @handler("UpdateEventSourceMapping", expand=False)
    def update_event_source_mapping(
        self,
        context: RequestContext,
        request: CreateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:
        ...

    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        ...

    def get_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        ...

    def list_event_source_mappings(
        self,
        context: RequestContext,
        event_source_arn: Arn = None,
        function_name: FunctionName = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListEventSourceMappingsResponse:
        ...

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
            raise ResourceNotFoundException("Where Alias?")

        normalized_qualifier = qualifier or "$LATEST"

        function_arn = (
            qualified_lambda_arn(resolved_fn_name, qualifier, context.account_id, context.region)
            if qualifier
            else lambda_arn_without_qualifier(resolved_fn_name, context.account_id, context.region)
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

        fn_name = api_utils.get_function_name(function_name)
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

        resource = lambda_arn_without_qualifier(
            resolved_fn_name, context.account_id, context.region
        )
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
        ...

    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: FunctionName,
    ) -> PutFunctionCodeSigningConfigResponse:
        ...

    def update_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        description: Description = None,
        allowed_publishers: AllowedPublishers = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> UpdateCodeSigningConfigResponse:
        ...

    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> GetCodeSigningConfigResponse:
        ...

    def get_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionCodeSigningConfigResponse:
        ...

    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        ...

    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> DeleteCodeSigningConfigResponse:
        ...

    def list_code_signing_configs(
        self, context: RequestContext, marker: String = None, max_items: MaxListItems = None
    ) -> ListCodeSigningConfigsResponse:
        ...

    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        ...

    # TODO(s)
    # Provisioned Concurrency Config
    # Event Invoke Config
    # Event Invoke Config
