import base64
import dataclasses
import logging
import re
import threading
import time
from typing import IO

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.lambda_ import (
    Architecture,
    Blob,
    CreateFunctionRequest,
    EnvironmentResponse,
    FunctionCodeLocation,
    FunctionConfiguration,
    FunctionName,
    GetFunctionResponse,
    InvocationResponse,
    InvocationType,
    LambdaApi,
    LastUpdateStatus,
    ListFunctionsResponse,
    LogType,
    MasterRegion,
    MaxListItems,
    NamespacedFunctionName,
    PackageType,
    Qualifier,
    ResourceConflictException,
    ResourceNotFoundException,
    ServiceException,
    State,
    String,
    TracingConfig,
    TracingMode,
    UpdateFunctionCodeRequest,
    UpdateFunctionConfigurationRequest,
)
from localstack.services.awslambda.invocation.lambda_models import (
    Function,
    FunctionConfigurationMeta,
    FunctionVersion,
    InvocationError,
    UpdateStatus,
    VersionFunctionConfiguration,
    VersionIdentifier,
)
from localstack.services.awslambda.invocation.lambda_service import (
    LambdaService,
    lambda_stores,
    store_lambda_archive,
    store_s3_bucket_archive,
)
from localstack.services.awslambda.invocation.lambda_util import (
    lambda_arn_without_qualifier,
    qualified_lambda_arn,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.strings import short_uid, to_bytes, to_str

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
        return FunctionConfiguration(
            RevisionId=version.config_meta.revision_id,
            FunctionName=version.id.function_name,
            FunctionArn=version.id.qualified_arn(),
            LastModified=version.config_meta.last_modified,
            LastUpdateStatus=LastUpdateStatus.Successful,
            State=State.Active,
            Version=version.id.qualifier,
            Description=version.config.description,
            Role=version.config.role,
            Timeout=version.config.timeout,
            Runtime=version.config.runtime,
            Handler=version.config.handler,
            Environment=EnvironmentResponse(Variables=version.config.environment, Error={}),
            CodeSize=version.config.code.code_size,
            CodeSha256=version.config.code.code_sha256,
            MemorySize=version.config.memory_size,
            PackageType=version.config.package_type,
            TracingConfig=TracingConfig(Mode=version.config.tracing_config_mode),
            Architectures=version.config.architectures,
        )

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

        # TODO: initial validations
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
            if request["PackageType"] == PackageType.Zip:
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
                config_meta=FunctionConfigurationMeta(
                    function_arn=arn.qualified_arn(),
                    revision_id="?",
                    last_modified="asdf",
                    last_update=UpdateStatus(status=LastUpdateStatus.Successful),
                ),
                config=VersionFunctionConfiguration(
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
                    architectures=[Architecture.x86_64],  # TODO
                    tracing_config_mode=TracingMode.PassThrough,  # TODO
                    image_config=None,  # TODO
                    code=code,
                    layers=[],  # TODO
                    internal_revision=short_uid(),
                ),
            )
            fn.versions["$LATEST"] = version
            state.functions[function_name] = fn
        self.lambda_service.create_function_version(version)

        return self._map_config_out(version)

    @handler(operation="UpdateFunctionConfiguration", expand=False)
    def update_function_configuration(
        self, context: RequestContext, request: UpdateFunctionConfigurationRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        return FunctionConfiguration()

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
                f"Function not found: {lambda_arn_without_qualifier(function_name=function_name, region=context.region, account=context.account_id)}"
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
        self.lambda_service.delete_version(function_version=old_function_version)
        # TODO this should be encapsulated better
        old_code = old_function_version.config.code
        old_code.destroy()
        config = dataclasses.replace(
            old_function_version.config, code=code, internal_revision=short_uid()
        )
        function_version = dataclasses.replace(old_function_version, config=config)
        function.versions["$LATEST"] = function_version

        self.lambda_service.create_function_version(function_version=function_version)
        return FunctionConfiguration()

    # TODO: does deleting the latest published version affect the next versions number?
    # TODO: what happens when we call this with a qualifier and a fully qualified ARN? (+ conflicts?)
    # TODO: test different ARN patterns (shorthand ARN?)
    # TODO: test deleting through regions?
    # TODO: test mismatch between context region and region in ARN
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

        if arn_match:
            groups = arn_match.groupdict()
            self.lambda_service.delete_function(
                groups["account_id"],
                groups["region_name"],
                groups["function_name"],
                groups["qualifier"],
            )
        else:
            self.lambda_service.delete_function(
                context.account_id, context.region, function_name, qualifier
            )

    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,  # (only relevant for lambda@edge)
        function_version: FunctionVersion = None,  # TODO
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListFunctionsResponse:
        versions = self.lambda_service.list_function_versions(context.account_id, context.region)
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
            FunctionError=function_error,  # TODO: should be conditional. Might have to get this from the invoke result as well
        )
        LOG.debug("Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000)
        LOG.debug("Result: %s", invocation_result)

        if log_type == LogType.Tail:
            response["LogResult"] = to_str(
                base64.b64encode(to_bytes(invocation_result.logs)[-4096:])
            )

        return response
