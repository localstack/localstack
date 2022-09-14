import base64
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
    ServiceException,
    State,
    String,
    TracingConfig,
    TracingMode,
    UpdateFunctionCodeRequest,
    UpdateFunctionConfigurationRequest,
)
from localstack.services.awslambda.invocation.lambda_models import (
    Code,
    FunctionVersion,
    InvocationError,
    VersionFunctionConfiguration,
)
from localstack.services.awslambda.invocation.lambda_service import LambdaService
from localstack.services.awslambda.invocation.lambda_util import qualified_lambda_arn
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.strings import to_bytes, to_str

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128


class LambdaProvider(LambdaApi, ServiceLifecycleHook):

    lambda_service: LambdaService
    lock: threading.RLock

    def __init__(self) -> None:
        self.lambda_service = LambdaService()
        self.lock = threading.RLock()

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
            CodeSize=version.config_meta.code_size,
            CodeSha256=version.config_meta.coda_sha256,
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
        # TODO: initial validations
        architectures = request.get("Architectures")
        if architectures and Architecture.arm64 in architectures:
            raise ServiceException("ARM64 is currently not supported by this provider")

        version = self.lambda_service.create_function(
            context.account_id,
            context.region,
            function_name=request["FunctionName"],
            function_config=VersionFunctionConfiguration(
                description=request.get("Description", ""),
                role=request["Role"],
                timeout=request["Timeout"] or LAMBDA_DEFAULT_TIMEOUT,
                runtime=request["Runtime"],
                memory_size=request["MemorySize"] or LAMBDA_DEFAULT_MEMORY_SIZE,
                handler=request["Handler"],
                package_type=PackageType.Zip,  # TODO
                reserved_concurrent_executions=0,
                environment={k: v for k, v in request["Environment"]["Variables"].items()},
                architectures=[Architecture.x86_64],  # TODO
                tracing_config_mode=TracingMode.PassThrough,  # TODO
                image_config=None,  # TODO
                layers=[],  # TODO
            ),
            code=Code(zip_file=request["Code"]["ZipFile"]),  # TODO: s3?
        )
        return self._map_config_out(version)

    @handler(operation="UpdateFunctionConfiguration", expand=False)
    def update_function_configuration(
        self, context: RequestContext, request: UpdateFunctionConfigurationRequest
    ) -> FunctionConfiguration:
        return FunctionConfiguration()

    @handler(operation="UpdateFunctionCode", expand=False)
    def update_function_code(
        self, context: RequestContext, request: UpdateFunctionCodeRequest
    ) -> FunctionConfiguration:
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
        versions = self.lambda_service.list_function_versions(context.region)
        return ListFunctionsResponse(
            Functions=[self._map_to_list_response(self._map_config_out(fc)) for fc in versions]
        )

    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,  # TODO
    ) -> GetFunctionResponse:
        version = self.lambda_service.get_function_version(
            context.account_id, context.region, function_name, qualifier or "$LATEST"
        )

        return GetFunctionResponse(
            Configuration=self._map_config_out(version),
            Code=FunctionCodeLocation(Location=""),  # TODO
            # Tags={},  # TODO
            # Concurrency={},  # TODO
        )

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
