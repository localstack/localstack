import base64
import logging
import threading
import time
from dataclasses import replace

from localstack.aws.api import RequestContext
from localstack.aws.api.awslambda import (
    Alias,
    AliasConfiguration,
    AliasRoutingConfiguration,
    Architecture,
    ArchitecturesList,
    Blob,
    Boolean,
    CodeSigningConfigArn,
    DeadLetterConfig,
    Description,
    Environment,
    EnvironmentResponse,
    FileSystemConfigList,
    FunctionCode,
    FunctionCodeLocation,
    FunctionConfiguration,
    FunctionName,
    GetFunctionResponse,
    Handler,
    ImageConfig,
    InvocationResponse,
    InvocationType,
    KMSKeyArn,
    LambdaApi,
    LastUpdateStatus,
    LayerList,
    ListAliasesResponse,
    ListFunctionsResponse,
    LogType,
    MasterRegion,
    MaxListItems,
    MemorySize,
    NamespacedFunctionName,
    PackageType,
    Qualifier,
    RoleArn,
    Runtime,
    S3Bucket,
    S3Key,
    S3ObjectVersion,
    ServiceException,
    State,
    String,
    Tags,
    Timeout,
    TracingConfig,
    TracingMode,
    Version,
    VpcConfig,
)
from localstack.services.awslambda.invocation.lambda_models import (
    Code,
    FunctionVersion,
    InvocationError,
    VersionAlias,
    VersionFunctionConfiguration,
)
from localstack.services.awslambda.invocation.lambda_service import LambdaService
from localstack.services.awslambda.invocation.lambda_util import qualified_lambda_arn
from localstack.services.awslambda.lambda_utils import generate_lambda_arn
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.strings import to_bytes, to_str

LOG = logging.getLogger(__name__)


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

    def create_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn,
        code: FunctionCode,
        runtime: Runtime = None,
        handler: Handler = None,
        description: Description = None,
        timeout: Timeout = None,
        memory_size: MemorySize = None,
        publish: Boolean = None,
        vpc_config: VpcConfig = None,  # TODO: ignored
        package_type: PackageType = None,
        dead_letter_config: DeadLetterConfig = None,  # TODO: ignored
        environment: Environment = None,
        kms_key_arn: KMSKeyArn = None,  # TODO: ignored
        tracing_config: TracingConfig = None,  # TODO: ignored
        tags: Tags = None,
        layers: LayerList = None,  # TODO: ignored
        file_system_configs: FileSystemConfigList = None,  # TODO: ignored
        image_config: ImageConfig = None,  # TODO: ignored
        code_signing_config_arn: CodeSigningConfigArn = None,  # TODO: ignored
        architectures: ArchitecturesList = None,
    ) -> FunctionConfiguration:
        # TODO: initial validations
        if architectures and Architecture.arm64 in architectures:
            raise ServiceException("ARM64 is currently not supported by this provider")

        version = self.lambda_service.create_function(
            context.account_id,
            context.region,
            function_name=function_name,
            function_config=VersionFunctionConfiguration(
                description=description or "",
                role=role,
                timeout=timeout or 3,
                runtime=runtime,
                memory_size=memory_size or 128,
                handler=handler,
                package_type=PackageType.Zip,
                reserved_concurrent_executions=0,
                environment={},
                # environment={k: v for k,v in environment['Variables'].items()},
                architectures=[Architecture.x86_64],
                tracing_config_mode=TracingMode.PassThrough,
                image_config=None,
                layers=[],
            ),
            code=Code(zip_file=code["ZipFile"]),
        )
        return self._map_config_out(version)

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
            context.region, function_name, qualifier or "$LATEST"
        )

        return GetFunctionResponse(
            Configuration=self._map_config_out(version),
            Code=FunctionCodeLocation(Location=""),  # TODO
            Tags={},  # TODO
            Concurrency={},  # TODO
        )

    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType = None,
        log_type: LogType = None,
        client_context: String = None,
        payload: Blob = None,
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
            payload=payload,
        )
        try:
            invocation_result = result.result()
        except Exception as e:
            LOG.error("Error while invoking lambda: %s", e)
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

    # TODO: does deleting the latest published version affect the next versions number?
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        self.lambda_service.delete_function(context.region, function_name)

    def update_function_code(
        self,
        context: RequestContext,
        function_name: FunctionName,
        zip_file: Blob = None,
        s3_bucket: S3Bucket = None,
        s3_key: S3Key = None,
        s3_object_version: S3ObjectVersion = None,
        image_uri: String = None,
        publish: Boolean = None,
        dry_run: Boolean = None,
        revision_id: String = None,
        architectures: ArchitecturesList = None,
    ) -> FunctionConfiguration:
        raise ServiceException("Not implemented (yet). Stay tuned!")  # TODO

    def update_function_configuration(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn = None,
        handler: Handler = None,
        description: Description = None,
        timeout: Timeout = None,
        memory_size: MemorySize = None,
        vpc_config: VpcConfig = None,
        environment: Environment = None,
        runtime: Runtime = None,
        dead_letter_config: DeadLetterConfig = None,
        kms_key_arn: KMSKeyArn = None,
        tracing_config: TracingConfig = None,
        revision_id: String = None,
        layers: LayerList = None,
        file_system_configs: FileSystemConfigList = None,
        image_config: ImageConfig = None,
    ) -> FunctionConfiguration:
        raise ServiceException("Not implemented (yet). Stay tuned!")  # TODO

    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String = None,  # TODO
        description: Description = None,  # TODO
        revision_id: String = None,
    ) -> FunctionConfiguration:
        version = self.lambda_service.create_version(
            region_name=context.region, function_name=function_name, description=description
        )
        return self._map_config_out(version)

    def _map_alias_to_aliasconfig(
        self, region: str, function_name: str, alias: VersionAlias
    ) -> AliasConfiguration:
        version = self.lambda_service.get_function_version(
            region_name=region, function_name=function_name, qualifier=str(alias.function_version)
        )
        return AliasConfiguration(
            AliasArn=replace(version.id, qualifier=alias.name).qualified_arn(),
            Name=alias.name,
            FunctionVersion=str(alias.function_version),
            Description=alias.description,
            # RoutingConfig=None, # TODO
            RevisionId=version.config_meta.revision_id,
        )

    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        version = self.lambda_service.create_alias(
            context.region, function_name, function_version, name, description or ""
        )  # TODO: routing config

        return AliasConfiguration(
            AliasArn=generate_lambda_arn(
                account_id=int(context.account_id),
                region=context.region,
                fn_name=function_name,
                qualifier=name,
            ),
            Name=name,
            Description=description or "",
            RevisionId=version.config_meta.revision_id,
            FunctionVersion=function_version,
            RoutingConfig=routing_config,
        )

    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        self.lambda_service.delete_alias(context.region, function_name, name)

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
        ...  # TODO

    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListAliasesResponse:
        aliases = self.lambda_service.list_aliases(
            region_name=context.region, function_name=function_name
        )
        return ListAliasesResponse(
            Aliases=[
                self._map_alias_to_aliasconfig(context.region, function_name, a) for a in aliases
            ]
        )

    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,  # TODO
    ) -> FunctionConfiguration:
        ...  # TODO

    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        return self._map_alias_to_aliasconfig(
            context.region,
            function_name,
            self.lambda_service.get_alias(
                region_name=context.region, function_name=function_name, alias_name=name
            ),
        )
