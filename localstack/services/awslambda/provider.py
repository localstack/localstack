import dataclasses
import logging
from typing import Any, Dict

from localstack.aws.api import RequestContext
from localstack.aws.api.awslambda import (
    ArchitecturesList,
    Blob,
    Boolean,
    CodeSigningConfigArn,
    DeadLetterConfig,
    Description,
    Environment,
    FileSystemConfigList,
    FunctionCode,
    FunctionConfiguration,
    FunctionName,
    Handler,
    ImageConfig,
    InvocationResponse,
    InvocationType,
    KMSKeyArn,
    LambdaApi,
    LayerList,
    LogType,
    MemorySize,
    NamespacedFunctionName,
    PackageType,
    Qualifier,
    RoleArn,
    Runtime,
    String,
    Tags,
    Timeout,
    TracingConfig,
    VpcConfig,
)
from localstack.services.awslambda.invocation.lambda_service import FunctionVersion, LambdaService
from localstack.services.awslambda.invocation.lambda_util import qualified_lambda_arn
from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)


class NoopListener(ProxyListener):
    def forward_request(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def return_response(self, *args: Any, **kwargs: Any) -> bool:
        return True


@dataclasses.dataclass
class LambdaVersion:
    pass


@dataclasses.dataclass
class ProvisionedConcurrencyConfig:
    pass


@dataclasses.dataclass
class EventInvokeConfig:
    pass


class LambdaServiceBackend(RegionBackend):
    # storage for lambda versions
    lambda_versions: Dict[str, LambdaVersion] = {}

    provisioned_concurrency_configs: Dict[str, ProvisionedConcurrencyConfig]

    # static tagging service instance
    TAGS = TaggingService()


class LambdaProvider(LambdaApi, ServiceLifecycleHook):
    """
    validations

    """

    lambda_service: LambdaService

    def __init__(self) -> None:
        self.lambda_service = LambdaService()

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
        memory_size: MemorySize = None,  # TODO
        publish: Boolean = None,
        vpc_config: VpcConfig = None,
        package_type: PackageType = None,
        dead_letter_config: DeadLetterConfig = None,  # TODO
        environment: Environment = None,
        kms_key_arn: KMSKeyArn = None,  # TODO
        tracing_config: TracingConfig = None,  # TODO
        tags: Tags = None,  # TODO
        layers: LayerList = None,
        file_system_configs: FileSystemConfigList = None,
        image_config: ImageConfig = None,  # TODO
        code_signing_config_arn: CodeSigningConfigArn = None,
        architectures: ArchitecturesList = None,
    ) -> FunctionConfiguration:
        LOG.debug("Creating lambda function with params: %s", dict(locals()))

        # TODO: validations
        FunctionConfiguration(FunctionName="bla", FunctionArn="bla", Runtime="")

        qualified_arn = qualified_lambda_arn(
            function_name, "$LATEST", context.account_id, context.region
        )
        environment = (
            environment["Variables"] if environment and environment.get("Variables") else {}
        )
        version = FunctionVersion(
            qualified_arn=qualified_arn,
            code=code.get("ZipFile"),
            runtime=runtime,
            architecture="amd64",
            role=role,
            environment=environment,
            handler=handler,
        )
        self.lambda_service.create_function_version(function_version_definition=version)

        # TODO: handle directly
        # publish

        # create a new version
        return FunctionConfiguration(FunctionName=function_name, FunctionArn=qualified_arn)

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
        result = self.lambda_service.invoke(
            function_arn_qualified=qualified_arn,
            invocation_type=invocation_type,
            log_type=log_type,
            client_context=client_context,
            payload=payload,
        )
        result = result.result()
        LOG.debug("Result: %s", result)
        return {}
