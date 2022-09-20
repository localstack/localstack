import abc
import dataclasses
import threading
from typing import TYPE_CHECKING, Optional

from localstack.aws.api.lambda_ import (
    Architecture,
    InvocationType,
    LastUpdateStatus,
    PackageType,
    Runtime,
    State,
    StateReasonCode,
    TracingMode,
)
from localstack.services.awslambda.invocation.lambda_util import (
    lambda_arn_without_qualifier,
    qualified_lambda_arn,
)
from localstack.utils.aws import aws_stack
from localstack.utils.strings import long_uid

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


@dataclasses.dataclass(frozen=True)
class VersionState:
    state: State
    code: Optional[StateReasonCode] = None
    reason: Optional[str] = None


@dataclasses.dataclass
class Invocation:
    payload: bytes
    client_context: Optional[str]
    invocation_type: InvocationType


@dataclasses.dataclass(frozen=True)
class S3Code:
    s3_bucket: str
    s3_key: str
    s3_object_version: str | None
    code_sha256: str
    code_size: int

    def get_lambda_archive(self) -> bytes:
        s3_client: "S3Client" = aws_stack.connect_to_service("s3", region_name="us-east-1")
        kwargs = {"VersionId": self.s3_object_version} if self.s3_object_version else {}
        return s3_client.get_object(Bucket=self.s3_bucket, Key=self.s3_key, **kwargs)["Body"].read()

    def generate_presigned_url(self) -> str:
        s3_client: "S3Client" = aws_stack.connect_to_service("s3", region_name="us-east-1")
        params = {"Bucket": self.s3_bucket, "Key": self.s3_key}
        if self.s3_object_version:
            params["VersionId"] = self.s3_object_version
        return s3_client.generate_presigned_url("get_object", Params=params)

    def destroy(self) -> None:
        s3_client: "S3Client" = aws_stack.connect_to_service("s3", region_name="us-east-1")
        kwargs = {"VersionId": self.s3_object_version} if self.s3_object_version else {}
        s3_client.delete_object(Bucket=self.s3_bucket, Key=self.s3_key, **kwargs)


@dataclasses.dataclass
class DeadLetterConfig:
    target_arn: str


@dataclasses.dataclass
class FileSystemConfig:
    arn: str
    local_mount_path: str


@dataclasses.dataclass
class ImageConfig:
    working_directory: str
    command: list[str] = dataclasses.field(default_factory=list)
    entrypoint: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class VpcConfig:
    security_group_ids: list[str] = dataclasses.field(default_factory=list)
    subnet_ids: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class UpdateStatus:
    status: LastUpdateStatus
    code: Optional[str] = None  # TODO: probably not a string
    reason: Optional[str] = None


@dataclasses.dataclass
class LambdaEphemeralStorage:
    size: int


@dataclasses.dataclass(frozen=True)
class VersionFunctionConfiguration:
    # fields
    # name: str
    function_arn: str  # TODO:?
    description: str
    role: str
    timeout: int
    runtime: Runtime
    memory_size: int
    handler: str
    package_type: PackageType
    reserved_concurrent_executions: int
    environment: dict[str, str]
    architectures: list[Architecture]
    # internal revision is updated when runtime restart is necessary
    internal_revision: str
    ephemeral_storage: LambdaEphemeralStorage

    tracing_config_mode: TracingMode
    code: S3Code
    last_modified: str  # ISO string

    image_config: Optional[ImageConfig] = None
    last_update: Optional[UpdateStatus] = None
    revision_id: str = dataclasses.field(init=False, default_factory=long_uid)
    layers: list[str] = dataclasses.field(default_factory=list)
    # kms_key_arn: str
    # dead_letter_config: DeadLetterConfig
    # file_system_configs: FileSystemConfig
    # vpc_config: VpcConfig


@dataclasses.dataclass
class ProvisionedConcurrencyConfiguration:
    provisioned_concurrent_executions: int


@dataclasses.dataclass
class VersionWeight:
    function_version: int
    function_weight: float


@dataclasses.dataclass
class AliasRoutingConfiguration:
    version_weights: list[VersionWeight]


@dataclasses.dataclass(frozen=True)
class VersionIdentifier:
    function_name: str
    qualifier: str
    region: str
    account: str

    def qualified_arn(self):
        return qualified_lambda_arn(
            function_name=self.function_name,
            qualifier=self.qualifier,
            region=self.region,
            account=self.account,
        )

    def unqualified_arn(self):
        return lambda_arn_without_qualifier(
            function_name=self.function_name,
            region=self.region,
            account=self.account,
        )


@dataclasses.dataclass(frozen=True)
class VersionAlias:
    function_version: int
    name: str
    description: str
    routing_configuration: Optional[AliasRoutingConfiguration]
    provisioned_concurrency_configuration: Optional[ProvisionedConcurrencyConfiguration] = None


@dataclasses.dataclass(frozen=True)
class FunctionVersion:
    id: VersionIdentifier
    qualifier: str
    config: VersionFunctionConfiguration
    provisioned_concurrency_config: Optional[ProvisionedConcurrencyConfiguration] = None

    @property
    def qualified_arn(self) -> str:
        return self.id.qualified_arn()


@dataclasses.dataclass
class Function:
    function_name: str
    aliases: dict[str, VersionAlias] = dataclasses.field(default_factory=dict)
    versions: dict[str, FunctionVersion] = dataclasses.field(default_factory=dict)

    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)
    next_version: int = 1

    def latest(self) -> FunctionVersion:
        return self.versions["$LATEST"]


# Result Models
@dataclasses.dataclass
class InvocationResult:
    invocation_id: str
    payload: Optional[bytes]
    logs: Optional[str] = None


@dataclasses.dataclass
class InvocationError:
    invocation_id: str
    payload: Optional[bytes]
    logs: Optional[str] = None


@dataclasses.dataclass
class InvocationLogs:
    invocation_id: str
    logs: str


class ServiceEndpoint(abc.ABC):
    def invocation_result(self, invoke_id: str, invocation_result: InvocationResult) -> None:
        """
        Processes the result of an invocation
        :param invoke_id: Invocation Id
        :param invocation_result: Invocation Result
        """
        raise NotImplementedError()

    def invocation_error(self, invoke_id: str, invocation_error: InvocationError) -> None:
        """
        Processes an error during an invocation
        :param invoke_id: Invocation Id
        :param invocation_error: Invocation Error
        """
        raise NotImplementedError()

    def invocation_logs(self, invoke_id: str, invocation_logs: InvocationLogs) -> None:
        """
        Processes the logs of an invocation
        :param invoke_id: Invocation Id
        :param invocation_logs: Invocation logs
        """
        raise NotImplementedError()

    def status_ready(self, executor_id: str) -> None:
        """
        Processes a status ready report by RAPID
        :param executor_id: Executor ID this ready report is for
        """
        raise NotImplementedError()

    def status_error(self, executor_id: str) -> None:
        """
        Processes a status error report by RAPID
        :param executor_id: Executor ID this error report is for
        """
        raise NotImplementedError()


@dataclasses.dataclass
class EventSourceMapping:
    ...


@dataclasses.dataclass
class CodeSigningConfig:
    ...


@dataclasses.dataclass
class Layer:
    ...


@dataclasses.dataclass
class LayerVersion:
    ...


# ASYNC
# @dataclasses.dataclass
# class OnFailure:
#     destination: str
#
#
# @dataclasses.dataclass
# class OnSuccess:
#     destination: str
#
#
# @dataclasses.dataclass
# class DestinationConfig:
#     on_failure: OnFailure
#     on_success: OnSuccess
#
#
# @dataclasses.dataclass
# class EventInvokeConfig:
#     function_name: str
#     qualifier: str
#     maximum_retry_attemps: int
#     maximum_event_age_in_seconds: int
#     destination_config: DestinationConfig
