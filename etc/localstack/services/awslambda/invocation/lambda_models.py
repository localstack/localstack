import abc
import dataclasses
import threading
from typing import Dict, List, Optional

from localstack.services.awslambda.invocation.lambda_util import qualified_lambda_arn


@dataclasses.dataclass
class Invocation:
    payload: bytes
    client_context: Optional[str]
    invocation_type: str


@dataclasses.dataclass
class Code:
    image_uri: Optional[str] = None

    s3_bucket: Optional[str] = None
    s3_key: Optional[str] = None
    s3_object_version: Optional[str] = None

    zip_file: Optional[str] = None


@dataclasses.dataclass
class DeadLetterConfig:
    target_arn: str


@dataclasses.dataclass
class FileSystemConfig:
    arn: str
    local_mount_path: str


@dataclasses.dataclass
class ImageConfig:
    command: List[str]
    entrypoint: List[str]
    working_directory: str


@dataclasses.dataclass
class VpcConfig:
    security_group_ids: List[str] = dataclasses.field(default_factory=list)
    subnet_ids: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class UpdateStatus:
    status: str
    code: Optional[str] = None  # TODO: probably not a string
    reason: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class FunctionConfigurationMeta:
    function_arn: str
    revision_id: str  # UUID, new one on each change
    code_size: int
    coda_sha256: str
    last_modified: str  # ISO string
    last_update: UpdateStatus


@dataclasses.dataclass(frozen=True)
class VersionFunctionConfiguration:
    # fields
    # name: str
    description: str
    role: str
    timeout: int
    runtime: str
    memory_size: int
    handler: str
    package_type: str  # TODO: enum or literal union
    reserved_concurrent_executions: int
    environment: Dict[str, str]
    architectures: List[str]

    tracing_config_mode: str
    image_config: Optional[ImageConfig] = None
    layers: List[str] = dataclasses.field(default_factory=list)
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
    version_weights: List[VersionWeight]


@dataclasses.dataclass
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
    code: Code  # TODO: code might make more sense in the functionconfiguration?
    config_meta: FunctionConfigurationMeta
    config: VersionFunctionConfiguration
    provisioned_concurrency_config: Optional[ProvisionedConcurrencyConfiguration] = None

    @property
    def qualified_arn(self) -> str:
        return self.id.qualified_arn()


@dataclasses.dataclass
class Function:
    function_name: str
    aliases: Dict[str, VersionAlias] = dataclasses.field(default_factory=dict)
    next_version: int = 1
    versions: Dict[str, FunctionVersion] = dataclasses.field(default_factory=dict)
    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)

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
