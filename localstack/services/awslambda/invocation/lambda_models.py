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
    image_uri: Optional[str]

    s3_bucket: Optional[str]
    s3_key: Optional[str]
    s3_object_version: Optional[str]

    zip_file: Optional[str]


@dataclasses.dataclass
class DeadLetterConfig:
    target_arn: str


@dataclasses.dataclass
class Environment:
    variables: Dict[str, str]


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
class TracingConfig:
    mode: str  # TODO: enum or literal union


@dataclasses.dataclass
class VpcConfig:
    security_group_ids: List[str] = dataclasses.field(default_factory=list)
    subnet_ids: List[str] = dataclasses.field(default_factory=list)


class UpdateStatus:
    status: str
    code: Optional[str] = None  # TODO: probably not a string
    reason: Optional[str] = None


class FunctionConfigurationParameter:
    """configurable parts of FunctionConfiguration"""

    pass


@dataclasses.dataclass(frozen=True)
class FunctionConfiguration:
    # calculated / derived
    revision_id: str  # UUID, new one on each change
    last_modified: str  # ISO string
    last_update: UpdateStatus
    code_size: int
    coda_sha256: str
    function_arn: str

    # fields
    name: str
    description: str
    role: str
    timeout: int
    runtime: str
    memory_size: int
    handler: str
    package_type: str  # TODO: enum or literal union
    reserved_concurrent_executions: int
    image_config: ImageConfig
    environment: Environment
    architectures: List[str]

    # layers: List[str]
    # dead_letter_config: DeadLetterConfig
    # tracing_config: TracingConfig
    # kms_key_arn: str
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


@dataclasses.dataclass(frozen=True)
class Alias:
    function_version: int
    name: str
    description: str
    routing_configuration: AliasRoutingConfiguration
    # provisioned_concurrency_configuration: Optional[ProvisionedConcurrencyConfiguration]


@dataclasses.dataclass(frozen=True)
class Version:
    qualified_arn: str
    qualifier: str
    description: str
    code: Code  # TODO: code might make more sense in the functionconfiguration?
    config: FunctionConfiguration
    # provisioned_concurrency_config: Optional[ProvisionedConcurrencyConfiguration]


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


@dataclasses.dataclass
class Function:
    function_name: str
    aliases: Dict[str, Alias] = dataclasses.field(default_factory=dict)
    next_version: int = 1
    versions: Dict[str, Version] = dataclasses.field(default_factory=dict)
    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)


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
