import dataclasses
import threading
from typing import Any, Dict, List, Optional


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
    """ configurable parts of FunctionConfiguration """
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
    qualifier: str
    description: str
    code: Code  # TODO: code might make more sense in the functionconfiguration?
    config: FunctionConfiguration
    # provisioned_concurrency_config: Optional[ProvisionedConcurrencyConfiguration]

@dataclasses.dataclass
class Function:
    function_name: str
    aliases: Dict[str, Alias] = dataclasses.field(default_factory=dict)
    next_version: int = 1
    versions: Dict[str, Version] = dataclasses.field(default_factory=dict)
    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)


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

