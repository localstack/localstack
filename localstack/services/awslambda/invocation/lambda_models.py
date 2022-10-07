import abc
import dataclasses
import logging
import threading
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Optional, TypedDict

from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException
from localstack.aws.api.lambda_ import (
    AllowedPublishers,
    Architecture,
    CodeSigningPolicies,
    Cors,
    DestinationConfig,
    FunctionUrlAuthType,
    InvocationType,
    LastUpdateStatus,
    PackageType,
    ProvisionedConcurrencyStatusEnum,
    Runtime,
    State,
    StateReasonCode,
    TracingMode,
)
from localstack.services.awslambda.api_utils import qualified_lambda_arn, unqualified_lambda_arn
from localstack.utils.aws import aws_stack
from localstack.utils.strings import long_uid

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

LOG = logging.getLogger(__name__)


# To add support for a new runtime, just add it here with the accompanying image postfix
IMAGE_MAPPING = {
    "python3.7": "python:3.7",
    "python3.8": "python:3.8",
    "python3.9": "python:3.9",
    "nodejs12.x": "nodejs:12",
    "nodejs14.x": "nodejs:14",
    "nodejs16.x": "nodejs:16",
    "ruby2.7": "ruby:2.7",
    "java8": "java:8",
    "java8.al2": "java:8.al2",
    "java11": "java:11",
    "dotnetcore3.1": "dotnet:core3.1",
    "dotnet6": "dotnet:6",
    "go1.x": "go:1",
    "provided": "provided:alami",
    "provided.al2": "provided:al2",
}


@dataclasses.dataclass(frozen=True)
class VersionState:
    state: State
    code: Optional[StateReasonCode] = None
    reason: Optional[str] = None


@dataclasses.dataclass
class Invocation:
    payload: bytes
    invoked_arn: str
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
        try:
            s3_client.delete_object(Bucket=self.s3_bucket, Key=self.s3_key, **kwargs)
        except ClientError as e:
            LOG.debug(
                "Cannot delete lambda archive %s in bucket %s: %s", self.s3_key, self.s3_bucket, e
            )


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
    status: LastUpdateStatus | None
    code: str | None = None  # TODO: probably not a string
    reason: str | None = None


@dataclasses.dataclass
class LambdaEphemeralStorage:
    size: int


@dataclasses.dataclass
class FunctionUrlConfig:
    """
    * HTTP(s)
    * You can apply function URLs to any function alias, or to the $LATEST unpublished function version. You can't add a function URL to any other function version.
    * Once you create a function URL, its URL endpoint never changes
    """

    function_arn: str  # fully qualified ARN
    function_name: str  # resolved name
    cors: Cors
    url_id: str  # generated unique subdomain id  e.g. pfn5bdb2dl5mzkbn6eb2oi3xfe0nthdn
    url: str  # full URL (e.g. "https://pfn5bdb2dl5mzkbn6eb2oi3xfe0nthdn.lambda-url.eu-west-3.on.aws/")
    auth_type: FunctionUrlAuthType
    creation_time: str  # time
    last_modified_time: Optional[
        str
    ] = None  # TODO: check if this is the creation time when initially creating
    function_qualifier: Optional[str] = "$LATEST"  # only $LATEST or alias name


@dataclasses.dataclass(frozen=True)
class VersionFunctionConfiguration:
    # fields
    # name: str
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
    state: VersionState

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
    last_modified: str  # date


@dataclasses.dataclass
class ProvisionedConcurrencyState:
    """transient items"""

    allocated: int = 0
    available: int = 0
    status: ProvisionedConcurrencyStatusEnum = dataclasses.field(
        default=ProvisionedConcurrencyStatusEnum.IN_PROGRESS
    )
    status_reason: Optional[str] = None


@dataclasses.dataclass
class AliasRoutingConfig:
    version_weights: Dict[str, float]


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
        return unqualified_lambda_arn(
            function_name=self.function_name,
            region=self.region,
            account=self.account,
        )


@dataclasses.dataclass(frozen=True)
class VersionAlias:
    function_version: str
    name: str
    description: str | None
    routing_configuration: AliasRoutingConfig | None = None
    revision_id: str = dataclasses.field(init=False, default_factory=long_uid)


@dataclasses.dataclass(frozen=True)
class FunctionVersion:
    id: VersionIdentifier
    config: VersionFunctionConfiguration

    @property
    def qualified_arn(self) -> str:
        return self.id.qualified_arn()


@dataclasses.dataclass
class ResourcePolicy:
    Version: str
    Id: str
    Statement: list[dict]


@dataclasses.dataclass
class FunctionResourcePolicy:
    revision_id: str
    policy: ResourcePolicy  # TODO: do we have a typed IAM policy somewhere already?


@dataclasses.dataclass
class EventInvokeConfig:
    function_name: str
    qualifier: str

    last_modified: Optional[str] = dataclasses.field(compare=False)
    destination_config: Optional[DestinationConfig] = None
    maximum_retry_attempts: Optional[int] = None
    maximum_event_age_in_seconds: Optional[int] = None


@dataclasses.dataclass
class Function:
    function_name: str
    code_signing_config_arn: Optional[str] = None
    aliases: dict[str, VersionAlias] = dataclasses.field(default_factory=dict)
    versions: dict[str, FunctionVersion] = dataclasses.field(default_factory=dict)
    function_url_configs: dict[str, FunctionUrlConfig] = dataclasses.field(
        default_factory=dict
    )  # key has to be $LATEST or alias name
    permissions: dict[str, FunctionResourcePolicy] = dataclasses.field(
        default_factory=dict
    )  # key is $LATEST, version or alias
    event_invoke_configs: dict[str, EventInvokeConfig] = dataclasses.field(
        default_factory=dict
    )  # key is $LATEST(?), version or alias
    reserved_concurrent_executions: Optional[int] = None
    provisioned_concurrency_configs: dict[
        str, ProvisionedConcurrencyConfiguration
    ] = dataclasses.field(default_factory=dict)
    tags: dict[str, str] | None = None

    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)
    next_version: int = 1

    def latest(self) -> FunctionVersion:
        return self.versions["$LATEST"]


# Result Models
@dataclasses.dataclass
class InvocationResult:
    invocation_id: str
    payload: bytes | None
    executed_version: str | None = None
    logs: str | None = None


@dataclasses.dataclass
class InvocationError:
    invocation_id: str
    payload: bytes | None
    executed_version: str | None = None
    logs: str | None = None


@dataclasses.dataclass
class InvocationLogs:
    invocation_id: str
    logs: str


class Credentials(TypedDict):
    AccessKeyId: str
    SecretAccessKey: str
    SessionToken: str
    Expiration: datetime


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


@dataclasses.dataclass(frozen=True)
class CodeSigningConfig:
    csc_id: str
    arn: str

    allowed_publishers: AllowedPublishers
    policies: CodeSigningPolicies
    last_modified: str
    description: Optional[str] = None


@dataclasses.dataclass
class Layer:
    ...


@dataclasses.dataclass
class LayerVersion:
    ...


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="ValidationException", status_code=400, message=message)


class RequestEntityTooLargeException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="RequestEntityTooLargeException", status_code=413, message=message)


# note: we might at some point want to generalize these limits across all services and fetch them from there

LAMBDA_LIMITS_TOTAL_CODE_SIZE_DEFAULT = 80530636800
LAMBDA_LIMITS_CODE_SIZE_ZIPPED_DEFAULT = 52428800
LAMBDA_LIMITS_CODE_SIZE_UNZIPPED_DEFAULT = 262144000
LAMBDA_LIMITS_CONCURRENT_EXECUTIONS_DEFAULT = 150
LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE = 69905067
LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES = 4 * 1024

LAMBDA_MINIMUM_UNRESERVED_CONCURRENCY = 100


@dataclasses.dataclass
class AccountSettings:
    total_code_size: int = LAMBDA_LIMITS_TOTAL_CODE_SIZE_DEFAULT
    code_size_zipped: int = LAMBDA_LIMITS_CODE_SIZE_ZIPPED_DEFAULT
    code_size_unzipped: int = LAMBDA_LIMITS_CODE_SIZE_UNZIPPED_DEFAULT
    concurrent_executions: int = LAMBDA_LIMITS_CONCURRENT_EXECUTIONS_DEFAULT


@dataclasses.dataclass
class AccountLimitUsage:
    unreserved_concurrent_executions: int
    total_code_size: int
    function_count: int
