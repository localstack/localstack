from collections.abc import Iterable, Iterator
from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Action = str
AdditionalVersion = str
Alias = str
AllowCredentials = bool
Arn = str
AttemptCount = int
BatchSize = int
BisectBatchOnFunctionError = bool
Boolean = bool
CallbackId = str
CapacityProviderArn = str
CapacityProviderMaxVCpuCount = int
CapacityProviderName = str
CheckpointToken = str
ClientToken = str
CodeSigningConfigArn = str
CodeSigningConfigId = str
CollectionName = str
DatabaseName = str
Description = str
DestinationArn = str
DurableExecutionArn = str
DurableExecutionName = str
DurationSeconds = int
Enabled = bool
Endpoint = str
EnvironmentVariableName = str
EnvironmentVariableValue = str
EphemeralStorageSize = int
ErrorData = str
ErrorMessage = str
ErrorType = str
EventId = int
EventSourceMappingArn = str
EventSourceToken = str
ExecutionEnvironmentMemoryGiBPerVCpu = float
ExecutionTimeout = int
FileSystemArn = str
FilterCriteriaErrorCode = str
FilterCriteriaErrorMessage = str
FunctionArn = str
FunctionName = str
FunctionScalingConfigExecutionEnvironments = int
FunctionUrl = str
FunctionUrlQualifier = str
Handler = str
Header = str
HttpStatus = int
IncludeExecutionData = bool
InputPayload = str
InstanceType = str
Integer = int
InvokedViaFunctionUrl = bool
ItemCount = int
KMSKeyArn = str
KMSKeyArnNonEmpty = str
LastUpdateStatusReason = str
LayerArn = str
LayerName = str
LayerPermissionAllowedAction = str
LayerPermissionAllowedPrincipal = str
LayerVersionArn = str
LicenseInfo = str
LocalMountPath = str
LogGroup = str
MasterRegion = str
MaxAge = int
MaxFiftyListItems = int
MaxFunctionEventInvokeConfigListItems = int
MaxItems = int
MaxLayerListItems = int
MaxListItems = int
MaxProvisionedConcurrencyConfigListItems = int
MaximumBatchingWindowInSeconds = int
MaximumConcurrency = int
MaximumEventAgeInSeconds = int
MaximumNumberOfPollers = int
MaximumRecordAgeInSeconds = int
MaximumRetryAttempts = int
MaximumRetryAttemptsEventSourceMapping = int
MemorySize = int
Method = str
MetricTargetValue = float
MinimumNumberOfPollers = int
NameSpacedFunctionArn = str
NamespacedFunctionName = str
NamespacedStatementId = str
NonNegativeInteger = int
NullableBoolean = bool
NumericLatestPublishedOrAliasQualifier = str
OperationId = str
OperationName = str
OperationPayload = str
OperationSubType = str
OrganizationId = str
Origin = str
OutputPayload = str
ParallelizationFactor = int
Pattern = str
PerExecutionEnvironmentMaxConcurrency = int
PositiveInteger = int
Principal = str
PrincipalOrgID = str
ProvisionedPollerGroupName = str
PublishedFunctionQualifier = str
Qualifier = str
Queue = str
ReplayChildren = bool
ReservedConcurrentExecutions = int
ResourceArn = str
RetentionPeriodInDays = int
ReverseOrder = bool
RoleArn = str
RuntimeVersionArn = str
S3Bucket = str
S3Key = str
S3ObjectVersion = str
SchemaRegistryUri = str
SecurityGroupId = str
SensitiveString = str
SourceOwner = str
StackTraceEntry = str
StateReason = str
StatementId = str
StepOptionsNextAttemptDelaySecondsInteger = int
String = str
SubnetId = str
TagKey = str
TagValue = str
TaggableResource = str
TagsErrorCode = str
TagsErrorMessage = str
TenantId = str
Timeout = int
Timestamp = str
Topic = str
Truncated = bool
TumblingWindowInSeconds = int
URI = str
UnqualifiedFunctionName = str
UnreservedConcurrentExecutions = int
Version = str
VersionWithLatestPublished = str
VpcId = str
WaitOptionsWaitSecondsInteger = int
Weight = float
WorkingDirectory = str
XAmznTraceId = str


class ApplicationLogLevel(StrEnum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"


class Architecture(StrEnum):
    x86_64 = "x86_64"
    arm64 = "arm64"


class CapacityProviderPredefinedMetricType(StrEnum):
    LambdaCapacityProviderAverageCPUUtilization = "LambdaCapacityProviderAverageCPUUtilization"


class CapacityProviderScalingMode(StrEnum):
    Auto = "Auto"
    Manual = "Manual"


class CapacityProviderState(StrEnum):
    Pending = "Pending"
    Active = "Active"
    Failed = "Failed"
    Deleting = "Deleting"


class CodeSigningPolicy(StrEnum):
    Warn = "Warn"
    Enforce = "Enforce"


class EndPointType(StrEnum):
    KAFKA_BOOTSTRAP_SERVERS = "KAFKA_BOOTSTRAP_SERVERS"


class EventSourceMappingMetric(StrEnum):
    EventCount = "EventCount"


class EventSourcePosition(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"


class EventType(StrEnum):
    ExecutionStarted = "ExecutionStarted"
    ExecutionSucceeded = "ExecutionSucceeded"
    ExecutionFailed = "ExecutionFailed"
    ExecutionTimedOut = "ExecutionTimedOut"
    ExecutionStopped = "ExecutionStopped"
    ContextStarted = "ContextStarted"
    ContextSucceeded = "ContextSucceeded"
    ContextFailed = "ContextFailed"
    WaitStarted = "WaitStarted"
    WaitSucceeded = "WaitSucceeded"
    WaitCancelled = "WaitCancelled"
    StepStarted = "StepStarted"
    StepSucceeded = "StepSucceeded"
    StepFailed = "StepFailed"
    ChainedInvokeStarted = "ChainedInvokeStarted"
    ChainedInvokeSucceeded = "ChainedInvokeSucceeded"
    ChainedInvokeFailed = "ChainedInvokeFailed"
    ChainedInvokeTimedOut = "ChainedInvokeTimedOut"
    ChainedInvokeStopped = "ChainedInvokeStopped"
    CallbackStarted = "CallbackStarted"
    CallbackSucceeded = "CallbackSucceeded"
    CallbackFailed = "CallbackFailed"
    CallbackTimedOut = "CallbackTimedOut"
    InvocationCompleted = "InvocationCompleted"


class ExecutionStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    STOPPED = "STOPPED"


class FullDocument(StrEnum):
    UpdateLookup = "UpdateLookup"
    Default = "Default"


class FunctionResponseType(StrEnum):
    ReportBatchItemFailures = "ReportBatchItemFailures"


class FunctionUrlAuthType(StrEnum):
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"


class FunctionVersion(StrEnum):
    ALL = "ALL"


class FunctionVersionLatestPublished(StrEnum):
    LATEST_PUBLISHED = "LATEST_PUBLISHED"


class InvocationType(StrEnum):
    Event = "Event"
    RequestResponse = "RequestResponse"
    DryRun = "DryRun"


class InvokeMode(StrEnum):
    BUFFERED = "BUFFERED"
    RESPONSE_STREAM = "RESPONSE_STREAM"


class KafkaSchemaRegistryAuthType(StrEnum):
    BASIC_AUTH = "BASIC_AUTH"
    CLIENT_CERTIFICATE_TLS_AUTH = "CLIENT_CERTIFICATE_TLS_AUTH"
    SERVER_ROOT_CA_CERTIFICATE = "SERVER_ROOT_CA_CERTIFICATE"


class KafkaSchemaValidationAttribute(StrEnum):
    KEY = "KEY"
    VALUE = "VALUE"


class LastUpdateStatus(StrEnum):
    Successful = "Successful"
    Failed = "Failed"
    InProgress = "InProgress"


class LastUpdateStatusReasonCode(StrEnum):
    EniLimitExceeded = "EniLimitExceeded"
    InsufficientRolePermissions = "InsufficientRolePermissions"
    InvalidConfiguration = "InvalidConfiguration"
    InternalError = "InternalError"
    SubnetOutOfIPAddresses = "SubnetOutOfIPAddresses"
    InvalidSubnet = "InvalidSubnet"
    InvalidSecurityGroup = "InvalidSecurityGroup"
    ImageDeleted = "ImageDeleted"
    ImageAccessDenied = "ImageAccessDenied"
    InvalidImage = "InvalidImage"
    KMSKeyAccessDenied = "KMSKeyAccessDenied"
    KMSKeyNotFound = "KMSKeyNotFound"
    InvalidStateKMSKey = "InvalidStateKMSKey"
    DisabledKMSKey = "DisabledKMSKey"
    EFSIOError = "EFSIOError"
    EFSMountConnectivityError = "EFSMountConnectivityError"
    EFSMountFailure = "EFSMountFailure"
    EFSMountTimeout = "EFSMountTimeout"
    InvalidRuntime = "InvalidRuntime"
    InvalidZipFileException = "InvalidZipFileException"
    FunctionError = "FunctionError"
    VcpuLimitExceeded = "VcpuLimitExceeded"
    CapacityProviderScalingLimitExceeded = "CapacityProviderScalingLimitExceeded"
    InsufficientCapacity = "InsufficientCapacity"
    EC2RequestLimitExceeded = "EC2RequestLimitExceeded"
    FunctionError_InitTimeout = "FunctionError.InitTimeout"
    FunctionError_RuntimeInitError = "FunctionError.RuntimeInitError"
    FunctionError_ExtensionInitError = "FunctionError.ExtensionInitError"
    FunctionError_InvalidEntryPoint = "FunctionError.InvalidEntryPoint"
    FunctionError_InvalidWorkingDirectory = "FunctionError.InvalidWorkingDirectory"
    FunctionError_PermissionDenied = "FunctionError.PermissionDenied"
    FunctionError_TooManyExtensions = "FunctionError.TooManyExtensions"
    FunctionError_InitResourceExhausted = "FunctionError.InitResourceExhausted"
    DisallowedByVpcEncryptionControl = "DisallowedByVpcEncryptionControl"


class LogFormat(StrEnum):
    JSON = "JSON"
    Text = "Text"


class LogType(StrEnum):
    None_ = "None"
    Tail = "Tail"


class OperationAction(StrEnum):
    START = "START"
    SUCCEED = "SUCCEED"
    FAIL = "FAIL"
    RETRY = "RETRY"
    CANCEL = "CANCEL"


class OperationStatus(StrEnum):
    STARTED = "STARTED"
    PENDING = "PENDING"
    READY = "READY"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    STOPPED = "STOPPED"


class OperationType(StrEnum):
    EXECUTION = "EXECUTION"
    CONTEXT = "CONTEXT"
    STEP = "STEP"
    WAIT = "WAIT"
    CALLBACK = "CALLBACK"
    CHAINED_INVOKE = "CHAINED_INVOKE"


class PackageType(StrEnum):
    Zip = "Zip"
    Image = "Image"


class ProvisionedConcurrencyStatusEnum(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    READY = "READY"
    FAILED = "FAILED"


class RecursiveLoop(StrEnum):
    Allow = "Allow"
    Terminate = "Terminate"


class ResponseStreamingInvocationType(StrEnum):
    RequestResponse = "RequestResponse"
    DryRun = "DryRun"


class Runtime(StrEnum):
    nodejs = "nodejs"
    nodejs4_3 = "nodejs4.3"
    nodejs6_10 = "nodejs6.10"
    nodejs8_10 = "nodejs8.10"
    nodejs10_x = "nodejs10.x"
    nodejs12_x = "nodejs12.x"
    nodejs14_x = "nodejs14.x"
    nodejs16_x = "nodejs16.x"
    java8 = "java8"
    java8_al2 = "java8.al2"
    java11 = "java11"
    python2_7 = "python2.7"
    python3_6 = "python3.6"
    python3_7 = "python3.7"
    python3_8 = "python3.8"
    python3_9 = "python3.9"
    dotnetcore1_0 = "dotnetcore1.0"
    dotnetcore2_0 = "dotnetcore2.0"
    dotnetcore2_1 = "dotnetcore2.1"
    dotnetcore3_1 = "dotnetcore3.1"
    dotnet6 = "dotnet6"
    dotnet8 = "dotnet8"
    nodejs4_3_edge = "nodejs4.3-edge"
    go1_x = "go1.x"
    ruby2_5 = "ruby2.5"
    ruby2_7 = "ruby2.7"
    provided = "provided"
    provided_al2 = "provided.al2"
    nodejs18_x = "nodejs18.x"
    python3_10 = "python3.10"
    java17 = "java17"
    ruby3_2 = "ruby3.2"
    ruby3_3 = "ruby3.3"
    ruby3_4 = "ruby3.4"
    python3_11 = "python3.11"
    nodejs20_x = "nodejs20.x"
    provided_al2023 = "provided.al2023"
    python3_12 = "python3.12"
    java21 = "java21"
    python3_13 = "python3.13"
    nodejs22_x = "nodejs22.x"
    nodejs24_x = "nodejs24.x"
    python3_14 = "python3.14"
    java25 = "java25"
    dotnet10 = "dotnet10"


class SchemaRegistryEventRecordFormat(StrEnum):
    JSON = "JSON"
    SOURCE = "SOURCE"


class SnapStartApplyOn(StrEnum):
    PublishedVersions = "PublishedVersions"
    None_ = "None"


class SnapStartOptimizationStatus(StrEnum):
    On = "On"
    Off = "Off"


class SourceAccessType(StrEnum):
    BASIC_AUTH = "BASIC_AUTH"
    VPC_SUBNET = "VPC_SUBNET"
    VPC_SECURITY_GROUP = "VPC_SECURITY_GROUP"
    SASL_SCRAM_512_AUTH = "SASL_SCRAM_512_AUTH"
    SASL_SCRAM_256_AUTH = "SASL_SCRAM_256_AUTH"
    VIRTUAL_HOST = "VIRTUAL_HOST"
    CLIENT_CERTIFICATE_TLS_AUTH = "CLIENT_CERTIFICATE_TLS_AUTH"
    SERVER_ROOT_CA_CERTIFICATE = "SERVER_ROOT_CA_CERTIFICATE"


class State(StrEnum):
    Pending = "Pending"
    Active = "Active"
    Inactive = "Inactive"
    Failed = "Failed"
    Deactivating = "Deactivating"
    Deactivated = "Deactivated"
    ActiveNonInvocable = "ActiveNonInvocable"
    Deleting = "Deleting"


class StateReasonCode(StrEnum):
    Idle = "Idle"
    Creating = "Creating"
    Restoring = "Restoring"
    EniLimitExceeded = "EniLimitExceeded"
    InsufficientRolePermissions = "InsufficientRolePermissions"
    InvalidConfiguration = "InvalidConfiguration"
    InternalError = "InternalError"
    SubnetOutOfIPAddresses = "SubnetOutOfIPAddresses"
    InvalidSubnet = "InvalidSubnet"
    InvalidSecurityGroup = "InvalidSecurityGroup"
    ImageDeleted = "ImageDeleted"
    ImageAccessDenied = "ImageAccessDenied"
    InvalidImage = "InvalidImage"
    KMSKeyAccessDenied = "KMSKeyAccessDenied"
    KMSKeyNotFound = "KMSKeyNotFound"
    InvalidStateKMSKey = "InvalidStateKMSKey"
    DisabledKMSKey = "DisabledKMSKey"
    EFSIOError = "EFSIOError"
    EFSMountConnectivityError = "EFSMountConnectivityError"
    EFSMountFailure = "EFSMountFailure"
    EFSMountTimeout = "EFSMountTimeout"
    InvalidRuntime = "InvalidRuntime"
    InvalidZipFileException = "InvalidZipFileException"
    FunctionError = "FunctionError"
    DrainingDurableExecutions = "DrainingDurableExecutions"
    VcpuLimitExceeded = "VcpuLimitExceeded"
    CapacityProviderScalingLimitExceeded = "CapacityProviderScalingLimitExceeded"
    InsufficientCapacity = "InsufficientCapacity"
    EC2RequestLimitExceeded = "EC2RequestLimitExceeded"
    FunctionError_InitTimeout = "FunctionError.InitTimeout"
    FunctionError_RuntimeInitError = "FunctionError.RuntimeInitError"
    FunctionError_ExtensionInitError = "FunctionError.ExtensionInitError"
    FunctionError_InvalidEntryPoint = "FunctionError.InvalidEntryPoint"
    FunctionError_InvalidWorkingDirectory = "FunctionError.InvalidWorkingDirectory"
    FunctionError_PermissionDenied = "FunctionError.PermissionDenied"
    FunctionError_TooManyExtensions = "FunctionError.TooManyExtensions"
    FunctionError_InitResourceExhausted = "FunctionError.InitResourceExhausted"
    DisallowedByVpcEncryptionControl = "DisallowedByVpcEncryptionControl"


class SystemLogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"


class TenantIsolationMode(StrEnum):
    PER_TENANT = "PER_TENANT"


class ThrottleReason(StrEnum):
    ConcurrentInvocationLimitExceeded = "ConcurrentInvocationLimitExceeded"
    FunctionInvocationRateLimitExceeded = "FunctionInvocationRateLimitExceeded"
    ReservedFunctionConcurrentInvocationLimitExceeded = (
        "ReservedFunctionConcurrentInvocationLimitExceeded"
    )
    ReservedFunctionInvocationRateLimitExceeded = "ReservedFunctionInvocationRateLimitExceeded"
    CallerRateLimitExceeded = "CallerRateLimitExceeded"
    ConcurrentSnapshotCreateLimitExceeded = "ConcurrentSnapshotCreateLimitExceeded"


class TracingMode(StrEnum):
    Active = "Active"
    PassThrough = "PassThrough"


class UpdateRuntimeOn(StrEnum):
    Auto = "Auto"
    Manual = "Manual"
    FunctionUpdate = "FunctionUpdate"


class CallbackTimeoutException(ServiceException):
    code: str = "CallbackTimeoutException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class CapacityProviderLimitExceededException(ServiceException):
    code: str = "CapacityProviderLimitExceededException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class CodeSigningConfigNotFoundException(ServiceException):
    code: str = "CodeSigningConfigNotFoundException"
    sender_fault: bool = True
    status_code: int = 404
    Type: String | None


class CodeStorageExceededException(ServiceException):
    code: str = "CodeStorageExceededException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class CodeVerificationFailedException(ServiceException):
    code: str = "CodeVerificationFailedException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class DurableExecutionAlreadyStartedException(ServiceException):
    code: str = "DurableExecutionAlreadyStartedException"
    sender_fault: bool = True
    status_code: int = 409
    Type: String | None


class EC2AccessDeniedException(ServiceException):
    code: str = "EC2AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class EC2ThrottledException(ServiceException):
    code: str = "EC2ThrottledException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class EC2UnexpectedException(ServiceException):
    code: str = "EC2UnexpectedException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None
    EC2ErrorCode: String | None


class EFSIOException(ServiceException):
    code: str = "EFSIOException"
    sender_fault: bool = True
    status_code: int = 410
    Type: String | None


class EFSMountConnectivityException(ServiceException):
    code: str = "EFSMountConnectivityException"
    sender_fault: bool = True
    status_code: int = 408
    Type: String | None


class EFSMountFailureException(ServiceException):
    code: str = "EFSMountFailureException"
    sender_fault: bool = True
    status_code: int = 403
    Type: String | None


class EFSMountTimeoutException(ServiceException):
    code: str = "EFSMountTimeoutException"
    sender_fault: bool = True
    status_code: int = 408
    Type: String | None


class ENILimitReachedException(ServiceException):
    code: str = "ENILimitReachedException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class FunctionVersionsPerCapacityProviderLimitExceededException(ServiceException):
    code: str = "FunctionVersionsPerCapacityProviderLimitExceededException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class InvalidCodeSignatureException(ServiceException):
    code: str = "InvalidCodeSignatureException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class InvalidParameterValueException(ServiceException):
    code: str = "InvalidParameterValueException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class InvalidRequestContentException(ServiceException):
    code: str = "InvalidRequestContentException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class InvalidRuntimeException(ServiceException):
    code: str = "InvalidRuntimeException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class InvalidSecurityGroupIDException(ServiceException):
    code: str = "InvalidSecurityGroupIDException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class InvalidSubnetIDException(ServiceException):
    code: str = "InvalidSubnetIDException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class InvalidZipFileException(ServiceException):
    code: str = "InvalidZipFileException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class KMSAccessDeniedException(ServiceException):
    code: str = "KMSAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class KMSDisabledException(ServiceException):
    code: str = "KMSDisabledException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class KMSInvalidStateException(ServiceException):
    code: str = "KMSInvalidStateException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class KMSNotFoundException(ServiceException):
    code: str = "KMSNotFoundException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class NoPublishedVersionException(ServiceException):
    code: str = "NoPublishedVersionException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class PolicyLengthExceededException(ServiceException):
    code: str = "PolicyLengthExceededException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class PreconditionFailedException(ServiceException):
    code: str = "PreconditionFailedException"
    sender_fault: bool = True
    status_code: int = 412
    Type: String | None


class ProvisionedConcurrencyConfigNotFoundException(ServiceException):
    code: str = "ProvisionedConcurrencyConfigNotFoundException"
    sender_fault: bool = True
    status_code: int = 404
    Type: String | None


class RecursiveInvocationException(ServiceException):
    code: str = "RecursiveInvocationException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class RequestTooLargeException(ServiceException):
    code: str = "RequestTooLargeException"
    sender_fault: bool = True
    status_code: int = 413
    Type: String | None


class ResourceConflictException(ServiceException):
    code: str = "ResourceConflictException"
    sender_fault: bool = True
    status_code: int = 409
    Type: String | None


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = True
    status_code: int = 404
    Type: String | None


class ResourceNotReadyException(ServiceException):
    code: str = "ResourceNotReadyException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class SerializedRequestEntityTooLargeException(ServiceException):
    code: str = "SerializedRequestEntityTooLargeException"
    sender_fault: bool = True
    status_code: int = 413
    Type: String | None


class ServiceException(ServiceException):
    code: str = "ServiceException"
    sender_fault: bool = False
    status_code: int = 500
    Type: String | None


class SnapStartException(ServiceException):
    code: str = "SnapStartException"
    sender_fault: bool = True
    status_code: int = 400
    Type: String | None


class SnapStartNotReadyException(ServiceException):
    code: str = "SnapStartNotReadyException"
    sender_fault: bool = True
    status_code: int = 409
    Type: String | None


class SnapStartTimeoutException(ServiceException):
    code: str = "SnapStartTimeoutException"
    sender_fault: bool = True
    status_code: int = 408
    Type: String | None


class SubnetIPAddressLimitReachedException(ServiceException):
    code: str = "SubnetIPAddressLimitReachedException"
    sender_fault: bool = False
    status_code: int = 502
    Type: String | None


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = True
    status_code: int = 429
    retryAfterSeconds: String | None
    Type: String | None
    Reason: ThrottleReason | None


class UnsupportedMediaTypeException(ServiceException):
    code: str = "UnsupportedMediaTypeException"
    sender_fault: bool = True
    status_code: int = 415
    Type: String | None


Long = int


class AccountLimit(TypedDict, total=False):
    TotalCodeSize: Long | None
    CodeSizeUnzipped: Long | None
    CodeSizeZipped: Long | None
    ConcurrentExecutions: Integer | None
    UnreservedConcurrentExecutions: UnreservedConcurrentExecutions | None


class AccountUsage(TypedDict, total=False):
    TotalCodeSize: Long | None
    FunctionCount: Long | None


LayerVersionNumber = int


class AddLayerVersionPermissionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber
    StatementId: StatementId
    Action: LayerPermissionAllowedAction
    Principal: LayerPermissionAllowedPrincipal
    OrganizationId: OrganizationId | None
    RevisionId: String | None


class AddLayerVersionPermissionResponse(TypedDict, total=False):
    Statement: String | None
    RevisionId: String | None


class AddPermissionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    StatementId: StatementId
    Action: Action
    Principal: Principal
    SourceArn: Arn | None
    SourceAccount: SourceOwner | None
    EventSourceToken: EventSourceToken | None
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    RevisionId: String | None
    PrincipalOrgID: PrincipalOrgID | None
    FunctionUrlAuthType: FunctionUrlAuthType | None
    InvokedViaFunctionUrl: InvokedViaFunctionUrl | None


class AddPermissionResponse(TypedDict, total=False):
    Statement: String | None


AdditionalVersionWeights = dict[AdditionalVersion, Weight]


class AliasRoutingConfiguration(TypedDict, total=False):
    AdditionalVersionWeights: AdditionalVersionWeights | None


class AliasConfiguration(TypedDict, total=False):
    AliasArn: FunctionArn | None
    Name: Alias | None
    FunctionVersion: Version | None
    Description: Description | None
    RoutingConfig: AliasRoutingConfiguration | None
    RevisionId: String | None


AliasList = list[AliasConfiguration]
AllowMethodsList = list[Method]
AllowOriginsList = list[Origin]
SigningProfileVersionArns = list[Arn]


class AllowedPublishers(TypedDict, total=False):
    SigningProfileVersionArns: SigningProfileVersionArns


class KafkaSchemaValidationConfig(TypedDict, total=False):
    Attribute: KafkaSchemaValidationAttribute | None


KafkaSchemaValidationConfigList = list[KafkaSchemaValidationConfig]


class KafkaSchemaRegistryAccessConfig(TypedDict, total=False):
    Type: KafkaSchemaRegistryAuthType | None
    URI: Arn | None


KafkaSchemaRegistryAccessConfigList = list[KafkaSchemaRegistryAccessConfig]


class KafkaSchemaRegistryConfig(TypedDict, total=False):
    SchemaRegistryURI: SchemaRegistryUri | None
    EventRecordFormat: SchemaRegistryEventRecordFormat | None
    AccessConfigs: KafkaSchemaRegistryAccessConfigList | None
    SchemaValidationConfigs: KafkaSchemaValidationConfigList | None


class AmazonManagedKafkaEventSourceConfig(TypedDict, total=False):
    ConsumerGroupId: URI | None
    SchemaRegistryConfig: KafkaSchemaRegistryConfig | None


ArchitecturesList = list[Architecture]
BinaryOperationPayload = bytes
Blob = bytes
BlobStream = bytes
StackTraceEntries = list[StackTraceEntry]


class ErrorObject(TypedDict, total=False):
    ErrorMessage: ErrorMessage | None
    ErrorType: ErrorType | None
    ErrorData: ErrorData | None
    StackTrace: StackTraceEntries | None


class CallbackDetails(TypedDict, total=False):
    CallbackId: CallbackId | None
    Result: OperationPayload | None
    Error: ErrorObject | None


class EventError(TypedDict, total=False):
    Payload: ErrorObject | None
    Truncated: Truncated | None


class CallbackFailedDetails(TypedDict, total=False):
    Error: EventError


class CallbackOptions(TypedDict, total=False):
    TimeoutSeconds: DurationSeconds | None
    HeartbeatTimeoutSeconds: DurationSeconds | None


class CallbackStartedDetails(TypedDict, total=False):
    CallbackId: CallbackId
    HeartbeatTimeout: DurationSeconds | None
    Timeout: DurationSeconds | None


class EventResult(TypedDict, total=False):
    Payload: OperationPayload | None
    Truncated: Truncated | None


class CallbackSucceededDetails(TypedDict, total=False):
    Result: EventResult


class CallbackTimedOutDetails(TypedDict, total=False):
    Error: EventError


class TargetTrackingScalingPolicy(TypedDict, total=False):
    PredefinedMetricType: CapacityProviderPredefinedMetricType
    TargetValue: MetricTargetValue


CapacityProviderScalingPoliciesList = list[TargetTrackingScalingPolicy]


class CapacityProviderScalingConfig(TypedDict, total=False):
    MaxVCpuCount: CapacityProviderMaxVCpuCount | None
    ScalingMode: CapacityProviderScalingMode | None
    ScalingPolicies: CapacityProviderScalingPoliciesList | None


InstanceTypeSet = list[InstanceType]


class InstanceRequirements(TypedDict, total=False):
    Architectures: ArchitecturesList | None
    AllowedInstanceTypes: InstanceTypeSet | None
    ExcludedInstanceTypes: InstanceTypeSet | None


class CapacityProviderPermissionsConfig(TypedDict, total=False):
    CapacityProviderOperatorRoleArn: RoleArn


CapacityProviderSecurityGroupIds = list[SecurityGroupId]
CapacityProviderSubnetIds = list[SubnetId]


class CapacityProviderVpcConfig(TypedDict, total=False):
    SubnetIds: CapacityProviderSubnetIds
    SecurityGroupIds: CapacityProviderSecurityGroupIds


class CapacityProvider(TypedDict, total=False):
    CapacityProviderArn: CapacityProviderArn
    State: CapacityProviderState
    VpcConfig: CapacityProviderVpcConfig
    PermissionsConfig: CapacityProviderPermissionsConfig
    InstanceRequirements: InstanceRequirements | None
    CapacityProviderScalingConfig: CapacityProviderScalingConfig | None
    KmsKeyArn: KMSKeyArn | None
    LastModified: Timestamp | None


class LambdaManagedInstancesCapacityProviderConfig(TypedDict, total=False):
    CapacityProviderArn: CapacityProviderArn
    PerExecutionEnvironmentMaxConcurrency: PerExecutionEnvironmentMaxConcurrency | None
    ExecutionEnvironmentMemoryGiBPerVCpu: ExecutionEnvironmentMemoryGiBPerVCpu | None


class CapacityProviderConfig(TypedDict, total=False):
    LambdaManagedInstancesCapacityProviderConfig: LambdaManagedInstancesCapacityProviderConfig


CapacityProvidersList = list[CapacityProvider]


class ChainedInvokeDetails(TypedDict, total=False):
    Result: OperationPayload | None
    Error: ErrorObject | None


class ChainedInvokeFailedDetails(TypedDict, total=False):
    Error: EventError


class ChainedInvokeOptions(TypedDict, total=False):
    FunctionName: NamespacedFunctionName
    TenantId: TenantId | None


class EventInput(TypedDict, total=False):
    Payload: InputPayload | None
    Truncated: Truncated | None


class ChainedInvokeStartedDetails(TypedDict, total=False):
    FunctionName: NamespacedFunctionName
    TenantId: TenantId | None
    Input: EventInput | None
    ExecutedVersion: VersionWithLatestPublished | None
    DurableExecutionArn: DurableExecutionArn | None


class ChainedInvokeStoppedDetails(TypedDict, total=False):
    Error: EventError


class ChainedInvokeSucceededDetails(TypedDict, total=False):
    Result: EventResult


class ChainedInvokeTimedOutDetails(TypedDict, total=False):
    Error: EventError


class WaitOptions(TypedDict, total=False):
    WaitSeconds: WaitOptionsWaitSecondsInteger | None


class StepOptions(TypedDict, total=False):
    NextAttemptDelaySeconds: StepOptionsNextAttemptDelaySecondsInteger | None


class ContextOptions(TypedDict, total=False):
    ReplayChildren: ReplayChildren | None


class OperationUpdate(TypedDict, total=False):
    Id: OperationId
    ParentId: OperationId | None
    Name: OperationName | None
    Type: OperationType
    SubType: OperationSubType | None
    Action: OperationAction
    Payload: OperationPayload | None
    Error: ErrorObject | None
    ContextOptions: ContextOptions | None
    StepOptions: StepOptions | None
    WaitOptions: WaitOptions | None
    CallbackOptions: CallbackOptions | None
    ChainedInvokeOptions: ChainedInvokeOptions | None


OperationUpdates = list[OperationUpdate]


class CheckpointDurableExecutionRequest(ServiceRequest):
    DurableExecutionArn: DurableExecutionArn
    CheckpointToken: CheckpointToken
    Updates: OperationUpdates | None
    ClientToken: ClientToken | None


ExecutionTimestamp = datetime


class WaitDetails(TypedDict, total=False):
    ScheduledEndTimestamp: ExecutionTimestamp | None


class StepDetails(TypedDict, total=False):
    Attempt: AttemptCount | None
    NextAttemptTimestamp: ExecutionTimestamp | None
    Result: OperationPayload | None
    Error: ErrorObject | None


class ContextDetails(TypedDict, total=False):
    ReplayChildren: ReplayChildren | None
    Result: OperationPayload | None
    Error: ErrorObject | None


class ExecutionDetails(TypedDict, total=False):
    InputPayload: InputPayload | None


class Operation(TypedDict, total=False):
    Id: OperationId
    ParentId: OperationId | None
    Name: OperationName | None
    Type: OperationType
    SubType: OperationSubType | None
    StartTimestamp: ExecutionTimestamp
    EndTimestamp: ExecutionTimestamp | None
    Status: OperationStatus
    ExecutionDetails: ExecutionDetails | None
    ContextDetails: ContextDetails | None
    StepDetails: StepDetails | None
    WaitDetails: WaitDetails | None
    CallbackDetails: CallbackDetails | None
    ChainedInvokeDetails: ChainedInvokeDetails | None


Operations = list[Operation]


class CheckpointUpdatedExecutionState(TypedDict, total=False):
    Operations: Operations | None
    NextMarker: String | None


class CheckpointDurableExecutionResponse(TypedDict, total=False):
    CheckpointToken: CheckpointToken | None
    NewExecutionState: CheckpointUpdatedExecutionState


class CodeSigningPolicies(TypedDict, total=False):
    UntrustedArtifactOnDeployment: CodeSigningPolicy | None


class CodeSigningConfig(TypedDict, total=False):
    CodeSigningConfigId: CodeSigningConfigId
    CodeSigningConfigArn: CodeSigningConfigArn
    Description: Description | None
    AllowedPublishers: AllowedPublishers
    CodeSigningPolicies: CodeSigningPolicies
    LastModified: Timestamp


CodeSigningConfigList = list[CodeSigningConfig]
CompatibleArchitectures = list[Architecture]
CompatibleRuntimes = list[Runtime]


class Concurrency(TypedDict, total=False):
    ReservedConcurrentExecutions: ReservedConcurrentExecutions | None


class ContextFailedDetails(TypedDict, total=False):
    Error: EventError


class ContextStartedDetails(TypedDict, total=False):
    pass


class ContextSucceededDetails(TypedDict, total=False):
    Result: EventResult


HeadersList = list[Header]


class Cors(TypedDict, total=False):
    AllowCredentials: AllowCredentials | None
    AllowHeaders: HeadersList | None
    AllowMethods: AllowMethodsList | None
    AllowOrigins: AllowOriginsList | None
    ExposeHeaders: HeadersList | None
    MaxAge: MaxAge | None


class CreateAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias
    FunctionVersion: VersionWithLatestPublished
    Description: Description | None
    RoutingConfig: AliasRoutingConfiguration | None


Tags = dict[TagKey, TagValue]


class CreateCapacityProviderRequest(ServiceRequest):
    CapacityProviderName: CapacityProviderName
    VpcConfig: CapacityProviderVpcConfig
    PermissionsConfig: CapacityProviderPermissionsConfig
    InstanceRequirements: InstanceRequirements | None
    CapacityProviderScalingConfig: CapacityProviderScalingConfig | None
    KmsKeyArn: KMSKeyArnNonEmpty | None
    Tags: Tags | None


class CreateCapacityProviderResponse(TypedDict, total=False):
    CapacityProvider: CapacityProvider


class CreateCodeSigningConfigRequest(ServiceRequest):
    Description: Description | None
    AllowedPublishers: AllowedPublishers
    CodeSigningPolicies: CodeSigningPolicies | None
    Tags: Tags | None


class CreateCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


class ProvisionedPollerConfig(TypedDict, total=False):
    MinimumPollers: MinimumNumberOfPollers | None
    MaximumPollers: MaximumNumberOfPollers | None
    PollerGroupName: ProvisionedPollerGroupName | None


EventSourceMappingMetricList = list[EventSourceMappingMetric]


class EventSourceMappingMetricsConfig(TypedDict, total=False):
    Metrics: EventSourceMappingMetricList | None


class DocumentDBEventSourceConfig(TypedDict, total=False):
    DatabaseName: DatabaseName | None
    CollectionName: CollectionName | None
    FullDocument: FullDocument | None


class ScalingConfig(TypedDict, total=False):
    MaximumConcurrency: MaximumConcurrency | None


class SelfManagedKafkaEventSourceConfig(TypedDict, total=False):
    ConsumerGroupId: URI | None
    SchemaRegistryConfig: KafkaSchemaRegistryConfig | None


FunctionResponseTypeList = list[FunctionResponseType]
EndpointLists = list[Endpoint]
Endpoints = dict[EndPointType, EndpointLists]


class SelfManagedEventSource(TypedDict, total=False):
    Endpoints: Endpoints | None


class SourceAccessConfiguration(TypedDict, total=False):
    Type: SourceAccessType | None
    URI: URI | None


SourceAccessConfigurations = list[SourceAccessConfiguration]
Queues = list[Queue]
Topics = list[Topic]


class OnFailure(TypedDict, total=False):
    Destination: DestinationArn | None


class OnSuccess(TypedDict, total=False):
    Destination: DestinationArn | None


class DestinationConfig(TypedDict, total=False):
    OnSuccess: OnSuccess | None
    OnFailure: OnFailure | None


Date = datetime


class Filter(TypedDict, total=False):
    Pattern: Pattern | None


FilterList = list[Filter]


class FilterCriteria(TypedDict, total=False):
    Filters: FilterList | None


class CreateEventSourceMappingRequest(ServiceRequest):
    EventSourceArn: Arn | None
    FunctionName: NamespacedFunctionName
    Enabled: Enabled | None
    BatchSize: BatchSize | None
    FilterCriteria: FilterCriteria | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    ParallelizationFactor: ParallelizationFactor | None
    StartingPosition: EventSourcePosition | None
    StartingPositionTimestamp: Date | None
    DestinationConfig: DestinationConfig | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    BisectBatchOnFunctionError: BisectBatchOnFunctionError | None
    MaximumRetryAttempts: MaximumRetryAttemptsEventSourceMapping | None
    Tags: Tags | None
    TumblingWindowInSeconds: TumblingWindowInSeconds | None
    Topics: Topics | None
    Queues: Queues | None
    SourceAccessConfigurations: SourceAccessConfigurations | None
    SelfManagedEventSource: SelfManagedEventSource | None
    FunctionResponseTypes: FunctionResponseTypeList | None
    AmazonManagedKafkaEventSourceConfig: AmazonManagedKafkaEventSourceConfig | None
    SelfManagedKafkaEventSourceConfig: SelfManagedKafkaEventSourceConfig | None
    ScalingConfig: ScalingConfig | None
    DocumentDBEventSourceConfig: DocumentDBEventSourceConfig | None
    KMSKeyArn: KMSKeyArn | None
    MetricsConfig: EventSourceMappingMetricsConfig | None
    ProvisionedPollerConfig: ProvisionedPollerConfig | None


class TenancyConfig(TypedDict, total=False):
    TenantIsolationMode: TenantIsolationMode


class DurableConfig(TypedDict, total=False):
    RetentionPeriodInDays: RetentionPeriodInDays | None
    ExecutionTimeout: ExecutionTimeout | None


class LoggingConfig(TypedDict, total=False):
    LogFormat: LogFormat | None
    ApplicationLogLevel: ApplicationLogLevel | None
    SystemLogLevel: SystemLogLevel | None
    LogGroup: LogGroup | None


class SnapStart(TypedDict, total=False):
    ApplyOn: SnapStartApplyOn | None


class EphemeralStorage(TypedDict, total=False):
    Size: EphemeralStorageSize


StringList = list[String]


class ImageConfig(TypedDict, total=False):
    EntryPoint: StringList | None
    Command: StringList | None
    WorkingDirectory: WorkingDirectory | None


class FileSystemConfig(TypedDict, total=False):
    Arn: FileSystemArn
    LocalMountPath: LocalMountPath


FileSystemConfigList = list[FileSystemConfig]
LayerList = list[LayerVersionArn]


class TracingConfig(TypedDict, total=False):
    Mode: TracingMode | None


EnvironmentVariables = dict[EnvironmentVariableName, EnvironmentVariableValue]


class Environment(TypedDict, total=False):
    Variables: EnvironmentVariables | None


class DeadLetterConfig(TypedDict, total=False):
    TargetArn: ResourceArn | None


SecurityGroupIds = list[SecurityGroupId]
SubnetIds = list[SubnetId]


class VpcConfig(TypedDict, total=False):
    SubnetIds: SubnetIds | None
    SecurityGroupIds: SecurityGroupIds | None
    Ipv6AllowedForDualStack: NullableBoolean | None


class FunctionCode(TypedDict, total=False):
    ZipFile: Blob | None
    S3Bucket: S3Bucket | None
    S3Key: S3Key | None
    S3ObjectVersion: S3ObjectVersion | None
    ImageUri: String | None
    SourceKMSKeyArn: KMSKeyArn | None


class CreateFunctionRequest(ServiceRequest):
    FunctionName: FunctionName
    Runtime: Runtime | None
    Role: RoleArn
    Handler: Handler | None
    Code: FunctionCode
    Description: Description | None
    Timeout: Timeout | None
    MemorySize: MemorySize | None
    Publish: Boolean | None
    VpcConfig: VpcConfig | None
    PackageType: PackageType | None
    DeadLetterConfig: DeadLetterConfig | None
    Environment: Environment | None
    KMSKeyArn: KMSKeyArn | None
    TracingConfig: TracingConfig | None
    Tags: Tags | None
    Layers: LayerList | None
    FileSystemConfigs: FileSystemConfigList | None
    ImageConfig: ImageConfig | None
    CodeSigningConfigArn: CodeSigningConfigArn | None
    Architectures: ArchitecturesList | None
    EphemeralStorage: EphemeralStorage | None
    SnapStart: SnapStart | None
    LoggingConfig: LoggingConfig | None
    CapacityProviderConfig: CapacityProviderConfig | None
    PublishTo: FunctionVersionLatestPublished | None
    DurableConfig: DurableConfig | None
    TenancyConfig: TenancyConfig | None


class CreateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: FunctionUrlQualifier | None
    AuthType: FunctionUrlAuthType
    Cors: Cors | None
    InvokeMode: InvokeMode | None


class CreateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Cors | None
    CreationTime: Timestamp
    InvokeMode: InvokeMode | None


class DeleteAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias


class DeleteCapacityProviderRequest(ServiceRequest):
    CapacityProviderName: CapacityProviderName


class DeleteCapacityProviderResponse(TypedDict, total=False):
    CapacityProvider: CapacityProvider


class DeleteCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn


class DeleteCodeSigningConfigResponse(TypedDict, total=False):
    pass


class DeleteEventSourceMappingRequest(ServiceRequest):
    UUID: String


class DeleteFunctionCodeSigningConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName


class DeleteFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName


class DeleteFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class DeleteFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class DeleteFunctionResponse(TypedDict, total=False):
    StatusCode: Integer | None


class DeleteFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: FunctionUrlQualifier | None


class DeleteLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class DeleteProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier


class Execution(TypedDict, total=False):
    DurableExecutionArn: DurableExecutionArn
    DurableExecutionName: DurableExecutionName
    FunctionArn: NameSpacedFunctionArn
    Status: ExecutionStatus
    StartTimestamp: ExecutionTimestamp
    EndTimestamp: ExecutionTimestamp | None


DurableExecutions = list[Execution]


class EnvironmentError(TypedDict, total=False):
    ErrorCode: String | None
    Message: SensitiveString | None


class EnvironmentResponse(TypedDict, total=False):
    Variables: EnvironmentVariables | None
    Error: EnvironmentError | None


class InvocationCompletedDetails(TypedDict, total=False):
    StartTimestamp: ExecutionTimestamp
    EndTimestamp: ExecutionTimestamp
    RequestId: String
    Error: EventError | None


class RetryDetails(TypedDict, total=False):
    CurrentAttempt: AttemptCount | None
    NextAttemptDelaySeconds: DurationSeconds | None


class StepFailedDetails(TypedDict, total=False):
    Error: EventError
    RetryDetails: RetryDetails


class StepSucceededDetails(TypedDict, total=False):
    Result: EventResult
    RetryDetails: RetryDetails


class StepStartedDetails(TypedDict, total=False):
    pass


class WaitCancelledDetails(TypedDict, total=False):
    Error: EventError | None


class WaitSucceededDetails(TypedDict, total=False):
    Duration: DurationSeconds | None


class WaitStartedDetails(TypedDict, total=False):
    Duration: DurationSeconds
    ScheduledEndTimestamp: ExecutionTimestamp


class ExecutionStoppedDetails(TypedDict, total=False):
    Error: EventError


class ExecutionTimedOutDetails(TypedDict, total=False):
    Error: EventError | None


class ExecutionFailedDetails(TypedDict, total=False):
    Error: EventError


class ExecutionSucceededDetails(TypedDict, total=False):
    Result: EventResult


class ExecutionStartedDetails(TypedDict, total=False):
    Input: EventInput
    ExecutionTimeout: DurationSeconds


class Event(TypedDict, total=False):
    EventType: EventType | None
    SubType: OperationSubType | None
    EventId: EventId | None
    Id: OperationId | None
    Name: OperationName | None
    EventTimestamp: ExecutionTimestamp | None
    ParentId: OperationId | None
    ExecutionStartedDetails: ExecutionStartedDetails | None
    ExecutionSucceededDetails: ExecutionSucceededDetails | None
    ExecutionFailedDetails: ExecutionFailedDetails | None
    ExecutionTimedOutDetails: ExecutionTimedOutDetails | None
    ExecutionStoppedDetails: ExecutionStoppedDetails | None
    ContextStartedDetails: ContextStartedDetails | None
    ContextSucceededDetails: ContextSucceededDetails | None
    ContextFailedDetails: ContextFailedDetails | None
    WaitStartedDetails: WaitStartedDetails | None
    WaitSucceededDetails: WaitSucceededDetails | None
    WaitCancelledDetails: WaitCancelledDetails | None
    StepStartedDetails: StepStartedDetails | None
    StepSucceededDetails: StepSucceededDetails | None
    StepFailedDetails: StepFailedDetails | None
    ChainedInvokeStartedDetails: ChainedInvokeStartedDetails | None
    ChainedInvokeSucceededDetails: ChainedInvokeSucceededDetails | None
    ChainedInvokeFailedDetails: ChainedInvokeFailedDetails | None
    ChainedInvokeTimedOutDetails: ChainedInvokeTimedOutDetails | None
    ChainedInvokeStoppedDetails: ChainedInvokeStoppedDetails | None
    CallbackStartedDetails: CallbackStartedDetails | None
    CallbackSucceededDetails: CallbackSucceededDetails | None
    CallbackFailedDetails: CallbackFailedDetails | None
    CallbackTimedOutDetails: CallbackTimedOutDetails | None
    InvocationCompletedDetails: InvocationCompletedDetails | None


class FilterCriteriaError(TypedDict, total=False):
    ErrorCode: FilterCriteriaErrorCode | None
    Message: FilterCriteriaErrorMessage | None


class EventSourceMappingConfiguration(TypedDict, total=False):
    UUID: String | None
    StartingPosition: EventSourcePosition | None
    StartingPositionTimestamp: Date | None
    BatchSize: BatchSize | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    ParallelizationFactor: ParallelizationFactor | None
    EventSourceArn: Arn | None
    FilterCriteria: FilterCriteria | None
    FunctionArn: FunctionArn | None
    LastModified: Date | None
    LastProcessingResult: String | None
    State: String | None
    StateTransitionReason: String | None
    DestinationConfig: DestinationConfig | None
    Topics: Topics | None
    Queues: Queues | None
    SourceAccessConfigurations: SourceAccessConfigurations | None
    SelfManagedEventSource: SelfManagedEventSource | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    BisectBatchOnFunctionError: BisectBatchOnFunctionError | None
    MaximumRetryAttempts: MaximumRetryAttemptsEventSourceMapping | None
    TumblingWindowInSeconds: TumblingWindowInSeconds | None
    FunctionResponseTypes: FunctionResponseTypeList | None
    AmazonManagedKafkaEventSourceConfig: AmazonManagedKafkaEventSourceConfig | None
    SelfManagedKafkaEventSourceConfig: SelfManagedKafkaEventSourceConfig | None
    ScalingConfig: ScalingConfig | None
    DocumentDBEventSourceConfig: DocumentDBEventSourceConfig | None
    KMSKeyArn: KMSKeyArn | None
    FilterCriteriaError: FilterCriteriaError | None
    EventSourceMappingArn: EventSourceMappingArn | None
    MetricsConfig: EventSourceMappingMetricsConfig | None
    ProvisionedPollerConfig: ProvisionedPollerConfig | None


EventSourceMappingsList = list[EventSourceMappingConfiguration]
Events = list[Event]
ExecutionStatusList = list[ExecutionStatus]
FunctionArnList = list[FunctionArn]


class FunctionCodeLocation(TypedDict, total=False):
    RepositoryType: String | None
    Location: String | None
    ImageUri: String | None
    ResolvedImageUri: String | None
    SourceKMSKeyArn: String | None


class RuntimeVersionError(TypedDict, total=False):
    ErrorCode: String | None
    Message: SensitiveString | None


class RuntimeVersionConfig(TypedDict, total=False):
    RuntimeVersionArn: RuntimeVersionArn | None
    Error: RuntimeVersionError | None


class SnapStartResponse(TypedDict, total=False):
    ApplyOn: SnapStartApplyOn | None
    OptimizationStatus: SnapStartOptimizationStatus | None


class ImageConfigError(TypedDict, total=False):
    ErrorCode: String | None
    Message: SensitiveString | None


class ImageConfigResponse(TypedDict, total=False):
    ImageConfig: ImageConfig | None
    Error: ImageConfigError | None


class Layer(TypedDict, total=False):
    Arn: LayerVersionArn | None
    CodeSize: Long | None
    SigningProfileVersionArn: Arn | None
    SigningJobArn: Arn | None


LayersReferenceList = list[Layer]


class TracingConfigResponse(TypedDict, total=False):
    Mode: TracingMode | None


class VpcConfigResponse(TypedDict, total=False):
    SubnetIds: SubnetIds | None
    SecurityGroupIds: SecurityGroupIds | None
    VpcId: VpcId | None
    Ipv6AllowedForDualStack: NullableBoolean | None


class FunctionConfiguration(TypedDict, total=False):
    FunctionName: NamespacedFunctionName | None
    FunctionArn: NameSpacedFunctionArn | None
    Runtime: Runtime | None
    Role: RoleArn | None
    Handler: Handler | None
    CodeSize: Long | None
    Description: Description | None
    Timeout: Timeout | None
    MemorySize: MemorySize | None
    LastModified: Timestamp | None
    CodeSha256: String | None
    Version: Version | None
    VpcConfig: VpcConfigResponse | None
    DeadLetterConfig: DeadLetterConfig | None
    Environment: EnvironmentResponse | None
    KMSKeyArn: KMSKeyArn | None
    TracingConfig: TracingConfigResponse | None
    MasterArn: FunctionArn | None
    RevisionId: String | None
    Layers: LayersReferenceList | None
    State: State | None
    StateReason: StateReason | None
    StateReasonCode: StateReasonCode | None
    LastUpdateStatus: LastUpdateStatus | None
    LastUpdateStatusReason: LastUpdateStatusReason | None
    LastUpdateStatusReasonCode: LastUpdateStatusReasonCode | None
    FileSystemConfigs: FileSystemConfigList | None
    PackageType: PackageType | None
    ImageConfigResponse: ImageConfigResponse | None
    SigningProfileVersionArn: Arn | None
    SigningJobArn: Arn | None
    Architectures: ArchitecturesList | None
    EphemeralStorage: EphemeralStorage | None
    SnapStart: SnapStartResponse | None
    RuntimeVersionConfig: RuntimeVersionConfig | None
    LoggingConfig: LoggingConfig | None
    CapacityProviderConfig: CapacityProviderConfig | None
    ConfigSha256: String | None
    DurableConfig: DurableConfig | None
    TenancyConfig: TenancyConfig | None


class FunctionEventInvokeConfig(TypedDict, total=False):
    LastModified: Date | None
    FunctionArn: FunctionArn | None
    MaximumRetryAttempts: MaximumRetryAttempts | None
    MaximumEventAgeInSeconds: MaximumEventAgeInSeconds | None
    DestinationConfig: DestinationConfig | None


FunctionEventInvokeConfigList = list[FunctionEventInvokeConfig]
FunctionList = list[FunctionConfiguration]


class FunctionScalingConfig(TypedDict, total=False):
    MinExecutionEnvironments: FunctionScalingConfigExecutionEnvironments | None
    MaxExecutionEnvironments: FunctionScalingConfigExecutionEnvironments | None


class FunctionUrlConfig(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    Cors: Cors | None
    AuthType: FunctionUrlAuthType
    InvokeMode: InvokeMode | None


FunctionUrlConfigList = list[FunctionUrlConfig]


class FunctionVersionsByCapacityProviderListItem(TypedDict, total=False):
    FunctionArn: NameSpacedFunctionArn
    State: State


FunctionVersionsByCapacityProviderList = list[FunctionVersionsByCapacityProviderListItem]


class GetAccountSettingsRequest(ServiceRequest):
    pass


class GetAccountSettingsResponse(TypedDict, total=False):
    AccountLimit: AccountLimit | None
    AccountUsage: AccountUsage | None


class GetAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias


class GetCapacityProviderRequest(ServiceRequest):
    CapacityProviderName: CapacityProviderName


class GetCapacityProviderResponse(TypedDict, total=False):
    CapacityProvider: CapacityProvider


class GetCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn


class GetCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


class GetDurableExecutionHistoryRequest(ServiceRequest):
    DurableExecutionArn: DurableExecutionArn
    IncludeExecutionData: IncludeExecutionData | None
    MaxItems: ItemCount | None
    Marker: String | None
    ReverseOrder: ReverseOrder | None


class GetDurableExecutionHistoryResponse(TypedDict, total=False):
    Events: Events
    NextMarker: String | None


class GetDurableExecutionRequest(ServiceRequest):
    DurableExecutionArn: DurableExecutionArn


class TraceHeader(TypedDict, total=False):
    XAmznTraceId: XAmznTraceId | None


class GetDurableExecutionResponse(TypedDict, total=False):
    DurableExecutionArn: DurableExecutionArn
    DurableExecutionName: DurableExecutionName
    FunctionArn: NameSpacedFunctionArn
    InputPayload: InputPayload | None
    Result: OutputPayload | None
    Error: ErrorObject | None
    StartTimestamp: ExecutionTimestamp
    Status: ExecutionStatus
    EndTimestamp: ExecutionTimestamp | None
    Version: VersionWithLatestPublished | None
    TraceHeader: TraceHeader | None


class GetDurableExecutionStateRequest(ServiceRequest):
    DurableExecutionArn: DurableExecutionArn
    CheckpointToken: CheckpointToken
    Marker: String | None
    MaxItems: ItemCount | None


class GetDurableExecutionStateResponse(TypedDict, total=False):
    Operations: Operations
    NextMarker: String | None


class GetEventSourceMappingRequest(ServiceRequest):
    UUID: String


class GetFunctionCodeSigningConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName


class GetFunctionCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: FunctionName


class GetFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName


class GetFunctionConcurrencyResponse(TypedDict, total=False):
    ReservedConcurrentExecutions: ReservedConcurrentExecutions | None


class GetFunctionConfigurationRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class GetFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class GetFunctionRecursionConfigRequest(ServiceRequest):
    FunctionName: UnqualifiedFunctionName


class GetFunctionRecursionConfigResponse(TypedDict, total=False):
    RecursiveLoop: RecursiveLoop | None


class GetFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class TagsError(TypedDict, total=False):
    ErrorCode: TagsErrorCode
    Message: TagsErrorMessage


class GetFunctionResponse(TypedDict, total=False):
    Configuration: FunctionConfiguration | None
    Code: FunctionCodeLocation | None
    Tags: Tags | None
    TagsError: TagsError | None
    Concurrency: Concurrency | None


class GetFunctionScalingConfigRequest(ServiceRequest):
    FunctionName: UnqualifiedFunctionName
    Qualifier: PublishedFunctionQualifier


class GetFunctionScalingConfigResponse(TypedDict, total=False):
    FunctionArn: FunctionArn | None
    AppliedFunctionScalingConfig: FunctionScalingConfig | None
    RequestedFunctionScalingConfig: FunctionScalingConfig | None


class GetFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: FunctionUrlQualifier | None


class GetFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Cors | None
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    InvokeMode: InvokeMode | None


class GetLayerVersionByArnRequest(ServiceRequest):
    Arn: LayerVersionArn


class GetLayerVersionPolicyRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class GetLayerVersionPolicyResponse(TypedDict, total=False):
    Policy: String | None
    RevisionId: String | None


class GetLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class LayerVersionContentOutput(TypedDict, total=False):
    Location: String | None
    CodeSha256: String | None
    CodeSize: Long | None
    SigningProfileVersionArn: String | None
    SigningJobArn: String | None


class GetLayerVersionResponse(TypedDict, total=False):
    Content: LayerVersionContentOutput | None
    LayerArn: LayerArn | None
    LayerVersionArn: LayerVersionArn | None
    Description: Description | None
    CreatedDate: Timestamp | None
    Version: LayerVersionNumber | None
    CompatibleRuntimes: CompatibleRuntimes | None
    LicenseInfo: LicenseInfo | None
    CompatibleArchitectures: CompatibleArchitectures | None


class GetPolicyRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class GetPolicyResponse(TypedDict, total=False):
    Policy: String | None
    RevisionId: String | None


class GetProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier


class GetProvisionedConcurrencyConfigResponse(TypedDict, total=False):
    RequestedProvisionedConcurrentExecutions: PositiveInteger | None
    AvailableProvisionedConcurrentExecutions: NonNegativeInteger | None
    AllocatedProvisionedConcurrentExecutions: NonNegativeInteger | None
    Status: ProvisionedConcurrencyStatusEnum | None
    StatusReason: String | None
    LastModified: Timestamp | None


class GetRuntimeManagementConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None


class GetRuntimeManagementConfigResponse(TypedDict, total=False):
    UpdateRuntimeOn: UpdateRuntimeOn | None
    RuntimeVersionArn: RuntimeVersionArn | None
    FunctionArn: NameSpacedFunctionArn | None


class InvocationRequest(ServiceRequest):
    Payload: IO[Blob] | None
    FunctionName: NamespacedFunctionName
    InvocationType: InvocationType | None
    LogType: LogType | None
    ClientContext: String | None
    DurableExecutionName: DurableExecutionName | None
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    TenantId: TenantId | None


class InvocationResponse(TypedDict, total=False):
    Payload: Blob | IO[Blob] | Iterable[Blob] | None
    StatusCode: Integer | None
    FunctionError: String | None
    LogResult: String | None
    ExecutedVersion: Version | None
    DurableExecutionArn: DurableExecutionArn | None


class InvokeAsyncRequest(ServiceRequest):
    InvokeArgs: IO[BlobStream]
    FunctionName: NamespacedFunctionName


class InvokeAsyncResponse(TypedDict, total=False):
    Status: HttpStatus | None


class InvokeResponseStreamUpdate(TypedDict, total=False):
    Payload: Blob | None


class InvokeWithResponseStreamCompleteEvent(TypedDict, total=False):
    ErrorCode: String | None
    ErrorDetails: String | None
    LogResult: String | None


class InvokeWithResponseStreamRequest(ServiceRequest):
    Payload: IO[Blob] | None
    FunctionName: NamespacedFunctionName
    InvocationType: ResponseStreamingInvocationType | None
    LogType: LogType | None
    ClientContext: String | None
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    TenantId: TenantId | None


class InvokeWithResponseStreamResponseEvent(TypedDict, total=False):
    PayloadChunk: InvokeResponseStreamUpdate | None
    InvokeComplete: InvokeWithResponseStreamCompleteEvent | None


class InvokeWithResponseStreamResponse(TypedDict, total=False):
    StatusCode: Integer | None
    ExecutedVersion: Version | None
    EventStream: Iterator[InvokeWithResponseStreamResponseEvent]
    ResponseStreamContentType: String | None


class LayerVersionContentInput(TypedDict, total=False):
    S3Bucket: S3Bucket | None
    S3Key: S3Key | None
    S3ObjectVersion: S3ObjectVersion | None
    ZipFile: Blob | None


class LayerVersionsListItem(TypedDict, total=False):
    LayerVersionArn: LayerVersionArn | None
    Version: LayerVersionNumber | None
    Description: Description | None
    CreatedDate: Timestamp | None
    CompatibleRuntimes: CompatibleRuntimes | None
    LicenseInfo: LicenseInfo | None
    CompatibleArchitectures: CompatibleArchitectures | None


LayerVersionsList = list[LayerVersionsListItem]


class LayersListItem(TypedDict, total=False):
    LayerName: LayerName | None
    LayerArn: LayerArn | None
    LatestMatchingVersion: LayerVersionsListItem | None


LayersList = list[LayersListItem]


class ListAliasesRequest(ServiceRequest):
    FunctionName: FunctionName
    FunctionVersion: VersionWithLatestPublished | None
    Marker: String | None
    MaxItems: MaxListItems | None


class ListAliasesResponse(TypedDict, total=False):
    NextMarker: String | None
    Aliases: AliasList | None


class ListCapacityProvidersRequest(ServiceRequest):
    State: CapacityProviderState | None
    Marker: String | None
    MaxItems: MaxFiftyListItems | None


class ListCapacityProvidersResponse(TypedDict, total=False):
    CapacityProviders: CapacityProvidersList
    NextMarker: String | None


class ListCodeSigningConfigsRequest(ServiceRequest):
    Marker: String | None
    MaxItems: MaxListItems | None


class ListCodeSigningConfigsResponse(TypedDict, total=False):
    NextMarker: String | None
    CodeSigningConfigs: CodeSigningConfigList | None


class ListDurableExecutionsByFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    DurableExecutionName: DurableExecutionName | None
    Statuses: ExecutionStatusList | None
    StartedAfter: ExecutionTimestamp | None
    StartedBefore: ExecutionTimestamp | None
    ReverseOrder: ReverseOrder | None
    Marker: String | None
    MaxItems: ItemCount | None


class ListDurableExecutionsByFunctionResponse(TypedDict, total=False):
    DurableExecutions: DurableExecutions | None
    NextMarker: String | None


class ListEventSourceMappingsRequest(ServiceRequest):
    EventSourceArn: Arn | None
    FunctionName: NamespacedFunctionName | None
    Marker: String | None
    MaxItems: MaxListItems | None


class ListEventSourceMappingsResponse(TypedDict, total=False):
    NextMarker: String | None
    EventSourceMappings: EventSourceMappingsList | None


class ListFunctionEventInvokeConfigsRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Marker: String | None
    MaxItems: MaxFunctionEventInvokeConfigListItems | None


class ListFunctionEventInvokeConfigsResponse(TypedDict, total=False):
    FunctionEventInvokeConfigs: FunctionEventInvokeConfigList | None
    NextMarker: String | None


class ListFunctionUrlConfigsRequest(ServiceRequest):
    FunctionName: FunctionName
    Marker: String | None
    MaxItems: MaxItems | None


class ListFunctionUrlConfigsResponse(TypedDict, total=False):
    FunctionUrlConfigs: FunctionUrlConfigList
    NextMarker: String | None


class ListFunctionVersionsByCapacityProviderRequest(ServiceRequest):
    CapacityProviderName: CapacityProviderName
    Marker: String | None
    MaxItems: MaxFiftyListItems | None


class ListFunctionVersionsByCapacityProviderResponse(TypedDict, total=False):
    CapacityProviderArn: CapacityProviderArn
    FunctionVersions: FunctionVersionsByCapacityProviderList
    NextMarker: String | None


class ListFunctionsByCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    Marker: String | None
    MaxItems: MaxListItems | None


class ListFunctionsByCodeSigningConfigResponse(TypedDict, total=False):
    NextMarker: String | None
    FunctionArns: FunctionArnList | None


class ListFunctionsRequest(ServiceRequest):
    MasterRegion: MasterRegion | None
    FunctionVersion: FunctionVersion | None
    Marker: String | None
    MaxItems: MaxListItems | None


class ListFunctionsResponse(TypedDict, total=False):
    NextMarker: String | None
    Functions: FunctionList | None


class ListLayerVersionsRequest(ServiceRequest):
    CompatibleRuntime: Runtime | None
    LayerName: LayerName
    Marker: String | None
    MaxItems: MaxLayerListItems | None
    CompatibleArchitecture: Architecture | None


class ListLayerVersionsResponse(TypedDict, total=False):
    NextMarker: String | None
    LayerVersions: LayerVersionsList | None


class ListLayersRequest(ServiceRequest):
    CompatibleRuntime: Runtime | None
    Marker: String | None
    MaxItems: MaxLayerListItems | None
    CompatibleArchitecture: Architecture | None


class ListLayersResponse(TypedDict, total=False):
    NextMarker: String | None
    Layers: LayersList | None


class ListProvisionedConcurrencyConfigsRequest(ServiceRequest):
    FunctionName: FunctionName
    Marker: String | None
    MaxItems: MaxProvisionedConcurrencyConfigListItems | None


class ProvisionedConcurrencyConfigListItem(TypedDict, total=False):
    FunctionArn: FunctionArn | None
    RequestedProvisionedConcurrentExecutions: PositiveInteger | None
    AvailableProvisionedConcurrentExecutions: NonNegativeInteger | None
    AllocatedProvisionedConcurrentExecutions: NonNegativeInteger | None
    Status: ProvisionedConcurrencyStatusEnum | None
    StatusReason: String | None
    LastModified: Timestamp | None


ProvisionedConcurrencyConfigList = list[ProvisionedConcurrencyConfigListItem]


class ListProvisionedConcurrencyConfigsResponse(TypedDict, total=False):
    ProvisionedConcurrencyConfigs: ProvisionedConcurrencyConfigList | None
    NextMarker: String | None


class ListTagsRequest(ServiceRequest):
    Resource: TaggableResource


class ListTagsResponse(TypedDict, total=False):
    Tags: Tags | None


class ListVersionsByFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Marker: String | None
    MaxItems: MaxListItems | None


class ListVersionsByFunctionResponse(TypedDict, total=False):
    NextMarker: String | None
    Versions: FunctionList | None


class PublishLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    Description: Description | None
    Content: LayerVersionContentInput
    CompatibleRuntimes: CompatibleRuntimes | None
    LicenseInfo: LicenseInfo | None
    CompatibleArchitectures: CompatibleArchitectures | None


class PublishLayerVersionResponse(TypedDict, total=False):
    Content: LayerVersionContentOutput | None
    LayerArn: LayerArn | None
    LayerVersionArn: LayerVersionArn | None
    Description: Description | None
    CreatedDate: Timestamp | None
    Version: LayerVersionNumber | None
    CompatibleRuntimes: CompatibleRuntimes | None
    LicenseInfo: LicenseInfo | None
    CompatibleArchitectures: CompatibleArchitectures | None


class PublishVersionRequest(ServiceRequest):
    FunctionName: FunctionName
    CodeSha256: String | None
    Description: Description | None
    RevisionId: String | None
    PublishTo: FunctionVersionLatestPublished | None


class PutFunctionCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: NamespacedFunctionName


class PutFunctionCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: FunctionName


class PutFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName
    ReservedConcurrentExecutions: ReservedConcurrentExecutions


class PutFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    MaximumRetryAttempts: MaximumRetryAttempts | None
    MaximumEventAgeInSeconds: MaximumEventAgeInSeconds | None
    DestinationConfig: DestinationConfig | None


class PutFunctionRecursionConfigRequest(ServiceRequest):
    FunctionName: UnqualifiedFunctionName
    RecursiveLoop: RecursiveLoop


class PutFunctionRecursionConfigResponse(TypedDict, total=False):
    RecursiveLoop: RecursiveLoop | None


class PutFunctionScalingConfigRequest(ServiceRequest):
    FunctionName: UnqualifiedFunctionName
    Qualifier: PublishedFunctionQualifier
    FunctionScalingConfig: FunctionScalingConfig | None


class PutFunctionScalingConfigResponse(TypedDict, total=False):
    FunctionState: State | None


class PutProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier
    ProvisionedConcurrentExecutions: PositiveInteger


class PutProvisionedConcurrencyConfigResponse(TypedDict, total=False):
    RequestedProvisionedConcurrentExecutions: PositiveInteger | None
    AvailableProvisionedConcurrentExecutions: NonNegativeInteger | None
    AllocatedProvisionedConcurrentExecutions: NonNegativeInteger | None
    Status: ProvisionedConcurrencyStatusEnum | None
    StatusReason: String | None
    LastModified: Timestamp | None


class PutRuntimeManagementConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    UpdateRuntimeOn: UpdateRuntimeOn
    RuntimeVersionArn: RuntimeVersionArn | None


class PutRuntimeManagementConfigResponse(TypedDict, total=False):
    UpdateRuntimeOn: UpdateRuntimeOn
    FunctionArn: FunctionArn
    RuntimeVersionArn: RuntimeVersionArn | None


class RemoveLayerVersionPermissionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber
    StatementId: StatementId
    RevisionId: String | None


class RemovePermissionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    StatementId: NamespacedStatementId
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    RevisionId: String | None


class SendDurableExecutionCallbackFailureRequest(ServiceRequest):
    CallbackId: CallbackId
    Error: ErrorObject | None


class SendDurableExecutionCallbackFailureResponse(TypedDict, total=False):
    pass


class SendDurableExecutionCallbackHeartbeatRequest(ServiceRequest):
    CallbackId: CallbackId


class SendDurableExecutionCallbackHeartbeatResponse(TypedDict, total=False):
    pass


class SendDurableExecutionCallbackSuccessRequest(ServiceRequest):
    Result: IO[BinaryOperationPayload] | None
    CallbackId: CallbackId


class SendDurableExecutionCallbackSuccessResponse(TypedDict, total=False):
    pass


class StopDurableExecutionRequest(ServiceRequest):
    DurableExecutionArn: DurableExecutionArn
    Error: ErrorObject | None


class StopDurableExecutionResponse(TypedDict, total=False):
    StopTimestamp: ExecutionTimestamp


TagKeyList = list[TagKey]


class TagResourceRequest(ServiceRequest):
    Resource: TaggableResource
    Tags: Tags


class UntagResourceRequest(ServiceRequest):
    Resource: TaggableResource
    TagKeys: TagKeyList


class UpdateAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias
    FunctionVersion: VersionWithLatestPublished | None
    Description: Description | None
    RoutingConfig: AliasRoutingConfiguration | None
    RevisionId: String | None


class UpdateCapacityProviderRequest(ServiceRequest):
    CapacityProviderName: CapacityProviderName
    CapacityProviderScalingConfig: CapacityProviderScalingConfig | None


class UpdateCapacityProviderResponse(TypedDict, total=False):
    CapacityProvider: CapacityProvider


class UpdateCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    Description: Description | None
    AllowedPublishers: AllowedPublishers | None
    CodeSigningPolicies: CodeSigningPolicies | None


class UpdateCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


class UpdateEventSourceMappingRequest(ServiceRequest):
    UUID: String
    FunctionName: NamespacedFunctionName | None
    Enabled: Enabled | None
    BatchSize: BatchSize | None
    FilterCriteria: FilterCriteria | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    DestinationConfig: DestinationConfig | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    BisectBatchOnFunctionError: BisectBatchOnFunctionError | None
    MaximumRetryAttempts: MaximumRetryAttemptsEventSourceMapping | None
    ParallelizationFactor: ParallelizationFactor | None
    SourceAccessConfigurations: SourceAccessConfigurations | None
    TumblingWindowInSeconds: TumblingWindowInSeconds | None
    FunctionResponseTypes: FunctionResponseTypeList | None
    ScalingConfig: ScalingConfig | None
    AmazonManagedKafkaEventSourceConfig: AmazonManagedKafkaEventSourceConfig | None
    SelfManagedKafkaEventSourceConfig: SelfManagedKafkaEventSourceConfig | None
    DocumentDBEventSourceConfig: DocumentDBEventSourceConfig | None
    KMSKeyArn: KMSKeyArn | None
    MetricsConfig: EventSourceMappingMetricsConfig | None
    ProvisionedPollerConfig: ProvisionedPollerConfig | None


class UpdateFunctionCodeRequest(ServiceRequest):
    FunctionName: FunctionName
    ZipFile: Blob | None
    S3Bucket: S3Bucket | None
    S3Key: S3Key | None
    S3ObjectVersion: S3ObjectVersion | None
    ImageUri: String | None
    Publish: Boolean | None
    DryRun: Boolean | None
    RevisionId: String | None
    Architectures: ArchitecturesList | None
    SourceKMSKeyArn: KMSKeyArn | None
    PublishTo: FunctionVersionLatestPublished | None


class UpdateFunctionConfigurationRequest(ServiceRequest):
    FunctionName: FunctionName
    Role: RoleArn | None
    Handler: Handler | None
    Description: Description | None
    Timeout: Timeout | None
    MemorySize: MemorySize | None
    VpcConfig: VpcConfig | None
    Environment: Environment | None
    Runtime: Runtime | None
    DeadLetterConfig: DeadLetterConfig | None
    KMSKeyArn: KMSKeyArn | None
    TracingConfig: TracingConfig | None
    RevisionId: String | None
    Layers: LayerList | None
    FileSystemConfigs: FileSystemConfigList | None
    ImageConfig: ImageConfig | None
    EphemeralStorage: EphemeralStorage | None
    SnapStart: SnapStart | None
    LoggingConfig: LoggingConfig | None
    CapacityProviderConfig: CapacityProviderConfig | None
    DurableConfig: DurableConfig | None


class UpdateFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: NumericLatestPublishedOrAliasQualifier | None
    MaximumRetryAttempts: MaximumRetryAttempts | None
    MaximumEventAgeInSeconds: MaximumEventAgeInSeconds | None
    DestinationConfig: DestinationConfig | None


class UpdateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: FunctionUrlQualifier | None
    AuthType: FunctionUrlAuthType | None
    Cors: Cors | None
    InvokeMode: InvokeMode | None


class UpdateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Cors | None
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    InvokeMode: InvokeMode | None


class LambdaApi:
    service: str = "lambda"
    version: str = "2015-03-31"

    @handler("AddLayerVersionPermission")
    def add_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        action: LayerPermissionAllowedAction,
        principal: LayerPermissionAllowedPrincipal,
        organization_id: OrganizationId | None = None,
        revision_id: String | None = None,
        **kwargs,
    ) -> AddLayerVersionPermissionResponse:
        raise NotImplementedError

    @handler("AddPermission")
    def add_permission(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        statement_id: StatementId,
        action: Action,
        principal: Principal,
        source_arn: Arn | None = None,
        source_account: SourceOwner | None = None,
        event_source_token: EventSourceToken | None = None,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        revision_id: String | None = None,
        principal_org_id: PrincipalOrgID | None = None,
        function_url_auth_type: FunctionUrlAuthType | None = None,
        invoked_via_function_url: InvokedViaFunctionUrl | None = None,
        **kwargs,
    ) -> AddPermissionResponse:
        raise NotImplementedError

    @handler("CheckpointDurableExecution")
    def checkpoint_durable_execution(
        self,
        context: RequestContext,
        durable_execution_arn: DurableExecutionArn,
        checkpoint_token: CheckpointToken,
        updates: OperationUpdates | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> CheckpointDurableExecutionResponse:
        raise NotImplementedError

    @handler("CreateAlias")
    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: VersionWithLatestPublished,
        description: Description | None = None,
        routing_config: AliasRoutingConfiguration | None = None,
        **kwargs,
    ) -> AliasConfiguration:
        raise NotImplementedError

    @handler("CreateCapacityProvider")
    def create_capacity_provider(
        self,
        context: RequestContext,
        capacity_provider_name: CapacityProviderName,
        vpc_config: CapacityProviderVpcConfig,
        permissions_config: CapacityProviderPermissionsConfig,
        instance_requirements: InstanceRequirements | None = None,
        capacity_provider_scaling_config: CapacityProviderScalingConfig | None = None,
        kms_key_arn: KMSKeyArnNonEmpty | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateCapacityProviderResponse:
        raise NotImplementedError

    @handler("CreateCodeSigningConfig")
    def create_code_signing_config(
        self,
        context: RequestContext,
        allowed_publishers: AllowedPublishers,
        description: Description | None = None,
        code_signing_policies: CodeSigningPolicies | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("CreateEventSourceMapping")
    def create_event_source_mapping(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        event_source_arn: Arn | None = None,
        enabled: Enabled | None = None,
        batch_size: BatchSize | None = None,
        filter_criteria: FilterCriteria | None = None,
        maximum_batching_window_in_seconds: MaximumBatchingWindowInSeconds | None = None,
        parallelization_factor: ParallelizationFactor | None = None,
        starting_position: EventSourcePosition | None = None,
        starting_position_timestamp: Date | None = None,
        destination_config: DestinationConfig | None = None,
        maximum_record_age_in_seconds: MaximumRecordAgeInSeconds | None = None,
        bisect_batch_on_function_error: BisectBatchOnFunctionError | None = None,
        maximum_retry_attempts: MaximumRetryAttemptsEventSourceMapping | None = None,
        tags: Tags | None = None,
        tumbling_window_in_seconds: TumblingWindowInSeconds | None = None,
        topics: Topics | None = None,
        queues: Queues | None = None,
        source_access_configurations: SourceAccessConfigurations | None = None,
        self_managed_event_source: SelfManagedEventSource | None = None,
        function_response_types: FunctionResponseTypeList | None = None,
        amazon_managed_kafka_event_source_config: AmazonManagedKafkaEventSourceConfig | None = None,
        self_managed_kafka_event_source_config: SelfManagedKafkaEventSourceConfig | None = None,
        scaling_config: ScalingConfig | None = None,
        document_db_event_source_config: DocumentDBEventSourceConfig | None = None,
        kms_key_arn: KMSKeyArn | None = None,
        metrics_config: EventSourceMappingMetricsConfig | None = None,
        provisioned_poller_config: ProvisionedPollerConfig | None = None,
        **kwargs,
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("CreateFunction")
    def create_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn,
        code: FunctionCode,
        runtime: Runtime | None = None,
        handler: Handler | None = None,
        description: Description | None = None,
        timeout: Timeout | None = None,
        memory_size: MemorySize | None = None,
        publish: Boolean | None = None,
        vpc_config: VpcConfig | None = None,
        package_type: PackageType | None = None,
        dead_letter_config: DeadLetterConfig | None = None,
        environment: Environment | None = None,
        kms_key_arn: KMSKeyArn | None = None,
        tracing_config: TracingConfig | None = None,
        tags: Tags | None = None,
        layers: LayerList | None = None,
        file_system_configs: FileSystemConfigList | None = None,
        image_config: ImageConfig | None = None,
        code_signing_config_arn: CodeSigningConfigArn | None = None,
        architectures: ArchitecturesList | None = None,
        ephemeral_storage: EphemeralStorage | None = None,
        snap_start: SnapStart | None = None,
        logging_config: LoggingConfig | None = None,
        capacity_provider_config: CapacityProviderConfig | None = None,
        publish_to: FunctionVersionLatestPublished | None = None,
        durable_config: DurableConfig | None = None,
        tenancy_config: TenancyConfig | None = None,
        **kwargs,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("CreateFunctionUrlConfig")
    def create_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        auth_type: FunctionUrlAuthType,
        qualifier: FunctionUrlQualifier | None = None,
        cors: Cors | None = None,
        invoke_mode: InvokeMode | None = None,
        **kwargs,
    ) -> CreateFunctionUrlConfigResponse:
        raise NotImplementedError

    @handler("DeleteAlias")
    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCapacityProvider")
    def delete_capacity_provider(
        self, context: RequestContext, capacity_provider_name: CapacityProviderName, **kwargs
    ) -> DeleteCapacityProviderResponse:
        raise NotImplementedError

    @handler("DeleteCodeSigningConfig")
    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn, **kwargs
    ) -> DeleteCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("DeleteEventSourceMapping")
    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String, **kwargs
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> DeleteFunctionResponse:
        raise NotImplementedError

    @handler("DeleteFunctionCodeSigningConfig")
    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: NamespacedFunctionName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionConcurrency")
    def delete_function_concurrency(
        self, context: RequestContext, function_name: FunctionName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionEventInvokeConfig")
    def delete_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionUrlConfig")
    def delete_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLayerVersion")
    def delete_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteProvisionedConcurrencyConfig")
    def delete_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("GetAccountSettings")
    def get_account_settings(self, context: RequestContext, **kwargs) -> GetAccountSettingsResponse:
        raise NotImplementedError

    @handler("GetAlias")
    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias, **kwargs
    ) -> AliasConfiguration:
        raise NotImplementedError

    @handler("GetCapacityProvider")
    def get_capacity_provider(
        self, context: RequestContext, capacity_provider_name: CapacityProviderName, **kwargs
    ) -> GetCapacityProviderResponse:
        raise NotImplementedError

    @handler("GetCodeSigningConfig")
    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn, **kwargs
    ) -> GetCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("GetDurableExecution")
    def get_durable_execution(
        self, context: RequestContext, durable_execution_arn: DurableExecutionArn, **kwargs
    ) -> GetDurableExecutionResponse:
        raise NotImplementedError

    @handler("GetDurableExecutionHistory")
    def get_durable_execution_history(
        self,
        context: RequestContext,
        durable_execution_arn: DurableExecutionArn,
        include_execution_data: IncludeExecutionData | None = None,
        max_items: ItemCount | None = None,
        marker: String | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> GetDurableExecutionHistoryResponse:
        raise NotImplementedError

    @handler("GetDurableExecutionState")
    def get_durable_execution_state(
        self,
        context: RequestContext,
        durable_execution_arn: DurableExecutionArn,
        checkpoint_token: CheckpointToken,
        marker: String | None = None,
        max_items: ItemCount | None = None,
        **kwargs,
    ) -> GetDurableExecutionStateResponse:
        raise NotImplementedError

    @handler("GetEventSourceMapping")
    def get_event_source_mapping(
        self, context: RequestContext, uuid: String, **kwargs
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> GetFunctionResponse:
        raise NotImplementedError

    @handler("GetFunctionCodeSigningConfig")
    def get_function_code_signing_config(
        self, context: RequestContext, function_name: NamespacedFunctionName, **kwargs
    ) -> GetFunctionCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("GetFunctionConcurrency")
    def get_function_concurrency(
        self, context: RequestContext, function_name: FunctionName, **kwargs
    ) -> GetFunctionConcurrencyResponse:
        raise NotImplementedError

    @handler("GetFunctionConfiguration")
    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("GetFunctionEventInvokeConfig")
    def get_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("GetFunctionRecursionConfig")
    def get_function_recursion_config(
        self, context: RequestContext, function_name: UnqualifiedFunctionName, **kwargs
    ) -> GetFunctionRecursionConfigResponse:
        raise NotImplementedError

    @handler("GetFunctionScalingConfig")
    def get_function_scaling_config(
        self,
        context: RequestContext,
        function_name: UnqualifiedFunctionName,
        qualifier: PublishedFunctionQualifier,
        **kwargs,
    ) -> GetFunctionScalingConfigResponse:
        raise NotImplementedError

    @handler("GetFunctionUrlConfig")
    def get_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier | None = None,
        **kwargs,
    ) -> GetFunctionUrlConfigResponse:
        raise NotImplementedError

    @handler("GetLayerVersion")
    def get_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        **kwargs,
    ) -> GetLayerVersionResponse:
        raise NotImplementedError

    @handler("GetLayerVersionByArn")
    def get_layer_version_by_arn(
        self, context: RequestContext, arn: LayerVersionArn, **kwargs
    ) -> GetLayerVersionResponse:
        raise NotImplementedError

    @handler("GetLayerVersionPolicy")
    def get_layer_version_policy(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        **kwargs,
    ) -> GetLayerVersionPolicyResponse:
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> GetPolicyResponse:
        raise NotImplementedError

    @handler("GetProvisionedConcurrencyConfig")
    def get_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier, **kwargs
    ) -> GetProvisionedConcurrencyConfigResponse:
        raise NotImplementedError

    @handler("GetRuntimeManagementConfig")
    def get_runtime_management_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        **kwargs,
    ) -> GetRuntimeManagementConfigResponse:
        raise NotImplementedError

    @handler("Invoke")
    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType | None = None,
        log_type: LogType | None = None,
        client_context: String | None = None,
        durable_execution_name: DurableExecutionName | None = None,
        payload: IO[Blob] | None = None,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        tenant_id: TenantId | None = None,
        **kwargs,
    ) -> InvocationResponse:
        raise NotImplementedError

    @handler("InvokeAsync")
    def invoke_async(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invoke_args: IO[BlobStream],
        **kwargs,
    ) -> InvokeAsyncResponse:
        raise NotImplementedError

    @handler("InvokeWithResponseStream")
    def invoke_with_response_stream(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: ResponseStreamingInvocationType | None = None,
        log_type: LogType | None = None,
        client_context: String | None = None,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        payload: IO[Blob] | None = None,
        tenant_id: TenantId | None = None,
        **kwargs,
    ) -> InvokeWithResponseStreamResponse:
        raise NotImplementedError

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: VersionWithLatestPublished | None = None,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListAliasesResponse:
        raise NotImplementedError

    @handler("ListCapacityProviders")
    def list_capacity_providers(
        self,
        context: RequestContext,
        state: CapacityProviderState | None = None,
        marker: String | None = None,
        max_items: MaxFiftyListItems | None = None,
        **kwargs,
    ) -> ListCapacityProvidersResponse:
        raise NotImplementedError

    @handler("ListCodeSigningConfigs")
    def list_code_signing_configs(
        self,
        context: RequestContext,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListCodeSigningConfigsResponse:
        raise NotImplementedError

    @handler("ListDurableExecutionsByFunction")
    def list_durable_executions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        durable_execution_name: DurableExecutionName | None = None,
        statuses: ExecutionStatusList | None = None,
        started_after: ExecutionTimestamp | None = None,
        started_before: ExecutionTimestamp | None = None,
        reverse_order: ReverseOrder | None = None,
        marker: String | None = None,
        max_items: ItemCount | None = None,
        **kwargs,
    ) -> ListDurableExecutionsByFunctionResponse:
        raise NotImplementedError

    @handler("ListEventSourceMappings")
    def list_event_source_mappings(
        self,
        context: RequestContext,
        event_source_arn: Arn | None = None,
        function_name: NamespacedFunctionName | None = None,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListEventSourceMappingsResponse:
        raise NotImplementedError

    @handler("ListFunctionEventInvokeConfigs")
    def list_function_event_invoke_configs(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String | None = None,
        max_items: MaxFunctionEventInvokeConfigListItems | None = None,
        **kwargs,
    ) -> ListFunctionEventInvokeConfigsResponse:
        raise NotImplementedError

    @handler("ListFunctionUrlConfigs")
    def list_function_url_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String | None = None,
        max_items: MaxItems | None = None,
        **kwargs,
    ) -> ListFunctionUrlConfigsResponse:
        raise NotImplementedError

    @handler("ListFunctionVersionsByCapacityProvider")
    def list_function_versions_by_capacity_provider(
        self,
        context: RequestContext,
        capacity_provider_name: CapacityProviderName,
        marker: String | None = None,
        max_items: MaxFiftyListItems | None = None,
        **kwargs,
    ) -> ListFunctionVersionsByCapacityProviderResponse:
        raise NotImplementedError

    @handler("ListFunctions")
    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion | None = None,
        function_version: FunctionVersion | None = None,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListFunctionsResponse:
        raise NotImplementedError

    @handler("ListFunctionsByCodeSigningConfig")
    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("ListLayerVersions")
    def list_layer_versions(
        self,
        context: RequestContext,
        layer_name: LayerName,
        compatible_runtime: Runtime | None = None,
        marker: String | None = None,
        max_items: MaxLayerListItems | None = None,
        compatible_architecture: Architecture | None = None,
        **kwargs,
    ) -> ListLayerVersionsResponse:
        raise NotImplementedError

    @handler("ListLayers")
    def list_layers(
        self,
        context: RequestContext,
        compatible_runtime: Runtime | None = None,
        marker: String | None = None,
        max_items: MaxLayerListItems | None = None,
        compatible_architecture: Architecture | None = None,
        **kwargs,
    ) -> ListLayersResponse:
        raise NotImplementedError

    @handler("ListProvisionedConcurrencyConfigs")
    def list_provisioned_concurrency_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String | None = None,
        max_items: MaxProvisionedConcurrencyConfigListItems | None = None,
        **kwargs,
    ) -> ListProvisionedConcurrencyConfigsResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(
        self, context: RequestContext, resource: TaggableResource, **kwargs
    ) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListVersionsByFunction")
    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String | None = None,
        max_items: MaxListItems | None = None,
        **kwargs,
    ) -> ListVersionsByFunctionResponse:
        raise NotImplementedError

    @handler("PublishLayerVersion")
    def publish_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        content: LayerVersionContentInput,
        description: Description | None = None,
        compatible_runtimes: CompatibleRuntimes | None = None,
        license_info: LicenseInfo | None = None,
        compatible_architectures: CompatibleArchitectures | None = None,
        **kwargs,
    ) -> PublishLayerVersionResponse:
        raise NotImplementedError

    @handler("PublishVersion")
    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String | None = None,
        description: Description | None = None,
        revision_id: String | None = None,
        publish_to: FunctionVersionLatestPublished | None = None,
        **kwargs,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("PutFunctionCodeSigningConfig")
    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: NamespacedFunctionName,
        **kwargs,
    ) -> PutFunctionCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("PutFunctionConcurrency")
    def put_function_concurrency(
        self,
        context: RequestContext,
        function_name: FunctionName,
        reserved_concurrent_executions: ReservedConcurrentExecutions,
        **kwargs,
    ) -> Concurrency:
        raise NotImplementedError

    @handler("PutFunctionEventInvokeConfig")
    def put_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        maximum_retry_attempts: MaximumRetryAttempts | None = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds | None = None,
        destination_config: DestinationConfig | None = None,
        **kwargs,
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("PutFunctionRecursionConfig")
    def put_function_recursion_config(
        self,
        context: RequestContext,
        function_name: UnqualifiedFunctionName,
        recursive_loop: RecursiveLoop,
        **kwargs,
    ) -> PutFunctionRecursionConfigResponse:
        raise NotImplementedError

    @handler("PutFunctionScalingConfig")
    def put_function_scaling_config(
        self,
        context: RequestContext,
        function_name: UnqualifiedFunctionName,
        qualifier: PublishedFunctionQualifier,
        function_scaling_config: FunctionScalingConfig | None = None,
        **kwargs,
    ) -> PutFunctionScalingConfigResponse:
        raise NotImplementedError

    @handler("PutProvisionedConcurrencyConfig")
    def put_provisioned_concurrency_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier,
        provisioned_concurrent_executions: PositiveInteger,
        **kwargs,
    ) -> PutProvisionedConcurrencyConfigResponse:
        raise NotImplementedError

    @handler("PutRuntimeManagementConfig")
    def put_runtime_management_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        update_runtime_on: UpdateRuntimeOn,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        runtime_version_arn: RuntimeVersionArn | None = None,
        **kwargs,
    ) -> PutRuntimeManagementConfigResponse:
        raise NotImplementedError

    @handler("RemoveLayerVersionPermission")
    def remove_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        revision_id: String | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        statement_id: NamespacedStatementId,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        revision_id: String | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SendDurableExecutionCallbackFailure")
    def send_durable_execution_callback_failure(
        self,
        context: RequestContext,
        callback_id: CallbackId,
        error: ErrorObject | None = None,
        **kwargs,
    ) -> SendDurableExecutionCallbackFailureResponse:
        raise NotImplementedError

    @handler("SendDurableExecutionCallbackHeartbeat")
    def send_durable_execution_callback_heartbeat(
        self, context: RequestContext, callback_id: CallbackId, **kwargs
    ) -> SendDurableExecutionCallbackHeartbeatResponse:
        raise NotImplementedError

    @handler("SendDurableExecutionCallbackSuccess")
    def send_durable_execution_callback_success(
        self,
        context: RequestContext,
        callback_id: CallbackId,
        result: IO[BinaryOperationPayload] | None = None,
        **kwargs,
    ) -> SendDurableExecutionCallbackSuccessResponse:
        raise NotImplementedError

    @handler("StopDurableExecution")
    def stop_durable_execution(
        self,
        context: RequestContext,
        durable_execution_arn: DurableExecutionArn,
        error: ErrorObject | None = None,
        **kwargs,
    ) -> StopDurableExecutionResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource: TaggableResource, tags: Tags, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource: TaggableResource, tag_keys: TagKeyList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAlias")
    def update_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: VersionWithLatestPublished | None = None,
        description: Description | None = None,
        routing_config: AliasRoutingConfiguration | None = None,
        revision_id: String | None = None,
        **kwargs,
    ) -> AliasConfiguration:
        raise NotImplementedError

    @handler("UpdateCapacityProvider")
    def update_capacity_provider(
        self,
        context: RequestContext,
        capacity_provider_name: CapacityProviderName,
        capacity_provider_scaling_config: CapacityProviderScalingConfig | None = None,
        **kwargs,
    ) -> UpdateCapacityProviderResponse:
        raise NotImplementedError

    @handler("UpdateCodeSigningConfig")
    def update_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        description: Description | None = None,
        allowed_publishers: AllowedPublishers | None = None,
        code_signing_policies: CodeSigningPolicies | None = None,
        **kwargs,
    ) -> UpdateCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("UpdateEventSourceMapping")
    def update_event_source_mapping(
        self,
        context: RequestContext,
        uuid: String,
        function_name: NamespacedFunctionName | None = None,
        enabled: Enabled | None = None,
        batch_size: BatchSize | None = None,
        filter_criteria: FilterCriteria | None = None,
        maximum_batching_window_in_seconds: MaximumBatchingWindowInSeconds | None = None,
        destination_config: DestinationConfig | None = None,
        maximum_record_age_in_seconds: MaximumRecordAgeInSeconds | None = None,
        bisect_batch_on_function_error: BisectBatchOnFunctionError | None = None,
        maximum_retry_attempts: MaximumRetryAttemptsEventSourceMapping | None = None,
        parallelization_factor: ParallelizationFactor | None = None,
        source_access_configurations: SourceAccessConfigurations | None = None,
        tumbling_window_in_seconds: TumblingWindowInSeconds | None = None,
        function_response_types: FunctionResponseTypeList | None = None,
        scaling_config: ScalingConfig | None = None,
        amazon_managed_kafka_event_source_config: AmazonManagedKafkaEventSourceConfig | None = None,
        self_managed_kafka_event_source_config: SelfManagedKafkaEventSourceConfig | None = None,
        document_db_event_source_config: DocumentDBEventSourceConfig | None = None,
        kms_key_arn: KMSKeyArn | None = None,
        metrics_config: EventSourceMappingMetricsConfig | None = None,
        provisioned_poller_config: ProvisionedPollerConfig | None = None,
        **kwargs,
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("UpdateFunctionCode")
    def update_function_code(
        self,
        context: RequestContext,
        function_name: FunctionName,
        zip_file: Blob | None = None,
        s3_bucket: S3Bucket | None = None,
        s3_key: S3Key | None = None,
        s3_object_version: S3ObjectVersion | None = None,
        image_uri: String | None = None,
        publish: Boolean | None = None,
        dry_run: Boolean | None = None,
        revision_id: String | None = None,
        architectures: ArchitecturesList | None = None,
        source_kms_key_arn: KMSKeyArn | None = None,
        publish_to: FunctionVersionLatestPublished | None = None,
        **kwargs,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("UpdateFunctionConfiguration")
    def update_function_configuration(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn | None = None,
        handler: Handler | None = None,
        description: Description | None = None,
        timeout: Timeout | None = None,
        memory_size: MemorySize | None = None,
        vpc_config: VpcConfig | None = None,
        environment: Environment | None = None,
        runtime: Runtime | None = None,
        dead_letter_config: DeadLetterConfig | None = None,
        kms_key_arn: KMSKeyArn | None = None,
        tracing_config: TracingConfig | None = None,
        revision_id: String | None = None,
        layers: LayerList | None = None,
        file_system_configs: FileSystemConfigList | None = None,
        image_config: ImageConfig | None = None,
        ephemeral_storage: EphemeralStorage | None = None,
        snap_start: SnapStart | None = None,
        logging_config: LoggingConfig | None = None,
        capacity_provider_config: CapacityProviderConfig | None = None,
        durable_config: DurableConfig | None = None,
        **kwargs,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("UpdateFunctionEventInvokeConfig")
    def update_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: NumericLatestPublishedOrAliasQualifier | None = None,
        maximum_retry_attempts: MaximumRetryAttempts | None = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds | None = None,
        destination_config: DestinationConfig | None = None,
        **kwargs,
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("UpdateFunctionUrlConfig")
    def update_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier | None = None,
        auth_type: FunctionUrlAuthType | None = None,
        cors: Cors | None = None,
        invoke_mode: InvokeMode | None = None,
        **kwargs,
    ) -> UpdateFunctionUrlConfigResponse:
        raise NotImplementedError
