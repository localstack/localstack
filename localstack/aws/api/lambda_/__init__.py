import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Action = str
AdditionalVersion = str
Alias = str
AllowCredentials = bool
Arn = str
BatchSize = int
BisectBatchOnFunctionError = bool
Boolean = bool
CodeSigningConfigArn = str
CodeSigningConfigId = str
Description = str
DestinationArn = str
Enabled = bool
Endpoint = str
EnvironmentVariableName = str
EnvironmentVariableValue = str
EphemeralStorageSize = int
EventSourceToken = str
FileSystemArn = str
FunctionArn = str
FunctionName = str
FunctionUrl = str
FunctionUrlQualifier = str
Handler = str
Header = str
HttpStatus = int
Integer = int
KMSKeyArn = str
LastUpdateStatusReason = str
LayerArn = str
LayerName = str
LayerPermissionAllowedAction = str
LayerPermissionAllowedPrincipal = str
LayerVersionArn = str
LicenseInfo = str
LocalMountPath = str
MasterRegion = str
MaxAge = int
MaxFunctionEventInvokeConfigListItems = int
MaxItems = int
MaxLayerListItems = int
MaxListItems = int
MaxProvisionedConcurrencyConfigListItems = int
MaximumBatchingWindowInSeconds = int
MaximumEventAgeInSeconds = int
MaximumRecordAgeInSeconds = int
MaximumRetryAttempts = int
MaximumRetryAttemptsEventSourceMapping = int
MemorySize = int
Method = str
NameSpacedFunctionArn = str
NamespacedFunctionName = str
NamespacedStatementId = str
NonNegativeInteger = int
OrganizationId = str
Origin = str
ParallelizationFactor = int
Pattern = str
PositiveInteger = int
Principal = str
PrincipalOrgID = str
Qualifier = str
Queue = str
ReservedConcurrentExecutions = int
ResourceArn = str
RoleArn = str
S3Bucket = str
S3Key = str
S3ObjectVersion = str
SecurityGroupId = str
SensitiveString = str
SourceOwner = str
StateReason = str
StatementId = str
String = str
SubnetId = str
TagKey = str
TagValue = str
Timeout = int
Timestamp = str
Topic = str
TumblingWindowInSeconds = int
URI = str
UnreservedConcurrentExecutions = int
Version = str
VpcId = str
Weight = float
WorkingDirectory = str


class Architecture(str):
    x86_64 = "x86_64"
    arm64 = "arm64"


class CodeSigningPolicy(str):
    Warn = "Warn"
    Enforce = "Enforce"


class EndPointType(str):
    KAFKA_BOOTSTRAP_SERVERS = "KAFKA_BOOTSTRAP_SERVERS"


class EventSourcePosition(str):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"


class FunctionResponseType(str):
    ReportBatchItemFailures = "ReportBatchItemFailures"


class FunctionUrlAuthType(str):
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"


class FunctionVersion(str):
    ALL = "ALL"


class InvocationType(str):
    Event = "Event"
    RequestResponse = "RequestResponse"
    DryRun = "DryRun"


class LastUpdateStatus(str):
    Successful = "Successful"
    Failed = "Failed"
    InProgress = "InProgress"


class LastUpdateStatusReasonCode(str):
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


class LogType(str):
    None_ = "None"
    Tail = "Tail"


class PackageType(str):
    Zip = "Zip"
    Image = "Image"


class ProvisionedConcurrencyStatusEnum(str):
    IN_PROGRESS = "IN_PROGRESS"
    READY = "READY"
    FAILED = "FAILED"


class Runtime(str):
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
    nodejs4_3_edge = "nodejs4.3-edge"
    go1_x = "go1.x"
    ruby2_5 = "ruby2.5"
    ruby2_7 = "ruby2.7"
    provided = "provided"
    provided_al2 = "provided.al2"


class SourceAccessType(str):
    BASIC_AUTH = "BASIC_AUTH"
    VPC_SUBNET = "VPC_SUBNET"
    VPC_SECURITY_GROUP = "VPC_SECURITY_GROUP"
    SASL_SCRAM_512_AUTH = "SASL_SCRAM_512_AUTH"
    SASL_SCRAM_256_AUTH = "SASL_SCRAM_256_AUTH"
    VIRTUAL_HOST = "VIRTUAL_HOST"
    CLIENT_CERTIFICATE_TLS_AUTH = "CLIENT_CERTIFICATE_TLS_AUTH"
    SERVER_ROOT_CA_CERTIFICATE = "SERVER_ROOT_CA_CERTIFICATE"


class State(str):
    Pending = "Pending"
    Active = "Active"
    Inactive = "Inactive"
    Failed = "Failed"


class StateReasonCode(str):
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


class ThrottleReason(str):
    ConcurrentInvocationLimitExceeded = "ConcurrentInvocationLimitExceeded"
    FunctionInvocationRateLimitExceeded = "FunctionInvocationRateLimitExceeded"
    ReservedFunctionConcurrentInvocationLimitExceeded = (
        "ReservedFunctionConcurrentInvocationLimitExceeded"
    )
    ReservedFunctionInvocationRateLimitExceeded = "ReservedFunctionInvocationRateLimitExceeded"
    CallerRateLimitExceeded = "CallerRateLimitExceeded"


class TracingMode(str):
    Active = "Active"
    PassThrough = "PassThrough"


class CodeSigningConfigNotFoundException(ServiceException):
    code: str = "CodeSigningConfigNotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class CodeStorageExceededException(ServiceException):
    code: str = "CodeStorageExceededException"
    sender_fault: bool = False
    status_code: int = 400


class CodeVerificationFailedException(ServiceException):
    code: str = "CodeVerificationFailedException"
    sender_fault: bool = False
    status_code: int = 400


class EC2AccessDeniedException(ServiceException):
    code: str = "EC2AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 502


class EC2ThrottledException(ServiceException):
    code: str = "EC2ThrottledException"
    sender_fault: bool = False
    status_code: int = 502


class EC2UnexpectedException(ServiceException):
    code: str = "EC2UnexpectedException"
    sender_fault: bool = False
    status_code: int = 502
    EC2ErrorCode: Optional[String]


class EFSIOException(ServiceException):
    code: str = "EFSIOException"
    sender_fault: bool = False
    status_code: int = 410


class EFSMountConnectivityException(ServiceException):
    code: str = "EFSMountConnectivityException"
    sender_fault: bool = False
    status_code: int = 408


class EFSMountFailureException(ServiceException):
    code: str = "EFSMountFailureException"
    sender_fault: bool = False
    status_code: int = 403


class EFSMountTimeoutException(ServiceException):
    code: str = "EFSMountTimeoutException"
    sender_fault: bool = False
    status_code: int = 408


class ENILimitReachedException(ServiceException):
    code: str = "ENILimitReachedException"
    sender_fault: bool = False
    status_code: int = 502


class InvalidCodeSignatureException(ServiceException):
    code: str = "InvalidCodeSignatureException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterValueException(ServiceException):
    code: str = "InvalidParameterValueException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestContentException(ServiceException):
    code: str = "InvalidRequestContentException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRuntimeException(ServiceException):
    code: str = "InvalidRuntimeException"
    sender_fault: bool = False
    status_code: int = 502


class InvalidSecurityGroupIDException(ServiceException):
    code: str = "InvalidSecurityGroupIDException"
    sender_fault: bool = False
    status_code: int = 502


class InvalidSubnetIDException(ServiceException):
    code: str = "InvalidSubnetIDException"
    sender_fault: bool = False
    status_code: int = 502


class InvalidZipFileException(ServiceException):
    code: str = "InvalidZipFileException"
    sender_fault: bool = False
    status_code: int = 502


class KMSAccessDeniedException(ServiceException):
    code: str = "KMSAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 502


class KMSDisabledException(ServiceException):
    code: str = "KMSDisabledException"
    sender_fault: bool = False
    status_code: int = 502


class KMSInvalidStateException(ServiceException):
    code: str = "KMSInvalidStateException"
    sender_fault: bool = False
    status_code: int = 502


class KMSNotFoundException(ServiceException):
    code: str = "KMSNotFoundException"
    sender_fault: bool = False
    status_code: int = 502


class PolicyLengthExceededException(ServiceException):
    code: str = "PolicyLengthExceededException"
    sender_fault: bool = False
    status_code: int = 400


class PreconditionFailedException(ServiceException):
    code: str = "PreconditionFailedException"
    sender_fault: bool = False
    status_code: int = 412


class ProvisionedConcurrencyConfigNotFoundException(ServiceException):
    code: str = "ProvisionedConcurrencyConfigNotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class RequestTooLargeException(ServiceException):
    code: str = "RequestTooLargeException"
    sender_fault: bool = False
    status_code: int = 413


class ResourceConflictException(ServiceException):
    code: str = "ResourceConflictException"
    sender_fault: bool = False
    status_code: int = 409


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class ResourceNotReadyException(ServiceException):
    code: str = "ResourceNotReadyException"
    sender_fault: bool = False
    status_code: int = 502


class ServiceException(ServiceException):
    code: str = "ServiceException"
    sender_fault: bool = False
    status_code: int = 500


class SubnetIPAddressLimitReachedException(ServiceException):
    code: str = "SubnetIPAddressLimitReachedException"
    sender_fault: bool = False
    status_code: int = 502


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429
    retryAfterSeconds: Optional[String]
    Reason: Optional[ThrottleReason]


class UnsupportedMediaTypeException(ServiceException):
    code: str = "UnsupportedMediaTypeException"
    sender_fault: bool = False
    status_code: int = 415


Long = int


class AccountLimit(TypedDict, total=False):
    TotalCodeSize: Optional[Long]
    CodeSizeUnzipped: Optional[Long]
    CodeSizeZipped: Optional[Long]
    ConcurrentExecutions: Optional[Integer]
    UnreservedConcurrentExecutions: Optional[UnreservedConcurrentExecutions]


class AccountUsage(TypedDict, total=False):
    TotalCodeSize: Optional[Long]
    FunctionCount: Optional[Long]


LayerVersionNumber = int


class AddLayerVersionPermissionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber
    StatementId: StatementId
    Action: LayerPermissionAllowedAction
    Principal: LayerPermissionAllowedPrincipal
    OrganizationId: Optional[OrganizationId]
    RevisionId: Optional[String]


class AddLayerVersionPermissionResponse(TypedDict, total=False):
    Statement: Optional[String]
    RevisionId: Optional[String]


class AddPermissionRequest(ServiceRequest):
    FunctionName: FunctionName
    StatementId: StatementId
    Action: Action
    Principal: Principal
    SourceArn: Optional[Arn]
    SourceAccount: Optional[SourceOwner]
    EventSourceToken: Optional[EventSourceToken]
    Qualifier: Optional[Qualifier]
    RevisionId: Optional[String]
    PrincipalOrgID: Optional[PrincipalOrgID]
    FunctionUrlAuthType: Optional[FunctionUrlAuthType]


class AddPermissionResponse(TypedDict, total=False):
    Statement: Optional[String]


AdditionalVersionWeights = Dict[AdditionalVersion, Weight]


class AliasRoutingConfiguration(TypedDict, total=False):
    AdditionalVersionWeights: Optional[AdditionalVersionWeights]


class AliasConfiguration(TypedDict, total=False):
    AliasArn: Optional[FunctionArn]
    Name: Optional[Alias]
    FunctionVersion: Optional[Version]
    Description: Optional[Description]
    RoutingConfig: Optional[AliasRoutingConfiguration]
    RevisionId: Optional[String]


AliasList = List[AliasConfiguration]
AllowMethodsList = List[Method]
AllowOriginsList = List[Origin]
SigningProfileVersionArns = List[Arn]


class AllowedPublishers(TypedDict, total=False):
    SigningProfileVersionArns: SigningProfileVersionArns


ArchitecturesList = List[Architecture]
Blob = bytes
BlobStream = bytes


class CodeSigningPolicies(TypedDict, total=False):
    UntrustedArtifactOnDeployment: Optional[CodeSigningPolicy]


class CodeSigningConfig(TypedDict, total=False):
    CodeSigningConfigId: CodeSigningConfigId
    CodeSigningConfigArn: CodeSigningConfigArn
    Description: Optional[Description]
    AllowedPublishers: AllowedPublishers
    CodeSigningPolicies: CodeSigningPolicies
    LastModified: Timestamp


CodeSigningConfigList = List[CodeSigningConfig]
CompatibleArchitectures = List[Architecture]
CompatibleRuntimes = List[Runtime]


class Concurrency(TypedDict, total=False):
    ReservedConcurrentExecutions: Optional[ReservedConcurrentExecutions]


HeadersList = List[Header]


class Cors(TypedDict, total=False):
    AllowCredentials: Optional[AllowCredentials]
    AllowHeaders: Optional[HeadersList]
    AllowMethods: Optional[AllowMethodsList]
    AllowOrigins: Optional[AllowOriginsList]
    ExposeHeaders: Optional[HeadersList]
    MaxAge: Optional[MaxAge]


class CreateAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias
    FunctionVersion: Version
    Description: Optional[Description]
    RoutingConfig: Optional[AliasRoutingConfiguration]


class CreateCodeSigningConfigRequest(ServiceRequest):
    Description: Optional[Description]
    AllowedPublishers: AllowedPublishers
    CodeSigningPolicies: Optional[CodeSigningPolicies]


class CreateCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


FunctionResponseTypeList = List[FunctionResponseType]
EndpointLists = List[Endpoint]
Endpoints = Dict[EndPointType, EndpointLists]


class SelfManagedEventSource(TypedDict, total=False):
    Endpoints: Optional[Endpoints]


class SourceAccessConfiguration(TypedDict, total=False):
    Type: Optional[SourceAccessType]
    URI: Optional[URI]


SourceAccessConfigurations = List[SourceAccessConfiguration]
Queues = List[Queue]
Topics = List[Topic]


class OnFailure(TypedDict, total=False):
    Destination: Optional[DestinationArn]


class OnSuccess(TypedDict, total=False):
    Destination: Optional[DestinationArn]


class DestinationConfig(TypedDict, total=False):
    OnSuccess: Optional[OnSuccess]
    OnFailure: Optional[OnFailure]


Date = datetime


class Filter(TypedDict, total=False):
    Pattern: Optional[Pattern]


FilterList = List[Filter]


class FilterCriteria(TypedDict, total=False):
    Filters: Optional[FilterList]


class CreateEventSourceMappingRequest(ServiceRequest):
    EventSourceArn: Optional[Arn]
    FunctionName: FunctionName
    Enabled: Optional[Enabled]
    BatchSize: Optional[BatchSize]
    FilterCriteria: Optional[FilterCriteria]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ParallelizationFactor: Optional[ParallelizationFactor]
    StartingPosition: Optional[EventSourcePosition]
    StartingPositionTimestamp: Optional[Date]
    DestinationConfig: Optional[DestinationConfig]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    BisectBatchOnFunctionError: Optional[BisectBatchOnFunctionError]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsEventSourceMapping]
    TumblingWindowInSeconds: Optional[TumblingWindowInSeconds]
    Topics: Optional[Topics]
    Queues: Optional[Queues]
    SourceAccessConfigurations: Optional[SourceAccessConfigurations]
    SelfManagedEventSource: Optional[SelfManagedEventSource]
    FunctionResponseTypes: Optional[FunctionResponseTypeList]


class EphemeralStorage(TypedDict, total=False):
    Size: EphemeralStorageSize


StringList = List[String]


class ImageConfig(TypedDict, total=False):
    EntryPoint: Optional[StringList]
    Command: Optional[StringList]
    WorkingDirectory: Optional[WorkingDirectory]


class FileSystemConfig(TypedDict, total=False):
    Arn: FileSystemArn
    LocalMountPath: LocalMountPath


FileSystemConfigList = List[FileSystemConfig]
LayerList = List[LayerVersionArn]
Tags = Dict[TagKey, TagValue]


class TracingConfig(TypedDict, total=False):
    Mode: Optional[TracingMode]


EnvironmentVariables = Dict[EnvironmentVariableName, EnvironmentVariableValue]


class Environment(TypedDict, total=False):
    Variables: Optional[EnvironmentVariables]


class DeadLetterConfig(TypedDict, total=False):
    TargetArn: Optional[ResourceArn]


SecurityGroupIds = List[SecurityGroupId]
SubnetIds = List[SubnetId]


class VpcConfig(TypedDict, total=False):
    SubnetIds: Optional[SubnetIds]
    SecurityGroupIds: Optional[SecurityGroupIds]


class FunctionCode(TypedDict, total=False):
    ZipFile: Optional[Blob]
    S3Bucket: Optional[S3Bucket]
    S3Key: Optional[S3Key]
    S3ObjectVersion: Optional[S3ObjectVersion]
    ImageUri: Optional[String]


class CreateFunctionRequest(ServiceRequest):
    FunctionName: FunctionName
    Runtime: Optional[Runtime]
    Role: RoleArn
    Handler: Optional[Handler]
    Code: FunctionCode
    Description: Optional[Description]
    Timeout: Optional[Timeout]
    MemorySize: Optional[MemorySize]
    Publish: Optional[Boolean]
    VpcConfig: Optional[VpcConfig]
    PackageType: Optional[PackageType]
    DeadLetterConfig: Optional[DeadLetterConfig]
    Environment: Optional[Environment]
    KMSKeyArn: Optional[KMSKeyArn]
    TracingConfig: Optional[TracingConfig]
    Tags: Optional[Tags]
    Layers: Optional[LayerList]
    FileSystemConfigs: Optional[FileSystemConfigList]
    ImageConfig: Optional[ImageConfig]
    CodeSigningConfigArn: Optional[CodeSigningConfigArn]
    Architectures: Optional[ArchitecturesList]
    EphemeralStorage: Optional[EphemeralStorage]


class CreateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]
    AuthType: FunctionUrlAuthType
    Cors: Optional[Cors]


class CreateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Optional[Cors]
    CreationTime: Timestamp


class DeleteAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias


class DeleteCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn


class DeleteCodeSigningConfigResponse(TypedDict, total=False):
    pass


class DeleteEventSourceMappingRequest(ServiceRequest):
    UUID: String


class DeleteFunctionCodeSigningConfigRequest(ServiceRequest):
    FunctionName: FunctionName


class DeleteFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName


class DeleteFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]


class DeleteFunctionRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]


class DeleteFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]


class DeleteLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class DeleteProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier


class EnvironmentError(TypedDict, total=False):
    ErrorCode: Optional[String]
    Message: Optional[SensitiveString]


class EnvironmentResponse(TypedDict, total=False):
    Variables: Optional[EnvironmentVariables]
    Error: Optional[EnvironmentError]


class EventSourceMappingConfiguration(TypedDict, total=False):
    UUID: Optional[String]
    StartingPosition: Optional[EventSourcePosition]
    StartingPositionTimestamp: Optional[Date]
    BatchSize: Optional[BatchSize]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ParallelizationFactor: Optional[ParallelizationFactor]
    EventSourceArn: Optional[Arn]
    FilterCriteria: Optional[FilterCriteria]
    FunctionArn: Optional[FunctionArn]
    LastModified: Optional[Date]
    LastProcessingResult: Optional[String]
    State: Optional[String]
    StateTransitionReason: Optional[String]
    DestinationConfig: Optional[DestinationConfig]
    Topics: Optional[Topics]
    Queues: Optional[Queues]
    SourceAccessConfigurations: Optional[SourceAccessConfigurations]
    SelfManagedEventSource: Optional[SelfManagedEventSource]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    BisectBatchOnFunctionError: Optional[BisectBatchOnFunctionError]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsEventSourceMapping]
    TumblingWindowInSeconds: Optional[TumblingWindowInSeconds]
    FunctionResponseTypes: Optional[FunctionResponseTypeList]


EventSourceMappingsList = List[EventSourceMappingConfiguration]
FunctionArnList = List[FunctionArn]


class FunctionCodeLocation(TypedDict, total=False):
    RepositoryType: Optional[String]
    Location: Optional[String]
    ImageUri: Optional[String]
    ResolvedImageUri: Optional[String]


class ImageConfigError(TypedDict, total=False):
    ErrorCode: Optional[String]
    Message: Optional[SensitiveString]


class ImageConfigResponse(TypedDict, total=False):
    ImageConfig: Optional[ImageConfig]
    Error: Optional[ImageConfigError]


class Layer(TypedDict, total=False):
    Arn: Optional[LayerVersionArn]
    CodeSize: Optional[Long]
    SigningProfileVersionArn: Optional[Arn]
    SigningJobArn: Optional[Arn]


LayersReferenceList = List[Layer]


class TracingConfigResponse(TypedDict, total=False):
    Mode: Optional[TracingMode]


class VpcConfigResponse(TypedDict, total=False):
    SubnetIds: Optional[SubnetIds]
    SecurityGroupIds: Optional[SecurityGroupIds]
    VpcId: Optional[VpcId]


class FunctionConfiguration(TypedDict, total=False):
    FunctionName: Optional[NamespacedFunctionName]
    FunctionArn: Optional[NameSpacedFunctionArn]
    Runtime: Optional[Runtime]
    Role: Optional[RoleArn]
    Handler: Optional[Handler]
    CodeSize: Optional[Long]
    Description: Optional[Description]
    Timeout: Optional[Timeout]
    MemorySize: Optional[MemorySize]
    LastModified: Optional[Timestamp]
    CodeSha256: Optional[String]
    Version: Optional[Version]
    VpcConfig: Optional[VpcConfigResponse]
    DeadLetterConfig: Optional[DeadLetterConfig]
    Environment: Optional[EnvironmentResponse]
    KMSKeyArn: Optional[KMSKeyArn]
    TracingConfig: Optional[TracingConfigResponse]
    MasterArn: Optional[FunctionArn]
    RevisionId: Optional[String]
    Layers: Optional[LayersReferenceList]
    State: Optional[State]
    StateReason: Optional[StateReason]
    StateReasonCode: Optional[StateReasonCode]
    LastUpdateStatus: Optional[LastUpdateStatus]
    LastUpdateStatusReason: Optional[LastUpdateStatusReason]
    LastUpdateStatusReasonCode: Optional[LastUpdateStatusReasonCode]
    FileSystemConfigs: Optional[FileSystemConfigList]
    PackageType: Optional[PackageType]
    ImageConfigResponse: Optional[ImageConfigResponse]
    SigningProfileVersionArn: Optional[Arn]
    SigningJobArn: Optional[Arn]
    Architectures: Optional[ArchitecturesList]
    EphemeralStorage: Optional[EphemeralStorage]


class FunctionEventInvokeConfig(TypedDict, total=False):
    LastModified: Optional[Date]
    FunctionArn: Optional[FunctionArn]
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]
    DestinationConfig: Optional[DestinationConfig]


FunctionEventInvokeConfigList = List[FunctionEventInvokeConfig]
FunctionList = List[FunctionConfiguration]


class FunctionUrlConfig(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    Cors: Optional[Cors]
    AuthType: FunctionUrlAuthType


FunctionUrlConfigList = List[FunctionUrlConfig]


class GetAccountSettingsRequest(ServiceRequest):
    pass


class GetAccountSettingsResponse(TypedDict, total=False):
    AccountLimit: Optional[AccountLimit]
    AccountUsage: Optional[AccountUsage]


class GetAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias


class GetCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn


class GetCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


class GetEventSourceMappingRequest(ServiceRequest):
    UUID: String


class GetFunctionCodeSigningConfigRequest(ServiceRequest):
    FunctionName: FunctionName


class GetFunctionCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: FunctionName


class GetFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName


class GetFunctionConcurrencyResponse(TypedDict, total=False):
    ReservedConcurrentExecutions: Optional[ReservedConcurrentExecutions]


class GetFunctionConfigurationRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: Optional[Qualifier]


class GetFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]


class GetFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: Optional[Qualifier]


class GetFunctionResponse(TypedDict, total=False):
    Configuration: Optional[FunctionConfiguration]
    Code: Optional[FunctionCodeLocation]
    Tags: Optional[Tags]
    Concurrency: Optional[Concurrency]


class GetFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]


class GetFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Optional[Cors]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp


class GetLayerVersionByArnRequest(ServiceRequest):
    Arn: LayerVersionArn


class GetLayerVersionPolicyRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class GetLayerVersionPolicyResponse(TypedDict, total=False):
    Policy: Optional[String]
    RevisionId: Optional[String]


class GetLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber


class LayerVersionContentOutput(TypedDict, total=False):
    Location: Optional[String]
    CodeSha256: Optional[String]
    CodeSize: Optional[Long]
    SigningProfileVersionArn: Optional[String]
    SigningJobArn: Optional[String]


class GetLayerVersionResponse(TypedDict, total=False):
    Content: Optional[LayerVersionContentOutput]
    LayerArn: Optional[LayerArn]
    LayerVersionArn: Optional[LayerVersionArn]
    Description: Optional[Description]
    CreatedDate: Optional[Timestamp]
    Version: Optional[LayerVersionNumber]
    CompatibleRuntimes: Optional[CompatibleRuntimes]
    LicenseInfo: Optional[LicenseInfo]
    CompatibleArchitectures: Optional[CompatibleArchitectures]


class GetPolicyRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Qualifier: Optional[Qualifier]


class GetPolicyResponse(TypedDict, total=False):
    Policy: Optional[String]
    RevisionId: Optional[String]


class GetProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier


class GetProvisionedConcurrencyConfigResponse(TypedDict, total=False):
    RequestedProvisionedConcurrentExecutions: Optional[PositiveInteger]
    AvailableProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    AllocatedProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    Status: Optional[ProvisionedConcurrencyStatusEnum]
    StatusReason: Optional[String]
    LastModified: Optional[Timestamp]


class InvocationRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    InvocationType: Optional[InvocationType]
    LogType: Optional[LogType]
    ClientContext: Optional[String]
    Payload: Optional[Blob]
    Qualifier: Optional[Qualifier]


class InvocationResponse(TypedDict, total=False):
    StatusCode: Optional[Integer]
    FunctionError: Optional[String]
    LogResult: Optional[String]
    Payload: Optional[Blob]
    ExecutedVersion: Optional[Version]


class InvokeAsyncRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    InvokeArgs: BlobStream


class InvokeAsyncResponse(TypedDict, total=False):
    Status: Optional[HttpStatus]


class LayerVersionContentInput(TypedDict, total=False):
    S3Bucket: Optional[S3Bucket]
    S3Key: Optional[S3Key]
    S3ObjectVersion: Optional[S3ObjectVersion]
    ZipFile: Optional[Blob]


class LayerVersionsListItem(TypedDict, total=False):
    LayerVersionArn: Optional[LayerVersionArn]
    Version: Optional[LayerVersionNumber]
    Description: Optional[Description]
    CreatedDate: Optional[Timestamp]
    CompatibleRuntimes: Optional[CompatibleRuntimes]
    LicenseInfo: Optional[LicenseInfo]
    CompatibleArchitectures: Optional[CompatibleArchitectures]


LayerVersionsList = List[LayerVersionsListItem]


class LayersListItem(TypedDict, total=False):
    LayerName: Optional[LayerName]
    LayerArn: Optional[LayerArn]
    LatestMatchingVersion: Optional[LayerVersionsListItem]


LayersList = List[LayersListItem]


class ListAliasesRequest(ServiceRequest):
    FunctionName: FunctionName
    FunctionVersion: Optional[Version]
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListAliasesResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    Aliases: Optional[AliasList]


class ListCodeSigningConfigsRequest(ServiceRequest):
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListCodeSigningConfigsResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    CodeSigningConfigs: Optional[CodeSigningConfigList]


class ListEventSourceMappingsRequest(ServiceRequest):
    EventSourceArn: Optional[Arn]
    FunctionName: Optional[FunctionName]
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListEventSourceMappingsResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    EventSourceMappings: Optional[EventSourceMappingsList]


class ListFunctionEventInvokeConfigsRequest(ServiceRequest):
    FunctionName: FunctionName
    Marker: Optional[String]
    MaxItems: Optional[MaxFunctionEventInvokeConfigListItems]


class ListFunctionEventInvokeConfigsResponse(TypedDict, total=False):
    FunctionEventInvokeConfigs: Optional[FunctionEventInvokeConfigList]
    NextMarker: Optional[String]


class ListFunctionUrlConfigsRequest(ServiceRequest):
    FunctionName: FunctionName
    Marker: Optional[String]
    MaxItems: Optional[MaxItems]


class ListFunctionUrlConfigsResponse(TypedDict, total=False):
    FunctionUrlConfigs: FunctionUrlConfigList
    NextMarker: Optional[String]


class ListFunctionsByCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListFunctionsByCodeSigningConfigResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    FunctionArns: Optional[FunctionArnList]


class ListFunctionsRequest(ServiceRequest):
    MasterRegion: Optional[MasterRegion]
    FunctionVersion: Optional[FunctionVersion]
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListFunctionsResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    Functions: Optional[FunctionList]


class ListLayerVersionsRequest(ServiceRequest):
    CompatibleRuntime: Optional[Runtime]
    LayerName: LayerName
    Marker: Optional[String]
    MaxItems: Optional[MaxLayerListItems]
    CompatibleArchitecture: Optional[Architecture]


class ListLayerVersionsResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    LayerVersions: Optional[LayerVersionsList]


class ListLayersRequest(ServiceRequest):
    CompatibleRuntime: Optional[Runtime]
    Marker: Optional[String]
    MaxItems: Optional[MaxLayerListItems]
    CompatibleArchitecture: Optional[Architecture]


class ListLayersResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    Layers: Optional[LayersList]


class ListProvisionedConcurrencyConfigsRequest(ServiceRequest):
    FunctionName: FunctionName
    Marker: Optional[String]
    MaxItems: Optional[MaxProvisionedConcurrencyConfigListItems]


class ProvisionedConcurrencyConfigListItem(TypedDict, total=False):
    FunctionArn: Optional[FunctionArn]
    RequestedProvisionedConcurrentExecutions: Optional[PositiveInteger]
    AvailableProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    AllocatedProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    Status: Optional[ProvisionedConcurrencyStatusEnum]
    StatusReason: Optional[String]
    LastModified: Optional[Timestamp]


ProvisionedConcurrencyConfigList = List[ProvisionedConcurrencyConfigListItem]


class ListProvisionedConcurrencyConfigsResponse(TypedDict, total=False):
    ProvisionedConcurrencyConfigs: Optional[ProvisionedConcurrencyConfigList]
    NextMarker: Optional[String]


class ListTagsRequest(ServiceRequest):
    Resource: FunctionArn


class ListTagsResponse(TypedDict, total=False):
    Tags: Optional[Tags]


class ListVersionsByFunctionRequest(ServiceRequest):
    FunctionName: NamespacedFunctionName
    Marker: Optional[String]
    MaxItems: Optional[MaxListItems]


class ListVersionsByFunctionResponse(TypedDict, total=False):
    NextMarker: Optional[String]
    Versions: Optional[FunctionList]


class PublishLayerVersionRequest(ServiceRequest):
    LayerName: LayerName
    Description: Optional[Description]
    Content: LayerVersionContentInput
    CompatibleRuntimes: Optional[CompatibleRuntimes]
    LicenseInfo: Optional[LicenseInfo]
    CompatibleArchitectures: Optional[CompatibleArchitectures]


class PublishLayerVersionResponse(TypedDict, total=False):
    Content: Optional[LayerVersionContentOutput]
    LayerArn: Optional[LayerArn]
    LayerVersionArn: Optional[LayerVersionArn]
    Description: Optional[Description]
    CreatedDate: Optional[Timestamp]
    Version: Optional[LayerVersionNumber]
    CompatibleRuntimes: Optional[CompatibleRuntimes]
    LicenseInfo: Optional[LicenseInfo]
    CompatibleArchitectures: Optional[CompatibleArchitectures]


class PublishVersionRequest(ServiceRequest):
    FunctionName: FunctionName
    CodeSha256: Optional[String]
    Description: Optional[Description]
    RevisionId: Optional[String]


class PutFunctionCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: FunctionName


class PutFunctionCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfigArn: CodeSigningConfigArn
    FunctionName: FunctionName


class PutFunctionConcurrencyRequest(ServiceRequest):
    FunctionName: FunctionName
    ReservedConcurrentExecutions: ReservedConcurrentExecutions


class PutFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]
    DestinationConfig: Optional[DestinationConfig]


class PutProvisionedConcurrencyConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Qualifier
    ProvisionedConcurrentExecutions: PositiveInteger


class PutProvisionedConcurrencyConfigResponse(TypedDict, total=False):
    RequestedProvisionedConcurrentExecutions: Optional[PositiveInteger]
    AvailableProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    AllocatedProvisionedConcurrentExecutions: Optional[NonNegativeInteger]
    Status: Optional[ProvisionedConcurrencyStatusEnum]
    StatusReason: Optional[String]
    LastModified: Optional[Timestamp]


class RemoveLayerVersionPermissionRequest(ServiceRequest):
    LayerName: LayerName
    VersionNumber: LayerVersionNumber
    StatementId: StatementId
    RevisionId: Optional[String]


class RemovePermissionRequest(ServiceRequest):
    FunctionName: FunctionName
    StatementId: NamespacedStatementId
    Qualifier: Optional[Qualifier]
    RevisionId: Optional[String]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    Resource: FunctionArn
    Tags: Tags


class UntagResourceRequest(ServiceRequest):
    Resource: FunctionArn
    TagKeys: TagKeyList


class UpdateAliasRequest(ServiceRequest):
    FunctionName: FunctionName
    Name: Alias
    FunctionVersion: Optional[Version]
    Description: Optional[Description]
    RoutingConfig: Optional[AliasRoutingConfiguration]
    RevisionId: Optional[String]


class UpdateCodeSigningConfigRequest(ServiceRequest):
    CodeSigningConfigArn: CodeSigningConfigArn
    Description: Optional[Description]
    AllowedPublishers: Optional[AllowedPublishers]
    CodeSigningPolicies: Optional[CodeSigningPolicies]


class UpdateCodeSigningConfigResponse(TypedDict, total=False):
    CodeSigningConfig: CodeSigningConfig


class UpdateEventSourceMappingRequest(ServiceRequest):
    UUID: String
    FunctionName: Optional[FunctionName]
    Enabled: Optional[Enabled]
    BatchSize: Optional[BatchSize]
    FilterCriteria: Optional[FilterCriteria]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    DestinationConfig: Optional[DestinationConfig]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    BisectBatchOnFunctionError: Optional[BisectBatchOnFunctionError]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsEventSourceMapping]
    ParallelizationFactor: Optional[ParallelizationFactor]
    SourceAccessConfigurations: Optional[SourceAccessConfigurations]
    TumblingWindowInSeconds: Optional[TumblingWindowInSeconds]
    FunctionResponseTypes: Optional[FunctionResponseTypeList]


class UpdateFunctionCodeRequest(ServiceRequest):
    FunctionName: FunctionName
    ZipFile: Optional[Blob]
    S3Bucket: Optional[S3Bucket]
    S3Key: Optional[S3Key]
    S3ObjectVersion: Optional[S3ObjectVersion]
    ImageUri: Optional[String]
    Publish: Optional[Boolean]
    DryRun: Optional[Boolean]
    RevisionId: Optional[String]
    Architectures: Optional[ArchitecturesList]


class UpdateFunctionConfigurationRequest(ServiceRequest):
    FunctionName: FunctionName
    Role: Optional[RoleArn]
    Handler: Optional[Handler]
    Description: Optional[Description]
    Timeout: Optional[Timeout]
    MemorySize: Optional[MemorySize]
    VpcConfig: Optional[VpcConfig]
    Environment: Optional[Environment]
    Runtime: Optional[Runtime]
    DeadLetterConfig: Optional[DeadLetterConfig]
    KMSKeyArn: Optional[KMSKeyArn]
    TracingConfig: Optional[TracingConfig]
    RevisionId: Optional[String]
    Layers: Optional[LayerList]
    FileSystemConfigs: Optional[FileSystemConfigList]
    ImageConfig: Optional[ImageConfig]
    EphemeralStorage: Optional[EphemeralStorage]


class UpdateFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]
    DestinationConfig: Optional[DestinationConfig]


class UpdateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]
    AuthType: Optional[FunctionUrlAuthType]
    Cors: Optional[Cors]


class UpdateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthType: FunctionUrlAuthType
    Cors: Optional[Cors]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp


class LambdaApi:

    service = "lambda"
    version = "2015-03-31"

    @handler("AddLayerVersionPermission")
    def add_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        action: LayerPermissionAllowedAction,
        principal: LayerPermissionAllowedPrincipal,
        organization_id: OrganizationId = None,
        revision_id: String = None,
    ) -> AddLayerVersionPermissionResponse:
        raise NotImplementedError

    @handler("AddPermission")
    def add_permission(
        self,
        context: RequestContext,
        function_name: FunctionName,
        statement_id: StatementId,
        action: Action,
        principal: Principal,
        source_arn: Arn = None,
        source_account: SourceOwner = None,
        event_source_token: EventSourceToken = None,
        qualifier: Qualifier = None,
        revision_id: String = None,
        principal_org_id: PrincipalOrgID = None,
        function_url_auth_type: FunctionUrlAuthType = None,
    ) -> AddPermissionResponse:
        raise NotImplementedError

    @handler("CreateAlias")
    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        raise NotImplementedError

    @handler("CreateCodeSigningConfig")
    def create_code_signing_config(
        self,
        context: RequestContext,
        allowed_publishers: AllowedPublishers,
        description: Description = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> CreateCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("CreateEventSourceMapping")
    def create_event_source_mapping(
        self,
        context: RequestContext,
        function_name: FunctionName,
        event_source_arn: Arn = None,
        enabled: Enabled = None,
        batch_size: BatchSize = None,
        filter_criteria: FilterCriteria = None,
        maximum_batching_window_in_seconds: MaximumBatchingWindowInSeconds = None,
        parallelization_factor: ParallelizationFactor = None,
        starting_position: EventSourcePosition = None,
        starting_position_timestamp: Date = None,
        destination_config: DestinationConfig = None,
        maximum_record_age_in_seconds: MaximumRecordAgeInSeconds = None,
        bisect_batch_on_function_error: BisectBatchOnFunctionError = None,
        maximum_retry_attempts: MaximumRetryAttemptsEventSourceMapping = None,
        tumbling_window_in_seconds: TumblingWindowInSeconds = None,
        topics: Topics = None,
        queues: Queues = None,
        source_access_configurations: SourceAccessConfigurations = None,
        self_managed_event_source: SelfManagedEventSource = None,
        function_response_types: FunctionResponseTypeList = None,
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("CreateFunction")
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
        vpc_config: VpcConfig = None,
        package_type: PackageType = None,
        dead_letter_config: DeadLetterConfig = None,
        environment: Environment = None,
        kms_key_arn: KMSKeyArn = None,
        tracing_config: TracingConfig = None,
        tags: Tags = None,
        layers: LayerList = None,
        file_system_configs: FileSystemConfigList = None,
        image_config: ImageConfig = None,
        code_signing_config_arn: CodeSigningConfigArn = None,
        architectures: ArchitecturesList = None,
        ephemeral_storage: EphemeralStorage = None,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("CreateFunctionUrlConfig")
    def create_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        auth_type: FunctionUrlAuthType,
        qualifier: FunctionUrlQualifier = None,
        cors: Cors = None,
    ) -> CreateFunctionUrlConfigResponse:
        raise NotImplementedError

    @handler("DeleteAlias")
    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCodeSigningConfig")
    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> DeleteCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("DeleteEventSourceMapping")
    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionCodeSigningConfig")
    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionConcurrency")
    def delete_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionEventInvokeConfig")
    def delete_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunctionUrlConfig")
    def delete_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLayerVersion")
    def delete_layer_version(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> None:
        raise NotImplementedError

    @handler("DeleteProvisionedConcurrencyConfig")
    def delete_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> None:
        raise NotImplementedError

    @handler("GetAccountSettings")
    def get_account_settings(
        self,
        context: RequestContext,
    ) -> GetAccountSettingsResponse:
        raise NotImplementedError

    @handler("GetAlias")
    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        raise NotImplementedError

    @handler("GetCodeSigningConfig")
    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> GetCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("GetEventSourceMapping")
    def get_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetFunctionResponse:
        raise NotImplementedError

    @handler("GetFunctionCodeSigningConfig")
    def get_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("GetFunctionConcurrency")
    def get_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionConcurrencyResponse:
        raise NotImplementedError

    @handler("GetFunctionConfiguration")
    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("GetFunctionEventInvokeConfig")
    def get_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("GetFunctionUrlConfig")
    def get_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> GetFunctionUrlConfigResponse:
        raise NotImplementedError

    @handler("GetLayerVersion")
    def get_layer_version(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> GetLayerVersionResponse:
        raise NotImplementedError

    @handler("GetLayerVersionByArn")
    def get_layer_version_by_arn(
        self, context: RequestContext, arn: LayerVersionArn
    ) -> GetLayerVersionResponse:
        raise NotImplementedError

    @handler("GetLayerVersionPolicy")
    def get_layer_version_policy(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> GetLayerVersionPolicyResponse:
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetPolicyResponse:
        raise NotImplementedError

    @handler("GetProvisionedConcurrencyConfig")
    def get_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> GetProvisionedConcurrencyConfigResponse:
        raise NotImplementedError

    @handler("Invoke")
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
        raise NotImplementedError

    @handler("InvokeAsync")
    def invoke_async(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invoke_args: BlobStream,
    ) -> InvokeAsyncResponse:
        raise NotImplementedError

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListAliasesResponse:
        raise NotImplementedError

    @handler("ListCodeSigningConfigs")
    def list_code_signing_configs(
        self, context: RequestContext, marker: String = None, max_items: MaxListItems = None
    ) -> ListCodeSigningConfigsResponse:
        raise NotImplementedError

    @handler("ListEventSourceMappings")
    def list_event_source_mappings(
        self,
        context: RequestContext,
        event_source_arn: Arn = None,
        function_name: FunctionName = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListEventSourceMappingsResponse:
        raise NotImplementedError

    @handler("ListFunctionEventInvokeConfigs")
    def list_function_event_invoke_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxFunctionEventInvokeConfigListItems = None,
    ) -> ListFunctionEventInvokeConfigsResponse:
        raise NotImplementedError

    @handler("ListFunctionUrlConfigs")
    def list_function_url_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxItems = None,
    ) -> ListFunctionUrlConfigsResponse:
        raise NotImplementedError

    @handler("ListFunctions")
    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,
        function_version: FunctionVersion = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsResponse:
        raise NotImplementedError

    @handler("ListFunctionsByCodeSigningConfig")
    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("ListLayerVersions")
    def list_layer_versions(
        self,
        context: RequestContext,
        layer_name: LayerName,
        compatible_runtime: Runtime = None,
        marker: String = None,
        max_items: MaxLayerListItems = None,
        compatible_architecture: Architecture = None,
    ) -> ListLayerVersionsResponse:
        raise NotImplementedError

    @handler("ListLayers")
    def list_layers(
        self,
        context: RequestContext,
        compatible_runtime: Runtime = None,
        marker: String = None,
        max_items: MaxLayerListItems = None,
        compatible_architecture: Architecture = None,
    ) -> ListLayersResponse:
        raise NotImplementedError

    @handler("ListProvisionedConcurrencyConfigs")
    def list_provisioned_concurrency_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxProvisionedConcurrencyConfigListItems = None,
    ) -> ListProvisionedConcurrencyConfigsResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, resource: FunctionArn) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListVersionsByFunction")
    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListVersionsByFunctionResponse:
        raise NotImplementedError

    @handler("PublishLayerVersion")
    def publish_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        content: LayerVersionContentInput,
        description: Description = None,
        compatible_runtimes: CompatibleRuntimes = None,
        license_info: LicenseInfo = None,
        compatible_architectures: CompatibleArchitectures = None,
    ) -> PublishLayerVersionResponse:
        raise NotImplementedError

    @handler("PublishVersion")
    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String = None,
        description: Description = None,
        revision_id: String = None,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("PutFunctionCodeSigningConfig")
    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: FunctionName,
    ) -> PutFunctionCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("PutFunctionConcurrency")
    def put_function_concurrency(
        self,
        context: RequestContext,
        function_name: FunctionName,
        reserved_concurrent_executions: ReservedConcurrentExecutions,
    ) -> Concurrency:
        raise NotImplementedError

    @handler("PutFunctionEventInvokeConfig")
    def put_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("PutProvisionedConcurrencyConfig")
    def put_provisioned_concurrency_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier,
        provisioned_concurrent_executions: PositiveInteger,
    ) -> PutProvisionedConcurrencyConfigResponse:
        raise NotImplementedError

    @handler("RemoveLayerVersionPermission")
    def remove_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        revision_id: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        function_name: FunctionName,
        statement_id: NamespacedStatementId,
        qualifier: Qualifier = None,
        revision_id: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource: FunctionArn, tags: Tags) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource: FunctionArn, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAlias")
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
        raise NotImplementedError

    @handler("UpdateCodeSigningConfig")
    def update_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        description: Description = None,
        allowed_publishers: AllowedPublishers = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> UpdateCodeSigningConfigResponse:
        raise NotImplementedError

    @handler("UpdateEventSourceMapping")
    def update_event_source_mapping(
        self,
        context: RequestContext,
        uuid: String,
        function_name: FunctionName = None,
        enabled: Enabled = None,
        batch_size: BatchSize = None,
        filter_criteria: FilterCriteria = None,
        maximum_batching_window_in_seconds: MaximumBatchingWindowInSeconds = None,
        destination_config: DestinationConfig = None,
        maximum_record_age_in_seconds: MaximumRecordAgeInSeconds = None,
        bisect_batch_on_function_error: BisectBatchOnFunctionError = None,
        maximum_retry_attempts: MaximumRetryAttemptsEventSourceMapping = None,
        parallelization_factor: ParallelizationFactor = None,
        source_access_configurations: SourceAccessConfigurations = None,
        tumbling_window_in_seconds: TumblingWindowInSeconds = None,
        function_response_types: FunctionResponseTypeList = None,
    ) -> EventSourceMappingConfiguration:
        raise NotImplementedError

    @handler("UpdateFunctionCode")
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
        raise NotImplementedError

    @handler("UpdateFunctionConfiguration")
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
        ephemeral_storage: EphemeralStorage = None,
    ) -> FunctionConfiguration:
        raise NotImplementedError

    @handler("UpdateFunctionEventInvokeConfig")
    def update_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        raise NotImplementedError

    @handler("UpdateFunctionUrlConfig")
    def update_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
        auth_type: FunctionUrlAuthType = None,
        cors: Cors = None,
    ) -> UpdateFunctionUrlConfigResponse:
        raise NotImplementedError
