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
PositiveInteger = int
Principal = str
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


class AuthorizationType(str):
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"


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
    """The specified code signing configuration does not exist."""

    Type: Optional[String]
    Message: Optional[String]


class CodeStorageExceededException(ServiceException):
    """You have exceeded your maximum total code size per account. `Learn
    more <https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`__
    """

    Type: Optional[String]
    message: Optional[String]


class CodeVerificationFailedException(ServiceException):
    """The code signature failed one or more of the validation checks for
    signature mismatch or expiry, and the code signing policy is set to
    ENFORCE. Lambda blocks the deployment.
    """

    Type: Optional[String]
    Message: Optional[String]


class EC2AccessDeniedException(ServiceException):
    """Need additional permissions to configure VPC settings."""

    Type: Optional[String]
    Message: Optional[String]


class EC2ThrottledException(ServiceException):
    """Lambda was throttled by Amazon EC2 during Lambda function initialization
    using the execution role provided for the Lambda function.
    """

    Type: Optional[String]
    Message: Optional[String]


class EC2UnexpectedException(ServiceException):
    """Lambda received an unexpected EC2 client exception while setting up for
    the Lambda function.
    """

    Type: Optional[String]
    Message: Optional[String]
    EC2ErrorCode: Optional[String]


class EFSIOException(ServiceException):
    """An error occurred when reading from or writing to a connected file
    system.
    """

    Type: Optional[String]
    Message: Optional[String]


class EFSMountConnectivityException(ServiceException):
    """The function couldn't make a network connection to the configured file
    system.
    """

    Type: Optional[String]
    Message: Optional[String]


class EFSMountFailureException(ServiceException):
    """The function couldn't mount the configured file system due to a
    permission or configuration issue.
    """

    Type: Optional[String]
    Message: Optional[String]


class EFSMountTimeoutException(ServiceException):
    """The function was able to make a network connection to the configured
    file system, but the mount operation timed out.
    """

    Type: Optional[String]
    Message: Optional[String]


class ENILimitReachedException(ServiceException):
    """Lambda was not able to create an elastic network interface in the VPC,
    specified as part of Lambda function configuration, because the limit
    for network interfaces has been reached.
    """

    Type: Optional[String]
    Message: Optional[String]


class InvalidCodeSignatureException(ServiceException):
    """The code signature failed the integrity check. Lambda always blocks
    deployment if the integrity check fails, even if code signing policy is
    set to WARN.
    """

    Type: Optional[String]
    Message: Optional[String]


class InvalidParameterValueException(ServiceException):
    """One of the parameters in the request is invalid."""

    Type: Optional[String]
    message: Optional[String]


class InvalidRequestContentException(ServiceException):
    """The request body could not be parsed as JSON."""

    Type: Optional[String]
    message: Optional[String]


class InvalidRuntimeException(ServiceException):
    """The runtime or runtime version specified is not supported."""

    Type: Optional[String]
    Message: Optional[String]


class InvalidSecurityGroupIDException(ServiceException):
    """The Security Group ID provided in the Lambda function VPC configuration
    is invalid.
    """

    Type: Optional[String]
    Message: Optional[String]


class InvalidSubnetIDException(ServiceException):
    """The Subnet ID provided in the Lambda function VPC configuration is
    invalid.
    """

    Type: Optional[String]
    Message: Optional[String]


class InvalidZipFileException(ServiceException):
    """Lambda could not unzip the deployment package."""

    Type: Optional[String]
    Message: Optional[String]


class KMSAccessDeniedException(ServiceException):
    """Lambda was unable to decrypt the environment variables because KMS
    access was denied. Check the Lambda function's KMS permissions.
    """

    Type: Optional[String]
    Message: Optional[String]


class KMSDisabledException(ServiceException):
    """Lambda was unable to decrypt the environment variables because the KMS
    key used is disabled. Check the Lambda function's KMS key settings.
    """

    Type: Optional[String]
    Message: Optional[String]


class KMSInvalidStateException(ServiceException):
    """Lambda was unable to decrypt the environment variables because the KMS
    key used is in an invalid state for Decrypt. Check the function's KMS
    key settings.
    """

    Type: Optional[String]
    Message: Optional[String]


class KMSNotFoundException(ServiceException):
    """Lambda was unable to decrypt the environment variables because the KMS
    key was not found. Check the function's KMS key settings.
    """

    Type: Optional[String]
    Message: Optional[String]


class PolicyLengthExceededException(ServiceException):
    """The permissions policy for the resource is too large. `Learn
    more <https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`__
    """

    Type: Optional[String]
    message: Optional[String]


class PreconditionFailedException(ServiceException):
    """The RevisionId provided does not match the latest RevisionId for the
    Lambda function or alias. Call the ``GetFunction`` or the ``GetAlias``
    API to retrieve the latest RevisionId for your resource.
    """

    Type: Optional[String]
    message: Optional[String]


class ProvisionedConcurrencyConfigNotFoundException(ServiceException):
    """The specified configuration does not exist."""

    Type: Optional[String]
    message: Optional[String]


class RequestTooLargeException(ServiceException):
    """The request payload exceeded the ``Invoke`` request body JSON input
    limit. For more information, see
    `Limits <https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`__.
    """

    Type: Optional[String]
    message: Optional[String]


class ResourceConflictException(ServiceException):
    """The resource already exists, or another operation is in progress."""

    Type: Optional[String]
    message: Optional[String]


class ResourceInUseException(ServiceException):
    """The operation conflicts with the resource's availability. For example,
    you attempted to update an EventSource Mapping in CREATING, or tried to
    delete a EventSource mapping currently in the UPDATING state.
    """

    Type: Optional[String]
    Message: Optional[String]


class ResourceNotFoundException(ServiceException):
    """The resource specified in the request does not exist."""

    Type: Optional[String]
    Message: Optional[String]


class ResourceNotReadyException(ServiceException):
    """The function is inactive and its VPC connection is no longer available.
    Wait for the VPC connection to reestablish and try again.
    """

    Type: Optional[String]
    message: Optional[String]


class ServiceException(ServiceException):
    """The Lambda service encountered an internal error."""

    Type: Optional[String]
    Message: Optional[String]


class SubnetIPAddressLimitReachedException(ServiceException):
    """Lambda was not able to set up VPC access for the Lambda function because
    one or more configured subnets has no available IP addresses.
    """

    Type: Optional[String]
    Message: Optional[String]


class TooManyRequestsException(ServiceException):
    """The request throughput limit was exceeded."""

    retryAfterSeconds: Optional[String]
    Type: Optional[String]
    message: Optional[String]
    Reason: Optional[ThrottleReason]


class UnsupportedMediaTypeException(ServiceException):
    """The content type of the ``Invoke`` request body is not JSON."""

    Type: Optional[String]
    message: Optional[String]


Long = int


class AccountLimit(TypedDict, total=False):
    """Limits that are related to concurrency and storage. All file and storage
    sizes are in bytes.
    """

    TotalCodeSize: Optional[Long]
    CodeSizeUnzipped: Optional[Long]
    CodeSizeZipped: Optional[Long]
    ConcurrentExecutions: Optional[Integer]
    UnreservedConcurrentExecutions: Optional[UnreservedConcurrentExecutions]


class AccountUsage(TypedDict, total=False):
    """The number of functions and amount of storage in use."""

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


class AddPermissionResponse(TypedDict, total=False):
    Statement: Optional[String]


AdditionalVersionWeights = Dict[AdditionalVersion, Weight]


class AliasRoutingConfiguration(TypedDict, total=False):
    """The
    `traffic-shifting <https://docs.aws.amazon.com/lambda/latest/dg/lambda-traffic-shifting-using-aliases.html>`__
    configuration of a Lambda function alias.
    """

    AdditionalVersionWeights: Optional[AdditionalVersionWeights]


class AliasConfiguration(TypedDict, total=False):
    """Provides configuration information about a Lambda function
    `alias <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__.
    """

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
    """List of signing profiles that can sign a code package."""

    SigningProfileVersionArns: SigningProfileVersionArns


ArchitecturesList = List[Architecture]
Blob = bytes
BlobStream = bytes


class CodeSigningPolicies(TypedDict, total=False):
    """Code signing configuration
    `policies <https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-policies>`__
    specify the validation failure action for signature mismatch or expiry.
    """

    UntrustedArtifactOnDeployment: Optional[CodeSigningPolicy]


class CodeSigningConfig(TypedDict, total=False):
    """Details about a `Code signing
    configuration <https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html>`__.
    """

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
    """The self-managed Apache Kafka cluster for your event source."""

    Endpoints: Optional[Endpoints]


class SourceAccessConfiguration(TypedDict, total=False):
    """To secure and define access to your event source, you can specify the
    authentication protocol, VPC components, or virtual host.
    """

    Type: Optional[SourceAccessType]
    URI: Optional[URI]


SourceAccessConfigurations = List[SourceAccessConfiguration]
Queues = List[Queue]
Topics = List[Topic]


class OnFailure(TypedDict, total=False):
    """A destination for events that failed processing."""

    Destination: Optional[DestinationArn]


class OnSuccess(TypedDict, total=False):
    """A destination for events that were processed successfully."""

    Destination: Optional[DestinationArn]


class DestinationConfig(TypedDict, total=False):
    """A configuration object that specifies the destination of an event after
    Lambda processes it.
    """

    OnSuccess: Optional[OnSuccess]
    OnFailure: Optional[OnFailure]


Date = datetime


class CreateEventSourceMappingRequest(ServiceRequest):
    EventSourceArn: Optional[Arn]
    FunctionName: FunctionName
    Enabled: Optional[Enabled]
    BatchSize: Optional[BatchSize]
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


StringList = List[String]


class ImageConfig(TypedDict, total=False):
    """Configuration values that override the container image Dockerfile
    settings. See `Container
    settings <https://docs.aws.amazon.com/lambda/latest/dg/images-create.html#images-parms>`__.
    """

    EntryPoint: Optional[StringList]
    Command: Optional[StringList]
    WorkingDirectory: Optional[WorkingDirectory]


class FileSystemConfig(TypedDict, total=False):
    """Details about the connection between a Lambda function and an `Amazon
    EFS file
    system <https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html>`__.
    """

    Arn: FileSystemArn
    LocalMountPath: LocalMountPath


FileSystemConfigList = List[FileSystemConfig]
LayerList = List[LayerVersionArn]
Tags = Dict[TagKey, TagValue]


class TracingConfig(TypedDict, total=False):
    """The function's
    `X-Ray <https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html>`__
    tracing configuration. To sample and record incoming requests, set
    ``Mode`` to ``Active``.
    """

    Mode: Optional[TracingMode]


EnvironmentVariables = Dict[EnvironmentVariableName, EnvironmentVariableValue]


class Environment(TypedDict, total=False):
    """A function's environment variable settings. You can use environment
    variables to adjust your function's behavior without updating code. An
    environment variable is a pair of strings that are stored in a
    function's version-specific configuration.
    """

    Variables: Optional[EnvironmentVariables]


class DeadLetterConfig(TypedDict, total=False):
    """The `dead-letter
    queue <https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#dlq>`__
    for failed asynchronous invocations.
    """

    TargetArn: Optional[ResourceArn]


SecurityGroupIds = List[SecurityGroupId]
SubnetIds = List[SubnetId]


class VpcConfig(TypedDict, total=False):
    """The VPC security groups and subnets that are attached to a Lambda
    function. For more information, see `VPC
    Settings <https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html>`__.
    """

    SubnetIds: Optional[SubnetIds]
    SecurityGroupIds: Optional[SecurityGroupIds]


class FunctionCode(TypedDict, total=False):
    """The code for the Lambda function. You can specify either an object in
    Amazon S3, upload a .zip file archive deployment package directly, or
    specify the URI of a container image.
    """

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


class CreateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]
    AuthorizationType: AuthorizationType
    Cors: Optional[Cors]


class CreateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthorizationType: AuthorizationType
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
    """Error messages for environment variables that couldn't be applied."""

    ErrorCode: Optional[String]
    Message: Optional[SensitiveString]


class EnvironmentResponse(TypedDict, total=False):
    """The results of an operation to update or read environment variables. If
    the operation is successful, the response contains the environment
    variables. If it failed, the response contains details about the error.
    """

    Variables: Optional[EnvironmentVariables]
    Error: Optional[EnvironmentError]


class EventSourceMappingConfiguration(TypedDict, total=False):
    """A mapping between an Amazon Web Services resource and a Lambda function.
    For details, see CreateEventSourceMapping.
    """

    UUID: Optional[String]
    StartingPosition: Optional[EventSourcePosition]
    StartingPositionTimestamp: Optional[Date]
    BatchSize: Optional[BatchSize]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ParallelizationFactor: Optional[ParallelizationFactor]
    EventSourceArn: Optional[Arn]
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
    """Details about a function's deployment package."""

    RepositoryType: Optional[String]
    Location: Optional[String]
    ImageUri: Optional[String]
    ResolvedImageUri: Optional[String]


class ImageConfigError(TypedDict, total=False):
    """Error response to GetFunctionConfiguration."""

    ErrorCode: Optional[String]
    Message: Optional[SensitiveString]


class ImageConfigResponse(TypedDict, total=False):
    """Response to GetFunctionConfiguration request."""

    ImageConfig: Optional[ImageConfig]
    Error: Optional[ImageConfigError]


class Layer(TypedDict, total=False):
    """An `Lambda
    layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
    """

    Arn: Optional[LayerVersionArn]
    CodeSize: Optional[Long]
    SigningProfileVersionArn: Optional[Arn]
    SigningJobArn: Optional[Arn]


LayersReferenceList = List[Layer]


class TracingConfigResponse(TypedDict, total=False):
    """The function's X-Ray tracing configuration."""

    Mode: Optional[TracingMode]


class VpcConfigResponse(TypedDict, total=False):
    """The VPC security groups and subnets that are attached to a Lambda
    function.
    """

    SubnetIds: Optional[SubnetIds]
    SecurityGroupIds: Optional[SecurityGroupIds]
    VpcId: Optional[VpcId]


class FunctionConfiguration(TypedDict, total=False):
    """Details about a function's configuration."""

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
    AuthorizationType: AuthorizationType


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
    AuthorizationType: AuthorizationType
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
    """Details about a version of an `Lambda
    layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
    """

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
    """A success response (``202 Accepted``) indicates that the request is
    queued for invocation.
    """

    Status: Optional[HttpStatus]


class LayerVersionContentInput(TypedDict, total=False):
    """A ZIP archive that contains the contents of an `Lambda
    layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
    You can specify either an Amazon S3 location, or upload a layer archive
    directly.
    """

    S3Bucket: Optional[S3Bucket]
    S3Key: Optional[S3Key]
    S3ObjectVersion: Optional[S3ObjectVersion]
    ZipFile: Optional[Blob]


class LayerVersionsListItem(TypedDict, total=False):
    """Details about a version of an `Lambda
    layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
    """

    LayerVersionArn: Optional[LayerVersionArn]
    Version: Optional[LayerVersionNumber]
    Description: Optional[Description]
    CreatedDate: Optional[Timestamp]
    CompatibleRuntimes: Optional[CompatibleRuntimes]
    LicenseInfo: Optional[LicenseInfo]
    CompatibleArchitectures: Optional[CompatibleArchitectures]


LayerVersionsList = List[LayerVersionsListItem]


class LayersListItem(TypedDict, total=False):
    """Details about an `Lambda
    layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
    """

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
    """A list of Lambda functions."""

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
    """Details about the provisioned concurrency configuration for a function
    alias or version.
    """

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


class UpdateFunctionEventInvokeConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[Qualifier]
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]
    DestinationConfig: Optional[DestinationConfig]


class UpdateFunctionUrlConfigRequest(ServiceRequest):
    FunctionName: FunctionName
    Qualifier: Optional[FunctionUrlQualifier]
    AuthorizationType: Optional[AuthorizationType]
    Cors: Optional[Cors]


class UpdateFunctionUrlConfigResponse(TypedDict, total=False):
    FunctionUrl: FunctionUrl
    FunctionArn: FunctionArn
    AuthorizationType: AuthorizationType
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
        """Adds permissions to the resource-based policy of a version of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
        Use this action to grant layer usage permission to other accounts. You
        can grant permission to a single account, all accounts in an
        organization, or all Amazon Web Services accounts.

        To revoke permission, call RemoveLayerVersionPermission with the
        statement ID that you specified when you added it.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param version_number: The version number.
        :param statement_id: An identifier that distinguishes the policy from others on the same
        layer version.
        :param action: The API action that grants access to the layer.
        :param principal: An account ID, or ``*`` to grant layer usage permission to all accounts
        in an organization, or all Amazon Web Services accounts (if
        ``organizationId`` is not specified).
        :param organization_id: With the principal set to ``*``, grant permission to all accounts in the
        specified organization.
        :param revision_id: Only update the policy if the revision ID matches the ID specified.
        :returns: AddLayerVersionPermissionResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        :raises PolicyLengthExceededException:
        :raises PreconditionFailedException:
        """
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
    ) -> AddPermissionResponse:
        """Grants an Amazon Web Services service or another account permission to
        use a function. You can apply the policy at the function level, or
        specify a qualifier to restrict access to a single version or alias. If
        you use a qualifier, the invoker must use the full Amazon Resource Name
        (ARN) of that version or alias to invoke the function. Note: Lambda does
        not support adding policies to version $LATEST.

        To grant permission to another account, specify the account ID as the
        ``Principal``. For Amazon Web Services services, the principal is a
        domain-style identifier defined by the service, like
        ``s3.amazonaws.com`` or ``sns.amazonaws.com``. For Amazon Web Services
        services, you can also specify the ARN of the associated resource as the
        ``SourceArn``. If you grant permission to a service principal without
        specifying the source, other accounts could potentially configure
        resources in their account to invoke your Lambda function.

        This action adds a statement to a resource-based permissions policy for
        the function. For more information about function policies, see `Lambda
        Function
        Policies <https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html>`__.

        :param function_name: The name of the Lambda function, version, or alias.
        :param statement_id: A statement identifier that differentiates the statement from others in
        the same policy.
        :param action: The action that the principal can use on the function.
        :param principal: The Amazon Web Services service or account that invokes the function.
        :param source_arn: For Amazon Web Services services, the ARN of the Amazon Web Services
        resource that invokes the function.
        :param source_account: For Amazon S3, the ID of the account that owns the resource.
        :param event_source_token: For Alexa Smart Home functions, a token that must be supplied by the
        invoker.
        :param qualifier: Specify a version or alias to add permissions to a published version of
        the function.
        :param revision_id: Only update the policy if the revision ID matches the ID that's
        specified.
        :returns: AddPermissionResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        :raises InvalidParameterValueException:
        :raises PolicyLengthExceededException:
        :raises TooManyRequestsException:
        :raises PreconditionFailedException:
        """
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
        """Creates an
        `alias <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__
        for a Lambda function version. Use aliases to provide clients with a
        function identifier that you can update to invoke a different version.

        You can also map an alias to split invocation requests between two
        versions. Use the ``RoutingConfig`` parameter to specify a second
        version and the percentage of invocation requests that it receives.

        :param function_name: The name of the Lambda function.
        :param name: The name of the alias.
        :param function_version: The function version that the alias invokes.
        :param description: A description of the alias.
        :param routing_config: The `routing
        configuration <https://docs.
        :returns: AliasConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("CreateCodeSigningConfig")
    def create_code_signing_config(
        self,
        context: RequestContext,
        allowed_publishers: AllowedPublishers,
        description: Description = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> CreateCodeSigningConfigResponse:
        """Creates a code signing configuration. A `code signing
        configuration <https://docs.aws.amazon.com/lambda/latest/dg/configuration-trustedcode.html>`__
        defines a list of allowed signing profiles and defines the code-signing
        validation policy (action to be taken if deployment validation checks
        fail).

        :param allowed_publishers: Signing profiles for this code signing configuration.
        :param description: Descriptive name for this code signing configuration.
        :param code_signing_policies: The code signing policies define the actions to take if the validation
        checks fail.
        :returns: CreateCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("CreateEventSourceMapping")
    def create_event_source_mapping(
        self,
        context: RequestContext,
        function_name: FunctionName,
        event_source_arn: Arn = None,
        enabled: Enabled = None,
        batch_size: BatchSize = None,
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
        """Creates a mapping between an event source and an Lambda function. Lambda
        reads items from the event source and triggers the function.

        For details about how to configure different event sources, see the
        following topics.

        -  `Amazon DynamoDB
           Streams <https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html#services-dynamodb-eventsourcemapping>`__

        -  `Amazon
           Kinesis <https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-eventsourcemapping>`__

        -  `Amazon
           SQS <https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#events-sqs-eventsource>`__

        -  `Amazon MQ and
           RabbitMQ <https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html#services-mq-eventsourcemapping>`__

        -  `Amazon
           MSK <https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html>`__

        -  `Apache
           Kafka <https://docs.aws.amazon.com/lambda/latest/dg/kafka-smaa.html>`__

        The following error handling options are only available for stream
        sources (DynamoDB and Kinesis):

        -  ``BisectBatchOnFunctionError`` - If the function returns an error,
           split the batch in two and retry.

        -  ``DestinationConfig`` - Send discarded records to an Amazon SQS queue
           or Amazon SNS topic.

        -  ``MaximumRecordAgeInSeconds`` - Discard records older than the
           specified age. The default value is infinite (-1). When set to
           infinite (-1), failed records are retried until the record expires

        -  ``MaximumRetryAttempts`` - Discard records after the specified number
           of retries. The default value is infinite (-1). When set to infinite
           (-1), failed records are retried until the record expires.

        -  ``ParallelizationFactor`` - Process multiple batches from each shard
           concurrently.

        For information about which configuration parameters apply to each event
        source, see the following topics.

        -  `Amazon DynamoDB
           Streams <https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html#services-ddb-params>`__

        -  `Amazon
           Kinesis <https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-params>`__

        -  `Amazon
           SQS <https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#services-sqs-params>`__

        -  `Amazon MQ and
           RabbitMQ <https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html#services-mq-params>`__

        -  `Amazon
           MSK <https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html#services-msk-parms>`__

        -  `Apache
           Kafka <https://docs.aws.amazon.com/lambda/latest/dg/with-kafka.html#services-kafka-parms>`__

        :param function_name: The name of the Lambda function.
        :param event_source_arn: The Amazon Resource Name (ARN) of the event source.
        :param enabled: When true, the event source mapping is active.
        :param batch_size: The maximum number of records in each batch that Lambda pulls from your
        stream or queue and sends to your function.
        :param maximum_batching_window_in_seconds: (Streams and Amazon SQS standard queues) The maximum amount of time, in
        seconds, that Lambda spends gathering records before invoking the
        function.
        :param parallelization_factor: (Streams only) The number of batches to process from each shard
        concurrently.
        :param starting_position: The position in a stream from which to start reading.
        :param starting_position_timestamp: With ``StartingPosition`` set to ``AT_TIMESTAMP``, the time from which
        to start reading.
        :param destination_config: (Streams only) An Amazon SQS queue or Amazon SNS topic destination for
        discarded records.
        :param maximum_record_age_in_seconds: (Streams only) Discard records older than the specified age.
        :param bisect_batch_on_function_error: (Streams only) If the function returns an error, split the batch in two
        and retry.
        :param maximum_retry_attempts: (Streams only) Discard records after the specified number of retries.
        :param tumbling_window_in_seconds: (Streams only) The duration in seconds of a processing window.
        :param topics: The name of the Kafka topic.
        :param queues: (MQ) The name of the Amazon MQ broker destination queue to consume.
        :param source_access_configurations: An array of authentication protocols or VPC components required to
        secure your event source.
        :param self_managed_event_source: The Self-Managed Apache Kafka cluster to send records.
        :param function_response_types: (Streams only) A list of current response type enums applied to the
        event source mapping.
        :returns: EventSourceMappingConfiguration
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceConflictException:
        :raises TooManyRequestsException:
        :raises ResourceNotFoundException:
        """
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
    ) -> FunctionConfiguration:
        """Creates a Lambda function. To create a function, you need a `deployment
        package <https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html>`__
        and an `execution
        role <https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#lambda-intro-execution-role>`__.
        The deployment package is a .zip file archive or container image that
        contains your function code. The execution role grants the function
        permission to use Amazon Web Services services, such as Amazon
        CloudWatch Logs for log streaming and X-Ray for request tracing.

        You set the package type to ``Image`` if the deployment package is a
        `container
        image <https://docs.aws.amazon.com/lambda/latest/dg/lambda-images.html>`__.
        For a container image, the code property must include the URI of a
        container image in the Amazon ECR registry. You do not need to specify
        the handler and runtime properties.

        You set the package type to ``Zip`` if the deployment package is a `.zip
        file
        archive <https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html#gettingstarted-package-zip>`__.
        For a .zip file archive, the code property specifies the location of the
        .zip file. You must also specify the handler and runtime properties. The
        code in the deployment package must be compatible with the target
        instruction set architecture of the function (``x86-64`` or ``arm64``).
        If you do not specify the architecture, the default value is ``x86-64``.

        When you create a function, Lambda provisions an instance of the
        function and its supporting resources. If your function connects to a
        VPC, this process can take a minute or so. During this time, you can't
        invoke or modify the function. The ``State``, ``StateReason``, and
        ``StateReasonCode`` fields in the response from GetFunctionConfiguration
        indicate when the function is ready to invoke. For more information, see
        `Function
        States <https://docs.aws.amazon.com/lambda/latest/dg/functions-states.html>`__.

        A function has an unpublished version, and can have published versions
        and aliases. The unpublished version changes when you update your
        function's code and configuration. A published version is a snapshot of
        your function code and configuration that can't be changed. An alias is
        a named resource that maps to a version, and can be changed to map to a
        different version. Use the ``Publish`` parameter to create version ``1``
        of your function from its initial configuration.

        The other parameters let you configure version-specific and
        function-level settings. You can modify version-specific settings later
        with UpdateFunctionConfiguration. Function-level settings apply to both
        the unpublished and published versions of the function, and include tags
        (TagResource) and per-function concurrency limits
        (PutFunctionConcurrency).

        You can use code signing if your deployment package is a .zip file
        archive. To enable code signing for this function, specify the ARN of a
        code-signing configuration. When a user attempts to deploy a code
        package with UpdateFunctionCode, Lambda checks that the code package has
        a valid signature from a trusted publisher. The code-signing
        configuration includes set set of signing profiles, which define the
        trusted publishers for this function.

        If another account or an Amazon Web Services service invokes your
        function, use AddPermission to grant permission by creating a
        resource-based IAM policy. You can grant permissions at the function
        level, on a version, or on an alias.

        To invoke your function directly, use Invoke. To invoke your function in
        response to events in other Amazon Web Services services, create an
        event source mapping (CreateEventSourceMapping), or configure a function
        trigger in the other service. For more information, see `Invoking
        Functions <https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html>`__.

        :param function_name: The name of the Lambda function.
        :param role: The Amazon Resource Name (ARN) of the function's execution role.
        :param code: The code for the function.
        :param runtime: The identifier of the function's
        `runtime <https://docs.
        :param handler: The name of the method within your code that Lambda calls to execute
        your function.
        :param description: A description of the function.
        :param timeout: The amount of time (in seconds) that Lambda allows a function to run
        before stopping it.
        :param memory_size: The amount of `memory available to the
        function <https://docs.
        :param publish: Set to true to publish the first version of the function during
        creation.
        :param vpc_config: For network connectivity to Amazon Web Services resources in a VPC,
        specify a list of security groups and subnets in the VPC.
        :param package_type: The type of deployment package.
        :param dead_letter_config: A dead letter queue configuration that specifies the queue or topic
        where Lambda sends asynchronous events when they fail processing.
        :param environment: Environment variables that are accessible from function code during
        execution.
        :param kms_key_arn: The ARN of the Amazon Web Services Key Management Service (KMS) key
        that's used to encrypt your function's environment variables.
        :param tracing_config: Set ``Mode`` to ``Active`` to sample and trace a subset of incoming
        requests with
        `X-Ray <https://docs.
        :param tags: A list of
        `tags <https://docs.
        :param layers: A list of `function
        layers <https://docs.
        :param file_system_configs: Connection settings for an Amazon EFS file system.
        :param image_config: Container image `configuration
        values <https://docs.
        :param code_signing_config_arn: To enable code signing for this function, specify the ARN of a
        code-signing configuration.
        :param architectures: The instruction set architecture that the function supports.
        :returns: FunctionConfiguration
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        :raises TooManyRequestsException:
        :raises CodeStorageExceededException:
        :raises CodeVerificationFailedException:
        :raises InvalidCodeSignatureException:
        :raises CodeSigningConfigNotFoundException:
        """
        raise NotImplementedError

    @handler("CreateFunctionUrlConfig")
    def create_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        authorization_type: AuthorizationType,
        qualifier: FunctionUrlQualifier = None,
        cors: Cors = None,
    ) -> CreateFunctionUrlConfigResponse:
        """

        :param function_name: .
        :param authorization_type: .
        :param qualifier: .
        :param cors: .
        :returns: CreateFunctionUrlConfigResponse
        :raises ResourceConflictException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises ServiceException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("DeleteAlias")
    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        """Deletes a Lambda function
        `alias <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__.

        :param function_name: The name of the Lambda function.
        :param name: The name of the alias.
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceConflictException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("DeleteCodeSigningConfig")
    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> DeleteCodeSigningConfigResponse:
        """Deletes the code signing configuration. You can delete the code signing
        configuration only if no function is using it.

        :param code_signing_config_arn: The The Amazon Resource Name (ARN) of the code signing configuration.
        :returns: DeleteCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("DeleteEventSourceMapping")
    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        """Deletes an `event source
        mapping <https://docs.aws.amazon.com/lambda/latest/dg/intro-invocation-modes.html>`__.
        You can get the identifier of a mapping from the output of
        ListEventSourceMappings.

        When you delete an event source mapping, it enters a ``Deleting`` state
        and might not be completely deleted for several seconds.

        :param uuid: The identifier of the event source mapping.
        :returns: EventSourceMappingConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceInUseException:
        """
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        """Deletes a Lambda function. To delete a specific function version, use
        the ``Qualifier`` parameter. Otherwise, all versions and aliases are
        deleted.

        To delete Lambda event source mappings that invoke a function, use
        DeleteEventSourceMapping. For Amazon Web Services services and resources
        that invoke your function directly, delete the trigger in the service
        where you originally configured it.

        :param function_name: The name of the Lambda function or version.
        :param qualifier: Specify a version to delete.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("DeleteFunctionCodeSigningConfig")
    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        """Removes the code signing configuration from the function.

        :param function_name: The name of the Lambda function.
        :raises InvalidParameterValueException:
        :raises CodeSigningConfigNotFoundException:
        :raises ResourceNotFoundException:
        :raises ServiceException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("DeleteFunctionConcurrency")
    def delete_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        """Removes a concurrent execution limit from a function.

        :param function_name: The name of the Lambda function.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("DeleteFunctionEventInvokeConfig")
    def delete_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        """Deletes the configuration for asynchronous invocation for a function,
        version, or alias.

        To configure options for asynchronous invocation, use
        PutFunctionEventInvokeConfig.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: A version number or alias name.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("DeleteFunctionUrlConfig")
    def delete_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> None:
        """

        :param function_name: .
        :param qualifier: .
        :raises ResourceConflictException:
        :raises ResourceNotFoundException:
        :raises ServiceException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("DeleteLayerVersion")
    def delete_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
    ) -> None:
        """Deletes a version of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
        Deleted versions can no longer be viewed or added to functions. To avoid
        breaking functions, a copy of the version remains in Lambda until no
        functions refer to it.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param version_number: The version number.
        :raises ServiceException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("DeleteProvisionedConcurrencyConfig")
    def delete_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> None:
        """Deletes the provisioned concurrency configuration for a function.

        :param function_name: The name of the Lambda function.
        :param qualifier: The version number or alias name.
        :raises InvalidParameterValueException:
        :raises ResourceConflictException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
        raise NotImplementedError

    @handler("GetAccountSettings")
    def get_account_settings(
        self,
        context: RequestContext,
    ) -> GetAccountSettingsResponse:
        """Retrieves details about your account's
        `limits <https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`__
        and usage in an Amazon Web Services Region.

        :returns: GetAccountSettingsResponse
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
        raise NotImplementedError

    @handler("GetAlias")
    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        """Returns details about a Lambda function
        `alias <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__.

        :param function_name: The name of the Lambda function.
        :param name: The name of the alias.
        :returns: AliasConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("GetCodeSigningConfig")
    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> GetCodeSigningConfigResponse:
        """Returns information about the specified code signing configuration.

        :param code_signing_config_arn: The The Amazon Resource Name (ARN) of the code signing configuration.
        :returns: GetCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("GetEventSourceMapping")
    def get_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        """Returns details about an event source mapping. You can get the
        identifier of a mapping from the output of ListEventSourceMappings.

        :param uuid: The identifier of the event source mapping.
        :returns: EventSourceMappingConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetFunctionResponse:
        """Returns information about the function or function version, with a link
        to download the deployment package that's valid for 10 minutes. If you
        specify a function version, only details that are specific to that
        version are returned.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: Specify a version or alias to get details about a published version of
        the function.
        :returns: GetFunctionResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("GetFunctionCodeSigningConfig")
    def get_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionCodeSigningConfigResponse:
        """Returns the code signing configuration for the specified function.

        :param function_name: The name of the Lambda function.
        :returns: GetFunctionCodeSigningConfigResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises ServiceException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("GetFunctionConcurrency")
    def get_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionConcurrencyResponse:
        """Returns details about the reserved concurrency configuration for a
        function. To set a concurrency limit for a function, use
        PutFunctionConcurrency.

        :param function_name: The name of the Lambda function.
        :returns: GetFunctionConcurrencyResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
        raise NotImplementedError

    @handler("GetFunctionConfiguration")
    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> FunctionConfiguration:
        """Returns the version-specific settings of a Lambda function or version.
        The output includes only options that can vary between versions of a
        function. To modify these settings, use UpdateFunctionConfiguration.

        To get all of a function's details, including function-level settings,
        use GetFunction.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: Specify a version or alias to get details about a published version of
        the function.
        :returns: FunctionConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("GetFunctionEventInvokeConfig")
    def get_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> FunctionEventInvokeConfig:
        """Retrieves the configuration for asynchronous invocation for a function,
        version, or alias.

        To configure options for asynchronous invocation, use
        PutFunctionEventInvokeConfig.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: A version number or alias name.
        :returns: FunctionEventInvokeConfig
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("GetFunctionUrlConfig")
    def get_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> GetFunctionUrlConfigResponse:
        """

        :param function_name: .
        :param qualifier: .
        :returns: GetFunctionUrlConfigResponse
        :raises InvalidParameterValueException:
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("GetLayerVersion")
    def get_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
    ) -> GetLayerVersionResponse:
        """Returns information about a version of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__,
        with a link to download the layer archive that's valid for 10 minutes.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param version_number: The version number.
        :returns: GetLayerVersionResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("GetLayerVersionByArn")
    def get_layer_version_by_arn(
        self, context: RequestContext, arn: LayerVersionArn
    ) -> GetLayerVersionResponse:
        """Returns information about a version of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__,
        with a link to download the layer archive that's valid for 10 minutes.

        :param arn: The ARN of the layer version.
        :returns: GetLayerVersionResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("GetLayerVersionPolicy")
    def get_layer_version_policy(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
    ) -> GetLayerVersionPolicyResponse:
        """Returns the permission policy for a version of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
        For more information, see AddLayerVersionPermission.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param version_number: The version number.
        :returns: GetLayerVersionPolicyResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetPolicyResponse:
        """Returns the `resource-based IAM
        policy <https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html>`__
        for a function, version, or alias.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: Specify a version or alias to get the policy for that resource.
        :returns: GetPolicyResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("GetProvisionedConcurrencyConfig")
    def get_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> GetProvisionedConcurrencyConfigResponse:
        """Retrieves the provisioned concurrency configuration for a function's
        alias or version.

        :param function_name: The name of the Lambda function.
        :param qualifier: The version number or alias name.
        :returns: GetProvisionedConcurrencyConfigResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        :raises ProvisionedConcurrencyConfigNotFoundException:
        """
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
        """Invokes a Lambda function. You can invoke a function synchronously (and
        wait for the response), or asynchronously. To invoke a function
        asynchronously, set ``InvocationType`` to ``Event``.

        For `synchronous
        invocation <https://docs.aws.amazon.com/lambda/latest/dg/invocation-sync.html>`__,
        details about the function response, including errors, are included in
        the response body and headers. For either invocation type, you can find
        more information in the `execution
        log <https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html>`__
        and
        `trace <https://docs.aws.amazon.com/lambda/latest/dg/lambda-x-ray.html>`__.

        When an error occurs, your function may be invoked multiple times. Retry
        behavior varies by error type, client, event source, and invocation
        type. For example, if you invoke a function asynchronously and it
        returns an error, Lambda executes the function up to two more times. For
        more information, see `Retry
        Behavior <https://docs.aws.amazon.com/lambda/latest/dg/retries-on-errors.html>`__.

        For `asynchronous
        invocation <https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html>`__,
        Lambda adds events to a queue before sending them to your function. If
        your function does not have enough capacity to keep up with the queue,
        events may be lost. Occasionally, your function may receive the same
        event multiple times, even if no error occurs. To retain events that
        were not processed, configure your function with a `dead-letter
        queue <https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#dlq>`__.

        The status code in the API response doesn't reflect function errors.
        Error codes are reserved for errors that prevent your function from
        executing, such as permissions errors, `limit
        errors <https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`__, or
        issues with your function's code and configuration. For example, Lambda
        returns ``TooManyRequestsException`` if executing the function would
        cause you to exceed a concurrency limit at either the account level
        (``ConcurrentInvocationLimitExceeded``) or function level
        (``ReservedFunctionConcurrentInvocationLimitExceeded``).

        For functions with a long timeout, your client might be disconnected
        during synchronous invocation while it waits for a response. Configure
        your HTTP client, SDK, firewall, proxy, or operating system to allow for
        long connections with timeout or keep-alive settings.

        This operation requires permission for the
        `lambda:InvokeFunction <https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awslambda.html>`__
        action.

        :param function_name: The name of the Lambda function, version, or alias.
        :param invocation_type: Choose from the following options.
        :param log_type: Set to ``Tail`` to include the execution log in the response.
        :param client_context: Up to 3583 bytes of base64-encoded data about the invoking client to
        pass to the function in the context object.
        :param payload: The JSON that you want to provide to your Lambda function as input.
        :param qualifier: Specify a version or alias to invoke a published version of the
        function.
        :returns: InvocationResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidRequestContentException:
        :raises RequestTooLargeException:
        :raises UnsupportedMediaTypeException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        :raises EC2UnexpectedException:
        :raises SubnetIPAddressLimitReachedException:
        :raises ENILimitReachedException:
        :raises EFSMountConnectivityException:
        :raises EFSMountFailureException:
        :raises EFSMountTimeoutException:
        :raises EFSIOException:
        :raises EC2ThrottledException:
        :raises EC2AccessDeniedException:
        :raises InvalidSubnetIDException:
        :raises InvalidSecurityGroupIDException:
        :raises InvalidZipFileException:
        :raises KMSDisabledException:
        :raises KMSInvalidStateException:
        :raises KMSAccessDeniedException:
        :raises KMSNotFoundException:
        :raises InvalidRuntimeException:
        :raises ResourceConflictException:
        :raises ResourceNotReadyException:
        """
        raise NotImplementedError

    @handler("InvokeAsync")
    def invoke_async(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invoke_args: BlobStream,
    ) -> InvokeAsyncResponse:
        """For asynchronous function invocation, use Invoke.

        Invokes a function asynchronously.

        :param function_name: The name of the Lambda function.
        :param invoke_args: The JSON that you want to provide to your Lambda function as input.
        :returns: InvokeAsyncResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidRequestContentException:
        :raises InvalidRuntimeException:
        :raises ResourceConflictException:
        """
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
        """Returns a list of
        `aliases <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__
        for a Lambda function.

        :param function_name: The name of the Lambda function.
        :param function_version: Specify a function version to only list aliases that invoke that
        version.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: Limit the number of aliases returned.
        :returns: ListAliasesResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("ListCodeSigningConfigs")
    def list_code_signing_configs(
        self,
        context: RequestContext,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListCodeSigningConfigsResponse:
        """Returns a list of `code signing
        configurations <https://docs.aws.amazon.com/lambda/latest/dg/configuring-codesigning.html>`__.
        A request returns up to 10,000 configurations per call. You can use the
        ``MaxItems`` parameter to return fewer configurations per call.

        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: Maximum number of items to return.
        :returns: ListCodeSigningConfigsResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        """
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
        """Lists event source mappings. Specify an ``EventSourceArn`` to only show
        event source mappings for a single event source.

        :param event_source_arn: The Amazon Resource Name (ARN) of the event source.
        :param function_name: The name of the Lambda function.
        :param marker: A pagination token returned by a previous call.
        :param max_items: The maximum number of event source mappings to return.
        :returns: ListEventSourceMappingsResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("ListFunctionEventInvokeConfigs")
    def list_function_event_invoke_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxFunctionEventInvokeConfigListItems = None,
    ) -> ListFunctionEventInvokeConfigsResponse:
        """Retrieves a list of configurations for asynchronous invocation for a
        function.

        To configure options for asynchronous invocation, use
        PutFunctionEventInvokeConfig.

        :param function_name: The name of the Lambda function.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: The maximum number of configurations to return.
        :returns: ListFunctionEventInvokeConfigsResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
        raise NotImplementedError

    @handler("ListFunctionUrlConfigs")
    def list_function_url_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxItems = None,
    ) -> ListFunctionUrlConfigsResponse:
        """

        :param function_name: .
        :param marker: .
        :param max_items: .
        :returns: ListFunctionUrlConfigsResponse
        :raises InvalidParameterValueException:
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        """
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
        """Returns a list of Lambda functions, with the version-specific
        configuration of each. Lambda returns up to 50 functions per call.

        Set ``FunctionVersion`` to ``ALL`` to include all published versions of
        each function in addition to the unpublished version.

        The ``ListFunctions`` action returns a subset of the
        FunctionConfiguration fields. To get the additional fields (State,
        StateReasonCode, StateReason, LastUpdateStatus, LastUpdateStatusReason,
        LastUpdateStatusReasonCode) for a function or version, use GetFunction.

        :param master_region: For Lambda@Edge functions, the Amazon Web Services Region of the master
        function.
        :param function_version: Set to ``ALL`` to include entries for all published versions of each
        function.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: The maximum number of functions to return in the response.
        :returns: ListFunctionsResponse
        :raises ServiceException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        """
        raise NotImplementedError

    @handler("ListFunctionsByCodeSigningConfig")
    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        """List the functions that use the specified code signing configuration.
        You can use this method prior to deleting a code signing configuration,
        to verify that no functions are using it.

        :param code_signing_config_arn: The The Amazon Resource Name (ARN) of the code signing configuration.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: Maximum number of items to return.
        :returns: ListFunctionsByCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        """
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
        """Lists the versions of an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
        Versions that have been deleted aren't listed. Specify a `runtime
        identifier <https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html>`__
        to list only versions that indicate that they're compatible with that
        runtime. Specify a compatible architecture to include only layer
        versions that are compatible with that architecture.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param compatible_runtime: A runtime identifier.
        :param marker: A pagination token returned by a previous call.
        :param max_items: The maximum number of versions to return.
        :param compatible_architecture: The compatible `instruction set
        architecture <https://docs.
        :returns: ListLayerVersionsResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        """
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
        """Lists `Lambda
        layers <https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html>`__
        and shows information about the latest version of each. Specify a
        `runtime
        identifier <https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html>`__
        to list only layers that indicate that they're compatible with that
        runtime. Specify a compatible architecture to include only layers that
        are compatible with that `instruction set
        architecture <https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html>`__.

        :param compatible_runtime: A runtime identifier.
        :param marker: A pagination token returned by a previous call.
        :param max_items: The maximum number of layers to return.
        :param compatible_architecture: The compatible `instruction set
        architecture <https://docs.
        :returns: ListLayersResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("ListProvisionedConcurrencyConfigs")
    def list_provisioned_concurrency_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxProvisionedConcurrencyConfigListItems = None,
    ) -> ListProvisionedConcurrencyConfigsResponse:
        """Retrieves a list of provisioned concurrency configurations for a
        function.

        :param function_name: The name of the Lambda function.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: Specify a number to limit the number of configurations returned.
        :returns: ListProvisionedConcurrencyConfigsResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, resource: FunctionArn) -> ListTagsResponse:
        """Returns a function's
        `tags <https://docs.aws.amazon.com/lambda/latest/dg/tagging.html>`__.
        You can also view tags with GetFunction.

        :param resource: The function's Amazon Resource Name (ARN).
        :returns: ListTagsResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError

    @handler("ListVersionsByFunction")
    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListVersionsByFunctionResponse:
        """Returns a list of
        `versions <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__,
        with the version-specific configuration of each. Lambda returns up to 50
        versions per call.

        :param function_name: The name of the Lambda function.
        :param marker: Specify the pagination token that's returned by a previous request to
        retrieve the next page of results.
        :param max_items: The maximum number of versions to return.
        :returns: ListVersionsByFunctionResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        """
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
        """Creates an `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__
        from a ZIP archive. Each time you call ``PublishLayerVersion`` with the
        same layer name, a new version is created.

        Add layers to your function with CreateFunction or
        UpdateFunctionConfiguration.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param content: The function layer archive.
        :param description: The description of the version.
        :param compatible_runtimes: A list of compatible `function
        runtimes <https://docs.
        :param license_info: The layer's software license.
        :param compatible_architectures: A list of compatible `instruction set
        architectures <https://docs.
        :returns: PublishLayerVersionResponse
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises InvalidParameterValueException:
        :raises CodeStorageExceededException:
        """
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
        """Creates a
        `version <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__
        from the current code and configuration of a function. Use versions to
        create a snapshot of your function code and configuration that doesn't
        change.

        Lambda doesn't publish a version if the function's configuration and
        code haven't changed since the last version. Use UpdateFunctionCode or
        UpdateFunctionConfiguration to update the function before publishing a
        version.

        Clients can invoke versions directly or with an alias. To create an
        alias, use CreateAlias.

        :param function_name: The name of the Lambda function.
        :param code_sha256: Only publish a version if the hash value matches the value that's
        specified.
        :param description: A description for the version to override the description in the
        function configuration.
        :param revision_id: Only update the function if the revision ID matches the ID that's
        specified.
        :returns: FunctionConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises CodeStorageExceededException:
        :raises PreconditionFailedException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("PutFunctionCodeSigningConfig")
    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: FunctionName,
    ) -> PutFunctionCodeSigningConfigResponse:
        """Update the code signing configuration for the function. Changes to the
        code signing configuration take effect the next time a user tries to
        deploy a code package to the function.

        :param code_signing_config_arn: The The Amazon Resource Name (ARN) of the code signing configuration.
        :param function_name: The name of the Lambda function.
        :returns: PutFunctionCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        :raises CodeSigningConfigNotFoundException:
        """
        raise NotImplementedError

    @handler("PutFunctionConcurrency")
    def put_function_concurrency(
        self,
        context: RequestContext,
        function_name: FunctionName,
        reserved_concurrent_executions: ReservedConcurrentExecutions,
    ) -> Concurrency:
        """Sets the maximum number of simultaneous executions for a function, and
        reserves capacity for that concurrency level.

        Concurrency settings apply to the function as a whole, including all
        published versions and the unpublished version. Reserving concurrency
        both ensures that your function has capacity to process the specified
        number of events simultaneously, and prevents it from scaling beyond
        that level. Use GetFunction to see the current setting for a function.

        Use GetAccountSettings to see your Regional concurrency limit. You can
        reserve concurrency for as many functions as you like, as long as you
        leave at least 100 simultaneous executions unreserved for functions that
        aren't configured with a per-function limit. For more information, see
        `Managing
        Concurrency <https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html>`__.

        :param function_name: The name of the Lambda function.
        :param reserved_concurrent_executions: The number of simultaneous executions to reserve for the function.
        :returns: Concurrency
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
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
        """Configures options for `asynchronous
        invocation <https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html>`__
        on a function, version, or alias. If a configuration already exists for
        a function, version, or alias, this operation overwrites it. If you
        exclude any settings, they are removed. To set one option without
        affecting existing settings for other options, use
        UpdateFunctionEventInvokeConfig.

        By default, Lambda retries an asynchronous invocation twice if the
        function returns an error. It retains events in a queue for up to six
        hours. When an event fails all processing attempts or stays in the
        asynchronous invocation queue for too long, Lambda discards it. To
        retain discarded events, configure a dead-letter queue with
        UpdateFunctionConfiguration.

        To send an invocation record to a queue, topic, function, or event bus,
        specify a
        `destination <https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-async-destinations>`__.
        You can configure separate destinations for successful invocations
        (on-success) and events that fail all processing attempts (on-failure).
        You can configure destinations in addition to or instead of a
        dead-letter queue.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: A version number or alias name.
        :param maximum_retry_attempts: The maximum number of times to retry when the function returns an error.
        :param maximum_event_age_in_seconds: The maximum age of a request that Lambda sends to a function for
        processing.
        :param destination_config: A destination for events after they have been sent to a function for
        processing.
        :returns: FunctionEventInvokeConfig
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("PutProvisionedConcurrencyConfig")
    def put_provisioned_concurrency_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier,
        provisioned_concurrent_executions: PositiveInteger,
    ) -> PutProvisionedConcurrencyConfigResponse:
        """Adds a provisioned concurrency configuration to a function's alias or
        version.

        :param function_name: The name of the Lambda function.
        :param qualifier: The version number or alias name.
        :param provisioned_concurrent_executions: The amount of provisioned concurrency to allocate for the version or
        alias.
        :returns: PutProvisionedConcurrencyConfigResponse
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        :raises ResourceConflictException:
        :raises TooManyRequestsException:
        :raises ServiceException:
        """
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
        """Removes a statement from the permissions policy for a version of an
        `Lambda
        layer <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html>`__.
        For more information, see AddLayerVersionPermission.

        :param layer_name: The name or Amazon Resource Name (ARN) of the layer.
        :param version_number: The version number.
        :param statement_id: The identifier that was specified when the statement was added.
        :param revision_id: Only update the policy if the revision ID matches the ID specified.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises PreconditionFailedException:
        """
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
        """Revokes function-use permission from an Amazon Web Services service or
        another account. You can get the ID of the statement from the output of
        GetPolicy.

        :param function_name: The name of the Lambda function, version, or alias.
        :param statement_id: Statement ID of the permission to remove.
        :param qualifier: Specify a version or alias to remove permissions from a published
        version of the function.
        :param revision_id: Only update the policy if the revision ID matches the ID that's
        specified.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises PreconditionFailedException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource: FunctionArn, tags: Tags) -> None:
        """Adds
        `tags <https://docs.aws.amazon.com/lambda/latest/dg/tagging.html>`__ to
        a function.

        :param resource: The function's Amazon Resource Name (ARN).
        :param tags: A list of tags to apply to the function.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource: FunctionArn, tag_keys: TagKeyList
    ) -> None:
        """Removes
        `tags <https://docs.aws.amazon.com/lambda/latest/dg/tagging.html>`__
        from a function.

        :param resource: The function's Amazon Resource Name (ARN).
        :param tag_keys: A list of tag keys to remove from the function.
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
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
        """Updates the configuration of a Lambda function
        `alias <https://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`__.

        :param function_name: The name of the Lambda function.
        :param name: The name of the alias.
        :param function_version: The function version that the alias invokes.
        :param description: A description of the alias.
        :param routing_config: The `routing
        configuration <https://docs.
        :param revision_id: Only update the alias if the revision ID matches the ID that's
        specified.
        :returns: AliasConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises PreconditionFailedException:
        :raises ResourceConflictException:
        """
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
        """Update the code signing configuration. Changes to the code signing
        configuration take effect the next time a user tries to deploy a code
        package to the function.

        :param code_signing_config_arn: The The Amazon Resource Name (ARN) of the code signing configuration.
        :param description: Descriptive name for this code signing configuration.
        :param allowed_publishers: Signing profiles for this code signing configuration.
        :param code_signing_policies: The code signing policy.
        :returns: UpdateCodeSigningConfigResponse
        :raises ServiceException:
        :raises InvalidParameterValueException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("UpdateEventSourceMapping")
    def update_event_source_mapping(
        self,
        context: RequestContext,
        uuid: String,
        function_name: FunctionName = None,
        enabled: Enabled = None,
        batch_size: BatchSize = None,
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
        """Updates an event source mapping. You can change the function that Lambda
        invokes, or pause invocation and resume later from the same location.

        For details about how to configure different event sources, see the
        following topics.

        -  `Amazon DynamoDB
           Streams <https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html#services-dynamodb-eventsourcemapping>`__

        -  `Amazon
           Kinesis <https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-eventsourcemapping>`__

        -  `Amazon
           SQS <https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#events-sqs-eventsource>`__

        -  `Amazon MQ and
           RabbitMQ <https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html#services-mq-eventsourcemapping>`__

        -  `Amazon
           MSK <https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html>`__

        -  `Apache
           Kafka <https://docs.aws.amazon.com/lambda/latest/dg/kafka-smaa.html>`__

        The following error handling options are only available for stream
        sources (DynamoDB and Kinesis):

        -  ``BisectBatchOnFunctionError`` - If the function returns an error,
           split the batch in two and retry.

        -  ``DestinationConfig`` - Send discarded records to an Amazon SQS queue
           or Amazon SNS topic.

        -  ``MaximumRecordAgeInSeconds`` - Discard records older than the
           specified age. The default value is infinite (-1). When set to
           infinite (-1), failed records are retried until the record expires

        -  ``MaximumRetryAttempts`` - Discard records after the specified number
           of retries. The default value is infinite (-1). When set to infinite
           (-1), failed records are retried until the record expires.

        -  ``ParallelizationFactor`` - Process multiple batches from each shard
           concurrently.

        For information about which configuration parameters apply to each event
        source, see the following topics.

        -  `Amazon DynamoDB
           Streams <https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html#services-ddb-params>`__

        -  `Amazon
           Kinesis <https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-params>`__

        -  `Amazon
           SQS <https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#services-sqs-params>`__

        -  `Amazon MQ and
           RabbitMQ <https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html#services-mq-params>`__

        -  `Amazon
           MSK <https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html#services-msk-parms>`__

        -  `Apache
           Kafka <https://docs.aws.amazon.com/lambda/latest/dg/with-kafka.html#services-kafka-parms>`__

        :param uuid: The identifier of the event source mapping.
        :param function_name: The name of the Lambda function.
        :param enabled: When true, the event source mapping is active.
        :param batch_size: The maximum number of records in each batch that Lambda pulls from your
        stream or queue and sends to your function.
        :param maximum_batching_window_in_seconds: (Streams and Amazon SQS standard queues) The maximum amount of time, in
        seconds, that Lambda spends gathering records before invoking the
        function.
        :param destination_config: (Streams only) An Amazon SQS queue or Amazon SNS topic destination for
        discarded records.
        :param maximum_record_age_in_seconds: (Streams only) Discard records older than the specified age.
        :param bisect_batch_on_function_error: (Streams only) If the function returns an error, split the batch in two
        and retry.
        :param maximum_retry_attempts: (Streams only) Discard records after the specified number of retries.
        :param parallelization_factor: (Streams only) The number of batches to process from each shard
        concurrently.
        :param source_access_configurations: An array of authentication protocols or VPC components required to
        secure your event source.
        :param tumbling_window_in_seconds: (Streams only) The duration in seconds of a processing window.
        :param function_response_types: (Streams only) A list of current response type enums applied to the
        event source mapping.
        :returns: EventSourceMappingConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        :raises ResourceInUseException:
        """
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
        """Updates a Lambda function's code. If code signing is enabled for the
        function, the code package must be signed by a trusted publisher. For
        more information, see `Configuring code
        signing <https://docs.aws.amazon.com/lambda/latest/dg/configuration-trustedcode.html>`__.

        The function's code is locked when you publish a version. You can't
        modify the code of a published version, only the unpublished version.

        For a function defined as a container image, Lambda resolves the image
        tag to an image digest. In Amazon ECR, if you update the image tag to a
        new image, Lambda does not automatically update the function.

        :param function_name: The name of the Lambda function.
        :param zip_file: The base64-encoded contents of the deployment package.
        :param s3_bucket: An Amazon S3 bucket in the same Amazon Web Services Region as your
        function.
        :param s3_key: The Amazon S3 key of the deployment package.
        :param s3_object_version: For versioned objects, the version of the deployment package object to
        use.
        :param image_uri: URI of a container image in the Amazon ECR registry.
        :param publish: Set to true to publish a new version of the function after updating the
        code.
        :param dry_run: Set to true to validate the request parameters and access permissions
        without modifying the function code.
        :param revision_id: Only update the function if the revision ID matches the ID that's
        specified.
        :param architectures: The instruction set architecture that the function supports.
        :returns: FunctionConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises CodeStorageExceededException:
        :raises PreconditionFailedException:
        :raises ResourceConflictException:
        :raises CodeVerificationFailedException:
        :raises InvalidCodeSignatureException:
        :raises CodeSigningConfigNotFoundException:
        """
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
    ) -> FunctionConfiguration:
        """Modify the version-specific settings of a Lambda function.

        When you update a function, Lambda provisions an instance of the
        function and its supporting resources. If your function connects to a
        VPC, this process can take a minute. During this time, you can't modify
        the function, but you can still invoke it. The ``LastUpdateStatus``,
        ``LastUpdateStatusReason``, and ``LastUpdateStatusReasonCode`` fields in
        the response from GetFunctionConfiguration indicate when the update is
        complete and the function is processing events with the new
        configuration. For more information, see `Function
        States <https://docs.aws.amazon.com/lambda/latest/dg/functions-states.html>`__.

        These settings can vary between versions of a function and are locked
        when you publish a version. You can't modify the configuration of a
        published version, only the unpublished version.

        To configure function concurrency, use PutFunctionConcurrency. To grant
        invoke permissions to an account or Amazon Web Services service, use
        AddPermission.

        :param function_name: The name of the Lambda function.
        :param role: The Amazon Resource Name (ARN) of the function's execution role.
        :param handler: The name of the method within your code that Lambda calls to execute
        your function.
        :param description: A description of the function.
        :param timeout: The amount of time (in seconds) that Lambda allows a function to run
        before stopping it.
        :param memory_size: The amount of `memory available to the
        function <https://docs.
        :param vpc_config: For network connectivity to Amazon Web Services resources in a VPC,
        specify a list of security groups and subnets in the VPC.
        :param environment: Environment variables that are accessible from function code during
        execution.
        :param runtime: The identifier of the function's
        `runtime <https://docs.
        :param dead_letter_config: A dead letter queue configuration that specifies the queue or topic
        where Lambda sends asynchronous events when they fail processing.
        :param kms_key_arn: The ARN of the Amazon Web Services Key Management Service (KMS) key
        that's used to encrypt your function's environment variables.
        :param tracing_config: Set ``Mode`` to ``Active`` to sample and trace a subset of incoming
        requests with
        `X-Ray <https://docs.
        :param revision_id: Only update the function if the revision ID matches the ID that's
        specified.
        :param layers: A list of `function
        layers <https://docs.
        :param file_system_configs: Connection settings for an Amazon EFS file system.
        :param image_config: `Container image configuration
        values <https://docs.
        :returns: FunctionConfiguration
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        :raises PreconditionFailedException:
        :raises CodeVerificationFailedException:
        :raises InvalidCodeSignatureException:
        :raises CodeSigningConfigNotFoundException:
        """
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
        """Updates the configuration for asynchronous invocation for a function,
        version, or alias.

        To configure options for asynchronous invocation, use
        PutFunctionEventInvokeConfig.

        :param function_name: The name of the Lambda function, version, or alias.
        :param qualifier: A version number or alias name.
        :param maximum_retry_attempts: The maximum number of times to retry when the function returns an error.
        :param maximum_event_age_in_seconds: The maximum age of a request that Lambda sends to a function for
        processing.
        :param destination_config: A destination for events after they have been sent to a function for
        processing.
        :returns: FunctionEventInvokeConfig
        :raises ServiceException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises TooManyRequestsException:
        :raises ResourceConflictException:
        """
        raise NotImplementedError

    @handler("UpdateFunctionUrlConfig")
    def update_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
        authorization_type: AuthorizationType = None,
        cors: Cors = None,
    ) -> UpdateFunctionUrlConfigResponse:
        """

        :param function_name: .
        :param qualifier: .
        :param authorization_type: .
        :param cors: .
        :returns: UpdateFunctionUrlConfigResponse
        :raises ResourceConflictException:
        :raises ResourceNotFoundException:
        :raises InvalidParameterValueException:
        :raises ServiceException:
        :raises TooManyRequestsException:
        """
        raise NotImplementedError
