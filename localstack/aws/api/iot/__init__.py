import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AbortThresholdPercentage = float
AcmCertificateArn = str
AggregationField = str
AggregationTypeValue = str
AlarmName = str
AlertTargetArn = str
AllowAuthorizerOverride = bool
AllowAutoRegistration = bool
AscendingOrder = bool
AssetId = str
AssetPropertyAlias = str
AssetPropertyBooleanValue = str
AssetPropertyDoubleValue = str
AssetPropertyEntryId = str
AssetPropertyId = str
AssetPropertyIntegerValue = str
AssetPropertyOffsetInNanos = str
AssetPropertyQuality = str
AssetPropertyStringValue = str
AssetPropertyTimeInSeconds = str
AttributeKey = str
AttributeName = str
AttributeValue = str
AuditCheckName = str
AuditDescription = str
AuditTaskId = str
AuthorizerArn = str
AuthorizerFunctionArn = str
AuthorizerName = str
Average = float
AwsAccountId = str
AwsArn = str
AwsIotJobArn = str
AwsIotJobId = str
AwsIotSqlVersion = str
AwsJobAbortCriteriaAbortThresholdPercentage = float
AwsJobAbortCriteriaMinimumNumberOfExecutedThings = int
AwsJobRateIncreaseCriteriaNumberOfThings = int
AwsJobRolloutIncrementFactor = float
AwsJobRolloutRatePerMinute = int
BatchMode = bool
BehaviorMetric = str
BehaviorName = str
BillingGroupArn = str
BillingGroupDescription = str
BillingGroupId = str
BillingGroupName = str
Boolean = bool
BooleanKey = bool
BucketKeyValue = str
BucketName = str
CanceledChecksCount = int
CanceledThings = int
CertificateArn = str
CertificateId = str
CertificateName = str
CertificatePathOnDevice = str
CertificatePem = str
CertificateSigningRequest = str
ChannelName = str
CheckCompliant = bool
Cidr = str
ClientId = str
ClientRequestToken = str
Code = str
CognitoIdentityPoolId = str
Comment = str
CompliantChecksCount = int
ConfirmationToken = str
ConsecutiveDatapointsToAlarm = int
ConsecutiveDatapointsToClear = int
Count = int
CredentialDurationSeconds = int
CustomMetricArn = str
CustomMetricDisplayName = str
CustomerVersion = int
DataCollectionPercentage = float
DayOfMonth = str
DeleteAdditionalMetricsToRetain = bool
DeleteAlertTargets = bool
DeleteBehaviors = bool
DeleteScheduledAudits = bool
DeleteStream = bool
DeliveryStreamName = str
Description = str
DetailsKey = str
DetailsValue = str
DetectMitigationActionExecutionErrorCode = str
DeviceDefenderThingName = str
DimensionArn = str
DimensionName = str
DimensionStringValue = str
DisableAllLogs = bool
DisconnectReason = str
DomainConfigurationArn = str
DomainConfigurationName = str
DomainName = str
DurationSeconds = int
DynamoOperation = str
ElasticsearchEndpoint = str
ElasticsearchId = str
ElasticsearchIndex = str
ElasticsearchType = str
EnableCachingForHttp = bool
Enabled = bool
EndpointAddress = str
EndpointType = str
Environment = str
ErrorCode = str
ErrorMessage = str
EvaluationStatistic = str
Example = str
ExecutionNamePrefix = str
FailedChecksCount = int
FailedThings = int
FieldName = str
FileId = int
FileName = str
FileType = int
FindingId = str
FirehoseSeparator = str
Flag = bool
FleetMetricArn = str
FleetMetricDescription = str
FleetMetricName = str
FleetMetricPeriod = int
ForceDelete = bool
ForceDeleteAWSJob = bool
ForceFlag = bool
Forced = bool
FunctionArn = str
GenerationId = str
HashAlgorithm = str
HashKeyField = str
HashKeyValue = str
HeaderKey = str
HeaderValue = str
HttpHeaderName = str
HttpHeaderValue = str
HttpQueryString = str
InProgressChecksCount = int
InProgressThings = int
IncrementFactor = float
IndexName = str
IndexSchema = str
InlineDocument = str
InputName = str
IsAuthenticated = bool
IsDefaultVersion = bool
IsDisabled = bool
IsSuppressed = bool
JobArn = str
JobDescription = str
JobDocument = str
JobDocumentSource = str
JobId = str
JobTemplateArn = str
JobTemplateId = str
JsonDocument = str
Key = str
KeyName = str
KeyValue = str
LaserMaxResults = int
ListSuppressedAlerts = bool
ListSuppressedFindings = bool
LogGroupName = str
LogTargetName = str
ManagedJobTemplateName = str
ManagedTemplateVersion = str
Marker = str
MaxBuckets = int
MaxJobExecutionsPerMin = int
MaxResults = int
Maximum = float
MaximumPerMinute = int
Message = str
MessageId = str
MetricName = str
Minimum = float
MinimumNumberOfExecutedThings = int
MissingContextValue = str
MitigationActionArn = str
MitigationActionId = str
MitigationActionName = str
MitigationActionsTaskId = str
MqttClientId = str
MqttUsername = str
NamespaceId = str
NextToken = str
NonCompliantChecksCount = int
NullableBoolean = bool
Number = float
NumberOfRetries = int
NumberOfThings = int
OTAUpdateArn = str
OTAUpdateDescription = str
OTAUpdateErrorMessage = str
OTAUpdateFileVersion = str
OTAUpdateId = str
Optional_ = bool
OverrideDynamicGroups = bool
PageSize = int
Parameter = str
ParameterKey = str
ParameterValue = str
PartitionKey = str
PayloadField = str
PayloadVersion = str
Percent = float
PercentValue = float
Percentage = int
Platform = str
PolicyArn = str
PolicyDocument = str
PolicyName = str
PolicyTarget = str
PolicyVersionId = str
Port = int
Prefix = str
PrimitiveBoolean = bool
Principal = str
PrincipalArn = str
PrincipalId = str
PrivateKey = str
ProcessingTargetName = str
PublicKey = str
Qos = int
QueryMaxResults = int
QueryString = str
QueryVersion = str
QueueUrl = str
QueuedThings = int
RangeKeyField = str
RangeKeyValue = str
ReasonCode = str
ReasonForNonCompliance = str
ReasonForNonComplianceCode = str
Recursive = bool
RecursiveWithoutDefault = bool
Regex = str
RegistrationCode = str
RegistryMaxResults = int
RegistryS3BucketName = str
RegistryS3KeyName = str
RejectedThings = int
RemoveAuthorizerConfig = bool
RemoveAutoRegistration = bool
RemoveHook = bool
RemoveThingType = bool
RemovedThings = int
ReservedDomainConfigurationName = str
Resource = str
ResourceArn = str
ResourceLogicalId = str
RetryAttempt = int
RoleAlias = str
RoleAliasArn = str
RoleArn = str
RolloutRatePerMinute = int
RuleArn = str
RuleName = str
S3Bucket = str
S3FileUrl = str
S3Key = str
S3Version = str
SQL = str
SalesforceEndpoint = str
SalesforceToken = str
ScheduledAuditArn = str
ScheduledAuditName = str
Seconds = int
SecurityGroupId = str
SecurityProfileArn = str
SecurityProfileDescription = str
SecurityProfileName = str
SecurityProfileTargetArn = str
ServerCertificateStatusDetail = str
ServerName = str
ServiceName = str
SetAsActive = bool
SetAsActiveFlag = bool
SetAsDefault = bool
SignatureAlgorithm = str
SigningJobId = str
SigningProfileName = str
SigningRegion = str
SkyfallMaxResults = int
SnsTopicArn = str
StateMachineName = str
StateReason = str
StateValue = str
StdDeviation = float
StreamArn = str
StreamDescription = str
StreamId = str
StreamName = str
StreamVersion = int
String = str
SubnetId = str
SucceededThings = int
Sum = float
SumOfSquares = float
SuppressAlerts = bool
SuppressIndefinitely = bool
TableName = str
TagKey = str
TagValue = str
Target = str
TargetArn = str
TaskId = str
TemplateArn = str
TemplateBody = str
TemplateDescription = str
TemplateName = str
TemplateVersionId = int
ThingArn = str
ThingGroupArn = str
ThingGroupDescription = str
ThingGroupId = str
ThingGroupName = str
ThingId = str
ThingName = str
ThingTypeArn = str
ThingTypeDescription = str
ThingTypeId = str
ThingTypeName = str
TimedOutThings = int
TimestreamDatabaseName = str
TimestreamDimensionName = str
TimestreamDimensionValue = str
TimestreamTableName = str
TimestreamTimestampUnit = str
TimestreamTimestampValue = str
TinyMaxResults = int
Token = str
TokenKeyName = str
TokenSignature = str
Topic = str
TopicPattern = str
TopicRuleDestinationMaxResults = int
TopicRuleMaxResults = int
TotalChecksCount = int
UndoDeprecate = bool
Url = str
UseBase64 = bool
Valid = bool
Value = str
Variance = float
VerificationStateDescription = str
ViolationId = str
VpcId = str
WaitingForDataCollectionChecksCount = int
errorMessage = str
resourceArn = str
resourceId = str
stringValue = str
usePrefixAttributeValue = bool


class AbortAction(str):
    CANCEL = "CANCEL"


class ActionType(str):
    PUBLISH = "PUBLISH"
    SUBSCRIBE = "SUBSCRIBE"
    RECEIVE = "RECEIVE"
    CONNECT = "CONNECT"


class AggregationTypeName(str):
    Statistics = "Statistics"
    Percentiles = "Percentiles"
    Cardinality = "Cardinality"


class AlertTargetType(str):
    SNS = "SNS"


class AuditCheckRunStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_FOR_DATA_COLLECTION = "WAITING_FOR_DATA_COLLECTION"
    CANCELED = "CANCELED"
    COMPLETED_COMPLIANT = "COMPLETED_COMPLIANT"
    COMPLETED_NON_COMPLIANT = "COMPLETED_NON_COMPLIANT"
    FAILED = "FAILED"


class AuditFindingSeverity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AuditFrequency(str):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    BIWEEKLY = "BIWEEKLY"
    MONTHLY = "MONTHLY"


class AuditMitigationActionsExecutionStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    SKIPPED = "SKIPPED"
    PENDING = "PENDING"


class AuditMitigationActionsTaskStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class AuditNotificationType(str):
    SNS = "SNS"


class AuditTaskStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class AuditTaskType(str):
    ON_DEMAND_AUDIT_TASK = "ON_DEMAND_AUDIT_TASK"
    SCHEDULED_AUDIT_TASK = "SCHEDULED_AUDIT_TASK"


class AuthDecision(str):
    ALLOWED = "ALLOWED"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    IMPLICIT_DENY = "IMPLICIT_DENY"


class AuthorizerStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class AutoRegistrationStatus(str):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"


class AwsJobAbortCriteriaAbortAction(str):
    CANCEL = "CANCEL"


class AwsJobAbortCriteriaFailureType(str):
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    ALL = "ALL"


class BehaviorCriteriaType(str):
    STATIC = "STATIC"
    STATISTICAL = "STATISTICAL"
    MACHINE_LEARNING = "MACHINE_LEARNING"


class CACertificateStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class CACertificateUpdateAction(str):
    DEACTIVATE = "DEACTIVATE"


class CannedAccessControlList(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    aws_exec_read = "aws-exec-read"
    authenticated_read = "authenticated-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"
    log_delivery_write = "log-delivery-write"


class CertificateMode(str):
    DEFAULT = "DEFAULT"
    SNI_ONLY = "SNI_ONLY"


class CertificateStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    REVOKED = "REVOKED"
    PENDING_TRANSFER = "PENDING_TRANSFER"
    REGISTER_INACTIVE = "REGISTER_INACTIVE"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"


class ComparisonOperator(str):
    less_than = "less-than"
    less_than_equals = "less-than-equals"
    greater_than = "greater-than"
    greater_than_equals = "greater-than-equals"
    in_cidr_set = "in-cidr-set"
    not_in_cidr_set = "not-in-cidr-set"
    in_port_set = "in-port-set"
    not_in_port_set = "not-in-port-set"
    in_set = "in-set"
    not_in_set = "not-in-set"


class ConfidenceLevel(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CustomMetricType(str):
    string_list = "string-list"
    ip_address_list = "ip-address-list"
    number_list = "number-list"
    number = "number"


class DayOfWeek(str):
    SUN = "SUN"
    MON = "MON"
    TUE = "TUE"
    WED = "WED"
    THU = "THU"
    FRI = "FRI"
    SAT = "SAT"


class DetectMitigationActionExecutionStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESSFUL = "SUCCESSFUL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class DetectMitigationActionsTaskStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESSFUL = "SUCCESSFUL"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class DeviceCertificateUpdateAction(str):
    DEACTIVATE = "DEACTIVATE"


class DeviceDefenderIndexingMode(str):
    OFF = "OFF"
    VIOLATIONS = "VIOLATIONS"


class DimensionType(str):
    TOPIC_FILTER = "TOPIC_FILTER"


class DimensionValueOperator(str):
    IN = "IN"
    NOT_IN = "NOT_IN"


class DomainConfigurationStatus(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class DomainType(str):
    ENDPOINT = "ENDPOINT"
    AWS_MANAGED = "AWS_MANAGED"
    CUSTOMER_MANAGED = "CUSTOMER_MANAGED"


class DynamicGroupStatus(str):
    ACTIVE = "ACTIVE"
    BUILDING = "BUILDING"
    REBUILDING = "REBUILDING"


class DynamoKeyType(str):
    STRING = "STRING"
    NUMBER = "NUMBER"


class EventType(str):
    THING = "THING"
    THING_GROUP = "THING_GROUP"
    THING_TYPE = "THING_TYPE"
    THING_GROUP_MEMBERSHIP = "THING_GROUP_MEMBERSHIP"
    THING_GROUP_HIERARCHY = "THING_GROUP_HIERARCHY"
    THING_TYPE_ASSOCIATION = "THING_TYPE_ASSOCIATION"
    JOB = "JOB"
    JOB_EXECUTION = "JOB_EXECUTION"
    POLICY = "POLICY"
    CERTIFICATE = "CERTIFICATE"
    CA_CERTIFICATE = "CA_CERTIFICATE"


class FieldType(str):
    Number = "Number"
    String = "String"
    Boolean = "Boolean"


class FleetMetricUnit(str):
    Seconds = "Seconds"
    Microseconds = "Microseconds"
    Milliseconds = "Milliseconds"
    Bytes = "Bytes"
    Kilobytes = "Kilobytes"
    Megabytes = "Megabytes"
    Gigabytes = "Gigabytes"
    Terabytes = "Terabytes"
    Bits = "Bits"
    Kilobits = "Kilobits"
    Megabits = "Megabits"
    Gigabits = "Gigabits"
    Terabits = "Terabits"
    Percent = "Percent"
    Count = "Count"
    Bytes_Second = "Bytes/Second"
    Kilobytes_Second = "Kilobytes/Second"
    Megabytes_Second = "Megabytes/Second"
    Gigabytes_Second = "Gigabytes/Second"
    Terabytes_Second = "Terabytes/Second"
    Bits_Second = "Bits/Second"
    Kilobits_Second = "Kilobits/Second"
    Megabits_Second = "Megabits/Second"
    Gigabits_Second = "Gigabits/Second"
    Terabits_Second = "Terabits/Second"
    Count_Second = "Count/Second"
    None_ = "None"


class IndexStatus(str):
    ACTIVE = "ACTIVE"
    BUILDING = "BUILDING"
    REBUILDING = "REBUILDING"


class JobExecutionFailureType(str):
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    ALL = "ALL"


class JobExecutionStatus(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    REJECTED = "REJECTED"
    REMOVED = "REMOVED"
    CANCELED = "CANCELED"


class JobStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    CANCELED = "CANCELED"
    COMPLETED = "COMPLETED"
    DELETION_IN_PROGRESS = "DELETION_IN_PROGRESS"


class LogLevel(str):
    DEBUG = "DEBUG"
    INFO = "INFO"
    ERROR = "ERROR"
    WARN = "WARN"
    DISABLED = "DISABLED"


class LogTargetType(str):
    DEFAULT = "DEFAULT"
    THING_GROUP = "THING_GROUP"
    CLIENT_ID = "CLIENT_ID"
    SOURCE_IP = "SOURCE_IP"
    PRINCIPAL_ID = "PRINCIPAL_ID"


class MessageFormat(str):
    RAW = "RAW"
    JSON = "JSON"


class MitigationActionType(str):
    UPDATE_DEVICE_CERTIFICATE = "UPDATE_DEVICE_CERTIFICATE"
    UPDATE_CA_CERTIFICATE = "UPDATE_CA_CERTIFICATE"
    ADD_THINGS_TO_THING_GROUP = "ADD_THINGS_TO_THING_GROUP"
    REPLACE_DEFAULT_POLICY_VERSION = "REPLACE_DEFAULT_POLICY_VERSION"
    ENABLE_IOT_LOGGING = "ENABLE_IOT_LOGGING"
    PUBLISH_FINDING_TO_SNS = "PUBLISH_FINDING_TO_SNS"


class ModelStatus(str):
    PENDING_BUILD = "PENDING_BUILD"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"


class NamedShadowIndexingMode(str):
    OFF = "OFF"
    ON = "ON"


class OTAUpdateStatus(str):
    CREATE_PENDING = "CREATE_PENDING"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    CREATE_FAILED = "CREATE_FAILED"


class PolicyTemplateName(str):
    BLANK_POLICY = "BLANK_POLICY"


class Protocol(str):
    MQTT = "MQTT"
    HTTP = "HTTP"


class ReportType(str):
    ERRORS = "ERRORS"
    RESULTS = "RESULTS"


class ResourceType(str):
    DEVICE_CERTIFICATE = "DEVICE_CERTIFICATE"
    CA_CERTIFICATE = "CA_CERTIFICATE"
    IOT_POLICY = "IOT_POLICY"
    COGNITO_IDENTITY_POOL = "COGNITO_IDENTITY_POOL"
    CLIENT_ID = "CLIENT_ID"
    ACCOUNT_SETTINGS = "ACCOUNT_SETTINGS"
    ROLE_ALIAS = "ROLE_ALIAS"
    IAM_ROLE = "IAM_ROLE"


class RetryableFailureType(str):
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    ALL = "ALL"


class ServerCertificateStatus(str):
    INVALID = "INVALID"
    VALID = "VALID"


class ServiceType(str):
    DATA = "DATA"
    CREDENTIAL_PROVIDER = "CREDENTIAL_PROVIDER"
    JOBS = "JOBS"


class Status(str):
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Cancelled = "Cancelled"
    Cancelling = "Cancelling"


class TargetSelection(str):
    CONTINUOUS = "CONTINUOUS"
    SNAPSHOT = "SNAPSHOT"


class ThingConnectivityIndexingMode(str):
    OFF = "OFF"
    STATUS = "STATUS"


class ThingGroupIndexingMode(str):
    OFF = "OFF"
    ON = "ON"


class ThingIndexingMode(str):
    OFF = "OFF"
    REGISTRY = "REGISTRY"
    REGISTRY_AND_SHADOW = "REGISTRY_AND_SHADOW"


class TopicRuleDestinationStatus(str):
    ENABLED = "ENABLED"
    IN_PROGRESS = "IN_PROGRESS"
    DISABLED = "DISABLED"
    ERROR = "ERROR"
    DELETING = "DELETING"


class VerificationState(str):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_POSITIVE = "BENIGN_POSITIVE"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    UNKNOWN = "UNKNOWN"


class ViolationEventType(str):
    in_alarm = "in-alarm"
    alarm_cleared = "alarm-cleared"
    alarm_invalidated = "alarm-invalidated"


class CertificateConflictException(ServiceException):
    message: Optional[errorMessage]


class CertificateStateException(ServiceException):
    message: Optional[errorMessage]


class CertificateValidationException(ServiceException):
    message: Optional[errorMessage]


class ConflictException(ServiceException):
    message: Optional[errorMessage]


class ConflictingResourceUpdateException(ServiceException):
    message: Optional[errorMessage]


class DeleteConflictException(ServiceException):
    message: Optional[errorMessage]


class IndexNotReadyException(ServiceException):
    message: Optional[errorMessage]


class InternalException(ServiceException):
    message: Optional[errorMessage]


class InternalFailureException(ServiceException):
    message: Optional[errorMessage]


class InternalServerException(ServiceException):
    message: Optional[errorMessage]


class InvalidAggregationException(ServiceException):
    message: Optional[errorMessage]


class InvalidQueryException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class InvalidResponseException(ServiceException):
    message: Optional[errorMessage]


class InvalidStateTransitionException(ServiceException):
    message: Optional[errorMessage]


class LimitExceededException(ServiceException):
    message: Optional[errorMessage]


class MalformedPolicyException(ServiceException):
    message: Optional[errorMessage]


class NotConfiguredException(ServiceException):
    message: Optional[errorMessage]


class RegistrationCodeValidationException(ServiceException):
    message: Optional[errorMessage]


class ResourceAlreadyExistsException(ServiceException):
    message: Optional[errorMessage]
    resourceId: Optional[resourceId]
    resourceArn: Optional[resourceArn]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ResourceRegistrationFailureException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class SqlParseException(ServiceException):
    message: Optional[errorMessage]


class TaskAlreadyExistsException(ServiceException):
    message: Optional[errorMessage]


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]


class TransferAlreadyCompletedException(ServiceException):
    message: Optional[errorMessage]


class TransferConflictException(ServiceException):
    message: Optional[errorMessage]


class UnauthorizedException(ServiceException):
    message: Optional[errorMessage]


class VersionConflictException(ServiceException):
    message: Optional[errorMessage]


class VersionsLimitExceededException(ServiceException):
    message: Optional[errorMessage]


class AbortCriteria(TypedDict, total=False):
    failureType: JobExecutionFailureType
    action: AbortAction
    thresholdPercentage: AbortThresholdPercentage
    minNumberOfExecutedThings: MinimumNumberOfExecutedThings


AbortCriteriaList = List[AbortCriteria]


class AbortConfig(TypedDict, total=False):
    criteriaList: AbortCriteriaList


class AcceptCertificateTransferRequest(ServiceRequest):
    certificateId: CertificateId
    setAsActive: Optional[SetAsActive]


OpenSearchAction = TypedDict(
    "OpenSearchAction",
    {
        "roleArn": AwsArn,
        "endpoint": ElasticsearchEndpoint,
        "index": ElasticsearchIndex,
        "type": ElasticsearchType,
        "id": ElasticsearchId,
    },
    total=False,
)
ClientProperties = Dict[String, String]


class KafkaAction(TypedDict, total=False):
    destinationArn: AwsArn
    topic: String
    key: Optional[String]
    partition: Optional[String]
    clientProperties: ClientProperties


class SigV4Authorization(TypedDict, total=False):
    signingRegion: SigningRegion
    serviceName: ServiceName
    roleArn: AwsArn


class HttpAuthorization(TypedDict, total=False):
    sigv4: Optional[SigV4Authorization]


class HttpActionHeader(TypedDict, total=False):
    key: HeaderKey
    value: HeaderValue


HeaderList = List[HttpActionHeader]


class HttpAction(TypedDict, total=False):
    url: Url
    confirmationUrl: Optional[Url]
    headers: Optional[HeaderList]
    auth: Optional[HttpAuthorization]


class TimestreamTimestamp(TypedDict, total=False):
    value: TimestreamTimestampValue
    unit: TimestreamTimestampUnit


class TimestreamDimension(TypedDict, total=False):
    name: TimestreamDimensionName
    value: TimestreamDimensionValue


TimestreamDimensionList = List[TimestreamDimension]


class TimestreamAction(TypedDict, total=False):
    roleArn: AwsArn
    databaseName: TimestreamDatabaseName
    tableName: TimestreamTableName
    dimensions: TimestreamDimensionList
    timestamp: Optional[TimestreamTimestamp]


class StepFunctionsAction(TypedDict, total=False):
    executionNamePrefix: Optional[ExecutionNamePrefix]
    stateMachineName: StateMachineName
    roleArn: AwsArn


class AssetPropertyTimestamp(TypedDict, total=False):
    timeInSeconds: AssetPropertyTimeInSeconds
    offsetInNanos: Optional[AssetPropertyOffsetInNanos]


class AssetPropertyVariant(TypedDict, total=False):
    stringValue: Optional[AssetPropertyStringValue]
    integerValue: Optional[AssetPropertyIntegerValue]
    doubleValue: Optional[AssetPropertyDoubleValue]
    booleanValue: Optional[AssetPropertyBooleanValue]


class AssetPropertyValue(TypedDict, total=False):
    value: AssetPropertyVariant
    timestamp: AssetPropertyTimestamp
    quality: Optional[AssetPropertyQuality]


AssetPropertyValueList = List[AssetPropertyValue]


class PutAssetPropertyValueEntry(TypedDict, total=False):
    entryId: Optional[AssetPropertyEntryId]
    assetId: Optional[AssetId]
    propertyId: Optional[AssetPropertyId]
    propertyAlias: Optional[AssetPropertyAlias]
    propertyValues: AssetPropertyValueList


PutAssetPropertyValueEntryList = List[PutAssetPropertyValueEntry]


class IotSiteWiseAction(TypedDict, total=False):
    putAssetPropertyValueEntries: PutAssetPropertyValueEntryList
    roleArn: AwsArn


class IotEventsAction(TypedDict, total=False):
    inputName: InputName
    messageId: Optional[MessageId]
    batchMode: Optional[BatchMode]
    roleArn: AwsArn


class IotAnalyticsAction(TypedDict, total=False):
    channelArn: Optional[AwsArn]
    channelName: Optional[ChannelName]
    batchMode: Optional[BatchMode]
    roleArn: Optional[AwsArn]


class SalesforceAction(TypedDict, total=False):
    token: SalesforceToken
    url: SalesforceEndpoint


ElasticsearchAction = TypedDict(
    "ElasticsearchAction",
    {
        "roleArn": AwsArn,
        "endpoint": ElasticsearchEndpoint,
        "index": ElasticsearchIndex,
        "type": ElasticsearchType,
        "id": ElasticsearchId,
    },
    total=False,
)


class CloudwatchLogsAction(TypedDict, total=False):
    roleArn: AwsArn
    logGroupName: LogGroupName


class CloudwatchAlarmAction(TypedDict, total=False):
    roleArn: AwsArn
    alarmName: AlarmName
    stateReason: StateReason
    stateValue: StateValue


class CloudwatchMetricAction(TypedDict, total=False):
    roleArn: AwsArn
    metricNamespace: String
    metricName: String
    metricValue: String
    metricUnit: String
    metricTimestamp: Optional[String]


class FirehoseAction(TypedDict, total=False):
    roleArn: AwsArn
    deliveryStreamName: DeliveryStreamName
    separator: Optional[FirehoseSeparator]
    batchMode: Optional[BatchMode]


class S3Action(TypedDict, total=False):
    roleArn: AwsArn
    bucketName: BucketName
    key: Key
    cannedAcl: Optional[CannedAccessControlList]


class RepublishAction(TypedDict, total=False):
    roleArn: AwsArn
    topic: TopicPattern
    qos: Optional[Qos]


class KinesisAction(TypedDict, total=False):
    roleArn: AwsArn
    streamName: StreamName
    partitionKey: Optional[PartitionKey]


class SqsAction(TypedDict, total=False):
    roleArn: AwsArn
    queueUrl: QueueUrl
    useBase64: Optional[UseBase64]


class SnsAction(TypedDict, total=False):
    targetArn: AwsArn
    roleArn: AwsArn
    messageFormat: Optional[MessageFormat]


class LambdaAction(TypedDict, total=False):
    functionArn: FunctionArn


class PutItemInput(TypedDict, total=False):
    tableName: TableName


class DynamoDBv2Action(TypedDict, total=False):
    roleArn: AwsArn
    putItem: PutItemInput


class DynamoDBAction(TypedDict, total=False):
    tableName: TableName
    roleArn: AwsArn
    operation: Optional[DynamoOperation]
    hashKeyField: HashKeyField
    hashKeyValue: HashKeyValue
    hashKeyType: Optional[DynamoKeyType]
    rangeKeyField: Optional[RangeKeyField]
    rangeKeyValue: Optional[RangeKeyValue]
    rangeKeyType: Optional[DynamoKeyType]
    payloadField: Optional[PayloadField]


Action = TypedDict(
    "Action",
    {
        "dynamoDB": Optional[DynamoDBAction],
        "dynamoDBv2": Optional[DynamoDBv2Action],
        "lambda": Optional[LambdaAction],
        "sns": Optional[SnsAction],
        "sqs": Optional[SqsAction],
        "kinesis": Optional[KinesisAction],
        "republish": Optional[RepublishAction],
        "s3": Optional[S3Action],
        "firehose": Optional[FirehoseAction],
        "cloudwatchMetric": Optional[CloudwatchMetricAction],
        "cloudwatchAlarm": Optional[CloudwatchAlarmAction],
        "cloudwatchLogs": Optional[CloudwatchLogsAction],
        "elasticsearch": Optional[ElasticsearchAction],
        "salesforce": Optional[SalesforceAction],
        "iotAnalytics": Optional[IotAnalyticsAction],
        "iotEvents": Optional[IotEventsAction],
        "iotSiteWise": Optional[IotSiteWiseAction],
        "stepFunctions": Optional[StepFunctionsAction],
        "timestream": Optional[TimestreamAction],
        "http": Optional[HttpAction],
        "kafka": Optional[KafkaAction],
        "openSearch": Optional[OpenSearchAction],
    },
    total=False,
)
ActionList = List[Action]
Timestamp = datetime


class ViolationEventAdditionalInfo(TypedDict, total=False):
    confidenceLevel: Optional[ConfidenceLevel]


StringList = List[stringValue]
NumberList = List[Number]
Ports = List[Port]
Cidrs = List[Cidr]
UnsignedLong = int


class MetricValue(TypedDict, total=False):
    count: Optional[UnsignedLong]
    cidrs: Optional[Cidrs]
    ports: Optional[Ports]
    number: Optional[Number]
    numbers: Optional[NumberList]
    strings: Optional[StringList]


class MachineLearningDetectionConfig(TypedDict, total=False):
    confidenceLevel: ConfidenceLevel


class StatisticalThreshold(TypedDict, total=False):
    statistic: Optional[EvaluationStatistic]


class BehaviorCriteria(TypedDict, total=False):
    comparisonOperator: Optional[ComparisonOperator]
    value: Optional[MetricValue]
    durationSeconds: Optional[DurationSeconds]
    consecutiveDatapointsToAlarm: Optional[ConsecutiveDatapointsToAlarm]
    consecutiveDatapointsToClear: Optional[ConsecutiveDatapointsToClear]
    statisticalThreshold: Optional[StatisticalThreshold]
    mlDetectionConfig: Optional[MachineLearningDetectionConfig]


class MetricDimension(TypedDict, total=False):
    dimensionName: DimensionName
    operator: Optional[DimensionValueOperator]


class Behavior(TypedDict, total=False):
    name: BehaviorName
    metric: Optional[BehaviorMetric]
    metricDimension: Optional[MetricDimension]
    criteria: Optional[BehaviorCriteria]
    suppressAlerts: Optional[SuppressAlerts]


class ActiveViolation(TypedDict, total=False):
    violationId: Optional[ViolationId]
    thingName: Optional[DeviceDefenderThingName]
    securityProfileName: Optional[SecurityProfileName]
    behavior: Optional[Behavior]
    lastViolationValue: Optional[MetricValue]
    violationEventAdditionalInfo: Optional[ViolationEventAdditionalInfo]
    verificationState: Optional[VerificationState]
    verificationStateDescription: Optional[VerificationStateDescription]
    lastViolationTime: Optional[Timestamp]
    violationStartTime: Optional[Timestamp]


ActiveViolations = List[ActiveViolation]


class AddThingToBillingGroupRequest(ServiceRequest):
    billingGroupName: Optional[BillingGroupName]
    billingGroupArn: Optional[BillingGroupArn]
    thingName: Optional[ThingName]
    thingArn: Optional[ThingArn]


class AddThingToBillingGroupResponse(TypedDict, total=False):
    pass


class AddThingToThingGroupRequest(ServiceRequest):
    thingGroupName: Optional[ThingGroupName]
    thingGroupArn: Optional[ThingGroupArn]
    thingName: Optional[ThingName]
    thingArn: Optional[ThingArn]
    overrideDynamicGroups: Optional[OverrideDynamicGroups]


class AddThingToThingGroupResponse(TypedDict, total=False):
    pass


ThingGroupNames = List[ThingGroupName]


class AddThingsToThingGroupParams(TypedDict, total=False):
    thingGroupNames: ThingGroupNames
    overrideDynamicGroups: Optional[OverrideDynamicGroups]


AdditionalMetricsToRetainList = List[BehaviorMetric]


class MetricToRetain(TypedDict, total=False):
    metric: BehaviorMetric
    metricDimension: Optional[MetricDimension]


AdditionalMetricsToRetainV2List = List[MetricToRetain]
AdditionalParameterMap = Dict[AttributeKey, Value]
AggregationTypeValues = List[AggregationTypeValue]


class AggregationType(TypedDict, total=False):
    name: AggregationTypeName
    values: Optional[AggregationTypeValues]


class AlertTarget(TypedDict, total=False):
    alertTargetArn: AlertTargetArn
    roleArn: RoleArn


AlertTargets = Dict[AlertTargetType, AlertTarget]


class Policy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyArn: Optional[PolicyArn]


Policies = List[Policy]


class Allowed(TypedDict, total=False):
    policies: Optional[Policies]


ApproximateSecondsBeforeTimedOut = int
JobTargets = List[TargetArn]


class AssociateTargetsWithJobRequest(ServiceRequest):
    targets: JobTargets
    jobId: JobId
    comment: Optional[Comment]
    namespaceId: Optional[NamespaceId]


class AssociateTargetsWithJobResponse(TypedDict, total=False):
    jobArn: Optional[JobArn]
    jobId: Optional[JobId]
    description: Optional[JobDescription]


class AttachPolicyRequest(ServiceRequest):
    policyName: PolicyName
    target: PolicyTarget


class AttachPrincipalPolicyRequest(ServiceRequest):
    policyName: PolicyName
    principal: Principal


class AttachSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    securityProfileTargetArn: SecurityProfileTargetArn


class AttachSecurityProfileResponse(TypedDict, total=False):
    pass


class AttachThingPrincipalRequest(ServiceRequest):
    thingName: ThingName
    principal: Principal


class AttachThingPrincipalResponse(TypedDict, total=False):
    pass


Attributes = Dict[AttributeName, AttributeValue]


class AttributePayload(TypedDict, total=False):
    attributes: Optional[Attributes]
    merge: Optional[Flag]


AttributesMap = Dict[AttributeKey, Value]


class AuditCheckConfiguration(TypedDict, total=False):
    enabled: Optional[Enabled]


AuditCheckConfigurations = Dict[AuditCheckName, AuditCheckConfiguration]
SuppressedNonCompliantResourcesCount = int
NonCompliantResourcesCount = int
TotalResourcesCount = int


class AuditCheckDetails(TypedDict, total=False):
    checkRunStatus: Optional[AuditCheckRunStatus]
    checkCompliant: Optional[CheckCompliant]
    totalResourcesCount: Optional[TotalResourcesCount]
    nonCompliantResourcesCount: Optional[NonCompliantResourcesCount]
    suppressedNonCompliantResourcesCount: Optional[SuppressedNonCompliantResourcesCount]
    errorCode: Optional[ErrorCode]
    message: Optional[ErrorMessage]


MitigationActionNameList = List[MitigationActionName]
AuditCheckToActionsMapping = Dict[AuditCheckName, MitigationActionNameList]
ReasonForNonComplianceCodes = List[ReasonForNonComplianceCode]
AuditCheckToReasonCodeFilter = Dict[AuditCheckName, ReasonForNonComplianceCodes]
AuditDetails = Dict[AuditCheckName, AuditCheckDetails]
StringMap = Dict[String, String]


class PolicyVersionIdentifier(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyVersionId: Optional[PolicyVersionId]


class ResourceIdentifier(TypedDict, total=False):
    deviceCertificateId: Optional[CertificateId]
    caCertificateId: Optional[CertificateId]
    cognitoIdentityPoolId: Optional[CognitoIdentityPoolId]
    clientId: Optional[ClientId]
    policyVersionIdentifier: Optional[PolicyVersionIdentifier]
    account: Optional[AwsAccountId]
    iamRoleArn: Optional[RoleArn]
    roleAliasArn: Optional[RoleAliasArn]


class RelatedResource(TypedDict, total=False):
    resourceType: Optional[ResourceType]
    resourceIdentifier: Optional[ResourceIdentifier]
    additionalInfo: Optional[StringMap]


RelatedResources = List[RelatedResource]


class NonCompliantResource(TypedDict, total=False):
    resourceType: Optional[ResourceType]
    resourceIdentifier: Optional[ResourceIdentifier]
    additionalInfo: Optional[StringMap]


class AuditFinding(TypedDict, total=False):
    findingId: Optional[FindingId]
    taskId: Optional[AuditTaskId]
    checkName: Optional[AuditCheckName]
    taskStartTime: Optional[Timestamp]
    findingTime: Optional[Timestamp]
    severity: Optional[AuditFindingSeverity]
    nonCompliantResource: Optional[NonCompliantResource]
    relatedResources: Optional[RelatedResources]
    reasonForNonCompliance: Optional[ReasonForNonCompliance]
    reasonForNonComplianceCode: Optional[ReasonForNonComplianceCode]
    isSuppressed: Optional[IsSuppressed]


AuditFindings = List[AuditFinding]


class AuditMitigationActionExecutionMetadata(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]
    findingId: Optional[FindingId]
    actionName: Optional[MitigationActionName]
    actionId: Optional[MitigationActionId]
    status: Optional[AuditMitigationActionsExecutionStatus]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    errorCode: Optional[ErrorCode]
    message: Optional[ErrorMessage]


AuditMitigationActionExecutionMetadataList = List[AuditMitigationActionExecutionMetadata]


class AuditMitigationActionsTaskMetadata(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]
    startTime: Optional[Timestamp]
    taskStatus: Optional[AuditMitigationActionsTaskStatus]


AuditMitigationActionsTaskMetadataList = List[AuditMitigationActionsTaskMetadata]
CanceledFindingsCount = int
SkippedFindingsCount = int
SucceededFindingsCount = int
FailedFindingsCount = int
TotalFindingsCount = int


class TaskStatisticsForAuditCheck(TypedDict, total=False):
    totalFindingsCount: Optional[TotalFindingsCount]
    failedFindingsCount: Optional[FailedFindingsCount]
    succeededFindingsCount: Optional[SucceededFindingsCount]
    skippedFindingsCount: Optional[SkippedFindingsCount]
    canceledFindingsCount: Optional[CanceledFindingsCount]


AuditMitigationActionsTaskStatistics = Dict[AuditCheckName, TaskStatisticsForAuditCheck]
FindingIds = List[FindingId]


class AuditMitigationActionsTaskTarget(TypedDict, total=False):
    auditTaskId: Optional[AuditTaskId]
    findingIds: Optional[FindingIds]
    auditCheckToReasonCodeFilter: Optional[AuditCheckToReasonCodeFilter]


class AuditNotificationTarget(TypedDict, total=False):
    targetArn: Optional[TargetArn]
    roleArn: Optional[RoleArn]
    enabled: Optional[Enabled]


AuditNotificationTargetConfigurations = Dict[AuditNotificationType, AuditNotificationTarget]


class AuditSuppression(TypedDict, total=False):
    checkName: AuditCheckName
    resourceIdentifier: ResourceIdentifier
    expirationDate: Optional[Timestamp]
    suppressIndefinitely: Optional[SuppressIndefinitely]
    description: Optional[AuditDescription]


AuditSuppressionList = List[AuditSuppression]


class AuditTaskMetadata(TypedDict, total=False):
    taskId: Optional[AuditTaskId]
    taskStatus: Optional[AuditTaskStatus]
    taskType: Optional[AuditTaskType]


AuditTaskMetadataList = List[AuditTaskMetadata]
Resources = List[Resource]


class AuthInfo(TypedDict, total=False):
    actionType: Optional[ActionType]
    resources: Resources


AuthInfos = List[AuthInfo]
MissingContextValues = List[MissingContextValue]


class ExplicitDeny(TypedDict, total=False):
    policies: Optional[Policies]


class ImplicitDeny(TypedDict, total=False):
    policies: Optional[Policies]


class Denied(TypedDict, total=False):
    implicitDeny: Optional[ImplicitDeny]
    explicitDeny: Optional[ExplicitDeny]


class AuthResult(TypedDict, total=False):
    authInfo: Optional[AuthInfo]
    allowed: Optional[Allowed]
    denied: Optional[Denied]
    authDecision: Optional[AuthDecision]
    missingContextValues: Optional[MissingContextValues]


AuthResults = List[AuthResult]


class AuthorizerConfig(TypedDict, total=False):
    defaultAuthorizerName: Optional[AuthorizerName]
    allowAuthorizerOverride: Optional[AllowAuthorizerOverride]


DateType = datetime
PublicKeyMap = Dict[KeyName, KeyValue]


class AuthorizerDescription(TypedDict, total=False):
    authorizerName: Optional[AuthorizerName]
    authorizerArn: Optional[AuthorizerArn]
    authorizerFunctionArn: Optional[AuthorizerFunctionArn]
    tokenKeyName: Optional[TokenKeyName]
    tokenSigningPublicKeys: Optional[PublicKeyMap]
    status: Optional[AuthorizerStatus]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    signingDisabled: Optional[BooleanKey]
    enableCachingForHttp: Optional[EnableCachingForHttp]


class AuthorizerSummary(TypedDict, total=False):
    authorizerName: Optional[AuthorizerName]
    authorizerArn: Optional[AuthorizerArn]


Authorizers = List[AuthorizerSummary]


class AwsJobAbortCriteria(TypedDict, total=False):
    failureType: AwsJobAbortCriteriaFailureType
    action: AwsJobAbortCriteriaAbortAction
    thresholdPercentage: AwsJobAbortCriteriaAbortThresholdPercentage
    minNumberOfExecutedThings: AwsJobAbortCriteriaMinimumNumberOfExecutedThings


AwsJobAbortCriteriaList = List[AwsJobAbortCriteria]


class AwsJobAbortConfig(TypedDict, total=False):
    abortCriteriaList: AwsJobAbortCriteriaList


class AwsJobRateIncreaseCriteria(TypedDict, total=False):
    numberOfNotifiedThings: Optional[AwsJobRateIncreaseCriteriaNumberOfThings]
    numberOfSucceededThings: Optional[AwsJobRateIncreaseCriteriaNumberOfThings]


class AwsJobExponentialRolloutRate(TypedDict, total=False):
    baseRatePerMinute: AwsJobRolloutRatePerMinute
    incrementFactor: AwsJobRolloutIncrementFactor
    rateIncreaseCriteria: AwsJobRateIncreaseCriteria


class AwsJobExecutionsRolloutConfig(TypedDict, total=False):
    maximumPerMinute: Optional[MaximumPerMinute]
    exponentialRate: Optional[AwsJobExponentialRolloutRate]


ExpiresInSeconds = int


class AwsJobPresignedUrlConfig(TypedDict, total=False):
    expiresInSec: Optional[ExpiresInSeconds]


AwsJobTimeoutInProgressTimeoutInMinutes = int


class AwsJobTimeoutConfig(TypedDict, total=False):
    inProgressTimeoutInMinutes: Optional[AwsJobTimeoutInProgressTimeoutInMinutes]


class BehaviorModelTrainingSummary(TypedDict, total=False):
    securityProfileName: Optional[SecurityProfileName]
    behaviorName: Optional[BehaviorName]
    trainingDataCollectionStartDate: Optional[Timestamp]
    modelStatus: Optional[ModelStatus]
    datapointsCollectionPercentage: Optional[DataCollectionPercentage]
    lastModelRefreshDate: Optional[Timestamp]


BehaviorModelTrainingSummaries = List[BehaviorModelTrainingSummary]
Behaviors = List[Behavior]
CreationDate = datetime


class BillingGroupMetadata(TypedDict, total=False):
    creationDate: Optional[CreationDate]


class GroupNameAndArn(TypedDict, total=False):
    groupName: Optional[ThingGroupName]
    groupArn: Optional[ThingGroupArn]


BillingGroupNameAndArnList = List[GroupNameAndArn]


class BillingGroupProperties(TypedDict, total=False):
    billingGroupDescription: Optional[BillingGroupDescription]


class Bucket(TypedDict, total=False):
    keyValue: Optional[BucketKeyValue]
    count: Optional[Count]


Buckets = List[Bucket]


class TermsAggregation(TypedDict, total=False):
    maxBuckets: Optional[MaxBuckets]


class BucketsAggregationType(TypedDict, total=False):
    termsAggregation: Optional[TermsAggregation]


class CACertificate(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    status: Optional[CACertificateStatus]
    creationDate: Optional[DateType]


class CertificateValidity(TypedDict, total=False):
    notBefore: Optional[DateType]
    notAfter: Optional[DateType]


class CACertificateDescription(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    status: Optional[CACertificateStatus]
    certificatePem: Optional[CertificatePem]
    ownedBy: Optional[AwsAccountId]
    creationDate: Optional[DateType]
    autoRegistrationStatus: Optional[AutoRegistrationStatus]
    lastModifiedDate: Optional[DateType]
    customerVersion: Optional[CustomerVersion]
    generationId: Optional[GenerationId]
    validity: Optional[CertificateValidity]


CACertificates = List[CACertificate]


class CancelAuditMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId


class CancelAuditMitigationActionsTaskResponse(TypedDict, total=False):
    pass


class CancelAuditTaskRequest(ServiceRequest):
    taskId: AuditTaskId


class CancelAuditTaskResponse(TypedDict, total=False):
    pass


class CancelCertificateTransferRequest(ServiceRequest):
    certificateId: CertificateId


class CancelDetectMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId


class CancelDetectMitigationActionsTaskResponse(TypedDict, total=False):
    pass


DetailsMap = Dict[DetailsKey, DetailsValue]
ExpectedVersion = int


class CancelJobExecutionRequest(ServiceRequest):
    jobId: JobId
    thingName: ThingName
    force: Optional[ForceFlag]
    expectedVersion: Optional[ExpectedVersion]
    statusDetails: Optional[DetailsMap]


class CancelJobRequest(ServiceRequest):
    jobId: JobId
    reasonCode: Optional[ReasonCode]
    comment: Optional[Comment]
    force: Optional[ForceFlag]


class CancelJobResponse(TypedDict, total=False):
    jobArn: Optional[JobArn]
    jobId: Optional[JobId]
    description: Optional[JobDescription]


class Certificate(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    status: Optional[CertificateStatus]
    certificateMode: Optional[CertificateMode]
    creationDate: Optional[DateType]


class TransferData(TypedDict, total=False):
    transferMessage: Optional[Message]
    rejectReason: Optional[Message]
    transferDate: Optional[DateType]
    acceptDate: Optional[DateType]
    rejectDate: Optional[DateType]


class CertificateDescription(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    caCertificateId: Optional[CertificateId]
    status: Optional[CertificateStatus]
    certificatePem: Optional[CertificatePem]
    ownedBy: Optional[AwsAccountId]
    previousOwnedBy: Optional[AwsAccountId]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    customerVersion: Optional[CustomerVersion]
    transferData: Optional[TransferData]
    generationId: Optional[GenerationId]
    validity: Optional[CertificateValidity]
    certificateMode: Optional[CertificateMode]


Certificates = List[Certificate]


class ClearDefaultAuthorizerRequest(ServiceRequest):
    pass


class ClearDefaultAuthorizerResponse(TypedDict, total=False):
    pass


class CodeSigningCertificateChain(TypedDict, total=False):
    certificateName: Optional[CertificateName]
    inlineDocument: Optional[InlineDocument]


Signature = bytes


class CodeSigningSignature(TypedDict, total=False):
    inlineDocument: Optional[Signature]


class CustomCodeSigning(TypedDict, total=False):
    signature: Optional[CodeSigningSignature]
    certificateChain: Optional[CodeSigningCertificateChain]
    hashAlgorithm: Optional[HashAlgorithm]
    signatureAlgorithm: Optional[SignatureAlgorithm]


class S3Destination(TypedDict, total=False):
    bucket: Optional[S3Bucket]
    prefix: Optional[Prefix]


class Destination(TypedDict, total=False):
    s3Destination: Optional[S3Destination]


class SigningProfileParameter(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    platform: Optional[Platform]
    certificatePathOnDevice: Optional[CertificatePathOnDevice]


class StartSigningJobParameter(TypedDict, total=False):
    signingProfileParameter: Optional[SigningProfileParameter]
    signingProfileName: Optional[SigningProfileName]
    destination: Optional[Destination]


class CodeSigning(TypedDict, total=False):
    awsSignerJobId: Optional[SigningJobId]
    startSigningJobParameter: Optional[StartSigningJobParameter]
    customCodeSigning: Optional[CustomCodeSigning]


class Configuration(TypedDict, total=False):
    Enabled: Optional[Enabled]


class ConfirmTopicRuleDestinationRequest(ServiceRequest):
    confirmationToken: ConfirmationToken


class ConfirmTopicRuleDestinationResponse(TypedDict, total=False):
    pass


ConnectivityTimestamp = int


class CreateAuditSuppressionRequest(ServiceRequest):
    checkName: AuditCheckName
    resourceIdentifier: ResourceIdentifier
    expirationDate: Optional[Timestamp]
    suppressIndefinitely: Optional[SuppressIndefinitely]
    description: Optional[AuditDescription]
    clientRequestToken: ClientRequestToken


class CreateAuditSuppressionResponse(TypedDict, total=False):
    pass


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class CreateAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName
    authorizerFunctionArn: AuthorizerFunctionArn
    tokenKeyName: Optional[TokenKeyName]
    tokenSigningPublicKeys: Optional[PublicKeyMap]
    status: Optional[AuthorizerStatus]
    tags: Optional[TagList]
    signingDisabled: Optional[BooleanKey]
    enableCachingForHttp: Optional[EnableCachingForHttp]


class CreateAuthorizerResponse(TypedDict, total=False):
    authorizerName: Optional[AuthorizerName]
    authorizerArn: Optional[AuthorizerArn]


class CreateBillingGroupRequest(ServiceRequest):
    billingGroupName: BillingGroupName
    billingGroupProperties: Optional[BillingGroupProperties]
    tags: Optional[TagList]


class CreateBillingGroupResponse(TypedDict, total=False):
    billingGroupName: Optional[BillingGroupName]
    billingGroupArn: Optional[BillingGroupArn]
    billingGroupId: Optional[BillingGroupId]


class CreateCertificateFromCsrRequest(ServiceRequest):
    certificateSigningRequest: CertificateSigningRequest
    setAsActive: Optional[SetAsActive]


class CreateCertificateFromCsrResponse(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    certificatePem: Optional[CertificatePem]


class CreateCustomMetricRequest(ServiceRequest):
    metricName: MetricName
    displayName: Optional[CustomMetricDisplayName]
    metricType: CustomMetricType
    tags: Optional[TagList]
    clientRequestToken: ClientRequestToken


class CreateCustomMetricResponse(TypedDict, total=False):
    metricName: Optional[MetricName]
    metricArn: Optional[CustomMetricArn]


DimensionStringValues = List[DimensionStringValue]
CreateDimensionRequest = TypedDict(
    "CreateDimensionRequest",
    {
        "name": DimensionName,
        "type": DimensionType,
        "stringValues": DimensionStringValues,
        "tags": Optional[TagList],
        "clientRequestToken": ClientRequestToken,
    },
    total=False,
)


class CreateDimensionResponse(TypedDict, total=False):
    name: Optional[DimensionName]
    arn: Optional[DimensionArn]


ServerCertificateArns = List[AcmCertificateArn]


class CreateDomainConfigurationRequest(ServiceRequest):
    domainConfigurationName: DomainConfigurationName
    domainName: Optional[DomainName]
    serverCertificateArns: Optional[ServerCertificateArns]
    validationCertificateArn: Optional[AcmCertificateArn]
    authorizerConfig: Optional[AuthorizerConfig]
    serviceType: Optional[ServiceType]
    tags: Optional[TagList]


class CreateDomainConfigurationResponse(TypedDict, total=False):
    domainConfigurationName: Optional[DomainConfigurationName]
    domainConfigurationArn: Optional[DomainConfigurationArn]


class ThingGroupProperties(TypedDict, total=False):
    thingGroupDescription: Optional[ThingGroupDescription]
    attributePayload: Optional[AttributePayload]


class CreateDynamicThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    thingGroupProperties: Optional[ThingGroupProperties]
    indexName: Optional[IndexName]
    queryString: QueryString
    queryVersion: Optional[QueryVersion]
    tags: Optional[TagList]


class CreateDynamicThingGroupResponse(TypedDict, total=False):
    thingGroupName: Optional[ThingGroupName]
    thingGroupArn: Optional[ThingGroupArn]
    thingGroupId: Optional[ThingGroupId]
    indexName: Optional[IndexName]
    queryString: Optional[QueryString]
    queryVersion: Optional[QueryVersion]


class CreateFleetMetricRequest(ServiceRequest):
    metricName: FleetMetricName
    queryString: QueryString
    aggregationType: AggregationType
    period: FleetMetricPeriod
    aggregationField: AggregationField
    description: Optional[FleetMetricDescription]
    queryVersion: Optional[QueryVersion]
    indexName: Optional[IndexName]
    unit: Optional[FleetMetricUnit]
    tags: Optional[TagList]


class CreateFleetMetricResponse(TypedDict, total=False):
    metricName: Optional[FleetMetricName]
    metricArn: Optional[FleetMetricArn]


ParameterMap = Dict[ParameterKey, ParameterValue]


class RetryCriteria(TypedDict, total=False):
    failureType: RetryableFailureType
    numberOfRetries: NumberOfRetries


RetryCriteriaList = List[RetryCriteria]


class JobExecutionsRetryConfig(TypedDict, total=False):
    criteriaList: RetryCriteriaList


InProgressTimeoutInMinutes = int


class TimeoutConfig(TypedDict, total=False):
    inProgressTimeoutInMinutes: Optional[InProgressTimeoutInMinutes]


class RateIncreaseCriteria(TypedDict, total=False):
    numberOfNotifiedThings: Optional[NumberOfThings]
    numberOfSucceededThings: Optional[NumberOfThings]


class ExponentialRolloutRate(TypedDict, total=False):
    baseRatePerMinute: RolloutRatePerMinute
    incrementFactor: IncrementFactor
    rateIncreaseCriteria: RateIncreaseCriteria


class JobExecutionsRolloutConfig(TypedDict, total=False):
    maximumPerMinute: Optional[MaxJobExecutionsPerMin]
    exponentialRate: Optional[ExponentialRolloutRate]


ExpiresInSec = int


class PresignedUrlConfig(TypedDict, total=False):
    roleArn: Optional[RoleArn]
    expiresInSec: Optional[ExpiresInSec]


class CreateJobRequest(ServiceRequest):
    jobId: JobId
    targets: JobTargets
    documentSource: Optional[JobDocumentSource]
    document: Optional[JobDocument]
    description: Optional[JobDescription]
    presignedUrlConfig: Optional[PresignedUrlConfig]
    targetSelection: Optional[TargetSelection]
    jobExecutionsRolloutConfig: Optional[JobExecutionsRolloutConfig]
    abortConfig: Optional[AbortConfig]
    timeoutConfig: Optional[TimeoutConfig]
    tags: Optional[TagList]
    namespaceId: Optional[NamespaceId]
    jobTemplateArn: Optional[JobTemplateArn]
    jobExecutionsRetryConfig: Optional[JobExecutionsRetryConfig]
    documentParameters: Optional[ParameterMap]


class CreateJobResponse(TypedDict, total=False):
    jobArn: Optional[JobArn]
    jobId: Optional[JobId]
    description: Optional[JobDescription]


class CreateJobTemplateRequest(ServiceRequest):
    jobTemplateId: JobTemplateId
    jobArn: Optional[JobArn]
    documentSource: Optional[JobDocumentSource]
    document: Optional[JobDocument]
    description: JobDescription
    presignedUrlConfig: Optional[PresignedUrlConfig]
    jobExecutionsRolloutConfig: Optional[JobExecutionsRolloutConfig]
    abortConfig: Optional[AbortConfig]
    timeoutConfig: Optional[TimeoutConfig]
    tags: Optional[TagList]
    jobExecutionsRetryConfig: Optional[JobExecutionsRetryConfig]


class CreateJobTemplateResponse(TypedDict, total=False):
    jobTemplateArn: Optional[JobTemplateArn]
    jobTemplateId: Optional[JobTemplateId]


class CreateKeysAndCertificateRequest(ServiceRequest):
    setAsActive: Optional[SetAsActive]


class KeyPair(TypedDict, total=False):
    PublicKey: Optional[PublicKey]
    PrivateKey: Optional[PrivateKey]


class CreateKeysAndCertificateResponse(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    certificatePem: Optional[CertificatePem]
    keyPair: Optional[KeyPair]


class PublishFindingToSnsParams(TypedDict, total=False):
    topicArn: SnsTopicArn


class EnableIoTLoggingParams(TypedDict, total=False):
    roleArnForLogging: RoleArn
    logLevel: LogLevel


class ReplaceDefaultPolicyVersionParams(TypedDict, total=False):
    templateName: PolicyTemplateName


class UpdateCACertificateParams(TypedDict, total=False):
    action: CACertificateUpdateAction


class UpdateDeviceCertificateParams(TypedDict, total=False):
    action: DeviceCertificateUpdateAction


class MitigationActionParams(TypedDict, total=False):
    updateDeviceCertificateParams: Optional[UpdateDeviceCertificateParams]
    updateCACertificateParams: Optional[UpdateCACertificateParams]
    addThingsToThingGroupParams: Optional[AddThingsToThingGroupParams]
    replaceDefaultPolicyVersionParams: Optional[ReplaceDefaultPolicyVersionParams]
    enableIoTLoggingParams: Optional[EnableIoTLoggingParams]
    publishFindingToSnsParams: Optional[PublishFindingToSnsParams]


class CreateMitigationActionRequest(ServiceRequest):
    actionName: MitigationActionName
    roleArn: RoleArn
    actionParams: MitigationActionParams
    tags: Optional[TagList]


class CreateMitigationActionResponse(TypedDict, total=False):
    actionArn: Optional[MitigationActionArn]
    actionId: Optional[MitigationActionId]


class S3Location(TypedDict, total=False):
    bucket: Optional[S3Bucket]
    key: Optional[S3Key]
    version: Optional[S3Version]


class Stream(TypedDict, total=False):
    streamId: Optional[StreamId]
    fileId: Optional[FileId]


class FileLocation(TypedDict, total=False):
    stream: Optional[Stream]
    s3Location: Optional[S3Location]


class OTAUpdateFile(TypedDict, total=False):
    fileName: Optional[FileName]
    fileType: Optional[FileType]
    fileVersion: Optional[OTAUpdateFileVersion]
    fileLocation: Optional[FileLocation]
    codeSigning: Optional[CodeSigning]
    attributes: Optional[AttributesMap]


OTAUpdateFiles = List[OTAUpdateFile]
Protocols = List[Protocol]
Targets = List[Target]


class CreateOTAUpdateRequest(ServiceRequest):
    otaUpdateId: OTAUpdateId
    description: Optional[OTAUpdateDescription]
    targets: Targets
    protocols: Optional[Protocols]
    targetSelection: Optional[TargetSelection]
    awsJobExecutionsRolloutConfig: Optional[AwsJobExecutionsRolloutConfig]
    awsJobPresignedUrlConfig: Optional[AwsJobPresignedUrlConfig]
    awsJobAbortConfig: Optional[AwsJobAbortConfig]
    awsJobTimeoutConfig: Optional[AwsJobTimeoutConfig]
    files: OTAUpdateFiles
    roleArn: RoleArn
    additionalParameters: Optional[AdditionalParameterMap]
    tags: Optional[TagList]


class CreateOTAUpdateResponse(TypedDict, total=False):
    otaUpdateId: Optional[OTAUpdateId]
    awsIotJobId: Optional[AwsIotJobId]
    otaUpdateArn: Optional[OTAUpdateArn]
    awsIotJobArn: Optional[AwsIotJobArn]
    otaUpdateStatus: Optional[OTAUpdateStatus]


class CreatePolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyDocument: PolicyDocument
    tags: Optional[TagList]


class CreatePolicyResponse(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyArn: Optional[PolicyArn]
    policyDocument: Optional[PolicyDocument]
    policyVersionId: Optional[PolicyVersionId]


class CreatePolicyVersionRequest(ServiceRequest):
    policyName: PolicyName
    policyDocument: PolicyDocument
    setAsDefault: Optional[SetAsDefault]


class CreatePolicyVersionResponse(TypedDict, total=False):
    policyArn: Optional[PolicyArn]
    policyDocument: Optional[PolicyDocument]
    policyVersionId: Optional[PolicyVersionId]
    isDefaultVersion: Optional[IsDefaultVersion]


class CreateProvisioningClaimRequest(ServiceRequest):
    templateName: TemplateName


class CreateProvisioningClaimResponse(TypedDict, total=False):
    certificateId: Optional[CertificateId]
    certificatePem: Optional[CertificatePem]
    keyPair: Optional[KeyPair]
    expiration: Optional[DateType]


class ProvisioningHook(TypedDict, total=False):
    payloadVersion: Optional[PayloadVersion]
    targetArn: TargetArn


class CreateProvisioningTemplateRequest(ServiceRequest):
    templateName: TemplateName
    description: Optional[TemplateDescription]
    templateBody: TemplateBody
    enabled: Optional[Enabled]
    provisioningRoleArn: RoleArn
    preProvisioningHook: Optional[ProvisioningHook]
    tags: Optional[TagList]


class CreateProvisioningTemplateResponse(TypedDict, total=False):
    templateArn: Optional[TemplateArn]
    templateName: Optional[TemplateName]
    defaultVersionId: Optional[TemplateVersionId]


class CreateProvisioningTemplateVersionRequest(ServiceRequest):
    templateName: TemplateName
    templateBody: TemplateBody
    setAsDefault: Optional[SetAsDefault]


class CreateProvisioningTemplateVersionResponse(TypedDict, total=False):
    templateArn: Optional[TemplateArn]
    templateName: Optional[TemplateName]
    versionId: Optional[TemplateVersionId]
    isDefaultVersion: Optional[IsDefaultVersion]


class CreateRoleAliasRequest(ServiceRequest):
    roleAlias: RoleAlias
    roleArn: RoleArn
    credentialDurationSeconds: Optional[CredentialDurationSeconds]
    tags: Optional[TagList]


class CreateRoleAliasResponse(TypedDict, total=False):
    roleAlias: Optional[RoleAlias]
    roleAliasArn: Optional[RoleAliasArn]


TargetAuditCheckNames = List[AuditCheckName]


class CreateScheduledAuditRequest(ServiceRequest):
    frequency: AuditFrequency
    dayOfMonth: Optional[DayOfMonth]
    dayOfWeek: Optional[DayOfWeek]
    targetCheckNames: TargetAuditCheckNames
    scheduledAuditName: ScheduledAuditName
    tags: Optional[TagList]


class CreateScheduledAuditResponse(TypedDict, total=False):
    scheduledAuditArn: Optional[ScheduledAuditArn]


class CreateSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    securityProfileDescription: Optional[SecurityProfileDescription]
    behaviors: Optional[Behaviors]
    alertTargets: Optional[AlertTargets]
    additionalMetricsToRetain: Optional[AdditionalMetricsToRetainList]
    additionalMetricsToRetainV2: Optional[AdditionalMetricsToRetainV2List]
    tags: Optional[TagList]


class CreateSecurityProfileResponse(TypedDict, total=False):
    securityProfileName: Optional[SecurityProfileName]
    securityProfileArn: Optional[SecurityProfileArn]


class StreamFile(TypedDict, total=False):
    fileId: Optional[FileId]
    s3Location: Optional[S3Location]


StreamFiles = List[StreamFile]


class CreateStreamRequest(ServiceRequest):
    streamId: StreamId
    description: Optional[StreamDescription]
    files: StreamFiles
    roleArn: RoleArn
    tags: Optional[TagList]


class CreateStreamResponse(TypedDict, total=False):
    streamId: Optional[StreamId]
    streamArn: Optional[StreamArn]
    description: Optional[StreamDescription]
    streamVersion: Optional[StreamVersion]


class CreateThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    parentGroupName: Optional[ThingGroupName]
    thingGroupProperties: Optional[ThingGroupProperties]
    tags: Optional[TagList]


class CreateThingGroupResponse(TypedDict, total=False):
    thingGroupName: Optional[ThingGroupName]
    thingGroupArn: Optional[ThingGroupArn]
    thingGroupId: Optional[ThingGroupId]


class CreateThingRequest(ServiceRequest):
    thingName: ThingName
    thingTypeName: Optional[ThingTypeName]
    attributePayload: Optional[AttributePayload]
    billingGroupName: Optional[BillingGroupName]


class CreateThingResponse(TypedDict, total=False):
    thingName: Optional[ThingName]
    thingArn: Optional[ThingArn]
    thingId: Optional[ThingId]


SearchableAttributes = List[AttributeName]


class ThingTypeProperties(TypedDict, total=False):
    thingTypeDescription: Optional[ThingTypeDescription]
    searchableAttributes: Optional[SearchableAttributes]


class CreateThingTypeRequest(ServiceRequest):
    thingTypeName: ThingTypeName
    thingTypeProperties: Optional[ThingTypeProperties]
    tags: Optional[TagList]


class CreateThingTypeResponse(TypedDict, total=False):
    thingTypeName: Optional[ThingTypeName]
    thingTypeArn: Optional[ThingTypeArn]
    thingTypeId: Optional[ThingTypeId]


SecurityGroupList = List[SecurityGroupId]
SubnetIdList = List[SubnetId]


class VpcDestinationConfiguration(TypedDict, total=False):
    subnetIds: SubnetIdList
    securityGroups: Optional[SecurityGroupList]
    vpcId: VpcId
    roleArn: AwsArn


class HttpUrlDestinationConfiguration(TypedDict, total=False):
    confirmationUrl: Url


class TopicRuleDestinationConfiguration(TypedDict, total=False):
    httpUrlConfiguration: Optional[HttpUrlDestinationConfiguration]
    vpcConfiguration: Optional[VpcDestinationConfiguration]


class CreateTopicRuleDestinationRequest(ServiceRequest):
    destinationConfiguration: TopicRuleDestinationConfiguration


class VpcDestinationProperties(TypedDict, total=False):
    subnetIds: Optional[SubnetIdList]
    securityGroups: Optional[SecurityGroupList]
    vpcId: Optional[VpcId]
    roleArn: Optional[AwsArn]


class HttpUrlDestinationProperties(TypedDict, total=False):
    confirmationUrl: Optional[Url]


LastUpdatedAtDate = datetime
CreatedAtDate = datetime


class TopicRuleDestination(TypedDict, total=False):
    arn: Optional[AwsArn]
    status: Optional[TopicRuleDestinationStatus]
    createdAt: Optional[CreatedAtDate]
    lastUpdatedAt: Optional[LastUpdatedAtDate]
    statusReason: Optional[String]
    httpUrlProperties: Optional[HttpUrlDestinationProperties]
    vpcProperties: Optional[VpcDestinationProperties]


class CreateTopicRuleDestinationResponse(TypedDict, total=False):
    topicRuleDestination: Optional[TopicRuleDestination]


class TopicRulePayload(TypedDict, total=False):
    sql: SQL
    description: Optional[Description]
    actions: ActionList
    ruleDisabled: Optional[IsDisabled]
    awsIotSqlVersion: Optional[AwsIotSqlVersion]
    errorAction: Optional[Action]


class CreateTopicRuleRequest(ServiceRequest):
    ruleName: RuleName
    topicRulePayload: TopicRulePayload
    tags: Optional[String]


class DeleteAccountAuditConfigurationRequest(ServiceRequest):
    deleteScheduledAudits: Optional[DeleteScheduledAudits]


class DeleteAccountAuditConfigurationResponse(TypedDict, total=False):
    pass


class DeleteAuditSuppressionRequest(ServiceRequest):
    checkName: AuditCheckName
    resourceIdentifier: ResourceIdentifier


class DeleteAuditSuppressionResponse(TypedDict, total=False):
    pass


class DeleteAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName


class DeleteAuthorizerResponse(TypedDict, total=False):
    pass


OptionalVersion = int


class DeleteBillingGroupRequest(ServiceRequest):
    billingGroupName: BillingGroupName
    expectedVersion: Optional[OptionalVersion]


class DeleteBillingGroupResponse(TypedDict, total=False):
    pass


class DeleteCACertificateRequest(ServiceRequest):
    certificateId: CertificateId


class DeleteCACertificateResponse(TypedDict, total=False):
    pass


class DeleteCertificateRequest(ServiceRequest):
    certificateId: CertificateId
    forceDelete: Optional[ForceDelete]


class DeleteCustomMetricRequest(ServiceRequest):
    metricName: MetricName


class DeleteCustomMetricResponse(TypedDict, total=False):
    pass


class DeleteDimensionRequest(ServiceRequest):
    name: DimensionName


class DeleteDimensionResponse(TypedDict, total=False):
    pass


class DeleteDomainConfigurationRequest(ServiceRequest):
    domainConfigurationName: DomainConfigurationName


class DeleteDomainConfigurationResponse(TypedDict, total=False):
    pass


class DeleteDynamicThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    expectedVersion: Optional[OptionalVersion]


class DeleteDynamicThingGroupResponse(TypedDict, total=False):
    pass


class DeleteFleetMetricRequest(ServiceRequest):
    metricName: FleetMetricName
    expectedVersion: Optional[OptionalVersion]


ExecutionNumber = int


class DeleteJobExecutionRequest(ServiceRequest):
    jobId: JobId
    thingName: ThingName
    executionNumber: ExecutionNumber
    force: Optional[ForceFlag]
    namespaceId: Optional[NamespaceId]


class DeleteJobRequest(ServiceRequest):
    jobId: JobId
    force: Optional[ForceFlag]
    namespaceId: Optional[NamespaceId]


class DeleteJobTemplateRequest(ServiceRequest):
    jobTemplateId: JobTemplateId


class DeleteMitigationActionRequest(ServiceRequest):
    actionName: MitigationActionName


class DeleteMitigationActionResponse(TypedDict, total=False):
    pass


class DeleteOTAUpdateRequest(ServiceRequest):
    otaUpdateId: OTAUpdateId
    deleteStream: Optional[DeleteStream]
    forceDeleteAWSJob: Optional[ForceDeleteAWSJob]


class DeleteOTAUpdateResponse(TypedDict, total=False):
    pass


class DeletePolicyRequest(ServiceRequest):
    policyName: PolicyName


class DeletePolicyVersionRequest(ServiceRequest):
    policyName: PolicyName
    policyVersionId: PolicyVersionId


class DeleteProvisioningTemplateRequest(ServiceRequest):
    templateName: TemplateName


class DeleteProvisioningTemplateResponse(TypedDict, total=False):
    pass


class DeleteProvisioningTemplateVersionRequest(ServiceRequest):
    templateName: TemplateName
    versionId: TemplateVersionId


class DeleteProvisioningTemplateVersionResponse(TypedDict, total=False):
    pass


class DeleteRegistrationCodeRequest(ServiceRequest):
    pass


class DeleteRegistrationCodeResponse(TypedDict, total=False):
    pass


class DeleteRoleAliasRequest(ServiceRequest):
    roleAlias: RoleAlias


class DeleteRoleAliasResponse(TypedDict, total=False):
    pass


class DeleteScheduledAuditRequest(ServiceRequest):
    scheduledAuditName: ScheduledAuditName


class DeleteScheduledAuditResponse(TypedDict, total=False):
    pass


class DeleteSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    expectedVersion: Optional[OptionalVersion]


class DeleteSecurityProfileResponse(TypedDict, total=False):
    pass


class DeleteStreamRequest(ServiceRequest):
    streamId: StreamId


class DeleteStreamResponse(TypedDict, total=False):
    pass


class DeleteThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    expectedVersion: Optional[OptionalVersion]


class DeleteThingGroupResponse(TypedDict, total=False):
    pass


class DeleteThingRequest(ServiceRequest):
    thingName: ThingName
    expectedVersion: Optional[OptionalVersion]


class DeleteThingResponse(TypedDict, total=False):
    pass


class DeleteThingTypeRequest(ServiceRequest):
    thingTypeName: ThingTypeName


class DeleteThingTypeResponse(TypedDict, total=False):
    pass


class DeleteTopicRuleDestinationRequest(ServiceRequest):
    arn: AwsArn


class DeleteTopicRuleDestinationResponse(TypedDict, total=False):
    pass


class DeleteTopicRuleRequest(ServiceRequest):
    ruleName: RuleName


class DeleteV2LoggingLevelRequest(ServiceRequest):
    targetType: LogTargetType
    targetName: LogTargetName


class DeprecateThingTypeRequest(ServiceRequest):
    thingTypeName: ThingTypeName
    undoDeprecate: Optional[UndoDeprecate]


class DeprecateThingTypeResponse(TypedDict, total=False):
    pass


DeprecationDate = datetime


class DescribeAccountAuditConfigurationRequest(ServiceRequest):
    pass


class DescribeAccountAuditConfigurationResponse(TypedDict, total=False):
    roleArn: Optional[RoleArn]
    auditNotificationTargetConfigurations: Optional[AuditNotificationTargetConfigurations]
    auditCheckConfigurations: Optional[AuditCheckConfigurations]


class DescribeAuditFindingRequest(ServiceRequest):
    findingId: FindingId


class DescribeAuditFindingResponse(TypedDict, total=False):
    finding: Optional[AuditFinding]


class DescribeAuditMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId


class MitigationAction(TypedDict, total=False):
    name: Optional[MitigationActionName]
    id: Optional[MitigationActionId]
    roleArn: Optional[RoleArn]
    actionParams: Optional[MitigationActionParams]


MitigationActionList = List[MitigationAction]


class DescribeAuditMitigationActionsTaskResponse(TypedDict, total=False):
    taskStatus: Optional[AuditMitigationActionsTaskStatus]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    taskStatistics: Optional[AuditMitigationActionsTaskStatistics]
    target: Optional[AuditMitigationActionsTaskTarget]
    auditCheckToActionsMapping: Optional[AuditCheckToActionsMapping]
    actionsDefinition: Optional[MitigationActionList]


class DescribeAuditSuppressionRequest(ServiceRequest):
    checkName: AuditCheckName
    resourceIdentifier: ResourceIdentifier


class DescribeAuditSuppressionResponse(TypedDict, total=False):
    checkName: Optional[AuditCheckName]
    resourceIdentifier: Optional[ResourceIdentifier]
    expirationDate: Optional[Timestamp]
    suppressIndefinitely: Optional[SuppressIndefinitely]
    description: Optional[AuditDescription]


class DescribeAuditTaskRequest(ServiceRequest):
    taskId: AuditTaskId


class TaskStatistics(TypedDict, total=False):
    totalChecks: Optional[TotalChecksCount]
    inProgressChecks: Optional[InProgressChecksCount]
    waitingForDataCollectionChecks: Optional[WaitingForDataCollectionChecksCount]
    compliantChecks: Optional[CompliantChecksCount]
    nonCompliantChecks: Optional[NonCompliantChecksCount]
    failedChecks: Optional[FailedChecksCount]
    canceledChecks: Optional[CanceledChecksCount]


class DescribeAuditTaskResponse(TypedDict, total=False):
    taskStatus: Optional[AuditTaskStatus]
    taskType: Optional[AuditTaskType]
    taskStartTime: Optional[Timestamp]
    taskStatistics: Optional[TaskStatistics]
    scheduledAuditName: Optional[ScheduledAuditName]
    auditDetails: Optional[AuditDetails]


class DescribeAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName


class DescribeAuthorizerResponse(TypedDict, total=False):
    authorizerDescription: Optional[AuthorizerDescription]


class DescribeBillingGroupRequest(ServiceRequest):
    billingGroupName: BillingGroupName


Version = int


class DescribeBillingGroupResponse(TypedDict, total=False):
    billingGroupName: Optional[BillingGroupName]
    billingGroupId: Optional[BillingGroupId]
    billingGroupArn: Optional[BillingGroupArn]
    version: Optional[Version]
    billingGroupProperties: Optional[BillingGroupProperties]
    billingGroupMetadata: Optional[BillingGroupMetadata]


class DescribeCACertificateRequest(ServiceRequest):
    certificateId: CertificateId


class RegistrationConfig(TypedDict, total=False):
    templateBody: Optional[TemplateBody]
    roleArn: Optional[RoleArn]


class DescribeCACertificateResponse(TypedDict, total=False):
    certificateDescription: Optional[CACertificateDescription]
    registrationConfig: Optional[RegistrationConfig]


class DescribeCertificateRequest(ServiceRequest):
    certificateId: CertificateId


class DescribeCertificateResponse(TypedDict, total=False):
    certificateDescription: Optional[CertificateDescription]


class DescribeCustomMetricRequest(ServiceRequest):
    metricName: MetricName


class DescribeCustomMetricResponse(TypedDict, total=False):
    metricName: Optional[MetricName]
    metricArn: Optional[CustomMetricArn]
    metricType: Optional[CustomMetricType]
    displayName: Optional[CustomMetricDisplayName]
    creationDate: Optional[Timestamp]
    lastModifiedDate: Optional[Timestamp]


class DescribeDefaultAuthorizerRequest(ServiceRequest):
    pass


class DescribeDefaultAuthorizerResponse(TypedDict, total=False):
    authorizerDescription: Optional[AuthorizerDescription]


class DescribeDetectMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId


GenericLongValue = int


class DetectMitigationActionsTaskStatistics(TypedDict, total=False):
    actionsExecuted: Optional[GenericLongValue]
    actionsSkipped: Optional[GenericLongValue]
    actionsFailed: Optional[GenericLongValue]


class ViolationEventOccurrenceRange(TypedDict, total=False):
    startTime: Timestamp
    endTime: Timestamp


TargetViolationIdsForDetectMitigationActions = List[ViolationId]


class DetectMitigationActionsTaskTarget(TypedDict, total=False):
    violationIds: Optional[TargetViolationIdsForDetectMitigationActions]
    securityProfileName: Optional[SecurityProfileName]
    behaviorName: Optional[BehaviorName]


class DetectMitigationActionsTaskSummary(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]
    taskStatus: Optional[DetectMitigationActionsTaskStatus]
    taskStartTime: Optional[Timestamp]
    taskEndTime: Optional[Timestamp]
    target: Optional[DetectMitigationActionsTaskTarget]
    violationEventOccurrenceRange: Optional[ViolationEventOccurrenceRange]
    onlyActiveViolationsIncluded: Optional[PrimitiveBoolean]
    suppressedAlertsIncluded: Optional[PrimitiveBoolean]
    actionsDefinition: Optional[MitigationActionList]
    taskStatistics: Optional[DetectMitigationActionsTaskStatistics]


class DescribeDetectMitigationActionsTaskResponse(TypedDict, total=False):
    taskSummary: Optional[DetectMitigationActionsTaskSummary]


class DescribeDimensionRequest(ServiceRequest):
    name: DimensionName


DescribeDimensionResponse = TypedDict(
    "DescribeDimensionResponse",
    {
        "name": Optional[DimensionName],
        "arn": Optional[DimensionArn],
        "type": Optional[DimensionType],
        "stringValues": Optional[DimensionStringValues],
        "creationDate": Optional[Timestamp],
        "lastModifiedDate": Optional[Timestamp],
    },
    total=False,
)


class DescribeDomainConfigurationRequest(ServiceRequest):
    domainConfigurationName: ReservedDomainConfigurationName


class ServerCertificateSummary(TypedDict, total=False):
    serverCertificateArn: Optional[AcmCertificateArn]
    serverCertificateStatus: Optional[ServerCertificateStatus]
    serverCertificateStatusDetail: Optional[ServerCertificateStatusDetail]


ServerCertificates = List[ServerCertificateSummary]


class DescribeDomainConfigurationResponse(TypedDict, total=False):
    domainConfigurationName: Optional[ReservedDomainConfigurationName]
    domainConfigurationArn: Optional[DomainConfigurationArn]
    domainName: Optional[DomainName]
    serverCertificates: Optional[ServerCertificates]
    authorizerConfig: Optional[AuthorizerConfig]
    domainConfigurationStatus: Optional[DomainConfigurationStatus]
    serviceType: Optional[ServiceType]
    domainType: Optional[DomainType]
    lastStatusChangeDate: Optional[DateType]


class DescribeEndpointRequest(ServiceRequest):
    endpointType: Optional[EndpointType]


class DescribeEndpointResponse(TypedDict, total=False):
    endpointAddress: Optional[EndpointAddress]


class DescribeEventConfigurationsRequest(ServiceRequest):
    pass


LastModifiedDate = datetime
EventConfigurations = Dict[EventType, Configuration]


class DescribeEventConfigurationsResponse(TypedDict, total=False):
    eventConfigurations: Optional[EventConfigurations]
    creationDate: Optional[CreationDate]
    lastModifiedDate: Optional[LastModifiedDate]


class DescribeFleetMetricRequest(ServiceRequest):
    metricName: FleetMetricName


class DescribeFleetMetricResponse(TypedDict, total=False):
    metricName: Optional[FleetMetricName]
    queryString: Optional[QueryString]
    aggregationType: Optional[AggregationType]
    period: Optional[FleetMetricPeriod]
    aggregationField: Optional[AggregationField]
    description: Optional[FleetMetricDescription]
    queryVersion: Optional[QueryVersion]
    indexName: Optional[IndexName]
    creationDate: Optional[CreationDate]
    lastModifiedDate: Optional[LastModifiedDate]
    unit: Optional[FleetMetricUnit]
    version: Optional[Version]
    metricArn: Optional[FleetMetricArn]


class DescribeIndexRequest(ServiceRequest):
    indexName: IndexName


class DescribeIndexResponse(TypedDict, total=False):
    indexName: Optional[IndexName]
    indexStatus: Optional[IndexStatus]
    schema: Optional[IndexSchema]


class DescribeJobExecutionRequest(ServiceRequest):
    jobId: JobId
    thingName: ThingName
    executionNumber: Optional[ExecutionNumber]


VersionNumber = int


class JobExecutionStatusDetails(TypedDict, total=False):
    detailsMap: Optional[DetailsMap]


class JobExecution(TypedDict, total=False):
    jobId: Optional[JobId]
    status: Optional[JobExecutionStatus]
    forceCanceled: Optional[Forced]
    statusDetails: Optional[JobExecutionStatusDetails]
    thingArn: Optional[ThingArn]
    queuedAt: Optional[DateType]
    startedAt: Optional[DateType]
    lastUpdatedAt: Optional[DateType]
    executionNumber: Optional[ExecutionNumber]
    versionNumber: Optional[VersionNumber]
    approximateSecondsBeforeTimedOut: Optional[ApproximateSecondsBeforeTimedOut]


class DescribeJobExecutionResponse(TypedDict, total=False):
    execution: Optional[JobExecution]


class DescribeJobRequest(ServiceRequest):
    jobId: JobId


ProcessingTargetNameList = List[ProcessingTargetName]


class JobProcessDetails(TypedDict, total=False):
    processingTargets: Optional[ProcessingTargetNameList]
    numberOfCanceledThings: Optional[CanceledThings]
    numberOfSucceededThings: Optional[SucceededThings]
    numberOfFailedThings: Optional[FailedThings]
    numberOfRejectedThings: Optional[RejectedThings]
    numberOfQueuedThings: Optional[QueuedThings]
    numberOfInProgressThings: Optional[InProgressThings]
    numberOfRemovedThings: Optional[RemovedThings]
    numberOfTimedOutThings: Optional[TimedOutThings]


class Job(TypedDict, total=False):
    jobArn: Optional[JobArn]
    jobId: Optional[JobId]
    targetSelection: Optional[TargetSelection]
    status: Optional[JobStatus]
    forceCanceled: Optional[Forced]
    reasonCode: Optional[ReasonCode]
    comment: Optional[Comment]
    targets: Optional[JobTargets]
    description: Optional[JobDescription]
    presignedUrlConfig: Optional[PresignedUrlConfig]
    jobExecutionsRolloutConfig: Optional[JobExecutionsRolloutConfig]
    abortConfig: Optional[AbortConfig]
    createdAt: Optional[DateType]
    lastUpdatedAt: Optional[DateType]
    completedAt: Optional[DateType]
    jobProcessDetails: Optional[JobProcessDetails]
    timeoutConfig: Optional[TimeoutConfig]
    namespaceId: Optional[NamespaceId]
    jobTemplateArn: Optional[JobTemplateArn]
    jobExecutionsRetryConfig: Optional[JobExecutionsRetryConfig]
    documentParameters: Optional[ParameterMap]


class DescribeJobResponse(TypedDict, total=False):
    documentSource: Optional[JobDocumentSource]
    job: Optional[Job]


class DescribeJobTemplateRequest(ServiceRequest):
    jobTemplateId: JobTemplateId


class DescribeJobTemplateResponse(TypedDict, total=False):
    jobTemplateArn: Optional[JobTemplateArn]
    jobTemplateId: Optional[JobTemplateId]
    description: Optional[JobDescription]
    documentSource: Optional[JobDocumentSource]
    document: Optional[JobDocument]
    createdAt: Optional[DateType]
    presignedUrlConfig: Optional[PresignedUrlConfig]
    jobExecutionsRolloutConfig: Optional[JobExecutionsRolloutConfig]
    abortConfig: Optional[AbortConfig]
    timeoutConfig: Optional[TimeoutConfig]
    jobExecutionsRetryConfig: Optional[JobExecutionsRetryConfig]


class DescribeManagedJobTemplateRequest(ServiceRequest):
    templateName: ManagedJobTemplateName
    templateVersion: Optional[ManagedTemplateVersion]


class DocumentParameter(TypedDict, total=False):
    key: Optional[ParameterKey]
    description: Optional[JobDescription]
    regex: Optional[Regex]
    example: Optional[Example]
    optional: Optional[Optional_]


DocumentParameters = List[DocumentParameter]
Environments = List[Environment]


class DescribeManagedJobTemplateResponse(TypedDict, total=False):
    templateName: Optional[ManagedJobTemplateName]
    templateArn: Optional[JobTemplateArn]
    description: Optional[JobDescription]
    templateVersion: Optional[ManagedTemplateVersion]
    environments: Optional[Environments]
    documentParameters: Optional[DocumentParameters]
    document: Optional[JobDocument]


class DescribeMitigationActionRequest(ServiceRequest):
    actionName: MitigationActionName


class DescribeMitigationActionResponse(TypedDict, total=False):
    actionName: Optional[MitigationActionName]
    actionType: Optional[MitigationActionType]
    actionArn: Optional[MitigationActionArn]
    actionId: Optional[MitigationActionId]
    roleArn: Optional[RoleArn]
    actionParams: Optional[MitigationActionParams]
    creationDate: Optional[Timestamp]
    lastModifiedDate: Optional[Timestamp]


class DescribeProvisioningTemplateRequest(ServiceRequest):
    templateName: TemplateName


class DescribeProvisioningTemplateResponse(TypedDict, total=False):
    templateArn: Optional[TemplateArn]
    templateName: Optional[TemplateName]
    description: Optional[TemplateDescription]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    defaultVersionId: Optional[TemplateVersionId]
    templateBody: Optional[TemplateBody]
    enabled: Optional[Enabled]
    provisioningRoleArn: Optional[RoleArn]
    preProvisioningHook: Optional[ProvisioningHook]


class DescribeProvisioningTemplateVersionRequest(ServiceRequest):
    templateName: TemplateName
    versionId: TemplateVersionId


class DescribeProvisioningTemplateVersionResponse(TypedDict, total=False):
    versionId: Optional[TemplateVersionId]
    creationDate: Optional[DateType]
    templateBody: Optional[TemplateBody]
    isDefaultVersion: Optional[IsDefaultVersion]


class DescribeRoleAliasRequest(ServiceRequest):
    roleAlias: RoleAlias


class RoleAliasDescription(TypedDict, total=False):
    roleAlias: Optional[RoleAlias]
    roleAliasArn: Optional[RoleAliasArn]
    roleArn: Optional[RoleArn]
    owner: Optional[AwsAccountId]
    credentialDurationSeconds: Optional[CredentialDurationSeconds]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]


class DescribeRoleAliasResponse(TypedDict, total=False):
    roleAliasDescription: Optional[RoleAliasDescription]


class DescribeScheduledAuditRequest(ServiceRequest):
    scheduledAuditName: ScheduledAuditName


class DescribeScheduledAuditResponse(TypedDict, total=False):
    frequency: Optional[AuditFrequency]
    dayOfMonth: Optional[DayOfMonth]
    dayOfWeek: Optional[DayOfWeek]
    targetCheckNames: Optional[TargetAuditCheckNames]
    scheduledAuditName: Optional[ScheduledAuditName]
    scheduledAuditArn: Optional[ScheduledAuditArn]


class DescribeSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName


class DescribeSecurityProfileResponse(TypedDict, total=False):
    securityProfileName: Optional[SecurityProfileName]
    securityProfileArn: Optional[SecurityProfileArn]
    securityProfileDescription: Optional[SecurityProfileDescription]
    behaviors: Optional[Behaviors]
    alertTargets: Optional[AlertTargets]
    additionalMetricsToRetain: Optional[AdditionalMetricsToRetainList]
    additionalMetricsToRetainV2: Optional[AdditionalMetricsToRetainV2List]
    version: Optional[Version]
    creationDate: Optional[Timestamp]
    lastModifiedDate: Optional[Timestamp]


class DescribeStreamRequest(ServiceRequest):
    streamId: StreamId


class StreamInfo(TypedDict, total=False):
    streamId: Optional[StreamId]
    streamArn: Optional[StreamArn]
    streamVersion: Optional[StreamVersion]
    description: Optional[StreamDescription]
    files: Optional[StreamFiles]
    createdAt: Optional[DateType]
    lastUpdatedAt: Optional[DateType]
    roleArn: Optional[RoleArn]


class DescribeStreamResponse(TypedDict, total=False):
    streamInfo: Optional[StreamInfo]


class DescribeThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName


ThingGroupNameAndArnList = List[GroupNameAndArn]


class ThingGroupMetadata(TypedDict, total=False):
    parentGroupName: Optional[ThingGroupName]
    rootToParentThingGroups: Optional[ThingGroupNameAndArnList]
    creationDate: Optional[CreationDate]


class DescribeThingGroupResponse(TypedDict, total=False):
    thingGroupName: Optional[ThingGroupName]
    thingGroupId: Optional[ThingGroupId]
    thingGroupArn: Optional[ThingGroupArn]
    version: Optional[Version]
    thingGroupProperties: Optional[ThingGroupProperties]
    thingGroupMetadata: Optional[ThingGroupMetadata]
    indexName: Optional[IndexName]
    queryString: Optional[QueryString]
    queryVersion: Optional[QueryVersion]
    status: Optional[DynamicGroupStatus]


class DescribeThingRegistrationTaskRequest(ServiceRequest):
    taskId: TaskId


class DescribeThingRegistrationTaskResponse(TypedDict, total=False):
    taskId: Optional[TaskId]
    creationDate: Optional[CreationDate]
    lastModifiedDate: Optional[LastModifiedDate]
    templateBody: Optional[TemplateBody]
    inputFileBucket: Optional[RegistryS3BucketName]
    inputFileKey: Optional[RegistryS3KeyName]
    roleArn: Optional[RoleArn]
    status: Optional[Status]
    message: Optional[ErrorMessage]
    successCount: Optional[Count]
    failureCount: Optional[Count]
    percentageProgress: Optional[Percentage]


class DescribeThingRequest(ServiceRequest):
    thingName: ThingName


class DescribeThingResponse(TypedDict, total=False):
    defaultClientId: Optional[ClientId]
    thingName: Optional[ThingName]
    thingId: Optional[ThingId]
    thingArn: Optional[ThingArn]
    thingTypeName: Optional[ThingTypeName]
    attributes: Optional[Attributes]
    version: Optional[Version]
    billingGroupName: Optional[BillingGroupName]


class DescribeThingTypeRequest(ServiceRequest):
    thingTypeName: ThingTypeName


class ThingTypeMetadata(TypedDict, total=False):
    deprecated: Optional[Boolean]
    deprecationDate: Optional[DeprecationDate]
    creationDate: Optional[CreationDate]


class DescribeThingTypeResponse(TypedDict, total=False):
    thingTypeName: Optional[ThingTypeName]
    thingTypeId: Optional[ThingTypeId]
    thingTypeArn: Optional[ThingTypeArn]
    thingTypeProperties: Optional[ThingTypeProperties]
    thingTypeMetadata: Optional[ThingTypeMetadata]


class DetachPolicyRequest(ServiceRequest):
    policyName: PolicyName
    target: PolicyTarget


class DetachPrincipalPolicyRequest(ServiceRequest):
    policyName: PolicyName
    principal: Principal


class DetachSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    securityProfileTargetArn: SecurityProfileTargetArn


class DetachSecurityProfileResponse(TypedDict, total=False):
    pass


class DetachThingPrincipalRequest(ServiceRequest):
    thingName: ThingName
    principal: Principal


class DetachThingPrincipalResponse(TypedDict, total=False):
    pass


class DetectMitigationActionExecution(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]
    violationId: Optional[ViolationId]
    actionName: Optional[MitigationActionName]
    thingName: Optional[DeviceDefenderThingName]
    executionStartDate: Optional[Timestamp]
    executionEndDate: Optional[Timestamp]
    status: Optional[DetectMitigationActionExecutionStatus]
    errorCode: Optional[DetectMitigationActionExecutionErrorCode]
    message: Optional[ErrorMessage]


DetectMitigationActionExecutionList = List[DetectMitigationActionExecution]
DetectMitigationActionsTaskSummaryList = List[DetectMitigationActionsTaskSummary]
DetectMitigationActionsToExecuteList = List[MitigationActionName]
DimensionNames = List[DimensionName]


class DisableTopicRuleRequest(ServiceRequest):
    ruleName: RuleName


class DomainConfigurationSummary(TypedDict, total=False):
    domainConfigurationName: Optional[ReservedDomainConfigurationName]
    domainConfigurationArn: Optional[DomainConfigurationArn]
    serviceType: Optional[ServiceType]


DomainConfigurations = List[DomainConfigurationSummary]


class EffectivePolicy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyArn: Optional[PolicyArn]
    policyDocument: Optional[PolicyDocument]


EffectivePolicies = List[EffectivePolicy]


class EnableTopicRuleRequest(ServiceRequest):
    ruleName: RuleName


class ErrorInfo(TypedDict, total=False):
    code: Optional[Code]
    message: Optional[OTAUpdateErrorMessage]


Field = TypedDict(
    "Field",
    {
        "name": Optional[FieldName],
        "type": Optional[FieldType],
    },
    total=False,
)
Fields = List[Field]


class FleetMetricNameAndArn(TypedDict, total=False):
    metricName: Optional[FleetMetricName]
    metricArn: Optional[FleetMetricArn]


FleetMetricNameAndArnList = List[FleetMetricNameAndArn]


class GetBehaviorModelTrainingSummariesRequest(ServiceRequest):
    securityProfileName: Optional[SecurityProfileName]
    maxResults: Optional[TinyMaxResults]
    nextToken: Optional[NextToken]


class GetBehaviorModelTrainingSummariesResponse(TypedDict, total=False):
    summaries: Optional[BehaviorModelTrainingSummaries]
    nextToken: Optional[NextToken]


class GetBucketsAggregationRequest(ServiceRequest):
    indexName: Optional[IndexName]
    queryString: QueryString
    aggregationField: AggregationField
    queryVersion: Optional[QueryVersion]
    bucketsAggregationType: BucketsAggregationType


class GetBucketsAggregationResponse(TypedDict, total=False):
    totalCount: Optional[Count]
    buckets: Optional[Buckets]


class GetCardinalityRequest(ServiceRequest):
    indexName: Optional[IndexName]
    queryString: QueryString
    aggregationField: Optional[AggregationField]
    queryVersion: Optional[QueryVersion]


class GetCardinalityResponse(TypedDict, total=False):
    cardinality: Optional[Count]


class GetEffectivePoliciesRequest(ServiceRequest):
    principal: Optional[Principal]
    cognitoIdentityPoolId: Optional[CognitoIdentityPoolId]
    thingName: Optional[ThingName]


class GetEffectivePoliciesResponse(TypedDict, total=False):
    effectivePolicies: Optional[EffectivePolicies]


class GetIndexingConfigurationRequest(ServiceRequest):
    pass


class ThingGroupIndexingConfiguration(TypedDict, total=False):
    thingGroupIndexingMode: ThingGroupIndexingMode
    managedFields: Optional[Fields]
    customFields: Optional[Fields]


class ThingIndexingConfiguration(TypedDict, total=False):
    thingIndexingMode: ThingIndexingMode
    thingConnectivityIndexingMode: Optional[ThingConnectivityIndexingMode]
    deviceDefenderIndexingMode: Optional[DeviceDefenderIndexingMode]
    namedShadowIndexingMode: Optional[NamedShadowIndexingMode]
    managedFields: Optional[Fields]
    customFields: Optional[Fields]


class GetIndexingConfigurationResponse(TypedDict, total=False):
    thingIndexingConfiguration: Optional[ThingIndexingConfiguration]
    thingGroupIndexingConfiguration: Optional[ThingGroupIndexingConfiguration]


class GetJobDocumentRequest(ServiceRequest):
    jobId: JobId


class GetJobDocumentResponse(TypedDict, total=False):
    document: Optional[JobDocument]


class GetLoggingOptionsRequest(ServiceRequest):
    pass


class GetLoggingOptionsResponse(TypedDict, total=False):
    roleArn: Optional[AwsArn]
    logLevel: Optional[LogLevel]


class GetOTAUpdateRequest(ServiceRequest):
    otaUpdateId: OTAUpdateId


class OTAUpdateInfo(TypedDict, total=False):
    otaUpdateId: Optional[OTAUpdateId]
    otaUpdateArn: Optional[OTAUpdateArn]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    description: Optional[OTAUpdateDescription]
    targets: Optional[Targets]
    protocols: Optional[Protocols]
    awsJobExecutionsRolloutConfig: Optional[AwsJobExecutionsRolloutConfig]
    awsJobPresignedUrlConfig: Optional[AwsJobPresignedUrlConfig]
    targetSelection: Optional[TargetSelection]
    otaUpdateFiles: Optional[OTAUpdateFiles]
    otaUpdateStatus: Optional[OTAUpdateStatus]
    awsIotJobId: Optional[AwsIotJobId]
    awsIotJobArn: Optional[AwsIotJobArn]
    errorInfo: Optional[ErrorInfo]
    additionalParameters: Optional[AdditionalParameterMap]


class GetOTAUpdateResponse(TypedDict, total=False):
    otaUpdateInfo: Optional[OTAUpdateInfo]


PercentList = List[Percent]


class GetPercentilesRequest(ServiceRequest):
    indexName: Optional[IndexName]
    queryString: QueryString
    aggregationField: Optional[AggregationField]
    queryVersion: Optional[QueryVersion]
    percents: Optional[PercentList]


class PercentPair(TypedDict, total=False):
    percent: Optional[Percent]
    value: Optional[PercentValue]


Percentiles = List[PercentPair]


class GetPercentilesResponse(TypedDict, total=False):
    percentiles: Optional[Percentiles]


class GetPolicyRequest(ServiceRequest):
    policyName: PolicyName


class GetPolicyResponse(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyArn: Optional[PolicyArn]
    policyDocument: Optional[PolicyDocument]
    defaultVersionId: Optional[PolicyVersionId]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    generationId: Optional[GenerationId]


class GetPolicyVersionRequest(ServiceRequest):
    policyName: PolicyName
    policyVersionId: PolicyVersionId


class GetPolicyVersionResponse(TypedDict, total=False):
    policyArn: Optional[PolicyArn]
    policyName: Optional[PolicyName]
    policyDocument: Optional[PolicyDocument]
    policyVersionId: Optional[PolicyVersionId]
    isDefaultVersion: Optional[IsDefaultVersion]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    generationId: Optional[GenerationId]


class GetRegistrationCodeRequest(ServiceRequest):
    pass


class GetRegistrationCodeResponse(TypedDict, total=False):
    registrationCode: Optional[RegistrationCode]


class GetStatisticsRequest(ServiceRequest):
    indexName: Optional[IndexName]
    queryString: QueryString
    aggregationField: Optional[AggregationField]
    queryVersion: Optional[QueryVersion]


class Statistics(TypedDict, total=False):
    count: Optional[Count]
    average: Optional[Average]
    sum: Optional[Sum]
    minimum: Optional[Minimum]
    maximum: Optional[Maximum]
    sumOfSquares: Optional[SumOfSquares]
    variance: Optional[Variance]
    stdDeviation: Optional[StdDeviation]


class GetStatisticsResponse(TypedDict, total=False):
    statistics: Optional[Statistics]


class GetTopicRuleDestinationRequest(ServiceRequest):
    arn: AwsArn


class GetTopicRuleDestinationResponse(TypedDict, total=False):
    topicRuleDestination: Optional[TopicRuleDestination]


class GetTopicRuleRequest(ServiceRequest):
    ruleName: RuleName


class TopicRule(TypedDict, total=False):
    ruleName: Optional[RuleName]
    sql: Optional[SQL]
    description: Optional[Description]
    createdAt: Optional[CreatedAtDate]
    actions: Optional[ActionList]
    ruleDisabled: Optional[IsDisabled]
    awsIotSqlVersion: Optional[AwsIotSqlVersion]
    errorAction: Optional[Action]


class GetTopicRuleResponse(TypedDict, total=False):
    ruleArn: Optional[RuleArn]
    rule: Optional[TopicRule]


class GetV2LoggingOptionsRequest(ServiceRequest):
    pass


class GetV2LoggingOptionsResponse(TypedDict, total=False):
    roleArn: Optional[AwsArn]
    defaultLogLevel: Optional[LogLevel]
    disableAllLogs: Optional[DisableAllLogs]


HttpHeaders = Dict[HttpHeaderName, HttpHeaderValue]


class HttpContext(TypedDict, total=False):
    headers: Optional[HttpHeaders]
    queryString: Optional[HttpQueryString]


class HttpUrlDestinationSummary(TypedDict, total=False):
    confirmationUrl: Optional[Url]


IndexNamesList = List[IndexName]


class JobExecutionSummary(TypedDict, total=False):
    status: Optional[JobExecutionStatus]
    queuedAt: Optional[DateType]
    startedAt: Optional[DateType]
    lastUpdatedAt: Optional[DateType]
    executionNumber: Optional[ExecutionNumber]
    retryAttempt: Optional[RetryAttempt]


class JobExecutionSummaryForJob(TypedDict, total=False):
    thingArn: Optional[ThingArn]
    jobExecutionSummary: Optional[JobExecutionSummary]


JobExecutionSummaryForJobList = List[JobExecutionSummaryForJob]


class JobExecutionSummaryForThing(TypedDict, total=False):
    jobId: Optional[JobId]
    jobExecutionSummary: Optional[JobExecutionSummary]


JobExecutionSummaryForThingList = List[JobExecutionSummaryForThing]


class JobSummary(TypedDict, total=False):
    jobArn: Optional[JobArn]
    jobId: Optional[JobId]
    thingGroupId: Optional[ThingGroupId]
    targetSelection: Optional[TargetSelection]
    status: Optional[JobStatus]
    createdAt: Optional[DateType]
    lastUpdatedAt: Optional[DateType]
    completedAt: Optional[DateType]


JobSummaryList = List[JobSummary]


class JobTemplateSummary(TypedDict, total=False):
    jobTemplateArn: Optional[JobTemplateArn]
    jobTemplateId: Optional[JobTemplateId]
    description: Optional[JobDescription]
    createdAt: Optional[DateType]


JobTemplateSummaryList = List[JobTemplateSummary]


class ListActiveViolationsRequest(ServiceRequest):
    thingName: Optional[DeviceDefenderThingName]
    securityProfileName: Optional[SecurityProfileName]
    behaviorCriteriaType: Optional[BehaviorCriteriaType]
    listSuppressedAlerts: Optional[ListSuppressedAlerts]
    verificationState: Optional[VerificationState]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListActiveViolationsResponse(TypedDict, total=False):
    activeViolations: Optional[ActiveViolations]
    nextToken: Optional[NextToken]


class ListAttachedPoliciesRequest(ServiceRequest):
    target: PolicyTarget
    recursive: Optional[Recursive]
    marker: Optional[Marker]
    pageSize: Optional[PageSize]


class ListAttachedPoliciesResponse(TypedDict, total=False):
    policies: Optional[Policies]
    nextMarker: Optional[Marker]


class ListAuditFindingsRequest(ServiceRequest):
    taskId: Optional[AuditTaskId]
    checkName: Optional[AuditCheckName]
    resourceIdentifier: Optional[ResourceIdentifier]
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    listSuppressedFindings: Optional[ListSuppressedFindings]


class ListAuditFindingsResponse(TypedDict, total=False):
    findings: Optional[AuditFindings]
    nextToken: Optional[NextToken]


class ListAuditMitigationActionsExecutionsRequest(ServiceRequest):
    taskId: MitigationActionsTaskId
    actionStatus: Optional[AuditMitigationActionsExecutionStatus]
    findingId: FindingId
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class ListAuditMitigationActionsExecutionsResponse(TypedDict, total=False):
    actionsExecutions: Optional[AuditMitigationActionExecutionMetadataList]
    nextToken: Optional[NextToken]


class ListAuditMitigationActionsTasksRequest(ServiceRequest):
    auditTaskId: Optional[AuditTaskId]
    findingId: Optional[FindingId]
    taskStatus: Optional[AuditMitigationActionsTaskStatus]
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]
    startTime: Timestamp
    endTime: Timestamp


class ListAuditMitigationActionsTasksResponse(TypedDict, total=False):
    tasks: Optional[AuditMitigationActionsTaskMetadataList]
    nextToken: Optional[NextToken]


class ListAuditSuppressionsRequest(ServiceRequest):
    checkName: Optional[AuditCheckName]
    resourceIdentifier: Optional[ResourceIdentifier]
    ascendingOrder: Optional[AscendingOrder]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAuditSuppressionsResponse(TypedDict, total=False):
    suppressions: Optional[AuditSuppressionList]
    nextToken: Optional[NextToken]


class ListAuditTasksRequest(ServiceRequest):
    startTime: Timestamp
    endTime: Timestamp
    taskType: Optional[AuditTaskType]
    taskStatus: Optional[AuditTaskStatus]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAuditTasksResponse(TypedDict, total=False):
    tasks: Optional[AuditTaskMetadataList]
    nextToken: Optional[NextToken]


class ListAuthorizersRequest(ServiceRequest):
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]
    status: Optional[AuthorizerStatus]


class ListAuthorizersResponse(TypedDict, total=False):
    authorizers: Optional[Authorizers]
    nextMarker: Optional[Marker]


class ListBillingGroupsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    namePrefixFilter: Optional[BillingGroupName]


class ListBillingGroupsResponse(TypedDict, total=False):
    billingGroups: Optional[BillingGroupNameAndArnList]
    nextToken: Optional[NextToken]


class ListCACertificatesRequest(ServiceRequest):
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]


class ListCACertificatesResponse(TypedDict, total=False):
    certificates: Optional[CACertificates]
    nextMarker: Optional[Marker]


class ListCertificatesByCARequest(ServiceRequest):
    caCertificateId: CertificateId
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]


class ListCertificatesByCAResponse(TypedDict, total=False):
    certificates: Optional[Certificates]
    nextMarker: Optional[Marker]


class ListCertificatesRequest(ServiceRequest):
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]


class ListCertificatesResponse(TypedDict, total=False):
    certificates: Optional[Certificates]
    nextMarker: Optional[Marker]


class ListCustomMetricsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


MetricNames = List[MetricName]


class ListCustomMetricsResponse(TypedDict, total=False):
    metricNames: Optional[MetricNames]
    nextToken: Optional[NextToken]


class ListDetectMitigationActionsExecutionsRequest(ServiceRequest):
    taskId: Optional[MitigationActionsTaskId]
    violationId: Optional[ViolationId]
    thingName: Optional[DeviceDefenderThingName]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class ListDetectMitigationActionsExecutionsResponse(TypedDict, total=False):
    actionsExecutions: Optional[DetectMitigationActionExecutionList]
    nextToken: Optional[NextToken]


class ListDetectMitigationActionsTasksRequest(ServiceRequest):
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]
    startTime: Timestamp
    endTime: Timestamp


class ListDetectMitigationActionsTasksResponse(TypedDict, total=False):
    tasks: Optional[DetectMitigationActionsTaskSummaryList]
    nextToken: Optional[NextToken]


class ListDimensionsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDimensionsResponse(TypedDict, total=False):
    dimensionNames: Optional[DimensionNames]
    nextToken: Optional[NextToken]


class ListDomainConfigurationsRequest(ServiceRequest):
    marker: Optional[Marker]
    pageSize: Optional[PageSize]
    serviceType: Optional[ServiceType]


class ListDomainConfigurationsResponse(TypedDict, total=False):
    domainConfigurations: Optional[DomainConfigurations]
    nextMarker: Optional[Marker]


class ListFleetMetricsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListFleetMetricsResponse(TypedDict, total=False):
    fleetMetrics: Optional[FleetMetricNameAndArnList]
    nextToken: Optional[NextToken]


class ListIndicesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[QueryMaxResults]


class ListIndicesResponse(TypedDict, total=False):
    indexNames: Optional[IndexNamesList]
    nextToken: Optional[NextToken]


class ListJobExecutionsForJobRequest(ServiceRequest):
    jobId: JobId
    status: Optional[JobExecutionStatus]
    maxResults: Optional[LaserMaxResults]
    nextToken: Optional[NextToken]


class ListJobExecutionsForJobResponse(TypedDict, total=False):
    executionSummaries: Optional[JobExecutionSummaryForJobList]
    nextToken: Optional[NextToken]


class ListJobExecutionsForThingRequest(ServiceRequest):
    thingName: ThingName
    status: Optional[JobExecutionStatus]
    namespaceId: Optional[NamespaceId]
    maxResults: Optional[LaserMaxResults]
    nextToken: Optional[NextToken]
    jobId: Optional[JobId]


class ListJobExecutionsForThingResponse(TypedDict, total=False):
    executionSummaries: Optional[JobExecutionSummaryForThingList]
    nextToken: Optional[NextToken]


class ListJobTemplatesRequest(ServiceRequest):
    maxResults: Optional[LaserMaxResults]
    nextToken: Optional[NextToken]


class ListJobTemplatesResponse(TypedDict, total=False):
    jobTemplates: Optional[JobTemplateSummaryList]
    nextToken: Optional[NextToken]


class ListJobsRequest(ServiceRequest):
    status: Optional[JobStatus]
    targetSelection: Optional[TargetSelection]
    maxResults: Optional[LaserMaxResults]
    nextToken: Optional[NextToken]
    thingGroupName: Optional[ThingGroupName]
    thingGroupId: Optional[ThingGroupId]
    namespaceId: Optional[NamespaceId]


class ListJobsResponse(TypedDict, total=False):
    jobs: Optional[JobSummaryList]
    nextToken: Optional[NextToken]


class ListManagedJobTemplatesRequest(ServiceRequest):
    templateName: Optional[ManagedJobTemplateName]
    maxResults: Optional[LaserMaxResults]
    nextToken: Optional[NextToken]


class ManagedJobTemplateSummary(TypedDict, total=False):
    templateArn: Optional[JobTemplateArn]
    templateName: Optional[ManagedJobTemplateName]
    description: Optional[JobDescription]
    environments: Optional[Environments]
    templateVersion: Optional[ManagedTemplateVersion]


ManagedJobTemplatesSummaryList = List[ManagedJobTemplateSummary]


class ListManagedJobTemplatesResponse(TypedDict, total=False):
    managedJobTemplates: Optional[ManagedJobTemplatesSummaryList]
    nextToken: Optional[NextToken]


class ListMitigationActionsRequest(ServiceRequest):
    actionType: Optional[MitigationActionType]
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class MitigationActionIdentifier(TypedDict, total=False):
    actionName: Optional[MitigationActionName]
    actionArn: Optional[MitigationActionArn]
    creationDate: Optional[Timestamp]


MitigationActionIdentifierList = List[MitigationActionIdentifier]


class ListMitigationActionsResponse(TypedDict, total=False):
    actionIdentifiers: Optional[MitigationActionIdentifierList]
    nextToken: Optional[NextToken]


class ListOTAUpdatesRequest(ServiceRequest):
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]
    otaUpdateStatus: Optional[OTAUpdateStatus]


class OTAUpdateSummary(TypedDict, total=False):
    otaUpdateId: Optional[OTAUpdateId]
    otaUpdateArn: Optional[OTAUpdateArn]
    creationDate: Optional[DateType]


OTAUpdatesSummary = List[OTAUpdateSummary]


class ListOTAUpdatesResponse(TypedDict, total=False):
    otaUpdates: Optional[OTAUpdatesSummary]
    nextToken: Optional[NextToken]


class ListOutgoingCertificatesRequest(ServiceRequest):
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]


class OutgoingCertificate(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]
    transferredTo: Optional[AwsAccountId]
    transferDate: Optional[DateType]
    transferMessage: Optional[Message]
    creationDate: Optional[DateType]


OutgoingCertificates = List[OutgoingCertificate]


class ListOutgoingCertificatesResponse(TypedDict, total=False):
    outgoingCertificates: Optional[OutgoingCertificates]
    nextMarker: Optional[Marker]


class ListPoliciesRequest(ServiceRequest):
    marker: Optional[Marker]
    pageSize: Optional[PageSize]
    ascendingOrder: Optional[AscendingOrder]


class ListPoliciesResponse(TypedDict, total=False):
    policies: Optional[Policies]
    nextMarker: Optional[Marker]


class ListPolicyPrincipalsRequest(ServiceRequest):
    policyName: PolicyName
    marker: Optional[Marker]
    pageSize: Optional[PageSize]
    ascendingOrder: Optional[AscendingOrder]


Principals = List[PrincipalArn]


class ListPolicyPrincipalsResponse(TypedDict, total=False):
    principals: Optional[Principals]
    nextMarker: Optional[Marker]


class ListPolicyVersionsRequest(ServiceRequest):
    policyName: PolicyName


class PolicyVersion(TypedDict, total=False):
    versionId: Optional[PolicyVersionId]
    isDefaultVersion: Optional[IsDefaultVersion]
    createDate: Optional[DateType]


PolicyVersions = List[PolicyVersion]


class ListPolicyVersionsResponse(TypedDict, total=False):
    policyVersions: Optional[PolicyVersions]


class ListPrincipalPoliciesRequest(ServiceRequest):
    principal: Principal
    marker: Optional[Marker]
    pageSize: Optional[PageSize]
    ascendingOrder: Optional[AscendingOrder]


class ListPrincipalPoliciesResponse(TypedDict, total=False):
    policies: Optional[Policies]
    nextMarker: Optional[Marker]


class ListPrincipalThingsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    principal: Principal


ThingNameList = List[ThingName]


class ListPrincipalThingsResponse(TypedDict, total=False):
    things: Optional[ThingNameList]
    nextToken: Optional[NextToken]


class ListProvisioningTemplateVersionsRequest(ServiceRequest):
    templateName: TemplateName
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class ProvisioningTemplateVersionSummary(TypedDict, total=False):
    versionId: Optional[TemplateVersionId]
    creationDate: Optional[DateType]
    isDefaultVersion: Optional[IsDefaultVersion]


ProvisioningTemplateVersionListing = List[ProvisioningTemplateVersionSummary]


class ListProvisioningTemplateVersionsResponse(TypedDict, total=False):
    versions: Optional[ProvisioningTemplateVersionListing]
    nextToken: Optional[NextToken]


class ListProvisioningTemplatesRequest(ServiceRequest):
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class ProvisioningTemplateSummary(TypedDict, total=False):
    templateArn: Optional[TemplateArn]
    templateName: Optional[TemplateName]
    description: Optional[TemplateDescription]
    creationDate: Optional[DateType]
    lastModifiedDate: Optional[DateType]
    enabled: Optional[Enabled]


ProvisioningTemplateListing = List[ProvisioningTemplateSummary]


class ListProvisioningTemplatesResponse(TypedDict, total=False):
    templates: Optional[ProvisioningTemplateListing]
    nextToken: Optional[NextToken]


class ListRoleAliasesRequest(ServiceRequest):
    pageSize: Optional[PageSize]
    marker: Optional[Marker]
    ascendingOrder: Optional[AscendingOrder]


RoleAliases = List[RoleAlias]


class ListRoleAliasesResponse(TypedDict, total=False):
    roleAliases: Optional[RoleAliases]
    nextMarker: Optional[Marker]


class ListScheduledAuditsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ScheduledAuditMetadata(TypedDict, total=False):
    scheduledAuditName: Optional[ScheduledAuditName]
    scheduledAuditArn: Optional[ScheduledAuditArn]
    frequency: Optional[AuditFrequency]
    dayOfMonth: Optional[DayOfMonth]
    dayOfWeek: Optional[DayOfWeek]


ScheduledAuditMetadataList = List[ScheduledAuditMetadata]


class ListScheduledAuditsResponse(TypedDict, total=False):
    scheduledAudits: Optional[ScheduledAuditMetadataList]
    nextToken: Optional[NextToken]


class ListSecurityProfilesForTargetRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    recursive: Optional[Recursive]
    securityProfileTargetArn: SecurityProfileTargetArn


class SecurityProfileTarget(TypedDict, total=False):
    arn: SecurityProfileTargetArn


class SecurityProfileIdentifier(TypedDict, total=False):
    name: SecurityProfileName
    arn: SecurityProfileArn


class SecurityProfileTargetMapping(TypedDict, total=False):
    securityProfileIdentifier: Optional[SecurityProfileIdentifier]
    target: Optional[SecurityProfileTarget]


SecurityProfileTargetMappings = List[SecurityProfileTargetMapping]


class ListSecurityProfilesForTargetResponse(TypedDict, total=False):
    securityProfileTargetMappings: Optional[SecurityProfileTargetMappings]
    nextToken: Optional[NextToken]


class ListSecurityProfilesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    dimensionName: Optional[DimensionName]
    metricName: Optional[MetricName]


SecurityProfileIdentifiers = List[SecurityProfileIdentifier]


class ListSecurityProfilesResponse(TypedDict, total=False):
    securityProfileIdentifiers: Optional[SecurityProfileIdentifiers]
    nextToken: Optional[NextToken]


class ListStreamsRequest(ServiceRequest):
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]
    ascendingOrder: Optional[AscendingOrder]


class StreamSummary(TypedDict, total=False):
    streamId: Optional[StreamId]
    streamArn: Optional[StreamArn]
    streamVersion: Optional[StreamVersion]
    description: Optional[StreamDescription]


StreamsSummary = List[StreamSummary]


class ListStreamsResponse(TypedDict, total=False):
    streams: Optional[StreamsSummary]
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    nextToken: Optional[NextToken]


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagList]
    nextToken: Optional[NextToken]


class ListTargetsForPolicyRequest(ServiceRequest):
    policyName: PolicyName
    marker: Optional[Marker]
    pageSize: Optional[PageSize]


PolicyTargets = List[PolicyTarget]


class ListTargetsForPolicyResponse(TypedDict, total=False):
    targets: Optional[PolicyTargets]
    nextMarker: Optional[Marker]


class ListTargetsForSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


SecurityProfileTargets = List[SecurityProfileTarget]


class ListTargetsForSecurityProfileResponse(TypedDict, total=False):
    securityProfileTargets: Optional[SecurityProfileTargets]
    nextToken: Optional[NextToken]


class ListThingGroupsForThingRequest(ServiceRequest):
    thingName: ThingName
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]


class ListThingGroupsForThingResponse(TypedDict, total=False):
    thingGroups: Optional[ThingGroupNameAndArnList]
    nextToken: Optional[NextToken]


class ListThingGroupsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    parentGroup: Optional[ThingGroupName]
    namePrefixFilter: Optional[ThingGroupName]
    recursive: Optional[RecursiveWithoutDefault]


class ListThingGroupsResponse(TypedDict, total=False):
    thingGroups: Optional[ThingGroupNameAndArnList]
    nextToken: Optional[NextToken]


class ListThingPrincipalsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    thingName: ThingName


class ListThingPrincipalsResponse(TypedDict, total=False):
    principals: Optional[Principals]
    nextToken: Optional[NextToken]


class ListThingRegistrationTaskReportsRequest(ServiceRequest):
    taskId: TaskId
    reportType: ReportType
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]


S3FileUrlList = List[S3FileUrl]


class ListThingRegistrationTaskReportsResponse(TypedDict, total=False):
    resourceLinks: Optional[S3FileUrlList]
    reportType: Optional[ReportType]
    nextToken: Optional[NextToken]


class ListThingRegistrationTasksRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    status: Optional[Status]


TaskIdList = List[TaskId]


class ListThingRegistrationTasksResponse(TypedDict, total=False):
    taskIds: Optional[TaskIdList]
    nextToken: Optional[NextToken]


class ListThingTypesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    thingTypeName: Optional[ThingTypeName]


class ThingTypeDefinition(TypedDict, total=False):
    thingTypeName: Optional[ThingTypeName]
    thingTypeArn: Optional[ThingTypeArn]
    thingTypeProperties: Optional[ThingTypeProperties]
    thingTypeMetadata: Optional[ThingTypeMetadata]


ThingTypeList = List[ThingTypeDefinition]


class ListThingTypesResponse(TypedDict, total=False):
    thingTypes: Optional[ThingTypeList]
    nextToken: Optional[NextToken]


class ListThingsInBillingGroupRequest(ServiceRequest):
    billingGroupName: BillingGroupName
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]


class ListThingsInBillingGroupResponse(TypedDict, total=False):
    things: Optional[ThingNameList]
    nextToken: Optional[NextToken]


class ListThingsInThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    recursive: Optional[Recursive]
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]


class ListThingsInThingGroupResponse(TypedDict, total=False):
    things: Optional[ThingNameList]
    nextToken: Optional[NextToken]


class ListThingsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[RegistryMaxResults]
    attributeName: Optional[AttributeName]
    attributeValue: Optional[AttributeValue]
    thingTypeName: Optional[ThingTypeName]
    usePrefixAttributeValue: Optional[usePrefixAttributeValue]


class ThingAttribute(TypedDict, total=False):
    thingName: Optional[ThingName]
    thingTypeName: Optional[ThingTypeName]
    thingArn: Optional[ThingArn]
    attributes: Optional[Attributes]
    version: Optional[Version]


ThingAttributeList = List[ThingAttribute]


class ListThingsResponse(TypedDict, total=False):
    things: Optional[ThingAttributeList]
    nextToken: Optional[NextToken]


class ListTopicRuleDestinationsRequest(ServiceRequest):
    maxResults: Optional[TopicRuleDestinationMaxResults]
    nextToken: Optional[NextToken]


class VpcDestinationSummary(TypedDict, total=False):
    subnetIds: Optional[SubnetIdList]
    securityGroups: Optional[SecurityGroupList]
    vpcId: Optional[VpcId]
    roleArn: Optional[AwsArn]


class TopicRuleDestinationSummary(TypedDict, total=False):
    arn: Optional[AwsArn]
    status: Optional[TopicRuleDestinationStatus]
    createdAt: Optional[CreatedAtDate]
    lastUpdatedAt: Optional[LastUpdatedAtDate]
    statusReason: Optional[String]
    httpUrlSummary: Optional[HttpUrlDestinationSummary]
    vpcDestinationSummary: Optional[VpcDestinationSummary]


TopicRuleDestinationSummaries = List[TopicRuleDestinationSummary]


class ListTopicRuleDestinationsResponse(TypedDict, total=False):
    destinationSummaries: Optional[TopicRuleDestinationSummaries]
    nextToken: Optional[NextToken]


class ListTopicRulesRequest(ServiceRequest):
    topic: Optional[Topic]
    maxResults: Optional[TopicRuleMaxResults]
    nextToken: Optional[NextToken]
    ruleDisabled: Optional[IsDisabled]


class TopicRuleListItem(TypedDict, total=False):
    ruleArn: Optional[RuleArn]
    ruleName: Optional[RuleName]
    topicPattern: Optional[TopicPattern]
    createdAt: Optional[CreatedAtDate]
    ruleDisabled: Optional[IsDisabled]


TopicRuleList = List[TopicRuleListItem]


class ListTopicRulesResponse(TypedDict, total=False):
    rules: Optional[TopicRuleList]
    nextToken: Optional[NextToken]


class ListV2LoggingLevelsRequest(ServiceRequest):
    targetType: Optional[LogTargetType]
    nextToken: Optional[NextToken]
    maxResults: Optional[SkyfallMaxResults]


class LogTarget(TypedDict, total=False):
    targetType: LogTargetType
    targetName: Optional[LogTargetName]


class LogTargetConfiguration(TypedDict, total=False):
    logTarget: Optional[LogTarget]
    logLevel: Optional[LogLevel]


LogTargetConfigurations = List[LogTargetConfiguration]


class ListV2LoggingLevelsResponse(TypedDict, total=False):
    logTargetConfigurations: Optional[LogTargetConfigurations]
    nextToken: Optional[NextToken]


class ListViolationEventsRequest(ServiceRequest):
    startTime: Timestamp
    endTime: Timestamp
    thingName: Optional[DeviceDefenderThingName]
    securityProfileName: Optional[SecurityProfileName]
    behaviorCriteriaType: Optional[BehaviorCriteriaType]
    listSuppressedAlerts: Optional[ListSuppressedAlerts]
    verificationState: Optional[VerificationState]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ViolationEvent(TypedDict, total=False):
    violationId: Optional[ViolationId]
    thingName: Optional[DeviceDefenderThingName]
    securityProfileName: Optional[SecurityProfileName]
    behavior: Optional[Behavior]
    metricValue: Optional[MetricValue]
    violationEventAdditionalInfo: Optional[ViolationEventAdditionalInfo]
    violationEventType: Optional[ViolationEventType]
    verificationState: Optional[VerificationState]
    verificationStateDescription: Optional[VerificationStateDescription]
    violationEventTime: Optional[Timestamp]


ViolationEvents = List[ViolationEvent]


class ListViolationEventsResponse(TypedDict, total=False):
    violationEvents: Optional[ViolationEvents]
    nextToken: Optional[NextToken]


class LoggingOptionsPayload(TypedDict, total=False):
    roleArn: AwsArn
    logLevel: Optional[LogLevel]


MqttPassword = bytes


class MqttContext(TypedDict, total=False):
    username: Optional[MqttUsername]
    password: Optional[MqttPassword]
    clientId: Optional[MqttClientId]


Parameters = Dict[Parameter, Value]
PolicyDocuments = List[PolicyDocument]
PolicyNames = List[PolicyName]


class PutVerificationStateOnViolationRequest(ServiceRequest):
    violationId: ViolationId
    verificationState: VerificationState
    verificationStateDescription: Optional[VerificationStateDescription]


class PutVerificationStateOnViolationResponse(TypedDict, total=False):
    pass


class RegisterCACertificateRequest(ServiceRequest):
    caCertificate: CertificatePem
    verificationCertificate: CertificatePem
    setAsActive: Optional[SetAsActive]
    allowAutoRegistration: Optional[AllowAutoRegistration]
    registrationConfig: Optional[RegistrationConfig]
    tags: Optional[TagList]


class RegisterCACertificateResponse(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]


class RegisterCertificateRequest(ServiceRequest):
    certificatePem: CertificatePem
    caCertificatePem: Optional[CertificatePem]
    setAsActive: Optional[SetAsActiveFlag]
    status: Optional[CertificateStatus]


class RegisterCertificateResponse(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]


class RegisterCertificateWithoutCARequest(ServiceRequest):
    certificatePem: CertificatePem
    status: Optional[CertificateStatus]


class RegisterCertificateWithoutCAResponse(TypedDict, total=False):
    certificateArn: Optional[CertificateArn]
    certificateId: Optional[CertificateId]


class RegisterThingRequest(ServiceRequest):
    templateBody: TemplateBody
    parameters: Optional[Parameters]


ResourceArns = Dict[ResourceLogicalId, ResourceArn]


class RegisterThingResponse(TypedDict, total=False):
    certificatePem: Optional[CertificatePem]
    resourceArns: Optional[ResourceArns]


class RejectCertificateTransferRequest(ServiceRequest):
    certificateId: CertificateId
    rejectReason: Optional[Message]


class RemoveThingFromBillingGroupRequest(ServiceRequest):
    billingGroupName: Optional[BillingGroupName]
    billingGroupArn: Optional[BillingGroupArn]
    thingName: Optional[ThingName]
    thingArn: Optional[ThingArn]


class RemoveThingFromBillingGroupResponse(TypedDict, total=False):
    pass


class RemoveThingFromThingGroupRequest(ServiceRequest):
    thingGroupName: Optional[ThingGroupName]
    thingGroupArn: Optional[ThingGroupArn]
    thingName: Optional[ThingName]
    thingArn: Optional[ThingArn]


class RemoveThingFromThingGroupResponse(TypedDict, total=False):
    pass


class ReplaceTopicRuleRequest(ServiceRequest):
    ruleName: RuleName
    topicRulePayload: TopicRulePayload


class SearchIndexRequest(ServiceRequest):
    indexName: Optional[IndexName]
    queryString: QueryString
    nextToken: Optional[NextToken]
    maxResults: Optional[QueryMaxResults]
    queryVersion: Optional[QueryVersion]


ThingGroupNameList = List[ThingGroupName]


class ThingGroupDocument(TypedDict, total=False):
    thingGroupName: Optional[ThingGroupName]
    thingGroupId: Optional[ThingGroupId]
    thingGroupDescription: Optional[ThingGroupDescription]
    attributes: Optional[Attributes]
    parentGroupNames: Optional[ThingGroupNameList]


ThingGroupDocumentList = List[ThingGroupDocument]


class ThingConnectivity(TypedDict, total=False):
    connected: Optional[Boolean]
    timestamp: Optional[ConnectivityTimestamp]
    disconnectReason: Optional[DisconnectReason]


class ThingDocument(TypedDict, total=False):
    thingName: Optional[ThingName]
    thingId: Optional[ThingId]
    thingTypeName: Optional[ThingTypeName]
    thingGroupNames: Optional[ThingGroupNameList]
    attributes: Optional[Attributes]
    shadow: Optional[JsonDocument]
    deviceDefender: Optional[JsonDocument]
    connectivity: Optional[ThingConnectivity]


ThingDocumentList = List[ThingDocument]


class SearchIndexResponse(TypedDict, total=False):
    nextToken: Optional[NextToken]
    things: Optional[ThingDocumentList]
    thingGroups: Optional[ThingGroupDocumentList]


class SetDefaultAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName


class SetDefaultAuthorizerResponse(TypedDict, total=False):
    authorizerName: Optional[AuthorizerName]
    authorizerArn: Optional[AuthorizerArn]


class SetDefaultPolicyVersionRequest(ServiceRequest):
    policyName: PolicyName
    policyVersionId: PolicyVersionId


class SetLoggingOptionsRequest(ServiceRequest):
    loggingOptionsPayload: LoggingOptionsPayload


class SetV2LoggingLevelRequest(ServiceRequest):
    logTarget: LogTarget
    logLevel: LogLevel


class SetV2LoggingOptionsRequest(ServiceRequest):
    roleArn: Optional[AwsArn]
    defaultLogLevel: Optional[LogLevel]
    disableAllLogs: Optional[DisableAllLogs]


class StartAuditMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId
    target: AuditMitigationActionsTaskTarget
    auditCheckToActionsMapping: AuditCheckToActionsMapping
    clientRequestToken: ClientRequestToken


class StartAuditMitigationActionsTaskResponse(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]


class StartDetectMitigationActionsTaskRequest(ServiceRequest):
    taskId: MitigationActionsTaskId
    target: DetectMitigationActionsTaskTarget
    actions: DetectMitigationActionsToExecuteList
    violationEventOccurrenceRange: Optional[ViolationEventOccurrenceRange]
    includeOnlyActiveViolations: Optional[NullableBoolean]
    includeSuppressedAlerts: Optional[NullableBoolean]
    clientRequestToken: ClientRequestToken


class StartDetectMitigationActionsTaskResponse(TypedDict, total=False):
    taskId: Optional[MitigationActionsTaskId]


class StartOnDemandAuditTaskRequest(ServiceRequest):
    targetCheckNames: TargetAuditCheckNames


class StartOnDemandAuditTaskResponse(TypedDict, total=False):
    taskId: Optional[AuditTaskId]


class StartThingRegistrationTaskRequest(ServiceRequest):
    templateBody: TemplateBody
    inputFileBucket: RegistryS3BucketName
    inputFileKey: RegistryS3KeyName
    roleArn: RoleArn


class StartThingRegistrationTaskResponse(TypedDict, total=False):
    taskId: Optional[TaskId]


class StopThingRegistrationTaskRequest(ServiceRequest):
    taskId: TaskId


class StopThingRegistrationTaskResponse(TypedDict, total=False):
    pass


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class TestAuthorizationRequest(ServiceRequest):
    principal: Optional[Principal]
    cognitoIdentityPoolId: Optional[CognitoIdentityPoolId]
    authInfos: AuthInfos
    clientId: Optional[ClientId]
    policyNamesToAdd: Optional[PolicyNames]
    policyNamesToSkip: Optional[PolicyNames]


class TestAuthorizationResponse(TypedDict, total=False):
    authResults: Optional[AuthResults]


class TlsContext(TypedDict, total=False):
    serverName: Optional[ServerName]


class TestInvokeAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName
    token: Optional[Token]
    tokenSignature: Optional[TokenSignature]
    httpContext: Optional[HttpContext]
    mqttContext: Optional[MqttContext]
    tlsContext: Optional[TlsContext]


class TestInvokeAuthorizerResponse(TypedDict, total=False):
    isAuthenticated: Optional[IsAuthenticated]
    principalId: Optional[PrincipalId]
    policyDocuments: Optional[PolicyDocuments]
    refreshAfterInSeconds: Optional[Seconds]
    disconnectAfterInSeconds: Optional[Seconds]


ThingGroupList = List[ThingGroupName]


class TransferCertificateRequest(ServiceRequest):
    certificateId: CertificateId
    targetAwsAccount: AwsAccountId
    transferMessage: Optional[Message]


class TransferCertificateResponse(TypedDict, total=False):
    transferredCertificateArn: Optional[CertificateArn]


class UntagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAccountAuditConfigurationRequest(ServiceRequest):
    roleArn: Optional[RoleArn]
    auditNotificationTargetConfigurations: Optional[AuditNotificationTargetConfigurations]
    auditCheckConfigurations: Optional[AuditCheckConfigurations]


class UpdateAccountAuditConfigurationResponse(TypedDict, total=False):
    pass


class UpdateAuditSuppressionRequest(ServiceRequest):
    checkName: AuditCheckName
    resourceIdentifier: ResourceIdentifier
    expirationDate: Optional[Timestamp]
    suppressIndefinitely: Optional[SuppressIndefinitely]
    description: Optional[AuditDescription]


class UpdateAuditSuppressionResponse(TypedDict, total=False):
    pass


class UpdateAuthorizerRequest(ServiceRequest):
    authorizerName: AuthorizerName
    authorizerFunctionArn: Optional[AuthorizerFunctionArn]
    tokenKeyName: Optional[TokenKeyName]
    tokenSigningPublicKeys: Optional[PublicKeyMap]
    status: Optional[AuthorizerStatus]
    enableCachingForHttp: Optional[EnableCachingForHttp]


class UpdateAuthorizerResponse(TypedDict, total=False):
    authorizerName: Optional[AuthorizerName]
    authorizerArn: Optional[AuthorizerArn]


class UpdateBillingGroupRequest(ServiceRequest):
    billingGroupName: BillingGroupName
    billingGroupProperties: BillingGroupProperties
    expectedVersion: Optional[OptionalVersion]


class UpdateBillingGroupResponse(TypedDict, total=False):
    version: Optional[Version]


class UpdateCACertificateRequest(ServiceRequest):
    certificateId: CertificateId
    newStatus: Optional[CACertificateStatus]
    newAutoRegistrationStatus: Optional[AutoRegistrationStatus]
    registrationConfig: Optional[RegistrationConfig]
    removeAutoRegistration: Optional[RemoveAutoRegistration]


class UpdateCertificateRequest(ServiceRequest):
    certificateId: CertificateId
    newStatus: CertificateStatus


class UpdateCustomMetricRequest(ServiceRequest):
    metricName: MetricName
    displayName: CustomMetricDisplayName


class UpdateCustomMetricResponse(TypedDict, total=False):
    metricName: Optional[MetricName]
    metricArn: Optional[CustomMetricArn]
    metricType: Optional[CustomMetricType]
    displayName: Optional[CustomMetricDisplayName]
    creationDate: Optional[Timestamp]
    lastModifiedDate: Optional[Timestamp]


class UpdateDimensionRequest(ServiceRequest):
    name: DimensionName
    stringValues: DimensionStringValues


UpdateDimensionResponse = TypedDict(
    "UpdateDimensionResponse",
    {
        "name": Optional[DimensionName],
        "arn": Optional[DimensionArn],
        "type": Optional[DimensionType],
        "stringValues": Optional[DimensionStringValues],
        "creationDate": Optional[Timestamp],
        "lastModifiedDate": Optional[Timestamp],
    },
    total=False,
)


class UpdateDomainConfigurationRequest(ServiceRequest):
    domainConfigurationName: ReservedDomainConfigurationName
    authorizerConfig: Optional[AuthorizerConfig]
    domainConfigurationStatus: Optional[DomainConfigurationStatus]
    removeAuthorizerConfig: Optional[RemoveAuthorizerConfig]


class UpdateDomainConfigurationResponse(TypedDict, total=False):
    domainConfigurationName: Optional[ReservedDomainConfigurationName]
    domainConfigurationArn: Optional[DomainConfigurationArn]


class UpdateDynamicThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    thingGroupProperties: ThingGroupProperties
    expectedVersion: Optional[OptionalVersion]
    indexName: Optional[IndexName]
    queryString: Optional[QueryString]
    queryVersion: Optional[QueryVersion]


class UpdateDynamicThingGroupResponse(TypedDict, total=False):
    version: Optional[Version]


class UpdateEventConfigurationsRequest(ServiceRequest):
    eventConfigurations: Optional[EventConfigurations]


class UpdateEventConfigurationsResponse(TypedDict, total=False):
    pass


class UpdateFleetMetricRequest(ServiceRequest):
    metricName: FleetMetricName
    queryString: Optional[QueryString]
    aggregationType: Optional[AggregationType]
    period: Optional[FleetMetricPeriod]
    aggregationField: Optional[AggregationField]
    description: Optional[FleetMetricDescription]
    queryVersion: Optional[QueryVersion]
    indexName: IndexName
    unit: Optional[FleetMetricUnit]
    expectedVersion: Optional[OptionalVersion]


class UpdateIndexingConfigurationRequest(ServiceRequest):
    thingIndexingConfiguration: Optional[ThingIndexingConfiguration]
    thingGroupIndexingConfiguration: Optional[ThingGroupIndexingConfiguration]


class UpdateIndexingConfigurationResponse(TypedDict, total=False):
    pass


class UpdateJobRequest(ServiceRequest):
    jobId: JobId
    description: Optional[JobDescription]
    presignedUrlConfig: Optional[PresignedUrlConfig]
    jobExecutionsRolloutConfig: Optional[JobExecutionsRolloutConfig]
    abortConfig: Optional[AbortConfig]
    timeoutConfig: Optional[TimeoutConfig]
    namespaceId: Optional[NamespaceId]
    jobExecutionsRetryConfig: Optional[JobExecutionsRetryConfig]


class UpdateMitigationActionRequest(ServiceRequest):
    actionName: MitigationActionName
    roleArn: Optional[RoleArn]
    actionParams: Optional[MitigationActionParams]


class UpdateMitigationActionResponse(TypedDict, total=False):
    actionArn: Optional[MitigationActionArn]
    actionId: Optional[MitigationActionId]


class UpdateProvisioningTemplateRequest(ServiceRequest):
    templateName: TemplateName
    description: Optional[TemplateDescription]
    enabled: Optional[Enabled]
    defaultVersionId: Optional[TemplateVersionId]
    provisioningRoleArn: Optional[RoleArn]
    preProvisioningHook: Optional[ProvisioningHook]
    removePreProvisioningHook: Optional[RemoveHook]


class UpdateProvisioningTemplateResponse(TypedDict, total=False):
    pass


class UpdateRoleAliasRequest(ServiceRequest):
    roleAlias: RoleAlias
    roleArn: Optional[RoleArn]
    credentialDurationSeconds: Optional[CredentialDurationSeconds]


class UpdateRoleAliasResponse(TypedDict, total=False):
    roleAlias: Optional[RoleAlias]
    roleAliasArn: Optional[RoleAliasArn]


class UpdateScheduledAuditRequest(ServiceRequest):
    frequency: Optional[AuditFrequency]
    dayOfMonth: Optional[DayOfMonth]
    dayOfWeek: Optional[DayOfWeek]
    targetCheckNames: Optional[TargetAuditCheckNames]
    scheduledAuditName: ScheduledAuditName


class UpdateScheduledAuditResponse(TypedDict, total=False):
    scheduledAuditArn: Optional[ScheduledAuditArn]


class UpdateSecurityProfileRequest(ServiceRequest):
    securityProfileName: SecurityProfileName
    securityProfileDescription: Optional[SecurityProfileDescription]
    behaviors: Optional[Behaviors]
    alertTargets: Optional[AlertTargets]
    additionalMetricsToRetain: Optional[AdditionalMetricsToRetainList]
    additionalMetricsToRetainV2: Optional[AdditionalMetricsToRetainV2List]
    deleteBehaviors: Optional[DeleteBehaviors]
    deleteAlertTargets: Optional[DeleteAlertTargets]
    deleteAdditionalMetricsToRetain: Optional[DeleteAdditionalMetricsToRetain]
    expectedVersion: Optional[OptionalVersion]


class UpdateSecurityProfileResponse(TypedDict, total=False):
    securityProfileName: Optional[SecurityProfileName]
    securityProfileArn: Optional[SecurityProfileArn]
    securityProfileDescription: Optional[SecurityProfileDescription]
    behaviors: Optional[Behaviors]
    alertTargets: Optional[AlertTargets]
    additionalMetricsToRetain: Optional[AdditionalMetricsToRetainList]
    additionalMetricsToRetainV2: Optional[AdditionalMetricsToRetainV2List]
    version: Optional[Version]
    creationDate: Optional[Timestamp]
    lastModifiedDate: Optional[Timestamp]


class UpdateStreamRequest(ServiceRequest):
    streamId: StreamId
    description: Optional[StreamDescription]
    files: Optional[StreamFiles]
    roleArn: Optional[RoleArn]


class UpdateStreamResponse(TypedDict, total=False):
    streamId: Optional[StreamId]
    streamArn: Optional[StreamArn]
    description: Optional[StreamDescription]
    streamVersion: Optional[StreamVersion]


class UpdateThingGroupRequest(ServiceRequest):
    thingGroupName: ThingGroupName
    thingGroupProperties: ThingGroupProperties
    expectedVersion: Optional[OptionalVersion]


class UpdateThingGroupResponse(TypedDict, total=False):
    version: Optional[Version]


class UpdateThingGroupsForThingRequest(ServiceRequest):
    thingName: Optional[ThingName]
    thingGroupsToAdd: Optional[ThingGroupList]
    thingGroupsToRemove: Optional[ThingGroupList]
    overrideDynamicGroups: Optional[OverrideDynamicGroups]


class UpdateThingGroupsForThingResponse(TypedDict, total=False):
    pass


class UpdateThingRequest(ServiceRequest):
    thingName: ThingName
    thingTypeName: Optional[ThingTypeName]
    attributePayload: Optional[AttributePayload]
    expectedVersion: Optional[OptionalVersion]
    removeThingType: Optional[RemoveThingType]


class UpdateThingResponse(TypedDict, total=False):
    pass


class UpdateTopicRuleDestinationRequest(ServiceRequest):
    arn: AwsArn
    status: TopicRuleDestinationStatus


class UpdateTopicRuleDestinationResponse(TypedDict, total=False):
    pass


class ValidateSecurityProfileBehaviorsRequest(ServiceRequest):
    behaviors: Behaviors


class ValidationError(TypedDict, total=False):
    errorMessage: Optional[ErrorMessage]


ValidationErrors = List[ValidationError]


class ValidateSecurityProfileBehaviorsResponse(TypedDict, total=False):
    valid: Optional[Valid]
    validationErrors: Optional[ValidationErrors]


class IotApi:

    service = "iot"
    version = "2015-05-28"

    @handler("AcceptCertificateTransfer")
    def accept_certificate_transfer(
        self,
        context: RequestContext,
        certificate_id: CertificateId,
        set_as_active: SetAsActive = None,
    ) -> None:
        raise NotImplementedError

    @handler("AddThingToBillingGroup")
    def add_thing_to_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName = None,
        billing_group_arn: BillingGroupArn = None,
        thing_name: ThingName = None,
        thing_arn: ThingArn = None,
    ) -> AddThingToBillingGroupResponse:
        raise NotImplementedError

    @handler("AddThingToThingGroup")
    def add_thing_to_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName = None,
        thing_group_arn: ThingGroupArn = None,
        thing_name: ThingName = None,
        thing_arn: ThingArn = None,
        override_dynamic_groups: OverrideDynamicGroups = None,
    ) -> AddThingToThingGroupResponse:
        raise NotImplementedError

    @handler("AssociateTargetsWithJob")
    def associate_targets_with_job(
        self,
        context: RequestContext,
        targets: JobTargets,
        job_id: JobId,
        comment: Comment = None,
        namespace_id: NamespaceId = None,
    ) -> AssociateTargetsWithJobResponse:
        raise NotImplementedError

    @handler("AttachPolicy")
    def attach_policy(
        self, context: RequestContext, policy_name: PolicyName, target: PolicyTarget
    ) -> None:
        raise NotImplementedError

    @handler("AttachPrincipalPolicy")
    def attach_principal_policy(
        self, context: RequestContext, policy_name: PolicyName, principal: Principal
    ) -> None:
        raise NotImplementedError

    @handler("AttachSecurityProfile")
    def attach_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        security_profile_target_arn: SecurityProfileTargetArn,
    ) -> AttachSecurityProfileResponse:
        raise NotImplementedError

    @handler("AttachThingPrincipal")
    def attach_thing_principal(
        self, context: RequestContext, thing_name: ThingName, principal: Principal
    ) -> AttachThingPrincipalResponse:
        raise NotImplementedError

    @handler("CancelAuditMitigationActionsTask")
    def cancel_audit_mitigation_actions_task(
        self, context: RequestContext, task_id: MitigationActionsTaskId
    ) -> CancelAuditMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("CancelAuditTask")
    def cancel_audit_task(
        self, context: RequestContext, task_id: AuditTaskId
    ) -> CancelAuditTaskResponse:
        raise NotImplementedError

    @handler("CancelCertificateTransfer")
    def cancel_certificate_transfer(
        self, context: RequestContext, certificate_id: CertificateId
    ) -> None:
        raise NotImplementedError

    @handler("CancelDetectMitigationActionsTask")
    def cancel_detect_mitigation_actions_task(
        self, context: RequestContext, task_id: MitigationActionsTaskId
    ) -> CancelDetectMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("CancelJob")
    def cancel_job(
        self,
        context: RequestContext,
        job_id: JobId,
        reason_code: ReasonCode = None,
        comment: Comment = None,
        force: ForceFlag = None,
    ) -> CancelJobResponse:
        raise NotImplementedError

    @handler("CancelJobExecution")
    def cancel_job_execution(
        self,
        context: RequestContext,
        job_id: JobId,
        thing_name: ThingName,
        force: ForceFlag = None,
        expected_version: ExpectedVersion = None,
        status_details: DetailsMap = None,
    ) -> None:
        raise NotImplementedError

    @handler("ClearDefaultAuthorizer")
    def clear_default_authorizer(
        self,
        context: RequestContext,
    ) -> ClearDefaultAuthorizerResponse:
        raise NotImplementedError

    @handler("ConfirmTopicRuleDestination")
    def confirm_topic_rule_destination(
        self, context: RequestContext, confirmation_token: ConfirmationToken
    ) -> ConfirmTopicRuleDestinationResponse:
        raise NotImplementedError

    @handler("CreateAuditSuppression")
    def create_audit_suppression(
        self,
        context: RequestContext,
        check_name: AuditCheckName,
        resource_identifier: ResourceIdentifier,
        client_request_token: ClientRequestToken,
        expiration_date: Timestamp = None,
        suppress_indefinitely: SuppressIndefinitely = None,
        description: AuditDescription = None,
    ) -> CreateAuditSuppressionResponse:
        raise NotImplementedError

    @handler("CreateAuthorizer")
    def create_authorizer(
        self,
        context: RequestContext,
        authorizer_name: AuthorizerName,
        authorizer_function_arn: AuthorizerFunctionArn,
        token_key_name: TokenKeyName = None,
        token_signing_public_keys: PublicKeyMap = None,
        status: AuthorizerStatus = None,
        tags: TagList = None,
        signing_disabled: BooleanKey = None,
        enable_caching_for_http: EnableCachingForHttp = None,
    ) -> CreateAuthorizerResponse:
        raise NotImplementedError

    @handler("CreateBillingGroup")
    def create_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName,
        billing_group_properties: BillingGroupProperties = None,
        tags: TagList = None,
    ) -> CreateBillingGroupResponse:
        raise NotImplementedError

    @handler("CreateCertificateFromCsr")
    def create_certificate_from_csr(
        self,
        context: RequestContext,
        certificate_signing_request: CertificateSigningRequest,
        set_as_active: SetAsActive = None,
    ) -> CreateCertificateFromCsrResponse:
        raise NotImplementedError

    @handler("CreateCustomMetric")
    def create_custom_metric(
        self,
        context: RequestContext,
        metric_name: MetricName,
        metric_type: CustomMetricType,
        client_request_token: ClientRequestToken,
        display_name: CustomMetricDisplayName = None,
        tags: TagList = None,
    ) -> CreateCustomMetricResponse:
        raise NotImplementedError

    @handler("CreateDimension", expand=False)
    def create_dimension(
        self, context: RequestContext, request: CreateDimensionRequest
    ) -> CreateDimensionResponse:
        raise NotImplementedError

    @handler("CreateDomainConfiguration")
    def create_domain_configuration(
        self,
        context: RequestContext,
        domain_configuration_name: DomainConfigurationName,
        domain_name: DomainName = None,
        server_certificate_arns: ServerCertificateArns = None,
        validation_certificate_arn: AcmCertificateArn = None,
        authorizer_config: AuthorizerConfig = None,
        service_type: ServiceType = None,
        tags: TagList = None,
    ) -> CreateDomainConfigurationResponse:
        raise NotImplementedError

    @handler("CreateDynamicThingGroup")
    def create_dynamic_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        query_string: QueryString,
        thing_group_properties: ThingGroupProperties = None,
        index_name: IndexName = None,
        query_version: QueryVersion = None,
        tags: TagList = None,
    ) -> CreateDynamicThingGroupResponse:
        raise NotImplementedError

    @handler("CreateFleetMetric")
    def create_fleet_metric(
        self,
        context: RequestContext,
        metric_name: FleetMetricName,
        query_string: QueryString,
        aggregation_type: AggregationType,
        period: FleetMetricPeriod,
        aggregation_field: AggregationField,
        description: FleetMetricDescription = None,
        query_version: QueryVersion = None,
        index_name: IndexName = None,
        unit: FleetMetricUnit = None,
        tags: TagList = None,
    ) -> CreateFleetMetricResponse:
        raise NotImplementedError

    @handler("CreateJob")
    def create_job(
        self,
        context: RequestContext,
        job_id: JobId,
        targets: JobTargets,
        document_source: JobDocumentSource = None,
        document: JobDocument = None,
        description: JobDescription = None,
        presigned_url_config: PresignedUrlConfig = None,
        target_selection: TargetSelection = None,
        job_executions_rollout_config: JobExecutionsRolloutConfig = None,
        abort_config: AbortConfig = None,
        timeout_config: TimeoutConfig = None,
        tags: TagList = None,
        namespace_id: NamespaceId = None,
        job_template_arn: JobTemplateArn = None,
        job_executions_retry_config: JobExecutionsRetryConfig = None,
        document_parameters: ParameterMap = None,
    ) -> CreateJobResponse:
        raise NotImplementedError

    @handler("CreateJobTemplate")
    def create_job_template(
        self,
        context: RequestContext,
        job_template_id: JobTemplateId,
        description: JobDescription,
        job_arn: JobArn = None,
        document_source: JobDocumentSource = None,
        document: JobDocument = None,
        presigned_url_config: PresignedUrlConfig = None,
        job_executions_rollout_config: JobExecutionsRolloutConfig = None,
        abort_config: AbortConfig = None,
        timeout_config: TimeoutConfig = None,
        tags: TagList = None,
        job_executions_retry_config: JobExecutionsRetryConfig = None,
    ) -> CreateJobTemplateResponse:
        raise NotImplementedError

    @handler("CreateKeysAndCertificate")
    def create_keys_and_certificate(
        self, context: RequestContext, set_as_active: SetAsActive = None
    ) -> CreateKeysAndCertificateResponse:
        raise NotImplementedError

    @handler("CreateMitigationAction")
    def create_mitigation_action(
        self,
        context: RequestContext,
        action_name: MitigationActionName,
        role_arn: RoleArn,
        action_params: MitigationActionParams,
        tags: TagList = None,
    ) -> CreateMitigationActionResponse:
        raise NotImplementedError

    @handler("CreateOTAUpdate")
    def create_ota_update(
        self,
        context: RequestContext,
        ota_update_id: OTAUpdateId,
        targets: Targets,
        files: OTAUpdateFiles,
        role_arn: RoleArn,
        description: OTAUpdateDescription = None,
        protocols: Protocols = None,
        target_selection: TargetSelection = None,
        aws_job_executions_rollout_config: AwsJobExecutionsRolloutConfig = None,
        aws_job_presigned_url_config: AwsJobPresignedUrlConfig = None,
        aws_job_abort_config: AwsJobAbortConfig = None,
        aws_job_timeout_config: AwsJobTimeoutConfig = None,
        additional_parameters: AdditionalParameterMap = None,
        tags: TagList = None,
    ) -> CreateOTAUpdateResponse:
        raise NotImplementedError

    @handler("CreatePolicy")
    def create_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        policy_document: PolicyDocument,
        tags: TagList = None,
    ) -> CreatePolicyResponse:
        raise NotImplementedError

    @handler("CreatePolicyVersion")
    def create_policy_version(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        policy_document: PolicyDocument,
        set_as_default: SetAsDefault = None,
    ) -> CreatePolicyVersionResponse:
        raise NotImplementedError

    @handler("CreateProvisioningClaim")
    def create_provisioning_claim(
        self, context: RequestContext, template_name: TemplateName
    ) -> CreateProvisioningClaimResponse:
        raise NotImplementedError

    @handler("CreateProvisioningTemplate")
    def create_provisioning_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        template_body: TemplateBody,
        provisioning_role_arn: RoleArn,
        description: TemplateDescription = None,
        enabled: Enabled = None,
        pre_provisioning_hook: ProvisioningHook = None,
        tags: TagList = None,
    ) -> CreateProvisioningTemplateResponse:
        raise NotImplementedError

    @handler("CreateProvisioningTemplateVersion")
    def create_provisioning_template_version(
        self,
        context: RequestContext,
        template_name: TemplateName,
        template_body: TemplateBody,
        set_as_default: SetAsDefault = None,
    ) -> CreateProvisioningTemplateVersionResponse:
        raise NotImplementedError

    @handler("CreateRoleAlias")
    def create_role_alias(
        self,
        context: RequestContext,
        role_alias: RoleAlias,
        role_arn: RoleArn,
        credential_duration_seconds: CredentialDurationSeconds = None,
        tags: TagList = None,
    ) -> CreateRoleAliasResponse:
        raise NotImplementedError

    @handler("CreateScheduledAudit")
    def create_scheduled_audit(
        self,
        context: RequestContext,
        frequency: AuditFrequency,
        target_check_names: TargetAuditCheckNames,
        scheduled_audit_name: ScheduledAuditName,
        day_of_month: DayOfMonth = None,
        day_of_week: DayOfWeek = None,
        tags: TagList = None,
    ) -> CreateScheduledAuditResponse:
        raise NotImplementedError

    @handler("CreateSecurityProfile")
    def create_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        security_profile_description: SecurityProfileDescription = None,
        behaviors: Behaviors = None,
        alert_targets: AlertTargets = None,
        additional_metrics_to_retain: AdditionalMetricsToRetainList = None,
        additional_metrics_to_retain_v2: AdditionalMetricsToRetainV2List = None,
        tags: TagList = None,
    ) -> CreateSecurityProfileResponse:
        raise NotImplementedError

    @handler("CreateStream")
    def create_stream(
        self,
        context: RequestContext,
        stream_id: StreamId,
        files: StreamFiles,
        role_arn: RoleArn,
        description: StreamDescription = None,
        tags: TagList = None,
    ) -> CreateStreamResponse:
        raise NotImplementedError

    @handler("CreateThing")
    def create_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        thing_type_name: ThingTypeName = None,
        attribute_payload: AttributePayload = None,
        billing_group_name: BillingGroupName = None,
    ) -> CreateThingResponse:
        raise NotImplementedError

    @handler("CreateThingGroup")
    def create_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        parent_group_name: ThingGroupName = None,
        thing_group_properties: ThingGroupProperties = None,
        tags: TagList = None,
    ) -> CreateThingGroupResponse:
        raise NotImplementedError

    @handler("CreateThingType")
    def create_thing_type(
        self,
        context: RequestContext,
        thing_type_name: ThingTypeName,
        thing_type_properties: ThingTypeProperties = None,
        tags: TagList = None,
    ) -> CreateThingTypeResponse:
        raise NotImplementedError

    @handler("CreateTopicRule")
    def create_topic_rule(
        self,
        context: RequestContext,
        rule_name: RuleName,
        topic_rule_payload: TopicRulePayload,
        tags: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("CreateTopicRuleDestination")
    def create_topic_rule_destination(
        self, context: RequestContext, destination_configuration: TopicRuleDestinationConfiguration
    ) -> CreateTopicRuleDestinationResponse:
        raise NotImplementedError

    @handler("DeleteAccountAuditConfiguration")
    def delete_account_audit_configuration(
        self, context: RequestContext, delete_scheduled_audits: DeleteScheduledAudits = None
    ) -> DeleteAccountAuditConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteAuditSuppression")
    def delete_audit_suppression(
        self,
        context: RequestContext,
        check_name: AuditCheckName,
        resource_identifier: ResourceIdentifier,
    ) -> DeleteAuditSuppressionResponse:
        raise NotImplementedError

    @handler("DeleteAuthorizer")
    def delete_authorizer(
        self, context: RequestContext, authorizer_name: AuthorizerName
    ) -> DeleteAuthorizerResponse:
        raise NotImplementedError

    @handler("DeleteBillingGroup")
    def delete_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName,
        expected_version: OptionalVersion = None,
    ) -> DeleteBillingGroupResponse:
        raise NotImplementedError

    @handler("DeleteCACertificate")
    def delete_ca_certificate(
        self, context: RequestContext, certificate_id: CertificateId
    ) -> DeleteCACertificateResponse:
        raise NotImplementedError

    @handler("DeleteCertificate")
    def delete_certificate(
        self,
        context: RequestContext,
        certificate_id: CertificateId,
        force_delete: ForceDelete = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCustomMetric")
    def delete_custom_metric(
        self, context: RequestContext, metric_name: MetricName
    ) -> DeleteCustomMetricResponse:
        raise NotImplementedError

    @handler("DeleteDimension")
    def delete_dimension(
        self, context: RequestContext, name: DimensionName
    ) -> DeleteDimensionResponse:
        raise NotImplementedError

    @handler("DeleteDomainConfiguration")
    def delete_domain_configuration(
        self, context: RequestContext, domain_configuration_name: DomainConfigurationName
    ) -> DeleteDomainConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteDynamicThingGroup")
    def delete_dynamic_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        expected_version: OptionalVersion = None,
    ) -> DeleteDynamicThingGroupResponse:
        raise NotImplementedError

    @handler("DeleteFleetMetric")
    def delete_fleet_metric(
        self,
        context: RequestContext,
        metric_name: FleetMetricName,
        expected_version: OptionalVersion = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteJob")
    def delete_job(
        self,
        context: RequestContext,
        job_id: JobId,
        force: ForceFlag = None,
        namespace_id: NamespaceId = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteJobExecution")
    def delete_job_execution(
        self,
        context: RequestContext,
        job_id: JobId,
        thing_name: ThingName,
        execution_number: ExecutionNumber,
        force: ForceFlag = None,
        namespace_id: NamespaceId = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteJobTemplate")
    def delete_job_template(self, context: RequestContext, job_template_id: JobTemplateId) -> None:
        raise NotImplementedError

    @handler("DeleteMitigationAction")
    def delete_mitigation_action(
        self, context: RequestContext, action_name: MitigationActionName
    ) -> DeleteMitigationActionResponse:
        raise NotImplementedError

    @handler("DeleteOTAUpdate")
    def delete_ota_update(
        self,
        context: RequestContext,
        ota_update_id: OTAUpdateId,
        delete_stream: DeleteStream = None,
        force_delete_aws_job: ForceDeleteAWSJob = None,
    ) -> DeleteOTAUpdateResponse:
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(self, context: RequestContext, policy_name: PolicyName) -> None:
        raise NotImplementedError

    @handler("DeletePolicyVersion")
    def delete_policy_version(
        self, context: RequestContext, policy_name: PolicyName, policy_version_id: PolicyVersionId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteProvisioningTemplate")
    def delete_provisioning_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DeleteProvisioningTemplateResponse:
        raise NotImplementedError

    @handler("DeleteProvisioningTemplateVersion")
    def delete_provisioning_template_version(
        self, context: RequestContext, template_name: TemplateName, version_id: TemplateVersionId
    ) -> DeleteProvisioningTemplateVersionResponse:
        raise NotImplementedError

    @handler("DeleteRegistrationCode")
    def delete_registration_code(
        self,
        context: RequestContext,
    ) -> DeleteRegistrationCodeResponse:
        raise NotImplementedError

    @handler("DeleteRoleAlias")
    def delete_role_alias(
        self, context: RequestContext, role_alias: RoleAlias
    ) -> DeleteRoleAliasResponse:
        raise NotImplementedError

    @handler("DeleteScheduledAudit")
    def delete_scheduled_audit(
        self, context: RequestContext, scheduled_audit_name: ScheduledAuditName
    ) -> DeleteScheduledAuditResponse:
        raise NotImplementedError

    @handler("DeleteSecurityProfile")
    def delete_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        expected_version: OptionalVersion = None,
    ) -> DeleteSecurityProfileResponse:
        raise NotImplementedError

    @handler("DeleteStream")
    def delete_stream(self, context: RequestContext, stream_id: StreamId) -> DeleteStreamResponse:
        raise NotImplementedError

    @handler("DeleteThing")
    def delete_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        expected_version: OptionalVersion = None,
    ) -> DeleteThingResponse:
        raise NotImplementedError

    @handler("DeleteThingGroup")
    def delete_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        expected_version: OptionalVersion = None,
    ) -> DeleteThingGroupResponse:
        raise NotImplementedError

    @handler("DeleteThingType")
    def delete_thing_type(
        self, context: RequestContext, thing_type_name: ThingTypeName
    ) -> DeleteThingTypeResponse:
        raise NotImplementedError

    @handler("DeleteTopicRule")
    def delete_topic_rule(self, context: RequestContext, rule_name: RuleName) -> None:
        raise NotImplementedError

    @handler("DeleteTopicRuleDestination")
    def delete_topic_rule_destination(
        self, context: RequestContext, arn: AwsArn
    ) -> DeleteTopicRuleDestinationResponse:
        raise NotImplementedError

    @handler("DeleteV2LoggingLevel")
    def delete_v2_logging_level(
        self, context: RequestContext, target_type: LogTargetType, target_name: LogTargetName
    ) -> None:
        raise NotImplementedError

    @handler("DeprecateThingType")
    def deprecate_thing_type(
        self,
        context: RequestContext,
        thing_type_name: ThingTypeName,
        undo_deprecate: UndoDeprecate = None,
    ) -> DeprecateThingTypeResponse:
        raise NotImplementedError

    @handler("DescribeAccountAuditConfiguration")
    def describe_account_audit_configuration(
        self,
        context: RequestContext,
    ) -> DescribeAccountAuditConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeAuditFinding")
    def describe_audit_finding(
        self, context: RequestContext, finding_id: FindingId
    ) -> DescribeAuditFindingResponse:
        raise NotImplementedError

    @handler("DescribeAuditMitigationActionsTask")
    def describe_audit_mitigation_actions_task(
        self, context: RequestContext, task_id: MitigationActionsTaskId
    ) -> DescribeAuditMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("DescribeAuditSuppression")
    def describe_audit_suppression(
        self,
        context: RequestContext,
        check_name: AuditCheckName,
        resource_identifier: ResourceIdentifier,
    ) -> DescribeAuditSuppressionResponse:
        raise NotImplementedError

    @handler("DescribeAuditTask")
    def describe_audit_task(
        self, context: RequestContext, task_id: AuditTaskId
    ) -> DescribeAuditTaskResponse:
        raise NotImplementedError

    @handler("DescribeAuthorizer")
    def describe_authorizer(
        self, context: RequestContext, authorizer_name: AuthorizerName
    ) -> DescribeAuthorizerResponse:
        raise NotImplementedError

    @handler("DescribeBillingGroup")
    def describe_billing_group(
        self, context: RequestContext, billing_group_name: BillingGroupName
    ) -> DescribeBillingGroupResponse:
        raise NotImplementedError

    @handler("DescribeCACertificate")
    def describe_ca_certificate(
        self, context: RequestContext, certificate_id: CertificateId
    ) -> DescribeCACertificateResponse:
        raise NotImplementedError

    @handler("DescribeCertificate")
    def describe_certificate(
        self, context: RequestContext, certificate_id: CertificateId
    ) -> DescribeCertificateResponse:
        raise NotImplementedError

    @handler("DescribeCustomMetric")
    def describe_custom_metric(
        self, context: RequestContext, metric_name: MetricName
    ) -> DescribeCustomMetricResponse:
        raise NotImplementedError

    @handler("DescribeDefaultAuthorizer")
    def describe_default_authorizer(
        self,
        context: RequestContext,
    ) -> DescribeDefaultAuthorizerResponse:
        raise NotImplementedError

    @handler("DescribeDetectMitigationActionsTask")
    def describe_detect_mitigation_actions_task(
        self, context: RequestContext, task_id: MitigationActionsTaskId
    ) -> DescribeDetectMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("DescribeDimension")
    def describe_dimension(
        self, context: RequestContext, name: DimensionName
    ) -> DescribeDimensionResponse:
        raise NotImplementedError

    @handler("DescribeDomainConfiguration")
    def describe_domain_configuration(
        self, context: RequestContext, domain_configuration_name: ReservedDomainConfigurationName
    ) -> DescribeDomainConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeEndpoint")
    def describe_endpoint(
        self, context: RequestContext, endpoint_type: EndpointType = None
    ) -> DescribeEndpointResponse:
        raise NotImplementedError

    @handler("DescribeEventConfigurations")
    def describe_event_configurations(
        self,
        context: RequestContext,
    ) -> DescribeEventConfigurationsResponse:
        raise NotImplementedError

    @handler("DescribeFleetMetric")
    def describe_fleet_metric(
        self, context: RequestContext, metric_name: FleetMetricName
    ) -> DescribeFleetMetricResponse:
        raise NotImplementedError

    @handler("DescribeIndex")
    def describe_index(
        self, context: RequestContext, index_name: IndexName
    ) -> DescribeIndexResponse:
        raise NotImplementedError

    @handler("DescribeJob")
    def describe_job(self, context: RequestContext, job_id: JobId) -> DescribeJobResponse:
        raise NotImplementedError

    @handler("DescribeJobExecution")
    def describe_job_execution(
        self,
        context: RequestContext,
        job_id: JobId,
        thing_name: ThingName,
        execution_number: ExecutionNumber = None,
    ) -> DescribeJobExecutionResponse:
        raise NotImplementedError

    @handler("DescribeJobTemplate")
    def describe_job_template(
        self, context: RequestContext, job_template_id: JobTemplateId
    ) -> DescribeJobTemplateResponse:
        raise NotImplementedError

    @handler("DescribeManagedJobTemplate")
    def describe_managed_job_template(
        self,
        context: RequestContext,
        template_name: ManagedJobTemplateName,
        template_version: ManagedTemplateVersion = None,
    ) -> DescribeManagedJobTemplateResponse:
        raise NotImplementedError

    @handler("DescribeMitigationAction")
    def describe_mitigation_action(
        self, context: RequestContext, action_name: MitigationActionName
    ) -> DescribeMitigationActionResponse:
        raise NotImplementedError

    @handler("DescribeProvisioningTemplate")
    def describe_provisioning_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DescribeProvisioningTemplateResponse:
        raise NotImplementedError

    @handler("DescribeProvisioningTemplateVersion")
    def describe_provisioning_template_version(
        self, context: RequestContext, template_name: TemplateName, version_id: TemplateVersionId
    ) -> DescribeProvisioningTemplateVersionResponse:
        raise NotImplementedError

    @handler("DescribeRoleAlias")
    def describe_role_alias(
        self, context: RequestContext, role_alias: RoleAlias
    ) -> DescribeRoleAliasResponse:
        raise NotImplementedError

    @handler("DescribeScheduledAudit")
    def describe_scheduled_audit(
        self, context: RequestContext, scheduled_audit_name: ScheduledAuditName
    ) -> DescribeScheduledAuditResponse:
        raise NotImplementedError

    @handler("DescribeSecurityProfile")
    def describe_security_profile(
        self, context: RequestContext, security_profile_name: SecurityProfileName
    ) -> DescribeSecurityProfileResponse:
        raise NotImplementedError

    @handler("DescribeStream")
    def describe_stream(
        self, context: RequestContext, stream_id: StreamId
    ) -> DescribeStreamResponse:
        raise NotImplementedError

    @handler("DescribeThing")
    def describe_thing(
        self, context: RequestContext, thing_name: ThingName
    ) -> DescribeThingResponse:
        raise NotImplementedError

    @handler("DescribeThingGroup")
    def describe_thing_group(
        self, context: RequestContext, thing_group_name: ThingGroupName
    ) -> DescribeThingGroupResponse:
        raise NotImplementedError

    @handler("DescribeThingRegistrationTask")
    def describe_thing_registration_task(
        self, context: RequestContext, task_id: TaskId
    ) -> DescribeThingRegistrationTaskResponse:
        raise NotImplementedError

    @handler("DescribeThingType")
    def describe_thing_type(
        self, context: RequestContext, thing_type_name: ThingTypeName
    ) -> DescribeThingTypeResponse:
        raise NotImplementedError

    @handler("DetachPolicy")
    def detach_policy(
        self, context: RequestContext, policy_name: PolicyName, target: PolicyTarget
    ) -> None:
        raise NotImplementedError

    @handler("DetachPrincipalPolicy")
    def detach_principal_policy(
        self, context: RequestContext, policy_name: PolicyName, principal: Principal
    ) -> None:
        raise NotImplementedError

    @handler("DetachSecurityProfile")
    def detach_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        security_profile_target_arn: SecurityProfileTargetArn,
    ) -> DetachSecurityProfileResponse:
        raise NotImplementedError

    @handler("DetachThingPrincipal")
    def detach_thing_principal(
        self, context: RequestContext, thing_name: ThingName, principal: Principal
    ) -> DetachThingPrincipalResponse:
        raise NotImplementedError

    @handler("DisableTopicRule")
    def disable_topic_rule(self, context: RequestContext, rule_name: RuleName) -> None:
        raise NotImplementedError

    @handler("EnableTopicRule")
    def enable_topic_rule(self, context: RequestContext, rule_name: RuleName) -> None:
        raise NotImplementedError

    @handler("GetBehaviorModelTrainingSummaries")
    def get_behavior_model_training_summaries(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName = None,
        max_results: TinyMaxResults = None,
        next_token: NextToken = None,
    ) -> GetBehaviorModelTrainingSummariesResponse:
        raise NotImplementedError

    @handler("GetBucketsAggregation")
    def get_buckets_aggregation(
        self,
        context: RequestContext,
        query_string: QueryString,
        aggregation_field: AggregationField,
        buckets_aggregation_type: BucketsAggregationType,
        index_name: IndexName = None,
        query_version: QueryVersion = None,
    ) -> GetBucketsAggregationResponse:
        raise NotImplementedError

    @handler("GetCardinality")
    def get_cardinality(
        self,
        context: RequestContext,
        query_string: QueryString,
        index_name: IndexName = None,
        aggregation_field: AggregationField = None,
        query_version: QueryVersion = None,
    ) -> GetCardinalityResponse:
        raise NotImplementedError

    @handler("GetEffectivePolicies")
    def get_effective_policies(
        self,
        context: RequestContext,
        principal: Principal = None,
        cognito_identity_pool_id: CognitoIdentityPoolId = None,
        thing_name: ThingName = None,
    ) -> GetEffectivePoliciesResponse:
        raise NotImplementedError

    @handler("GetIndexingConfiguration")
    def get_indexing_configuration(
        self,
        context: RequestContext,
    ) -> GetIndexingConfigurationResponse:
        raise NotImplementedError

    @handler("GetJobDocument")
    def get_job_document(self, context: RequestContext, job_id: JobId) -> GetJobDocumentResponse:
        raise NotImplementedError

    @handler("GetLoggingOptions")
    def get_logging_options(
        self,
        context: RequestContext,
    ) -> GetLoggingOptionsResponse:
        raise NotImplementedError

    @handler("GetOTAUpdate")
    def get_ota_update(
        self, context: RequestContext, ota_update_id: OTAUpdateId
    ) -> GetOTAUpdateResponse:
        raise NotImplementedError

    @handler("GetPercentiles")
    def get_percentiles(
        self,
        context: RequestContext,
        query_string: QueryString,
        index_name: IndexName = None,
        aggregation_field: AggregationField = None,
        query_version: QueryVersion = None,
        percents: PercentList = None,
    ) -> GetPercentilesResponse:
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(self, context: RequestContext, policy_name: PolicyName) -> GetPolicyResponse:
        raise NotImplementedError

    @handler("GetPolicyVersion")
    def get_policy_version(
        self, context: RequestContext, policy_name: PolicyName, policy_version_id: PolicyVersionId
    ) -> GetPolicyVersionResponse:
        raise NotImplementedError

    @handler("GetRegistrationCode")
    def get_registration_code(
        self,
        context: RequestContext,
    ) -> GetRegistrationCodeResponse:
        raise NotImplementedError

    @handler("GetStatistics")
    def get_statistics(
        self,
        context: RequestContext,
        query_string: QueryString,
        index_name: IndexName = None,
        aggregation_field: AggregationField = None,
        query_version: QueryVersion = None,
    ) -> GetStatisticsResponse:
        raise NotImplementedError

    @handler("GetTopicRule")
    def get_topic_rule(self, context: RequestContext, rule_name: RuleName) -> GetTopicRuleResponse:
        raise NotImplementedError

    @handler("GetTopicRuleDestination")
    def get_topic_rule_destination(
        self, context: RequestContext, arn: AwsArn
    ) -> GetTopicRuleDestinationResponse:
        raise NotImplementedError

    @handler("GetV2LoggingOptions")
    def get_v2_logging_options(
        self,
        context: RequestContext,
    ) -> GetV2LoggingOptionsResponse:
        raise NotImplementedError

    @handler("ListActiveViolations")
    def list_active_violations(
        self,
        context: RequestContext,
        thing_name: DeviceDefenderThingName = None,
        security_profile_name: SecurityProfileName = None,
        behavior_criteria_type: BehaviorCriteriaType = None,
        list_suppressed_alerts: ListSuppressedAlerts = None,
        verification_state: VerificationState = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListActiveViolationsResponse:
        raise NotImplementedError

    @handler("ListAttachedPolicies")
    def list_attached_policies(
        self,
        context: RequestContext,
        target: PolicyTarget,
        recursive: Recursive = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> ListAttachedPoliciesResponse:
        raise NotImplementedError

    @handler("ListAuditFindings")
    def list_audit_findings(
        self,
        context: RequestContext,
        task_id: AuditTaskId = None,
        check_name: AuditCheckName = None,
        resource_identifier: ResourceIdentifier = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        list_suppressed_findings: ListSuppressedFindings = None,
    ) -> ListAuditFindingsResponse:
        raise NotImplementedError

    @handler("ListAuditMitigationActionsExecutions")
    def list_audit_mitigation_actions_executions(
        self,
        context: RequestContext,
        task_id: MitigationActionsTaskId,
        finding_id: FindingId,
        action_status: AuditMitigationActionsExecutionStatus = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListAuditMitigationActionsExecutionsResponse:
        raise NotImplementedError

    @handler("ListAuditMitigationActionsTasks")
    def list_audit_mitigation_actions_tasks(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        audit_task_id: AuditTaskId = None,
        finding_id: FindingId = None,
        task_status: AuditMitigationActionsTaskStatus = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListAuditMitigationActionsTasksResponse:
        raise NotImplementedError

    @handler("ListAuditSuppressions")
    def list_audit_suppressions(
        self,
        context: RequestContext,
        check_name: AuditCheckName = None,
        resource_identifier: ResourceIdentifier = None,
        ascending_order: AscendingOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAuditSuppressionsResponse:
        raise NotImplementedError

    @handler("ListAuditTasks")
    def list_audit_tasks(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        task_type: AuditTaskType = None,
        task_status: AuditTaskStatus = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAuditTasksResponse:
        raise NotImplementedError

    @handler("ListAuthorizers")
    def list_authorizers(
        self,
        context: RequestContext,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
        status: AuthorizerStatus = None,
    ) -> ListAuthorizersResponse:
        raise NotImplementedError

    @handler("ListBillingGroups")
    def list_billing_groups(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
        name_prefix_filter: BillingGroupName = None,
    ) -> ListBillingGroupsResponse:
        raise NotImplementedError

    @handler("ListCACertificates")
    def list_ca_certificates(
        self,
        context: RequestContext,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
    ) -> ListCACertificatesResponse:
        raise NotImplementedError

    @handler("ListCertificates")
    def list_certificates(
        self,
        context: RequestContext,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
    ) -> ListCertificatesResponse:
        raise NotImplementedError

    @handler("ListCertificatesByCA")
    def list_certificates_by_ca(
        self,
        context: RequestContext,
        ca_certificate_id: CertificateId,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
    ) -> ListCertificatesByCAResponse:
        raise NotImplementedError

    @handler("ListCustomMetrics")
    def list_custom_metrics(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListCustomMetricsResponse:
        raise NotImplementedError

    @handler("ListDetectMitigationActionsExecutions")
    def list_detect_mitigation_actions_executions(
        self,
        context: RequestContext,
        task_id: MitigationActionsTaskId = None,
        violation_id: ViolationId = None,
        thing_name: DeviceDefenderThingName = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDetectMitigationActionsExecutionsResponse:
        raise NotImplementedError

    @handler("ListDetectMitigationActionsTasks")
    def list_detect_mitigation_actions_tasks(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDetectMitigationActionsTasksResponse:
        raise NotImplementedError

    @handler("ListDimensions")
    def list_dimensions(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDimensionsResponse:
        raise NotImplementedError

    @handler("ListDomainConfigurations")
    def list_domain_configurations(
        self,
        context: RequestContext,
        marker: Marker = None,
        page_size: PageSize = None,
        service_type: ServiceType = None,
    ) -> ListDomainConfigurationsResponse:
        raise NotImplementedError

    @handler("ListFleetMetrics")
    def list_fleet_metrics(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListFleetMetricsResponse:
        raise NotImplementedError

    @handler("ListIndices")
    def list_indices(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: QueryMaxResults = None,
    ) -> ListIndicesResponse:
        raise NotImplementedError

    @handler("ListJobExecutionsForJob")
    def list_job_executions_for_job(
        self,
        context: RequestContext,
        job_id: JobId,
        status: JobExecutionStatus = None,
        max_results: LaserMaxResults = None,
        next_token: NextToken = None,
    ) -> ListJobExecutionsForJobResponse:
        raise NotImplementedError

    @handler("ListJobExecutionsForThing")
    def list_job_executions_for_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        status: JobExecutionStatus = None,
        namespace_id: NamespaceId = None,
        max_results: LaserMaxResults = None,
        next_token: NextToken = None,
        job_id: JobId = None,
    ) -> ListJobExecutionsForThingResponse:
        raise NotImplementedError

    @handler("ListJobTemplates")
    def list_job_templates(
        self,
        context: RequestContext,
        max_results: LaserMaxResults = None,
        next_token: NextToken = None,
    ) -> ListJobTemplatesResponse:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        status: JobStatus = None,
        target_selection: TargetSelection = None,
        max_results: LaserMaxResults = None,
        next_token: NextToken = None,
        thing_group_name: ThingGroupName = None,
        thing_group_id: ThingGroupId = None,
        namespace_id: NamespaceId = None,
    ) -> ListJobsResponse:
        raise NotImplementedError

    @handler("ListManagedJobTemplates")
    def list_managed_job_templates(
        self,
        context: RequestContext,
        template_name: ManagedJobTemplateName = None,
        max_results: LaserMaxResults = None,
        next_token: NextToken = None,
    ) -> ListManagedJobTemplatesResponse:
        raise NotImplementedError

    @handler("ListMitigationActions")
    def list_mitigation_actions(
        self,
        context: RequestContext,
        action_type: MitigationActionType = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListMitigationActionsResponse:
        raise NotImplementedError

    @handler("ListOTAUpdates")
    def list_ota_updates(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        ota_update_status: OTAUpdateStatus = None,
    ) -> ListOTAUpdatesResponse:
        raise NotImplementedError

    @handler("ListOutgoingCertificates")
    def list_outgoing_certificates(
        self,
        context: RequestContext,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
    ) -> ListOutgoingCertificatesResponse:
        raise NotImplementedError

    @handler("ListPolicies")
    def list_policies(
        self,
        context: RequestContext,
        marker: Marker = None,
        page_size: PageSize = None,
        ascending_order: AscendingOrder = None,
    ) -> ListPoliciesResponse:
        raise NotImplementedError

    @handler("ListPolicyPrincipals")
    def list_policy_principals(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        marker: Marker = None,
        page_size: PageSize = None,
        ascending_order: AscendingOrder = None,
    ) -> ListPolicyPrincipalsResponse:
        raise NotImplementedError

    @handler("ListPolicyVersions")
    def list_policy_versions(
        self, context: RequestContext, policy_name: PolicyName
    ) -> ListPolicyVersionsResponse:
        raise NotImplementedError

    @handler("ListPrincipalPolicies")
    def list_principal_policies(
        self,
        context: RequestContext,
        principal: Principal,
        marker: Marker = None,
        page_size: PageSize = None,
        ascending_order: AscendingOrder = None,
    ) -> ListPrincipalPoliciesResponse:
        raise NotImplementedError

    @handler("ListPrincipalThings")
    def list_principal_things(
        self,
        context: RequestContext,
        principal: Principal,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListPrincipalThingsResponse:
        raise NotImplementedError

    @handler("ListProvisioningTemplateVersions")
    def list_provisioning_template_versions(
        self,
        context: RequestContext,
        template_name: TemplateName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListProvisioningTemplateVersionsResponse:
        raise NotImplementedError

    @handler("ListProvisioningTemplates")
    def list_provisioning_templates(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListProvisioningTemplatesResponse:
        raise NotImplementedError

    @handler("ListRoleAliases")
    def list_role_aliases(
        self,
        context: RequestContext,
        page_size: PageSize = None,
        marker: Marker = None,
        ascending_order: AscendingOrder = None,
    ) -> ListRoleAliasesResponse:
        raise NotImplementedError

    @handler("ListScheduledAudits")
    def list_scheduled_audits(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListScheduledAuditsResponse:
        raise NotImplementedError

    @handler("ListSecurityProfiles")
    def list_security_profiles(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        dimension_name: DimensionName = None,
        metric_name: MetricName = None,
    ) -> ListSecurityProfilesResponse:
        raise NotImplementedError

    @handler("ListSecurityProfilesForTarget")
    def list_security_profiles_for_target(
        self,
        context: RequestContext,
        security_profile_target_arn: SecurityProfileTargetArn,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        recursive: Recursive = None,
    ) -> ListSecurityProfilesForTargetResponse:
        raise NotImplementedError

    @handler("ListStreams")
    def list_streams(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        ascending_order: AscendingOrder = None,
    ) -> ListStreamsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn, next_token: NextToken = None
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTargetsForPolicy")
    def list_targets_for_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> ListTargetsForPolicyResponse:
        raise NotImplementedError

    @handler("ListTargetsForSecurityProfile")
    def list_targets_for_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTargetsForSecurityProfileResponse:
        raise NotImplementedError

    @handler("ListThingGroups")
    def list_thing_groups(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
        parent_group: ThingGroupName = None,
        name_prefix_filter: ThingGroupName = None,
        recursive: RecursiveWithoutDefault = None,
    ) -> ListThingGroupsResponse:
        raise NotImplementedError

    @handler("ListThingGroupsForThing")
    def list_thing_groups_for_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListThingGroupsForThingResponse:
        raise NotImplementedError

    @handler("ListThingPrincipals")
    def list_thing_principals(
        self,
        context: RequestContext,
        thing_name: ThingName,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListThingPrincipalsResponse:
        raise NotImplementedError

    @handler("ListThingRegistrationTaskReports")
    def list_thing_registration_task_reports(
        self,
        context: RequestContext,
        task_id: TaskId,
        report_type: ReportType,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListThingRegistrationTaskReportsResponse:
        raise NotImplementedError

    @handler("ListThingRegistrationTasks")
    def list_thing_registration_tasks(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
        status: Status = None,
    ) -> ListThingRegistrationTasksResponse:
        raise NotImplementedError

    @handler("ListThingTypes")
    def list_thing_types(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
        thing_type_name: ThingTypeName = None,
    ) -> ListThingTypesResponse:
        raise NotImplementedError

    @handler("ListThings")
    def list_things(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
        attribute_name: AttributeName = None,
        attribute_value: AttributeValue = None,
        thing_type_name: ThingTypeName = None,
        use_prefix_attribute_value: usePrefixAttributeValue = None,
    ) -> ListThingsResponse:
        raise NotImplementedError

    @handler("ListThingsInBillingGroup")
    def list_things_in_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListThingsInBillingGroupResponse:
        raise NotImplementedError

    @handler("ListThingsInThingGroup")
    def list_things_in_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        recursive: Recursive = None,
        next_token: NextToken = None,
        max_results: RegistryMaxResults = None,
    ) -> ListThingsInThingGroupResponse:
        raise NotImplementedError

    @handler("ListTopicRuleDestinations")
    def list_topic_rule_destinations(
        self,
        context: RequestContext,
        max_results: TopicRuleDestinationMaxResults = None,
        next_token: NextToken = None,
    ) -> ListTopicRuleDestinationsResponse:
        raise NotImplementedError

    @handler("ListTopicRules")
    def list_topic_rules(
        self,
        context: RequestContext,
        topic: Topic = None,
        max_results: TopicRuleMaxResults = None,
        next_token: NextToken = None,
        rule_disabled: IsDisabled = None,
    ) -> ListTopicRulesResponse:
        raise NotImplementedError

    @handler("ListV2LoggingLevels")
    def list_v2_logging_levels(
        self,
        context: RequestContext,
        target_type: LogTargetType = None,
        next_token: NextToken = None,
        max_results: SkyfallMaxResults = None,
    ) -> ListV2LoggingLevelsResponse:
        raise NotImplementedError

    @handler("ListViolationEvents")
    def list_violation_events(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        thing_name: DeviceDefenderThingName = None,
        security_profile_name: SecurityProfileName = None,
        behavior_criteria_type: BehaviorCriteriaType = None,
        list_suppressed_alerts: ListSuppressedAlerts = None,
        verification_state: VerificationState = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListViolationEventsResponse:
        raise NotImplementedError

    @handler("PutVerificationStateOnViolation")
    def put_verification_state_on_violation(
        self,
        context: RequestContext,
        violation_id: ViolationId,
        verification_state: VerificationState,
        verification_state_description: VerificationStateDescription = None,
    ) -> PutVerificationStateOnViolationResponse:
        raise NotImplementedError

    @handler("RegisterCACertificate")
    def register_ca_certificate(
        self,
        context: RequestContext,
        ca_certificate: CertificatePem,
        verification_certificate: CertificatePem,
        set_as_active: SetAsActive = None,
        allow_auto_registration: AllowAutoRegistration = None,
        registration_config: RegistrationConfig = None,
        tags: TagList = None,
    ) -> RegisterCACertificateResponse:
        raise NotImplementedError

    @handler("RegisterCertificate")
    def register_certificate(
        self,
        context: RequestContext,
        certificate_pem: CertificatePem,
        ca_certificate_pem: CertificatePem = None,
        set_as_active: SetAsActiveFlag = None,
        status: CertificateStatus = None,
    ) -> RegisterCertificateResponse:
        raise NotImplementedError

    @handler("RegisterCertificateWithoutCA")
    def register_certificate_without_ca(
        self,
        context: RequestContext,
        certificate_pem: CertificatePem,
        status: CertificateStatus = None,
    ) -> RegisterCertificateWithoutCAResponse:
        raise NotImplementedError

    @handler("RegisterThing")
    def register_thing(
        self, context: RequestContext, template_body: TemplateBody, parameters: Parameters = None
    ) -> RegisterThingResponse:
        raise NotImplementedError

    @handler("RejectCertificateTransfer")
    def reject_certificate_transfer(
        self, context: RequestContext, certificate_id: CertificateId, reject_reason: Message = None
    ) -> None:
        raise NotImplementedError

    @handler("RemoveThingFromBillingGroup")
    def remove_thing_from_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName = None,
        billing_group_arn: BillingGroupArn = None,
        thing_name: ThingName = None,
        thing_arn: ThingArn = None,
    ) -> RemoveThingFromBillingGroupResponse:
        raise NotImplementedError

    @handler("RemoveThingFromThingGroup")
    def remove_thing_from_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName = None,
        thing_group_arn: ThingGroupArn = None,
        thing_name: ThingName = None,
        thing_arn: ThingArn = None,
    ) -> RemoveThingFromThingGroupResponse:
        raise NotImplementedError

    @handler("ReplaceTopicRule")
    def replace_topic_rule(
        self, context: RequestContext, rule_name: RuleName, topic_rule_payload: TopicRulePayload
    ) -> None:
        raise NotImplementedError

    @handler("SearchIndex")
    def search_index(
        self,
        context: RequestContext,
        query_string: QueryString,
        index_name: IndexName = None,
        next_token: NextToken = None,
        max_results: QueryMaxResults = None,
        query_version: QueryVersion = None,
    ) -> SearchIndexResponse:
        raise NotImplementedError

    @handler("SetDefaultAuthorizer")
    def set_default_authorizer(
        self, context: RequestContext, authorizer_name: AuthorizerName
    ) -> SetDefaultAuthorizerResponse:
        raise NotImplementedError

    @handler("SetDefaultPolicyVersion")
    def set_default_policy_version(
        self, context: RequestContext, policy_name: PolicyName, policy_version_id: PolicyVersionId
    ) -> None:
        raise NotImplementedError

    @handler("SetLoggingOptions")
    def set_logging_options(
        self, context: RequestContext, logging_options_payload: LoggingOptionsPayload
    ) -> None:
        raise NotImplementedError

    @handler("SetV2LoggingLevel")
    def set_v2_logging_level(
        self, context: RequestContext, log_target: LogTarget, log_level: LogLevel
    ) -> None:
        raise NotImplementedError

    @handler("SetV2LoggingOptions")
    def set_v2_logging_options(
        self,
        context: RequestContext,
        role_arn: AwsArn = None,
        default_log_level: LogLevel = None,
        disable_all_logs: DisableAllLogs = None,
    ) -> None:
        raise NotImplementedError

    @handler("StartAuditMitigationActionsTask")
    def start_audit_mitigation_actions_task(
        self,
        context: RequestContext,
        task_id: MitigationActionsTaskId,
        target: AuditMitigationActionsTaskTarget,
        audit_check_to_actions_mapping: AuditCheckToActionsMapping,
        client_request_token: ClientRequestToken,
    ) -> StartAuditMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("StartDetectMitigationActionsTask")
    def start_detect_mitigation_actions_task(
        self,
        context: RequestContext,
        task_id: MitigationActionsTaskId,
        target: DetectMitigationActionsTaskTarget,
        actions: DetectMitigationActionsToExecuteList,
        client_request_token: ClientRequestToken,
        violation_event_occurrence_range: ViolationEventOccurrenceRange = None,
        include_only_active_violations: NullableBoolean = None,
        include_suppressed_alerts: NullableBoolean = None,
    ) -> StartDetectMitigationActionsTaskResponse:
        raise NotImplementedError

    @handler("StartOnDemandAuditTask")
    def start_on_demand_audit_task(
        self, context: RequestContext, target_check_names: TargetAuditCheckNames
    ) -> StartOnDemandAuditTaskResponse:
        raise NotImplementedError

    @handler("StartThingRegistrationTask")
    def start_thing_registration_task(
        self,
        context: RequestContext,
        template_body: TemplateBody,
        input_file_bucket: RegistryS3BucketName,
        input_file_key: RegistryS3KeyName,
        role_arn: RoleArn,
    ) -> StartThingRegistrationTaskResponse:
        raise NotImplementedError

    @handler("StopThingRegistrationTask")
    def stop_thing_registration_task(
        self, context: RequestContext, task_id: TaskId
    ) -> StopThingRegistrationTaskResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestAuthorization")
    def test_authorization(
        self,
        context: RequestContext,
        auth_infos: AuthInfos,
        principal: Principal = None,
        cognito_identity_pool_id: CognitoIdentityPoolId = None,
        client_id: ClientId = None,
        policy_names_to_add: PolicyNames = None,
        policy_names_to_skip: PolicyNames = None,
    ) -> TestAuthorizationResponse:
        raise NotImplementedError

    @handler("TestInvokeAuthorizer")
    def test_invoke_authorizer(
        self,
        context: RequestContext,
        authorizer_name: AuthorizerName,
        token: Token = None,
        token_signature: TokenSignature = None,
        http_context: HttpContext = None,
        mqtt_context: MqttContext = None,
        tls_context: TlsContext = None,
    ) -> TestInvokeAuthorizerResponse:
        raise NotImplementedError

    @handler("TransferCertificate")
    def transfer_certificate(
        self,
        context: RequestContext,
        certificate_id: CertificateId,
        target_aws_account: AwsAccountId,
        transfer_message: Message = None,
    ) -> TransferCertificateResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateAccountAuditConfiguration")
    def update_account_audit_configuration(
        self,
        context: RequestContext,
        role_arn: RoleArn = None,
        audit_notification_target_configurations: AuditNotificationTargetConfigurations = None,
        audit_check_configurations: AuditCheckConfigurations = None,
    ) -> UpdateAccountAuditConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateAuditSuppression")
    def update_audit_suppression(
        self,
        context: RequestContext,
        check_name: AuditCheckName,
        resource_identifier: ResourceIdentifier,
        expiration_date: Timestamp = None,
        suppress_indefinitely: SuppressIndefinitely = None,
        description: AuditDescription = None,
    ) -> UpdateAuditSuppressionResponse:
        raise NotImplementedError

    @handler("UpdateAuthorizer")
    def update_authorizer(
        self,
        context: RequestContext,
        authorizer_name: AuthorizerName,
        authorizer_function_arn: AuthorizerFunctionArn = None,
        token_key_name: TokenKeyName = None,
        token_signing_public_keys: PublicKeyMap = None,
        status: AuthorizerStatus = None,
        enable_caching_for_http: EnableCachingForHttp = None,
    ) -> UpdateAuthorizerResponse:
        raise NotImplementedError

    @handler("UpdateBillingGroup")
    def update_billing_group(
        self,
        context: RequestContext,
        billing_group_name: BillingGroupName,
        billing_group_properties: BillingGroupProperties,
        expected_version: OptionalVersion = None,
    ) -> UpdateBillingGroupResponse:
        raise NotImplementedError

    @handler("UpdateCACertificate")
    def update_ca_certificate(
        self,
        context: RequestContext,
        certificate_id: CertificateId,
        new_status: CACertificateStatus = None,
        new_auto_registration_status: AutoRegistrationStatus = None,
        registration_config: RegistrationConfig = None,
        remove_auto_registration: RemoveAutoRegistration = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCertificate")
    def update_certificate(
        self, context: RequestContext, certificate_id: CertificateId, new_status: CertificateStatus
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCustomMetric")
    def update_custom_metric(
        self,
        context: RequestContext,
        metric_name: MetricName,
        display_name: CustomMetricDisplayName,
    ) -> UpdateCustomMetricResponse:
        raise NotImplementedError

    @handler("UpdateDimension")
    def update_dimension(
        self, context: RequestContext, name: DimensionName, string_values: DimensionStringValues
    ) -> UpdateDimensionResponse:
        raise NotImplementedError

    @handler("UpdateDomainConfiguration")
    def update_domain_configuration(
        self,
        context: RequestContext,
        domain_configuration_name: ReservedDomainConfigurationName,
        authorizer_config: AuthorizerConfig = None,
        domain_configuration_status: DomainConfigurationStatus = None,
        remove_authorizer_config: RemoveAuthorizerConfig = None,
    ) -> UpdateDomainConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateDynamicThingGroup")
    def update_dynamic_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        thing_group_properties: ThingGroupProperties,
        expected_version: OptionalVersion = None,
        index_name: IndexName = None,
        query_string: QueryString = None,
        query_version: QueryVersion = None,
    ) -> UpdateDynamicThingGroupResponse:
        raise NotImplementedError

    @handler("UpdateEventConfigurations")
    def update_event_configurations(
        self, context: RequestContext, event_configurations: EventConfigurations = None
    ) -> UpdateEventConfigurationsResponse:
        raise NotImplementedError

    @handler("UpdateFleetMetric")
    def update_fleet_metric(
        self,
        context: RequestContext,
        metric_name: FleetMetricName,
        index_name: IndexName,
        query_string: QueryString = None,
        aggregation_type: AggregationType = None,
        period: FleetMetricPeriod = None,
        aggregation_field: AggregationField = None,
        description: FleetMetricDescription = None,
        query_version: QueryVersion = None,
        unit: FleetMetricUnit = None,
        expected_version: OptionalVersion = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateIndexingConfiguration")
    def update_indexing_configuration(
        self,
        context: RequestContext,
        thing_indexing_configuration: ThingIndexingConfiguration = None,
        thing_group_indexing_configuration: ThingGroupIndexingConfiguration = None,
    ) -> UpdateIndexingConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateJob")
    def update_job(
        self,
        context: RequestContext,
        job_id: JobId,
        description: JobDescription = None,
        presigned_url_config: PresignedUrlConfig = None,
        job_executions_rollout_config: JobExecutionsRolloutConfig = None,
        abort_config: AbortConfig = None,
        timeout_config: TimeoutConfig = None,
        namespace_id: NamespaceId = None,
        job_executions_retry_config: JobExecutionsRetryConfig = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateMitigationAction")
    def update_mitigation_action(
        self,
        context: RequestContext,
        action_name: MitigationActionName,
        role_arn: RoleArn = None,
        action_params: MitigationActionParams = None,
    ) -> UpdateMitigationActionResponse:
        raise NotImplementedError

    @handler("UpdateProvisioningTemplate")
    def update_provisioning_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        description: TemplateDescription = None,
        enabled: Enabled = None,
        default_version_id: TemplateVersionId = None,
        provisioning_role_arn: RoleArn = None,
        pre_provisioning_hook: ProvisioningHook = None,
        remove_pre_provisioning_hook: RemoveHook = None,
    ) -> UpdateProvisioningTemplateResponse:
        raise NotImplementedError

    @handler("UpdateRoleAlias")
    def update_role_alias(
        self,
        context: RequestContext,
        role_alias: RoleAlias,
        role_arn: RoleArn = None,
        credential_duration_seconds: CredentialDurationSeconds = None,
    ) -> UpdateRoleAliasResponse:
        raise NotImplementedError

    @handler("UpdateScheduledAudit")
    def update_scheduled_audit(
        self,
        context: RequestContext,
        scheduled_audit_name: ScheduledAuditName,
        frequency: AuditFrequency = None,
        day_of_month: DayOfMonth = None,
        day_of_week: DayOfWeek = None,
        target_check_names: TargetAuditCheckNames = None,
    ) -> UpdateScheduledAuditResponse:
        raise NotImplementedError

    @handler("UpdateSecurityProfile")
    def update_security_profile(
        self,
        context: RequestContext,
        security_profile_name: SecurityProfileName,
        security_profile_description: SecurityProfileDescription = None,
        behaviors: Behaviors = None,
        alert_targets: AlertTargets = None,
        additional_metrics_to_retain: AdditionalMetricsToRetainList = None,
        additional_metrics_to_retain_v2: AdditionalMetricsToRetainV2List = None,
        delete_behaviors: DeleteBehaviors = None,
        delete_alert_targets: DeleteAlertTargets = None,
        delete_additional_metrics_to_retain: DeleteAdditionalMetricsToRetain = None,
        expected_version: OptionalVersion = None,
    ) -> UpdateSecurityProfileResponse:
        raise NotImplementedError

    @handler("UpdateStream")
    def update_stream(
        self,
        context: RequestContext,
        stream_id: StreamId,
        description: StreamDescription = None,
        files: StreamFiles = None,
        role_arn: RoleArn = None,
    ) -> UpdateStreamResponse:
        raise NotImplementedError

    @handler("UpdateThing")
    def update_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        thing_type_name: ThingTypeName = None,
        attribute_payload: AttributePayload = None,
        expected_version: OptionalVersion = None,
        remove_thing_type: RemoveThingType = None,
    ) -> UpdateThingResponse:
        raise NotImplementedError

    @handler("UpdateThingGroup")
    def update_thing_group(
        self,
        context: RequestContext,
        thing_group_name: ThingGroupName,
        thing_group_properties: ThingGroupProperties,
        expected_version: OptionalVersion = None,
    ) -> UpdateThingGroupResponse:
        raise NotImplementedError

    @handler("UpdateThingGroupsForThing")
    def update_thing_groups_for_thing(
        self,
        context: RequestContext,
        thing_name: ThingName = None,
        thing_groups_to_add: ThingGroupList = None,
        thing_groups_to_remove: ThingGroupList = None,
        override_dynamic_groups: OverrideDynamicGroups = None,
    ) -> UpdateThingGroupsForThingResponse:
        raise NotImplementedError

    @handler("UpdateTopicRuleDestination")
    def update_topic_rule_destination(
        self, context: RequestContext, arn: AwsArn, status: TopicRuleDestinationStatus
    ) -> UpdateTopicRuleDestinationResponse:
        raise NotImplementedError

    @handler("ValidateSecurityProfileBehaviors")
    def validate_security_profile_behaviors(
        self, context: RequestContext, behaviors: Behaviors
    ) -> ValidateSecurityProfileBehaviorsResponse:
        raise NotImplementedError
