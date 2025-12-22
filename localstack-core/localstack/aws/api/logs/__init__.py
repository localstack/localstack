from collections.abc import Iterator
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessPolicy = str
AccountId = str
AccountPolicyDocument = str
AddKeyValue = str
AllowedActionForAllowVendedLogsDeliveryForResource = str
AmazonResourceName = str
AnomalyDetectorArn = str
AnomalyId = str
ApplyOnTransformedLogs = bool
Arn = str
Baseline = bool
BatchId = str
Boolean = bool
ClientToken = str
CollectionRetentionDays = int
Column = str
DataProtectionPolicyDocument = str
DataSourceName = str
DataSourceType = str
DataType = str
Days = int
DefaultValue = float
DeletionProtectionEnabled = bool
Delimiter = str
DeliveryDestinationName = str
DeliveryDestinationPolicy = str
DeliveryId = str
DeliverySourceName = str
DeliverySuffixPath = str
Descending = bool
DescribeLimit = int
DescribeQueriesMaxResults = int
Description = str
DestinationArn = str
DestinationField = str
DestinationName = str
DetectorKmsKeyArn = str
DetectorName = str
DimensionsKey = str
DimensionsValue = str
DynamicTokenPosition = int
EncryptionKey = str
EntityAttributesKey = str
EntityAttributesValue = str
EntityKeyAttributesKey = str
EntityKeyAttributesValue = str
ErrorMessage = str
EventId = str
EventMessage = str
EventsLimit = int
ExpectedRevisionId = str
ExportDestinationBucket = str
ExportDestinationPrefix = str
ExportTaskId = str
ExportTaskName = str
ExportTaskStatusMessage = str
Field = str
FieldDelimiter = str
FieldHeader = str
FieldIndexName = str
FieldSelectionCriteria = str
FilterCount = int
FilterName = str
FilterPattern = str
Flatten = bool
Force = bool
ForceUpdate = bool
FromKey = str
GetScheduledQueryHistoryMaxResults = int
GrokMatch = str
GroupingIdentifierKey = str
GroupingIdentifierValue = str
ImportId = str
IncludeLinkedAccounts = bool
InferredTokenName = str
Integer = int
IntegrationName = str
IntegrationNamePrefix = str
IntegrationStatusMessage = str
Interleaved = bool
IsSampled = bool
Key = str
KeyPrefix = str
KeyValueDelimiter = str
KmsKeyId = str
ListAnomaliesLimit = int
ListLimit = int
ListLogAnomalyDetectorsLimit = int
ListLogGroupsForQueryMaxResults = int
ListLogGroupsRequestLimit = int
ListScheduledQueriesMaxResults = int
ListSourcesForS3TableIntegrationMaxResults = int
Locale = str
LogEventIndex = int
LogFieldName = str
LogGroupArn = str
LogGroupCount = int
LogGroupIdentifier = str
LogGroupName = str
LogGroupNamePattern = str
LogGroupNameRegexPattern = str
LogObjectPointer = str
LogRecordPointer = str
LogStreamName = str
LogStreamSearchedCompletely = bool
LogType = str
MappingVersion = str
MatchPattern = str
Message = str
MetricName = str
MetricNamespace = str
MetricValue = str
NextToken = str
NonMatchValue = str
OpenSearchApplicationEndpoint = str
OpenSearchApplicationId = str
OpenSearchCollectionEndpoint = str
OpenSearchDataSourceName = str
OpenSearchPolicyName = str
OpenSearchWorkspaceId = str
OverwriteIfExists = bool
ParserFieldDelimiter = str
PatternId = str
PatternRegex = str
PatternString = str
Percentage = int
PolicyDocument = str
PolicyName = str
Priority = str
QueryCharOffset = int
QueryDefinitionName = str
QueryDefinitionString = str
QueryId = str
QueryListMaxResults = int
QueryString = str
QuoteCharacter = str
RenameTo = str
RequestId = str
ResourceIdentifier = str
ResourceType = str
RoleArn = str
S3TableIntegrationSourceIdentifier = str
S3TableIntegrationSourceStatusReason = str
S3Uri = str
ScheduleExpression = str
ScheduleTimezone = str
ScheduledQueryDescription = str
ScheduledQueryIdentifier = str
ScheduledQueryName = str
SelectionCriteria = str
SequenceToken = str
Service = str
SessionId = str
Source = str
SourceTimezone = str
SplitStringDelimiter = str
StartFromHead = bool
StatsValue = float
String = str
Success = bool
SystemField = str
TagKey = str
TagValue = str
Target = str
TargetArn = str
TargetFormat = str
TargetTimezone = str
Time = str
ToKey = str
Token = str
TokenString = str
TransformedEventMessage = str
Unmask = bool
Value = str
ValueKey = str
WithKey = str


class ActionStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    CLIENT_ERROR = "CLIENT_ERROR"
    FAILED = "FAILED"
    COMPLETE = "COMPLETE"


class AnomalyDetectorStatus(StrEnum):
    INITIALIZING = "INITIALIZING"
    TRAINING = "TRAINING"
    ANALYZING = "ANALYZING"
    FAILED = "FAILED"
    DELETED = "DELETED"
    PAUSED = "PAUSED"


class DataProtectionStatus(StrEnum):
    ACTIVATED = "ACTIVATED"
    DELETED = "DELETED"
    ARCHIVED = "ARCHIVED"
    DISABLED = "DISABLED"


class DeliveryDestinationType(StrEnum):
    S3 = "S3"
    CWL = "CWL"
    FH = "FH"
    XRAY = "XRAY"


class Distribution(StrEnum):
    Random = "Random"
    ByLogStream = "ByLogStream"


class EntityRejectionErrorType(StrEnum):
    InvalidEntity = "InvalidEntity"
    InvalidTypeValue = "InvalidTypeValue"
    InvalidKeyAttributes = "InvalidKeyAttributes"
    InvalidAttributes = "InvalidAttributes"
    EntitySizeTooLarge = "EntitySizeTooLarge"
    UnsupportedLogGroupType = "UnsupportedLogGroupType"
    MissingRequiredFields = "MissingRequiredFields"


class EvaluationFrequency(StrEnum):
    ONE_MIN = "ONE_MIN"
    FIVE_MIN = "FIVE_MIN"
    TEN_MIN = "TEN_MIN"
    FIFTEEN_MIN = "FIFTEEN_MIN"
    THIRTY_MIN = "THIRTY_MIN"
    ONE_HOUR = "ONE_HOUR"


class EventSource(StrEnum):
    CloudTrail = "CloudTrail"
    Route53Resolver = "Route53Resolver"
    VPCFlow = "VPCFlow"
    EKSAudit = "EKSAudit"
    AWSWAF = "AWSWAF"


class ExecutionStatus(StrEnum):
    Running = "Running"
    InvalidQuery = "InvalidQuery"
    Complete = "Complete"
    Failed = "Failed"
    Timeout = "Timeout"


class ExportTaskStatusCode(StrEnum):
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    PENDING_CANCEL = "PENDING_CANCEL"
    RUNNING = "RUNNING"


class FlattenedElement(StrEnum):
    first = "first"
    last = "last"


class ImportStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class IndexSource(StrEnum):
    ACCOUNT = "ACCOUNT"
    LOG_GROUP = "LOG_GROUP"


class IndexType(StrEnum):
    FACET = "FACET"
    FIELD_INDEX = "FIELD_INDEX"


class InheritedProperty(StrEnum):
    ACCOUNT_DATA_PROTECTION = "ACCOUNT_DATA_PROTECTION"


class IntegrationStatus(StrEnum):
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class IntegrationType(StrEnum):
    OPENSEARCH = "OPENSEARCH"


class ListAggregateLogGroupSummariesGroupBy(StrEnum):
    DATA_SOURCE_NAME_TYPE_AND_FORMAT = "DATA_SOURCE_NAME_TYPE_AND_FORMAT"
    DATA_SOURCE_NAME_AND_TYPE = "DATA_SOURCE_NAME_AND_TYPE"


class LogGroupClass(StrEnum):
    STANDARD = "STANDARD"
    INFREQUENT_ACCESS = "INFREQUENT_ACCESS"
    DELIVERY = "DELIVERY"


class OCSFVersion(StrEnum):
    V1_1 = "V1.1"
    V1_5 = "V1.5"


class OpenSearchResourceStatusType(StrEnum):
    ACTIVE = "ACTIVE"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"


class OrderBy(StrEnum):
    LogStreamName = "LogStreamName"
    LastEventTime = "LastEventTime"


class OutputFormat(StrEnum):
    json = "json"
    plain = "plain"
    w3c = "w3c"
    raw = "raw"
    parquet = "parquet"


class PolicyScope(StrEnum):
    ACCOUNT = "ACCOUNT"
    RESOURCE = "RESOURCE"


class PolicyType(StrEnum):
    DATA_PROTECTION_POLICY = "DATA_PROTECTION_POLICY"
    SUBSCRIPTION_FILTER_POLICY = "SUBSCRIPTION_FILTER_POLICY"
    FIELD_INDEX_POLICY = "FIELD_INDEX_POLICY"
    TRANSFORMER_POLICY = "TRANSFORMER_POLICY"
    METRIC_EXTRACTION_POLICY = "METRIC_EXTRACTION_POLICY"


class QueryLanguage(StrEnum):
    CWLI = "CWLI"
    SQL = "SQL"
    PPL = "PPL"


class QueryStatus(StrEnum):
    Scheduled = "Scheduled"
    Running = "Running"
    Complete = "Complete"
    Failed = "Failed"
    Cancelled = "Cancelled"
    Timeout = "Timeout"
    Unknown = "Unknown"


class S3TableIntegrationSourceStatus(StrEnum):
    ACTIVE = "ACTIVE"
    UNHEALTHY = "UNHEALTHY"
    FAILED = "FAILED"
    DATA_SOURCE_DELETE_IN_PROGRESS = "DATA_SOURCE_DELETE_IN_PROGRESS"


class ScheduledQueryDestinationType(StrEnum):
    S3 = "S3"


class ScheduledQueryState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Scope(StrEnum):
    ALL = "ALL"


class StandardUnit(StrEnum):
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


class State(StrEnum):
    Active = "Active"
    Suppressed = "Suppressed"
    Baseline = "Baseline"


class SuppressionState(StrEnum):
    SUPPRESSED = "SUPPRESSED"
    UNSUPPRESSED = "UNSUPPRESSED"


class SuppressionType(StrEnum):
    LIMITED = "LIMITED"
    INFINITE = "INFINITE"


class SuppressionUnit(StrEnum):
    SECONDS = "SECONDS"
    MINUTES = "MINUTES"
    HOURS = "HOURS"


class Type(StrEnum):
    boolean = "boolean"
    integer = "integer"
    double = "double"
    string = "string"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class DataAlreadyAcceptedException(ServiceException):
    code: str = "DataAlreadyAcceptedException"
    sender_fault: bool = False
    status_code: int = 400
    expectedSequenceToken: SequenceToken | None


class InternalServerException(ServiceException):
    code: str = "InternalServerException"
    sender_fault: bool = False
    status_code: int = 400


class InternalStreamingException(ServiceException):
    code: str = "InternalStreamingException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidOperationException(ServiceException):
    code: str = "InvalidOperationException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSequenceTokenException(ServiceException):
    code: str = "InvalidSequenceTokenException"
    sender_fault: bool = False
    status_code: int = 400
    expectedSequenceToken: SequenceToken | None


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class QueryCompileErrorLocation(TypedDict, total=False):
    startCharOffset: QueryCharOffset | None
    endCharOffset: QueryCharOffset | None


class QueryCompileError(TypedDict, total=False):
    location: QueryCompileErrorLocation | None
    message: Message | None


class MalformedQueryException(ServiceException):
    code: str = "MalformedQueryException"
    sender_fault: bool = False
    status_code: int = 400
    queryCompileError: QueryCompileError | None


class OperationAbortedException(ServiceException):
    code: str = "OperationAbortedException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceAlreadyExistsException(ServiceException):
    code: str = "ResourceAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class SessionStreamingException(ServiceException):
    code: str = "SessionStreamingException"
    sender_fault: bool = False
    status_code: int = 400


class SessionTimeoutException(ServiceException):
    code: str = "SessionTimeoutException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400
    resourceName: AmazonResourceName | None


class UnrecognizedClientException(ServiceException):
    code: str = "UnrecognizedClientException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


AccountIds = list[AccountId]
Timestamp = int


class AccountPolicy(TypedDict, total=False):
    policyName: PolicyName | None
    policyDocument: AccountPolicyDocument | None
    lastUpdatedTime: Timestamp | None
    policyType: PolicyType | None
    scope: Scope | None
    selectionCriteria: SelectionCriteria | None
    accountId: AccountId | None


AccountPolicies = list[AccountPolicy]


class AddKeyEntry(TypedDict, total=False):
    key: Key
    value: AddKeyValue
    overwriteIfExists: OverwriteIfExists | None


AddKeyEntries = list[AddKeyEntry]


class AddKeys(TypedDict, total=False):
    entries: AddKeyEntries


class GroupingIdentifier(TypedDict, total=False):
    key: GroupingIdentifierKey | None
    value: GroupingIdentifierValue | None


GroupingIdentifiers = list[GroupingIdentifier]


class AggregateLogGroupSummary(TypedDict, total=False):
    logGroupCount: LogGroupCount | None
    groupingIdentifiers: GroupingIdentifiers | None


AggregateLogGroupSummaries = list[AggregateLogGroupSummary]
AllowedFieldDelimiters = list[FieldDelimiter]


class RecordField(TypedDict, total=False):
    name: FieldHeader | None
    mandatory: Boolean | None


AllowedFields = list[RecordField]
EpochMillis = int
LogGroupArnList = list[LogGroupArn]
TokenValue = int
Enumerations = dict[TokenString, TokenValue]


class PatternToken(TypedDict, total=False):
    dynamicTokenPosition: DynamicTokenPosition | None
    isDynamic: Boolean | None
    tokenString: TokenString | None
    enumerations: Enumerations | None
    inferredTokenName: InferredTokenName | None


PatternTokens = list[PatternToken]


class LogEvent(TypedDict, total=False):
    timestamp: Timestamp | None
    message: EventMessage | None


LogSamples = list[LogEvent]
Count = int
Histogram = dict[Time, Count]


class Anomaly(TypedDict, total=False):
    anomalyId: AnomalyId
    patternId: PatternId
    anomalyDetectorArn: AnomalyDetectorArn
    patternString: PatternString
    patternRegex: PatternRegex | None
    priority: Priority | None
    firstSeen: EpochMillis
    lastSeen: EpochMillis
    description: Description
    active: Boolean
    state: State
    histogram: Histogram
    logSamples: LogSamples
    patternTokens: PatternTokens
    logGroupArnList: LogGroupArnList
    suppressed: Boolean | None
    suppressedDate: EpochMillis | None
    suppressedUntil: EpochMillis | None
    isPatternLevelSuppression: Boolean | None


Anomalies = list[Anomaly]
AnomalyVisibilityTime = int


class AnomalyDetector(TypedDict, total=False):
    anomalyDetectorArn: AnomalyDetectorArn | None
    detectorName: DetectorName | None
    logGroupArnList: LogGroupArnList | None
    evaluationFrequency: EvaluationFrequency | None
    filterPattern: FilterPattern | None
    anomalyDetectorStatus: AnomalyDetectorStatus | None
    kmsKeyId: KmsKeyId | None
    creationTimeStamp: EpochMillis | None
    lastModifiedTimeStamp: EpochMillis | None
    anomalyVisibilityTime: AnomalyVisibilityTime | None


AnomalyDetectors = list[AnomalyDetector]


class AssociateKmsKeyRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    kmsKeyId: KmsKeyId
    resourceIdentifier: ResourceIdentifier | None


class DataSource(TypedDict, total=False):
    name: DataSourceName
    type: DataSourceType | None


class AssociateSourceToS3TableIntegrationRequest(ServiceRequest):
    integrationArn: Arn
    dataSource: DataSource


class AssociateSourceToS3TableIntegrationResponse(TypedDict, total=False):
    identifier: S3TableIntegrationSourceIdentifier | None


Columns = list[Column]


class CSV(TypedDict, total=False):
    quoteCharacter: QuoteCharacter | None
    delimiter: Delimiter | None
    columns: Columns | None
    source: Source | None


class CancelExportTaskRequest(ServiceRequest):
    taskId: ExportTaskId


class CancelImportTaskRequest(ServiceRequest):
    importId: ImportId


StoredBytes = int


class ImportStatistics(TypedDict, total=False):
    bytesImported: StoredBytes | None


class CancelImportTaskResponse(TypedDict, total=False):
    importId: ImportId | None
    importStatistics: ImportStatistics | None
    importStatus: ImportStatus | None
    creationTime: Timestamp | None
    lastUpdatedTime: Timestamp | None


RecordFields = list[FieldHeader]
OutputFormats = list[OutputFormat]


class S3DeliveryConfiguration(TypedDict, total=False):
    suffixPath: DeliverySuffixPath | None
    enableHiveCompatiblePath: Boolean | None


class ConfigurationTemplateDeliveryConfigValues(TypedDict, total=False):
    recordFields: RecordFields | None
    fieldDelimiter: FieldDelimiter | None
    s3DeliveryConfiguration: S3DeliveryConfiguration | None


class ConfigurationTemplate(TypedDict, total=False):
    service: Service | None
    logType: LogType | None
    resourceType: ResourceType | None
    deliveryDestinationType: DeliveryDestinationType | None
    defaultDeliveryConfigValues: ConfigurationTemplateDeliveryConfigValues | None
    allowedFields: AllowedFields | None
    allowedOutputFormats: OutputFormats | None
    allowedActionForAllowVendedLogsDeliveryForResource: (
        AllowedActionForAllowVendedLogsDeliveryForResource | None
    )
    allowedFieldDelimiters: AllowedFieldDelimiters | None
    allowedSuffixPathFields: RecordFields | None


ConfigurationTemplates = list[ConfigurationTemplate]


class CopyValueEntry(TypedDict, total=False):
    source: Source
    target: Target
    overwriteIfExists: OverwriteIfExists | None


CopyValueEntries = list[CopyValueEntry]


class CopyValue(TypedDict, total=False):
    entries: CopyValueEntries


Tags = dict[TagKey, TagValue]


class CreateDeliveryRequest(ServiceRequest):
    deliverySourceName: DeliverySourceName
    deliveryDestinationArn: Arn
    recordFields: RecordFields | None
    fieldDelimiter: FieldDelimiter | None
    s3DeliveryConfiguration: S3DeliveryConfiguration | None
    tags: Tags | None


class Delivery(TypedDict, total=False):
    id: DeliveryId | None
    arn: Arn | None
    deliverySourceName: DeliverySourceName | None
    deliveryDestinationArn: Arn | None
    deliveryDestinationType: DeliveryDestinationType | None
    recordFields: RecordFields | None
    fieldDelimiter: FieldDelimiter | None
    s3DeliveryConfiguration: S3DeliveryConfiguration | None
    tags: Tags | None


class CreateDeliveryResponse(TypedDict, total=False):
    delivery: Delivery | None


CreateExportTaskRequest = TypedDict(
    "CreateExportTaskRequest",
    {
        "taskName": ExportTaskName | None,
        "logGroupName": LogGroupName,
        "logStreamNamePrefix": LogStreamName | None,
        "from": Timestamp,
        "to": Timestamp,
        "destination": ExportDestinationBucket,
        "destinationPrefix": ExportDestinationPrefix | None,
    },
    total=False,
)


class CreateExportTaskResponse(TypedDict, total=False):
    taskId: ExportTaskId | None


class ImportFilter(TypedDict, total=False):
    startEventTime: Timestamp | None
    endEventTime: Timestamp | None


class CreateImportTaskRequest(ServiceRequest):
    importSourceArn: Arn
    importRoleArn: RoleArn
    importFilter: ImportFilter | None


class CreateImportTaskResponse(TypedDict, total=False):
    importId: ImportId | None
    importDestinationArn: Arn | None
    creationTime: Timestamp | None


class CreateLogAnomalyDetectorRequest(ServiceRequest):
    logGroupArnList: LogGroupArnList
    detectorName: DetectorName | None
    evaluationFrequency: EvaluationFrequency | None
    filterPattern: FilterPattern | None
    kmsKeyId: DetectorKmsKeyArn | None
    anomalyVisibilityTime: AnomalyVisibilityTime | None
    tags: Tags | None


class CreateLogAnomalyDetectorResponse(TypedDict, total=False):
    anomalyDetectorArn: AnomalyDetectorArn | None


class CreateLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    kmsKeyId: KmsKeyId | None
    tags: Tags | None
    logGroupClass: LogGroupClass | None
    deletionProtectionEnabled: DeletionProtectionEnabled | None


class CreateLogStreamRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName


class S3Configuration(TypedDict, total=False):
    destinationIdentifier: S3Uri
    roleArn: RoleArn


class DestinationConfiguration(TypedDict, total=False):
    s3Configuration: S3Configuration


StartTimeOffset = int
ScheduledQueryLogGroupIdentifiers = list[LogGroupIdentifier]


class CreateScheduledQueryRequest(ServiceRequest):
    name: ScheduledQueryName
    description: ScheduledQueryDescription | None
    queryLanguage: QueryLanguage
    queryString: QueryString
    logGroupIdentifiers: ScheduledQueryLogGroupIdentifiers | None
    scheduleExpression: ScheduleExpression
    timezone: ScheduleTimezone | None
    startTimeOffset: StartTimeOffset | None
    destinationConfiguration: DestinationConfiguration | None
    scheduleStartTime: Timestamp | None
    scheduleEndTime: Timestamp | None
    executionRoleArn: RoleArn
    state: ScheduledQueryState | None
    tags: Tags | None


class CreateScheduledQueryResponse(TypedDict, total=False):
    scheduledQueryArn: Arn | None
    state: ScheduledQueryState | None


DashboardViewerPrincipals = list[Arn]
Data = bytes


class DataSourceFilter(TypedDict, total=False):
    name: DataSourceName
    type: DataSourceType | None


DataSourceFilters = list[DataSourceFilter]
MatchPatterns = list[MatchPattern]


class DateTimeConverter(TypedDict, total=False):
    source: Source
    target: Target
    targetFormat: TargetFormat | None
    matchPatterns: MatchPatterns
    sourceTimezone: SourceTimezone | None
    targetTimezone: TargetTimezone | None
    locale: Locale | None


class DeleteAccountPolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyType: PolicyType


class DeleteDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class DeleteDeliveryDestinationPolicyRequest(ServiceRequest):
    deliveryDestinationName: DeliveryDestinationName


class DeleteDeliveryDestinationRequest(ServiceRequest):
    name: DeliveryDestinationName


class DeleteDeliveryRequest(ServiceRequest):
    id: DeliveryId


class DeleteDeliverySourceRequest(ServiceRequest):
    name: DeliverySourceName


class DeleteDestinationRequest(ServiceRequest):
    destinationName: DestinationName


class DeleteIndexPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class DeleteIndexPolicyResponse(TypedDict, total=False):
    pass


class DeleteIntegrationRequest(ServiceRequest):
    integrationName: IntegrationName
    force: Force | None


class DeleteIntegrationResponse(TypedDict, total=False):
    pass


DeleteWithKeys = list[WithKey]


class DeleteKeys(TypedDict, total=False):
    withKeys: DeleteWithKeys


class DeleteLogAnomalyDetectorRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn


class DeleteLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName


class DeleteLogStreamRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName


class DeleteMetricFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName


class DeleteQueryDefinitionRequest(ServiceRequest):
    queryDefinitionId: QueryId


class DeleteQueryDefinitionResponse(TypedDict, total=False):
    success: Success | None


class DeleteResourcePolicyRequest(ServiceRequest):
    policyName: PolicyName | None
    resourceArn: Arn | None
    expectedRevisionId: ExpectedRevisionId | None


class DeleteRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName


class DeleteScheduledQueryRequest(ServiceRequest):
    identifier: ScheduledQueryIdentifier


class DeleteScheduledQueryResponse(TypedDict, total=False):
    pass


class DeleteSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName


class DeleteTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


Deliveries = list[Delivery]


class DeliveryDestinationConfiguration(TypedDict, total=False):
    destinationResourceArn: Arn


class DeliveryDestination(TypedDict, total=False):
    name: DeliveryDestinationName | None
    arn: Arn | None
    deliveryDestinationType: DeliveryDestinationType | None
    outputFormat: OutputFormat | None
    deliveryDestinationConfiguration: DeliveryDestinationConfiguration | None
    tags: Tags | None


DeliveryDestinationTypes = list[DeliveryDestinationType]
DeliveryDestinations = list[DeliveryDestination]
ResourceArns = list[Arn]


class DeliverySource(TypedDict, total=False):
    name: DeliverySourceName | None
    arn: Arn | None
    resourceArns: ResourceArns | None
    service: Service | None
    logType: LogType | None
    tags: Tags | None


DeliverySources = list[DeliverySource]


class DescribeAccountPoliciesRequest(ServiceRequest):
    policyType: PolicyType
    policyName: PolicyName | None
    accountIdentifiers: AccountIds | None
    nextToken: NextToken | None


class DescribeAccountPoliciesResponse(TypedDict, total=False):
    accountPolicies: AccountPolicies | None
    nextToken: NextToken | None


ResourceTypes = list[ResourceType]
LogTypes = list[LogType]


class DescribeConfigurationTemplatesRequest(ServiceRequest):
    service: Service | None
    logTypes: LogTypes | None
    resourceTypes: ResourceTypes | None
    deliveryDestinationTypes: DeliveryDestinationTypes | None
    nextToken: NextToken | None
    limit: DescribeLimit | None


class DescribeConfigurationTemplatesResponse(TypedDict, total=False):
    configurationTemplates: ConfigurationTemplates | None
    nextToken: NextToken | None


class DescribeDeliveriesRequest(ServiceRequest):
    nextToken: NextToken | None
    limit: DescribeLimit | None


class DescribeDeliveriesResponse(TypedDict, total=False):
    deliveries: Deliveries | None
    nextToken: NextToken | None


class DescribeDeliveryDestinationsRequest(ServiceRequest):
    nextToken: NextToken | None
    limit: DescribeLimit | None


class DescribeDeliveryDestinationsResponse(TypedDict, total=False):
    deliveryDestinations: DeliveryDestinations | None
    nextToken: NextToken | None


class DescribeDeliverySourcesRequest(ServiceRequest):
    nextToken: NextToken | None
    limit: DescribeLimit | None


class DescribeDeliverySourcesResponse(TypedDict, total=False):
    deliverySources: DeliverySources | None
    nextToken: NextToken | None


class DescribeDestinationsRequest(ServiceRequest):
    DestinationNamePrefix: DestinationName | None
    nextToken: NextToken | None
    limit: DescribeLimit | None


class Destination(TypedDict, total=False):
    destinationName: DestinationName | None
    targetArn: TargetArn | None
    roleArn: RoleArn | None
    accessPolicy: AccessPolicy | None
    arn: Arn | None
    creationTime: Timestamp | None


Destinations = list[Destination]


class DescribeDestinationsResponse(TypedDict, total=False):
    destinations: Destinations | None
    nextToken: NextToken | None


class DescribeExportTasksRequest(ServiceRequest):
    taskId: ExportTaskId | None
    statusCode: ExportTaskStatusCode | None
    nextToken: NextToken | None
    limit: DescribeLimit | None


class ExportTaskExecutionInfo(TypedDict, total=False):
    creationTime: Timestamp | None
    completionTime: Timestamp | None


class ExportTaskStatus(TypedDict, total=False):
    code: ExportTaskStatusCode | None
    message: ExportTaskStatusMessage | None


ExportTask = TypedDict(
    "ExportTask",
    {
        "taskId": ExportTaskId | None,
        "taskName": ExportTaskName | None,
        "logGroupName": LogGroupName | None,
        "from": Timestamp | None,
        "to": Timestamp | None,
        "destination": ExportDestinationBucket | None,
        "destinationPrefix": ExportDestinationPrefix | None,
        "status": ExportTaskStatus | None,
        "executionInfo": ExportTaskExecutionInfo | None,
    },
    total=False,
)
ExportTasks = list[ExportTask]


class DescribeExportTasksResponse(TypedDict, total=False):
    exportTasks: ExportTasks | None
    nextToken: NextToken | None


DescribeFieldIndexesLogGroupIdentifiers = list[LogGroupIdentifier]


class DescribeFieldIndexesRequest(ServiceRequest):
    logGroupIdentifiers: DescribeFieldIndexesLogGroupIdentifiers
    nextToken: NextToken | None


class FieldIndex(TypedDict, total=False):
    logGroupIdentifier: LogGroupIdentifier | None
    fieldIndexName: FieldIndexName | None
    lastScanTime: Timestamp | None
    firstEventTime: Timestamp | None
    lastEventTime: Timestamp | None
    type: IndexType | None


FieldIndexes = list[FieldIndex]


class DescribeFieldIndexesResponse(TypedDict, total=False):
    fieldIndexes: FieldIndexes | None
    nextToken: NextToken | None


ImportStatusList = list[ImportStatus]


class DescribeImportTaskBatchesRequest(ServiceRequest):
    importId: ImportId
    batchImportStatus: ImportStatusList | None
    limit: DescribeLimit | None
    nextToken: NextToken | None


class ImportBatch(TypedDict, total=False):
    batchId: BatchId
    status: ImportStatus
    errorMessage: ErrorMessage | None


ImportBatchList = list[ImportBatch]


class DescribeImportTaskBatchesResponse(TypedDict, total=False):
    importSourceArn: Arn | None
    importId: ImportId | None
    importBatches: ImportBatchList | None
    nextToken: NextToken | None


class DescribeImportTasksRequest(ServiceRequest):
    importId: ImportId | None
    importStatus: ImportStatus | None
    importSourceArn: Arn | None
    limit: DescribeLimit | None
    nextToken: NextToken | None


class Import(TypedDict, total=False):
    importId: ImportId | None
    importSourceArn: Arn | None
    importStatus: ImportStatus | None
    importDestinationArn: Arn | None
    importStatistics: ImportStatistics | None
    importFilter: ImportFilter | None
    creationTime: Timestamp | None
    lastUpdatedTime: Timestamp | None
    errorMessage: ErrorMessage | None


ImportList = list[Import]


class DescribeImportTasksResponse(TypedDict, total=False):
    imports: ImportList | None
    nextToken: NextToken | None


DescribeIndexPoliciesLogGroupIdentifiers = list[LogGroupIdentifier]


class DescribeIndexPoliciesRequest(ServiceRequest):
    logGroupIdentifiers: DescribeIndexPoliciesLogGroupIdentifiers
    nextToken: NextToken | None


class IndexPolicy(TypedDict, total=False):
    logGroupIdentifier: LogGroupIdentifier | None
    lastUpdateTime: Timestamp | None
    policyDocument: PolicyDocument | None
    policyName: PolicyName | None
    source: IndexSource | None


IndexPolicies = list[IndexPolicy]


class DescribeIndexPoliciesResponse(TypedDict, total=False):
    indexPolicies: IndexPolicies | None
    nextToken: NextToken | None


DescribeLogGroupsLogGroupIdentifiers = list[LogGroupIdentifier]


class DescribeLogGroupsRequest(ServiceRequest):
    accountIdentifiers: AccountIds | None
    logGroupNamePrefix: LogGroupName | None
    logGroupNamePattern: LogGroupNamePattern | None
    nextToken: NextToken | None
    limit: DescribeLimit | None
    includeLinkedAccounts: IncludeLinkedAccounts | None
    logGroupClass: LogGroupClass | None
    logGroupIdentifiers: DescribeLogGroupsLogGroupIdentifiers | None


InheritedProperties = list[InheritedProperty]


class LogGroup(TypedDict, total=False):
    logGroupName: LogGroupName | None
    creationTime: Timestamp | None
    retentionInDays: Days | None
    metricFilterCount: FilterCount | None
    arn: Arn | None
    storedBytes: StoredBytes | None
    kmsKeyId: KmsKeyId | None
    dataProtectionStatus: DataProtectionStatus | None
    inheritedProperties: InheritedProperties | None
    logGroupClass: LogGroupClass | None
    logGroupArn: Arn | None
    deletionProtectionEnabled: DeletionProtectionEnabled | None


LogGroups = list[LogGroup]


class DescribeLogGroupsResponse(TypedDict, total=False):
    logGroups: LogGroups | None
    nextToken: NextToken | None


class DescribeLogStreamsRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    logGroupIdentifier: LogGroupIdentifier | None
    logStreamNamePrefix: LogStreamName | None
    orderBy: OrderBy | None
    descending: Descending | None
    nextToken: NextToken | None
    limit: DescribeLimit | None


class LogStream(TypedDict, total=False):
    logStreamName: LogStreamName | None
    creationTime: Timestamp | None
    firstEventTimestamp: Timestamp | None
    lastEventTimestamp: Timestamp | None
    lastIngestionTime: Timestamp | None
    uploadSequenceToken: SequenceToken | None
    arn: Arn | None
    storedBytes: StoredBytes | None


LogStreams = list[LogStream]


class DescribeLogStreamsResponse(TypedDict, total=False):
    logStreams: LogStreams | None
    nextToken: NextToken | None


class DescribeMetricFiltersRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    filterNamePrefix: FilterName | None
    nextToken: NextToken | None
    limit: DescribeLimit | None
    metricName: MetricName | None
    metricNamespace: MetricNamespace | None


EmitSystemFields = list[SystemField]
Dimensions = dict[DimensionsKey, DimensionsValue]


class MetricTransformation(TypedDict, total=False):
    metricName: MetricName
    metricNamespace: MetricNamespace
    metricValue: MetricValue
    defaultValue: DefaultValue | None
    dimensions: Dimensions | None
    unit: StandardUnit | None


MetricTransformations = list[MetricTransformation]


class MetricFilter(TypedDict, total=False):
    filterName: FilterName | None
    filterPattern: FilterPattern | None
    metricTransformations: MetricTransformations | None
    creationTime: Timestamp | None
    logGroupName: LogGroupName | None
    applyOnTransformedLogs: ApplyOnTransformedLogs | None
    fieldSelectionCriteria: FieldSelectionCriteria | None
    emitSystemFieldDimensions: EmitSystemFields | None


MetricFilters = list[MetricFilter]


class DescribeMetricFiltersResponse(TypedDict, total=False):
    metricFilters: MetricFilters | None
    nextToken: NextToken | None


class DescribeQueriesRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    status: QueryStatus | None
    maxResults: DescribeQueriesMaxResults | None
    nextToken: NextToken | None
    queryLanguage: QueryLanguage | None


class QueryInfo(TypedDict, total=False):
    queryLanguage: QueryLanguage | None
    queryId: QueryId | None
    queryString: QueryString | None
    status: QueryStatus | None
    createTime: Timestamp | None
    logGroupName: LogGroupName | None


QueryInfoList = list[QueryInfo]


class DescribeQueriesResponse(TypedDict, total=False):
    queries: QueryInfoList | None
    nextToken: NextToken | None


class DescribeQueryDefinitionsRequest(ServiceRequest):
    queryLanguage: QueryLanguage | None
    queryDefinitionNamePrefix: QueryDefinitionName | None
    maxResults: QueryListMaxResults | None
    nextToken: NextToken | None


LogGroupNames = list[LogGroupName]


class QueryDefinition(TypedDict, total=False):
    queryLanguage: QueryLanguage | None
    queryDefinitionId: QueryId | None
    name: QueryDefinitionName | None
    queryString: QueryDefinitionString | None
    lastModified: Timestamp | None
    logGroupNames: LogGroupNames | None


QueryDefinitionList = list[QueryDefinition]


class DescribeQueryDefinitionsResponse(TypedDict, total=False):
    queryDefinitions: QueryDefinitionList | None
    nextToken: NextToken | None


class DescribeResourcePoliciesRequest(ServiceRequest):
    nextToken: NextToken | None
    limit: DescribeLimit | None
    resourceArn: Arn | None
    policyScope: PolicyScope | None


class ResourcePolicy(TypedDict, total=False):
    policyName: PolicyName | None
    policyDocument: PolicyDocument | None
    lastUpdatedTime: Timestamp | None
    policyScope: PolicyScope | None
    resourceArn: Arn | None
    revisionId: ExpectedRevisionId | None


ResourcePolicies = list[ResourcePolicy]


class DescribeResourcePoliciesResponse(TypedDict, total=False):
    resourcePolicies: ResourcePolicies | None
    nextToken: NextToken | None


class DescribeSubscriptionFiltersRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterNamePrefix: FilterName | None
    nextToken: NextToken | None
    limit: DescribeLimit | None


class SubscriptionFilter(TypedDict, total=False):
    filterName: FilterName | None
    logGroupName: LogGroupName | None
    filterPattern: FilterPattern | None
    destinationArn: DestinationArn | None
    roleArn: RoleArn | None
    distribution: Distribution | None
    applyOnTransformedLogs: ApplyOnTransformedLogs | None
    creationTime: Timestamp | None
    fieldSelectionCriteria: FieldSelectionCriteria | None
    emitSystemFields: EmitSystemFields | None


SubscriptionFilters = list[SubscriptionFilter]


class DescribeSubscriptionFiltersResponse(TypedDict, total=False):
    subscriptionFilters: SubscriptionFilters | None
    nextToken: NextToken | None


class DisassociateKmsKeyRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    resourceIdentifier: ResourceIdentifier | None


class DisassociateSourceFromS3TableIntegrationRequest(ServiceRequest):
    identifier: S3TableIntegrationSourceIdentifier


class DisassociateSourceFromS3TableIntegrationResponse(TypedDict, total=False):
    identifier: S3TableIntegrationSourceIdentifier | None


EntityAttributes = dict[EntityAttributesKey, EntityAttributesValue]
EntityKeyAttributes = dict[EntityKeyAttributesKey, EntityKeyAttributesValue]


class Entity(TypedDict, total=False):
    keyAttributes: EntityKeyAttributes | None
    attributes: EntityAttributes | None


EventNumber = int
ExecutionStatusList = list[ExecutionStatus]
ExtractedValues = dict[Token, Value]
FieldIndexNames = list[FieldIndexName]


class FieldsData(TypedDict, total=False):
    data: Data | None


InputLogStreamNames = list[LogStreamName]


class FilterLogEventsRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    logGroupIdentifier: LogGroupIdentifier | None
    logStreamNames: InputLogStreamNames | None
    logStreamNamePrefix: LogStreamName | None
    startTime: Timestamp | None
    endTime: Timestamp | None
    filterPattern: FilterPattern | None
    nextToken: NextToken | None
    limit: EventsLimit | None
    interleaved: Interleaved | None
    unmask: Unmask | None


class SearchedLogStream(TypedDict, total=False):
    logStreamName: LogStreamName | None
    searchedCompletely: LogStreamSearchedCompletely | None


SearchedLogStreams = list[SearchedLogStream]


class FilteredLogEvent(TypedDict, total=False):
    logStreamName: LogStreamName | None
    timestamp: Timestamp | None
    message: EventMessage | None
    ingestionTime: Timestamp | None
    eventId: EventId | None


FilteredLogEvents = list[FilteredLogEvent]


class FilterLogEventsResponse(TypedDict, total=False):
    events: FilteredLogEvents | None
    searchedLogStreams: SearchedLogStreams | None
    nextToken: NextToken | None


class GetDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class GetDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: LogGroupIdentifier | None
    policyDocument: DataProtectionPolicyDocument | None
    lastUpdatedTime: Timestamp | None


class GetDeliveryDestinationPolicyRequest(ServiceRequest):
    deliveryDestinationName: DeliveryDestinationName


class Policy(TypedDict, total=False):
    deliveryDestinationPolicy: DeliveryDestinationPolicy | None


class GetDeliveryDestinationPolicyResponse(TypedDict, total=False):
    policy: Policy | None


class GetDeliveryDestinationRequest(ServiceRequest):
    name: DeliveryDestinationName


class GetDeliveryDestinationResponse(TypedDict, total=False):
    deliveryDestination: DeliveryDestination | None


class GetDeliveryRequest(ServiceRequest):
    id: DeliveryId


class GetDeliveryResponse(TypedDict, total=False):
    delivery: Delivery | None


class GetDeliverySourceRequest(ServiceRequest):
    name: DeliverySourceName


class GetDeliverySourceResponse(TypedDict, total=False):
    deliverySource: DeliverySource | None


class GetIntegrationRequest(ServiceRequest):
    integrationName: IntegrationName


class OpenSearchResourceStatus(TypedDict, total=False):
    status: OpenSearchResourceStatusType | None
    statusMessage: IntegrationStatusMessage | None


class OpenSearchLifecyclePolicy(TypedDict, total=False):
    policyName: OpenSearchPolicyName | None
    status: OpenSearchResourceStatus | None


class OpenSearchDataAccessPolicy(TypedDict, total=False):
    policyName: OpenSearchPolicyName | None
    status: OpenSearchResourceStatus | None


class OpenSearchNetworkPolicy(TypedDict, total=False):
    policyName: OpenSearchPolicyName | None
    status: OpenSearchResourceStatus | None


class OpenSearchEncryptionPolicy(TypedDict, total=False):
    policyName: OpenSearchPolicyName | None
    status: OpenSearchResourceStatus | None


class OpenSearchWorkspace(TypedDict, total=False):
    workspaceId: OpenSearchWorkspaceId | None
    status: OpenSearchResourceStatus | None


class OpenSearchCollection(TypedDict, total=False):
    collectionEndpoint: OpenSearchCollectionEndpoint | None
    collectionArn: Arn | None
    status: OpenSearchResourceStatus | None


class OpenSearchApplication(TypedDict, total=False):
    applicationEndpoint: OpenSearchApplicationEndpoint | None
    applicationArn: Arn | None
    applicationId: OpenSearchApplicationId | None
    status: OpenSearchResourceStatus | None


class OpenSearchDataSource(TypedDict, total=False):
    dataSourceName: OpenSearchDataSourceName | None
    status: OpenSearchResourceStatus | None


class OpenSearchIntegrationDetails(TypedDict, total=False):
    dataSource: OpenSearchDataSource | None
    application: OpenSearchApplication | None
    collection: OpenSearchCollection | None
    workspace: OpenSearchWorkspace | None
    encryptionPolicy: OpenSearchEncryptionPolicy | None
    networkPolicy: OpenSearchNetworkPolicy | None
    accessPolicy: OpenSearchDataAccessPolicy | None
    lifecyclePolicy: OpenSearchLifecyclePolicy | None


class IntegrationDetails(TypedDict, total=False):
    openSearchIntegrationDetails: OpenSearchIntegrationDetails | None


class GetIntegrationResponse(TypedDict, total=False):
    integrationName: IntegrationName | None
    integrationType: IntegrationType | None
    integrationStatus: IntegrationStatus | None
    integrationDetails: IntegrationDetails | None


class GetLogAnomalyDetectorRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn


class GetLogAnomalyDetectorResponse(TypedDict, total=False):
    detectorName: DetectorName | None
    logGroupArnList: LogGroupArnList | None
    evaluationFrequency: EvaluationFrequency | None
    filterPattern: FilterPattern | None
    anomalyDetectorStatus: AnomalyDetectorStatus | None
    kmsKeyId: KmsKeyId | None
    creationTimeStamp: EpochMillis | None
    lastModifiedTimeStamp: EpochMillis | None
    anomalyVisibilityTime: AnomalyVisibilityTime | None


class GetLogEventsRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    logGroupIdentifier: LogGroupIdentifier | None
    logStreamName: LogStreamName
    startTime: Timestamp | None
    endTime: Timestamp | None
    nextToken: NextToken | None
    limit: EventsLimit | None
    startFromHead: StartFromHead | None
    unmask: Unmask | None


class OutputLogEvent(TypedDict, total=False):
    timestamp: Timestamp | None
    message: EventMessage | None
    ingestionTime: Timestamp | None


OutputLogEvents = list[OutputLogEvent]


class GetLogEventsResponse(TypedDict, total=False):
    events: OutputLogEvents | None
    nextForwardToken: NextToken | None
    nextBackwardToken: NextToken | None


class GetLogFieldsRequest(ServiceRequest):
    dataSourceName: DataSourceName
    dataSourceType: DataSourceType


LogFieldsList = list["LogFieldsListItem"]


class LogFieldType(TypedDict, total=False):
    type: "DataType | None"
    element: "LogFieldType | None"
    fields: "LogFieldsList | None"


class LogFieldsListItem(TypedDict, total=False):
    logFieldName: LogFieldName | None
    logFieldType: LogFieldType | None


class GetLogFieldsResponse(TypedDict, total=False):
    logFields: LogFieldsList | None


class GetLogGroupFieldsRequest(ServiceRequest):
    logGroupName: LogGroupName | None
    time: Timestamp | None
    logGroupIdentifier: LogGroupIdentifier | None


class LogGroupField(TypedDict, total=False):
    name: Field | None
    percent: Percentage | None


LogGroupFieldList = list[LogGroupField]


class GetLogGroupFieldsResponse(TypedDict, total=False):
    logGroupFields: LogGroupFieldList | None


class GetLogObjectRequest(ServiceRequest):
    unmask: Unmask | None
    logObjectPointer: LogObjectPointer


class GetLogObjectResponseStream(TypedDict, total=False):
    fields: FieldsData | None
    InternalStreamingException: InternalStreamingException | None


class GetLogObjectResponse(TypedDict, total=False):
    fieldStream: Iterator[GetLogObjectResponseStream]


class GetLogRecordRequest(ServiceRequest):
    logRecordPointer: LogRecordPointer
    unmask: Unmask | None


LogRecord = dict[Field, Value]


class GetLogRecordResponse(TypedDict, total=False):
    logRecord: LogRecord | None


class GetQueryResultsRequest(ServiceRequest):
    queryId: QueryId


class QueryStatistics(TypedDict, total=False):
    recordsMatched: StatsValue | None
    recordsScanned: StatsValue | None
    estimatedRecordsSkipped: StatsValue | None
    bytesScanned: StatsValue | None
    estimatedBytesSkipped: StatsValue | None
    logGroupsScanned: StatsValue | None


class ResultField(TypedDict, total=False):
    field: Field | None
    value: Value | None


ResultRows = list[ResultField]
QueryResults = list[ResultRows]


class GetQueryResultsResponse(TypedDict, total=False):
    queryLanguage: QueryLanguage | None
    results: QueryResults | None
    statistics: QueryStatistics | None
    status: QueryStatus | None
    encryptionKey: EncryptionKey | None


class GetScheduledQueryHistoryRequest(ServiceRequest):
    identifier: ScheduledQueryIdentifier
    startTime: Timestamp
    endTime: Timestamp
    executionStatuses: ExecutionStatusList | None
    maxResults: GetScheduledQueryHistoryMaxResults | None
    nextToken: NextToken | None


class ScheduledQueryDestination(TypedDict, total=False):
    destinationType: ScheduledQueryDestinationType | None
    destinationIdentifier: String | None
    status: ActionStatus | None
    processedIdentifier: String | None
    errorMessage: String | None


ScheduledQueryDestinationList = list[ScheduledQueryDestination]


class TriggerHistoryRecord(TypedDict, total=False):
    queryId: QueryId | None
    executionStatus: ExecutionStatus | None
    triggeredTimestamp: Timestamp | None
    errorMessage: String | None
    destinations: ScheduledQueryDestinationList | None


TriggerHistoryRecordList = list[TriggerHistoryRecord]


class GetScheduledQueryHistoryResponse(TypedDict, total=False):
    name: ScheduledQueryName | None
    scheduledQueryArn: Arn | None
    triggerHistory: TriggerHistoryRecordList | None
    nextToken: NextToken | None


class GetScheduledQueryRequest(ServiceRequest):
    identifier: ScheduledQueryIdentifier


class GetScheduledQueryResponse(TypedDict, total=False):
    scheduledQueryArn: Arn | None
    name: ScheduledQueryName | None
    description: ScheduledQueryDescription | None
    queryLanguage: QueryLanguage | None
    queryString: QueryString | None
    logGroupIdentifiers: ScheduledQueryLogGroupIdentifiers | None
    scheduleExpression: ScheduleExpression | None
    timezone: ScheduleTimezone | None
    startTimeOffset: StartTimeOffset | None
    destinationConfiguration: DestinationConfiguration | None
    state: ScheduledQueryState | None
    lastTriggeredTime: Timestamp | None
    lastExecutionStatus: ExecutionStatus | None
    scheduleStartTime: Timestamp | None
    scheduleEndTime: Timestamp | None
    executionRoleArn: RoleArn | None
    creationTime: Timestamp | None
    lastUpdatedTime: Timestamp | None


class GetTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


UpperCaseStringWithKeys = list[WithKey]


class UpperCaseString(TypedDict, total=False):
    withKeys: UpperCaseStringWithKeys


class TypeConverterEntry(TypedDict, total=False):
    key: Key
    type: Type


TypeConverterEntries = list[TypeConverterEntry]


class TypeConverter(TypedDict, total=False):
    entries: TypeConverterEntries


TrimStringWithKeys = list[WithKey]


class TrimString(TypedDict, total=False):
    withKeys: TrimStringWithKeys


SubstituteStringEntry = TypedDict(
    "SubstituteStringEntry",
    {
        "source": Source,
        "from": FromKey,
        "to": ToKey,
    },
    total=False,
)
SubstituteStringEntries = list[SubstituteStringEntry]


class SubstituteString(TypedDict, total=False):
    entries: SubstituteStringEntries


class SplitStringEntry(TypedDict, total=False):
    source: Source
    delimiter: SplitStringDelimiter


SplitStringEntries = list[SplitStringEntry]


class SplitString(TypedDict, total=False):
    entries: SplitStringEntries


class RenameKeyEntry(TypedDict, total=False):
    key: Key
    renameTo: RenameTo
    overwriteIfExists: OverwriteIfExists | None


RenameKeyEntries = list[RenameKeyEntry]


class RenameKeys(TypedDict, total=False):
    entries: RenameKeyEntries


class ParseWAF(TypedDict, total=False):
    source: Source | None


class ParseVPC(TypedDict, total=False):
    source: Source | None


class ParsePostgres(TypedDict, total=False):
    source: Source | None


class ParseToOCSF(TypedDict, total=False):
    source: Source | None
    eventSource: EventSource
    ocsfVersion: OCSFVersion
    mappingVersion: MappingVersion | None


class ParseRoute53(TypedDict, total=False):
    source: Source | None


class ParseKeyValue(TypedDict, total=False):
    source: Source | None
    destination: DestinationField | None
    fieldDelimiter: ParserFieldDelimiter | None
    keyValueDelimiter: KeyValueDelimiter | None
    keyPrefix: KeyPrefix | None
    nonMatchValue: NonMatchValue | None
    overwriteIfExists: OverwriteIfExists | None


class ParseJSON(TypedDict, total=False):
    source: Source | None
    destination: DestinationField | None


class ParseCloudfront(TypedDict, total=False):
    source: Source | None


class MoveKeyEntry(TypedDict, total=False):
    source: Source
    target: Target
    overwriteIfExists: OverwriteIfExists | None


MoveKeyEntries = list[MoveKeyEntry]


class MoveKeys(TypedDict, total=False):
    entries: MoveKeyEntries


LowerCaseStringWithKeys = list[WithKey]


class LowerCaseString(TypedDict, total=False):
    withKeys: LowerCaseStringWithKeys


class ListToMap(TypedDict, total=False):
    source: Source
    key: Key
    valueKey: ValueKey | None
    target: Target | None
    flatten: Flatten | None
    flattenedElement: FlattenedElement | None


class Grok(TypedDict, total=False):
    source: Source | None
    match: GrokMatch


class Processor(TypedDict, total=False):
    addKeys: AddKeys | None
    copyValue: CopyValue | None
    csv: CSV | None
    dateTimeConverter: DateTimeConverter | None
    deleteKeys: DeleteKeys | None
    grok: Grok | None
    listToMap: ListToMap | None
    lowerCaseString: LowerCaseString | None
    moveKeys: MoveKeys | None
    parseCloudfront: ParseCloudfront | None
    parseJSON: ParseJSON | None
    parseKeyValue: ParseKeyValue | None
    parseRoute53: ParseRoute53 | None
    parseToOCSF: ParseToOCSF | None
    parsePostgres: ParsePostgres | None
    parseVPC: ParseVPC | None
    parseWAF: ParseWAF | None
    renameKeys: RenameKeys | None
    splitString: SplitString | None
    substituteString: SubstituteString | None
    trimString: TrimString | None
    typeConverter: TypeConverter | None
    upperCaseString: UpperCaseString | None


Processors = list[Processor]


class GetTransformerResponse(TypedDict, total=False):
    logGroupIdentifier: LogGroupIdentifier | None
    creationTime: Timestamp | None
    lastModifiedTime: Timestamp | None
    transformerConfig: Processors | None


class InputLogEvent(TypedDict, total=False):
    timestamp: Timestamp
    message: EventMessage


InputLogEvents = list[InputLogEvent]


class IntegrationSummary(TypedDict, total=False):
    integrationName: IntegrationName | None
    integrationType: IntegrationType | None
    integrationStatus: IntegrationStatus | None


IntegrationSummaries = list[IntegrationSummary]


class ListAggregateLogGroupSummariesRequest(ServiceRequest):
    accountIdentifiers: AccountIds | None
    includeLinkedAccounts: IncludeLinkedAccounts | None
    logGroupClass: LogGroupClass | None
    logGroupNamePattern: LogGroupNameRegexPattern | None
    dataSources: DataSourceFilters | None
    groupBy: ListAggregateLogGroupSummariesGroupBy
    nextToken: NextToken | None
    limit: ListLogGroupsRequestLimit | None


class ListAggregateLogGroupSummariesResponse(TypedDict, total=False):
    aggregateLogGroupSummaries: AggregateLogGroupSummaries | None
    nextToken: NextToken | None


class ListAnomaliesRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn | None
    suppressionState: SuppressionState | None
    limit: ListAnomaliesLimit | None
    nextToken: NextToken | None


class ListAnomaliesResponse(TypedDict, total=False):
    anomalies: Anomalies | None
    nextToken: NextToken | None


class ListIntegrationsRequest(ServiceRequest):
    integrationNamePrefix: IntegrationNamePrefix | None
    integrationType: IntegrationType | None
    integrationStatus: IntegrationStatus | None


class ListIntegrationsResponse(TypedDict, total=False):
    integrationSummaries: IntegrationSummaries | None


class ListLogAnomalyDetectorsRequest(ServiceRequest):
    filterLogGroupArn: LogGroupArn | None
    limit: ListLogAnomalyDetectorsLimit | None
    nextToken: NextToken | None


class ListLogAnomalyDetectorsResponse(TypedDict, total=False):
    anomalyDetectors: AnomalyDetectors | None
    nextToken: NextToken | None


class ListLogGroupsForQueryRequest(ServiceRequest):
    queryId: QueryId
    nextToken: NextToken | None
    maxResults: ListLogGroupsForQueryMaxResults | None


LogGroupIdentifiers = list[LogGroupIdentifier]


class ListLogGroupsForQueryResponse(TypedDict, total=False):
    logGroupIdentifiers: LogGroupIdentifiers | None
    nextToken: NextToken | None


class ListLogGroupsRequest(ServiceRequest):
    logGroupNamePattern: LogGroupNameRegexPattern | None
    logGroupClass: LogGroupClass | None
    includeLinkedAccounts: IncludeLinkedAccounts | None
    accountIdentifiers: AccountIds | None
    nextToken: NextToken | None
    limit: ListLimit | None
    dataSources: DataSourceFilters | None
    fieldIndexNames: FieldIndexNames | None


class LogGroupSummary(TypedDict, total=False):
    logGroupName: LogGroupName | None
    logGroupArn: Arn | None
    logGroupClass: LogGroupClass | None


LogGroupSummaries = list[LogGroupSummary]


class ListLogGroupsResponse(TypedDict, total=False):
    logGroups: LogGroupSummaries | None
    nextToken: NextToken | None


class ListScheduledQueriesRequest(ServiceRequest):
    maxResults: ListScheduledQueriesMaxResults | None
    nextToken: NextToken | None
    state: ScheduledQueryState | None


class ScheduledQuerySummary(TypedDict, total=False):
    scheduledQueryArn: Arn | None
    name: ScheduledQueryName | None
    state: ScheduledQueryState | None
    lastTriggeredTime: Timestamp | None
    lastExecutionStatus: ExecutionStatus | None
    scheduleExpression: ScheduleExpression | None
    timezone: ScheduleTimezone | None
    destinationConfiguration: DestinationConfiguration | None
    creationTime: Timestamp | None
    lastUpdatedTime: Timestamp | None


ScheduledQuerySummaryList = list[ScheduledQuerySummary]


class ListScheduledQueriesResponse(TypedDict, total=False):
    nextToken: NextToken | None
    scheduledQueries: ScheduledQuerySummaryList | None


class ListSourcesForS3TableIntegrationRequest(ServiceRequest):
    integrationArn: Arn
    maxResults: ListSourcesForS3TableIntegrationMaxResults | None
    nextToken: NextToken | None


class S3TableIntegrationSource(TypedDict, total=False):
    identifier: S3TableIntegrationSourceIdentifier | None
    dataSource: DataSource | None
    status: S3TableIntegrationSourceStatus | None
    statusReason: S3TableIntegrationSourceStatusReason | None
    createdTimeStamp: Timestamp | None


S3TableIntegrationSources = list[S3TableIntegrationSource]


class ListSourcesForS3TableIntegrationResponse(TypedDict, total=False):
    sources: S3TableIntegrationSources | None
    nextToken: NextToken | None


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Tags | None


class ListTagsLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName


class ListTagsLogGroupResponse(TypedDict, total=False):
    tags: Tags | None


class LiveTailSessionLogEvent(TypedDict, total=False):
    logStreamName: LogStreamName | None
    logGroupIdentifier: LogGroupIdentifier | None
    message: EventMessage | None
    timestamp: Timestamp | None
    ingestionTime: Timestamp | None


class LiveTailSessionMetadata(TypedDict, total=False):
    sampled: IsSampled | None


LiveTailSessionResults = list[LiveTailSessionLogEvent]
StartLiveTailLogGroupIdentifiers = list[LogGroupIdentifier]


class LiveTailSessionStart(TypedDict, total=False):
    requestId: RequestId | None
    sessionId: SessionId | None
    logGroupIdentifiers: StartLiveTailLogGroupIdentifiers | None
    logStreamNames: InputLogStreamNames | None
    logStreamNamePrefixes: InputLogStreamNames | None
    logEventFilterPattern: FilterPattern | None


class LiveTailSessionUpdate(TypedDict, total=False):
    sessionMetadata: LiveTailSessionMetadata | None
    sessionResults: LiveTailSessionResults | None


class MetricFilterMatchRecord(TypedDict, total=False):
    eventNumber: EventNumber | None
    eventMessage: EventMessage | None
    extractedValues: ExtractedValues | None


MetricFilterMatches = list[MetricFilterMatchRecord]


class OpenSearchResourceConfig(TypedDict, total=False):
    kmsKeyArn: Arn | None
    dataSourceRoleArn: Arn
    dashboardViewerPrincipals: DashboardViewerPrincipals
    applicationArn: Arn | None
    retentionDays: CollectionRetentionDays


class PutAccountPolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyDocument: AccountPolicyDocument
    policyType: PolicyType
    scope: Scope | None
    selectionCriteria: SelectionCriteria | None


class PutAccountPolicyResponse(TypedDict, total=False):
    accountPolicy: AccountPolicy | None


class PutDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    policyDocument: DataProtectionPolicyDocument


class PutDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: LogGroupIdentifier | None
    policyDocument: DataProtectionPolicyDocument | None
    lastUpdatedTime: Timestamp | None


class PutDeliveryDestinationPolicyRequest(ServiceRequest):
    deliveryDestinationName: DeliveryDestinationName
    deliveryDestinationPolicy: DeliveryDestinationPolicy


class PutDeliveryDestinationPolicyResponse(TypedDict, total=False):
    policy: Policy | None


class PutDeliveryDestinationRequest(ServiceRequest):
    name: DeliveryDestinationName
    outputFormat: OutputFormat | None
    deliveryDestinationConfiguration: DeliveryDestinationConfiguration | None
    deliveryDestinationType: DeliveryDestinationType | None
    tags: Tags | None


class PutDeliveryDestinationResponse(TypedDict, total=False):
    deliveryDestination: DeliveryDestination | None


class PutDeliverySourceRequest(ServiceRequest):
    name: DeliverySourceName
    resourceArn: Arn
    logType: LogType
    tags: Tags | None


class PutDeliverySourceResponse(TypedDict, total=False):
    deliverySource: DeliverySource | None


class PutDestinationPolicyRequest(ServiceRequest):
    destinationName: DestinationName
    accessPolicy: AccessPolicy
    forceUpdate: ForceUpdate | None


class PutDestinationRequest(ServiceRequest):
    destinationName: DestinationName
    targetArn: TargetArn
    roleArn: RoleArn
    tags: Tags | None


class PutDestinationResponse(TypedDict, total=False):
    destination: Destination | None


class PutIndexPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    policyDocument: PolicyDocument


class PutIndexPolicyResponse(TypedDict, total=False):
    indexPolicy: IndexPolicy | None


class ResourceConfig(TypedDict, total=False):
    openSearchResourceConfig: OpenSearchResourceConfig | None


class PutIntegrationRequest(ServiceRequest):
    integrationName: IntegrationName
    resourceConfig: ResourceConfig
    integrationType: IntegrationType


class PutIntegrationResponse(TypedDict, total=False):
    integrationName: IntegrationName | None
    integrationStatus: IntegrationStatus | None


class PutLogEventsRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName
    logEvents: InputLogEvents
    sequenceToken: SequenceToken | None
    entity: Entity | None


class RejectedEntityInfo(TypedDict, total=False):
    errorType: EntityRejectionErrorType


class RejectedLogEventsInfo(TypedDict, total=False):
    tooNewLogEventStartIndex: LogEventIndex | None
    tooOldLogEventEndIndex: LogEventIndex | None
    expiredLogEventEndIndex: LogEventIndex | None


class PutLogEventsResponse(TypedDict, total=False):
    nextSequenceToken: SequenceToken | None
    rejectedLogEventsInfo: RejectedLogEventsInfo | None
    rejectedEntityInfo: RejectedEntityInfo | None


class PutLogGroupDeletionProtectionRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    deletionProtectionEnabled: DeletionProtectionEnabled


class PutMetricFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    metricTransformations: MetricTransformations
    applyOnTransformedLogs: ApplyOnTransformedLogs | None
    fieldSelectionCriteria: FieldSelectionCriteria | None
    emitSystemFieldDimensions: EmitSystemFields | None


class PutQueryDefinitionRequest(ServiceRequest):
    queryLanguage: QueryLanguage | None
    name: QueryDefinitionName
    queryDefinitionId: QueryId | None
    logGroupNames: LogGroupNames | None
    queryString: QueryDefinitionString
    clientToken: ClientToken | None


class PutQueryDefinitionResponse(TypedDict, total=False):
    queryDefinitionId: QueryId | None


class PutResourcePolicyRequest(ServiceRequest):
    policyName: PolicyName | None
    policyDocument: PolicyDocument | None
    resourceArn: Arn | None
    expectedRevisionId: ExpectedRevisionId | None


class PutResourcePolicyResponse(TypedDict, total=False):
    resourcePolicy: ResourcePolicy | None
    revisionId: ExpectedRevisionId | None


class PutRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName
    retentionInDays: Days


class PutSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    destinationArn: DestinationArn
    roleArn: RoleArn | None
    distribution: Distribution | None
    applyOnTransformedLogs: ApplyOnTransformedLogs | None
    fieldSelectionCriteria: FieldSelectionCriteria | None
    emitSystemFields: EmitSystemFields | None


class PutTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    transformerConfig: Processors


class StartLiveTailRequest(ServiceRequest):
    logGroupIdentifiers: StartLiveTailLogGroupIdentifiers
    logStreamNames: InputLogStreamNames | None
    logStreamNamePrefixes: InputLogStreamNames | None
    logEventFilterPattern: FilterPattern | None


class StartLiveTailResponseStream(TypedDict, total=False):
    sessionStart: LiveTailSessionStart | None
    sessionUpdate: LiveTailSessionUpdate | None
    SessionTimeoutException: SessionTimeoutException | None
    SessionStreamingException: SessionStreamingException | None


class StartLiveTailResponse(TypedDict, total=False):
    responseStream: Iterator[StartLiveTailResponseStream]


class StartQueryRequest(ServiceRequest):
    queryLanguage: QueryLanguage | None
    logGroupName: LogGroupName | None
    logGroupNames: LogGroupNames | None
    logGroupIdentifiers: LogGroupIdentifiers | None
    startTime: Timestamp
    endTime: Timestamp
    queryString: QueryString
    limit: EventsLimit | None


class StartQueryResponse(TypedDict, total=False):
    queryId: QueryId | None


class StopQueryRequest(ServiceRequest):
    queryId: QueryId


class StopQueryResponse(TypedDict, total=False):
    success: Success | None


class SuppressionPeriod(TypedDict, total=False):
    value: Integer | None
    suppressionUnit: SuppressionUnit | None


TagKeyList = list[TagKey]
TagList = list[TagKey]


class TagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: Tags


class TagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tags: Tags


TestEventMessages = list[EventMessage]


class TestMetricFilterRequest(ServiceRequest):
    filterPattern: FilterPattern
    logEventMessages: TestEventMessages


class TestMetricFilterResponse(TypedDict, total=False):
    matches: MetricFilterMatches | None


class TestTransformerRequest(ServiceRequest):
    transformerConfig: Processors
    logEventMessages: TestEventMessages


class TransformedLogRecord(TypedDict, total=False):
    eventNumber: EventNumber | None
    eventMessage: EventMessage | None
    transformedEventMessage: TransformedEventMessage | None


TransformedLogs = list[TransformedLogRecord]


class TestTransformerResponse(TypedDict, total=False):
    transformedLogs: TransformedLogs | None


class UntagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: TagList


class UntagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tagKeys: TagKeyList


class UpdateAnomalyRequest(ServiceRequest):
    anomalyId: AnomalyId | None
    patternId: PatternId | None
    anomalyDetectorArn: AnomalyDetectorArn
    suppressionType: SuppressionType | None
    suppressionPeriod: SuppressionPeriod | None
    baseline: Baseline | None


class UpdateDeliveryConfigurationRequest(ServiceRequest):
    id: DeliveryId
    recordFields: RecordFields | None
    fieldDelimiter: FieldDelimiter | None
    s3DeliveryConfiguration: S3DeliveryConfiguration | None


class UpdateDeliveryConfigurationResponse(TypedDict, total=False):
    pass


class UpdateLogAnomalyDetectorRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn
    evaluationFrequency: EvaluationFrequency | None
    filterPattern: FilterPattern | None
    anomalyVisibilityTime: AnomalyVisibilityTime | None
    enabled: Boolean


class UpdateScheduledQueryRequest(ServiceRequest):
    identifier: ScheduledQueryIdentifier
    description: ScheduledQueryDescription | None
    queryLanguage: QueryLanguage
    queryString: QueryString
    logGroupIdentifiers: ScheduledQueryLogGroupIdentifiers | None
    scheduleExpression: ScheduleExpression
    timezone: ScheduleTimezone | None
    startTimeOffset: StartTimeOffset | None
    destinationConfiguration: DestinationConfiguration | None
    scheduleStartTime: Timestamp | None
    scheduleEndTime: Timestamp | None
    executionRoleArn: RoleArn
    state: ScheduledQueryState | None


class UpdateScheduledQueryResponse(TypedDict, total=False):
    scheduledQueryArn: Arn | None
    name: ScheduledQueryName | None
    description: ScheduledQueryDescription | None
    queryLanguage: QueryLanguage | None
    queryString: QueryString | None
    logGroupIdentifiers: ScheduledQueryLogGroupIdentifiers | None
    scheduleExpression: ScheduleExpression | None
    timezone: ScheduleTimezone | None
    startTimeOffset: StartTimeOffset | None
    destinationConfiguration: DestinationConfiguration | None
    state: ScheduledQueryState | None
    lastTriggeredTime: Timestamp | None
    lastExecutionStatus: ExecutionStatus | None
    scheduleStartTime: Timestamp | None
    scheduleEndTime: Timestamp | None
    executionRoleArn: RoleArn | None
    creationTime: Timestamp | None
    lastUpdatedTime: Timestamp | None


class LogsApi:
    service: str = "logs"
    version: str = "2014-03-28"

    @handler("AssociateKmsKey")
    def associate_kms_key(
        self,
        context: RequestContext,
        kms_key_id: KmsKeyId,
        log_group_name: LogGroupName | None = None,
        resource_identifier: ResourceIdentifier | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AssociateSourceToS3TableIntegration")
    def associate_source_to_s3_table_integration(
        self, context: RequestContext, integration_arn: Arn, data_source: DataSource, **kwargs
    ) -> AssociateSourceToS3TableIntegrationResponse:
        raise NotImplementedError

    @handler("CancelExportTask")
    def cancel_export_task(self, context: RequestContext, task_id: ExportTaskId, **kwargs) -> None:
        raise NotImplementedError

    @handler("CancelImportTask")
    def cancel_import_task(
        self, context: RequestContext, import_id: ImportId, **kwargs
    ) -> CancelImportTaskResponse:
        raise NotImplementedError

    @handler("CreateDelivery")
    def create_delivery(
        self,
        context: RequestContext,
        delivery_source_name: DeliverySourceName,
        delivery_destination_arn: Arn,
        record_fields: RecordFields | None = None,
        field_delimiter: FieldDelimiter | None = None,
        s3_delivery_configuration: S3DeliveryConfiguration | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateDeliveryResponse:
        raise NotImplementedError

    @handler("CreateExportTask", expand=False)
    def create_export_task(
        self, context: RequestContext, request: CreateExportTaskRequest, **kwargs
    ) -> CreateExportTaskResponse:
        raise NotImplementedError

    @handler("CreateImportTask")
    def create_import_task(
        self,
        context: RequestContext,
        import_source_arn: Arn,
        import_role_arn: RoleArn,
        import_filter: ImportFilter | None = None,
        **kwargs,
    ) -> CreateImportTaskResponse:
        raise NotImplementedError

    @handler("CreateLogAnomalyDetector")
    def create_log_anomaly_detector(
        self,
        context: RequestContext,
        log_group_arn_list: LogGroupArnList,
        detector_name: DetectorName | None = None,
        evaluation_frequency: EvaluationFrequency | None = None,
        filter_pattern: FilterPattern | None = None,
        kms_key_id: DetectorKmsKeyArn | None = None,
        anomaly_visibility_time: AnomalyVisibilityTime | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateLogAnomalyDetectorResponse:
        raise NotImplementedError

    @handler("CreateLogGroup")
    def create_log_group(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        kms_key_id: KmsKeyId | None = None,
        tags: Tags | None = None,
        log_group_class: LogGroupClass | None = None,
        deletion_protection_enabled: DeletionProtectionEnabled | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateLogStream")
    def create_log_stream(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateScheduledQuery")
    def create_scheduled_query(
        self,
        context: RequestContext,
        name: ScheduledQueryName,
        query_language: QueryLanguage,
        query_string: QueryString,
        schedule_expression: ScheduleExpression,
        execution_role_arn: RoleArn,
        description: ScheduledQueryDescription | None = None,
        log_group_identifiers: ScheduledQueryLogGroupIdentifiers | None = None,
        timezone: ScheduleTimezone | None = None,
        start_time_offset: StartTimeOffset | None = None,
        destination_configuration: DestinationConfiguration | None = None,
        schedule_start_time: Timestamp | None = None,
        schedule_end_time: Timestamp | None = None,
        state: ScheduledQueryState | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateScheduledQueryResponse:
        raise NotImplementedError

    @handler("DeleteAccountPolicy")
    def delete_account_policy(
        self, context: RequestContext, policy_name: PolicyName, policy_type: PolicyType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDataProtectionPolicy")
    def delete_data_protection_policy(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDelivery")
    def delete_delivery(self, context: RequestContext, id: DeliveryId, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteDeliveryDestination")
    def delete_delivery_destination(
        self, context: RequestContext, name: DeliveryDestinationName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeliveryDestinationPolicy")
    def delete_delivery_destination_policy(
        self, context: RequestContext, delivery_destination_name: DeliveryDestinationName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeliverySource")
    def delete_delivery_source(
        self, context: RequestContext, name: DeliverySourceName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDestination")
    def delete_destination(
        self, context: RequestContext, destination_name: DestinationName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIndexPolicy")
    def delete_index_policy(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> DeleteIndexPolicyResponse:
        raise NotImplementedError

    @handler("DeleteIntegration")
    def delete_integration(
        self,
        context: RequestContext,
        integration_name: IntegrationName,
        force: Force | None = None,
        **kwargs,
    ) -> DeleteIntegrationResponse:
        raise NotImplementedError

    @handler("DeleteLogAnomalyDetector")
    def delete_log_anomaly_detector(
        self, context: RequestContext, anomaly_detector_arn: AnomalyDetectorArn, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLogGroup")
    def delete_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLogStream")
    def delete_log_stream(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMetricFilter")
    def delete_metric_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteQueryDefinition")
    def delete_query_definition(
        self, context: RequestContext, query_definition_id: QueryId, **kwargs
    ) -> DeleteQueryDefinitionResponse:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName | None = None,
        resource_arn: Arn | None = None,
        expected_revision_id: ExpectedRevisionId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRetentionPolicy")
    def delete_retention_policy(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteScheduledQuery")
    def delete_scheduled_query(
        self, context: RequestContext, identifier: ScheduledQueryIdentifier, **kwargs
    ) -> DeleteScheduledQueryResponse:
        raise NotImplementedError

    @handler("DeleteSubscriptionFilter")
    def delete_subscription_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTransformer")
    def delete_transformer(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAccountPolicies")
    def describe_account_policies(
        self,
        context: RequestContext,
        policy_type: PolicyType,
        policy_name: PolicyName | None = None,
        account_identifiers: AccountIds | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAccountPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationTemplates")
    def describe_configuration_templates(
        self,
        context: RequestContext,
        service: Service | None = None,
        log_types: LogTypes | None = None,
        resource_types: ResourceTypes | None = None,
        delivery_destination_types: DeliveryDestinationTypes | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeConfigurationTemplatesResponse:
        raise NotImplementedError

    @handler("DescribeDeliveries")
    def describe_deliveries(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeDeliveriesResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryDestinations")
    def describe_delivery_destinations(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeDeliveryDestinationsResponse:
        raise NotImplementedError

    @handler("DescribeDeliverySources")
    def describe_delivery_sources(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeDeliverySourcesResponse:
        raise NotImplementedError

    @handler("DescribeDestinations")
    def describe_destinations(
        self,
        context: RequestContext,
        destination_name_prefix: DestinationName | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeDestinationsResponse:
        raise NotImplementedError

    @handler("DescribeExportTasks")
    def describe_export_tasks(
        self,
        context: RequestContext,
        task_id: ExportTaskId | None = None,
        status_code: ExportTaskStatusCode | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeExportTasksResponse:
        raise NotImplementedError

    @handler("DescribeFieldIndexes")
    def describe_field_indexes(
        self,
        context: RequestContext,
        log_group_identifiers: DescribeFieldIndexesLogGroupIdentifiers,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeFieldIndexesResponse:
        raise NotImplementedError

    @handler("DescribeImportTaskBatches")
    def describe_import_task_batches(
        self,
        context: RequestContext,
        import_id: ImportId,
        batch_import_status: ImportStatusList | None = None,
        limit: DescribeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeImportTaskBatchesResponse:
        raise NotImplementedError

    @handler("DescribeImportTasks")
    def describe_import_tasks(
        self,
        context: RequestContext,
        import_id: ImportId | None = None,
        import_status: ImportStatus | None = None,
        import_source_arn: Arn | None = None,
        limit: DescribeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeImportTasksResponse:
        raise NotImplementedError

    @handler("DescribeIndexPolicies")
    def describe_index_policies(
        self,
        context: RequestContext,
        log_group_identifiers: DescribeIndexPoliciesLogGroupIdentifiers,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeIndexPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeLogGroups")
    def describe_log_groups(
        self,
        context: RequestContext,
        account_identifiers: AccountIds | None = None,
        log_group_name_prefix: LogGroupName | None = None,
        log_group_name_pattern: LogGroupNamePattern | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        include_linked_accounts: IncludeLinkedAccounts | None = None,
        log_group_class: LogGroupClass | None = None,
        log_group_identifiers: DescribeLogGroupsLogGroupIdentifiers | None = None,
        **kwargs,
    ) -> DescribeLogGroupsResponse:
        raise NotImplementedError

    @handler("DescribeLogStreams")
    def describe_log_streams(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        log_group_identifier: LogGroupIdentifier | None = None,
        log_stream_name_prefix: LogStreamName | None = None,
        order_by: OrderBy | None = None,
        descending: Descending | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeLogStreamsResponse:
        raise NotImplementedError

    @handler("DescribeMetricFilters")
    def describe_metric_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        filter_name_prefix: FilterName | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        metric_name: MetricName | None = None,
        metric_namespace: MetricNamespace | None = None,
        **kwargs,
    ) -> DescribeMetricFiltersResponse:
        raise NotImplementedError

    @handler("DescribeQueries")
    def describe_queries(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        status: QueryStatus | None = None,
        max_results: DescribeQueriesMaxResults | None = None,
        next_token: NextToken | None = None,
        query_language: QueryLanguage | None = None,
        **kwargs,
    ) -> DescribeQueriesResponse:
        raise NotImplementedError

    @handler("DescribeQueryDefinitions")
    def describe_query_definitions(
        self,
        context: RequestContext,
        query_language: QueryLanguage | None = None,
        query_definition_name_prefix: QueryDefinitionName | None = None,
        max_results: QueryListMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeQueryDefinitionsResponse:
        raise NotImplementedError

    @handler("DescribeResourcePolicies")
    def describe_resource_policies(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        resource_arn: Arn | None = None,
        policy_scope: PolicyScope | None = None,
        **kwargs,
    ) -> DescribeResourcePoliciesResponse:
        raise NotImplementedError

    @handler("DescribeSubscriptionFilters")
    def describe_subscription_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name_prefix: FilterName | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeSubscriptionFiltersResponse:
        raise NotImplementedError

    @handler("DisassociateKmsKey")
    def disassociate_kms_key(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        resource_identifier: ResourceIdentifier | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DisassociateSourceFromS3TableIntegration")
    def disassociate_source_from_s3_table_integration(
        self, context: RequestContext, identifier: S3TableIntegrationSourceIdentifier, **kwargs
    ) -> DisassociateSourceFromS3TableIntegrationResponse:
        raise NotImplementedError

    @handler("FilterLogEvents")
    def filter_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        log_group_identifier: LogGroupIdentifier | None = None,
        log_stream_names: InputLogStreamNames | None = None,
        log_stream_name_prefix: LogStreamName | None = None,
        start_time: Timestamp | None = None,
        end_time: Timestamp | None = None,
        filter_pattern: FilterPattern | None = None,
        next_token: NextToken | None = None,
        limit: EventsLimit | None = None,
        interleaved: Interleaved | None = None,
        unmask: Unmask | None = None,
        **kwargs,
    ) -> FilterLogEventsResponse:
        raise NotImplementedError

    @handler("GetDataProtectionPolicy")
    def get_data_protection_policy(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> GetDataProtectionPolicyResponse:
        raise NotImplementedError

    @handler("GetDelivery")
    def get_delivery(
        self, context: RequestContext, id: DeliveryId, **kwargs
    ) -> GetDeliveryResponse:
        raise NotImplementedError

    @handler("GetDeliveryDestination")
    def get_delivery_destination(
        self, context: RequestContext, name: DeliveryDestinationName, **kwargs
    ) -> GetDeliveryDestinationResponse:
        raise NotImplementedError

    @handler("GetDeliveryDestinationPolicy")
    def get_delivery_destination_policy(
        self, context: RequestContext, delivery_destination_name: DeliveryDestinationName, **kwargs
    ) -> GetDeliveryDestinationPolicyResponse:
        raise NotImplementedError

    @handler("GetDeliverySource")
    def get_delivery_source(
        self, context: RequestContext, name: DeliverySourceName, **kwargs
    ) -> GetDeliverySourceResponse:
        raise NotImplementedError

    @handler("GetIntegration")
    def get_integration(
        self, context: RequestContext, integration_name: IntegrationName, **kwargs
    ) -> GetIntegrationResponse:
        raise NotImplementedError

    @handler("GetLogAnomalyDetector")
    def get_log_anomaly_detector(
        self, context: RequestContext, anomaly_detector_arn: AnomalyDetectorArn, **kwargs
    ) -> GetLogAnomalyDetectorResponse:
        raise NotImplementedError

    @handler("GetLogEvents")
    def get_log_events(
        self,
        context: RequestContext,
        log_stream_name: LogStreamName,
        log_group_name: LogGroupName | None = None,
        log_group_identifier: LogGroupIdentifier | None = None,
        start_time: Timestamp | None = None,
        end_time: Timestamp | None = None,
        next_token: NextToken | None = None,
        limit: EventsLimit | None = None,
        start_from_head: StartFromHead | None = None,
        unmask: Unmask | None = None,
        **kwargs,
    ) -> GetLogEventsResponse:
        raise NotImplementedError

    @handler("GetLogFields")
    def get_log_fields(
        self,
        context: RequestContext,
        data_source_name: DataSourceName,
        data_source_type: DataSourceType,
        **kwargs,
    ) -> GetLogFieldsResponse:
        raise NotImplementedError

    @handler("GetLogGroupFields")
    def get_log_group_fields(
        self,
        context: RequestContext,
        log_group_name: LogGroupName | None = None,
        time: Timestamp | None = None,
        log_group_identifier: LogGroupIdentifier | None = None,
        **kwargs,
    ) -> GetLogGroupFieldsResponse:
        raise NotImplementedError

    @handler("GetLogObject")
    def get_log_object(
        self,
        context: RequestContext,
        log_object_pointer: LogObjectPointer,
        unmask: Unmask | None = None,
        **kwargs,
    ) -> GetLogObjectResponse:
        raise NotImplementedError

    @handler("GetLogRecord")
    def get_log_record(
        self,
        context: RequestContext,
        log_record_pointer: LogRecordPointer,
        unmask: Unmask | None = None,
        **kwargs,
    ) -> GetLogRecordResponse:
        raise NotImplementedError

    @handler("GetQueryResults")
    def get_query_results(
        self, context: RequestContext, query_id: QueryId, **kwargs
    ) -> GetQueryResultsResponse:
        raise NotImplementedError

    @handler("GetScheduledQuery")
    def get_scheduled_query(
        self, context: RequestContext, identifier: ScheduledQueryIdentifier, **kwargs
    ) -> GetScheduledQueryResponse:
        raise NotImplementedError

    @handler("GetScheduledQueryHistory")
    def get_scheduled_query_history(
        self,
        context: RequestContext,
        identifier: ScheduledQueryIdentifier,
        start_time: Timestamp,
        end_time: Timestamp,
        execution_statuses: ExecutionStatusList | None = None,
        max_results: GetScheduledQueryHistoryMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetScheduledQueryHistoryResponse:
        raise NotImplementedError

    @handler("GetTransformer")
    def get_transformer(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> GetTransformerResponse:
        raise NotImplementedError

    @handler("ListAggregateLogGroupSummaries")
    def list_aggregate_log_group_summaries(
        self,
        context: RequestContext,
        group_by: ListAggregateLogGroupSummariesGroupBy,
        account_identifiers: AccountIds | None = None,
        include_linked_accounts: IncludeLinkedAccounts | None = None,
        log_group_class: LogGroupClass | None = None,
        log_group_name_pattern: LogGroupNameRegexPattern | None = None,
        data_sources: DataSourceFilters | None = None,
        next_token: NextToken | None = None,
        limit: ListLogGroupsRequestLimit | None = None,
        **kwargs,
    ) -> ListAggregateLogGroupSummariesResponse:
        raise NotImplementedError

    @handler("ListAnomalies")
    def list_anomalies(
        self,
        context: RequestContext,
        anomaly_detector_arn: AnomalyDetectorArn | None = None,
        suppression_state: SuppressionState | None = None,
        limit: ListAnomaliesLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListAnomaliesResponse:
        raise NotImplementedError

    @handler("ListIntegrations")
    def list_integrations(
        self,
        context: RequestContext,
        integration_name_prefix: IntegrationNamePrefix | None = None,
        integration_type: IntegrationType | None = None,
        integration_status: IntegrationStatus | None = None,
        **kwargs,
    ) -> ListIntegrationsResponse:
        raise NotImplementedError

    @handler("ListLogAnomalyDetectors")
    def list_log_anomaly_detectors(
        self,
        context: RequestContext,
        filter_log_group_arn: LogGroupArn | None = None,
        limit: ListLogAnomalyDetectorsLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListLogAnomalyDetectorsResponse:
        raise NotImplementedError

    @handler("ListLogGroups")
    def list_log_groups(
        self,
        context: RequestContext,
        log_group_name_pattern: LogGroupNameRegexPattern | None = None,
        log_group_class: LogGroupClass | None = None,
        include_linked_accounts: IncludeLinkedAccounts | None = None,
        account_identifiers: AccountIds | None = None,
        next_token: NextToken | None = None,
        limit: ListLimit | None = None,
        data_sources: DataSourceFilters | None = None,
        field_index_names: FieldIndexNames | None = None,
        **kwargs,
    ) -> ListLogGroupsResponse:
        raise NotImplementedError

    @handler("ListLogGroupsForQuery")
    def list_log_groups_for_query(
        self,
        context: RequestContext,
        query_id: QueryId,
        next_token: NextToken | None = None,
        max_results: ListLogGroupsForQueryMaxResults | None = None,
        **kwargs,
    ) -> ListLogGroupsForQueryResponse:
        raise NotImplementedError

    @handler("ListScheduledQueries")
    def list_scheduled_queries(
        self,
        context: RequestContext,
        max_results: ListScheduledQueriesMaxResults | None = None,
        next_token: NextToken | None = None,
        state: ScheduledQueryState | None = None,
        **kwargs,
    ) -> ListScheduledQueriesResponse:
        raise NotImplementedError

    @handler("ListSourcesForS3TableIntegration")
    def list_sources_for_s3_table_integration(
        self,
        context: RequestContext,
        integration_arn: Arn,
        max_results: ListSourcesForS3TableIntegrationMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListSourcesForS3TableIntegrationResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTagsLogGroup")
    def list_tags_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> ListTagsLogGroupResponse:
        raise NotImplementedError

    @handler("PutAccountPolicy")
    def put_account_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        policy_document: AccountPolicyDocument,
        policy_type: PolicyType,
        scope: Scope | None = None,
        selection_criteria: SelectionCriteria | None = None,
        **kwargs,
    ) -> PutAccountPolicyResponse:
        raise NotImplementedError

    @handler("PutDataProtectionPolicy")
    def put_data_protection_policy(
        self,
        context: RequestContext,
        log_group_identifier: LogGroupIdentifier,
        policy_document: DataProtectionPolicyDocument,
        **kwargs,
    ) -> PutDataProtectionPolicyResponse:
        raise NotImplementedError

    @handler("PutDeliveryDestination")
    def put_delivery_destination(
        self,
        context: RequestContext,
        name: DeliveryDestinationName,
        output_format: OutputFormat | None = None,
        delivery_destination_configuration: DeliveryDestinationConfiguration | None = None,
        delivery_destination_type: DeliveryDestinationType | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> PutDeliveryDestinationResponse:
        raise NotImplementedError

    @handler("PutDeliveryDestinationPolicy")
    def put_delivery_destination_policy(
        self,
        context: RequestContext,
        delivery_destination_name: DeliveryDestinationName,
        delivery_destination_policy: DeliveryDestinationPolicy,
        **kwargs,
    ) -> PutDeliveryDestinationPolicyResponse:
        raise NotImplementedError

    @handler("PutDeliverySource")
    def put_delivery_source(
        self,
        context: RequestContext,
        name: DeliverySourceName,
        resource_arn: Arn,
        log_type: LogType,
        tags: Tags | None = None,
        **kwargs,
    ) -> PutDeliverySourceResponse:
        raise NotImplementedError

    @handler("PutDestination")
    def put_destination(
        self,
        context: RequestContext,
        destination_name: DestinationName,
        target_arn: TargetArn,
        role_arn: RoleArn,
        tags: Tags | None = None,
        **kwargs,
    ) -> PutDestinationResponse:
        raise NotImplementedError

    @handler("PutDestinationPolicy")
    def put_destination_policy(
        self,
        context: RequestContext,
        destination_name: DestinationName,
        access_policy: AccessPolicy,
        force_update: ForceUpdate | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutIndexPolicy")
    def put_index_policy(
        self,
        context: RequestContext,
        log_group_identifier: LogGroupIdentifier,
        policy_document: PolicyDocument,
        **kwargs,
    ) -> PutIndexPolicyResponse:
        raise NotImplementedError

    @handler("PutIntegration")
    def put_integration(
        self,
        context: RequestContext,
        integration_name: IntegrationName,
        resource_config: ResourceConfig,
        integration_type: IntegrationType,
        **kwargs,
    ) -> PutIntegrationResponse:
        raise NotImplementedError

    @handler("PutLogEvents")
    def put_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        log_events: InputLogEvents,
        sequence_token: SequenceToken | None = None,
        entity: Entity | None = None,
        **kwargs,
    ) -> PutLogEventsResponse:
        raise NotImplementedError

    @handler("PutLogGroupDeletionProtection")
    def put_log_group_deletion_protection(
        self,
        context: RequestContext,
        log_group_identifier: LogGroupIdentifier,
        deletion_protection_enabled: DeletionProtectionEnabled,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutMetricFilter")
    def put_metric_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        metric_transformations: MetricTransformations,
        apply_on_transformed_logs: ApplyOnTransformedLogs | None = None,
        field_selection_criteria: FieldSelectionCriteria | None = None,
        emit_system_field_dimensions: EmitSystemFields | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutQueryDefinition")
    def put_query_definition(
        self,
        context: RequestContext,
        name: QueryDefinitionName,
        query_string: QueryDefinitionString,
        query_language: QueryLanguage | None = None,
        query_definition_id: QueryId | None = None,
        log_group_names: LogGroupNames | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> PutQueryDefinitionResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName | None = None,
        policy_document: PolicyDocument | None = None,
        resource_arn: Arn | None = None,
        expected_revision_id: ExpectedRevisionId | None = None,
        **kwargs,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("PutRetentionPolicy")
    def put_retention_policy(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        retention_in_days: Days,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutSubscriptionFilter")
    def put_subscription_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        destination_arn: DestinationArn,
        role_arn: RoleArn | None = None,
        distribution: Distribution | None = None,
        apply_on_transformed_logs: ApplyOnTransformedLogs | None = None,
        field_selection_criteria: FieldSelectionCriteria | None = None,
        emit_system_fields: EmitSystemFields | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutTransformer")
    def put_transformer(
        self,
        context: RequestContext,
        log_group_identifier: LogGroupIdentifier,
        transformer_config: Processors,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StartLiveTail")
    def start_live_tail(
        self,
        context: RequestContext,
        log_group_identifiers: StartLiveTailLogGroupIdentifiers,
        log_stream_names: InputLogStreamNames | None = None,
        log_stream_name_prefixes: InputLogStreamNames | None = None,
        log_event_filter_pattern: FilterPattern | None = None,
        **kwargs,
    ) -> StartLiveTailResponse:
        raise NotImplementedError

    @handler("StartQuery")
    def start_query(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        query_string: QueryString,
        query_language: QueryLanguage | None = None,
        log_group_name: LogGroupName | None = None,
        log_group_names: LogGroupNames | None = None,
        log_group_identifiers: LogGroupIdentifiers | None = None,
        limit: EventsLimit | None = None,
        **kwargs,
    ) -> StartQueryResponse:
        raise NotImplementedError

    @handler("StopQuery")
    def stop_query(self, context: RequestContext, query_id: QueryId, **kwargs) -> StopQueryResponse:
        raise NotImplementedError

    @handler("TagLogGroup")
    def tag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: Tags, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: Tags, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TestMetricFilter")
    def test_metric_filter(
        self,
        context: RequestContext,
        filter_pattern: FilterPattern,
        log_event_messages: TestEventMessages,
        **kwargs,
    ) -> TestMetricFilterResponse:
        raise NotImplementedError

    @handler("TestTransformer")
    def test_transformer(
        self,
        context: RequestContext,
        transformer_config: Processors,
        log_event_messages: TestEventMessages,
        **kwargs,
    ) -> TestTransformerResponse:
        raise NotImplementedError

    @handler("UntagLogGroup")
    def untag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAnomaly")
    def update_anomaly(
        self,
        context: RequestContext,
        anomaly_detector_arn: AnomalyDetectorArn,
        anomaly_id: AnomalyId | None = None,
        pattern_id: PatternId | None = None,
        suppression_type: SuppressionType | None = None,
        suppression_period: SuppressionPeriod | None = None,
        baseline: Baseline | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDeliveryConfiguration")
    def update_delivery_configuration(
        self,
        context: RequestContext,
        id: DeliveryId,
        record_fields: RecordFields | None = None,
        field_delimiter: FieldDelimiter | None = None,
        s3_delivery_configuration: S3DeliveryConfiguration | None = None,
        **kwargs,
    ) -> UpdateDeliveryConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateLogAnomalyDetector")
    def update_log_anomaly_detector(
        self,
        context: RequestContext,
        anomaly_detector_arn: AnomalyDetectorArn,
        enabled: Boolean,
        evaluation_frequency: EvaluationFrequency | None = None,
        filter_pattern: FilterPattern | None = None,
        anomaly_visibility_time: AnomalyVisibilityTime | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateScheduledQuery")
    def update_scheduled_query(
        self,
        context: RequestContext,
        identifier: ScheduledQueryIdentifier,
        query_language: QueryLanguage,
        query_string: QueryString,
        schedule_expression: ScheduleExpression,
        execution_role_arn: RoleArn,
        description: ScheduledQueryDescription | None = None,
        log_group_identifiers: ScheduledQueryLogGroupIdentifiers | None = None,
        timezone: ScheduleTimezone | None = None,
        start_time_offset: StartTimeOffset | None = None,
        destination_configuration: DestinationConfiguration | None = None,
        schedule_start_time: Timestamp | None = None,
        schedule_end_time: Timestamp | None = None,
        state: ScheduledQueryState | None = None,
        **kwargs,
    ) -> UpdateScheduledQueryResponse:
        raise NotImplementedError
