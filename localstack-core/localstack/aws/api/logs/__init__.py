from enum import StrEnum
from typing import Dict, Iterator, List, Optional, TypedDict

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
Boolean = bool
ClientToken = str
CollectionRetentionDays = int
Column = str
DataProtectionPolicyDocument = str
Days = int
DefaultValue = float
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
EventId = str
EventMessage = str
EventsLimit = int
ExportDestinationBucket = str
ExportDestinationPrefix = str
ExportTaskId = str
ExportTaskName = str
ExportTaskStatusMessage = str
Field = str
FieldDelimiter = str
FieldHeader = str
FieldIndexName = str
FilterCount = int
FilterName = str
FilterPattern = str
Flatten = bool
Force = bool
ForceUpdate = bool
FromKey = str
GrokMatch = str
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
ListLogAnomalyDetectorsLimit = int
ListLogGroupsForQueryMaxResults = int
Locale = str
LogEventIndex = int
LogGroupArn = str
LogGroupIdentifier = str
LogGroupName = str
LogGroupNamePattern = str
LogRecordPointer = str
LogStreamName = str
LogStreamSearchedCompletely = bool
LogType = str
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
SelectionCriteria = str
SequenceToken = str
Service = str
SessionId = str
Source = str
SourceTimezone = str
StartFromHead = bool
StatsValue = float
Success = bool
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


class IndexSource(StrEnum):
    ACCOUNT = "ACCOUNT"
    LOG_GROUP = "LOG_GROUP"


class InheritedProperty(StrEnum):
    ACCOUNT_DATA_PROTECTION = "ACCOUNT_DATA_PROTECTION"


class IntegrationStatus(StrEnum):
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class IntegrationType(StrEnum):
    OPENSEARCH = "OPENSEARCH"


class LogGroupClass(StrEnum):
    STANDARD = "STANDARD"
    INFREQUENT_ACCESS = "INFREQUENT_ACCESS"


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


class PolicyType(StrEnum):
    DATA_PROTECTION_POLICY = "DATA_PROTECTION_POLICY"
    SUBSCRIPTION_FILTER_POLICY = "SUBSCRIPTION_FILTER_POLICY"
    FIELD_INDEX_POLICY = "FIELD_INDEX_POLICY"
    TRANSFORMER_POLICY = "TRANSFORMER_POLICY"


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
    expectedSequenceToken: Optional[SequenceToken]


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
    expectedSequenceToken: Optional[SequenceToken]


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class QueryCompileErrorLocation(TypedDict, total=False):
    startCharOffset: Optional[QueryCharOffset]
    endCharOffset: Optional[QueryCharOffset]


class QueryCompileError(TypedDict, total=False):
    location: Optional[QueryCompileErrorLocation]
    message: Optional[Message]


class MalformedQueryException(ServiceException):
    code: str = "MalformedQueryException"
    sender_fault: bool = False
    status_code: int = 400
    queryCompileError: Optional[QueryCompileError]


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
    resourceName: Optional[AmazonResourceName]


class UnrecognizedClientException(ServiceException):
    code: str = "UnrecognizedClientException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


AccountIds = List[AccountId]
Timestamp = int


class AccountPolicy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyDocument: Optional[AccountPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]
    policyType: Optional[PolicyType]
    scope: Optional[Scope]
    selectionCriteria: Optional[SelectionCriteria]
    accountId: Optional[AccountId]


AccountPolicies = List[AccountPolicy]


class AddKeyEntry(TypedDict, total=False):
    key: Key
    value: AddKeyValue
    overwriteIfExists: Optional[OverwriteIfExists]


AddKeyEntries = List[AddKeyEntry]


class AddKeys(TypedDict, total=False):
    entries: AddKeyEntries


AllowedFieldDelimiters = List[FieldDelimiter]


class RecordField(TypedDict, total=False):
    name: Optional[FieldHeader]
    mandatory: Optional[Boolean]


AllowedFields = List[RecordField]
EpochMillis = int
LogGroupArnList = List[LogGroupArn]
TokenValue = int
Enumerations = Dict[TokenString, TokenValue]


class PatternToken(TypedDict, total=False):
    dynamicTokenPosition: Optional[DynamicTokenPosition]
    isDynamic: Optional[Boolean]
    tokenString: Optional[TokenString]
    enumerations: Optional[Enumerations]
    inferredTokenName: Optional[InferredTokenName]


PatternTokens = List[PatternToken]


class LogEvent(TypedDict, total=False):
    timestamp: Optional[Timestamp]
    message: Optional[EventMessage]


LogSamples = List[LogEvent]
Count = int
Histogram = Dict[Time, Count]


class Anomaly(TypedDict, total=False):
    anomalyId: AnomalyId
    patternId: PatternId
    anomalyDetectorArn: AnomalyDetectorArn
    patternString: PatternString
    patternRegex: Optional[PatternRegex]
    priority: Optional[Priority]
    firstSeen: EpochMillis
    lastSeen: EpochMillis
    description: Description
    active: Boolean
    state: State
    histogram: Histogram
    logSamples: LogSamples
    patternTokens: PatternTokens
    logGroupArnList: LogGroupArnList
    suppressed: Optional[Boolean]
    suppressedDate: Optional[EpochMillis]
    suppressedUntil: Optional[EpochMillis]
    isPatternLevelSuppression: Optional[Boolean]


Anomalies = List[Anomaly]
AnomalyVisibilityTime = int


class AnomalyDetector(TypedDict, total=False):
    anomalyDetectorArn: Optional[AnomalyDetectorArn]
    detectorName: Optional[DetectorName]
    logGroupArnList: Optional[LogGroupArnList]
    evaluationFrequency: Optional[EvaluationFrequency]
    filterPattern: Optional[FilterPattern]
    anomalyDetectorStatus: Optional[AnomalyDetectorStatus]
    kmsKeyId: Optional[KmsKeyId]
    creationTimeStamp: Optional[EpochMillis]
    lastModifiedTimeStamp: Optional[EpochMillis]
    anomalyVisibilityTime: Optional[AnomalyVisibilityTime]


AnomalyDetectors = List[AnomalyDetector]


class AssociateKmsKeyRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    kmsKeyId: KmsKeyId
    resourceIdentifier: Optional[ResourceIdentifier]


Columns = List[Column]


class CSV(TypedDict, total=False):
    quoteCharacter: Optional[QuoteCharacter]
    delimiter: Optional[Delimiter]
    columns: Optional[Columns]
    source: Optional[Source]


class CancelExportTaskRequest(ServiceRequest):
    taskId: ExportTaskId


RecordFields = List[FieldHeader]
OutputFormats = List[OutputFormat]


class S3DeliveryConfiguration(TypedDict, total=False):
    suffixPath: Optional[DeliverySuffixPath]
    enableHiveCompatiblePath: Optional[Boolean]


class ConfigurationTemplateDeliveryConfigValues(TypedDict, total=False):
    recordFields: Optional[RecordFields]
    fieldDelimiter: Optional[FieldDelimiter]
    s3DeliveryConfiguration: Optional[S3DeliveryConfiguration]


class ConfigurationTemplate(TypedDict, total=False):
    service: Optional[Service]
    logType: Optional[LogType]
    resourceType: Optional[ResourceType]
    deliveryDestinationType: Optional[DeliveryDestinationType]
    defaultDeliveryConfigValues: Optional[ConfigurationTemplateDeliveryConfigValues]
    allowedFields: Optional[AllowedFields]
    allowedOutputFormats: Optional[OutputFormats]
    allowedActionForAllowVendedLogsDeliveryForResource: Optional[
        AllowedActionForAllowVendedLogsDeliveryForResource
    ]
    allowedFieldDelimiters: Optional[AllowedFieldDelimiters]
    allowedSuffixPathFields: Optional[RecordFields]


ConfigurationTemplates = List[ConfigurationTemplate]


class CopyValueEntry(TypedDict, total=False):
    source: Source
    target: Target
    overwriteIfExists: Optional[OverwriteIfExists]


CopyValueEntries = List[CopyValueEntry]


class CopyValue(TypedDict, total=False):
    entries: CopyValueEntries


Tags = Dict[TagKey, TagValue]


class CreateDeliveryRequest(ServiceRequest):
    deliverySourceName: DeliverySourceName
    deliveryDestinationArn: Arn
    recordFields: Optional[RecordFields]
    fieldDelimiter: Optional[FieldDelimiter]
    s3DeliveryConfiguration: Optional[S3DeliveryConfiguration]
    tags: Optional[Tags]


class Delivery(TypedDict, total=False):
    id: Optional[DeliveryId]
    arn: Optional[Arn]
    deliverySourceName: Optional[DeliverySourceName]
    deliveryDestinationArn: Optional[Arn]
    deliveryDestinationType: Optional[DeliveryDestinationType]
    recordFields: Optional[RecordFields]
    fieldDelimiter: Optional[FieldDelimiter]
    s3DeliveryConfiguration: Optional[S3DeliveryConfiguration]
    tags: Optional[Tags]


class CreateDeliveryResponse(TypedDict, total=False):
    delivery: Optional[Delivery]


CreateExportTaskRequest = TypedDict(
    "CreateExportTaskRequest",
    {
        "taskName": Optional[ExportTaskName],
        "logGroupName": LogGroupName,
        "logStreamNamePrefix": Optional[LogStreamName],
        "from": Timestamp,
        "to": Timestamp,
        "destination": ExportDestinationBucket,
        "destinationPrefix": Optional[ExportDestinationPrefix],
    },
    total=False,
)


class CreateExportTaskResponse(TypedDict, total=False):
    taskId: Optional[ExportTaskId]


class CreateLogAnomalyDetectorRequest(ServiceRequest):
    logGroupArnList: LogGroupArnList
    detectorName: Optional[DetectorName]
    evaluationFrequency: Optional[EvaluationFrequency]
    filterPattern: Optional[FilterPattern]
    kmsKeyId: Optional[DetectorKmsKeyArn]
    anomalyVisibilityTime: Optional[AnomalyVisibilityTime]
    tags: Optional[Tags]


class CreateLogAnomalyDetectorResponse(TypedDict, total=False):
    anomalyDetectorArn: Optional[AnomalyDetectorArn]


class CreateLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    kmsKeyId: Optional[KmsKeyId]
    tags: Optional[Tags]
    logGroupClass: Optional[LogGroupClass]


class CreateLogStreamRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName


DashboardViewerPrincipals = List[Arn]
MatchPatterns = List[MatchPattern]


class DateTimeConverter(TypedDict, total=False):
    source: Source
    target: Target
    targetFormat: Optional[TargetFormat]
    matchPatterns: MatchPatterns
    sourceTimezone: Optional[SourceTimezone]
    targetTimezone: Optional[TargetTimezone]
    locale: Optional[Locale]


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
    force: Optional[Force]


class DeleteIntegrationResponse(TypedDict, total=False):
    pass


DeleteWithKeys = List[WithKey]


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
    success: Optional[Success]


class DeleteResourcePolicyRequest(ServiceRequest):
    policyName: Optional[PolicyName]


class DeleteRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName


class DeleteSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName


class DeleteTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


Deliveries = List[Delivery]


class DeliveryDestinationConfiguration(TypedDict, total=False):
    destinationResourceArn: Arn


class DeliveryDestination(TypedDict, total=False):
    name: Optional[DeliveryDestinationName]
    arn: Optional[Arn]
    deliveryDestinationType: Optional[DeliveryDestinationType]
    outputFormat: Optional[OutputFormat]
    deliveryDestinationConfiguration: Optional[DeliveryDestinationConfiguration]
    tags: Optional[Tags]


DeliveryDestinationTypes = List[DeliveryDestinationType]
DeliveryDestinations = List[DeliveryDestination]
ResourceArns = List[Arn]


class DeliverySource(TypedDict, total=False):
    name: Optional[DeliverySourceName]
    arn: Optional[Arn]
    resourceArns: Optional[ResourceArns]
    service: Optional[Service]
    logType: Optional[LogType]
    tags: Optional[Tags]


DeliverySources = List[DeliverySource]


class DescribeAccountPoliciesRequest(ServiceRequest):
    policyType: PolicyType
    policyName: Optional[PolicyName]
    accountIdentifiers: Optional[AccountIds]
    nextToken: Optional[NextToken]


class DescribeAccountPoliciesResponse(TypedDict, total=False):
    accountPolicies: Optional[AccountPolicies]
    nextToken: Optional[NextToken]


ResourceTypes = List[ResourceType]
LogTypes = List[LogType]


class DescribeConfigurationTemplatesRequest(ServiceRequest):
    service: Optional[Service]
    logTypes: Optional[LogTypes]
    resourceTypes: Optional[ResourceTypes]
    deliveryDestinationTypes: Optional[DeliveryDestinationTypes]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class DescribeConfigurationTemplatesResponse(TypedDict, total=False):
    configurationTemplates: Optional[ConfigurationTemplates]
    nextToken: Optional[NextToken]


class DescribeDeliveriesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class DescribeDeliveriesResponse(TypedDict, total=False):
    deliveries: Optional[Deliveries]
    nextToken: Optional[NextToken]


class DescribeDeliveryDestinationsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class DescribeDeliveryDestinationsResponse(TypedDict, total=False):
    deliveryDestinations: Optional[DeliveryDestinations]
    nextToken: Optional[NextToken]


class DescribeDeliverySourcesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class DescribeDeliverySourcesResponse(TypedDict, total=False):
    deliverySources: Optional[DeliverySources]
    nextToken: Optional[NextToken]


class DescribeDestinationsRequest(ServiceRequest):
    DestinationNamePrefix: Optional[DestinationName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class Destination(TypedDict, total=False):
    destinationName: Optional[DestinationName]
    targetArn: Optional[TargetArn]
    roleArn: Optional[RoleArn]
    accessPolicy: Optional[AccessPolicy]
    arn: Optional[Arn]
    creationTime: Optional[Timestamp]


Destinations = List[Destination]


class DescribeDestinationsResponse(TypedDict, total=False):
    destinations: Optional[Destinations]
    nextToken: Optional[NextToken]


class DescribeExportTasksRequest(ServiceRequest):
    taskId: Optional[ExportTaskId]
    statusCode: Optional[ExportTaskStatusCode]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class ExportTaskExecutionInfo(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    completionTime: Optional[Timestamp]


class ExportTaskStatus(TypedDict, total=False):
    code: Optional[ExportTaskStatusCode]
    message: Optional[ExportTaskStatusMessage]


ExportTask = TypedDict(
    "ExportTask",
    {
        "taskId": Optional[ExportTaskId],
        "taskName": Optional[ExportTaskName],
        "logGroupName": Optional[LogGroupName],
        "from": Optional[Timestamp],
        "to": Optional[Timestamp],
        "destination": Optional[ExportDestinationBucket],
        "destinationPrefix": Optional[ExportDestinationPrefix],
        "status": Optional[ExportTaskStatus],
        "executionInfo": Optional[ExportTaskExecutionInfo],
    },
    total=False,
)
ExportTasks = List[ExportTask]


class DescribeExportTasksResponse(TypedDict, total=False):
    exportTasks: Optional[ExportTasks]
    nextToken: Optional[NextToken]


DescribeFieldIndexesLogGroupIdentifiers = List[LogGroupIdentifier]


class DescribeFieldIndexesRequest(ServiceRequest):
    logGroupIdentifiers: DescribeFieldIndexesLogGroupIdentifiers
    nextToken: Optional[NextToken]


class FieldIndex(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    fieldIndexName: Optional[FieldIndexName]
    lastScanTime: Optional[Timestamp]
    firstEventTime: Optional[Timestamp]
    lastEventTime: Optional[Timestamp]


FieldIndexes = List[FieldIndex]


class DescribeFieldIndexesResponse(TypedDict, total=False):
    fieldIndexes: Optional[FieldIndexes]
    nextToken: Optional[NextToken]


DescribeIndexPoliciesLogGroupIdentifiers = List[LogGroupIdentifier]


class DescribeIndexPoliciesRequest(ServiceRequest):
    logGroupIdentifiers: DescribeIndexPoliciesLogGroupIdentifiers
    nextToken: Optional[NextToken]


class IndexPolicy(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    lastUpdateTime: Optional[Timestamp]
    policyDocument: Optional[PolicyDocument]
    policyName: Optional[PolicyName]
    source: Optional[IndexSource]


IndexPolicies = List[IndexPolicy]


class DescribeIndexPoliciesResponse(TypedDict, total=False):
    indexPolicies: Optional[IndexPolicies]
    nextToken: Optional[NextToken]


class DescribeLogGroupsRequest(ServiceRequest):
    accountIdentifiers: Optional[AccountIds]
    logGroupNamePrefix: Optional[LogGroupName]
    logGroupNamePattern: Optional[LogGroupNamePattern]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]
    includeLinkedAccounts: Optional[IncludeLinkedAccounts]
    logGroupClass: Optional[LogGroupClass]


InheritedProperties = List[InheritedProperty]
StoredBytes = int


class LogGroup(TypedDict, total=False):
    logGroupName: Optional[LogGroupName]
    creationTime: Optional[Timestamp]
    retentionInDays: Optional[Days]
    metricFilterCount: Optional[FilterCount]
    arn: Optional[Arn]
    storedBytes: Optional[StoredBytes]
    kmsKeyId: Optional[KmsKeyId]
    dataProtectionStatus: Optional[DataProtectionStatus]
    inheritedProperties: Optional[InheritedProperties]
    logGroupClass: Optional[LogGroupClass]
    logGroupArn: Optional[Arn]


LogGroups = List[LogGroup]


class DescribeLogGroupsResponse(TypedDict, total=False):
    logGroups: Optional[LogGroups]
    nextToken: Optional[NextToken]


class DescribeLogStreamsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamNamePrefix: Optional[LogStreamName]
    orderBy: Optional[OrderBy]
    descending: Optional[Descending]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class LogStream(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    creationTime: Optional[Timestamp]
    firstEventTimestamp: Optional[Timestamp]
    lastEventTimestamp: Optional[Timestamp]
    lastIngestionTime: Optional[Timestamp]
    uploadSequenceToken: Optional[SequenceToken]
    arn: Optional[Arn]
    storedBytes: Optional[StoredBytes]


LogStreams = List[LogStream]


class DescribeLogStreamsResponse(TypedDict, total=False):
    logStreams: Optional[LogStreams]
    nextToken: Optional[NextToken]


class DescribeMetricFiltersRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    filterNamePrefix: Optional[FilterName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]
    metricName: Optional[MetricName]
    metricNamespace: Optional[MetricNamespace]


Dimensions = Dict[DimensionsKey, DimensionsValue]


class MetricTransformation(TypedDict, total=False):
    metricName: MetricName
    metricNamespace: MetricNamespace
    metricValue: MetricValue
    defaultValue: Optional[DefaultValue]
    dimensions: Optional[Dimensions]
    unit: Optional[StandardUnit]


MetricTransformations = List[MetricTransformation]


class MetricFilter(TypedDict, total=False):
    filterName: Optional[FilterName]
    filterPattern: Optional[FilterPattern]
    metricTransformations: Optional[MetricTransformations]
    creationTime: Optional[Timestamp]
    logGroupName: Optional[LogGroupName]
    applyOnTransformedLogs: Optional[ApplyOnTransformedLogs]


MetricFilters = List[MetricFilter]


class DescribeMetricFiltersResponse(TypedDict, total=False):
    metricFilters: Optional[MetricFilters]
    nextToken: Optional[NextToken]


class DescribeQueriesRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    status: Optional[QueryStatus]
    maxResults: Optional[DescribeQueriesMaxResults]
    nextToken: Optional[NextToken]
    queryLanguage: Optional[QueryLanguage]


class QueryInfo(TypedDict, total=False):
    queryLanguage: Optional[QueryLanguage]
    queryId: Optional[QueryId]
    queryString: Optional[QueryString]
    status: Optional[QueryStatus]
    createTime: Optional[Timestamp]
    logGroupName: Optional[LogGroupName]


QueryInfoList = List[QueryInfo]


class DescribeQueriesResponse(TypedDict, total=False):
    queries: Optional[QueryInfoList]
    nextToken: Optional[NextToken]


class DescribeQueryDefinitionsRequest(ServiceRequest):
    queryLanguage: Optional[QueryLanguage]
    queryDefinitionNamePrefix: Optional[QueryDefinitionName]
    maxResults: Optional[QueryListMaxResults]
    nextToken: Optional[NextToken]


LogGroupNames = List[LogGroupName]


class QueryDefinition(TypedDict, total=False):
    queryLanguage: Optional[QueryLanguage]
    queryDefinitionId: Optional[QueryId]
    name: Optional[QueryDefinitionName]
    queryString: Optional[QueryDefinitionString]
    lastModified: Optional[Timestamp]
    logGroupNames: Optional[LogGroupNames]


QueryDefinitionList = List[QueryDefinition]


class DescribeQueryDefinitionsResponse(TypedDict, total=False):
    queryDefinitions: Optional[QueryDefinitionList]
    nextToken: Optional[NextToken]


class DescribeResourcePoliciesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class ResourcePolicy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyDocument: Optional[PolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


ResourcePolicies = List[ResourcePolicy]


class DescribeResourcePoliciesResponse(TypedDict, total=False):
    resourcePolicies: Optional[ResourcePolicies]
    nextToken: Optional[NextToken]


class DescribeSubscriptionFiltersRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterNamePrefix: Optional[FilterName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class SubscriptionFilter(TypedDict, total=False):
    filterName: Optional[FilterName]
    logGroupName: Optional[LogGroupName]
    filterPattern: Optional[FilterPattern]
    destinationArn: Optional[DestinationArn]
    roleArn: Optional[RoleArn]
    distribution: Optional[Distribution]
    applyOnTransformedLogs: Optional[ApplyOnTransformedLogs]
    creationTime: Optional[Timestamp]


SubscriptionFilters = List[SubscriptionFilter]


class DescribeSubscriptionFiltersResponse(TypedDict, total=False):
    subscriptionFilters: Optional[SubscriptionFilters]
    nextToken: Optional[NextToken]


class DisassociateKmsKeyRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    resourceIdentifier: Optional[ResourceIdentifier]


EntityAttributes = Dict[EntityAttributesKey, EntityAttributesValue]
EntityKeyAttributes = Dict[EntityKeyAttributesKey, EntityKeyAttributesValue]


class Entity(TypedDict, total=False):
    keyAttributes: Optional[EntityKeyAttributes]
    attributes: Optional[EntityAttributes]


EventNumber = int
ExtractedValues = Dict[Token, Value]
InputLogStreamNames = List[LogStreamName]


class FilterLogEventsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamNames: Optional[InputLogStreamNames]
    logStreamNamePrefix: Optional[LogStreamName]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    filterPattern: Optional[FilterPattern]
    nextToken: Optional[NextToken]
    limit: Optional[EventsLimit]
    interleaved: Optional[Interleaved]
    unmask: Optional[Unmask]


class SearchedLogStream(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    searchedCompletely: Optional[LogStreamSearchedCompletely]


SearchedLogStreams = List[SearchedLogStream]


class FilteredLogEvent(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    timestamp: Optional[Timestamp]
    message: Optional[EventMessage]
    ingestionTime: Optional[Timestamp]
    eventId: Optional[EventId]


FilteredLogEvents = List[FilteredLogEvent]


class FilterLogEventsResponse(TypedDict, total=False):
    events: Optional[FilteredLogEvents]
    searchedLogStreams: Optional[SearchedLogStreams]
    nextToken: Optional[NextToken]


class GetDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class GetDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    policyDocument: Optional[DataProtectionPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


class GetDeliveryDestinationPolicyRequest(ServiceRequest):
    deliveryDestinationName: DeliveryDestinationName


class Policy(TypedDict, total=False):
    deliveryDestinationPolicy: Optional[DeliveryDestinationPolicy]


class GetDeliveryDestinationPolicyResponse(TypedDict, total=False):
    policy: Optional[Policy]


class GetDeliveryDestinationRequest(ServiceRequest):
    name: DeliveryDestinationName


class GetDeliveryDestinationResponse(TypedDict, total=False):
    deliveryDestination: Optional[DeliveryDestination]


class GetDeliveryRequest(ServiceRequest):
    id: DeliveryId


class GetDeliveryResponse(TypedDict, total=False):
    delivery: Optional[Delivery]


class GetDeliverySourceRequest(ServiceRequest):
    name: DeliverySourceName


class GetDeliverySourceResponse(TypedDict, total=False):
    deliverySource: Optional[DeliverySource]


class GetIntegrationRequest(ServiceRequest):
    integrationName: IntegrationName


class OpenSearchResourceStatus(TypedDict, total=False):
    status: Optional[OpenSearchResourceStatusType]
    statusMessage: Optional[IntegrationStatusMessage]


class OpenSearchLifecyclePolicy(TypedDict, total=False):
    policyName: Optional[OpenSearchPolicyName]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchDataAccessPolicy(TypedDict, total=False):
    policyName: Optional[OpenSearchPolicyName]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchNetworkPolicy(TypedDict, total=False):
    policyName: Optional[OpenSearchPolicyName]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchEncryptionPolicy(TypedDict, total=False):
    policyName: Optional[OpenSearchPolicyName]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchWorkspace(TypedDict, total=False):
    workspaceId: Optional[OpenSearchWorkspaceId]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchCollection(TypedDict, total=False):
    collectionEndpoint: Optional[OpenSearchCollectionEndpoint]
    collectionArn: Optional[Arn]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchApplication(TypedDict, total=False):
    applicationEndpoint: Optional[OpenSearchApplicationEndpoint]
    applicationArn: Optional[Arn]
    applicationId: Optional[OpenSearchApplicationId]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchDataSource(TypedDict, total=False):
    dataSourceName: Optional[OpenSearchDataSourceName]
    status: Optional[OpenSearchResourceStatus]


class OpenSearchIntegrationDetails(TypedDict, total=False):
    dataSource: Optional[OpenSearchDataSource]
    application: Optional[OpenSearchApplication]
    collection: Optional[OpenSearchCollection]
    workspace: Optional[OpenSearchWorkspace]
    encryptionPolicy: Optional[OpenSearchEncryptionPolicy]
    networkPolicy: Optional[OpenSearchNetworkPolicy]
    accessPolicy: Optional[OpenSearchDataAccessPolicy]
    lifecyclePolicy: Optional[OpenSearchLifecyclePolicy]


class IntegrationDetails(TypedDict, total=False):
    openSearchIntegrationDetails: Optional[OpenSearchIntegrationDetails]


class GetIntegrationResponse(TypedDict, total=False):
    integrationName: Optional[IntegrationName]
    integrationType: Optional[IntegrationType]
    integrationStatus: Optional[IntegrationStatus]
    integrationDetails: Optional[IntegrationDetails]


class GetLogAnomalyDetectorRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn


class GetLogAnomalyDetectorResponse(TypedDict, total=False):
    detectorName: Optional[DetectorName]
    logGroupArnList: Optional[LogGroupArnList]
    evaluationFrequency: Optional[EvaluationFrequency]
    filterPattern: Optional[FilterPattern]
    anomalyDetectorStatus: Optional[AnomalyDetectorStatus]
    kmsKeyId: Optional[KmsKeyId]
    creationTimeStamp: Optional[EpochMillis]
    lastModifiedTimeStamp: Optional[EpochMillis]
    anomalyVisibilityTime: Optional[AnomalyVisibilityTime]


class GetLogEventsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamName: LogStreamName
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    nextToken: Optional[NextToken]
    limit: Optional[EventsLimit]
    startFromHead: Optional[StartFromHead]
    unmask: Optional[Unmask]


class OutputLogEvent(TypedDict, total=False):
    timestamp: Optional[Timestamp]
    message: Optional[EventMessage]
    ingestionTime: Optional[Timestamp]


OutputLogEvents = List[OutputLogEvent]


class GetLogEventsResponse(TypedDict, total=False):
    events: Optional[OutputLogEvents]
    nextForwardToken: Optional[NextToken]
    nextBackwardToken: Optional[NextToken]


class GetLogGroupFieldsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    time: Optional[Timestamp]
    logGroupIdentifier: Optional[LogGroupIdentifier]


class LogGroupField(TypedDict, total=False):
    name: Optional[Field]
    percent: Optional[Percentage]


LogGroupFieldList = List[LogGroupField]


class GetLogGroupFieldsResponse(TypedDict, total=False):
    logGroupFields: Optional[LogGroupFieldList]


class GetLogRecordRequest(ServiceRequest):
    logRecordPointer: LogRecordPointer
    unmask: Optional[Unmask]


LogRecord = Dict[Field, Value]


class GetLogRecordResponse(TypedDict, total=False):
    logRecord: Optional[LogRecord]


class GetQueryResultsRequest(ServiceRequest):
    queryId: QueryId


class QueryStatistics(TypedDict, total=False):
    recordsMatched: Optional[StatsValue]
    recordsScanned: Optional[StatsValue]
    estimatedRecordsSkipped: Optional[StatsValue]
    bytesScanned: Optional[StatsValue]
    estimatedBytesSkipped: Optional[StatsValue]
    logGroupsScanned: Optional[StatsValue]


class ResultField(TypedDict, total=False):
    field: Optional[Field]
    value: Optional[Value]


ResultRows = List[ResultField]
QueryResults = List[ResultRows]


class GetQueryResultsResponse(TypedDict, total=False):
    queryLanguage: Optional[QueryLanguage]
    results: Optional[QueryResults]
    statistics: Optional[QueryStatistics]
    status: Optional[QueryStatus]
    encryptionKey: Optional[EncryptionKey]


class GetTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


UpperCaseStringWithKeys = List[WithKey]


class UpperCaseString(TypedDict, total=False):
    withKeys: UpperCaseStringWithKeys


TypeConverterEntry = TypedDict(
    "TypeConverterEntry",
    {
        "key": Key,
        "type": Type,
    },
    total=False,
)
TypeConverterEntries = List[TypeConverterEntry]


class TypeConverter(TypedDict, total=False):
    entries: TypeConverterEntries


TrimStringWithKeys = List[WithKey]


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
SubstituteStringEntries = List[SubstituteStringEntry]


class SubstituteString(TypedDict, total=False):
    entries: SubstituteStringEntries


class SplitStringEntry(TypedDict, total=False):
    source: Source
    delimiter: Delimiter


SplitStringEntries = List[SplitStringEntry]


class SplitString(TypedDict, total=False):
    entries: SplitStringEntries


class RenameKeyEntry(TypedDict, total=False):
    key: Key
    renameTo: RenameTo
    overwriteIfExists: Optional[OverwriteIfExists]


RenameKeyEntries = List[RenameKeyEntry]


class RenameKeys(TypedDict, total=False):
    entries: RenameKeyEntries


class ParseWAF(TypedDict, total=False):
    source: Optional[Source]


class ParseVPC(TypedDict, total=False):
    source: Optional[Source]


class ParsePostgres(TypedDict, total=False):
    source: Optional[Source]


class ParseRoute53(TypedDict, total=False):
    source: Optional[Source]


class ParseKeyValue(TypedDict, total=False):
    source: Optional[Source]
    destination: Optional[DestinationField]
    fieldDelimiter: Optional[ParserFieldDelimiter]
    keyValueDelimiter: Optional[KeyValueDelimiter]
    keyPrefix: Optional[KeyPrefix]
    nonMatchValue: Optional[NonMatchValue]
    overwriteIfExists: Optional[OverwriteIfExists]


class ParseJSON(TypedDict, total=False):
    source: Optional[Source]
    destination: Optional[DestinationField]


class ParseCloudfront(TypedDict, total=False):
    source: Optional[Source]


class MoveKeyEntry(TypedDict, total=False):
    source: Source
    target: Target
    overwriteIfExists: Optional[OverwriteIfExists]


MoveKeyEntries = List[MoveKeyEntry]


class MoveKeys(TypedDict, total=False):
    entries: MoveKeyEntries


LowerCaseStringWithKeys = List[WithKey]


class LowerCaseString(TypedDict, total=False):
    withKeys: LowerCaseStringWithKeys


class ListToMap(TypedDict, total=False):
    source: Source
    key: Key
    valueKey: Optional[ValueKey]
    target: Optional[Target]
    flatten: Optional[Flatten]
    flattenedElement: Optional[FlattenedElement]


class Grok(TypedDict, total=False):
    source: Optional[Source]
    match: GrokMatch


class Processor(TypedDict, total=False):
    addKeys: Optional[AddKeys]
    copyValue: Optional[CopyValue]
    csv: Optional[CSV]
    dateTimeConverter: Optional[DateTimeConverter]
    deleteKeys: Optional[DeleteKeys]
    grok: Optional[Grok]
    listToMap: Optional[ListToMap]
    lowerCaseString: Optional[LowerCaseString]
    moveKeys: Optional[MoveKeys]
    parseCloudfront: Optional[ParseCloudfront]
    parseJSON: Optional[ParseJSON]
    parseKeyValue: Optional[ParseKeyValue]
    parseRoute53: Optional[ParseRoute53]
    parsePostgres: Optional[ParsePostgres]
    parseVPC: Optional[ParseVPC]
    parseWAF: Optional[ParseWAF]
    renameKeys: Optional[RenameKeys]
    splitString: Optional[SplitString]
    substituteString: Optional[SubstituteString]
    trimString: Optional[TrimString]
    typeConverter: Optional[TypeConverter]
    upperCaseString: Optional[UpperCaseString]


Processors = List[Processor]


class GetTransformerResponse(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    creationTime: Optional[Timestamp]
    lastModifiedTime: Optional[Timestamp]
    transformerConfig: Optional[Processors]


class InputLogEvent(TypedDict, total=False):
    timestamp: Timestamp
    message: EventMessage


InputLogEvents = List[InputLogEvent]


class IntegrationSummary(TypedDict, total=False):
    integrationName: Optional[IntegrationName]
    integrationType: Optional[IntegrationType]
    integrationStatus: Optional[IntegrationStatus]


IntegrationSummaries = List[IntegrationSummary]


class ListAnomaliesRequest(ServiceRequest):
    anomalyDetectorArn: Optional[AnomalyDetectorArn]
    suppressionState: Optional[SuppressionState]
    limit: Optional[ListAnomaliesLimit]
    nextToken: Optional[NextToken]


class ListAnomaliesResponse(TypedDict, total=False):
    anomalies: Optional[Anomalies]
    nextToken: Optional[NextToken]


class ListIntegrationsRequest(ServiceRequest):
    integrationNamePrefix: Optional[IntegrationNamePrefix]
    integrationType: Optional[IntegrationType]
    integrationStatus: Optional[IntegrationStatus]


class ListIntegrationsResponse(TypedDict, total=False):
    integrationSummaries: Optional[IntegrationSummaries]


class ListLogAnomalyDetectorsRequest(ServiceRequest):
    filterLogGroupArn: Optional[LogGroupArn]
    limit: Optional[ListLogAnomalyDetectorsLimit]
    nextToken: Optional[NextToken]


class ListLogAnomalyDetectorsResponse(TypedDict, total=False):
    anomalyDetectors: Optional[AnomalyDetectors]
    nextToken: Optional[NextToken]


class ListLogGroupsForQueryRequest(ServiceRequest):
    queryId: QueryId
    nextToken: Optional[NextToken]
    maxResults: Optional[ListLogGroupsForQueryMaxResults]


LogGroupIdentifiers = List[LogGroupIdentifier]


class ListLogGroupsForQueryResponse(TypedDict, total=False):
    logGroupIdentifiers: Optional[LogGroupIdentifiers]
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[Tags]


class ListTagsLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName


class ListTagsLogGroupResponse(TypedDict, total=False):
    tags: Optional[Tags]


class LiveTailSessionLogEvent(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    message: Optional[EventMessage]
    timestamp: Optional[Timestamp]
    ingestionTime: Optional[Timestamp]


class LiveTailSessionMetadata(TypedDict, total=False):
    sampled: Optional[IsSampled]


LiveTailSessionResults = List[LiveTailSessionLogEvent]
StartLiveTailLogGroupIdentifiers = List[LogGroupIdentifier]


class LiveTailSessionStart(TypedDict, total=False):
    requestId: Optional[RequestId]
    sessionId: Optional[SessionId]
    logGroupIdentifiers: Optional[StartLiveTailLogGroupIdentifiers]
    logStreamNames: Optional[InputLogStreamNames]
    logStreamNamePrefixes: Optional[InputLogStreamNames]
    logEventFilterPattern: Optional[FilterPattern]


class LiveTailSessionUpdate(TypedDict, total=False):
    sessionMetadata: Optional[LiveTailSessionMetadata]
    sessionResults: Optional[LiveTailSessionResults]


class MetricFilterMatchRecord(TypedDict, total=False):
    eventNumber: Optional[EventNumber]
    eventMessage: Optional[EventMessage]
    extractedValues: Optional[ExtractedValues]


MetricFilterMatches = List[MetricFilterMatchRecord]


class OpenSearchResourceConfig(TypedDict, total=False):
    kmsKeyArn: Optional[Arn]
    dataSourceRoleArn: Arn
    dashboardViewerPrincipals: DashboardViewerPrincipals
    applicationArn: Optional[Arn]
    retentionDays: CollectionRetentionDays


class PutAccountPolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyDocument: AccountPolicyDocument
    policyType: PolicyType
    scope: Optional[Scope]
    selectionCriteria: Optional[SelectionCriteria]


class PutAccountPolicyResponse(TypedDict, total=False):
    accountPolicy: Optional[AccountPolicy]


class PutDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    policyDocument: DataProtectionPolicyDocument


class PutDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    policyDocument: Optional[DataProtectionPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


class PutDeliveryDestinationPolicyRequest(ServiceRequest):
    deliveryDestinationName: DeliveryDestinationName
    deliveryDestinationPolicy: DeliveryDestinationPolicy


class PutDeliveryDestinationPolicyResponse(TypedDict, total=False):
    policy: Optional[Policy]


class PutDeliveryDestinationRequest(ServiceRequest):
    name: DeliveryDestinationName
    outputFormat: Optional[OutputFormat]
    deliveryDestinationConfiguration: DeliveryDestinationConfiguration
    tags: Optional[Tags]


class PutDeliveryDestinationResponse(TypedDict, total=False):
    deliveryDestination: Optional[DeliveryDestination]


class PutDeliverySourceRequest(ServiceRequest):
    name: DeliverySourceName
    resourceArn: Arn
    logType: LogType
    tags: Optional[Tags]


class PutDeliverySourceResponse(TypedDict, total=False):
    deliverySource: Optional[DeliverySource]


class PutDestinationPolicyRequest(ServiceRequest):
    destinationName: DestinationName
    accessPolicy: AccessPolicy
    forceUpdate: Optional[ForceUpdate]


class PutDestinationRequest(ServiceRequest):
    destinationName: DestinationName
    targetArn: TargetArn
    roleArn: RoleArn
    tags: Optional[Tags]


class PutDestinationResponse(TypedDict, total=False):
    destination: Optional[Destination]


class PutIndexPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    policyDocument: PolicyDocument


class PutIndexPolicyResponse(TypedDict, total=False):
    indexPolicy: Optional[IndexPolicy]


class ResourceConfig(TypedDict, total=False):
    openSearchResourceConfig: Optional[OpenSearchResourceConfig]


class PutIntegrationRequest(ServiceRequest):
    integrationName: IntegrationName
    resourceConfig: ResourceConfig
    integrationType: IntegrationType


class PutIntegrationResponse(TypedDict, total=False):
    integrationName: Optional[IntegrationName]
    integrationStatus: Optional[IntegrationStatus]


class PutLogEventsRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName
    logEvents: InputLogEvents
    sequenceToken: Optional[SequenceToken]
    entity: Optional[Entity]


class RejectedEntityInfo(TypedDict, total=False):
    errorType: EntityRejectionErrorType


class RejectedLogEventsInfo(TypedDict, total=False):
    tooNewLogEventStartIndex: Optional[LogEventIndex]
    tooOldLogEventEndIndex: Optional[LogEventIndex]
    expiredLogEventEndIndex: Optional[LogEventIndex]


class PutLogEventsResponse(TypedDict, total=False):
    nextSequenceToken: Optional[SequenceToken]
    rejectedLogEventsInfo: Optional[RejectedLogEventsInfo]
    rejectedEntityInfo: Optional[RejectedEntityInfo]


class PutMetricFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    metricTransformations: MetricTransformations
    applyOnTransformedLogs: Optional[ApplyOnTransformedLogs]


class PutQueryDefinitionRequest(ServiceRequest):
    queryLanguage: Optional[QueryLanguage]
    name: QueryDefinitionName
    queryDefinitionId: Optional[QueryId]
    logGroupNames: Optional[LogGroupNames]
    queryString: QueryDefinitionString
    clientToken: Optional[ClientToken]


class PutQueryDefinitionResponse(TypedDict, total=False):
    queryDefinitionId: Optional[QueryId]


class PutResourcePolicyRequest(ServiceRequest):
    policyName: Optional[PolicyName]
    policyDocument: Optional[PolicyDocument]


class PutResourcePolicyResponse(TypedDict, total=False):
    resourcePolicy: Optional[ResourcePolicy]


class PutRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName
    retentionInDays: Days


class PutSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    destinationArn: DestinationArn
    roleArn: Optional[RoleArn]
    distribution: Optional[Distribution]
    applyOnTransformedLogs: Optional[ApplyOnTransformedLogs]


class PutTransformerRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    transformerConfig: Processors


class StartLiveTailRequest(ServiceRequest):
    logGroupIdentifiers: StartLiveTailLogGroupIdentifiers
    logStreamNames: Optional[InputLogStreamNames]
    logStreamNamePrefixes: Optional[InputLogStreamNames]
    logEventFilterPattern: Optional[FilterPattern]


class StartLiveTailResponseStream(TypedDict, total=False):
    sessionStart: Optional[LiveTailSessionStart]
    sessionUpdate: Optional[LiveTailSessionUpdate]
    SessionTimeoutException: Optional[SessionTimeoutException]
    SessionStreamingException: Optional[SessionStreamingException]


class StartLiveTailResponse(TypedDict, total=False):
    responseStream: Iterator[StartLiveTailResponseStream]


class StartQueryRequest(ServiceRequest):
    queryLanguage: Optional[QueryLanguage]
    logGroupName: Optional[LogGroupName]
    logGroupNames: Optional[LogGroupNames]
    logGroupIdentifiers: Optional[LogGroupIdentifiers]
    startTime: Timestamp
    endTime: Timestamp
    queryString: QueryString
    limit: Optional[EventsLimit]


class StartQueryResponse(TypedDict, total=False):
    queryId: Optional[QueryId]


class StopQueryRequest(ServiceRequest):
    queryId: QueryId


class StopQueryResponse(TypedDict, total=False):
    success: Optional[Success]


class SuppressionPeriod(TypedDict, total=False):
    value: Optional[Integer]
    suppressionUnit: Optional[SuppressionUnit]


TagKeyList = List[TagKey]
TagList = List[TagKey]


class TagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: Tags


class TagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tags: Tags


TestEventMessages = List[EventMessage]


class TestMetricFilterRequest(ServiceRequest):
    filterPattern: FilterPattern
    logEventMessages: TestEventMessages


class TestMetricFilterResponse(TypedDict, total=False):
    matches: Optional[MetricFilterMatches]


class TestTransformerRequest(ServiceRequest):
    transformerConfig: Processors
    logEventMessages: TestEventMessages


class TransformedLogRecord(TypedDict, total=False):
    eventNumber: Optional[EventNumber]
    eventMessage: Optional[EventMessage]
    transformedEventMessage: Optional[TransformedEventMessage]


TransformedLogs = List[TransformedLogRecord]


class TestTransformerResponse(TypedDict, total=False):
    transformedLogs: Optional[TransformedLogs]


class UntagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: TagList


class UntagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tagKeys: TagKeyList


class UpdateAnomalyRequest(ServiceRequest):
    anomalyId: Optional[AnomalyId]
    patternId: Optional[PatternId]
    anomalyDetectorArn: AnomalyDetectorArn
    suppressionType: Optional[SuppressionType]
    suppressionPeriod: Optional[SuppressionPeriod]
    baseline: Optional[Baseline]


class UpdateDeliveryConfigurationRequest(ServiceRequest):
    id: DeliveryId
    recordFields: Optional[RecordFields]
    fieldDelimiter: Optional[FieldDelimiter]
    s3DeliveryConfiguration: Optional[S3DeliveryConfiguration]


class UpdateDeliveryConfigurationResponse(TypedDict, total=False):
    pass


class UpdateLogAnomalyDetectorRequest(ServiceRequest):
    anomalyDetectorArn: AnomalyDetectorArn
    evaluationFrequency: Optional[EvaluationFrequency]
    filterPattern: Optional[FilterPattern]
    anomalyVisibilityTime: Optional[AnomalyVisibilityTime]
    enabled: Boolean


class LogsApi:
    service = "logs"
    version = "2014-03-28"

    @handler("AssociateKmsKey")
    def associate_kms_key(
        self,
        context: RequestContext,
        kms_key_id: KmsKeyId,
        log_group_name: LogGroupName = None,
        resource_identifier: ResourceIdentifier = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CancelExportTask")
    def cancel_export_task(self, context: RequestContext, task_id: ExportTaskId, **kwargs) -> None:
        raise NotImplementedError

    @handler("CreateDelivery")
    def create_delivery(
        self,
        context: RequestContext,
        delivery_source_name: DeliverySourceName,
        delivery_destination_arn: Arn,
        record_fields: RecordFields = None,
        field_delimiter: FieldDelimiter = None,
        s3_delivery_configuration: S3DeliveryConfiguration = None,
        tags: Tags = None,
        **kwargs,
    ) -> CreateDeliveryResponse:
        raise NotImplementedError

    @handler("CreateExportTask", expand=False)
    def create_export_task(
        self, context: RequestContext, request: CreateExportTaskRequest, **kwargs
    ) -> CreateExportTaskResponse:
        raise NotImplementedError

    @handler("CreateLogAnomalyDetector")
    def create_log_anomaly_detector(
        self,
        context: RequestContext,
        log_group_arn_list: LogGroupArnList,
        detector_name: DetectorName = None,
        evaluation_frequency: EvaluationFrequency = None,
        filter_pattern: FilterPattern = None,
        kms_key_id: DetectorKmsKeyArn = None,
        anomaly_visibility_time: AnomalyVisibilityTime = None,
        tags: Tags = None,
        **kwargs,
    ) -> CreateLogAnomalyDetectorResponse:
        raise NotImplementedError

    @handler("CreateLogGroup")
    def create_log_group(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        kms_key_id: KmsKeyId = None,
        tags: Tags = None,
        log_group_class: LogGroupClass = None,
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
        force: Force = None,
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
        self, context: RequestContext, policy_name: PolicyName = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRetentionPolicy")
    def delete_retention_policy(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> None:
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
        policy_name: PolicyName = None,
        account_identifiers: AccountIds = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeAccountPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationTemplates")
    def describe_configuration_templates(
        self,
        context: RequestContext,
        service: Service = None,
        log_types: LogTypes = None,
        resource_types: ResourceTypes = None,
        delivery_destination_types: DeliveryDestinationTypes = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeConfigurationTemplatesResponse:
        raise NotImplementedError

    @handler("DescribeDeliveries")
    def describe_deliveries(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeDeliveriesResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryDestinations")
    def describe_delivery_destinations(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeDeliveryDestinationsResponse:
        raise NotImplementedError

    @handler("DescribeDeliverySources")
    def describe_delivery_sources(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeDeliverySourcesResponse:
        raise NotImplementedError

    @handler("DescribeDestinations")
    def describe_destinations(
        self,
        context: RequestContext,
        destination_name_prefix: DestinationName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeDestinationsResponse:
        raise NotImplementedError

    @handler("DescribeExportTasks")
    def describe_export_tasks(
        self,
        context: RequestContext,
        task_id: ExportTaskId = None,
        status_code: ExportTaskStatusCode = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeExportTasksResponse:
        raise NotImplementedError

    @handler("DescribeFieldIndexes")
    def describe_field_indexes(
        self,
        context: RequestContext,
        log_group_identifiers: DescribeFieldIndexesLogGroupIdentifiers,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeFieldIndexesResponse:
        raise NotImplementedError

    @handler("DescribeIndexPolicies")
    def describe_index_policies(
        self,
        context: RequestContext,
        log_group_identifiers: DescribeIndexPoliciesLogGroupIdentifiers,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeIndexPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeLogGroups")
    def describe_log_groups(
        self,
        context: RequestContext,
        account_identifiers: AccountIds = None,
        log_group_name_prefix: LogGroupName = None,
        log_group_name_pattern: LogGroupNamePattern = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        include_linked_accounts: IncludeLinkedAccounts = None,
        log_group_class: LogGroupClass = None,
        **kwargs,
    ) -> DescribeLogGroupsResponse:
        raise NotImplementedError

    @handler("DescribeLogStreams")
    def describe_log_streams(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        log_stream_name_prefix: LogStreamName = None,
        order_by: OrderBy = None,
        descending: Descending = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeLogStreamsResponse:
        raise NotImplementedError

    @handler("DescribeMetricFilters")
    def describe_metric_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        filter_name_prefix: FilterName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        metric_name: MetricName = None,
        metric_namespace: MetricNamespace = None,
        **kwargs,
    ) -> DescribeMetricFiltersResponse:
        raise NotImplementedError

    @handler("DescribeQueries")
    def describe_queries(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        status: QueryStatus = None,
        max_results: DescribeQueriesMaxResults = None,
        next_token: NextToken = None,
        query_language: QueryLanguage = None,
        **kwargs,
    ) -> DescribeQueriesResponse:
        raise NotImplementedError

    @handler("DescribeQueryDefinitions")
    def describe_query_definitions(
        self,
        context: RequestContext,
        query_language: QueryLanguage = None,
        query_definition_name_prefix: QueryDefinitionName = None,
        max_results: QueryListMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeQueryDefinitionsResponse:
        raise NotImplementedError

    @handler("DescribeResourcePolicies")
    def describe_resource_policies(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeResourcePoliciesResponse:
        raise NotImplementedError

    @handler("DescribeSubscriptionFilters")
    def describe_subscription_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name_prefix: FilterName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        **kwargs,
    ) -> DescribeSubscriptionFiltersResponse:
        raise NotImplementedError

    @handler("DisassociateKmsKey")
    def disassociate_kms_key(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        resource_identifier: ResourceIdentifier = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("FilterLogEvents")
    def filter_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        log_stream_names: InputLogStreamNames = None,
        log_stream_name_prefix: LogStreamName = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        filter_pattern: FilterPattern = None,
        next_token: NextToken = None,
        limit: EventsLimit = None,
        interleaved: Interleaved = None,
        unmask: Unmask = None,
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
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        next_token: NextToken = None,
        limit: EventsLimit = None,
        start_from_head: StartFromHead = None,
        unmask: Unmask = None,
        **kwargs,
    ) -> GetLogEventsResponse:
        raise NotImplementedError

    @handler("GetLogGroupFields")
    def get_log_group_fields(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        time: Timestamp = None,
        log_group_identifier: LogGroupIdentifier = None,
        **kwargs,
    ) -> GetLogGroupFieldsResponse:
        raise NotImplementedError

    @handler("GetLogRecord")
    def get_log_record(
        self,
        context: RequestContext,
        log_record_pointer: LogRecordPointer,
        unmask: Unmask = None,
        **kwargs,
    ) -> GetLogRecordResponse:
        raise NotImplementedError

    @handler("GetQueryResults")
    def get_query_results(
        self, context: RequestContext, query_id: QueryId, **kwargs
    ) -> GetQueryResultsResponse:
        raise NotImplementedError

    @handler("GetTransformer")
    def get_transformer(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier, **kwargs
    ) -> GetTransformerResponse:
        raise NotImplementedError

    @handler("ListAnomalies")
    def list_anomalies(
        self,
        context: RequestContext,
        anomaly_detector_arn: AnomalyDetectorArn = None,
        suppression_state: SuppressionState = None,
        limit: ListAnomaliesLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListAnomaliesResponse:
        raise NotImplementedError

    @handler("ListIntegrations")
    def list_integrations(
        self,
        context: RequestContext,
        integration_name_prefix: IntegrationNamePrefix = None,
        integration_type: IntegrationType = None,
        integration_status: IntegrationStatus = None,
        **kwargs,
    ) -> ListIntegrationsResponse:
        raise NotImplementedError

    @handler("ListLogAnomalyDetectors")
    def list_log_anomaly_detectors(
        self,
        context: RequestContext,
        filter_log_group_arn: LogGroupArn = None,
        limit: ListLogAnomalyDetectorsLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListLogAnomalyDetectorsResponse:
        raise NotImplementedError

    @handler("ListLogGroupsForQuery")
    def list_log_groups_for_query(
        self,
        context: RequestContext,
        query_id: QueryId,
        next_token: NextToken = None,
        max_results: ListLogGroupsForQueryMaxResults = None,
        **kwargs,
    ) -> ListLogGroupsForQueryResponse:
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
        scope: Scope = None,
        selection_criteria: SelectionCriteria = None,
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
        delivery_destination_configuration: DeliveryDestinationConfiguration,
        output_format: OutputFormat = None,
        tags: Tags = None,
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
        tags: Tags = None,
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
        tags: Tags = None,
        **kwargs,
    ) -> PutDestinationResponse:
        raise NotImplementedError

    @handler("PutDestinationPolicy")
    def put_destination_policy(
        self,
        context: RequestContext,
        destination_name: DestinationName,
        access_policy: AccessPolicy,
        force_update: ForceUpdate = None,
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
        sequence_token: SequenceToken = None,
        entity: Entity = None,
        **kwargs,
    ) -> PutLogEventsResponse:
        raise NotImplementedError

    @handler("PutMetricFilter")
    def put_metric_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        metric_transformations: MetricTransformations,
        apply_on_transformed_logs: ApplyOnTransformedLogs = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutQueryDefinition")
    def put_query_definition(
        self,
        context: RequestContext,
        name: QueryDefinitionName,
        query_string: QueryDefinitionString,
        query_language: QueryLanguage = None,
        query_definition_id: QueryId = None,
        log_group_names: LogGroupNames = None,
        client_token: ClientToken = None,
        **kwargs,
    ) -> PutQueryDefinitionResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName = None,
        policy_document: PolicyDocument = None,
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
        role_arn: RoleArn = None,
        distribution: Distribution = None,
        apply_on_transformed_logs: ApplyOnTransformedLogs = None,
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
        log_stream_names: InputLogStreamNames = None,
        log_stream_name_prefixes: InputLogStreamNames = None,
        log_event_filter_pattern: FilterPattern = None,
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
        query_language: QueryLanguage = None,
        log_group_name: LogGroupName = None,
        log_group_names: LogGroupNames = None,
        log_group_identifiers: LogGroupIdentifiers = None,
        limit: EventsLimit = None,
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
        anomaly_id: AnomalyId = None,
        pattern_id: PatternId = None,
        suppression_type: SuppressionType = None,
        suppression_period: SuppressionPeriod = None,
        baseline: Baseline = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDeliveryConfiguration")
    def update_delivery_configuration(
        self,
        context: RequestContext,
        id: DeliveryId,
        record_fields: RecordFields = None,
        field_delimiter: FieldDelimiter = None,
        s3_delivery_configuration: S3DeliveryConfiguration = None,
        **kwargs,
    ) -> UpdateDeliveryConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateLogAnomalyDetector")
    def update_log_anomaly_detector(
        self,
        context: RequestContext,
        anomaly_detector_arn: AnomalyDetectorArn,
        enabled: Boolean,
        evaluation_frequency: EvaluationFrequency = None,
        filter_pattern: FilterPattern = None,
        anomaly_visibility_time: AnomalyVisibilityTime = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError
