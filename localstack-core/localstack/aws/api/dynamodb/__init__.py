from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ArchivalReason = str
AttributeName = str
AutoScalingPolicyName = str
AutoScalingRoleArn = str
AvailabilityErrorMessage = str
Backfilling = bool
BackupArn = str
BackupName = str
BackupsInputLimit = int
BooleanAttributeValue = bool
BooleanObject = bool
ClientRequestToken = str
ClientToken = str
CloudWatchLogGroupArn = str
Code = str
ConditionExpression = str
ConfirmRemoveSelfResourceAccess = bool
ConsistentRead = bool
ConsumedCapacityUnits = float
ContributorInsightsRule = str
CsvDelimiter = str
CsvHeader = str
DeletionProtectionEnabled = bool
DoubleObject = float
ErrorMessage = str
ExceptionDescription = str
ExceptionName = str
ExportArn = str
ExportManifest = str
ExportNextToken = str
ExpressionAttributeNameVariable = str
ExpressionAttributeValueVariable = str
FailureCode = str
FailureMessage = str
GlobalTableArnString = str
ImportArn = str
ImportNextToken = str
IndexName = str
Integer = int
IntegerObject = int
ItemCollectionSizeEstimateBound = float
KMSMasterKeyArn = str
KMSMasterKeyId = str
KeyExpression = str
KeySchemaAttributeName = str
ListContributorInsightsLimit = int
ListExportsMaxLimit = int
ListImportsMaxLimit = int
ListTablesInputLimit = int
NextTokenString = str
NonKeyAttributeName = str
NullAttributeValue = bool
NumberAttributeValue = str
PartiQLNextToken = str
PartiQLStatement = str
PolicyRevisionId = str
PositiveIntegerObject = int
ProjectionExpression = str
Reason = str
RecoveryPeriodInDays = int
RegionName = str
ReplicaStatusDescription = str
ReplicaStatusPercentProgress = str
Resource = str
ResourceArnString = str
ResourcePolicy = str
RestoreInProgress = bool
S3Bucket = str
S3BucketOwner = str
S3Prefix = str
S3SseKmsKeyId = str
SSEEnabled = bool
ScanSegment = int
ScanTotalSegments = int
StreamArn = str
StreamEnabled = bool
String = str
StringAttributeValue = str
TableArn = str
TableId = str
TableName = str
TagKeyString = str
TagValueString = str
TimeToLiveAttributeName = str
TimeToLiveEnabled = bool
UpdateExpression = str


class ApproximateCreationDateTimePrecision(StrEnum):
    MILLISECOND = "MILLISECOND"
    MICROSECOND = "MICROSECOND"


class AttributeAction(StrEnum):
    ADD = "ADD"
    PUT = "PUT"
    DELETE = "DELETE"


class BackupStatus(StrEnum):
    CREATING = "CREATING"
    DELETED = "DELETED"
    AVAILABLE = "AVAILABLE"


class BackupType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    AWS_BACKUP = "AWS_BACKUP"


class BackupTypeFilter(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    AWS_BACKUP = "AWS_BACKUP"
    ALL = "ALL"


class BatchStatementErrorCodeEnum(StrEnum):
    ConditionalCheckFailed = "ConditionalCheckFailed"
    ItemCollectionSizeLimitExceeded = "ItemCollectionSizeLimitExceeded"
    RequestLimitExceeded = "RequestLimitExceeded"
    ValidationError = "ValidationError"
    ProvisionedThroughputExceeded = "ProvisionedThroughputExceeded"
    TransactionConflict = "TransactionConflict"
    ThrottlingError = "ThrottlingError"
    InternalServerError = "InternalServerError"
    ResourceNotFound = "ResourceNotFound"
    AccessDenied = "AccessDenied"
    DuplicateItem = "DuplicateItem"


class BillingMode(StrEnum):
    PROVISIONED = "PROVISIONED"
    PAY_PER_REQUEST = "PAY_PER_REQUEST"


class ComparisonOperator(StrEnum):
    EQ = "EQ"
    NE = "NE"
    IN = "IN"
    LE = "LE"
    LT = "LT"
    GE = "GE"
    GT = "GT"
    BETWEEN = "BETWEEN"
    NOT_NULL = "NOT_NULL"
    NULL = "NULL"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    BEGINS_WITH = "BEGINS_WITH"


class ConditionalOperator(StrEnum):
    AND = "AND"
    OR = "OR"


class ContinuousBackupsStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ContributorInsightsAction(StrEnum):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"


class ContributorInsightsMode(StrEnum):
    ACCESSED_AND_THROTTLED_KEYS = "ACCESSED_AND_THROTTLED_KEYS"
    THROTTLED_KEYS = "THROTTLED_KEYS"


class ContributorInsightsStatus(StrEnum):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"
    FAILED = "FAILED"


class DestinationStatus(StrEnum):
    ENABLING = "ENABLING"
    ACTIVE = "ACTIVE"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"
    ENABLE_FAILED = "ENABLE_FAILED"
    UPDATING = "UPDATING"


class ExportFormat(StrEnum):
    DYNAMODB_JSON = "DYNAMODB_JSON"
    ION = "ION"


class ExportStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ExportType(StrEnum):
    FULL_EXPORT = "FULL_EXPORT"
    INCREMENTAL_EXPORT = "INCREMENTAL_EXPORT"


class ExportViewType(StrEnum):
    NEW_IMAGE = "NEW_IMAGE"
    NEW_AND_OLD_IMAGES = "NEW_AND_OLD_IMAGES"


class GlobalTableStatus(StrEnum):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class ImportStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class IndexStatus(StrEnum):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"


class InputCompressionType(StrEnum):
    GZIP = "GZIP"
    ZSTD = "ZSTD"
    NONE = "NONE"


class InputFormat(StrEnum):
    DYNAMODB_JSON = "DYNAMODB_JSON"
    ION = "ION"
    CSV = "CSV"


class KeyType(StrEnum):
    HASH = "HASH"
    RANGE = "RANGE"


class MultiRegionConsistency(StrEnum):
    EVENTUAL = "EVENTUAL"
    STRONG = "STRONG"


class PointInTimeRecoveryStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ProjectionType(StrEnum):
    ALL = "ALL"
    KEYS_ONLY = "KEYS_ONLY"
    INCLUDE = "INCLUDE"


class ReplicaStatus(StrEnum):
    CREATING = "CREATING"
    CREATION_FAILED = "CREATION_FAILED"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"
    REGION_DISABLED = "REGION_DISABLED"
    INACCESSIBLE_ENCRYPTION_CREDENTIALS = "INACCESSIBLE_ENCRYPTION_CREDENTIALS"
    ARCHIVING = "ARCHIVING"
    ARCHIVED = "ARCHIVED"
    REPLICATION_NOT_AUTHORIZED = "REPLICATION_NOT_AUTHORIZED"


class ReturnConsumedCapacity(StrEnum):
    INDEXES = "INDEXES"
    TOTAL = "TOTAL"
    NONE = "NONE"


class ReturnItemCollectionMetrics(StrEnum):
    SIZE = "SIZE"
    NONE = "NONE"


class ReturnValue(StrEnum):
    NONE = "NONE"
    ALL_OLD = "ALL_OLD"
    UPDATED_OLD = "UPDATED_OLD"
    ALL_NEW = "ALL_NEW"
    UPDATED_NEW = "UPDATED_NEW"


class ReturnValuesOnConditionCheckFailure(StrEnum):
    ALL_OLD = "ALL_OLD"
    NONE = "NONE"


class S3SseAlgorithm(StrEnum):
    AES256 = "AES256"
    KMS = "KMS"


class SSEStatus(StrEnum):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"
    UPDATING = "UPDATING"


class SSEType(StrEnum):
    AES256 = "AES256"
    KMS = "KMS"


class ScalarAttributeType(StrEnum):
    S = "S"
    N = "N"
    B = "B"


class Select(StrEnum):
    ALL_ATTRIBUTES = "ALL_ATTRIBUTES"
    ALL_PROJECTED_ATTRIBUTES = "ALL_PROJECTED_ATTRIBUTES"
    SPECIFIC_ATTRIBUTES = "SPECIFIC_ATTRIBUTES"
    COUNT = "COUNT"


class StreamViewType(StrEnum):
    NEW_IMAGE = "NEW_IMAGE"
    OLD_IMAGE = "OLD_IMAGE"
    NEW_AND_OLD_IMAGES = "NEW_AND_OLD_IMAGES"
    KEYS_ONLY = "KEYS_ONLY"


class TableClass(StrEnum):
    STANDARD = "STANDARD"
    STANDARD_INFREQUENT_ACCESS = "STANDARD_INFREQUENT_ACCESS"


class TableStatus(StrEnum):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"
    INACCESSIBLE_ENCRYPTION_CREDENTIALS = "INACCESSIBLE_ENCRYPTION_CREDENTIALS"
    ARCHIVING = "ARCHIVING"
    ARCHIVED = "ARCHIVED"
    REPLICATION_NOT_AUTHORIZED = "REPLICATION_NOT_AUTHORIZED"


class TimeToLiveStatus(StrEnum):
    ENABLING = "ENABLING"
    DISABLING = "DISABLING"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class WitnessStatus(StrEnum):
    CREATING = "CREATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"


class BackupInUseException(ServiceException):
    code: str = "BackupInUseException"
    sender_fault: bool = False
    status_code: int = 400


class BackupNotFoundException(ServiceException):
    code: str = "BackupNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class AttributeValue(TypedDict, total=False):
    S: "StringAttributeValue | None"
    N: "NumberAttributeValue | None"
    B: "BinaryAttributeValue | None"
    SS: "StringSetAttributeValue | None"
    NS: "NumberSetAttributeValue | None"
    BS: "BinarySetAttributeValue | None"
    M: "MapAttributeValue | None"
    L: "ListAttributeValue | None"
    NULL: "NullAttributeValue | None"
    BOOL: "BooleanAttributeValue | None"


ListAttributeValue = list[AttributeValue]
MapAttributeValue = dict[AttributeName, AttributeValue]
BinaryAttributeValue = bytes
BinarySetAttributeValue = list[BinaryAttributeValue]
NumberSetAttributeValue = list[NumberAttributeValue]
StringSetAttributeValue = list[StringAttributeValue]
AttributeMap = dict[AttributeName, AttributeValue]


class ConditionalCheckFailedException(ServiceException):
    code: str = "ConditionalCheckFailedException"
    sender_fault: bool = False
    status_code: int = 400
    Item: AttributeMap | None


class ContinuousBackupsUnavailableException(ServiceException):
    code: str = "ContinuousBackupsUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class DuplicateItemException(ServiceException):
    code: str = "DuplicateItemException"
    sender_fault: bool = False
    status_code: int = 400


class ExportConflictException(ServiceException):
    code: str = "ExportConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ExportNotFoundException(ServiceException):
    code: str = "ExportNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class GlobalTableAlreadyExistsException(ServiceException):
    code: str = "GlobalTableAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class GlobalTableNotFoundException(ServiceException):
    code: str = "GlobalTableNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class IdempotentParameterMismatchException(ServiceException):
    code: str = "IdempotentParameterMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class ImportConflictException(ServiceException):
    code: str = "ImportConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ImportNotFoundException(ServiceException):
    code: str = "ImportNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class IndexNotFoundException(ServiceException):
    code: str = "IndexNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServerError(ServiceException):
    code: str = "InternalServerError"
    sender_fault: bool = False
    status_code: int = 400


class InvalidExportTimeException(ServiceException):
    code: str = "InvalidExportTimeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRestoreTimeException(ServiceException):
    code: str = "InvalidRestoreTimeException"
    sender_fault: bool = False
    status_code: int = 400


class ItemCollectionSizeLimitExceededException(ServiceException):
    code: str = "ItemCollectionSizeLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class PointInTimeRecoveryUnavailableException(ServiceException):
    code: str = "PointInTimeRecoveryUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class PolicyNotFoundException(ServiceException):
    code: str = "PolicyNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingReason(TypedDict, total=False):
    reason: Reason | None
    resource: Resource | None


ThrottlingReasonList = list[ThrottlingReason]


class ProvisionedThroughputExceededException(ServiceException):
    code: str = "ProvisionedThroughputExceededException"
    sender_fault: bool = False
    status_code: int = 400
    ThrottlingReasons: ThrottlingReasonList | None


class ReplicaAlreadyExistsException(ServiceException):
    code: str = "ReplicaAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ReplicaNotFoundException(ServiceException):
    code: str = "ReplicaNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ReplicatedWriteConflictException(ServiceException):
    code: str = "ReplicatedWriteConflictException"
    sender_fault: bool = False
    status_code: int = 400


class RequestLimitExceeded(ServiceException):
    code: str = "RequestLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400
    ThrottlingReasons: ThrottlingReasonList | None


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TableAlreadyExistsException(ServiceException):
    code: str = "TableAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class TableInUseException(ServiceException):
    code: str = "TableInUseException"
    sender_fault: bool = False
    status_code: int = 400


class TableNotFoundException(ServiceException):
    code: str = "TableNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400
    throttlingReasons: ThrottlingReasonList | None


class CancellationReason(TypedDict, total=False):
    Item: AttributeMap | None
    Code: Code | None
    Message: ErrorMessage | None


CancellationReasonList = list[CancellationReason]


class TransactionCanceledException(ServiceException):
    code: str = "TransactionCanceledException"
    sender_fault: bool = False
    status_code: int = 400
    CancellationReasons: CancellationReasonList | None


class TransactionConflictException(ServiceException):
    code: str = "TransactionConflictException"
    sender_fault: bool = False
    status_code: int = 400


class TransactionInProgressException(ServiceException):
    code: str = "TransactionInProgressException"
    sender_fault: bool = False
    status_code: int = 400


Date = datetime


class ArchivalSummary(TypedDict, total=False):
    ArchivalDateTime: Date | None
    ArchivalReason: ArchivalReason | None
    ArchivalBackupArn: BackupArn | None


class AttributeDefinition(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    AttributeType: ScalarAttributeType


AttributeDefinitions = list[AttributeDefinition]
AttributeNameList = list[AttributeName]


class AttributeValueUpdate(TypedDict, total=False):
    Value: AttributeValue | None
    Action: AttributeAction | None


AttributeUpdates = dict[AttributeName, AttributeValueUpdate]
AttributeValueList = list[AttributeValue]


class AutoScalingTargetTrackingScalingPolicyConfigurationDescription(TypedDict, total=False):
    DisableScaleIn: BooleanObject | None
    ScaleInCooldown: IntegerObject | None
    ScaleOutCooldown: IntegerObject | None
    TargetValue: DoubleObject


class AutoScalingPolicyDescription(TypedDict, total=False):
    PolicyName: AutoScalingPolicyName | None
    TargetTrackingScalingPolicyConfiguration: (
        AutoScalingTargetTrackingScalingPolicyConfigurationDescription | None
    )


AutoScalingPolicyDescriptionList = list[AutoScalingPolicyDescription]


class AutoScalingTargetTrackingScalingPolicyConfigurationUpdate(TypedDict, total=False):
    DisableScaleIn: BooleanObject | None
    ScaleInCooldown: IntegerObject | None
    ScaleOutCooldown: IntegerObject | None
    TargetValue: DoubleObject


class AutoScalingPolicyUpdate(TypedDict, total=False):
    PolicyName: AutoScalingPolicyName | None
    TargetTrackingScalingPolicyConfiguration: (
        AutoScalingTargetTrackingScalingPolicyConfigurationUpdate
    )


PositiveLongObject = int


class AutoScalingSettingsDescription(TypedDict, total=False):
    MinimumUnits: PositiveLongObject | None
    MaximumUnits: PositiveLongObject | None
    AutoScalingDisabled: BooleanObject | None
    AutoScalingRoleArn: String | None
    ScalingPolicies: AutoScalingPolicyDescriptionList | None


class AutoScalingSettingsUpdate(TypedDict, total=False):
    MinimumUnits: PositiveLongObject | None
    MaximumUnits: PositiveLongObject | None
    AutoScalingDisabled: BooleanObject | None
    AutoScalingRoleArn: AutoScalingRoleArn | None
    ScalingPolicyUpdate: AutoScalingPolicyUpdate | None


BackupCreationDateTime = datetime


class SSEDescription(TypedDict, total=False):
    Status: SSEStatus | None
    SSEType: SSEType | None
    KMSMasterKeyArn: KMSMasterKeyArn | None
    InaccessibleEncryptionDateTime: Date | None


class TimeToLiveDescription(TypedDict, total=False):
    TimeToLiveStatus: TimeToLiveStatus | None
    AttributeName: TimeToLiveAttributeName | None


class StreamSpecification(TypedDict, total=False):
    StreamEnabled: StreamEnabled
    StreamViewType: StreamViewType | None


LongObject = int


class OnDemandThroughput(TypedDict, total=False):
    MaxReadRequestUnits: LongObject | None
    MaxWriteRequestUnits: LongObject | None


class ProvisionedThroughput(TypedDict, total=False):
    ReadCapacityUnits: PositiveLongObject
    WriteCapacityUnits: PositiveLongObject


NonKeyAttributeNameList = list[NonKeyAttributeName]


class Projection(TypedDict, total=False):
    ProjectionType: ProjectionType | None
    NonKeyAttributes: NonKeyAttributeNameList | None


class KeySchemaElement(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    KeyType: KeyType


KeySchema = list[KeySchemaElement]


class GlobalSecondaryIndexInfo(TypedDict, total=False):
    IndexName: IndexName | None
    KeySchema: KeySchema | None
    Projection: Projection | None
    ProvisionedThroughput: ProvisionedThroughput | None
    OnDemandThroughput: OnDemandThroughput | None


GlobalSecondaryIndexes = list[GlobalSecondaryIndexInfo]


class LocalSecondaryIndexInfo(TypedDict, total=False):
    IndexName: IndexName | None
    KeySchema: KeySchema | None
    Projection: Projection | None


LocalSecondaryIndexes = list[LocalSecondaryIndexInfo]


class SourceTableFeatureDetails(TypedDict, total=False):
    LocalSecondaryIndexes: LocalSecondaryIndexes | None
    GlobalSecondaryIndexes: GlobalSecondaryIndexes | None
    StreamDescription: StreamSpecification | None
    TimeToLiveDescription: TimeToLiveDescription | None
    SSEDescription: SSEDescription | None


ItemCount = int
TableCreationDateTime = datetime


class SourceTableDetails(TypedDict, total=False):
    TableName: TableName
    TableId: TableId
    TableArn: TableArn | None
    TableSizeBytes: LongObject | None
    KeySchema: KeySchema
    TableCreationDateTime: TableCreationDateTime
    ProvisionedThroughput: ProvisionedThroughput
    OnDemandThroughput: OnDemandThroughput | None
    ItemCount: ItemCount | None
    BillingMode: BillingMode | None


BackupSizeBytes = int


class BackupDetails(TypedDict, total=False):
    BackupArn: BackupArn
    BackupName: BackupName
    BackupSizeBytes: BackupSizeBytes | None
    BackupStatus: BackupStatus
    BackupType: BackupType
    BackupCreationDateTime: BackupCreationDateTime
    BackupExpiryDateTime: Date | None


class BackupDescription(TypedDict, total=False):
    BackupDetails: BackupDetails | None
    SourceTableDetails: SourceTableDetails | None
    SourceTableFeatureDetails: SourceTableFeatureDetails | None


class BackupSummary(TypedDict, total=False):
    TableName: TableName | None
    TableId: TableId | None
    TableArn: TableArn | None
    BackupArn: BackupArn | None
    BackupName: BackupName | None
    BackupCreationDateTime: BackupCreationDateTime | None
    BackupExpiryDateTime: Date | None
    BackupStatus: BackupStatus | None
    BackupType: BackupType | None
    BackupSizeBytes: BackupSizeBytes | None


BackupSummaries = list[BackupSummary]
PreparedStatementParameters = list[AttributeValue]


class BatchStatementRequest(TypedDict, total=False):
    Statement: PartiQLStatement
    Parameters: PreparedStatementParameters | None
    ConsistentRead: ConsistentRead | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


PartiQLBatchRequest = list[BatchStatementRequest]


class BatchExecuteStatementInput(ServiceRequest):
    Statements: PartiQLBatchRequest
    ReturnConsumedCapacity: ReturnConsumedCapacity | None


class Capacity(TypedDict, total=False):
    ReadCapacityUnits: ConsumedCapacityUnits | None
    WriteCapacityUnits: ConsumedCapacityUnits | None
    CapacityUnits: ConsumedCapacityUnits | None


SecondaryIndexesCapacityMap = dict[IndexName, Capacity]


class ConsumedCapacity(TypedDict, total=False):
    TableName: TableArn | None
    CapacityUnits: ConsumedCapacityUnits | None
    ReadCapacityUnits: ConsumedCapacityUnits | None
    WriteCapacityUnits: ConsumedCapacityUnits | None
    Table: Capacity | None
    LocalSecondaryIndexes: SecondaryIndexesCapacityMap | None
    GlobalSecondaryIndexes: SecondaryIndexesCapacityMap | None


ConsumedCapacityMultiple = list[ConsumedCapacity]


class BatchStatementError(TypedDict, total=False):
    Code: BatchStatementErrorCodeEnum | None
    Message: String | None
    Item: AttributeMap | None


class BatchStatementResponse(TypedDict, total=False):
    Error: BatchStatementError | None
    TableName: TableName | None
    Item: AttributeMap | None


PartiQLBatchResponse = list[BatchStatementResponse]


class BatchExecuteStatementOutput(TypedDict, total=False):
    Responses: PartiQLBatchResponse | None
    ConsumedCapacity: ConsumedCapacityMultiple | None


ExpressionAttributeNameMap = dict[ExpressionAttributeNameVariable, AttributeName]
Key = dict[AttributeName, AttributeValue]
KeyList = list[Key]


class KeysAndAttributes(TypedDict, total=False):
    Keys: KeyList
    AttributesToGet: AttributeNameList | None
    ConsistentRead: ConsistentRead | None
    ProjectionExpression: ProjectionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None


BatchGetRequestMap = dict[TableArn, KeysAndAttributes]


class BatchGetItemInput(ServiceRequest):
    RequestItems: BatchGetRequestMap
    ReturnConsumedCapacity: ReturnConsumedCapacity | None


ItemList = list[AttributeMap]
BatchGetResponseMap = dict[TableArn, ItemList]


class BatchGetItemOutput(TypedDict, total=False):
    Responses: BatchGetResponseMap | None
    UnprocessedKeys: BatchGetRequestMap | None
    ConsumedCapacity: ConsumedCapacityMultiple | None


class DeleteRequest(TypedDict, total=False):
    Key: Key


PutItemInputAttributeMap = dict[AttributeName, AttributeValue]


class PutRequest(TypedDict, total=False):
    Item: PutItemInputAttributeMap


class WriteRequest(TypedDict, total=False):
    PutRequest: PutRequest | None
    DeleteRequest: DeleteRequest | None


WriteRequests = list[WriteRequest]
BatchWriteItemRequestMap = dict[TableArn, WriteRequests]


class BatchWriteItemInput(ServiceRequest):
    RequestItems: BatchWriteItemRequestMap
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ReturnItemCollectionMetrics: ReturnItemCollectionMetrics | None


ItemCollectionSizeEstimateRange = list[ItemCollectionSizeEstimateBound]
ItemCollectionKeyAttributeMap = dict[AttributeName, AttributeValue]


class ItemCollectionMetrics(TypedDict, total=False):
    ItemCollectionKey: ItemCollectionKeyAttributeMap | None
    SizeEstimateRangeGB: ItemCollectionSizeEstimateRange | None


ItemCollectionMetricsMultiple = list[ItemCollectionMetrics]
ItemCollectionMetricsPerTable = dict[TableArn, ItemCollectionMetricsMultiple]


class BatchWriteItemOutput(TypedDict, total=False):
    UnprocessedItems: BatchWriteItemRequestMap | None
    ItemCollectionMetrics: ItemCollectionMetricsPerTable | None
    ConsumedCapacity: ConsumedCapacityMultiple | None


BilledSizeBytes = int


class BillingModeSummary(TypedDict, total=False):
    BillingMode: BillingMode | None
    LastUpdateToPayPerRequestDateTime: Date | None


class Condition(TypedDict, total=False):
    AttributeValueList: AttributeValueList | None
    ComparisonOperator: ComparisonOperator


ExpressionAttributeValueMap = dict[ExpressionAttributeValueVariable, AttributeValue]


class ConditionCheck(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ConditionExpression: ConditionExpression
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class PointInTimeRecoveryDescription(TypedDict, total=False):
    PointInTimeRecoveryStatus: PointInTimeRecoveryStatus | None
    RecoveryPeriodInDays: RecoveryPeriodInDays | None
    EarliestRestorableDateTime: Date | None
    LatestRestorableDateTime: Date | None


class ContinuousBackupsDescription(TypedDict, total=False):
    ContinuousBackupsStatus: ContinuousBackupsStatus
    PointInTimeRecoveryDescription: PointInTimeRecoveryDescription | None


ContributorInsightsRuleList = list[ContributorInsightsRule]


class ContributorInsightsSummary(TypedDict, total=False):
    TableName: TableName | None
    IndexName: IndexName | None
    ContributorInsightsStatus: ContributorInsightsStatus | None
    ContributorInsightsMode: ContributorInsightsMode | None


ContributorInsightsSummaries = list[ContributorInsightsSummary]


class CreateBackupInput(ServiceRequest):
    TableName: TableArn
    BackupName: BackupName


class CreateBackupOutput(TypedDict, total=False):
    BackupDetails: BackupDetails | None


class WarmThroughput(TypedDict, total=False):
    ReadUnitsPerSecond: LongObject | None
    WriteUnitsPerSecond: LongObject | None


class CreateGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection
    ProvisionedThroughput: ProvisionedThroughput | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: WarmThroughput | None


class Replica(TypedDict, total=False):
    RegionName: RegionName | None


ReplicaList = list[Replica]


class CreateGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName
    ReplicationGroup: ReplicaList


class TableClassSummary(TypedDict, total=False):
    TableClass: TableClass | None
    LastUpdateDateTime: Date | None


class GlobalSecondaryIndexWarmThroughputDescription(TypedDict, total=False):
    ReadUnitsPerSecond: PositiveLongObject | None
    WriteUnitsPerSecond: PositiveLongObject | None
    Status: IndexStatus | None


class OnDemandThroughputOverride(TypedDict, total=False):
    MaxReadRequestUnits: LongObject | None


class ProvisionedThroughputOverride(TypedDict, total=False):
    ReadCapacityUnits: PositiveLongObject | None


class ReplicaGlobalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: IndexName | None
    ProvisionedThroughputOverride: ProvisionedThroughputOverride | None
    OnDemandThroughputOverride: OnDemandThroughputOverride | None
    WarmThroughput: GlobalSecondaryIndexWarmThroughputDescription | None


ReplicaGlobalSecondaryIndexDescriptionList = list[ReplicaGlobalSecondaryIndexDescription]


class TableWarmThroughputDescription(TypedDict, total=False):
    ReadUnitsPerSecond: PositiveLongObject | None
    WriteUnitsPerSecond: PositiveLongObject | None
    Status: TableStatus | None


class ReplicaDescription(TypedDict, total=False):
    RegionName: RegionName | None
    ReplicaStatus: ReplicaStatus | None
    ReplicaStatusDescription: ReplicaStatusDescription | None
    ReplicaStatusPercentProgress: ReplicaStatusPercentProgress | None
    KMSMasterKeyId: KMSMasterKeyId | None
    ProvisionedThroughputOverride: ProvisionedThroughputOverride | None
    OnDemandThroughputOverride: OnDemandThroughputOverride | None
    WarmThroughput: TableWarmThroughputDescription | None
    GlobalSecondaryIndexes: ReplicaGlobalSecondaryIndexDescriptionList | None
    ReplicaInaccessibleDateTime: Date | None
    ReplicaTableClassSummary: TableClassSummary | None


ReplicaDescriptionList = list[ReplicaDescription]


class GlobalTableDescription(TypedDict, total=False):
    ReplicationGroup: ReplicaDescriptionList | None
    GlobalTableArn: GlobalTableArnString | None
    CreationDateTime: Date | None
    GlobalTableStatus: GlobalTableStatus | None
    GlobalTableName: TableName | None


class CreateGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: GlobalTableDescription | None


class CreateGlobalTableWitnessGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName


class CreateReplicaAction(TypedDict, total=False):
    RegionName: RegionName


class ReplicaGlobalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedThroughputOverride: ProvisionedThroughputOverride | None
    OnDemandThroughputOverride: OnDemandThroughputOverride | None


ReplicaGlobalSecondaryIndexList = list[ReplicaGlobalSecondaryIndex]


class CreateReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName
    KMSMasterKeyId: KMSMasterKeyId | None
    ProvisionedThroughputOverride: ProvisionedThroughputOverride | None
    OnDemandThroughputOverride: OnDemandThroughputOverride | None
    GlobalSecondaryIndexes: ReplicaGlobalSecondaryIndexList | None
    TableClassOverride: TableClass | None


class Tag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


TagList = list[Tag]


class SSESpecification(TypedDict, total=False):
    Enabled: SSEEnabled | None
    SSEType: SSEType | None
    KMSMasterKeyId: KMSMasterKeyId | None


class GlobalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection
    ProvisionedThroughput: ProvisionedThroughput | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: WarmThroughput | None


GlobalSecondaryIndexList = list[GlobalSecondaryIndex]


class LocalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection


LocalSecondaryIndexList = list[LocalSecondaryIndex]


class CreateTableInput(ServiceRequest):
    AttributeDefinitions: AttributeDefinitions
    TableName: TableArn
    KeySchema: KeySchema
    LocalSecondaryIndexes: LocalSecondaryIndexList | None
    GlobalSecondaryIndexes: GlobalSecondaryIndexList | None
    BillingMode: BillingMode | None
    ProvisionedThroughput: ProvisionedThroughput | None
    StreamSpecification: StreamSpecification | None
    SSESpecification: SSESpecification | None
    Tags: TagList | None
    TableClass: TableClass | None
    DeletionProtectionEnabled: DeletionProtectionEnabled | None
    WarmThroughput: WarmThroughput | None
    ResourcePolicy: ResourcePolicy | None
    OnDemandThroughput: OnDemandThroughput | None


class RestoreSummary(TypedDict, total=False):
    SourceBackupArn: BackupArn | None
    SourceTableArn: TableArn | None
    RestoreDateTime: Date
    RestoreInProgress: RestoreInProgress


class GlobalTableWitnessDescription(TypedDict, total=False):
    RegionName: RegionName | None
    WitnessStatus: WitnessStatus | None


GlobalTableWitnessDescriptionList = list[GlobalTableWitnessDescription]
NonNegativeLongObject = int


class ProvisionedThroughputDescription(TypedDict, total=False):
    LastIncreaseDateTime: Date | None
    LastDecreaseDateTime: Date | None
    NumberOfDecreasesToday: PositiveLongObject | None
    ReadCapacityUnits: NonNegativeLongObject | None
    WriteCapacityUnits: NonNegativeLongObject | None


class GlobalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: IndexName | None
    KeySchema: KeySchema | None
    Projection: Projection | None
    IndexStatus: IndexStatus | None
    Backfilling: Backfilling | None
    ProvisionedThroughput: ProvisionedThroughputDescription | None
    IndexSizeBytes: LongObject | None
    ItemCount: LongObject | None
    IndexArn: String | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: GlobalSecondaryIndexWarmThroughputDescription | None


GlobalSecondaryIndexDescriptionList = list[GlobalSecondaryIndexDescription]


class LocalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: IndexName | None
    KeySchema: KeySchema | None
    Projection: Projection | None
    IndexSizeBytes: LongObject | None
    ItemCount: LongObject | None
    IndexArn: String | None


LocalSecondaryIndexDescriptionList = list[LocalSecondaryIndexDescription]


class TableDescription(TypedDict, total=False):
    AttributeDefinitions: AttributeDefinitions | None
    TableName: TableName | None
    KeySchema: KeySchema | None
    TableStatus: TableStatus | None
    CreationDateTime: Date | None
    ProvisionedThroughput: ProvisionedThroughputDescription | None
    TableSizeBytes: LongObject | None
    ItemCount: LongObject | None
    TableArn: String | None
    TableId: TableId | None
    BillingModeSummary: BillingModeSummary | None
    LocalSecondaryIndexes: LocalSecondaryIndexDescriptionList | None
    GlobalSecondaryIndexes: GlobalSecondaryIndexDescriptionList | None
    StreamSpecification: StreamSpecification | None
    LatestStreamLabel: String | None
    LatestStreamArn: StreamArn | None
    GlobalTableVersion: String | None
    Replicas: ReplicaDescriptionList | None
    GlobalTableWitnesses: GlobalTableWitnessDescriptionList | None
    RestoreSummary: RestoreSummary | None
    SSEDescription: SSEDescription | None
    ArchivalSummary: ArchivalSummary | None
    TableClassSummary: TableClassSummary | None
    DeletionProtectionEnabled: DeletionProtectionEnabled | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: TableWarmThroughputDescription | None
    MultiRegionConsistency: MultiRegionConsistency | None


class CreateTableOutput(TypedDict, total=False):
    TableDescription: TableDescription | None


CsvHeaderList = list[CsvHeader]


class CsvOptions(TypedDict, total=False):
    Delimiter: CsvDelimiter | None
    HeaderList: CsvHeaderList | None


class Delete(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class DeleteBackupInput(ServiceRequest):
    BackupArn: BackupArn


class DeleteBackupOutput(TypedDict, total=False):
    BackupDescription: BackupDescription | None


class DeleteGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName


class DeleteGlobalTableWitnessGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName


class ExpectedAttributeValue(TypedDict, total=False):
    Value: AttributeValue | None
    Exists: BooleanObject | None
    ComparisonOperator: ComparisonOperator | None
    AttributeValueList: AttributeValueList | None


ExpectedAttributeMap = dict[AttributeName, ExpectedAttributeValue]


class DeleteItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    Expected: ExpectedAttributeMap | None
    ConditionalOperator: ConditionalOperator | None
    ReturnValues: ReturnValue | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ReturnItemCollectionMetrics: ReturnItemCollectionMetrics | None
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class DeleteItemOutput(TypedDict, total=False):
    Attributes: AttributeMap | None
    ConsumedCapacity: ConsumedCapacity | None
    ItemCollectionMetrics: ItemCollectionMetrics | None


class DeleteReplicaAction(TypedDict, total=False):
    RegionName: RegionName


class DeleteReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName


class DeleteResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString
    ExpectedRevisionId: PolicyRevisionId | None


class DeleteResourcePolicyOutput(TypedDict, total=False):
    RevisionId: PolicyRevisionId | None


class DeleteTableInput(ServiceRequest):
    TableName: TableArn


class DeleteTableOutput(TypedDict, total=False):
    TableDescription: TableDescription | None


class DescribeBackupInput(ServiceRequest):
    BackupArn: BackupArn


class DescribeBackupOutput(TypedDict, total=False):
    BackupDescription: BackupDescription | None


class DescribeContinuousBackupsInput(ServiceRequest):
    TableName: TableArn


class DescribeContinuousBackupsOutput(TypedDict, total=False):
    ContinuousBackupsDescription: ContinuousBackupsDescription | None


class DescribeContributorInsightsInput(ServiceRequest):
    TableName: TableArn
    IndexName: IndexName | None


class FailureException(TypedDict, total=False):
    ExceptionName: ExceptionName | None
    ExceptionDescription: ExceptionDescription | None


LastUpdateDateTime = datetime


class DescribeContributorInsightsOutput(TypedDict, total=False):
    TableName: TableName | None
    IndexName: IndexName | None
    ContributorInsightsRuleList: ContributorInsightsRuleList | None
    ContributorInsightsStatus: ContributorInsightsStatus | None
    LastUpdateDateTime: LastUpdateDateTime | None
    FailureException: FailureException | None
    ContributorInsightsMode: ContributorInsightsMode | None


class DescribeEndpointsRequest(ServiceRequest):
    pass


Long = int


class Endpoint(TypedDict, total=False):
    Address: String
    CachePeriodInMinutes: Long


Endpoints = list[Endpoint]


class DescribeEndpointsResponse(TypedDict, total=False):
    Endpoints: Endpoints


class DescribeExportInput(ServiceRequest):
    ExportArn: ExportArn


ExportToTime = datetime
ExportFromTime = datetime


class IncrementalExportSpecification(TypedDict, total=False):
    ExportFromTime: ExportFromTime | None
    ExportToTime: ExportToTime | None
    ExportViewType: ExportViewType | None


ExportTime = datetime
ExportEndTime = datetime
ExportStartTime = datetime


class ExportDescription(TypedDict, total=False):
    ExportArn: ExportArn | None
    ExportStatus: ExportStatus | None
    StartTime: ExportStartTime | None
    EndTime: ExportEndTime | None
    ExportManifest: ExportManifest | None
    TableArn: TableArn | None
    TableId: TableId | None
    ExportTime: ExportTime | None
    ClientToken: ClientToken | None
    S3Bucket: S3Bucket | None
    S3BucketOwner: S3BucketOwner | None
    S3Prefix: S3Prefix | None
    S3SseAlgorithm: S3SseAlgorithm | None
    S3SseKmsKeyId: S3SseKmsKeyId | None
    FailureCode: FailureCode | None
    FailureMessage: FailureMessage | None
    ExportFormat: ExportFormat | None
    BilledSizeBytes: BilledSizeBytes | None
    ItemCount: ItemCount | None
    ExportType: ExportType | None
    IncrementalExportSpecification: IncrementalExportSpecification | None


class DescribeExportOutput(TypedDict, total=False):
    ExportDescription: ExportDescription | None


class DescribeGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName


class DescribeGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: GlobalTableDescription | None


class DescribeGlobalTableSettingsInput(ServiceRequest):
    GlobalTableName: TableName


class ReplicaGlobalSecondaryIndexSettingsDescription(TypedDict, total=False):
    IndexName: IndexName
    IndexStatus: IndexStatus | None
    ProvisionedReadCapacityUnits: PositiveLongObject | None
    ProvisionedReadCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ProvisionedWriteCapacityUnits: PositiveLongObject | None
    ProvisionedWriteCapacityAutoScalingSettings: AutoScalingSettingsDescription | None


ReplicaGlobalSecondaryIndexSettingsDescriptionList = list[
    ReplicaGlobalSecondaryIndexSettingsDescription
]


class ReplicaSettingsDescription(TypedDict, total=False):
    RegionName: RegionName
    ReplicaStatus: ReplicaStatus | None
    ReplicaBillingModeSummary: BillingModeSummary | None
    ReplicaProvisionedReadCapacityUnits: NonNegativeLongObject | None
    ReplicaProvisionedReadCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ReplicaProvisionedWriteCapacityUnits: NonNegativeLongObject | None
    ReplicaProvisionedWriteCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ReplicaGlobalSecondaryIndexSettings: ReplicaGlobalSecondaryIndexSettingsDescriptionList | None
    ReplicaTableClassSummary: TableClassSummary | None


ReplicaSettingsDescriptionList = list[ReplicaSettingsDescription]


class DescribeGlobalTableSettingsOutput(TypedDict, total=False):
    GlobalTableName: TableName | None
    ReplicaSettings: ReplicaSettingsDescriptionList | None


class DescribeImportInput(ServiceRequest):
    ImportArn: ImportArn


ImportedItemCount = int
ProcessedItemCount = int
ImportEndTime = datetime
ImportStartTime = datetime


class TableCreationParameters(TypedDict, total=False):
    TableName: TableName
    AttributeDefinitions: AttributeDefinitions
    KeySchema: KeySchema
    BillingMode: BillingMode | None
    ProvisionedThroughput: ProvisionedThroughput | None
    OnDemandThroughput: OnDemandThroughput | None
    SSESpecification: SSESpecification | None
    GlobalSecondaryIndexes: GlobalSecondaryIndexList | None


class InputFormatOptions(TypedDict, total=False):
    Csv: CsvOptions | None


ErrorCount = int


class S3BucketSource(TypedDict, total=False):
    S3BucketOwner: S3BucketOwner | None
    S3Bucket: S3Bucket
    S3KeyPrefix: S3Prefix | None


class ImportTableDescription(TypedDict, total=False):
    ImportArn: ImportArn | None
    ImportStatus: ImportStatus | None
    TableArn: TableArn | None
    TableId: TableId | None
    ClientToken: ClientToken | None
    S3BucketSource: S3BucketSource | None
    ErrorCount: ErrorCount | None
    CloudWatchLogGroupArn: CloudWatchLogGroupArn | None
    InputFormat: InputFormat | None
    InputFormatOptions: InputFormatOptions | None
    InputCompressionType: InputCompressionType | None
    TableCreationParameters: TableCreationParameters | None
    StartTime: ImportStartTime | None
    EndTime: ImportEndTime | None
    ProcessedSizeBytes: LongObject | None
    ProcessedItemCount: ProcessedItemCount | None
    ImportedItemCount: ImportedItemCount | None
    FailureCode: FailureCode | None
    FailureMessage: FailureMessage | None


class DescribeImportOutput(TypedDict, total=False):
    ImportTableDescription: ImportTableDescription


class DescribeKinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn


class KinesisDataStreamDestination(TypedDict, total=False):
    StreamArn: StreamArn | None
    DestinationStatus: DestinationStatus | None
    DestinationStatusDescription: String | None
    ApproximateCreationDateTimePrecision: ApproximateCreationDateTimePrecision | None


KinesisDataStreamDestinations = list[KinesisDataStreamDestination]


class DescribeKinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: TableName | None
    KinesisDataStreamDestinations: KinesisDataStreamDestinations | None


class DescribeLimitsInput(ServiceRequest):
    pass


class DescribeLimitsOutput(TypedDict, total=False):
    AccountMaxReadCapacityUnits: PositiveLongObject | None
    AccountMaxWriteCapacityUnits: PositiveLongObject | None
    TableMaxReadCapacityUnits: PositiveLongObject | None
    TableMaxWriteCapacityUnits: PositiveLongObject | None


class DescribeTableInput(ServiceRequest):
    TableName: TableArn


class DescribeTableOutput(TypedDict, total=False):
    Table: TableDescription | None


class DescribeTableReplicaAutoScalingInput(ServiceRequest):
    TableName: TableArn


class ReplicaGlobalSecondaryIndexAutoScalingDescription(TypedDict, total=False):
    IndexName: IndexName | None
    IndexStatus: IndexStatus | None
    ProvisionedReadCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ProvisionedWriteCapacityAutoScalingSettings: AutoScalingSettingsDescription | None


ReplicaGlobalSecondaryIndexAutoScalingDescriptionList = list[
    ReplicaGlobalSecondaryIndexAutoScalingDescription
]


class ReplicaAutoScalingDescription(TypedDict, total=False):
    RegionName: RegionName | None
    GlobalSecondaryIndexes: ReplicaGlobalSecondaryIndexAutoScalingDescriptionList | None
    ReplicaProvisionedReadCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ReplicaProvisionedWriteCapacityAutoScalingSettings: AutoScalingSettingsDescription | None
    ReplicaStatus: ReplicaStatus | None


ReplicaAutoScalingDescriptionList = list[ReplicaAutoScalingDescription]


class TableAutoScalingDescription(TypedDict, total=False):
    TableName: TableName | None
    TableStatus: TableStatus | None
    Replicas: ReplicaAutoScalingDescriptionList | None


class DescribeTableReplicaAutoScalingOutput(TypedDict, total=False):
    TableAutoScalingDescription: TableAutoScalingDescription | None


class DescribeTimeToLiveInput(ServiceRequest):
    TableName: TableArn


class DescribeTimeToLiveOutput(TypedDict, total=False):
    TimeToLiveDescription: TimeToLiveDescription | None


class EnableKinesisStreamingConfiguration(TypedDict, total=False):
    ApproximateCreationDateTimePrecision: ApproximateCreationDateTimePrecision | None


class ExecuteStatementInput(ServiceRequest):
    Statement: PartiQLStatement
    Parameters: PreparedStatementParameters | None
    ConsistentRead: ConsistentRead | None
    NextToken: PartiQLNextToken | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    Limit: PositiveIntegerObject | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class ExecuteStatementOutput(TypedDict, total=False):
    Items: ItemList | None
    NextToken: PartiQLNextToken | None
    ConsumedCapacity: ConsumedCapacity | None
    LastEvaluatedKey: Key | None


class ParameterizedStatement(TypedDict, total=False):
    Statement: PartiQLStatement
    Parameters: PreparedStatementParameters | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


ParameterizedStatements = list[ParameterizedStatement]


class ExecuteTransactionInput(ServiceRequest):
    TransactStatements: ParameterizedStatements
    ClientRequestToken: ClientRequestToken | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None


class ItemResponse(TypedDict, total=False):
    Item: AttributeMap | None


ItemResponseList = list[ItemResponse]


class ExecuteTransactionOutput(TypedDict, total=False):
    Responses: ItemResponseList | None
    ConsumedCapacity: ConsumedCapacityMultiple | None


class ExportSummary(TypedDict, total=False):
    ExportArn: ExportArn | None
    ExportStatus: ExportStatus | None
    ExportType: ExportType | None


ExportSummaries = list[ExportSummary]


class ExportTableToPointInTimeInput(ServiceRequest):
    TableArn: TableArn
    ExportTime: ExportTime | None
    ClientToken: ClientToken | None
    S3Bucket: S3Bucket
    S3BucketOwner: S3BucketOwner | None
    S3Prefix: S3Prefix | None
    S3SseAlgorithm: S3SseAlgorithm | None
    S3SseKmsKeyId: S3SseKmsKeyId | None
    ExportFormat: ExportFormat | None
    ExportType: ExportType | None
    IncrementalExportSpecification: IncrementalExportSpecification | None


class ExportTableToPointInTimeOutput(TypedDict, total=False):
    ExportDescription: ExportDescription | None


FilterConditionMap = dict[AttributeName, Condition]


class Get(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ProjectionExpression: ProjectionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None


class GetItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    AttributesToGet: AttributeNameList | None
    ConsistentRead: ConsistentRead | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ProjectionExpression: ProjectionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None


class GetItemOutput(TypedDict, total=False):
    Item: AttributeMap | None
    ConsumedCapacity: ConsumedCapacity | None


class GetResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString


class GetResourcePolicyOutput(TypedDict, total=False):
    Policy: ResourcePolicy | None
    RevisionId: PolicyRevisionId | None


class GlobalSecondaryIndexAutoScalingUpdate(TypedDict, total=False):
    IndexName: IndexName | None
    ProvisionedWriteCapacityAutoScalingUpdate: AutoScalingSettingsUpdate | None


GlobalSecondaryIndexAutoScalingUpdateList = list[GlobalSecondaryIndexAutoScalingUpdate]


class UpdateGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedThroughput: ProvisionedThroughput | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: WarmThroughput | None


class GlobalSecondaryIndexUpdate(TypedDict, total=False):
    Update: UpdateGlobalSecondaryIndexAction | None
    Create: CreateGlobalSecondaryIndexAction | None
    Delete: DeleteGlobalSecondaryIndexAction | None


GlobalSecondaryIndexUpdateList = list[GlobalSecondaryIndexUpdate]


class GlobalTable(TypedDict, total=False):
    GlobalTableName: TableName | None
    ReplicationGroup: ReplicaList | None


class GlobalTableGlobalSecondaryIndexSettingsUpdate(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedWriteCapacityUnits: PositiveLongObject | None
    ProvisionedWriteCapacityAutoScalingSettingsUpdate: AutoScalingSettingsUpdate | None


GlobalTableGlobalSecondaryIndexSettingsUpdateList = list[
    GlobalTableGlobalSecondaryIndexSettingsUpdate
]
GlobalTableList = list[GlobalTable]


class GlobalTableWitnessGroupUpdate(TypedDict, total=False):
    Create: CreateGlobalTableWitnessGroupMemberAction | None
    Delete: DeleteGlobalTableWitnessGroupMemberAction | None


GlobalTableWitnessGroupUpdateList = list[GlobalTableWitnessGroupUpdate]


class ImportSummary(TypedDict, total=False):
    ImportArn: ImportArn | None
    ImportStatus: ImportStatus | None
    TableArn: TableArn | None
    S3BucketSource: S3BucketSource | None
    CloudWatchLogGroupArn: CloudWatchLogGroupArn | None
    InputFormat: InputFormat | None
    StartTime: ImportStartTime | None
    EndTime: ImportEndTime | None


ImportSummaryList = list[ImportSummary]


class ImportTableInput(ServiceRequest):
    ClientToken: ClientToken | None
    S3BucketSource: S3BucketSource
    InputFormat: InputFormat
    InputFormatOptions: InputFormatOptions | None
    InputCompressionType: InputCompressionType | None
    TableCreationParameters: TableCreationParameters


class ImportTableOutput(TypedDict, total=False):
    ImportTableDescription: ImportTableDescription


KeyConditions = dict[AttributeName, Condition]


class KinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn
    StreamArn: StreamArn
    EnableKinesisStreamingConfiguration: EnableKinesisStreamingConfiguration | None


class KinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: TableName | None
    StreamArn: StreamArn | None
    DestinationStatus: DestinationStatus | None
    EnableKinesisStreamingConfiguration: EnableKinesisStreamingConfiguration | None


TimeRangeUpperBound = datetime
TimeRangeLowerBound = datetime


class ListBackupsInput(ServiceRequest):
    TableName: TableArn | None
    Limit: BackupsInputLimit | None
    TimeRangeLowerBound: TimeRangeLowerBound | None
    TimeRangeUpperBound: TimeRangeUpperBound | None
    ExclusiveStartBackupArn: BackupArn | None
    BackupType: BackupTypeFilter | None


class ListBackupsOutput(TypedDict, total=False):
    BackupSummaries: BackupSummaries | None
    LastEvaluatedBackupArn: BackupArn | None


class ListContributorInsightsInput(ServiceRequest):
    TableName: TableArn | None
    NextToken: NextTokenString | None
    MaxResults: ListContributorInsightsLimit | None


class ListContributorInsightsOutput(TypedDict, total=False):
    ContributorInsightsSummaries: ContributorInsightsSummaries | None
    NextToken: NextTokenString | None


class ListExportsInput(ServiceRequest):
    TableArn: TableArn | None
    MaxResults: ListExportsMaxLimit | None
    NextToken: ExportNextToken | None


class ListExportsOutput(TypedDict, total=False):
    ExportSummaries: ExportSummaries | None
    NextToken: ExportNextToken | None


class ListGlobalTablesInput(ServiceRequest):
    ExclusiveStartGlobalTableName: TableName | None
    Limit: PositiveIntegerObject | None
    RegionName: RegionName | None


class ListGlobalTablesOutput(TypedDict, total=False):
    GlobalTables: GlobalTableList | None
    LastEvaluatedGlobalTableName: TableName | None


class ListImportsInput(ServiceRequest):
    TableArn: TableArn | None
    PageSize: ListImportsMaxLimit | None
    NextToken: ImportNextToken | None


class ListImportsOutput(TypedDict, total=False):
    ImportSummaryList: ImportSummaryList | None
    NextToken: ImportNextToken | None


class ListTablesInput(ServiceRequest):
    ExclusiveStartTableName: TableName | None
    Limit: ListTablesInputLimit | None


TableNameList = list[TableName]


class ListTablesOutput(TypedDict, total=False):
    TableNames: TableNameList | None
    LastEvaluatedTableName: TableName | None


class ListTagsOfResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    NextToken: NextTokenString | None


class ListTagsOfResourceOutput(TypedDict, total=False):
    Tags: TagList | None
    NextToken: NextTokenString | None


class PointInTimeRecoverySpecification(TypedDict, total=False):
    PointInTimeRecoveryEnabled: BooleanObject
    RecoveryPeriodInDays: RecoveryPeriodInDays | None


class Put(TypedDict, total=False):
    Item: PutItemInputAttributeMap
    TableName: TableArn
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class PutItemInput(ServiceRequest):
    TableName: TableArn
    Item: PutItemInputAttributeMap
    Expected: ExpectedAttributeMap | None
    ReturnValues: ReturnValue | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ReturnItemCollectionMetrics: ReturnItemCollectionMetrics | None
    ConditionalOperator: ConditionalOperator | None
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class PutItemOutput(TypedDict, total=False):
    Attributes: AttributeMap | None
    ConsumedCapacity: ConsumedCapacity | None
    ItemCollectionMetrics: ItemCollectionMetrics | None


class PutResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString
    Policy: ResourcePolicy
    ExpectedRevisionId: PolicyRevisionId | None
    ConfirmRemoveSelfResourceAccess: ConfirmRemoveSelfResourceAccess | None


class PutResourcePolicyOutput(TypedDict, total=False):
    RevisionId: PolicyRevisionId | None


class QueryInput(ServiceRequest):
    TableName: TableArn
    IndexName: IndexName | None
    Select: Select | None
    AttributesToGet: AttributeNameList | None
    Limit: PositiveIntegerObject | None
    ConsistentRead: ConsistentRead | None
    KeyConditions: KeyConditions | None
    QueryFilter: FilterConditionMap | None
    ConditionalOperator: ConditionalOperator | None
    ScanIndexForward: BooleanObject | None
    ExclusiveStartKey: Key | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ProjectionExpression: ProjectionExpression | None
    FilterExpression: ConditionExpression | None
    KeyConditionExpression: KeyExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None


class QueryOutput(TypedDict, total=False):
    Items: ItemList | None
    Count: Integer | None
    ScannedCount: Integer | None
    LastEvaluatedKey: Key | None
    ConsumedCapacity: ConsumedCapacity | None


class ReplicaGlobalSecondaryIndexAutoScalingUpdate(TypedDict, total=False):
    IndexName: IndexName | None
    ProvisionedReadCapacityAutoScalingUpdate: AutoScalingSettingsUpdate | None


ReplicaGlobalSecondaryIndexAutoScalingUpdateList = list[
    ReplicaGlobalSecondaryIndexAutoScalingUpdate
]


class ReplicaAutoScalingUpdate(TypedDict, total=False):
    RegionName: RegionName
    ReplicaGlobalSecondaryIndexUpdates: ReplicaGlobalSecondaryIndexAutoScalingUpdateList | None
    ReplicaProvisionedReadCapacityAutoScalingUpdate: AutoScalingSettingsUpdate | None


ReplicaAutoScalingUpdateList = list[ReplicaAutoScalingUpdate]


class ReplicaGlobalSecondaryIndexSettingsUpdate(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedReadCapacityUnits: PositiveLongObject | None
    ProvisionedReadCapacityAutoScalingSettingsUpdate: AutoScalingSettingsUpdate | None


ReplicaGlobalSecondaryIndexSettingsUpdateList = list[ReplicaGlobalSecondaryIndexSettingsUpdate]


class ReplicaSettingsUpdate(TypedDict, total=False):
    RegionName: RegionName
    ReplicaProvisionedReadCapacityUnits: PositiveLongObject | None
    ReplicaProvisionedReadCapacityAutoScalingSettingsUpdate: AutoScalingSettingsUpdate | None
    ReplicaGlobalSecondaryIndexSettingsUpdate: ReplicaGlobalSecondaryIndexSettingsUpdateList | None
    ReplicaTableClass: TableClass | None


ReplicaSettingsUpdateList = list[ReplicaSettingsUpdate]


class ReplicaUpdate(TypedDict, total=False):
    Create: CreateReplicaAction | None
    Delete: DeleteReplicaAction | None


ReplicaUpdateList = list[ReplicaUpdate]


class UpdateReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName
    KMSMasterKeyId: KMSMasterKeyId | None
    ProvisionedThroughputOverride: ProvisionedThroughputOverride | None
    OnDemandThroughputOverride: OnDemandThroughputOverride | None
    GlobalSecondaryIndexes: ReplicaGlobalSecondaryIndexList | None
    TableClassOverride: TableClass | None


class ReplicationGroupUpdate(TypedDict, total=False):
    Create: CreateReplicationGroupMemberAction | None
    Update: UpdateReplicationGroupMemberAction | None
    Delete: DeleteReplicationGroupMemberAction | None


ReplicationGroupUpdateList = list[ReplicationGroupUpdate]


class RestoreTableFromBackupInput(ServiceRequest):
    TargetTableName: TableName
    BackupArn: BackupArn
    BillingModeOverride: BillingMode | None
    GlobalSecondaryIndexOverride: GlobalSecondaryIndexList | None
    LocalSecondaryIndexOverride: LocalSecondaryIndexList | None
    ProvisionedThroughputOverride: ProvisionedThroughput | None
    OnDemandThroughputOverride: OnDemandThroughput | None
    SSESpecificationOverride: SSESpecification | None


class RestoreTableFromBackupOutput(TypedDict, total=False):
    TableDescription: TableDescription | None


class RestoreTableToPointInTimeInput(ServiceRequest):
    SourceTableArn: TableArn | None
    SourceTableName: TableName | None
    TargetTableName: TableName
    UseLatestRestorableTime: BooleanObject | None
    RestoreDateTime: Date | None
    BillingModeOverride: BillingMode | None
    GlobalSecondaryIndexOverride: GlobalSecondaryIndexList | None
    LocalSecondaryIndexOverride: LocalSecondaryIndexList | None
    ProvisionedThroughputOverride: ProvisionedThroughput | None
    OnDemandThroughputOverride: OnDemandThroughput | None
    SSESpecificationOverride: SSESpecification | None


class RestoreTableToPointInTimeOutput(TypedDict, total=False):
    TableDescription: TableDescription | None


class ScanInput(ServiceRequest):
    TableName: TableArn
    IndexName: IndexName | None
    AttributesToGet: AttributeNameList | None
    Limit: PositiveIntegerObject | None
    Select: Select | None
    ScanFilter: FilterConditionMap | None
    ConditionalOperator: ConditionalOperator | None
    ExclusiveStartKey: Key | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    TotalSegments: ScanTotalSegments | None
    Segment: ScanSegment | None
    ProjectionExpression: ProjectionExpression | None
    FilterExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ConsistentRead: ConsistentRead | None


class ScanOutput(TypedDict, total=False):
    Items: ItemList | None
    Count: Integer | None
    ScannedCount: Integer | None
    LastEvaluatedKey: Key | None
    ConsumedCapacity: ConsumedCapacity | None


TagKeyList = list[TagKeyString]


class TagResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    Tags: TagList


class TimeToLiveSpecification(TypedDict, total=False):
    Enabled: TimeToLiveEnabled
    AttributeName: TimeToLiveAttributeName


class TransactGetItem(TypedDict, total=False):
    Get: Get


TransactGetItemList = list[TransactGetItem]


class TransactGetItemsInput(ServiceRequest):
    TransactItems: TransactGetItemList
    ReturnConsumedCapacity: ReturnConsumedCapacity | None


class TransactGetItemsOutput(TypedDict, total=False):
    ConsumedCapacity: ConsumedCapacityMultiple | None
    Responses: ItemResponseList | None


class Update(TypedDict, total=False):
    Key: Key
    UpdateExpression: UpdateExpression
    TableName: TableArn
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class TransactWriteItem(TypedDict, total=False):
    ConditionCheck: ConditionCheck | None
    Put: Put | None
    Delete: Delete | None
    Update: Update | None


TransactWriteItemList = list[TransactWriteItem]


class TransactWriteItemsInput(ServiceRequest):
    TransactItems: TransactWriteItemList
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ReturnItemCollectionMetrics: ReturnItemCollectionMetrics | None
    ClientRequestToken: ClientRequestToken | None


class TransactWriteItemsOutput(TypedDict, total=False):
    ConsumedCapacity: ConsumedCapacityMultiple | None
    ItemCollectionMetrics: ItemCollectionMetricsPerTable | None


class UntagResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    TagKeys: TagKeyList


class UpdateContinuousBackupsInput(ServiceRequest):
    TableName: TableArn
    PointInTimeRecoverySpecification: PointInTimeRecoverySpecification


class UpdateContinuousBackupsOutput(TypedDict, total=False):
    ContinuousBackupsDescription: ContinuousBackupsDescription | None


class UpdateContributorInsightsInput(ServiceRequest):
    TableName: TableArn
    IndexName: IndexName | None
    ContributorInsightsAction: ContributorInsightsAction
    ContributorInsightsMode: ContributorInsightsMode | None


class UpdateContributorInsightsOutput(TypedDict, total=False):
    TableName: TableName | None
    IndexName: IndexName | None
    ContributorInsightsStatus: ContributorInsightsStatus | None
    ContributorInsightsMode: ContributorInsightsMode | None


class UpdateGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName
    ReplicaUpdates: ReplicaUpdateList


class UpdateGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: GlobalTableDescription | None


class UpdateGlobalTableSettingsInput(ServiceRequest):
    GlobalTableName: TableName
    GlobalTableBillingMode: BillingMode | None
    GlobalTableProvisionedWriteCapacityUnits: PositiveLongObject | None
    GlobalTableProvisionedWriteCapacityAutoScalingSettingsUpdate: AutoScalingSettingsUpdate | None
    GlobalTableGlobalSecondaryIndexSettingsUpdate: (
        GlobalTableGlobalSecondaryIndexSettingsUpdateList | None
    )
    ReplicaSettingsUpdate: ReplicaSettingsUpdateList | None


class UpdateGlobalTableSettingsOutput(TypedDict, total=False):
    GlobalTableName: TableName | None
    ReplicaSettings: ReplicaSettingsDescriptionList | None


class UpdateItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    AttributeUpdates: AttributeUpdates | None
    Expected: ExpectedAttributeMap | None
    ConditionalOperator: ConditionalOperator | None
    ReturnValues: ReturnValue | None
    ReturnConsumedCapacity: ReturnConsumedCapacity | None
    ReturnItemCollectionMetrics: ReturnItemCollectionMetrics | None
    UpdateExpression: UpdateExpression | None
    ConditionExpression: ConditionExpression | None
    ExpressionAttributeNames: ExpressionAttributeNameMap | None
    ExpressionAttributeValues: ExpressionAttributeValueMap | None
    ReturnValuesOnConditionCheckFailure: ReturnValuesOnConditionCheckFailure | None


class UpdateItemOutput(TypedDict, total=False):
    Attributes: AttributeMap | None
    ConsumedCapacity: ConsumedCapacity | None
    ItemCollectionMetrics: ItemCollectionMetrics | None


class UpdateKinesisStreamingConfiguration(TypedDict, total=False):
    ApproximateCreationDateTimePrecision: ApproximateCreationDateTimePrecision | None


class UpdateKinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn
    StreamArn: StreamArn
    UpdateKinesisStreamingConfiguration: UpdateKinesisStreamingConfiguration | None


class UpdateKinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: TableName | None
    StreamArn: StreamArn | None
    DestinationStatus: DestinationStatus | None
    UpdateKinesisStreamingConfiguration: UpdateKinesisStreamingConfiguration | None


class UpdateTableInput(ServiceRequest):
    AttributeDefinitions: AttributeDefinitions | None
    TableName: TableArn
    BillingMode: BillingMode | None
    ProvisionedThroughput: ProvisionedThroughput | None
    GlobalSecondaryIndexUpdates: GlobalSecondaryIndexUpdateList | None
    StreamSpecification: StreamSpecification | None
    SSESpecification: SSESpecification | None
    ReplicaUpdates: ReplicationGroupUpdateList | None
    TableClass: TableClass | None
    DeletionProtectionEnabled: DeletionProtectionEnabled | None
    MultiRegionConsistency: MultiRegionConsistency | None
    GlobalTableWitnessUpdates: GlobalTableWitnessGroupUpdateList | None
    OnDemandThroughput: OnDemandThroughput | None
    WarmThroughput: WarmThroughput | None


class UpdateTableOutput(TypedDict, total=False):
    TableDescription: TableDescription | None


class UpdateTableReplicaAutoScalingInput(ServiceRequest):
    GlobalSecondaryIndexUpdates: GlobalSecondaryIndexAutoScalingUpdateList | None
    TableName: TableArn
    ProvisionedWriteCapacityAutoScalingUpdate: AutoScalingSettingsUpdate | None
    ReplicaUpdates: ReplicaAutoScalingUpdateList | None


class UpdateTableReplicaAutoScalingOutput(TypedDict, total=False):
    TableAutoScalingDescription: TableAutoScalingDescription | None


class UpdateTimeToLiveInput(ServiceRequest):
    TableName: TableArn
    TimeToLiveSpecification: TimeToLiveSpecification


class UpdateTimeToLiveOutput(TypedDict, total=False):
    TimeToLiveSpecification: TimeToLiveSpecification | None


class DynamodbApi:
    service: str = "dynamodb"
    version: str = "2012-08-10"

    @handler("BatchExecuteStatement")
    def batch_execute_statement(
        self,
        context: RequestContext,
        statements: PartiQLBatchRequest,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        **kwargs,
    ) -> BatchExecuteStatementOutput:
        raise NotImplementedError

    @handler("BatchGetItem")
    def batch_get_item(
        self,
        context: RequestContext,
        request_items: BatchGetRequestMap,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        **kwargs,
    ) -> BatchGetItemOutput:
        raise NotImplementedError

    @handler("BatchWriteItem")
    def batch_write_item(
        self,
        context: RequestContext,
        request_items: BatchWriteItemRequestMap,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        return_item_collection_metrics: ReturnItemCollectionMetrics | None = None,
        **kwargs,
    ) -> BatchWriteItemOutput:
        raise NotImplementedError

    @handler("CreateBackup")
    def create_backup(
        self, context: RequestContext, table_name: TableArn, backup_name: BackupName, **kwargs
    ) -> CreateBackupOutput:
        raise NotImplementedError

    @handler("CreateGlobalTable")
    def create_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replication_group: ReplicaList,
        **kwargs,
    ) -> CreateGlobalTableOutput:
        raise NotImplementedError

    @handler("CreateTable")
    def create_table(
        self,
        context: RequestContext,
        attribute_definitions: AttributeDefinitions,
        table_name: TableArn,
        key_schema: KeySchema,
        local_secondary_indexes: LocalSecondaryIndexList | None = None,
        global_secondary_indexes: GlobalSecondaryIndexList | None = None,
        billing_mode: BillingMode | None = None,
        provisioned_throughput: ProvisionedThroughput | None = None,
        stream_specification: StreamSpecification | None = None,
        sse_specification: SSESpecification | None = None,
        tags: TagList | None = None,
        table_class: TableClass | None = None,
        deletion_protection_enabled: DeletionProtectionEnabled | None = None,
        warm_throughput: WarmThroughput | None = None,
        resource_policy: ResourcePolicy | None = None,
        on_demand_throughput: OnDemandThroughput | None = None,
        **kwargs,
    ) -> CreateTableOutput:
        raise NotImplementedError

    @handler("DeleteBackup")
    def delete_backup(
        self, context: RequestContext, backup_arn: BackupArn, **kwargs
    ) -> DeleteBackupOutput:
        raise NotImplementedError

    @handler("DeleteItem")
    def delete_item(
        self,
        context: RequestContext,
        table_name: TableArn,
        key: Key,
        expected: ExpectedAttributeMap | None = None,
        conditional_operator: ConditionalOperator | None = None,
        return_values: ReturnValue | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        return_item_collection_metrics: ReturnItemCollectionMetrics | None = None,
        condition_expression: ConditionExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        expression_attribute_values: ExpressionAttributeValueMap | None = None,
        return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure | None = None,
        **kwargs,
    ) -> DeleteItemOutput:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        expected_revision_id: PolicyRevisionId | None = None,
        **kwargs,
    ) -> DeleteResourcePolicyOutput:
        raise NotImplementedError

    @handler("DeleteTable")
    def delete_table(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DeleteTableOutput:
        raise NotImplementedError

    @handler("DescribeBackup")
    def describe_backup(
        self, context: RequestContext, backup_arn: BackupArn, **kwargs
    ) -> DescribeBackupOutput:
        raise NotImplementedError

    @handler("DescribeContinuousBackups")
    def describe_continuous_backups(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DescribeContinuousBackupsOutput:
        raise NotImplementedError

    @handler("DescribeContributorInsights")
    def describe_contributor_insights(
        self,
        context: RequestContext,
        table_name: TableArn,
        index_name: IndexName | None = None,
        **kwargs,
    ) -> DescribeContributorInsightsOutput:
        raise NotImplementedError

    @handler("DescribeEndpoints")
    def describe_endpoints(self, context: RequestContext, **kwargs) -> DescribeEndpointsResponse:
        raise NotImplementedError

    @handler("DescribeExport")
    def describe_export(
        self, context: RequestContext, export_arn: ExportArn, **kwargs
    ) -> DescribeExportOutput:
        raise NotImplementedError

    @handler("DescribeGlobalTable")
    def describe_global_table(
        self, context: RequestContext, global_table_name: TableName, **kwargs
    ) -> DescribeGlobalTableOutput:
        raise NotImplementedError

    @handler("DescribeGlobalTableSettings")
    def describe_global_table_settings(
        self, context: RequestContext, global_table_name: TableName, **kwargs
    ) -> DescribeGlobalTableSettingsOutput:
        raise NotImplementedError

    @handler("DescribeImport")
    def describe_import(
        self, context: RequestContext, import_arn: ImportArn, **kwargs
    ) -> DescribeImportOutput:
        raise NotImplementedError

    @handler("DescribeKinesisStreamingDestination")
    def describe_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DescribeKinesisStreamingDestinationOutput:
        raise NotImplementedError

    @handler("DescribeLimits")
    def describe_limits(self, context: RequestContext, **kwargs) -> DescribeLimitsOutput:
        raise NotImplementedError

    @handler("DescribeTable")
    def describe_table(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DescribeTableOutput:
        raise NotImplementedError

    @handler("DescribeTableReplicaAutoScaling")
    def describe_table_replica_auto_scaling(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DescribeTableReplicaAutoScalingOutput:
        raise NotImplementedError

    @handler("DescribeTimeToLive")
    def describe_time_to_live(
        self, context: RequestContext, table_name: TableArn, **kwargs
    ) -> DescribeTimeToLiveOutput:
        raise NotImplementedError

    @handler("DisableKinesisStreamingDestination")
    def disable_kinesis_streaming_destination(
        self,
        context: RequestContext,
        table_name: TableArn,
        stream_arn: StreamArn,
        enable_kinesis_streaming_configuration: EnableKinesisStreamingConfiguration | None = None,
        **kwargs,
    ) -> KinesisStreamingDestinationOutput:
        raise NotImplementedError

    @handler("EnableKinesisStreamingDestination")
    def enable_kinesis_streaming_destination(
        self,
        context: RequestContext,
        table_name: TableArn,
        stream_arn: StreamArn,
        enable_kinesis_streaming_configuration: EnableKinesisStreamingConfiguration | None = None,
        **kwargs,
    ) -> KinesisStreamingDestinationOutput:
        raise NotImplementedError

    @handler("ExecuteStatement")
    def execute_statement(
        self,
        context: RequestContext,
        statement: PartiQLStatement,
        parameters: PreparedStatementParameters | None = None,
        consistent_read: ConsistentRead | None = None,
        next_token: PartiQLNextToken | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        limit: PositiveIntegerObject | None = None,
        return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure | None = None,
        **kwargs,
    ) -> ExecuteStatementOutput:
        raise NotImplementedError

    @handler("ExecuteTransaction")
    def execute_transaction(
        self,
        context: RequestContext,
        transact_statements: ParameterizedStatements,
        client_request_token: ClientRequestToken | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        **kwargs,
    ) -> ExecuteTransactionOutput:
        raise NotImplementedError

    @handler("ExportTableToPointInTime")
    def export_table_to_point_in_time(
        self,
        context: RequestContext,
        table_arn: TableArn,
        s3_bucket: S3Bucket,
        export_time: ExportTime | None = None,
        client_token: ClientToken | None = None,
        s3_bucket_owner: S3BucketOwner | None = None,
        s3_prefix: S3Prefix | None = None,
        s3_sse_algorithm: S3SseAlgorithm | None = None,
        s3_sse_kms_key_id: S3SseKmsKeyId | None = None,
        export_format: ExportFormat | None = None,
        export_type: ExportType | None = None,
        incremental_export_specification: IncrementalExportSpecification | None = None,
        **kwargs,
    ) -> ExportTableToPointInTimeOutput:
        raise NotImplementedError

    @handler("GetItem")
    def get_item(
        self,
        context: RequestContext,
        table_name: TableArn,
        key: Key,
        attributes_to_get: AttributeNameList | None = None,
        consistent_read: ConsistentRead | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        projection_expression: ProjectionExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        **kwargs,
    ) -> GetItemOutput:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, resource_arn: ResourceArnString, **kwargs
    ) -> GetResourcePolicyOutput:
        raise NotImplementedError

    @handler("ImportTable")
    def import_table(
        self,
        context: RequestContext,
        s3_bucket_source: S3BucketSource,
        input_format: InputFormat,
        table_creation_parameters: TableCreationParameters,
        client_token: ClientToken | None = None,
        input_format_options: InputFormatOptions | None = None,
        input_compression_type: InputCompressionType | None = None,
        **kwargs,
    ) -> ImportTableOutput:
        raise NotImplementedError

    @handler("ListBackups")
    def list_backups(
        self,
        context: RequestContext,
        table_name: TableArn | None = None,
        limit: BackupsInputLimit | None = None,
        time_range_lower_bound: TimeRangeLowerBound | None = None,
        time_range_upper_bound: TimeRangeUpperBound | None = None,
        exclusive_start_backup_arn: BackupArn | None = None,
        backup_type: BackupTypeFilter | None = None,
        **kwargs,
    ) -> ListBackupsOutput:
        raise NotImplementedError

    @handler("ListContributorInsights")
    def list_contributor_insights(
        self,
        context: RequestContext,
        table_name: TableArn | None = None,
        next_token: NextTokenString | None = None,
        max_results: ListContributorInsightsLimit | None = None,
        **kwargs,
    ) -> ListContributorInsightsOutput:
        raise NotImplementedError

    @handler("ListExports")
    def list_exports(
        self,
        context: RequestContext,
        table_arn: TableArn | None = None,
        max_results: ListExportsMaxLimit | None = None,
        next_token: ExportNextToken | None = None,
        **kwargs,
    ) -> ListExportsOutput:
        raise NotImplementedError

    @handler("ListGlobalTables")
    def list_global_tables(
        self,
        context: RequestContext,
        exclusive_start_global_table_name: TableName | None = None,
        limit: PositiveIntegerObject | None = None,
        region_name: RegionName | None = None,
        **kwargs,
    ) -> ListGlobalTablesOutput:
        raise NotImplementedError

    @handler("ListImports")
    def list_imports(
        self,
        context: RequestContext,
        table_arn: TableArn | None = None,
        page_size: ListImportsMaxLimit | None = None,
        next_token: ImportNextToken | None = None,
        **kwargs,
    ) -> ListImportsOutput:
        raise NotImplementedError

    @handler("ListTables")
    def list_tables(
        self,
        context: RequestContext,
        exclusive_start_table_name: TableName | None = None,
        limit: ListTablesInputLimit | None = None,
        **kwargs,
    ) -> ListTablesOutput:
        raise NotImplementedError

    @handler("ListTagsOfResource")
    def list_tags_of_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: NextTokenString | None = None,
        **kwargs,
    ) -> ListTagsOfResourceOutput:
        raise NotImplementedError

    @handler("PutItem")
    def put_item(
        self,
        context: RequestContext,
        table_name: TableArn,
        item: PutItemInputAttributeMap,
        expected: ExpectedAttributeMap | None = None,
        return_values: ReturnValue | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        return_item_collection_metrics: ReturnItemCollectionMetrics | None = None,
        conditional_operator: ConditionalOperator | None = None,
        condition_expression: ConditionExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        expression_attribute_values: ExpressionAttributeValueMap | None = None,
        return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure | None = None,
        **kwargs,
    ) -> PutItemOutput:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        policy: ResourcePolicy,
        expected_revision_id: PolicyRevisionId | None = None,
        confirm_remove_self_resource_access: ConfirmRemoveSelfResourceAccess | None = None,
        **kwargs,
    ) -> PutResourcePolicyOutput:
        raise NotImplementedError

    @handler("Query")
    def query(
        self,
        context: RequestContext,
        table_name: TableArn,
        index_name: IndexName | None = None,
        select: Select | None = None,
        attributes_to_get: AttributeNameList | None = None,
        limit: PositiveIntegerObject | None = None,
        consistent_read: ConsistentRead | None = None,
        key_conditions: KeyConditions | None = None,
        query_filter: FilterConditionMap | None = None,
        conditional_operator: ConditionalOperator | None = None,
        scan_index_forward: BooleanObject | None = None,
        exclusive_start_key: Key | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        projection_expression: ProjectionExpression | None = None,
        filter_expression: ConditionExpression | None = None,
        key_condition_expression: KeyExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        expression_attribute_values: ExpressionAttributeValueMap | None = None,
        **kwargs,
    ) -> QueryOutput:
        raise NotImplementedError

    @handler("RestoreTableFromBackup")
    def restore_table_from_backup(
        self,
        context: RequestContext,
        target_table_name: TableName,
        backup_arn: BackupArn,
        billing_mode_override: BillingMode | None = None,
        global_secondary_index_override: GlobalSecondaryIndexList | None = None,
        local_secondary_index_override: LocalSecondaryIndexList | None = None,
        provisioned_throughput_override: ProvisionedThroughput | None = None,
        on_demand_throughput_override: OnDemandThroughput | None = None,
        sse_specification_override: SSESpecification | None = None,
        **kwargs,
    ) -> RestoreTableFromBackupOutput:
        raise NotImplementedError

    @handler("RestoreTableToPointInTime")
    def restore_table_to_point_in_time(
        self,
        context: RequestContext,
        target_table_name: TableName,
        source_table_arn: TableArn | None = None,
        source_table_name: TableName | None = None,
        use_latest_restorable_time: BooleanObject | None = None,
        restore_date_time: Date | None = None,
        billing_mode_override: BillingMode | None = None,
        global_secondary_index_override: GlobalSecondaryIndexList | None = None,
        local_secondary_index_override: LocalSecondaryIndexList | None = None,
        provisioned_throughput_override: ProvisionedThroughput | None = None,
        on_demand_throughput_override: OnDemandThroughput | None = None,
        sse_specification_override: SSESpecification | None = None,
        **kwargs,
    ) -> RestoreTableToPointInTimeOutput:
        raise NotImplementedError

    @handler("Scan")
    def scan(
        self,
        context: RequestContext,
        table_name: TableArn,
        index_name: IndexName | None = None,
        attributes_to_get: AttributeNameList | None = None,
        limit: PositiveIntegerObject | None = None,
        select: Select | None = None,
        scan_filter: FilterConditionMap | None = None,
        conditional_operator: ConditionalOperator | None = None,
        exclusive_start_key: Key | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        total_segments: ScanTotalSegments | None = None,
        segment: ScanSegment | None = None,
        projection_expression: ProjectionExpression | None = None,
        filter_expression: ConditionExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        expression_attribute_values: ExpressionAttributeValueMap | None = None,
        consistent_read: ConsistentRead | None = None,
        **kwargs,
    ) -> ScanOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TransactGetItems")
    def transact_get_items(
        self,
        context: RequestContext,
        transact_items: TransactGetItemList,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        **kwargs,
    ) -> TransactGetItemsOutput:
        raise NotImplementedError

    @handler("TransactWriteItems")
    def transact_write_items(
        self,
        context: RequestContext,
        transact_items: TransactWriteItemList,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        return_item_collection_metrics: ReturnItemCollectionMetrics | None = None,
        client_request_token: ClientRequestToken | None = None,
        **kwargs,
    ) -> TransactWriteItemsOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateContinuousBackups")
    def update_continuous_backups(
        self,
        context: RequestContext,
        table_name: TableArn,
        point_in_time_recovery_specification: PointInTimeRecoverySpecification,
        **kwargs,
    ) -> UpdateContinuousBackupsOutput:
        raise NotImplementedError

    @handler("UpdateContributorInsights")
    def update_contributor_insights(
        self,
        context: RequestContext,
        table_name: TableArn,
        contributor_insights_action: ContributorInsightsAction,
        index_name: IndexName | None = None,
        contributor_insights_mode: ContributorInsightsMode | None = None,
        **kwargs,
    ) -> UpdateContributorInsightsOutput:
        raise NotImplementedError

    @handler("UpdateGlobalTable")
    def update_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replica_updates: ReplicaUpdateList,
        **kwargs,
    ) -> UpdateGlobalTableOutput:
        raise NotImplementedError

    @handler("UpdateGlobalTableSettings")
    def update_global_table_settings(
        self,
        context: RequestContext,
        global_table_name: TableName,
        global_table_billing_mode: BillingMode | None = None,
        global_table_provisioned_write_capacity_units: PositiveLongObject | None = None,
        global_table_provisioned_write_capacity_auto_scaling_settings_update: AutoScalingSettingsUpdate
        | None = None,
        global_table_global_secondary_index_settings_update: GlobalTableGlobalSecondaryIndexSettingsUpdateList
        | None = None,
        replica_settings_update: ReplicaSettingsUpdateList | None = None,
        **kwargs,
    ) -> UpdateGlobalTableSettingsOutput:
        raise NotImplementedError

    @handler("UpdateItem")
    def update_item(
        self,
        context: RequestContext,
        table_name: TableArn,
        key: Key,
        attribute_updates: AttributeUpdates | None = None,
        expected: ExpectedAttributeMap | None = None,
        conditional_operator: ConditionalOperator | None = None,
        return_values: ReturnValue | None = None,
        return_consumed_capacity: ReturnConsumedCapacity | None = None,
        return_item_collection_metrics: ReturnItemCollectionMetrics | None = None,
        update_expression: UpdateExpression | None = None,
        condition_expression: ConditionExpression | None = None,
        expression_attribute_names: ExpressionAttributeNameMap | None = None,
        expression_attribute_values: ExpressionAttributeValueMap | None = None,
        return_values_on_condition_check_failure: ReturnValuesOnConditionCheckFailure | None = None,
        **kwargs,
    ) -> UpdateItemOutput:
        raise NotImplementedError

    @handler("UpdateKinesisStreamingDestination")
    def update_kinesis_streaming_destination(
        self,
        context: RequestContext,
        table_name: TableArn,
        stream_arn: StreamArn,
        update_kinesis_streaming_configuration: UpdateKinesisStreamingConfiguration | None = None,
        **kwargs,
    ) -> UpdateKinesisStreamingDestinationOutput:
        raise NotImplementedError

    @handler("UpdateTable")
    def update_table(
        self,
        context: RequestContext,
        table_name: TableArn,
        attribute_definitions: AttributeDefinitions | None = None,
        billing_mode: BillingMode | None = None,
        provisioned_throughput: ProvisionedThroughput | None = None,
        global_secondary_index_updates: GlobalSecondaryIndexUpdateList | None = None,
        stream_specification: StreamSpecification | None = None,
        sse_specification: SSESpecification | None = None,
        replica_updates: ReplicationGroupUpdateList | None = None,
        table_class: TableClass | None = None,
        deletion_protection_enabled: DeletionProtectionEnabled | None = None,
        multi_region_consistency: MultiRegionConsistency | None = None,
        global_table_witness_updates: GlobalTableWitnessGroupUpdateList | None = None,
        on_demand_throughput: OnDemandThroughput | None = None,
        warm_throughput: WarmThroughput | None = None,
        **kwargs,
    ) -> UpdateTableOutput:
        raise NotImplementedError

    @handler("UpdateTableReplicaAutoScaling")
    def update_table_replica_auto_scaling(
        self,
        context: RequestContext,
        table_name: TableArn,
        global_secondary_index_updates: GlobalSecondaryIndexAutoScalingUpdateList | None = None,
        provisioned_write_capacity_auto_scaling_update: AutoScalingSettingsUpdate | None = None,
        replica_updates: ReplicaAutoScalingUpdateList | None = None,
        **kwargs,
    ) -> UpdateTableReplicaAutoScalingOutput:
        raise NotImplementedError

    @handler("UpdateTimeToLive")
    def update_time_to_live(
        self,
        context: RequestContext,
        table_name: TableArn,
        time_to_live_specification: TimeToLiveSpecification,
        **kwargs,
    ) -> UpdateTimeToLiveOutput:
        raise NotImplementedError
