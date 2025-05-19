from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ArchivalReason = str
AttributeName = str
AutoScalingPolicyName = str
AutoScalingRoleArn = str
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
RecoveryPeriodInDays = int
RegionName = str
ReplicaStatusDescription = str
ReplicaStatusPercentProgress = str
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


class TimeToLiveStatus(StrEnum):
    ENABLING = "ENABLING"
    DISABLING = "DISABLING"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class BackupInUseException(ServiceException):
    code: str = "BackupInUseException"
    sender_fault: bool = False
    status_code: int = 400


class BackupNotFoundException(ServiceException):
    code: str = "BackupNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class AttributeValue(TypedDict, total=False):
    S: Optional["StringAttributeValue"]
    N: Optional["NumberAttributeValue"]
    B: Optional["BinaryAttributeValue"]
    SS: Optional["StringSetAttributeValue"]
    NS: Optional["NumberSetAttributeValue"]
    BS: Optional["BinarySetAttributeValue"]
    M: Optional["MapAttributeValue"]
    L: Optional["ListAttributeValue"]
    NULL: Optional["NullAttributeValue"]
    BOOL: Optional["BooleanAttributeValue"]


ListAttributeValue = List[AttributeValue]
MapAttributeValue = Dict[AttributeName, AttributeValue]
BinaryAttributeValue = bytes
BinarySetAttributeValue = List[BinaryAttributeValue]
NumberSetAttributeValue = List[NumberAttributeValue]
StringSetAttributeValue = List[StringAttributeValue]
AttributeMap = Dict[AttributeName, AttributeValue]


class ConditionalCheckFailedException(ServiceException):
    code: str = "ConditionalCheckFailedException"
    sender_fault: bool = False
    status_code: int = 400
    Item: Optional[AttributeMap]


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


class ProvisionedThroughputExceededException(ServiceException):
    code: str = "ProvisionedThroughputExceededException"
    sender_fault: bool = False
    status_code: int = 400


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


class CancellationReason(TypedDict, total=False):
    Item: Optional[AttributeMap]
    Code: Optional[Code]
    Message: Optional[ErrorMessage]


CancellationReasonList = List[CancellationReason]


class TransactionCanceledException(ServiceException):
    code: str = "TransactionCanceledException"
    sender_fault: bool = False
    status_code: int = 400
    CancellationReasons: Optional[CancellationReasonList]


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
    ArchivalDateTime: Optional[Date]
    ArchivalReason: Optional[ArchivalReason]
    ArchivalBackupArn: Optional[BackupArn]


class AttributeDefinition(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    AttributeType: ScalarAttributeType


AttributeDefinitions = List[AttributeDefinition]
AttributeNameList = List[AttributeName]


class AttributeValueUpdate(TypedDict, total=False):
    Value: Optional[AttributeValue]
    Action: Optional[AttributeAction]


AttributeUpdates = Dict[AttributeName, AttributeValueUpdate]
AttributeValueList = List[AttributeValue]


class AutoScalingTargetTrackingScalingPolicyConfigurationDescription(TypedDict, total=False):
    DisableScaleIn: Optional[BooleanObject]
    ScaleInCooldown: Optional[IntegerObject]
    ScaleOutCooldown: Optional[IntegerObject]
    TargetValue: DoubleObject


class AutoScalingPolicyDescription(TypedDict, total=False):
    PolicyName: Optional[AutoScalingPolicyName]
    TargetTrackingScalingPolicyConfiguration: Optional[
        AutoScalingTargetTrackingScalingPolicyConfigurationDescription
    ]


AutoScalingPolicyDescriptionList = List[AutoScalingPolicyDescription]


class AutoScalingTargetTrackingScalingPolicyConfigurationUpdate(TypedDict, total=False):
    DisableScaleIn: Optional[BooleanObject]
    ScaleInCooldown: Optional[IntegerObject]
    ScaleOutCooldown: Optional[IntegerObject]
    TargetValue: DoubleObject


class AutoScalingPolicyUpdate(TypedDict, total=False):
    PolicyName: Optional[AutoScalingPolicyName]
    TargetTrackingScalingPolicyConfiguration: (
        AutoScalingTargetTrackingScalingPolicyConfigurationUpdate
    )


PositiveLongObject = int


class AutoScalingSettingsDescription(TypedDict, total=False):
    MinimumUnits: Optional[PositiveLongObject]
    MaximumUnits: Optional[PositiveLongObject]
    AutoScalingDisabled: Optional[BooleanObject]
    AutoScalingRoleArn: Optional[String]
    ScalingPolicies: Optional[AutoScalingPolicyDescriptionList]


class AutoScalingSettingsUpdate(TypedDict, total=False):
    MinimumUnits: Optional[PositiveLongObject]
    MaximumUnits: Optional[PositiveLongObject]
    AutoScalingDisabled: Optional[BooleanObject]
    AutoScalingRoleArn: Optional[AutoScalingRoleArn]
    ScalingPolicyUpdate: Optional[AutoScalingPolicyUpdate]


BackupCreationDateTime = datetime


class SSEDescription(TypedDict, total=False):
    Status: Optional[SSEStatus]
    SSEType: Optional[SSEType]
    KMSMasterKeyArn: Optional[KMSMasterKeyArn]
    InaccessibleEncryptionDateTime: Optional[Date]


class TimeToLiveDescription(TypedDict, total=False):
    TimeToLiveStatus: Optional[TimeToLiveStatus]
    AttributeName: Optional[TimeToLiveAttributeName]


class StreamSpecification(TypedDict, total=False):
    StreamEnabled: StreamEnabled
    StreamViewType: Optional[StreamViewType]


LongObject = int


class OnDemandThroughput(TypedDict, total=False):
    MaxReadRequestUnits: Optional[LongObject]
    MaxWriteRequestUnits: Optional[LongObject]


class ProvisionedThroughput(TypedDict, total=False):
    ReadCapacityUnits: PositiveLongObject
    WriteCapacityUnits: PositiveLongObject


NonKeyAttributeNameList = List[NonKeyAttributeName]


class Projection(TypedDict, total=False):
    ProjectionType: Optional[ProjectionType]
    NonKeyAttributes: Optional[NonKeyAttributeNameList]


class KeySchemaElement(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    KeyType: KeyType


KeySchema = List[KeySchemaElement]


class GlobalSecondaryIndexInfo(TypedDict, total=False):
    IndexName: Optional[IndexName]
    KeySchema: Optional[KeySchema]
    Projection: Optional[Projection]
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    OnDemandThroughput: Optional[OnDemandThroughput]


GlobalSecondaryIndexes = List[GlobalSecondaryIndexInfo]


class LocalSecondaryIndexInfo(TypedDict, total=False):
    IndexName: Optional[IndexName]
    KeySchema: Optional[KeySchema]
    Projection: Optional[Projection]


LocalSecondaryIndexes = List[LocalSecondaryIndexInfo]


class SourceTableFeatureDetails(TypedDict, total=False):
    LocalSecondaryIndexes: Optional[LocalSecondaryIndexes]
    GlobalSecondaryIndexes: Optional[GlobalSecondaryIndexes]
    StreamDescription: Optional[StreamSpecification]
    TimeToLiveDescription: Optional[TimeToLiveDescription]
    SSEDescription: Optional[SSEDescription]


ItemCount = int
TableCreationDateTime = datetime


class SourceTableDetails(TypedDict, total=False):
    TableName: TableName
    TableId: TableId
    TableArn: Optional[TableArn]
    TableSizeBytes: Optional[LongObject]
    KeySchema: KeySchema
    TableCreationDateTime: TableCreationDateTime
    ProvisionedThroughput: ProvisionedThroughput
    OnDemandThroughput: Optional[OnDemandThroughput]
    ItemCount: Optional[ItemCount]
    BillingMode: Optional[BillingMode]


BackupSizeBytes = int


class BackupDetails(TypedDict, total=False):
    BackupArn: BackupArn
    BackupName: BackupName
    BackupSizeBytes: Optional[BackupSizeBytes]
    BackupStatus: BackupStatus
    BackupType: BackupType
    BackupCreationDateTime: BackupCreationDateTime
    BackupExpiryDateTime: Optional[Date]


class BackupDescription(TypedDict, total=False):
    BackupDetails: Optional[BackupDetails]
    SourceTableDetails: Optional[SourceTableDetails]
    SourceTableFeatureDetails: Optional[SourceTableFeatureDetails]


class BackupSummary(TypedDict, total=False):
    TableName: Optional[TableName]
    TableId: Optional[TableId]
    TableArn: Optional[TableArn]
    BackupArn: Optional[BackupArn]
    BackupName: Optional[BackupName]
    BackupCreationDateTime: Optional[BackupCreationDateTime]
    BackupExpiryDateTime: Optional[Date]
    BackupStatus: Optional[BackupStatus]
    BackupType: Optional[BackupType]
    BackupSizeBytes: Optional[BackupSizeBytes]


BackupSummaries = List[BackupSummary]
PreparedStatementParameters = List[AttributeValue]


class BatchStatementRequest(TypedDict, total=False):
    Statement: PartiQLStatement
    Parameters: Optional[PreparedStatementParameters]
    ConsistentRead: Optional[ConsistentRead]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


PartiQLBatchRequest = List[BatchStatementRequest]


class BatchExecuteStatementInput(ServiceRequest):
    Statements: PartiQLBatchRequest
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]


class Capacity(TypedDict, total=False):
    ReadCapacityUnits: Optional[ConsumedCapacityUnits]
    WriteCapacityUnits: Optional[ConsumedCapacityUnits]
    CapacityUnits: Optional[ConsumedCapacityUnits]


SecondaryIndexesCapacityMap = Dict[IndexName, Capacity]


class ConsumedCapacity(TypedDict, total=False):
    TableName: Optional[TableArn]
    CapacityUnits: Optional[ConsumedCapacityUnits]
    ReadCapacityUnits: Optional[ConsumedCapacityUnits]
    WriteCapacityUnits: Optional[ConsumedCapacityUnits]
    Table: Optional[Capacity]
    LocalSecondaryIndexes: Optional[SecondaryIndexesCapacityMap]
    GlobalSecondaryIndexes: Optional[SecondaryIndexesCapacityMap]


ConsumedCapacityMultiple = List[ConsumedCapacity]


class BatchStatementError(TypedDict, total=False):
    Code: Optional[BatchStatementErrorCodeEnum]
    Message: Optional[String]
    Item: Optional[AttributeMap]


class BatchStatementResponse(TypedDict, total=False):
    Error: Optional[BatchStatementError]
    TableName: Optional[TableName]
    Item: Optional[AttributeMap]


PartiQLBatchResponse = List[BatchStatementResponse]


class BatchExecuteStatementOutput(TypedDict, total=False):
    Responses: Optional[PartiQLBatchResponse]
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]


ExpressionAttributeNameMap = Dict[ExpressionAttributeNameVariable, AttributeName]
Key = Dict[AttributeName, AttributeValue]
KeyList = List[Key]


class KeysAndAttributes(TypedDict, total=False):
    Keys: KeyList
    AttributesToGet: Optional[AttributeNameList]
    ConsistentRead: Optional[ConsistentRead]
    ProjectionExpression: Optional[ProjectionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]


BatchGetRequestMap = Dict[TableArn, KeysAndAttributes]


class BatchGetItemInput(ServiceRequest):
    RequestItems: BatchGetRequestMap
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]


ItemList = List[AttributeMap]
BatchGetResponseMap = Dict[TableArn, ItemList]


class BatchGetItemOutput(TypedDict, total=False):
    Responses: Optional[BatchGetResponseMap]
    UnprocessedKeys: Optional[BatchGetRequestMap]
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]


class DeleteRequest(TypedDict, total=False):
    Key: Key


PutItemInputAttributeMap = Dict[AttributeName, AttributeValue]


class PutRequest(TypedDict, total=False):
    Item: PutItemInputAttributeMap


class WriteRequest(TypedDict, total=False):
    PutRequest: Optional[PutRequest]
    DeleteRequest: Optional[DeleteRequest]


WriteRequests = List[WriteRequest]
BatchWriteItemRequestMap = Dict[TableArn, WriteRequests]


class BatchWriteItemInput(ServiceRequest):
    RequestItems: BatchWriteItemRequestMap
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ReturnItemCollectionMetrics: Optional[ReturnItemCollectionMetrics]


ItemCollectionSizeEstimateRange = List[ItemCollectionSizeEstimateBound]
ItemCollectionKeyAttributeMap = Dict[AttributeName, AttributeValue]


class ItemCollectionMetrics(TypedDict, total=False):
    ItemCollectionKey: Optional[ItemCollectionKeyAttributeMap]
    SizeEstimateRangeGB: Optional[ItemCollectionSizeEstimateRange]


ItemCollectionMetricsMultiple = List[ItemCollectionMetrics]
ItemCollectionMetricsPerTable = Dict[TableArn, ItemCollectionMetricsMultiple]


class BatchWriteItemOutput(TypedDict, total=False):
    UnprocessedItems: Optional[BatchWriteItemRequestMap]
    ItemCollectionMetrics: Optional[ItemCollectionMetricsPerTable]
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]


BilledSizeBytes = int


class BillingModeSummary(TypedDict, total=False):
    BillingMode: Optional[BillingMode]
    LastUpdateToPayPerRequestDateTime: Optional[Date]


class Condition(TypedDict, total=False):
    AttributeValueList: Optional[AttributeValueList]
    ComparisonOperator: ComparisonOperator


ExpressionAttributeValueMap = Dict[ExpressionAttributeValueVariable, AttributeValue]


class ConditionCheck(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ConditionExpression: ConditionExpression
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class PointInTimeRecoveryDescription(TypedDict, total=False):
    PointInTimeRecoveryStatus: Optional[PointInTimeRecoveryStatus]
    RecoveryPeriodInDays: Optional[RecoveryPeriodInDays]
    EarliestRestorableDateTime: Optional[Date]
    LatestRestorableDateTime: Optional[Date]


class ContinuousBackupsDescription(TypedDict, total=False):
    ContinuousBackupsStatus: ContinuousBackupsStatus
    PointInTimeRecoveryDescription: Optional[PointInTimeRecoveryDescription]


ContributorInsightsRuleList = List[ContributorInsightsRule]


class ContributorInsightsSummary(TypedDict, total=False):
    TableName: Optional[TableName]
    IndexName: Optional[IndexName]
    ContributorInsightsStatus: Optional[ContributorInsightsStatus]


ContributorInsightsSummaries = List[ContributorInsightsSummary]


class CreateBackupInput(ServiceRequest):
    TableName: TableArn
    BackupName: BackupName


class CreateBackupOutput(TypedDict, total=False):
    BackupDetails: Optional[BackupDetails]


class WarmThroughput(TypedDict, total=False):
    ReadUnitsPerSecond: Optional[LongObject]
    WriteUnitsPerSecond: Optional[LongObject]


class CreateGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[WarmThroughput]


class Replica(TypedDict, total=False):
    RegionName: Optional[RegionName]


ReplicaList = List[Replica]


class CreateGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName
    ReplicationGroup: ReplicaList


class TableClassSummary(TypedDict, total=False):
    TableClass: Optional[TableClass]
    LastUpdateDateTime: Optional[Date]


class GlobalSecondaryIndexWarmThroughputDescription(TypedDict, total=False):
    ReadUnitsPerSecond: Optional[PositiveLongObject]
    WriteUnitsPerSecond: Optional[PositiveLongObject]
    Status: Optional[IndexStatus]


class OnDemandThroughputOverride(TypedDict, total=False):
    MaxReadRequestUnits: Optional[LongObject]


class ProvisionedThroughputOverride(TypedDict, total=False):
    ReadCapacityUnits: Optional[PositiveLongObject]


class ReplicaGlobalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: Optional[IndexName]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughputOverride]
    OnDemandThroughputOverride: Optional[OnDemandThroughputOverride]
    WarmThroughput: Optional[GlobalSecondaryIndexWarmThroughputDescription]


ReplicaGlobalSecondaryIndexDescriptionList = List[ReplicaGlobalSecondaryIndexDescription]


class TableWarmThroughputDescription(TypedDict, total=False):
    ReadUnitsPerSecond: Optional[PositiveLongObject]
    WriteUnitsPerSecond: Optional[PositiveLongObject]
    Status: Optional[TableStatus]


class ReplicaDescription(TypedDict, total=False):
    RegionName: Optional[RegionName]
    ReplicaStatus: Optional[ReplicaStatus]
    ReplicaStatusDescription: Optional[ReplicaStatusDescription]
    ReplicaStatusPercentProgress: Optional[ReplicaStatusPercentProgress]
    KMSMasterKeyId: Optional[KMSMasterKeyId]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughputOverride]
    OnDemandThroughputOverride: Optional[OnDemandThroughputOverride]
    WarmThroughput: Optional[TableWarmThroughputDescription]
    GlobalSecondaryIndexes: Optional[ReplicaGlobalSecondaryIndexDescriptionList]
    ReplicaInaccessibleDateTime: Optional[Date]
    ReplicaTableClassSummary: Optional[TableClassSummary]


ReplicaDescriptionList = List[ReplicaDescription]


class GlobalTableDescription(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicaDescriptionList]
    GlobalTableArn: Optional[GlobalTableArnString]
    CreationDateTime: Optional[Date]
    GlobalTableStatus: Optional[GlobalTableStatus]
    GlobalTableName: Optional[TableName]


class CreateGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: Optional[GlobalTableDescription]


class CreateReplicaAction(TypedDict, total=False):
    RegionName: RegionName


class ReplicaGlobalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedThroughputOverride: Optional[ProvisionedThroughputOverride]
    OnDemandThroughputOverride: Optional[OnDemandThroughputOverride]


ReplicaGlobalSecondaryIndexList = List[ReplicaGlobalSecondaryIndex]


class CreateReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName
    KMSMasterKeyId: Optional[KMSMasterKeyId]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughputOverride]
    OnDemandThroughputOverride: Optional[OnDemandThroughputOverride]
    GlobalSecondaryIndexes: Optional[ReplicaGlobalSecondaryIndexList]
    TableClassOverride: Optional[TableClass]


class Tag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


TagList = List[Tag]


class SSESpecification(TypedDict, total=False):
    Enabled: Optional[SSEEnabled]
    SSEType: Optional[SSEType]
    KMSMasterKeyId: Optional[KMSMasterKeyId]


class GlobalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[WarmThroughput]


GlobalSecondaryIndexList = List[GlobalSecondaryIndex]


class LocalSecondaryIndex(TypedDict, total=False):
    IndexName: IndexName
    KeySchema: KeySchema
    Projection: Projection


LocalSecondaryIndexList = List[LocalSecondaryIndex]


class CreateTableInput(ServiceRequest):
    AttributeDefinitions: AttributeDefinitions
    TableName: TableArn
    KeySchema: KeySchema
    LocalSecondaryIndexes: Optional[LocalSecondaryIndexList]
    GlobalSecondaryIndexes: Optional[GlobalSecondaryIndexList]
    BillingMode: Optional[BillingMode]
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    StreamSpecification: Optional[StreamSpecification]
    SSESpecification: Optional[SSESpecification]
    Tags: Optional[TagList]
    TableClass: Optional[TableClass]
    DeletionProtectionEnabled: Optional[DeletionProtectionEnabled]
    WarmThroughput: Optional[WarmThroughput]
    ResourcePolicy: Optional[ResourcePolicy]
    OnDemandThroughput: Optional[OnDemandThroughput]


class RestoreSummary(TypedDict, total=False):
    SourceBackupArn: Optional[BackupArn]
    SourceTableArn: Optional[TableArn]
    RestoreDateTime: Date
    RestoreInProgress: RestoreInProgress


NonNegativeLongObject = int


class ProvisionedThroughputDescription(TypedDict, total=False):
    LastIncreaseDateTime: Optional[Date]
    LastDecreaseDateTime: Optional[Date]
    NumberOfDecreasesToday: Optional[PositiveLongObject]
    ReadCapacityUnits: Optional[NonNegativeLongObject]
    WriteCapacityUnits: Optional[NonNegativeLongObject]


class GlobalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: Optional[IndexName]
    KeySchema: Optional[KeySchema]
    Projection: Optional[Projection]
    IndexStatus: Optional[IndexStatus]
    Backfilling: Optional[Backfilling]
    ProvisionedThroughput: Optional[ProvisionedThroughputDescription]
    IndexSizeBytes: Optional[LongObject]
    ItemCount: Optional[LongObject]
    IndexArn: Optional[String]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[GlobalSecondaryIndexWarmThroughputDescription]


GlobalSecondaryIndexDescriptionList = List[GlobalSecondaryIndexDescription]


class LocalSecondaryIndexDescription(TypedDict, total=False):
    IndexName: Optional[IndexName]
    KeySchema: Optional[KeySchema]
    Projection: Optional[Projection]
    IndexSizeBytes: Optional[LongObject]
    ItemCount: Optional[LongObject]
    IndexArn: Optional[String]


LocalSecondaryIndexDescriptionList = List[LocalSecondaryIndexDescription]


class TableDescription(TypedDict, total=False):
    AttributeDefinitions: Optional[AttributeDefinitions]
    TableName: Optional[TableName]
    KeySchema: Optional[KeySchema]
    TableStatus: Optional[TableStatus]
    CreationDateTime: Optional[Date]
    ProvisionedThroughput: Optional[ProvisionedThroughputDescription]
    TableSizeBytes: Optional[LongObject]
    ItemCount: Optional[LongObject]
    TableArn: Optional[String]
    TableId: Optional[TableId]
    BillingModeSummary: Optional[BillingModeSummary]
    LocalSecondaryIndexes: Optional[LocalSecondaryIndexDescriptionList]
    GlobalSecondaryIndexes: Optional[GlobalSecondaryIndexDescriptionList]
    StreamSpecification: Optional[StreamSpecification]
    LatestStreamLabel: Optional[String]
    LatestStreamArn: Optional[StreamArn]
    GlobalTableVersion: Optional[String]
    Replicas: Optional[ReplicaDescriptionList]
    RestoreSummary: Optional[RestoreSummary]
    SSEDescription: Optional[SSEDescription]
    ArchivalSummary: Optional[ArchivalSummary]
    TableClassSummary: Optional[TableClassSummary]
    DeletionProtectionEnabled: Optional[DeletionProtectionEnabled]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[TableWarmThroughputDescription]
    MultiRegionConsistency: Optional[MultiRegionConsistency]


class CreateTableOutput(TypedDict, total=False):
    TableDescription: Optional[TableDescription]


CsvHeaderList = List[CsvHeader]


class CsvOptions(TypedDict, total=False):
    Delimiter: Optional[CsvDelimiter]
    HeaderList: Optional[CsvHeaderList]


class Delete(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class DeleteBackupInput(ServiceRequest):
    BackupArn: BackupArn


class DeleteBackupOutput(TypedDict, total=False):
    BackupDescription: Optional[BackupDescription]


class DeleteGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName


class ExpectedAttributeValue(TypedDict, total=False):
    Value: Optional[AttributeValue]
    Exists: Optional[BooleanObject]
    ComparisonOperator: Optional[ComparisonOperator]
    AttributeValueList: Optional[AttributeValueList]


ExpectedAttributeMap = Dict[AttributeName, ExpectedAttributeValue]


class DeleteItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    Expected: Optional[ExpectedAttributeMap]
    ConditionalOperator: Optional[ConditionalOperator]
    ReturnValues: Optional[ReturnValue]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ReturnItemCollectionMetrics: Optional[ReturnItemCollectionMetrics]
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class DeleteItemOutput(TypedDict, total=False):
    Attributes: Optional[AttributeMap]
    ConsumedCapacity: Optional[ConsumedCapacity]
    ItemCollectionMetrics: Optional[ItemCollectionMetrics]


class DeleteReplicaAction(TypedDict, total=False):
    RegionName: RegionName


class DeleteReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName


class DeleteResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString
    ExpectedRevisionId: Optional[PolicyRevisionId]


class DeleteResourcePolicyOutput(TypedDict, total=False):
    RevisionId: Optional[PolicyRevisionId]


class DeleteTableInput(ServiceRequest):
    TableName: TableArn


class DeleteTableOutput(TypedDict, total=False):
    TableDescription: Optional[TableDescription]


class DescribeBackupInput(ServiceRequest):
    BackupArn: BackupArn


class DescribeBackupOutput(TypedDict, total=False):
    BackupDescription: Optional[BackupDescription]


class DescribeContinuousBackupsInput(ServiceRequest):
    TableName: TableArn


class DescribeContinuousBackupsOutput(TypedDict, total=False):
    ContinuousBackupsDescription: Optional[ContinuousBackupsDescription]


class DescribeContributorInsightsInput(ServiceRequest):
    TableName: TableArn
    IndexName: Optional[IndexName]


class FailureException(TypedDict, total=False):
    ExceptionName: Optional[ExceptionName]
    ExceptionDescription: Optional[ExceptionDescription]


LastUpdateDateTime = datetime


class DescribeContributorInsightsOutput(TypedDict, total=False):
    TableName: Optional[TableName]
    IndexName: Optional[IndexName]
    ContributorInsightsRuleList: Optional[ContributorInsightsRuleList]
    ContributorInsightsStatus: Optional[ContributorInsightsStatus]
    LastUpdateDateTime: Optional[LastUpdateDateTime]
    FailureException: Optional[FailureException]


class DescribeEndpointsRequest(ServiceRequest):
    pass


Long = int


class Endpoint(TypedDict, total=False):
    Address: String
    CachePeriodInMinutes: Long


Endpoints = List[Endpoint]


class DescribeEndpointsResponse(TypedDict, total=False):
    Endpoints: Endpoints


class DescribeExportInput(ServiceRequest):
    ExportArn: ExportArn


ExportToTime = datetime
ExportFromTime = datetime


class IncrementalExportSpecification(TypedDict, total=False):
    ExportFromTime: Optional[ExportFromTime]
    ExportToTime: Optional[ExportToTime]
    ExportViewType: Optional[ExportViewType]


ExportTime = datetime
ExportEndTime = datetime
ExportStartTime = datetime


class ExportDescription(TypedDict, total=False):
    ExportArn: Optional[ExportArn]
    ExportStatus: Optional[ExportStatus]
    StartTime: Optional[ExportStartTime]
    EndTime: Optional[ExportEndTime]
    ExportManifest: Optional[ExportManifest]
    TableArn: Optional[TableArn]
    TableId: Optional[TableId]
    ExportTime: Optional[ExportTime]
    ClientToken: Optional[ClientToken]
    S3Bucket: Optional[S3Bucket]
    S3BucketOwner: Optional[S3BucketOwner]
    S3Prefix: Optional[S3Prefix]
    S3SseAlgorithm: Optional[S3SseAlgorithm]
    S3SseKmsKeyId: Optional[S3SseKmsKeyId]
    FailureCode: Optional[FailureCode]
    FailureMessage: Optional[FailureMessage]
    ExportFormat: Optional[ExportFormat]
    BilledSizeBytes: Optional[BilledSizeBytes]
    ItemCount: Optional[ItemCount]
    ExportType: Optional[ExportType]
    IncrementalExportSpecification: Optional[IncrementalExportSpecification]


class DescribeExportOutput(TypedDict, total=False):
    ExportDescription: Optional[ExportDescription]


class DescribeGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName


class DescribeGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: Optional[GlobalTableDescription]


class DescribeGlobalTableSettingsInput(ServiceRequest):
    GlobalTableName: TableName


class ReplicaGlobalSecondaryIndexSettingsDescription(TypedDict, total=False):
    IndexName: IndexName
    IndexStatus: Optional[IndexStatus]
    ProvisionedReadCapacityUnits: Optional[PositiveLongObject]
    ProvisionedReadCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ProvisionedWriteCapacityUnits: Optional[PositiveLongObject]
    ProvisionedWriteCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]


ReplicaGlobalSecondaryIndexSettingsDescriptionList = List[
    ReplicaGlobalSecondaryIndexSettingsDescription
]


class ReplicaSettingsDescription(TypedDict, total=False):
    RegionName: RegionName
    ReplicaStatus: Optional[ReplicaStatus]
    ReplicaBillingModeSummary: Optional[BillingModeSummary]
    ReplicaProvisionedReadCapacityUnits: Optional[NonNegativeLongObject]
    ReplicaProvisionedReadCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ReplicaProvisionedWriteCapacityUnits: Optional[NonNegativeLongObject]
    ReplicaProvisionedWriteCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ReplicaGlobalSecondaryIndexSettings: Optional[
        ReplicaGlobalSecondaryIndexSettingsDescriptionList
    ]
    ReplicaTableClassSummary: Optional[TableClassSummary]


ReplicaSettingsDescriptionList = List[ReplicaSettingsDescription]


class DescribeGlobalTableSettingsOutput(TypedDict, total=False):
    GlobalTableName: Optional[TableName]
    ReplicaSettings: Optional[ReplicaSettingsDescriptionList]


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
    BillingMode: Optional[BillingMode]
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    OnDemandThroughput: Optional[OnDemandThroughput]
    SSESpecification: Optional[SSESpecification]
    GlobalSecondaryIndexes: Optional[GlobalSecondaryIndexList]


class InputFormatOptions(TypedDict, total=False):
    Csv: Optional[CsvOptions]


ErrorCount = int


class S3BucketSource(TypedDict, total=False):
    S3BucketOwner: Optional[S3BucketOwner]
    S3Bucket: S3Bucket
    S3KeyPrefix: Optional[S3Prefix]


class ImportTableDescription(TypedDict, total=False):
    ImportArn: Optional[ImportArn]
    ImportStatus: Optional[ImportStatus]
    TableArn: Optional[TableArn]
    TableId: Optional[TableId]
    ClientToken: Optional[ClientToken]
    S3BucketSource: Optional[S3BucketSource]
    ErrorCount: Optional[ErrorCount]
    CloudWatchLogGroupArn: Optional[CloudWatchLogGroupArn]
    InputFormat: Optional[InputFormat]
    InputFormatOptions: Optional[InputFormatOptions]
    InputCompressionType: Optional[InputCompressionType]
    TableCreationParameters: Optional[TableCreationParameters]
    StartTime: Optional[ImportStartTime]
    EndTime: Optional[ImportEndTime]
    ProcessedSizeBytes: Optional[LongObject]
    ProcessedItemCount: Optional[ProcessedItemCount]
    ImportedItemCount: Optional[ImportedItemCount]
    FailureCode: Optional[FailureCode]
    FailureMessage: Optional[FailureMessage]


class DescribeImportOutput(TypedDict, total=False):
    ImportTableDescription: ImportTableDescription


class DescribeKinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn


class KinesisDataStreamDestination(TypedDict, total=False):
    StreamArn: Optional[StreamArn]
    DestinationStatus: Optional[DestinationStatus]
    DestinationStatusDescription: Optional[String]
    ApproximateCreationDateTimePrecision: Optional[ApproximateCreationDateTimePrecision]


KinesisDataStreamDestinations = List[KinesisDataStreamDestination]


class DescribeKinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: Optional[TableName]
    KinesisDataStreamDestinations: Optional[KinesisDataStreamDestinations]


class DescribeLimitsInput(ServiceRequest):
    pass


class DescribeLimitsOutput(TypedDict, total=False):
    AccountMaxReadCapacityUnits: Optional[PositiveLongObject]
    AccountMaxWriteCapacityUnits: Optional[PositiveLongObject]
    TableMaxReadCapacityUnits: Optional[PositiveLongObject]
    TableMaxWriteCapacityUnits: Optional[PositiveLongObject]


class DescribeTableInput(ServiceRequest):
    TableName: TableArn


class DescribeTableOutput(TypedDict, total=False):
    Table: Optional[TableDescription]


class DescribeTableReplicaAutoScalingInput(ServiceRequest):
    TableName: TableArn


class ReplicaGlobalSecondaryIndexAutoScalingDescription(TypedDict, total=False):
    IndexName: Optional[IndexName]
    IndexStatus: Optional[IndexStatus]
    ProvisionedReadCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ProvisionedWriteCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]


ReplicaGlobalSecondaryIndexAutoScalingDescriptionList = List[
    ReplicaGlobalSecondaryIndexAutoScalingDescription
]


class ReplicaAutoScalingDescription(TypedDict, total=False):
    RegionName: Optional[RegionName]
    GlobalSecondaryIndexes: Optional[ReplicaGlobalSecondaryIndexAutoScalingDescriptionList]
    ReplicaProvisionedReadCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ReplicaProvisionedWriteCapacityAutoScalingSettings: Optional[AutoScalingSettingsDescription]
    ReplicaStatus: Optional[ReplicaStatus]


ReplicaAutoScalingDescriptionList = List[ReplicaAutoScalingDescription]


class TableAutoScalingDescription(TypedDict, total=False):
    TableName: Optional[TableName]
    TableStatus: Optional[TableStatus]
    Replicas: Optional[ReplicaAutoScalingDescriptionList]


class DescribeTableReplicaAutoScalingOutput(TypedDict, total=False):
    TableAutoScalingDescription: Optional[TableAutoScalingDescription]


class DescribeTimeToLiveInput(ServiceRequest):
    TableName: TableArn


class DescribeTimeToLiveOutput(TypedDict, total=False):
    TimeToLiveDescription: Optional[TimeToLiveDescription]


class EnableKinesisStreamingConfiguration(TypedDict, total=False):
    ApproximateCreationDateTimePrecision: Optional[ApproximateCreationDateTimePrecision]


class ExecuteStatementInput(ServiceRequest):
    Statement: PartiQLStatement
    Parameters: Optional[PreparedStatementParameters]
    ConsistentRead: Optional[ConsistentRead]
    NextToken: Optional[PartiQLNextToken]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    Limit: Optional[PositiveIntegerObject]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class ExecuteStatementOutput(TypedDict, total=False):
    Items: Optional[ItemList]
    NextToken: Optional[PartiQLNextToken]
    ConsumedCapacity: Optional[ConsumedCapacity]
    LastEvaluatedKey: Optional[Key]


class ParameterizedStatement(TypedDict, total=False):
    Statement: PartiQLStatement
    Parameters: Optional[PreparedStatementParameters]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


ParameterizedStatements = List[ParameterizedStatement]


class ExecuteTransactionInput(ServiceRequest):
    TransactStatements: ParameterizedStatements
    ClientRequestToken: Optional[ClientRequestToken]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]


class ItemResponse(TypedDict, total=False):
    Item: Optional[AttributeMap]


ItemResponseList = List[ItemResponse]


class ExecuteTransactionOutput(TypedDict, total=False):
    Responses: Optional[ItemResponseList]
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]


class ExportSummary(TypedDict, total=False):
    ExportArn: Optional[ExportArn]
    ExportStatus: Optional[ExportStatus]
    ExportType: Optional[ExportType]


ExportSummaries = List[ExportSummary]


class ExportTableToPointInTimeInput(ServiceRequest):
    TableArn: TableArn
    ExportTime: Optional[ExportTime]
    ClientToken: Optional[ClientToken]
    S3Bucket: S3Bucket
    S3BucketOwner: Optional[S3BucketOwner]
    S3Prefix: Optional[S3Prefix]
    S3SseAlgorithm: Optional[S3SseAlgorithm]
    S3SseKmsKeyId: Optional[S3SseKmsKeyId]
    ExportFormat: Optional[ExportFormat]
    ExportType: Optional[ExportType]
    IncrementalExportSpecification: Optional[IncrementalExportSpecification]


class ExportTableToPointInTimeOutput(TypedDict, total=False):
    ExportDescription: Optional[ExportDescription]


FilterConditionMap = Dict[AttributeName, Condition]


class Get(TypedDict, total=False):
    Key: Key
    TableName: TableArn
    ProjectionExpression: Optional[ProjectionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]


class GetItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    AttributesToGet: Optional[AttributeNameList]
    ConsistentRead: Optional[ConsistentRead]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ProjectionExpression: Optional[ProjectionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]


class GetItemOutput(TypedDict, total=False):
    Item: Optional[AttributeMap]
    ConsumedCapacity: Optional[ConsumedCapacity]


class GetResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString


class GetResourcePolicyOutput(TypedDict, total=False):
    Policy: Optional[ResourcePolicy]
    RevisionId: Optional[PolicyRevisionId]


class GlobalSecondaryIndexAutoScalingUpdate(TypedDict, total=False):
    IndexName: Optional[IndexName]
    ProvisionedWriteCapacityAutoScalingUpdate: Optional[AutoScalingSettingsUpdate]


GlobalSecondaryIndexAutoScalingUpdateList = List[GlobalSecondaryIndexAutoScalingUpdate]


class UpdateGlobalSecondaryIndexAction(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[WarmThroughput]


class GlobalSecondaryIndexUpdate(TypedDict, total=False):
    Update: Optional[UpdateGlobalSecondaryIndexAction]
    Create: Optional[CreateGlobalSecondaryIndexAction]
    Delete: Optional[DeleteGlobalSecondaryIndexAction]


GlobalSecondaryIndexUpdateList = List[GlobalSecondaryIndexUpdate]


class GlobalTable(TypedDict, total=False):
    GlobalTableName: Optional[TableName]
    ReplicationGroup: Optional[ReplicaList]


class GlobalTableGlobalSecondaryIndexSettingsUpdate(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedWriteCapacityUnits: Optional[PositiveLongObject]
    ProvisionedWriteCapacityAutoScalingSettingsUpdate: Optional[AutoScalingSettingsUpdate]


GlobalTableGlobalSecondaryIndexSettingsUpdateList = List[
    GlobalTableGlobalSecondaryIndexSettingsUpdate
]
GlobalTableList = List[GlobalTable]


class ImportSummary(TypedDict, total=False):
    ImportArn: Optional[ImportArn]
    ImportStatus: Optional[ImportStatus]
    TableArn: Optional[TableArn]
    S3BucketSource: Optional[S3BucketSource]
    CloudWatchLogGroupArn: Optional[CloudWatchLogGroupArn]
    InputFormat: Optional[InputFormat]
    StartTime: Optional[ImportStartTime]
    EndTime: Optional[ImportEndTime]


ImportSummaryList = List[ImportSummary]


class ImportTableInput(ServiceRequest):
    ClientToken: Optional[ClientToken]
    S3BucketSource: S3BucketSource
    InputFormat: InputFormat
    InputFormatOptions: Optional[InputFormatOptions]
    InputCompressionType: Optional[InputCompressionType]
    TableCreationParameters: TableCreationParameters


class ImportTableOutput(TypedDict, total=False):
    ImportTableDescription: ImportTableDescription


KeyConditions = Dict[AttributeName, Condition]


class KinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn
    StreamArn: StreamArn
    EnableKinesisStreamingConfiguration: Optional[EnableKinesisStreamingConfiguration]


class KinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: Optional[TableName]
    StreamArn: Optional[StreamArn]
    DestinationStatus: Optional[DestinationStatus]
    EnableKinesisStreamingConfiguration: Optional[EnableKinesisStreamingConfiguration]


TimeRangeUpperBound = datetime
TimeRangeLowerBound = datetime


class ListBackupsInput(ServiceRequest):
    TableName: Optional[TableArn]
    Limit: Optional[BackupsInputLimit]
    TimeRangeLowerBound: Optional[TimeRangeLowerBound]
    TimeRangeUpperBound: Optional[TimeRangeUpperBound]
    ExclusiveStartBackupArn: Optional[BackupArn]
    BackupType: Optional[BackupTypeFilter]


class ListBackupsOutput(TypedDict, total=False):
    BackupSummaries: Optional[BackupSummaries]
    LastEvaluatedBackupArn: Optional[BackupArn]


class ListContributorInsightsInput(ServiceRequest):
    TableName: Optional[TableArn]
    NextToken: Optional[NextTokenString]
    MaxResults: Optional[ListContributorInsightsLimit]


class ListContributorInsightsOutput(TypedDict, total=False):
    ContributorInsightsSummaries: Optional[ContributorInsightsSummaries]
    NextToken: Optional[NextTokenString]


class ListExportsInput(ServiceRequest):
    TableArn: Optional[TableArn]
    MaxResults: Optional[ListExportsMaxLimit]
    NextToken: Optional[ExportNextToken]


class ListExportsOutput(TypedDict, total=False):
    ExportSummaries: Optional[ExportSummaries]
    NextToken: Optional[ExportNextToken]


class ListGlobalTablesInput(ServiceRequest):
    ExclusiveStartGlobalTableName: Optional[TableName]
    Limit: Optional[PositiveIntegerObject]
    RegionName: Optional[RegionName]


class ListGlobalTablesOutput(TypedDict, total=False):
    GlobalTables: Optional[GlobalTableList]
    LastEvaluatedGlobalTableName: Optional[TableName]


class ListImportsInput(ServiceRequest):
    TableArn: Optional[TableArn]
    PageSize: Optional[ListImportsMaxLimit]
    NextToken: Optional[ImportNextToken]


class ListImportsOutput(TypedDict, total=False):
    ImportSummaryList: Optional[ImportSummaryList]
    NextToken: Optional[ImportNextToken]


class ListTablesInput(ServiceRequest):
    ExclusiveStartTableName: Optional[TableName]
    Limit: Optional[ListTablesInputLimit]


TableNameList = List[TableName]


class ListTablesOutput(TypedDict, total=False):
    TableNames: Optional[TableNameList]
    LastEvaluatedTableName: Optional[TableName]


class ListTagsOfResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    NextToken: Optional[NextTokenString]


class ListTagsOfResourceOutput(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[NextTokenString]


class PointInTimeRecoverySpecification(TypedDict, total=False):
    PointInTimeRecoveryEnabled: BooleanObject
    RecoveryPeriodInDays: Optional[RecoveryPeriodInDays]


class Put(TypedDict, total=False):
    Item: PutItemInputAttributeMap
    TableName: TableArn
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class PutItemInput(ServiceRequest):
    TableName: TableArn
    Item: PutItemInputAttributeMap
    Expected: Optional[ExpectedAttributeMap]
    ReturnValues: Optional[ReturnValue]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ReturnItemCollectionMetrics: Optional[ReturnItemCollectionMetrics]
    ConditionalOperator: Optional[ConditionalOperator]
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class PutItemOutput(TypedDict, total=False):
    Attributes: Optional[AttributeMap]
    ConsumedCapacity: Optional[ConsumedCapacity]
    ItemCollectionMetrics: Optional[ItemCollectionMetrics]


class PutResourcePolicyInput(ServiceRequest):
    ResourceArn: ResourceArnString
    Policy: ResourcePolicy
    ExpectedRevisionId: Optional[PolicyRevisionId]
    ConfirmRemoveSelfResourceAccess: Optional[ConfirmRemoveSelfResourceAccess]


class PutResourcePolicyOutput(TypedDict, total=False):
    RevisionId: Optional[PolicyRevisionId]


class QueryInput(ServiceRequest):
    TableName: TableArn
    IndexName: Optional[IndexName]
    Select: Optional[Select]
    AttributesToGet: Optional[AttributeNameList]
    Limit: Optional[PositiveIntegerObject]
    ConsistentRead: Optional[ConsistentRead]
    KeyConditions: Optional[KeyConditions]
    QueryFilter: Optional[FilterConditionMap]
    ConditionalOperator: Optional[ConditionalOperator]
    ScanIndexForward: Optional[BooleanObject]
    ExclusiveStartKey: Optional[Key]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ProjectionExpression: Optional[ProjectionExpression]
    FilterExpression: Optional[ConditionExpression]
    KeyConditionExpression: Optional[KeyExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]


class QueryOutput(TypedDict, total=False):
    Items: Optional[ItemList]
    Count: Optional[Integer]
    ScannedCount: Optional[Integer]
    LastEvaluatedKey: Optional[Key]
    ConsumedCapacity: Optional[ConsumedCapacity]


class ReplicaGlobalSecondaryIndexAutoScalingUpdate(TypedDict, total=False):
    IndexName: Optional[IndexName]
    ProvisionedReadCapacityAutoScalingUpdate: Optional[AutoScalingSettingsUpdate]


ReplicaGlobalSecondaryIndexAutoScalingUpdateList = List[
    ReplicaGlobalSecondaryIndexAutoScalingUpdate
]


class ReplicaAutoScalingUpdate(TypedDict, total=False):
    RegionName: RegionName
    ReplicaGlobalSecondaryIndexUpdates: Optional[ReplicaGlobalSecondaryIndexAutoScalingUpdateList]
    ReplicaProvisionedReadCapacityAutoScalingUpdate: Optional[AutoScalingSettingsUpdate]


ReplicaAutoScalingUpdateList = List[ReplicaAutoScalingUpdate]


class ReplicaGlobalSecondaryIndexSettingsUpdate(TypedDict, total=False):
    IndexName: IndexName
    ProvisionedReadCapacityUnits: Optional[PositiveLongObject]
    ProvisionedReadCapacityAutoScalingSettingsUpdate: Optional[AutoScalingSettingsUpdate]


ReplicaGlobalSecondaryIndexSettingsUpdateList = List[ReplicaGlobalSecondaryIndexSettingsUpdate]


class ReplicaSettingsUpdate(TypedDict, total=False):
    RegionName: RegionName
    ReplicaProvisionedReadCapacityUnits: Optional[PositiveLongObject]
    ReplicaProvisionedReadCapacityAutoScalingSettingsUpdate: Optional[AutoScalingSettingsUpdate]
    ReplicaGlobalSecondaryIndexSettingsUpdate: Optional[
        ReplicaGlobalSecondaryIndexSettingsUpdateList
    ]
    ReplicaTableClass: Optional[TableClass]


ReplicaSettingsUpdateList = List[ReplicaSettingsUpdate]


class ReplicaUpdate(TypedDict, total=False):
    Create: Optional[CreateReplicaAction]
    Delete: Optional[DeleteReplicaAction]


ReplicaUpdateList = List[ReplicaUpdate]


class UpdateReplicationGroupMemberAction(TypedDict, total=False):
    RegionName: RegionName
    KMSMasterKeyId: Optional[KMSMasterKeyId]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughputOverride]
    OnDemandThroughputOverride: Optional[OnDemandThroughputOverride]
    GlobalSecondaryIndexes: Optional[ReplicaGlobalSecondaryIndexList]
    TableClassOverride: Optional[TableClass]


class ReplicationGroupUpdate(TypedDict, total=False):
    Create: Optional[CreateReplicationGroupMemberAction]
    Update: Optional[UpdateReplicationGroupMemberAction]
    Delete: Optional[DeleteReplicationGroupMemberAction]


ReplicationGroupUpdateList = List[ReplicationGroupUpdate]


class RestoreTableFromBackupInput(ServiceRequest):
    TargetTableName: TableName
    BackupArn: BackupArn
    BillingModeOverride: Optional[BillingMode]
    GlobalSecondaryIndexOverride: Optional[GlobalSecondaryIndexList]
    LocalSecondaryIndexOverride: Optional[LocalSecondaryIndexList]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughput]
    OnDemandThroughputOverride: Optional[OnDemandThroughput]
    SSESpecificationOverride: Optional[SSESpecification]


class RestoreTableFromBackupOutput(TypedDict, total=False):
    TableDescription: Optional[TableDescription]


class RestoreTableToPointInTimeInput(ServiceRequest):
    SourceTableArn: Optional[TableArn]
    SourceTableName: Optional[TableName]
    TargetTableName: TableName
    UseLatestRestorableTime: Optional[BooleanObject]
    RestoreDateTime: Optional[Date]
    BillingModeOverride: Optional[BillingMode]
    GlobalSecondaryIndexOverride: Optional[GlobalSecondaryIndexList]
    LocalSecondaryIndexOverride: Optional[LocalSecondaryIndexList]
    ProvisionedThroughputOverride: Optional[ProvisionedThroughput]
    OnDemandThroughputOverride: Optional[OnDemandThroughput]
    SSESpecificationOverride: Optional[SSESpecification]


class RestoreTableToPointInTimeOutput(TypedDict, total=False):
    TableDescription: Optional[TableDescription]


class ScanInput(ServiceRequest):
    TableName: TableArn
    IndexName: Optional[IndexName]
    AttributesToGet: Optional[AttributeNameList]
    Limit: Optional[PositiveIntegerObject]
    Select: Optional[Select]
    ScanFilter: Optional[FilterConditionMap]
    ConditionalOperator: Optional[ConditionalOperator]
    ExclusiveStartKey: Optional[Key]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    TotalSegments: Optional[ScanTotalSegments]
    Segment: Optional[ScanSegment]
    ProjectionExpression: Optional[ProjectionExpression]
    FilterExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ConsistentRead: Optional[ConsistentRead]


class ScanOutput(TypedDict, total=False):
    Items: Optional[ItemList]
    Count: Optional[Integer]
    ScannedCount: Optional[Integer]
    LastEvaluatedKey: Optional[Key]
    ConsumedCapacity: Optional[ConsumedCapacity]


TagKeyList = List[TagKeyString]


class TagResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    Tags: TagList


class TimeToLiveSpecification(TypedDict, total=False):
    Enabled: TimeToLiveEnabled
    AttributeName: TimeToLiveAttributeName


class TransactGetItem(TypedDict, total=False):
    Get: Get


TransactGetItemList = List[TransactGetItem]


class TransactGetItemsInput(ServiceRequest):
    TransactItems: TransactGetItemList
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]


class TransactGetItemsOutput(TypedDict, total=False):
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]
    Responses: Optional[ItemResponseList]


class Update(TypedDict, total=False):
    Key: Key
    UpdateExpression: UpdateExpression
    TableName: TableArn
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class TransactWriteItem(TypedDict, total=False):
    ConditionCheck: Optional[ConditionCheck]
    Put: Optional[Put]
    Delete: Optional[Delete]
    Update: Optional[Update]


TransactWriteItemList = List[TransactWriteItem]


class TransactWriteItemsInput(ServiceRequest):
    TransactItems: TransactWriteItemList
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ReturnItemCollectionMetrics: Optional[ReturnItemCollectionMetrics]
    ClientRequestToken: Optional[ClientRequestToken]


class TransactWriteItemsOutput(TypedDict, total=False):
    ConsumedCapacity: Optional[ConsumedCapacityMultiple]
    ItemCollectionMetrics: Optional[ItemCollectionMetricsPerTable]


class UntagResourceInput(ServiceRequest):
    ResourceArn: ResourceArnString
    TagKeys: TagKeyList


class UpdateContinuousBackupsInput(ServiceRequest):
    TableName: TableArn
    PointInTimeRecoverySpecification: PointInTimeRecoverySpecification


class UpdateContinuousBackupsOutput(TypedDict, total=False):
    ContinuousBackupsDescription: Optional[ContinuousBackupsDescription]


class UpdateContributorInsightsInput(ServiceRequest):
    TableName: TableArn
    IndexName: Optional[IndexName]
    ContributorInsightsAction: ContributorInsightsAction


class UpdateContributorInsightsOutput(TypedDict, total=False):
    TableName: Optional[TableName]
    IndexName: Optional[IndexName]
    ContributorInsightsStatus: Optional[ContributorInsightsStatus]


class UpdateGlobalTableInput(ServiceRequest):
    GlobalTableName: TableName
    ReplicaUpdates: ReplicaUpdateList


class UpdateGlobalTableOutput(TypedDict, total=False):
    GlobalTableDescription: Optional[GlobalTableDescription]


class UpdateGlobalTableSettingsInput(ServiceRequest):
    GlobalTableName: TableName
    GlobalTableBillingMode: Optional[BillingMode]
    GlobalTableProvisionedWriteCapacityUnits: Optional[PositiveLongObject]
    GlobalTableProvisionedWriteCapacityAutoScalingSettingsUpdate: Optional[
        AutoScalingSettingsUpdate
    ]
    GlobalTableGlobalSecondaryIndexSettingsUpdate: Optional[
        GlobalTableGlobalSecondaryIndexSettingsUpdateList
    ]
    ReplicaSettingsUpdate: Optional[ReplicaSettingsUpdateList]


class UpdateGlobalTableSettingsOutput(TypedDict, total=False):
    GlobalTableName: Optional[TableName]
    ReplicaSettings: Optional[ReplicaSettingsDescriptionList]


class UpdateItemInput(ServiceRequest):
    TableName: TableArn
    Key: Key
    AttributeUpdates: Optional[AttributeUpdates]
    Expected: Optional[ExpectedAttributeMap]
    ConditionalOperator: Optional[ConditionalOperator]
    ReturnValues: Optional[ReturnValue]
    ReturnConsumedCapacity: Optional[ReturnConsumedCapacity]
    ReturnItemCollectionMetrics: Optional[ReturnItemCollectionMetrics]
    UpdateExpression: Optional[UpdateExpression]
    ConditionExpression: Optional[ConditionExpression]
    ExpressionAttributeNames: Optional[ExpressionAttributeNameMap]
    ExpressionAttributeValues: Optional[ExpressionAttributeValueMap]
    ReturnValuesOnConditionCheckFailure: Optional[ReturnValuesOnConditionCheckFailure]


class UpdateItemOutput(TypedDict, total=False):
    Attributes: Optional[AttributeMap]
    ConsumedCapacity: Optional[ConsumedCapacity]
    ItemCollectionMetrics: Optional[ItemCollectionMetrics]


class UpdateKinesisStreamingConfiguration(TypedDict, total=False):
    ApproximateCreationDateTimePrecision: Optional[ApproximateCreationDateTimePrecision]


class UpdateKinesisStreamingDestinationInput(ServiceRequest):
    TableName: TableArn
    StreamArn: StreamArn
    UpdateKinesisStreamingConfiguration: Optional[UpdateKinesisStreamingConfiguration]


class UpdateKinesisStreamingDestinationOutput(TypedDict, total=False):
    TableName: Optional[TableName]
    StreamArn: Optional[StreamArn]
    DestinationStatus: Optional[DestinationStatus]
    UpdateKinesisStreamingConfiguration: Optional[UpdateKinesisStreamingConfiguration]


class UpdateTableInput(ServiceRequest):
    AttributeDefinitions: Optional[AttributeDefinitions]
    TableName: TableArn
    BillingMode: Optional[BillingMode]
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    GlobalSecondaryIndexUpdates: Optional[GlobalSecondaryIndexUpdateList]
    StreamSpecification: Optional[StreamSpecification]
    SSESpecification: Optional[SSESpecification]
    ReplicaUpdates: Optional[ReplicationGroupUpdateList]
    TableClass: Optional[TableClass]
    DeletionProtectionEnabled: Optional[DeletionProtectionEnabled]
    MultiRegionConsistency: Optional[MultiRegionConsistency]
    OnDemandThroughput: Optional[OnDemandThroughput]
    WarmThroughput: Optional[WarmThroughput]


class UpdateTableOutput(TypedDict, total=False):
    TableDescription: Optional[TableDescription]


class UpdateTableReplicaAutoScalingInput(ServiceRequest):
    GlobalSecondaryIndexUpdates: Optional[GlobalSecondaryIndexAutoScalingUpdateList]
    TableName: TableArn
    ProvisionedWriteCapacityAutoScalingUpdate: Optional[AutoScalingSettingsUpdate]
    ReplicaUpdates: Optional[ReplicaAutoScalingUpdateList]


class UpdateTableReplicaAutoScalingOutput(TypedDict, total=False):
    TableAutoScalingDescription: Optional[TableAutoScalingDescription]


class UpdateTimeToLiveInput(ServiceRequest):
    TableName: TableArn
    TimeToLiveSpecification: TimeToLiveSpecification


class UpdateTimeToLiveOutput(TypedDict, total=False):
    TimeToLiveSpecification: Optional[TimeToLiveSpecification]


class DynamodbApi:
    service = "dynamodb"
    version = "2012-08-10"

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
