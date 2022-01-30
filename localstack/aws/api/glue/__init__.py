import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
AttemptCount = int
AuditContextString = str
BatchSize = int
BatchWindow = int
BlueprintParameterSpec = str
BlueprintParameters = str
Boolean = bool
BooleanNullable = bool
BooleanValue = bool
CatalogGetterPageSize = int
CatalogIdString = str
Classification = str
CodeGenArgName = str
CodeGenArgValue = str
CodeGenIdentifier = str
CodeGenNodeType = str
ColumnNameString = str
ColumnTypeString = str
ColumnValuesString = str
CommentString = str
ConnectionName = str
CrawlerConfiguration = str
CrawlerSecurityConfiguration = str
CreatedTimestamp = str
CronExpression = str
CsvColumnDelimiter = str
CsvQuoteSymbol = str
CustomPatterns = str
DataLakePrincipalString = str
DatabaseName = str
DescriptionString = str
DescriptionStringRemovable = str
Double = float
ErrorCodeString = str
ErrorMessageString = str
ErrorString = str
EventQueueArn = str
ExecutionTime = int
FieldType = str
FilterString = str
FormatString = str
Generic512CharString = str
GenericBoundedDouble = float
GenericString = str
GlueResourceArn = str
GlueVersionString = str
GrokPattern = str
HashString = str
IdString = str
Integer = int
IntegerFlag = int
IntegerValue = int
IsVersionValid = bool
JobName = str
JsonPath = str
JsonValue = str
KeyString = str
KmsKeyArn = str
LabelCount = int
LatestSchemaVersionBoolean = bool
LocationString = str
LogGroup = str
LogStream = str
MaxConcurrentRuns = int
MaxResultsNumber = int
MaxRetries = int
MessagePrefix = str
MessageString = str
MetadataKeyString = str
MetadataValueString = str
NameString = str
NonNegativeDouble = float
NonNegativeInteger = int
NotifyDelayAfter = int
NullableBoolean = bool
NullableDouble = float
NullableInteger = int
OrchestrationIAMRoleArn = str
OrchestrationNameString = str
OrchestrationS3Location = str
PageSize = int
PaginationToken = str
ParametersMapValue = str
Path = str
PolicyJsonString = str
PredicateString = str
PythonScript = str
PythonVersionString = str
QuerySchemaVersionMetadataMaxResults = int
ReplaceBoolean = bool
Role = str
RoleArn = str
RoleString = str
RowTag = str
RunId = str
ScalaCode = str
SchemaDefinitionDiff = str
SchemaDefinitionString = str
SchemaPathString = str
SchemaRegistryNameString = str
SchemaRegistryTokenString = str
SchemaValidationError = str
SchemaVersionIdString = str
ScriptLocationString = str
TableName = str
TablePrefix = str
TableTypeString = str
TagKey = str
TagValue = str
Timeout = int
Token = str
TotalSegmentsInteger = int
TransactionIdString = str
TypeString = str
URI = str
UpdatedTimestamp = str
UriString = str
ValueString = str
VersionString = str
VersionsString = str
ViewTextString = str


class BackfillErrorCode(str):
    ENCRYPTED_PARTITION_ERROR = "ENCRYPTED_PARTITION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_PARTITION_TYPE_DATA_ERROR = "INVALID_PARTITION_TYPE_DATA_ERROR"
    MISSING_PARTITION_VALUE_ERROR = "MISSING_PARTITION_VALUE_ERROR"
    UNSUPPORTED_PARTITION_CHARACTER_ERROR = "UNSUPPORTED_PARTITION_CHARACTER_ERROR"


class BlueprintRunState(str):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"


class BlueprintStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    UPDATING = "UPDATING"
    FAILED = "FAILED"


class CatalogEncryptionMode(str):
    DISABLED = "DISABLED"
    SSE_KMS = "SSE-KMS"


class CloudWatchEncryptionMode(str):
    DISABLED = "DISABLED"
    SSE_KMS = "SSE-KMS"


class ColumnStatisticsType(str):
    BOOLEAN = "BOOLEAN"
    DATE = "DATE"
    DECIMAL = "DECIMAL"
    DOUBLE = "DOUBLE"
    LONG = "LONG"
    STRING = "STRING"
    BINARY = "BINARY"


class Comparator(str):
    EQUALS = "EQUALS"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN_EQUALS = "GREATER_THAN_EQUALS"
    LESS_THAN_EQUALS = "LESS_THAN_EQUALS"


class Compatibility(str):
    NONE = "NONE"
    DISABLED = "DISABLED"
    BACKWARD = "BACKWARD"
    BACKWARD_ALL = "BACKWARD_ALL"
    FORWARD = "FORWARD"
    FORWARD_ALL = "FORWARD_ALL"
    FULL = "FULL"
    FULL_ALL = "FULL_ALL"


class ConnectionPropertyKey(str):
    HOST = "HOST"
    PORT = "PORT"
    USERNAME = "USERNAME"
    PASSWORD = "PASSWORD"
    ENCRYPTED_PASSWORD = "ENCRYPTED_PASSWORD"
    JDBC_DRIVER_JAR_URI = "JDBC_DRIVER_JAR_URI"
    JDBC_DRIVER_CLASS_NAME = "JDBC_DRIVER_CLASS_NAME"
    JDBC_ENGINE = "JDBC_ENGINE"
    JDBC_ENGINE_VERSION = "JDBC_ENGINE_VERSION"
    CONFIG_FILES = "CONFIG_FILES"
    INSTANCE_ID = "INSTANCE_ID"
    JDBC_CONNECTION_URL = "JDBC_CONNECTION_URL"
    JDBC_ENFORCE_SSL = "JDBC_ENFORCE_SSL"
    CUSTOM_JDBC_CERT = "CUSTOM_JDBC_CERT"
    SKIP_CUSTOM_JDBC_CERT_VALIDATION = "SKIP_CUSTOM_JDBC_CERT_VALIDATION"
    CUSTOM_JDBC_CERT_STRING = "CUSTOM_JDBC_CERT_STRING"
    CONNECTION_URL = "CONNECTION_URL"
    KAFKA_BOOTSTRAP_SERVERS = "KAFKA_BOOTSTRAP_SERVERS"
    KAFKA_SSL_ENABLED = "KAFKA_SSL_ENABLED"
    KAFKA_CUSTOM_CERT = "KAFKA_CUSTOM_CERT"
    KAFKA_SKIP_CUSTOM_CERT_VALIDATION = "KAFKA_SKIP_CUSTOM_CERT_VALIDATION"
    KAFKA_CLIENT_KEYSTORE = "KAFKA_CLIENT_KEYSTORE"
    KAFKA_CLIENT_KEYSTORE_PASSWORD = "KAFKA_CLIENT_KEYSTORE_PASSWORD"
    KAFKA_CLIENT_KEY_PASSWORD = "KAFKA_CLIENT_KEY_PASSWORD"
    ENCRYPTED_KAFKA_CLIENT_KEYSTORE_PASSWORD = "ENCRYPTED_KAFKA_CLIENT_KEYSTORE_PASSWORD"
    ENCRYPTED_KAFKA_CLIENT_KEY_PASSWORD = "ENCRYPTED_KAFKA_CLIENT_KEY_PASSWORD"
    SECRET_ID = "SECRET_ID"
    CONNECTOR_URL = "CONNECTOR_URL"
    CONNECTOR_TYPE = "CONNECTOR_TYPE"
    CONNECTOR_CLASS_NAME = "CONNECTOR_CLASS_NAME"


class ConnectionType(str):
    JDBC = "JDBC"
    SFTP = "SFTP"
    MONGODB = "MONGODB"
    KAFKA = "KAFKA"
    NETWORK = "NETWORK"
    MARKETPLACE = "MARKETPLACE"
    CUSTOM = "CUSTOM"


class CrawlState(str):
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class CrawlerLineageSettings(str):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"


class CrawlerState(str):
    READY = "READY"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"


class CsvHeaderOption(str):
    UNKNOWN = "UNKNOWN"
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"


class DataFormat(str):
    AVRO = "AVRO"
    JSON = "JSON"
    PROTOBUF = "PROTOBUF"


class DeleteBehavior(str):
    LOG = "LOG"
    DELETE_FROM_DATABASE = "DELETE_FROM_DATABASE"
    DEPRECATE_IN_DATABASE = "DEPRECATE_IN_DATABASE"


class EnableHybridValues(str):
    TRUE = "TRUE"
    FALSE = "FALSE"


class ExistCondition(str):
    MUST_EXIST = "MUST_EXIST"
    NOT_EXIST = "NOT_EXIST"
    NONE = "NONE"


class JobBookmarksEncryptionMode(str):
    DISABLED = "DISABLED"
    CSE_KMS = "CSE-KMS"


class JobRunState(str):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class Language(str):
    PYTHON = "PYTHON"
    SCALA = "SCALA"


class LastCrawlStatus(str):
    SUCCEEDED = "SUCCEEDED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class Logical(str):
    AND = "AND"
    ANY = "ANY"


class LogicalOperator(str):
    EQUALS = "EQUALS"


class MLUserDataEncryptionModeString(str):
    DISABLED = "DISABLED"
    SSE_KMS = "SSE-KMS"


class NodeType(str):
    CRAWLER = "CRAWLER"
    JOB = "JOB"
    TRIGGER = "TRIGGER"


class PartitionIndexStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    FAILED = "FAILED"


class Permission(str):
    ALL = "ALL"
    SELECT = "SELECT"
    ALTER = "ALTER"
    DROP = "DROP"
    DELETE = "DELETE"
    INSERT = "INSERT"
    CREATE_DATABASE = "CREATE_DATABASE"
    CREATE_TABLE = "CREATE_TABLE"
    DATA_LOCATION_ACCESS = "DATA_LOCATION_ACCESS"


class PermissionType(str):
    COLUMN_PERMISSION = "COLUMN_PERMISSION"
    CELL_FILTER_PERMISSION = "CELL_FILTER_PERMISSION"


class PrincipalType(str):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"


class RecrawlBehavior(str):
    CRAWL_EVERYTHING = "CRAWL_EVERYTHING"
    CRAWL_NEW_FOLDERS_ONLY = "CRAWL_NEW_FOLDERS_ONLY"
    CRAWL_EVENT_MODE = "CRAWL_EVENT_MODE"


class RegistryStatus(str):
    AVAILABLE = "AVAILABLE"
    DELETING = "DELETING"


class ResourceShareType(str):
    FOREIGN = "FOREIGN"
    ALL = "ALL"


class ResourceType(str):
    JAR = "JAR"
    FILE = "FILE"
    ARCHIVE = "ARCHIVE"


class S3EncryptionMode(str):
    DISABLED = "DISABLED"
    SSE_KMS = "SSE-KMS"
    SSE_S3 = "SSE-S3"


class ScheduleState(str):
    SCHEDULED = "SCHEDULED"
    NOT_SCHEDULED = "NOT_SCHEDULED"
    TRANSITIONING = "TRANSITIONING"


class SchemaDiffType(str):
    SYNTAX_DIFF = "SYNTAX_DIFF"


class SchemaStatus(str):
    AVAILABLE = "AVAILABLE"
    PENDING = "PENDING"
    DELETING = "DELETING"


class SchemaVersionStatus(str):
    AVAILABLE = "AVAILABLE"
    PENDING = "PENDING"
    FAILURE = "FAILURE"
    DELETING = "DELETING"


class Sort(str):
    ASC = "ASC"
    DESC = "DESC"


class SortDirectionType(str):
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"


class TaskRunSortColumnType(str):
    TASK_RUN_TYPE = "TASK_RUN_TYPE"
    STATUS = "STATUS"
    STARTED = "STARTED"


class TaskStatusType(str):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class TaskType(str):
    EVALUATION = "EVALUATION"
    LABELING_SET_GENERATION = "LABELING_SET_GENERATION"
    IMPORT_LABELS = "IMPORT_LABELS"
    EXPORT_LABELS = "EXPORT_LABELS"
    FIND_MATCHES = "FIND_MATCHES"


class TransformSortColumnType(str):
    NAME = "NAME"
    TRANSFORM_TYPE = "TRANSFORM_TYPE"
    STATUS = "STATUS"
    CREATED = "CREATED"
    LAST_MODIFIED = "LAST_MODIFIED"


class TransformStatusType(str):
    NOT_READY = "NOT_READY"
    READY = "READY"
    DELETING = "DELETING"


class TransformType(str):
    FIND_MATCHES = "FIND_MATCHES"


class TriggerState(str):
    CREATING = "CREATING"
    CREATED = "CREATED"
    ACTIVATING = "ACTIVATING"
    ACTIVATED = "ACTIVATED"
    DEACTIVATING = "DEACTIVATING"
    DEACTIVATED = "DEACTIVATED"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class TriggerType(str):
    SCHEDULED = "SCHEDULED"
    CONDITIONAL = "CONDITIONAL"
    ON_DEMAND = "ON_DEMAND"
    EVENT = "EVENT"


class UpdateBehavior(str):
    LOG = "LOG"
    UPDATE_IN_DATABASE = "UPDATE_IN_DATABASE"


class WorkerType(str):
    Standard = "Standard"
    G_1X = "G.1X"
    G_2X = "G.2X"


class WorkflowRunStatus(str):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class AccessDeniedException(ServiceException):
    Message: Optional[MessageString]


class AlreadyExistsException(ServiceException):
    Message: Optional[MessageString]


class ConcurrentModificationException(ServiceException):
    Message: Optional[MessageString]


class ConcurrentRunsExceededException(ServiceException):
    Message: Optional[MessageString]


class ConditionCheckFailureException(ServiceException):
    Message: Optional[MessageString]


class ConflictException(ServiceException):
    Message: Optional[MessageString]


class CrawlerNotRunningException(ServiceException):
    Message: Optional[MessageString]


class CrawlerRunningException(ServiceException):
    Message: Optional[MessageString]


class CrawlerStoppingException(ServiceException):
    Message: Optional[MessageString]


class EntityNotFoundException(ServiceException):
    Message: Optional[MessageString]


class GlueEncryptionException(ServiceException):
    Message: Optional[MessageString]


class IdempotentParameterMismatchException(ServiceException):
    Message: Optional[MessageString]


class IllegalBlueprintStateException(ServiceException):
    Message: Optional[MessageString]


class IllegalWorkflowStateException(ServiceException):
    Message: Optional[MessageString]


class InternalServiceException(ServiceException):
    Message: Optional[MessageString]


class InvalidInputException(ServiceException):
    Message: Optional[MessageString]


class InvalidStateException(ServiceException):
    Message: Optional[MessageString]


class MLTransformNotReadyException(ServiceException):
    Message: Optional[MessageString]


class NoScheduleException(ServiceException):
    Message: Optional[MessageString]


class OperationTimeoutException(ServiceException):
    Message: Optional[MessageString]


class PermissionTypeMismatchException(ServiceException):
    Message: Optional[MessageString]


class ResourceNotReadyException(ServiceException):
    Message: Optional[MessageString]


class ResourceNumberLimitExceededException(ServiceException):
    Message: Optional[MessageString]


class SchedulerNotRunningException(ServiceException):
    Message: Optional[MessageString]


class SchedulerRunningException(ServiceException):
    Message: Optional[MessageString]


class SchedulerTransitioningException(ServiceException):
    Message: Optional[MessageString]


class ValidationException(ServiceException):
    Message: Optional[MessageString]


class VersionMismatchException(ServiceException):
    Message: Optional[MessageString]


class NotificationProperty(TypedDict, total=False):
    NotifyDelayAfter: Optional[NotifyDelayAfter]


GenericMap = Dict[GenericString, GenericString]


class Action(TypedDict, total=False):
    JobName: Optional[NameString]
    Arguments: Optional[GenericMap]
    Timeout: Optional[Timeout]
    SecurityConfiguration: Optional[NameString]
    NotificationProperty: Optional[NotificationProperty]
    CrawlerName: Optional[NameString]


ActionList = List[Action]
AdditionalPlanOptionsMap = Dict[GenericString, GenericString]


class AuditContext(TypedDict, total=False):
    AdditionalAuditContext: Optional[AuditContextString]


ValueStringList = List[ValueString]


class PartitionValueList(TypedDict, total=False):
    Values: ValueStringList


BackfillErroredPartitionsList = List[PartitionValueList]


class BackfillError(TypedDict, total=False):
    Code: Optional[BackfillErrorCode]
    Partitions: Optional[BackfillErroredPartitionsList]


BackfillErrors = List[BackfillError]
Timestamp = datetime
ParametersMap = Dict[KeyString, ParametersMapValue]
VersionLongNumber = int


class SchemaId(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    RegistryName: Optional[SchemaRegistryNameString]


class SchemaReference(TypedDict, total=False):
    SchemaId: Optional[SchemaId]
    SchemaVersionId: Optional[SchemaVersionIdString]
    SchemaVersionNumber: Optional[VersionLongNumber]


LocationMap = Dict[ColumnValuesString, ColumnValuesString]
ColumnValueStringList = List[ColumnValuesString]
NameStringList = List[NameString]


class SkewedInfo(TypedDict, total=False):
    SkewedColumnNames: Optional[NameStringList]
    SkewedColumnValues: Optional[ColumnValueStringList]
    SkewedColumnValueLocationMaps: Optional[LocationMap]


class Order(TypedDict, total=False):
    Column: NameString
    SortOrder: IntegerFlag


OrderList = List[Order]


class SerDeInfo(TypedDict, total=False):
    Name: Optional[NameString]
    SerializationLibrary: Optional[NameString]
    Parameters: Optional[ParametersMap]


LocationStringList = List[LocationString]


class Column(TypedDict, total=False):
    Name: NameString
    Type: Optional[ColumnTypeString]
    Comment: Optional[CommentString]
    Parameters: Optional[ParametersMap]


ColumnList = List[Column]


class StorageDescriptor(TypedDict, total=False):
    Columns: Optional[ColumnList]
    Location: Optional[LocationString]
    AdditionalLocations: Optional[LocationStringList]
    InputFormat: Optional[FormatString]
    OutputFormat: Optional[FormatString]
    Compressed: Optional[Boolean]
    NumberOfBuckets: Optional[Integer]
    SerdeInfo: Optional[SerDeInfo]
    BucketColumns: Optional[NameStringList]
    SortColumns: Optional[OrderList]
    Parameters: Optional[ParametersMap]
    SkewedInfo: Optional[SkewedInfo]
    StoredAsSubDirectories: Optional[Boolean]
    SchemaReference: Optional[SchemaReference]


class PartitionInput(TypedDict, total=False):
    Values: Optional[ValueStringList]
    LastAccessTime: Optional[Timestamp]
    StorageDescriptor: Optional[StorageDescriptor]
    Parameters: Optional[ParametersMap]
    LastAnalyzedTime: Optional[Timestamp]


PartitionInputList = List[PartitionInput]


class BatchCreatePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionInputList: PartitionInputList


class ErrorDetail(TypedDict, total=False):
    ErrorCode: Optional[NameString]
    ErrorMessage: Optional[DescriptionString]


class PartitionError(TypedDict, total=False):
    PartitionValues: Optional[ValueStringList]
    ErrorDetail: Optional[ErrorDetail]


PartitionErrors = List[PartitionError]


class BatchCreatePartitionResponse(TypedDict, total=False):
    Errors: Optional[PartitionErrors]


DeleteConnectionNameList = List[NameString]


class BatchDeleteConnectionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    ConnectionNameList: DeleteConnectionNameList


ErrorByName = Dict[NameString, ErrorDetail]


class BatchDeleteConnectionResponse(TypedDict, total=False):
    Succeeded: Optional[NameStringList]
    Errors: Optional[ErrorByName]


BatchDeletePartitionValueList = List[PartitionValueList]


class BatchDeletePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionsToDelete: BatchDeletePartitionValueList


class BatchDeletePartitionResponse(TypedDict, total=False):
    Errors: Optional[PartitionErrors]


BatchDeleteTableNameList = List[NameString]


class BatchDeleteTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TablesToDelete: BatchDeleteTableNameList
    TransactionId: Optional[TransactionIdString]


class TableError(TypedDict, total=False):
    TableName: Optional[NameString]
    ErrorDetail: Optional[ErrorDetail]


TableErrors = List[TableError]


class BatchDeleteTableResponse(TypedDict, total=False):
    Errors: Optional[TableErrors]


BatchDeleteTableVersionList = List[VersionString]


class BatchDeleteTableVersionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    VersionIds: BatchDeleteTableVersionList


class TableVersionError(TypedDict, total=False):
    TableName: Optional[NameString]
    VersionId: Optional[VersionString]
    ErrorDetail: Optional[ErrorDetail]


TableVersionErrors = List[TableVersionError]


class BatchDeleteTableVersionResponse(TypedDict, total=False):
    Errors: Optional[TableVersionErrors]


BatchGetBlueprintNames = List[OrchestrationNameString]


class BatchGetBlueprintsRequest(ServiceRequest):
    Names: BatchGetBlueprintNames
    IncludeBlueprint: Optional[NullableBoolean]
    IncludeParameterSpec: Optional[NullableBoolean]


BlueprintNames = List[OrchestrationNameString]
TimestampValue = datetime


class LastActiveDefinition(TypedDict, total=False):
    Description: Optional[Generic512CharString]
    LastModifiedOn: Optional[TimestampValue]
    ParameterSpec: Optional[BlueprintParameterSpec]
    BlueprintLocation: Optional[GenericString]
    BlueprintServiceLocation: Optional[GenericString]


class Blueprint(TypedDict, total=False):
    Name: Optional[OrchestrationNameString]
    Description: Optional[Generic512CharString]
    CreatedOn: Optional[TimestampValue]
    LastModifiedOn: Optional[TimestampValue]
    ParameterSpec: Optional[BlueprintParameterSpec]
    BlueprintLocation: Optional[GenericString]
    BlueprintServiceLocation: Optional[GenericString]
    Status: Optional[BlueprintStatus]
    ErrorMessage: Optional[ErrorString]
    LastActiveDefinition: Optional[LastActiveDefinition]


Blueprints = List[Blueprint]


class BatchGetBlueprintsResponse(TypedDict, total=False):
    Blueprints: Optional[Blueprints]
    MissingBlueprints: Optional[BlueprintNames]


CrawlerNameList = List[NameString]


class BatchGetCrawlersRequest(ServiceRequest):
    CrawlerNames: CrawlerNameList


class LakeFormationConfiguration(TypedDict, total=False):
    UseLakeFormationCredentials: Optional[NullableBoolean]
    AccountId: Optional[AccountId]


VersionId = int


class LastCrawlInfo(TypedDict, total=False):
    Status: Optional[LastCrawlStatus]
    ErrorMessage: Optional[DescriptionString]
    LogGroup: Optional[LogGroup]
    LogStream: Optional[LogStream]
    MessagePrefix: Optional[MessagePrefix]
    StartTime: Optional[Timestamp]


MillisecondsCount = int


class Schedule(TypedDict, total=False):
    ScheduleExpression: Optional[CronExpression]
    State: Optional[ScheduleState]


class LineageConfiguration(TypedDict, total=False):
    CrawlerLineageSettings: Optional[CrawlerLineageSettings]


class SchemaChangePolicy(TypedDict, total=False):
    UpdateBehavior: Optional[UpdateBehavior]
    DeleteBehavior: Optional[DeleteBehavior]


class RecrawlPolicy(TypedDict, total=False):
    RecrawlBehavior: Optional[RecrawlBehavior]


ClassifierNameList = List[NameString]
PathList = List[Path]


class DeltaTarget(TypedDict, total=False):
    DeltaTables: Optional[PathList]
    ConnectionName: Optional[ConnectionName]
    WriteManifest: Optional[NullableBoolean]


DeltaTargetList = List[DeltaTarget]
CatalogTablesList = List[NameString]


class CatalogTarget(TypedDict, total=False):
    DatabaseName: NameString
    Tables: CatalogTablesList
    ConnectionName: Optional[ConnectionName]


CatalogTargetList = List[CatalogTarget]


class DynamoDBTarget(TypedDict, total=False):
    Path: Optional[Path]
    scanAll: Optional[NullableBoolean]
    scanRate: Optional[NullableDouble]


DynamoDBTargetList = List[DynamoDBTarget]


class MongoDBTarget(TypedDict, total=False):
    ConnectionName: Optional[ConnectionName]
    Path: Optional[Path]
    ScanAll: Optional[NullableBoolean]


MongoDBTargetList = List[MongoDBTarget]


class JdbcTarget(TypedDict, total=False):
    ConnectionName: Optional[ConnectionName]
    Path: Optional[Path]
    Exclusions: Optional[PathList]


JdbcTargetList = List[JdbcTarget]


class S3Target(TypedDict, total=False):
    Path: Optional[Path]
    Exclusions: Optional[PathList]
    ConnectionName: Optional[ConnectionName]
    SampleSize: Optional[NullableInteger]
    EventQueueArn: Optional[EventQueueArn]
    DlqEventQueueArn: Optional[EventQueueArn]


S3TargetList = List[S3Target]


class CrawlerTargets(TypedDict, total=False):
    S3Targets: Optional[S3TargetList]
    JdbcTargets: Optional[JdbcTargetList]
    MongoDBTargets: Optional[MongoDBTargetList]
    DynamoDBTargets: Optional[DynamoDBTargetList]
    CatalogTargets: Optional[CatalogTargetList]
    DeltaTargets: Optional[DeltaTargetList]


class Crawler(TypedDict, total=False):
    Name: Optional[NameString]
    Role: Optional[Role]
    Targets: Optional[CrawlerTargets]
    DatabaseName: Optional[DatabaseName]
    Description: Optional[DescriptionString]
    Classifiers: Optional[ClassifierNameList]
    RecrawlPolicy: Optional[RecrawlPolicy]
    SchemaChangePolicy: Optional[SchemaChangePolicy]
    LineageConfiguration: Optional[LineageConfiguration]
    State: Optional[CrawlerState]
    TablePrefix: Optional[TablePrefix]
    Schedule: Optional[Schedule]
    CrawlElapsedTime: Optional[MillisecondsCount]
    CreationTime: Optional[Timestamp]
    LastUpdated: Optional[Timestamp]
    LastCrawl: Optional[LastCrawlInfo]
    Version: Optional[VersionId]
    Configuration: Optional[CrawlerConfiguration]
    CrawlerSecurityConfiguration: Optional[CrawlerSecurityConfiguration]
    LakeFormationConfiguration: Optional[LakeFormationConfiguration]


CrawlerList = List[Crawler]


class BatchGetCrawlersResponse(TypedDict, total=False):
    Crawlers: Optional[CrawlerList]
    CrawlersNotFound: Optional[CrawlerNameList]


DevEndpointNames = List[GenericString]


class BatchGetDevEndpointsRequest(ServiceRequest):
    DevEndpointNames: DevEndpointNames


MapValue = Dict[GenericString, GenericString]
PublicKeysList = List[GenericString]
StringList = List[GenericString]


class DevEndpoint(TypedDict, total=False):
    EndpointName: Optional[GenericString]
    RoleArn: Optional[RoleArn]
    SecurityGroupIds: Optional[StringList]
    SubnetId: Optional[GenericString]
    YarnEndpointAddress: Optional[GenericString]
    PrivateAddress: Optional[GenericString]
    ZeppelinRemoteSparkInterpreterPort: Optional[IntegerValue]
    PublicAddress: Optional[GenericString]
    Status: Optional[GenericString]
    WorkerType: Optional[WorkerType]
    GlueVersion: Optional[GlueVersionString]
    NumberOfWorkers: Optional[NullableInteger]
    NumberOfNodes: Optional[IntegerValue]
    AvailabilityZone: Optional[GenericString]
    VpcId: Optional[GenericString]
    ExtraPythonLibsS3Path: Optional[GenericString]
    ExtraJarsS3Path: Optional[GenericString]
    FailureReason: Optional[GenericString]
    LastUpdateStatus: Optional[GenericString]
    CreatedTimestamp: Optional[TimestampValue]
    LastModifiedTimestamp: Optional[TimestampValue]
    PublicKey: Optional[GenericString]
    PublicKeys: Optional[PublicKeysList]
    SecurityConfiguration: Optional[NameString]
    Arguments: Optional[MapValue]


DevEndpointList = List[DevEndpoint]


class BatchGetDevEndpointsResponse(TypedDict, total=False):
    DevEndpoints: Optional[DevEndpointList]
    DevEndpointsNotFound: Optional[DevEndpointNames]


JobNameList = List[NameString]


class BatchGetJobsRequest(ServiceRequest):
    JobNames: JobNameList


OrchestrationStringList = List[GenericString]


class ConnectionsList(TypedDict, total=False):
    Connections: Optional[OrchestrationStringList]


class JobCommand(TypedDict, total=False):
    Name: Optional[GenericString]
    ScriptLocation: Optional[ScriptLocationString]
    PythonVersion: Optional[PythonVersionString]


class ExecutionProperty(TypedDict, total=False):
    MaxConcurrentRuns: Optional[MaxConcurrentRuns]


class Job(TypedDict, total=False):
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    LogUri: Optional[UriString]
    Role: Optional[RoleString]
    CreatedOn: Optional[TimestampValue]
    LastModifiedOn: Optional[TimestampValue]
    ExecutionProperty: Optional[ExecutionProperty]
    Command: Optional[JobCommand]
    DefaultArguments: Optional[GenericMap]
    NonOverridableArguments: Optional[GenericMap]
    Connections: Optional[ConnectionsList]
    MaxRetries: Optional[MaxRetries]
    AllocatedCapacity: Optional[IntegerValue]
    Timeout: Optional[Timeout]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    SecurityConfiguration: Optional[NameString]
    NotificationProperty: Optional[NotificationProperty]
    GlueVersion: Optional[GlueVersionString]


JobList = List[Job]


class BatchGetJobsResponse(TypedDict, total=False):
    Jobs: Optional[JobList]
    JobsNotFound: Optional[JobNameList]


BatchGetPartitionValueList = List[PartitionValueList]


class BatchGetPartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionsToGet: BatchGetPartitionValueList


class Partition(TypedDict, total=False):
    Values: Optional[ValueStringList]
    DatabaseName: Optional[NameString]
    TableName: Optional[NameString]
    CreationTime: Optional[Timestamp]
    LastAccessTime: Optional[Timestamp]
    StorageDescriptor: Optional[StorageDescriptor]
    Parameters: Optional[ParametersMap]
    LastAnalyzedTime: Optional[Timestamp]
    CatalogId: Optional[CatalogIdString]


PartitionList = List[Partition]


class BatchGetPartitionResponse(TypedDict, total=False):
    Partitions: Optional[PartitionList]
    UnprocessedKeys: Optional[BatchGetPartitionValueList]


TriggerNameList = List[NameString]


class BatchGetTriggersRequest(ServiceRequest):
    TriggerNames: TriggerNameList


class EventBatchingCondition(TypedDict, total=False):
    BatchSize: BatchSize
    BatchWindow: Optional[BatchWindow]


class Condition(TypedDict, total=False):
    LogicalOperator: Optional[LogicalOperator]
    JobName: Optional[NameString]
    State: Optional[JobRunState]
    CrawlerName: Optional[NameString]
    CrawlState: Optional[CrawlState]


ConditionList = List[Condition]


class Predicate(TypedDict, total=False):
    Logical: Optional[Logical]
    Conditions: Optional[ConditionList]


class Trigger(TypedDict, total=False):
    Name: Optional[NameString]
    WorkflowName: Optional[NameString]
    Id: Optional[IdString]
    Type: Optional[TriggerType]
    State: Optional[TriggerState]
    Description: Optional[DescriptionString]
    Schedule: Optional[GenericString]
    Actions: Optional[ActionList]
    Predicate: Optional[Predicate]
    EventBatchingCondition: Optional[EventBatchingCondition]


TriggerList = List[Trigger]


class BatchGetTriggersResponse(TypedDict, total=False):
    Triggers: Optional[TriggerList]
    TriggersNotFound: Optional[TriggerNameList]


WorkflowNames = List[NameString]


class BatchGetWorkflowsRequest(ServiceRequest):
    Names: WorkflowNames
    IncludeGraph: Optional[NullableBoolean]


class BlueprintDetails(TypedDict, total=False):
    BlueprintName: Optional[OrchestrationNameString]
    RunId: Optional[IdString]


class Edge(TypedDict, total=False):
    SourceId: Optional[NameString]
    DestinationId: Optional[NameString]


EdgeList = List[Edge]


class Crawl(TypedDict, total=False):
    State: Optional[CrawlState]
    StartedOn: Optional[TimestampValue]
    CompletedOn: Optional[TimestampValue]
    ErrorMessage: Optional[DescriptionString]
    LogGroup: Optional[LogGroup]
    LogStream: Optional[LogStream]


CrawlList = List[Crawl]


class CrawlerNodeDetails(TypedDict, total=False):
    Crawls: Optional[CrawlList]


class Predecessor(TypedDict, total=False):
    JobName: Optional[NameString]
    RunId: Optional[IdString]


PredecessorList = List[Predecessor]


class JobRun(TypedDict, total=False):
    Id: Optional[IdString]
    Attempt: Optional[AttemptCount]
    PreviousRunId: Optional[IdString]
    TriggerName: Optional[NameString]
    JobName: Optional[NameString]
    StartedOn: Optional[TimestampValue]
    LastModifiedOn: Optional[TimestampValue]
    CompletedOn: Optional[TimestampValue]
    JobRunState: Optional[JobRunState]
    Arguments: Optional[GenericMap]
    ErrorMessage: Optional[ErrorString]
    PredecessorRuns: Optional[PredecessorList]
    AllocatedCapacity: Optional[IntegerValue]
    ExecutionTime: Optional[ExecutionTime]
    Timeout: Optional[Timeout]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    SecurityConfiguration: Optional[NameString]
    LogGroupName: Optional[GenericString]
    NotificationProperty: Optional[NotificationProperty]
    GlueVersion: Optional[GlueVersionString]


JobRunList = List[JobRun]


class JobNodeDetails(TypedDict, total=False):
    JobRuns: Optional[JobRunList]


class TriggerNodeDetails(TypedDict, total=False):
    Trigger: Optional[Trigger]


class Node(TypedDict, total=False):
    Type: Optional[NodeType]
    Name: Optional[NameString]
    UniqueId: Optional[NameString]
    TriggerDetails: Optional[TriggerNodeDetails]
    JobDetails: Optional[JobNodeDetails]
    CrawlerDetails: Optional[CrawlerNodeDetails]


NodeList = List[Node]


class WorkflowGraph(TypedDict, total=False):
    Nodes: Optional[NodeList]
    Edges: Optional[EdgeList]


class StartingEventBatchCondition(TypedDict, total=False):
    BatchSize: Optional[NullableInteger]
    BatchWindow: Optional[NullableInteger]


class WorkflowRunStatistics(TypedDict, total=False):
    TotalActions: Optional[IntegerValue]
    TimeoutActions: Optional[IntegerValue]
    FailedActions: Optional[IntegerValue]
    StoppedActions: Optional[IntegerValue]
    SucceededActions: Optional[IntegerValue]
    RunningActions: Optional[IntegerValue]


WorkflowRunProperties = Dict[IdString, GenericString]


class WorkflowRun(TypedDict, total=False):
    Name: Optional[NameString]
    WorkflowRunId: Optional[IdString]
    PreviousRunId: Optional[IdString]
    WorkflowRunProperties: Optional[WorkflowRunProperties]
    StartedOn: Optional[TimestampValue]
    CompletedOn: Optional[TimestampValue]
    Status: Optional[WorkflowRunStatus]
    ErrorMessage: Optional[ErrorString]
    Statistics: Optional[WorkflowRunStatistics]
    Graph: Optional[WorkflowGraph]
    StartingEventBatchCondition: Optional[StartingEventBatchCondition]


class Workflow(TypedDict, total=False):
    Name: Optional[NameString]
    Description: Optional[GenericString]
    DefaultRunProperties: Optional[WorkflowRunProperties]
    CreatedOn: Optional[TimestampValue]
    LastModifiedOn: Optional[TimestampValue]
    LastRun: Optional[WorkflowRun]
    Graph: Optional[WorkflowGraph]
    MaxConcurrentRuns: Optional[NullableInteger]
    BlueprintDetails: Optional[BlueprintDetails]


Workflows = List[Workflow]


class BatchGetWorkflowsResponse(TypedDict, total=False):
    Workflows: Optional[Workflows]
    MissingWorkflows: Optional[WorkflowNames]


class BatchStopJobRunError(TypedDict, total=False):
    JobName: Optional[NameString]
    JobRunId: Optional[IdString]
    ErrorDetail: Optional[ErrorDetail]


BatchStopJobRunErrorList = List[BatchStopJobRunError]
BatchStopJobRunJobRunIdList = List[IdString]


class BatchStopJobRunRequest(ServiceRequest):
    JobName: NameString
    JobRunIds: BatchStopJobRunJobRunIdList


class BatchStopJobRunSuccessfulSubmission(TypedDict, total=False):
    JobName: Optional[NameString]
    JobRunId: Optional[IdString]


BatchStopJobRunSuccessfulSubmissionList = List[BatchStopJobRunSuccessfulSubmission]


class BatchStopJobRunResponse(TypedDict, total=False):
    SuccessfulSubmissions: Optional[BatchStopJobRunSuccessfulSubmissionList]
    Errors: Optional[BatchStopJobRunErrorList]


BoundedPartitionValueList = List[ValueString]


class BatchUpdatePartitionFailureEntry(TypedDict, total=False):
    PartitionValueList: Optional[BoundedPartitionValueList]
    ErrorDetail: Optional[ErrorDetail]


BatchUpdatePartitionFailureList = List[BatchUpdatePartitionFailureEntry]


class BatchUpdatePartitionRequestEntry(TypedDict, total=False):
    PartitionValueList: BoundedPartitionValueList
    PartitionInput: PartitionInput


BatchUpdatePartitionRequestEntryList = List[BatchUpdatePartitionRequestEntry]


class BatchUpdatePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    Entries: BatchUpdatePartitionRequestEntryList


class BatchUpdatePartitionResponse(TypedDict, total=False):
    Errors: Optional[BatchUpdatePartitionFailureList]


NonNegativeLong = int


class BinaryColumnStatisticsData(TypedDict, total=False):
    MaximumLength: NonNegativeLong
    AverageLength: NonNegativeDouble
    NumberOfNulls: NonNegativeLong


Blob = bytes


class BlueprintRun(TypedDict, total=False):
    BlueprintName: Optional[OrchestrationNameString]
    RunId: Optional[IdString]
    WorkflowName: Optional[NameString]
    State: Optional[BlueprintRunState]
    StartedOn: Optional[TimestampValue]
    CompletedOn: Optional[TimestampValue]
    ErrorMessage: Optional[MessageString]
    RollbackErrorMessage: Optional[MessageString]
    Parameters: Optional[BlueprintParameters]
    RoleArn: Optional[OrchestrationIAMRoleArn]


BlueprintRuns = List[BlueprintRun]


class BooleanColumnStatisticsData(TypedDict, total=False):
    NumberOfTrues: NonNegativeLong
    NumberOfFalses: NonNegativeLong
    NumberOfNulls: NonNegativeLong


class CancelMLTaskRunRequest(ServiceRequest):
    TransformId: HashString
    TaskRunId: HashString


class CancelMLTaskRunResponse(TypedDict, total=False):
    TransformId: Optional[HashString]
    TaskRunId: Optional[HashString]
    Status: Optional[TaskStatusType]


class CatalogEntry(TypedDict, total=False):
    DatabaseName: NameString
    TableName: NameString


CatalogEntries = List[CatalogEntry]


class CatalogImportStatus(TypedDict, total=False):
    ImportCompleted: Optional[Boolean]
    ImportTime: Optional[Timestamp]
    ImportedBy: Optional[NameString]


class CheckSchemaVersionValidityInput(ServiceRequest):
    DataFormat: DataFormat
    SchemaDefinition: SchemaDefinitionString


class CheckSchemaVersionValidityResponse(TypedDict, total=False):
    Valid: Optional[IsVersionValid]
    Error: Optional[SchemaValidationError]


CsvHeader = List[NameString]


class CsvClassifier(TypedDict, total=False):
    Name: NameString
    CreationTime: Optional[Timestamp]
    LastUpdated: Optional[Timestamp]
    Version: Optional[VersionId]
    Delimiter: Optional[CsvColumnDelimiter]
    QuoteSymbol: Optional[CsvQuoteSymbol]
    ContainsHeader: Optional[CsvHeaderOption]
    Header: Optional[CsvHeader]
    DisableValueTrimming: Optional[NullableBoolean]
    AllowSingleColumn: Optional[NullableBoolean]


class JsonClassifier(TypedDict, total=False):
    Name: NameString
    CreationTime: Optional[Timestamp]
    LastUpdated: Optional[Timestamp]
    Version: Optional[VersionId]
    JsonPath: JsonPath


class XMLClassifier(TypedDict, total=False):
    Name: NameString
    Classification: Classification
    CreationTime: Optional[Timestamp]
    LastUpdated: Optional[Timestamp]
    Version: Optional[VersionId]
    RowTag: Optional[RowTag]


class GrokClassifier(TypedDict, total=False):
    Name: NameString
    Classification: Classification
    CreationTime: Optional[Timestamp]
    LastUpdated: Optional[Timestamp]
    Version: Optional[VersionId]
    GrokPattern: GrokPattern
    CustomPatterns: Optional[CustomPatterns]


class Classifier(TypedDict, total=False):
    GrokClassifier: Optional[GrokClassifier]
    XMLClassifier: Optional[XMLClassifier]
    JsonClassifier: Optional[JsonClassifier]
    CsvClassifier: Optional[CsvClassifier]


ClassifierList = List[Classifier]


class CloudWatchEncryption(TypedDict, total=False):
    CloudWatchEncryptionMode: Optional[CloudWatchEncryptionMode]
    KmsKeyArn: Optional[KmsKeyArn]


class CodeGenEdge(TypedDict, total=False):
    Source: CodeGenIdentifier
    Target: CodeGenIdentifier
    TargetParameter: Optional[CodeGenArgName]


class CodeGenNodeArg(TypedDict, total=False):
    Name: CodeGenArgName
    Value: CodeGenArgValue
    Param: Optional[Boolean]


CodeGenNodeArgs = List[CodeGenNodeArg]


class CodeGenNode(TypedDict, total=False):
    Id: CodeGenIdentifier
    NodeType: CodeGenNodeType
    Args: CodeGenNodeArgs
    LineNumber: Optional[Integer]


class ColumnError(TypedDict, total=False):
    ColumnName: Optional[NameString]
    Error: Optional[ErrorDetail]


ColumnErrors = List[ColumnError]


class ColumnImportance(TypedDict, total=False):
    ColumnName: Optional[NameString]
    Importance: Optional[GenericBoundedDouble]


ColumnImportanceList = List[ColumnImportance]


class ColumnRowFilter(TypedDict, total=False):
    ColumnName: Optional[NameString]
    RowFilterExpression: Optional[PredicateString]


ColumnRowFilterList = List[ColumnRowFilter]


class StringColumnStatisticsData(TypedDict, total=False):
    MaximumLength: NonNegativeLong
    AverageLength: NonNegativeDouble
    NumberOfNulls: NonNegativeLong
    NumberOfDistinctValues: NonNegativeLong


Long = int


class LongColumnStatisticsData(TypedDict, total=False):
    MinimumValue: Optional[Long]
    MaximumValue: Optional[Long]
    NumberOfNulls: NonNegativeLong
    NumberOfDistinctValues: NonNegativeLong


class DoubleColumnStatisticsData(TypedDict, total=False):
    MinimumValue: Optional[Double]
    MaximumValue: Optional[Double]
    NumberOfNulls: NonNegativeLong
    NumberOfDistinctValues: NonNegativeLong


class DecimalNumber(TypedDict, total=False):
    UnscaledValue: Blob
    Scale: Integer


class DecimalColumnStatisticsData(TypedDict, total=False):
    MinimumValue: Optional[DecimalNumber]
    MaximumValue: Optional[DecimalNumber]
    NumberOfNulls: NonNegativeLong
    NumberOfDistinctValues: NonNegativeLong


class DateColumnStatisticsData(TypedDict, total=False):
    MinimumValue: Optional[Timestamp]
    MaximumValue: Optional[Timestamp]
    NumberOfNulls: NonNegativeLong
    NumberOfDistinctValues: NonNegativeLong


class ColumnStatisticsData(TypedDict, total=False):
    Type: ColumnStatisticsType
    BooleanColumnStatisticsData: Optional[BooleanColumnStatisticsData]
    DateColumnStatisticsData: Optional[DateColumnStatisticsData]
    DecimalColumnStatisticsData: Optional[DecimalColumnStatisticsData]
    DoubleColumnStatisticsData: Optional[DoubleColumnStatisticsData]
    LongColumnStatisticsData: Optional[LongColumnStatisticsData]
    StringColumnStatisticsData: Optional[StringColumnStatisticsData]
    BinaryColumnStatisticsData: Optional[BinaryColumnStatisticsData]


class ColumnStatistics(TypedDict, total=False):
    ColumnName: NameString
    ColumnType: TypeString
    AnalyzedTime: Timestamp
    StatisticsData: ColumnStatisticsData


class ColumnStatisticsError(TypedDict, total=False):
    ColumnStatistics: Optional[ColumnStatistics]
    Error: Optional[ErrorDetail]


ColumnStatisticsErrors = List[ColumnStatisticsError]
ColumnStatisticsList = List[ColumnStatistics]
RecordsCount = int


class ConfusionMatrix(TypedDict, total=False):
    NumTruePositives: Optional[RecordsCount]
    NumFalsePositives: Optional[RecordsCount]
    NumTrueNegatives: Optional[RecordsCount]
    NumFalseNegatives: Optional[RecordsCount]


SecurityGroupIdList = List[NameString]


class PhysicalConnectionRequirements(TypedDict, total=False):
    SubnetId: Optional[NameString]
    SecurityGroupIdList: Optional[SecurityGroupIdList]
    AvailabilityZone: Optional[NameString]


ConnectionProperties = Dict[ConnectionPropertyKey, ValueString]
MatchCriteria = List[NameString]


class Connection(TypedDict, total=False):
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    ConnectionType: Optional[ConnectionType]
    MatchCriteria: Optional[MatchCriteria]
    ConnectionProperties: Optional[ConnectionProperties]
    PhysicalConnectionRequirements: Optional[PhysicalConnectionRequirements]
    CreationTime: Optional[Timestamp]
    LastUpdatedTime: Optional[Timestamp]
    LastUpdatedBy: Optional[NameString]


class ConnectionInput(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    ConnectionType: ConnectionType
    MatchCriteria: Optional[MatchCriteria]
    ConnectionProperties: ConnectionProperties
    PhysicalConnectionRequirements: Optional[PhysicalConnectionRequirements]


ConnectionList = List[Connection]


class ConnectionPasswordEncryption(TypedDict, total=False):
    ReturnConnectionPasswordEncrypted: Boolean
    AwsKmsKeyId: Optional[NameString]


class CrawlerMetrics(TypedDict, total=False):
    CrawlerName: Optional[NameString]
    TimeLeftSeconds: Optional[NonNegativeDouble]
    StillEstimating: Optional[Boolean]
    LastRuntimeSeconds: Optional[NonNegativeDouble]
    MedianRuntimeSeconds: Optional[NonNegativeDouble]
    TablesCreated: Optional[NonNegativeInteger]
    TablesUpdated: Optional[NonNegativeInteger]
    TablesDeleted: Optional[NonNegativeInteger]


CrawlerMetricsList = List[CrawlerMetrics]
TagsMap = Dict[TagKey, TagValue]


class CreateBlueprintRequest(ServiceRequest):
    Name: OrchestrationNameString
    Description: Optional[Generic512CharString]
    BlueprintLocation: OrchestrationS3Location
    Tags: Optional[TagsMap]


class CreateBlueprintResponse(TypedDict, total=False):
    Name: Optional[NameString]


class CreateCsvClassifierRequest(TypedDict, total=False):
    Name: NameString
    Delimiter: Optional[CsvColumnDelimiter]
    QuoteSymbol: Optional[CsvQuoteSymbol]
    ContainsHeader: Optional[CsvHeaderOption]
    Header: Optional[CsvHeader]
    DisableValueTrimming: Optional[NullableBoolean]
    AllowSingleColumn: Optional[NullableBoolean]


class CreateJsonClassifierRequest(TypedDict, total=False):
    Name: NameString
    JsonPath: JsonPath


class CreateXMLClassifierRequest(TypedDict, total=False):
    Classification: Classification
    Name: NameString
    RowTag: Optional[RowTag]


class CreateGrokClassifierRequest(TypedDict, total=False):
    Classification: Classification
    Name: NameString
    GrokPattern: GrokPattern
    CustomPatterns: Optional[CustomPatterns]


class CreateClassifierRequest(ServiceRequest):
    GrokClassifier: Optional[CreateGrokClassifierRequest]
    XMLClassifier: Optional[CreateXMLClassifierRequest]
    JsonClassifier: Optional[CreateJsonClassifierRequest]
    CsvClassifier: Optional[CreateCsvClassifierRequest]


class CreateClassifierResponse(TypedDict, total=False):
    pass


class CreateConnectionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    ConnectionInput: ConnectionInput
    Tags: Optional[TagsMap]


class CreateConnectionResponse(TypedDict, total=False):
    pass


class CreateCrawlerRequest(ServiceRequest):
    Name: NameString
    Role: Role
    DatabaseName: Optional[DatabaseName]
    Description: Optional[DescriptionString]
    Targets: CrawlerTargets
    Schedule: Optional[CronExpression]
    Classifiers: Optional[ClassifierNameList]
    TablePrefix: Optional[TablePrefix]
    SchemaChangePolicy: Optional[SchemaChangePolicy]
    RecrawlPolicy: Optional[RecrawlPolicy]
    LineageConfiguration: Optional[LineageConfiguration]
    LakeFormationConfiguration: Optional[LakeFormationConfiguration]
    Configuration: Optional[CrawlerConfiguration]
    CrawlerSecurityConfiguration: Optional[CrawlerSecurityConfiguration]
    Tags: Optional[TagsMap]


class CreateCrawlerResponse(TypedDict, total=False):
    pass


class DatabaseIdentifier(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: Optional[NameString]


PermissionList = List[Permission]


class DataLakePrincipal(TypedDict, total=False):
    DataLakePrincipalIdentifier: Optional[DataLakePrincipalString]


class PrincipalPermissions(TypedDict, total=False):
    Principal: Optional[DataLakePrincipal]
    Permissions: Optional[PermissionList]


PrincipalPermissionsList = List[PrincipalPermissions]


class DatabaseInput(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    LocationUri: Optional[URI]
    Parameters: Optional[ParametersMap]
    CreateTableDefaultPermissions: Optional[PrincipalPermissionsList]
    TargetDatabase: Optional[DatabaseIdentifier]


class CreateDatabaseRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseInput: DatabaseInput


class CreateDatabaseResponse(TypedDict, total=False):
    pass


class CreateDevEndpointRequest(ServiceRequest):
    EndpointName: GenericString
    RoleArn: RoleArn
    SecurityGroupIds: Optional[StringList]
    SubnetId: Optional[GenericString]
    PublicKey: Optional[GenericString]
    PublicKeys: Optional[PublicKeysList]
    NumberOfNodes: Optional[IntegerValue]
    WorkerType: Optional[WorkerType]
    GlueVersion: Optional[GlueVersionString]
    NumberOfWorkers: Optional[NullableInteger]
    ExtraPythonLibsS3Path: Optional[GenericString]
    ExtraJarsS3Path: Optional[GenericString]
    SecurityConfiguration: Optional[NameString]
    Tags: Optional[TagsMap]
    Arguments: Optional[MapValue]


class CreateDevEndpointResponse(TypedDict, total=False):
    EndpointName: Optional[GenericString]
    Status: Optional[GenericString]
    SecurityGroupIds: Optional[StringList]
    SubnetId: Optional[GenericString]
    RoleArn: Optional[RoleArn]
    YarnEndpointAddress: Optional[GenericString]
    ZeppelinRemoteSparkInterpreterPort: Optional[IntegerValue]
    NumberOfNodes: Optional[IntegerValue]
    WorkerType: Optional[WorkerType]
    GlueVersion: Optional[GlueVersionString]
    NumberOfWorkers: Optional[NullableInteger]
    AvailabilityZone: Optional[GenericString]
    VpcId: Optional[GenericString]
    ExtraPythonLibsS3Path: Optional[GenericString]
    ExtraJarsS3Path: Optional[GenericString]
    FailureReason: Optional[GenericString]
    SecurityConfiguration: Optional[NameString]
    CreatedTimestamp: Optional[TimestampValue]
    Arguments: Optional[MapValue]


class CreateJobRequest(ServiceRequest):
    Name: NameString
    Description: Optional[DescriptionString]
    LogUri: Optional[UriString]
    Role: RoleString
    ExecutionProperty: Optional[ExecutionProperty]
    Command: JobCommand
    DefaultArguments: Optional[GenericMap]
    NonOverridableArguments: Optional[GenericMap]
    Connections: Optional[ConnectionsList]
    MaxRetries: Optional[MaxRetries]
    AllocatedCapacity: Optional[IntegerValue]
    Timeout: Optional[Timeout]
    MaxCapacity: Optional[NullableDouble]
    SecurityConfiguration: Optional[NameString]
    Tags: Optional[TagsMap]
    NotificationProperty: Optional[NotificationProperty]
    GlueVersion: Optional[GlueVersionString]
    NumberOfWorkers: Optional[NullableInteger]
    WorkerType: Optional[WorkerType]


class CreateJobResponse(TypedDict, total=False):
    Name: Optional[NameString]


class MLUserDataEncryption(TypedDict, total=False):
    MlUserDataEncryptionMode: MLUserDataEncryptionModeString
    KmsKeyId: Optional[NameString]


class TransformEncryption(TypedDict, total=False):
    MlUserDataEncryption: Optional[MLUserDataEncryption]
    TaskRunSecurityConfigurationName: Optional[NameString]


class FindMatchesParameters(TypedDict, total=False):
    PrimaryKeyColumnName: Optional[ColumnNameString]
    PrecisionRecallTradeoff: Optional[GenericBoundedDouble]
    AccuracyCostTradeoff: Optional[GenericBoundedDouble]
    EnforceProvidedLabels: Optional[NullableBoolean]


class TransformParameters(TypedDict, total=False):
    TransformType: TransformType
    FindMatchesParameters: Optional[FindMatchesParameters]


class GlueTable(TypedDict, total=False):
    DatabaseName: NameString
    TableName: NameString
    CatalogId: Optional[NameString]
    ConnectionName: Optional[NameString]


GlueTables = List[GlueTable]


class CreateMLTransformRequest(ServiceRequest):
    Name: NameString
    Description: Optional[DescriptionString]
    InputRecordTables: GlueTables
    Parameters: TransformParameters
    Role: RoleString
    GlueVersion: Optional[GlueVersionString]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    Timeout: Optional[Timeout]
    MaxRetries: Optional[NullableInteger]
    Tags: Optional[TagsMap]
    TransformEncryption: Optional[TransformEncryption]


class CreateMLTransformResponse(TypedDict, total=False):
    TransformId: Optional[HashString]


KeyList = List[NameString]


class PartitionIndex(TypedDict, total=False):
    Keys: KeyList
    IndexName: NameString


class CreatePartitionIndexRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionIndex: PartitionIndex


class CreatePartitionIndexResponse(TypedDict, total=False):
    pass


class CreatePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionInput: PartitionInput


class CreatePartitionResponse(TypedDict, total=False):
    pass


class CreateRegistryInput(ServiceRequest):
    RegistryName: SchemaRegistryNameString
    Description: Optional[DescriptionString]
    Tags: Optional[TagsMap]


class CreateRegistryResponse(TypedDict, total=False):
    RegistryArn: Optional[GlueResourceArn]
    RegistryName: Optional[SchemaRegistryNameString]
    Description: Optional[DescriptionString]
    Tags: Optional[TagsMap]


class RegistryId(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]


class CreateSchemaInput(ServiceRequest):
    RegistryId: Optional[RegistryId]
    SchemaName: SchemaRegistryNameString
    DataFormat: DataFormat
    Compatibility: Optional[Compatibility]
    Description: Optional[DescriptionString]
    Tags: Optional[TagsMap]
    SchemaDefinition: Optional[SchemaDefinitionString]


SchemaCheckpointNumber = int


class CreateSchemaResponse(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    SchemaArn: Optional[GlueResourceArn]
    Description: Optional[DescriptionString]
    DataFormat: Optional[DataFormat]
    Compatibility: Optional[Compatibility]
    SchemaCheckpoint: Optional[SchemaCheckpointNumber]
    LatestSchemaVersion: Optional[VersionLongNumber]
    NextSchemaVersion: Optional[VersionLongNumber]
    SchemaStatus: Optional[SchemaStatus]
    Tags: Optional[TagsMap]
    SchemaVersionId: Optional[SchemaVersionIdString]
    SchemaVersionStatus: Optional[SchemaVersionStatus]


DagEdges = List[CodeGenEdge]
DagNodes = List[CodeGenNode]


class CreateScriptRequest(ServiceRequest):
    DagNodes: Optional[DagNodes]
    DagEdges: Optional[DagEdges]
    Language: Optional[Language]


class CreateScriptResponse(TypedDict, total=False):
    PythonScript: Optional[PythonScript]
    ScalaCode: Optional[ScalaCode]


class JobBookmarksEncryption(TypedDict, total=False):
    JobBookmarksEncryptionMode: Optional[JobBookmarksEncryptionMode]
    KmsKeyArn: Optional[KmsKeyArn]


class S3Encryption(TypedDict, total=False):
    S3EncryptionMode: Optional[S3EncryptionMode]
    KmsKeyArn: Optional[KmsKeyArn]


S3EncryptionList = List[S3Encryption]


class EncryptionConfiguration(TypedDict, total=False):
    S3Encryption: Optional[S3EncryptionList]
    CloudWatchEncryption: Optional[CloudWatchEncryption]
    JobBookmarksEncryption: Optional[JobBookmarksEncryption]


class CreateSecurityConfigurationRequest(ServiceRequest):
    Name: NameString
    EncryptionConfiguration: EncryptionConfiguration


class CreateSecurityConfigurationResponse(TypedDict, total=False):
    Name: Optional[NameString]
    CreatedTimestamp: Optional[TimestampValue]


PartitionIndexList = List[PartitionIndex]


class TableIdentifier(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: Optional[NameString]
    Name: Optional[NameString]


class TableInput(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    Owner: Optional[NameString]
    LastAccessTime: Optional[Timestamp]
    LastAnalyzedTime: Optional[Timestamp]
    Retention: Optional[NonNegativeInteger]
    StorageDescriptor: Optional[StorageDescriptor]
    PartitionKeys: Optional[ColumnList]
    ViewOriginalText: Optional[ViewTextString]
    ViewExpandedText: Optional[ViewTextString]
    TableType: Optional[TableTypeString]
    Parameters: Optional[ParametersMap]
    TargetTable: Optional[TableIdentifier]


class CreateTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableInput: TableInput
    PartitionIndexes: Optional[PartitionIndexList]
    TransactionId: Optional[TransactionIdString]


class CreateTableResponse(TypedDict, total=False):
    pass


class CreateTriggerRequest(ServiceRequest):
    Name: NameString
    WorkflowName: Optional[NameString]
    Type: TriggerType
    Schedule: Optional[GenericString]
    Predicate: Optional[Predicate]
    Actions: ActionList
    Description: Optional[DescriptionString]
    StartOnCreation: Optional[BooleanValue]
    Tags: Optional[TagsMap]
    EventBatchingCondition: Optional[EventBatchingCondition]


class CreateTriggerResponse(TypedDict, total=False):
    Name: Optional[NameString]


class ResourceUri(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    Uri: Optional[URI]


ResourceUriList = List[ResourceUri]


class UserDefinedFunctionInput(TypedDict, total=False):
    FunctionName: Optional[NameString]
    ClassName: Optional[NameString]
    OwnerName: Optional[NameString]
    OwnerType: Optional[PrincipalType]
    ResourceUris: Optional[ResourceUriList]


class CreateUserDefinedFunctionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    FunctionInput: UserDefinedFunctionInput


class CreateUserDefinedFunctionResponse(TypedDict, total=False):
    pass


class CreateWorkflowRequest(ServiceRequest):
    Name: NameString
    Description: Optional[GenericString]
    DefaultRunProperties: Optional[WorkflowRunProperties]
    Tags: Optional[TagsMap]
    MaxConcurrentRuns: Optional[NullableInteger]


class CreateWorkflowResponse(TypedDict, total=False):
    Name: Optional[NameString]


class EncryptionAtRest(TypedDict, total=False):
    CatalogEncryptionMode: CatalogEncryptionMode
    SseAwsKmsKeyId: Optional[NameString]


class DataCatalogEncryptionSettings(TypedDict, total=False):
    EncryptionAtRest: Optional[EncryptionAtRest]
    ConnectionPasswordEncryption: Optional[ConnectionPasswordEncryption]


class Database(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    LocationUri: Optional[URI]
    Parameters: Optional[ParametersMap]
    CreateTime: Optional[Timestamp]
    CreateTableDefaultPermissions: Optional[PrincipalPermissionsList]
    TargetDatabase: Optional[DatabaseIdentifier]
    CatalogId: Optional[CatalogIdString]


DatabaseList = List[Database]


class DeleteBlueprintRequest(ServiceRequest):
    Name: NameString


class DeleteBlueprintResponse(TypedDict, total=False):
    Name: Optional[NameString]


class DeleteClassifierRequest(ServiceRequest):
    Name: NameString


class DeleteClassifierResponse(TypedDict, total=False):
    pass


class DeleteColumnStatisticsForPartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList
    ColumnName: NameString


class DeleteColumnStatisticsForPartitionResponse(TypedDict, total=False):
    pass


class DeleteColumnStatisticsForTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    ColumnName: NameString


class DeleteColumnStatisticsForTableResponse(TypedDict, total=False):
    pass


class DeleteConnectionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    ConnectionName: NameString


class DeleteConnectionResponse(TypedDict, total=False):
    pass


class DeleteCrawlerRequest(ServiceRequest):
    Name: NameString


class DeleteCrawlerResponse(TypedDict, total=False):
    pass


class DeleteDatabaseRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Name: NameString


class DeleteDatabaseResponse(TypedDict, total=False):
    pass


class DeleteDevEndpointRequest(ServiceRequest):
    EndpointName: GenericString


class DeleteDevEndpointResponse(TypedDict, total=False):
    pass


class DeleteJobRequest(ServiceRequest):
    JobName: NameString


class DeleteJobResponse(TypedDict, total=False):
    JobName: Optional[NameString]


class DeleteMLTransformRequest(ServiceRequest):
    TransformId: HashString


class DeleteMLTransformResponse(TypedDict, total=False):
    TransformId: Optional[HashString]


class DeletePartitionIndexRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    IndexName: NameString


class DeletePartitionIndexResponse(TypedDict, total=False):
    pass


class DeletePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList


class DeletePartitionResponse(TypedDict, total=False):
    pass


class DeleteRegistryInput(ServiceRequest):
    RegistryId: RegistryId


class DeleteRegistryResponse(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]
    Status: Optional[RegistryStatus]


class DeleteResourcePolicyRequest(ServiceRequest):
    PolicyHashCondition: Optional[HashString]
    ResourceArn: Optional[GlueResourceArn]


class DeleteResourcePolicyResponse(TypedDict, total=False):
    pass


class DeleteSchemaInput(ServiceRequest):
    SchemaId: SchemaId


class DeleteSchemaResponse(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    Status: Optional[SchemaStatus]


class DeleteSchemaVersionsInput(ServiceRequest):
    SchemaId: SchemaId
    Versions: VersionsString


class ErrorDetails(TypedDict, total=False):
    ErrorCode: Optional[ErrorCodeString]
    ErrorMessage: Optional[ErrorMessageString]


class SchemaVersionErrorItem(TypedDict, total=False):
    VersionNumber: Optional[VersionLongNumber]
    ErrorDetails: Optional[ErrorDetails]


SchemaVersionErrorList = List[SchemaVersionErrorItem]


class DeleteSchemaVersionsResponse(TypedDict, total=False):
    SchemaVersionErrors: Optional[SchemaVersionErrorList]


class DeleteSecurityConfigurationRequest(ServiceRequest):
    Name: NameString


class DeleteSecurityConfigurationResponse(TypedDict, total=False):
    pass


class DeleteTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    Name: NameString
    TransactionId: Optional[TransactionIdString]


class DeleteTableResponse(TypedDict, total=False):
    pass


class DeleteTableVersionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    VersionId: VersionString


class DeleteTableVersionResponse(TypedDict, total=False):
    pass


class DeleteTriggerRequest(ServiceRequest):
    Name: NameString


class DeleteTriggerResponse(TypedDict, total=False):
    Name: Optional[NameString]


class DeleteUserDefinedFunctionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    FunctionName: NameString


class DeleteUserDefinedFunctionResponse(TypedDict, total=False):
    pass


class DeleteWorkflowRequest(ServiceRequest):
    Name: NameString


class DeleteWorkflowResponse(TypedDict, total=False):
    Name: Optional[NameString]


class DevEndpointCustomLibraries(TypedDict, total=False):
    ExtraPythonLibsS3Path: Optional[GenericString]
    ExtraJarsS3Path: Optional[GenericString]


DevEndpointNameList = List[NameString]


class FindMatchesMetrics(TypedDict, total=False):
    AreaUnderPRCurve: Optional[GenericBoundedDouble]
    Precision: Optional[GenericBoundedDouble]
    Recall: Optional[GenericBoundedDouble]
    F1: Optional[GenericBoundedDouble]
    ConfusionMatrix: Optional[ConfusionMatrix]
    ColumnImportances: Optional[ColumnImportanceList]


class EvaluationMetrics(TypedDict, total=False):
    TransformType: TransformType
    FindMatchesMetrics: Optional[FindMatchesMetrics]


class ExportLabelsTaskRunProperties(TypedDict, total=False):
    OutputS3Path: Optional[UriString]


class FindMatchesTaskRunProperties(TypedDict, total=False):
    JobId: Optional[HashString]
    JobName: Optional[NameString]
    JobRunId: Optional[HashString]


class GetBlueprintRequest(ServiceRequest):
    Name: NameString
    IncludeBlueprint: Optional[NullableBoolean]
    IncludeParameterSpec: Optional[NullableBoolean]


class GetBlueprintResponse(TypedDict, total=False):
    Blueprint: Optional[Blueprint]


class GetBlueprintRunRequest(ServiceRequest):
    BlueprintName: OrchestrationNameString
    RunId: IdString


class GetBlueprintRunResponse(TypedDict, total=False):
    BlueprintRun: Optional[BlueprintRun]


class GetBlueprintRunsRequest(ServiceRequest):
    BlueprintName: NameString
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]


class GetBlueprintRunsResponse(TypedDict, total=False):
    BlueprintRuns: Optional[BlueprintRuns]
    NextToken: Optional[GenericString]


class GetCatalogImportStatusRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]


class GetCatalogImportStatusResponse(TypedDict, total=False):
    ImportStatus: Optional[CatalogImportStatus]


class GetClassifierRequest(ServiceRequest):
    Name: NameString


class GetClassifierResponse(TypedDict, total=False):
    Classifier: Optional[Classifier]


class GetClassifiersRequest(ServiceRequest):
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


class GetClassifiersResponse(TypedDict, total=False):
    Classifiers: Optional[ClassifierList]
    NextToken: Optional[Token]


GetColumnNamesList = List[NameString]


class GetColumnStatisticsForPartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList
    ColumnNames: GetColumnNamesList


class GetColumnStatisticsForPartitionResponse(TypedDict, total=False):
    ColumnStatisticsList: Optional[ColumnStatisticsList]
    Errors: Optional[ColumnErrors]


class GetColumnStatisticsForTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    ColumnNames: GetColumnNamesList


class GetColumnStatisticsForTableResponse(TypedDict, total=False):
    ColumnStatisticsList: Optional[ColumnStatisticsList]
    Errors: Optional[ColumnErrors]


class GetConnectionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Name: NameString
    HidePassword: Optional[Boolean]


class GetConnectionResponse(TypedDict, total=False):
    Connection: Optional[Connection]


class GetConnectionsFilter(TypedDict, total=False):
    MatchCriteria: Optional[MatchCriteria]
    ConnectionType: Optional[ConnectionType]


class GetConnectionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Filter: Optional[GetConnectionsFilter]
    HidePassword: Optional[Boolean]
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]


class GetConnectionsResponse(TypedDict, total=False):
    ConnectionList: Optional[ConnectionList]
    NextToken: Optional[Token]


class GetCrawlerMetricsRequest(ServiceRequest):
    CrawlerNameList: Optional[CrawlerNameList]
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


class GetCrawlerMetricsResponse(TypedDict, total=False):
    CrawlerMetricsList: Optional[CrawlerMetricsList]
    NextToken: Optional[Token]


class GetCrawlerRequest(ServiceRequest):
    Name: NameString


class GetCrawlerResponse(TypedDict, total=False):
    Crawler: Optional[Crawler]


class GetCrawlersRequest(ServiceRequest):
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


class GetCrawlersResponse(TypedDict, total=False):
    Crawlers: Optional[CrawlerList]
    NextToken: Optional[Token]


class GetDataCatalogEncryptionSettingsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]


class GetDataCatalogEncryptionSettingsResponse(TypedDict, total=False):
    DataCatalogEncryptionSettings: Optional[DataCatalogEncryptionSettings]


class GetDatabaseRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Name: NameString


class GetDatabaseResponse(TypedDict, total=False):
    Database: Optional[Database]


class GetDatabasesRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    NextToken: Optional[Token]
    MaxResults: Optional[CatalogGetterPageSize]
    ResourceShareType: Optional[ResourceShareType]


class GetDatabasesResponse(TypedDict, total=False):
    DatabaseList: DatabaseList
    NextToken: Optional[Token]


class GetDataflowGraphRequest(ServiceRequest):
    PythonScript: Optional[PythonScript]


class GetDataflowGraphResponse(TypedDict, total=False):
    DagNodes: Optional[DagNodes]
    DagEdges: Optional[DagEdges]


class GetDevEndpointRequest(ServiceRequest):
    EndpointName: GenericString


class GetDevEndpointResponse(TypedDict, total=False):
    DevEndpoint: Optional[DevEndpoint]


class GetDevEndpointsRequest(ServiceRequest):
    MaxResults: Optional[PageSize]
    NextToken: Optional[GenericString]


class GetDevEndpointsResponse(TypedDict, total=False):
    DevEndpoints: Optional[DevEndpointList]
    NextToken: Optional[GenericString]


class GetJobBookmarkRequest(ServiceRequest):
    JobName: JobName
    RunId: Optional[RunId]


class JobBookmarkEntry(TypedDict, total=False):
    JobName: Optional[JobName]
    Version: Optional[IntegerValue]
    Run: Optional[IntegerValue]
    Attempt: Optional[IntegerValue]
    PreviousRunId: Optional[RunId]
    RunId: Optional[RunId]
    JobBookmark: Optional[JsonValue]


class GetJobBookmarkResponse(TypedDict, total=False):
    JobBookmarkEntry: Optional[JobBookmarkEntry]


class GetJobRequest(ServiceRequest):
    JobName: NameString


class GetJobResponse(TypedDict, total=False):
    Job: Optional[Job]


class GetJobRunRequest(ServiceRequest):
    JobName: NameString
    RunId: IdString
    PredecessorsIncluded: Optional[BooleanValue]


class GetJobRunResponse(TypedDict, total=False):
    JobRun: Optional[JobRun]


class GetJobRunsRequest(ServiceRequest):
    JobName: NameString
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]


class GetJobRunsResponse(TypedDict, total=False):
    JobRuns: Optional[JobRunList]
    NextToken: Optional[GenericString]


class GetJobsRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]


class GetJobsResponse(TypedDict, total=False):
    Jobs: Optional[JobList]
    NextToken: Optional[GenericString]


class GetMLTaskRunRequest(ServiceRequest):
    TransformId: HashString
    TaskRunId: HashString


class LabelingSetGenerationTaskRunProperties(TypedDict, total=False):
    OutputS3Path: Optional[UriString]


class ImportLabelsTaskRunProperties(TypedDict, total=False):
    InputS3Path: Optional[UriString]
    Replace: Optional[ReplaceBoolean]


class TaskRunProperties(TypedDict, total=False):
    TaskType: Optional[TaskType]
    ImportLabelsTaskRunProperties: Optional[ImportLabelsTaskRunProperties]
    ExportLabelsTaskRunProperties: Optional[ExportLabelsTaskRunProperties]
    LabelingSetGenerationTaskRunProperties: Optional[LabelingSetGenerationTaskRunProperties]
    FindMatchesTaskRunProperties: Optional[FindMatchesTaskRunProperties]


class GetMLTaskRunResponse(TypedDict, total=False):
    TransformId: Optional[HashString]
    TaskRunId: Optional[HashString]
    Status: Optional[TaskStatusType]
    LogGroupName: Optional[GenericString]
    Properties: Optional[TaskRunProperties]
    ErrorString: Optional[GenericString]
    StartedOn: Optional[Timestamp]
    LastModifiedOn: Optional[Timestamp]
    CompletedOn: Optional[Timestamp]
    ExecutionTime: Optional[ExecutionTime]


class TaskRunSortCriteria(TypedDict, total=False):
    Column: TaskRunSortColumnType
    SortDirection: SortDirectionType


class TaskRunFilterCriteria(TypedDict, total=False):
    TaskRunType: Optional[TaskType]
    Status: Optional[TaskStatusType]
    StartedBefore: Optional[Timestamp]
    StartedAfter: Optional[Timestamp]


class GetMLTaskRunsRequest(ServiceRequest):
    TransformId: HashString
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[PageSize]
    Filter: Optional[TaskRunFilterCriteria]
    Sort: Optional[TaskRunSortCriteria]


class TaskRun(TypedDict, total=False):
    TransformId: Optional[HashString]
    TaskRunId: Optional[HashString]
    Status: Optional[TaskStatusType]
    LogGroupName: Optional[GenericString]
    Properties: Optional[TaskRunProperties]
    ErrorString: Optional[GenericString]
    StartedOn: Optional[Timestamp]
    LastModifiedOn: Optional[Timestamp]
    CompletedOn: Optional[Timestamp]
    ExecutionTime: Optional[ExecutionTime]


TaskRunList = List[TaskRun]


class GetMLTaskRunsResponse(TypedDict, total=False):
    TaskRuns: Optional[TaskRunList]
    NextToken: Optional[PaginationToken]


class GetMLTransformRequest(ServiceRequest):
    TransformId: HashString


class SchemaColumn(TypedDict, total=False):
    Name: Optional[ColumnNameString]
    DataType: Optional[ColumnTypeString]


TransformSchema = List[SchemaColumn]


class GetMLTransformResponse(TypedDict, total=False):
    TransformId: Optional[HashString]
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    Status: Optional[TransformStatusType]
    CreatedOn: Optional[Timestamp]
    LastModifiedOn: Optional[Timestamp]
    InputRecordTables: Optional[GlueTables]
    Parameters: Optional[TransformParameters]
    EvaluationMetrics: Optional[EvaluationMetrics]
    LabelCount: Optional[LabelCount]
    Schema: Optional[TransformSchema]
    Role: Optional[RoleString]
    GlueVersion: Optional[GlueVersionString]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    Timeout: Optional[Timeout]
    MaxRetries: Optional[NullableInteger]
    TransformEncryption: Optional[TransformEncryption]


class TransformSortCriteria(TypedDict, total=False):
    Column: TransformSortColumnType
    SortDirection: SortDirectionType


class TransformFilterCriteria(TypedDict, total=False):
    Name: Optional[NameString]
    TransformType: Optional[TransformType]
    Status: Optional[TransformStatusType]
    GlueVersion: Optional[GlueVersionString]
    CreatedBefore: Optional[Timestamp]
    CreatedAfter: Optional[Timestamp]
    LastModifiedBefore: Optional[Timestamp]
    LastModifiedAfter: Optional[Timestamp]
    Schema: Optional[TransformSchema]


class GetMLTransformsRequest(ServiceRequest):
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[PageSize]
    Filter: Optional[TransformFilterCriteria]
    Sort: Optional[TransformSortCriteria]


class MLTransform(TypedDict, total=False):
    TransformId: Optional[HashString]
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    Status: Optional[TransformStatusType]
    CreatedOn: Optional[Timestamp]
    LastModifiedOn: Optional[Timestamp]
    InputRecordTables: Optional[GlueTables]
    Parameters: Optional[TransformParameters]
    EvaluationMetrics: Optional[EvaluationMetrics]
    LabelCount: Optional[LabelCount]
    Schema: Optional[TransformSchema]
    Role: Optional[RoleString]
    GlueVersion: Optional[GlueVersionString]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    Timeout: Optional[Timeout]
    MaxRetries: Optional[NullableInteger]
    TransformEncryption: Optional[TransformEncryption]


TransformList = List[MLTransform]


class GetMLTransformsResponse(TypedDict, total=False):
    Transforms: TransformList
    NextToken: Optional[PaginationToken]


class Location(TypedDict, total=False):
    Jdbc: Optional[CodeGenNodeArgs]
    S3: Optional[CodeGenNodeArgs]
    DynamoDB: Optional[CodeGenNodeArgs]


class GetMappingRequest(ServiceRequest):
    Source: CatalogEntry
    Sinks: Optional[CatalogEntries]
    Location: Optional[Location]


class MappingEntry(TypedDict, total=False):
    SourceTable: Optional[TableName]
    SourcePath: Optional[SchemaPathString]
    SourceType: Optional[FieldType]
    TargetTable: Optional[TableName]
    TargetPath: Optional[SchemaPathString]
    TargetType: Optional[FieldType]


MappingList = List[MappingEntry]


class GetMappingResponse(TypedDict, total=False):
    Mapping: MappingList


class GetPartitionIndexesRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    NextToken: Optional[Token]


class KeySchemaElement(TypedDict, total=False):
    Name: NameString
    Type: ColumnTypeString


KeySchemaElementList = List[KeySchemaElement]


class PartitionIndexDescriptor(TypedDict, total=False):
    IndexName: NameString
    Keys: KeySchemaElementList
    IndexStatus: PartitionIndexStatus
    BackfillErrors: Optional[BackfillErrors]


PartitionIndexDescriptorList = List[PartitionIndexDescriptor]


class GetPartitionIndexesResponse(TypedDict, total=False):
    PartitionIndexDescriptorList: Optional[PartitionIndexDescriptorList]
    NextToken: Optional[Token]


class GetPartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList


class GetPartitionResponse(TypedDict, total=False):
    Partition: Optional[Partition]


class Segment(TypedDict, total=False):
    SegmentNumber: NonNegativeInteger
    TotalSegments: TotalSegmentsInteger


class GetPartitionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    Expression: Optional[PredicateString]
    NextToken: Optional[Token]
    Segment: Optional[Segment]
    MaxResults: Optional[PageSize]
    ExcludeColumnSchema: Optional[BooleanNullable]
    TransactionId: Optional[TransactionIdString]
    QueryAsOfTime: Optional[Timestamp]


class GetPartitionsResponse(TypedDict, total=False):
    Partitions: Optional[PartitionList]
    NextToken: Optional[Token]


class GetPlanRequest(ServiceRequest):
    Mapping: MappingList
    Source: CatalogEntry
    Sinks: Optional[CatalogEntries]
    Location: Optional[Location]
    Language: Optional[Language]
    AdditionalPlanOptionsMap: Optional[AdditionalPlanOptionsMap]


class GetPlanResponse(TypedDict, total=False):
    PythonScript: Optional[PythonScript]
    ScalaCode: Optional[ScalaCode]


class GetRegistryInput(ServiceRequest):
    RegistryId: RegistryId


class GetRegistryResponse(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]
    Description: Optional[DescriptionString]
    Status: Optional[RegistryStatus]
    CreatedTime: Optional[CreatedTimestamp]
    UpdatedTime: Optional[UpdatedTimestamp]


class GetResourcePoliciesRequest(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]


class GluePolicy(TypedDict, total=False):
    PolicyInJson: Optional[PolicyJsonString]
    PolicyHash: Optional[HashString]
    CreateTime: Optional[Timestamp]
    UpdateTime: Optional[Timestamp]


GetResourcePoliciesResponseList = List[GluePolicy]


class GetResourcePoliciesResponse(TypedDict, total=False):
    GetResourcePoliciesResponseList: Optional[GetResourcePoliciesResponseList]
    NextToken: Optional[Token]


class GetResourcePolicyRequest(ServiceRequest):
    ResourceArn: Optional[GlueResourceArn]


class GetResourcePolicyResponse(TypedDict, total=False):
    PolicyInJson: Optional[PolicyJsonString]
    PolicyHash: Optional[HashString]
    CreateTime: Optional[Timestamp]
    UpdateTime: Optional[Timestamp]


class GetSchemaByDefinitionInput(ServiceRequest):
    SchemaId: SchemaId
    SchemaDefinition: SchemaDefinitionString


class GetSchemaByDefinitionResponse(TypedDict, total=False):
    SchemaVersionId: Optional[SchemaVersionIdString]
    SchemaArn: Optional[GlueResourceArn]
    DataFormat: Optional[DataFormat]
    Status: Optional[SchemaVersionStatus]
    CreatedTime: Optional[CreatedTimestamp]


class GetSchemaInput(ServiceRequest):
    SchemaId: SchemaId


class GetSchemaResponse(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    SchemaArn: Optional[GlueResourceArn]
    Description: Optional[DescriptionString]
    DataFormat: Optional[DataFormat]
    Compatibility: Optional[Compatibility]
    SchemaCheckpoint: Optional[SchemaCheckpointNumber]
    LatestSchemaVersion: Optional[VersionLongNumber]
    NextSchemaVersion: Optional[VersionLongNumber]
    SchemaStatus: Optional[SchemaStatus]
    CreatedTime: Optional[CreatedTimestamp]
    UpdatedTime: Optional[UpdatedTimestamp]


class SchemaVersionNumber(TypedDict, total=False):
    LatestVersion: Optional[LatestSchemaVersionBoolean]
    VersionNumber: Optional[VersionLongNumber]


class GetSchemaVersionInput(ServiceRequest):
    SchemaId: Optional[SchemaId]
    SchemaVersionId: Optional[SchemaVersionIdString]
    SchemaVersionNumber: Optional[SchemaVersionNumber]


class GetSchemaVersionResponse(TypedDict, total=False):
    SchemaVersionId: Optional[SchemaVersionIdString]
    SchemaDefinition: Optional[SchemaDefinitionString]
    DataFormat: Optional[DataFormat]
    SchemaArn: Optional[GlueResourceArn]
    VersionNumber: Optional[VersionLongNumber]
    Status: Optional[SchemaVersionStatus]
    CreatedTime: Optional[CreatedTimestamp]


class GetSchemaVersionsDiffInput(ServiceRequest):
    SchemaId: SchemaId
    FirstSchemaVersionNumber: SchemaVersionNumber
    SecondSchemaVersionNumber: SchemaVersionNumber
    SchemaDiffType: SchemaDiffType


class GetSchemaVersionsDiffResponse(TypedDict, total=False):
    Diff: Optional[SchemaDefinitionDiff]


class GetSecurityConfigurationRequest(ServiceRequest):
    Name: NameString


class SecurityConfiguration(TypedDict, total=False):
    Name: Optional[NameString]
    CreatedTimeStamp: Optional[TimestampValue]
    EncryptionConfiguration: Optional[EncryptionConfiguration]


class GetSecurityConfigurationResponse(TypedDict, total=False):
    SecurityConfiguration: Optional[SecurityConfiguration]


class GetSecurityConfigurationsRequest(ServiceRequest):
    MaxResults: Optional[PageSize]
    NextToken: Optional[GenericString]


SecurityConfigurationList = List[SecurityConfiguration]


class GetSecurityConfigurationsResponse(TypedDict, total=False):
    SecurityConfigurations: Optional[SecurityConfigurationList]
    NextToken: Optional[GenericString]


class GetTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    Name: NameString
    TransactionId: Optional[TransactionIdString]
    QueryAsOfTime: Optional[Timestamp]


class Table(TypedDict, total=False):
    Name: NameString
    DatabaseName: Optional[NameString]
    Description: Optional[DescriptionString]
    Owner: Optional[NameString]
    CreateTime: Optional[Timestamp]
    UpdateTime: Optional[Timestamp]
    LastAccessTime: Optional[Timestamp]
    LastAnalyzedTime: Optional[Timestamp]
    Retention: Optional[NonNegativeInteger]
    StorageDescriptor: Optional[StorageDescriptor]
    PartitionKeys: Optional[ColumnList]
    ViewOriginalText: Optional[ViewTextString]
    ViewExpandedText: Optional[ViewTextString]
    TableType: Optional[TableTypeString]
    Parameters: Optional[ParametersMap]
    CreatedBy: Optional[NameString]
    IsRegisteredWithLakeFormation: Optional[Boolean]
    TargetTable: Optional[TableIdentifier]
    CatalogId: Optional[CatalogIdString]
    VersionId: Optional[VersionString]


class GetTableResponse(TypedDict, total=False):
    Table: Optional[Table]


class GetTableVersionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    VersionId: Optional[VersionString]


class TableVersion(TypedDict, total=False):
    Table: Optional[Table]
    VersionId: Optional[VersionString]


class GetTableVersionResponse(TypedDict, total=False):
    TableVersion: Optional[TableVersion]


GetTableVersionsList = List[TableVersion]


class GetTableVersionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    NextToken: Optional[Token]
    MaxResults: Optional[CatalogGetterPageSize]


class GetTableVersionsResponse(TypedDict, total=False):
    TableVersions: Optional[GetTableVersionsList]
    NextToken: Optional[Token]


class GetTablesRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    Expression: Optional[FilterString]
    NextToken: Optional[Token]
    MaxResults: Optional[CatalogGetterPageSize]
    TransactionId: Optional[TransactionIdString]
    QueryAsOfTime: Optional[Timestamp]


TableList = List[Table]


class GetTablesResponse(TypedDict, total=False):
    TableList: Optional[TableList]
    NextToken: Optional[Token]


class GetTagsRequest(ServiceRequest):
    ResourceArn: GlueResourceArn


class GetTagsResponse(TypedDict, total=False):
    Tags: Optional[TagsMap]


class GetTriggerRequest(ServiceRequest):
    Name: NameString


class GetTriggerResponse(TypedDict, total=False):
    Trigger: Optional[Trigger]


class GetTriggersRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    DependentJobName: Optional[NameString]
    MaxResults: Optional[PageSize]


class GetTriggersResponse(TypedDict, total=False):
    Triggers: Optional[TriggerList]
    NextToken: Optional[GenericString]


PermissionTypeList = List[PermissionType]


class GetUnfilteredPartitionMetadataRequest(ServiceRequest):
    CatalogId: CatalogIdString
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList
    AuditContext: Optional[AuditContext]
    SupportedPermissionTypes: PermissionTypeList


class GetUnfilteredPartitionMetadataResponse(TypedDict, total=False):
    Partition: Optional[Partition]
    AuthorizedColumns: Optional[NameStringList]
    IsRegisteredWithLakeFormation: Optional[Boolean]


class GetUnfilteredPartitionsMetadataRequest(ServiceRequest):
    CatalogId: CatalogIdString
    DatabaseName: NameString
    TableName: NameString
    Expression: Optional[PredicateString]
    AuditContext: Optional[AuditContext]
    SupportedPermissionTypes: PermissionTypeList
    NextToken: Optional[Token]
    Segment: Optional[Segment]
    MaxResults: Optional[PageSize]


class UnfilteredPartition(TypedDict, total=False):
    Partition: Optional[Partition]
    AuthorizedColumns: Optional[NameStringList]
    IsRegisteredWithLakeFormation: Optional[Boolean]


UnfilteredPartitionList = List[UnfilteredPartition]


class GetUnfilteredPartitionsMetadataResponse(TypedDict, total=False):
    UnfilteredPartitions: Optional[UnfilteredPartitionList]
    NextToken: Optional[Token]


class GetUnfilteredTableMetadataRequest(ServiceRequest):
    CatalogId: CatalogIdString
    DatabaseName: NameString
    Name: NameString
    AuditContext: Optional[AuditContext]
    SupportedPermissionTypes: PermissionTypeList


class GetUnfilteredTableMetadataResponse(TypedDict, total=False):
    Table: Optional[Table]
    AuthorizedColumns: Optional[NameStringList]
    IsRegisteredWithLakeFormation: Optional[Boolean]
    CellFilters: Optional[ColumnRowFilterList]


class GetUserDefinedFunctionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    FunctionName: NameString


class UserDefinedFunction(TypedDict, total=False):
    FunctionName: Optional[NameString]
    DatabaseName: Optional[NameString]
    ClassName: Optional[NameString]
    OwnerName: Optional[NameString]
    OwnerType: Optional[PrincipalType]
    CreateTime: Optional[Timestamp]
    ResourceUris: Optional[ResourceUriList]
    CatalogId: Optional[CatalogIdString]


class GetUserDefinedFunctionResponse(TypedDict, total=False):
    UserDefinedFunction: Optional[UserDefinedFunction]


class GetUserDefinedFunctionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: Optional[NameString]
    Pattern: NameString
    NextToken: Optional[Token]
    MaxResults: Optional[CatalogGetterPageSize]


UserDefinedFunctionList = List[UserDefinedFunction]


class GetUserDefinedFunctionsResponse(TypedDict, total=False):
    UserDefinedFunctions: Optional[UserDefinedFunctionList]
    NextToken: Optional[Token]


class GetWorkflowRequest(ServiceRequest):
    Name: NameString
    IncludeGraph: Optional[NullableBoolean]


class GetWorkflowResponse(TypedDict, total=False):
    Workflow: Optional[Workflow]


class GetWorkflowRunPropertiesRequest(ServiceRequest):
    Name: NameString
    RunId: IdString


class GetWorkflowRunPropertiesResponse(TypedDict, total=False):
    RunProperties: Optional[WorkflowRunProperties]


class GetWorkflowRunRequest(ServiceRequest):
    Name: NameString
    RunId: IdString
    IncludeGraph: Optional[NullableBoolean]


class GetWorkflowRunResponse(TypedDict, total=False):
    Run: Optional[WorkflowRun]


class GetWorkflowRunsRequest(ServiceRequest):
    Name: NameString
    IncludeGraph: Optional[NullableBoolean]
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]


WorkflowRuns = List[WorkflowRun]


class GetWorkflowRunsResponse(TypedDict, total=False):
    Runs: Optional[WorkflowRuns]
    NextToken: Optional[GenericString]


class ImportCatalogToGlueRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]


class ImportCatalogToGlueResponse(TypedDict, total=False):
    pass


class JobUpdate(TypedDict, total=False):
    Description: Optional[DescriptionString]
    LogUri: Optional[UriString]
    Role: Optional[RoleString]
    ExecutionProperty: Optional[ExecutionProperty]
    Command: Optional[JobCommand]
    DefaultArguments: Optional[GenericMap]
    NonOverridableArguments: Optional[GenericMap]
    Connections: Optional[ConnectionsList]
    MaxRetries: Optional[MaxRetries]
    AllocatedCapacity: Optional[IntegerValue]
    Timeout: Optional[Timeout]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    SecurityConfiguration: Optional[NameString]
    NotificationProperty: Optional[NotificationProperty]
    GlueVersion: Optional[GlueVersionString]


class ListBlueprintsRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]
    Tags: Optional[TagsMap]


class ListBlueprintsResponse(TypedDict, total=False):
    Blueprints: Optional[BlueprintNames]
    NextToken: Optional[GenericString]


class ListCrawlersRequest(ServiceRequest):
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]
    Tags: Optional[TagsMap]


class ListCrawlersResponse(TypedDict, total=False):
    CrawlerNames: Optional[CrawlerNameList]
    NextToken: Optional[Token]


class ListDevEndpointsRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]
    Tags: Optional[TagsMap]


class ListDevEndpointsResponse(TypedDict, total=False):
    DevEndpointNames: Optional[DevEndpointNameList]
    NextToken: Optional[GenericString]


class ListJobsRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]
    Tags: Optional[TagsMap]


class ListJobsResponse(TypedDict, total=False):
    JobNames: Optional[JobNameList]
    NextToken: Optional[GenericString]


class ListMLTransformsRequest(ServiceRequest):
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[PageSize]
    Filter: Optional[TransformFilterCriteria]
    Sort: Optional[TransformSortCriteria]
    Tags: Optional[TagsMap]


TransformIdList = List[HashString]


class ListMLTransformsResponse(TypedDict, total=False):
    TransformIds: TransformIdList
    NextToken: Optional[PaginationToken]


class ListRegistriesInput(ServiceRequest):
    MaxResults: Optional[MaxResultsNumber]
    NextToken: Optional[SchemaRegistryTokenString]


class RegistryListItem(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]
    Description: Optional[DescriptionString]
    Status: Optional[RegistryStatus]
    CreatedTime: Optional[CreatedTimestamp]
    UpdatedTime: Optional[UpdatedTimestamp]


RegistryListDefinition = List[RegistryListItem]


class ListRegistriesResponse(TypedDict, total=False):
    Registries: Optional[RegistryListDefinition]
    NextToken: Optional[SchemaRegistryTokenString]


class ListSchemaVersionsInput(ServiceRequest):
    SchemaId: SchemaId
    MaxResults: Optional[MaxResultsNumber]
    NextToken: Optional[SchemaRegistryTokenString]


class SchemaVersionListItem(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaVersionId: Optional[SchemaVersionIdString]
    VersionNumber: Optional[VersionLongNumber]
    Status: Optional[SchemaVersionStatus]
    CreatedTime: Optional[CreatedTimestamp]


SchemaVersionList = List[SchemaVersionListItem]


class ListSchemaVersionsResponse(TypedDict, total=False):
    Schemas: Optional[SchemaVersionList]
    NextToken: Optional[SchemaRegistryTokenString]


class ListSchemasInput(ServiceRequest):
    RegistryId: Optional[RegistryId]
    MaxResults: Optional[MaxResultsNumber]
    NextToken: Optional[SchemaRegistryTokenString]


class SchemaListItem(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    SchemaName: Optional[SchemaRegistryNameString]
    SchemaArn: Optional[GlueResourceArn]
    Description: Optional[DescriptionString]
    SchemaStatus: Optional[SchemaStatus]
    CreatedTime: Optional[CreatedTimestamp]
    UpdatedTime: Optional[UpdatedTimestamp]


SchemaListDefinition = List[SchemaListItem]


class ListSchemasResponse(TypedDict, total=False):
    Schemas: Optional[SchemaListDefinition]
    NextToken: Optional[SchemaRegistryTokenString]


class ListTriggersRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    DependentJobName: Optional[NameString]
    MaxResults: Optional[PageSize]
    Tags: Optional[TagsMap]


class ListTriggersResponse(TypedDict, total=False):
    TriggerNames: Optional[TriggerNameList]
    NextToken: Optional[GenericString]


class ListWorkflowsRequest(ServiceRequest):
    NextToken: Optional[GenericString]
    MaxResults: Optional[PageSize]


class ListWorkflowsResponse(TypedDict, total=False):
    Workflows: Optional[WorkflowNames]
    NextToken: Optional[GenericString]


class OtherMetadataValueListItem(TypedDict, total=False):
    MetadataValue: Optional[MetadataValueString]
    CreatedTime: Optional[CreatedTimestamp]


OtherMetadataValueList = List[OtherMetadataValueListItem]


class MetadataInfo(TypedDict, total=False):
    MetadataValue: Optional[MetadataValueString]
    CreatedTime: Optional[CreatedTimestamp]
    OtherMetadataValueList: Optional[OtherMetadataValueList]


MetadataInfoMap = Dict[MetadataKeyString, MetadataInfo]


class MetadataKeyValuePair(TypedDict, total=False):
    MetadataKey: Optional[MetadataKeyString]
    MetadataValue: Optional[MetadataValueString]


MetadataList = List[MetadataKeyValuePair]
NodeIdList = List[NameString]


class PropertyPredicate(TypedDict, total=False):
    Key: Optional[ValueString]
    Value: Optional[ValueString]
    Comparator: Optional[Comparator]


class PutDataCatalogEncryptionSettingsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DataCatalogEncryptionSettings: DataCatalogEncryptionSettings


class PutDataCatalogEncryptionSettingsResponse(TypedDict, total=False):
    pass


class PutResourcePolicyRequest(ServiceRequest):
    PolicyInJson: PolicyJsonString
    ResourceArn: Optional[GlueResourceArn]
    PolicyHashCondition: Optional[HashString]
    PolicyExistsCondition: Optional[ExistCondition]
    EnableHybrid: Optional[EnableHybridValues]


class PutResourcePolicyResponse(TypedDict, total=False):
    PolicyHash: Optional[HashString]


class PutSchemaVersionMetadataInput(ServiceRequest):
    SchemaId: Optional[SchemaId]
    SchemaVersionNumber: Optional[SchemaVersionNumber]
    SchemaVersionId: Optional[SchemaVersionIdString]
    MetadataKeyValue: MetadataKeyValuePair


class PutSchemaVersionMetadataResponse(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    RegistryName: Optional[SchemaRegistryNameString]
    LatestVersion: Optional[LatestSchemaVersionBoolean]
    VersionNumber: Optional[VersionLongNumber]
    SchemaVersionId: Optional[SchemaVersionIdString]
    MetadataKey: Optional[MetadataKeyString]
    MetadataValue: Optional[MetadataValueString]


class PutWorkflowRunPropertiesRequest(ServiceRequest):
    Name: NameString
    RunId: IdString
    RunProperties: WorkflowRunProperties


class PutWorkflowRunPropertiesResponse(TypedDict, total=False):
    pass


class QuerySchemaVersionMetadataInput(ServiceRequest):
    SchemaId: Optional[SchemaId]
    SchemaVersionNumber: Optional[SchemaVersionNumber]
    SchemaVersionId: Optional[SchemaVersionIdString]
    MetadataList: Optional[MetadataList]
    MaxResults: Optional[QuerySchemaVersionMetadataMaxResults]
    NextToken: Optional[SchemaRegistryTokenString]


class QuerySchemaVersionMetadataResponse(TypedDict, total=False):
    MetadataInfoMap: Optional[MetadataInfoMap]
    SchemaVersionId: Optional[SchemaVersionIdString]
    NextToken: Optional[SchemaRegistryTokenString]


class RegisterSchemaVersionInput(ServiceRequest):
    SchemaId: SchemaId
    SchemaDefinition: SchemaDefinitionString


class RegisterSchemaVersionResponse(TypedDict, total=False):
    SchemaVersionId: Optional[SchemaVersionIdString]
    VersionNumber: Optional[VersionLongNumber]
    Status: Optional[SchemaVersionStatus]


class RemoveSchemaVersionMetadataInput(ServiceRequest):
    SchemaId: Optional[SchemaId]
    SchemaVersionNumber: Optional[SchemaVersionNumber]
    SchemaVersionId: Optional[SchemaVersionIdString]
    MetadataKeyValue: MetadataKeyValuePair


class RemoveSchemaVersionMetadataResponse(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    RegistryName: Optional[SchemaRegistryNameString]
    LatestVersion: Optional[LatestSchemaVersionBoolean]
    VersionNumber: Optional[VersionLongNumber]
    SchemaVersionId: Optional[SchemaVersionIdString]
    MetadataKey: Optional[MetadataKeyString]
    MetadataValue: Optional[MetadataValueString]


class ResetJobBookmarkRequest(ServiceRequest):
    JobName: JobName
    RunId: Optional[RunId]


class ResetJobBookmarkResponse(TypedDict, total=False):
    JobBookmarkEntry: Optional[JobBookmarkEntry]


class ResumeWorkflowRunRequest(ServiceRequest):
    Name: NameString
    RunId: IdString
    NodeIds: NodeIdList


class ResumeWorkflowRunResponse(TypedDict, total=False):
    RunId: Optional[IdString]
    NodeIds: Optional[NodeIdList]


SearchPropertyPredicates = List[PropertyPredicate]


class SortCriterion(TypedDict, total=False):
    FieldName: Optional[ValueString]
    Sort: Optional[Sort]


SortCriteria = List[SortCriterion]


class SearchTablesRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    NextToken: Optional[Token]
    Filters: Optional[SearchPropertyPredicates]
    SearchText: Optional[ValueString]
    SortCriteria: Optional[SortCriteria]
    MaxResults: Optional[PageSize]
    ResourceShareType: Optional[ResourceShareType]


class SearchTablesResponse(TypedDict, total=False):
    NextToken: Optional[Token]
    TableList: Optional[TableList]


class StartBlueprintRunRequest(ServiceRequest):
    BlueprintName: OrchestrationNameString
    Parameters: Optional[BlueprintParameters]
    RoleArn: OrchestrationIAMRoleArn


class StartBlueprintRunResponse(TypedDict, total=False):
    RunId: Optional[IdString]


class StartCrawlerRequest(ServiceRequest):
    Name: NameString


class StartCrawlerResponse(TypedDict, total=False):
    pass


class StartCrawlerScheduleRequest(ServiceRequest):
    CrawlerName: NameString


class StartCrawlerScheduleResponse(TypedDict, total=False):
    pass


class StartExportLabelsTaskRunRequest(ServiceRequest):
    TransformId: HashString
    OutputS3Path: UriString


class StartExportLabelsTaskRunResponse(TypedDict, total=False):
    TaskRunId: Optional[HashString]


class StartImportLabelsTaskRunRequest(ServiceRequest):
    TransformId: HashString
    InputS3Path: UriString
    ReplaceAllLabels: Optional[ReplaceBoolean]


class StartImportLabelsTaskRunResponse(TypedDict, total=False):
    TaskRunId: Optional[HashString]


class StartJobRunRequest(ServiceRequest):
    JobName: NameString
    JobRunId: Optional[IdString]
    Arguments: Optional[GenericMap]
    AllocatedCapacity: Optional[IntegerValue]
    Timeout: Optional[Timeout]
    MaxCapacity: Optional[NullableDouble]
    SecurityConfiguration: Optional[NameString]
    NotificationProperty: Optional[NotificationProperty]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]


class StartJobRunResponse(TypedDict, total=False):
    JobRunId: Optional[IdString]


class StartMLEvaluationTaskRunRequest(ServiceRequest):
    TransformId: HashString


class StartMLEvaluationTaskRunResponse(TypedDict, total=False):
    TaskRunId: Optional[HashString]


class StartMLLabelingSetGenerationTaskRunRequest(ServiceRequest):
    TransformId: HashString
    OutputS3Path: UriString


class StartMLLabelingSetGenerationTaskRunResponse(TypedDict, total=False):
    TaskRunId: Optional[HashString]


class StartTriggerRequest(ServiceRequest):
    Name: NameString


class StartTriggerResponse(TypedDict, total=False):
    Name: Optional[NameString]


class StartWorkflowRunRequest(ServiceRequest):
    Name: NameString
    RunProperties: Optional[WorkflowRunProperties]


class StartWorkflowRunResponse(TypedDict, total=False):
    RunId: Optional[IdString]


class StopCrawlerRequest(ServiceRequest):
    Name: NameString


class StopCrawlerResponse(TypedDict, total=False):
    pass


class StopCrawlerScheduleRequest(ServiceRequest):
    CrawlerName: NameString


class StopCrawlerScheduleResponse(TypedDict, total=False):
    pass


class StopTriggerRequest(ServiceRequest):
    Name: NameString


class StopTriggerResponse(TypedDict, total=False):
    Name: Optional[NameString]


class StopWorkflowRunRequest(ServiceRequest):
    Name: NameString
    RunId: IdString


class StopWorkflowRunResponse(TypedDict, total=False):
    pass


TagKeysList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: GlueResourceArn
    TagsToAdd: TagsMap


class TagResourceResponse(TypedDict, total=False):
    pass


class TriggerUpdate(TypedDict, total=False):
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    Schedule: Optional[GenericString]
    Actions: Optional[ActionList]
    Predicate: Optional[Predicate]
    EventBatchingCondition: Optional[EventBatchingCondition]


class UntagResourceRequest(ServiceRequest):
    ResourceArn: GlueResourceArn
    TagsToRemove: TagKeysList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateBlueprintRequest(ServiceRequest):
    Name: OrchestrationNameString
    Description: Optional[Generic512CharString]
    BlueprintLocation: OrchestrationS3Location


class UpdateBlueprintResponse(TypedDict, total=False):
    Name: Optional[NameString]


class UpdateCsvClassifierRequest(TypedDict, total=False):
    Name: NameString
    Delimiter: Optional[CsvColumnDelimiter]
    QuoteSymbol: Optional[CsvQuoteSymbol]
    ContainsHeader: Optional[CsvHeaderOption]
    Header: Optional[CsvHeader]
    DisableValueTrimming: Optional[NullableBoolean]
    AllowSingleColumn: Optional[NullableBoolean]


class UpdateJsonClassifierRequest(TypedDict, total=False):
    Name: NameString
    JsonPath: Optional[JsonPath]


class UpdateXMLClassifierRequest(TypedDict, total=False):
    Name: NameString
    Classification: Optional[Classification]
    RowTag: Optional[RowTag]


class UpdateGrokClassifierRequest(TypedDict, total=False):
    Name: NameString
    Classification: Optional[Classification]
    GrokPattern: Optional[GrokPattern]
    CustomPatterns: Optional[CustomPatterns]


class UpdateClassifierRequest(ServiceRequest):
    GrokClassifier: Optional[UpdateGrokClassifierRequest]
    XMLClassifier: Optional[UpdateXMLClassifierRequest]
    JsonClassifier: Optional[UpdateJsonClassifierRequest]
    CsvClassifier: Optional[UpdateCsvClassifierRequest]


class UpdateClassifierResponse(TypedDict, total=False):
    pass


UpdateColumnStatisticsList = List[ColumnStatistics]


class UpdateColumnStatisticsForPartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValues: ValueStringList
    ColumnStatisticsList: UpdateColumnStatisticsList


class UpdateColumnStatisticsForPartitionResponse(TypedDict, total=False):
    Errors: Optional[ColumnStatisticsErrors]


class UpdateColumnStatisticsForTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    ColumnStatisticsList: UpdateColumnStatisticsList


class UpdateColumnStatisticsForTableResponse(TypedDict, total=False):
    Errors: Optional[ColumnStatisticsErrors]


class UpdateConnectionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Name: NameString
    ConnectionInput: ConnectionInput


class UpdateConnectionResponse(TypedDict, total=False):
    pass


class UpdateCrawlerRequest(ServiceRequest):
    Name: NameString
    Role: Optional[Role]
    DatabaseName: Optional[DatabaseName]
    Description: Optional[DescriptionStringRemovable]
    Targets: Optional[CrawlerTargets]
    Schedule: Optional[CronExpression]
    Classifiers: Optional[ClassifierNameList]
    TablePrefix: Optional[TablePrefix]
    SchemaChangePolicy: Optional[SchemaChangePolicy]
    RecrawlPolicy: Optional[RecrawlPolicy]
    LineageConfiguration: Optional[LineageConfiguration]
    LakeFormationConfiguration: Optional[LakeFormationConfiguration]
    Configuration: Optional[CrawlerConfiguration]
    CrawlerSecurityConfiguration: Optional[CrawlerSecurityConfiguration]


class UpdateCrawlerResponse(TypedDict, total=False):
    pass


class UpdateCrawlerScheduleRequest(ServiceRequest):
    CrawlerName: NameString
    Schedule: Optional[CronExpression]


class UpdateCrawlerScheduleResponse(TypedDict, total=False):
    pass


class UpdateDatabaseRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Name: NameString
    DatabaseInput: DatabaseInput


class UpdateDatabaseResponse(TypedDict, total=False):
    pass


class UpdateDevEndpointRequest(ServiceRequest):
    EndpointName: GenericString
    PublicKey: Optional[GenericString]
    AddPublicKeys: Optional[PublicKeysList]
    DeletePublicKeys: Optional[PublicKeysList]
    CustomLibraries: Optional[DevEndpointCustomLibraries]
    UpdateEtlLibraries: Optional[BooleanValue]
    DeleteArguments: Optional[StringList]
    AddArguments: Optional[MapValue]


class UpdateDevEndpointResponse(TypedDict, total=False):
    pass


class UpdateJobRequest(ServiceRequest):
    JobName: NameString
    JobUpdate: JobUpdate


class UpdateJobResponse(TypedDict, total=False):
    JobName: Optional[NameString]


class UpdateMLTransformRequest(ServiceRequest):
    TransformId: HashString
    Name: Optional[NameString]
    Description: Optional[DescriptionString]
    Parameters: Optional[TransformParameters]
    Role: Optional[RoleString]
    GlueVersion: Optional[GlueVersionString]
    MaxCapacity: Optional[NullableDouble]
    WorkerType: Optional[WorkerType]
    NumberOfWorkers: Optional[NullableInteger]
    Timeout: Optional[Timeout]
    MaxRetries: Optional[NullableInteger]


class UpdateMLTransformResponse(TypedDict, total=False):
    TransformId: Optional[HashString]


class UpdatePartitionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    PartitionValueList: BoundedPartitionValueList
    PartitionInput: PartitionInput


class UpdatePartitionResponse(TypedDict, total=False):
    pass


class UpdateRegistryInput(ServiceRequest):
    RegistryId: RegistryId
    Description: DescriptionString


class UpdateRegistryResponse(TypedDict, total=False):
    RegistryName: Optional[SchemaRegistryNameString]
    RegistryArn: Optional[GlueResourceArn]


class UpdateSchemaInput(ServiceRequest):
    SchemaId: SchemaId
    SchemaVersionNumber: Optional[SchemaVersionNumber]
    Compatibility: Optional[Compatibility]
    Description: Optional[DescriptionString]


class UpdateSchemaResponse(TypedDict, total=False):
    SchemaArn: Optional[GlueResourceArn]
    SchemaName: Optional[SchemaRegistryNameString]
    RegistryName: Optional[SchemaRegistryNameString]


class UpdateTableRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableInput: TableInput
    SkipArchive: Optional[BooleanNullable]
    TransactionId: Optional[TransactionIdString]
    VersionId: Optional[VersionString]


class UpdateTableResponse(TypedDict, total=False):
    pass


class UpdateTriggerRequest(ServiceRequest):
    Name: NameString
    TriggerUpdate: TriggerUpdate


class UpdateTriggerResponse(TypedDict, total=False):
    Trigger: Optional[Trigger]


class UpdateUserDefinedFunctionRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    FunctionName: NameString
    FunctionInput: UserDefinedFunctionInput


class UpdateUserDefinedFunctionResponse(TypedDict, total=False):
    pass


class UpdateWorkflowRequest(ServiceRequest):
    Name: NameString
    Description: Optional[GenericString]
    DefaultRunProperties: Optional[WorkflowRunProperties]
    MaxConcurrentRuns: Optional[NullableInteger]


class UpdateWorkflowResponse(TypedDict, total=False):
    Name: Optional[NameString]


class GlueApi:

    service = "glue"
    version = "2017-03-31"

    @handler("BatchCreatePartition")
    def batch_create_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_input_list: PartitionInputList,
        catalog_id: CatalogIdString = None,
    ) -> BatchCreatePartitionResponse:
        raise NotImplementedError

    @handler("BatchDeleteConnection")
    def batch_delete_connection(
        self,
        context: RequestContext,
        connection_name_list: DeleteConnectionNameList,
        catalog_id: CatalogIdString = None,
    ) -> BatchDeleteConnectionResponse:
        raise NotImplementedError

    @handler("BatchDeletePartition")
    def batch_delete_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partitions_to_delete: BatchDeletePartitionValueList,
        catalog_id: CatalogIdString = None,
    ) -> BatchDeletePartitionResponse:
        raise NotImplementedError

    @handler("BatchDeleteTable")
    def batch_delete_table(
        self,
        context: RequestContext,
        database_name: NameString,
        tables_to_delete: BatchDeleteTableNameList,
        catalog_id: CatalogIdString = None,
        transaction_id: TransactionIdString = None,
    ) -> BatchDeleteTableResponse:
        raise NotImplementedError

    @handler("BatchDeleteTableVersion")
    def batch_delete_table_version(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        version_ids: BatchDeleteTableVersionList,
        catalog_id: CatalogIdString = None,
    ) -> BatchDeleteTableVersionResponse:
        raise NotImplementedError

    @handler("BatchGetBlueprints")
    def batch_get_blueprints(
        self,
        context: RequestContext,
        names: BatchGetBlueprintNames,
        include_blueprint: NullableBoolean = None,
        include_parameter_spec: NullableBoolean = None,
    ) -> BatchGetBlueprintsResponse:
        raise NotImplementedError

    @handler("BatchGetCrawlers")
    def batch_get_crawlers(
        self, context: RequestContext, crawler_names: CrawlerNameList
    ) -> BatchGetCrawlersResponse:
        raise NotImplementedError

    @handler("BatchGetDevEndpoints")
    def batch_get_dev_endpoints(
        self, context: RequestContext, dev_endpoint_names: DevEndpointNames
    ) -> BatchGetDevEndpointsResponse:
        raise NotImplementedError

    @handler("BatchGetJobs")
    def batch_get_jobs(
        self, context: RequestContext, job_names: JobNameList
    ) -> BatchGetJobsResponse:
        raise NotImplementedError

    @handler("BatchGetPartition")
    def batch_get_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partitions_to_get: BatchGetPartitionValueList,
        catalog_id: CatalogIdString = None,
    ) -> BatchGetPartitionResponse:
        raise NotImplementedError

    @handler("BatchGetTriggers")
    def batch_get_triggers(
        self, context: RequestContext, trigger_names: TriggerNameList
    ) -> BatchGetTriggersResponse:
        raise NotImplementedError

    @handler("BatchGetWorkflows")
    def batch_get_workflows(
        self, context: RequestContext, names: WorkflowNames, include_graph: NullableBoolean = None
    ) -> BatchGetWorkflowsResponse:
        raise NotImplementedError

    @handler("BatchStopJobRun")
    def batch_stop_job_run(
        self,
        context: RequestContext,
        job_name: NameString,
        job_run_ids: BatchStopJobRunJobRunIdList,
    ) -> BatchStopJobRunResponse:
        raise NotImplementedError

    @handler("BatchUpdatePartition")
    def batch_update_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        entries: BatchUpdatePartitionRequestEntryList,
        catalog_id: CatalogIdString = None,
    ) -> BatchUpdatePartitionResponse:
        raise NotImplementedError

    @handler("CancelMLTaskRun")
    def cancel_ml_task_run(
        self, context: RequestContext, transform_id: HashString, task_run_id: HashString
    ) -> CancelMLTaskRunResponse:
        raise NotImplementedError

    @handler("CheckSchemaVersionValidity")
    def check_schema_version_validity(
        self,
        context: RequestContext,
        data_format: DataFormat,
        schema_definition: SchemaDefinitionString,
    ) -> CheckSchemaVersionValidityResponse:
        raise NotImplementedError

    @handler("CreateBlueprint")
    def create_blueprint(
        self,
        context: RequestContext,
        name: OrchestrationNameString,
        blueprint_location: OrchestrationS3Location,
        description: Generic512CharString = None,
        tags: TagsMap = None,
    ) -> CreateBlueprintResponse:
        raise NotImplementedError

    @handler("CreateClassifier")
    def create_classifier(
        self,
        context: RequestContext,
        grok_classifier: CreateGrokClassifierRequest = None,
        xml_classifier: CreateXMLClassifierRequest = None,
        json_classifier: CreateJsonClassifierRequest = None,
        csv_classifier: CreateCsvClassifierRequest = None,
    ) -> CreateClassifierResponse:
        raise NotImplementedError

    @handler("CreateConnection")
    def create_connection(
        self,
        context: RequestContext,
        connection_input: ConnectionInput,
        catalog_id: CatalogIdString = None,
        tags: TagsMap = None,
    ) -> CreateConnectionResponse:
        raise NotImplementedError

    @handler("CreateCrawler")
    def create_crawler(
        self,
        context: RequestContext,
        name: NameString,
        role: Role,
        targets: CrawlerTargets,
        database_name: DatabaseName = None,
        description: DescriptionString = None,
        schedule: CronExpression = None,
        classifiers: ClassifierNameList = None,
        table_prefix: TablePrefix = None,
        schema_change_policy: SchemaChangePolicy = None,
        recrawl_policy: RecrawlPolicy = None,
        lineage_configuration: LineageConfiguration = None,
        lake_formation_configuration: LakeFormationConfiguration = None,
        configuration: CrawlerConfiguration = None,
        crawler_security_configuration: CrawlerSecurityConfiguration = None,
        tags: TagsMap = None,
    ) -> CreateCrawlerResponse:
        raise NotImplementedError

    @handler("CreateDatabase")
    def create_database(
        self,
        context: RequestContext,
        database_input: DatabaseInput,
        catalog_id: CatalogIdString = None,
    ) -> CreateDatabaseResponse:
        raise NotImplementedError

    @handler("CreateDevEndpoint")
    def create_dev_endpoint(
        self,
        context: RequestContext,
        endpoint_name: GenericString,
        role_arn: RoleArn,
        security_group_ids: StringList = None,
        subnet_id: GenericString = None,
        public_key: GenericString = None,
        public_keys: PublicKeysList = None,
        number_of_nodes: IntegerValue = None,
        worker_type: WorkerType = None,
        glue_version: GlueVersionString = None,
        number_of_workers: NullableInteger = None,
        extra_python_libs_s3_path: GenericString = None,
        extra_jars_s3_path: GenericString = None,
        security_configuration: NameString = None,
        tags: TagsMap = None,
        arguments: MapValue = None,
    ) -> CreateDevEndpointResponse:
        raise NotImplementedError

    @handler("CreateJob")
    def create_job(
        self,
        context: RequestContext,
        name: NameString,
        role: RoleString,
        command: JobCommand,
        description: DescriptionString = None,
        log_uri: UriString = None,
        execution_property: ExecutionProperty = None,
        default_arguments: GenericMap = None,
        non_overridable_arguments: GenericMap = None,
        connections: ConnectionsList = None,
        max_retries: MaxRetries = None,
        allocated_capacity: IntegerValue = None,
        timeout: Timeout = None,
        max_capacity: NullableDouble = None,
        security_configuration: NameString = None,
        tags: TagsMap = None,
        notification_property: NotificationProperty = None,
        glue_version: GlueVersionString = None,
        number_of_workers: NullableInteger = None,
        worker_type: WorkerType = None,
    ) -> CreateJobResponse:
        raise NotImplementedError

    @handler("CreateMLTransform")
    def create_ml_transform(
        self,
        context: RequestContext,
        name: NameString,
        input_record_tables: GlueTables,
        parameters: TransformParameters,
        role: RoleString,
        description: DescriptionString = None,
        glue_version: GlueVersionString = None,
        max_capacity: NullableDouble = None,
        worker_type: WorkerType = None,
        number_of_workers: NullableInteger = None,
        timeout: Timeout = None,
        max_retries: NullableInteger = None,
        tags: TagsMap = None,
        transform_encryption: TransformEncryption = None,
    ) -> CreateMLTransformResponse:
        raise NotImplementedError

    @handler("CreatePartition")
    def create_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_input: PartitionInput,
        catalog_id: CatalogIdString = None,
    ) -> CreatePartitionResponse:
        raise NotImplementedError

    @handler("CreatePartitionIndex")
    def create_partition_index(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_index: PartitionIndex,
        catalog_id: CatalogIdString = None,
    ) -> CreatePartitionIndexResponse:
        raise NotImplementedError

    @handler("CreateRegistry")
    def create_registry(
        self,
        context: RequestContext,
        registry_name: SchemaRegistryNameString,
        description: DescriptionString = None,
        tags: TagsMap = None,
    ) -> CreateRegistryResponse:
        raise NotImplementedError

    @handler("CreateSchema")
    def create_schema(
        self,
        context: RequestContext,
        schema_name: SchemaRegistryNameString,
        data_format: DataFormat,
        registry_id: RegistryId = None,
        compatibility: Compatibility = None,
        description: DescriptionString = None,
        tags: TagsMap = None,
        schema_definition: SchemaDefinitionString = None,
    ) -> CreateSchemaResponse:
        raise NotImplementedError

    @handler("CreateScript")
    def create_script(
        self,
        context: RequestContext,
        dag_nodes: DagNodes = None,
        dag_edges: DagEdges = None,
        language: Language = None,
    ) -> CreateScriptResponse:
        raise NotImplementedError

    @handler("CreateSecurityConfiguration")
    def create_security_configuration(
        self,
        context: RequestContext,
        name: NameString,
        encryption_configuration: EncryptionConfiguration,
    ) -> CreateSecurityConfigurationResponse:
        raise NotImplementedError

    @handler("CreateTable")
    def create_table(
        self,
        context: RequestContext,
        database_name: NameString,
        table_input: TableInput,
        catalog_id: CatalogIdString = None,
        partition_indexes: PartitionIndexList = None,
        transaction_id: TransactionIdString = None,
    ) -> CreateTableResponse:
        raise NotImplementedError

    @handler("CreateTrigger", expand=False)
    def create_trigger(
        self, context: RequestContext, request: CreateTriggerRequest
    ) -> CreateTriggerResponse:
        raise NotImplementedError

    @handler("CreateUserDefinedFunction")
    def create_user_defined_function(
        self,
        context: RequestContext,
        database_name: NameString,
        function_input: UserDefinedFunctionInput,
        catalog_id: CatalogIdString = None,
    ) -> CreateUserDefinedFunctionResponse:
        raise NotImplementedError

    @handler("CreateWorkflow")
    def create_workflow(
        self,
        context: RequestContext,
        name: NameString,
        description: GenericString = None,
        default_run_properties: WorkflowRunProperties = None,
        tags: TagsMap = None,
        max_concurrent_runs: NullableInteger = None,
    ) -> CreateWorkflowResponse:
        raise NotImplementedError

    @handler("DeleteBlueprint")
    def delete_blueprint(
        self, context: RequestContext, name: NameString
    ) -> DeleteBlueprintResponse:
        raise NotImplementedError

    @handler("DeleteClassifier")
    def delete_classifier(
        self, context: RequestContext, name: NameString
    ) -> DeleteClassifierResponse:
        raise NotImplementedError

    @handler("DeleteColumnStatisticsForPartition")
    def delete_column_statistics_for_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        column_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> DeleteColumnStatisticsForPartitionResponse:
        raise NotImplementedError

    @handler("DeleteColumnStatisticsForTable")
    def delete_column_statistics_for_table(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        column_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> DeleteColumnStatisticsForTableResponse:
        raise NotImplementedError

    @handler("DeleteConnection")
    def delete_connection(
        self,
        context: RequestContext,
        connection_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> DeleteConnectionResponse:
        raise NotImplementedError

    @handler("DeleteCrawler")
    def delete_crawler(self, context: RequestContext, name: NameString) -> DeleteCrawlerResponse:
        raise NotImplementedError

    @handler("DeleteDatabase")
    def delete_database(
        self, context: RequestContext, name: NameString, catalog_id: CatalogIdString = None
    ) -> DeleteDatabaseResponse:
        raise NotImplementedError

    @handler("DeleteDevEndpoint")
    def delete_dev_endpoint(
        self, context: RequestContext, endpoint_name: GenericString
    ) -> DeleteDevEndpointResponse:
        raise NotImplementedError

    @handler("DeleteJob")
    def delete_job(self, context: RequestContext, job_name: NameString) -> DeleteJobResponse:
        raise NotImplementedError

    @handler("DeleteMLTransform")
    def delete_ml_transform(
        self, context: RequestContext, transform_id: HashString
    ) -> DeleteMLTransformResponse:
        raise NotImplementedError

    @handler("DeletePartition")
    def delete_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        catalog_id: CatalogIdString = None,
    ) -> DeletePartitionResponse:
        raise NotImplementedError

    @handler("DeletePartitionIndex")
    def delete_partition_index(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        index_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> DeletePartitionIndexResponse:
        raise NotImplementedError

    @handler("DeleteRegistry")
    def delete_registry(
        self, context: RequestContext, registry_id: RegistryId
    ) -> DeleteRegistryResponse:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self,
        context: RequestContext,
        policy_hash_condition: HashString = None,
        resource_arn: GlueResourceArn = None,
    ) -> DeleteResourcePolicyResponse:
        raise NotImplementedError

    @handler("DeleteSchema")
    def delete_schema(self, context: RequestContext, schema_id: SchemaId) -> DeleteSchemaResponse:
        raise NotImplementedError

    @handler("DeleteSchemaVersions")
    def delete_schema_versions(
        self, context: RequestContext, schema_id: SchemaId, versions: VersionsString
    ) -> DeleteSchemaVersionsResponse:
        raise NotImplementedError

    @handler("DeleteSecurityConfiguration")
    def delete_security_configuration(
        self, context: RequestContext, name: NameString
    ) -> DeleteSecurityConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteTable")
    def delete_table(
        self,
        context: RequestContext,
        database_name: NameString,
        name: NameString,
        catalog_id: CatalogIdString = None,
        transaction_id: TransactionIdString = None,
    ) -> DeleteTableResponse:
        raise NotImplementedError

    @handler("DeleteTableVersion")
    def delete_table_version(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        version_id: VersionString,
        catalog_id: CatalogIdString = None,
    ) -> DeleteTableVersionResponse:
        raise NotImplementedError

    @handler("DeleteTrigger")
    def delete_trigger(self, context: RequestContext, name: NameString) -> DeleteTriggerResponse:
        raise NotImplementedError

    @handler("DeleteUserDefinedFunction")
    def delete_user_defined_function(
        self,
        context: RequestContext,
        database_name: NameString,
        function_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> DeleteUserDefinedFunctionResponse:
        raise NotImplementedError

    @handler("DeleteWorkflow")
    def delete_workflow(self, context: RequestContext, name: NameString) -> DeleteWorkflowResponse:
        raise NotImplementedError

    @handler("GetBlueprint")
    def get_blueprint(
        self,
        context: RequestContext,
        name: NameString,
        include_blueprint: NullableBoolean = None,
        include_parameter_spec: NullableBoolean = None,
    ) -> GetBlueprintResponse:
        raise NotImplementedError

    @handler("GetBlueprintRun")
    def get_blueprint_run(
        self, context: RequestContext, blueprint_name: OrchestrationNameString, run_id: IdString
    ) -> GetBlueprintRunResponse:
        raise NotImplementedError

    @handler("GetBlueprintRuns")
    def get_blueprint_runs(
        self,
        context: RequestContext,
        blueprint_name: NameString,
        next_token: GenericString = None,
        max_results: PageSize = None,
    ) -> GetBlueprintRunsResponse:
        raise NotImplementedError

    @handler("GetCatalogImportStatus")
    def get_catalog_import_status(
        self, context: RequestContext, catalog_id: CatalogIdString = None
    ) -> GetCatalogImportStatusResponse:
        raise NotImplementedError

    @handler("GetClassifier")
    def get_classifier(self, context: RequestContext, name: NameString) -> GetClassifierResponse:
        raise NotImplementedError

    @handler("GetClassifiers")
    def get_classifiers(
        self, context: RequestContext, max_results: PageSize = None, next_token: Token = None
    ) -> GetClassifiersResponse:
        raise NotImplementedError

    @handler("GetColumnStatisticsForPartition")
    def get_column_statistics_for_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        column_names: GetColumnNamesList,
        catalog_id: CatalogIdString = None,
    ) -> GetColumnStatisticsForPartitionResponse:
        raise NotImplementedError

    @handler("GetColumnStatisticsForTable")
    def get_column_statistics_for_table(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        column_names: GetColumnNamesList,
        catalog_id: CatalogIdString = None,
    ) -> GetColumnStatisticsForTableResponse:
        raise NotImplementedError

    @handler("GetConnection")
    def get_connection(
        self,
        context: RequestContext,
        name: NameString,
        catalog_id: CatalogIdString = None,
        hide_password: Boolean = None,
    ) -> GetConnectionResponse:
        raise NotImplementedError

    @handler("GetConnections")
    def get_connections(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        filter: GetConnectionsFilter = None,
        hide_password: Boolean = None,
        next_token: Token = None,
        max_results: PageSize = None,
    ) -> GetConnectionsResponse:
        raise NotImplementedError

    @handler("GetCrawler")
    def get_crawler(self, context: RequestContext, name: NameString) -> GetCrawlerResponse:
        raise NotImplementedError

    @handler("GetCrawlerMetrics")
    def get_crawler_metrics(
        self,
        context: RequestContext,
        crawler_name_list: CrawlerNameList = None,
        max_results: PageSize = None,
        next_token: Token = None,
    ) -> GetCrawlerMetricsResponse:
        raise NotImplementedError

    @handler("GetCrawlers")
    def get_crawlers(
        self, context: RequestContext, max_results: PageSize = None, next_token: Token = None
    ) -> GetCrawlersResponse:
        raise NotImplementedError

    @handler("GetDataCatalogEncryptionSettings")
    def get_data_catalog_encryption_settings(
        self, context: RequestContext, catalog_id: CatalogIdString = None
    ) -> GetDataCatalogEncryptionSettingsResponse:
        raise NotImplementedError

    @handler("GetDatabase")
    def get_database(
        self, context: RequestContext, name: NameString, catalog_id: CatalogIdString = None
    ) -> GetDatabaseResponse:
        raise NotImplementedError

    @handler("GetDatabases")
    def get_databases(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        next_token: Token = None,
        max_results: CatalogGetterPageSize = None,
        resource_share_type: ResourceShareType = None,
    ) -> GetDatabasesResponse:
        raise NotImplementedError

    @handler("GetDataflowGraph")
    def get_dataflow_graph(
        self, context: RequestContext, python_script: PythonScript = None
    ) -> GetDataflowGraphResponse:
        raise NotImplementedError

    @handler("GetDevEndpoint")
    def get_dev_endpoint(
        self, context: RequestContext, endpoint_name: GenericString
    ) -> GetDevEndpointResponse:
        raise NotImplementedError

    @handler("GetDevEndpoints")
    def get_dev_endpoints(
        self,
        context: RequestContext,
        max_results: PageSize = None,
        next_token: GenericString = None,
    ) -> GetDevEndpointsResponse:
        raise NotImplementedError

    @handler("GetJob")
    def get_job(self, context: RequestContext, job_name: NameString) -> GetJobResponse:
        raise NotImplementedError

    @handler("GetJobBookmark")
    def get_job_bookmark(
        self, context: RequestContext, job_name: JobName, run_id: RunId = None
    ) -> GetJobBookmarkResponse:
        raise NotImplementedError

    @handler("GetJobRun")
    def get_job_run(
        self,
        context: RequestContext,
        job_name: NameString,
        run_id: IdString,
        predecessors_included: BooleanValue = None,
    ) -> GetJobRunResponse:
        raise NotImplementedError

    @handler("GetJobRuns")
    def get_job_runs(
        self,
        context: RequestContext,
        job_name: NameString,
        next_token: GenericString = None,
        max_results: PageSize = None,
    ) -> GetJobRunsResponse:
        raise NotImplementedError

    @handler("GetJobs")
    def get_jobs(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        max_results: PageSize = None,
    ) -> GetJobsResponse:
        raise NotImplementedError

    @handler("GetMLTaskRun")
    def get_ml_task_run(
        self, context: RequestContext, transform_id: HashString, task_run_id: HashString
    ) -> GetMLTaskRunResponse:
        raise NotImplementedError

    @handler("GetMLTaskRuns")
    def get_ml_task_runs(
        self,
        context: RequestContext,
        transform_id: HashString,
        next_token: PaginationToken = None,
        max_results: PageSize = None,
        filter: TaskRunFilterCriteria = None,
        sort: TaskRunSortCriteria = None,
    ) -> GetMLTaskRunsResponse:
        raise NotImplementedError

    @handler("GetMLTransform")
    def get_ml_transform(
        self, context: RequestContext, transform_id: HashString
    ) -> GetMLTransformResponse:
        raise NotImplementedError

    @handler("GetMLTransforms")
    def get_ml_transforms(
        self,
        context: RequestContext,
        next_token: PaginationToken = None,
        max_results: PageSize = None,
        filter: TransformFilterCriteria = None,
        sort: TransformSortCriteria = None,
    ) -> GetMLTransformsResponse:
        raise NotImplementedError

    @handler("GetMapping")
    def get_mapping(
        self,
        context: RequestContext,
        source: CatalogEntry,
        sinks: CatalogEntries = None,
        location: Location = None,
    ) -> GetMappingResponse:
        raise NotImplementedError

    @handler("GetPartition")
    def get_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        catalog_id: CatalogIdString = None,
    ) -> GetPartitionResponse:
        raise NotImplementedError

    @handler("GetPartitionIndexes")
    def get_partition_indexes(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        next_token: Token = None,
    ) -> GetPartitionIndexesResponse:
        raise NotImplementedError

    @handler("GetPartitions")
    def get_partitions(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        expression: PredicateString = None,
        next_token: Token = None,
        segment: Segment = None,
        max_results: PageSize = None,
        exclude_column_schema: BooleanNullable = None,
        transaction_id: TransactionIdString = None,
        query_as_of_time: Timestamp = None,
    ) -> GetPartitionsResponse:
        raise NotImplementedError

    @handler("GetPlan")
    def get_plan(
        self,
        context: RequestContext,
        mapping: MappingList,
        source: CatalogEntry,
        sinks: CatalogEntries = None,
        location: Location = None,
        language: Language = None,
        additional_plan_options_map: AdditionalPlanOptionsMap = None,
    ) -> GetPlanResponse:
        raise NotImplementedError

    @handler("GetRegistry")
    def get_registry(self, context: RequestContext, registry_id: RegistryId) -> GetRegistryResponse:
        raise NotImplementedError

    @handler("GetResourcePolicies")
    def get_resource_policies(
        self, context: RequestContext, next_token: Token = None, max_results: PageSize = None
    ) -> GetResourcePoliciesResponse:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, resource_arn: GlueResourceArn = None
    ) -> GetResourcePolicyResponse:
        raise NotImplementedError

    @handler("GetSchema")
    def get_schema(self, context: RequestContext, schema_id: SchemaId) -> GetSchemaResponse:
        raise NotImplementedError

    @handler("GetSchemaByDefinition")
    def get_schema_by_definition(
        self,
        context: RequestContext,
        schema_id: SchemaId,
        schema_definition: SchemaDefinitionString,
    ) -> GetSchemaByDefinitionResponse:
        raise NotImplementedError

    @handler("GetSchemaVersion")
    def get_schema_version(
        self,
        context: RequestContext,
        schema_id: SchemaId = None,
        schema_version_id: SchemaVersionIdString = None,
        schema_version_number: SchemaVersionNumber = None,
    ) -> GetSchemaVersionResponse:
        raise NotImplementedError

    @handler("GetSchemaVersionsDiff")
    def get_schema_versions_diff(
        self,
        context: RequestContext,
        schema_id: SchemaId,
        first_schema_version_number: SchemaVersionNumber,
        second_schema_version_number: SchemaVersionNumber,
        schema_diff_type: SchemaDiffType,
    ) -> GetSchemaVersionsDiffResponse:
        raise NotImplementedError

    @handler("GetSecurityConfiguration")
    def get_security_configuration(
        self, context: RequestContext, name: NameString
    ) -> GetSecurityConfigurationResponse:
        raise NotImplementedError

    @handler("GetSecurityConfigurations")
    def get_security_configurations(
        self,
        context: RequestContext,
        max_results: PageSize = None,
        next_token: GenericString = None,
    ) -> GetSecurityConfigurationsResponse:
        raise NotImplementedError

    @handler("GetTable")
    def get_table(
        self,
        context: RequestContext,
        database_name: NameString,
        name: NameString,
        catalog_id: CatalogIdString = None,
        transaction_id: TransactionIdString = None,
        query_as_of_time: Timestamp = None,
    ) -> GetTableResponse:
        raise NotImplementedError

    @handler("GetTableVersion")
    def get_table_version(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        version_id: VersionString = None,
    ) -> GetTableVersionResponse:
        raise NotImplementedError

    @handler("GetTableVersions")
    def get_table_versions(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        next_token: Token = None,
        max_results: CatalogGetterPageSize = None,
    ) -> GetTableVersionsResponse:
        raise NotImplementedError

    @handler("GetTables")
    def get_tables(
        self,
        context: RequestContext,
        database_name: NameString,
        catalog_id: CatalogIdString = None,
        expression: FilterString = None,
        next_token: Token = None,
        max_results: CatalogGetterPageSize = None,
        transaction_id: TransactionIdString = None,
        query_as_of_time: Timestamp = None,
    ) -> GetTablesResponse:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(self, context: RequestContext, resource_arn: GlueResourceArn) -> GetTagsResponse:
        raise NotImplementedError

    @handler("GetTrigger")
    def get_trigger(self, context: RequestContext, name: NameString) -> GetTriggerResponse:
        raise NotImplementedError

    @handler("GetTriggers")
    def get_triggers(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        dependent_job_name: NameString = None,
        max_results: PageSize = None,
    ) -> GetTriggersResponse:
        raise NotImplementedError

    @handler("GetUnfilteredPartitionMetadata")
    def get_unfiltered_partition_metadata(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        supported_permission_types: PermissionTypeList,
        audit_context: AuditContext = None,
    ) -> GetUnfilteredPartitionMetadataResponse:
        raise NotImplementedError

    @handler("GetUnfilteredPartitionsMetadata")
    def get_unfiltered_partitions_metadata(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString,
        database_name: NameString,
        table_name: NameString,
        supported_permission_types: PermissionTypeList,
        expression: PredicateString = None,
        audit_context: AuditContext = None,
        next_token: Token = None,
        segment: Segment = None,
        max_results: PageSize = None,
    ) -> GetUnfilteredPartitionsMetadataResponse:
        raise NotImplementedError

    @handler("GetUnfilteredTableMetadata")
    def get_unfiltered_table_metadata(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString,
        database_name: NameString,
        name: NameString,
        supported_permission_types: PermissionTypeList,
        audit_context: AuditContext = None,
    ) -> GetUnfilteredTableMetadataResponse:
        raise NotImplementedError

    @handler("GetUserDefinedFunction")
    def get_user_defined_function(
        self,
        context: RequestContext,
        database_name: NameString,
        function_name: NameString,
        catalog_id: CatalogIdString = None,
    ) -> GetUserDefinedFunctionResponse:
        raise NotImplementedError

    @handler("GetUserDefinedFunctions")
    def get_user_defined_functions(
        self,
        context: RequestContext,
        pattern: NameString,
        catalog_id: CatalogIdString = None,
        database_name: NameString = None,
        next_token: Token = None,
        max_results: CatalogGetterPageSize = None,
    ) -> GetUserDefinedFunctionsResponse:
        raise NotImplementedError

    @handler("GetWorkflow")
    def get_workflow(
        self, context: RequestContext, name: NameString, include_graph: NullableBoolean = None
    ) -> GetWorkflowResponse:
        raise NotImplementedError

    @handler("GetWorkflowRun")
    def get_workflow_run(
        self,
        context: RequestContext,
        name: NameString,
        run_id: IdString,
        include_graph: NullableBoolean = None,
    ) -> GetWorkflowRunResponse:
        raise NotImplementedError

    @handler("GetWorkflowRunProperties")
    def get_workflow_run_properties(
        self, context: RequestContext, name: NameString, run_id: IdString
    ) -> GetWorkflowRunPropertiesResponse:
        raise NotImplementedError

    @handler("GetWorkflowRuns")
    def get_workflow_runs(
        self,
        context: RequestContext,
        name: NameString,
        include_graph: NullableBoolean = None,
        next_token: GenericString = None,
        max_results: PageSize = None,
    ) -> GetWorkflowRunsResponse:
        raise NotImplementedError

    @handler("ImportCatalogToGlue")
    def import_catalog_to_glue(
        self, context: RequestContext, catalog_id: CatalogIdString = None
    ) -> ImportCatalogToGlueResponse:
        raise NotImplementedError

    @handler("ListBlueprints")
    def list_blueprints(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        max_results: PageSize = None,
        tags: TagsMap = None,
    ) -> ListBlueprintsResponse:
        raise NotImplementedError

    @handler("ListCrawlers")
    def list_crawlers(
        self,
        context: RequestContext,
        max_results: PageSize = None,
        next_token: Token = None,
        tags: TagsMap = None,
    ) -> ListCrawlersResponse:
        raise NotImplementedError

    @handler("ListDevEndpoints")
    def list_dev_endpoints(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        max_results: PageSize = None,
        tags: TagsMap = None,
    ) -> ListDevEndpointsResponse:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        max_results: PageSize = None,
        tags: TagsMap = None,
    ) -> ListJobsResponse:
        raise NotImplementedError

    @handler("ListMLTransforms")
    def list_ml_transforms(
        self,
        context: RequestContext,
        next_token: PaginationToken = None,
        max_results: PageSize = None,
        filter: TransformFilterCriteria = None,
        sort: TransformSortCriteria = None,
        tags: TagsMap = None,
    ) -> ListMLTransformsResponse:
        raise NotImplementedError

    @handler("ListRegistries")
    def list_registries(
        self,
        context: RequestContext,
        max_results: MaxResultsNumber = None,
        next_token: SchemaRegistryTokenString = None,
    ) -> ListRegistriesResponse:
        raise NotImplementedError

    @handler("ListSchemaVersions")
    def list_schema_versions(
        self,
        context: RequestContext,
        schema_id: SchemaId,
        max_results: MaxResultsNumber = None,
        next_token: SchemaRegistryTokenString = None,
    ) -> ListSchemaVersionsResponse:
        raise NotImplementedError

    @handler("ListSchemas")
    def list_schemas(
        self,
        context: RequestContext,
        registry_id: RegistryId = None,
        max_results: MaxResultsNumber = None,
        next_token: SchemaRegistryTokenString = None,
    ) -> ListSchemasResponse:
        raise NotImplementedError

    @handler("ListTriggers")
    def list_triggers(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        dependent_job_name: NameString = None,
        max_results: PageSize = None,
        tags: TagsMap = None,
    ) -> ListTriggersResponse:
        raise NotImplementedError

    @handler("ListWorkflows")
    def list_workflows(
        self,
        context: RequestContext,
        next_token: GenericString = None,
        max_results: PageSize = None,
    ) -> ListWorkflowsResponse:
        raise NotImplementedError

    @handler("PutDataCatalogEncryptionSettings")
    def put_data_catalog_encryption_settings(
        self,
        context: RequestContext,
        data_catalog_encryption_settings: DataCatalogEncryptionSettings,
        catalog_id: CatalogIdString = None,
    ) -> PutDataCatalogEncryptionSettingsResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        policy_in_json: PolicyJsonString,
        resource_arn: GlueResourceArn = None,
        policy_hash_condition: HashString = None,
        policy_exists_condition: ExistCondition = None,
        enable_hybrid: EnableHybridValues = None,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("PutSchemaVersionMetadata")
    def put_schema_version_metadata(
        self,
        context: RequestContext,
        metadata_key_value: MetadataKeyValuePair,
        schema_id: SchemaId = None,
        schema_version_number: SchemaVersionNumber = None,
        schema_version_id: SchemaVersionIdString = None,
    ) -> PutSchemaVersionMetadataResponse:
        raise NotImplementedError

    @handler("PutWorkflowRunProperties")
    def put_workflow_run_properties(
        self,
        context: RequestContext,
        name: NameString,
        run_id: IdString,
        run_properties: WorkflowRunProperties,
    ) -> PutWorkflowRunPropertiesResponse:
        raise NotImplementedError

    @handler("QuerySchemaVersionMetadata")
    def query_schema_version_metadata(
        self,
        context: RequestContext,
        schema_id: SchemaId = None,
        schema_version_number: SchemaVersionNumber = None,
        schema_version_id: SchemaVersionIdString = None,
        metadata_list: MetadataList = None,
        max_results: QuerySchemaVersionMetadataMaxResults = None,
        next_token: SchemaRegistryTokenString = None,
    ) -> QuerySchemaVersionMetadataResponse:
        raise NotImplementedError

    @handler("RegisterSchemaVersion")
    def register_schema_version(
        self,
        context: RequestContext,
        schema_id: SchemaId,
        schema_definition: SchemaDefinitionString,
    ) -> RegisterSchemaVersionResponse:
        raise NotImplementedError

    @handler("RemoveSchemaVersionMetadata")
    def remove_schema_version_metadata(
        self,
        context: RequestContext,
        metadata_key_value: MetadataKeyValuePair,
        schema_id: SchemaId = None,
        schema_version_number: SchemaVersionNumber = None,
        schema_version_id: SchemaVersionIdString = None,
    ) -> RemoveSchemaVersionMetadataResponse:
        raise NotImplementedError

    @handler("ResetJobBookmark")
    def reset_job_bookmark(
        self, context: RequestContext, job_name: JobName, run_id: RunId = None
    ) -> ResetJobBookmarkResponse:
        raise NotImplementedError

    @handler("ResumeWorkflowRun")
    def resume_workflow_run(
        self, context: RequestContext, name: NameString, run_id: IdString, node_ids: NodeIdList
    ) -> ResumeWorkflowRunResponse:
        raise NotImplementedError

    @handler("SearchTables")
    def search_tables(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        next_token: Token = None,
        filters: SearchPropertyPredicates = None,
        search_text: ValueString = None,
        sort_criteria: SortCriteria = None,
        max_results: PageSize = None,
        resource_share_type: ResourceShareType = None,
    ) -> SearchTablesResponse:
        raise NotImplementedError

    @handler("StartBlueprintRun")
    def start_blueprint_run(
        self,
        context: RequestContext,
        blueprint_name: OrchestrationNameString,
        role_arn: OrchestrationIAMRoleArn,
        parameters: BlueprintParameters = None,
    ) -> StartBlueprintRunResponse:
        raise NotImplementedError

    @handler("StartCrawler")
    def start_crawler(self, context: RequestContext, name: NameString) -> StartCrawlerResponse:
        raise NotImplementedError

    @handler("StartCrawlerSchedule")
    def start_crawler_schedule(
        self, context: RequestContext, crawler_name: NameString
    ) -> StartCrawlerScheduleResponse:
        raise NotImplementedError

    @handler("StartExportLabelsTaskRun")
    def start_export_labels_task_run(
        self, context: RequestContext, transform_id: HashString, output_s3_path: UriString
    ) -> StartExportLabelsTaskRunResponse:
        raise NotImplementedError

    @handler("StartImportLabelsTaskRun")
    def start_import_labels_task_run(
        self,
        context: RequestContext,
        transform_id: HashString,
        input_s3_path: UriString,
        replace_all_labels: ReplaceBoolean = None,
    ) -> StartImportLabelsTaskRunResponse:
        raise NotImplementedError

    @handler("StartJobRun")
    def start_job_run(
        self,
        context: RequestContext,
        job_name: NameString,
        job_run_id: IdString = None,
        arguments: GenericMap = None,
        allocated_capacity: IntegerValue = None,
        timeout: Timeout = None,
        max_capacity: NullableDouble = None,
        security_configuration: NameString = None,
        notification_property: NotificationProperty = None,
        worker_type: WorkerType = None,
        number_of_workers: NullableInteger = None,
    ) -> StartJobRunResponse:
        raise NotImplementedError

    @handler("StartMLEvaluationTaskRun")
    def start_ml_evaluation_task_run(
        self, context: RequestContext, transform_id: HashString
    ) -> StartMLEvaluationTaskRunResponse:
        raise NotImplementedError

    @handler("StartMLLabelingSetGenerationTaskRun")
    def start_ml_labeling_set_generation_task_run(
        self, context: RequestContext, transform_id: HashString, output_s3_path: UriString
    ) -> StartMLLabelingSetGenerationTaskRunResponse:
        raise NotImplementedError

    @handler("StartTrigger")
    def start_trigger(self, context: RequestContext, name: NameString) -> StartTriggerResponse:
        raise NotImplementedError

    @handler("StartWorkflowRun")
    def start_workflow_run(
        self,
        context: RequestContext,
        name: NameString,
        run_properties: WorkflowRunProperties = None,
    ) -> StartWorkflowRunResponse:
        raise NotImplementedError

    @handler("StopCrawler")
    def stop_crawler(self, context: RequestContext, name: NameString) -> StopCrawlerResponse:
        raise NotImplementedError

    @handler("StopCrawlerSchedule")
    def stop_crawler_schedule(
        self, context: RequestContext, crawler_name: NameString
    ) -> StopCrawlerScheduleResponse:
        raise NotImplementedError

    @handler("StopTrigger")
    def stop_trigger(self, context: RequestContext, name: NameString) -> StopTriggerResponse:
        raise NotImplementedError

    @handler("StopWorkflowRun")
    def stop_workflow_run(
        self, context: RequestContext, name: NameString, run_id: IdString
    ) -> StopWorkflowRunResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: GlueResourceArn, tags_to_add: TagsMap
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: GlueResourceArn, tags_to_remove: TagKeysList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateBlueprint")
    def update_blueprint(
        self,
        context: RequestContext,
        name: OrchestrationNameString,
        blueprint_location: OrchestrationS3Location,
        description: Generic512CharString = None,
    ) -> UpdateBlueprintResponse:
        raise NotImplementedError

    @handler("UpdateClassifier")
    def update_classifier(
        self,
        context: RequestContext,
        grok_classifier: UpdateGrokClassifierRequest = None,
        xml_classifier: UpdateXMLClassifierRequest = None,
        json_classifier: UpdateJsonClassifierRequest = None,
        csv_classifier: UpdateCsvClassifierRequest = None,
    ) -> UpdateClassifierResponse:
        raise NotImplementedError

    @handler("UpdateColumnStatisticsForPartition")
    def update_column_statistics_for_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_values: ValueStringList,
        column_statistics_list: UpdateColumnStatisticsList,
        catalog_id: CatalogIdString = None,
    ) -> UpdateColumnStatisticsForPartitionResponse:
        raise NotImplementedError

    @handler("UpdateColumnStatisticsForTable")
    def update_column_statistics_for_table(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        column_statistics_list: UpdateColumnStatisticsList,
        catalog_id: CatalogIdString = None,
    ) -> UpdateColumnStatisticsForTableResponse:
        raise NotImplementedError

    @handler("UpdateConnection")
    def update_connection(
        self,
        context: RequestContext,
        name: NameString,
        connection_input: ConnectionInput,
        catalog_id: CatalogIdString = None,
    ) -> UpdateConnectionResponse:
        raise NotImplementedError

    @handler("UpdateCrawler")
    def update_crawler(
        self,
        context: RequestContext,
        name: NameString,
        role: Role = None,
        database_name: DatabaseName = None,
        description: DescriptionStringRemovable = None,
        targets: CrawlerTargets = None,
        schedule: CronExpression = None,
        classifiers: ClassifierNameList = None,
        table_prefix: TablePrefix = None,
        schema_change_policy: SchemaChangePolicy = None,
        recrawl_policy: RecrawlPolicy = None,
        lineage_configuration: LineageConfiguration = None,
        lake_formation_configuration: LakeFormationConfiguration = None,
        configuration: CrawlerConfiguration = None,
        crawler_security_configuration: CrawlerSecurityConfiguration = None,
    ) -> UpdateCrawlerResponse:
        raise NotImplementedError

    @handler("UpdateCrawlerSchedule")
    def update_crawler_schedule(
        self, context: RequestContext, crawler_name: NameString, schedule: CronExpression = None
    ) -> UpdateCrawlerScheduleResponse:
        raise NotImplementedError

    @handler("UpdateDatabase")
    def update_database(
        self,
        context: RequestContext,
        name: NameString,
        database_input: DatabaseInput,
        catalog_id: CatalogIdString = None,
    ) -> UpdateDatabaseResponse:
        raise NotImplementedError

    @handler("UpdateDevEndpoint")
    def update_dev_endpoint(
        self,
        context: RequestContext,
        endpoint_name: GenericString,
        public_key: GenericString = None,
        add_public_keys: PublicKeysList = None,
        delete_public_keys: PublicKeysList = None,
        custom_libraries: DevEndpointCustomLibraries = None,
        update_etl_libraries: BooleanValue = None,
        delete_arguments: StringList = None,
        add_arguments: MapValue = None,
    ) -> UpdateDevEndpointResponse:
        raise NotImplementedError

    @handler("UpdateJob")
    def update_job(
        self, context: RequestContext, job_name: NameString, job_update: JobUpdate
    ) -> UpdateJobResponse:
        raise NotImplementedError

    @handler("UpdateMLTransform")
    def update_ml_transform(
        self,
        context: RequestContext,
        transform_id: HashString,
        name: NameString = None,
        description: DescriptionString = None,
        parameters: TransformParameters = None,
        role: RoleString = None,
        glue_version: GlueVersionString = None,
        max_capacity: NullableDouble = None,
        worker_type: WorkerType = None,
        number_of_workers: NullableInteger = None,
        timeout: Timeout = None,
        max_retries: NullableInteger = None,
    ) -> UpdateMLTransformResponse:
        raise NotImplementedError

    @handler("UpdatePartition")
    def update_partition(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        partition_value_list: BoundedPartitionValueList,
        partition_input: PartitionInput,
        catalog_id: CatalogIdString = None,
    ) -> UpdatePartitionResponse:
        raise NotImplementedError

    @handler("UpdateRegistry")
    def update_registry(
        self, context: RequestContext, registry_id: RegistryId, description: DescriptionString
    ) -> UpdateRegistryResponse:
        raise NotImplementedError

    @handler("UpdateSchema")
    def update_schema(
        self,
        context: RequestContext,
        schema_id: SchemaId,
        schema_version_number: SchemaVersionNumber = None,
        compatibility: Compatibility = None,
        description: DescriptionString = None,
    ) -> UpdateSchemaResponse:
        raise NotImplementedError

    @handler("UpdateTable")
    def update_table(
        self,
        context: RequestContext,
        database_name: NameString,
        table_input: TableInput,
        catalog_id: CatalogIdString = None,
        skip_archive: BooleanNullable = None,
        transaction_id: TransactionIdString = None,
        version_id: VersionString = None,
    ) -> UpdateTableResponse:
        raise NotImplementedError

    @handler("UpdateTrigger")
    def update_trigger(
        self, context: RequestContext, name: NameString, trigger_update: TriggerUpdate
    ) -> UpdateTriggerResponse:
        raise NotImplementedError

    @handler("UpdateUserDefinedFunction")
    def update_user_defined_function(
        self,
        context: RequestContext,
        database_name: NameString,
        function_name: NameString,
        function_input: UserDefinedFunctionInput,
        catalog_id: CatalogIdString = None,
    ) -> UpdateUserDefinedFunctionResponse:
        raise NotImplementedError

    @handler("UpdateWorkflow")
    def update_workflow(
        self,
        context: RequestContext,
        name: NameString,
        description: GenericString = None,
        default_run_properties: WorkflowRunProperties = None,
        max_concurrent_runs: NullableInteger = None,
    ) -> UpdateWorkflowResponse:
        raise NotImplementedError
