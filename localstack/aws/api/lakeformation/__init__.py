import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessKeyIdString = str
AuditContextString = str
BooleanNullable = bool
CatalogIdString = str
CredentialTimeoutDurationSecondInteger = int
DataLakePrincipalString = str
DescriptionString = str
ETagString = str
ErrorMessageString = str
GetQueryStateRequestQueryIdString = str
GetQueryStatisticsRequestQueryIdString = str
GetWorkUnitResultsRequestQueryIdString = str
GetWorkUnitsRequestQueryIdString = str
IAMRoleArn = str
Identifier = str
Integer = int
LFTagKey = str
LFTagValue = str
MessageString = str
NameString = str
NullableBoolean = bool
PageSize = int
PartitionValueString = str
PredicateString = str
QueryIdString = str
QueryPlanningContextDatabaseNameString = str
RAMResourceShareArn = str
ResourceArnString = str
Result = str
SecretAccessKeyString = str
SessionTokenString = str
StorageOptimizerConfigKey = str
StorageOptimizerConfigValue = str
String = str
StringValue = str
SyntheticGetWorkUnitResultsRequestWorkUnitTokenString = str
SyntheticStartQueryPlanningRequestQueryString = str
Token = str
TokenString = str
TransactionIdString = str
TrueFalseString = str
URI = str
ValueString = str
WorkUnitTokenString = str


class ComparisonOperator(str):
    EQ = "EQ"
    NE = "NE"
    LE = "LE"
    LT = "LT"
    GE = "GE"
    GT = "GT"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    BEGINS_WITH = "BEGINS_WITH"
    IN = "IN"
    BETWEEN = "BETWEEN"


class DataLakeResourceType(str):
    CATALOG = "CATALOG"
    DATABASE = "DATABASE"
    TABLE = "TABLE"
    DATA_LOCATION = "DATA_LOCATION"
    LF_TAG = "LF_TAG"
    LF_TAG_POLICY = "LF_TAG_POLICY"
    LF_TAG_POLICY_DATABASE = "LF_TAG_POLICY_DATABASE"
    LF_TAG_POLICY_TABLE = "LF_TAG_POLICY_TABLE"


class FieldNameString(str):
    RESOURCE_ARN = "RESOURCE_ARN"
    ROLE_ARN = "ROLE_ARN"
    LAST_MODIFIED = "LAST_MODIFIED"


class OptimizerType(str):
    COMPACTION = "COMPACTION"
    GARBAGE_COLLECTION = "GARBAGE_COLLECTION"
    ALL = "ALL"


class Permission(str):
    ALL = "ALL"
    SELECT = "SELECT"
    ALTER = "ALTER"
    DROP = "DROP"
    DELETE = "DELETE"
    INSERT = "INSERT"
    DESCRIBE = "DESCRIBE"
    CREATE_DATABASE = "CREATE_DATABASE"
    CREATE_TABLE = "CREATE_TABLE"
    DATA_LOCATION_ACCESS = "DATA_LOCATION_ACCESS"
    CREATE_TAG = "CREATE_TAG"
    ALTER_TAG = "ALTER_TAG"
    DELETE_TAG = "DELETE_TAG"
    DESCRIBE_TAG = "DESCRIBE_TAG"
    ASSOCIATE_TAG = "ASSOCIATE_TAG"


class PermissionType(str):
    COLUMN_PERMISSION = "COLUMN_PERMISSION"
    CELL_FILTER_PERMISSION = "CELL_FILTER_PERMISSION"


class QueryStateString(str):
    PENDING = "PENDING"
    WORKUNITS_AVAILABLE = "WORKUNITS_AVAILABLE"
    ERROR = "ERROR"
    FINISHED = "FINISHED"
    EXPIRED = "EXPIRED"


class ResourceShareType(str):
    FOREIGN = "FOREIGN"
    ALL = "ALL"


class ResourceType(str):
    DATABASE = "DATABASE"
    TABLE = "TABLE"


class TransactionStatus(str):
    ACTIVE = "ACTIVE"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"
    COMMIT_IN_PROGRESS = "COMMIT_IN_PROGRESS"


class TransactionStatusFilter(str):
    ALL = "ALL"
    COMPLETED = "COMPLETED"
    ACTIVE = "ACTIVE"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"


class TransactionType(str):
    READ_AND_WRITE = "READ_AND_WRITE"
    READ_ONLY = "READ_ONLY"


class AccessDeniedException(ServiceException):
    Message: Optional[MessageString]


class AlreadyExistsException(ServiceException):
    Message: Optional[MessageString]


class ConcurrentModificationException(ServiceException):
    Message: Optional[MessageString]


class EntityNotFoundException(ServiceException):
    Message: Optional[MessageString]


class ExpiredException(ServiceException):
    Message: Optional[MessageString]


class GlueEncryptionException(ServiceException):
    Message: Optional[MessageString]


class InternalServiceException(ServiceException):
    Message: Optional[MessageString]


class InvalidInputException(ServiceException):
    Message: Optional[MessageString]


class OperationTimeoutException(ServiceException):
    Message: Optional[MessageString]


class PermissionTypeMismatchException(ServiceException):
    Message: Optional[MessageString]


class ResourceNotReadyException(ServiceException):
    Message: Optional[MessageString]


class ResourceNumberLimitExceededException(ServiceException):
    Message: Optional[MessageString]


class StatisticsNotReadyYetException(ServiceException):
    Message: Optional[MessageString]


class ThrottledException(ServiceException):
    Message: Optional[MessageString]


class TransactionCanceledException(ServiceException):
    Message: Optional[MessageString]


class TransactionCommitInProgressException(ServiceException):
    Message: Optional[MessageString]


class TransactionCommittedException(ServiceException):
    Message: Optional[MessageString]


class WorkUnitsNotReadyYetException(ServiceException):
    Message: Optional[MessageString]


TagValueList = List[LFTagValue]


class LFTagPair(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    TagKey: LFTagKey
    TagValues: TagValueList


LFTagsList = List[LFTagPair]


class LFTag(TypedDict, total=False):
    TagKey: LFTagKey
    TagValues: TagValueList


Expression = List[LFTag]


class LFTagPolicyResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    ResourceType: ResourceType
    Expression: Expression


class LFTagKeyResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    TagKey: NameString
    TagValues: TagValueList


class DataCellsFilterResource(TypedDict, total=False):
    TableCatalogId: Optional[CatalogIdString]
    DatabaseName: Optional[NameString]
    TableName: Optional[NameString]
    Name: Optional[NameString]


class DataLocationResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    ResourceArn: ResourceArnString


ColumnNames = List[NameString]


class ColumnWildcard(TypedDict, total=False):
    ExcludedColumnNames: Optional[ColumnNames]


class TableWithColumnsResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    Name: NameString
    ColumnNames: Optional[ColumnNames]
    ColumnWildcard: Optional[ColumnWildcard]


class TableWildcard(TypedDict, total=False):
    pass


class TableResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    Name: Optional[NameString]
    TableWildcard: Optional[TableWildcard]


class DatabaseResource(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    Name: NameString


class CatalogResource(TypedDict, total=False):
    pass


class Resource(TypedDict, total=False):
    Catalog: Optional[CatalogResource]
    Database: Optional[DatabaseResource]
    Table: Optional[TableResource]
    TableWithColumns: Optional[TableWithColumnsResource]
    DataLocation: Optional[DataLocationResource]
    DataCellsFilter: Optional[DataCellsFilterResource]
    LFTag: Optional[LFTagKeyResource]
    LFTagPolicy: Optional[LFTagPolicyResource]


class AddLFTagsToResourceRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Resource: Resource
    LFTags: LFTagsList


class ErrorDetail(TypedDict, total=False):
    ErrorCode: Optional[NameString]
    ErrorMessage: Optional[DescriptionString]


class LFTagError(TypedDict, total=False):
    LFTag: Optional[LFTagPair]
    Error: Optional[ErrorDetail]


LFTagErrors = List[LFTagError]


class AddLFTagsToResourceResponse(TypedDict, total=False):
    Failures: Optional[LFTagErrors]


PartitionValuesList = List[PartitionValueString]
ObjectSize = int


class AddObjectInput(TypedDict, total=False):
    Uri: URI
    ETag: ETagString
    Size: ObjectSize
    PartitionValues: Optional[PartitionValuesList]


class AllRowsWildcard(TypedDict, total=False):
    pass


class AuditContext(TypedDict, total=False):
    AdditionalAuditContext: Optional[AuditContextString]


AuthorizedSessionTagValueList = List[NameString]
PermissionList = List[Permission]


class DataLakePrincipal(TypedDict, total=False):
    DataLakePrincipalIdentifier: Optional[DataLakePrincipalString]


class BatchPermissionsRequestEntry(TypedDict, total=False):
    Id: Identifier
    Principal: Optional[DataLakePrincipal]
    Resource: Optional[Resource]
    Permissions: Optional[PermissionList]
    PermissionsWithGrantOption: Optional[PermissionList]


BatchPermissionsRequestEntryList = List[BatchPermissionsRequestEntry]


class BatchGrantPermissionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Entries: BatchPermissionsRequestEntryList


class BatchPermissionsFailureEntry(TypedDict, total=False):
    RequestEntry: Optional[BatchPermissionsRequestEntry]
    Error: Optional[ErrorDetail]


BatchPermissionsFailureList = List[BatchPermissionsFailureEntry]


class BatchGrantPermissionsResponse(TypedDict, total=False):
    Failures: Optional[BatchPermissionsFailureList]


class BatchRevokePermissionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Entries: BatchPermissionsRequestEntryList


class BatchRevokePermissionsResponse(TypedDict, total=False):
    Failures: Optional[BatchPermissionsFailureList]


class CancelTransactionRequest(ServiceRequest):
    TransactionId: TransactionIdString


class CancelTransactionResponse(TypedDict, total=False):
    pass


class ColumnLFTag(TypedDict, total=False):
    Name: Optional[NameString]
    LFTags: Optional[LFTagsList]


ColumnLFTagsList = List[ColumnLFTag]


class CommitTransactionRequest(ServiceRequest):
    TransactionId: TransactionIdString


class CommitTransactionResponse(TypedDict, total=False):
    TransactionStatus: Optional[TransactionStatus]


class RowFilter(TypedDict, total=False):
    FilterExpression: Optional[PredicateString]
    AllRowsWildcard: Optional[AllRowsWildcard]


class DataCellsFilter(TypedDict, total=False):
    TableCatalogId: CatalogIdString
    DatabaseName: NameString
    TableName: NameString
    Name: NameString
    RowFilter: Optional[RowFilter]
    ColumnNames: Optional[ColumnNames]
    ColumnWildcard: Optional[ColumnWildcard]


class CreateDataCellsFilterRequest(ServiceRequest):
    TableData: DataCellsFilter


class CreateDataCellsFilterResponse(TypedDict, total=False):
    pass


class CreateLFTagRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    TagKey: LFTagKey
    TagValues: TagValueList


class CreateLFTagResponse(TypedDict, total=False):
    pass


DataCellsFilterList = List[DataCellsFilter]
DataLakePrincipalList = List[DataLakePrincipal]
TrustedResourceOwners = List[CatalogIdString]


class PrincipalPermissions(TypedDict, total=False):
    Principal: Optional[DataLakePrincipal]
    Permissions: Optional[PermissionList]


PrincipalPermissionsList = List[PrincipalPermissions]


class DataLakeSettings(TypedDict, total=False):
    DataLakeAdmins: Optional[DataLakePrincipalList]
    CreateDatabaseDefaultPermissions: Optional[PrincipalPermissionsList]
    CreateTableDefaultPermissions: Optional[PrincipalPermissionsList]
    TrustedResourceOwners: Optional[TrustedResourceOwners]
    AllowExternalDataFiltering: Optional[NullableBoolean]
    ExternalDataFilteringAllowList: Optional[DataLakePrincipalList]
    AuthorizedSessionTagValueList: Optional[AuthorizedSessionTagValueList]


class TaggedDatabase(TypedDict, total=False):
    Database: Optional[DatabaseResource]
    LFTags: Optional[LFTagsList]


DatabaseLFTagsList = List[TaggedDatabase]
DateTime = datetime


class DeleteDataCellsFilterRequest(ServiceRequest):
    TableCatalogId: Optional[CatalogIdString]
    DatabaseName: Optional[NameString]
    TableName: Optional[NameString]
    Name: Optional[NameString]


class DeleteDataCellsFilterResponse(TypedDict, total=False):
    pass


class DeleteLFTagRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    TagKey: LFTagKey


class DeleteLFTagResponse(TypedDict, total=False):
    pass


class DeleteObjectInput(TypedDict, total=False):
    Uri: URI
    ETag: Optional[ETagString]
    PartitionValues: Optional[PartitionValuesList]


class VirtualObject(TypedDict, total=False):
    Uri: URI
    ETag: Optional[ETagString]


VirtualObjectList = List[VirtualObject]


class DeleteObjectsOnCancelRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    TransactionId: TransactionIdString
    Objects: VirtualObjectList


class DeleteObjectsOnCancelResponse(TypedDict, total=False):
    pass


class DeregisterResourceRequest(ServiceRequest):
    ResourceArn: ResourceArnString


class DeregisterResourceResponse(TypedDict, total=False):
    pass


class DescribeResourceRequest(ServiceRequest):
    ResourceArn: ResourceArnString


LastModifiedTimestamp = datetime


class ResourceInfo(TypedDict, total=False):
    ResourceArn: Optional[ResourceArnString]
    RoleArn: Optional[IAMRoleArn]
    LastModified: Optional[LastModifiedTimestamp]


class DescribeResourceResponse(TypedDict, total=False):
    ResourceInfo: Optional[ResourceInfo]


class DescribeTransactionRequest(ServiceRequest):
    TransactionId: TransactionIdString


Timestamp = datetime


class TransactionDescription(TypedDict, total=False):
    TransactionId: Optional[TransactionIdString]
    TransactionStatus: Optional[TransactionStatus]
    TransactionStartTime: Optional[Timestamp]
    TransactionEndTime: Optional[Timestamp]


class DescribeTransactionResponse(TypedDict, total=False):
    TransactionDescription: Optional[TransactionDescription]


ResourceShareList = List[RAMResourceShareArn]


class DetailsMap(TypedDict, total=False):
    ResourceShare: Optional[ResourceShareList]


NumberOfItems = int
NumberOfBytes = int
NumberOfMilliseconds = int


class ExecutionStatistics(TypedDict, total=False):
    AverageExecutionTimeMillis: Optional[NumberOfMilliseconds]
    DataScannedBytes: Optional[NumberOfBytes]
    WorkUnitsExecutedCount: Optional[NumberOfItems]


ExpirationTimestamp = datetime


class ExtendTransactionRequest(ServiceRequest):
    TransactionId: Optional[TransactionIdString]


class ExtendTransactionResponse(TypedDict, total=False):
    pass


StringValueList = List[StringValue]


class FilterCondition(TypedDict, total=False):
    Field: Optional[FieldNameString]
    ComparisonOperator: Optional[ComparisonOperator]
    StringValueList: Optional[StringValueList]


FilterConditionList = List[FilterCondition]


class GetDataLakeSettingsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]


class GetDataLakeSettingsResponse(TypedDict, total=False):
    DataLakeSettings: Optional[DataLakeSettings]


class GetEffectivePermissionsForPathRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    ResourceArn: ResourceArnString
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]


class PrincipalResourcePermissions(TypedDict, total=False):
    Principal: Optional[DataLakePrincipal]
    Resource: Optional[Resource]
    Permissions: Optional[PermissionList]
    PermissionsWithGrantOption: Optional[PermissionList]
    AdditionalDetails: Optional[DetailsMap]


PrincipalResourcePermissionsList = List[PrincipalResourcePermissions]


class GetEffectivePermissionsForPathResponse(TypedDict, total=False):
    Permissions: Optional[PrincipalResourcePermissionsList]
    NextToken: Optional[Token]


class GetLFTagRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    TagKey: LFTagKey


class GetLFTagResponse(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    TagKey: Optional[LFTagKey]
    TagValues: Optional[TagValueList]


class GetQueryStateRequest(ServiceRequest):
    QueryId: GetQueryStateRequestQueryIdString


class GetQueryStateResponse(TypedDict, total=False):
    Error: Optional[ErrorMessageString]
    State: QueryStateString


class GetQueryStatisticsRequest(ServiceRequest):
    QueryId: GetQueryStatisticsRequestQueryIdString


class PlanningStatistics(TypedDict, total=False):
    EstimatedDataToScanBytes: Optional[NumberOfBytes]
    PlanningTimeMillis: Optional[NumberOfMilliseconds]
    QueueTimeMillis: Optional[NumberOfMilliseconds]
    WorkUnitsGeneratedCount: Optional[NumberOfItems]


class GetQueryStatisticsResponse(TypedDict, total=False):
    ExecutionStatistics: Optional[ExecutionStatistics]
    PlanningStatistics: Optional[PlanningStatistics]
    QuerySubmissionTime: Optional[DateTime]


class GetResourceLFTagsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Resource: Resource
    ShowAssignedLFTags: Optional[BooleanNullable]


class GetResourceLFTagsResponse(TypedDict, total=False):
    LFTagOnDatabase: Optional[LFTagsList]
    LFTagsOnTable: Optional[LFTagsList]
    LFTagsOnColumns: Optional[ColumnLFTagsList]


class GetTableObjectsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    TransactionId: Optional[TransactionIdString]
    QueryAsOfTime: Optional[Timestamp]
    PartitionPredicate: Optional[PredicateString]
    MaxResults: Optional[PageSize]
    NextToken: Optional[TokenString]


class TableObject(TypedDict, total=False):
    Uri: Optional[URI]
    ETag: Optional[ETagString]
    Size: Optional[ObjectSize]


TableObjectList = List[TableObject]


class PartitionObjects(TypedDict, total=False):
    PartitionValues: Optional[PartitionValuesList]
    Objects: Optional[TableObjectList]


PartitionedTableObjectsList = List[PartitionObjects]


class GetTableObjectsResponse(TypedDict, total=False):
    Objects: Optional[PartitionedTableObjectsList]
    NextToken: Optional[TokenString]


PermissionTypeList = List[PermissionType]
ValueStringList = List[ValueString]


class PartitionValueList(TypedDict, total=False):
    Values: ValueStringList


class GetTemporaryGluePartitionCredentialsRequest(ServiceRequest):
    TableArn: ResourceArnString
    Partition: PartitionValueList
    Permissions: Optional[PermissionList]
    DurationSeconds: Optional[CredentialTimeoutDurationSecondInteger]
    AuditContext: Optional[AuditContext]
    SupportedPermissionTypes: PermissionTypeList


class GetTemporaryGluePartitionCredentialsResponse(TypedDict, total=False):
    AccessKeyId: Optional[AccessKeyIdString]
    SecretAccessKey: Optional[SecretAccessKeyString]
    SessionToken: Optional[SessionTokenString]
    Expiration: Optional[ExpirationTimestamp]


class GetTemporaryGlueTableCredentialsRequest(ServiceRequest):
    TableArn: ResourceArnString
    Permissions: Optional[PermissionList]
    DurationSeconds: Optional[CredentialTimeoutDurationSecondInteger]
    AuditContext: Optional[AuditContext]
    SupportedPermissionTypes: PermissionTypeList


class GetTemporaryGlueTableCredentialsResponse(TypedDict, total=False):
    AccessKeyId: Optional[AccessKeyIdString]
    SecretAccessKey: Optional[SecretAccessKeyString]
    SessionToken: Optional[SessionTokenString]
    Expiration: Optional[ExpirationTimestamp]


GetWorkUnitResultsRequestWorkUnitIdLong = int


class GetWorkUnitResultsRequest(ServiceRequest):
    QueryId: GetWorkUnitResultsRequestQueryIdString
    WorkUnitId: GetWorkUnitResultsRequestWorkUnitIdLong
    WorkUnitToken: SyntheticGetWorkUnitResultsRequestWorkUnitTokenString


ResultStream = bytes


class GetWorkUnitResultsResponse(TypedDict, total=False):
    ResultStream: Optional[ResultStream]


class GetWorkUnitsRequest(ServiceRequest):
    NextToken: Optional[Token]
    PageSize: Optional[Integer]
    QueryId: GetWorkUnitsRequestQueryIdString


WorkUnitIdLong = int


class WorkUnitRange(TypedDict, total=False):
    WorkUnitIdMax: WorkUnitIdLong
    WorkUnitIdMin: WorkUnitIdLong
    WorkUnitToken: WorkUnitTokenString


WorkUnitRangeList = List[WorkUnitRange]


class GetWorkUnitsResponse(TypedDict, total=False):
    NextToken: Optional[Token]
    QueryId: QueryIdString
    WorkUnitRanges: WorkUnitRangeList


class GrantPermissionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Principal: DataLakePrincipal
    Resource: Resource
    Permissions: PermissionList
    PermissionsWithGrantOption: Optional[PermissionList]


class GrantPermissionsResponse(TypedDict, total=False):
    pass


class ListDataCellsFilterRequest(ServiceRequest):
    Table: Optional[TableResource]
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]


class ListDataCellsFilterResponse(TypedDict, total=False):
    DataCellsFilters: Optional[DataCellsFilterList]
    NextToken: Optional[Token]


class ListLFTagsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    ResourceShareType: Optional[ResourceShareType]
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


class ListLFTagsResponse(TypedDict, total=False):
    LFTags: Optional[LFTagsList]
    NextToken: Optional[Token]


class ListPermissionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Principal: Optional[DataLakePrincipal]
    ResourceType: Optional[DataLakeResourceType]
    Resource: Optional[Resource]
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]
    IncludeRelated: Optional[TrueFalseString]


class ListPermissionsResponse(TypedDict, total=False):
    PrincipalResourcePermissions: Optional[PrincipalResourcePermissionsList]
    NextToken: Optional[Token]


class ListResourcesRequest(ServiceRequest):
    FilterConditionList: Optional[FilterConditionList]
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


ResourceInfoList = List[ResourceInfo]


class ListResourcesResponse(TypedDict, total=False):
    ResourceInfoList: Optional[ResourceInfoList]
    NextToken: Optional[Token]


class ListTableStorageOptimizersRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    StorageOptimizerType: Optional[OptimizerType]
    MaxResults: Optional[PageSize]
    NextToken: Optional[Token]


StorageOptimizerConfig = Dict[StorageOptimizerConfigKey, StorageOptimizerConfigValue]


class StorageOptimizer(TypedDict, total=False):
    StorageOptimizerType: Optional[OptimizerType]
    Config: Optional[StorageOptimizerConfig]
    ErrorMessage: Optional[MessageString]
    Warnings: Optional[MessageString]
    LastRunDetails: Optional[MessageString]


StorageOptimizerList = List[StorageOptimizer]


class ListTableStorageOptimizersResponse(TypedDict, total=False):
    StorageOptimizerList: Optional[StorageOptimizerList]
    NextToken: Optional[Token]


class ListTransactionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    StatusFilter: Optional[TransactionStatusFilter]
    MaxResults: Optional[PageSize]
    NextToken: Optional[TokenString]


TransactionDescriptionList = List[TransactionDescription]


class ListTransactionsResponse(TypedDict, total=False):
    Transactions: Optional[TransactionDescriptionList]
    NextToken: Optional[TokenString]


class PutDataLakeSettingsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DataLakeSettings: DataLakeSettings


class PutDataLakeSettingsResponse(TypedDict, total=False):
    pass


QueryParameterMap = Dict[String, String]


class QueryPlanningContext(TypedDict, total=False):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: QueryPlanningContextDatabaseNameString
    QueryAsOfTime: Optional[Timestamp]
    QueryParameters: Optional[QueryParameterMap]
    TransactionId: Optional[TransactionIdString]


class RegisterResourceRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    UseServiceLinkedRole: Optional[NullableBoolean]
    RoleArn: Optional[IAMRoleArn]


class RegisterResourceResponse(TypedDict, total=False):
    pass


class RemoveLFTagsFromResourceRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Resource: Resource
    LFTags: LFTagsList


class RemoveLFTagsFromResourceResponse(TypedDict, total=False):
    Failures: Optional[LFTagErrors]


class RevokePermissionsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    Principal: DataLakePrincipal
    Resource: Resource
    Permissions: PermissionList
    PermissionsWithGrantOption: Optional[PermissionList]


class RevokePermissionsResponse(TypedDict, total=False):
    pass


class SearchDatabasesByLFTagsRequest(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]
    CatalogId: Optional[CatalogIdString]
    Expression: Expression


class SearchDatabasesByLFTagsResponse(TypedDict, total=False):
    NextToken: Optional[Token]
    DatabaseList: Optional[DatabaseLFTagsList]


class SearchTablesByLFTagsRequest(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[PageSize]
    CatalogId: Optional[CatalogIdString]
    Expression: Expression


class TaggedTable(TypedDict, total=False):
    Table: Optional[TableResource]
    LFTagOnDatabase: Optional[LFTagsList]
    LFTagsOnTable: Optional[LFTagsList]
    LFTagsOnColumns: Optional[ColumnLFTagsList]


TableLFTagsList = List[TaggedTable]


class SearchTablesByLFTagsResponse(TypedDict, total=False):
    NextToken: Optional[Token]
    TableList: Optional[TableLFTagsList]


class StartQueryPlanningRequest(ServiceRequest):
    QueryPlanningContext: QueryPlanningContext
    QueryString: SyntheticStartQueryPlanningRequestQueryString


class StartQueryPlanningResponse(TypedDict, total=False):
    QueryId: QueryIdString


class StartTransactionRequest(ServiceRequest):
    TransactionType: Optional[TransactionType]


class StartTransactionResponse(TypedDict, total=False):
    TransactionId: Optional[TransactionIdString]


StorageOptimizerConfigMap = Dict[OptimizerType, StorageOptimizerConfig]


class UpdateLFTagRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    TagKey: LFTagKey
    TagValuesToDelete: Optional[TagValueList]
    TagValuesToAdd: Optional[TagValueList]


class UpdateLFTagResponse(TypedDict, total=False):
    pass


class UpdateResourceRequest(ServiceRequest):
    RoleArn: IAMRoleArn
    ResourceArn: ResourceArnString


class UpdateResourceResponse(TypedDict, total=False):
    pass


class WriteOperation(TypedDict, total=False):
    AddObject: Optional[AddObjectInput]
    DeleteObject: Optional[DeleteObjectInput]


WriteOperationList = List[WriteOperation]


class UpdateTableObjectsRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    TransactionId: Optional[TransactionIdString]
    WriteOperations: WriteOperationList


class UpdateTableObjectsResponse(TypedDict, total=False):
    pass


class UpdateTableStorageOptimizerRequest(ServiceRequest):
    CatalogId: Optional[CatalogIdString]
    DatabaseName: NameString
    TableName: NameString
    StorageOptimizerConfig: StorageOptimizerConfigMap


class UpdateTableStorageOptimizerResponse(TypedDict, total=False):
    Result: Optional[Result]


class LakeformationApi:

    service = "lakeformation"
    version = "2017-03-31"

    @handler("AddLFTagsToResource")
    def add_lf_tags_to_resource(
        self,
        context: RequestContext,
        resource: Resource,
        lf_tags: LFTagsList,
        catalog_id: CatalogIdString = None,
    ) -> AddLFTagsToResourceResponse:
        raise NotImplementedError

    @handler("BatchGrantPermissions")
    def batch_grant_permissions(
        self,
        context: RequestContext,
        entries: BatchPermissionsRequestEntryList,
        catalog_id: CatalogIdString = None,
    ) -> BatchGrantPermissionsResponse:
        raise NotImplementedError

    @handler("BatchRevokePermissions")
    def batch_revoke_permissions(
        self,
        context: RequestContext,
        entries: BatchPermissionsRequestEntryList,
        catalog_id: CatalogIdString = None,
    ) -> BatchRevokePermissionsResponse:
        raise NotImplementedError

    @handler("CancelTransaction")
    def cancel_transaction(
        self, context: RequestContext, transaction_id: TransactionIdString
    ) -> CancelTransactionResponse:
        raise NotImplementedError

    @handler("CommitTransaction")
    def commit_transaction(
        self, context: RequestContext, transaction_id: TransactionIdString
    ) -> CommitTransactionResponse:
        raise NotImplementedError

    @handler("CreateDataCellsFilter")
    def create_data_cells_filter(
        self, context: RequestContext, table_data: DataCellsFilter
    ) -> CreateDataCellsFilterResponse:
        raise NotImplementedError

    @handler("CreateLFTag")
    def create_lf_tag(
        self,
        context: RequestContext,
        tag_key: LFTagKey,
        tag_values: TagValueList,
        catalog_id: CatalogIdString = None,
    ) -> CreateLFTagResponse:
        raise NotImplementedError

    @handler("DeleteDataCellsFilter")
    def delete_data_cells_filter(
        self,
        context: RequestContext,
        table_catalog_id: CatalogIdString = None,
        database_name: NameString = None,
        table_name: NameString = None,
        name: NameString = None,
    ) -> DeleteDataCellsFilterResponse:
        raise NotImplementedError

    @handler("DeleteLFTag")
    def delete_lf_tag(
        self, context: RequestContext, tag_key: LFTagKey, catalog_id: CatalogIdString = None
    ) -> DeleteLFTagResponse:
        raise NotImplementedError

    @handler("DeleteObjectsOnCancel")
    def delete_objects_on_cancel(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        transaction_id: TransactionIdString,
        objects: VirtualObjectList,
        catalog_id: CatalogIdString = None,
    ) -> DeleteObjectsOnCancelResponse:
        raise NotImplementedError

    @handler("DeregisterResource")
    def deregister_resource(
        self, context: RequestContext, resource_arn: ResourceArnString
    ) -> DeregisterResourceResponse:
        raise NotImplementedError

    @handler("DescribeResource")
    def describe_resource(
        self, context: RequestContext, resource_arn: ResourceArnString
    ) -> DescribeResourceResponse:
        raise NotImplementedError

    @handler("DescribeTransaction")
    def describe_transaction(
        self, context: RequestContext, transaction_id: TransactionIdString
    ) -> DescribeTransactionResponse:
        raise NotImplementedError

    @handler("ExtendTransaction")
    def extend_transaction(
        self, context: RequestContext, transaction_id: TransactionIdString = None
    ) -> ExtendTransactionResponse:
        raise NotImplementedError

    @handler("GetDataLakeSettings")
    def get_data_lake_settings(
        self, context: RequestContext, catalog_id: CatalogIdString = None
    ) -> GetDataLakeSettingsResponse:
        raise NotImplementedError

    @handler("GetEffectivePermissionsForPath")
    def get_effective_permissions_for_path(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        catalog_id: CatalogIdString = None,
        next_token: Token = None,
        max_results: PageSize = None,
    ) -> GetEffectivePermissionsForPathResponse:
        raise NotImplementedError

    @handler("GetLFTag")
    def get_lf_tag(
        self, context: RequestContext, tag_key: LFTagKey, catalog_id: CatalogIdString = None
    ) -> GetLFTagResponse:
        raise NotImplementedError

    @handler("GetQueryState")
    def get_query_state(
        self, context: RequestContext, query_id: GetQueryStateRequestQueryIdString
    ) -> GetQueryStateResponse:
        raise NotImplementedError

    @handler("GetQueryStatistics")
    def get_query_statistics(
        self, context: RequestContext, query_id: GetQueryStatisticsRequestQueryIdString
    ) -> GetQueryStatisticsResponse:
        raise NotImplementedError

    @handler("GetResourceLFTags")
    def get_resource_lf_tags(
        self,
        context: RequestContext,
        resource: Resource,
        catalog_id: CatalogIdString = None,
        show_assigned_lf_tags: BooleanNullable = None,
    ) -> GetResourceLFTagsResponse:
        raise NotImplementedError

    @handler("GetTableObjects")
    def get_table_objects(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        transaction_id: TransactionIdString = None,
        query_as_of_time: Timestamp = None,
        partition_predicate: PredicateString = None,
        max_results: PageSize = None,
        next_token: TokenString = None,
    ) -> GetTableObjectsResponse:
        raise NotImplementedError

    @handler("GetTemporaryGluePartitionCredentials")
    def get_temporary_glue_partition_credentials(
        self,
        context: RequestContext,
        table_arn: ResourceArnString,
        partition: PartitionValueList,
        supported_permission_types: PermissionTypeList,
        permissions: PermissionList = None,
        duration_seconds: CredentialTimeoutDurationSecondInteger = None,
        audit_context: AuditContext = None,
    ) -> GetTemporaryGluePartitionCredentialsResponse:
        raise NotImplementedError

    @handler("GetTemporaryGlueTableCredentials")
    def get_temporary_glue_table_credentials(
        self,
        context: RequestContext,
        table_arn: ResourceArnString,
        supported_permission_types: PermissionTypeList,
        permissions: PermissionList = None,
        duration_seconds: CredentialTimeoutDurationSecondInteger = None,
        audit_context: AuditContext = None,
    ) -> GetTemporaryGlueTableCredentialsResponse:
        raise NotImplementedError

    @handler("GetWorkUnitResults")
    def get_work_unit_results(
        self,
        context: RequestContext,
        query_id: GetWorkUnitResultsRequestQueryIdString,
        work_unit_id: GetWorkUnitResultsRequestWorkUnitIdLong,
        work_unit_token: SyntheticGetWorkUnitResultsRequestWorkUnitTokenString,
    ) -> GetWorkUnitResultsResponse:
        raise NotImplementedError

    @handler("GetWorkUnits")
    def get_work_units(
        self,
        context: RequestContext,
        query_id: GetWorkUnitsRequestQueryIdString,
        next_token: Token = None,
        page_size: Integer = None,
    ) -> GetWorkUnitsResponse:
        raise NotImplementedError

    @handler("GrantPermissions")
    def grant_permissions(
        self,
        context: RequestContext,
        principal: DataLakePrincipal,
        resource: Resource,
        permissions: PermissionList,
        catalog_id: CatalogIdString = None,
        permissions_with_grant_option: PermissionList = None,
    ) -> GrantPermissionsResponse:
        raise NotImplementedError

    @handler("ListDataCellsFilter")
    def list_data_cells_filter(
        self,
        context: RequestContext,
        table: TableResource = None,
        next_token: Token = None,
        max_results: PageSize = None,
    ) -> ListDataCellsFilterResponse:
        raise NotImplementedError

    @handler("ListLFTags")
    def list_lf_tags(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        resource_share_type: ResourceShareType = None,
        max_results: PageSize = None,
        next_token: Token = None,
    ) -> ListLFTagsResponse:
        raise NotImplementedError

    @handler("ListPermissions")
    def list_permissions(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        principal: DataLakePrincipal = None,
        resource_type: DataLakeResourceType = None,
        resource: Resource = None,
        next_token: Token = None,
        max_results: PageSize = None,
        include_related: TrueFalseString = None,
    ) -> ListPermissionsResponse:
        raise NotImplementedError

    @handler("ListResources")
    def list_resources(
        self,
        context: RequestContext,
        filter_condition_list: FilterConditionList = None,
        max_results: PageSize = None,
        next_token: Token = None,
    ) -> ListResourcesResponse:
        raise NotImplementedError

    @handler("ListTableStorageOptimizers")
    def list_table_storage_optimizers(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        catalog_id: CatalogIdString = None,
        storage_optimizer_type: OptimizerType = None,
        max_results: PageSize = None,
        next_token: Token = None,
    ) -> ListTableStorageOptimizersResponse:
        raise NotImplementedError

    @handler("ListTransactions")
    def list_transactions(
        self,
        context: RequestContext,
        catalog_id: CatalogIdString = None,
        status_filter: TransactionStatusFilter = None,
        max_results: PageSize = None,
        next_token: TokenString = None,
    ) -> ListTransactionsResponse:
        raise NotImplementedError

    @handler("PutDataLakeSettings")
    def put_data_lake_settings(
        self,
        context: RequestContext,
        data_lake_settings: DataLakeSettings,
        catalog_id: CatalogIdString = None,
    ) -> PutDataLakeSettingsResponse:
        raise NotImplementedError

    @handler("RegisterResource")
    def register_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        use_service_linked_role: NullableBoolean = None,
        role_arn: IAMRoleArn = None,
    ) -> RegisterResourceResponse:
        raise NotImplementedError

    @handler("RemoveLFTagsFromResource")
    def remove_lf_tags_from_resource(
        self,
        context: RequestContext,
        resource: Resource,
        lf_tags: LFTagsList,
        catalog_id: CatalogIdString = None,
    ) -> RemoveLFTagsFromResourceResponse:
        raise NotImplementedError

    @handler("RevokePermissions")
    def revoke_permissions(
        self,
        context: RequestContext,
        principal: DataLakePrincipal,
        resource: Resource,
        permissions: PermissionList,
        catalog_id: CatalogIdString = None,
        permissions_with_grant_option: PermissionList = None,
    ) -> RevokePermissionsResponse:
        raise NotImplementedError

    @handler("SearchDatabasesByLFTags")
    def search_databases_by_lf_tags(
        self,
        context: RequestContext,
        expression: Expression,
        next_token: Token = None,
        max_results: PageSize = None,
        catalog_id: CatalogIdString = None,
    ) -> SearchDatabasesByLFTagsResponse:
        raise NotImplementedError

    @handler("SearchTablesByLFTags")
    def search_tables_by_lf_tags(
        self,
        context: RequestContext,
        expression: Expression,
        next_token: Token = None,
        max_results: PageSize = None,
        catalog_id: CatalogIdString = None,
    ) -> SearchTablesByLFTagsResponse:
        raise NotImplementedError

    @handler("StartQueryPlanning")
    def start_query_planning(
        self,
        context: RequestContext,
        query_planning_context: QueryPlanningContext,
        query_string: SyntheticStartQueryPlanningRequestQueryString,
    ) -> StartQueryPlanningResponse:
        raise NotImplementedError

    @handler("StartTransaction")
    def start_transaction(
        self, context: RequestContext, transaction_type: TransactionType = None
    ) -> StartTransactionResponse:
        raise NotImplementedError

    @handler("UpdateLFTag")
    def update_lf_tag(
        self,
        context: RequestContext,
        tag_key: LFTagKey,
        catalog_id: CatalogIdString = None,
        tag_values_to_delete: TagValueList = None,
        tag_values_to_add: TagValueList = None,
    ) -> UpdateLFTagResponse:
        raise NotImplementedError

    @handler("UpdateResource")
    def update_resource(
        self, context: RequestContext, role_arn: IAMRoleArn, resource_arn: ResourceArnString
    ) -> UpdateResourceResponse:
        raise NotImplementedError

    @handler("UpdateTableObjects")
    def update_table_objects(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        write_operations: WriteOperationList,
        catalog_id: CatalogIdString = None,
        transaction_id: TransactionIdString = None,
    ) -> UpdateTableObjectsResponse:
        raise NotImplementedError

    @handler("UpdateTableStorageOptimizer")
    def update_table_storage_optimizer(
        self,
        context: RequestContext,
        database_name: NameString,
        table_name: NameString,
        storage_optimizer_config: StorageOptimizerConfigMap,
        catalog_id: CatalogIdString = None,
    ) -> UpdateTableStorageOptimizerResponse:
        raise NotImplementedError
