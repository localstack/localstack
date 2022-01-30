import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
Boolean = bool
BoxedBoolean = bool
CatalogNameString = str
CommentString = str
DatabaseString = str
DescriptionString = str
ErrorCategory = int
ErrorCode = str
ErrorMessage = str
ErrorType = int
ExpressionString = str
IdempotencyToken = str
Integer = int
KeyString = str
MaxDataCatalogsCount = int
MaxDatabasesCount = int
MaxEngineVersionsCount = int
MaxNamedQueriesCount = int
MaxPreparedStatementsCount = int
MaxQueryExecutionsCount = int
MaxQueryResults = int
MaxTableMetadataCount = int
MaxTagsCount = int
MaxWorkGroupsCount = int
NameString = str
NamedQueryDescriptionString = str
NamedQueryId = str
ParametersMapValue = str
QueryExecutionId = str
QueryString = str
StatementName = str
String = str
TableTypeString = str
TagKey = str
TagValue = str
Token = str
TypeString = str
WorkGroupDescriptionString = str
WorkGroupName = str
datumString = str


class ColumnNullable(str):
    NOT_NULL = "NOT_NULL"
    NULLABLE = "NULLABLE"
    UNKNOWN = "UNKNOWN"


class DataCatalogType(str):
    LAMBDA = "LAMBDA"
    GLUE = "GLUE"
    HIVE = "HIVE"


class EncryptionOption(str):
    SSE_S3 = "SSE_S3"
    SSE_KMS = "SSE_KMS"
    CSE_KMS = "CSE_KMS"


class QueryExecutionState(str):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class S3AclOption(str):
    BUCKET_OWNER_FULL_CONTROL = "BUCKET_OWNER_FULL_CONTROL"


class StatementType(str):
    DDL = "DDL"
    DML = "DML"
    UTILITY = "UTILITY"


class ThrottleReason(str):
    CONCURRENT_QUERY_LIMIT_EXCEEDED = "CONCURRENT_QUERY_LIMIT_EXCEEDED"


class WorkGroupState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class InternalServerException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidRequestException(ServiceException):
    AthenaErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class MetadataException(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceName: Optional[AmazonResourceName]


class TooManyRequestsException(ServiceException):
    Message: Optional[ErrorMessage]
    Reason: Optional[ThrottleReason]


class AclConfiguration(TypedDict, total=False):
    S3AclOption: S3AclOption


class AthenaError(TypedDict, total=False):
    ErrorCategory: Optional[ErrorCategory]
    ErrorType: Optional[ErrorType]


NamedQueryIdList = List[NamedQueryId]


class BatchGetNamedQueryInput(ServiceRequest):
    NamedQueryIds: NamedQueryIdList


class UnprocessedNamedQueryId(TypedDict, total=False):
    NamedQueryId: Optional[NamedQueryId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


UnprocessedNamedQueryIdList = List[UnprocessedNamedQueryId]


class NamedQuery(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    Database: DatabaseString
    QueryString: QueryString
    NamedQueryId: Optional[NamedQueryId]
    WorkGroup: Optional[WorkGroupName]


NamedQueryList = List[NamedQuery]


class BatchGetNamedQueryOutput(TypedDict, total=False):
    NamedQueries: Optional[NamedQueryList]
    UnprocessedNamedQueryIds: Optional[UnprocessedNamedQueryIdList]


QueryExecutionIdList = List[QueryExecutionId]


class BatchGetQueryExecutionInput(ServiceRequest):
    QueryExecutionIds: QueryExecutionIdList


class UnprocessedQueryExecutionId(TypedDict, total=False):
    QueryExecutionId: Optional[QueryExecutionId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


UnprocessedQueryExecutionIdList = List[UnprocessedQueryExecutionId]


class EngineVersion(TypedDict, total=False):
    SelectedEngineVersion: Optional[NameString]
    EffectiveEngineVersion: Optional[NameString]


Long = int


class QueryExecutionStatistics(TypedDict, total=False):
    EngineExecutionTimeInMillis: Optional[Long]
    DataScannedInBytes: Optional[Long]
    DataManifestLocation: Optional[String]
    TotalExecutionTimeInMillis: Optional[Long]
    QueryQueueTimeInMillis: Optional[Long]
    QueryPlanningTimeInMillis: Optional[Long]
    ServiceProcessingTimeInMillis: Optional[Long]


Date = datetime


class QueryExecutionStatus(TypedDict, total=False):
    State: Optional[QueryExecutionState]
    StateChangeReason: Optional[String]
    SubmissionDateTime: Optional[Date]
    CompletionDateTime: Optional[Date]
    AthenaError: Optional[AthenaError]


class QueryExecutionContext(TypedDict, total=False):
    Database: Optional[DatabaseString]
    Catalog: Optional[CatalogNameString]


class EncryptionConfiguration(TypedDict, total=False):
    EncryptionOption: EncryptionOption
    KmsKey: Optional[String]


class ResultConfiguration(TypedDict, total=False):
    OutputLocation: Optional[String]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    ExpectedBucketOwner: Optional[String]
    AclConfiguration: Optional[AclConfiguration]


class QueryExecution(TypedDict, total=False):
    QueryExecutionId: Optional[QueryExecutionId]
    Query: Optional[QueryString]
    StatementType: Optional[StatementType]
    ResultConfiguration: Optional[ResultConfiguration]
    QueryExecutionContext: Optional[QueryExecutionContext]
    Status: Optional[QueryExecutionStatus]
    Statistics: Optional[QueryExecutionStatistics]
    WorkGroup: Optional[WorkGroupName]
    EngineVersion: Optional[EngineVersion]


QueryExecutionList = List[QueryExecution]


class BatchGetQueryExecutionOutput(TypedDict, total=False):
    QueryExecutions: Optional[QueryExecutionList]
    UnprocessedQueryExecutionIds: Optional[UnprocessedQueryExecutionIdList]


BytesScannedCutoffValue = int


class Column(TypedDict, total=False):
    Name: NameString
    Type: Optional[TypeString]
    Comment: Optional[CommentString]


class ColumnInfo(TypedDict, total=False):
    CatalogName: Optional[String]
    SchemaName: Optional[String]
    TableName: Optional[String]
    Name: String
    Label: Optional[String]
    Type: String
    Precision: Optional[Integer]
    Scale: Optional[Integer]
    Nullable: Optional[ColumnNullable]
    CaseSensitive: Optional[Boolean]


ColumnInfoList = List[ColumnInfo]
ColumnList = List[Column]


class Tag(TypedDict, total=False):
    Key: Optional[TagKey]
    Value: Optional[TagValue]


TagList = List[Tag]
ParametersMap = Dict[KeyString, ParametersMapValue]


class CreateDataCatalogInput(ServiceRequest):
    Name: CatalogNameString
    Type: DataCatalogType
    Description: Optional[DescriptionString]
    Parameters: Optional[ParametersMap]
    Tags: Optional[TagList]


class CreateDataCatalogOutput(TypedDict, total=False):
    pass


class CreateNamedQueryInput(ServiceRequest):
    Name: NameString
    Description: Optional[DescriptionString]
    Database: DatabaseString
    QueryString: QueryString
    ClientRequestToken: Optional[IdempotencyToken]
    WorkGroup: Optional[WorkGroupName]


class CreateNamedQueryOutput(TypedDict, total=False):
    NamedQueryId: Optional[NamedQueryId]


class CreatePreparedStatementInput(ServiceRequest):
    StatementName: StatementName
    WorkGroup: WorkGroupName
    QueryStatement: QueryString
    Description: Optional[DescriptionString]


class CreatePreparedStatementOutput(TypedDict, total=False):
    pass


class WorkGroupConfiguration(TypedDict, total=False):
    ResultConfiguration: Optional[ResultConfiguration]
    EnforceWorkGroupConfiguration: Optional[BoxedBoolean]
    PublishCloudWatchMetricsEnabled: Optional[BoxedBoolean]
    BytesScannedCutoffPerQuery: Optional[BytesScannedCutoffValue]
    RequesterPaysEnabled: Optional[BoxedBoolean]
    EngineVersion: Optional[EngineVersion]


class CreateWorkGroupInput(ServiceRequest):
    Name: WorkGroupName
    Configuration: Optional[WorkGroupConfiguration]
    Description: Optional[WorkGroupDescriptionString]
    Tags: Optional[TagList]


class CreateWorkGroupOutput(TypedDict, total=False):
    pass


class DataCatalog(TypedDict, total=False):
    Name: CatalogNameString
    Description: Optional[DescriptionString]
    Type: DataCatalogType
    Parameters: Optional[ParametersMap]


class DataCatalogSummary(TypedDict, total=False):
    CatalogName: Optional[CatalogNameString]
    Type: Optional[DataCatalogType]


DataCatalogSummaryList = List[DataCatalogSummary]


class Database(TypedDict, total=False):
    Name: NameString
    Description: Optional[DescriptionString]
    Parameters: Optional[ParametersMap]


DatabaseList = List[Database]


class Datum(TypedDict, total=False):
    VarCharValue: Optional[datumString]


class DeleteDataCatalogInput(ServiceRequest):
    Name: CatalogNameString


class DeleteDataCatalogOutput(TypedDict, total=False):
    pass


class DeleteNamedQueryInput(ServiceRequest):
    NamedQueryId: NamedQueryId


class DeleteNamedQueryOutput(TypedDict, total=False):
    pass


class DeletePreparedStatementInput(ServiceRequest):
    StatementName: StatementName
    WorkGroup: WorkGroupName


class DeletePreparedStatementOutput(TypedDict, total=False):
    pass


class DeleteWorkGroupInput(ServiceRequest):
    WorkGroup: WorkGroupName
    RecursiveDeleteOption: Optional[BoxedBoolean]


class DeleteWorkGroupOutput(TypedDict, total=False):
    pass


EngineVersionsList = List[EngineVersion]


class GetDataCatalogInput(ServiceRequest):
    Name: CatalogNameString


class GetDataCatalogOutput(TypedDict, total=False):
    DataCatalog: Optional[DataCatalog]


class GetDatabaseInput(ServiceRequest):
    CatalogName: CatalogNameString
    DatabaseName: NameString


class GetDatabaseOutput(TypedDict, total=False):
    Database: Optional[Database]


class GetNamedQueryInput(ServiceRequest):
    NamedQueryId: NamedQueryId


class GetNamedQueryOutput(TypedDict, total=False):
    NamedQuery: Optional[NamedQuery]


class GetPreparedStatementInput(ServiceRequest):
    StatementName: StatementName
    WorkGroup: WorkGroupName


class PreparedStatement(TypedDict, total=False):
    StatementName: Optional[StatementName]
    QueryStatement: Optional[QueryString]
    WorkGroupName: Optional[WorkGroupName]
    Description: Optional[DescriptionString]
    LastModifiedTime: Optional[Date]


class GetPreparedStatementOutput(TypedDict, total=False):
    PreparedStatement: Optional[PreparedStatement]


class GetQueryExecutionInput(ServiceRequest):
    QueryExecutionId: QueryExecutionId


class GetQueryExecutionOutput(TypedDict, total=False):
    QueryExecution: Optional[QueryExecution]


class GetQueryResultsInput(ServiceRequest):
    QueryExecutionId: QueryExecutionId
    NextToken: Optional[Token]
    MaxResults: Optional[MaxQueryResults]


class ResultSetMetadata(TypedDict, total=False):
    ColumnInfo: Optional[ColumnInfoList]


datumList = List[Datum]


class Row(TypedDict, total=False):
    Data: Optional[datumList]


RowList = List[Row]


class ResultSet(TypedDict, total=False):
    Rows: Optional[RowList]
    ResultSetMetadata: Optional[ResultSetMetadata]


class GetQueryResultsOutput(TypedDict, total=False):
    UpdateCount: Optional[Long]
    ResultSet: Optional[ResultSet]
    NextToken: Optional[Token]


class GetTableMetadataInput(ServiceRequest):
    CatalogName: CatalogNameString
    DatabaseName: NameString
    TableName: NameString


Timestamp = datetime


class TableMetadata(TypedDict, total=False):
    Name: NameString
    CreateTime: Optional[Timestamp]
    LastAccessTime: Optional[Timestamp]
    TableType: Optional[TableTypeString]
    Columns: Optional[ColumnList]
    PartitionKeys: Optional[ColumnList]
    Parameters: Optional[ParametersMap]


class GetTableMetadataOutput(TypedDict, total=False):
    TableMetadata: Optional[TableMetadata]


class GetWorkGroupInput(ServiceRequest):
    WorkGroup: WorkGroupName


class WorkGroup(TypedDict, total=False):
    Name: WorkGroupName
    State: Optional[WorkGroupState]
    Configuration: Optional[WorkGroupConfiguration]
    Description: Optional[WorkGroupDescriptionString]
    CreationTime: Optional[Date]


class GetWorkGroupOutput(TypedDict, total=False):
    WorkGroup: Optional[WorkGroup]


class ListDataCatalogsInput(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxDataCatalogsCount]


class ListDataCatalogsOutput(TypedDict, total=False):
    DataCatalogsSummary: Optional[DataCatalogSummaryList]
    NextToken: Optional[Token]


class ListDatabasesInput(ServiceRequest):
    CatalogName: CatalogNameString
    NextToken: Optional[Token]
    MaxResults: Optional[MaxDatabasesCount]


class ListDatabasesOutput(TypedDict, total=False):
    DatabaseList: Optional[DatabaseList]
    NextToken: Optional[Token]


class ListEngineVersionsInput(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxEngineVersionsCount]


class ListEngineVersionsOutput(TypedDict, total=False):
    EngineVersions: Optional[EngineVersionsList]
    NextToken: Optional[Token]


class ListNamedQueriesInput(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxNamedQueriesCount]
    WorkGroup: Optional[WorkGroupName]


class ListNamedQueriesOutput(TypedDict, total=False):
    NamedQueryIds: Optional[NamedQueryIdList]
    NextToken: Optional[Token]


class ListPreparedStatementsInput(ServiceRequest):
    WorkGroup: WorkGroupName
    NextToken: Optional[Token]
    MaxResults: Optional[MaxPreparedStatementsCount]


class PreparedStatementSummary(TypedDict, total=False):
    StatementName: Optional[StatementName]
    LastModifiedTime: Optional[Date]


PreparedStatementsList = List[PreparedStatementSummary]


class ListPreparedStatementsOutput(TypedDict, total=False):
    PreparedStatements: Optional[PreparedStatementsList]
    NextToken: Optional[Token]


class ListQueryExecutionsInput(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxQueryExecutionsCount]
    WorkGroup: Optional[WorkGroupName]


class ListQueryExecutionsOutput(TypedDict, total=False):
    QueryExecutionIds: Optional[QueryExecutionIdList]
    NextToken: Optional[Token]


class ListTableMetadataInput(ServiceRequest):
    CatalogName: CatalogNameString
    DatabaseName: NameString
    Expression: Optional[ExpressionString]
    NextToken: Optional[Token]
    MaxResults: Optional[MaxTableMetadataCount]


TableMetadataList = List[TableMetadata]


class ListTableMetadataOutput(TypedDict, total=False):
    TableMetadataList: Optional[TableMetadataList]
    NextToken: Optional[Token]


class ListTagsForResourceInput(ServiceRequest):
    ResourceARN: AmazonResourceName
    NextToken: Optional[Token]
    MaxResults: Optional[MaxTagsCount]


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[Token]


class ListWorkGroupsInput(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxWorkGroupsCount]


class WorkGroupSummary(TypedDict, total=False):
    Name: Optional[WorkGroupName]
    State: Optional[WorkGroupState]
    Description: Optional[WorkGroupDescriptionString]
    CreationTime: Optional[Date]
    EngineVersion: Optional[EngineVersion]


WorkGroupsList = List[WorkGroupSummary]


class ListWorkGroupsOutput(TypedDict, total=False):
    WorkGroups: Optional[WorkGroupsList]
    NextToken: Optional[Token]


class ResultConfigurationUpdates(TypedDict, total=False):
    OutputLocation: Optional[String]
    RemoveOutputLocation: Optional[BoxedBoolean]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    RemoveEncryptionConfiguration: Optional[BoxedBoolean]
    ExpectedBucketOwner: Optional[String]
    RemoveExpectedBucketOwner: Optional[BoxedBoolean]
    AclConfiguration: Optional[AclConfiguration]
    RemoveAclConfiguration: Optional[BoxedBoolean]


class StartQueryExecutionInput(ServiceRequest):
    QueryString: QueryString
    ClientRequestToken: Optional[IdempotencyToken]
    QueryExecutionContext: Optional[QueryExecutionContext]
    ResultConfiguration: Optional[ResultConfiguration]
    WorkGroup: Optional[WorkGroupName]


class StartQueryExecutionOutput(TypedDict, total=False):
    QueryExecutionId: Optional[QueryExecutionId]


class StopQueryExecutionInput(ServiceRequest):
    QueryExecutionId: QueryExecutionId


class StopQueryExecutionOutput(TypedDict, total=False):
    pass


TagKeyList = List[TagKey]


class TagResourceInput(ServiceRequest):
    ResourceARN: AmazonResourceName
    Tags: TagList


class TagResourceOutput(TypedDict, total=False):
    pass


class UntagResourceInput(ServiceRequest):
    ResourceARN: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class UpdateDataCatalogInput(ServiceRequest):
    Name: CatalogNameString
    Type: DataCatalogType
    Description: Optional[DescriptionString]
    Parameters: Optional[ParametersMap]


class UpdateDataCatalogOutput(TypedDict, total=False):
    pass


class UpdateNamedQueryInput(ServiceRequest):
    NamedQueryId: NamedQueryId
    Name: NameString
    Description: Optional[NamedQueryDescriptionString]
    QueryString: QueryString


class UpdateNamedQueryOutput(TypedDict, total=False):
    pass


class UpdatePreparedStatementInput(ServiceRequest):
    StatementName: StatementName
    WorkGroup: WorkGroupName
    QueryStatement: QueryString
    Description: Optional[DescriptionString]


class UpdatePreparedStatementOutput(TypedDict, total=False):
    pass


class WorkGroupConfigurationUpdates(TypedDict, total=False):
    EnforceWorkGroupConfiguration: Optional[BoxedBoolean]
    ResultConfigurationUpdates: Optional[ResultConfigurationUpdates]
    PublishCloudWatchMetricsEnabled: Optional[BoxedBoolean]
    BytesScannedCutoffPerQuery: Optional[BytesScannedCutoffValue]
    RemoveBytesScannedCutoffPerQuery: Optional[BoxedBoolean]
    RequesterPaysEnabled: Optional[BoxedBoolean]
    EngineVersion: Optional[EngineVersion]


class UpdateWorkGroupInput(ServiceRequest):
    WorkGroup: WorkGroupName
    Description: Optional[WorkGroupDescriptionString]
    ConfigurationUpdates: Optional[WorkGroupConfigurationUpdates]
    State: Optional[WorkGroupState]


class UpdateWorkGroupOutput(TypedDict, total=False):
    pass


class AthenaApi:

    service = "athena"
    version = "2017-05-18"

    @handler("BatchGetNamedQuery")
    def batch_get_named_query(
        self, context: RequestContext, named_query_ids: NamedQueryIdList
    ) -> BatchGetNamedQueryOutput:
        raise NotImplementedError

    @handler("BatchGetQueryExecution")
    def batch_get_query_execution(
        self, context: RequestContext, query_execution_ids: QueryExecutionIdList
    ) -> BatchGetQueryExecutionOutput:
        raise NotImplementedError

    @handler("CreateDataCatalog", expand=False)
    def create_data_catalog(
        self, context: RequestContext, request: CreateDataCatalogInput
    ) -> CreateDataCatalogOutput:
        raise NotImplementedError

    @handler("CreateNamedQuery")
    def create_named_query(
        self,
        context: RequestContext,
        name: NameString,
        database: DatabaseString,
        query_string: QueryString,
        description: DescriptionString = None,
        client_request_token: IdempotencyToken = None,
        work_group: WorkGroupName = None,
    ) -> CreateNamedQueryOutput:
        raise NotImplementedError

    @handler("CreatePreparedStatement")
    def create_prepared_statement(
        self,
        context: RequestContext,
        statement_name: StatementName,
        work_group: WorkGroupName,
        query_statement: QueryString,
        description: DescriptionString = None,
    ) -> CreatePreparedStatementOutput:
        raise NotImplementedError

    @handler("CreateWorkGroup")
    def create_work_group(
        self,
        context: RequestContext,
        name: WorkGroupName,
        configuration: WorkGroupConfiguration = None,
        description: WorkGroupDescriptionString = None,
        tags: TagList = None,
    ) -> CreateWorkGroupOutput:
        raise NotImplementedError

    @handler("DeleteDataCatalog")
    def delete_data_catalog(
        self, context: RequestContext, name: CatalogNameString
    ) -> DeleteDataCatalogOutput:
        raise NotImplementedError

    @handler("DeleteNamedQuery")
    def delete_named_query(
        self, context: RequestContext, named_query_id: NamedQueryId
    ) -> DeleteNamedQueryOutput:
        raise NotImplementedError

    @handler("DeletePreparedStatement")
    def delete_prepared_statement(
        self, context: RequestContext, statement_name: StatementName, work_group: WorkGroupName
    ) -> DeletePreparedStatementOutput:
        raise NotImplementedError

    @handler("DeleteWorkGroup")
    def delete_work_group(
        self,
        context: RequestContext,
        work_group: WorkGroupName,
        recursive_delete_option: BoxedBoolean = None,
    ) -> DeleteWorkGroupOutput:
        raise NotImplementedError

    @handler("GetDataCatalog")
    def get_data_catalog(
        self, context: RequestContext, name: CatalogNameString
    ) -> GetDataCatalogOutput:
        raise NotImplementedError

    @handler("GetDatabase")
    def get_database(
        self, context: RequestContext, catalog_name: CatalogNameString, database_name: NameString
    ) -> GetDatabaseOutput:
        raise NotImplementedError

    @handler("GetNamedQuery")
    def get_named_query(
        self, context: RequestContext, named_query_id: NamedQueryId
    ) -> GetNamedQueryOutput:
        raise NotImplementedError

    @handler("GetPreparedStatement")
    def get_prepared_statement(
        self, context: RequestContext, statement_name: StatementName, work_group: WorkGroupName
    ) -> GetPreparedStatementOutput:
        raise NotImplementedError

    @handler("GetQueryExecution")
    def get_query_execution(
        self, context: RequestContext, query_execution_id: QueryExecutionId
    ) -> GetQueryExecutionOutput:
        raise NotImplementedError

    @handler("GetQueryResults")
    def get_query_results(
        self,
        context: RequestContext,
        query_execution_id: QueryExecutionId,
        next_token: Token = None,
        max_results: MaxQueryResults = None,
    ) -> GetQueryResultsOutput:
        raise NotImplementedError

    @handler("GetTableMetadata")
    def get_table_metadata(
        self,
        context: RequestContext,
        catalog_name: CatalogNameString,
        database_name: NameString,
        table_name: NameString,
    ) -> GetTableMetadataOutput:
        raise NotImplementedError

    @handler("GetWorkGroup")
    def get_work_group(
        self, context: RequestContext, work_group: WorkGroupName
    ) -> GetWorkGroupOutput:
        raise NotImplementedError

    @handler("ListDataCatalogs")
    def list_data_catalogs(
        self,
        context: RequestContext,
        next_token: Token = None,
        max_results: MaxDataCatalogsCount = None,
    ) -> ListDataCatalogsOutput:
        raise NotImplementedError

    @handler("ListDatabases")
    def list_databases(
        self,
        context: RequestContext,
        catalog_name: CatalogNameString,
        next_token: Token = None,
        max_results: MaxDatabasesCount = None,
    ) -> ListDatabasesOutput:
        raise NotImplementedError

    @handler("ListEngineVersions")
    def list_engine_versions(
        self,
        context: RequestContext,
        next_token: Token = None,
        max_results: MaxEngineVersionsCount = None,
    ) -> ListEngineVersionsOutput:
        raise NotImplementedError

    @handler("ListNamedQueries")
    def list_named_queries(
        self,
        context: RequestContext,
        next_token: Token = None,
        max_results: MaxNamedQueriesCount = None,
        work_group: WorkGroupName = None,
    ) -> ListNamedQueriesOutput:
        raise NotImplementedError

    @handler("ListPreparedStatements")
    def list_prepared_statements(
        self,
        context: RequestContext,
        work_group: WorkGroupName,
        next_token: Token = None,
        max_results: MaxPreparedStatementsCount = None,
    ) -> ListPreparedStatementsOutput:
        raise NotImplementedError

    @handler("ListQueryExecutions")
    def list_query_executions(
        self,
        context: RequestContext,
        next_token: Token = None,
        max_results: MaxQueryExecutionsCount = None,
        work_group: WorkGroupName = None,
    ) -> ListQueryExecutionsOutput:
        raise NotImplementedError

    @handler("ListTableMetadata")
    def list_table_metadata(
        self,
        context: RequestContext,
        catalog_name: CatalogNameString,
        database_name: NameString,
        expression: ExpressionString = None,
        next_token: Token = None,
        max_results: MaxTableMetadataCount = None,
    ) -> ListTableMetadataOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        next_token: Token = None,
        max_results: MaxTagsCount = None,
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("ListWorkGroups")
    def list_work_groups(
        self,
        context: RequestContext,
        next_token: Token = None,
        max_results: MaxWorkGroupsCount = None,
    ) -> ListWorkGroupsOutput:
        raise NotImplementedError

    @handler("StartQueryExecution")
    def start_query_execution(
        self,
        context: RequestContext,
        query_string: QueryString,
        client_request_token: IdempotencyToken = None,
        query_execution_context: QueryExecutionContext = None,
        result_configuration: ResultConfiguration = None,
        work_group: WorkGroupName = None,
    ) -> StartQueryExecutionOutput:
        raise NotImplementedError

    @handler("StopQueryExecution")
    def stop_query_execution(
        self, context: RequestContext, query_execution_id: QueryExecutionId
    ) -> StopQueryExecutionOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        raise NotImplementedError

    @handler("UpdateDataCatalog", expand=False)
    def update_data_catalog(
        self, context: RequestContext, request: UpdateDataCatalogInput
    ) -> UpdateDataCatalogOutput:
        raise NotImplementedError

    @handler("UpdateNamedQuery")
    def update_named_query(
        self,
        context: RequestContext,
        named_query_id: NamedQueryId,
        name: NameString,
        query_string: QueryString,
        description: NamedQueryDescriptionString = None,
    ) -> UpdateNamedQueryOutput:
        raise NotImplementedError

    @handler("UpdatePreparedStatement")
    def update_prepared_statement(
        self,
        context: RequestContext,
        statement_name: StatementName,
        work_group: WorkGroupName,
        query_statement: QueryString,
        description: DescriptionString = None,
    ) -> UpdatePreparedStatementOutput:
        raise NotImplementedError

    @handler("UpdateWorkGroup")
    def update_work_group(
        self,
        context: RequestContext,
        work_group: WorkGroupName,
        description: WorkGroupDescriptionString = None,
        configuration_updates: WorkGroupConfigurationUpdates = None,
        state: WorkGroupState = None,
    ) -> UpdateWorkGroupOutput:
        raise NotImplementedError
