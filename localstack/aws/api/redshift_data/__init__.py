import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BoxedBoolean = bool
BoxedDouble = float
Integer = int
ListStatementsLimit = int
Location = str
PageSize = int
ParameterName = str
ParameterValue = str
SecretArn = str
StatementId = str
StatementNameString = str
StatementString = str
String = str
bool = bool


class StatementStatusString(str):
    SUBMITTED = "SUBMITTED"
    PICKED = "PICKED"
    STARTED = "STARTED"
    FINISHED = "FINISHED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class StatusString(str):
    SUBMITTED = "SUBMITTED"
    PICKED = "PICKED"
    STARTED = "STARTED"
    FINISHED = "FINISHED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"
    ALL = "ALL"


class ActiveStatementsExceededException(ServiceException):
    Message: Optional[String]


class BatchExecuteStatementException(ServiceException):
    Message: String
    StatementId: String


class DatabaseConnectionException(ServiceException):
    Message: String


class ExecuteStatementException(ServiceException):
    Message: String
    StatementId: String


class InternalServerException(ServiceException):
    Message: String


class ResourceNotFoundException(ServiceException):
    Message: String
    ResourceId: String


class ValidationException(ServiceException):
    Message: Optional[String]


SqlList = List[StatementString]


class BatchExecuteStatementInput(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    Database: String
    DbUser: Optional[String]
    SecretArn: Optional[SecretArn]
    Sqls: SqlList
    StatementName: Optional[StatementNameString]
    WithEvent: Optional[Boolean]


Timestamp = datetime


class BatchExecuteStatementOutput(TypedDict, total=False):
    ClusterIdentifier: Optional[Location]
    CreatedAt: Optional[Timestamp]
    Database: Optional[String]
    DbUser: Optional[String]
    Id: Optional[StatementId]
    SecretArn: Optional[SecretArn]


Blob = bytes
BoxedLong = int


class CancelStatementRequest(ServiceRequest):
    Id: StatementId


class CancelStatementResponse(TypedDict, total=False):
    Status: Optional[Boolean]


class ColumnMetadata(TypedDict, total=False):
    columnDefault: Optional[String]
    isCaseSensitive: Optional[bool]
    isCurrency: Optional[bool]
    isSigned: Optional[bool]
    label: Optional[String]
    length: Optional[Integer]
    name: Optional[String]
    nullable: Optional[Integer]
    precision: Optional[Integer]
    scale: Optional[Integer]
    schemaName: Optional[String]
    tableName: Optional[String]
    typeName: Optional[String]


ColumnList = List[ColumnMetadata]
ColumnMetadataList = List[ColumnMetadata]
DatabaseList = List[String]


class DescribeStatementRequest(ServiceRequest):
    Id: StatementId


Long = int


class SubStatementData(TypedDict, total=False):
    CreatedAt: Optional[Timestamp]
    Duration: Optional[Long]
    Error: Optional[String]
    HasResultSet: Optional[Boolean]
    Id: StatementId
    QueryString: Optional[StatementString]
    RedshiftQueryId: Optional[Long]
    ResultRows: Optional[Long]
    ResultSize: Optional[Long]
    Status: Optional[StatementStatusString]
    UpdatedAt: Optional[Timestamp]


SubStatementList = List[SubStatementData]


class SqlParameter(TypedDict, total=False):
    name: ParameterName
    value: ParameterValue


SqlParametersList = List[SqlParameter]


class DescribeStatementResponse(TypedDict, total=False):
    ClusterIdentifier: Optional[String]
    CreatedAt: Optional[Timestamp]
    Database: Optional[String]
    DbUser: Optional[String]
    Duration: Optional[Long]
    Error: Optional[String]
    HasResultSet: Optional[Boolean]
    Id: StatementId
    QueryParameters: Optional[SqlParametersList]
    QueryString: Optional[StatementString]
    RedshiftPid: Optional[Long]
    RedshiftQueryId: Optional[Long]
    ResultRows: Optional[Long]
    ResultSize: Optional[Long]
    SecretArn: Optional[SecretArn]
    Status: Optional[StatusString]
    SubStatements: Optional[SubStatementList]
    UpdatedAt: Optional[Timestamp]


class DescribeTableRequest(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    ConnectedDatabase: Optional[String]
    Database: String
    DbUser: Optional[String]
    MaxResults: Optional[PageSize]
    NextToken: Optional[String]
    Schema: Optional[String]
    SecretArn: Optional[SecretArn]
    Table: Optional[String]


class DescribeTableResponse(TypedDict, total=False):
    ColumnList: Optional[ColumnList]
    NextToken: Optional[String]
    TableName: Optional[String]


class ExecuteStatementInput(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    Database: String
    DbUser: Optional[String]
    Parameters: Optional[SqlParametersList]
    SecretArn: Optional[SecretArn]
    Sql: StatementString
    StatementName: Optional[StatementNameString]
    WithEvent: Optional[Boolean]


class ExecuteStatementOutput(TypedDict, total=False):
    ClusterIdentifier: Optional[Location]
    CreatedAt: Optional[Timestamp]
    Database: Optional[String]
    DbUser: Optional[String]
    Id: Optional[StatementId]
    SecretArn: Optional[SecretArn]


class Field(TypedDict, total=False):
    blobValue: Optional[Blob]
    booleanValue: Optional[BoxedBoolean]
    doubleValue: Optional[BoxedDouble]
    isNull: Optional[BoxedBoolean]
    longValue: Optional[BoxedLong]
    stringValue: Optional[String]


FieldList = List[Field]


class GetStatementResultRequest(ServiceRequest):
    Id: StatementId
    NextToken: Optional[String]


SqlRecords = List[FieldList]


class GetStatementResultResponse(TypedDict, total=False):
    ColumnMetadata: Optional[ColumnMetadataList]
    NextToken: Optional[String]
    Records: SqlRecords
    TotalNumRows: Optional[Long]


class ListDatabasesRequest(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    Database: String
    DbUser: Optional[String]
    MaxResults: Optional[PageSize]
    NextToken: Optional[String]
    SecretArn: Optional[SecretArn]


class ListDatabasesResponse(TypedDict, total=False):
    Databases: Optional[DatabaseList]
    NextToken: Optional[String]


class ListSchemasRequest(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    ConnectedDatabase: Optional[String]
    Database: String
    DbUser: Optional[String]
    MaxResults: Optional[PageSize]
    NextToken: Optional[String]
    SchemaPattern: Optional[String]
    SecretArn: Optional[SecretArn]


SchemaList = List[String]


class ListSchemasResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Schemas: Optional[SchemaList]


class ListStatementsRequest(ServiceRequest):
    MaxResults: Optional[ListStatementsLimit]
    NextToken: Optional[String]
    RoleLevel: Optional[Boolean]
    StatementName: Optional[StatementNameString]
    Status: Optional[StatusString]


StatementStringList = List[StatementString]


class StatementData(TypedDict, total=False):
    CreatedAt: Optional[Timestamp]
    Id: StatementId
    IsBatchStatement: Optional[Boolean]
    QueryParameters: Optional[SqlParametersList]
    QueryString: Optional[StatementString]
    QueryStrings: Optional[StatementStringList]
    SecretArn: Optional[SecretArn]
    StatementName: Optional[StatementNameString]
    Status: Optional[StatusString]
    UpdatedAt: Optional[Timestamp]


StatementList = List[StatementData]


class ListStatementsResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Statements: StatementList


class ListTablesRequest(ServiceRequest):
    ClusterIdentifier: Optional[Location]
    ConnectedDatabase: Optional[String]
    Database: String
    DbUser: Optional[String]
    MaxResults: Optional[PageSize]
    NextToken: Optional[String]
    SchemaPattern: Optional[String]
    SecretArn: Optional[SecretArn]
    TablePattern: Optional[String]


TableMember = TypedDict(
    "TableMember",
    {
        "name": Optional[String],
        "schema": Optional[String],
        "type": Optional[String],
    },
    total=False,
)
TableList = List[TableMember]


class ListTablesResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Tables: Optional[TableList]


class RedshiftDataApi:

    service = "redshift-data"
    version = "2019-12-20"

    @handler("BatchExecuteStatement")
    def batch_execute_statement(
        self,
        context: RequestContext,
        database: String,
        sqls: SqlList,
        cluster_identifier: Location = None,
        db_user: String = None,
        secret_arn: SecretArn = None,
        statement_name: StatementNameString = None,
        with_event: Boolean = None,
    ) -> BatchExecuteStatementOutput:
        raise NotImplementedError

    @handler("CancelStatement")
    def cancel_statement(self, context: RequestContext, id: StatementId) -> CancelStatementResponse:
        raise NotImplementedError

    @handler("DescribeStatement")
    def describe_statement(
        self, context: RequestContext, id: StatementId
    ) -> DescribeStatementResponse:
        raise NotImplementedError

    @handler("DescribeTable")
    def describe_table(
        self,
        context: RequestContext,
        database: String,
        cluster_identifier: Location = None,
        connected_database: String = None,
        db_user: String = None,
        max_results: PageSize = None,
        next_token: String = None,
        schema: String = None,
        secret_arn: SecretArn = None,
        table: String = None,
    ) -> DescribeTableResponse:
        raise NotImplementedError

    @handler("ExecuteStatement")
    def execute_statement(
        self,
        context: RequestContext,
        database: String,
        sql: StatementString,
        cluster_identifier: Location = None,
        db_user: String = None,
        parameters: SqlParametersList = None,
        secret_arn: SecretArn = None,
        statement_name: StatementNameString = None,
        with_event: Boolean = None,
    ) -> ExecuteStatementOutput:
        raise NotImplementedError

    @handler("GetStatementResult")
    def get_statement_result(
        self, context: RequestContext, id: StatementId, next_token: String = None
    ) -> GetStatementResultResponse:
        raise NotImplementedError

    @handler("ListDatabases")
    def list_databases(
        self,
        context: RequestContext,
        database: String,
        cluster_identifier: Location = None,
        db_user: String = None,
        max_results: PageSize = None,
        next_token: String = None,
        secret_arn: SecretArn = None,
    ) -> ListDatabasesResponse:
        raise NotImplementedError

    @handler("ListSchemas")
    def list_schemas(
        self,
        context: RequestContext,
        database: String,
        cluster_identifier: Location = None,
        connected_database: String = None,
        db_user: String = None,
        max_results: PageSize = None,
        next_token: String = None,
        schema_pattern: String = None,
        secret_arn: SecretArn = None,
    ) -> ListSchemasResponse:
        raise NotImplementedError

    @handler("ListStatements")
    def list_statements(
        self,
        context: RequestContext,
        max_results: ListStatementsLimit = None,
        next_token: String = None,
        role_level: Boolean = None,
        statement_name: StatementNameString = None,
        status: StatusString = None,
    ) -> ListStatementsResponse:
        raise NotImplementedError

    @handler("ListTables")
    def list_tables(
        self,
        context: RequestContext,
        database: String,
        cluster_identifier: Location = None,
        connected_database: String = None,
        db_user: String = None,
        max_results: PageSize = None,
        next_token: String = None,
        schema_pattern: String = None,
        secret_arn: SecretArn = None,
        table_pattern: String = None,
    ) -> ListTablesResponse:
        raise NotImplementedError
