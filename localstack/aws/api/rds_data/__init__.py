import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
Boolean = bool
BoxedBoolean = bool
BoxedDouble = float
BoxedFloat = float
BoxedInteger = int
DbName = str
ErrorMessage = str
Id = str
Integer = int
ParameterName = str
SqlStatement = str
String = str
TransactionStatus = str


class DecimalReturnType(str):
    STRING = "STRING"
    DOUBLE_OR_LONG = "DOUBLE_OR_LONG"


class TypeHint(str):
    JSON = "JSON"
    UUID = "UUID"
    TIMESTAMP = "TIMESTAMP"
    DATE = "DATE"
    TIME = "TIME"
    DECIMAL = "DECIMAL"


class BadRequestException(ServiceException):
    message: Optional[ErrorMessage]


class ForbiddenException(ServiceException):
    message: Optional[ErrorMessage]


class InternalServerErrorException(ServiceException):
    pass


class NotFoundException(ServiceException):
    message: Optional[ErrorMessage]


class ServiceUnavailableError(ServiceException):
    pass


Long = int


class StatementTimeoutException(ServiceException):
    dbConnectionId: Optional[Long]
    message: Optional[ErrorMessage]


StringArray = List[String]
BoxedLong = int
LongArray = List[BoxedLong]
DoubleArray = List[BoxedDouble]
BooleanArray = List[BoxedBoolean]
ArrayOfArray = List["ArrayValue"]


class ArrayValue(TypedDict, total=False):
    arrayValues: Optional[ArrayOfArray]
    booleanValues: Optional[BooleanArray]
    doubleValues: Optional[DoubleArray]
    longValues: Optional[LongArray]
    stringValues: Optional[StringArray]


ArrayValueList = List["Value"]


class StructValue(TypedDict, total=False):
    attributes: Optional[ArrayValueList]


Blob = bytes


class Value(TypedDict, total=False):
    arrayValues: Optional[ArrayValueList]
    bigIntValue: Optional[BoxedLong]
    bitValue: Optional[BoxedBoolean]
    blobValue: Optional[Blob]
    doubleValue: Optional[BoxedDouble]
    intValue: Optional[BoxedInteger]
    isNull: Optional[BoxedBoolean]
    realValue: Optional[BoxedFloat]
    stringValue: Optional[String]
    structValue: Optional[StructValue]


class Field(TypedDict, total=False):
    arrayValue: Optional[ArrayValue]
    blobValue: Optional[Blob]
    booleanValue: Optional[BoxedBoolean]
    doubleValue: Optional[BoxedDouble]
    isNull: Optional[BoxedBoolean]
    longValue: Optional[BoxedLong]
    stringValue: Optional[String]


class SqlParameter(TypedDict, total=False):
    name: Optional[ParameterName]
    typeHint: Optional[TypeHint]
    value: Optional[Field]


SqlParametersList = List[SqlParameter]
SqlParameterSets = List[SqlParametersList]


class BatchExecuteStatementRequest(ServiceRequest):
    database: Optional[DbName]
    parameterSets: Optional[SqlParameterSets]
    resourceArn: Arn
    schema: Optional[DbName]
    secretArn: Arn
    sql: SqlStatement
    transactionId: Optional[Id]


FieldList = List[Field]


class UpdateResult(TypedDict, total=False):
    generatedFields: Optional[FieldList]


UpdateResults = List[UpdateResult]


class BatchExecuteStatementResponse(TypedDict, total=False):
    updateResults: Optional[UpdateResults]


class BeginTransactionRequest(ServiceRequest):
    database: Optional[DbName]
    resourceArn: Arn
    schema: Optional[DbName]
    secretArn: Arn


class BeginTransactionResponse(TypedDict, total=False):
    transactionId: Optional[Id]


ColumnMetadata = TypedDict(
    "ColumnMetadata",
    {
        "arrayBaseColumnType": Optional[Integer],
        "isAutoIncrement": Optional[Boolean],
        "isCaseSensitive": Optional[Boolean],
        "isCurrency": Optional[Boolean],
        "isSigned": Optional[Boolean],
        "label": Optional[String],
        "name": Optional[String],
        "nullable": Optional[Integer],
        "precision": Optional[Integer],
        "scale": Optional[Integer],
        "schemaName": Optional[String],
        "tableName": Optional[String],
        "type": Optional[Integer],
        "typeName": Optional[String],
    },
    total=False,
)


class CommitTransactionRequest(ServiceRequest):
    resourceArn: Arn
    secretArn: Arn
    transactionId: Id


class CommitTransactionResponse(TypedDict, total=False):
    transactionStatus: Optional[TransactionStatus]


class ExecuteSqlRequest(ServiceRequest):
    awsSecretStoreArn: Arn
    database: Optional[DbName]
    dbClusterOrInstanceArn: Arn
    schema: Optional[DbName]
    sqlStatements: SqlStatement


Metadata = List[ColumnMetadata]


class ResultSetMetadata(TypedDict, total=False):
    columnCount: Optional[Long]
    columnMetadata: Optional[Metadata]


Row = List[Value]


class Record(TypedDict, total=False):
    values: Optional[Row]


Records = List[Record]


class ResultFrame(TypedDict, total=False):
    records: Optional[Records]
    resultSetMetadata: Optional[ResultSetMetadata]


RecordsUpdated = int


class SqlStatementResult(TypedDict, total=False):
    numberOfRecordsUpdated: Optional[RecordsUpdated]
    resultFrame: Optional[ResultFrame]


SqlStatementResults = List[SqlStatementResult]


class ExecuteSqlResponse(TypedDict, total=False):
    sqlStatementResults: Optional[SqlStatementResults]


class ResultSetOptions(TypedDict, total=False):
    decimalReturnType: Optional[DecimalReturnType]


class ExecuteStatementRequest(ServiceRequest):
    continueAfterTimeout: Optional[Boolean]
    database: Optional[DbName]
    includeResultMetadata: Optional[Boolean]
    parameters: Optional[SqlParametersList]
    resourceArn: Arn
    resultSetOptions: Optional[ResultSetOptions]
    schema: Optional[DbName]
    secretArn: Arn
    sql: SqlStatement
    transactionId: Optional[Id]


SqlRecords = List[FieldList]


class ExecuteStatementResponse(TypedDict, total=False):
    columnMetadata: Optional[Metadata]
    generatedFields: Optional[FieldList]
    numberOfRecordsUpdated: Optional[RecordsUpdated]
    records: Optional[SqlRecords]


class RollbackTransactionRequest(ServiceRequest):
    resourceArn: Arn
    secretArn: Arn
    transactionId: Id


class RollbackTransactionResponse(TypedDict, total=False):
    transactionStatus: Optional[TransactionStatus]


class RdsDataApi:

    service = "rds-data"
    version = "2018-08-01"

    @handler("BatchExecuteStatement")
    def batch_execute_statement(
        self,
        context: RequestContext,
        resource_arn: Arn,
        secret_arn: Arn,
        sql: SqlStatement,
        database: DbName = None,
        parameter_sets: SqlParameterSets = None,
        schema: DbName = None,
        transaction_id: Id = None,
    ) -> BatchExecuteStatementResponse:
        raise NotImplementedError

    @handler("BeginTransaction")
    def begin_transaction(
        self,
        context: RequestContext,
        resource_arn: Arn,
        secret_arn: Arn,
        database: DbName = None,
        schema: DbName = None,
    ) -> BeginTransactionResponse:
        raise NotImplementedError

    @handler("CommitTransaction")
    def commit_transaction(
        self, context: RequestContext, resource_arn: Arn, secret_arn: Arn, transaction_id: Id
    ) -> CommitTransactionResponse:
        raise NotImplementedError

    @handler("ExecuteSql")
    def execute_sql(
        self,
        context: RequestContext,
        aws_secret_store_arn: Arn,
        db_cluster_or_instance_arn: Arn,
        sql_statements: SqlStatement,
        database: DbName = None,
        schema: DbName = None,
    ) -> ExecuteSqlResponse:
        raise NotImplementedError

    @handler("ExecuteStatement")
    def execute_statement(
        self,
        context: RequestContext,
        resource_arn: Arn,
        secret_arn: Arn,
        sql: SqlStatement,
        continue_after_timeout: Boolean = None,
        database: DbName = None,
        include_result_metadata: Boolean = None,
        parameters: SqlParametersList = None,
        result_set_options: ResultSetOptions = None,
        schema: DbName = None,
        transaction_id: Id = None,
    ) -> ExecuteStatementResponse:
        raise NotImplementedError

    @handler("RollbackTransaction")
    def rollback_transaction(
        self, context: RequestContext, resource_arn: Arn, secret_arn: Arn, transaction_id: Id
    ) -> RollbackTransactionResponse:
        raise NotImplementedError
