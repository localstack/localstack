import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
ClientRequestToken = str
ClientToken = str
Double = float
ErrorMessage = str
MaxQueryResults = int
MaxScheduledQueriesResults = int
MaxTagsForResourceResult = int
NextScheduledQueriesResultsToken = str
NextTagsForResourceResultsToken = str
NullableBoolean = bool
PaginationToken = str
QueryId = str
QueryString = str
ResourceName = str
S3BucketName = str
S3ObjectKey = str
S3ObjectKeyPrefix = str
ScalarValue = str
ScheduleExpression = str
ScheduledQueryName = str
SchemaName = str
ServiceErrorMessage = str
String = str
StringValue2048 = str
TagKey = str
TagValue = str
Timestamp = str


class DimensionValueType(str):
    VARCHAR = "VARCHAR"


class MeasureValueType(str):
    BIGINT = "BIGINT"
    BOOLEAN = "BOOLEAN"
    DOUBLE = "DOUBLE"
    VARCHAR = "VARCHAR"
    MULTI = "MULTI"


class S3EncryptionOption(str):
    SSE_S3 = "SSE_S3"
    SSE_KMS = "SSE_KMS"


class ScalarMeasureValueType(str):
    BIGINT = "BIGINT"
    BOOLEAN = "BOOLEAN"
    DOUBLE = "DOUBLE"
    VARCHAR = "VARCHAR"


class ScalarType(str):
    VARCHAR = "VARCHAR"
    BOOLEAN = "BOOLEAN"
    BIGINT = "BIGINT"
    DOUBLE = "DOUBLE"
    TIMESTAMP = "TIMESTAMP"
    DATE = "DATE"
    TIME = "TIME"
    INTERVAL_DAY_TO_SECOND = "INTERVAL_DAY_TO_SECOND"
    INTERVAL_YEAR_TO_MONTH = "INTERVAL_YEAR_TO_MONTH"
    UNKNOWN = "UNKNOWN"
    INTEGER = "INTEGER"


class ScheduledQueryRunStatus(str):
    AUTO_TRIGGER_SUCCESS = "AUTO_TRIGGER_SUCCESS"
    AUTO_TRIGGER_FAILURE = "AUTO_TRIGGER_FAILURE"
    MANUAL_TRIGGER_SUCCESS = "MANUAL_TRIGGER_SUCCESS"
    MANUAL_TRIGGER_FAILURE = "MANUAL_TRIGGER_FAILURE"


class ScheduledQueryState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class AccessDeniedException(ServiceException):
    Message: Optional[ServiceErrorMessage]


class ConflictException(ServiceException):
    Message: Optional[ErrorMessage]


class InternalServerException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidEndpointException(ServiceException):
    Message: Optional[ErrorMessage]


class QueryExecutionException(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]
    ScheduledQueryArn: Optional[AmazonResourceName]


class ServiceQuotaExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class ThrottlingException(ServiceException):
    Message: Optional[ErrorMessage]


class ValidationException(ServiceException):
    Message: Optional[ErrorMessage]


class CancelQueryRequest(ServiceRequest):
    QueryId: QueryId


class CancelQueryResponse(TypedDict, total=False):
    CancellationMessage: Optional[String]


class ColumnInfo(TypedDict, total=False):
    Name: Optional["String"]
    Type: "Type"


ColumnInfoList = List[ColumnInfo]


class Type(TypedDict, total=False):
    ScalarType: Optional[ScalarType]
    ArrayColumnInfo: Optional[ColumnInfo]
    TimeSeriesMeasureValueColumnInfo: Optional[ColumnInfo]
    RowColumnInfo: Optional[ColumnInfoList]


class S3Configuration(TypedDict, total=False):
    BucketName: S3BucketName
    ObjectKeyPrefix: Optional[S3ObjectKeyPrefix]
    EncryptionOption: Optional[S3EncryptionOption]


class ErrorReportConfiguration(TypedDict, total=False):
    S3Configuration: S3Configuration


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class MultiMeasureAttributeMapping(TypedDict, total=False):
    SourceColumn: SchemaName
    TargetMultiMeasureAttributeName: Optional[SchemaName]
    MeasureValueType: ScalarMeasureValueType


MultiMeasureAttributeMappingList = List[MultiMeasureAttributeMapping]


class MixedMeasureMapping(TypedDict, total=False):
    MeasureName: Optional[SchemaName]
    SourceColumn: Optional[SchemaName]
    TargetMeasureName: Optional[SchemaName]
    MeasureValueType: MeasureValueType
    MultiMeasureAttributeMappings: Optional[MultiMeasureAttributeMappingList]


MixedMeasureMappingList = List[MixedMeasureMapping]


class MultiMeasureMappings(TypedDict, total=False):
    TargetMultiMeasureName: Optional[SchemaName]
    MultiMeasureAttributeMappings: MultiMeasureAttributeMappingList


class DimensionMapping(TypedDict, total=False):
    Name: SchemaName
    DimensionValueType: DimensionValueType


DimensionMappingList = List[DimensionMapping]


class TimestreamConfiguration(TypedDict, total=False):
    DatabaseName: ResourceName
    TableName: ResourceName
    TimeColumn: SchemaName
    DimensionMappings: DimensionMappingList
    MultiMeasureMappings: Optional[MultiMeasureMappings]
    MixedMeasureMappings: Optional[MixedMeasureMappingList]
    MeasureNameColumn: Optional[SchemaName]


class TargetConfiguration(TypedDict, total=False):
    TimestreamConfiguration: TimestreamConfiguration


class SnsConfiguration(TypedDict, total=False):
    TopicArn: AmazonResourceName


class NotificationConfiguration(TypedDict, total=False):
    SnsConfiguration: SnsConfiguration


class ScheduleConfiguration(TypedDict, total=False):
    ScheduleExpression: ScheduleExpression


class CreateScheduledQueryRequest(ServiceRequest):
    Name: ScheduledQueryName
    QueryString: QueryString
    ScheduleConfiguration: ScheduleConfiguration
    NotificationConfiguration: NotificationConfiguration
    TargetConfiguration: Optional[TargetConfiguration]
    ClientToken: Optional[ClientToken]
    ScheduledQueryExecutionRoleArn: AmazonResourceName
    Tags: Optional[TagList]
    KmsKeyId: Optional[StringValue2048]
    ErrorReportConfiguration: ErrorReportConfiguration


class CreateScheduledQueryResponse(TypedDict, total=False):
    Arn: AmazonResourceName


class Datum(TypedDict, total=False):
    ScalarValue: Optional["ScalarValue"]
    TimeSeriesValue: Optional["TimeSeriesDataPointList"]
    ArrayValue: Optional["DatumList"]
    RowValue: Optional["Row"]
    NullValue: Optional["NullableBoolean"]


DatumList = List[Datum]


class Row(TypedDict, total=False):
    Data: DatumList


class TimeSeriesDataPoint(TypedDict, total=False):
    Time: Timestamp
    Value: Datum


TimeSeriesDataPointList = List[TimeSeriesDataPoint]


class DeleteScheduledQueryRequest(ServiceRequest):
    ScheduledQueryArn: AmazonResourceName


class DescribeEndpointsRequest(ServiceRequest):
    pass


Long = int


class Endpoint(TypedDict, total=False):
    Address: String
    CachePeriodInMinutes: Long


Endpoints = List[Endpoint]


class DescribeEndpointsResponse(TypedDict, total=False):
    Endpoints: Endpoints


class DescribeScheduledQueryRequest(ServiceRequest):
    ScheduledQueryArn: AmazonResourceName


class S3ReportLocation(TypedDict, total=False):
    BucketName: Optional[S3BucketName]
    ObjectKey: Optional[S3ObjectKey]


class ErrorReportLocation(TypedDict, total=False):
    S3ReportLocation: Optional[S3ReportLocation]


class ExecutionStats(TypedDict, total=False):
    ExecutionTimeInMillis: Optional[Long]
    DataWrites: Optional[Long]
    BytesMetered: Optional[Long]
    RecordsIngested: Optional[Long]
    QueryResultRows: Optional[Long]


Time = datetime


class ScheduledQueryRunSummary(TypedDict, total=False):
    InvocationTime: Optional[Time]
    TriggerTime: Optional[Time]
    RunStatus: Optional[ScheduledQueryRunStatus]
    ExecutionStats: Optional[ExecutionStats]
    ErrorReportLocation: Optional[ErrorReportLocation]
    FailureReason: Optional[ErrorMessage]


ScheduledQueryRunSummaryList = List[ScheduledQueryRunSummary]


class ScheduledQueryDescription(TypedDict, total=False):
    Arn: AmazonResourceName
    Name: ScheduledQueryName
    QueryString: QueryString
    CreationTime: Optional[Time]
    State: ScheduledQueryState
    PreviousInvocationTime: Optional[Time]
    NextInvocationTime: Optional[Time]
    ScheduleConfiguration: ScheduleConfiguration
    NotificationConfiguration: NotificationConfiguration
    TargetConfiguration: Optional[TargetConfiguration]
    ScheduledQueryExecutionRoleArn: Optional[AmazonResourceName]
    KmsKeyId: Optional[StringValue2048]
    ErrorReportConfiguration: Optional[ErrorReportConfiguration]
    LastRunSummary: Optional[ScheduledQueryRunSummary]
    RecentlyFailedRuns: Optional[ScheduledQueryRunSummaryList]


class DescribeScheduledQueryResponse(TypedDict, total=False):
    ScheduledQuery: ScheduledQueryDescription


class ExecuteScheduledQueryRequest(ServiceRequest):
    ScheduledQueryArn: AmazonResourceName
    InvocationTime: Time
    ClientToken: Optional[ClientToken]


class ListScheduledQueriesRequest(ServiceRequest):
    MaxResults: Optional[MaxScheduledQueriesResults]
    NextToken: Optional[NextScheduledQueriesResultsToken]


class TimestreamDestination(TypedDict, total=False):
    DatabaseName: Optional[ResourceName]
    TableName: Optional[ResourceName]


class TargetDestination(TypedDict, total=False):
    TimestreamDestination: Optional[TimestreamDestination]


class ScheduledQuery(TypedDict, total=False):
    Arn: AmazonResourceName
    Name: ScheduledQueryName
    CreationTime: Optional[Time]
    State: ScheduledQueryState
    PreviousInvocationTime: Optional[Time]
    NextInvocationTime: Optional[Time]
    ErrorReportConfiguration: Optional[ErrorReportConfiguration]
    TargetDestination: Optional[TargetDestination]
    LastRunStatus: Optional[ScheduledQueryRunStatus]


ScheduledQueryList = List[ScheduledQuery]


class ListScheduledQueriesResponse(TypedDict, total=False):
    ScheduledQueries: ScheduledQueryList
    NextToken: Optional[NextScheduledQueriesResultsToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    MaxResults: Optional[MaxTagsForResourceResult]
    NextToken: Optional[NextTagsForResourceResultsToken]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList
    NextToken: Optional[NextTagsForResourceResultsToken]


class ParameterMapping(TypedDict, total=False):
    Name: String
    Type: Type


ParameterMappingList = List[ParameterMapping]


class PrepareQueryRequest(ServiceRequest):
    QueryString: QueryString
    ValidateOnly: Optional[NullableBoolean]


class SelectColumn(TypedDict, total=False):
    Name: Optional[String]
    Type: Optional[Type]
    DatabaseName: Optional[ResourceName]
    TableName: Optional[ResourceName]
    Aliased: Optional[NullableBoolean]


SelectColumnList = List[SelectColumn]


class PrepareQueryResponse(TypedDict, total=False):
    QueryString: QueryString
    Columns: SelectColumnList
    Parameters: ParameterMappingList


class QueryRequest(ServiceRequest):
    QueryString: QueryString
    ClientToken: Optional[ClientRequestToken]
    NextToken: Optional[PaginationToken]
    MaxRows: Optional[MaxQueryResults]


class QueryStatus(TypedDict, total=False):
    ProgressPercentage: Optional[Double]
    CumulativeBytesScanned: Optional[Long]
    CumulativeBytesMetered: Optional[Long]


RowList = List[Row]


class QueryResponse(TypedDict, total=False):
    QueryId: QueryId
    NextToken: Optional[PaginationToken]
    Rows: RowList
    ColumnInfo: ColumnInfoList
    QueryStatus: Optional[QueryStatus]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateScheduledQueryRequest(ServiceRequest):
    ScheduledQueryArn: AmazonResourceName
    State: ScheduledQueryState


class TimestreamQueryApi:

    service = "timestream-query"
    version = "2018-11-01"

    @handler("CancelQuery")
    def cancel_query(self, context: RequestContext, query_id: QueryId) -> CancelQueryResponse:
        raise NotImplementedError

    @handler("CreateScheduledQuery")
    def create_scheduled_query(
        self,
        context: RequestContext,
        name: ScheduledQueryName,
        query_string: QueryString,
        schedule_configuration: ScheduleConfiguration,
        notification_configuration: NotificationConfiguration,
        scheduled_query_execution_role_arn: AmazonResourceName,
        error_report_configuration: ErrorReportConfiguration,
        target_configuration: TargetConfiguration = None,
        client_token: ClientToken = None,
        tags: TagList = None,
        kms_key_id: StringValue2048 = None,
    ) -> CreateScheduledQueryResponse:
        raise NotImplementedError

    @handler("DeleteScheduledQuery")
    def delete_scheduled_query(
        self, context: RequestContext, scheduled_query_arn: AmazonResourceName
    ) -> None:
        raise NotImplementedError

    @handler("DescribeEndpoints")
    def describe_endpoints(
        self,
        context: RequestContext,
    ) -> DescribeEndpointsResponse:
        raise NotImplementedError

    @handler("DescribeScheduledQuery")
    def describe_scheduled_query(
        self, context: RequestContext, scheduled_query_arn: AmazonResourceName
    ) -> DescribeScheduledQueryResponse:
        raise NotImplementedError

    @handler("ExecuteScheduledQuery")
    def execute_scheduled_query(
        self,
        context: RequestContext,
        scheduled_query_arn: AmazonResourceName,
        invocation_time: Time,
        client_token: ClientToken = None,
    ) -> None:
        raise NotImplementedError

    @handler("ListScheduledQueries")
    def list_scheduled_queries(
        self,
        context: RequestContext,
        max_results: MaxScheduledQueriesResults = None,
        next_token: NextScheduledQueriesResultsToken = None,
    ) -> ListScheduledQueriesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        max_results: MaxTagsForResourceResult = None,
        next_token: NextTagsForResourceResultsToken = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PrepareQuery")
    def prepare_query(
        self,
        context: RequestContext,
        query_string: QueryString,
        validate_only: NullableBoolean = None,
    ) -> PrepareQueryResponse:
        raise NotImplementedError

    @handler("Query")
    def query(
        self,
        context: RequestContext,
        query_string: QueryString,
        client_token: ClientRequestToken = None,
        next_token: PaginationToken = None,
        max_rows: MaxQueryResults = None,
    ) -> QueryResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateScheduledQuery")
    def update_scheduled_query(
        self,
        context: RequestContext,
        scheduled_query_arn: AmazonResourceName,
        state: ScheduledQueryState,
    ) -> None:
        raise NotImplementedError
