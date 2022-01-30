import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
AnnotationKey = str
AttributeKey = str
AttributeValue = str
Boolean = bool
BorrowCount = int
ClientID = str
Double = float
EC2InstanceId = str
EncryptionKeyId = str
EntitySelectorExpression = str
ErrorMessage = str
EventSummaryText = str
FilterExpression = str
FixedRate = float
GetGroupsNextToken = str
GetInsightEventsMaxResults = int
GetInsightSummariesMaxResults = int
GroupARN = str
GroupName = str
HTTPMethod = str
Host = str
Hostname = str
InsightId = str
InsightSummaryText = str
Integer = int
NullableBoolean = bool
NullableDouble = float
NullableInteger = int
Priority = int
RequestCount = int
ReservoirSize = int
ResourceARN = str
RuleName = str
SampledCount = int
SegmentDocument = str
SegmentId = str
ServiceName = str
ServiceType = str
String = str
TagKey = str
TagValue = str
Token = str
TraceId = str
TraceSegmentDocument = str
URLPath = str
Version = int


class EncryptionStatus(str):
    UPDATING = "UPDATING"
    ACTIVE = "ACTIVE"


class EncryptionType(str):
    NONE = "NONE"
    KMS = "KMS"


class InsightCategory(str):
    FAULT = "FAULT"


class InsightState(str):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


class SamplingStrategyName(str):
    PartialScan = "PartialScan"
    FixedRate = "FixedRate"


class TimeRangeType(str):
    TraceId = "TraceId"
    Event = "Event"


class InvalidRequestException(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceName: Optional[AmazonResourceName]


class RuleLimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class ThrottledException(ServiceException):
    Message: Optional[ErrorMessage]


class TooManyTagsException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceName: Optional[AmazonResourceName]


AliasNames = List[String]


class Alias(TypedDict, total=False):
    Name: Optional[String]
    Names: Optional[AliasNames]
    Type: Optional[String]


AliasList = List[Alias]


class AnnotationValue(TypedDict, total=False):
    NumberValue: Optional[NullableDouble]
    BooleanValue: Optional[NullableBoolean]
    StringValue: Optional[String]


ServiceNames = List[String]


class ServiceId(TypedDict, total=False):
    Name: Optional[String]
    Names: Optional[ServiceNames]
    AccountId: Optional[String]
    Type: Optional[String]


ServiceIds = List[ServiceId]


class ValueWithServiceIds(TypedDict, total=False):
    AnnotationValue: Optional[AnnotationValue]
    ServiceIds: Optional[ServiceIds]


ValuesWithServiceIds = List[ValueWithServiceIds]
Annotations = Dict[AnnotationKey, ValuesWithServiceIds]


class AnomalousService(TypedDict, total=False):
    ServiceId: Optional[ServiceId]


AnomalousServiceList = List[AnomalousService]
AttributeMap = Dict[AttributeKey, AttributeValue]


class AvailabilityZoneDetail(TypedDict, total=False):
    Name: Optional[String]


class BackendConnectionErrors(TypedDict, total=False):
    TimeoutCount: Optional[NullableInteger]
    ConnectionRefusedCount: Optional[NullableInteger]
    HTTPCode4XXCount: Optional[NullableInteger]
    HTTPCode5XXCount: Optional[NullableInteger]
    UnknownHostCount: Optional[NullableInteger]
    OtherCount: Optional[NullableInteger]


TraceIdList = List[TraceId]


class BatchGetTracesRequest(ServiceRequest):
    TraceIds: TraceIdList
    NextToken: Optional[String]


UnprocessedTraceIdList = List[TraceId]


class Segment(TypedDict, total=False):
    Id: Optional[SegmentId]
    Document: Optional[SegmentDocument]


SegmentList = List[Segment]


class Trace(TypedDict, total=False):
    Id: Optional[TraceId]
    Duration: Optional[NullableDouble]
    LimitExceeded: Optional[NullableBoolean]
    Segments: Optional[SegmentList]


TraceList = List[Trace]


class BatchGetTracesResult(TypedDict, total=False):
    Traces: Optional[TraceList]
    UnprocessedTraceIds: Optional[UnprocessedTraceIdList]
    NextToken: Optional[String]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class InsightsConfiguration(TypedDict, total=False):
    InsightsEnabled: Optional[NullableBoolean]
    NotificationsEnabled: Optional[NullableBoolean]


class CreateGroupRequest(ServiceRequest):
    GroupName: GroupName
    FilterExpression: Optional[FilterExpression]
    InsightsConfiguration: Optional[InsightsConfiguration]
    Tags: Optional[TagList]


class Group(TypedDict, total=False):
    GroupName: Optional[String]
    GroupARN: Optional[String]
    FilterExpression: Optional[String]
    InsightsConfiguration: Optional[InsightsConfiguration]


class CreateGroupResult(TypedDict, total=False):
    Group: Optional[Group]


class SamplingRule(TypedDict, total=False):
    RuleName: Optional[RuleName]
    RuleARN: Optional[String]
    ResourceARN: ResourceARN
    Priority: Priority
    FixedRate: FixedRate
    ReservoirSize: ReservoirSize
    ServiceName: ServiceName
    ServiceType: ServiceType
    Host: Host
    HTTPMethod: HTTPMethod
    URLPath: URLPath
    Version: Version
    Attributes: Optional[AttributeMap]


class CreateSamplingRuleRequest(ServiceRequest):
    SamplingRule: SamplingRule
    Tags: Optional[TagList]


Timestamp = datetime


class SamplingRuleRecord(TypedDict, total=False):
    SamplingRule: Optional[SamplingRule]
    CreatedAt: Optional[Timestamp]
    ModifiedAt: Optional[Timestamp]


class CreateSamplingRuleResult(TypedDict, total=False):
    SamplingRuleRecord: Optional[SamplingRuleRecord]


class DeleteGroupRequest(ServiceRequest):
    GroupName: Optional[GroupName]
    GroupARN: Optional[GroupARN]


class DeleteGroupResult(TypedDict, total=False):
    pass


class DeleteSamplingRuleRequest(ServiceRequest):
    RuleName: Optional[String]
    RuleARN: Optional[String]


class DeleteSamplingRuleResult(TypedDict, total=False):
    SamplingRuleRecord: Optional[SamplingRuleRecord]


class HistogramEntry(TypedDict, total=False):
    Value: Optional[Double]
    Count: Optional[Integer]


Histogram = List[HistogramEntry]
NullableLong = int


class FaultStatistics(TypedDict, total=False):
    OtherCount: Optional[NullableLong]
    TotalCount: Optional[NullableLong]


class ErrorStatistics(TypedDict, total=False):
    ThrottleCount: Optional[NullableLong]
    OtherCount: Optional[NullableLong]
    TotalCount: Optional[NullableLong]


class EdgeStatistics(TypedDict, total=False):
    OkCount: Optional[NullableLong]
    ErrorStatistics: Optional[ErrorStatistics]
    FaultStatistics: Optional[FaultStatistics]
    TotalCount: Optional[NullableLong]
    TotalResponseTime: Optional[NullableDouble]


class Edge(TypedDict, total=False):
    ReferenceId: Optional[NullableInteger]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    SummaryStatistics: Optional[EdgeStatistics]
    ResponseTimeHistogram: Optional[Histogram]
    Aliases: Optional[AliasList]


EdgeList = List[Edge]


class EncryptionConfig(TypedDict, total=False):
    KeyId: Optional[String]
    Status: Optional[EncryptionStatus]
    Type: Optional[EncryptionType]


class RootCauseException(TypedDict, total=False):
    Name: Optional[String]
    Message: Optional[String]


RootCauseExceptions = List[RootCauseException]


class ErrorRootCauseEntity(TypedDict, total=False):
    Name: Optional[String]
    Exceptions: Optional[RootCauseExceptions]
    Remote: Optional[NullableBoolean]


ErrorRootCauseEntityPath = List[ErrorRootCauseEntity]


class ErrorRootCauseService(TypedDict, total=False):
    Name: Optional[String]
    Names: Optional[ServiceNames]
    Type: Optional[String]
    AccountId: Optional[String]
    EntityPath: Optional[ErrorRootCauseEntityPath]
    Inferred: Optional[NullableBoolean]


ErrorRootCauseServices = List[ErrorRootCauseService]


class ErrorRootCause(TypedDict, total=False):
    Services: Optional[ErrorRootCauseServices]
    ClientImpacting: Optional[NullableBoolean]


ErrorRootCauses = List[ErrorRootCause]


class FaultRootCauseEntity(TypedDict, total=False):
    Name: Optional[String]
    Exceptions: Optional[RootCauseExceptions]
    Remote: Optional[NullableBoolean]


FaultRootCauseEntityPath = List[FaultRootCauseEntity]


class FaultRootCauseService(TypedDict, total=False):
    Name: Optional[String]
    Names: Optional[ServiceNames]
    Type: Optional[String]
    AccountId: Optional[String]
    EntityPath: Optional[FaultRootCauseEntityPath]
    Inferred: Optional[NullableBoolean]


FaultRootCauseServices = List[FaultRootCauseService]


class FaultRootCause(TypedDict, total=False):
    Services: Optional[FaultRootCauseServices]
    ClientImpacting: Optional[NullableBoolean]


FaultRootCauses = List[FaultRootCause]


class ForecastStatistics(TypedDict, total=False):
    FaultCountHigh: Optional[NullableLong]
    FaultCountLow: Optional[NullableLong]


class GetEncryptionConfigRequest(ServiceRequest):
    pass


class GetEncryptionConfigResult(TypedDict, total=False):
    EncryptionConfig: Optional[EncryptionConfig]


class GetGroupRequest(ServiceRequest):
    GroupName: Optional[GroupName]
    GroupARN: Optional[GroupARN]


class GetGroupResult(TypedDict, total=False):
    Group: Optional[Group]


class GetGroupsRequest(ServiceRequest):
    NextToken: Optional[GetGroupsNextToken]


class GroupSummary(TypedDict, total=False):
    GroupName: Optional[String]
    GroupARN: Optional[String]
    FilterExpression: Optional[String]
    InsightsConfiguration: Optional[InsightsConfiguration]


GroupSummaryList = List[GroupSummary]


class GetGroupsResult(TypedDict, total=False):
    Groups: Optional[GroupSummaryList]
    NextToken: Optional[String]


class GetInsightEventsRequest(ServiceRequest):
    InsightId: InsightId
    MaxResults: Optional[GetInsightEventsMaxResults]
    NextToken: Optional[Token]


class RequestImpactStatistics(TypedDict, total=False):
    FaultCount: Optional[NullableLong]
    OkCount: Optional[NullableLong]
    TotalCount: Optional[NullableLong]


class InsightEvent(TypedDict, total=False):
    Summary: Optional[EventSummaryText]
    EventTime: Optional[Timestamp]
    ClientRequestImpactStatistics: Optional[RequestImpactStatistics]
    RootCauseServiceRequestImpactStatistics: Optional[RequestImpactStatistics]
    TopAnomalousServices: Optional[AnomalousServiceList]


InsightEventList = List[InsightEvent]


class GetInsightEventsResult(TypedDict, total=False):
    InsightEvents: Optional[InsightEventList]
    NextToken: Optional[Token]


class GetInsightImpactGraphRequest(ServiceRequest):
    InsightId: InsightId
    StartTime: Timestamp
    EndTime: Timestamp
    NextToken: Optional[Token]


class InsightImpactGraphEdge(TypedDict, total=False):
    ReferenceId: Optional[NullableInteger]


InsightImpactGraphEdgeList = List[InsightImpactGraphEdge]


class InsightImpactGraphService(TypedDict, total=False):
    ReferenceId: Optional[NullableInteger]
    Type: Optional[String]
    Name: Optional[String]
    Names: Optional[ServiceNames]
    AccountId: Optional[String]
    Edges: Optional[InsightImpactGraphEdgeList]


InsightImpactGraphServiceList = List[InsightImpactGraphService]


class GetInsightImpactGraphResult(TypedDict, total=False):
    InsightId: Optional[InsightId]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    ServiceGraphStartTime: Optional[Timestamp]
    ServiceGraphEndTime: Optional[Timestamp]
    Services: Optional[InsightImpactGraphServiceList]
    NextToken: Optional[Token]


class GetInsightRequest(ServiceRequest):
    InsightId: InsightId


InsightCategoryList = List[InsightCategory]


class Insight(TypedDict, total=False):
    InsightId: Optional[InsightId]
    GroupARN: Optional[GroupARN]
    GroupName: Optional[GroupName]
    RootCauseServiceId: Optional[ServiceId]
    Categories: Optional[InsightCategoryList]
    State: Optional[InsightState]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Summary: Optional[InsightSummaryText]
    ClientRequestImpactStatistics: Optional[RequestImpactStatistics]
    RootCauseServiceRequestImpactStatistics: Optional[RequestImpactStatistics]
    TopAnomalousServices: Optional[AnomalousServiceList]


class GetInsightResult(TypedDict, total=False):
    Insight: Optional[Insight]


InsightStateList = List[InsightState]


class GetInsightSummariesRequest(ServiceRequest):
    States: Optional[InsightStateList]
    GroupARN: Optional[GroupARN]
    GroupName: Optional[GroupName]
    StartTime: Timestamp
    EndTime: Timestamp
    MaxResults: Optional[GetInsightSummariesMaxResults]
    NextToken: Optional[Token]


class InsightSummary(TypedDict, total=False):
    InsightId: Optional[InsightId]
    GroupARN: Optional[GroupARN]
    GroupName: Optional[GroupName]
    RootCauseServiceId: Optional[ServiceId]
    Categories: Optional[InsightCategoryList]
    State: Optional[InsightState]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Summary: Optional[InsightSummaryText]
    ClientRequestImpactStatistics: Optional[RequestImpactStatistics]
    RootCauseServiceRequestImpactStatistics: Optional[RequestImpactStatistics]
    TopAnomalousServices: Optional[AnomalousServiceList]
    LastUpdateTime: Optional[Timestamp]


InsightSummaryList = List[InsightSummary]


class GetInsightSummariesResult(TypedDict, total=False):
    InsightSummaries: Optional[InsightSummaryList]
    NextToken: Optional[Token]


class GetSamplingRulesRequest(ServiceRequest):
    NextToken: Optional[String]


SamplingRuleRecordList = List[SamplingRuleRecord]


class GetSamplingRulesResult(TypedDict, total=False):
    SamplingRuleRecords: Optional[SamplingRuleRecordList]
    NextToken: Optional[String]


class GetSamplingStatisticSummariesRequest(ServiceRequest):
    NextToken: Optional[String]


class SamplingStatisticSummary(TypedDict, total=False):
    RuleName: Optional[String]
    Timestamp: Optional[Timestamp]
    RequestCount: Optional[Integer]
    BorrowCount: Optional[Integer]
    SampledCount: Optional[Integer]


SamplingStatisticSummaryList = List[SamplingStatisticSummary]


class GetSamplingStatisticSummariesResult(TypedDict, total=False):
    SamplingStatisticSummaries: Optional[SamplingStatisticSummaryList]
    NextToken: Optional[String]


class SamplingStatisticsDocument(TypedDict, total=False):
    RuleName: RuleName
    ClientID: ClientID
    Timestamp: Timestamp
    RequestCount: RequestCount
    SampledCount: SampledCount
    BorrowCount: Optional[BorrowCount]


SamplingStatisticsDocumentList = List[SamplingStatisticsDocument]


class GetSamplingTargetsRequest(ServiceRequest):
    SamplingStatisticsDocuments: SamplingStatisticsDocumentList


class UnprocessedStatistics(TypedDict, total=False):
    RuleName: Optional[String]
    ErrorCode: Optional[String]
    Message: Optional[String]


UnprocessedStatisticsList = List[UnprocessedStatistics]


class SamplingTargetDocument(TypedDict, total=False):
    RuleName: Optional[String]
    FixedRate: Optional[Double]
    ReservoirQuota: Optional[NullableInteger]
    ReservoirQuotaTTL: Optional[Timestamp]
    Interval: Optional[NullableInteger]


SamplingTargetDocumentList = List[SamplingTargetDocument]


class GetSamplingTargetsResult(TypedDict, total=False):
    SamplingTargetDocuments: Optional[SamplingTargetDocumentList]
    LastRuleModification: Optional[Timestamp]
    UnprocessedStatistics: Optional[UnprocessedStatisticsList]


class GetServiceGraphRequest(ServiceRequest):
    StartTime: Timestamp
    EndTime: Timestamp
    GroupName: Optional[GroupName]
    GroupARN: Optional[GroupARN]
    NextToken: Optional[String]


class ServiceStatistics(TypedDict, total=False):
    OkCount: Optional[NullableLong]
    ErrorStatistics: Optional[ErrorStatistics]
    FaultStatistics: Optional[FaultStatistics]
    TotalCount: Optional[NullableLong]
    TotalResponseTime: Optional[NullableDouble]


class Service(TypedDict, total=False):
    ReferenceId: Optional[NullableInteger]
    Name: Optional[String]
    Names: Optional[ServiceNames]
    Root: Optional[NullableBoolean]
    AccountId: Optional[String]
    Type: Optional[String]
    State: Optional[String]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Edges: Optional[EdgeList]
    SummaryStatistics: Optional[ServiceStatistics]
    DurationHistogram: Optional[Histogram]
    ResponseTimeHistogram: Optional[Histogram]


ServiceList = List[Service]


class GetServiceGraphResult(TypedDict, total=False):
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Services: Optional[ServiceList]
    ContainsOldGroupVersions: Optional[Boolean]
    NextToken: Optional[String]


class GetTimeSeriesServiceStatisticsRequest(ServiceRequest):
    StartTime: Timestamp
    EndTime: Timestamp
    GroupName: Optional[GroupName]
    GroupARN: Optional[GroupARN]
    EntitySelectorExpression: Optional[EntitySelectorExpression]
    Period: Optional[NullableInteger]
    ForecastStatistics: Optional[NullableBoolean]
    NextToken: Optional[String]


class TimeSeriesServiceStatistics(TypedDict, total=False):
    Timestamp: Optional[Timestamp]
    EdgeSummaryStatistics: Optional[EdgeStatistics]
    ServiceSummaryStatistics: Optional[ServiceStatistics]
    ServiceForecastStatistics: Optional[ForecastStatistics]
    ResponseTimeHistogram: Optional[Histogram]


TimeSeriesServiceStatisticsList = List[TimeSeriesServiceStatistics]


class GetTimeSeriesServiceStatisticsResult(TypedDict, total=False):
    TimeSeriesServiceStatistics: Optional[TimeSeriesServiceStatisticsList]
    ContainsOldGroupVersions: Optional[Boolean]
    NextToken: Optional[String]


class GetTraceGraphRequest(ServiceRequest):
    TraceIds: TraceIdList
    NextToken: Optional[String]


class GetTraceGraphResult(TypedDict, total=False):
    Services: Optional[ServiceList]
    NextToken: Optional[String]


class SamplingStrategy(TypedDict, total=False):
    Name: Optional[SamplingStrategyName]
    Value: Optional[NullableDouble]


class GetTraceSummariesRequest(ServiceRequest):
    StartTime: Timestamp
    EndTime: Timestamp
    TimeRangeType: Optional[TimeRangeType]
    Sampling: Optional[NullableBoolean]
    SamplingStrategy: Optional[SamplingStrategy]
    FilterExpression: Optional[FilterExpression]
    NextToken: Optional[String]


class ResponseTimeRootCauseEntity(TypedDict, total=False):
    Name: Optional[String]
    Coverage: Optional[NullableDouble]
    Remote: Optional[NullableBoolean]


ResponseTimeRootCauseEntityPath = List[ResponseTimeRootCauseEntity]


class ResponseTimeRootCauseService(TypedDict, total=False):
    Name: Optional[String]
    Names: Optional[ServiceNames]
    Type: Optional[String]
    AccountId: Optional[String]
    EntityPath: Optional[ResponseTimeRootCauseEntityPath]
    Inferred: Optional[NullableBoolean]


ResponseTimeRootCauseServices = List[ResponseTimeRootCauseService]


class ResponseTimeRootCause(TypedDict, total=False):
    Services: Optional[ResponseTimeRootCauseServices]
    ClientImpacting: Optional[NullableBoolean]


ResponseTimeRootCauses = List[ResponseTimeRootCause]
TraceAvailabilityZones = List[AvailabilityZoneDetail]


class InstanceIdDetail(TypedDict, total=False):
    Id: Optional[String]


TraceInstanceIds = List[InstanceIdDetail]


class ResourceARNDetail(TypedDict, total=False):
    ARN: Optional[String]


TraceResourceARNs = List[ResourceARNDetail]


class TraceUser(TypedDict, total=False):
    UserName: Optional[String]
    ServiceIds: Optional[ServiceIds]


TraceUsers = List[TraceUser]


class Http(TypedDict, total=False):
    HttpURL: Optional[String]
    HttpStatus: Optional[NullableInteger]
    HttpMethod: Optional[String]
    UserAgent: Optional[String]
    ClientIp: Optional[String]


class TraceSummary(TypedDict, total=False):
    Id: Optional[TraceId]
    Duration: Optional[NullableDouble]
    ResponseTime: Optional[NullableDouble]
    HasFault: Optional[NullableBoolean]
    HasError: Optional[NullableBoolean]
    HasThrottle: Optional[NullableBoolean]
    IsPartial: Optional[NullableBoolean]
    Http: Optional[Http]
    Annotations: Optional[Annotations]
    Users: Optional[TraceUsers]
    ServiceIds: Optional[ServiceIds]
    ResourceARNs: Optional[TraceResourceARNs]
    InstanceIds: Optional[TraceInstanceIds]
    AvailabilityZones: Optional[TraceAvailabilityZones]
    EntryPoint: Optional[ServiceId]
    FaultRootCauses: Optional[FaultRootCauses]
    ErrorRootCauses: Optional[ErrorRootCauses]
    ResponseTimeRootCauses: Optional[ResponseTimeRootCauses]
    Revision: Optional[Integer]
    MatchedEventTime: Optional[Timestamp]


TraceSummaryList = List[TraceSummary]


class GetTraceSummariesResult(TypedDict, total=False):
    TraceSummaries: Optional[TraceSummaryList]
    ApproximateTime: Optional[Timestamp]
    TracesProcessedCount: Optional[NullableLong]
    NextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    NextToken: Optional[String]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[String]


class PutEncryptionConfigRequest(ServiceRequest):
    KeyId: Optional[EncryptionKeyId]
    Type: EncryptionType


class PutEncryptionConfigResult(TypedDict, total=False):
    EncryptionConfig: Optional[EncryptionConfig]


class TelemetryRecord(TypedDict, total=False):
    Timestamp: Timestamp
    SegmentsReceivedCount: Optional[NullableInteger]
    SegmentsSentCount: Optional[NullableInteger]
    SegmentsSpilloverCount: Optional[NullableInteger]
    SegmentsRejectedCount: Optional[NullableInteger]
    BackendConnectionErrors: Optional[BackendConnectionErrors]


TelemetryRecordList = List[TelemetryRecord]


class PutTelemetryRecordsRequest(ServiceRequest):
    TelemetryRecords: TelemetryRecordList
    EC2InstanceId: Optional[EC2InstanceId]
    Hostname: Optional[Hostname]
    ResourceARN: Optional[ResourceARN]


class PutTelemetryRecordsResult(TypedDict, total=False):
    pass


TraceSegmentDocumentList = List[TraceSegmentDocument]


class PutTraceSegmentsRequest(ServiceRequest):
    TraceSegmentDocuments: TraceSegmentDocumentList


class UnprocessedTraceSegment(TypedDict, total=False):
    Id: Optional[String]
    ErrorCode: Optional[String]
    Message: Optional[String]


UnprocessedTraceSegmentList = List[UnprocessedTraceSegment]


class PutTraceSegmentsResult(TypedDict, total=False):
    UnprocessedTraceSegments: Optional[UnprocessedTraceSegmentList]


class SamplingRuleUpdate(TypedDict, total=False):
    RuleName: Optional[RuleName]
    RuleARN: Optional[String]
    ResourceARN: Optional[ResourceARN]
    Priority: Optional[NullableInteger]
    FixedRate: Optional[NullableDouble]
    ReservoirSize: Optional[NullableInteger]
    Host: Optional[Host]
    ServiceName: Optional[ServiceName]
    ServiceType: Optional[ServiceType]
    HTTPMethod: Optional[HTTPMethod]
    URLPath: Optional[URLPath]
    Attributes: Optional[AttributeMap]


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


class UpdateGroupRequest(ServiceRequest):
    GroupName: Optional[GroupName]
    GroupARN: Optional[GroupARN]
    FilterExpression: Optional[FilterExpression]
    InsightsConfiguration: Optional[InsightsConfiguration]


class UpdateGroupResult(TypedDict, total=False):
    Group: Optional[Group]


class UpdateSamplingRuleRequest(ServiceRequest):
    SamplingRuleUpdate: SamplingRuleUpdate


class UpdateSamplingRuleResult(TypedDict, total=False):
    SamplingRuleRecord: Optional[SamplingRuleRecord]


class XrayApi:

    service = "xray"
    version = "2016-04-12"

    @handler("BatchGetTraces")
    def batch_get_traces(
        self, context: RequestContext, trace_ids: TraceIdList, next_token: String = None
    ) -> BatchGetTracesResult:
        raise NotImplementedError

    @handler("CreateGroup")
    def create_group(
        self,
        context: RequestContext,
        group_name: GroupName,
        filter_expression: FilterExpression = None,
        insights_configuration: InsightsConfiguration = None,
        tags: TagList = None,
    ) -> CreateGroupResult:
        raise NotImplementedError

    @handler("CreateSamplingRule")
    def create_sampling_rule(
        self, context: RequestContext, sampling_rule: SamplingRule, tags: TagList = None
    ) -> CreateSamplingRuleResult:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(
        self, context: RequestContext, group_name: GroupName = None, group_arn: GroupARN = None
    ) -> DeleteGroupResult:
        raise NotImplementedError

    @handler("DeleteSamplingRule")
    def delete_sampling_rule(
        self, context: RequestContext, rule_name: String = None, rule_arn: String = None
    ) -> DeleteSamplingRuleResult:
        raise NotImplementedError

    @handler("GetEncryptionConfig")
    def get_encryption_config(
        self,
        context: RequestContext,
    ) -> GetEncryptionConfigResult:
        raise NotImplementedError

    @handler("GetGroup")
    def get_group(
        self, context: RequestContext, group_name: GroupName = None, group_arn: GroupARN = None
    ) -> GetGroupResult:
        raise NotImplementedError

    @handler("GetGroups")
    def get_groups(
        self, context: RequestContext, next_token: GetGroupsNextToken = None
    ) -> GetGroupsResult:
        raise NotImplementedError

    @handler("GetInsight")
    def get_insight(self, context: RequestContext, insight_id: InsightId) -> GetInsightResult:
        raise NotImplementedError

    @handler("GetInsightEvents")
    def get_insight_events(
        self,
        context: RequestContext,
        insight_id: InsightId,
        max_results: GetInsightEventsMaxResults = None,
        next_token: Token = None,
    ) -> GetInsightEventsResult:
        raise NotImplementedError

    @handler("GetInsightImpactGraph")
    def get_insight_impact_graph(
        self,
        context: RequestContext,
        insight_id: InsightId,
        start_time: Timestamp,
        end_time: Timestamp,
        next_token: Token = None,
    ) -> GetInsightImpactGraphResult:
        raise NotImplementedError

    @handler("GetInsightSummaries")
    def get_insight_summaries(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        states: InsightStateList = None,
        group_arn: GroupARN = None,
        group_name: GroupName = None,
        max_results: GetInsightSummariesMaxResults = None,
        next_token: Token = None,
    ) -> GetInsightSummariesResult:
        raise NotImplementedError

    @handler("GetSamplingRules")
    def get_sampling_rules(
        self, context: RequestContext, next_token: String = None
    ) -> GetSamplingRulesResult:
        raise NotImplementedError

    @handler("GetSamplingStatisticSummaries")
    def get_sampling_statistic_summaries(
        self, context: RequestContext, next_token: String = None
    ) -> GetSamplingStatisticSummariesResult:
        raise NotImplementedError

    @handler("GetSamplingTargets")
    def get_sampling_targets(
        self, context: RequestContext, sampling_statistics_documents: SamplingStatisticsDocumentList
    ) -> GetSamplingTargetsResult:
        raise NotImplementedError

    @handler("GetServiceGraph")
    def get_service_graph(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        group_name: GroupName = None,
        group_arn: GroupARN = None,
        next_token: String = None,
    ) -> GetServiceGraphResult:
        raise NotImplementedError

    @handler("GetTimeSeriesServiceStatistics")
    def get_time_series_service_statistics(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        group_name: GroupName = None,
        group_arn: GroupARN = None,
        entity_selector_expression: EntitySelectorExpression = None,
        period: NullableInteger = None,
        forecast_statistics: NullableBoolean = None,
        next_token: String = None,
    ) -> GetTimeSeriesServiceStatisticsResult:
        raise NotImplementedError

    @handler("GetTraceGraph")
    def get_trace_graph(
        self, context: RequestContext, trace_ids: TraceIdList, next_token: String = None
    ) -> GetTraceGraphResult:
        raise NotImplementedError

    @handler("GetTraceSummaries")
    def get_trace_summaries(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        time_range_type: TimeRangeType = None,
        sampling: NullableBoolean = None,
        sampling_strategy: SamplingStrategy = None,
        filter_expression: FilterExpression = None,
        next_token: String = None,
    ) -> GetTraceSummariesResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, next_token: String = None
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutEncryptionConfig", expand=False)
    def put_encryption_config(
        self, context: RequestContext, request: PutEncryptionConfigRequest
    ) -> PutEncryptionConfigResult:
        raise NotImplementedError

    @handler("PutTelemetryRecords")
    def put_telemetry_records(
        self,
        context: RequestContext,
        telemetry_records: TelemetryRecordList,
        ec2_instance_id: EC2InstanceId = None,
        hostname: Hostname = None,
        resource_arn: ResourceARN = None,
    ) -> PutTelemetryRecordsResult:
        raise NotImplementedError

    @handler("PutTraceSegments")
    def put_trace_segments(
        self, context: RequestContext, trace_segment_documents: TraceSegmentDocumentList
    ) -> PutTraceSegmentsResult:
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

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group_arn: GroupARN = None,
        filter_expression: FilterExpression = None,
        insights_configuration: InsightsConfiguration = None,
    ) -> UpdateGroupResult:
        raise NotImplementedError

    @handler("UpdateSamplingRule")
    def update_sampling_rule(
        self, context: RequestContext, sampling_rule_update: SamplingRuleUpdate
    ) -> UpdateSamplingRuleResult:
        raise NotImplementedError
