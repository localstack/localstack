from datetime import datetime
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
ActionPrefix = str
ActionsEnabled = bool
ActionsSuppressedReason = str
AlarmArn = str
AlarmDescription = str
AlarmName = str
AlarmNamePrefix = str
AlarmRule = str
AmazonResourceName = str
AnomalyDetectorMetricStat = str
AnomalyDetectorMetricTimezone = str
AwsQueryErrorMessage = str
DashboardArn = str
DashboardBody = str
DashboardErrorMessage = str
DashboardName = str
DashboardNamePrefix = str
DataPath = str
DatapointValue = float
DatapointsToAlarm = int
DimensionName = str
DimensionValue = str
ErrorMessage = str
EvaluateLowSampleCountPercentile = str
EvaluationPeriods = int
ExceptionType = str
ExtendedStatistic = str
FailureCode = str
FailureDescription = str
FailureResource = str
FaultDescription = str
GetMetricDataLabelTimezone = str
GetMetricDataMaxDatapoints = int
HistoryData = str
HistorySummary = str
IncludeLinkedAccounts = bool
IncludeLinkedAccountsMetrics = bool
InsightRuleAggregationStatistic = str
InsightRuleContributorKey = str
InsightRuleContributorKeyLabel = str
InsightRuleDefinition = str
InsightRuleIsManaged = bool
InsightRuleMaxResults = int
InsightRuleMetricName = str
InsightRuleName = str
InsightRuleOrderBy = str
InsightRuleSchema = str
InsightRuleState = str
InsightRuleUnboundDouble = float
InsightRuleUnboundInteger = int
ListMetricStreamsMaxResults = int
MaxRecords = int
MaxReturnedResultsCount = int
Message = str
MessageDataCode = str
MessageDataValue = str
MetricExpression = str
MetricId = str
MetricLabel = str
MetricName = str
MetricStreamName = str
MetricStreamState = str
MetricStreamStatistic = str
MetricWidget = str
Namespace = str
NextToken = str
OutputFormat = str
Period = int
ResourceId = str
ResourceName = str
ResourceType = str
ReturnData = bool
Stat = str
StateReason = str
StateReasonData = str
StorageResolution = int
SuppressorPeriod = int
TagKey = str
TagValue = str
TemplateName = str
Threshold = float
TreatMissingData = str


class ActionsSuppressedBy(str):
    WaitPeriod = "WaitPeriod"
    ExtensionPeriod = "ExtensionPeriod"
    Alarm = "Alarm"


class AlarmType(str):
    CompositeAlarm = "CompositeAlarm"
    MetricAlarm = "MetricAlarm"


class AnomalyDetectorStateValue(str):
    PENDING_TRAINING = "PENDING_TRAINING"
    TRAINED_INSUFFICIENT_DATA = "TRAINED_INSUFFICIENT_DATA"
    TRAINED = "TRAINED"


class AnomalyDetectorType(str):
    SINGLE_METRIC = "SINGLE_METRIC"
    METRIC_MATH = "METRIC_MATH"


class ComparisonOperator(str):
    GreaterThanOrEqualToThreshold = "GreaterThanOrEqualToThreshold"
    GreaterThanThreshold = "GreaterThanThreshold"
    LessThanThreshold = "LessThanThreshold"
    LessThanOrEqualToThreshold = "LessThanOrEqualToThreshold"
    LessThanLowerOrGreaterThanUpperThreshold = "LessThanLowerOrGreaterThanUpperThreshold"
    LessThanLowerThreshold = "LessThanLowerThreshold"
    GreaterThanUpperThreshold = "GreaterThanUpperThreshold"


class EvaluationState(str):
    PARTIAL_DATA = "PARTIAL_DATA"


class HistoryItemType(str):
    ConfigurationUpdate = "ConfigurationUpdate"
    StateUpdate = "StateUpdate"
    Action = "Action"


class MetricStreamOutputFormat(str):
    json = "json"
    opentelemetry0_7 = "opentelemetry0.7"
    opentelemetry1_0 = "opentelemetry1.0"


class RecentlyActive(str):
    PT3H = "PT3H"


class ScanBy(str):
    TimestampDescending = "TimestampDescending"
    TimestampAscending = "TimestampAscending"


class StandardUnit(str):
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


class StateValue(str):
    OK = "OK"
    ALARM = "ALARM"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Statistic(str):
    SampleCount = "SampleCount"
    Average = "Average"
    Sum = "Sum"
    Minimum = "Minimum"
    Maximum = "Maximum"


class StatusCode(str):
    Complete = "Complete"
    InternalError = "InternalError"
    PartialData = "PartialData"
    Forbidden = "Forbidden"


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = True
    status_code: int = 429


class DashboardValidationMessage(TypedDict, total=False):
    DataPath: Optional[DataPath]
    Message: Optional[Message]


DashboardValidationMessages = List[DashboardValidationMessage]


class DashboardInvalidInputError(ServiceException):
    code: str = "InvalidParameterInput"
    sender_fault: bool = True
    status_code: int = 400
    dashboardValidationMessages: Optional[DashboardValidationMessages]


class DashboardNotFoundError(ServiceException):
    code: str = "ResourceNotFound"
    sender_fault: bool = True
    status_code: int = 404


class InternalServiceFault(ServiceException):
    code: str = "InternalServiceError"
    sender_fault: bool = False
    status_code: int = 500


class InvalidFormatFault(ServiceException):
    code: str = "InvalidFormat"
    sender_fault: bool = True
    status_code: int = 400


class InvalidNextToken(ServiceException):
    code: str = "InvalidNextToken"
    sender_fault: bool = True
    status_code: int = 400


class InvalidParameterCombinationException(ServiceException):
    code: str = "InvalidParameterCombination"
    sender_fault: bool = True
    status_code: int = 400


class InvalidParameterValueException(ServiceException):
    code: str = "InvalidParameterValue"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededFault(ServiceException):
    code: str = "LimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class MissingRequiredParameterException(ServiceException):
    code: str = "MissingParameter"
    sender_fault: bool = True
    status_code: int = 400


class ResourceNotFound(ServiceException):
    code: str = "ResourceNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = True
    status_code: int = 404
    ResourceType: Optional[ResourceType]
    ResourceId: Optional[ResourceId]


Timestamp = datetime


class AlarmHistoryItem(TypedDict, total=False):
    AlarmName: Optional[AlarmName]
    AlarmType: Optional[AlarmType]
    Timestamp: Optional[Timestamp]
    HistoryItemType: Optional[HistoryItemType]
    HistorySummary: Optional[HistorySummary]
    HistoryData: Optional[HistoryData]


AlarmHistoryItems = List[AlarmHistoryItem]
AlarmNames = List[AlarmName]
AlarmTypes = List[AlarmType]


class Dimension(TypedDict, total=False):
    Name: DimensionName
    Value: DimensionValue


Dimensions = List[Dimension]


class Metric(TypedDict, total=False):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]


class MetricStat(TypedDict, total=False):
    Metric: Metric
    Period: Period
    Stat: Stat
    Unit: Optional[StandardUnit]


class MetricDataQuery(TypedDict, total=False):
    Id: MetricId
    MetricStat: Optional[MetricStat]
    Expression: Optional[MetricExpression]
    Label: Optional[MetricLabel]
    ReturnData: Optional[ReturnData]
    Period: Optional[Period]
    AccountId: Optional[AccountId]


MetricDataQueries = List[MetricDataQuery]


class MetricMathAnomalyDetector(TypedDict, total=False):
    MetricDataQueries: Optional[MetricDataQueries]


class SingleMetricAnomalyDetector(TypedDict, total=False):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]
    Stat: Optional[AnomalyDetectorMetricStat]


class Range(TypedDict, total=False):
    StartTime: Timestamp
    EndTime: Timestamp


AnomalyDetectorExcludedTimeRanges = List[Range]


class AnomalyDetectorConfiguration(TypedDict, total=False):
    ExcludedTimeRanges: Optional[AnomalyDetectorExcludedTimeRanges]
    MetricTimezone: Optional[AnomalyDetectorMetricTimezone]


class AnomalyDetector(TypedDict, total=False):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]
    Stat: Optional[AnomalyDetectorMetricStat]
    Configuration: Optional[AnomalyDetectorConfiguration]
    StateValue: Optional[AnomalyDetectorStateValue]
    SingleMetricAnomalyDetector: Optional[SingleMetricAnomalyDetector]
    MetricMathAnomalyDetector: Optional[MetricMathAnomalyDetector]


AnomalyDetectorTypes = List[AnomalyDetectorType]
AnomalyDetectors = List[AnomalyDetector]


class PartialFailure(TypedDict, total=False):
    FailureResource: Optional[FailureResource]
    ExceptionType: Optional[ExceptionType]
    FailureCode: Optional[FailureCode]
    FailureDescription: Optional[FailureDescription]


BatchFailures = List[PartialFailure]
ResourceList = List[ResourceName]


class CompositeAlarm(TypedDict, total=False):
    ActionsEnabled: Optional[ActionsEnabled]
    AlarmActions: Optional[ResourceList]
    AlarmArn: Optional[AlarmArn]
    AlarmConfigurationUpdatedTimestamp: Optional[Timestamp]
    AlarmDescription: Optional[AlarmDescription]
    AlarmName: Optional[AlarmName]
    AlarmRule: Optional[AlarmRule]
    InsufficientDataActions: Optional[ResourceList]
    OKActions: Optional[ResourceList]
    StateReason: Optional[StateReason]
    StateReasonData: Optional[StateReasonData]
    StateUpdatedTimestamp: Optional[Timestamp]
    StateValue: Optional[StateValue]
    StateTransitionedTimestamp: Optional[Timestamp]
    ActionsSuppressedBy: Optional[ActionsSuppressedBy]
    ActionsSuppressedReason: Optional[ActionsSuppressedReason]
    ActionsSuppressor: Optional[AlarmArn]
    ActionsSuppressorWaitPeriod: Optional[SuppressorPeriod]
    ActionsSuppressorExtensionPeriod: Optional[SuppressorPeriod]


CompositeAlarms = List[CompositeAlarm]
Counts = List[DatapointValue]
Size = int
LastModified = datetime


class DashboardEntry(TypedDict, total=False):
    DashboardName: Optional[DashboardName]
    DashboardArn: Optional[DashboardArn]
    LastModified: Optional[LastModified]
    Size: Optional[Size]


DashboardEntries = List[DashboardEntry]
DashboardNames = List[DashboardName]
DatapointValueMap = Dict[ExtendedStatistic, DatapointValue]


class Datapoint(TypedDict, total=False):
    Timestamp: Optional[Timestamp]
    SampleCount: Optional[DatapointValue]
    Average: Optional[DatapointValue]
    Sum: Optional[DatapointValue]
    Minimum: Optional[DatapointValue]
    Maximum: Optional[DatapointValue]
    Unit: Optional[StandardUnit]
    ExtendedStatistics: Optional[DatapointValueMap]


DatapointValues = List[DatapointValue]
Datapoints = List[Datapoint]


class DeleteAlarmsInput(ServiceRequest):
    AlarmNames: AlarmNames


class DeleteAnomalyDetectorInput(ServiceRequest):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]
    Stat: Optional[AnomalyDetectorMetricStat]
    SingleMetricAnomalyDetector: Optional[SingleMetricAnomalyDetector]
    MetricMathAnomalyDetector: Optional[MetricMathAnomalyDetector]


class DeleteAnomalyDetectorOutput(TypedDict, total=False):
    pass


class DeleteDashboardsInput(ServiceRequest):
    DashboardNames: DashboardNames


class DeleteDashboardsOutput(TypedDict, total=False):
    pass


InsightRuleNames = List[InsightRuleName]


class DeleteInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class DeleteInsightRulesOutput(TypedDict, total=False):
    Failures: Optional[BatchFailures]


class DeleteMetricStreamInput(ServiceRequest):
    Name: MetricStreamName


class DeleteMetricStreamOutput(TypedDict, total=False):
    pass


class DescribeAlarmHistoryInput(ServiceRequest):
    AlarmName: Optional[AlarmName]
    AlarmTypes: Optional[AlarmTypes]
    HistoryItemType: Optional[HistoryItemType]
    StartDate: Optional[Timestamp]
    EndDate: Optional[Timestamp]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[NextToken]
    ScanBy: Optional[ScanBy]


class DescribeAlarmHistoryOutput(TypedDict, total=False):
    AlarmHistoryItems: Optional[AlarmHistoryItems]
    NextToken: Optional[NextToken]


class DescribeAlarmsForMetricInput(ServiceRequest):
    MetricName: MetricName
    Namespace: Namespace
    Statistic: Optional[Statistic]
    ExtendedStatistic: Optional[ExtendedStatistic]
    Dimensions: Optional[Dimensions]
    Period: Optional[Period]
    Unit: Optional[StandardUnit]


class MetricAlarm(TypedDict, total=False):
    AlarmName: Optional[AlarmName]
    AlarmArn: Optional[AlarmArn]
    AlarmDescription: Optional[AlarmDescription]
    AlarmConfigurationUpdatedTimestamp: Optional[Timestamp]
    ActionsEnabled: Optional[ActionsEnabled]
    OKActions: Optional[ResourceList]
    AlarmActions: Optional[ResourceList]
    InsufficientDataActions: Optional[ResourceList]
    StateValue: Optional[StateValue]
    StateReason: Optional[StateReason]
    StateReasonData: Optional[StateReasonData]
    StateUpdatedTimestamp: Optional[Timestamp]
    MetricName: Optional[MetricName]
    Namespace: Optional[Namespace]
    Statistic: Optional[Statistic]
    ExtendedStatistic: Optional[ExtendedStatistic]
    Dimensions: Optional[Dimensions]
    Period: Optional[Period]
    Unit: Optional[StandardUnit]
    EvaluationPeriods: Optional[EvaluationPeriods]
    DatapointsToAlarm: Optional[DatapointsToAlarm]
    Threshold: Optional[Threshold]
    ComparisonOperator: Optional[ComparisonOperator]
    TreatMissingData: Optional[TreatMissingData]
    EvaluateLowSampleCountPercentile: Optional[EvaluateLowSampleCountPercentile]
    Metrics: Optional[MetricDataQueries]
    ThresholdMetricId: Optional[MetricId]
    EvaluationState: Optional[EvaluationState]
    StateTransitionedTimestamp: Optional[Timestamp]


MetricAlarms = List[MetricAlarm]


class DescribeAlarmsForMetricOutput(TypedDict, total=False):
    MetricAlarms: Optional[MetricAlarms]


class DescribeAlarmsInput(ServiceRequest):
    AlarmNames: Optional[AlarmNames]
    AlarmNamePrefix: Optional[AlarmNamePrefix]
    AlarmTypes: Optional[AlarmTypes]
    ChildrenOfAlarmName: Optional[AlarmName]
    ParentsOfAlarmName: Optional[AlarmName]
    StateValue: Optional[StateValue]
    ActionPrefix: Optional[ActionPrefix]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[NextToken]


class DescribeAlarmsOutput(TypedDict, total=False):
    CompositeAlarms: Optional[CompositeAlarms]
    MetricAlarms: Optional[MetricAlarms]
    NextToken: Optional[NextToken]


class DescribeAnomalyDetectorsInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxReturnedResultsCount]
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]
    AnomalyDetectorTypes: Optional[AnomalyDetectorTypes]


class DescribeAnomalyDetectorsOutput(TypedDict, total=False):
    AnomalyDetectors: Optional[AnomalyDetectors]
    NextToken: Optional[NextToken]


class DescribeInsightRulesInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[InsightRuleMaxResults]


class InsightRule(TypedDict, total=False):
    Name: InsightRuleName
    State: InsightRuleState
    Schema: InsightRuleSchema
    Definition: InsightRuleDefinition
    ManagedRule: Optional[InsightRuleIsManaged]


InsightRules = List[InsightRule]


class DescribeInsightRulesOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    InsightRules: Optional[InsightRules]


class DimensionFilter(TypedDict, total=False):
    Name: DimensionName
    Value: Optional[DimensionValue]


DimensionFilters = List[DimensionFilter]


class DisableAlarmActionsInput(ServiceRequest):
    AlarmNames: AlarmNames


class DisableInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class DisableInsightRulesOutput(TypedDict, total=False):
    Failures: Optional[BatchFailures]


class EnableAlarmActionsInput(ServiceRequest):
    AlarmNames: AlarmNames


class EnableInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class EnableInsightRulesOutput(TypedDict, total=False):
    Failures: Optional[BatchFailures]


ExtendedStatistics = List[ExtendedStatistic]


class GetDashboardInput(ServiceRequest):
    DashboardName: DashboardName


class GetDashboardOutput(TypedDict, total=False):
    DashboardArn: Optional[DashboardArn]
    DashboardBody: Optional[DashboardBody]
    DashboardName: Optional[DashboardName]


InsightRuleMetricList = List[InsightRuleMetricName]


class GetInsightRuleReportInput(ServiceRequest):
    RuleName: InsightRuleName
    StartTime: Timestamp
    EndTime: Timestamp
    Period: Period
    MaxContributorCount: Optional[InsightRuleUnboundInteger]
    Metrics: Optional[InsightRuleMetricList]
    OrderBy: Optional[InsightRuleOrderBy]


class InsightRuleMetricDatapoint(TypedDict, total=False):
    Timestamp: Timestamp
    UniqueContributors: Optional[InsightRuleUnboundDouble]
    MaxContributorValue: Optional[InsightRuleUnboundDouble]
    SampleCount: Optional[InsightRuleUnboundDouble]
    Average: Optional[InsightRuleUnboundDouble]
    Sum: Optional[InsightRuleUnboundDouble]
    Minimum: Optional[InsightRuleUnboundDouble]
    Maximum: Optional[InsightRuleUnboundDouble]


InsightRuleMetricDatapoints = List[InsightRuleMetricDatapoint]


class InsightRuleContributorDatapoint(TypedDict, total=False):
    Timestamp: Timestamp
    ApproximateValue: InsightRuleUnboundDouble


InsightRuleContributorDatapoints = List[InsightRuleContributorDatapoint]
InsightRuleContributorKeys = List[InsightRuleContributorKey]


class InsightRuleContributor(TypedDict, total=False):
    Keys: InsightRuleContributorKeys
    ApproximateAggregateValue: InsightRuleUnboundDouble
    Datapoints: InsightRuleContributorDatapoints


InsightRuleContributors = List[InsightRuleContributor]
InsightRuleUnboundLong = int
InsightRuleContributorKeyLabels = List[InsightRuleContributorKeyLabel]


class GetInsightRuleReportOutput(TypedDict, total=False):
    KeyLabels: Optional[InsightRuleContributorKeyLabels]
    AggregationStatistic: Optional[InsightRuleAggregationStatistic]
    AggregateValue: Optional[InsightRuleUnboundDouble]
    ApproximateUniqueCount: Optional[InsightRuleUnboundLong]
    Contributors: Optional[InsightRuleContributors]
    MetricDatapoints: Optional[InsightRuleMetricDatapoints]


class LabelOptions(TypedDict, total=False):
    Timezone: Optional[GetMetricDataLabelTimezone]


class GetMetricDataInput(ServiceRequest):
    MetricDataQueries: MetricDataQueries
    StartTime: Timestamp
    EndTime: Timestamp
    NextToken: Optional[NextToken]
    ScanBy: Optional[ScanBy]
    MaxDatapoints: Optional[GetMetricDataMaxDatapoints]
    LabelOptions: Optional[LabelOptions]


class MessageData(TypedDict, total=False):
    Code: Optional[MessageDataCode]
    Value: Optional[MessageDataValue]


MetricDataResultMessages = List[MessageData]
Timestamps = List[Timestamp]


class MetricDataResult(TypedDict, total=False):
    Id: Optional[MetricId]
    Label: Optional[MetricLabel]
    Timestamps: Optional[Timestamps]
    Values: Optional[DatapointValues]
    StatusCode: Optional[StatusCode]
    Messages: Optional[MetricDataResultMessages]


MetricDataResults = List[MetricDataResult]


class GetMetricDataOutput(TypedDict, total=False):
    MetricDataResults: Optional[MetricDataResults]
    NextToken: Optional[NextToken]
    Messages: Optional[MetricDataResultMessages]


Statistics = List[Statistic]


class GetMetricStatisticsInput(ServiceRequest):
    Namespace: Namespace
    MetricName: MetricName
    Dimensions: Optional[Dimensions]
    StartTime: Timestamp
    EndTime: Timestamp
    Period: Period
    Statistics: Optional[Statistics]
    ExtendedStatistics: Optional[ExtendedStatistics]
    Unit: Optional[StandardUnit]


class GetMetricStatisticsOutput(TypedDict, total=False):
    Label: Optional[MetricLabel]
    Datapoints: Optional[Datapoints]


class GetMetricStreamInput(ServiceRequest):
    Name: MetricStreamName


MetricStreamStatisticsAdditionalStatistics = List[MetricStreamStatistic]


class MetricStreamStatisticsMetric(TypedDict, total=False):
    Namespace: Namespace
    MetricName: MetricName


MetricStreamStatisticsIncludeMetrics = List[MetricStreamStatisticsMetric]


class MetricStreamStatisticsConfiguration(TypedDict, total=False):
    IncludeMetrics: MetricStreamStatisticsIncludeMetrics
    AdditionalStatistics: MetricStreamStatisticsAdditionalStatistics


MetricStreamStatisticsConfigurations = List[MetricStreamStatisticsConfiguration]
MetricStreamFilterMetricNames = List[MetricName]


class MetricStreamFilter(TypedDict, total=False):
    Namespace: Optional[Namespace]
    MetricNames: Optional[MetricStreamFilterMetricNames]


MetricStreamFilters = List[MetricStreamFilter]


class GetMetricStreamOutput(TypedDict, total=False):
    Arn: Optional[AmazonResourceName]
    Name: Optional[MetricStreamName]
    IncludeFilters: Optional[MetricStreamFilters]
    ExcludeFilters: Optional[MetricStreamFilters]
    FirehoseArn: Optional[AmazonResourceName]
    RoleArn: Optional[AmazonResourceName]
    State: Optional[MetricStreamState]
    CreationDate: Optional[Timestamp]
    LastUpdateDate: Optional[Timestamp]
    OutputFormat: Optional[MetricStreamOutputFormat]
    StatisticsConfigurations: Optional[MetricStreamStatisticsConfigurations]
    IncludeLinkedAccountsMetrics: Optional[IncludeLinkedAccountsMetrics]


class GetMetricWidgetImageInput(ServiceRequest):
    MetricWidget: MetricWidget
    OutputFormat: Optional[OutputFormat]


MetricWidgetImage = bytes


class GetMetricWidgetImageOutput(TypedDict, total=False):
    MetricWidgetImage: Optional[MetricWidgetImage]


class ListDashboardsInput(ServiceRequest):
    DashboardNamePrefix: Optional[DashboardNamePrefix]
    NextToken: Optional[NextToken]


class ListDashboardsOutput(TypedDict, total=False):
    DashboardEntries: Optional[DashboardEntries]
    NextToken: Optional[NextToken]


class ListManagedInsightRulesInput(ServiceRequest):
    ResourceARN: AmazonResourceName
    NextToken: Optional[NextToken]
    MaxResults: Optional[InsightRuleMaxResults]


class ManagedRuleState(TypedDict, total=False):
    RuleName: InsightRuleName
    State: InsightRuleState


class ManagedRuleDescription(TypedDict, total=False):
    TemplateName: Optional[TemplateName]
    ResourceARN: Optional[AmazonResourceName]
    RuleState: Optional[ManagedRuleState]


ManagedRuleDescriptions = List[ManagedRuleDescription]


class ListManagedInsightRulesOutput(TypedDict, total=False):
    ManagedRules: Optional[ManagedRuleDescriptions]
    NextToken: Optional[NextToken]


class ListMetricStreamsInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListMetricStreamsMaxResults]


class MetricStreamEntry(TypedDict, total=False):
    Arn: Optional[AmazonResourceName]
    CreationDate: Optional[Timestamp]
    LastUpdateDate: Optional[Timestamp]
    Name: Optional[MetricStreamName]
    FirehoseArn: Optional[AmazonResourceName]
    State: Optional[MetricStreamState]
    OutputFormat: Optional[MetricStreamOutputFormat]


MetricStreamEntries = List[MetricStreamEntry]


class ListMetricStreamsOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Entries: Optional[MetricStreamEntries]


class ListMetricsInput(ServiceRequest):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[DimensionFilters]
    NextToken: Optional[NextToken]
    RecentlyActive: Optional[RecentlyActive]
    IncludeLinkedAccounts: Optional[IncludeLinkedAccounts]
    OwningAccount: Optional[AccountId]


OwningAccounts = List[AccountId]
Metrics = List[Metric]


class ListMetricsOutput(TypedDict, total=False):
    Metrics: Optional[Metrics]
    NextToken: Optional[NextToken]
    OwningAccounts: Optional[OwningAccounts]


class ListTagsForResourceInput(ServiceRequest):
    ResourceARN: AmazonResourceName


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: Optional[TagList]


class ManagedRule(TypedDict, total=False):
    TemplateName: TemplateName
    ResourceARN: AmazonResourceName
    Tags: Optional[TagList]


ManagedRules = List[ManagedRule]
Values = List[DatapointValue]


class StatisticSet(TypedDict, total=False):
    SampleCount: DatapointValue
    Sum: DatapointValue
    Minimum: DatapointValue
    Maximum: DatapointValue


class MetricDatum(TypedDict, total=False):
    MetricName: MetricName
    Dimensions: Optional[Dimensions]
    Timestamp: Optional[Timestamp]
    Value: Optional[DatapointValue]
    StatisticValues: Optional[StatisticSet]
    Values: Optional[Values]
    Counts: Optional[Counts]
    Unit: Optional[StandardUnit]
    StorageResolution: Optional[StorageResolution]


MetricData = List[MetricDatum]
MetricStreamNames = List[MetricStreamName]


class PutAnomalyDetectorInput(ServiceRequest):
    Namespace: Optional[Namespace]
    MetricName: Optional[MetricName]
    Dimensions: Optional[Dimensions]
    Stat: Optional[AnomalyDetectorMetricStat]
    Configuration: Optional[AnomalyDetectorConfiguration]
    SingleMetricAnomalyDetector: Optional[SingleMetricAnomalyDetector]
    MetricMathAnomalyDetector: Optional[MetricMathAnomalyDetector]


class PutAnomalyDetectorOutput(TypedDict, total=False):
    pass


class PutCompositeAlarmInput(ServiceRequest):
    ActionsEnabled: Optional[ActionsEnabled]
    AlarmActions: Optional[ResourceList]
    AlarmDescription: Optional[AlarmDescription]
    AlarmName: AlarmName
    AlarmRule: AlarmRule
    InsufficientDataActions: Optional[ResourceList]
    OKActions: Optional[ResourceList]
    Tags: Optional[TagList]
    ActionsSuppressor: Optional[AlarmArn]
    ActionsSuppressorWaitPeriod: Optional[SuppressorPeriod]
    ActionsSuppressorExtensionPeriod: Optional[SuppressorPeriod]


class PutDashboardInput(ServiceRequest):
    DashboardName: DashboardName
    DashboardBody: DashboardBody


class PutDashboardOutput(TypedDict, total=False):
    DashboardValidationMessages: Optional[DashboardValidationMessages]


class PutInsightRuleInput(ServiceRequest):
    RuleName: InsightRuleName
    RuleState: Optional[InsightRuleState]
    RuleDefinition: InsightRuleDefinition
    Tags: Optional[TagList]


class PutInsightRuleOutput(TypedDict, total=False):
    pass


class PutManagedInsightRulesInput(ServiceRequest):
    ManagedRules: ManagedRules


class PutManagedInsightRulesOutput(TypedDict, total=False):
    Failures: Optional[BatchFailures]


class PutMetricAlarmInput(ServiceRequest):
    AlarmName: AlarmName
    AlarmDescription: Optional[AlarmDescription]
    ActionsEnabled: Optional[ActionsEnabled]
    OKActions: Optional[ResourceList]
    AlarmActions: Optional[ResourceList]
    InsufficientDataActions: Optional[ResourceList]
    MetricName: Optional[MetricName]
    Namespace: Optional[Namespace]
    Statistic: Optional[Statistic]
    ExtendedStatistic: Optional[ExtendedStatistic]
    Dimensions: Optional[Dimensions]
    Period: Optional[Period]
    Unit: Optional[StandardUnit]
    EvaluationPeriods: EvaluationPeriods
    DatapointsToAlarm: Optional[DatapointsToAlarm]
    Threshold: Optional[Threshold]
    ComparisonOperator: ComparisonOperator
    TreatMissingData: Optional[TreatMissingData]
    EvaluateLowSampleCountPercentile: Optional[EvaluateLowSampleCountPercentile]
    Metrics: Optional[MetricDataQueries]
    Tags: Optional[TagList]
    ThresholdMetricId: Optional[MetricId]


class PutMetricDataInput(ServiceRequest):
    Namespace: Namespace
    MetricData: MetricData


class PutMetricStreamInput(ServiceRequest):
    Name: MetricStreamName
    IncludeFilters: Optional[MetricStreamFilters]
    ExcludeFilters: Optional[MetricStreamFilters]
    FirehoseArn: AmazonResourceName
    RoleArn: AmazonResourceName
    OutputFormat: MetricStreamOutputFormat
    Tags: Optional[TagList]
    StatisticsConfigurations: Optional[MetricStreamStatisticsConfigurations]
    IncludeLinkedAccountsMetrics: Optional[IncludeLinkedAccountsMetrics]


class PutMetricStreamOutput(TypedDict, total=False):
    Arn: Optional[AmazonResourceName]


class SetAlarmStateInput(ServiceRequest):
    AlarmName: AlarmName
    StateValue: StateValue
    StateReason: StateReason
    StateReasonData: Optional[StateReasonData]


class StartMetricStreamsInput(ServiceRequest):
    Names: MetricStreamNames


class StartMetricStreamsOutput(TypedDict, total=False):
    pass


class StopMetricStreamsInput(ServiceRequest):
    Names: MetricStreamNames


class StopMetricStreamsOutput(TypedDict, total=False):
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


class CloudwatchApi:
    service = "cloudwatch"
    version = "2010-08-01"

    @handler("DeleteAlarms")
    def delete_alarms(self, context: RequestContext, alarm_names: AlarmNames, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteAnomalyDetector")
    def delete_anomaly_detector(
        self,
        context: RequestContext,
        namespace: Namespace = None,
        metric_name: MetricName = None,
        dimensions: Dimensions = None,
        stat: AnomalyDetectorMetricStat = None,
        single_metric_anomaly_detector: SingleMetricAnomalyDetector = None,
        metric_math_anomaly_detector: MetricMathAnomalyDetector = None,
        **kwargs,
    ) -> DeleteAnomalyDetectorOutput:
        raise NotImplementedError

    @handler("DeleteDashboards")
    def delete_dashboards(
        self, context: RequestContext, dashboard_names: DashboardNames, **kwargs
    ) -> DeleteDashboardsOutput:
        raise NotImplementedError

    @handler("DeleteInsightRules")
    def delete_insight_rules(
        self, context: RequestContext, rule_names: InsightRuleNames, **kwargs
    ) -> DeleteInsightRulesOutput:
        raise NotImplementedError

    @handler("DeleteMetricStream")
    def delete_metric_stream(
        self, context: RequestContext, name: MetricStreamName, **kwargs
    ) -> DeleteMetricStreamOutput:
        raise NotImplementedError

    @handler("DescribeAlarmHistory")
    def describe_alarm_history(
        self,
        context: RequestContext,
        alarm_name: AlarmName = None,
        alarm_types: AlarmTypes = None,
        history_item_type: HistoryItemType = None,
        start_date: Timestamp = None,
        end_date: Timestamp = None,
        max_records: MaxRecords = None,
        next_token: NextToken = None,
        scan_by: ScanBy = None,
        **kwargs,
    ) -> DescribeAlarmHistoryOutput:
        raise NotImplementedError

    @handler("DescribeAlarms")
    def describe_alarms(
        self,
        context: RequestContext,
        alarm_names: AlarmNames = None,
        alarm_name_prefix: AlarmNamePrefix = None,
        alarm_types: AlarmTypes = None,
        children_of_alarm_name: AlarmName = None,
        parents_of_alarm_name: AlarmName = None,
        state_value: StateValue = None,
        action_prefix: ActionPrefix = None,
        max_records: MaxRecords = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeAlarmsOutput:
        raise NotImplementedError

    @handler("DescribeAlarmsForMetric")
    def describe_alarms_for_metric(
        self,
        context: RequestContext,
        metric_name: MetricName,
        namespace: Namespace,
        statistic: Statistic = None,
        extended_statistic: ExtendedStatistic = None,
        dimensions: Dimensions = None,
        period: Period = None,
        unit: StandardUnit = None,
        **kwargs,
    ) -> DescribeAlarmsForMetricOutput:
        raise NotImplementedError

    @handler("DescribeAnomalyDetectors")
    def describe_anomaly_detectors(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxReturnedResultsCount = None,
        namespace: Namespace = None,
        metric_name: MetricName = None,
        dimensions: Dimensions = None,
        anomaly_detector_types: AnomalyDetectorTypes = None,
        **kwargs,
    ) -> DescribeAnomalyDetectorsOutput:
        raise NotImplementedError

    @handler("DescribeInsightRules")
    def describe_insight_rules(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: InsightRuleMaxResults = None,
        **kwargs,
    ) -> DescribeInsightRulesOutput:
        raise NotImplementedError

    @handler("DisableAlarmActions")
    def disable_alarm_actions(
        self, context: RequestContext, alarm_names: AlarmNames, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DisableInsightRules")
    def disable_insight_rules(
        self, context: RequestContext, rule_names: InsightRuleNames, **kwargs
    ) -> DisableInsightRulesOutput:
        raise NotImplementedError

    @handler("EnableAlarmActions")
    def enable_alarm_actions(
        self, context: RequestContext, alarm_names: AlarmNames, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("EnableInsightRules")
    def enable_insight_rules(
        self, context: RequestContext, rule_names: InsightRuleNames, **kwargs
    ) -> EnableInsightRulesOutput:
        raise NotImplementedError

    @handler("GetDashboard")
    def get_dashboard(
        self, context: RequestContext, dashboard_name: DashboardName, **kwargs
    ) -> GetDashboardOutput:
        raise NotImplementedError

    @handler("GetInsightRuleReport")
    def get_insight_rule_report(
        self,
        context: RequestContext,
        rule_name: InsightRuleName,
        start_time: Timestamp,
        end_time: Timestamp,
        period: Period,
        max_contributor_count: InsightRuleUnboundInteger = None,
        metrics: InsightRuleMetricList = None,
        order_by: InsightRuleOrderBy = None,
        **kwargs,
    ) -> GetInsightRuleReportOutput:
        raise NotImplementedError

    @handler("GetMetricData")
    def get_metric_data(
        self,
        context: RequestContext,
        metric_data_queries: MetricDataQueries,
        start_time: Timestamp,
        end_time: Timestamp,
        next_token: NextToken = None,
        scan_by: ScanBy = None,
        max_datapoints: GetMetricDataMaxDatapoints = None,
        label_options: LabelOptions = None,
        **kwargs,
    ) -> GetMetricDataOutput:
        raise NotImplementedError

    @handler("GetMetricStatistics")
    def get_metric_statistics(
        self,
        context: RequestContext,
        namespace: Namespace,
        metric_name: MetricName,
        start_time: Timestamp,
        end_time: Timestamp,
        period: Period,
        dimensions: Dimensions = None,
        statistics: Statistics = None,
        extended_statistics: ExtendedStatistics = None,
        unit: StandardUnit = None,
        **kwargs,
    ) -> GetMetricStatisticsOutput:
        raise NotImplementedError

    @handler("GetMetricStream")
    def get_metric_stream(
        self, context: RequestContext, name: MetricStreamName, **kwargs
    ) -> GetMetricStreamOutput:
        raise NotImplementedError

    @handler("GetMetricWidgetImage")
    def get_metric_widget_image(
        self,
        context: RequestContext,
        metric_widget: MetricWidget,
        output_format: OutputFormat = None,
        **kwargs,
    ) -> GetMetricWidgetImageOutput:
        raise NotImplementedError

    @handler("ListDashboards")
    def list_dashboards(
        self,
        context: RequestContext,
        dashboard_name_prefix: DashboardNamePrefix = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListDashboardsOutput:
        raise NotImplementedError

    @handler("ListManagedInsightRules")
    def list_managed_insight_rules(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        next_token: NextToken = None,
        max_results: InsightRuleMaxResults = None,
        **kwargs,
    ) -> ListManagedInsightRulesOutput:
        raise NotImplementedError

    @handler("ListMetricStreams")
    def list_metric_streams(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: ListMetricStreamsMaxResults = None,
        **kwargs,
    ) -> ListMetricStreamsOutput:
        raise NotImplementedError

    @handler("ListMetrics")
    def list_metrics(
        self,
        context: RequestContext,
        namespace: Namespace = None,
        metric_name: MetricName = None,
        dimensions: DimensionFilters = None,
        next_token: NextToken = None,
        recently_active: RecentlyActive = None,
        include_linked_accounts: IncludeLinkedAccounts = None,
        owning_account: AccountId = None,
        **kwargs,
    ) -> ListMetricsOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("PutAnomalyDetector")
    def put_anomaly_detector(
        self,
        context: RequestContext,
        namespace: Namespace = None,
        metric_name: MetricName = None,
        dimensions: Dimensions = None,
        stat: AnomalyDetectorMetricStat = None,
        configuration: AnomalyDetectorConfiguration = None,
        single_metric_anomaly_detector: SingleMetricAnomalyDetector = None,
        metric_math_anomaly_detector: MetricMathAnomalyDetector = None,
        **kwargs,
    ) -> PutAnomalyDetectorOutput:
        raise NotImplementedError

    @handler("PutCompositeAlarm")
    def put_composite_alarm(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        alarm_rule: AlarmRule,
        actions_enabled: ActionsEnabled = None,
        alarm_actions: ResourceList = None,
        alarm_description: AlarmDescription = None,
        insufficient_data_actions: ResourceList = None,
        ok_actions: ResourceList = None,
        tags: TagList = None,
        actions_suppressor: AlarmArn = None,
        actions_suppressor_wait_period: SuppressorPeriod = None,
        actions_suppressor_extension_period: SuppressorPeriod = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutDashboard")
    def put_dashboard(
        self,
        context: RequestContext,
        dashboard_name: DashboardName,
        dashboard_body: DashboardBody,
        **kwargs,
    ) -> PutDashboardOutput:
        raise NotImplementedError

    @handler("PutInsightRule")
    def put_insight_rule(
        self,
        context: RequestContext,
        rule_name: InsightRuleName,
        rule_definition: InsightRuleDefinition,
        rule_state: InsightRuleState = None,
        tags: TagList = None,
        **kwargs,
    ) -> PutInsightRuleOutput:
        raise NotImplementedError

    @handler("PutManagedInsightRules")
    def put_managed_insight_rules(
        self, context: RequestContext, managed_rules: ManagedRules, **kwargs
    ) -> PutManagedInsightRulesOutput:
        raise NotImplementedError

    @handler("PutMetricAlarm")
    def put_metric_alarm(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        evaluation_periods: EvaluationPeriods,
        comparison_operator: ComparisonOperator,
        alarm_description: AlarmDescription = None,
        actions_enabled: ActionsEnabled = None,
        ok_actions: ResourceList = None,
        alarm_actions: ResourceList = None,
        insufficient_data_actions: ResourceList = None,
        metric_name: MetricName = None,
        namespace: Namespace = None,
        statistic: Statistic = None,
        extended_statistic: ExtendedStatistic = None,
        dimensions: Dimensions = None,
        period: Period = None,
        unit: StandardUnit = None,
        datapoints_to_alarm: DatapointsToAlarm = None,
        threshold: Threshold = None,
        treat_missing_data: TreatMissingData = None,
        evaluate_low_sample_count_percentile: EvaluateLowSampleCountPercentile = None,
        metrics: MetricDataQueries = None,
        tags: TagList = None,
        threshold_metric_id: MetricId = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutMetricData")
    def put_metric_data(
        self, context: RequestContext, namespace: Namespace, metric_data: MetricData, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("PutMetricStream")
    def put_metric_stream(
        self,
        context: RequestContext,
        name: MetricStreamName,
        firehose_arn: AmazonResourceName,
        role_arn: AmazonResourceName,
        output_format: MetricStreamOutputFormat,
        include_filters: MetricStreamFilters = None,
        exclude_filters: MetricStreamFilters = None,
        tags: TagList = None,
        statistics_configurations: MetricStreamStatisticsConfigurations = None,
        include_linked_accounts_metrics: IncludeLinkedAccountsMetrics = None,
        **kwargs,
    ) -> PutMetricStreamOutput:
        raise NotImplementedError

    @handler("SetAlarmState")
    def set_alarm_state(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        state_value: StateValue,
        state_reason: StateReason,
        state_reason_data: StateReasonData = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StartMetricStreams")
    def start_metric_streams(
        self, context: RequestContext, names: MetricStreamNames, **kwargs
    ) -> StartMetricStreamsOutput:
        raise NotImplementedError

    @handler("StopMetricStreams")
    def stop_metric_streams(
        self, context: RequestContext, names: MetricStreamNames, **kwargs
    ) -> StopMetricStreamsOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceOutput:
        raise NotImplementedError
