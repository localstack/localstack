from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
AttributeName = str
AttributeValue = str
AwsQueryErrorMessage = str
ContributorId = str
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
EntityAttributesMapKeyString = str
EntityAttributesMapValueString = str
EntityKeyAttributesMapKeyString = str
EntityKeyAttributesMapValueString = str
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
InsightRuleOnTransformedLogs = bool
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
PeriodicSpikes = bool
ResourceId = str
ResourceName = str
ResourceType = str
ReturnData = bool
Stat = str
StateReason = str
StateReasonData = str
StorageResolution = int
StrictEntityValidation = bool
SuppressorPeriod = int
TagKey = str
TagValue = str
TemplateName = str
Threshold = float
TreatMissingData = str


class ActionsSuppressedBy(StrEnum):
    WaitPeriod = "WaitPeriod"
    ExtensionPeriod = "ExtensionPeriod"
    Alarm = "Alarm"


class AlarmType(StrEnum):
    CompositeAlarm = "CompositeAlarm"
    MetricAlarm = "MetricAlarm"


class AnomalyDetectorStateValue(StrEnum):
    PENDING_TRAINING = "PENDING_TRAINING"
    TRAINED_INSUFFICIENT_DATA = "TRAINED_INSUFFICIENT_DATA"
    TRAINED = "TRAINED"


class AnomalyDetectorType(StrEnum):
    SINGLE_METRIC = "SINGLE_METRIC"
    METRIC_MATH = "METRIC_MATH"


class ComparisonOperator(StrEnum):
    GreaterThanOrEqualToThreshold = "GreaterThanOrEqualToThreshold"
    GreaterThanThreshold = "GreaterThanThreshold"
    LessThanThreshold = "LessThanThreshold"
    LessThanOrEqualToThreshold = "LessThanOrEqualToThreshold"
    LessThanLowerOrGreaterThanUpperThreshold = "LessThanLowerOrGreaterThanUpperThreshold"
    LessThanLowerThreshold = "LessThanLowerThreshold"
    GreaterThanUpperThreshold = "GreaterThanUpperThreshold"


class EvaluationState(StrEnum):
    PARTIAL_DATA = "PARTIAL_DATA"


class HistoryItemType(StrEnum):
    ConfigurationUpdate = "ConfigurationUpdate"
    StateUpdate = "StateUpdate"
    Action = "Action"
    AlarmContributorStateUpdate = "AlarmContributorStateUpdate"
    AlarmContributorAction = "AlarmContributorAction"


class MetricStreamOutputFormat(StrEnum):
    json = "json"
    opentelemetry0_7 = "opentelemetry0.7"
    opentelemetry1_0 = "opentelemetry1.0"


class RecentlyActive(StrEnum):
    PT3H = "PT3H"


class ScanBy(StrEnum):
    TimestampDescending = "TimestampDescending"
    TimestampAscending = "TimestampAscending"


class StandardUnit(StrEnum):
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


class StateValue(StrEnum):
    OK = "OK"
    ALARM = "ALARM"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Statistic(StrEnum):
    SampleCount = "SampleCount"
    Average = "Average"
    Sum = "Sum"
    Minimum = "Minimum"
    Maximum = "Maximum"


class StatusCode(StrEnum):
    Complete = "Complete"
    InternalError = "InternalError"
    PartialData = "PartialData"
    Forbidden = "Forbidden"


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = True
    status_code: int = 429


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409


class DashboardValidationMessage(TypedDict, total=False):
    DataPath: DataPath | None
    Message: Message | None


DashboardValidationMessages = list[DashboardValidationMessage]


class DashboardInvalidInputError(ServiceException):
    code: str = "InvalidParameterInput"
    sender_fault: bool = True
    status_code: int = 400
    dashboardValidationMessages: DashboardValidationMessages | None


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
    ResourceType: ResourceType | None
    ResourceId: ResourceId | None


Timestamp = datetime
ContributorAttributes = dict[AttributeName, AttributeValue]


class AlarmContributor(TypedDict, total=False):
    ContributorId: ContributorId
    ContributorAttributes: ContributorAttributes
    StateReason: StateReason
    StateTransitionedTimestamp: Timestamp | None


AlarmContributors = list[AlarmContributor]


class AlarmHistoryItem(TypedDict, total=False):
    AlarmName: AlarmName | None
    AlarmContributorId: ContributorId | None
    AlarmType: AlarmType | None
    Timestamp: Timestamp | None
    HistoryItemType: HistoryItemType | None
    HistorySummary: HistorySummary | None
    HistoryData: HistoryData | None
    AlarmContributorAttributes: ContributorAttributes | None


AlarmHistoryItems = list[AlarmHistoryItem]
AlarmNames = list[AlarmName]
AlarmTypes = list[AlarmType]


class Dimension(TypedDict, total=False):
    Name: DimensionName
    Value: DimensionValue


Dimensions = list[Dimension]


class Metric(TypedDict, total=False):
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None


class MetricStat(TypedDict, total=False):
    Metric: Metric
    Period: Period
    Stat: Stat
    Unit: StandardUnit | None


class MetricDataQuery(TypedDict, total=False):
    Id: MetricId
    MetricStat: MetricStat | None
    Expression: MetricExpression | None
    Label: MetricLabel | None
    ReturnData: ReturnData | None
    Period: Period | None
    AccountId: AccountId | None


MetricDataQueries = list[MetricDataQuery]


class MetricMathAnomalyDetector(TypedDict, total=False):
    MetricDataQueries: MetricDataQueries | None


class SingleMetricAnomalyDetector(TypedDict, total=False):
    AccountId: AccountId | None
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None
    Stat: AnomalyDetectorMetricStat | None


class MetricCharacteristics(TypedDict, total=False):
    PeriodicSpikes: PeriodicSpikes | None


class Range(TypedDict, total=False):
    StartTime: Timestamp
    EndTime: Timestamp


AnomalyDetectorExcludedTimeRanges = list[Range]


class AnomalyDetectorConfiguration(TypedDict, total=False):
    ExcludedTimeRanges: AnomalyDetectorExcludedTimeRanges | None
    MetricTimezone: AnomalyDetectorMetricTimezone | None


class AnomalyDetector(TypedDict, total=False):
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None
    Stat: AnomalyDetectorMetricStat | None
    Configuration: AnomalyDetectorConfiguration | None
    StateValue: AnomalyDetectorStateValue | None
    MetricCharacteristics: MetricCharacteristics | None
    SingleMetricAnomalyDetector: SingleMetricAnomalyDetector | None
    MetricMathAnomalyDetector: MetricMathAnomalyDetector | None


AnomalyDetectorTypes = list[AnomalyDetectorType]
AnomalyDetectors = list[AnomalyDetector]


class PartialFailure(TypedDict, total=False):
    FailureResource: FailureResource | None
    ExceptionType: ExceptionType | None
    FailureCode: FailureCode | None
    FailureDescription: FailureDescription | None


BatchFailures = list[PartialFailure]
ResourceList = list[ResourceName]


class CompositeAlarm(TypedDict, total=False):
    ActionsEnabled: ActionsEnabled | None
    AlarmActions: ResourceList | None
    AlarmArn: AlarmArn | None
    AlarmConfigurationUpdatedTimestamp: Timestamp | None
    AlarmDescription: AlarmDescription | None
    AlarmName: AlarmName | None
    AlarmRule: AlarmRule | None
    InsufficientDataActions: ResourceList | None
    OKActions: ResourceList | None
    StateReason: StateReason | None
    StateReasonData: StateReasonData | None
    StateUpdatedTimestamp: Timestamp | None
    StateValue: StateValue | None
    StateTransitionedTimestamp: Timestamp | None
    ActionsSuppressedBy: ActionsSuppressedBy | None
    ActionsSuppressedReason: ActionsSuppressedReason | None
    ActionsSuppressor: AlarmArn | None
    ActionsSuppressorWaitPeriod: SuppressorPeriod | None
    ActionsSuppressorExtensionPeriod: SuppressorPeriod | None


CompositeAlarms = list[CompositeAlarm]
Counts = list[DatapointValue]
Size = int
LastModified = datetime


class DashboardEntry(TypedDict, total=False):
    DashboardName: DashboardName | None
    DashboardArn: DashboardArn | None
    LastModified: LastModified | None
    Size: Size | None


DashboardEntries = list[DashboardEntry]
DashboardNames = list[DashboardName]
DatapointValueMap = dict[ExtendedStatistic, DatapointValue]


class Datapoint(TypedDict, total=False):
    Timestamp: Timestamp | None
    SampleCount: DatapointValue | None
    Average: DatapointValue | None
    Sum: DatapointValue | None
    Minimum: DatapointValue | None
    Maximum: DatapointValue | None
    Unit: StandardUnit | None
    ExtendedStatistics: DatapointValueMap | None


DatapointValues = list[DatapointValue]
Datapoints = list[Datapoint]


class DeleteAlarmsInput(ServiceRequest):
    AlarmNames: AlarmNames


class DeleteAnomalyDetectorInput(ServiceRequest):
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None
    Stat: AnomalyDetectorMetricStat | None
    SingleMetricAnomalyDetector: SingleMetricAnomalyDetector | None
    MetricMathAnomalyDetector: MetricMathAnomalyDetector | None


class DeleteAnomalyDetectorOutput(TypedDict, total=False):
    pass


class DeleteDashboardsInput(ServiceRequest):
    DashboardNames: DashboardNames


class DeleteDashboardsOutput(TypedDict, total=False):
    pass


InsightRuleNames = list[InsightRuleName]


class DeleteInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class DeleteInsightRulesOutput(TypedDict, total=False):
    Failures: BatchFailures | None


class DeleteMetricStreamInput(ServiceRequest):
    Name: MetricStreamName


class DeleteMetricStreamOutput(TypedDict, total=False):
    pass


class DescribeAlarmContributorsInput(ServiceRequest):
    AlarmName: AlarmName
    NextToken: NextToken | None


class DescribeAlarmContributorsOutput(TypedDict, total=False):
    AlarmContributors: AlarmContributors
    NextToken: NextToken | None


class DescribeAlarmHistoryInput(ServiceRequest):
    AlarmName: AlarmName | None
    AlarmContributorId: ContributorId | None
    AlarmTypes: AlarmTypes | None
    HistoryItemType: HistoryItemType | None
    StartDate: Timestamp | None
    EndDate: Timestamp | None
    MaxRecords: MaxRecords | None
    NextToken: NextToken | None
    ScanBy: ScanBy | None


class DescribeAlarmHistoryOutput(TypedDict, total=False):
    AlarmHistoryItems: AlarmHistoryItems | None
    NextToken: NextToken | None


class DescribeAlarmsForMetricInput(ServiceRequest):
    MetricName: MetricName
    Namespace: Namespace
    Statistic: Statistic | None
    ExtendedStatistic: ExtendedStatistic | None
    Dimensions: Dimensions | None
    Period: Period | None
    Unit: StandardUnit | None


class MetricAlarm(TypedDict, total=False):
    AlarmName: AlarmName | None
    AlarmArn: AlarmArn | None
    AlarmDescription: AlarmDescription | None
    AlarmConfigurationUpdatedTimestamp: Timestamp | None
    ActionsEnabled: ActionsEnabled | None
    OKActions: ResourceList | None
    AlarmActions: ResourceList | None
    InsufficientDataActions: ResourceList | None
    StateValue: StateValue | None
    StateReason: StateReason | None
    StateReasonData: StateReasonData | None
    StateUpdatedTimestamp: Timestamp | None
    MetricName: MetricName | None
    Namespace: Namespace | None
    Statistic: Statistic | None
    ExtendedStatistic: ExtendedStatistic | None
    Dimensions: Dimensions | None
    Period: Period | None
    Unit: StandardUnit | None
    EvaluationPeriods: EvaluationPeriods | None
    DatapointsToAlarm: DatapointsToAlarm | None
    Threshold: Threshold | None
    ComparisonOperator: ComparisonOperator | None
    TreatMissingData: TreatMissingData | None
    EvaluateLowSampleCountPercentile: EvaluateLowSampleCountPercentile | None
    Metrics: MetricDataQueries | None
    ThresholdMetricId: MetricId | None
    EvaluationState: EvaluationState | None
    StateTransitionedTimestamp: Timestamp | None


MetricAlarms = list[MetricAlarm]


class DescribeAlarmsForMetricOutput(TypedDict, total=False):
    MetricAlarms: MetricAlarms | None


class DescribeAlarmsInput(ServiceRequest):
    AlarmNames: AlarmNames | None
    AlarmNamePrefix: AlarmNamePrefix | None
    AlarmTypes: AlarmTypes | None
    ChildrenOfAlarmName: AlarmName | None
    ParentsOfAlarmName: AlarmName | None
    StateValue: StateValue | None
    ActionPrefix: ActionPrefix | None
    MaxRecords: MaxRecords | None
    NextToken: NextToken | None


class DescribeAlarmsOutput(TypedDict, total=False):
    CompositeAlarms: CompositeAlarms | None
    MetricAlarms: MetricAlarms | None
    NextToken: NextToken | None


class DescribeAnomalyDetectorsInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxReturnedResultsCount | None
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None
    AnomalyDetectorTypes: AnomalyDetectorTypes | None


class DescribeAnomalyDetectorsOutput(TypedDict, total=False):
    AnomalyDetectors: AnomalyDetectors | None
    NextToken: NextToken | None


class DescribeInsightRulesInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: InsightRuleMaxResults | None


class InsightRule(TypedDict, total=False):
    Name: InsightRuleName
    State: InsightRuleState
    Schema: InsightRuleSchema
    Definition: InsightRuleDefinition
    ManagedRule: InsightRuleIsManaged | None
    ApplyOnTransformedLogs: InsightRuleOnTransformedLogs | None


InsightRules = list[InsightRule]


class DescribeInsightRulesOutput(TypedDict, total=False):
    NextToken: NextToken | None
    InsightRules: InsightRules | None


class DimensionFilter(TypedDict, total=False):
    Name: DimensionName
    Value: DimensionValue | None


DimensionFilters = list[DimensionFilter]


class DisableAlarmActionsInput(ServiceRequest):
    AlarmNames: AlarmNames


class DisableInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class DisableInsightRulesOutput(TypedDict, total=False):
    Failures: BatchFailures | None


class EnableAlarmActionsInput(ServiceRequest):
    AlarmNames: AlarmNames


class EnableInsightRulesInput(ServiceRequest):
    RuleNames: InsightRuleNames


class EnableInsightRulesOutput(TypedDict, total=False):
    Failures: BatchFailures | None


EntityAttributesMap = dict[EntityAttributesMapKeyString, EntityAttributesMapValueString]
EntityKeyAttributesMap = dict[EntityKeyAttributesMapKeyString, EntityKeyAttributesMapValueString]


class Entity(TypedDict, total=False):
    KeyAttributes: EntityKeyAttributesMap | None
    Attributes: EntityAttributesMap | None


Values = list[DatapointValue]


class StatisticSet(TypedDict, total=False):
    SampleCount: DatapointValue
    Sum: DatapointValue
    Minimum: DatapointValue
    Maximum: DatapointValue


class MetricDatum(TypedDict, total=False):
    MetricName: MetricName
    Dimensions: Dimensions | None
    Timestamp: Timestamp | None
    Value: DatapointValue | None
    StatisticValues: StatisticSet | None
    Values: Values | None
    Counts: Counts | None
    Unit: StandardUnit | None
    StorageResolution: StorageResolution | None


MetricData = list[MetricDatum]


class EntityMetricData(TypedDict, total=False):
    Entity: Entity | None
    MetricData: MetricData | None


EntityMetricDataList = list[EntityMetricData]
ExtendedStatistics = list[ExtendedStatistic]


class GetDashboardInput(ServiceRequest):
    DashboardName: DashboardName


class GetDashboardOutput(TypedDict, total=False):
    DashboardArn: DashboardArn | None
    DashboardBody: DashboardBody | None
    DashboardName: DashboardName | None


InsightRuleMetricList = list[InsightRuleMetricName]


class GetInsightRuleReportInput(ServiceRequest):
    RuleName: InsightRuleName
    StartTime: Timestamp
    EndTime: Timestamp
    Period: Period
    MaxContributorCount: InsightRuleUnboundInteger | None
    Metrics: InsightRuleMetricList | None
    OrderBy: InsightRuleOrderBy | None


class InsightRuleMetricDatapoint(TypedDict, total=False):
    Timestamp: Timestamp
    UniqueContributors: InsightRuleUnboundDouble | None
    MaxContributorValue: InsightRuleUnboundDouble | None
    SampleCount: InsightRuleUnboundDouble | None
    Average: InsightRuleUnboundDouble | None
    Sum: InsightRuleUnboundDouble | None
    Minimum: InsightRuleUnboundDouble | None
    Maximum: InsightRuleUnboundDouble | None


InsightRuleMetricDatapoints = list[InsightRuleMetricDatapoint]


class InsightRuleContributorDatapoint(TypedDict, total=False):
    Timestamp: Timestamp
    ApproximateValue: InsightRuleUnboundDouble


InsightRuleContributorDatapoints = list[InsightRuleContributorDatapoint]
InsightRuleContributorKeys = list[InsightRuleContributorKey]


class InsightRuleContributor(TypedDict, total=False):
    Keys: InsightRuleContributorKeys
    ApproximateAggregateValue: InsightRuleUnboundDouble
    Datapoints: InsightRuleContributorDatapoints


InsightRuleContributors = list[InsightRuleContributor]
InsightRuleUnboundLong = int
InsightRuleContributorKeyLabels = list[InsightRuleContributorKeyLabel]


class GetInsightRuleReportOutput(TypedDict, total=False):
    KeyLabels: InsightRuleContributorKeyLabels | None
    AggregationStatistic: InsightRuleAggregationStatistic | None
    AggregateValue: InsightRuleUnboundDouble | None
    ApproximateUniqueCount: InsightRuleUnboundLong | None
    Contributors: InsightRuleContributors | None
    MetricDatapoints: InsightRuleMetricDatapoints | None


class LabelOptions(TypedDict, total=False):
    Timezone: GetMetricDataLabelTimezone | None


class GetMetricDataInput(ServiceRequest):
    MetricDataQueries: MetricDataQueries
    StartTime: Timestamp
    EndTime: Timestamp
    NextToken: NextToken | None
    ScanBy: ScanBy | None
    MaxDatapoints: GetMetricDataMaxDatapoints | None
    LabelOptions: LabelOptions | None


class MessageData(TypedDict, total=False):
    Code: MessageDataCode | None
    Value: MessageDataValue | None


MetricDataResultMessages = list[MessageData]
Timestamps = list[Timestamp]


class MetricDataResult(TypedDict, total=False):
    Id: MetricId | None
    Label: MetricLabel | None
    Timestamps: Timestamps | None
    Values: DatapointValues | None
    StatusCode: StatusCode | None
    Messages: MetricDataResultMessages | None


MetricDataResults = list[MetricDataResult]


class GetMetricDataOutput(TypedDict, total=False):
    MetricDataResults: MetricDataResults | None
    NextToken: NextToken | None
    Messages: MetricDataResultMessages | None


Statistics = list[Statistic]


class GetMetricStatisticsInput(ServiceRequest):
    Namespace: Namespace
    MetricName: MetricName
    Dimensions: Dimensions | None
    StartTime: Timestamp
    EndTime: Timestamp
    Period: Period
    Statistics: Statistics | None
    ExtendedStatistics: ExtendedStatistics | None
    Unit: StandardUnit | None


class GetMetricStatisticsOutput(TypedDict, total=False):
    Label: MetricLabel | None
    Datapoints: Datapoints | None


class GetMetricStreamInput(ServiceRequest):
    Name: MetricStreamName


MetricStreamStatisticsAdditionalStatistics = list[MetricStreamStatistic]


class MetricStreamStatisticsMetric(TypedDict, total=False):
    Namespace: Namespace
    MetricName: MetricName


MetricStreamStatisticsIncludeMetrics = list[MetricStreamStatisticsMetric]


class MetricStreamStatisticsConfiguration(TypedDict, total=False):
    IncludeMetrics: MetricStreamStatisticsIncludeMetrics
    AdditionalStatistics: MetricStreamStatisticsAdditionalStatistics


MetricStreamStatisticsConfigurations = list[MetricStreamStatisticsConfiguration]
MetricStreamFilterMetricNames = list[MetricName]


class MetricStreamFilter(TypedDict, total=False):
    Namespace: Namespace | None
    MetricNames: MetricStreamFilterMetricNames | None


MetricStreamFilters = list[MetricStreamFilter]


class GetMetricStreamOutput(TypedDict, total=False):
    Arn: AmazonResourceName | None
    Name: MetricStreamName | None
    IncludeFilters: MetricStreamFilters | None
    ExcludeFilters: MetricStreamFilters | None
    FirehoseArn: AmazonResourceName | None
    RoleArn: AmazonResourceName | None
    State: MetricStreamState | None
    CreationDate: Timestamp | None
    LastUpdateDate: Timestamp | None
    OutputFormat: MetricStreamOutputFormat | None
    StatisticsConfigurations: MetricStreamStatisticsConfigurations | None
    IncludeLinkedAccountsMetrics: IncludeLinkedAccountsMetrics | None


class GetMetricWidgetImageInput(ServiceRequest):
    MetricWidget: MetricWidget
    OutputFormat: OutputFormat | None


MetricWidgetImage = bytes


class GetMetricWidgetImageOutput(TypedDict, total=False):
    MetricWidgetImage: MetricWidgetImage | None


class ListDashboardsInput(ServiceRequest):
    DashboardNamePrefix: DashboardNamePrefix | None
    NextToken: NextToken | None


class ListDashboardsOutput(TypedDict, total=False):
    DashboardEntries: DashboardEntries | None
    NextToken: NextToken | None


class ListManagedInsightRulesInput(ServiceRequest):
    ResourceARN: AmazonResourceName
    NextToken: NextToken | None
    MaxResults: InsightRuleMaxResults | None


class ManagedRuleState(TypedDict, total=False):
    RuleName: InsightRuleName
    State: InsightRuleState


class ManagedRuleDescription(TypedDict, total=False):
    TemplateName: TemplateName | None
    ResourceARN: AmazonResourceName | None
    RuleState: ManagedRuleState | None


ManagedRuleDescriptions = list[ManagedRuleDescription]


class ListManagedInsightRulesOutput(TypedDict, total=False):
    ManagedRules: ManagedRuleDescriptions | None
    NextToken: NextToken | None


class ListMetricStreamsInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: ListMetricStreamsMaxResults | None


class MetricStreamEntry(TypedDict, total=False):
    Arn: AmazonResourceName | None
    CreationDate: Timestamp | None
    LastUpdateDate: Timestamp | None
    Name: MetricStreamName | None
    FirehoseArn: AmazonResourceName | None
    State: MetricStreamState | None
    OutputFormat: MetricStreamOutputFormat | None


MetricStreamEntries = list[MetricStreamEntry]


class ListMetricStreamsOutput(TypedDict, total=False):
    NextToken: NextToken | None
    Entries: MetricStreamEntries | None


class ListMetricsInput(ServiceRequest):
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: DimensionFilters | None
    NextToken: NextToken | None
    RecentlyActive: RecentlyActive | None
    IncludeLinkedAccounts: IncludeLinkedAccounts | None
    OwningAccount: AccountId | None


OwningAccounts = list[AccountId]
Metrics = list[Metric]


class ListMetricsOutput(TypedDict, total=False):
    Metrics: Metrics | None
    NextToken: NextToken | None
    OwningAccounts: OwningAccounts | None


class ListTagsForResourceInput(ServiceRequest):
    ResourceARN: AmazonResourceName


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: TagList | None


class ManagedRule(TypedDict, total=False):
    TemplateName: TemplateName
    ResourceARN: AmazonResourceName
    Tags: TagList | None


ManagedRules = list[ManagedRule]
MetricStreamNames = list[MetricStreamName]


class PutAnomalyDetectorInput(ServiceRequest):
    Namespace: Namespace | None
    MetricName: MetricName | None
    Dimensions: Dimensions | None
    Stat: AnomalyDetectorMetricStat | None
    Configuration: AnomalyDetectorConfiguration | None
    MetricCharacteristics: MetricCharacteristics | None
    SingleMetricAnomalyDetector: SingleMetricAnomalyDetector | None
    MetricMathAnomalyDetector: MetricMathAnomalyDetector | None


class PutAnomalyDetectorOutput(TypedDict, total=False):
    pass


class PutCompositeAlarmInput(ServiceRequest):
    ActionsEnabled: ActionsEnabled | None
    AlarmActions: ResourceList | None
    AlarmDescription: AlarmDescription | None
    AlarmName: AlarmName
    AlarmRule: AlarmRule
    InsufficientDataActions: ResourceList | None
    OKActions: ResourceList | None
    Tags: TagList | None
    ActionsSuppressor: AlarmArn | None
    ActionsSuppressorWaitPeriod: SuppressorPeriod | None
    ActionsSuppressorExtensionPeriod: SuppressorPeriod | None


class PutDashboardInput(ServiceRequest):
    DashboardName: DashboardName
    DashboardBody: DashboardBody


class PutDashboardOutput(TypedDict, total=False):
    DashboardValidationMessages: DashboardValidationMessages | None


class PutInsightRuleInput(ServiceRequest):
    RuleName: InsightRuleName
    RuleState: InsightRuleState | None
    RuleDefinition: InsightRuleDefinition
    Tags: TagList | None
    ApplyOnTransformedLogs: InsightRuleOnTransformedLogs | None


class PutInsightRuleOutput(TypedDict, total=False):
    pass


class PutManagedInsightRulesInput(ServiceRequest):
    ManagedRules: ManagedRules


class PutManagedInsightRulesOutput(TypedDict, total=False):
    Failures: BatchFailures | None


class PutMetricAlarmInput(ServiceRequest):
    AlarmName: AlarmName
    AlarmDescription: AlarmDescription | None
    ActionsEnabled: ActionsEnabled | None
    OKActions: ResourceList | None
    AlarmActions: ResourceList | None
    InsufficientDataActions: ResourceList | None
    MetricName: MetricName | None
    Namespace: Namespace | None
    Statistic: Statistic | None
    ExtendedStatistic: ExtendedStatistic | None
    Dimensions: Dimensions | None
    Period: Period | None
    Unit: StandardUnit | None
    EvaluationPeriods: EvaluationPeriods
    DatapointsToAlarm: DatapointsToAlarm | None
    Threshold: Threshold | None
    ComparisonOperator: ComparisonOperator
    TreatMissingData: TreatMissingData | None
    EvaluateLowSampleCountPercentile: EvaluateLowSampleCountPercentile | None
    Metrics: MetricDataQueries | None
    Tags: TagList | None
    ThresholdMetricId: MetricId | None


class PutMetricDataInput(ServiceRequest):
    Namespace: Namespace
    MetricData: MetricData | None
    EntityMetricData: EntityMetricDataList | None
    StrictEntityValidation: StrictEntityValidation | None


class PutMetricStreamInput(ServiceRequest):
    Name: MetricStreamName
    IncludeFilters: MetricStreamFilters | None
    ExcludeFilters: MetricStreamFilters | None
    FirehoseArn: AmazonResourceName
    RoleArn: AmazonResourceName
    OutputFormat: MetricStreamOutputFormat
    Tags: TagList | None
    StatisticsConfigurations: MetricStreamStatisticsConfigurations | None
    IncludeLinkedAccountsMetrics: IncludeLinkedAccountsMetrics | None


class PutMetricStreamOutput(TypedDict, total=False):
    Arn: AmazonResourceName | None


class SetAlarmStateInput(ServiceRequest):
    AlarmName: AlarmName
    StateValue: StateValue
    StateReason: StateReason
    StateReasonData: StateReasonData | None


class StartMetricStreamsInput(ServiceRequest):
    Names: MetricStreamNames


class StartMetricStreamsOutput(TypedDict, total=False):
    pass


class StopMetricStreamsInput(ServiceRequest):
    Names: MetricStreamNames


class StopMetricStreamsOutput(TypedDict, total=False):
    pass


TagKeyList = list[TagKey]


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
    service: str = "cloudwatch"
    version: str = "2010-08-01"

    @handler("DeleteAlarms")
    def delete_alarms(self, context: RequestContext, alarm_names: AlarmNames, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteAnomalyDetector")
    def delete_anomaly_detector(
        self,
        context: RequestContext,
        namespace: Namespace | None = None,
        metric_name: MetricName | None = None,
        dimensions: Dimensions | None = None,
        stat: AnomalyDetectorMetricStat | None = None,
        single_metric_anomaly_detector: SingleMetricAnomalyDetector | None = None,
        metric_math_anomaly_detector: MetricMathAnomalyDetector | None = None,
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

    @handler("DescribeAlarmContributors")
    def describe_alarm_contributors(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAlarmContributorsOutput:
        raise NotImplementedError

    @handler("DescribeAlarmHistory")
    def describe_alarm_history(
        self,
        context: RequestContext,
        alarm_name: AlarmName | None = None,
        alarm_contributor_id: ContributorId | None = None,
        alarm_types: AlarmTypes | None = None,
        history_item_type: HistoryItemType | None = None,
        start_date: Timestamp | None = None,
        end_date: Timestamp | None = None,
        max_records: MaxRecords | None = None,
        next_token: NextToken | None = None,
        scan_by: ScanBy | None = None,
        **kwargs,
    ) -> DescribeAlarmHistoryOutput:
        raise NotImplementedError

    @handler("DescribeAlarms")
    def describe_alarms(
        self,
        context: RequestContext,
        alarm_names: AlarmNames | None = None,
        alarm_name_prefix: AlarmNamePrefix | None = None,
        alarm_types: AlarmTypes | None = None,
        children_of_alarm_name: AlarmName | None = None,
        parents_of_alarm_name: AlarmName | None = None,
        state_value: StateValue | None = None,
        action_prefix: ActionPrefix | None = None,
        max_records: MaxRecords | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAlarmsOutput:
        raise NotImplementedError

    @handler("DescribeAlarmsForMetric")
    def describe_alarms_for_metric(
        self,
        context: RequestContext,
        metric_name: MetricName,
        namespace: Namespace,
        statistic: Statistic | None = None,
        extended_statistic: ExtendedStatistic | None = None,
        dimensions: Dimensions | None = None,
        period: Period | None = None,
        unit: StandardUnit | None = None,
        **kwargs,
    ) -> DescribeAlarmsForMetricOutput:
        raise NotImplementedError

    @handler("DescribeAnomalyDetectors")
    def describe_anomaly_detectors(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxReturnedResultsCount | None = None,
        namespace: Namespace | None = None,
        metric_name: MetricName | None = None,
        dimensions: Dimensions | None = None,
        anomaly_detector_types: AnomalyDetectorTypes | None = None,
        **kwargs,
    ) -> DescribeAnomalyDetectorsOutput:
        raise NotImplementedError

    @handler("DescribeInsightRules")
    def describe_insight_rules(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: InsightRuleMaxResults | None = None,
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
        max_contributor_count: InsightRuleUnboundInteger | None = None,
        metrics: InsightRuleMetricList | None = None,
        order_by: InsightRuleOrderBy | None = None,
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
        next_token: NextToken | None = None,
        scan_by: ScanBy | None = None,
        max_datapoints: GetMetricDataMaxDatapoints | None = None,
        label_options: LabelOptions | None = None,
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
        dimensions: Dimensions | None = None,
        statistics: Statistics | None = None,
        extended_statistics: ExtendedStatistics | None = None,
        unit: StandardUnit | None = None,
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
        output_format: OutputFormat | None = None,
        **kwargs,
    ) -> GetMetricWidgetImageOutput:
        raise NotImplementedError

    @handler("ListDashboards")
    def list_dashboards(
        self,
        context: RequestContext,
        dashboard_name_prefix: DashboardNamePrefix | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDashboardsOutput:
        raise NotImplementedError

    @handler("ListManagedInsightRules")
    def list_managed_insight_rules(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        next_token: NextToken | None = None,
        max_results: InsightRuleMaxResults | None = None,
        **kwargs,
    ) -> ListManagedInsightRulesOutput:
        raise NotImplementedError

    @handler("ListMetricStreams")
    def list_metric_streams(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: ListMetricStreamsMaxResults | None = None,
        **kwargs,
    ) -> ListMetricStreamsOutput:
        raise NotImplementedError

    @handler("ListMetrics")
    def list_metrics(
        self,
        context: RequestContext,
        namespace: Namespace | None = None,
        metric_name: MetricName | None = None,
        dimensions: DimensionFilters | None = None,
        next_token: NextToken | None = None,
        recently_active: RecentlyActive | None = None,
        include_linked_accounts: IncludeLinkedAccounts | None = None,
        owning_account: AccountId | None = None,
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
        namespace: Namespace | None = None,
        metric_name: MetricName | None = None,
        dimensions: Dimensions | None = None,
        stat: AnomalyDetectorMetricStat | None = None,
        configuration: AnomalyDetectorConfiguration | None = None,
        metric_characteristics: MetricCharacteristics | None = None,
        single_metric_anomaly_detector: SingleMetricAnomalyDetector | None = None,
        metric_math_anomaly_detector: MetricMathAnomalyDetector | None = None,
        **kwargs,
    ) -> PutAnomalyDetectorOutput:
        raise NotImplementedError

    @handler("PutCompositeAlarm")
    def put_composite_alarm(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        alarm_rule: AlarmRule,
        actions_enabled: ActionsEnabled | None = None,
        alarm_actions: ResourceList | None = None,
        alarm_description: AlarmDescription | None = None,
        insufficient_data_actions: ResourceList | None = None,
        ok_actions: ResourceList | None = None,
        tags: TagList | None = None,
        actions_suppressor: AlarmArn | None = None,
        actions_suppressor_wait_period: SuppressorPeriod | None = None,
        actions_suppressor_extension_period: SuppressorPeriod | None = None,
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
        rule_state: InsightRuleState | None = None,
        tags: TagList | None = None,
        apply_on_transformed_logs: InsightRuleOnTransformedLogs | None = None,
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
        alarm_description: AlarmDescription | None = None,
        actions_enabled: ActionsEnabled | None = None,
        ok_actions: ResourceList | None = None,
        alarm_actions: ResourceList | None = None,
        insufficient_data_actions: ResourceList | None = None,
        metric_name: MetricName | None = None,
        namespace: Namespace | None = None,
        statistic: Statistic | None = None,
        extended_statistic: ExtendedStatistic | None = None,
        dimensions: Dimensions | None = None,
        period: Period | None = None,
        unit: StandardUnit | None = None,
        datapoints_to_alarm: DatapointsToAlarm | None = None,
        threshold: Threshold | None = None,
        treat_missing_data: TreatMissingData | None = None,
        evaluate_low_sample_count_percentile: EvaluateLowSampleCountPercentile | None = None,
        metrics: MetricDataQueries | None = None,
        tags: TagList | None = None,
        threshold_metric_id: MetricId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutMetricData")
    def put_metric_data(
        self,
        context: RequestContext,
        namespace: Namespace,
        metric_data: MetricData | None = None,
        entity_metric_data: EntityMetricDataList | None = None,
        strict_entity_validation: StrictEntityValidation | None = None,
        **kwargs,
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
        include_filters: MetricStreamFilters | None = None,
        exclude_filters: MetricStreamFilters | None = None,
        tags: TagList | None = None,
        statistics_configurations: MetricStreamStatisticsConfigurations | None = None,
        include_linked_accounts_metrics: IncludeLinkedAccountsMetrics | None = None,
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
        state_reason_data: StateReasonData | None = None,
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
