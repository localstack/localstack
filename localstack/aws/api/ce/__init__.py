import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmortizedRecurringFee = str
AmortizedUpfrontFee = str
Arn = str
AttributeType = str
AttributeValue = str
CostCategoryMaxResults = int
CostCategoryName = str
CostCategoryValue = str
CoverageHoursPercentage = str
CoverageNormalizedUnitsPercentage = str
Entity = str
ErrorMessage = str
Estimated = bool
GenericBoolean = bool
GenericDouble = float
GenericString = str
GroupDefinitionKey = str
Key = str
MaxResults = int
MetricAmount = str
MetricName = str
MetricUnit = str
NetRISavings = str
NextPageToken = str
NonNegativeInteger = int
NullableNonNegativeDouble = float
OnDemandCost = str
OnDemandCostOfRIHoursUsed = str
OnDemandHours = str
OnDemandNormalizedUnits = str
PageSize = int
PredictionIntervalLevel = int
PurchasedHours = str
PurchasedUnits = str
RICostForUnusedHours = str
RealizedSavings = str
ReservationGroupKey = str
ReservationGroupValue = str
ReservedHours = str
ReservedNormalizedUnits = str
SavingsPlanArn = str
SearchString = str
SortDefinitionKey = str
SubscriberAddress = str
TagKey = str
TotalActualHours = str
TotalActualUnits = str
TotalAmortizedFee = str
TotalPotentialRISavings = str
TotalRunningHours = str
TotalRunningNormalizedUnits = str
UnrealizedSavings = str
UnusedHours = str
UnusedUnits = str
UtilizationPercentage = str
UtilizationPercentageInUnits = str
Value = str
YearMonthDay = str
ZonedDateTime = str


class AccountScope(str):
    PAYER = "PAYER"
    LINKED = "LINKED"


class AnomalyFeedbackType(str):
    YES = "YES"
    NO = "NO"
    PLANNED_ACTIVITY = "PLANNED_ACTIVITY"


class AnomalySubscriptionFrequency(str):
    DAILY = "DAILY"
    IMMEDIATE = "IMMEDIATE"
    WEEKLY = "WEEKLY"


class Context(str):
    COST_AND_USAGE = "COST_AND_USAGE"
    RESERVATIONS = "RESERVATIONS"
    SAVINGS_PLANS = "SAVINGS_PLANS"


class CostCategoryInheritedValueDimensionName(str):
    LINKED_ACCOUNT_NAME = "LINKED_ACCOUNT_NAME"
    TAG = "TAG"


class CostCategoryRuleType(str):
    REGULAR = "REGULAR"
    INHERITED_VALUE = "INHERITED_VALUE"


class CostCategoryRuleVersion(str):
    CostCategoryExpression_v1 = "CostCategoryExpression.v1"


class CostCategorySplitChargeMethod(str):
    FIXED = "FIXED"
    PROPORTIONAL = "PROPORTIONAL"
    EVEN = "EVEN"


class CostCategorySplitChargeRuleParameterType(str):
    ALLOCATION_PERCENTAGES = "ALLOCATION_PERCENTAGES"


class CostCategoryStatus(str):
    PROCESSING = "PROCESSING"
    APPLIED = "APPLIED"


class CostCategoryStatusComponent(str):
    COST_EXPLORER = "COST_EXPLORER"


class Dimension(str):
    AZ = "AZ"
    INSTANCE_TYPE = "INSTANCE_TYPE"
    LINKED_ACCOUNT = "LINKED_ACCOUNT"
    LINKED_ACCOUNT_NAME = "LINKED_ACCOUNT_NAME"
    OPERATION = "OPERATION"
    PURCHASE_TYPE = "PURCHASE_TYPE"
    REGION = "REGION"
    SERVICE = "SERVICE"
    SERVICE_CODE = "SERVICE_CODE"
    USAGE_TYPE = "USAGE_TYPE"
    USAGE_TYPE_GROUP = "USAGE_TYPE_GROUP"
    RECORD_TYPE = "RECORD_TYPE"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    TENANCY = "TENANCY"
    SCOPE = "SCOPE"
    PLATFORM = "PLATFORM"
    SUBSCRIPTION_ID = "SUBSCRIPTION_ID"
    LEGAL_ENTITY_NAME = "LEGAL_ENTITY_NAME"
    DEPLOYMENT_OPTION = "DEPLOYMENT_OPTION"
    DATABASE_ENGINE = "DATABASE_ENGINE"
    CACHE_ENGINE = "CACHE_ENGINE"
    INSTANCE_TYPE_FAMILY = "INSTANCE_TYPE_FAMILY"
    BILLING_ENTITY = "BILLING_ENTITY"
    RESERVATION_ID = "RESERVATION_ID"
    RESOURCE_ID = "RESOURCE_ID"
    RIGHTSIZING_TYPE = "RIGHTSIZING_TYPE"
    SAVINGS_PLANS_TYPE = "SAVINGS_PLANS_TYPE"
    SAVINGS_PLAN_ARN = "SAVINGS_PLAN_ARN"
    PAYMENT_OPTION = "PAYMENT_OPTION"
    AGREEMENT_END_DATE_TIME_AFTER = "AGREEMENT_END_DATE_TIME_AFTER"
    AGREEMENT_END_DATE_TIME_BEFORE = "AGREEMENT_END_DATE_TIME_BEFORE"
    INVOICING_ENTITY = "INVOICING_ENTITY"


class FindingReasonCode(str):
    CPU_OVER_PROVISIONED = "CPU_OVER_PROVISIONED"
    CPU_UNDER_PROVISIONED = "CPU_UNDER_PROVISIONED"
    MEMORY_OVER_PROVISIONED = "MEMORY_OVER_PROVISIONED"
    MEMORY_UNDER_PROVISIONED = "MEMORY_UNDER_PROVISIONED"
    EBS_THROUGHPUT_OVER_PROVISIONED = "EBS_THROUGHPUT_OVER_PROVISIONED"
    EBS_THROUGHPUT_UNDER_PROVISIONED = "EBS_THROUGHPUT_UNDER_PROVISIONED"
    EBS_IOPS_OVER_PROVISIONED = "EBS_IOPS_OVER_PROVISIONED"
    EBS_IOPS_UNDER_PROVISIONED = "EBS_IOPS_UNDER_PROVISIONED"
    NETWORK_BANDWIDTH_OVER_PROVISIONED = "NETWORK_BANDWIDTH_OVER_PROVISIONED"
    NETWORK_BANDWIDTH_UNDER_PROVISIONED = "NETWORK_BANDWIDTH_UNDER_PROVISIONED"
    NETWORK_PPS_OVER_PROVISIONED = "NETWORK_PPS_OVER_PROVISIONED"
    NETWORK_PPS_UNDER_PROVISIONED = "NETWORK_PPS_UNDER_PROVISIONED"
    DISK_IOPS_OVER_PROVISIONED = "DISK_IOPS_OVER_PROVISIONED"
    DISK_IOPS_UNDER_PROVISIONED = "DISK_IOPS_UNDER_PROVISIONED"
    DISK_THROUGHPUT_OVER_PROVISIONED = "DISK_THROUGHPUT_OVER_PROVISIONED"
    DISK_THROUGHPUT_UNDER_PROVISIONED = "DISK_THROUGHPUT_UNDER_PROVISIONED"


class Granularity(str):
    DAILY = "DAILY"
    MONTHLY = "MONTHLY"
    HOURLY = "HOURLY"


class GroupDefinitionType(str):
    DIMENSION = "DIMENSION"
    TAG = "TAG"
    COST_CATEGORY = "COST_CATEGORY"


class LookbackPeriodInDays(str):
    SEVEN_DAYS = "SEVEN_DAYS"
    THIRTY_DAYS = "THIRTY_DAYS"
    SIXTY_DAYS = "SIXTY_DAYS"


class MatchOption(str):
    EQUALS = "EQUALS"
    ABSENT = "ABSENT"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    CONTAINS = "CONTAINS"
    CASE_SENSITIVE = "CASE_SENSITIVE"
    CASE_INSENSITIVE = "CASE_INSENSITIVE"


class Metric(str):
    BLENDED_COST = "BLENDED_COST"
    UNBLENDED_COST = "UNBLENDED_COST"
    AMORTIZED_COST = "AMORTIZED_COST"
    NET_UNBLENDED_COST = "NET_UNBLENDED_COST"
    NET_AMORTIZED_COST = "NET_AMORTIZED_COST"
    USAGE_QUANTITY = "USAGE_QUANTITY"
    NORMALIZED_USAGE_AMOUNT = "NORMALIZED_USAGE_AMOUNT"


class MonitorDimension(str):
    SERVICE = "SERVICE"


class MonitorType(str):
    DIMENSIONAL = "DIMENSIONAL"
    CUSTOM = "CUSTOM"


class NumericOperator(str):
    EQUAL = "EQUAL"
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    BETWEEN = "BETWEEN"


class OfferingClass(str):
    STANDARD = "STANDARD"
    CONVERTIBLE = "CONVERTIBLE"


class PaymentOption(str):
    NO_UPFRONT = "NO_UPFRONT"
    PARTIAL_UPFRONT = "PARTIAL_UPFRONT"
    ALL_UPFRONT = "ALL_UPFRONT"
    LIGHT_UTILIZATION = "LIGHT_UTILIZATION"
    MEDIUM_UTILIZATION = "MEDIUM_UTILIZATION"
    HEAVY_UTILIZATION = "HEAVY_UTILIZATION"


class PlatformDifference(str):
    HYPERVISOR = "HYPERVISOR"
    NETWORK_INTERFACE = "NETWORK_INTERFACE"
    STORAGE_INTERFACE = "STORAGE_INTERFACE"
    INSTANCE_STORE_AVAILABILITY = "INSTANCE_STORE_AVAILABILITY"
    VIRTUALIZATION_TYPE = "VIRTUALIZATION_TYPE"


class RecommendationTarget(str):
    SAME_INSTANCE_FAMILY = "SAME_INSTANCE_FAMILY"
    CROSS_INSTANCE_FAMILY = "CROSS_INSTANCE_FAMILY"


class RightsizingType(str):
    TERMINATE = "TERMINATE"
    MODIFY = "MODIFY"


class SavingsPlansDataType(str):
    ATTRIBUTES = "ATTRIBUTES"
    UTILIZATION = "UTILIZATION"
    AMORTIZED_COMMITMENT = "AMORTIZED_COMMITMENT"
    SAVINGS = "SAVINGS"


class SortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class SubscriberStatus(str):
    CONFIRMED = "CONFIRMED"
    DECLINED = "DECLINED"


class SubscriberType(str):
    EMAIL = "EMAIL"
    SNS = "SNS"


class SupportedSavingsPlansType(str):
    COMPUTE_SP = "COMPUTE_SP"
    EC2_INSTANCE_SP = "EC2_INSTANCE_SP"
    SAGEMAKER_SP = "SAGEMAKER_SP"


class TermInYears(str):
    ONE_YEAR = "ONE_YEAR"
    THREE_YEARS = "THREE_YEARS"


class BillExpirationException(ServiceException):
    Message: Optional[ErrorMessage]


class DataUnavailableException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidNextTokenException(ServiceException):
    Message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class RequestChangedException(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class ServiceQuotaExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class UnknownMonitorException(ServiceException):
    Message: Optional[ErrorMessage]


class UnknownSubscriptionException(ServiceException):
    Message: Optional[ErrorMessage]


class UnresolvableUsageUnitException(ServiceException):
    Message: Optional[ErrorMessage]


class Impact(TypedDict, total=False):
    MaxImpact: GenericDouble
    TotalImpact: Optional[GenericDouble]


class AnomalyScore(TypedDict, total=False):
    MaxScore: GenericDouble
    CurrentScore: GenericDouble


class RootCause(TypedDict, total=False):
    Service: Optional[GenericString]
    Region: Optional[GenericString]
    LinkedAccount: Optional[GenericString]
    UsageType: Optional[GenericString]


RootCauses = List[RootCause]


class Anomaly(TypedDict, total=False):
    AnomalyId: GenericString
    AnomalyStartDate: Optional[YearMonthDay]
    AnomalyEndDate: Optional[YearMonthDay]
    DimensionValue: Optional[GenericString]
    RootCauses: Optional[RootCauses]
    AnomalyScore: AnomalyScore
    Impact: Impact
    MonitorArn: GenericString
    Feedback: Optional[AnomalyFeedbackType]


Anomalies = List[Anomaly]


class AnomalyDateInterval(TypedDict, total=False):
    StartDate: YearMonthDay
    EndDate: Optional[YearMonthDay]


MatchOptions = List[MatchOption]
Values = List[Value]


class CostCategoryValues(TypedDict, total=False):
    Key: Optional[CostCategoryName]
    Values: Optional[Values]
    MatchOptions: Optional[MatchOptions]


class TagValues(TypedDict, total=False):
    Key: Optional[TagKey]
    Values: Optional[Values]
    MatchOptions: Optional[MatchOptions]


class DimensionValues(TypedDict, total=False):
    Key: Optional[Dimension]
    Values: Optional[Values]
    MatchOptions: Optional[MatchOptions]


class Expression(TypedDict, total=False):
    Or: Optional["Expressions"]
    And: Optional["Expressions"]
    Not: Optional["Expression"]
    Dimensions: Optional["DimensionValues"]
    Tags: Optional["TagValues"]
    CostCategories: Optional["CostCategoryValues"]


Expressions = List[Expression]


class AnomalyMonitor(TypedDict, total=False):
    MonitorArn: Optional[GenericString]
    MonitorName: GenericString
    CreationDate: Optional[YearMonthDay]
    LastUpdatedDate: Optional[YearMonthDay]
    LastEvaluatedDate: Optional[YearMonthDay]
    MonitorType: MonitorType
    MonitorDimension: Optional[MonitorDimension]
    MonitorSpecification: Optional[Expression]
    DimensionalValueCount: Optional[NonNegativeInteger]


AnomalyMonitors = List[AnomalyMonitor]


class Subscriber(TypedDict, total=False):
    Address: Optional[SubscriberAddress]
    Type: Optional[SubscriberType]
    Status: Optional[SubscriberStatus]


Subscribers = List[Subscriber]
MonitorArnList = List[Arn]


class AnomalySubscription(TypedDict, total=False):
    SubscriptionArn: Optional[GenericString]
    AccountId: Optional[GenericString]
    MonitorArnList: MonitorArnList
    Subscribers: Subscribers
    Threshold: NullableNonNegativeDouble
    Frequency: AnomalySubscriptionFrequency
    SubscriptionName: GenericString


AnomalySubscriptions = List[AnomalySubscription]
Attributes = Dict[AttributeType, AttributeValue]


class CostCategoryProcessingStatus(TypedDict, total=False):
    Component: Optional[CostCategoryStatusComponent]
    Status: Optional[CostCategoryStatus]


CostCategoryProcessingStatusList = List[CostCategoryProcessingStatus]
CostCategorySplitChargeRuleParameterValuesList = List[GenericString]


class CostCategorySplitChargeRuleParameter(TypedDict, total=False):
    Type: CostCategorySplitChargeRuleParameterType
    Values: CostCategorySplitChargeRuleParameterValuesList


CostCategorySplitChargeRuleParametersList = List[CostCategorySplitChargeRuleParameter]
CostCategorySplitChargeRuleTargetsList = List[GenericString]


class CostCategorySplitChargeRule(TypedDict, total=False):
    Source: GenericString
    Targets: CostCategorySplitChargeRuleTargetsList
    Method: CostCategorySplitChargeMethod
    Parameters: Optional[CostCategorySplitChargeRuleParametersList]


CostCategorySplitChargeRulesList = List[CostCategorySplitChargeRule]


class CostCategoryInheritedValueDimension(TypedDict, total=False):
    DimensionName: Optional[CostCategoryInheritedValueDimensionName]
    DimensionKey: Optional[GenericString]


class CostCategoryRule(TypedDict, total=False):
    Value: Optional[CostCategoryValue]
    Rule: Optional[Expression]
    InheritedValue: Optional[CostCategoryInheritedValueDimension]
    Type: Optional[CostCategoryRuleType]


CostCategoryRulesList = List[CostCategoryRule]


class CostCategory(TypedDict, total=False):
    CostCategoryArn: Arn
    EffectiveStart: ZonedDateTime
    EffectiveEnd: Optional[ZonedDateTime]
    Name: CostCategoryName
    RuleVersion: CostCategoryRuleVersion
    Rules: CostCategoryRulesList
    SplitChargeRules: Optional[CostCategorySplitChargeRulesList]
    ProcessingStatus: Optional[CostCategoryProcessingStatusList]
    DefaultValue: Optional[CostCategoryValue]


CostCategoryNamesList = List[CostCategoryName]
CostCategoryValuesList = List[CostCategoryValue]


class CostCategoryReference(TypedDict, total=False):
    CostCategoryArn: Optional[Arn]
    Name: Optional[CostCategoryName]
    EffectiveStart: Optional[ZonedDateTime]
    EffectiveEnd: Optional[ZonedDateTime]
    NumberOfRules: Optional[NonNegativeInteger]
    ProcessingStatus: Optional[CostCategoryProcessingStatusList]
    Values: Optional[CostCategoryValuesList]
    DefaultValue: Optional[CostCategoryValue]


CostCategoryReferencesList = List[CostCategoryReference]


class CoverageCost(TypedDict, total=False):
    OnDemandCost: Optional[OnDemandCost]


class CoverageNormalizedUnits(TypedDict, total=False):
    OnDemandNormalizedUnits: Optional[OnDemandNormalizedUnits]
    ReservedNormalizedUnits: Optional[ReservedNormalizedUnits]
    TotalRunningNormalizedUnits: Optional[TotalRunningNormalizedUnits]
    CoverageNormalizedUnitsPercentage: Optional[CoverageNormalizedUnitsPercentage]


class CoverageHours(TypedDict, total=False):
    OnDemandHours: Optional[OnDemandHours]
    ReservedHours: Optional[ReservedHours]
    TotalRunningHours: Optional[TotalRunningHours]
    CoverageHoursPercentage: Optional[CoverageHoursPercentage]


class Coverage(TypedDict, total=False):
    CoverageHours: Optional[CoverageHours]
    CoverageNormalizedUnits: Optional[CoverageNormalizedUnits]
    CoverageCost: Optional[CoverageCost]


class ReservationCoverageGroup(TypedDict, total=False):
    Attributes: Optional[Attributes]
    Coverage: Optional[Coverage]


ReservationCoverageGroups = List[ReservationCoverageGroup]


class DateInterval(TypedDict, total=False):
    Start: YearMonthDay
    End: YearMonthDay


class CoverageByTime(TypedDict, total=False):
    TimePeriod: Optional[DateInterval]
    Groups: Optional[ReservationCoverageGroups]
    Total: Optional[Coverage]


CoveragesByTime = List[CoverageByTime]


class CreateAnomalyMonitorRequest(ServiceRequest):
    AnomalyMonitor: AnomalyMonitor


class CreateAnomalyMonitorResponse(TypedDict, total=False):
    MonitorArn: GenericString


class CreateAnomalySubscriptionRequest(ServiceRequest):
    AnomalySubscription: AnomalySubscription


class CreateAnomalySubscriptionResponse(TypedDict, total=False):
    SubscriptionArn: GenericString


class CreateCostCategoryDefinitionRequest(ServiceRequest):
    Name: CostCategoryName
    RuleVersion: CostCategoryRuleVersion
    Rules: CostCategoryRulesList
    DefaultValue: Optional[CostCategoryValue]
    SplitChargeRules: Optional[CostCategorySplitChargeRulesList]


class CreateCostCategoryDefinitionResponse(TypedDict, total=False):
    CostCategoryArn: Optional[Arn]
    EffectiveStart: Optional[ZonedDateTime]


class NetworkResourceUtilization(TypedDict, total=False):
    NetworkInBytesPerSecond: Optional[GenericString]
    NetworkOutBytesPerSecond: Optional[GenericString]
    NetworkPacketsInPerSecond: Optional[GenericString]
    NetworkPacketsOutPerSecond: Optional[GenericString]


class DiskResourceUtilization(TypedDict, total=False):
    DiskReadOpsPerSecond: Optional[GenericString]
    DiskWriteOpsPerSecond: Optional[GenericString]
    DiskReadBytesPerSecond: Optional[GenericString]
    DiskWriteBytesPerSecond: Optional[GenericString]


class EBSResourceUtilization(TypedDict, total=False):
    EbsReadOpsPerSecond: Optional[GenericString]
    EbsWriteOpsPerSecond: Optional[GenericString]
    EbsReadBytesPerSecond: Optional[GenericString]
    EbsWriteBytesPerSecond: Optional[GenericString]


class EC2ResourceUtilization(TypedDict, total=False):
    MaxCpuUtilizationPercentage: Optional[GenericString]
    MaxMemoryUtilizationPercentage: Optional[GenericString]
    MaxStorageUtilizationPercentage: Optional[GenericString]
    EBSResourceUtilization: Optional[EBSResourceUtilization]
    DiskResourceUtilization: Optional[DiskResourceUtilization]
    NetworkResourceUtilization: Optional[NetworkResourceUtilization]


class ResourceUtilization(TypedDict, total=False):
    EC2ResourceUtilization: Optional[EC2ResourceUtilization]


class EC2ResourceDetails(TypedDict, total=False):
    HourlyOnDemandRate: Optional[GenericString]
    InstanceType: Optional[GenericString]
    Platform: Optional[GenericString]
    Region: Optional[GenericString]
    Sku: Optional[GenericString]
    Memory: Optional[GenericString]
    NetworkPerformance: Optional[GenericString]
    Storage: Optional[GenericString]
    Vcpu: Optional[GenericString]


class ResourceDetails(TypedDict, total=False):
    EC2ResourceDetails: Optional[EC2ResourceDetails]


TagValuesList = List[TagValues]


class CurrentInstance(TypedDict, total=False):
    ResourceId: Optional[GenericString]
    InstanceName: Optional[GenericString]
    Tags: Optional[TagValuesList]
    ResourceDetails: Optional[ResourceDetails]
    ResourceUtilization: Optional[ResourceUtilization]
    ReservationCoveredHoursInLookbackPeriod: Optional[GenericString]
    SavingsPlansCoveredHoursInLookbackPeriod: Optional[GenericString]
    OnDemandHoursInLookbackPeriod: Optional[GenericString]
    TotalRunningHoursInLookbackPeriod: Optional[GenericString]
    MonthlyCost: Optional[GenericString]
    CurrencyCode: Optional[GenericString]


class DeleteAnomalyMonitorRequest(ServiceRequest):
    MonitorArn: GenericString


class DeleteAnomalyMonitorResponse(TypedDict, total=False):
    pass


class DeleteAnomalySubscriptionRequest(ServiceRequest):
    SubscriptionArn: GenericString


class DeleteAnomalySubscriptionResponse(TypedDict, total=False):
    pass


class DeleteCostCategoryDefinitionRequest(ServiceRequest):
    CostCategoryArn: Arn


class DeleteCostCategoryDefinitionResponse(TypedDict, total=False):
    CostCategoryArn: Optional[Arn]
    EffectiveEnd: Optional[ZonedDateTime]


class DescribeCostCategoryDefinitionRequest(ServiceRequest):
    CostCategoryArn: Arn
    EffectiveOn: Optional[ZonedDateTime]


class DescribeCostCategoryDefinitionResponse(TypedDict, total=False):
    CostCategory: Optional[CostCategory]


class DimensionValuesWithAttributes(TypedDict, total=False):
    Value: Optional[Value]
    Attributes: Optional[Attributes]


DimensionValuesWithAttributesList = List[DimensionValuesWithAttributes]


class EC2InstanceDetails(TypedDict, total=False):
    Family: Optional[GenericString]
    InstanceType: Optional[GenericString]
    Region: Optional[GenericString]
    AvailabilityZone: Optional[GenericString]
    Platform: Optional[GenericString]
    Tenancy: Optional[GenericString]
    CurrentGeneration: Optional[GenericBoolean]
    SizeFlexEligible: Optional[GenericBoolean]


class EC2Specification(TypedDict, total=False):
    OfferingClass: Optional[OfferingClass]


class ESInstanceDetails(TypedDict, total=False):
    InstanceClass: Optional[GenericString]
    InstanceSize: Optional[GenericString]
    Region: Optional[GenericString]
    CurrentGeneration: Optional[GenericBoolean]
    SizeFlexEligible: Optional[GenericBoolean]


class ElastiCacheInstanceDetails(TypedDict, total=False):
    Family: Optional[GenericString]
    NodeType: Optional[GenericString]
    Region: Optional[GenericString]
    ProductDescription: Optional[GenericString]
    CurrentGeneration: Optional[GenericBoolean]
    SizeFlexEligible: Optional[GenericBoolean]


FindingReasonCodes = List[FindingReasonCode]


class ForecastResult(TypedDict, total=False):
    TimePeriod: Optional[DateInterval]
    MeanValue: Optional[GenericString]
    PredictionIntervalLowerBound: Optional[GenericString]
    PredictionIntervalUpperBound: Optional[GenericString]


ForecastResultsByTime = List[ForecastResult]


class TotalImpactFilter(TypedDict, total=False):
    NumericOperator: NumericOperator
    StartValue: GenericDouble
    EndValue: Optional[GenericDouble]


class GetAnomaliesRequest(ServiceRequest):
    MonitorArn: Optional[GenericString]
    DateInterval: AnomalyDateInterval
    Feedback: Optional[AnomalyFeedbackType]
    TotalImpact: Optional[TotalImpactFilter]
    NextPageToken: Optional[NextPageToken]
    MaxResults: Optional[PageSize]


class GetAnomaliesResponse(TypedDict, total=False):
    Anomalies: Anomalies
    NextPageToken: Optional[NextPageToken]


class GetAnomalyMonitorsRequest(ServiceRequest):
    MonitorArnList: Optional[Values]
    NextPageToken: Optional[NextPageToken]
    MaxResults: Optional[PageSize]


class GetAnomalyMonitorsResponse(TypedDict, total=False):
    AnomalyMonitors: AnomalyMonitors
    NextPageToken: Optional[NextPageToken]


class GetAnomalySubscriptionsRequest(ServiceRequest):
    SubscriptionArnList: Optional[Values]
    MonitorArn: Optional[GenericString]
    NextPageToken: Optional[NextPageToken]
    MaxResults: Optional[PageSize]


class GetAnomalySubscriptionsResponse(TypedDict, total=False):
    AnomalySubscriptions: AnomalySubscriptions
    NextPageToken: Optional[NextPageToken]


class GroupDefinition(TypedDict, total=False):
    Type: Optional[GroupDefinitionType]
    Key: Optional[GroupDefinitionKey]


GroupDefinitions = List[GroupDefinition]
MetricNames = List[MetricName]


class GetCostAndUsageRequest(ServiceRequest):
    TimePeriod: DateInterval
    Granularity: Granularity
    Filter: Optional[Expression]
    Metrics: MetricNames
    GroupBy: Optional[GroupDefinitions]
    NextPageToken: Optional[NextPageToken]


class MetricValue(TypedDict, total=False):
    Amount: Optional[MetricAmount]
    Unit: Optional[MetricUnit]


Metrics = Dict[MetricName, MetricValue]
Keys = List[Key]


class Group(TypedDict, total=False):
    Keys: Optional[Keys]
    Metrics: Optional[Metrics]


Groups = List[Group]


class ResultByTime(TypedDict, total=False):
    TimePeriod: Optional[DateInterval]
    Total: Optional[Metrics]
    Groups: Optional[Groups]
    Estimated: Optional[Estimated]


ResultsByTime = List[ResultByTime]


class GetCostAndUsageResponse(TypedDict, total=False):
    NextPageToken: Optional[NextPageToken]
    GroupDefinitions: Optional[GroupDefinitions]
    ResultsByTime: Optional[ResultsByTime]
    DimensionValueAttributes: Optional[DimensionValuesWithAttributesList]


class GetCostAndUsageWithResourcesRequest(ServiceRequest):
    TimePeriod: DateInterval
    Granularity: Granularity
    Filter: Expression
    Metrics: Optional[MetricNames]
    GroupBy: Optional[GroupDefinitions]
    NextPageToken: Optional[NextPageToken]


class GetCostAndUsageWithResourcesResponse(TypedDict, total=False):
    NextPageToken: Optional[NextPageToken]
    GroupDefinitions: Optional[GroupDefinitions]
    ResultsByTime: Optional[ResultsByTime]
    DimensionValueAttributes: Optional[DimensionValuesWithAttributesList]


class SortDefinition(TypedDict, total=False):
    Key: SortDefinitionKey
    SortOrder: Optional[SortOrder]


SortDefinitions = List[SortDefinition]


class GetCostCategoriesRequest(ServiceRequest):
    SearchString: Optional[SearchString]
    TimePeriod: DateInterval
    CostCategoryName: Optional[CostCategoryName]
    Filter: Optional[Expression]
    SortBy: Optional[SortDefinitions]
    MaxResults: Optional[MaxResults]
    NextPageToken: Optional[NextPageToken]


class GetCostCategoriesResponse(TypedDict, total=False):
    NextPageToken: Optional[NextPageToken]
    CostCategoryNames: Optional[CostCategoryNamesList]
    CostCategoryValues: Optional[CostCategoryValuesList]
    ReturnSize: PageSize
    TotalSize: PageSize


class GetCostForecastRequest(ServiceRequest):
    TimePeriod: DateInterval
    Metric: Metric
    Granularity: Granularity
    Filter: Optional[Expression]
    PredictionIntervalLevel: Optional[PredictionIntervalLevel]


class GetCostForecastResponse(TypedDict, total=False):
    Total: Optional[MetricValue]
    ForecastResultsByTime: Optional[ForecastResultsByTime]


class GetDimensionValuesRequest(ServiceRequest):
    SearchString: Optional[SearchString]
    TimePeriod: DateInterval
    Dimension: Dimension
    Context: Optional[Context]
    Filter: Optional[Expression]
    SortBy: Optional[SortDefinitions]
    MaxResults: Optional[MaxResults]
    NextPageToken: Optional[NextPageToken]


class GetDimensionValuesResponse(TypedDict, total=False):
    DimensionValues: DimensionValuesWithAttributesList
    ReturnSize: PageSize
    TotalSize: PageSize
    NextPageToken: Optional[NextPageToken]


class GetReservationCoverageRequest(ServiceRequest):
    TimePeriod: DateInterval
    GroupBy: Optional[GroupDefinitions]
    Granularity: Optional[Granularity]
    Filter: Optional[Expression]
    Metrics: Optional[MetricNames]
    NextPageToken: Optional[NextPageToken]
    SortBy: Optional[SortDefinition]
    MaxResults: Optional[MaxResults]


class GetReservationCoverageResponse(TypedDict, total=False):
    CoveragesByTime: CoveragesByTime
    Total: Optional[Coverage]
    NextPageToken: Optional[NextPageToken]


class ServiceSpecification(TypedDict, total=False):
    EC2Specification: Optional[EC2Specification]


class GetReservationPurchaseRecommendationRequest(ServiceRequest):
    AccountId: Optional[GenericString]
    Service: GenericString
    Filter: Optional[Expression]
    AccountScope: Optional[AccountScope]
    LookbackPeriodInDays: Optional[LookbackPeriodInDays]
    TermInYears: Optional[TermInYears]
    PaymentOption: Optional[PaymentOption]
    ServiceSpecification: Optional[ServiceSpecification]
    PageSize: Optional[NonNegativeInteger]
    NextPageToken: Optional[NextPageToken]


class ReservationPurchaseRecommendationSummary(TypedDict, total=False):
    TotalEstimatedMonthlySavingsAmount: Optional[GenericString]
    TotalEstimatedMonthlySavingsPercentage: Optional[GenericString]
    CurrencyCode: Optional[GenericString]


class RedshiftInstanceDetails(TypedDict, total=False):
    Family: Optional[GenericString]
    NodeType: Optional[GenericString]
    Region: Optional[GenericString]
    CurrentGeneration: Optional[GenericBoolean]
    SizeFlexEligible: Optional[GenericBoolean]


class RDSInstanceDetails(TypedDict, total=False):
    Family: Optional[GenericString]
    InstanceType: Optional[GenericString]
    Region: Optional[GenericString]
    DatabaseEngine: Optional[GenericString]
    DatabaseEdition: Optional[GenericString]
    DeploymentOption: Optional[GenericString]
    LicenseModel: Optional[GenericString]
    CurrentGeneration: Optional[GenericBoolean]
    SizeFlexEligible: Optional[GenericBoolean]


class InstanceDetails(TypedDict, total=False):
    EC2InstanceDetails: Optional[EC2InstanceDetails]
    RDSInstanceDetails: Optional[RDSInstanceDetails]
    RedshiftInstanceDetails: Optional[RedshiftInstanceDetails]
    ElastiCacheInstanceDetails: Optional[ElastiCacheInstanceDetails]
    ESInstanceDetails: Optional[ESInstanceDetails]


class ReservationPurchaseRecommendationDetail(TypedDict, total=False):
    AccountId: Optional[GenericString]
    InstanceDetails: Optional[InstanceDetails]
    RecommendedNumberOfInstancesToPurchase: Optional[GenericString]
    RecommendedNormalizedUnitsToPurchase: Optional[GenericString]
    MinimumNumberOfInstancesUsedPerHour: Optional[GenericString]
    MinimumNormalizedUnitsUsedPerHour: Optional[GenericString]
    MaximumNumberOfInstancesUsedPerHour: Optional[GenericString]
    MaximumNormalizedUnitsUsedPerHour: Optional[GenericString]
    AverageNumberOfInstancesUsedPerHour: Optional[GenericString]
    AverageNormalizedUnitsUsedPerHour: Optional[GenericString]
    AverageUtilization: Optional[GenericString]
    EstimatedBreakEvenInMonths: Optional[GenericString]
    CurrencyCode: Optional[GenericString]
    EstimatedMonthlySavingsAmount: Optional[GenericString]
    EstimatedMonthlySavingsPercentage: Optional[GenericString]
    EstimatedMonthlyOnDemandCost: Optional[GenericString]
    EstimatedReservationCostForLookbackPeriod: Optional[GenericString]
    UpfrontCost: Optional[GenericString]
    RecurringStandardMonthlyCost: Optional[GenericString]


ReservationPurchaseRecommendationDetails = List[ReservationPurchaseRecommendationDetail]


class ReservationPurchaseRecommendation(TypedDict, total=False):
    AccountScope: Optional[AccountScope]
    LookbackPeriodInDays: Optional[LookbackPeriodInDays]
    TermInYears: Optional[TermInYears]
    PaymentOption: Optional[PaymentOption]
    ServiceSpecification: Optional[ServiceSpecification]
    RecommendationDetails: Optional[ReservationPurchaseRecommendationDetails]
    RecommendationSummary: Optional[ReservationPurchaseRecommendationSummary]


ReservationPurchaseRecommendations = List[ReservationPurchaseRecommendation]


class ReservationPurchaseRecommendationMetadata(TypedDict, total=False):
    RecommendationId: Optional[GenericString]
    GenerationTimestamp: Optional[GenericString]


class GetReservationPurchaseRecommendationResponse(TypedDict, total=False):
    Metadata: Optional[ReservationPurchaseRecommendationMetadata]
    Recommendations: Optional[ReservationPurchaseRecommendations]
    NextPageToken: Optional[NextPageToken]


class GetReservationUtilizationRequest(ServiceRequest):
    TimePeriod: DateInterval
    GroupBy: Optional[GroupDefinitions]
    Granularity: Optional[Granularity]
    Filter: Optional[Expression]
    SortBy: Optional[SortDefinition]
    NextPageToken: Optional[NextPageToken]
    MaxResults: Optional[MaxResults]


class ReservationAggregates(TypedDict, total=False):
    UtilizationPercentage: Optional[UtilizationPercentage]
    UtilizationPercentageInUnits: Optional[UtilizationPercentageInUnits]
    PurchasedHours: Optional[PurchasedHours]
    PurchasedUnits: Optional[PurchasedUnits]
    TotalActualHours: Optional[TotalActualHours]
    TotalActualUnits: Optional[TotalActualUnits]
    UnusedHours: Optional[UnusedHours]
    UnusedUnits: Optional[UnusedUnits]
    OnDemandCostOfRIHoursUsed: Optional[OnDemandCostOfRIHoursUsed]
    NetRISavings: Optional[NetRISavings]
    TotalPotentialRISavings: Optional[TotalPotentialRISavings]
    AmortizedUpfrontFee: Optional[AmortizedUpfrontFee]
    AmortizedRecurringFee: Optional[AmortizedRecurringFee]
    TotalAmortizedFee: Optional[TotalAmortizedFee]
    RICostForUnusedHours: Optional[RICostForUnusedHours]
    RealizedSavings: Optional[RealizedSavings]
    UnrealizedSavings: Optional[UnrealizedSavings]


class ReservationUtilizationGroup(TypedDict, total=False):
    Key: Optional[ReservationGroupKey]
    Value: Optional[ReservationGroupValue]
    Attributes: Optional[Attributes]
    Utilization: Optional[ReservationAggregates]


ReservationUtilizationGroups = List[ReservationUtilizationGroup]


class UtilizationByTime(TypedDict, total=False):
    TimePeriod: Optional[DateInterval]
    Groups: Optional[ReservationUtilizationGroups]
    Total: Optional[ReservationAggregates]


UtilizationsByTime = List[UtilizationByTime]


class GetReservationUtilizationResponse(TypedDict, total=False):
    UtilizationsByTime: UtilizationsByTime
    Total: Optional[ReservationAggregates]
    NextPageToken: Optional[NextPageToken]


class RightsizingRecommendationConfiguration(TypedDict, total=False):
    RecommendationTarget: RecommendationTarget
    BenefitsConsidered: GenericBoolean


class GetRightsizingRecommendationRequest(ServiceRequest):
    Filter: Optional[Expression]
    Configuration: Optional[RightsizingRecommendationConfiguration]
    Service: GenericString
    PageSize: Optional[NonNegativeInteger]
    NextPageToken: Optional[NextPageToken]


class TerminateRecommendationDetail(TypedDict, total=False):
    EstimatedMonthlySavings: Optional[GenericString]
    CurrencyCode: Optional[GenericString]


PlatformDifferences = List[PlatformDifference]


class TargetInstance(TypedDict, total=False):
    EstimatedMonthlyCost: Optional[GenericString]
    EstimatedMonthlySavings: Optional[GenericString]
    CurrencyCode: Optional[GenericString]
    DefaultTargetInstance: Optional[GenericBoolean]
    ResourceDetails: Optional[ResourceDetails]
    ExpectedResourceUtilization: Optional[ResourceUtilization]
    PlatformDifferences: Optional[PlatformDifferences]


TargetInstancesList = List[TargetInstance]


class ModifyRecommendationDetail(TypedDict, total=False):
    TargetInstances: Optional[TargetInstancesList]


class RightsizingRecommendation(TypedDict, total=False):
    AccountId: Optional[GenericString]
    CurrentInstance: Optional[CurrentInstance]
    RightsizingType: Optional[RightsizingType]
    ModifyRecommendationDetail: Optional[ModifyRecommendationDetail]
    TerminateRecommendationDetail: Optional[TerminateRecommendationDetail]
    FindingReasonCodes: Optional[FindingReasonCodes]


RightsizingRecommendationList = List[RightsizingRecommendation]


class RightsizingRecommendationSummary(TypedDict, total=False):
    TotalRecommendationCount: Optional[GenericString]
    EstimatedTotalMonthlySavingsAmount: Optional[GenericString]
    SavingsCurrencyCode: Optional[GenericString]
    SavingsPercentage: Optional[GenericString]


class RightsizingRecommendationMetadata(TypedDict, total=False):
    RecommendationId: Optional[GenericString]
    GenerationTimestamp: Optional[GenericString]
    LookbackPeriodInDays: Optional[LookbackPeriodInDays]
    AdditionalMetadata: Optional[GenericString]


class GetRightsizingRecommendationResponse(TypedDict, total=False):
    Metadata: Optional[RightsizingRecommendationMetadata]
    Summary: Optional[RightsizingRecommendationSummary]
    RightsizingRecommendations: Optional[RightsizingRecommendationList]
    NextPageToken: Optional[NextPageToken]
    Configuration: Optional[RightsizingRecommendationConfiguration]


class GetSavingsPlansCoverageRequest(ServiceRequest):
    TimePeriod: DateInterval
    GroupBy: Optional[GroupDefinitions]
    Granularity: Optional[Granularity]
    Filter: Optional[Expression]
    Metrics: Optional[MetricNames]
    NextToken: Optional[NextPageToken]
    MaxResults: Optional[MaxResults]
    SortBy: Optional[SortDefinition]


class SavingsPlansCoverageData(TypedDict, total=False):
    SpendCoveredBySavingsPlans: Optional[GenericString]
    OnDemandCost: Optional[GenericString]
    TotalCost: Optional[GenericString]
    CoveragePercentage: Optional[GenericString]


class SavingsPlansCoverage(TypedDict, total=False):
    Attributes: Optional[Attributes]
    Coverage: Optional[SavingsPlansCoverageData]
    TimePeriod: Optional[DateInterval]


SavingsPlansCoverages = List[SavingsPlansCoverage]


class GetSavingsPlansCoverageResponse(TypedDict, total=False):
    SavingsPlansCoverages: SavingsPlansCoverages
    NextToken: Optional[NextPageToken]


class GetSavingsPlansPurchaseRecommendationRequest(ServiceRequest):
    SavingsPlansType: SupportedSavingsPlansType
    TermInYears: TermInYears
    PaymentOption: PaymentOption
    AccountScope: Optional[AccountScope]
    NextPageToken: Optional[NextPageToken]
    PageSize: Optional[NonNegativeInteger]
    LookbackPeriodInDays: LookbackPeriodInDays
    Filter: Optional[Expression]


class SavingsPlansPurchaseRecommendationSummary(TypedDict, total=False):
    EstimatedROI: Optional[GenericString]
    CurrencyCode: Optional[GenericString]
    EstimatedTotalCost: Optional[GenericString]
    CurrentOnDemandSpend: Optional[GenericString]
    EstimatedSavingsAmount: Optional[GenericString]
    TotalRecommendationCount: Optional[GenericString]
    DailyCommitmentToPurchase: Optional[GenericString]
    HourlyCommitmentToPurchase: Optional[GenericString]
    EstimatedSavingsPercentage: Optional[GenericString]
    EstimatedMonthlySavingsAmount: Optional[GenericString]
    EstimatedOnDemandCostWithCurrentCommitment: Optional[GenericString]


class SavingsPlansDetails(TypedDict, total=False):
    Region: Optional[GenericString]
    InstanceFamily: Optional[GenericString]
    OfferingId: Optional[GenericString]


class SavingsPlansPurchaseRecommendationDetail(TypedDict, total=False):
    SavingsPlansDetails: Optional[SavingsPlansDetails]
    AccountId: Optional[GenericString]
    UpfrontCost: Optional[GenericString]
    EstimatedROI: Optional[GenericString]
    CurrencyCode: Optional[GenericString]
    EstimatedSPCost: Optional[GenericString]
    EstimatedOnDemandCost: Optional[GenericString]
    EstimatedOnDemandCostWithCurrentCommitment: Optional[GenericString]
    EstimatedSavingsAmount: Optional[GenericString]
    EstimatedSavingsPercentage: Optional[GenericString]
    HourlyCommitmentToPurchase: Optional[GenericString]
    EstimatedAverageUtilization: Optional[GenericString]
    EstimatedMonthlySavingsAmount: Optional[GenericString]
    CurrentMinimumHourlyOnDemandSpend: Optional[GenericString]
    CurrentMaximumHourlyOnDemandSpend: Optional[GenericString]
    CurrentAverageHourlyOnDemandSpend: Optional[GenericString]


SavingsPlansPurchaseRecommendationDetailList = List[SavingsPlansPurchaseRecommendationDetail]


class SavingsPlansPurchaseRecommendation(TypedDict, total=False):
    AccountScope: Optional[AccountScope]
    SavingsPlansType: Optional[SupportedSavingsPlansType]
    TermInYears: Optional[TermInYears]
    PaymentOption: Optional[PaymentOption]
    LookbackPeriodInDays: Optional[LookbackPeriodInDays]
    SavingsPlansPurchaseRecommendationDetails: Optional[
        SavingsPlansPurchaseRecommendationDetailList
    ]
    SavingsPlansPurchaseRecommendationSummary: Optional[SavingsPlansPurchaseRecommendationSummary]


class SavingsPlansPurchaseRecommendationMetadata(TypedDict, total=False):
    RecommendationId: Optional[GenericString]
    GenerationTimestamp: Optional[GenericString]
    AdditionalMetadata: Optional[GenericString]


class GetSavingsPlansPurchaseRecommendationResponse(TypedDict, total=False):
    Metadata: Optional[SavingsPlansPurchaseRecommendationMetadata]
    SavingsPlansPurchaseRecommendation: Optional[SavingsPlansPurchaseRecommendation]
    NextPageToken: Optional[NextPageToken]


SavingsPlansDataTypes = List[SavingsPlansDataType]


class GetSavingsPlansUtilizationDetailsRequest(ServiceRequest):
    TimePeriod: DateInterval
    Filter: Optional[Expression]
    DataType: Optional[SavingsPlansDataTypes]
    NextToken: Optional[NextPageToken]
    MaxResults: Optional[MaxResults]
    SortBy: Optional[SortDefinition]


class SavingsPlansAmortizedCommitment(TypedDict, total=False):
    AmortizedRecurringCommitment: Optional[GenericString]
    AmortizedUpfrontCommitment: Optional[GenericString]
    TotalAmortizedCommitment: Optional[GenericString]


class SavingsPlansSavings(TypedDict, total=False):
    NetSavings: Optional[GenericString]
    OnDemandCostEquivalent: Optional[GenericString]


class SavingsPlansUtilization(TypedDict, total=False):
    TotalCommitment: Optional[GenericString]
    UsedCommitment: Optional[GenericString]
    UnusedCommitment: Optional[GenericString]
    UtilizationPercentage: Optional[GenericString]


class SavingsPlansUtilizationAggregates(TypedDict, total=False):
    Utilization: SavingsPlansUtilization
    Savings: Optional[SavingsPlansSavings]
    AmortizedCommitment: Optional[SavingsPlansAmortizedCommitment]


class SavingsPlansUtilizationDetail(TypedDict, total=False):
    SavingsPlanArn: Optional[SavingsPlanArn]
    Attributes: Optional[Attributes]
    Utilization: Optional[SavingsPlansUtilization]
    Savings: Optional[SavingsPlansSavings]
    AmortizedCommitment: Optional[SavingsPlansAmortizedCommitment]


SavingsPlansUtilizationDetails = List[SavingsPlansUtilizationDetail]


class GetSavingsPlansUtilizationDetailsResponse(TypedDict, total=False):
    SavingsPlansUtilizationDetails: SavingsPlansUtilizationDetails
    Total: Optional[SavingsPlansUtilizationAggregates]
    TimePeriod: DateInterval
    NextToken: Optional[NextPageToken]


class GetSavingsPlansUtilizationRequest(ServiceRequest):
    TimePeriod: DateInterval
    Granularity: Optional[Granularity]
    Filter: Optional[Expression]
    SortBy: Optional[SortDefinition]


class SavingsPlansUtilizationByTime(TypedDict, total=False):
    TimePeriod: DateInterval
    Utilization: SavingsPlansUtilization
    Savings: Optional[SavingsPlansSavings]
    AmortizedCommitment: Optional[SavingsPlansAmortizedCommitment]


SavingsPlansUtilizationsByTime = List[SavingsPlansUtilizationByTime]


class GetSavingsPlansUtilizationResponse(TypedDict, total=False):
    SavingsPlansUtilizationsByTime: Optional[SavingsPlansUtilizationsByTime]
    Total: SavingsPlansUtilizationAggregates


class GetTagsRequest(ServiceRequest):
    SearchString: Optional[SearchString]
    TimePeriod: DateInterval
    TagKey: Optional[TagKey]
    Filter: Optional[Expression]
    SortBy: Optional[SortDefinitions]
    MaxResults: Optional[MaxResults]
    NextPageToken: Optional[NextPageToken]


TagList = List[Entity]


class GetTagsResponse(TypedDict, total=False):
    NextPageToken: Optional[NextPageToken]
    Tags: TagList
    ReturnSize: PageSize
    TotalSize: PageSize


class GetUsageForecastRequest(ServiceRequest):
    TimePeriod: DateInterval
    Metric: Metric
    Granularity: Granularity
    Filter: Optional[Expression]
    PredictionIntervalLevel: Optional[PredictionIntervalLevel]


class GetUsageForecastResponse(TypedDict, total=False):
    Total: Optional[MetricValue]
    ForecastResultsByTime: Optional[ForecastResultsByTime]


class ListCostCategoryDefinitionsRequest(ServiceRequest):
    EffectiveOn: Optional[ZonedDateTime]
    NextToken: Optional[NextPageToken]
    MaxResults: Optional[CostCategoryMaxResults]


class ListCostCategoryDefinitionsResponse(TypedDict, total=False):
    CostCategoryReferences: Optional[CostCategoryReferencesList]
    NextToken: Optional[NextPageToken]


class ProvideAnomalyFeedbackRequest(ServiceRequest):
    AnomalyId: GenericString
    Feedback: AnomalyFeedbackType


class ProvideAnomalyFeedbackResponse(TypedDict, total=False):
    AnomalyId: GenericString


class UpdateAnomalyMonitorRequest(ServiceRequest):
    MonitorArn: GenericString
    MonitorName: Optional[GenericString]


class UpdateAnomalyMonitorResponse(TypedDict, total=False):
    MonitorArn: GenericString


class UpdateAnomalySubscriptionRequest(ServiceRequest):
    SubscriptionArn: GenericString
    Threshold: Optional[NullableNonNegativeDouble]
    Frequency: Optional[AnomalySubscriptionFrequency]
    MonitorArnList: Optional[MonitorArnList]
    Subscribers: Optional[Subscribers]
    SubscriptionName: Optional[GenericString]


class UpdateAnomalySubscriptionResponse(TypedDict, total=False):
    SubscriptionArn: GenericString


class UpdateCostCategoryDefinitionRequest(ServiceRequest):
    CostCategoryArn: Arn
    RuleVersion: CostCategoryRuleVersion
    Rules: CostCategoryRulesList
    DefaultValue: Optional[CostCategoryValue]
    SplitChargeRules: Optional[CostCategorySplitChargeRulesList]


class UpdateCostCategoryDefinitionResponse(TypedDict, total=False):
    CostCategoryArn: Optional[Arn]
    EffectiveStart: Optional[ZonedDateTime]


class CeApi:

    service = "ce"
    version = "2017-10-25"

    @handler("CreateAnomalyMonitor")
    def create_anomaly_monitor(
        self, context: RequestContext, anomaly_monitor: AnomalyMonitor
    ) -> CreateAnomalyMonitorResponse:
        raise NotImplementedError

    @handler("CreateAnomalySubscription")
    def create_anomaly_subscription(
        self, context: RequestContext, anomaly_subscription: AnomalySubscription
    ) -> CreateAnomalySubscriptionResponse:
        raise NotImplementedError

    @handler("CreateCostCategoryDefinition")
    def create_cost_category_definition(
        self,
        context: RequestContext,
        name: CostCategoryName,
        rule_version: CostCategoryRuleVersion,
        rules: CostCategoryRulesList,
        default_value: CostCategoryValue = None,
        split_charge_rules: CostCategorySplitChargeRulesList = None,
    ) -> CreateCostCategoryDefinitionResponse:
        raise NotImplementedError

    @handler("DeleteAnomalyMonitor")
    def delete_anomaly_monitor(
        self, context: RequestContext, monitor_arn: GenericString
    ) -> DeleteAnomalyMonitorResponse:
        raise NotImplementedError

    @handler("DeleteAnomalySubscription")
    def delete_anomaly_subscription(
        self, context: RequestContext, subscription_arn: GenericString
    ) -> DeleteAnomalySubscriptionResponse:
        raise NotImplementedError

    @handler("DeleteCostCategoryDefinition")
    def delete_cost_category_definition(
        self, context: RequestContext, cost_category_arn: Arn
    ) -> DeleteCostCategoryDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeCostCategoryDefinition")
    def describe_cost_category_definition(
        self, context: RequestContext, cost_category_arn: Arn, effective_on: ZonedDateTime = None
    ) -> DescribeCostCategoryDefinitionResponse:
        raise NotImplementedError

    @handler("GetAnomalies")
    def get_anomalies(
        self,
        context: RequestContext,
        date_interval: AnomalyDateInterval,
        monitor_arn: GenericString = None,
        feedback: AnomalyFeedbackType = None,
        total_impact: TotalImpactFilter = None,
        next_page_token: NextPageToken = None,
        max_results: PageSize = None,
    ) -> GetAnomaliesResponse:
        raise NotImplementedError

    @handler("GetAnomalyMonitors")
    def get_anomaly_monitors(
        self,
        context: RequestContext,
        monitor_arn_list: Values = None,
        next_page_token: NextPageToken = None,
        max_results: PageSize = None,
    ) -> GetAnomalyMonitorsResponse:
        raise NotImplementedError

    @handler("GetAnomalySubscriptions")
    def get_anomaly_subscriptions(
        self,
        context: RequestContext,
        subscription_arn_list: Values = None,
        monitor_arn: GenericString = None,
        next_page_token: NextPageToken = None,
        max_results: PageSize = None,
    ) -> GetAnomalySubscriptionsResponse:
        raise NotImplementedError

    @handler("GetCostAndUsage")
    def get_cost_and_usage(
        self,
        context: RequestContext,
        time_period: DateInterval,
        granularity: Granularity,
        metrics: MetricNames,
        filter: Expression = None,
        group_by: GroupDefinitions = None,
        next_page_token: NextPageToken = None,
    ) -> GetCostAndUsageResponse:
        raise NotImplementedError

    @handler("GetCostAndUsageWithResources")
    def get_cost_and_usage_with_resources(
        self,
        context: RequestContext,
        time_period: DateInterval,
        granularity: Granularity,
        filter: Expression,
        metrics: MetricNames = None,
        group_by: GroupDefinitions = None,
        next_page_token: NextPageToken = None,
    ) -> GetCostAndUsageWithResourcesResponse:
        raise NotImplementedError

    @handler("GetCostCategories")
    def get_cost_categories(
        self,
        context: RequestContext,
        time_period: DateInterval,
        search_string: SearchString = None,
        cost_category_name: CostCategoryName = None,
        filter: Expression = None,
        sort_by: SortDefinitions = None,
        max_results: MaxResults = None,
        next_page_token: NextPageToken = None,
    ) -> GetCostCategoriesResponse:
        raise NotImplementedError

    @handler("GetCostForecast")
    def get_cost_forecast(
        self,
        context: RequestContext,
        time_period: DateInterval,
        metric: Metric,
        granularity: Granularity,
        filter: Expression = None,
        prediction_interval_level: PredictionIntervalLevel = None,
    ) -> GetCostForecastResponse:
        raise NotImplementedError

    @handler("GetDimensionValues", expand=False)
    def get_dimension_values(
        self, context: RequestContext, request: GetDimensionValuesRequest
    ) -> GetDimensionValuesResponse:
        raise NotImplementedError

    @handler("GetReservationCoverage")
    def get_reservation_coverage(
        self,
        context: RequestContext,
        time_period: DateInterval,
        group_by: GroupDefinitions = None,
        granularity: Granularity = None,
        filter: Expression = None,
        metrics: MetricNames = None,
        next_page_token: NextPageToken = None,
        sort_by: SortDefinition = None,
        max_results: MaxResults = None,
    ) -> GetReservationCoverageResponse:
        raise NotImplementedError

    @handler("GetReservationPurchaseRecommendation")
    def get_reservation_purchase_recommendation(
        self,
        context: RequestContext,
        service: GenericString,
        account_id: GenericString = None,
        filter: Expression = None,
        account_scope: AccountScope = None,
        lookback_period_in_days: LookbackPeriodInDays = None,
        term_in_years: TermInYears = None,
        payment_option: PaymentOption = None,
        service_specification: ServiceSpecification = None,
        page_size: NonNegativeInteger = None,
        next_page_token: NextPageToken = None,
    ) -> GetReservationPurchaseRecommendationResponse:
        raise NotImplementedError

    @handler("GetReservationUtilization")
    def get_reservation_utilization(
        self,
        context: RequestContext,
        time_period: DateInterval,
        group_by: GroupDefinitions = None,
        granularity: Granularity = None,
        filter: Expression = None,
        sort_by: SortDefinition = None,
        next_page_token: NextPageToken = None,
        max_results: MaxResults = None,
    ) -> GetReservationUtilizationResponse:
        raise NotImplementedError

    @handler("GetRightsizingRecommendation")
    def get_rightsizing_recommendation(
        self,
        context: RequestContext,
        service: GenericString,
        filter: Expression = None,
        configuration: RightsizingRecommendationConfiguration = None,
        page_size: NonNegativeInteger = None,
        next_page_token: NextPageToken = None,
    ) -> GetRightsizingRecommendationResponse:
        raise NotImplementedError

    @handler("GetSavingsPlansCoverage")
    def get_savings_plans_coverage(
        self,
        context: RequestContext,
        time_period: DateInterval,
        group_by: GroupDefinitions = None,
        granularity: Granularity = None,
        filter: Expression = None,
        metrics: MetricNames = None,
        next_token: NextPageToken = None,
        max_results: MaxResults = None,
        sort_by: SortDefinition = None,
    ) -> GetSavingsPlansCoverageResponse:
        raise NotImplementedError

    @handler("GetSavingsPlansPurchaseRecommendation")
    def get_savings_plans_purchase_recommendation(
        self,
        context: RequestContext,
        savings_plans_type: SupportedSavingsPlansType,
        term_in_years: TermInYears,
        payment_option: PaymentOption,
        lookback_period_in_days: LookbackPeriodInDays,
        account_scope: AccountScope = None,
        next_page_token: NextPageToken = None,
        page_size: NonNegativeInteger = None,
        filter: Expression = None,
    ) -> GetSavingsPlansPurchaseRecommendationResponse:
        raise NotImplementedError

    @handler("GetSavingsPlansUtilization")
    def get_savings_plans_utilization(
        self,
        context: RequestContext,
        time_period: DateInterval,
        granularity: Granularity = None,
        filter: Expression = None,
        sort_by: SortDefinition = None,
    ) -> GetSavingsPlansUtilizationResponse:
        raise NotImplementedError

    @handler("GetSavingsPlansUtilizationDetails")
    def get_savings_plans_utilization_details(
        self,
        context: RequestContext,
        time_period: DateInterval,
        filter: Expression = None,
        data_type: SavingsPlansDataTypes = None,
        next_token: NextPageToken = None,
        max_results: MaxResults = None,
        sort_by: SortDefinition = None,
    ) -> GetSavingsPlansUtilizationDetailsResponse:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(
        self,
        context: RequestContext,
        time_period: DateInterval,
        search_string: SearchString = None,
        tag_key: TagKey = None,
        filter: Expression = None,
        sort_by: SortDefinitions = None,
        max_results: MaxResults = None,
        next_page_token: NextPageToken = None,
    ) -> GetTagsResponse:
        raise NotImplementedError

    @handler("GetUsageForecast")
    def get_usage_forecast(
        self,
        context: RequestContext,
        time_period: DateInterval,
        metric: Metric,
        granularity: Granularity,
        filter: Expression = None,
        prediction_interval_level: PredictionIntervalLevel = None,
    ) -> GetUsageForecastResponse:
        raise NotImplementedError

    @handler("ListCostCategoryDefinitions")
    def list_cost_category_definitions(
        self,
        context: RequestContext,
        effective_on: ZonedDateTime = None,
        next_token: NextPageToken = None,
        max_results: CostCategoryMaxResults = None,
    ) -> ListCostCategoryDefinitionsResponse:
        raise NotImplementedError

    @handler("ProvideAnomalyFeedback")
    def provide_anomaly_feedback(
        self, context: RequestContext, anomaly_id: GenericString, feedback: AnomalyFeedbackType
    ) -> ProvideAnomalyFeedbackResponse:
        raise NotImplementedError

    @handler("UpdateAnomalyMonitor")
    def update_anomaly_monitor(
        self,
        context: RequestContext,
        monitor_arn: GenericString,
        monitor_name: GenericString = None,
    ) -> UpdateAnomalyMonitorResponse:
        raise NotImplementedError

    @handler("UpdateAnomalySubscription")
    def update_anomaly_subscription(
        self,
        context: RequestContext,
        subscription_arn: GenericString,
        threshold: NullableNonNegativeDouble = None,
        frequency: AnomalySubscriptionFrequency = None,
        monitor_arn_list: MonitorArnList = None,
        subscribers: Subscribers = None,
        subscription_name: GenericString = None,
    ) -> UpdateAnomalySubscriptionResponse:
        raise NotImplementedError

    @handler("UpdateCostCategoryDefinition")
    def update_cost_category_definition(
        self,
        context: RequestContext,
        cost_category_arn: Arn,
        rule_version: CostCategoryRuleVersion,
        rules: CostCategoryRulesList,
        default_value: CostCategoryValue = None,
        split_charge_rules: CostCategorySplitChargeRulesList = None,
    ) -> UpdateCostCategoryDefinitionResponse:
        raise NotImplementedError
