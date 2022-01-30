import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AsciiStringMaxLen255 = str
AssociatePublicIpAddress = bool
AutoScalingGroupDesiredCapacity = int
AutoScalingGroupMaxSize = int
AutoScalingGroupMinSize = int
AutoScalingGroupPredictedCapacity = int
AutoScalingGroupState = str
BlockDeviceEbsDeleteOnTermination = bool
BlockDeviceEbsEncrypted = bool
BlockDeviceEbsIops = int
BlockDeviceEbsThroughput = int
BlockDeviceEbsVolumeSize = int
BlockDeviceEbsVolumeType = str
CapacityRebalanceEnabled = bool
CheckpointDelay = int
Context = str
Cooldown = int
DisableScaleIn = bool
EbsOptimized = bool
EstimatedInstanceWarmup = int
ExcludedInstance = str
ForceDelete = bool
GlobalTimeout = int
HealthCheckGracePeriod = int
HeartbeatTimeout = int
HonorCooldown = bool
IncludeDeletedGroups = bool
InstanceMetadataHttpPutResponseHopLimit = int
InstanceProtected = bool
InstancesToUpdate = int
IntPercent = int
LaunchTemplateName = str
LifecycleActionResult = str
LifecycleActionToken = str
LifecycleTransition = str
MaxGroupPreparedCapacity = int
MaxInstanceLifetime = int
MaxNumberOfAutoScalingGroups = int
MaxNumberOfLaunchConfigurations = int
MaxRecords = int
MetricDimensionName = str
MetricDimensionValue = str
MetricName = str
MetricNamespace = str
MetricScale = float
MetricUnit = str
MinAdjustmentMagnitude = int
MinAdjustmentStep = int
MixedInstanceSpotPrice = str
MonitoringEnabled = bool
NoDevice = bool
NonZeroIntPercent = int
NotificationTargetResourceName = str
NullableBoolean = bool
NullablePositiveDouble = float
NullablePositiveInteger = int
NumberOfAutoScalingGroups = int
NumberOfLaunchConfigurations = int
OnDemandBaseCapacity = int
OnDemandPercentageAboveBaseCapacity = int
PolicyIncrement = int
PredictiveScalingMaxCapacityBuffer = int
PredictiveScalingSchedulingBufferTime = int
Progress = int
PropagateAtLaunch = bool
ProtectedFromScaleIn = bool
RefreshInstanceWarmup = int
ResourceName = str
ReturnData = bool
ReuseOnScaleIn = bool
ScalingPolicyEnabled = bool
ShouldDecrementDesiredCapacity = bool
ShouldRespectGracePeriod = bool
SkipMatching = bool
SpotInstancePools = int
SpotPrice = str
TagKey = str
TagValue = str
WarmPoolMinSize = int
WarmPoolSize = int
XmlString = str
XmlStringMaxLen1023 = str
XmlStringMaxLen1600 = str
XmlStringMaxLen19 = str
XmlStringMaxLen2047 = str
XmlStringMaxLen255 = str
XmlStringMaxLen32 = str
XmlStringMaxLen511 = str
XmlStringMaxLen64 = str
XmlStringMetricLabel = str
XmlStringMetricStat = str
XmlStringUserData = str


class AcceleratorManufacturer(str):
    nvidia = "nvidia"
    amd = "amd"
    amazon_web_services = "amazon-web-services"
    xilinx = "xilinx"


class AcceleratorName(str):
    a100 = "a100"
    v100 = "v100"
    k80 = "k80"
    t4 = "t4"
    m60 = "m60"
    radeon_pro_v520 = "radeon-pro-v520"
    vu9p = "vu9p"


class AcceleratorType(str):
    gpu = "gpu"
    fpga = "fpga"
    inference = "inference"


class BareMetal(str):
    included = "included"
    excluded = "excluded"
    required = "required"


class BurstablePerformance(str):
    included = "included"
    excluded = "excluded"
    required = "required"


class CpuManufacturer(str):
    intel = "intel"
    amd = "amd"
    amazon_web_services = "amazon-web-services"


class InstanceGeneration(str):
    current = "current"
    previous = "previous"


class InstanceMetadataEndpointState(str):
    disabled = "disabled"
    enabled = "enabled"


class InstanceMetadataHttpTokensState(str):
    optional = "optional"
    required = "required"


class InstanceRefreshStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Successful = "Successful"
    Failed = "Failed"
    Cancelling = "Cancelling"
    Cancelled = "Cancelled"


class LifecycleState(str):
    Pending = "Pending"
    Pending_Wait = "Pending:Wait"
    Pending_Proceed = "Pending:Proceed"
    Quarantined = "Quarantined"
    InService = "InService"
    Terminating = "Terminating"
    Terminating_Wait = "Terminating:Wait"
    Terminating_Proceed = "Terminating:Proceed"
    Terminated = "Terminated"
    Detaching = "Detaching"
    Detached = "Detached"
    EnteringStandby = "EnteringStandby"
    Standby = "Standby"
    Warmed_Pending = "Warmed:Pending"
    Warmed_Pending_Wait = "Warmed:Pending:Wait"
    Warmed_Pending_Proceed = "Warmed:Pending:Proceed"
    Warmed_Terminating = "Warmed:Terminating"
    Warmed_Terminating_Wait = "Warmed:Terminating:Wait"
    Warmed_Terminating_Proceed = "Warmed:Terminating:Proceed"
    Warmed_Terminated = "Warmed:Terminated"
    Warmed_Stopped = "Warmed:Stopped"
    Warmed_Running = "Warmed:Running"
    Warmed_Hibernated = "Warmed:Hibernated"


class LocalStorage(str):
    included = "included"
    excluded = "excluded"
    required = "required"


class LocalStorageType(str):
    hdd = "hdd"
    ssd = "ssd"


class MetricStatistic(str):
    Average = "Average"
    Minimum = "Minimum"
    Maximum = "Maximum"
    SampleCount = "SampleCount"
    Sum = "Sum"


class MetricType(str):
    ASGAverageCPUUtilization = "ASGAverageCPUUtilization"
    ASGAverageNetworkIn = "ASGAverageNetworkIn"
    ASGAverageNetworkOut = "ASGAverageNetworkOut"
    ALBRequestCountPerTarget = "ALBRequestCountPerTarget"


class PredefinedLoadMetricType(str):
    ASGTotalCPUUtilization = "ASGTotalCPUUtilization"
    ASGTotalNetworkIn = "ASGTotalNetworkIn"
    ASGTotalNetworkOut = "ASGTotalNetworkOut"
    ALBTargetGroupRequestCount = "ALBTargetGroupRequestCount"


class PredefinedMetricPairType(str):
    ASGCPUUtilization = "ASGCPUUtilization"
    ASGNetworkIn = "ASGNetworkIn"
    ASGNetworkOut = "ASGNetworkOut"
    ALBRequestCount = "ALBRequestCount"


class PredefinedScalingMetricType(str):
    ASGAverageCPUUtilization = "ASGAverageCPUUtilization"
    ASGAverageNetworkIn = "ASGAverageNetworkIn"
    ASGAverageNetworkOut = "ASGAverageNetworkOut"
    ALBRequestCountPerTarget = "ALBRequestCountPerTarget"


class PredictiveScalingMaxCapacityBreachBehavior(str):
    HonorMaxCapacity = "HonorMaxCapacity"
    IncreaseMaxCapacity = "IncreaseMaxCapacity"


class PredictiveScalingMode(str):
    ForecastAndScale = "ForecastAndScale"
    ForecastOnly = "ForecastOnly"


class RefreshStrategy(str):
    Rolling = "Rolling"


class ScalingActivityStatusCode(str):
    PendingSpotBidPlacement = "PendingSpotBidPlacement"
    WaitingForSpotInstanceRequestId = "WaitingForSpotInstanceRequestId"
    WaitingForSpotInstanceId = "WaitingForSpotInstanceId"
    WaitingForInstanceId = "WaitingForInstanceId"
    PreInService = "PreInService"
    InProgress = "InProgress"
    WaitingForELBConnectionDraining = "WaitingForELBConnectionDraining"
    MidLifecycleAction = "MidLifecycleAction"
    WaitingForInstanceWarmup = "WaitingForInstanceWarmup"
    Successful = "Successful"
    Failed = "Failed"
    Cancelled = "Cancelled"


class WarmPoolState(str):
    Stopped = "Stopped"
    Running = "Running"
    Hibernated = "Hibernated"


class WarmPoolStatus(str):
    PendingDelete = "PendingDelete"


class ActiveInstanceRefreshNotFoundFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class AlreadyExistsFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class InstanceRefreshInProgressFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class InvalidNextToken(ServiceException):
    message: Optional[XmlStringMaxLen255]


class LimitExceededFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class ResourceContentionFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class ResourceInUseFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class ScalingActivityInProgressFault(ServiceException):
    message: Optional[XmlStringMaxLen255]


class ServiceLinkedRoleFailure(ServiceException):
    message: Optional[XmlStringMaxLen255]


class AcceleratorCountRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveInteger]
    Max: Optional[NullablePositiveInteger]


AcceleratorManufacturers = List[AcceleratorManufacturer]
AcceleratorNames = List[AcceleratorName]


class AcceleratorTotalMemoryMiBRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveInteger]
    Max: Optional[NullablePositiveInteger]


AcceleratorTypes = List[AcceleratorType]
TimestampType = datetime


class Activity(TypedDict, total=False):
    ActivityId: XmlString
    AutoScalingGroupName: XmlStringMaxLen255
    Description: Optional[XmlString]
    Cause: XmlStringMaxLen1023
    StartTime: TimestampType
    EndTime: Optional[TimestampType]
    StatusCode: ScalingActivityStatusCode
    StatusMessage: Optional[XmlStringMaxLen255]
    Progress: Optional[Progress]
    Details: Optional[XmlString]
    AutoScalingGroupState: Optional[AutoScalingGroupState]
    AutoScalingGroupARN: Optional[ResourceName]


Activities = List[Activity]


class ActivitiesType(TypedDict, total=False):
    Activities: Activities
    NextToken: Optional[XmlString]


ActivityIds = List[XmlString]


class ActivityType(TypedDict, total=False):
    Activity: Optional[Activity]


class AdjustmentType(TypedDict, total=False):
    AdjustmentType: Optional[XmlStringMaxLen255]


AdjustmentTypes = List[AdjustmentType]


class Alarm(TypedDict, total=False):
    AlarmName: Optional[XmlStringMaxLen255]
    AlarmARN: Optional[ResourceName]


Alarms = List[Alarm]
InstanceIds = List[XmlStringMaxLen19]


class AttachInstancesQuery(ServiceRequest):
    InstanceIds: Optional[InstanceIds]
    AutoScalingGroupName: XmlStringMaxLen255


class AttachLoadBalancerTargetGroupsResultType(TypedDict, total=False):
    pass


TargetGroupARNs = List[XmlStringMaxLen511]


class AttachLoadBalancerTargetGroupsType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    TargetGroupARNs: TargetGroupARNs


class AttachLoadBalancersResultType(TypedDict, total=False):
    pass


LoadBalancerNames = List[XmlStringMaxLen255]


class AttachLoadBalancersType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    LoadBalancerNames: LoadBalancerNames


class InstanceReusePolicy(TypedDict, total=False):
    ReuseOnScaleIn: Optional[ReuseOnScaleIn]


class WarmPoolConfiguration(TypedDict, total=False):
    MaxGroupPreparedCapacity: Optional[MaxGroupPreparedCapacity]
    MinSize: Optional[WarmPoolMinSize]
    PoolState: Optional[WarmPoolState]
    Status: Optional[WarmPoolStatus]
    InstanceReusePolicy: Optional[InstanceReusePolicy]


TerminationPolicies = List[XmlStringMaxLen1600]


class TagDescription(TypedDict, total=False):
    ResourceId: Optional[XmlString]
    ResourceType: Optional[XmlString]
    Key: Optional[TagKey]
    Value: Optional[TagValue]
    PropagateAtLaunch: Optional[PropagateAtLaunch]


TagDescriptionList = List[TagDescription]


class EnabledMetric(TypedDict, total=False):
    Metric: Optional[XmlStringMaxLen255]
    Granularity: Optional[XmlStringMaxLen255]


EnabledMetrics = List[EnabledMetric]


class SuspendedProcess(TypedDict, total=False):
    ProcessName: Optional[XmlStringMaxLen255]
    SuspensionReason: Optional[XmlStringMaxLen255]


SuspendedProcesses = List[SuspendedProcess]


class LaunchTemplateSpecification(TypedDict, total=False):
    LaunchTemplateId: Optional[XmlStringMaxLen255]
    LaunchTemplateName: Optional[LaunchTemplateName]
    Version: Optional[XmlStringMaxLen255]


class Instance(TypedDict, total=False):
    InstanceId: XmlStringMaxLen19
    InstanceType: Optional[XmlStringMaxLen255]
    AvailabilityZone: XmlStringMaxLen255
    LifecycleState: LifecycleState
    HealthStatus: XmlStringMaxLen32
    LaunchConfigurationName: Optional[XmlStringMaxLen255]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    ProtectedFromScaleIn: InstanceProtected
    WeightedCapacity: Optional[XmlStringMaxLen32]


Instances = List[Instance]
AvailabilityZones = List[XmlStringMaxLen255]


class InstancesDistribution(TypedDict, total=False):
    OnDemandAllocationStrategy: Optional[XmlString]
    OnDemandBaseCapacity: Optional[OnDemandBaseCapacity]
    OnDemandPercentageAboveBaseCapacity: Optional[OnDemandPercentageAboveBaseCapacity]
    SpotAllocationStrategy: Optional[XmlString]
    SpotInstancePools: Optional[SpotInstancePools]
    SpotMaxPrice: Optional[MixedInstanceSpotPrice]


class BaselineEbsBandwidthMbpsRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveInteger]
    Max: Optional[NullablePositiveInteger]


class TotalLocalStorageGBRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveDouble]
    Max: Optional[NullablePositiveDouble]


LocalStorageTypes = List[LocalStorageType]


class NetworkInterfaceCountRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveInteger]
    Max: Optional[NullablePositiveInteger]


InstanceGenerations = List[InstanceGeneration]
ExcludedInstanceTypes = List[ExcludedInstance]


class MemoryGiBPerVCpuRequest(TypedDict, total=False):
    Min: Optional[NullablePositiveDouble]
    Max: Optional[NullablePositiveDouble]


CpuManufacturers = List[CpuManufacturer]


class MemoryMiBRequest(TypedDict, total=False):
    Min: NullablePositiveInteger
    Max: Optional[NullablePositiveInteger]


class VCpuCountRequest(TypedDict, total=False):
    Min: NullablePositiveInteger
    Max: Optional[NullablePositiveInteger]


class InstanceRequirements(TypedDict, total=False):
    VCpuCount: VCpuCountRequest
    MemoryMiB: MemoryMiBRequest
    CpuManufacturers: Optional[CpuManufacturers]
    MemoryGiBPerVCpu: Optional[MemoryGiBPerVCpuRequest]
    ExcludedInstanceTypes: Optional[ExcludedInstanceTypes]
    InstanceGenerations: Optional[InstanceGenerations]
    SpotMaxPricePercentageOverLowestPrice: Optional[NullablePositiveInteger]
    OnDemandMaxPricePercentageOverLowestPrice: Optional[NullablePositiveInteger]
    BareMetal: Optional[BareMetal]
    BurstablePerformance: Optional[BurstablePerformance]
    RequireHibernateSupport: Optional[NullableBoolean]
    NetworkInterfaceCount: Optional[NetworkInterfaceCountRequest]
    LocalStorage: Optional[LocalStorage]
    LocalStorageTypes: Optional[LocalStorageTypes]
    TotalLocalStorageGB: Optional[TotalLocalStorageGBRequest]
    BaselineEbsBandwidthMbps: Optional[BaselineEbsBandwidthMbpsRequest]
    AcceleratorTypes: Optional[AcceleratorTypes]
    AcceleratorCount: Optional[AcceleratorCountRequest]
    AcceleratorManufacturers: Optional[AcceleratorManufacturers]
    AcceleratorNames: Optional[AcceleratorNames]
    AcceleratorTotalMemoryMiB: Optional[AcceleratorTotalMemoryMiBRequest]


class LaunchTemplateOverrides(TypedDict, total=False):
    InstanceType: Optional[XmlStringMaxLen255]
    WeightedCapacity: Optional[XmlStringMaxLen32]
    LaunchTemplateSpecification: Optional[LaunchTemplateSpecification]
    InstanceRequirements: Optional[InstanceRequirements]


Overrides = List[LaunchTemplateOverrides]


class LaunchTemplate(TypedDict, total=False):
    LaunchTemplateSpecification: Optional[LaunchTemplateSpecification]
    Overrides: Optional[Overrides]


class MixedInstancesPolicy(TypedDict, total=False):
    LaunchTemplate: Optional[LaunchTemplate]
    InstancesDistribution: Optional[InstancesDistribution]


class AutoScalingGroup(TypedDict, total=False):
    AutoScalingGroupName: XmlStringMaxLen255
    AutoScalingGroupARN: Optional[ResourceName]
    LaunchConfigurationName: Optional[XmlStringMaxLen255]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    MixedInstancesPolicy: Optional[MixedInstancesPolicy]
    MinSize: AutoScalingGroupMinSize
    MaxSize: AutoScalingGroupMaxSize
    DesiredCapacity: AutoScalingGroupDesiredCapacity
    PredictedCapacity: Optional[AutoScalingGroupPredictedCapacity]
    DefaultCooldown: Cooldown
    AvailabilityZones: AvailabilityZones
    LoadBalancerNames: Optional[LoadBalancerNames]
    TargetGroupARNs: Optional[TargetGroupARNs]
    HealthCheckType: XmlStringMaxLen32
    HealthCheckGracePeriod: Optional[HealthCheckGracePeriod]
    Instances: Optional[Instances]
    CreatedTime: TimestampType
    SuspendedProcesses: Optional[SuspendedProcesses]
    PlacementGroup: Optional[XmlStringMaxLen255]
    VPCZoneIdentifier: Optional[XmlStringMaxLen2047]
    EnabledMetrics: Optional[EnabledMetrics]
    Status: Optional[XmlStringMaxLen255]
    Tags: Optional[TagDescriptionList]
    TerminationPolicies: Optional[TerminationPolicies]
    NewInstancesProtectedFromScaleIn: Optional[InstanceProtected]
    ServiceLinkedRoleARN: Optional[ResourceName]
    MaxInstanceLifetime: Optional[MaxInstanceLifetime]
    CapacityRebalance: Optional[CapacityRebalanceEnabled]
    WarmPoolConfiguration: Optional[WarmPoolConfiguration]
    WarmPoolSize: Optional[WarmPoolSize]
    Context: Optional[Context]
    DesiredCapacityType: Optional[XmlStringMaxLen255]


AutoScalingGroupNames = List[XmlStringMaxLen255]
Values = List[XmlString]


class Filter(TypedDict, total=False):
    Name: Optional[XmlString]
    Values: Optional[Values]


Filters = List[Filter]


class AutoScalingGroupNamesType(ServiceRequest):
    AutoScalingGroupNames: Optional[AutoScalingGroupNames]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]
    Filters: Optional[Filters]


AutoScalingGroups = List[AutoScalingGroup]


class AutoScalingGroupsType(TypedDict, total=False):
    AutoScalingGroups: AutoScalingGroups
    NextToken: Optional[XmlString]


class AutoScalingInstanceDetails(TypedDict, total=False):
    InstanceId: XmlStringMaxLen19
    InstanceType: Optional[XmlStringMaxLen255]
    AutoScalingGroupName: XmlStringMaxLen255
    AvailabilityZone: XmlStringMaxLen255
    LifecycleState: XmlStringMaxLen32
    HealthStatus: XmlStringMaxLen32
    LaunchConfigurationName: Optional[XmlStringMaxLen255]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    ProtectedFromScaleIn: InstanceProtected
    WeightedCapacity: Optional[XmlStringMaxLen32]


AutoScalingInstances = List[AutoScalingInstanceDetails]


class AutoScalingInstancesType(TypedDict, total=False):
    AutoScalingInstances: Optional[AutoScalingInstances]
    NextToken: Optional[XmlString]


AutoScalingNotificationTypes = List[XmlStringMaxLen255]


class FailedScheduledUpdateGroupActionRequest(TypedDict, total=False):
    ScheduledActionName: XmlStringMaxLen255
    ErrorCode: Optional[XmlStringMaxLen64]
    ErrorMessage: Optional[XmlString]


FailedScheduledUpdateGroupActionRequests = List[FailedScheduledUpdateGroupActionRequest]


class BatchDeleteScheduledActionAnswer(TypedDict, total=False):
    FailedScheduledActions: Optional[FailedScheduledUpdateGroupActionRequests]


ScheduledActionNames = List[XmlStringMaxLen255]


class BatchDeleteScheduledActionType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ScheduledActionNames: ScheduledActionNames


class BatchPutScheduledUpdateGroupActionAnswer(TypedDict, total=False):
    FailedScheduledUpdateGroupActions: Optional[FailedScheduledUpdateGroupActionRequests]


class ScheduledUpdateGroupActionRequest(TypedDict, total=False):
    ScheduledActionName: XmlStringMaxLen255
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    Recurrence: Optional[XmlStringMaxLen255]
    MinSize: Optional[AutoScalingGroupMinSize]
    MaxSize: Optional[AutoScalingGroupMaxSize]
    DesiredCapacity: Optional[AutoScalingGroupDesiredCapacity]
    TimeZone: Optional[XmlStringMaxLen255]


ScheduledUpdateGroupActionRequests = List[ScheduledUpdateGroupActionRequest]


class BatchPutScheduledUpdateGroupActionType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ScheduledUpdateGroupActions: ScheduledUpdateGroupActionRequests


class Ebs(TypedDict, total=False):
    SnapshotId: Optional[XmlStringMaxLen255]
    VolumeSize: Optional[BlockDeviceEbsVolumeSize]
    VolumeType: Optional[BlockDeviceEbsVolumeType]
    DeleteOnTermination: Optional[BlockDeviceEbsDeleteOnTermination]
    Iops: Optional[BlockDeviceEbsIops]
    Encrypted: Optional[BlockDeviceEbsEncrypted]
    Throughput: Optional[BlockDeviceEbsThroughput]


class BlockDeviceMapping(TypedDict, total=False):
    VirtualName: Optional[XmlStringMaxLen255]
    DeviceName: XmlStringMaxLen255
    Ebs: Optional[Ebs]
    NoDevice: Optional[NoDevice]


BlockDeviceMappings = List[BlockDeviceMapping]


class CancelInstanceRefreshAnswer(TypedDict, total=False):
    InstanceRefreshId: Optional[XmlStringMaxLen255]


class CancelInstanceRefreshType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255


PredictiveScalingForecastValues = List[MetricScale]
PredictiveScalingForecastTimestamps = List[TimestampType]


class CapacityForecast(TypedDict, total=False):
    Timestamps: PredictiveScalingForecastTimestamps
    Values: PredictiveScalingForecastValues


CheckpointPercentages = List[NonZeroIntPercent]
ClassicLinkVPCSecurityGroups = List[XmlStringMaxLen255]


class CompleteLifecycleActionAnswer(TypedDict, total=False):
    pass


class CompleteLifecycleActionType(ServiceRequest):
    LifecycleHookName: AsciiStringMaxLen255
    AutoScalingGroupName: ResourceName
    LifecycleActionToken: Optional[LifecycleActionToken]
    LifecycleActionResult: LifecycleActionResult
    InstanceId: Optional[XmlStringMaxLen19]


class Tag(TypedDict, total=False):
    ResourceId: Optional[XmlString]
    ResourceType: Optional[XmlString]
    Key: TagKey
    Value: Optional[TagValue]
    PropagateAtLaunch: Optional[PropagateAtLaunch]


Tags = List[Tag]


class LifecycleHookSpecification(TypedDict, total=False):
    LifecycleHookName: AsciiStringMaxLen255
    LifecycleTransition: LifecycleTransition
    NotificationMetadata: Optional[XmlStringMaxLen1023]
    HeartbeatTimeout: Optional[HeartbeatTimeout]
    DefaultResult: Optional[LifecycleActionResult]
    NotificationTargetARN: Optional[NotificationTargetResourceName]
    RoleARN: Optional[XmlStringMaxLen255]


LifecycleHookSpecifications = List[LifecycleHookSpecification]


class CreateAutoScalingGroupType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    LaunchConfigurationName: Optional[XmlStringMaxLen255]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    MixedInstancesPolicy: Optional[MixedInstancesPolicy]
    InstanceId: Optional[XmlStringMaxLen19]
    MinSize: AutoScalingGroupMinSize
    MaxSize: AutoScalingGroupMaxSize
    DesiredCapacity: Optional[AutoScalingGroupDesiredCapacity]
    DefaultCooldown: Optional[Cooldown]
    AvailabilityZones: Optional[AvailabilityZones]
    LoadBalancerNames: Optional[LoadBalancerNames]
    TargetGroupARNs: Optional[TargetGroupARNs]
    HealthCheckType: Optional[XmlStringMaxLen32]
    HealthCheckGracePeriod: Optional[HealthCheckGracePeriod]
    PlacementGroup: Optional[XmlStringMaxLen255]
    VPCZoneIdentifier: Optional[XmlStringMaxLen2047]
    TerminationPolicies: Optional[TerminationPolicies]
    NewInstancesProtectedFromScaleIn: Optional[InstanceProtected]
    CapacityRebalance: Optional[CapacityRebalanceEnabled]
    LifecycleHookSpecificationList: Optional[LifecycleHookSpecifications]
    Tags: Optional[Tags]
    ServiceLinkedRoleARN: Optional[ResourceName]
    MaxInstanceLifetime: Optional[MaxInstanceLifetime]
    Context: Optional[Context]
    DesiredCapacityType: Optional[XmlStringMaxLen255]


class InstanceMetadataOptions(TypedDict, total=False):
    HttpTokens: Optional[InstanceMetadataHttpTokensState]
    HttpPutResponseHopLimit: Optional[InstanceMetadataHttpPutResponseHopLimit]
    HttpEndpoint: Optional[InstanceMetadataEndpointState]


class InstanceMonitoring(TypedDict, total=False):
    Enabled: Optional[MonitoringEnabled]


SecurityGroups = List[XmlString]


class CreateLaunchConfigurationType(ServiceRequest):
    LaunchConfigurationName: XmlStringMaxLen255
    ImageId: Optional[XmlStringMaxLen255]
    KeyName: Optional[XmlStringMaxLen255]
    SecurityGroups: Optional[SecurityGroups]
    ClassicLinkVPCId: Optional[XmlStringMaxLen255]
    ClassicLinkVPCSecurityGroups: Optional[ClassicLinkVPCSecurityGroups]
    UserData: Optional[XmlStringUserData]
    InstanceId: Optional[XmlStringMaxLen19]
    InstanceType: Optional[XmlStringMaxLen255]
    KernelId: Optional[XmlStringMaxLen255]
    RamdiskId: Optional[XmlStringMaxLen255]
    BlockDeviceMappings: Optional[BlockDeviceMappings]
    InstanceMonitoring: Optional[InstanceMonitoring]
    SpotPrice: Optional[SpotPrice]
    IamInstanceProfile: Optional[XmlStringMaxLen1600]
    EbsOptimized: Optional[EbsOptimized]
    AssociatePublicIpAddress: Optional[AssociatePublicIpAddress]
    PlacementTenancy: Optional[XmlStringMaxLen64]
    MetadataOptions: Optional[InstanceMetadataOptions]


class CreateOrUpdateTagsType(ServiceRequest):
    Tags: Tags


class MetricDimension(TypedDict, total=False):
    Name: MetricDimensionName
    Value: MetricDimensionValue


MetricDimensions = List[MetricDimension]


class CustomizedMetricSpecification(TypedDict, total=False):
    MetricName: MetricName
    Namespace: MetricNamespace
    Dimensions: Optional[MetricDimensions]
    Statistic: MetricStatistic
    Unit: Optional[MetricUnit]


class DeleteAutoScalingGroupType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ForceDelete: Optional[ForceDelete]


class DeleteLifecycleHookAnswer(TypedDict, total=False):
    pass


class DeleteLifecycleHookType(ServiceRequest):
    LifecycleHookName: AsciiStringMaxLen255
    AutoScalingGroupName: XmlStringMaxLen255


class DeleteNotificationConfigurationType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    TopicARN: XmlStringMaxLen255


class DeletePolicyType(ServiceRequest):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    PolicyName: ResourceName


class DeleteScheduledActionType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ScheduledActionName: XmlStringMaxLen255


class DeleteTagsType(ServiceRequest):
    Tags: Tags


class DeleteWarmPoolAnswer(TypedDict, total=False):
    pass


class DeleteWarmPoolType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ForceDelete: Optional[ForceDelete]


class DescribeAccountLimitsAnswer(TypedDict, total=False):
    MaxNumberOfAutoScalingGroups: Optional[MaxNumberOfAutoScalingGroups]
    MaxNumberOfLaunchConfigurations: Optional[MaxNumberOfLaunchConfigurations]
    NumberOfAutoScalingGroups: Optional[NumberOfAutoScalingGroups]
    NumberOfLaunchConfigurations: Optional[NumberOfLaunchConfigurations]


class DescribeAdjustmentTypesAnswer(TypedDict, total=False):
    AdjustmentTypes: Optional[AdjustmentTypes]


class DescribeAutoScalingInstancesType(ServiceRequest):
    InstanceIds: Optional[InstanceIds]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[XmlString]


class DescribeAutoScalingNotificationTypesAnswer(TypedDict, total=False):
    AutoScalingNotificationTypes: Optional[AutoScalingNotificationTypes]


class DesiredConfiguration(TypedDict, total=False):
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    MixedInstancesPolicy: Optional[MixedInstancesPolicy]


class RefreshPreferences(TypedDict, total=False):
    MinHealthyPercentage: Optional[IntPercent]
    InstanceWarmup: Optional[RefreshInstanceWarmup]
    CheckpointPercentages: Optional[CheckpointPercentages]
    CheckpointDelay: Optional[CheckpointDelay]
    SkipMatching: Optional[SkipMatching]


class InstanceRefreshWarmPoolProgress(TypedDict, total=False):
    PercentageComplete: Optional[IntPercent]
    InstancesToUpdate: Optional[InstancesToUpdate]


class InstanceRefreshLivePoolProgress(TypedDict, total=False):
    PercentageComplete: Optional[IntPercent]
    InstancesToUpdate: Optional[InstancesToUpdate]


class InstanceRefreshProgressDetails(TypedDict, total=False):
    LivePoolProgress: Optional[InstanceRefreshLivePoolProgress]
    WarmPoolProgress: Optional[InstanceRefreshWarmPoolProgress]


class InstanceRefresh(TypedDict, total=False):
    InstanceRefreshId: Optional[XmlStringMaxLen255]
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    Status: Optional[InstanceRefreshStatus]
    StatusReason: Optional[XmlStringMaxLen1023]
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    PercentageComplete: Optional[IntPercent]
    InstancesToUpdate: Optional[InstancesToUpdate]
    ProgressDetails: Optional[InstanceRefreshProgressDetails]
    Preferences: Optional[RefreshPreferences]
    DesiredConfiguration: Optional[DesiredConfiguration]


InstanceRefreshes = List[InstanceRefresh]


class DescribeInstanceRefreshesAnswer(TypedDict, total=False):
    InstanceRefreshes: Optional[InstanceRefreshes]
    NextToken: Optional[XmlString]


InstanceRefreshIds = List[XmlStringMaxLen255]


class DescribeInstanceRefreshesType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    InstanceRefreshIds: Optional[InstanceRefreshIds]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class DescribeLifecycleHookTypesAnswer(TypedDict, total=False):
    LifecycleHookTypes: Optional[AutoScalingNotificationTypes]


class LifecycleHook(TypedDict, total=False):
    LifecycleHookName: Optional[AsciiStringMaxLen255]
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    LifecycleTransition: Optional[LifecycleTransition]
    NotificationTargetARN: Optional[NotificationTargetResourceName]
    RoleARN: Optional[XmlStringMaxLen255]
    NotificationMetadata: Optional[XmlStringMaxLen1023]
    HeartbeatTimeout: Optional[HeartbeatTimeout]
    GlobalTimeout: Optional[GlobalTimeout]
    DefaultResult: Optional[LifecycleActionResult]


LifecycleHooks = List[LifecycleHook]


class DescribeLifecycleHooksAnswer(TypedDict, total=False):
    LifecycleHooks: Optional[LifecycleHooks]


LifecycleHookNames = List[AsciiStringMaxLen255]


class DescribeLifecycleHooksType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    LifecycleHookNames: Optional[LifecycleHookNames]


class DescribeLoadBalancerTargetGroupsRequest(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class LoadBalancerTargetGroupState(TypedDict, total=False):
    LoadBalancerTargetGroupARN: Optional[XmlStringMaxLen511]
    State: Optional[XmlStringMaxLen255]


LoadBalancerTargetGroupStates = List[LoadBalancerTargetGroupState]


class DescribeLoadBalancerTargetGroupsResponse(TypedDict, total=False):
    LoadBalancerTargetGroups: Optional[LoadBalancerTargetGroupStates]
    NextToken: Optional[XmlString]


class DescribeLoadBalancersRequest(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class LoadBalancerState(TypedDict, total=False):
    LoadBalancerName: Optional[XmlStringMaxLen255]
    State: Optional[XmlStringMaxLen255]


LoadBalancerStates = List[LoadBalancerState]


class DescribeLoadBalancersResponse(TypedDict, total=False):
    LoadBalancers: Optional[LoadBalancerStates]
    NextToken: Optional[XmlString]


class MetricGranularityType(TypedDict, total=False):
    Granularity: Optional[XmlStringMaxLen255]


MetricGranularityTypes = List[MetricGranularityType]


class MetricCollectionType(TypedDict, total=False):
    Metric: Optional[XmlStringMaxLen255]


MetricCollectionTypes = List[MetricCollectionType]


class DescribeMetricCollectionTypesAnswer(TypedDict, total=False):
    Metrics: Optional[MetricCollectionTypes]
    Granularities: Optional[MetricGranularityTypes]


class NotificationConfiguration(TypedDict, total=False):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    TopicARN: Optional[XmlStringMaxLen255]
    NotificationType: Optional[XmlStringMaxLen255]


NotificationConfigurations = List[NotificationConfiguration]


class DescribeNotificationConfigurationsAnswer(TypedDict, total=False):
    NotificationConfigurations: NotificationConfigurations
    NextToken: Optional[XmlString]


class DescribeNotificationConfigurationsType(ServiceRequest):
    AutoScalingGroupNames: Optional[AutoScalingGroupNames]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


PolicyTypes = List[XmlStringMaxLen64]
PolicyNames = List[ResourceName]


class DescribePoliciesType(ServiceRequest):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    PolicyNames: Optional[PolicyNames]
    PolicyTypes: Optional[PolicyTypes]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class DescribeScalingActivitiesType(ServiceRequest):
    ActivityIds: Optional[ActivityIds]
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    IncludeDeletedGroups: Optional[IncludeDeletedGroups]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[XmlString]


class DescribeScheduledActionsType(ServiceRequest):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    ScheduledActionNames: Optional[ScheduledActionNames]
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class DescribeTagsType(ServiceRequest):
    Filters: Optional[Filters]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


class DescribeTerminationPolicyTypesAnswer(TypedDict, total=False):
    TerminationPolicyTypes: Optional[TerminationPolicies]


class DescribeWarmPoolAnswer(TypedDict, total=False):
    WarmPoolConfiguration: Optional[WarmPoolConfiguration]
    Instances: Optional[Instances]
    NextToken: Optional[XmlString]


class DescribeWarmPoolType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[XmlString]


class DetachInstancesAnswer(TypedDict, total=False):
    Activities: Optional[Activities]


class DetachInstancesQuery(ServiceRequest):
    InstanceIds: Optional[InstanceIds]
    AutoScalingGroupName: XmlStringMaxLen255
    ShouldDecrementDesiredCapacity: ShouldDecrementDesiredCapacity


class DetachLoadBalancerTargetGroupsResultType(TypedDict, total=False):
    pass


class DetachLoadBalancerTargetGroupsType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    TargetGroupARNs: TargetGroupARNs


class DetachLoadBalancersResultType(TypedDict, total=False):
    pass


class DetachLoadBalancersType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    LoadBalancerNames: LoadBalancerNames


Metrics = List[XmlStringMaxLen255]


class DisableMetricsCollectionQuery(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    Metrics: Optional[Metrics]


class EnableMetricsCollectionQuery(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    Metrics: Optional[Metrics]
    Granularity: XmlStringMaxLen255


class EnterStandbyAnswer(TypedDict, total=False):
    Activities: Optional[Activities]


class EnterStandbyQuery(ServiceRequest):
    InstanceIds: Optional[InstanceIds]
    AutoScalingGroupName: XmlStringMaxLen255
    ShouldDecrementDesiredCapacity: ShouldDecrementDesiredCapacity


class ExecutePolicyType(ServiceRequest):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    PolicyName: ResourceName
    HonorCooldown: Optional[HonorCooldown]
    MetricValue: Optional[MetricScale]
    BreachThreshold: Optional[MetricScale]


class ExitStandbyAnswer(TypedDict, total=False):
    Activities: Optional[Activities]


class ExitStandbyQuery(ServiceRequest):
    InstanceIds: Optional[InstanceIds]
    AutoScalingGroupName: XmlStringMaxLen255


class Metric(TypedDict, total=False):
    Namespace: MetricNamespace
    MetricName: MetricName
    Dimensions: Optional[MetricDimensions]


class MetricStat(TypedDict, total=False):
    Metric: Metric
    Stat: XmlStringMetricStat
    Unit: Optional[MetricUnit]


class MetricDataQuery(TypedDict, total=False):
    Id: XmlStringMaxLen255
    Expression: Optional[XmlStringMaxLen1023]
    MetricStat: Optional[MetricStat]
    Label: Optional[XmlStringMetricLabel]
    ReturnData: Optional[ReturnData]


MetricDataQueries = List[MetricDataQuery]


class PredictiveScalingCustomizedCapacityMetric(TypedDict, total=False):
    MetricDataQueries: MetricDataQueries


class PredictiveScalingCustomizedLoadMetric(TypedDict, total=False):
    MetricDataQueries: MetricDataQueries


class PredictiveScalingCustomizedScalingMetric(TypedDict, total=False):
    MetricDataQueries: MetricDataQueries


class PredictiveScalingPredefinedLoadMetric(TypedDict, total=False):
    PredefinedMetricType: PredefinedLoadMetricType
    ResourceLabel: Optional[XmlStringMaxLen1023]


class PredictiveScalingPredefinedScalingMetric(TypedDict, total=False):
    PredefinedMetricType: PredefinedScalingMetricType
    ResourceLabel: Optional[XmlStringMaxLen1023]


class PredictiveScalingPredefinedMetricPair(TypedDict, total=False):
    PredefinedMetricType: PredefinedMetricPairType
    ResourceLabel: Optional[XmlStringMaxLen1023]


class PredictiveScalingMetricSpecification(TypedDict, total=False):
    TargetValue: MetricScale
    PredefinedMetricPairSpecification: Optional[PredictiveScalingPredefinedMetricPair]
    PredefinedScalingMetricSpecification: Optional[PredictiveScalingPredefinedScalingMetric]
    PredefinedLoadMetricSpecification: Optional[PredictiveScalingPredefinedLoadMetric]
    CustomizedScalingMetricSpecification: Optional[PredictiveScalingCustomizedScalingMetric]
    CustomizedLoadMetricSpecification: Optional[PredictiveScalingCustomizedLoadMetric]
    CustomizedCapacityMetricSpecification: Optional[PredictiveScalingCustomizedCapacityMetric]


class LoadForecast(TypedDict, total=False):
    Timestamps: PredictiveScalingForecastTimestamps
    Values: PredictiveScalingForecastValues
    MetricSpecification: PredictiveScalingMetricSpecification


LoadForecasts = List[LoadForecast]


class GetPredictiveScalingForecastAnswer(TypedDict, total=False):
    LoadForecast: LoadForecasts
    CapacityForecast: CapacityForecast
    UpdateTime: TimestampType


class GetPredictiveScalingForecastType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    PolicyName: XmlStringMaxLen255
    StartTime: TimestampType
    EndTime: TimestampType


class LaunchConfiguration(TypedDict, total=False):
    LaunchConfigurationName: XmlStringMaxLen255
    LaunchConfigurationARN: Optional[ResourceName]
    ImageId: XmlStringMaxLen255
    KeyName: Optional[XmlStringMaxLen255]
    SecurityGroups: Optional[SecurityGroups]
    ClassicLinkVPCId: Optional[XmlStringMaxLen255]
    ClassicLinkVPCSecurityGroups: Optional[ClassicLinkVPCSecurityGroups]
    UserData: Optional[XmlStringUserData]
    InstanceType: XmlStringMaxLen255
    KernelId: Optional[XmlStringMaxLen255]
    RamdiskId: Optional[XmlStringMaxLen255]
    BlockDeviceMappings: Optional[BlockDeviceMappings]
    InstanceMonitoring: Optional[InstanceMonitoring]
    SpotPrice: Optional[SpotPrice]
    IamInstanceProfile: Optional[XmlStringMaxLen1600]
    CreatedTime: TimestampType
    EbsOptimized: Optional[EbsOptimized]
    AssociatePublicIpAddress: Optional[AssociatePublicIpAddress]
    PlacementTenancy: Optional[XmlStringMaxLen64]
    MetadataOptions: Optional[InstanceMetadataOptions]


class LaunchConfigurationNameType(ServiceRequest):
    LaunchConfigurationName: XmlStringMaxLen255


LaunchConfigurationNames = List[XmlStringMaxLen255]


class LaunchConfigurationNamesType(ServiceRequest):
    LaunchConfigurationNames: Optional[LaunchConfigurationNames]
    NextToken: Optional[XmlString]
    MaxRecords: Optional[MaxRecords]


LaunchConfigurations = List[LaunchConfiguration]


class LaunchConfigurationsType(TypedDict, total=False):
    LaunchConfigurations: LaunchConfigurations
    NextToken: Optional[XmlString]


PredictiveScalingMetricSpecifications = List[PredictiveScalingMetricSpecification]


class PredictiveScalingConfiguration(TypedDict, total=False):
    MetricSpecifications: PredictiveScalingMetricSpecifications
    Mode: Optional[PredictiveScalingMode]
    SchedulingBufferTime: Optional[PredictiveScalingSchedulingBufferTime]
    MaxCapacityBreachBehavior: Optional[PredictiveScalingMaxCapacityBreachBehavior]
    MaxCapacityBuffer: Optional[PredictiveScalingMaxCapacityBuffer]


class PredefinedMetricSpecification(TypedDict, total=False):
    PredefinedMetricType: MetricType
    ResourceLabel: Optional[XmlStringMaxLen1023]


class TargetTrackingConfiguration(TypedDict, total=False):
    PredefinedMetricSpecification: Optional[PredefinedMetricSpecification]
    CustomizedMetricSpecification: Optional[CustomizedMetricSpecification]
    TargetValue: MetricScale
    DisableScaleIn: Optional[DisableScaleIn]


class StepAdjustment(TypedDict, total=False):
    MetricIntervalLowerBound: Optional[MetricScale]
    MetricIntervalUpperBound: Optional[MetricScale]
    ScalingAdjustment: PolicyIncrement


StepAdjustments = List[StepAdjustment]


class ScalingPolicy(TypedDict, total=False):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    PolicyName: Optional[XmlStringMaxLen255]
    PolicyARN: Optional[ResourceName]
    PolicyType: Optional[XmlStringMaxLen64]
    AdjustmentType: Optional[XmlStringMaxLen255]
    MinAdjustmentStep: Optional[MinAdjustmentStep]
    MinAdjustmentMagnitude: Optional[MinAdjustmentMagnitude]
    ScalingAdjustment: Optional[PolicyIncrement]
    Cooldown: Optional[Cooldown]
    StepAdjustments: Optional[StepAdjustments]
    MetricAggregationType: Optional[XmlStringMaxLen32]
    EstimatedInstanceWarmup: Optional[EstimatedInstanceWarmup]
    Alarms: Optional[Alarms]
    TargetTrackingConfiguration: Optional[TargetTrackingConfiguration]
    Enabled: Optional[ScalingPolicyEnabled]
    PredictiveScalingConfiguration: Optional[PredictiveScalingConfiguration]


ScalingPolicies = List[ScalingPolicy]


class PoliciesType(TypedDict, total=False):
    ScalingPolicies: Optional[ScalingPolicies]
    NextToken: Optional[XmlString]


class PolicyARNType(TypedDict, total=False):
    PolicyARN: Optional[ResourceName]
    Alarms: Optional[Alarms]


ProcessNames = List[XmlStringMaxLen255]


class ProcessType(TypedDict, total=False):
    ProcessName: XmlStringMaxLen255


Processes = List[ProcessType]


class ProcessesType(TypedDict, total=False):
    Processes: Optional[Processes]


class PutLifecycleHookAnswer(TypedDict, total=False):
    pass


class PutLifecycleHookType(ServiceRequest):
    LifecycleHookName: AsciiStringMaxLen255
    AutoScalingGroupName: XmlStringMaxLen255
    LifecycleTransition: Optional[LifecycleTransition]
    RoleARN: Optional[XmlStringMaxLen255]
    NotificationTargetARN: Optional[NotificationTargetResourceName]
    NotificationMetadata: Optional[XmlStringMaxLen1023]
    HeartbeatTimeout: Optional[HeartbeatTimeout]
    DefaultResult: Optional[LifecycleActionResult]


class PutNotificationConfigurationType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    TopicARN: XmlStringMaxLen255
    NotificationTypes: AutoScalingNotificationTypes


class PutScalingPolicyType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    PolicyName: XmlStringMaxLen255
    PolicyType: Optional[XmlStringMaxLen64]
    AdjustmentType: Optional[XmlStringMaxLen255]
    MinAdjustmentStep: Optional[MinAdjustmentStep]
    MinAdjustmentMagnitude: Optional[MinAdjustmentMagnitude]
    ScalingAdjustment: Optional[PolicyIncrement]
    Cooldown: Optional[Cooldown]
    MetricAggregationType: Optional[XmlStringMaxLen32]
    StepAdjustments: Optional[StepAdjustments]
    EstimatedInstanceWarmup: Optional[EstimatedInstanceWarmup]
    TargetTrackingConfiguration: Optional[TargetTrackingConfiguration]
    Enabled: Optional[ScalingPolicyEnabled]
    PredictiveScalingConfiguration: Optional[PredictiveScalingConfiguration]


class PutScheduledUpdateGroupActionType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ScheduledActionName: XmlStringMaxLen255
    Time: Optional[TimestampType]
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    Recurrence: Optional[XmlStringMaxLen255]
    MinSize: Optional[AutoScalingGroupMinSize]
    MaxSize: Optional[AutoScalingGroupMaxSize]
    DesiredCapacity: Optional[AutoScalingGroupDesiredCapacity]
    TimeZone: Optional[XmlStringMaxLen255]


class PutWarmPoolAnswer(TypedDict, total=False):
    pass


class PutWarmPoolType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    MaxGroupPreparedCapacity: Optional[MaxGroupPreparedCapacity]
    MinSize: Optional[WarmPoolMinSize]
    PoolState: Optional[WarmPoolState]
    InstanceReusePolicy: Optional[InstanceReusePolicy]


class RecordLifecycleActionHeartbeatAnswer(TypedDict, total=False):
    pass


class RecordLifecycleActionHeartbeatType(ServiceRequest):
    LifecycleHookName: AsciiStringMaxLen255
    AutoScalingGroupName: ResourceName
    LifecycleActionToken: Optional[LifecycleActionToken]
    InstanceId: Optional[XmlStringMaxLen19]


class ScalingProcessQuery(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    ScalingProcesses: Optional[ProcessNames]


class ScheduledUpdateGroupAction(TypedDict, total=False):
    AutoScalingGroupName: Optional[XmlStringMaxLen255]
    ScheduledActionName: Optional[XmlStringMaxLen255]
    ScheduledActionARN: Optional[ResourceName]
    Time: Optional[TimestampType]
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    Recurrence: Optional[XmlStringMaxLen255]
    MinSize: Optional[AutoScalingGroupMinSize]
    MaxSize: Optional[AutoScalingGroupMaxSize]
    DesiredCapacity: Optional[AutoScalingGroupDesiredCapacity]
    TimeZone: Optional[XmlStringMaxLen255]


ScheduledUpdateGroupActions = List[ScheduledUpdateGroupAction]


class ScheduledActionsType(TypedDict, total=False):
    ScheduledUpdateGroupActions: Optional[ScheduledUpdateGroupActions]
    NextToken: Optional[XmlString]


class SetDesiredCapacityType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    DesiredCapacity: AutoScalingGroupDesiredCapacity
    HonorCooldown: Optional[HonorCooldown]


class SetInstanceHealthQuery(ServiceRequest):
    InstanceId: XmlStringMaxLen19
    HealthStatus: XmlStringMaxLen32
    ShouldRespectGracePeriod: Optional[ShouldRespectGracePeriod]


class SetInstanceProtectionAnswer(TypedDict, total=False):
    pass


class SetInstanceProtectionQuery(ServiceRequest):
    InstanceIds: InstanceIds
    AutoScalingGroupName: XmlStringMaxLen255
    ProtectedFromScaleIn: ProtectedFromScaleIn


class StartInstanceRefreshAnswer(TypedDict, total=False):
    InstanceRefreshId: Optional[XmlStringMaxLen255]


class StartInstanceRefreshType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    Strategy: Optional[RefreshStrategy]
    DesiredConfiguration: Optional[DesiredConfiguration]
    Preferences: Optional[RefreshPreferences]


class TagsType(TypedDict, total=False):
    Tags: Optional[TagDescriptionList]
    NextToken: Optional[XmlString]


class TerminateInstanceInAutoScalingGroupType(ServiceRequest):
    InstanceId: XmlStringMaxLen19
    ShouldDecrementDesiredCapacity: ShouldDecrementDesiredCapacity


class UpdateAutoScalingGroupType(ServiceRequest):
    AutoScalingGroupName: XmlStringMaxLen255
    LaunchConfigurationName: Optional[XmlStringMaxLen255]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    MixedInstancesPolicy: Optional[MixedInstancesPolicy]
    MinSize: Optional[AutoScalingGroupMinSize]
    MaxSize: Optional[AutoScalingGroupMaxSize]
    DesiredCapacity: Optional[AutoScalingGroupDesiredCapacity]
    DefaultCooldown: Optional[Cooldown]
    AvailabilityZones: Optional[AvailabilityZones]
    HealthCheckType: Optional[XmlStringMaxLen32]
    HealthCheckGracePeriod: Optional[HealthCheckGracePeriod]
    PlacementGroup: Optional[XmlStringMaxLen255]
    VPCZoneIdentifier: Optional[XmlStringMaxLen2047]
    TerminationPolicies: Optional[TerminationPolicies]
    NewInstancesProtectedFromScaleIn: Optional[InstanceProtected]
    ServiceLinkedRoleARN: Optional[ResourceName]
    MaxInstanceLifetime: Optional[MaxInstanceLifetime]
    CapacityRebalance: Optional[CapacityRebalanceEnabled]
    Context: Optional[Context]
    DesiredCapacityType: Optional[XmlStringMaxLen255]


class AutoscalingApi:

    service = "autoscaling"
    version = "2011-01-01"

    @handler("AttachInstances")
    def attach_instances(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        instance_ids: InstanceIds = None,
    ) -> None:
        raise NotImplementedError

    @handler("AttachLoadBalancerTargetGroups")
    def attach_load_balancer_target_groups(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        target_group_arns: TargetGroupARNs,
    ) -> AttachLoadBalancerTargetGroupsResultType:
        raise NotImplementedError

    @handler("AttachLoadBalancers")
    def attach_load_balancers(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        load_balancer_names: LoadBalancerNames,
    ) -> AttachLoadBalancersResultType:
        raise NotImplementedError

    @handler("BatchDeleteScheduledAction")
    def batch_delete_scheduled_action(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scheduled_action_names: ScheduledActionNames,
    ) -> BatchDeleteScheduledActionAnswer:
        raise NotImplementedError

    @handler("BatchPutScheduledUpdateGroupAction")
    def batch_put_scheduled_update_group_action(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scheduled_update_group_actions: ScheduledUpdateGroupActionRequests,
    ) -> BatchPutScheduledUpdateGroupActionAnswer:
        raise NotImplementedError

    @handler("CancelInstanceRefresh")
    def cancel_instance_refresh(
        self, context: RequestContext, auto_scaling_group_name: XmlStringMaxLen255
    ) -> CancelInstanceRefreshAnswer:
        raise NotImplementedError

    @handler("CompleteLifecycleAction")
    def complete_lifecycle_action(
        self,
        context: RequestContext,
        lifecycle_hook_name: AsciiStringMaxLen255,
        auto_scaling_group_name: ResourceName,
        lifecycle_action_result: LifecycleActionResult,
        lifecycle_action_token: LifecycleActionToken = None,
        instance_id: XmlStringMaxLen19 = None,
    ) -> CompleteLifecycleActionAnswer:
        raise NotImplementedError

    @handler("CreateAutoScalingGroup", expand=False)
    def create_auto_scaling_group(
        self, context: RequestContext, request: CreateAutoScalingGroupType
    ) -> None:
        raise NotImplementedError

    @handler("CreateLaunchConfiguration")
    def create_launch_configuration(
        self,
        context: RequestContext,
        launch_configuration_name: XmlStringMaxLen255,
        image_id: XmlStringMaxLen255 = None,
        key_name: XmlStringMaxLen255 = None,
        security_groups: SecurityGroups = None,
        classic_link_vpc_id: XmlStringMaxLen255 = None,
        classic_link_vpc_security_groups: ClassicLinkVPCSecurityGroups = None,
        user_data: XmlStringUserData = None,
        instance_id: XmlStringMaxLen19 = None,
        instance_type: XmlStringMaxLen255 = None,
        kernel_id: XmlStringMaxLen255 = None,
        ramdisk_id: XmlStringMaxLen255 = None,
        block_device_mappings: BlockDeviceMappings = None,
        instance_monitoring: InstanceMonitoring = None,
        spot_price: SpotPrice = None,
        iam_instance_profile: XmlStringMaxLen1600 = None,
        ebs_optimized: EbsOptimized = None,
        associate_public_ip_address: AssociatePublicIpAddress = None,
        placement_tenancy: XmlStringMaxLen64 = None,
        metadata_options: InstanceMetadataOptions = None,
    ) -> None:
        raise NotImplementedError

    @handler("CreateOrUpdateTags")
    def create_or_update_tags(self, context: RequestContext, tags: Tags) -> None:
        raise NotImplementedError

    @handler("DeleteAutoScalingGroup")
    def delete_auto_scaling_group(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        force_delete: ForceDelete = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLaunchConfiguration")
    def delete_launch_configuration(
        self, context: RequestContext, launch_configuration_name: XmlStringMaxLen255
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLifecycleHook")
    def delete_lifecycle_hook(
        self,
        context: RequestContext,
        lifecycle_hook_name: AsciiStringMaxLen255,
        auto_scaling_group_name: XmlStringMaxLen255,
    ) -> DeleteLifecycleHookAnswer:
        raise NotImplementedError

    @handler("DeleteNotificationConfiguration")
    def delete_notification_configuration(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        topic_arn: XmlStringMaxLen255,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(
        self,
        context: RequestContext,
        policy_name: ResourceName,
        auto_scaling_group_name: XmlStringMaxLen255 = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteScheduledAction")
    def delete_scheduled_action(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scheduled_action_name: XmlStringMaxLen255,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(self, context: RequestContext, tags: Tags) -> None:
        raise NotImplementedError

    @handler("DeleteWarmPool")
    def delete_warm_pool(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        force_delete: ForceDelete = None,
    ) -> DeleteWarmPoolAnswer:
        raise NotImplementedError

    @handler("DescribeAccountLimits")
    def describe_account_limits(
        self,
        context: RequestContext,
    ) -> DescribeAccountLimitsAnswer:
        raise NotImplementedError

    @handler("DescribeAdjustmentTypes")
    def describe_adjustment_types(
        self,
        context: RequestContext,
    ) -> DescribeAdjustmentTypesAnswer:
        raise NotImplementedError

    @handler("DescribeAutoScalingGroups")
    def describe_auto_scaling_groups(
        self,
        context: RequestContext,
        auto_scaling_group_names: AutoScalingGroupNames = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
        filters: Filters = None,
    ) -> AutoScalingGroupsType:
        raise NotImplementedError

    @handler("DescribeAutoScalingInstances")
    def describe_auto_scaling_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIds = None,
        max_records: MaxRecords = None,
        next_token: XmlString = None,
    ) -> AutoScalingInstancesType:
        raise NotImplementedError

    @handler("DescribeAutoScalingNotificationTypes")
    def describe_auto_scaling_notification_types(
        self,
        context: RequestContext,
    ) -> DescribeAutoScalingNotificationTypesAnswer:
        raise NotImplementedError

    @handler("DescribeInstanceRefreshes")
    def describe_instance_refreshes(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        instance_refresh_ids: InstanceRefreshIds = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> DescribeInstanceRefreshesAnswer:
        raise NotImplementedError

    @handler("DescribeLaunchConfigurations")
    def describe_launch_configurations(
        self,
        context: RequestContext,
        launch_configuration_names: LaunchConfigurationNames = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> LaunchConfigurationsType:
        raise NotImplementedError

    @handler("DescribeLifecycleHookTypes")
    def describe_lifecycle_hook_types(
        self,
        context: RequestContext,
    ) -> DescribeLifecycleHookTypesAnswer:
        raise NotImplementedError

    @handler("DescribeLifecycleHooks")
    def describe_lifecycle_hooks(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        lifecycle_hook_names: LifecycleHookNames = None,
    ) -> DescribeLifecycleHooksAnswer:
        raise NotImplementedError

    @handler("DescribeLoadBalancerTargetGroups")
    def describe_load_balancer_target_groups(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> DescribeLoadBalancerTargetGroupsResponse:
        raise NotImplementedError

    @handler("DescribeLoadBalancers")
    def describe_load_balancers(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> DescribeLoadBalancersResponse:
        raise NotImplementedError

    @handler("DescribeMetricCollectionTypes")
    def describe_metric_collection_types(
        self,
        context: RequestContext,
    ) -> DescribeMetricCollectionTypesAnswer:
        raise NotImplementedError

    @handler("DescribeNotificationConfigurations")
    def describe_notification_configurations(
        self,
        context: RequestContext,
        auto_scaling_group_names: AutoScalingGroupNames = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> DescribeNotificationConfigurationsAnswer:
        raise NotImplementedError

    @handler("DescribePolicies")
    def describe_policies(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255 = None,
        policy_names: PolicyNames = None,
        policy_types: PolicyTypes = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> PoliciesType:
        raise NotImplementedError

    @handler("DescribeScalingActivities")
    def describe_scaling_activities(
        self,
        context: RequestContext,
        activity_ids: ActivityIds = None,
        auto_scaling_group_name: XmlStringMaxLen255 = None,
        include_deleted_groups: IncludeDeletedGroups = None,
        max_records: MaxRecords = None,
        next_token: XmlString = None,
    ) -> ActivitiesType:
        raise NotImplementedError

    @handler("DescribeScalingProcessTypes")
    def describe_scaling_process_types(
        self,
        context: RequestContext,
    ) -> ProcessesType:
        raise NotImplementedError

    @handler("DescribeScheduledActions")
    def describe_scheduled_actions(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255 = None,
        scheduled_action_names: ScheduledActionNames = None,
        start_time: TimestampType = None,
        end_time: TimestampType = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> ScheduledActionsType:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self,
        context: RequestContext,
        filters: Filters = None,
        next_token: XmlString = None,
        max_records: MaxRecords = None,
    ) -> TagsType:
        raise NotImplementedError

    @handler("DescribeTerminationPolicyTypes")
    def describe_termination_policy_types(
        self,
        context: RequestContext,
    ) -> DescribeTerminationPolicyTypesAnswer:
        raise NotImplementedError

    @handler("DescribeWarmPool")
    def describe_warm_pool(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        max_records: MaxRecords = None,
        next_token: XmlString = None,
    ) -> DescribeWarmPoolAnswer:
        raise NotImplementedError

    @handler("DetachInstances")
    def detach_instances(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        should_decrement_desired_capacity: ShouldDecrementDesiredCapacity,
        instance_ids: InstanceIds = None,
    ) -> DetachInstancesAnswer:
        raise NotImplementedError

    @handler("DetachLoadBalancerTargetGroups")
    def detach_load_balancer_target_groups(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        target_group_arns: TargetGroupARNs,
    ) -> DetachLoadBalancerTargetGroupsResultType:
        raise NotImplementedError

    @handler("DetachLoadBalancers")
    def detach_load_balancers(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        load_balancer_names: LoadBalancerNames,
    ) -> DetachLoadBalancersResultType:
        raise NotImplementedError

    @handler("DisableMetricsCollection")
    def disable_metrics_collection(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        metrics: Metrics = None,
    ) -> None:
        raise NotImplementedError

    @handler("EnableMetricsCollection")
    def enable_metrics_collection(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        granularity: XmlStringMaxLen255,
        metrics: Metrics = None,
    ) -> None:
        raise NotImplementedError

    @handler("EnterStandby")
    def enter_standby(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        should_decrement_desired_capacity: ShouldDecrementDesiredCapacity,
        instance_ids: InstanceIds = None,
    ) -> EnterStandbyAnswer:
        raise NotImplementedError

    @handler("ExecutePolicy")
    def execute_policy(
        self,
        context: RequestContext,
        policy_name: ResourceName,
        auto_scaling_group_name: XmlStringMaxLen255 = None,
        honor_cooldown: HonorCooldown = None,
        metric_value: MetricScale = None,
        breach_threshold: MetricScale = None,
    ) -> None:
        raise NotImplementedError

    @handler("ExitStandby")
    def exit_standby(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        instance_ids: InstanceIds = None,
    ) -> ExitStandbyAnswer:
        raise NotImplementedError

    @handler("GetPredictiveScalingForecast")
    def get_predictive_scaling_forecast(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        policy_name: XmlStringMaxLen255,
        start_time: TimestampType,
        end_time: TimestampType,
    ) -> GetPredictiveScalingForecastAnswer:
        raise NotImplementedError

    @handler("PutLifecycleHook")
    def put_lifecycle_hook(
        self,
        context: RequestContext,
        lifecycle_hook_name: AsciiStringMaxLen255,
        auto_scaling_group_name: XmlStringMaxLen255,
        lifecycle_transition: LifecycleTransition = None,
        role_arn: XmlStringMaxLen255 = None,
        notification_target_arn: NotificationTargetResourceName = None,
        notification_metadata: XmlStringMaxLen1023 = None,
        heartbeat_timeout: HeartbeatTimeout = None,
        default_result: LifecycleActionResult = None,
    ) -> PutLifecycleHookAnswer:
        raise NotImplementedError

    @handler("PutNotificationConfiguration")
    def put_notification_configuration(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        topic_arn: XmlStringMaxLen255,
        notification_types: AutoScalingNotificationTypes,
    ) -> None:
        raise NotImplementedError

    @handler("PutScalingPolicy")
    def put_scaling_policy(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        policy_name: XmlStringMaxLen255,
        policy_type: XmlStringMaxLen64 = None,
        adjustment_type: XmlStringMaxLen255 = None,
        min_adjustment_step: MinAdjustmentStep = None,
        min_adjustment_magnitude: MinAdjustmentMagnitude = None,
        scaling_adjustment: PolicyIncrement = None,
        cooldown: Cooldown = None,
        metric_aggregation_type: XmlStringMaxLen32 = None,
        step_adjustments: StepAdjustments = None,
        estimated_instance_warmup: EstimatedInstanceWarmup = None,
        target_tracking_configuration: TargetTrackingConfiguration = None,
        enabled: ScalingPolicyEnabled = None,
        predictive_scaling_configuration: PredictiveScalingConfiguration = None,
    ) -> PolicyARNType:
        raise NotImplementedError

    @handler("PutScheduledUpdateGroupAction")
    def put_scheduled_update_group_action(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scheduled_action_name: XmlStringMaxLen255,
        time: TimestampType = None,
        start_time: TimestampType = None,
        end_time: TimestampType = None,
        recurrence: XmlStringMaxLen255 = None,
        min_size: AutoScalingGroupMinSize = None,
        max_size: AutoScalingGroupMaxSize = None,
        desired_capacity: AutoScalingGroupDesiredCapacity = None,
        time_zone: XmlStringMaxLen255 = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutWarmPool")
    def put_warm_pool(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        max_group_prepared_capacity: MaxGroupPreparedCapacity = None,
        min_size: WarmPoolMinSize = None,
        pool_state: WarmPoolState = None,
        instance_reuse_policy: InstanceReusePolicy = None,
    ) -> PutWarmPoolAnswer:
        raise NotImplementedError

    @handler("RecordLifecycleActionHeartbeat")
    def record_lifecycle_action_heartbeat(
        self,
        context: RequestContext,
        lifecycle_hook_name: AsciiStringMaxLen255,
        auto_scaling_group_name: ResourceName,
        lifecycle_action_token: LifecycleActionToken = None,
        instance_id: XmlStringMaxLen19 = None,
    ) -> RecordLifecycleActionHeartbeatAnswer:
        raise NotImplementedError

    @handler("ResumeProcesses")
    def resume_processes(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scaling_processes: ProcessNames = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetDesiredCapacity")
    def set_desired_capacity(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        desired_capacity: AutoScalingGroupDesiredCapacity,
        honor_cooldown: HonorCooldown = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetInstanceHealth")
    def set_instance_health(
        self,
        context: RequestContext,
        instance_id: XmlStringMaxLen19,
        health_status: XmlStringMaxLen32,
        should_respect_grace_period: ShouldRespectGracePeriod = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetInstanceProtection")
    def set_instance_protection(
        self,
        context: RequestContext,
        instance_ids: InstanceIds,
        auto_scaling_group_name: XmlStringMaxLen255,
        protected_from_scale_in: ProtectedFromScaleIn,
    ) -> SetInstanceProtectionAnswer:
        raise NotImplementedError

    @handler("StartInstanceRefresh")
    def start_instance_refresh(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        strategy: RefreshStrategy = None,
        desired_configuration: DesiredConfiguration = None,
        preferences: RefreshPreferences = None,
    ) -> StartInstanceRefreshAnswer:
        raise NotImplementedError

    @handler("SuspendProcesses")
    def suspend_processes(
        self,
        context: RequestContext,
        auto_scaling_group_name: XmlStringMaxLen255,
        scaling_processes: ProcessNames = None,
    ) -> None:
        raise NotImplementedError

    @handler("TerminateInstanceInAutoScalingGroup")
    def terminate_instance_in_auto_scaling_group(
        self,
        context: RequestContext,
        instance_id: XmlStringMaxLen19,
        should_decrement_desired_capacity: ShouldDecrementDesiredCapacity,
    ) -> ActivityType:
        raise NotImplementedError

    @handler("UpdateAutoScalingGroup", expand=False)
    def update_auto_scaling_group(
        self, context: RequestContext, request: UpdateAutoScalingGroupType
    ) -> None:
        raise NotImplementedError
