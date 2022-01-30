import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ArnType = str
Boolean = bool
BooleanObject = bool
ClusterId = str
ErrorCode = str
ErrorMessage = str
InstanceFleetId = str
InstanceGroupId = str
InstanceId = str
InstanceType = str
Integer = int
Marker = str
MaxResultsNumber = int
NonNegativeDouble = float
OptionalArnType = str
Port = int
ResourceId = str
StepId = str
String = str
WholeNumber = int
XmlString = str
XmlStringMaxLen256 = str


class ActionOnFailure(str):
    TERMINATE_JOB_FLOW = "TERMINATE_JOB_FLOW"
    TERMINATE_CLUSTER = "TERMINATE_CLUSTER"
    CANCEL_AND_WAIT = "CANCEL_AND_WAIT"
    CONTINUE = "CONTINUE"


class AdjustmentType(str):
    CHANGE_IN_CAPACITY = "CHANGE_IN_CAPACITY"
    PERCENT_CHANGE_IN_CAPACITY = "PERCENT_CHANGE_IN_CAPACITY"
    EXACT_CAPACITY = "EXACT_CAPACITY"


class AuthMode(str):
    SSO = "SSO"
    IAM = "IAM"


class AutoScalingPolicyState(str):
    PENDING = "PENDING"
    ATTACHING = "ATTACHING"
    ATTACHED = "ATTACHED"
    DETACHING = "DETACHING"
    DETACHED = "DETACHED"
    FAILED = "FAILED"


class AutoScalingPolicyStateChangeReasonCode(str):
    USER_REQUEST = "USER_REQUEST"
    PROVISION_FAILURE = "PROVISION_FAILURE"
    CLEANUP_FAILURE = "CLEANUP_FAILURE"


class CancelStepsRequestStatus(str):
    SUBMITTED = "SUBMITTED"
    FAILED = "FAILED"


class ClusterState(str):
    STARTING = "STARTING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    TERMINATED_WITH_ERRORS = "TERMINATED_WITH_ERRORS"


class ClusterStateChangeReasonCode(str):
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INSTANCE_FAILURE = "INSTANCE_FAILURE"
    INSTANCE_FLEET_TIMEOUT = "INSTANCE_FLEET_TIMEOUT"
    BOOTSTRAP_FAILURE = "BOOTSTRAP_FAILURE"
    USER_REQUEST = "USER_REQUEST"
    STEP_FAILURE = "STEP_FAILURE"
    ALL_STEPS_COMPLETED = "ALL_STEPS_COMPLETED"


class ComparisonOperator(str):
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"


class ComputeLimitsUnitType(str):
    InstanceFleetUnits = "InstanceFleetUnits"
    Instances = "Instances"
    VCPU = "VCPU"


class ExecutionEngineType(str):
    EMR = "EMR"


class IdentityType(str):
    USER = "USER"
    GROUP = "GROUP"


class InstanceCollectionType(str):
    INSTANCE_FLEET = "INSTANCE_FLEET"
    INSTANCE_GROUP = "INSTANCE_GROUP"


class InstanceFleetState(str):
    PROVISIONING = "PROVISIONING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    RESIZING = "RESIZING"
    SUSPENDED = "SUSPENDED"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"


class InstanceFleetStateChangeReasonCode(str):
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INSTANCE_FAILURE = "INSTANCE_FAILURE"
    CLUSTER_TERMINATED = "CLUSTER_TERMINATED"


class InstanceFleetType(str):
    MASTER = "MASTER"
    CORE = "CORE"
    TASK = "TASK"


class InstanceGroupState(str):
    PROVISIONING = "PROVISIONING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    RECONFIGURING = "RECONFIGURING"
    RESIZING = "RESIZING"
    SUSPENDED = "SUSPENDED"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    ARRESTED = "ARRESTED"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    ENDED = "ENDED"


class InstanceGroupStateChangeReasonCode(str):
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INSTANCE_FAILURE = "INSTANCE_FAILURE"
    CLUSTER_TERMINATED = "CLUSTER_TERMINATED"


class InstanceGroupType(str):
    MASTER = "MASTER"
    CORE = "CORE"
    TASK = "TASK"


class InstanceRoleType(str):
    MASTER = "MASTER"
    CORE = "CORE"
    TASK = "TASK"


class InstanceState(str):
    AWAITING_FULFILLMENT = "AWAITING_FULFILLMENT"
    PROVISIONING = "PROVISIONING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    TERMINATED = "TERMINATED"


class InstanceStateChangeReasonCode(str):
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INSTANCE_FAILURE = "INSTANCE_FAILURE"
    BOOTSTRAP_FAILURE = "BOOTSTRAP_FAILURE"
    CLUSTER_TERMINATED = "CLUSTER_TERMINATED"


class JobFlowExecutionState(str):
    STARTING = "STARTING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    TERMINATED = "TERMINATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class MarketType(str):
    ON_DEMAND = "ON_DEMAND"
    SPOT = "SPOT"


class NotebookExecutionStatus(str):
    START_PENDING = "START_PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    FINISHING = "FINISHING"
    FINISHED = "FINISHED"
    FAILING = "FAILING"
    FAILED = "FAILED"
    STOP_PENDING = "STOP_PENDING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class OnDemandCapacityReservationPreference(str):
    open = "open"
    none = "none"


class OnDemandCapacityReservationUsageStrategy(str):
    use_capacity_reservations_first = "use-capacity-reservations-first"


class OnDemandProvisioningAllocationStrategy(str):
    lowest_price = "lowest-price"


class PlacementGroupStrategy(str):
    SPREAD = "SPREAD"
    PARTITION = "PARTITION"
    CLUSTER = "CLUSTER"
    NONE = "NONE"


class RepoUpgradeOnBoot(str):
    SECURITY = "SECURITY"
    NONE = "NONE"


class ScaleDownBehavior(str):
    TERMINATE_AT_INSTANCE_HOUR = "TERMINATE_AT_INSTANCE_HOUR"
    TERMINATE_AT_TASK_COMPLETION = "TERMINATE_AT_TASK_COMPLETION"


class SpotProvisioningAllocationStrategy(str):
    capacity_optimized = "capacity-optimized"


class SpotProvisioningTimeoutAction(str):
    SWITCH_TO_ON_DEMAND = "SWITCH_TO_ON_DEMAND"
    TERMINATE_CLUSTER = "TERMINATE_CLUSTER"


class Statistic(str):
    SAMPLE_COUNT = "SAMPLE_COUNT"
    AVERAGE = "AVERAGE"
    SUM = "SUM"
    MINIMUM = "MINIMUM"
    MAXIMUM = "MAXIMUM"


class StepCancellationOption(str):
    SEND_INTERRUPT = "SEND_INTERRUPT"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"


class StepExecutionState(str):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    CONTINUE = "CONTINUE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class StepState(str):
    PENDING = "PENDING"
    CANCEL_PENDING = "CANCEL_PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class StepStateChangeReasonCode(str):
    NONE = "NONE"


class Unit(str):
    NONE = "NONE"
    SECONDS = "SECONDS"
    MICRO_SECONDS = "MICRO_SECONDS"
    MILLI_SECONDS = "MILLI_SECONDS"
    BYTES = "BYTES"
    KILO_BYTES = "KILO_BYTES"
    MEGA_BYTES = "MEGA_BYTES"
    GIGA_BYTES = "GIGA_BYTES"
    TERA_BYTES = "TERA_BYTES"
    BITS = "BITS"
    KILO_BITS = "KILO_BITS"
    MEGA_BITS = "MEGA_BITS"
    GIGA_BITS = "GIGA_BITS"
    TERA_BITS = "TERA_BITS"
    PERCENT = "PERCENT"
    COUNT = "COUNT"
    BYTES_PER_SECOND = "BYTES_PER_SECOND"
    KILO_BYTES_PER_SECOND = "KILO_BYTES_PER_SECOND"
    MEGA_BYTES_PER_SECOND = "MEGA_BYTES_PER_SECOND"
    GIGA_BYTES_PER_SECOND = "GIGA_BYTES_PER_SECOND"
    TERA_BYTES_PER_SECOND = "TERA_BYTES_PER_SECOND"
    BITS_PER_SECOND = "BITS_PER_SECOND"
    KILO_BITS_PER_SECOND = "KILO_BITS_PER_SECOND"
    MEGA_BITS_PER_SECOND = "MEGA_BITS_PER_SECOND"
    GIGA_BITS_PER_SECOND = "GIGA_BITS_PER_SECOND"
    TERA_BITS_PER_SECOND = "TERA_BITS_PER_SECOND"
    COUNT_PER_SECOND = "COUNT_PER_SECOND"


class InternalServerError(ServiceException):
    pass


class InternalServerException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidRequestException(ServiceException):
    ErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class OnDemandCapacityReservationOptions(TypedDict, total=False):
    UsageStrategy: Optional[OnDemandCapacityReservationUsageStrategy]
    CapacityReservationPreference: Optional[OnDemandCapacityReservationPreference]
    CapacityReservationResourceGroupArn: Optional[XmlStringMaxLen256]


class OnDemandProvisioningSpecification(TypedDict, total=False):
    AllocationStrategy: OnDemandProvisioningAllocationStrategy
    CapacityReservationOptions: Optional[OnDemandCapacityReservationOptions]


class SpotProvisioningSpecification(TypedDict, total=False):
    TimeoutDurationMinutes: WholeNumber
    TimeoutAction: SpotProvisioningTimeoutAction
    BlockDurationMinutes: Optional[WholeNumber]
    AllocationStrategy: Optional[SpotProvisioningAllocationStrategy]


class InstanceFleetProvisioningSpecifications(TypedDict, total=False):
    SpotSpecification: Optional[SpotProvisioningSpecification]
    OnDemandSpecification: Optional[OnDemandProvisioningSpecification]


StringMap = Dict[String, String]
ConfigurationList = List["Configuration"]


class Configuration(TypedDict, total=False):
    Classification: Optional[String]
    Configurations: Optional[ConfigurationList]
    Properties: Optional[StringMap]


class VolumeSpecification(TypedDict, total=False):
    VolumeType: String
    Iops: Optional[Integer]
    SizeInGB: Integer


class EbsBlockDeviceConfig(TypedDict, total=False):
    VolumeSpecification: VolumeSpecification
    VolumesPerInstance: Optional[Integer]


EbsBlockDeviceConfigList = List[EbsBlockDeviceConfig]


class EbsConfiguration(TypedDict, total=False):
    EbsBlockDeviceConfigs: Optional[EbsBlockDeviceConfigList]
    EbsOptimized: Optional[BooleanObject]


class InstanceTypeConfig(TypedDict, total=False):
    InstanceType: InstanceType
    WeightedCapacity: Optional[WholeNumber]
    BidPrice: Optional[XmlStringMaxLen256]
    BidPriceAsPercentageOfOnDemandPrice: Optional[NonNegativeDouble]
    EbsConfiguration: Optional[EbsConfiguration]
    Configurations: Optional[ConfigurationList]
    CustomAmiId: Optional[XmlStringMaxLen256]


InstanceTypeConfigList = List[InstanceTypeConfig]


class InstanceFleetConfig(TypedDict, total=False):
    Name: Optional[XmlStringMaxLen256]
    InstanceFleetType: InstanceFleetType
    TargetOnDemandCapacity: Optional[WholeNumber]
    TargetSpotCapacity: Optional[WholeNumber]
    InstanceTypeConfigs: Optional[InstanceTypeConfigList]
    LaunchSpecifications: Optional[InstanceFleetProvisioningSpecifications]


class AddInstanceFleetInput(ServiceRequest):
    ClusterId: XmlStringMaxLen256
    InstanceFleet: InstanceFleetConfig


class AddInstanceFleetOutput(TypedDict, total=False):
    ClusterId: Optional[XmlStringMaxLen256]
    InstanceFleetId: Optional[InstanceFleetId]
    ClusterArn: Optional[ArnType]


class MetricDimension(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


MetricDimensionList = List[MetricDimension]


class CloudWatchAlarmDefinition(TypedDict, total=False):
    ComparisonOperator: ComparisonOperator
    EvaluationPeriods: Optional[Integer]
    MetricName: String
    Namespace: Optional[String]
    Period: Integer
    Statistic: Optional[Statistic]
    Threshold: NonNegativeDouble
    Unit: Optional[Unit]
    Dimensions: Optional[MetricDimensionList]


class ScalingTrigger(TypedDict, total=False):
    CloudWatchAlarmDefinition: CloudWatchAlarmDefinition


class SimpleScalingPolicyConfiguration(TypedDict, total=False):
    AdjustmentType: Optional[AdjustmentType]
    ScalingAdjustment: Integer
    CoolDown: Optional[Integer]


class ScalingAction(TypedDict, total=False):
    Market: Optional[MarketType]
    SimpleScalingPolicyConfiguration: SimpleScalingPolicyConfiguration


class ScalingRule(TypedDict, total=False):
    Name: String
    Description: Optional[String]
    Action: ScalingAction
    Trigger: ScalingTrigger


ScalingRuleList = List[ScalingRule]


class ScalingConstraints(TypedDict, total=False):
    MinCapacity: Integer
    MaxCapacity: Integer


class AutoScalingPolicy(TypedDict, total=False):
    Constraints: ScalingConstraints
    Rules: ScalingRuleList


class InstanceGroupConfig(TypedDict, total=False):
    Name: Optional[XmlStringMaxLen256]
    Market: Optional[MarketType]
    InstanceRole: InstanceRoleType
    BidPrice: Optional[XmlStringMaxLen256]
    InstanceType: InstanceType
    InstanceCount: Integer
    Configurations: Optional[ConfigurationList]
    EbsConfiguration: Optional[EbsConfiguration]
    AutoScalingPolicy: Optional[AutoScalingPolicy]
    CustomAmiId: Optional[XmlStringMaxLen256]


InstanceGroupConfigList = List[InstanceGroupConfig]


class AddInstanceGroupsInput(ServiceRequest):
    InstanceGroups: InstanceGroupConfigList
    JobFlowId: XmlStringMaxLen256


InstanceGroupIdsList = List[XmlStringMaxLen256]


class AddInstanceGroupsOutput(TypedDict, total=False):
    JobFlowId: Optional[XmlStringMaxLen256]
    InstanceGroupIds: Optional[InstanceGroupIdsList]
    ClusterArn: Optional[ArnType]


XmlStringList = List[XmlString]


class KeyValue(TypedDict, total=False):
    Key: Optional[XmlString]
    Value: Optional[XmlString]


KeyValueList = List[KeyValue]


class HadoopJarStepConfig(TypedDict, total=False):
    Properties: Optional[KeyValueList]
    Jar: XmlString
    MainClass: Optional[XmlString]
    Args: Optional[XmlStringList]


class StepConfig(TypedDict, total=False):
    Name: XmlStringMaxLen256
    ActionOnFailure: Optional[ActionOnFailure]
    HadoopJarStep: HadoopJarStepConfig


StepConfigList = List[StepConfig]


class AddJobFlowStepsInput(ServiceRequest):
    JobFlowId: XmlStringMaxLen256
    Steps: StepConfigList


StepIdsList = List[XmlStringMaxLen256]


class AddJobFlowStepsOutput(TypedDict, total=False):
    StepIds: Optional[StepIdsList]


class Tag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


TagList = List[Tag]


class AddTagsInput(ServiceRequest):
    ResourceId: ResourceId
    Tags: TagList


class AddTagsOutput(TypedDict, total=False):
    pass


StringList = List[String]


class Application(TypedDict, total=False):
    Name: Optional[String]
    Version: Optional[String]
    Args: Optional[StringList]
    AdditionalInfo: Optional[StringMap]


ApplicationList = List[Application]


class AutoScalingPolicyStateChangeReason(TypedDict, total=False):
    Code: Optional[AutoScalingPolicyStateChangeReasonCode]
    Message: Optional[String]


class AutoScalingPolicyStatus(TypedDict, total=False):
    State: Optional[AutoScalingPolicyState]
    StateChangeReason: Optional[AutoScalingPolicyStateChangeReason]


class AutoScalingPolicyDescription(TypedDict, total=False):
    Status: Optional[AutoScalingPolicyStatus]
    Constraints: Optional[ScalingConstraints]
    Rules: Optional[ScalingRuleList]


Long = int


class AutoTerminationPolicy(TypedDict, total=False):
    IdleTimeout: Optional[Long]


class PortRange(TypedDict, total=False):
    MinRange: Port
    MaxRange: Optional[Port]


PortRanges = List[PortRange]


class BlockPublicAccessConfiguration(TypedDict, total=False):
    BlockPublicSecurityGroupRules: Boolean
    PermittedPublicSecurityGroupRuleRanges: Optional[PortRanges]


Date = datetime


class BlockPublicAccessConfigurationMetadata(TypedDict, total=False):
    CreationDateTime: Date
    CreatedByArn: ArnType


class ScriptBootstrapActionConfig(TypedDict, total=False):
    Path: XmlString
    Args: Optional[XmlStringList]


class BootstrapActionConfig(TypedDict, total=False):
    Name: XmlStringMaxLen256
    ScriptBootstrapAction: ScriptBootstrapActionConfig


BootstrapActionConfigList = List[BootstrapActionConfig]


class BootstrapActionDetail(TypedDict, total=False):
    BootstrapActionConfig: Optional[BootstrapActionConfig]


BootstrapActionDetailList = List[BootstrapActionDetail]


class CancelStepsInfo(TypedDict, total=False):
    StepId: Optional[StepId]
    Status: Optional[CancelStepsRequestStatus]
    Reason: Optional[String]


CancelStepsInfoList = List[CancelStepsInfo]


class CancelStepsInput(ServiceRequest):
    ClusterId: XmlStringMaxLen256
    StepIds: StepIdsList
    StepCancellationOption: Optional[StepCancellationOption]


class CancelStepsOutput(TypedDict, total=False):
    CancelStepsInfoList: Optional[CancelStepsInfoList]


class PlacementGroupConfig(TypedDict, total=False):
    InstanceRole: InstanceRoleType
    PlacementStrategy: Optional[PlacementGroupStrategy]


PlacementGroupConfigList = List[PlacementGroupConfig]


class KerberosAttributes(TypedDict, total=False):
    Realm: XmlStringMaxLen256
    KdcAdminPassword: XmlStringMaxLen256
    CrossRealmTrustPrincipalPassword: Optional[XmlStringMaxLen256]
    ADDomainJoinUser: Optional[XmlStringMaxLen256]
    ADDomainJoinPassword: Optional[XmlStringMaxLen256]


XmlStringMaxLen256List = List[XmlStringMaxLen256]


class Ec2InstanceAttributes(TypedDict, total=False):
    Ec2KeyName: Optional[String]
    Ec2SubnetId: Optional[String]
    RequestedEc2SubnetIds: Optional[XmlStringMaxLen256List]
    Ec2AvailabilityZone: Optional[String]
    RequestedEc2AvailabilityZones: Optional[XmlStringMaxLen256List]
    IamInstanceProfile: Optional[String]
    EmrManagedMasterSecurityGroup: Optional[String]
    EmrManagedSlaveSecurityGroup: Optional[String]
    ServiceAccessSecurityGroup: Optional[String]
    AdditionalMasterSecurityGroups: Optional[StringList]
    AdditionalSlaveSecurityGroups: Optional[StringList]


class ClusterTimeline(TypedDict, total=False):
    CreationDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]


class ClusterStateChangeReason(TypedDict, total=False):
    Code: Optional[ClusterStateChangeReasonCode]
    Message: Optional[String]


class ClusterStatus(TypedDict, total=False):
    State: Optional[ClusterState]
    StateChangeReason: Optional[ClusterStateChangeReason]
    Timeline: Optional[ClusterTimeline]


class Cluster(TypedDict, total=False):
    Id: Optional[ClusterId]
    Name: Optional[String]
    Status: Optional[ClusterStatus]
    Ec2InstanceAttributes: Optional[Ec2InstanceAttributes]
    InstanceCollectionType: Optional[InstanceCollectionType]
    LogUri: Optional[String]
    LogEncryptionKmsKeyId: Optional[String]
    RequestedAmiVersion: Optional[String]
    RunningAmiVersion: Optional[String]
    ReleaseLabel: Optional[String]
    AutoTerminate: Optional[Boolean]
    TerminationProtected: Optional[Boolean]
    VisibleToAllUsers: Optional[Boolean]
    Applications: Optional[ApplicationList]
    Tags: Optional[TagList]
    ServiceRole: Optional[String]
    NormalizedInstanceHours: Optional[Integer]
    MasterPublicDnsName: Optional[String]
    Configurations: Optional[ConfigurationList]
    SecurityConfiguration: Optional[XmlString]
    AutoScalingRole: Optional[XmlString]
    ScaleDownBehavior: Optional[ScaleDownBehavior]
    CustomAmiId: Optional[XmlStringMaxLen256]
    EbsRootVolumeSize: Optional[Integer]
    RepoUpgradeOnBoot: Optional[RepoUpgradeOnBoot]
    KerberosAttributes: Optional[KerberosAttributes]
    ClusterArn: Optional[ArnType]
    OutpostArn: Optional[OptionalArnType]
    StepConcurrencyLevel: Optional[Integer]
    PlacementGroups: Optional[PlacementGroupConfigList]


ClusterStateList = List[ClusterState]


class ClusterSummary(TypedDict, total=False):
    Id: Optional[ClusterId]
    Name: Optional[String]
    Status: Optional[ClusterStatus]
    NormalizedInstanceHours: Optional[Integer]
    ClusterArn: Optional[ArnType]
    OutpostArn: Optional[OptionalArnType]


ClusterSummaryList = List[ClusterSummary]


class Command(TypedDict, total=False):
    Name: Optional[String]
    ScriptPath: Optional[String]
    Args: Optional[StringList]


CommandList = List[Command]


class ComputeLimits(TypedDict, total=False):
    UnitType: ComputeLimitsUnitType
    MinimumCapacityUnits: Integer
    MaximumCapacityUnits: Integer
    MaximumOnDemandCapacityUnits: Optional[Integer]
    MaximumCoreCapacityUnits: Optional[Integer]


class CreateSecurityConfigurationInput(ServiceRequest):
    Name: XmlString
    SecurityConfiguration: String


class CreateSecurityConfigurationOutput(TypedDict, total=False):
    Name: XmlString
    CreationDateTime: Date


SubnetIdList = List[String]


class CreateStudioInput(ServiceRequest):
    Name: XmlStringMaxLen256
    Description: Optional[XmlStringMaxLen256]
    AuthMode: AuthMode
    VpcId: XmlStringMaxLen256
    SubnetIds: SubnetIdList
    ServiceRole: XmlString
    UserRole: Optional[XmlString]
    WorkspaceSecurityGroupId: XmlStringMaxLen256
    EngineSecurityGroupId: XmlStringMaxLen256
    DefaultS3Location: XmlString
    IdpAuthUrl: Optional[XmlString]
    IdpRelayStateParameterName: Optional[XmlStringMaxLen256]
    Tags: Optional[TagList]


class CreateStudioOutput(TypedDict, total=False):
    StudioId: Optional[XmlStringMaxLen256]
    Url: Optional[XmlString]


class CreateStudioSessionMappingInput(ServiceRequest):
    StudioId: XmlStringMaxLen256
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: IdentityType
    SessionPolicyArn: XmlStringMaxLen256


class DeleteSecurityConfigurationInput(ServiceRequest):
    Name: XmlString


class DeleteSecurityConfigurationOutput(TypedDict, total=False):
    pass


class DeleteStudioInput(ServiceRequest):
    StudioId: XmlStringMaxLen256


class DeleteStudioSessionMappingInput(ServiceRequest):
    StudioId: XmlStringMaxLen256
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: IdentityType


class DescribeClusterInput(ServiceRequest):
    ClusterId: ClusterId


class DescribeClusterOutput(TypedDict, total=False):
    Cluster: Optional[Cluster]


JobFlowExecutionStateList = List[JobFlowExecutionState]


class DescribeJobFlowsInput(ServiceRequest):
    CreatedAfter: Optional[Date]
    CreatedBefore: Optional[Date]
    JobFlowIds: Optional[XmlStringList]
    JobFlowStates: Optional[JobFlowExecutionStateList]


SupportedProductsList = List[XmlStringMaxLen256]


class StepExecutionStatusDetail(TypedDict, total=False):
    State: StepExecutionState
    CreationDateTime: Date
    StartDateTime: Optional[Date]
    EndDateTime: Optional[Date]
    LastStateChangeReason: Optional[XmlString]


class StepDetail(TypedDict, total=False):
    StepConfig: StepConfig
    ExecutionStatusDetail: StepExecutionStatusDetail


StepDetailList = List[StepDetail]


class PlacementType(TypedDict, total=False):
    AvailabilityZone: Optional[XmlString]
    AvailabilityZones: Optional[XmlStringMaxLen256List]


class InstanceGroupDetail(TypedDict, total=False):
    InstanceGroupId: Optional[XmlStringMaxLen256]
    Name: Optional[XmlStringMaxLen256]
    Market: MarketType
    InstanceRole: InstanceRoleType
    BidPrice: Optional[XmlStringMaxLen256]
    InstanceType: InstanceType
    InstanceRequestCount: Integer
    InstanceRunningCount: Integer
    State: InstanceGroupState
    LastStateChangeReason: Optional[XmlString]
    CreationDateTime: Date
    StartDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]
    CustomAmiId: Optional[XmlStringMaxLen256]


InstanceGroupDetailList = List[InstanceGroupDetail]


class JobFlowInstancesDetail(TypedDict, total=False):
    MasterInstanceType: InstanceType
    MasterPublicDnsName: Optional[XmlString]
    MasterInstanceId: Optional[XmlString]
    SlaveInstanceType: InstanceType
    InstanceCount: Integer
    InstanceGroups: Optional[InstanceGroupDetailList]
    NormalizedInstanceHours: Optional[Integer]
    Ec2KeyName: Optional[XmlStringMaxLen256]
    Ec2SubnetId: Optional[XmlStringMaxLen256]
    Placement: Optional[PlacementType]
    KeepJobFlowAliveWhenNoSteps: Optional[Boolean]
    TerminationProtected: Optional[Boolean]
    HadoopVersion: Optional[XmlStringMaxLen256]


class JobFlowExecutionStatusDetail(TypedDict, total=False):
    State: JobFlowExecutionState
    CreationDateTime: Date
    StartDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]
    LastStateChangeReason: Optional[XmlString]


class JobFlowDetail(TypedDict, total=False):
    JobFlowId: XmlStringMaxLen256
    Name: XmlStringMaxLen256
    LogUri: Optional[XmlString]
    LogEncryptionKmsKeyId: Optional[XmlString]
    AmiVersion: Optional[XmlStringMaxLen256]
    ExecutionStatusDetail: JobFlowExecutionStatusDetail
    Instances: JobFlowInstancesDetail
    Steps: Optional[StepDetailList]
    BootstrapActions: Optional[BootstrapActionDetailList]
    SupportedProducts: Optional[SupportedProductsList]
    VisibleToAllUsers: Optional[Boolean]
    JobFlowRole: Optional[XmlString]
    ServiceRole: Optional[XmlString]
    AutoScalingRole: Optional[XmlString]
    ScaleDownBehavior: Optional[ScaleDownBehavior]


JobFlowDetailList = List[JobFlowDetail]


class DescribeJobFlowsOutput(TypedDict, total=False):
    JobFlows: Optional[JobFlowDetailList]


class DescribeNotebookExecutionInput(ServiceRequest):
    NotebookExecutionId: XmlStringMaxLen256


class ExecutionEngineConfig(TypedDict, total=False):
    Id: XmlStringMaxLen256
    Type: Optional[ExecutionEngineType]
    MasterInstanceSecurityGroupId: Optional[XmlStringMaxLen256]


class NotebookExecution(TypedDict, total=False):
    NotebookExecutionId: Optional[XmlStringMaxLen256]
    EditorId: Optional[XmlStringMaxLen256]
    ExecutionEngine: Optional[ExecutionEngineConfig]
    NotebookExecutionName: Optional[XmlStringMaxLen256]
    NotebookParams: Optional[XmlString]
    Status: Optional[NotebookExecutionStatus]
    StartTime: Optional[Date]
    EndTime: Optional[Date]
    Arn: Optional[XmlStringMaxLen256]
    OutputNotebookURI: Optional[XmlString]
    LastStateChangeReason: Optional[XmlString]
    NotebookInstanceSecurityGroupId: Optional[XmlStringMaxLen256]
    Tags: Optional[TagList]


class DescribeNotebookExecutionOutput(TypedDict, total=False):
    NotebookExecution: Optional[NotebookExecution]


class DescribeReleaseLabelInput(ServiceRequest):
    ReleaseLabel: Optional[String]
    NextToken: Optional[String]
    MaxResults: Optional[MaxResultsNumber]


class SimplifiedApplication(TypedDict, total=False):
    Name: Optional[String]
    Version: Optional[String]


SimplifiedApplicationList = List[SimplifiedApplication]


class DescribeReleaseLabelOutput(TypedDict, total=False):
    ReleaseLabel: Optional[String]
    Applications: Optional[SimplifiedApplicationList]
    NextToken: Optional[String]


class DescribeSecurityConfigurationInput(ServiceRequest):
    Name: XmlString


class DescribeSecurityConfigurationOutput(TypedDict, total=False):
    Name: Optional[XmlString]
    SecurityConfiguration: Optional[String]
    CreationDateTime: Optional[Date]


class DescribeStepInput(ServiceRequest):
    ClusterId: ClusterId
    StepId: StepId


class StepTimeline(TypedDict, total=False):
    CreationDateTime: Optional[Date]
    StartDateTime: Optional[Date]
    EndDateTime: Optional[Date]


class FailureDetails(TypedDict, total=False):
    Reason: Optional[String]
    Message: Optional[String]
    LogFile: Optional[String]


class StepStateChangeReason(TypedDict, total=False):
    Code: Optional[StepStateChangeReasonCode]
    Message: Optional[String]


class StepStatus(TypedDict, total=False):
    State: Optional[StepState]
    StateChangeReason: Optional[StepStateChangeReason]
    FailureDetails: Optional[FailureDetails]
    Timeline: Optional[StepTimeline]


class HadoopStepConfig(TypedDict, total=False):
    Jar: Optional[String]
    Properties: Optional[StringMap]
    MainClass: Optional[String]
    Args: Optional[StringList]


class Step(TypedDict, total=False):
    Id: Optional[StepId]
    Name: Optional[String]
    Config: Optional[HadoopStepConfig]
    ActionOnFailure: Optional[ActionOnFailure]
    Status: Optional[StepStatus]


class DescribeStepOutput(TypedDict, total=False):
    Step: Optional[Step]


class DescribeStudioInput(ServiceRequest):
    StudioId: XmlStringMaxLen256


class Studio(TypedDict, total=False):
    StudioId: Optional[XmlStringMaxLen256]
    StudioArn: Optional[XmlStringMaxLen256]
    Name: Optional[XmlStringMaxLen256]
    Description: Optional[XmlStringMaxLen256]
    AuthMode: Optional[AuthMode]
    VpcId: Optional[XmlStringMaxLen256]
    SubnetIds: Optional[SubnetIdList]
    ServiceRole: Optional[XmlString]
    UserRole: Optional[XmlString]
    WorkspaceSecurityGroupId: Optional[XmlStringMaxLen256]
    EngineSecurityGroupId: Optional[XmlStringMaxLen256]
    Url: Optional[XmlString]
    CreationTime: Optional[Date]
    DefaultS3Location: Optional[XmlString]
    IdpAuthUrl: Optional[XmlString]
    IdpRelayStateParameterName: Optional[XmlStringMaxLen256]
    Tags: Optional[TagList]


class DescribeStudioOutput(TypedDict, total=False):
    Studio: Optional[Studio]


EC2InstanceIdsList = List[InstanceId]
EC2InstanceIdsToTerminateList = List[InstanceId]


class EbsBlockDevice(TypedDict, total=False):
    VolumeSpecification: Optional[VolumeSpecification]
    Device: Optional[String]


EbsBlockDeviceList = List[EbsBlockDevice]


class EbsVolume(TypedDict, total=False):
    Device: Optional[String]
    VolumeId: Optional[String]


EbsVolumeList = List[EbsVolume]


class GetAutoTerminationPolicyInput(ServiceRequest):
    ClusterId: ClusterId


class GetAutoTerminationPolicyOutput(TypedDict, total=False):
    AutoTerminationPolicy: Optional[AutoTerminationPolicy]


class GetBlockPublicAccessConfigurationInput(ServiceRequest):
    pass


class GetBlockPublicAccessConfigurationOutput(TypedDict, total=False):
    BlockPublicAccessConfiguration: BlockPublicAccessConfiguration
    BlockPublicAccessConfigurationMetadata: BlockPublicAccessConfigurationMetadata


class GetManagedScalingPolicyInput(ServiceRequest):
    ClusterId: ClusterId


class ManagedScalingPolicy(TypedDict, total=False):
    ComputeLimits: Optional[ComputeLimits]


class GetManagedScalingPolicyOutput(TypedDict, total=False):
    ManagedScalingPolicy: Optional[ManagedScalingPolicy]


class GetStudioSessionMappingInput(ServiceRequest):
    StudioId: XmlStringMaxLen256
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: IdentityType


class SessionMappingDetail(TypedDict, total=False):
    StudioId: Optional[XmlStringMaxLen256]
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: Optional[IdentityType]
    SessionPolicyArn: Optional[XmlStringMaxLen256]
    CreationTime: Optional[Date]
    LastModifiedTime: Optional[Date]


class GetStudioSessionMappingOutput(TypedDict, total=False):
    SessionMapping: Optional[SessionMappingDetail]


class InstanceTimeline(TypedDict, total=False):
    CreationDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]


class InstanceStateChangeReason(TypedDict, total=False):
    Code: Optional[InstanceStateChangeReasonCode]
    Message: Optional[String]


class InstanceStatus(TypedDict, total=False):
    State: Optional[InstanceState]
    StateChangeReason: Optional[InstanceStateChangeReason]
    Timeline: Optional[InstanceTimeline]


class Instance(TypedDict, total=False):
    Id: Optional[InstanceId]
    Ec2InstanceId: Optional[InstanceId]
    PublicDnsName: Optional[String]
    PublicIpAddress: Optional[String]
    PrivateDnsName: Optional[String]
    PrivateIpAddress: Optional[String]
    Status: Optional[InstanceStatus]
    InstanceGroupId: Optional[String]
    InstanceFleetId: Optional[InstanceFleetId]
    Market: Optional[MarketType]
    InstanceType: Optional[InstanceType]
    EbsVolumes: Optional[EbsVolumeList]


class InstanceTypeSpecification(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    WeightedCapacity: Optional[WholeNumber]
    BidPrice: Optional[XmlStringMaxLen256]
    BidPriceAsPercentageOfOnDemandPrice: Optional[NonNegativeDouble]
    Configurations: Optional[ConfigurationList]
    EbsBlockDevices: Optional[EbsBlockDeviceList]
    EbsOptimized: Optional[BooleanObject]
    CustomAmiId: Optional[XmlStringMaxLen256]


InstanceTypeSpecificationList = List[InstanceTypeSpecification]


class InstanceFleetTimeline(TypedDict, total=False):
    CreationDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]


class InstanceFleetStateChangeReason(TypedDict, total=False):
    Code: Optional[InstanceFleetStateChangeReasonCode]
    Message: Optional[String]


class InstanceFleetStatus(TypedDict, total=False):
    State: Optional[InstanceFleetState]
    StateChangeReason: Optional[InstanceFleetStateChangeReason]
    Timeline: Optional[InstanceFleetTimeline]


class InstanceFleet(TypedDict, total=False):
    Id: Optional[InstanceFleetId]
    Name: Optional[XmlStringMaxLen256]
    Status: Optional[InstanceFleetStatus]
    InstanceFleetType: Optional[InstanceFleetType]
    TargetOnDemandCapacity: Optional[WholeNumber]
    TargetSpotCapacity: Optional[WholeNumber]
    ProvisionedOnDemandCapacity: Optional[WholeNumber]
    ProvisionedSpotCapacity: Optional[WholeNumber]
    InstanceTypeSpecifications: Optional[InstanceTypeSpecificationList]
    LaunchSpecifications: Optional[InstanceFleetProvisioningSpecifications]


InstanceFleetConfigList = List[InstanceFleetConfig]
InstanceFleetList = List[InstanceFleet]


class InstanceFleetModifyConfig(TypedDict, total=False):
    InstanceFleetId: InstanceFleetId
    TargetOnDemandCapacity: Optional[WholeNumber]
    TargetSpotCapacity: Optional[WholeNumber]


class InstanceResizePolicy(TypedDict, total=False):
    InstancesToTerminate: Optional[EC2InstanceIdsList]
    InstancesToProtect: Optional[EC2InstanceIdsList]
    InstanceTerminationTimeout: Optional[Integer]


class ShrinkPolicy(TypedDict, total=False):
    DecommissionTimeout: Optional[Integer]
    InstanceResizePolicy: Optional[InstanceResizePolicy]


class InstanceGroupTimeline(TypedDict, total=False):
    CreationDateTime: Optional[Date]
    ReadyDateTime: Optional[Date]
    EndDateTime: Optional[Date]


class InstanceGroupStateChangeReason(TypedDict, total=False):
    Code: Optional[InstanceGroupStateChangeReasonCode]
    Message: Optional[String]


class InstanceGroupStatus(TypedDict, total=False):
    State: Optional[InstanceGroupState]
    StateChangeReason: Optional[InstanceGroupStateChangeReason]
    Timeline: Optional[InstanceGroupTimeline]


class InstanceGroup(TypedDict, total=False):
    Id: Optional[InstanceGroupId]
    Name: Optional[String]
    Market: Optional[MarketType]
    InstanceGroupType: Optional[InstanceGroupType]
    BidPrice: Optional[String]
    InstanceType: Optional[InstanceType]
    RequestedInstanceCount: Optional[Integer]
    RunningInstanceCount: Optional[Integer]
    Status: Optional[InstanceGroupStatus]
    Configurations: Optional[ConfigurationList]
    ConfigurationsVersion: Optional[Long]
    LastSuccessfullyAppliedConfigurations: Optional[ConfigurationList]
    LastSuccessfullyAppliedConfigurationsVersion: Optional[Long]
    EbsBlockDevices: Optional[EbsBlockDeviceList]
    EbsOptimized: Optional[BooleanObject]
    ShrinkPolicy: Optional[ShrinkPolicy]
    AutoScalingPolicy: Optional[AutoScalingPolicyDescription]
    CustomAmiId: Optional[XmlStringMaxLen256]


InstanceGroupList = List[InstanceGroup]


class InstanceGroupModifyConfig(TypedDict, total=False):
    InstanceGroupId: XmlStringMaxLen256
    InstanceCount: Optional[Integer]
    EC2InstanceIdsToTerminate: Optional[EC2InstanceIdsToTerminateList]
    ShrinkPolicy: Optional[ShrinkPolicy]
    Configurations: Optional[ConfigurationList]


InstanceGroupModifyConfigList = List[InstanceGroupModifyConfig]
InstanceGroupTypeList = List[InstanceGroupType]
InstanceList = List[Instance]
InstanceStateList = List[InstanceState]
SecurityGroupsList = List[XmlStringMaxLen256]


class JobFlowInstancesConfig(TypedDict, total=False):
    MasterInstanceType: Optional[InstanceType]
    SlaveInstanceType: Optional[InstanceType]
    InstanceCount: Optional[Integer]
    InstanceGroups: Optional[InstanceGroupConfigList]
    InstanceFleets: Optional[InstanceFleetConfigList]
    Ec2KeyName: Optional[XmlStringMaxLen256]
    Placement: Optional[PlacementType]
    KeepJobFlowAliveWhenNoSteps: Optional[Boolean]
    TerminationProtected: Optional[Boolean]
    HadoopVersion: Optional[XmlStringMaxLen256]
    Ec2SubnetId: Optional[XmlStringMaxLen256]
    Ec2SubnetIds: Optional[XmlStringMaxLen256List]
    EmrManagedMasterSecurityGroup: Optional[XmlStringMaxLen256]
    EmrManagedSlaveSecurityGroup: Optional[XmlStringMaxLen256]
    ServiceAccessSecurityGroup: Optional[XmlStringMaxLen256]
    AdditionalMasterSecurityGroups: Optional[SecurityGroupsList]
    AdditionalSlaveSecurityGroups: Optional[SecurityGroupsList]


class ListBootstrapActionsInput(ServiceRequest):
    ClusterId: ClusterId
    Marker: Optional[Marker]


class ListBootstrapActionsOutput(TypedDict, total=False):
    BootstrapActions: Optional[CommandList]
    Marker: Optional[Marker]


class ListClustersInput(ServiceRequest):
    CreatedAfter: Optional[Date]
    CreatedBefore: Optional[Date]
    ClusterStates: Optional[ClusterStateList]
    Marker: Optional[Marker]


class ListClustersOutput(TypedDict, total=False):
    Clusters: Optional[ClusterSummaryList]
    Marker: Optional[Marker]


class ListInstanceFleetsInput(ServiceRequest):
    ClusterId: ClusterId
    Marker: Optional[Marker]


class ListInstanceFleetsOutput(TypedDict, total=False):
    InstanceFleets: Optional[InstanceFleetList]
    Marker: Optional[Marker]


class ListInstanceGroupsInput(ServiceRequest):
    ClusterId: ClusterId
    Marker: Optional[Marker]


class ListInstanceGroupsOutput(TypedDict, total=False):
    InstanceGroups: Optional[InstanceGroupList]
    Marker: Optional[Marker]


class ListInstancesInput(ServiceRequest):
    ClusterId: ClusterId
    InstanceGroupId: Optional[InstanceGroupId]
    InstanceGroupTypes: Optional[InstanceGroupTypeList]
    InstanceFleetId: Optional[InstanceFleetId]
    InstanceFleetType: Optional[InstanceFleetType]
    InstanceStates: Optional[InstanceStateList]
    Marker: Optional[Marker]


class ListInstancesOutput(TypedDict, total=False):
    Instances: Optional[InstanceList]
    Marker: Optional[Marker]


class ListNotebookExecutionsInput(ServiceRequest):
    EditorId: Optional[XmlStringMaxLen256]
    Status: Optional[NotebookExecutionStatus]
    From: Optional[Date]
    To: Optional[Date]
    Marker: Optional[Marker]


class NotebookExecutionSummary(TypedDict, total=False):
    NotebookExecutionId: Optional[XmlStringMaxLen256]
    EditorId: Optional[XmlStringMaxLen256]
    NotebookExecutionName: Optional[XmlStringMaxLen256]
    Status: Optional[NotebookExecutionStatus]
    StartTime: Optional[Date]
    EndTime: Optional[Date]


NotebookExecutionSummaryList = List[NotebookExecutionSummary]


class ListNotebookExecutionsOutput(TypedDict, total=False):
    NotebookExecutions: Optional[NotebookExecutionSummaryList]
    Marker: Optional[Marker]


class ReleaseLabelFilter(TypedDict, total=False):
    Prefix: Optional[String]
    Application: Optional[String]


class ListReleaseLabelsInput(ServiceRequest):
    Filters: Optional[ReleaseLabelFilter]
    NextToken: Optional[String]
    MaxResults: Optional[MaxResultsNumber]


class ListReleaseLabelsOutput(TypedDict, total=False):
    ReleaseLabels: Optional[StringList]
    NextToken: Optional[String]


class ListSecurityConfigurationsInput(ServiceRequest):
    Marker: Optional[Marker]


class SecurityConfigurationSummary(TypedDict, total=False):
    Name: Optional[XmlString]
    CreationDateTime: Optional[Date]


SecurityConfigurationList = List[SecurityConfigurationSummary]


class ListSecurityConfigurationsOutput(TypedDict, total=False):
    SecurityConfigurations: Optional[SecurityConfigurationList]
    Marker: Optional[Marker]


StepStateList = List[StepState]


class ListStepsInput(ServiceRequest):
    ClusterId: ClusterId
    StepStates: Optional[StepStateList]
    StepIds: Optional[XmlStringList]
    Marker: Optional[Marker]


class StepSummary(TypedDict, total=False):
    Id: Optional[StepId]
    Name: Optional[String]
    Config: Optional[HadoopStepConfig]
    ActionOnFailure: Optional[ActionOnFailure]
    Status: Optional[StepStatus]


StepSummaryList = List[StepSummary]


class ListStepsOutput(TypedDict, total=False):
    Steps: Optional[StepSummaryList]
    Marker: Optional[Marker]


class ListStudioSessionMappingsInput(ServiceRequest):
    StudioId: Optional[XmlStringMaxLen256]
    IdentityType: Optional[IdentityType]
    Marker: Optional[Marker]


class SessionMappingSummary(TypedDict, total=False):
    StudioId: Optional[XmlStringMaxLen256]
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: Optional[IdentityType]
    SessionPolicyArn: Optional[XmlStringMaxLen256]
    CreationTime: Optional[Date]


SessionMappingSummaryList = List[SessionMappingSummary]


class ListStudioSessionMappingsOutput(TypedDict, total=False):
    SessionMappings: Optional[SessionMappingSummaryList]
    Marker: Optional[Marker]


class ListStudiosInput(ServiceRequest):
    Marker: Optional[Marker]


class StudioSummary(TypedDict, total=False):
    StudioId: Optional[XmlStringMaxLen256]
    Name: Optional[XmlStringMaxLen256]
    VpcId: Optional[XmlStringMaxLen256]
    Description: Optional[XmlStringMaxLen256]
    Url: Optional[XmlStringMaxLen256]
    AuthMode: Optional[AuthMode]
    CreationTime: Optional[Date]


StudioSummaryList = List[StudioSummary]


class ListStudiosOutput(TypedDict, total=False):
    Studios: Optional[StudioSummaryList]
    Marker: Optional[Marker]


class ModifyClusterInput(ServiceRequest):
    ClusterId: String
    StepConcurrencyLevel: Optional[Integer]


class ModifyClusterOutput(TypedDict, total=False):
    StepConcurrencyLevel: Optional[Integer]


class ModifyInstanceFleetInput(ServiceRequest):
    ClusterId: ClusterId
    InstanceFleet: InstanceFleetModifyConfig


class ModifyInstanceGroupsInput(ServiceRequest):
    ClusterId: Optional[ClusterId]
    InstanceGroups: Optional[InstanceGroupModifyConfigList]


class SupportedProductConfig(TypedDict, total=False):
    Name: Optional[XmlStringMaxLen256]
    Args: Optional[XmlStringList]


NewSupportedProductsList = List[SupportedProductConfig]


class PutAutoScalingPolicyInput(ServiceRequest):
    ClusterId: ClusterId
    InstanceGroupId: InstanceGroupId
    AutoScalingPolicy: AutoScalingPolicy


class PutAutoScalingPolicyOutput(TypedDict, total=False):
    ClusterId: Optional[ClusterId]
    InstanceGroupId: Optional[InstanceGroupId]
    AutoScalingPolicy: Optional[AutoScalingPolicyDescription]
    ClusterArn: Optional[ArnType]


class PutAutoTerminationPolicyInput(ServiceRequest):
    ClusterId: ClusterId
    AutoTerminationPolicy: Optional[AutoTerminationPolicy]


class PutAutoTerminationPolicyOutput(TypedDict, total=False):
    pass


class PutBlockPublicAccessConfigurationInput(ServiceRequest):
    BlockPublicAccessConfiguration: BlockPublicAccessConfiguration


class PutBlockPublicAccessConfigurationOutput(TypedDict, total=False):
    pass


class PutManagedScalingPolicyInput(ServiceRequest):
    ClusterId: ClusterId
    ManagedScalingPolicy: ManagedScalingPolicy


class PutManagedScalingPolicyOutput(TypedDict, total=False):
    pass


class RemoveAutoScalingPolicyInput(ServiceRequest):
    ClusterId: ClusterId
    InstanceGroupId: InstanceGroupId


class RemoveAutoScalingPolicyOutput(TypedDict, total=False):
    pass


class RemoveAutoTerminationPolicyInput(ServiceRequest):
    ClusterId: ClusterId


class RemoveAutoTerminationPolicyOutput(TypedDict, total=False):
    pass


class RemoveManagedScalingPolicyInput(ServiceRequest):
    ClusterId: ClusterId


class RemoveManagedScalingPolicyOutput(TypedDict, total=False):
    pass


class RemoveTagsInput(ServiceRequest):
    ResourceId: ResourceId
    TagKeys: StringList


class RemoveTagsOutput(TypedDict, total=False):
    pass


class RunJobFlowInput(ServiceRequest):
    Name: XmlStringMaxLen256
    LogUri: Optional[XmlString]
    LogEncryptionKmsKeyId: Optional[XmlString]
    AdditionalInfo: Optional[XmlString]
    AmiVersion: Optional[XmlStringMaxLen256]
    ReleaseLabel: Optional[XmlStringMaxLen256]
    Instances: JobFlowInstancesConfig
    Steps: Optional[StepConfigList]
    BootstrapActions: Optional[BootstrapActionConfigList]
    SupportedProducts: Optional[SupportedProductsList]
    NewSupportedProducts: Optional[NewSupportedProductsList]
    Applications: Optional[ApplicationList]
    Configurations: Optional[ConfigurationList]
    VisibleToAllUsers: Optional[Boolean]
    JobFlowRole: Optional[XmlString]
    ServiceRole: Optional[XmlString]
    Tags: Optional[TagList]
    SecurityConfiguration: Optional[XmlString]
    AutoScalingRole: Optional[XmlString]
    ScaleDownBehavior: Optional[ScaleDownBehavior]
    CustomAmiId: Optional[XmlStringMaxLen256]
    EbsRootVolumeSize: Optional[Integer]
    RepoUpgradeOnBoot: Optional[RepoUpgradeOnBoot]
    KerberosAttributes: Optional[KerberosAttributes]
    StepConcurrencyLevel: Optional[Integer]
    ManagedScalingPolicy: Optional[ManagedScalingPolicy]
    PlacementGroupConfigs: Optional[PlacementGroupConfigList]
    AutoTerminationPolicy: Optional[AutoTerminationPolicy]


class RunJobFlowOutput(TypedDict, total=False):
    JobFlowId: Optional[XmlStringMaxLen256]
    ClusterArn: Optional[ArnType]


class SetTerminationProtectionInput(ServiceRequest):
    JobFlowIds: XmlStringList
    TerminationProtected: Boolean


class SetVisibleToAllUsersInput(ServiceRequest):
    JobFlowIds: XmlStringList
    VisibleToAllUsers: Boolean


class StartNotebookExecutionInput(ServiceRequest):
    EditorId: XmlStringMaxLen256
    RelativePath: XmlString
    NotebookExecutionName: Optional[XmlStringMaxLen256]
    NotebookParams: Optional[XmlString]
    ExecutionEngine: ExecutionEngineConfig
    ServiceRole: XmlString
    NotebookInstanceSecurityGroupId: Optional[XmlStringMaxLen256]
    Tags: Optional[TagList]


class StartNotebookExecutionOutput(TypedDict, total=False):
    NotebookExecutionId: Optional[XmlStringMaxLen256]


class StopNotebookExecutionInput(ServiceRequest):
    NotebookExecutionId: XmlStringMaxLen256


class TerminateJobFlowsInput(ServiceRequest):
    JobFlowIds: XmlStringList


class UpdateStudioInput(ServiceRequest):
    StudioId: XmlStringMaxLen256
    Name: Optional[XmlStringMaxLen256]
    Description: Optional[XmlStringMaxLen256]
    SubnetIds: Optional[SubnetIdList]
    DefaultS3Location: Optional[XmlString]


class UpdateStudioSessionMappingInput(ServiceRequest):
    StudioId: XmlStringMaxLen256
    IdentityId: Optional[XmlStringMaxLen256]
    IdentityName: Optional[XmlStringMaxLen256]
    IdentityType: IdentityType
    SessionPolicyArn: XmlStringMaxLen256


class EmrApi:

    service = "emr"
    version = "2009-03-31"

    @handler("AddInstanceFleet")
    def add_instance_fleet(
        self,
        context: RequestContext,
        cluster_id: XmlStringMaxLen256,
        instance_fleet: InstanceFleetConfig,
    ) -> AddInstanceFleetOutput:
        raise NotImplementedError

    @handler("AddInstanceGroups")
    def add_instance_groups(
        self,
        context: RequestContext,
        instance_groups: InstanceGroupConfigList,
        job_flow_id: XmlStringMaxLen256,
    ) -> AddInstanceGroupsOutput:
        raise NotImplementedError

    @handler("AddJobFlowSteps")
    def add_job_flow_steps(
        self, context: RequestContext, job_flow_id: XmlStringMaxLen256, steps: StepConfigList
    ) -> AddJobFlowStepsOutput:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(
        self, context: RequestContext, resource_id: ResourceId, tags: TagList
    ) -> AddTagsOutput:
        raise NotImplementedError

    @handler("CancelSteps")
    def cancel_steps(
        self,
        context: RequestContext,
        cluster_id: XmlStringMaxLen256,
        step_ids: StepIdsList,
        step_cancellation_option: StepCancellationOption = None,
    ) -> CancelStepsOutput:
        raise NotImplementedError

    @handler("CreateSecurityConfiguration")
    def create_security_configuration(
        self, context: RequestContext, name: XmlString, security_configuration: String
    ) -> CreateSecurityConfigurationOutput:
        raise NotImplementedError

    @handler("CreateStudio")
    def create_studio(
        self,
        context: RequestContext,
        name: XmlStringMaxLen256,
        auth_mode: AuthMode,
        vpc_id: XmlStringMaxLen256,
        subnet_ids: SubnetIdList,
        service_role: XmlString,
        workspace_security_group_id: XmlStringMaxLen256,
        engine_security_group_id: XmlStringMaxLen256,
        default_s3_location: XmlString,
        description: XmlStringMaxLen256 = None,
        user_role: XmlString = None,
        idp_auth_url: XmlString = None,
        idp_relay_state_parameter_name: XmlStringMaxLen256 = None,
        tags: TagList = None,
    ) -> CreateStudioOutput:
        raise NotImplementedError

    @handler("CreateStudioSessionMapping")
    def create_studio_session_mapping(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256,
        identity_type: IdentityType,
        session_policy_arn: XmlStringMaxLen256,
        identity_id: XmlStringMaxLen256 = None,
        identity_name: XmlStringMaxLen256 = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSecurityConfiguration")
    def delete_security_configuration(
        self, context: RequestContext, name: XmlString
    ) -> DeleteSecurityConfigurationOutput:
        raise NotImplementedError

    @handler("DeleteStudio")
    def delete_studio(self, context: RequestContext, studio_id: XmlStringMaxLen256) -> None:
        raise NotImplementedError

    @handler("DeleteStudioSessionMapping")
    def delete_studio_session_mapping(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256,
        identity_type: IdentityType,
        identity_id: XmlStringMaxLen256 = None,
        identity_name: XmlStringMaxLen256 = None,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeCluster")
    def describe_cluster(
        self, context: RequestContext, cluster_id: ClusterId
    ) -> DescribeClusterOutput:
        raise NotImplementedError

    @handler("DescribeJobFlows")
    def describe_job_flows(
        self,
        context: RequestContext,
        created_after: Date = None,
        created_before: Date = None,
        job_flow_ids: XmlStringList = None,
        job_flow_states: JobFlowExecutionStateList = None,
    ) -> DescribeJobFlowsOutput:
        raise NotImplementedError

    @handler("DescribeNotebookExecution")
    def describe_notebook_execution(
        self, context: RequestContext, notebook_execution_id: XmlStringMaxLen256
    ) -> DescribeNotebookExecutionOutput:
        raise NotImplementedError

    @handler("DescribeReleaseLabel")
    def describe_release_label(
        self,
        context: RequestContext,
        release_label: String = None,
        next_token: String = None,
        max_results: MaxResultsNumber = None,
    ) -> DescribeReleaseLabelOutput:
        raise NotImplementedError

    @handler("DescribeSecurityConfiguration")
    def describe_security_configuration(
        self, context: RequestContext, name: XmlString
    ) -> DescribeSecurityConfigurationOutput:
        raise NotImplementedError

    @handler("DescribeStep")
    def describe_step(
        self, context: RequestContext, cluster_id: ClusterId, step_id: StepId
    ) -> DescribeStepOutput:
        raise NotImplementedError

    @handler("DescribeStudio")
    def describe_studio(
        self, context: RequestContext, studio_id: XmlStringMaxLen256
    ) -> DescribeStudioOutput:
        raise NotImplementedError

    @handler("GetAutoTerminationPolicy")
    def get_auto_termination_policy(
        self, context: RequestContext, cluster_id: ClusterId
    ) -> GetAutoTerminationPolicyOutput:
        raise NotImplementedError

    @handler("GetBlockPublicAccessConfiguration")
    def get_block_public_access_configuration(
        self,
        context: RequestContext,
    ) -> GetBlockPublicAccessConfigurationOutput:
        raise NotImplementedError

    @handler("GetManagedScalingPolicy")
    def get_managed_scaling_policy(
        self, context: RequestContext, cluster_id: ClusterId
    ) -> GetManagedScalingPolicyOutput:
        raise NotImplementedError

    @handler("GetStudioSessionMapping")
    def get_studio_session_mapping(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256,
        identity_type: IdentityType,
        identity_id: XmlStringMaxLen256 = None,
        identity_name: XmlStringMaxLen256 = None,
    ) -> GetStudioSessionMappingOutput:
        raise NotImplementedError

    @handler("ListBootstrapActions")
    def list_bootstrap_actions(
        self, context: RequestContext, cluster_id: ClusterId, marker: Marker = None
    ) -> ListBootstrapActionsOutput:
        raise NotImplementedError

    @handler("ListClusters")
    def list_clusters(
        self,
        context: RequestContext,
        created_after: Date = None,
        created_before: Date = None,
        cluster_states: ClusterStateList = None,
        marker: Marker = None,
    ) -> ListClustersOutput:
        raise NotImplementedError

    @handler("ListInstanceFleets")
    def list_instance_fleets(
        self, context: RequestContext, cluster_id: ClusterId, marker: Marker = None
    ) -> ListInstanceFleetsOutput:
        raise NotImplementedError

    @handler("ListInstanceGroups")
    def list_instance_groups(
        self, context: RequestContext, cluster_id: ClusterId, marker: Marker = None
    ) -> ListInstanceGroupsOutput:
        raise NotImplementedError

    @handler("ListInstances")
    def list_instances(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        instance_group_id: InstanceGroupId = None,
        instance_group_types: InstanceGroupTypeList = None,
        instance_fleet_id: InstanceFleetId = None,
        instance_fleet_type: InstanceFleetType = None,
        instance_states: InstanceStateList = None,
        marker: Marker = None,
    ) -> ListInstancesOutput:
        raise NotImplementedError

    @handler("ListNotebookExecutions", expand=False)
    def list_notebook_executions(
        self, context: RequestContext, request: ListNotebookExecutionsInput
    ) -> ListNotebookExecutionsOutput:
        raise NotImplementedError

    @handler("ListReleaseLabels")
    def list_release_labels(
        self,
        context: RequestContext,
        filters: ReleaseLabelFilter = None,
        next_token: String = None,
        max_results: MaxResultsNumber = None,
    ) -> ListReleaseLabelsOutput:
        raise NotImplementedError

    @handler("ListSecurityConfigurations")
    def list_security_configurations(
        self, context: RequestContext, marker: Marker = None
    ) -> ListSecurityConfigurationsOutput:
        raise NotImplementedError

    @handler("ListSteps")
    def list_steps(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        step_states: StepStateList = None,
        step_ids: XmlStringList = None,
        marker: Marker = None,
    ) -> ListStepsOutput:
        raise NotImplementedError

    @handler("ListStudioSessionMappings")
    def list_studio_session_mappings(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256 = None,
        identity_type: IdentityType = None,
        marker: Marker = None,
    ) -> ListStudioSessionMappingsOutput:
        raise NotImplementedError

    @handler("ListStudios")
    def list_studios(self, context: RequestContext, marker: Marker = None) -> ListStudiosOutput:
        raise NotImplementedError

    @handler("ModifyCluster")
    def modify_cluster(
        self, context: RequestContext, cluster_id: String, step_concurrency_level: Integer = None
    ) -> ModifyClusterOutput:
        raise NotImplementedError

    @handler("ModifyInstanceFleet")
    def modify_instance_fleet(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        instance_fleet: InstanceFleetModifyConfig,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyInstanceGroups")
    def modify_instance_groups(
        self,
        context: RequestContext,
        cluster_id: ClusterId = None,
        instance_groups: InstanceGroupModifyConfigList = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutAutoScalingPolicy")
    def put_auto_scaling_policy(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        instance_group_id: InstanceGroupId,
        auto_scaling_policy: AutoScalingPolicy,
    ) -> PutAutoScalingPolicyOutput:
        raise NotImplementedError

    @handler("PutAutoTerminationPolicy")
    def put_auto_termination_policy(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        auto_termination_policy: AutoTerminationPolicy = None,
    ) -> PutAutoTerminationPolicyOutput:
        raise NotImplementedError

    @handler("PutBlockPublicAccessConfiguration")
    def put_block_public_access_configuration(
        self,
        context: RequestContext,
        block_public_access_configuration: BlockPublicAccessConfiguration,
    ) -> PutBlockPublicAccessConfigurationOutput:
        raise NotImplementedError

    @handler("PutManagedScalingPolicy")
    def put_managed_scaling_policy(
        self,
        context: RequestContext,
        cluster_id: ClusterId,
        managed_scaling_policy: ManagedScalingPolicy,
    ) -> PutManagedScalingPolicyOutput:
        raise NotImplementedError

    @handler("RemoveAutoScalingPolicy")
    def remove_auto_scaling_policy(
        self, context: RequestContext, cluster_id: ClusterId, instance_group_id: InstanceGroupId
    ) -> RemoveAutoScalingPolicyOutput:
        raise NotImplementedError

    @handler("RemoveAutoTerminationPolicy")
    def remove_auto_termination_policy(
        self, context: RequestContext, cluster_id: ClusterId
    ) -> RemoveAutoTerminationPolicyOutput:
        raise NotImplementedError

    @handler("RemoveManagedScalingPolicy")
    def remove_managed_scaling_policy(
        self, context: RequestContext, cluster_id: ClusterId
    ) -> RemoveManagedScalingPolicyOutput:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(
        self, context: RequestContext, resource_id: ResourceId, tag_keys: StringList
    ) -> RemoveTagsOutput:
        raise NotImplementedError

    @handler("RunJobFlow")
    def run_job_flow(
        self,
        context: RequestContext,
        name: XmlStringMaxLen256,
        instances: JobFlowInstancesConfig,
        log_uri: XmlString = None,
        log_encryption_kms_key_id: XmlString = None,
        additional_info: XmlString = None,
        ami_version: XmlStringMaxLen256 = None,
        release_label: XmlStringMaxLen256 = None,
        steps: StepConfigList = None,
        bootstrap_actions: BootstrapActionConfigList = None,
        supported_products: SupportedProductsList = None,
        new_supported_products: NewSupportedProductsList = None,
        applications: ApplicationList = None,
        configurations: ConfigurationList = None,
        visible_to_all_users: Boolean = None,
        job_flow_role: XmlString = None,
        service_role: XmlString = None,
        tags: TagList = None,
        security_configuration: XmlString = None,
        auto_scaling_role: XmlString = None,
        scale_down_behavior: ScaleDownBehavior = None,
        custom_ami_id: XmlStringMaxLen256 = None,
        ebs_root_volume_size: Integer = None,
        repo_upgrade_on_boot: RepoUpgradeOnBoot = None,
        kerberos_attributes: KerberosAttributes = None,
        step_concurrency_level: Integer = None,
        managed_scaling_policy: ManagedScalingPolicy = None,
        placement_group_configs: PlacementGroupConfigList = None,
        auto_termination_policy: AutoTerminationPolicy = None,
    ) -> RunJobFlowOutput:
        raise NotImplementedError

    @handler("SetTerminationProtection")
    def set_termination_protection(
        self, context: RequestContext, job_flow_ids: XmlStringList, termination_protected: Boolean
    ) -> None:
        raise NotImplementedError

    @handler("SetVisibleToAllUsers")
    def set_visible_to_all_users(
        self, context: RequestContext, job_flow_ids: XmlStringList, visible_to_all_users: Boolean
    ) -> None:
        raise NotImplementedError

    @handler("StartNotebookExecution")
    def start_notebook_execution(
        self,
        context: RequestContext,
        editor_id: XmlStringMaxLen256,
        relative_path: XmlString,
        execution_engine: ExecutionEngineConfig,
        service_role: XmlString,
        notebook_execution_name: XmlStringMaxLen256 = None,
        notebook_params: XmlString = None,
        notebook_instance_security_group_id: XmlStringMaxLen256 = None,
        tags: TagList = None,
    ) -> StartNotebookExecutionOutput:
        raise NotImplementedError

    @handler("StopNotebookExecution")
    def stop_notebook_execution(
        self, context: RequestContext, notebook_execution_id: XmlStringMaxLen256
    ) -> None:
        raise NotImplementedError

    @handler("TerminateJobFlows")
    def terminate_job_flows(self, context: RequestContext, job_flow_ids: XmlStringList) -> None:
        raise NotImplementedError

    @handler("UpdateStudio")
    def update_studio(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256,
        name: XmlStringMaxLen256 = None,
        description: XmlStringMaxLen256 = None,
        subnet_ids: SubnetIdList = None,
        default_s3_location: XmlString = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateStudioSessionMapping")
    def update_studio_session_mapping(
        self,
        context: RequestContext,
        studio_id: XmlStringMaxLen256,
        identity_type: IdentityType,
        session_policy_arn: XmlStringMaxLen256,
        identity_id: XmlStringMaxLen256 = None,
        identity_name: XmlStringMaxLen256 = None,
    ) -> None:
        raise NotImplementedError
