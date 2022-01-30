import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessString = str
AllowedNodeGroupId = str
AwsQueryErrorMessage = str
Boolean = bool
BooleanOptional = bool
Double = float
EngineType = str
FilterName = str
FilterValue = str
Integer = int
IntegerOptional = int
String = str
UserGroupId = str
UserId = str
UserName = str


class AZMode(str):
    single_az = "single-az"
    cross_az = "cross-az"


class AuthTokenUpdateStatus(str):
    SETTING = "SETTING"
    ROTATING = "ROTATING"


class AuthTokenUpdateStrategyType(str):
    SET = "SET"
    ROTATE = "ROTATE"
    DELETE = "DELETE"


class AuthenticationType(str):
    password = "password"
    no_password = "no-password"


class AutomaticFailoverStatus(str):
    enabled = "enabled"
    disabled = "disabled"
    enabling = "enabling"
    disabling = "disabling"


class ChangeType(str):
    immediate = "immediate"
    requires_reboot = "requires-reboot"


class DataTieringStatus(str):
    enabled = "enabled"
    disabled = "disabled"


class DestinationType(str):
    cloudwatch_logs = "cloudwatch-logs"
    kinesis_firehose = "kinesis-firehose"


class LogDeliveryConfigurationStatus(str):
    active = "active"
    enabling = "enabling"
    modifying = "modifying"
    disabling = "disabling"
    error = "error"


class LogFormat(str):
    text = "text"
    json = "json"


class LogType(str):
    slow_log = "slow-log"
    engine_log = "engine-log"


class MultiAZStatus(str):
    enabled = "enabled"
    disabled = "disabled"


class NodeUpdateInitiatedBy(str):
    system = "system"
    customer = "customer"


class NodeUpdateStatus(str):
    not_applied = "not-applied"
    waiting_to_start = "waiting-to-start"
    in_progress = "in-progress"
    stopping = "stopping"
    stopped = "stopped"
    complete = "complete"


class OutpostMode(str):
    single_outpost = "single-outpost"
    cross_outpost = "cross-outpost"


class PendingAutomaticFailoverStatus(str):
    enabled = "enabled"
    disabled = "disabled"


class ServiceUpdateSeverity(str):
    critical = "critical"
    important = "important"
    medium = "medium"
    low = "low"


class ServiceUpdateStatus(str):
    available = "available"
    cancelled = "cancelled"
    expired = "expired"


class ServiceUpdateType(str):
    security_update = "security-update"


class SlaMet(str):
    yes = "yes"
    no = "no"
    n_a = "n/a"


class SourceType(str):
    cache_cluster = "cache-cluster"
    cache_parameter_group = "cache-parameter-group"
    cache_security_group = "cache-security-group"
    cache_subnet_group = "cache-subnet-group"
    replication_group = "replication-group"
    user = "user"
    user_group = "user-group"


class UpdateActionStatus(str):
    not_applied = "not-applied"
    waiting_to_start = "waiting-to-start"
    in_progress = "in-progress"
    stopping = "stopping"
    stopped = "stopped"
    complete = "complete"
    scheduling = "scheduling"
    scheduled = "scheduled"
    not_applicable = "not-applicable"


class APICallRateForCustomerExceededFault(ServiceException):
    pass


class AuthorizationAlreadyExistsFault(ServiceException):
    pass


class AuthorizationNotFoundFault(ServiceException):
    pass


class CacheClusterAlreadyExistsFault(ServiceException):
    pass


class CacheClusterNotFoundFault(ServiceException):
    pass


class CacheParameterGroupAlreadyExistsFault(ServiceException):
    pass


class CacheParameterGroupNotFoundFault(ServiceException):
    pass


class CacheParameterGroupQuotaExceededFault(ServiceException):
    pass


class CacheSecurityGroupAlreadyExistsFault(ServiceException):
    pass


class CacheSecurityGroupNotFoundFault(ServiceException):
    pass


class CacheSecurityGroupQuotaExceededFault(ServiceException):
    pass


class CacheSubnetGroupAlreadyExistsFault(ServiceException):
    pass


class CacheSubnetGroupInUse(ServiceException):
    pass


class CacheSubnetGroupNotFoundFault(ServiceException):
    pass


class CacheSubnetGroupQuotaExceededFault(ServiceException):
    pass


class CacheSubnetQuotaExceededFault(ServiceException):
    pass


class ClusterQuotaForCustomerExceededFault(ServiceException):
    pass


class DefaultUserAssociatedToUserGroupFault(ServiceException):
    pass


class DefaultUserRequired(ServiceException):
    pass


class DuplicateUserNameFault(ServiceException):
    pass


class GlobalReplicationGroupAlreadyExistsFault(ServiceException):
    pass


class GlobalReplicationGroupNotFoundFault(ServiceException):
    pass


class InsufficientCacheClusterCapacityFault(ServiceException):
    pass


class InvalidARNFault(ServiceException):
    pass


class InvalidCacheClusterStateFault(ServiceException):
    pass


class InvalidCacheParameterGroupStateFault(ServiceException):
    pass


class InvalidCacheSecurityGroupStateFault(ServiceException):
    pass


class InvalidGlobalReplicationGroupStateFault(ServiceException):
    pass


class InvalidKMSKeyFault(ServiceException):
    pass


class InvalidParameterCombinationException(ServiceException):
    message: Optional[AwsQueryErrorMessage]


class InvalidParameterValueException(ServiceException):
    message: Optional[AwsQueryErrorMessage]


class InvalidReplicationGroupStateFault(ServiceException):
    pass


class InvalidSnapshotStateFault(ServiceException):
    pass


class InvalidSubnet(ServiceException):
    pass


class InvalidUserGroupStateFault(ServiceException):
    pass


class InvalidUserStateFault(ServiceException):
    pass


class InvalidVPCNetworkStateFault(ServiceException):
    pass


class NoOperationFault(ServiceException):
    pass


class NodeGroupNotFoundFault(ServiceException):
    pass


class NodeGroupsPerReplicationGroupQuotaExceededFault(ServiceException):
    pass


class NodeQuotaForClusterExceededFault(ServiceException):
    pass


class NodeQuotaForCustomerExceededFault(ServiceException):
    pass


class ReplicationGroupAlreadyExistsFault(ServiceException):
    pass


class ReplicationGroupAlreadyUnderMigrationFault(ServiceException):
    pass


class ReplicationGroupNotFoundFault(ServiceException):
    pass


class ReplicationGroupNotUnderMigrationFault(ServiceException):
    pass


class ReservedCacheNodeAlreadyExistsFault(ServiceException):
    pass


class ReservedCacheNodeNotFoundFault(ServiceException):
    pass


class ReservedCacheNodeQuotaExceededFault(ServiceException):
    pass


class ReservedCacheNodesOfferingNotFoundFault(ServiceException):
    pass


class ServiceLinkedRoleNotFoundFault(ServiceException):
    pass


class ServiceUpdateNotFoundFault(ServiceException):
    pass


class SnapshotAlreadyExistsFault(ServiceException):
    pass


class SnapshotFeatureNotSupportedFault(ServiceException):
    pass


class SnapshotNotFoundFault(ServiceException):
    pass


class SnapshotQuotaExceededFault(ServiceException):
    pass


class SubnetInUse(ServiceException):
    pass


class SubnetNotAllowedFault(ServiceException):
    pass


class TagNotFoundFault(ServiceException):
    pass


class TagQuotaPerResourceExceeded(ServiceException):
    pass


class TestFailoverNotAvailableFault(ServiceException):
    pass


class UserAlreadyExistsFault(ServiceException):
    pass


class UserGroupAlreadyExistsFault(ServiceException):
    pass


class UserGroupNotFoundFault(ServiceException):
    pass


class UserGroupQuotaExceededFault(ServiceException):
    pass


class UserNotFoundFault(ServiceException):
    pass


class UserQuotaExceededFault(ServiceException):
    pass


class Tag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


TagList = List[Tag]


class AddTagsToResourceMessage(ServiceRequest):
    ResourceName: String
    Tags: TagList


NodeTypeList = List[String]


class AllowedNodeTypeModificationsMessage(TypedDict, total=False):
    ScaleUpModifications: Optional[NodeTypeList]
    ScaleDownModifications: Optional[NodeTypeList]


class Authentication(TypedDict, total=False):
    Type: Optional[AuthenticationType]
    PasswordCount: Optional[IntegerOptional]


class AuthorizeCacheSecurityGroupIngressMessage(ServiceRequest):
    CacheSecurityGroupName: String
    EC2SecurityGroupName: String
    EC2SecurityGroupOwnerId: String


class EC2SecurityGroup(TypedDict, total=False):
    Status: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


EC2SecurityGroupList = List[EC2SecurityGroup]


class CacheSecurityGroup(TypedDict, total=False):
    OwnerId: Optional[String]
    CacheSecurityGroupName: Optional[String]
    Description: Optional[String]
    EC2SecurityGroups: Optional[EC2SecurityGroupList]
    ARN: Optional[String]


class AuthorizeCacheSecurityGroupIngressResult(TypedDict, total=False):
    CacheSecurityGroup: Optional[CacheSecurityGroup]


class AvailabilityZone(TypedDict, total=False):
    Name: Optional[String]


AvailabilityZonesList = List[String]
CacheClusterIdList = List[String]
ReplicationGroupIdList = List[String]


class BatchApplyUpdateActionMessage(ServiceRequest):
    ReplicationGroupIds: Optional[ReplicationGroupIdList]
    CacheClusterIds: Optional[CacheClusterIdList]
    ServiceUpdateName: String


class BatchStopUpdateActionMessage(ServiceRequest):
    ReplicationGroupIds: Optional[ReplicationGroupIdList]
    CacheClusterIds: Optional[CacheClusterIdList]
    ServiceUpdateName: String


class KinesisFirehoseDestinationDetails(TypedDict, total=False):
    DeliveryStream: Optional[String]


class CloudWatchLogsDestinationDetails(TypedDict, total=False):
    LogGroup: Optional[String]


class DestinationDetails(TypedDict, total=False):
    CloudWatchLogsDetails: Optional[CloudWatchLogsDestinationDetails]
    KinesisFirehoseDetails: Optional[KinesisFirehoseDestinationDetails]


class LogDeliveryConfiguration(TypedDict, total=False):
    LogType: Optional[LogType]
    DestinationType: Optional[DestinationType]
    DestinationDetails: Optional[DestinationDetails]
    LogFormat: Optional[LogFormat]
    Status: Optional[LogDeliveryConfigurationStatus]
    Message: Optional[String]


LogDeliveryConfigurationList = List[LogDeliveryConfiguration]
TStamp = datetime


class SecurityGroupMembership(TypedDict, total=False):
    SecurityGroupId: Optional[String]
    Status: Optional[String]


SecurityGroupMembershipList = List[SecurityGroupMembership]


class Endpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[Integer]


class CacheNode(TypedDict, total=False):
    CacheNodeId: Optional[String]
    CacheNodeStatus: Optional[String]
    CacheNodeCreateTime: Optional[TStamp]
    Endpoint: Optional[Endpoint]
    ParameterGroupStatus: Optional[String]
    SourceCacheNodeId: Optional[String]
    CustomerAvailabilityZone: Optional[String]
    CustomerOutpostArn: Optional[String]


CacheNodeList = List[CacheNode]
CacheNodeIdsList = List[String]


class CacheParameterGroupStatus(TypedDict, total=False):
    CacheParameterGroupName: Optional[String]
    ParameterApplyStatus: Optional[String]
    CacheNodeIdsToReboot: Optional[CacheNodeIdsList]


class CacheSecurityGroupMembership(TypedDict, total=False):
    CacheSecurityGroupName: Optional[String]
    Status: Optional[String]


CacheSecurityGroupMembershipList = List[CacheSecurityGroupMembership]


class NotificationConfiguration(TypedDict, total=False):
    TopicArn: Optional[String]
    TopicStatus: Optional[String]


class PendingLogDeliveryConfiguration(TypedDict, total=False):
    LogType: Optional[LogType]
    DestinationType: Optional[DestinationType]
    DestinationDetails: Optional[DestinationDetails]
    LogFormat: Optional[LogFormat]


PendingLogDeliveryConfigurationList = List[PendingLogDeliveryConfiguration]


class PendingModifiedValues(TypedDict, total=False):
    NumCacheNodes: Optional[IntegerOptional]
    CacheNodeIdsToRemove: Optional[CacheNodeIdsList]
    EngineVersion: Optional[String]
    CacheNodeType: Optional[String]
    AuthTokenStatus: Optional[AuthTokenUpdateStatus]
    LogDeliveryConfigurations: Optional[PendingLogDeliveryConfigurationList]


class CacheCluster(TypedDict, total=False):
    CacheClusterId: Optional[String]
    ConfigurationEndpoint: Optional[Endpoint]
    ClientDownloadLandingPage: Optional[String]
    CacheNodeType: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    CacheClusterStatus: Optional[String]
    NumCacheNodes: Optional[IntegerOptional]
    PreferredAvailabilityZone: Optional[String]
    PreferredOutpostArn: Optional[String]
    CacheClusterCreateTime: Optional[TStamp]
    PreferredMaintenanceWindow: Optional[String]
    PendingModifiedValues: Optional[PendingModifiedValues]
    NotificationConfiguration: Optional[NotificationConfiguration]
    CacheSecurityGroups: Optional[CacheSecurityGroupMembershipList]
    CacheParameterGroup: Optional[CacheParameterGroupStatus]
    CacheSubnetGroupName: Optional[String]
    CacheNodes: Optional[CacheNodeList]
    AutoMinorVersionUpgrade: Optional[Boolean]
    SecurityGroups: Optional[SecurityGroupMembershipList]
    ReplicationGroupId: Optional[String]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    AuthTokenEnabled: Optional[BooleanOptional]
    AuthTokenLastModifiedDate: Optional[TStamp]
    TransitEncryptionEnabled: Optional[BooleanOptional]
    AtRestEncryptionEnabled: Optional[BooleanOptional]
    ARN: Optional[String]
    ReplicationGroupLogDeliveryEnabled: Optional[Boolean]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationList]


CacheClusterList = List[CacheCluster]


class CacheClusterMessage(TypedDict, total=False):
    Marker: Optional[String]
    CacheClusters: Optional[CacheClusterList]


class CacheEngineVersion(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    CacheParameterGroupFamily: Optional[String]
    CacheEngineDescription: Optional[String]
    CacheEngineVersionDescription: Optional[String]


CacheEngineVersionList = List[CacheEngineVersion]


class CacheEngineVersionMessage(TypedDict, total=False):
    Marker: Optional[String]
    CacheEngineVersions: Optional[CacheEngineVersionList]


class CacheNodeTypeSpecificValue(TypedDict, total=False):
    CacheNodeType: Optional[String]
    Value: Optional[String]


CacheNodeTypeSpecificValueList = List[CacheNodeTypeSpecificValue]


class CacheNodeTypeSpecificParameter(TypedDict, total=False):
    ParameterName: Optional[String]
    Description: Optional[String]
    Source: Optional[String]
    DataType: Optional[String]
    AllowedValues: Optional[String]
    IsModifiable: Optional[Boolean]
    MinimumEngineVersion: Optional[String]
    CacheNodeTypeSpecificValues: Optional[CacheNodeTypeSpecificValueList]
    ChangeType: Optional[ChangeType]


CacheNodeTypeSpecificParametersList = List[CacheNodeTypeSpecificParameter]


class CacheNodeUpdateStatus(TypedDict, total=False):
    CacheNodeId: Optional[String]
    NodeUpdateStatus: Optional[NodeUpdateStatus]
    NodeDeletionDate: Optional[TStamp]
    NodeUpdateStartDate: Optional[TStamp]
    NodeUpdateEndDate: Optional[TStamp]
    NodeUpdateInitiatedBy: Optional[NodeUpdateInitiatedBy]
    NodeUpdateInitiatedDate: Optional[TStamp]
    NodeUpdateStatusModifiedDate: Optional[TStamp]


CacheNodeUpdateStatusList = List[CacheNodeUpdateStatus]


class CacheParameterGroup(TypedDict, total=False):
    CacheParameterGroupName: Optional[String]
    CacheParameterGroupFamily: Optional[String]
    Description: Optional[String]
    IsGlobal: Optional[Boolean]
    ARN: Optional[String]


class Parameter(TypedDict, total=False):
    ParameterName: Optional[String]
    ParameterValue: Optional[String]
    Description: Optional[String]
    Source: Optional[String]
    DataType: Optional[String]
    AllowedValues: Optional[String]
    IsModifiable: Optional[Boolean]
    MinimumEngineVersion: Optional[String]
    ChangeType: Optional[ChangeType]


ParametersList = List[Parameter]


class CacheParameterGroupDetails(TypedDict, total=False):
    Marker: Optional[String]
    Parameters: Optional[ParametersList]
    CacheNodeTypeSpecificParameters: Optional[CacheNodeTypeSpecificParametersList]


CacheParameterGroupList = List[CacheParameterGroup]


class CacheParameterGroupNameMessage(TypedDict, total=False):
    CacheParameterGroupName: Optional[String]


class CacheParameterGroupsMessage(TypedDict, total=False):
    Marker: Optional[String]
    CacheParameterGroups: Optional[CacheParameterGroupList]


CacheSecurityGroups = List[CacheSecurityGroup]


class CacheSecurityGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    CacheSecurityGroups: Optional[CacheSecurityGroups]


CacheSecurityGroupNameList = List[String]


class SubnetOutpost(TypedDict, total=False):
    SubnetOutpostArn: Optional[String]


class Subnet(TypedDict, total=False):
    SubnetIdentifier: Optional[String]
    SubnetAvailabilityZone: Optional[AvailabilityZone]
    SubnetOutpost: Optional[SubnetOutpost]


SubnetList = List[Subnet]


class CacheSubnetGroup(TypedDict, total=False):
    CacheSubnetGroupName: Optional[String]
    CacheSubnetGroupDescription: Optional[String]
    VpcId: Optional[String]
    Subnets: Optional[SubnetList]
    ARN: Optional[String]


CacheSubnetGroups = List[CacheSubnetGroup]


class CacheSubnetGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    CacheSubnetGroups: Optional[CacheSubnetGroups]


ClusterIdList = List[String]


class CompleteMigrationMessage(ServiceRequest):
    ReplicationGroupId: String
    Force: Optional[Boolean]


UserGroupIdList = List[UserGroupId]
ReplicationGroupOutpostArnList = List[String]


class NodeGroupMember(TypedDict, total=False):
    CacheClusterId: Optional[String]
    CacheNodeId: Optional[String]
    ReadEndpoint: Optional[Endpoint]
    PreferredAvailabilityZone: Optional[String]
    PreferredOutpostArn: Optional[String]
    CurrentRole: Optional[String]


NodeGroupMemberList = List[NodeGroupMember]


class NodeGroup(TypedDict, total=False):
    NodeGroupId: Optional[String]
    Status: Optional[String]
    PrimaryEndpoint: Optional[Endpoint]
    ReaderEndpoint: Optional[Endpoint]
    Slots: Optional[String]
    NodeGroupMembers: Optional[NodeGroupMemberList]


NodeGroupList = List[NodeGroup]


class UserGroupsUpdateStatus(TypedDict, total=False):
    UserGroupIdsToAdd: Optional[UserGroupIdList]
    UserGroupIdsToRemove: Optional[UserGroupIdList]


class SlotMigration(TypedDict, total=False):
    ProgressPercentage: Optional[Double]


class ReshardingStatus(TypedDict, total=False):
    SlotMigration: Optional[SlotMigration]


class ReplicationGroupPendingModifiedValues(TypedDict, total=False):
    PrimaryClusterId: Optional[String]
    AutomaticFailoverStatus: Optional[PendingAutomaticFailoverStatus]
    Resharding: Optional[ReshardingStatus]
    AuthTokenStatus: Optional[AuthTokenUpdateStatus]
    UserGroups: Optional[UserGroupsUpdateStatus]
    LogDeliveryConfigurations: Optional[PendingLogDeliveryConfigurationList]


class GlobalReplicationGroupInfo(TypedDict, total=False):
    GlobalReplicationGroupId: Optional[String]
    GlobalReplicationGroupMemberRole: Optional[String]


class ReplicationGroup(TypedDict, total=False):
    ReplicationGroupId: Optional[String]
    Description: Optional[String]
    GlobalReplicationGroupInfo: Optional[GlobalReplicationGroupInfo]
    Status: Optional[String]
    PendingModifiedValues: Optional[ReplicationGroupPendingModifiedValues]
    MemberClusters: Optional[ClusterIdList]
    NodeGroups: Optional[NodeGroupList]
    SnapshottingClusterId: Optional[String]
    AutomaticFailover: Optional[AutomaticFailoverStatus]
    MultiAZ: Optional[MultiAZStatus]
    ConfigurationEndpoint: Optional[Endpoint]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    ClusterEnabled: Optional[BooleanOptional]
    CacheNodeType: Optional[String]
    AuthTokenEnabled: Optional[BooleanOptional]
    AuthTokenLastModifiedDate: Optional[TStamp]
    TransitEncryptionEnabled: Optional[BooleanOptional]
    AtRestEncryptionEnabled: Optional[BooleanOptional]
    MemberClustersOutpostArns: Optional[ReplicationGroupOutpostArnList]
    KmsKeyId: Optional[String]
    ARN: Optional[String]
    UserGroupIds: Optional[UserGroupIdList]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationList]
    ReplicationGroupCreateTime: Optional[TStamp]
    DataTiering: Optional[DataTieringStatus]


class CompleteMigrationResponse(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


PreferredOutpostArnList = List[String]
PreferredAvailabilityZoneList = List[String]


class ConfigureShard(TypedDict, total=False):
    NodeGroupId: AllowedNodeGroupId
    NewReplicaCount: Integer
    PreferredAvailabilityZones: Optional[PreferredAvailabilityZoneList]
    PreferredOutpostArns: Optional[PreferredOutpostArnList]


class CopySnapshotMessage(ServiceRequest):
    SourceSnapshotName: String
    TargetSnapshotName: String
    TargetBucket: Optional[String]
    KmsKeyId: Optional[String]
    Tags: Optional[TagList]


OutpostArnsList = List[String]


class NodeGroupConfiguration(TypedDict, total=False):
    NodeGroupId: Optional[AllowedNodeGroupId]
    Slots: Optional[String]
    ReplicaCount: Optional[IntegerOptional]
    PrimaryAvailabilityZone: Optional[String]
    ReplicaAvailabilityZones: Optional[AvailabilityZonesList]
    PrimaryOutpostArn: Optional[String]
    ReplicaOutpostArns: Optional[OutpostArnsList]


class NodeSnapshot(TypedDict, total=False):
    CacheClusterId: Optional[String]
    NodeGroupId: Optional[String]
    CacheNodeId: Optional[String]
    NodeGroupConfiguration: Optional[NodeGroupConfiguration]
    CacheSize: Optional[String]
    CacheNodeCreateTime: Optional[TStamp]
    SnapshotCreateTime: Optional[TStamp]


NodeSnapshotList = List[NodeSnapshot]


class Snapshot(TypedDict, total=False):
    SnapshotName: Optional[String]
    ReplicationGroupId: Optional[String]
    ReplicationGroupDescription: Optional[String]
    CacheClusterId: Optional[String]
    SnapshotStatus: Optional[String]
    SnapshotSource: Optional[String]
    CacheNodeType: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    NumCacheNodes: Optional[IntegerOptional]
    PreferredAvailabilityZone: Optional[String]
    PreferredOutpostArn: Optional[String]
    CacheClusterCreateTime: Optional[TStamp]
    PreferredMaintenanceWindow: Optional[String]
    TopicArn: Optional[String]
    Port: Optional[IntegerOptional]
    CacheParameterGroupName: Optional[String]
    CacheSubnetGroupName: Optional[String]
    VpcId: Optional[String]
    AutoMinorVersionUpgrade: Optional[Boolean]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    NumNodeGroups: Optional[IntegerOptional]
    AutomaticFailover: Optional[AutomaticFailoverStatus]
    NodeSnapshots: Optional[NodeSnapshotList]
    KmsKeyId: Optional[String]
    ARN: Optional[String]
    DataTiering: Optional[DataTieringStatus]


class CopySnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class LogDeliveryConfigurationRequest(TypedDict, total=False):
    LogType: Optional[LogType]
    DestinationType: Optional[DestinationType]
    DestinationDetails: Optional[DestinationDetails]
    LogFormat: Optional[LogFormat]
    Enabled: Optional[BooleanOptional]


LogDeliveryConfigurationRequestList = List[LogDeliveryConfigurationRequest]
SnapshotArnsList = List[String]
SecurityGroupIdsList = List[String]


class CreateCacheClusterMessage(ServiceRequest):
    CacheClusterId: String
    ReplicationGroupId: Optional[String]
    AZMode: Optional[AZMode]
    PreferredAvailabilityZone: Optional[String]
    PreferredAvailabilityZones: Optional[PreferredAvailabilityZoneList]
    NumCacheNodes: Optional[IntegerOptional]
    CacheNodeType: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    CacheParameterGroupName: Optional[String]
    CacheSubnetGroupName: Optional[String]
    CacheSecurityGroupNames: Optional[CacheSecurityGroupNameList]
    SecurityGroupIds: Optional[SecurityGroupIdsList]
    Tags: Optional[TagList]
    SnapshotArns: Optional[SnapshotArnsList]
    SnapshotName: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    Port: Optional[IntegerOptional]
    NotificationTopicArn: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    AuthToken: Optional[String]
    OutpostMode: Optional[OutpostMode]
    PreferredOutpostArn: Optional[String]
    PreferredOutpostArns: Optional[PreferredOutpostArnList]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationRequestList]


class CreateCacheClusterResult(TypedDict, total=False):
    CacheCluster: Optional[CacheCluster]


class CreateCacheParameterGroupMessage(ServiceRequest):
    CacheParameterGroupName: String
    CacheParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateCacheParameterGroupResult(TypedDict, total=False):
    CacheParameterGroup: Optional[CacheParameterGroup]


class CreateCacheSecurityGroupMessage(ServiceRequest):
    CacheSecurityGroupName: String
    Description: String
    Tags: Optional[TagList]


class CreateCacheSecurityGroupResult(TypedDict, total=False):
    CacheSecurityGroup: Optional[CacheSecurityGroup]


SubnetIdentifierList = List[String]


class CreateCacheSubnetGroupMessage(ServiceRequest):
    CacheSubnetGroupName: String
    CacheSubnetGroupDescription: String
    SubnetIds: SubnetIdentifierList
    Tags: Optional[TagList]


class CreateCacheSubnetGroupResult(TypedDict, total=False):
    CacheSubnetGroup: Optional[CacheSubnetGroup]


class CreateGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupIdSuffix: String
    GlobalReplicationGroupDescription: Optional[String]
    PrimaryReplicationGroupId: String


class GlobalNodeGroup(TypedDict, total=False):
    GlobalNodeGroupId: Optional[String]
    Slots: Optional[String]


GlobalNodeGroupList = List[GlobalNodeGroup]


class GlobalReplicationGroupMember(TypedDict, total=False):
    ReplicationGroupId: Optional[String]
    ReplicationGroupRegion: Optional[String]
    Role: Optional[String]
    AutomaticFailover: Optional[AutomaticFailoverStatus]
    Status: Optional[String]


GlobalReplicationGroupMemberList = List[GlobalReplicationGroupMember]


class GlobalReplicationGroup(TypedDict, total=False):
    GlobalReplicationGroupId: Optional[String]
    GlobalReplicationGroupDescription: Optional[String]
    Status: Optional[String]
    CacheNodeType: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    Members: Optional[GlobalReplicationGroupMemberList]
    ClusterEnabled: Optional[BooleanOptional]
    GlobalNodeGroups: Optional[GlobalNodeGroupList]
    AuthTokenEnabled: Optional[BooleanOptional]
    TransitEncryptionEnabled: Optional[BooleanOptional]
    AtRestEncryptionEnabled: Optional[BooleanOptional]
    ARN: Optional[String]


class CreateGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


UserGroupIdListInput = List[UserGroupId]
NodeGroupConfigurationList = List[NodeGroupConfiguration]


class CreateReplicationGroupMessage(ServiceRequest):
    ReplicationGroupId: String
    ReplicationGroupDescription: String
    GlobalReplicationGroupId: Optional[String]
    PrimaryClusterId: Optional[String]
    AutomaticFailoverEnabled: Optional[BooleanOptional]
    MultiAZEnabled: Optional[BooleanOptional]
    NumCacheClusters: Optional[IntegerOptional]
    PreferredCacheClusterAZs: Optional[AvailabilityZonesList]
    NumNodeGroups: Optional[IntegerOptional]
    ReplicasPerNodeGroup: Optional[IntegerOptional]
    NodeGroupConfiguration: Optional[NodeGroupConfigurationList]
    CacheNodeType: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    CacheParameterGroupName: Optional[String]
    CacheSubnetGroupName: Optional[String]
    CacheSecurityGroupNames: Optional[CacheSecurityGroupNameList]
    SecurityGroupIds: Optional[SecurityGroupIdsList]
    Tags: Optional[TagList]
    SnapshotArns: Optional[SnapshotArnsList]
    SnapshotName: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    Port: Optional[IntegerOptional]
    NotificationTopicArn: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    AuthToken: Optional[String]
    TransitEncryptionEnabled: Optional[BooleanOptional]
    AtRestEncryptionEnabled: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    UserGroupIds: Optional[UserGroupIdListInput]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationRequestList]
    DataTieringEnabled: Optional[BooleanOptional]


class CreateReplicationGroupResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class CreateSnapshotMessage(ServiceRequest):
    ReplicationGroupId: Optional[String]
    CacheClusterId: Optional[String]
    SnapshotName: String
    KmsKeyId: Optional[String]
    Tags: Optional[TagList]


class CreateSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


UserIdListInput = List[UserId]


class CreateUserGroupMessage(ServiceRequest):
    UserGroupId: String
    Engine: EngineType
    UserIds: Optional[UserIdListInput]
    Tags: Optional[TagList]


PasswordListInput = List[String]


class CreateUserMessage(ServiceRequest):
    UserId: UserId
    UserName: UserName
    Engine: EngineType
    Passwords: Optional[PasswordListInput]
    AccessString: AccessString
    NoPasswordRequired: Optional[BooleanOptional]
    Tags: Optional[TagList]


class CustomerNodeEndpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[IntegerOptional]


CustomerNodeEndpointList = List[CustomerNodeEndpoint]
GlobalNodeGroupIdList = List[String]


class DecreaseNodeGroupsInGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    NodeGroupCount: Integer
    GlobalNodeGroupsToRemove: Optional[GlobalNodeGroupIdList]
    GlobalNodeGroupsToRetain: Optional[GlobalNodeGroupIdList]
    ApplyImmediately: Boolean


class DecreaseNodeGroupsInGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


RemoveReplicasList = List[String]
ReplicaConfigurationList = List[ConfigureShard]


class DecreaseReplicaCountMessage(ServiceRequest):
    ReplicationGroupId: String
    NewReplicaCount: Optional[IntegerOptional]
    ReplicaConfiguration: Optional[ReplicaConfigurationList]
    ReplicasToRemove: Optional[RemoveReplicasList]
    ApplyImmediately: Boolean


class DecreaseReplicaCountResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class DeleteCacheClusterMessage(ServiceRequest):
    CacheClusterId: String
    FinalSnapshotIdentifier: Optional[String]


class DeleteCacheClusterResult(TypedDict, total=False):
    CacheCluster: Optional[CacheCluster]


class DeleteCacheParameterGroupMessage(ServiceRequest):
    CacheParameterGroupName: String


class DeleteCacheSecurityGroupMessage(ServiceRequest):
    CacheSecurityGroupName: String


class DeleteCacheSubnetGroupMessage(ServiceRequest):
    CacheSubnetGroupName: String


class DeleteGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    RetainPrimaryReplicationGroup: Boolean


class DeleteGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class DeleteReplicationGroupMessage(ServiceRequest):
    ReplicationGroupId: String
    RetainPrimaryCluster: Optional[BooleanOptional]
    FinalSnapshotIdentifier: Optional[String]


class DeleteReplicationGroupResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class DeleteSnapshotMessage(ServiceRequest):
    SnapshotName: String


class DeleteSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class DeleteUserGroupMessage(ServiceRequest):
    UserGroupId: String


class DeleteUserMessage(ServiceRequest):
    UserId: UserId


class DescribeCacheClustersMessage(ServiceRequest):
    CacheClusterId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    ShowCacheNodeInfo: Optional[BooleanOptional]
    ShowCacheClustersNotInReplicationGroups: Optional[BooleanOptional]


class DescribeCacheEngineVersionsMessage(ServiceRequest):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    CacheParameterGroupFamily: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    DefaultOnly: Optional[Boolean]


class DescribeCacheParameterGroupsMessage(ServiceRequest):
    CacheParameterGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeCacheParametersMessage(ServiceRequest):
    CacheParameterGroupName: String
    Source: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeCacheSecurityGroupsMessage(ServiceRequest):
    CacheSecurityGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeCacheSubnetGroupsMessage(ServiceRequest):
    CacheSubnetGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEngineDefaultParametersMessage(ServiceRequest):
    CacheParameterGroupFamily: String
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class EngineDefaults(TypedDict, total=False):
    CacheParameterGroupFamily: Optional[String]
    Marker: Optional[String]
    Parameters: Optional[ParametersList]
    CacheNodeTypeSpecificParameters: Optional[CacheNodeTypeSpecificParametersList]


class DescribeEngineDefaultParametersResult(TypedDict, total=False):
    EngineDefaults: Optional[EngineDefaults]


class DescribeEventsMessage(ServiceRequest):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Duration: Optional[IntegerOptional]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeGlobalReplicationGroupsMessage(ServiceRequest):
    GlobalReplicationGroupId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    ShowMemberInfo: Optional[BooleanOptional]


GlobalReplicationGroupList = List[GlobalReplicationGroup]


class DescribeGlobalReplicationGroupsResult(TypedDict, total=False):
    Marker: Optional[String]
    GlobalReplicationGroups: Optional[GlobalReplicationGroupList]


class DescribeReplicationGroupsMessage(ServiceRequest):
    ReplicationGroupId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeReservedCacheNodesMessage(ServiceRequest):
    ReservedCacheNodeId: Optional[String]
    ReservedCacheNodesOfferingId: Optional[String]
    CacheNodeType: Optional[String]
    Duration: Optional[String]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeReservedCacheNodesOfferingsMessage(ServiceRequest):
    ReservedCacheNodesOfferingId: Optional[String]
    CacheNodeType: Optional[String]
    Duration: Optional[String]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


ServiceUpdateStatusList = List[ServiceUpdateStatus]


class DescribeServiceUpdatesMessage(ServiceRequest):
    ServiceUpdateName: Optional[String]
    ServiceUpdateStatus: Optional[ServiceUpdateStatusList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


SnapshotList = List[Snapshot]


class DescribeSnapshotsListMessage(TypedDict, total=False):
    Marker: Optional[String]
    Snapshots: Optional[SnapshotList]


class DescribeSnapshotsMessage(ServiceRequest):
    ReplicationGroupId: Optional[String]
    CacheClusterId: Optional[String]
    SnapshotName: Optional[String]
    SnapshotSource: Optional[String]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    ShowNodeGroupConfig: Optional[BooleanOptional]


UpdateActionStatusList = List[UpdateActionStatus]


class TimeRangeFilter(TypedDict, total=False):
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]


class DescribeUpdateActionsMessage(ServiceRequest):
    ServiceUpdateName: Optional[String]
    ReplicationGroupIds: Optional[ReplicationGroupIdList]
    CacheClusterIds: Optional[CacheClusterIdList]
    Engine: Optional[String]
    ServiceUpdateStatus: Optional[ServiceUpdateStatusList]
    ServiceUpdateTimeRange: Optional[TimeRangeFilter]
    UpdateActionStatus: Optional[UpdateActionStatusList]
    ShowNodeLevelUpdateStatus: Optional[BooleanOptional]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeUserGroupsMessage(ServiceRequest):
    UserGroupId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


UGReplicationGroupIdList = List[String]
UserIdList = List[UserId]


class UserGroupPendingChanges(TypedDict, total=False):
    UserIdsToRemove: Optional[UserIdList]
    UserIdsToAdd: Optional[UserIdList]


class UserGroup(TypedDict, total=False):
    UserGroupId: Optional[String]
    Status: Optional[String]
    Engine: Optional[EngineType]
    UserIds: Optional[UserIdList]
    MinimumEngineVersion: Optional[String]
    PendingChanges: Optional[UserGroupPendingChanges]
    ReplicationGroups: Optional[UGReplicationGroupIdList]
    ARN: Optional[String]


UserGroupList = List[UserGroup]


class DescribeUserGroupsResult(TypedDict, total=False):
    UserGroups: Optional[UserGroupList]
    Marker: Optional[String]


FilterValueList = List[FilterValue]


class Filter(TypedDict, total=False):
    Name: FilterName
    Values: FilterValueList


FilterList = List[Filter]


class DescribeUsersMessage(ServiceRequest):
    Engine: Optional[EngineType]
    UserId: Optional[UserId]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class User(TypedDict, total=False):
    UserId: Optional[String]
    UserName: Optional[String]
    Status: Optional[String]
    Engine: Optional[EngineType]
    MinimumEngineVersion: Optional[String]
    AccessString: Optional[String]
    UserGroupIds: Optional[UserGroupIdList]
    Authentication: Optional[Authentication]
    ARN: Optional[String]


UserList = List[User]


class DescribeUsersResult(TypedDict, total=False):
    Users: Optional[UserList]
    Marker: Optional[String]


class DisassociateGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    ReplicationGroupId: String
    ReplicationGroupRegion: String


class DisassociateGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class Event(TypedDict, total=False):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    Message: Optional[String]
    Date: Optional[TStamp]


EventList = List[Event]


class EventsMessage(TypedDict, total=False):
    Marker: Optional[String]
    Events: Optional[EventList]


class FailoverGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    PrimaryRegion: String
    PrimaryReplicationGroupId: String


class FailoverGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class ReshardingConfiguration(TypedDict, total=False):
    NodeGroupId: Optional[AllowedNodeGroupId]
    PreferredAvailabilityZones: Optional[AvailabilityZonesList]


ReshardingConfigurationList = List[ReshardingConfiguration]


class RegionalConfiguration(TypedDict, total=False):
    ReplicationGroupId: String
    ReplicationGroupRegion: String
    ReshardingConfiguration: ReshardingConfigurationList


RegionalConfigurationList = List[RegionalConfiguration]


class IncreaseNodeGroupsInGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    NodeGroupCount: Integer
    RegionalConfigurations: Optional[RegionalConfigurationList]
    ApplyImmediately: Boolean


class IncreaseNodeGroupsInGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class IncreaseReplicaCountMessage(ServiceRequest):
    ReplicationGroupId: String
    NewReplicaCount: Optional[IntegerOptional]
    ReplicaConfiguration: Optional[ReplicaConfigurationList]
    ApplyImmediately: Boolean


class IncreaseReplicaCountResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


KeyList = List[String]


class ListAllowedNodeTypeModificationsMessage(ServiceRequest):
    CacheClusterId: Optional[String]
    ReplicationGroupId: Optional[String]


class ListTagsForResourceMessage(ServiceRequest):
    ResourceName: String


class ModifyCacheClusterMessage(ServiceRequest):
    CacheClusterId: String
    NumCacheNodes: Optional[IntegerOptional]
    CacheNodeIdsToRemove: Optional[CacheNodeIdsList]
    AZMode: Optional[AZMode]
    NewAvailabilityZones: Optional[PreferredAvailabilityZoneList]
    CacheSecurityGroupNames: Optional[CacheSecurityGroupNameList]
    SecurityGroupIds: Optional[SecurityGroupIdsList]
    PreferredMaintenanceWindow: Optional[String]
    NotificationTopicArn: Optional[String]
    CacheParameterGroupName: Optional[String]
    NotificationTopicStatus: Optional[String]
    ApplyImmediately: Optional[Boolean]
    EngineVersion: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    CacheNodeType: Optional[String]
    AuthToken: Optional[String]
    AuthTokenUpdateStrategy: Optional[AuthTokenUpdateStrategyType]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationRequestList]


class ModifyCacheClusterResult(TypedDict, total=False):
    CacheCluster: Optional[CacheCluster]


class ParameterNameValue(TypedDict, total=False):
    ParameterName: Optional[String]
    ParameterValue: Optional[String]


ParameterNameValueList = List[ParameterNameValue]


class ModifyCacheParameterGroupMessage(ServiceRequest):
    CacheParameterGroupName: String
    ParameterNameValues: ParameterNameValueList


class ModifyCacheSubnetGroupMessage(ServiceRequest):
    CacheSubnetGroupName: String
    CacheSubnetGroupDescription: Optional[String]
    SubnetIds: Optional[SubnetIdentifierList]


class ModifyCacheSubnetGroupResult(TypedDict, total=False):
    CacheSubnetGroup: Optional[CacheSubnetGroup]


class ModifyGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    ApplyImmediately: Boolean
    CacheNodeType: Optional[String]
    EngineVersion: Optional[String]
    CacheParameterGroupName: Optional[String]
    GlobalReplicationGroupDescription: Optional[String]
    AutomaticFailoverEnabled: Optional[BooleanOptional]


class ModifyGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class ModifyReplicationGroupMessage(ServiceRequest):
    ReplicationGroupId: String
    ReplicationGroupDescription: Optional[String]
    PrimaryClusterId: Optional[String]
    SnapshottingClusterId: Optional[String]
    AutomaticFailoverEnabled: Optional[BooleanOptional]
    MultiAZEnabled: Optional[BooleanOptional]
    NodeGroupId: Optional[String]
    CacheSecurityGroupNames: Optional[CacheSecurityGroupNameList]
    SecurityGroupIds: Optional[SecurityGroupIdsList]
    PreferredMaintenanceWindow: Optional[String]
    NotificationTopicArn: Optional[String]
    CacheParameterGroupName: Optional[String]
    NotificationTopicStatus: Optional[String]
    ApplyImmediately: Optional[Boolean]
    EngineVersion: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    SnapshotRetentionLimit: Optional[IntegerOptional]
    SnapshotWindow: Optional[String]
    CacheNodeType: Optional[String]
    AuthToken: Optional[String]
    AuthTokenUpdateStrategy: Optional[AuthTokenUpdateStrategyType]
    UserGroupIdsToAdd: Optional[UserGroupIdList]
    UserGroupIdsToRemove: Optional[UserGroupIdList]
    RemoveUserGroups: Optional[BooleanOptional]
    LogDeliveryConfigurations: Optional[LogDeliveryConfigurationRequestList]


class ModifyReplicationGroupResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


NodeGroupsToRetainList = List[AllowedNodeGroupId]
NodeGroupsToRemoveList = List[AllowedNodeGroupId]


class ModifyReplicationGroupShardConfigurationMessage(ServiceRequest):
    ReplicationGroupId: String
    NodeGroupCount: Integer
    ApplyImmediately: Boolean
    ReshardingConfiguration: Optional[ReshardingConfigurationList]
    NodeGroupsToRemove: Optional[NodeGroupsToRemoveList]
    NodeGroupsToRetain: Optional[NodeGroupsToRetainList]


class ModifyReplicationGroupShardConfigurationResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class ModifyUserGroupMessage(ServiceRequest):
    UserGroupId: String
    UserIdsToAdd: Optional[UserIdListInput]
    UserIdsToRemove: Optional[UserIdListInput]


class ModifyUserMessage(ServiceRequest):
    UserId: UserId
    AccessString: Optional[AccessString]
    AppendAccessString: Optional[AccessString]
    Passwords: Optional[PasswordListInput]
    NoPasswordRequired: Optional[BooleanOptional]


class NodeGroupMemberUpdateStatus(TypedDict, total=False):
    CacheClusterId: Optional[String]
    CacheNodeId: Optional[String]
    NodeUpdateStatus: Optional[NodeUpdateStatus]
    NodeDeletionDate: Optional[TStamp]
    NodeUpdateStartDate: Optional[TStamp]
    NodeUpdateEndDate: Optional[TStamp]
    NodeUpdateInitiatedBy: Optional[NodeUpdateInitiatedBy]
    NodeUpdateInitiatedDate: Optional[TStamp]
    NodeUpdateStatusModifiedDate: Optional[TStamp]


NodeGroupMemberUpdateStatusList = List[NodeGroupMemberUpdateStatus]


class NodeGroupUpdateStatus(TypedDict, total=False):
    NodeGroupId: Optional[String]
    NodeGroupMemberUpdateStatus: Optional[NodeGroupMemberUpdateStatusList]


NodeGroupUpdateStatusList = List[NodeGroupUpdateStatus]


class ProcessedUpdateAction(TypedDict, total=False):
    ReplicationGroupId: Optional[String]
    CacheClusterId: Optional[String]
    ServiceUpdateName: Optional[String]
    UpdateActionStatus: Optional[UpdateActionStatus]


ProcessedUpdateActionList = List[ProcessedUpdateAction]


class PurchaseReservedCacheNodesOfferingMessage(ServiceRequest):
    ReservedCacheNodesOfferingId: String
    ReservedCacheNodeId: Optional[String]
    CacheNodeCount: Optional[IntegerOptional]
    Tags: Optional[TagList]


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedCacheNode(TypedDict, total=False):
    ReservedCacheNodeId: Optional[String]
    ReservedCacheNodesOfferingId: Optional[String]
    CacheNodeType: Optional[String]
    StartTime: Optional[TStamp]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CacheNodeCount: Optional[Integer]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    State: Optional[String]
    RecurringCharges: Optional[RecurringChargeList]
    ReservationARN: Optional[String]


class PurchaseReservedCacheNodesOfferingResult(TypedDict, total=False):
    ReservedCacheNode: Optional[ReservedCacheNode]


class RebalanceSlotsInGlobalReplicationGroupMessage(ServiceRequest):
    GlobalReplicationGroupId: String
    ApplyImmediately: Boolean


class RebalanceSlotsInGlobalReplicationGroupResult(TypedDict, total=False):
    GlobalReplicationGroup: Optional[GlobalReplicationGroup]


class RebootCacheClusterMessage(ServiceRequest):
    CacheClusterId: String
    CacheNodeIdsToReboot: CacheNodeIdsList


class RebootCacheClusterResult(TypedDict, total=False):
    CacheCluster: Optional[CacheCluster]


class RemoveTagsFromResourceMessage(ServiceRequest):
    ResourceName: String
    TagKeys: KeyList


ReplicationGroupList = List[ReplicationGroup]


class ReplicationGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReplicationGroups: Optional[ReplicationGroupList]


ReservedCacheNodeList = List[ReservedCacheNode]


class ReservedCacheNodeMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedCacheNodes: Optional[ReservedCacheNodeList]


class ReservedCacheNodesOffering(TypedDict, total=False):
    ReservedCacheNodesOfferingId: Optional[String]
    CacheNodeType: Optional[String]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    RecurringCharges: Optional[RecurringChargeList]


ReservedCacheNodesOfferingList = List[ReservedCacheNodesOffering]


class ReservedCacheNodesOfferingMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedCacheNodesOfferings: Optional[ReservedCacheNodesOfferingList]


class ResetCacheParameterGroupMessage(ServiceRequest):
    CacheParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    ParameterNameValues: Optional[ParameterNameValueList]


class RevokeCacheSecurityGroupIngressMessage(ServiceRequest):
    CacheSecurityGroupName: String
    EC2SecurityGroupName: String
    EC2SecurityGroupOwnerId: String


class RevokeCacheSecurityGroupIngressResult(TypedDict, total=False):
    CacheSecurityGroup: Optional[CacheSecurityGroup]


class ServiceUpdate(TypedDict, total=False):
    ServiceUpdateName: Optional[String]
    ServiceUpdateReleaseDate: Optional[TStamp]
    ServiceUpdateEndDate: Optional[TStamp]
    ServiceUpdateSeverity: Optional[ServiceUpdateSeverity]
    ServiceUpdateRecommendedApplyByDate: Optional[TStamp]
    ServiceUpdateStatus: Optional[ServiceUpdateStatus]
    ServiceUpdateDescription: Optional[String]
    ServiceUpdateType: Optional[ServiceUpdateType]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    AutoUpdateAfterRecommendedApplyByDate: Optional[BooleanOptional]
    EstimatedUpdateTime: Optional[String]


ServiceUpdateList = List[ServiceUpdate]


class ServiceUpdatesMessage(TypedDict, total=False):
    Marker: Optional[String]
    ServiceUpdates: Optional[ServiceUpdateList]


class StartMigrationMessage(ServiceRequest):
    ReplicationGroupId: String
    CustomerNodeEndpointList: CustomerNodeEndpointList


class StartMigrationResponse(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class TagListMessage(TypedDict, total=False):
    TagList: Optional[TagList]


class TestFailoverMessage(ServiceRequest):
    ReplicationGroupId: String
    NodeGroupId: AllowedNodeGroupId


class TestFailoverResult(TypedDict, total=False):
    ReplicationGroup: Optional[ReplicationGroup]


class UnprocessedUpdateAction(TypedDict, total=False):
    ReplicationGroupId: Optional[String]
    CacheClusterId: Optional[String]
    ServiceUpdateName: Optional[String]
    ErrorType: Optional[String]
    ErrorMessage: Optional[String]


UnprocessedUpdateActionList = List[UnprocessedUpdateAction]


class UpdateAction(TypedDict, total=False):
    ReplicationGroupId: Optional[String]
    CacheClusterId: Optional[String]
    ServiceUpdateName: Optional[String]
    ServiceUpdateReleaseDate: Optional[TStamp]
    ServiceUpdateSeverity: Optional[ServiceUpdateSeverity]
    ServiceUpdateStatus: Optional[ServiceUpdateStatus]
    ServiceUpdateRecommendedApplyByDate: Optional[TStamp]
    ServiceUpdateType: Optional[ServiceUpdateType]
    UpdateActionAvailableDate: Optional[TStamp]
    UpdateActionStatus: Optional[UpdateActionStatus]
    NodesUpdated: Optional[String]
    UpdateActionStatusModifiedDate: Optional[TStamp]
    SlaMet: Optional[SlaMet]
    NodeGroupUpdateStatus: Optional[NodeGroupUpdateStatusList]
    CacheNodeUpdateStatus: Optional[CacheNodeUpdateStatusList]
    EstimatedUpdateTime: Optional[String]
    Engine: Optional[String]


UpdateActionList = List[UpdateAction]


class UpdateActionResultsMessage(TypedDict, total=False):
    ProcessedUpdateActions: Optional[ProcessedUpdateActionList]
    UnprocessedUpdateActions: Optional[UnprocessedUpdateActionList]


class UpdateActionsMessage(TypedDict, total=False):
    Marker: Optional[String]
    UpdateActions: Optional[UpdateActionList]


class ElasticacheApi:

    service = "elasticache"
    version = "2015-02-02"

    @handler("AddTagsToResource")
    def add_tags_to_resource(
        self, context: RequestContext, resource_name: String, tags: TagList
    ) -> TagListMessage:
        raise NotImplementedError

    @handler("AuthorizeCacheSecurityGroupIngress")
    def authorize_cache_security_group_ingress(
        self,
        context: RequestContext,
        cache_security_group_name: String,
        ec2_security_group_name: String,
        ec2_security_group_owner_id: String,
    ) -> AuthorizeCacheSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("BatchApplyUpdateAction")
    def batch_apply_update_action(
        self,
        context: RequestContext,
        service_update_name: String,
        replication_group_ids: ReplicationGroupIdList = None,
        cache_cluster_ids: CacheClusterIdList = None,
    ) -> UpdateActionResultsMessage:
        raise NotImplementedError

    @handler("BatchStopUpdateAction")
    def batch_stop_update_action(
        self,
        context: RequestContext,
        service_update_name: String,
        replication_group_ids: ReplicationGroupIdList = None,
        cache_cluster_ids: CacheClusterIdList = None,
    ) -> UpdateActionResultsMessage:
        raise NotImplementedError

    @handler("CompleteMigration")
    def complete_migration(
        self, context: RequestContext, replication_group_id: String, force: Boolean = None
    ) -> CompleteMigrationResponse:
        raise NotImplementedError

    @handler("CopySnapshot")
    def copy_snapshot(
        self,
        context: RequestContext,
        source_snapshot_name: String,
        target_snapshot_name: String,
        target_bucket: String = None,
        kms_key_id: String = None,
        tags: TagList = None,
    ) -> CopySnapshotResult:
        raise NotImplementedError

    @handler("CreateCacheCluster")
    def create_cache_cluster(
        self,
        context: RequestContext,
        cache_cluster_id: String,
        replication_group_id: String = None,
        az_mode: AZMode = None,
        preferred_availability_zone: String = None,
        preferred_availability_zones: PreferredAvailabilityZoneList = None,
        num_cache_nodes: IntegerOptional = None,
        cache_node_type: String = None,
        engine: String = None,
        engine_version: String = None,
        cache_parameter_group_name: String = None,
        cache_subnet_group_name: String = None,
        cache_security_group_names: CacheSecurityGroupNameList = None,
        security_group_ids: SecurityGroupIdsList = None,
        tags: TagList = None,
        snapshot_arns: SnapshotArnsList = None,
        snapshot_name: String = None,
        preferred_maintenance_window: String = None,
        port: IntegerOptional = None,
        notification_topic_arn: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        snapshot_retention_limit: IntegerOptional = None,
        snapshot_window: String = None,
        auth_token: String = None,
        outpost_mode: OutpostMode = None,
        preferred_outpost_arn: String = None,
        preferred_outpost_arns: PreferredOutpostArnList = None,
        log_delivery_configurations: LogDeliveryConfigurationRequestList = None,
    ) -> CreateCacheClusterResult:
        raise NotImplementedError

    @handler("CreateCacheParameterGroup")
    def create_cache_parameter_group(
        self,
        context: RequestContext,
        cache_parameter_group_name: String,
        cache_parameter_group_family: String,
        description: String,
        tags: TagList = None,
    ) -> CreateCacheParameterGroupResult:
        raise NotImplementedError

    @handler("CreateCacheSecurityGroup")
    def create_cache_security_group(
        self,
        context: RequestContext,
        cache_security_group_name: String,
        description: String,
        tags: TagList = None,
    ) -> CreateCacheSecurityGroupResult:
        raise NotImplementedError

    @handler("CreateCacheSubnetGroup")
    def create_cache_subnet_group(
        self,
        context: RequestContext,
        cache_subnet_group_name: String,
        cache_subnet_group_description: String,
        subnet_ids: SubnetIdentifierList,
        tags: TagList = None,
    ) -> CreateCacheSubnetGroupResult:
        raise NotImplementedError

    @handler("CreateGlobalReplicationGroup")
    def create_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id_suffix: String,
        primary_replication_group_id: String,
        global_replication_group_description: String = None,
    ) -> CreateGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("CreateReplicationGroup")
    def create_replication_group(
        self,
        context: RequestContext,
        replication_group_id: String,
        replication_group_description: String,
        global_replication_group_id: String = None,
        primary_cluster_id: String = None,
        automatic_failover_enabled: BooleanOptional = None,
        multi_az_enabled: BooleanOptional = None,
        num_cache_clusters: IntegerOptional = None,
        preferred_cache_cluster_azs: AvailabilityZonesList = None,
        num_node_groups: IntegerOptional = None,
        replicas_per_node_group: IntegerOptional = None,
        node_group_configuration: NodeGroupConfigurationList = None,
        cache_node_type: String = None,
        engine: String = None,
        engine_version: String = None,
        cache_parameter_group_name: String = None,
        cache_subnet_group_name: String = None,
        cache_security_group_names: CacheSecurityGroupNameList = None,
        security_group_ids: SecurityGroupIdsList = None,
        tags: TagList = None,
        snapshot_arns: SnapshotArnsList = None,
        snapshot_name: String = None,
        preferred_maintenance_window: String = None,
        port: IntegerOptional = None,
        notification_topic_arn: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        snapshot_retention_limit: IntegerOptional = None,
        snapshot_window: String = None,
        auth_token: String = None,
        transit_encryption_enabled: BooleanOptional = None,
        at_rest_encryption_enabled: BooleanOptional = None,
        kms_key_id: String = None,
        user_group_ids: UserGroupIdListInput = None,
        log_delivery_configurations: LogDeliveryConfigurationRequestList = None,
        data_tiering_enabled: BooleanOptional = None,
    ) -> CreateReplicationGroupResult:
        raise NotImplementedError

    @handler("CreateSnapshot")
    def create_snapshot(
        self,
        context: RequestContext,
        snapshot_name: String,
        replication_group_id: String = None,
        cache_cluster_id: String = None,
        kms_key_id: String = None,
        tags: TagList = None,
    ) -> CreateSnapshotResult:
        raise NotImplementedError

    @handler("CreateUser")
    def create_user(
        self,
        context: RequestContext,
        user_id: UserId,
        user_name: UserName,
        engine: EngineType,
        access_string: AccessString,
        passwords: PasswordListInput = None,
        no_password_required: BooleanOptional = None,
        tags: TagList = None,
    ) -> User:
        raise NotImplementedError

    @handler("CreateUserGroup")
    def create_user_group(
        self,
        context: RequestContext,
        user_group_id: String,
        engine: EngineType,
        user_ids: UserIdListInput = None,
        tags: TagList = None,
    ) -> UserGroup:
        raise NotImplementedError

    @handler("DecreaseNodeGroupsInGlobalReplicationGroup")
    def decrease_node_groups_in_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        node_group_count: Integer,
        apply_immediately: Boolean,
        global_node_groups_to_remove: GlobalNodeGroupIdList = None,
        global_node_groups_to_retain: GlobalNodeGroupIdList = None,
    ) -> DecreaseNodeGroupsInGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("DecreaseReplicaCount")
    def decrease_replica_count(
        self,
        context: RequestContext,
        replication_group_id: String,
        apply_immediately: Boolean,
        new_replica_count: IntegerOptional = None,
        replica_configuration: ReplicaConfigurationList = None,
        replicas_to_remove: RemoveReplicasList = None,
    ) -> DecreaseReplicaCountResult:
        raise NotImplementedError

    @handler("DeleteCacheCluster")
    def delete_cache_cluster(
        self,
        context: RequestContext,
        cache_cluster_id: String,
        final_snapshot_identifier: String = None,
    ) -> DeleteCacheClusterResult:
        raise NotImplementedError

    @handler("DeleteCacheParameterGroup")
    def delete_cache_parameter_group(
        self, context: RequestContext, cache_parameter_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCacheSecurityGroup")
    def delete_cache_security_group(
        self, context: RequestContext, cache_security_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCacheSubnetGroup")
    def delete_cache_subnet_group(
        self, context: RequestContext, cache_subnet_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteGlobalReplicationGroup")
    def delete_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        retain_primary_replication_group: Boolean,
    ) -> DeleteGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("DeleteReplicationGroup")
    def delete_replication_group(
        self,
        context: RequestContext,
        replication_group_id: String,
        retain_primary_cluster: BooleanOptional = None,
        final_snapshot_identifier: String = None,
    ) -> DeleteReplicationGroupResult:
        raise NotImplementedError

    @handler("DeleteSnapshot")
    def delete_snapshot(
        self, context: RequestContext, snapshot_name: String
    ) -> DeleteSnapshotResult:
        raise NotImplementedError

    @handler("DeleteUser")
    def delete_user(self, context: RequestContext, user_id: UserId) -> User:
        raise NotImplementedError

    @handler("DeleteUserGroup")
    def delete_user_group(self, context: RequestContext, user_group_id: String) -> UserGroup:
        raise NotImplementedError

    @handler("DescribeCacheClusters")
    def describe_cache_clusters(
        self,
        context: RequestContext,
        cache_cluster_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        show_cache_node_info: BooleanOptional = None,
        show_cache_clusters_not_in_replication_groups: BooleanOptional = None,
    ) -> CacheClusterMessage:
        raise NotImplementedError

    @handler("DescribeCacheEngineVersions")
    def describe_cache_engine_versions(
        self,
        context: RequestContext,
        engine: String = None,
        engine_version: String = None,
        cache_parameter_group_family: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        default_only: Boolean = None,
    ) -> CacheEngineVersionMessage:
        raise NotImplementedError

    @handler("DescribeCacheParameterGroups")
    def describe_cache_parameter_groups(
        self,
        context: RequestContext,
        cache_parameter_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CacheParameterGroupsMessage:
        raise NotImplementedError

    @handler("DescribeCacheParameters")
    def describe_cache_parameters(
        self,
        context: RequestContext,
        cache_parameter_group_name: String,
        source: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CacheParameterGroupDetails:
        raise NotImplementedError

    @handler("DescribeCacheSecurityGroups")
    def describe_cache_security_groups(
        self,
        context: RequestContext,
        cache_security_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CacheSecurityGroupMessage:
        raise NotImplementedError

    @handler("DescribeCacheSubnetGroups")
    def describe_cache_subnet_groups(
        self,
        context: RequestContext,
        cache_subnet_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CacheSubnetGroupMessage:
        raise NotImplementedError

    @handler("DescribeEngineDefaultParameters")
    def describe_engine_default_parameters(
        self,
        context: RequestContext,
        cache_parameter_group_family: String,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeEngineDefaultParametersResult:
        raise NotImplementedError

    @handler("DescribeEvents")
    def describe_events(
        self,
        context: RequestContext,
        source_identifier: String = None,
        source_type: SourceType = None,
        start_time: TStamp = None,
        end_time: TStamp = None,
        duration: IntegerOptional = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EventsMessage:
        raise NotImplementedError

    @handler("DescribeGlobalReplicationGroups")
    def describe_global_replication_groups(
        self,
        context: RequestContext,
        global_replication_group_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        show_member_info: BooleanOptional = None,
    ) -> DescribeGlobalReplicationGroupsResult:
        raise NotImplementedError

    @handler("DescribeReplicationGroups")
    def describe_replication_groups(
        self,
        context: RequestContext,
        replication_group_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReplicationGroupMessage:
        raise NotImplementedError

    @handler("DescribeReservedCacheNodes")
    def describe_reserved_cache_nodes(
        self,
        context: RequestContext,
        reserved_cache_node_id: String = None,
        reserved_cache_nodes_offering_id: String = None,
        cache_node_type: String = None,
        duration: String = None,
        product_description: String = None,
        offering_type: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedCacheNodeMessage:
        raise NotImplementedError

    @handler("DescribeReservedCacheNodesOfferings")
    def describe_reserved_cache_nodes_offerings(
        self,
        context: RequestContext,
        reserved_cache_nodes_offering_id: String = None,
        cache_node_type: String = None,
        duration: String = None,
        product_description: String = None,
        offering_type: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedCacheNodesOfferingMessage:
        raise NotImplementedError

    @handler("DescribeServiceUpdates")
    def describe_service_updates(
        self,
        context: RequestContext,
        service_update_name: String = None,
        service_update_status: ServiceUpdateStatusList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ServiceUpdatesMessage:
        raise NotImplementedError

    @handler("DescribeSnapshots")
    def describe_snapshots(
        self,
        context: RequestContext,
        replication_group_id: String = None,
        cache_cluster_id: String = None,
        snapshot_name: String = None,
        snapshot_source: String = None,
        marker: String = None,
        max_records: IntegerOptional = None,
        show_node_group_config: BooleanOptional = None,
    ) -> DescribeSnapshotsListMessage:
        raise NotImplementedError

    @handler("DescribeUpdateActions")
    def describe_update_actions(
        self,
        context: RequestContext,
        service_update_name: String = None,
        replication_group_ids: ReplicationGroupIdList = None,
        cache_cluster_ids: CacheClusterIdList = None,
        engine: String = None,
        service_update_status: ServiceUpdateStatusList = None,
        service_update_time_range: TimeRangeFilter = None,
        update_action_status: UpdateActionStatusList = None,
        show_node_level_update_status: BooleanOptional = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> UpdateActionsMessage:
        raise NotImplementedError

    @handler("DescribeUserGroups")
    def describe_user_groups(
        self,
        context: RequestContext,
        user_group_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeUserGroupsResult:
        raise NotImplementedError

    @handler("DescribeUsers")
    def describe_users(
        self,
        context: RequestContext,
        engine: EngineType = None,
        user_id: UserId = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeUsersResult:
        raise NotImplementedError

    @handler("DisassociateGlobalReplicationGroup")
    def disassociate_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        replication_group_id: String,
        replication_group_region: String,
    ) -> DisassociateGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("FailoverGlobalReplicationGroup")
    def failover_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        primary_region: String,
        primary_replication_group_id: String,
    ) -> FailoverGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("IncreaseNodeGroupsInGlobalReplicationGroup")
    def increase_node_groups_in_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        node_group_count: Integer,
        apply_immediately: Boolean,
        regional_configurations: RegionalConfigurationList = None,
    ) -> IncreaseNodeGroupsInGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("IncreaseReplicaCount")
    def increase_replica_count(
        self,
        context: RequestContext,
        replication_group_id: String,
        apply_immediately: Boolean,
        new_replica_count: IntegerOptional = None,
        replica_configuration: ReplicaConfigurationList = None,
    ) -> IncreaseReplicaCountResult:
        raise NotImplementedError

    @handler("ListAllowedNodeTypeModifications")
    def list_allowed_node_type_modifications(
        self,
        context: RequestContext,
        cache_cluster_id: String = None,
        replication_group_id: String = None,
    ) -> AllowedNodeTypeModificationsMessage:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_name: String
    ) -> TagListMessage:
        raise NotImplementedError

    @handler("ModifyCacheCluster")
    def modify_cache_cluster(
        self,
        context: RequestContext,
        cache_cluster_id: String,
        num_cache_nodes: IntegerOptional = None,
        cache_node_ids_to_remove: CacheNodeIdsList = None,
        az_mode: AZMode = None,
        new_availability_zones: PreferredAvailabilityZoneList = None,
        cache_security_group_names: CacheSecurityGroupNameList = None,
        security_group_ids: SecurityGroupIdsList = None,
        preferred_maintenance_window: String = None,
        notification_topic_arn: String = None,
        cache_parameter_group_name: String = None,
        notification_topic_status: String = None,
        apply_immediately: Boolean = None,
        engine_version: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        snapshot_retention_limit: IntegerOptional = None,
        snapshot_window: String = None,
        cache_node_type: String = None,
        auth_token: String = None,
        auth_token_update_strategy: AuthTokenUpdateStrategyType = None,
        log_delivery_configurations: LogDeliveryConfigurationRequestList = None,
    ) -> ModifyCacheClusterResult:
        raise NotImplementedError

    @handler("ModifyCacheParameterGroup")
    def modify_cache_parameter_group(
        self,
        context: RequestContext,
        cache_parameter_group_name: String,
        parameter_name_values: ParameterNameValueList,
    ) -> CacheParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyCacheSubnetGroup")
    def modify_cache_subnet_group(
        self,
        context: RequestContext,
        cache_subnet_group_name: String,
        cache_subnet_group_description: String = None,
        subnet_ids: SubnetIdentifierList = None,
    ) -> ModifyCacheSubnetGroupResult:
        raise NotImplementedError

    @handler("ModifyGlobalReplicationGroup")
    def modify_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        apply_immediately: Boolean,
        cache_node_type: String = None,
        engine_version: String = None,
        cache_parameter_group_name: String = None,
        global_replication_group_description: String = None,
        automatic_failover_enabled: BooleanOptional = None,
    ) -> ModifyGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("ModifyReplicationGroup")
    def modify_replication_group(
        self,
        context: RequestContext,
        replication_group_id: String,
        replication_group_description: String = None,
        primary_cluster_id: String = None,
        snapshotting_cluster_id: String = None,
        automatic_failover_enabled: BooleanOptional = None,
        multi_az_enabled: BooleanOptional = None,
        node_group_id: String = None,
        cache_security_group_names: CacheSecurityGroupNameList = None,
        security_group_ids: SecurityGroupIdsList = None,
        preferred_maintenance_window: String = None,
        notification_topic_arn: String = None,
        cache_parameter_group_name: String = None,
        notification_topic_status: String = None,
        apply_immediately: Boolean = None,
        engine_version: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        snapshot_retention_limit: IntegerOptional = None,
        snapshot_window: String = None,
        cache_node_type: String = None,
        auth_token: String = None,
        auth_token_update_strategy: AuthTokenUpdateStrategyType = None,
        user_group_ids_to_add: UserGroupIdList = None,
        user_group_ids_to_remove: UserGroupIdList = None,
        remove_user_groups: BooleanOptional = None,
        log_delivery_configurations: LogDeliveryConfigurationRequestList = None,
    ) -> ModifyReplicationGroupResult:
        raise NotImplementedError

    @handler("ModifyReplicationGroupShardConfiguration")
    def modify_replication_group_shard_configuration(
        self,
        context: RequestContext,
        replication_group_id: String,
        node_group_count: Integer,
        apply_immediately: Boolean,
        resharding_configuration: ReshardingConfigurationList = None,
        node_groups_to_remove: NodeGroupsToRemoveList = None,
        node_groups_to_retain: NodeGroupsToRetainList = None,
    ) -> ModifyReplicationGroupShardConfigurationResult:
        raise NotImplementedError

    @handler("ModifyUser")
    def modify_user(
        self,
        context: RequestContext,
        user_id: UserId,
        access_string: AccessString = None,
        append_access_string: AccessString = None,
        passwords: PasswordListInput = None,
        no_password_required: BooleanOptional = None,
    ) -> User:
        raise NotImplementedError

    @handler("ModifyUserGroup")
    def modify_user_group(
        self,
        context: RequestContext,
        user_group_id: String,
        user_ids_to_add: UserIdListInput = None,
        user_ids_to_remove: UserIdListInput = None,
    ) -> UserGroup:
        raise NotImplementedError

    @handler("PurchaseReservedCacheNodesOffering")
    def purchase_reserved_cache_nodes_offering(
        self,
        context: RequestContext,
        reserved_cache_nodes_offering_id: String,
        reserved_cache_node_id: String = None,
        cache_node_count: IntegerOptional = None,
        tags: TagList = None,
    ) -> PurchaseReservedCacheNodesOfferingResult:
        raise NotImplementedError

    @handler("RebalanceSlotsInGlobalReplicationGroup")
    def rebalance_slots_in_global_replication_group(
        self,
        context: RequestContext,
        global_replication_group_id: String,
        apply_immediately: Boolean,
    ) -> RebalanceSlotsInGlobalReplicationGroupResult:
        raise NotImplementedError

    @handler("RebootCacheCluster")
    def reboot_cache_cluster(
        self,
        context: RequestContext,
        cache_cluster_id: String,
        cache_node_ids_to_reboot: CacheNodeIdsList,
    ) -> RebootCacheClusterResult:
        raise NotImplementedError

    @handler("RemoveTagsFromResource")
    def remove_tags_from_resource(
        self, context: RequestContext, resource_name: String, tag_keys: KeyList
    ) -> TagListMessage:
        raise NotImplementedError

    @handler("ResetCacheParameterGroup")
    def reset_cache_parameter_group(
        self,
        context: RequestContext,
        cache_parameter_group_name: String,
        reset_all_parameters: Boolean = None,
        parameter_name_values: ParameterNameValueList = None,
    ) -> CacheParameterGroupNameMessage:
        raise NotImplementedError

    @handler("RevokeCacheSecurityGroupIngress")
    def revoke_cache_security_group_ingress(
        self,
        context: RequestContext,
        cache_security_group_name: String,
        ec2_security_group_name: String,
        ec2_security_group_owner_id: String,
    ) -> RevokeCacheSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("StartMigration")
    def start_migration(
        self,
        context: RequestContext,
        replication_group_id: String,
        customer_node_endpoint_list: CustomerNodeEndpointList,
    ) -> StartMigrationResponse:
        raise NotImplementedError

    @handler("TestFailover")
    def test_failover(
        self,
        context: RequestContext,
        replication_group_id: String,
        node_group_id: AllowedNodeGroupId,
    ) -> TestFailoverResult:
        raise NotImplementedError
