import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BooleanOptional = bool
Double = float
DoubleOptional = float
Integer = int
IntegerOptional = int
String = str


class ApplyMethod(str):
    immediate = "immediate"
    pending_reboot = "pending-reboot"


class SourceType(str):
    db_instance = "db-instance"
    db_parameter_group = "db-parameter-group"
    db_security_group = "db-security-group"
    db_snapshot = "db-snapshot"
    db_cluster = "db-cluster"
    db_cluster_snapshot = "db-cluster-snapshot"


class AuthorizationNotFoundFault(ServiceException):
    pass


class CertificateNotFoundFault(ServiceException):
    pass


class DBClusterAlreadyExistsFault(ServiceException):
    pass


class DBClusterEndpointAlreadyExistsFault(ServiceException):
    pass


class DBClusterEndpointNotFoundFault(ServiceException):
    pass


class DBClusterEndpointQuotaExceededFault(ServiceException):
    pass


class DBClusterNotFoundFault(ServiceException):
    pass


class DBClusterParameterGroupNotFoundFault(ServiceException):
    pass


class DBClusterQuotaExceededFault(ServiceException):
    pass


class DBClusterRoleAlreadyExistsFault(ServiceException):
    pass


class DBClusterRoleNotFoundFault(ServiceException):
    pass


class DBClusterRoleQuotaExceededFault(ServiceException):
    pass


class DBClusterSnapshotAlreadyExistsFault(ServiceException):
    pass


class DBClusterSnapshotNotFoundFault(ServiceException):
    pass


class DBInstanceAlreadyExistsFault(ServiceException):
    pass


class DBInstanceNotFoundFault(ServiceException):
    pass


class DBParameterGroupAlreadyExistsFault(ServiceException):
    pass


class DBParameterGroupNotFoundFault(ServiceException):
    pass


class DBParameterGroupQuotaExceededFault(ServiceException):
    pass


class DBSecurityGroupNotFoundFault(ServiceException):
    pass


class DBSnapshotAlreadyExistsFault(ServiceException):
    pass


class DBSnapshotNotFoundFault(ServiceException):
    pass


class DBSubnetGroupAlreadyExistsFault(ServiceException):
    pass


class DBSubnetGroupDoesNotCoverEnoughAZs(ServiceException):
    pass


class DBSubnetGroupNotFoundFault(ServiceException):
    pass


class DBSubnetGroupQuotaExceededFault(ServiceException):
    pass


class DBSubnetQuotaExceededFault(ServiceException):
    pass


class DBUpgradeDependencyFailureFault(ServiceException):
    pass


class DomainNotFoundFault(ServiceException):
    pass


class EventSubscriptionQuotaExceededFault(ServiceException):
    pass


class InstanceQuotaExceededFault(ServiceException):
    pass


class InsufficientDBClusterCapacityFault(ServiceException):
    pass


class InsufficientDBInstanceCapacityFault(ServiceException):
    pass


class InsufficientStorageClusterCapacityFault(ServiceException):
    pass


class InvalidDBClusterEndpointStateFault(ServiceException):
    pass


class InvalidDBClusterSnapshotStateFault(ServiceException):
    pass


class InvalidDBClusterStateFault(ServiceException):
    pass


class InvalidDBInstanceStateFault(ServiceException):
    pass


class InvalidDBParameterGroupStateFault(ServiceException):
    pass


class InvalidDBSecurityGroupStateFault(ServiceException):
    pass


class InvalidDBSnapshotStateFault(ServiceException):
    pass


class InvalidDBSubnetGroupStateFault(ServiceException):
    pass


class InvalidDBSubnetStateFault(ServiceException):
    pass


class InvalidEventSubscriptionStateFault(ServiceException):
    pass


class InvalidRestoreFault(ServiceException):
    pass


class InvalidSubnet(ServiceException):
    pass


class InvalidVPCNetworkStateFault(ServiceException):
    pass


class KMSKeyNotAccessibleFault(ServiceException):
    pass


class OptionGroupNotFoundFault(ServiceException):
    pass


class ProvisionedIopsNotAvailableInAZFault(ServiceException):
    pass


class ResourceNotFoundFault(ServiceException):
    pass


class SNSInvalidTopicFault(ServiceException):
    pass


class SNSNoAuthorizationFault(ServiceException):
    pass


class SNSTopicArnNotFoundFault(ServiceException):
    pass


class SharedSnapshotQuotaExceededFault(ServiceException):
    pass


class SnapshotQuotaExceededFault(ServiceException):
    pass


class SourceNotFoundFault(ServiceException):
    pass


class StorageQuotaExceededFault(ServiceException):
    pass


class StorageTypeNotSupportedFault(ServiceException):
    pass


class SubnetAlreadyInUse(ServiceException):
    pass


class SubscriptionAlreadyExistFault(ServiceException):
    pass


class SubscriptionCategoryNotFoundFault(ServiceException):
    pass


class SubscriptionNotFoundFault(ServiceException):
    pass


class AddRoleToDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    RoleArn: String
    FeatureName: Optional[String]


class AddSourceIdentifierToSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SourceIdentifier: String


EventCategoriesList = List[String]
SourceIdsList = List[String]


class EventSubscription(TypedDict, total=False):
    CustomerAwsId: Optional[String]
    CustSubscriptionId: Optional[String]
    SnsTopicArn: Optional[String]
    Status: Optional[String]
    SubscriptionCreationTime: Optional[String]
    SourceType: Optional[String]
    SourceIdsList: Optional[SourceIdsList]
    EventCategoriesList: Optional[EventCategoriesList]
    Enabled: Optional[Boolean]
    EventSubscriptionArn: Optional[String]


class AddSourceIdentifierToSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class Tag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


TagList = List[Tag]


class AddTagsToResourceMessage(ServiceRequest):
    ResourceName: String
    Tags: TagList


class ApplyPendingMaintenanceActionMessage(ServiceRequest):
    ResourceIdentifier: String
    ApplyAction: String
    OptInType: String


TStamp = datetime


class PendingMaintenanceAction(TypedDict, total=False):
    Action: Optional[String]
    AutoAppliedAfterDate: Optional[TStamp]
    ForcedApplyDate: Optional[TStamp]
    OptInStatus: Optional[String]
    CurrentApplyDate: Optional[TStamp]
    Description: Optional[String]


PendingMaintenanceActionDetails = List[PendingMaintenanceAction]


class ResourcePendingMaintenanceActions(TypedDict, total=False):
    ResourceIdentifier: Optional[String]
    PendingMaintenanceActionDetails: Optional[PendingMaintenanceActionDetails]


class ApplyPendingMaintenanceActionResult(TypedDict, total=False):
    ResourcePendingMaintenanceActions: Optional[ResourcePendingMaintenanceActions]


AttributeValueList = List[String]


class AvailabilityZone(TypedDict, total=False):
    Name: Optional[String]


AvailabilityZoneList = List[AvailabilityZone]
AvailabilityZones = List[String]


class CharacterSet(TypedDict, total=False):
    CharacterSetName: Optional[String]
    CharacterSetDescription: Optional[String]


LogTypeList = List[String]


class CloudwatchLogsExportConfiguration(TypedDict, total=False):
    EnableLogTypes: Optional[LogTypeList]
    DisableLogTypes: Optional[LogTypeList]


class CopyDBClusterParameterGroupMessage(ServiceRequest):
    SourceDBClusterParameterGroupIdentifier: String
    TargetDBClusterParameterGroupIdentifier: String
    TargetDBClusterParameterGroupDescription: String
    Tags: Optional[TagList]


class DBClusterParameterGroup(TypedDict, total=False):
    DBClusterParameterGroupName: Optional[String]
    DBParameterGroupFamily: Optional[String]
    Description: Optional[String]
    DBClusterParameterGroupArn: Optional[String]


class CopyDBClusterParameterGroupResult(TypedDict, total=False):
    DBClusterParameterGroup: Optional[DBClusterParameterGroup]


class CopyDBClusterSnapshotMessage(ServiceRequest):
    SourceDBClusterSnapshotIdentifier: String
    TargetDBClusterSnapshotIdentifier: String
    KmsKeyId: Optional[String]
    PreSignedUrl: Optional[String]
    CopyTags: Optional[BooleanOptional]
    Tags: Optional[TagList]
    SourceRegion: Optional[String]


class DBClusterSnapshot(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZones]
    DBClusterSnapshotIdentifier: Optional[String]
    DBClusterIdentifier: Optional[String]
    SnapshotCreateTime: Optional[TStamp]
    Engine: Optional[String]
    AllocatedStorage: Optional[Integer]
    Status: Optional[String]
    Port: Optional[Integer]
    VpcId: Optional[String]
    ClusterCreateTime: Optional[TStamp]
    MasterUsername: Optional[String]
    EngineVersion: Optional[String]
    LicenseModel: Optional[String]
    SnapshotType: Optional[String]
    PercentProgress: Optional[Integer]
    StorageEncrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DBClusterSnapshotArn: Optional[String]
    SourceDBClusterSnapshotArn: Optional[String]
    IAMDatabaseAuthenticationEnabled: Optional[Boolean]


class CopyDBClusterSnapshotResult(TypedDict, total=False):
    DBClusterSnapshot: Optional[DBClusterSnapshot]


class CopyDBParameterGroupMessage(ServiceRequest):
    SourceDBParameterGroupIdentifier: String
    TargetDBParameterGroupIdentifier: String
    TargetDBParameterGroupDescription: String
    Tags: Optional[TagList]


class DBParameterGroup(TypedDict, total=False):
    DBParameterGroupName: Optional[String]
    DBParameterGroupFamily: Optional[String]
    Description: Optional[String]
    DBParameterGroupArn: Optional[String]


class CopyDBParameterGroupResult(TypedDict, total=False):
    DBParameterGroup: Optional[DBParameterGroup]


StringList = List[String]


class CreateDBClusterEndpointMessage(ServiceRequest):
    DBClusterIdentifier: String
    DBClusterEndpointIdentifier: String
    EndpointType: String
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    Tags: Optional[TagList]


class CreateDBClusterEndpointOutput(TypedDict, total=False):
    DBClusterEndpointIdentifier: Optional[String]
    DBClusterIdentifier: Optional[String]
    DBClusterEndpointResourceIdentifier: Optional[String]
    Endpoint: Optional[String]
    Status: Optional[String]
    EndpointType: Optional[String]
    CustomEndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    DBClusterEndpointArn: Optional[String]


VpcSecurityGroupIdList = List[String]


class CreateDBClusterMessage(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
    CharacterSetName: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    DatabaseName: Optional[String]
    DBClusterIdentifier: String
    DBClusterParameterGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    DBSubnetGroupName: Optional[String]
    Engine: String
    EngineVersion: Optional[String]
    Port: Optional[IntegerOptional]
    MasterUsername: Optional[String]
    MasterUserPassword: Optional[String]
    OptionGroupName: Optional[String]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    ReplicationSourceIdentifier: Optional[String]
    Tags: Optional[TagList]
    StorageEncrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    PreSignedUrl: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]
    SourceRegion: Optional[String]


class CreateDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    DBParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateDBClusterParameterGroupResult(TypedDict, total=False):
    DBClusterParameterGroup: Optional[DBClusterParameterGroup]


class DBClusterRole(TypedDict, total=False):
    RoleArn: Optional[String]
    Status: Optional[String]
    FeatureName: Optional[String]


DBClusterRoles = List[DBClusterRole]


class VpcSecurityGroupMembership(TypedDict, total=False):
    VpcSecurityGroupId: Optional[String]
    Status: Optional[String]


VpcSecurityGroupMembershipList = List[VpcSecurityGroupMembership]


class DBClusterMember(TypedDict, total=False):
    DBInstanceIdentifier: Optional[String]
    IsClusterWriter: Optional[Boolean]
    DBClusterParameterGroupStatus: Optional[String]
    PromotionTier: Optional[IntegerOptional]


DBClusterMemberList = List[DBClusterMember]
ReadReplicaIdentifierList = List[String]


class DBClusterOptionGroupStatus(TypedDict, total=False):
    DBClusterOptionGroupName: Optional[String]
    Status: Optional[String]


DBClusterOptionGroupMemberships = List[DBClusterOptionGroupStatus]


class DBCluster(TypedDict, total=False):
    AllocatedStorage: Optional[IntegerOptional]
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
    CharacterSetName: Optional[String]
    DatabaseName: Optional[String]
    DBClusterIdentifier: Optional[String]
    DBClusterParameterGroup: Optional[String]
    DBSubnetGroup: Optional[String]
    Status: Optional[String]
    PercentProgress: Optional[String]
    EarliestRestorableTime: Optional[TStamp]
    Endpoint: Optional[String]
    ReaderEndpoint: Optional[String]
    MultiAZ: Optional[Boolean]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    LatestRestorableTime: Optional[TStamp]
    Port: Optional[IntegerOptional]
    MasterUsername: Optional[String]
    DBClusterOptionGroupMemberships: Optional[DBClusterOptionGroupMemberships]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    ReplicationSourceIdentifier: Optional[String]
    ReadReplicaIdentifiers: Optional[ReadReplicaIdentifierList]
    DBClusterMembers: Optional[DBClusterMemberList]
    VpcSecurityGroups: Optional[VpcSecurityGroupMembershipList]
    HostedZoneId: Optional[String]
    StorageEncrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DbClusterResourceId: Optional[String]
    DBClusterArn: Optional[String]
    AssociatedRoles: Optional[DBClusterRoles]
    IAMDatabaseAuthenticationEnabled: Optional[Boolean]
    CloneGroupId: Optional[String]
    ClusterCreateTime: Optional[TStamp]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]
    CrossAccountClone: Optional[BooleanOptional]
    AutomaticRestartTime: Optional[TStamp]


class CreateDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class CreateDBClusterSnapshotMessage(ServiceRequest):
    DBClusterSnapshotIdentifier: String
    DBClusterIdentifier: String
    Tags: Optional[TagList]


class CreateDBClusterSnapshotResult(TypedDict, total=False):
    DBClusterSnapshot: Optional[DBClusterSnapshot]


DBSecurityGroupNameList = List[String]


class CreateDBInstanceMessage(ServiceRequest):
    DBName: Optional[String]
    DBInstanceIdentifier: String
    AllocatedStorage: Optional[IntegerOptional]
    DBInstanceClass: String
    Engine: String
    MasterUsername: Optional[String]
    MasterUserPassword: Optional[String]
    DBSecurityGroups: Optional[DBSecurityGroupNameList]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    AvailabilityZone: Optional[String]
    DBSubnetGroupName: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    DBParameterGroupName: Optional[String]
    BackupRetentionPeriod: Optional[IntegerOptional]
    PreferredBackupWindow: Optional[String]
    Port: Optional[IntegerOptional]
    MultiAZ: Optional[BooleanOptional]
    EngineVersion: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    CharacterSetName: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    Tags: Optional[TagList]
    DBClusterIdentifier: Optional[String]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    TdeCredentialPassword: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    Domain: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    DomainIAMRoleName: Optional[String]
    PromotionTier: Optional[IntegerOptional]
    Timezone: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]


class DomainMembership(TypedDict, total=False):
    Domain: Optional[String]
    Status: Optional[String]
    FQDN: Optional[String]
    IAMRoleName: Optional[String]


DomainMembershipList = List[DomainMembership]


class DBInstanceStatusInfo(TypedDict, total=False):
    StatusType: Optional[String]
    Normal: Optional[Boolean]
    Status: Optional[String]
    Message: Optional[String]


DBInstanceStatusInfoList = List[DBInstanceStatusInfo]


class OptionGroupMembership(TypedDict, total=False):
    OptionGroupName: Optional[String]
    Status: Optional[String]


OptionGroupMembershipList = List[OptionGroupMembership]
ReadReplicaDBClusterIdentifierList = List[String]
ReadReplicaDBInstanceIdentifierList = List[String]


class PendingCloudwatchLogsExports(TypedDict, total=False):
    LogTypesToEnable: Optional[LogTypeList]
    LogTypesToDisable: Optional[LogTypeList]


class PendingModifiedValues(TypedDict, total=False):
    DBInstanceClass: Optional[String]
    AllocatedStorage: Optional[IntegerOptional]
    MasterUserPassword: Optional[String]
    Port: Optional[IntegerOptional]
    BackupRetentionPeriod: Optional[IntegerOptional]
    MultiAZ: Optional[BooleanOptional]
    EngineVersion: Optional[String]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    DBInstanceIdentifier: Optional[String]
    StorageType: Optional[String]
    CACertificateIdentifier: Optional[String]
    DBSubnetGroupName: Optional[String]
    PendingCloudwatchLogsExports: Optional[PendingCloudwatchLogsExports]


class Subnet(TypedDict, total=False):
    SubnetIdentifier: Optional[String]
    SubnetAvailabilityZone: Optional[AvailabilityZone]
    SubnetStatus: Optional[String]


SubnetList = List[Subnet]


class DBSubnetGroup(TypedDict, total=False):
    DBSubnetGroupName: Optional[String]
    DBSubnetGroupDescription: Optional[String]
    VpcId: Optional[String]
    SubnetGroupStatus: Optional[String]
    Subnets: Optional[SubnetList]
    DBSubnetGroupArn: Optional[String]


class DBParameterGroupStatus(TypedDict, total=False):
    DBParameterGroupName: Optional[String]
    ParameterApplyStatus: Optional[String]


DBParameterGroupStatusList = List[DBParameterGroupStatus]


class DBSecurityGroupMembership(TypedDict, total=False):
    DBSecurityGroupName: Optional[String]
    Status: Optional[String]


DBSecurityGroupMembershipList = List[DBSecurityGroupMembership]


class Endpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[Integer]
    HostedZoneId: Optional[String]


class DBInstance(TypedDict, total=False):
    DBInstanceIdentifier: Optional[String]
    DBInstanceClass: Optional[String]
    Engine: Optional[String]
    DBInstanceStatus: Optional[String]
    MasterUsername: Optional[String]
    DBName: Optional[String]
    Endpoint: Optional[Endpoint]
    AllocatedStorage: Optional[Integer]
    InstanceCreateTime: Optional[TStamp]
    PreferredBackupWindow: Optional[String]
    BackupRetentionPeriod: Optional[Integer]
    DBSecurityGroups: Optional[DBSecurityGroupMembershipList]
    VpcSecurityGroups: Optional[VpcSecurityGroupMembershipList]
    DBParameterGroups: Optional[DBParameterGroupStatusList]
    AvailabilityZone: Optional[String]
    DBSubnetGroup: Optional[DBSubnetGroup]
    PreferredMaintenanceWindow: Optional[String]
    PendingModifiedValues: Optional[PendingModifiedValues]
    LatestRestorableTime: Optional[TStamp]
    MultiAZ: Optional[Boolean]
    EngineVersion: Optional[String]
    AutoMinorVersionUpgrade: Optional[Boolean]
    ReadReplicaSourceDBInstanceIdentifier: Optional[String]
    ReadReplicaDBInstanceIdentifiers: Optional[ReadReplicaDBInstanceIdentifierList]
    ReadReplicaDBClusterIdentifiers: Optional[ReadReplicaDBClusterIdentifierList]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupMemberships: Optional[OptionGroupMembershipList]
    CharacterSetName: Optional[String]
    SecondaryAvailabilityZone: Optional[String]
    PubliclyAccessible: Optional[Boolean]
    StatusInfos: Optional[DBInstanceStatusInfoList]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    DbInstancePort: Optional[Integer]
    DBClusterIdentifier: Optional[String]
    StorageEncrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DbiResourceId: Optional[String]
    CACertificateIdentifier: Optional[String]
    DomainMemberships: Optional[DomainMembershipList]
    CopyTagsToSnapshot: Optional[Boolean]
    MonitoringInterval: Optional[IntegerOptional]
    EnhancedMonitoringResourceArn: Optional[String]
    MonitoringRoleArn: Optional[String]
    PromotionTier: Optional[IntegerOptional]
    DBInstanceArn: Optional[String]
    Timezone: Optional[String]
    IAMDatabaseAuthenticationEnabled: Optional[Boolean]
    PerformanceInsightsEnabled: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]


class CreateDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class CreateDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    DBParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateDBParameterGroupResult(TypedDict, total=False):
    DBParameterGroup: Optional[DBParameterGroup]


SubnetIdentifierList = List[String]


class CreateDBSubnetGroupMessage(ServiceRequest):
    DBSubnetGroupName: String
    DBSubnetGroupDescription: String
    SubnetIds: SubnetIdentifierList
    Tags: Optional[TagList]


class CreateDBSubnetGroupResult(TypedDict, total=False):
    DBSubnetGroup: Optional[DBSubnetGroup]


class CreateEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: String
    SourceType: Optional[String]
    EventCategories: Optional[EventCategoriesList]
    SourceIds: Optional[SourceIdsList]
    Enabled: Optional[BooleanOptional]
    Tags: Optional[TagList]


class CreateEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class DBClusterEndpoint(TypedDict, total=False):
    DBClusterEndpointIdentifier: Optional[String]
    DBClusterIdentifier: Optional[String]
    DBClusterEndpointResourceIdentifier: Optional[String]
    Endpoint: Optional[String]
    Status: Optional[String]
    EndpointType: Optional[String]
    CustomEndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    DBClusterEndpointArn: Optional[String]


DBClusterEndpointList = List[DBClusterEndpoint]


class DBClusterEndpointMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBClusterEndpoints: Optional[DBClusterEndpointList]


DBClusterList = List[DBCluster]


class DBClusterMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBClusters: Optional[DBClusterList]


class Parameter(TypedDict, total=False):
    ParameterName: Optional[String]
    ParameterValue: Optional[String]
    Description: Optional[String]
    Source: Optional[String]
    ApplyType: Optional[String]
    DataType: Optional[String]
    AllowedValues: Optional[String]
    IsModifiable: Optional[Boolean]
    MinimumEngineVersion: Optional[String]
    ApplyMethod: Optional[ApplyMethod]


ParametersList = List[Parameter]


class DBClusterParameterGroupDetails(TypedDict, total=False):
    Parameters: Optional[ParametersList]
    Marker: Optional[String]


DBClusterParameterGroupList = List[DBClusterParameterGroup]


class DBClusterParameterGroupNameMessage(TypedDict, total=False):
    DBClusterParameterGroupName: Optional[String]


class DBClusterParameterGroupsMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBClusterParameterGroups: Optional[DBClusterParameterGroupList]


class DBClusterSnapshotAttribute(TypedDict, total=False):
    AttributeName: Optional[String]
    AttributeValues: Optional[AttributeValueList]


DBClusterSnapshotAttributeList = List[DBClusterSnapshotAttribute]


class DBClusterSnapshotAttributesResult(TypedDict, total=False):
    DBClusterSnapshotIdentifier: Optional[String]
    DBClusterSnapshotAttributes: Optional[DBClusterSnapshotAttributeList]


DBClusterSnapshotList = List[DBClusterSnapshot]


class DBClusterSnapshotMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBClusterSnapshots: Optional[DBClusterSnapshotList]


class Timezone(TypedDict, total=False):
    TimezoneName: Optional[String]


SupportedTimezonesList = List[Timezone]


class UpgradeTarget(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    Description: Optional[String]
    AutoUpgrade: Optional[Boolean]
    IsMajorVersionUpgrade: Optional[Boolean]


ValidUpgradeTargetList = List[UpgradeTarget]
SupportedCharacterSetsList = List[CharacterSet]


class DBEngineVersion(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBParameterGroupFamily: Optional[String]
    DBEngineDescription: Optional[String]
    DBEngineVersionDescription: Optional[String]
    DefaultCharacterSet: Optional[CharacterSet]
    SupportedCharacterSets: Optional[SupportedCharacterSetsList]
    ValidUpgradeTarget: Optional[ValidUpgradeTargetList]
    SupportedTimezones: Optional[SupportedTimezonesList]
    ExportableLogTypes: Optional[LogTypeList]
    SupportsLogExportsToCloudwatchLogs: Optional[Boolean]
    SupportsReadReplica: Optional[Boolean]


DBEngineVersionList = List[DBEngineVersion]


class DBEngineVersionMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBEngineVersions: Optional[DBEngineVersionList]


DBInstanceList = List[DBInstance]


class DBInstanceMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBInstances: Optional[DBInstanceList]


class DBParameterGroupDetails(TypedDict, total=False):
    Parameters: Optional[ParametersList]
    Marker: Optional[String]


DBParameterGroupList = List[DBParameterGroup]


class DBParameterGroupNameMessage(TypedDict, total=False):
    DBParameterGroupName: Optional[String]


class DBParameterGroupsMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBParameterGroups: Optional[DBParameterGroupList]


DBSubnetGroups = List[DBSubnetGroup]


class DBSubnetGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBSubnetGroups: Optional[DBSubnetGroups]


class DeleteDBClusterEndpointMessage(ServiceRequest):
    DBClusterEndpointIdentifier: String


class DeleteDBClusterEndpointOutput(TypedDict, total=False):
    DBClusterEndpointIdentifier: Optional[String]
    DBClusterIdentifier: Optional[String]
    DBClusterEndpointResourceIdentifier: Optional[String]
    Endpoint: Optional[String]
    Status: Optional[String]
    EndpointType: Optional[String]
    CustomEndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    DBClusterEndpointArn: Optional[String]


class DeleteDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    SkipFinalSnapshot: Optional[Boolean]
    FinalDBSnapshotIdentifier: Optional[String]


class DeleteDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String


class DeleteDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class DeleteDBClusterSnapshotMessage(ServiceRequest):
    DBClusterSnapshotIdentifier: String


class DeleteDBClusterSnapshotResult(TypedDict, total=False):
    DBClusterSnapshot: Optional[DBClusterSnapshot]


class DeleteDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    SkipFinalSnapshot: Optional[Boolean]
    FinalDBSnapshotIdentifier: Optional[String]


class DeleteDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class DeleteDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String


class DeleteDBSubnetGroupMessage(ServiceRequest):
    DBSubnetGroupName: String


class DeleteEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String


class DeleteEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


FilterValueList = List[String]


class Filter(TypedDict, total=False):
    Name: String
    Values: FilterValueList


FilterList = List[Filter]


class DescribeDBClusterEndpointsMessage(ServiceRequest):
    DBClusterIdentifier: Optional[String]
    DBClusterEndpointIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBClusterParameterGroupsMessage(ServiceRequest):
    DBClusterParameterGroupName: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBClusterParametersMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    Source: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBClusterSnapshotAttributesMessage(ServiceRequest):
    DBClusterSnapshotIdentifier: String


class DescribeDBClusterSnapshotAttributesResult(TypedDict, total=False):
    DBClusterSnapshotAttributesResult: Optional[DBClusterSnapshotAttributesResult]


class DescribeDBClusterSnapshotsMessage(ServiceRequest):
    DBClusterIdentifier: Optional[String]
    DBClusterSnapshotIdentifier: Optional[String]
    SnapshotType: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    IncludeShared: Optional[Boolean]
    IncludePublic: Optional[Boolean]


class DescribeDBClustersMessage(ServiceRequest):
    DBClusterIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBEngineVersionsMessage(ServiceRequest):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBParameterGroupFamily: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    DefaultOnly: Optional[Boolean]
    ListSupportedCharacterSets: Optional[BooleanOptional]
    ListSupportedTimezones: Optional[BooleanOptional]


class DescribeDBInstancesMessage(ServiceRequest):
    DBInstanceIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBParameterGroupsMessage(ServiceRequest):
    DBParameterGroupName: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBParametersMessage(ServiceRequest):
    DBParameterGroupName: String
    Source: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBSubnetGroupsMessage(ServiceRequest):
    DBSubnetGroupName: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEngineDefaultClusterParametersMessage(ServiceRequest):
    DBParameterGroupFamily: String
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class EngineDefaults(TypedDict, total=False):
    DBParameterGroupFamily: Optional[String]
    Marker: Optional[String]
    Parameters: Optional[ParametersList]


class DescribeEngineDefaultClusterParametersResult(TypedDict, total=False):
    EngineDefaults: Optional[EngineDefaults]


class DescribeEngineDefaultParametersMessage(ServiceRequest):
    DBParameterGroupFamily: String
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEngineDefaultParametersResult(TypedDict, total=False):
    EngineDefaults: Optional[EngineDefaults]


class DescribeEventCategoriesMessage(ServiceRequest):
    SourceType: Optional[String]
    Filters: Optional[FilterList]


class DescribeEventSubscriptionsMessage(ServiceRequest):
    SubscriptionName: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEventsMessage(ServiceRequest):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Duration: Optional[IntegerOptional]
    EventCategories: Optional[EventCategoriesList]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeOrderableDBInstanceOptionsMessage(ServiceRequest):
    Engine: String
    EngineVersion: Optional[String]
    DBInstanceClass: Optional[String]
    LicenseModel: Optional[String]
    Vpc: Optional[BooleanOptional]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribePendingMaintenanceActionsMessage(ServiceRequest):
    ResourceIdentifier: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]


class DescribeValidDBInstanceModificationsMessage(ServiceRequest):
    DBInstanceIdentifier: String


class DoubleRange(TypedDict, total=False):
    From: Optional[Double]
    To: Optional[Double]


DoubleRangeList = List[DoubleRange]


class Range(TypedDict, total=False):
    From: Optional[Integer]
    To: Optional[Integer]
    Step: Optional[IntegerOptional]


RangeList = List[Range]


class ValidStorageOptions(TypedDict, total=False):
    StorageType: Optional[String]
    StorageSize: Optional[RangeList]
    ProvisionedIops: Optional[RangeList]
    IopsToStorageRatio: Optional[DoubleRangeList]


ValidStorageOptionsList = List[ValidStorageOptions]


class ValidDBInstanceModificationsMessage(TypedDict, total=False):
    Storage: Optional[ValidStorageOptionsList]


class DescribeValidDBInstanceModificationsResult(TypedDict, total=False):
    ValidDBInstanceModificationsMessage: Optional[ValidDBInstanceModificationsMessage]


class Event(TypedDict, total=False):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    Message: Optional[String]
    EventCategories: Optional[EventCategoriesList]
    Date: Optional[TStamp]
    SourceArn: Optional[String]


class EventCategoriesMap(TypedDict, total=False):
    SourceType: Optional[String]
    EventCategories: Optional[EventCategoriesList]


EventCategoriesMapList = List[EventCategoriesMap]


class EventCategoriesMessage(TypedDict, total=False):
    EventCategoriesMapList: Optional[EventCategoriesMapList]


EventList = List[Event]
EventSubscriptionsList = List[EventSubscription]


class EventSubscriptionsMessage(TypedDict, total=False):
    Marker: Optional[String]
    EventSubscriptionsList: Optional[EventSubscriptionsList]


class EventsMessage(TypedDict, total=False):
    Marker: Optional[String]
    Events: Optional[EventList]


class FailoverDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: Optional[String]
    TargetDBInstanceIdentifier: Optional[String]


class FailoverDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


KeyList = List[String]


class ListTagsForResourceMessage(ServiceRequest):
    ResourceName: String
    Filters: Optional[FilterList]


class ModifyDBClusterEndpointMessage(ServiceRequest):
    DBClusterEndpointIdentifier: String
    EndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]


class ModifyDBClusterEndpointOutput(TypedDict, total=False):
    DBClusterEndpointIdentifier: Optional[String]
    DBClusterIdentifier: Optional[String]
    DBClusterEndpointResourceIdentifier: Optional[String]
    Endpoint: Optional[String]
    Status: Optional[String]
    EndpointType: Optional[String]
    CustomEndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    DBClusterEndpointArn: Optional[String]


class ModifyDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    NewDBClusterIdentifier: Optional[String]
    ApplyImmediately: Optional[Boolean]
    BackupRetentionPeriod: Optional[IntegerOptional]
    DBClusterParameterGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Port: Optional[IntegerOptional]
    MasterUserPassword: Optional[String]
    OptionGroupName: Optional[String]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    CloudwatchLogsExportConfiguration: Optional[CloudwatchLogsExportConfiguration]
    EngineVersion: Optional[String]
    AllowMajorVersionUpgrade: Optional[Boolean]
    DBInstanceParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]


class ModifyDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    Parameters: ParametersList


class ModifyDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class ModifyDBClusterSnapshotAttributeMessage(ServiceRequest):
    DBClusterSnapshotIdentifier: String
    AttributeName: String
    ValuesToAdd: Optional[AttributeValueList]
    ValuesToRemove: Optional[AttributeValueList]


class ModifyDBClusterSnapshotAttributeResult(TypedDict, total=False):
    DBClusterSnapshotAttributesResult: Optional[DBClusterSnapshotAttributesResult]


class ModifyDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    AllocatedStorage: Optional[IntegerOptional]
    DBInstanceClass: Optional[String]
    DBSubnetGroupName: Optional[String]
    DBSecurityGroups: Optional[DBSecurityGroupNameList]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    ApplyImmediately: Optional[Boolean]
    MasterUserPassword: Optional[String]
    DBParameterGroupName: Optional[String]
    BackupRetentionPeriod: Optional[IntegerOptional]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    MultiAZ: Optional[BooleanOptional]
    EngineVersion: Optional[String]
    AllowMajorVersionUpgrade: Optional[Boolean]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    NewDBInstanceIdentifier: Optional[String]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    TdeCredentialPassword: Optional[String]
    CACertificateIdentifier: Optional[String]
    Domain: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    DBPortNumber: Optional[IntegerOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    MonitoringRoleArn: Optional[String]
    DomainIAMRoleName: Optional[String]
    PromotionTier: Optional[IntegerOptional]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    CloudwatchLogsExportConfiguration: Optional[CloudwatchLogsExportConfiguration]
    DeletionProtection: Optional[BooleanOptional]


class ModifyDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class ModifyDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    Parameters: ParametersList


class ModifyDBSubnetGroupMessage(ServiceRequest):
    DBSubnetGroupName: String
    DBSubnetGroupDescription: Optional[String]
    SubnetIds: SubnetIdentifierList


class ModifyDBSubnetGroupResult(TypedDict, total=False):
    DBSubnetGroup: Optional[DBSubnetGroup]


class ModifyEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: Optional[String]
    SourceType: Optional[String]
    EventCategories: Optional[EventCategoriesList]
    Enabled: Optional[BooleanOptional]


class ModifyEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class OrderableDBInstanceOption(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBInstanceClass: Optional[String]
    LicenseModel: Optional[String]
    AvailabilityZones: Optional[AvailabilityZoneList]
    MultiAZCapable: Optional[Boolean]
    ReadReplicaCapable: Optional[Boolean]
    Vpc: Optional[Boolean]
    SupportsStorageEncryption: Optional[Boolean]
    StorageType: Optional[String]
    SupportsIops: Optional[Boolean]
    SupportsEnhancedMonitoring: Optional[Boolean]
    SupportsIAMDatabaseAuthentication: Optional[Boolean]
    SupportsPerformanceInsights: Optional[Boolean]
    MinStorageSize: Optional[IntegerOptional]
    MaxStorageSize: Optional[IntegerOptional]
    MinIopsPerDbInstance: Optional[IntegerOptional]
    MaxIopsPerDbInstance: Optional[IntegerOptional]
    MinIopsPerGib: Optional[DoubleOptional]
    MaxIopsPerGib: Optional[DoubleOptional]


OrderableDBInstanceOptionsList = List[OrderableDBInstanceOption]


class OrderableDBInstanceOptionsMessage(TypedDict, total=False):
    OrderableDBInstanceOptions: Optional[OrderableDBInstanceOptionsList]
    Marker: Optional[String]


PendingMaintenanceActions = List[ResourcePendingMaintenanceActions]


class PendingMaintenanceActionsMessage(TypedDict, total=False):
    PendingMaintenanceActions: Optional[PendingMaintenanceActions]
    Marker: Optional[String]


class PromoteReadReplicaDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class PromoteReadReplicaDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class RebootDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    ForceFailover: Optional[BooleanOptional]


class RebootDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RemoveRoleFromDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    RoleArn: String
    FeatureName: Optional[String]


class RemoveSourceIdentifierFromSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SourceIdentifier: String


class RemoveSourceIdentifierFromSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class RemoveTagsFromResourceMessage(ServiceRequest):
    ResourceName: String
    TagKeys: KeyList


class ResetDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    Parameters: Optional[ParametersList]


class ResetDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    Parameters: Optional[ParametersList]


class RestoreDBClusterFromSnapshotMessage(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    DBClusterIdentifier: String
    SnapshotIdentifier: String
    Engine: String
    EngineVersion: Optional[String]
    Port: Optional[IntegerOptional]
    DBSubnetGroupName: Optional[String]
    DatabaseName: Optional[String]
    OptionGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DBClusterParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]


class RestoreDBClusterFromSnapshotResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class RestoreDBClusterToPointInTimeMessage(ServiceRequest):
    DBClusterIdentifier: String
    RestoreType: Optional[String]
    SourceDBClusterIdentifier: String
    RestoreToTime: Optional[TStamp]
    UseLatestRestorableTime: Optional[Boolean]
    Port: Optional[IntegerOptional]
    DBSubnetGroupName: Optional[String]
    OptionGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DBClusterParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]


class RestoreDBClusterToPointInTimeResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class StartDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class StartDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class StopDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class StopDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class TagListMessage(TypedDict, total=False):
    TagList: Optional[TagList]


class NeptuneApi:

    service = "neptune"
    version = "2014-10-31"

    @handler("AddRoleToDBCluster")
    def add_role_to_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        role_arn: String,
        feature_name: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("AddSourceIdentifierToSubscription")
    def add_source_identifier_to_subscription(
        self, context: RequestContext, subscription_name: String, source_identifier: String
    ) -> AddSourceIdentifierToSubscriptionResult:
        raise NotImplementedError

    @handler("AddTagsToResource")
    def add_tags_to_resource(
        self, context: RequestContext, resource_name: String, tags: TagList
    ) -> None:
        raise NotImplementedError

    @handler("ApplyPendingMaintenanceAction")
    def apply_pending_maintenance_action(
        self,
        context: RequestContext,
        resource_identifier: String,
        apply_action: String,
        opt_in_type: String,
    ) -> ApplyPendingMaintenanceActionResult:
        raise NotImplementedError

    @handler("CopyDBClusterParameterGroup")
    def copy_db_cluster_parameter_group(
        self,
        context: RequestContext,
        source_db_cluster_parameter_group_identifier: String,
        target_db_cluster_parameter_group_identifier: String,
        target_db_cluster_parameter_group_description: String,
        tags: TagList = None,
    ) -> CopyDBClusterParameterGroupResult:
        raise NotImplementedError

    @handler("CopyDBClusterSnapshot")
    def copy_db_cluster_snapshot(
        self,
        context: RequestContext,
        source_db_cluster_snapshot_identifier: String,
        target_db_cluster_snapshot_identifier: String,
        kms_key_id: String = None,
        pre_signed_url: String = None,
        copy_tags: BooleanOptional = None,
        tags: TagList = None,
        source_region: String = None,
    ) -> CopyDBClusterSnapshotResult:
        raise NotImplementedError

    @handler("CopyDBParameterGroup")
    def copy_db_parameter_group(
        self,
        context: RequestContext,
        source_db_parameter_group_identifier: String,
        target_db_parameter_group_identifier: String,
        target_db_parameter_group_description: String,
        tags: TagList = None,
    ) -> CopyDBParameterGroupResult:
        raise NotImplementedError

    @handler("CreateDBCluster")
    def create_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        engine: String,
        availability_zones: AvailabilityZones = None,
        backup_retention_period: IntegerOptional = None,
        character_set_name: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        database_name: String = None,
        db_cluster_parameter_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        db_subnet_group_name: String = None,
        engine_version: String = None,
        port: IntegerOptional = None,
        master_username: String = None,
        master_user_password: String = None,
        option_group_name: String = None,
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        replication_source_identifier: String = None,
        tags: TagList = None,
        storage_encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        pre_signed_url: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        deletion_protection: BooleanOptional = None,
        source_region: String = None,
    ) -> CreateDBClusterResult:
        raise NotImplementedError

    @handler("CreateDBClusterEndpoint")
    def create_db_cluster_endpoint(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        db_cluster_endpoint_identifier: String,
        endpoint_type: String,
        static_members: StringList = None,
        excluded_members: StringList = None,
        tags: TagList = None,
    ) -> CreateDBClusterEndpointOutput:
        raise NotImplementedError

    @handler("CreateDBClusterParameterGroup")
    def create_db_cluster_parameter_group(
        self,
        context: RequestContext,
        db_cluster_parameter_group_name: String,
        db_parameter_group_family: String,
        description: String,
        tags: TagList = None,
    ) -> CreateDBClusterParameterGroupResult:
        raise NotImplementedError

    @handler("CreateDBClusterSnapshot")
    def create_db_cluster_snapshot(
        self,
        context: RequestContext,
        db_cluster_snapshot_identifier: String,
        db_cluster_identifier: String,
        tags: TagList = None,
    ) -> CreateDBClusterSnapshotResult:
        raise NotImplementedError

    @handler("CreateDBInstance")
    def create_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        db_instance_class: String,
        engine: String,
        db_name: String = None,
        allocated_storage: IntegerOptional = None,
        master_username: String = None,
        master_user_password: String = None,
        db_security_groups: DBSecurityGroupNameList = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        availability_zone: String = None,
        db_subnet_group_name: String = None,
        preferred_maintenance_window: String = None,
        db_parameter_group_name: String = None,
        backup_retention_period: IntegerOptional = None,
        preferred_backup_window: String = None,
        port: IntegerOptional = None,
        multi_az: BooleanOptional = None,
        engine_version: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        license_model: String = None,
        iops: IntegerOptional = None,
        option_group_name: String = None,
        character_set_name: String = None,
        publicly_accessible: BooleanOptional = None,
        tags: TagList = None,
        db_cluster_identifier: String = None,
        storage_type: String = None,
        tde_credential_arn: String = None,
        tde_credential_password: String = None,
        storage_encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        domain: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        monitoring_role_arn: String = None,
        domain_iam_role_name: String = None,
        promotion_tier: IntegerOptional = None,
        timezone: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        deletion_protection: BooleanOptional = None,
    ) -> CreateDBInstanceResult:
        raise NotImplementedError

    @handler("CreateDBParameterGroup")
    def create_db_parameter_group(
        self,
        context: RequestContext,
        db_parameter_group_name: String,
        db_parameter_group_family: String,
        description: String,
        tags: TagList = None,
    ) -> CreateDBParameterGroupResult:
        raise NotImplementedError

    @handler("CreateDBSubnetGroup")
    def create_db_subnet_group(
        self,
        context: RequestContext,
        db_subnet_group_name: String,
        db_subnet_group_description: String,
        subnet_ids: SubnetIdentifierList,
        tags: TagList = None,
    ) -> CreateDBSubnetGroupResult:
        raise NotImplementedError

    @handler("CreateEventSubscription")
    def create_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String,
        source_type: String = None,
        event_categories: EventCategoriesList = None,
        source_ids: SourceIdsList = None,
        enabled: BooleanOptional = None,
        tags: TagList = None,
    ) -> CreateEventSubscriptionResult:
        raise NotImplementedError

    @handler("DeleteDBCluster")
    def delete_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        skip_final_snapshot: Boolean = None,
        final_db_snapshot_identifier: String = None,
    ) -> DeleteDBClusterResult:
        raise NotImplementedError

    @handler("DeleteDBClusterEndpoint")
    def delete_db_cluster_endpoint(
        self, context: RequestContext, db_cluster_endpoint_identifier: String
    ) -> DeleteDBClusterEndpointOutput:
        raise NotImplementedError

    @handler("DeleteDBClusterParameterGroup")
    def delete_db_cluster_parameter_group(
        self, context: RequestContext, db_cluster_parameter_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDBClusterSnapshot")
    def delete_db_cluster_snapshot(
        self, context: RequestContext, db_cluster_snapshot_identifier: String
    ) -> DeleteDBClusterSnapshotResult:
        raise NotImplementedError

    @handler("DeleteDBInstance")
    def delete_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        skip_final_snapshot: Boolean = None,
        final_db_snapshot_identifier: String = None,
    ) -> DeleteDBInstanceResult:
        raise NotImplementedError

    @handler("DeleteDBParameterGroup")
    def delete_db_parameter_group(
        self, context: RequestContext, db_parameter_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDBSubnetGroup")
    def delete_db_subnet_group(self, context: RequestContext, db_subnet_group_name: String) -> None:
        raise NotImplementedError

    @handler("DeleteEventSubscription")
    def delete_event_subscription(
        self, context: RequestContext, subscription_name: String
    ) -> DeleteEventSubscriptionResult:
        raise NotImplementedError

    @handler("DescribeDBClusterEndpoints")
    def describe_db_cluster_endpoints(
        self,
        context: RequestContext,
        db_cluster_identifier: String = None,
        db_cluster_endpoint_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBClusterEndpointMessage:
        raise NotImplementedError

    @handler("DescribeDBClusterParameterGroups")
    def describe_db_cluster_parameter_groups(
        self,
        context: RequestContext,
        db_cluster_parameter_group_name: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBClusterParameterGroupsMessage:
        raise NotImplementedError

    @handler("DescribeDBClusterParameters")
    def describe_db_cluster_parameters(
        self,
        context: RequestContext,
        db_cluster_parameter_group_name: String,
        source: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBClusterParameterGroupDetails:
        raise NotImplementedError

    @handler("DescribeDBClusterSnapshotAttributes")
    def describe_db_cluster_snapshot_attributes(
        self, context: RequestContext, db_cluster_snapshot_identifier: String
    ) -> DescribeDBClusterSnapshotAttributesResult:
        raise NotImplementedError

    @handler("DescribeDBClusterSnapshots")
    def describe_db_cluster_snapshots(
        self,
        context: RequestContext,
        db_cluster_identifier: String = None,
        db_cluster_snapshot_identifier: String = None,
        snapshot_type: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        include_shared: Boolean = None,
        include_public: Boolean = None,
    ) -> DBClusterSnapshotMessage:
        raise NotImplementedError

    @handler("DescribeDBClusters")
    def describe_db_clusters(
        self,
        context: RequestContext,
        db_cluster_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBClusterMessage:
        raise NotImplementedError

    @handler("DescribeDBEngineVersions")
    def describe_db_engine_versions(
        self,
        context: RequestContext,
        engine: String = None,
        engine_version: String = None,
        db_parameter_group_family: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        default_only: Boolean = None,
        list_supported_character_sets: BooleanOptional = None,
        list_supported_timezones: BooleanOptional = None,
    ) -> DBEngineVersionMessage:
        raise NotImplementedError

    @handler("DescribeDBInstances")
    def describe_db_instances(
        self,
        context: RequestContext,
        db_instance_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBInstanceMessage:
        raise NotImplementedError

    @handler("DescribeDBParameterGroups")
    def describe_db_parameter_groups(
        self,
        context: RequestContext,
        db_parameter_group_name: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBParameterGroupsMessage:
        raise NotImplementedError

    @handler("DescribeDBParameters")
    def describe_db_parameters(
        self,
        context: RequestContext,
        db_parameter_group_name: String,
        source: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBParameterGroupDetails:
        raise NotImplementedError

    @handler("DescribeDBSubnetGroups")
    def describe_db_subnet_groups(
        self,
        context: RequestContext,
        db_subnet_group_name: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBSubnetGroupMessage:
        raise NotImplementedError

    @handler("DescribeEngineDefaultClusterParameters")
    def describe_engine_default_cluster_parameters(
        self,
        context: RequestContext,
        db_parameter_group_family: String,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeEngineDefaultClusterParametersResult:
        raise NotImplementedError

    @handler("DescribeEngineDefaultParameters")
    def describe_engine_default_parameters(
        self,
        context: RequestContext,
        db_parameter_group_family: String,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeEngineDefaultParametersResult:
        raise NotImplementedError

    @handler("DescribeEventCategories")
    def describe_event_categories(
        self, context: RequestContext, source_type: String = None, filters: FilterList = None
    ) -> EventCategoriesMessage:
        raise NotImplementedError

    @handler("DescribeEventSubscriptions")
    def describe_event_subscriptions(
        self,
        context: RequestContext,
        subscription_name: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EventSubscriptionsMessage:
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
        event_categories: EventCategoriesList = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EventsMessage:
        raise NotImplementedError

    @handler("DescribeOrderableDBInstanceOptions")
    def describe_orderable_db_instance_options(
        self,
        context: RequestContext,
        engine: String,
        engine_version: String = None,
        db_instance_class: String = None,
        license_model: String = None,
        vpc: BooleanOptional = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> OrderableDBInstanceOptionsMessage:
        raise NotImplementedError

    @handler("DescribePendingMaintenanceActions")
    def describe_pending_maintenance_actions(
        self,
        context: RequestContext,
        resource_identifier: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: IntegerOptional = None,
    ) -> PendingMaintenanceActionsMessage:
        raise NotImplementedError

    @handler("DescribeValidDBInstanceModifications")
    def describe_valid_db_instance_modifications(
        self, context: RequestContext, db_instance_identifier: String
    ) -> DescribeValidDBInstanceModificationsResult:
        raise NotImplementedError

    @handler("FailoverDBCluster")
    def failover_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String = None,
        target_db_instance_identifier: String = None,
    ) -> FailoverDBClusterResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_name: String, filters: FilterList = None
    ) -> TagListMessage:
        raise NotImplementedError

    @handler("ModifyDBCluster")
    def modify_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        new_db_cluster_identifier: String = None,
        apply_immediately: Boolean = None,
        backup_retention_period: IntegerOptional = None,
        db_cluster_parameter_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        port: IntegerOptional = None,
        master_user_password: String = None,
        option_group_name: String = None,
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        cloudwatch_logs_export_configuration: CloudwatchLogsExportConfiguration = None,
        engine_version: String = None,
        allow_major_version_upgrade: Boolean = None,
        db_instance_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
    ) -> ModifyDBClusterResult:
        raise NotImplementedError

    @handler("ModifyDBClusterEndpoint")
    def modify_db_cluster_endpoint(
        self,
        context: RequestContext,
        db_cluster_endpoint_identifier: String,
        endpoint_type: String = None,
        static_members: StringList = None,
        excluded_members: StringList = None,
    ) -> ModifyDBClusterEndpointOutput:
        raise NotImplementedError

    @handler("ModifyDBClusterParameterGroup")
    def modify_db_cluster_parameter_group(
        self,
        context: RequestContext,
        db_cluster_parameter_group_name: String,
        parameters: ParametersList,
    ) -> DBClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyDBClusterSnapshotAttribute")
    def modify_db_cluster_snapshot_attribute(
        self,
        context: RequestContext,
        db_cluster_snapshot_identifier: String,
        attribute_name: String,
        values_to_add: AttributeValueList = None,
        values_to_remove: AttributeValueList = None,
    ) -> ModifyDBClusterSnapshotAttributeResult:
        raise NotImplementedError

    @handler("ModifyDBInstance")
    def modify_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        allocated_storage: IntegerOptional = None,
        db_instance_class: String = None,
        db_subnet_group_name: String = None,
        db_security_groups: DBSecurityGroupNameList = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        apply_immediately: Boolean = None,
        master_user_password: String = None,
        db_parameter_group_name: String = None,
        backup_retention_period: IntegerOptional = None,
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        multi_az: BooleanOptional = None,
        engine_version: String = None,
        allow_major_version_upgrade: Boolean = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        license_model: String = None,
        iops: IntegerOptional = None,
        option_group_name: String = None,
        new_db_instance_identifier: String = None,
        storage_type: String = None,
        tde_credential_arn: String = None,
        tde_credential_password: String = None,
        ca_certificate_identifier: String = None,
        domain: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        db_port_number: IntegerOptional = None,
        publicly_accessible: BooleanOptional = None,
        monitoring_role_arn: String = None,
        domain_iam_role_name: String = None,
        promotion_tier: IntegerOptional = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        cloudwatch_logs_export_configuration: CloudwatchLogsExportConfiguration = None,
        deletion_protection: BooleanOptional = None,
    ) -> ModifyDBInstanceResult:
        raise NotImplementedError

    @handler("ModifyDBParameterGroup")
    def modify_db_parameter_group(
        self, context: RequestContext, db_parameter_group_name: String, parameters: ParametersList
    ) -> DBParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyDBSubnetGroup")
    def modify_db_subnet_group(
        self,
        context: RequestContext,
        db_subnet_group_name: String,
        subnet_ids: SubnetIdentifierList,
        db_subnet_group_description: String = None,
    ) -> ModifyDBSubnetGroupResult:
        raise NotImplementedError

    @handler("ModifyEventSubscription")
    def modify_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String = None,
        source_type: String = None,
        event_categories: EventCategoriesList = None,
        enabled: BooleanOptional = None,
    ) -> ModifyEventSubscriptionResult:
        raise NotImplementedError

    @handler("PromoteReadReplicaDBCluster")
    def promote_read_replica_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> PromoteReadReplicaDBClusterResult:
        raise NotImplementedError

    @handler("RebootDBInstance")
    def reboot_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        force_failover: BooleanOptional = None,
    ) -> RebootDBInstanceResult:
        raise NotImplementedError

    @handler("RemoveRoleFromDBCluster")
    def remove_role_from_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        role_arn: String,
        feature_name: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveSourceIdentifierFromSubscription")
    def remove_source_identifier_from_subscription(
        self, context: RequestContext, subscription_name: String, source_identifier: String
    ) -> RemoveSourceIdentifierFromSubscriptionResult:
        raise NotImplementedError

    @handler("RemoveTagsFromResource")
    def remove_tags_from_resource(
        self, context: RequestContext, resource_name: String, tag_keys: KeyList
    ) -> None:
        raise NotImplementedError

    @handler("ResetDBClusterParameterGroup")
    def reset_db_cluster_parameter_group(
        self,
        context: RequestContext,
        db_cluster_parameter_group_name: String,
        reset_all_parameters: Boolean = None,
        parameters: ParametersList = None,
    ) -> DBClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ResetDBParameterGroup")
    def reset_db_parameter_group(
        self,
        context: RequestContext,
        db_parameter_group_name: String,
        reset_all_parameters: Boolean = None,
        parameters: ParametersList = None,
    ) -> DBParameterGroupNameMessage:
        raise NotImplementedError

    @handler("RestoreDBClusterFromSnapshot")
    def restore_db_cluster_from_snapshot(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        snapshot_identifier: String,
        engine: String,
        availability_zones: AvailabilityZones = None,
        engine_version: String = None,
        port: IntegerOptional = None,
        db_subnet_group_name: String = None,
        database_name: String = None,
        option_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        tags: TagList = None,
        kms_key_id: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        db_cluster_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
    ) -> RestoreDBClusterFromSnapshotResult:
        raise NotImplementedError

    @handler("RestoreDBClusterToPointInTime")
    def restore_db_cluster_to_point_in_time(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        source_db_cluster_identifier: String,
        restore_type: String = None,
        restore_to_time: TStamp = None,
        use_latest_restorable_time: Boolean = None,
        port: IntegerOptional = None,
        db_subnet_group_name: String = None,
        option_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        tags: TagList = None,
        kms_key_id: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        db_cluster_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
    ) -> RestoreDBClusterToPointInTimeResult:
        raise NotImplementedError

    @handler("StartDBCluster")
    def start_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> StartDBClusterResult:
        raise NotImplementedError

    @handler("StopDBCluster")
    def stop_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> StopDBClusterResult:
        raise NotImplementedError
