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
GlobalClusterIdentifier = str
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


class DBClusterNotFoundFault(ServiceException):
    pass


class DBClusterParameterGroupNotFoundFault(ServiceException):
    pass


class DBClusterQuotaExceededFault(ServiceException):
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


class EventSubscriptionQuotaExceededFault(ServiceException):
    pass


class GlobalClusterAlreadyExistsFault(ServiceException):
    pass


class GlobalClusterNotFoundFault(ServiceException):
    pass


class GlobalClusterQuotaExceededFault(ServiceException):
    pass


class InstanceQuotaExceededFault(ServiceException):
    pass


class InsufficientDBClusterCapacityFault(ServiceException):
    pass


class InsufficientDBInstanceCapacityFault(ServiceException):
    pass


class InsufficientStorageClusterCapacityFault(ServiceException):
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


class InvalidGlobalClusterStateFault(ServiceException):
    pass


class InvalidRestoreFault(ServiceException):
    pass


class InvalidSubnet(ServiceException):
    pass


class InvalidVPCNetworkStateFault(ServiceException):
    pass


class KMSKeyNotAccessibleFault(ServiceException):
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


class Certificate(TypedDict, total=False):
    CertificateIdentifier: Optional[String]
    CertificateType: Optional[String]
    Thumbprint: Optional[String]
    ValidFrom: Optional[TStamp]
    ValidTill: Optional[TStamp]
    CertificateArn: Optional[String]


CertificateList = List[Certificate]


class CertificateMessage(TypedDict, total=False):
    Certificates: Optional[CertificateList]
    Marker: Optional[String]


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
    Status: Optional[String]
    Port: Optional[Integer]
    VpcId: Optional[String]
    ClusterCreateTime: Optional[TStamp]
    MasterUsername: Optional[String]
    EngineVersion: Optional[String]
    SnapshotType: Optional[String]
    PercentProgress: Optional[Integer]
    StorageEncrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DBClusterSnapshotArn: Optional[String]
    SourceDBClusterSnapshotArn: Optional[String]


class CopyDBClusterSnapshotResult(TypedDict, total=False):
    DBClusterSnapshot: Optional[DBClusterSnapshot]


VpcSecurityGroupIdList = List[String]


class CreateDBClusterMessage(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
    DBClusterIdentifier: String
    DBClusterParameterGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    DBSubnetGroupName: Optional[String]
    Engine: String
    EngineVersion: Optional[String]
    Port: Optional[IntegerOptional]
    MasterUsername: Optional[String]
    MasterUserPassword: Optional[String]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    Tags: Optional[TagList]
    StorageEncrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    PreSignedUrl: Optional[String]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]
    GlobalClusterIdentifier: Optional[GlobalClusterIdentifier]
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


class DBCluster(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
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
    ClusterCreateTime: Optional[TStamp]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[Boolean]


class CreateDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class CreateDBClusterSnapshotMessage(ServiceRequest):
    DBClusterSnapshotIdentifier: String
    DBClusterIdentifier: String
    Tags: Optional[TagList]


class CreateDBClusterSnapshotResult(TypedDict, total=False):
    DBClusterSnapshot: Optional[DBClusterSnapshot]


class CreateDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    DBInstanceClass: String
    Engine: String
    AvailabilityZone: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    Tags: Optional[TagList]
    DBClusterIdentifier: String
    PromotionTier: Optional[IntegerOptional]


class DBInstanceStatusInfo(TypedDict, total=False):
    StatusType: Optional[String]
    Normal: Optional[Boolean]
    Status: Optional[String]
    Message: Optional[String]


DBInstanceStatusInfoList = List[DBInstanceStatusInfo]


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


class Endpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[Integer]
    HostedZoneId: Optional[String]


class DBInstance(TypedDict, total=False):
    DBInstanceIdentifier: Optional[String]
    DBInstanceClass: Optional[String]
    Engine: Optional[String]
    DBInstanceStatus: Optional[String]
    Endpoint: Optional[Endpoint]
    InstanceCreateTime: Optional[TStamp]
    PreferredBackupWindow: Optional[String]
    BackupRetentionPeriod: Optional[Integer]
    VpcSecurityGroups: Optional[VpcSecurityGroupMembershipList]
    AvailabilityZone: Optional[String]
    DBSubnetGroup: Optional[DBSubnetGroup]
    PreferredMaintenanceWindow: Optional[String]
    PendingModifiedValues: Optional[PendingModifiedValues]
    LatestRestorableTime: Optional[TStamp]
    EngineVersion: Optional[String]
    AutoMinorVersionUpgrade: Optional[Boolean]
    PubliclyAccessible: Optional[Boolean]
    StatusInfos: Optional[DBInstanceStatusInfoList]
    DBClusterIdentifier: Optional[String]
    StorageEncrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DbiResourceId: Optional[String]
    CACertificateIdentifier: Optional[String]
    PromotionTier: Optional[IntegerOptional]
    DBInstanceArn: Optional[String]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]


class CreateDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


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


class CreateGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: GlobalClusterIdentifier
    SourceDBClusterIdentifier: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    DatabaseName: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]


ReadersArnList = List[String]


class GlobalClusterMember(TypedDict, total=False):
    DBClusterArn: Optional[String]
    Readers: Optional[ReadersArnList]
    IsWriter: Optional[Boolean]


GlobalClusterMemberList = List[GlobalClusterMember]


class GlobalCluster(TypedDict, total=False):
    GlobalClusterIdentifier: Optional[GlobalClusterIdentifier]
    GlobalClusterResourceId: Optional[String]
    GlobalClusterArn: Optional[String]
    Status: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DatabaseName: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]
    DeletionProtection: Optional[BooleanOptional]
    GlobalClusterMembers: Optional[GlobalClusterMemberList]


class CreateGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


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


class UpgradeTarget(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    Description: Optional[String]
    AutoUpgrade: Optional[Boolean]
    IsMajorVersionUpgrade: Optional[Boolean]


ValidUpgradeTargetList = List[UpgradeTarget]


class DBEngineVersion(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBParameterGroupFamily: Optional[String]
    DBEngineDescription: Optional[String]
    DBEngineVersionDescription: Optional[String]
    ValidUpgradeTarget: Optional[ValidUpgradeTargetList]
    ExportableLogTypes: Optional[LogTypeList]
    SupportsLogExportsToCloudwatchLogs: Optional[Boolean]


DBEngineVersionList = List[DBEngineVersion]


class DBEngineVersionMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBEngineVersions: Optional[DBEngineVersionList]


DBInstanceList = List[DBInstance]


class DBInstanceMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBInstances: Optional[DBInstanceList]


DBSubnetGroups = List[DBSubnetGroup]


class DBSubnetGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBSubnetGroups: Optional[DBSubnetGroups]


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


class DeleteDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class DeleteDBSubnetGroupMessage(ServiceRequest):
    DBSubnetGroupName: String


class DeleteEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String


class DeleteEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class DeleteGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: GlobalClusterIdentifier


class DeleteGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


FilterValueList = List[String]


class Filter(TypedDict, total=False):
    Name: String
    Values: FilterValueList


FilterList = List[Filter]


class DescribeCertificatesMessage(ServiceRequest):
    CertificateIdentifier: Optional[String]
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


class DescribeGlobalClustersMessage(ServiceRequest):
    GlobalClusterIdentifier: Optional[GlobalClusterIdentifier]
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


GlobalClusterList = List[GlobalCluster]


class GlobalClustersMessage(TypedDict, total=False):
    Marker: Optional[String]
    GlobalClusters: Optional[GlobalClusterList]


KeyList = List[String]


class ListTagsForResourceMessage(ServiceRequest):
    ResourceName: String
    Filters: Optional[FilterList]


class ModifyDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    NewDBClusterIdentifier: Optional[String]
    ApplyImmediately: Optional[Boolean]
    BackupRetentionPeriod: Optional[IntegerOptional]
    DBClusterParameterGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Port: Optional[IntegerOptional]
    MasterUserPassword: Optional[String]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    CloudwatchLogsExportConfiguration: Optional[CloudwatchLogsExportConfiguration]
    EngineVersion: Optional[String]
    DeletionProtection: Optional[BooleanOptional]


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
    DBInstanceClass: Optional[String]
    ApplyImmediately: Optional[Boolean]
    PreferredMaintenanceWindow: Optional[String]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    NewDBInstanceIdentifier: Optional[String]
    CACertificateIdentifier: Optional[String]
    PromotionTier: Optional[IntegerOptional]


class ModifyDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


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


class ModifyGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: GlobalClusterIdentifier
    NewGlobalClusterIdentifier: Optional[GlobalClusterIdentifier]
    DeletionProtection: Optional[BooleanOptional]


class ModifyGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


class OrderableDBInstanceOption(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBInstanceClass: Optional[String]
    LicenseModel: Optional[String]
    AvailabilityZones: Optional[AvailabilityZoneList]
    Vpc: Optional[Boolean]


OrderableDBInstanceOptionsList = List[OrderableDBInstanceOption]


class OrderableDBInstanceOptionsMessage(TypedDict, total=False):
    OrderableDBInstanceOptions: Optional[OrderableDBInstanceOptionsList]
    Marker: Optional[String]


PendingMaintenanceActions = List[ResourcePendingMaintenanceActions]


class PendingMaintenanceActionsMessage(TypedDict, total=False):
    PendingMaintenanceActions: Optional[PendingMaintenanceActions]
    Marker: Optional[String]


class RebootDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    ForceFailover: Optional[BooleanOptional]


class RebootDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RemoveFromGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: GlobalClusterIdentifier
    DbClusterIdentifier: String


class RemoveFromGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


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


class RestoreDBClusterFromSnapshotMessage(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    DBClusterIdentifier: String
    SnapshotIdentifier: String
    Engine: String
    EngineVersion: Optional[String]
    Port: Optional[IntegerOptional]
    DBSubnetGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]


class RestoreDBClusterFromSnapshotResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class RestoreDBClusterToPointInTimeMessage(ServiceRequest):
    DBClusterIdentifier: String
    SourceDBClusterIdentifier: String
    RestoreToTime: Optional[TStamp]
    UseLatestRestorableTime: Optional[Boolean]
    Port: Optional[IntegerOptional]
    DBSubnetGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
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


class DocdbApi:

    service = "docdb"
    version = "2014-10-31"

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

    @handler("CreateDBCluster")
    def create_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        engine: String,
        availability_zones: AvailabilityZones = None,
        backup_retention_period: IntegerOptional = None,
        db_cluster_parameter_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        db_subnet_group_name: String = None,
        engine_version: String = None,
        port: IntegerOptional = None,
        master_username: String = None,
        master_user_password: String = None,
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        tags: TagList = None,
        storage_encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        pre_signed_url: String = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        deletion_protection: BooleanOptional = None,
        global_cluster_identifier: GlobalClusterIdentifier = None,
        source_region: String = None,
    ) -> CreateDBClusterResult:
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
        db_cluster_identifier: String,
        availability_zone: String = None,
        preferred_maintenance_window: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        tags: TagList = None,
        promotion_tier: IntegerOptional = None,
    ) -> CreateDBInstanceResult:
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

    @handler("CreateGlobalCluster")
    def create_global_cluster(
        self,
        context: RequestContext,
        global_cluster_identifier: GlobalClusterIdentifier,
        source_db_cluster_identifier: String = None,
        engine: String = None,
        engine_version: String = None,
        deletion_protection: BooleanOptional = None,
        database_name: String = None,
        storage_encrypted: BooleanOptional = None,
    ) -> CreateGlobalClusterResult:
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
        self, context: RequestContext, db_instance_identifier: String
    ) -> DeleteDBInstanceResult:
        raise NotImplementedError

    @handler("DeleteDBSubnetGroup")
    def delete_db_subnet_group(self, context: RequestContext, db_subnet_group_name: String) -> None:
        raise NotImplementedError

    @handler("DeleteEventSubscription")
    def delete_event_subscription(
        self, context: RequestContext, subscription_name: String
    ) -> DeleteEventSubscriptionResult:
        raise NotImplementedError

    @handler("DeleteGlobalCluster")
    def delete_global_cluster(
        self, context: RequestContext, global_cluster_identifier: GlobalClusterIdentifier
    ) -> DeleteGlobalClusterResult:
        raise NotImplementedError

    @handler("DescribeCertificates")
    def describe_certificates(
        self,
        context: RequestContext,
        certificate_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CertificateMessage:
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

    @handler("DescribeGlobalClusters")
    def describe_global_clusters(
        self,
        context: RequestContext,
        global_cluster_identifier: GlobalClusterIdentifier = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> GlobalClustersMessage:
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
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        cloudwatch_logs_export_configuration: CloudwatchLogsExportConfiguration = None,
        engine_version: String = None,
        deletion_protection: BooleanOptional = None,
    ) -> ModifyDBClusterResult:
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
        db_instance_class: String = None,
        apply_immediately: Boolean = None,
        preferred_maintenance_window: String = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        new_db_instance_identifier: String = None,
        ca_certificate_identifier: String = None,
        promotion_tier: IntegerOptional = None,
    ) -> ModifyDBInstanceResult:
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

    @handler("ModifyGlobalCluster")
    def modify_global_cluster(
        self,
        context: RequestContext,
        global_cluster_identifier: GlobalClusterIdentifier,
        new_global_cluster_identifier: GlobalClusterIdentifier = None,
        deletion_protection: BooleanOptional = None,
    ) -> ModifyGlobalClusterResult:
        raise NotImplementedError

    @handler("RebootDBInstance")
    def reboot_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        force_failover: BooleanOptional = None,
    ) -> RebootDBInstanceResult:
        raise NotImplementedError

    @handler("RemoveFromGlobalCluster")
    def remove_from_global_cluster(
        self,
        context: RequestContext,
        global_cluster_identifier: GlobalClusterIdentifier,
        db_cluster_identifier: String,
    ) -> RemoveFromGlobalClusterResult:
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
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        tags: TagList = None,
        kms_key_id: String = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        deletion_protection: BooleanOptional = None,
    ) -> RestoreDBClusterFromSnapshotResult:
        raise NotImplementedError

    @handler("RestoreDBClusterToPointInTime")
    def restore_db_cluster_to_point_in_time(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        source_db_cluster_identifier: String,
        restore_to_time: TStamp = None,
        use_latest_restorable_time: Boolean = None,
        port: IntegerOptional = None,
        db_subnet_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        tags: TagList = None,
        kms_key_id: String = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
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
