import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AwsBackupRecoveryPointArn = str
Boolean = bool
BooleanOptional = bool
BucketName = str
CustomDBEngineVersionManifest = str
CustomEngineName = str
CustomEngineVersion = str
DBClusterIdentifier = str
DBProxyEndpointName = str
DBProxyName = str
Description = str
Double = float
DoubleOptional = float
GlobalClusterIdentifier = str
Integer = int
IntegerOptional = int
KmsKeyIdOrArn = str
MaxRecords = int
String = str
String255 = str
StringSensitive = str


class ActivityStreamMode(str):
    sync = "sync"
    async_ = "async"


class ActivityStreamStatus(str):
    stopped = "stopped"
    starting = "starting"
    started = "started"
    stopping = "stopping"


class ApplyMethod(str):
    immediate = "immediate"
    pending_reboot = "pending-reboot"


class AuthScheme(str):
    SECRETS = "SECRETS"


class AutomationMode(str):
    full = "full"
    all_paused = "all-paused"


class CustomEngineVersionStatus(str):
    available = "available"
    inactive = "inactive"
    inactive_except_restore = "inactive-except-restore"


class DBProxyEndpointStatus(str):
    available = "available"
    modifying = "modifying"
    incompatible_network = "incompatible-network"
    insufficient_resource_limits = "insufficient-resource-limits"
    creating = "creating"
    deleting = "deleting"


class DBProxyEndpointTargetRole(str):
    READ_WRITE = "READ_WRITE"
    READ_ONLY = "READ_ONLY"


class DBProxyStatus(str):
    available = "available"
    modifying = "modifying"
    incompatible_network = "incompatible-network"
    insufficient_resource_limits = "insufficient-resource-limits"
    creating = "creating"
    deleting = "deleting"
    suspended = "suspended"
    suspending = "suspending"
    reactivating = "reactivating"


class EngineFamily(str):
    MYSQL = "MYSQL"
    POSTGRESQL = "POSTGRESQL"


class FailoverStatus(str):
    pending = "pending"
    failing_over = "failing-over"
    cancelling = "cancelling"


class IAMAuthMode(str):
    DISABLED = "DISABLED"
    REQUIRED = "REQUIRED"


class ReplicaMode(str):
    open_read_only = "open-read-only"
    mounted = "mounted"


class SourceType(str):
    db_instance = "db-instance"
    db_parameter_group = "db-parameter-group"
    db_security_group = "db-security-group"
    db_snapshot = "db-snapshot"
    db_cluster = "db-cluster"
    db_cluster_snapshot = "db-cluster-snapshot"
    custom_engine_version = "custom-engine-version"
    db_proxy = "db-proxy"


class TargetHealthReason(str):
    UNREACHABLE = "UNREACHABLE"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    AUTH_FAILURE = "AUTH_FAILURE"
    PENDING_PROXY_CAPACITY = "PENDING_PROXY_CAPACITY"
    INVALID_REPLICATION_STATE = "INVALID_REPLICATION_STATE"


class TargetRole(str):
    READ_WRITE = "READ_WRITE"
    READ_ONLY = "READ_ONLY"
    UNKNOWN = "UNKNOWN"


class TargetState(str):
    REGISTERING = "REGISTERING"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class TargetType(str):
    RDS_INSTANCE = "RDS_INSTANCE"
    RDS_SERVERLESS_ENDPOINT = "RDS_SERVERLESS_ENDPOINT"
    TRACKED_CLUSTER = "TRACKED_CLUSTER"


class WriteForwardingStatus(str):
    enabled = "enabled"
    disabled = "disabled"
    enabling = "enabling"
    disabling = "disabling"
    unknown = "unknown"


class AuthorizationAlreadyExistsFault(ServiceException):
    pass


class AuthorizationNotFoundFault(ServiceException):
    pass


class AuthorizationQuotaExceededFault(ServiceException):
    pass


class BackupPolicyNotFoundFault(ServiceException):
    pass


class CertificateNotFoundFault(ServiceException):
    pass


class CustomAvailabilityZoneAlreadyExistsFault(ServiceException):
    pass


class CustomAvailabilityZoneNotFoundFault(ServiceException):
    pass


class CustomAvailabilityZoneQuotaExceededFault(ServiceException):
    pass


class CustomDBEngineVersionAlreadyExistsFault(ServiceException):
    pass


class CustomDBEngineVersionNotFoundFault(ServiceException):
    pass


class CustomDBEngineVersionQuotaExceededFault(ServiceException):
    pass


class DBClusterAlreadyExistsFault(ServiceException):
    pass


class DBClusterBacktrackNotFoundFault(ServiceException):
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


class DBInstanceAutomatedBackupNotFoundFault(ServiceException):
    pass


class DBInstanceAutomatedBackupQuotaExceededFault(ServiceException):
    pass


class DBInstanceNotFoundFault(ServiceException):
    pass


class DBInstanceRoleAlreadyExistsFault(ServiceException):
    pass


class DBInstanceRoleNotFoundFault(ServiceException):
    pass


class DBInstanceRoleQuotaExceededFault(ServiceException):
    pass


class DBLogFileNotFoundFault(ServiceException):
    pass


class DBParameterGroupAlreadyExistsFault(ServiceException):
    pass


class DBParameterGroupNotFoundFault(ServiceException):
    pass


class DBParameterGroupQuotaExceededFault(ServiceException):
    pass


class DBProxyAlreadyExistsFault(ServiceException):
    pass


class DBProxyEndpointAlreadyExistsFault(ServiceException):
    pass


class DBProxyEndpointNotFoundFault(ServiceException):
    pass


class DBProxyEndpointQuotaExceededFault(ServiceException):
    pass


class DBProxyNotFoundFault(ServiceException):
    pass


class DBProxyQuotaExceededFault(ServiceException):
    pass


class DBProxyTargetAlreadyRegisteredFault(ServiceException):
    pass


class DBProxyTargetGroupNotFoundFault(ServiceException):
    pass


class DBProxyTargetNotFoundFault(ServiceException):
    pass


class DBSecurityGroupAlreadyExistsFault(ServiceException):
    pass


class DBSecurityGroupNotFoundFault(ServiceException):
    pass


class DBSecurityGroupNotSupportedFault(ServiceException):
    pass


class DBSecurityGroupQuotaExceededFault(ServiceException):
    pass


class DBSnapshotAlreadyExistsFault(ServiceException):
    pass


class DBSnapshotNotFoundFault(ServiceException):
    pass


class DBSubnetGroupAlreadyExistsFault(ServiceException):
    pass


class DBSubnetGroupDoesNotCoverEnoughAZs(ServiceException):
    pass


class DBSubnetGroupNotAllowedFault(ServiceException):
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


class ExportTaskAlreadyExistsFault(ServiceException):
    pass


class ExportTaskNotFoundFault(ServiceException):
    pass


class GlobalClusterAlreadyExistsFault(ServiceException):
    pass


class GlobalClusterNotFoundFault(ServiceException):
    pass


class GlobalClusterQuotaExceededFault(ServiceException):
    pass


class IamRoleMissingPermissionsFault(ServiceException):
    pass


class IamRoleNotFoundFault(ServiceException):
    pass


class InstallationMediaAlreadyExistsFault(ServiceException):
    pass


class InstallationMediaNotFoundFault(ServiceException):
    pass


class InstanceQuotaExceededFault(ServiceException):
    pass


class InsufficientAvailableIPsInSubnetFault(ServiceException):
    pass


class InsufficientDBClusterCapacityFault(ServiceException):
    pass


class InsufficientDBInstanceCapacityFault(ServiceException):
    pass


class InsufficientStorageClusterCapacityFault(ServiceException):
    pass


class InvalidCustomDBEngineVersionStateFault(ServiceException):
    pass


class InvalidDBClusterCapacityFault(ServiceException):
    pass


class InvalidDBClusterEndpointStateFault(ServiceException):
    pass


class InvalidDBClusterSnapshotStateFault(ServiceException):
    pass


class InvalidDBClusterStateFault(ServiceException):
    pass


class InvalidDBInstanceAutomatedBackupStateFault(ServiceException):
    pass


class InvalidDBInstanceStateFault(ServiceException):
    pass


class InvalidDBParameterGroupStateFault(ServiceException):
    pass


class InvalidDBProxyEndpointStateFault(ServiceException):
    pass


class InvalidDBProxyStateFault(ServiceException):
    pass


class InvalidDBSecurityGroupStateFault(ServiceException):
    pass


class InvalidDBSnapshotStateFault(ServiceException):
    pass


class InvalidDBSubnetGroupFault(ServiceException):
    pass


class InvalidDBSubnetGroupStateFault(ServiceException):
    pass


class InvalidDBSubnetStateFault(ServiceException):
    pass


class InvalidEventSubscriptionStateFault(ServiceException):
    pass


class InvalidExportOnlyFault(ServiceException):
    pass


class InvalidExportSourceStateFault(ServiceException):
    pass


class InvalidExportTaskStateFault(ServiceException):
    pass


class InvalidGlobalClusterStateFault(ServiceException):
    pass


class InvalidOptionGroupStateFault(ServiceException):
    pass


class InvalidRestoreFault(ServiceException):
    pass


class InvalidS3BucketFault(ServiceException):
    pass


class InvalidSubnet(ServiceException):
    pass


class InvalidVPCNetworkStateFault(ServiceException):
    pass


class KMSKeyNotAccessibleFault(ServiceException):
    pass


class OptionGroupAlreadyExistsFault(ServiceException):
    pass


class OptionGroupNotFoundFault(ServiceException):
    pass


class OptionGroupQuotaExceededFault(ServiceException):
    pass


class PointInTimeRestoreNotEnabledFault(ServiceException):
    pass


class ProvisionedIopsNotAvailableInAZFault(ServiceException):
    pass


class ReservedDBInstanceAlreadyExistsFault(ServiceException):
    pass


class ReservedDBInstanceNotFoundFault(ServiceException):
    pass


class ReservedDBInstanceQuotaExceededFault(ServiceException):
    pass


class ReservedDBInstancesOfferingNotFoundFault(ServiceException):
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


Long = int


class AccountQuota(TypedDict, total=False):
    AccountQuotaName: Optional[String]
    Used: Optional[Long]
    Max: Optional[Long]


AccountQuotaList = List[AccountQuota]


class AccountAttributesMessage(TypedDict, total=False):
    AccountQuotas: Optional[AccountQuotaList]


ActivityStreamModeList = List[String]


class AddRoleToDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    RoleArn: String
    FeatureName: Optional[String]


class AddRoleToDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    RoleArn: String
    FeatureName: String


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


class AuthorizeDBSecurityGroupIngressMessage(ServiceRequest):
    DBSecurityGroupName: String
    CIDRIP: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupId: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


class IPRange(TypedDict, total=False):
    Status: Optional[String]
    CIDRIP: Optional[String]


IPRangeList = List[IPRange]


class EC2SecurityGroup(TypedDict, total=False):
    Status: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupId: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


EC2SecurityGroupList = List[EC2SecurityGroup]


class DBSecurityGroup(TypedDict, total=False):
    OwnerId: Optional[String]
    DBSecurityGroupName: Optional[String]
    DBSecurityGroupDescription: Optional[String]
    VpcId: Optional[String]
    EC2SecurityGroups: Optional[EC2SecurityGroupList]
    IPRanges: Optional[IPRangeList]
    DBSecurityGroupArn: Optional[String]


class AuthorizeDBSecurityGroupIngressResult(TypedDict, total=False):
    DBSecurityGroup: Optional[DBSecurityGroup]


class AvailabilityZone(TypedDict, total=False):
    Name: Optional[String]


AvailabilityZoneList = List[AvailabilityZone]
AvailabilityZones = List[String]


class AvailableProcessorFeature(TypedDict, total=False):
    Name: Optional[String]
    DefaultValue: Optional[String]
    AllowedValues: Optional[String]


AvailableProcessorFeatureList = List[AvailableProcessorFeature]


class BacktrackDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    BacktrackTo: TStamp
    Force: Optional[BooleanOptional]
    UseEarliestTimeOnPointInTimeUnavailable: Optional[BooleanOptional]


class CancelExportTaskMessage(ServiceRequest):
    ExportTaskIdentifier: String


class Certificate(TypedDict, total=False):
    CertificateIdentifier: Optional[String]
    CertificateType: Optional[String]
    Thumbprint: Optional[String]
    ValidFrom: Optional[TStamp]
    ValidTill: Optional[TStamp]
    CertificateArn: Optional[String]
    CustomerOverride: Optional[BooleanOptional]
    CustomerOverrideValidTill: Optional[TStamp]


CertificateList = List[Certificate]


class CertificateMessage(TypedDict, total=False):
    Certificates: Optional[CertificateList]
    Marker: Optional[String]


class CharacterSet(TypedDict, total=False):
    CharacterSetName: Optional[String]
    CharacterSetDescription: Optional[String]


LogTypeList = List[String]


class CloudwatchLogsExportConfiguration(TypedDict, total=False):
    EnableLogTypes: Optional[LogTypeList]
    DisableLogTypes: Optional[LogTypeList]


class PendingCloudwatchLogsExports(TypedDict, total=False):
    LogTypesToEnable: Optional[LogTypeList]
    LogTypesToDisable: Optional[LogTypeList]


class ClusterPendingModifiedValues(TypedDict, total=False):
    PendingCloudwatchLogsExports: Optional[PendingCloudwatchLogsExports]
    DBClusterIdentifier: Optional[String]
    MasterUserPassword: Optional[String]
    IAMDatabaseAuthenticationEnabled: Optional[BooleanOptional]
    EngineVersion: Optional[String]


StringList = List[String]


class ConnectionPoolConfiguration(TypedDict, total=False):
    MaxConnectionsPercent: Optional[IntegerOptional]
    MaxIdleConnectionsPercent: Optional[IntegerOptional]
    ConnectionBorrowTimeout: Optional[IntegerOptional]
    SessionPinningFilters: Optional[StringList]
    InitQuery: Optional[String]


class ConnectionPoolConfigurationInfo(TypedDict, total=False):
    MaxConnectionsPercent: Optional[Integer]
    MaxIdleConnectionsPercent: Optional[Integer]
    ConnectionBorrowTimeout: Optional[Integer]
    SessionPinningFilters: Optional[StringList]
    InitQuery: Optional[String]


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
    EngineMode: Optional[String]
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
    TagList: Optional[TagList]


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


class CopyDBSnapshotMessage(ServiceRequest):
    SourceDBSnapshotIdentifier: String
    TargetDBSnapshotIdentifier: String
    KmsKeyId: Optional[String]
    Tags: Optional[TagList]
    CopyTags: Optional[BooleanOptional]
    PreSignedUrl: Optional[String]
    OptionGroupName: Optional[String]
    TargetCustomAvailabilityZone: Optional[String]
    SourceRegion: Optional[String]


class ProcessorFeature(TypedDict, total=False):
    Name: Optional[String]
    Value: Optional[String]


ProcessorFeatureList = List[ProcessorFeature]


class DBSnapshot(TypedDict, total=False):
    DBSnapshotIdentifier: Optional[String]
    DBInstanceIdentifier: Optional[String]
    SnapshotCreateTime: Optional[TStamp]
    Engine: Optional[String]
    AllocatedStorage: Optional[Integer]
    Status: Optional[String]
    Port: Optional[Integer]
    AvailabilityZone: Optional[String]
    VpcId: Optional[String]
    InstanceCreateTime: Optional[TStamp]
    MasterUsername: Optional[String]
    EngineVersion: Optional[String]
    LicenseModel: Optional[String]
    SnapshotType: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    PercentProgress: Optional[Integer]
    SourceRegion: Optional[String]
    SourceDBSnapshotIdentifier: Optional[String]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DBSnapshotArn: Optional[String]
    Timezone: Optional[String]
    IAMDatabaseAuthenticationEnabled: Optional[Boolean]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    DbiResourceId: Optional[String]
    TagList: Optional[TagList]
    OriginalSnapshotCreateTime: Optional[TStamp]
    SnapshotTarget: Optional[String]


class CopyDBSnapshotResult(TypedDict, total=False):
    DBSnapshot: Optional[DBSnapshot]


class CopyOptionGroupMessage(ServiceRequest):
    SourceOptionGroupIdentifier: String
    TargetOptionGroupIdentifier: String
    TargetOptionGroupDescription: String
    Tags: Optional[TagList]


class VpcSecurityGroupMembership(TypedDict, total=False):
    VpcSecurityGroupId: Optional[String]
    Status: Optional[String]


VpcSecurityGroupMembershipList = List[VpcSecurityGroupMembership]


class DBSecurityGroupMembership(TypedDict, total=False):
    DBSecurityGroupName: Optional[String]
    Status: Optional[String]


DBSecurityGroupMembershipList = List[DBSecurityGroupMembership]


class OptionSetting(TypedDict, total=False):
    Name: Optional[String]
    Value: Optional[String]
    DefaultValue: Optional[String]
    Description: Optional[String]
    ApplyType: Optional[String]
    DataType: Optional[String]
    AllowedValues: Optional[String]
    IsModifiable: Optional[Boolean]
    IsCollection: Optional[Boolean]


OptionSettingConfigurationList = List[OptionSetting]


class Option(TypedDict, total=False):
    OptionName: Optional[String]
    OptionDescription: Optional[String]
    Persistent: Optional[Boolean]
    Permanent: Optional[Boolean]
    Port: Optional[IntegerOptional]
    OptionVersion: Optional[String]
    OptionSettings: Optional[OptionSettingConfigurationList]
    DBSecurityGroupMemberships: Optional[DBSecurityGroupMembershipList]
    VpcSecurityGroupMemberships: Optional[VpcSecurityGroupMembershipList]


OptionsList = List[Option]


class OptionGroup(TypedDict, total=False):
    OptionGroupName: Optional[String]
    OptionGroupDescription: Optional[String]
    EngineName: Optional[String]
    MajorEngineVersion: Optional[String]
    Options: Optional[OptionsList]
    AllowsVpcAndNonVpcInstanceMemberships: Optional[Boolean]
    VpcId: Optional[String]
    OptionGroupArn: Optional[String]


class CopyOptionGroupResult(TypedDict, total=False):
    OptionGroup: Optional[OptionGroup]


class CreateCustomAvailabilityZoneMessage(ServiceRequest):
    CustomAvailabilityZoneName: String
    ExistingVpnId: Optional[String]
    NewVpnTunnelName: Optional[String]
    VpnTunnelOriginatorIP: Optional[String]


class VpnDetails(TypedDict, total=False):
    VpnId: Optional[String]
    VpnTunnelOriginatorIP: Optional[String]
    VpnGatewayIp: Optional[String]
    VpnPSK: Optional[StringSensitive]
    VpnName: Optional[String]
    VpnState: Optional[String]


class CustomAvailabilityZone(TypedDict, total=False):
    CustomAvailabilityZoneId: Optional[String]
    CustomAvailabilityZoneName: Optional[String]
    CustomAvailabilityZoneStatus: Optional[String]
    VpnDetails: Optional[VpnDetails]


class CreateCustomAvailabilityZoneResult(TypedDict, total=False):
    CustomAvailabilityZone: Optional[CustomAvailabilityZone]


class CreateCustomDBEngineVersionMessage(ServiceRequest):
    Engine: CustomEngineName
    EngineVersion: CustomEngineVersion
    DatabaseInstallationFilesS3BucketName: BucketName
    DatabaseInstallationFilesS3Prefix: Optional[String255]
    KMSKeyId: KmsKeyIdOrArn
    Description: Optional[Description]
    Manifest: CustomDBEngineVersionManifest
    Tags: Optional[TagList]


class CreateDBClusterEndpointMessage(ServiceRequest):
    DBClusterIdentifier: String
    DBClusterEndpointIdentifier: String
    EndpointType: String
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]
    Tags: Optional[TagList]


class ScalingConfiguration(TypedDict, total=False):
    MinCapacity: Optional[IntegerOptional]
    MaxCapacity: Optional[IntegerOptional]
    AutoPause: Optional[BooleanOptional]
    SecondsUntilAutoPause: Optional[IntegerOptional]
    TimeoutAction: Optional[String]
    SecondsBeforeTimeout: Optional[IntegerOptional]


LongOptional = int
VpcSecurityGroupIdList = List[String]


class CreateDBClusterMessage(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
    CharacterSetName: Optional[String]
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
    BacktrackWindow: Optional[LongOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    EngineMode: Optional[String]
    ScalingConfiguration: Optional[ScalingConfiguration]
    DeletionProtection: Optional[BooleanOptional]
    GlobalClusterIdentifier: Optional[String]
    EnableHttpEndpoint: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    EnableGlobalWriteForwarding: Optional[BooleanOptional]
    DBClusterInstanceClass: Optional[String]
    AllocatedStorage: Optional[IntegerOptional]
    StorageType: Optional[String]
    Iops: Optional[IntegerOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    SourceRegion: Optional[String]


class CreateDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    DBParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateDBClusterParameterGroupResult(TypedDict, total=False):
    DBClusterParameterGroup: Optional[DBClusterParameterGroup]


class DomainMembership(TypedDict, total=False):
    Domain: Optional[String]
    Status: Optional[String]
    FQDN: Optional[String]
    IAMRoleName: Optional[String]


DomainMembershipList = List[DomainMembership]


class ScalingConfigurationInfo(TypedDict, total=False):
    MinCapacity: Optional[IntegerOptional]
    MaxCapacity: Optional[IntegerOptional]
    AutoPause: Optional[BooleanOptional]
    SecondsUntilAutoPause: Optional[IntegerOptional]
    TimeoutAction: Optional[String]
    SecondsBeforeTimeout: Optional[IntegerOptional]


class DBClusterRole(TypedDict, total=False):
    RoleArn: Optional[String]
    Status: Optional[String]
    FeatureName: Optional[String]


DBClusterRoles = List[DBClusterRole]


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
    AutomaticRestartTime: Optional[TStamp]
    PercentProgress: Optional[String]
    EarliestRestorableTime: Optional[TStamp]
    Endpoint: Optional[String]
    ReaderEndpoint: Optional[String]
    CustomEndpoints: Optional[StringList]
    MultiAZ: Optional[BooleanOptional]
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
    IAMDatabaseAuthenticationEnabled: Optional[BooleanOptional]
    CloneGroupId: Optional[String]
    ClusterCreateTime: Optional[TStamp]
    EarliestBacktrackTime: Optional[TStamp]
    BacktrackWindow: Optional[LongOptional]
    BacktrackConsumedChangeRecords: Optional[LongOptional]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]
    Capacity: Optional[IntegerOptional]
    EngineMode: Optional[String]
    ScalingConfigurationInfo: Optional[ScalingConfigurationInfo]
    DeletionProtection: Optional[BooleanOptional]
    HttpEndpointEnabled: Optional[BooleanOptional]
    ActivityStreamMode: Optional[ActivityStreamMode]
    ActivityStreamStatus: Optional[ActivityStreamStatus]
    ActivityStreamKmsKeyId: Optional[String]
    ActivityStreamKinesisStreamName: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    CrossAccountClone: Optional[BooleanOptional]
    DomainMemberships: Optional[DomainMembershipList]
    TagList: Optional[TagList]
    GlobalWriteForwardingStatus: Optional[WriteForwardingStatus]
    GlobalWriteForwardingRequested: Optional[BooleanOptional]
    PendingModifiedValues: Optional[ClusterPendingModifiedValues]
    DBClusterInstanceClass: Optional[String]
    StorageType: Optional[String]
    Iops: Optional[IntegerOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    AutoMinorVersionUpgrade: Optional[Boolean]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    PerformanceInsightsEnabled: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]


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
    NcharCharacterSetName: Optional[String]
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
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    DeletionProtection: Optional[BooleanOptional]
    MaxAllocatedStorage: Optional[IntegerOptional]
    EnableCustomerOwnedIp: Optional[BooleanOptional]
    CustomIamInstanceProfile: Optional[String]
    BackupTarget: Optional[String]


class CreateDBInstanceReadReplicaMessage(ServiceRequest):
    DBInstanceIdentifier: String
    SourceDBInstanceIdentifier: String
    DBInstanceClass: Optional[String]
    AvailabilityZone: Optional[String]
    Port: Optional[IntegerOptional]
    MultiAZ: Optional[BooleanOptional]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    DBParameterGroupName: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    Tags: Optional[TagList]
    DBSubnetGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    StorageType: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    KmsKeyId: Optional[String]
    PreSignedUrl: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    UseDefaultProcessorFeatures: Optional[BooleanOptional]
    DeletionProtection: Optional[BooleanOptional]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    ReplicaMode: Optional[ReplicaMode]
    MaxAllocatedStorage: Optional[IntegerOptional]
    CustomIamInstanceProfile: Optional[String]
    SourceRegion: Optional[String]


class DBInstanceAutomatedBackupsReplication(TypedDict, total=False):
    DBInstanceAutomatedBackupsArn: Optional[String]


DBInstanceAutomatedBackupsReplicationList = List[DBInstanceAutomatedBackupsReplication]


class Endpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[Integer]
    HostedZoneId: Optional[String]


class DBInstanceRole(TypedDict, total=False):
    RoleArn: Optional[String]
    FeatureName: Optional[String]
    Status: Optional[String]


DBInstanceRoles = List[DBInstanceRole]


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
    ProcessorFeatures: Optional[ProcessorFeatureList]
    IAMDatabaseAuthenticationEnabled: Optional[BooleanOptional]
    AutomationMode: Optional[AutomationMode]
    ResumeFullAutomationModeTime: Optional[TStamp]


class Outpost(TypedDict, total=False):
    Arn: Optional[String]


class Subnet(TypedDict, total=False):
    SubnetIdentifier: Optional[String]
    SubnetAvailabilityZone: Optional[AvailabilityZone]
    SubnetOutpost: Optional[Outpost]
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


class DBInstance(TypedDict, total=False):
    DBInstanceIdentifier: Optional[String]
    DBInstanceClass: Optional[String]
    Engine: Optional[String]
    DBInstanceStatus: Optional[String]
    AutomaticRestartTime: Optional[TStamp]
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
    ReplicaMode: Optional[ReplicaMode]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupMemberships: Optional[OptionGroupMembershipList]
    CharacterSetName: Optional[String]
    NcharCharacterSetName: Optional[String]
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
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    EnabledCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    DeletionProtection: Optional[Boolean]
    AssociatedRoles: Optional[DBInstanceRoles]
    ListenerEndpoint: Optional[Endpoint]
    MaxAllocatedStorage: Optional[IntegerOptional]
    TagList: Optional[TagList]
    DBInstanceAutomatedBackupsReplications: Optional[DBInstanceAutomatedBackupsReplicationList]
    CustomerOwnedIpEnabled: Optional[BooleanOptional]
    AwsBackupRecoveryPointArn: Optional[String]
    ActivityStreamStatus: Optional[ActivityStreamStatus]
    ActivityStreamKmsKeyId: Optional[String]
    ActivityStreamKinesisStreamName: Optional[String]
    ActivityStreamMode: Optional[ActivityStreamMode]
    ActivityStreamEngineNativeAuditFieldsIncluded: Optional[BooleanOptional]
    AutomationMode: Optional[AutomationMode]
    ResumeFullAutomationModeTime: Optional[TStamp]
    CustomIamInstanceProfile: Optional[String]
    BackupTarget: Optional[String]


class CreateDBInstanceReadReplicaResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class CreateDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class CreateDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    DBParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateDBParameterGroupResult(TypedDict, total=False):
    DBParameterGroup: Optional[DBParameterGroup]


class CreateDBProxyEndpointRequest(ServiceRequest):
    DBProxyName: DBProxyName
    DBProxyEndpointName: DBProxyEndpointName
    VpcSubnetIds: StringList
    VpcSecurityGroupIds: Optional[StringList]
    TargetRole: Optional[DBProxyEndpointTargetRole]
    Tags: Optional[TagList]


class DBProxyEndpoint(TypedDict, total=False):
    DBProxyEndpointName: Optional[String]
    DBProxyEndpointArn: Optional[String]
    DBProxyName: Optional[String]
    Status: Optional[DBProxyEndpointStatus]
    VpcId: Optional[String]
    VpcSecurityGroupIds: Optional[StringList]
    VpcSubnetIds: Optional[StringList]
    Endpoint: Optional[String]
    CreatedDate: Optional[TStamp]
    TargetRole: Optional[DBProxyEndpointTargetRole]
    IsDefault: Optional[Boolean]


class CreateDBProxyEndpointResponse(TypedDict, total=False):
    DBProxyEndpoint: Optional[DBProxyEndpoint]


class UserAuthConfig(TypedDict, total=False):
    Description: Optional[String]
    UserName: Optional[String]
    AuthScheme: Optional[AuthScheme]
    SecretArn: Optional[String]
    IAMAuth: Optional[IAMAuthMode]


UserAuthConfigList = List[UserAuthConfig]


class CreateDBProxyRequest(ServiceRequest):
    DBProxyName: String
    EngineFamily: EngineFamily
    Auth: UserAuthConfigList
    RoleArn: String
    VpcSubnetIds: StringList
    VpcSecurityGroupIds: Optional[StringList]
    RequireTLS: Optional[Boolean]
    IdleClientTimeout: Optional[IntegerOptional]
    DebugLogging: Optional[Boolean]
    Tags: Optional[TagList]


class UserAuthConfigInfo(TypedDict, total=False):
    Description: Optional[String]
    UserName: Optional[String]
    AuthScheme: Optional[AuthScheme]
    SecretArn: Optional[String]
    IAMAuth: Optional[IAMAuthMode]


UserAuthConfigInfoList = List[UserAuthConfigInfo]


class DBProxy(TypedDict, total=False):
    DBProxyName: Optional[String]
    DBProxyArn: Optional[String]
    Status: Optional[DBProxyStatus]
    EngineFamily: Optional[String]
    VpcId: Optional[String]
    VpcSecurityGroupIds: Optional[StringList]
    VpcSubnetIds: Optional[StringList]
    Auth: Optional[UserAuthConfigInfoList]
    RoleArn: Optional[String]
    Endpoint: Optional[String]
    RequireTLS: Optional[Boolean]
    IdleClientTimeout: Optional[Integer]
    DebugLogging: Optional[Boolean]
    CreatedDate: Optional[TStamp]
    UpdatedDate: Optional[TStamp]


class CreateDBProxyResponse(TypedDict, total=False):
    DBProxy: Optional[DBProxy]


class CreateDBSecurityGroupMessage(ServiceRequest):
    DBSecurityGroupName: String
    DBSecurityGroupDescription: String
    Tags: Optional[TagList]


class CreateDBSecurityGroupResult(TypedDict, total=False):
    DBSecurityGroup: Optional[DBSecurityGroup]


class CreateDBSnapshotMessage(ServiceRequest):
    DBSnapshotIdentifier: String
    DBInstanceIdentifier: String
    Tags: Optional[TagList]


class CreateDBSnapshotResult(TypedDict, total=False):
    DBSnapshot: Optional[DBSnapshot]


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
    GlobalClusterIdentifier: Optional[String]
    SourceDBClusterIdentifier: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    DatabaseName: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]


class FailoverState(TypedDict, total=False):
    Status: Optional[FailoverStatus]
    FromDbClusterArn: Optional[String]
    ToDbClusterArn: Optional[String]


ReadersArnList = List[String]


class GlobalClusterMember(TypedDict, total=False):
    DBClusterArn: Optional[String]
    Readers: Optional[ReadersArnList]
    IsWriter: Optional[Boolean]
    GlobalWriteForwardingStatus: Optional[WriteForwardingStatus]


GlobalClusterMemberList = List[GlobalClusterMember]


class GlobalCluster(TypedDict, total=False):
    GlobalClusterIdentifier: Optional[String]
    GlobalClusterResourceId: Optional[String]
    GlobalClusterArn: Optional[String]
    Status: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DatabaseName: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]
    DeletionProtection: Optional[BooleanOptional]
    GlobalClusterMembers: Optional[GlobalClusterMemberList]
    FailoverState: Optional[FailoverState]


class CreateGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


class CreateOptionGroupMessage(ServiceRequest):
    OptionGroupName: String
    EngineName: String
    MajorEngineVersion: String
    OptionGroupDescription: String
    Tags: Optional[TagList]


class CreateOptionGroupResult(TypedDict, total=False):
    OptionGroup: Optional[OptionGroup]


CustomAvailabilityZoneList = List[CustomAvailabilityZone]


class CustomAvailabilityZoneMessage(TypedDict, total=False):
    Marker: Optional[String]
    CustomAvailabilityZones: Optional[CustomAvailabilityZoneList]


class DBClusterBacktrack(TypedDict, total=False):
    DBClusterIdentifier: Optional[String]
    BacktrackIdentifier: Optional[String]
    BacktrackTo: Optional[TStamp]
    BacktrackedFrom: Optional[TStamp]
    BacktrackRequestCreationTime: Optional[TStamp]
    Status: Optional[String]


DBClusterBacktrackList = List[DBClusterBacktrack]


class DBClusterBacktrackMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBClusterBacktracks: Optional[DBClusterBacktrackList]


class DBClusterCapacityInfo(TypedDict, total=False):
    DBClusterIdentifier: Optional[String]
    PendingCapacity: Optional[IntegerOptional]
    CurrentCapacity: Optional[IntegerOptional]
    SecondsBeforeTimeout: Optional[IntegerOptional]
    TimeoutAction: Optional[String]


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


EngineModeList = List[String]


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
    SupportedEngineModes: Optional[EngineModeList]


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


FeatureNameList = List[String]


class Timezone(TypedDict, total=False):
    TimezoneName: Optional[String]


SupportedTimezonesList = List[Timezone]


class UpgradeTarget(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    Description: Optional[String]
    AutoUpgrade: Optional[Boolean]
    IsMajorVersionUpgrade: Optional[Boolean]
    SupportedEngineModes: Optional[EngineModeList]
    SupportsParallelQuery: Optional[BooleanOptional]
    SupportsGlobalDatabases: Optional[BooleanOptional]
    SupportsBabelfish: Optional[BooleanOptional]


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
    SupportedNcharCharacterSets: Optional[SupportedCharacterSetsList]
    ValidUpgradeTarget: Optional[ValidUpgradeTargetList]
    SupportedTimezones: Optional[SupportedTimezonesList]
    ExportableLogTypes: Optional[LogTypeList]
    SupportsLogExportsToCloudwatchLogs: Optional[Boolean]
    SupportsReadReplica: Optional[Boolean]
    SupportedEngineModes: Optional[EngineModeList]
    SupportedFeatureNames: Optional[FeatureNameList]
    Status: Optional[String]
    SupportsParallelQuery: Optional[Boolean]
    SupportsGlobalDatabases: Optional[Boolean]
    MajorEngineVersion: Optional[String]
    DatabaseInstallationFilesS3BucketName: Optional[String]
    DatabaseInstallationFilesS3Prefix: Optional[String]
    DBEngineVersionArn: Optional[String]
    KMSKeyId: Optional[String]
    CreateTime: Optional[TStamp]
    TagList: Optional[TagList]
    SupportsBabelfish: Optional[Boolean]


DBEngineVersionList = List[DBEngineVersion]


class DBEngineVersionMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBEngineVersions: Optional[DBEngineVersionList]


class RestoreWindow(TypedDict, total=False):
    EarliestTime: Optional[TStamp]
    LatestTime: Optional[TStamp]


class DBInstanceAutomatedBackup(TypedDict, total=False):
    DBInstanceArn: Optional[String]
    DbiResourceId: Optional[String]
    Region: Optional[String]
    DBInstanceIdentifier: Optional[String]
    RestoreWindow: Optional[RestoreWindow]
    AllocatedStorage: Optional[Integer]
    Status: Optional[String]
    Port: Optional[Integer]
    AvailabilityZone: Optional[String]
    VpcId: Optional[String]
    InstanceCreateTime: Optional[TStamp]
    MasterUsername: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    LicenseModel: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    TdeCredentialArn: Optional[String]
    Encrypted: Optional[Boolean]
    StorageType: Optional[String]
    KmsKeyId: Optional[String]
    Timezone: Optional[String]
    IAMDatabaseAuthenticationEnabled: Optional[Boolean]
    BackupRetentionPeriod: Optional[IntegerOptional]
    DBInstanceAutomatedBackupsArn: Optional[String]
    DBInstanceAutomatedBackupsReplications: Optional[DBInstanceAutomatedBackupsReplicationList]
    BackupTarget: Optional[String]


DBInstanceAutomatedBackupList = List[DBInstanceAutomatedBackup]


class DBInstanceAutomatedBackupMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBInstanceAutomatedBackups: Optional[DBInstanceAutomatedBackupList]


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


DBProxyEndpointList = List[DBProxyEndpoint]
DBProxyList = List[DBProxy]


class TargetHealth(TypedDict, total=False):
    State: Optional[TargetState]
    Reason: Optional[TargetHealthReason]
    Description: Optional[String]


class DBProxyTarget(TypedDict, total=False):
    TargetArn: Optional[String]
    Endpoint: Optional[String]
    TrackedClusterId: Optional[String]
    RdsResourceId: Optional[String]
    Port: Optional[Integer]
    Type: Optional[TargetType]
    Role: Optional[TargetRole]
    TargetHealth: Optional[TargetHealth]


class DBProxyTargetGroup(TypedDict, total=False):
    DBProxyName: Optional[String]
    TargetGroupName: Optional[String]
    TargetGroupArn: Optional[String]
    IsDefault: Optional[Boolean]
    Status: Optional[String]
    ConnectionPoolConfig: Optional[ConnectionPoolConfigurationInfo]
    CreatedDate: Optional[TStamp]
    UpdatedDate: Optional[TStamp]


DBSecurityGroups = List[DBSecurityGroup]


class DBSecurityGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBSecurityGroups: Optional[DBSecurityGroups]


class DBSnapshotAttribute(TypedDict, total=False):
    AttributeName: Optional[String]
    AttributeValues: Optional[AttributeValueList]


DBSnapshotAttributeList = List[DBSnapshotAttribute]


class DBSnapshotAttributesResult(TypedDict, total=False):
    DBSnapshotIdentifier: Optional[String]
    DBSnapshotAttributes: Optional[DBSnapshotAttributeList]


DBSnapshotList = List[DBSnapshot]


class DBSnapshotMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBSnapshots: Optional[DBSnapshotList]


DBSubnetGroups = List[DBSubnetGroup]


class DBSubnetGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    DBSubnetGroups: Optional[DBSubnetGroups]


class DeleteCustomAvailabilityZoneMessage(ServiceRequest):
    CustomAvailabilityZoneId: String


class DeleteCustomAvailabilityZoneResult(TypedDict, total=False):
    CustomAvailabilityZone: Optional[CustomAvailabilityZone]


class DeleteCustomDBEngineVersionMessage(ServiceRequest):
    Engine: CustomEngineName
    EngineVersion: CustomEngineVersion


class DeleteDBClusterEndpointMessage(ServiceRequest):
    DBClusterEndpointIdentifier: String


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


class DeleteDBInstanceAutomatedBackupMessage(ServiceRequest):
    DbiResourceId: Optional[String]
    DBInstanceAutomatedBackupsArn: Optional[String]


class DeleteDBInstanceAutomatedBackupResult(TypedDict, total=False):
    DBInstanceAutomatedBackup: Optional[DBInstanceAutomatedBackup]


class DeleteDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    SkipFinalSnapshot: Optional[Boolean]
    FinalDBSnapshotIdentifier: Optional[String]
    DeleteAutomatedBackups: Optional[BooleanOptional]


class DeleteDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class DeleteDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String


class DeleteDBProxyEndpointRequest(ServiceRequest):
    DBProxyEndpointName: DBProxyEndpointName


class DeleteDBProxyEndpointResponse(TypedDict, total=False):
    DBProxyEndpoint: Optional[DBProxyEndpoint]


class DeleteDBProxyRequest(ServiceRequest):
    DBProxyName: String


class DeleteDBProxyResponse(TypedDict, total=False):
    DBProxy: Optional[DBProxy]


class DeleteDBSecurityGroupMessage(ServiceRequest):
    DBSecurityGroupName: String


class DeleteDBSnapshotMessage(ServiceRequest):
    DBSnapshotIdentifier: String


class DeleteDBSnapshotResult(TypedDict, total=False):
    DBSnapshot: Optional[DBSnapshot]


class DeleteDBSubnetGroupMessage(ServiceRequest):
    DBSubnetGroupName: String


class DeleteEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String


class DeleteEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class DeleteGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: String


class DeleteGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


class DeleteInstallationMediaMessage(ServiceRequest):
    InstallationMediaId: String


class DeleteOptionGroupMessage(ServiceRequest):
    OptionGroupName: String


class DeregisterDBProxyTargetsRequest(ServiceRequest):
    DBProxyName: String
    TargetGroupName: Optional[String]
    DBInstanceIdentifiers: Optional[StringList]
    DBClusterIdentifiers: Optional[StringList]


class DeregisterDBProxyTargetsResponse(TypedDict, total=False):
    pass


class DescribeAccountAttributesMessage(ServiceRequest):
    pass


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


class DescribeCustomAvailabilityZonesMessage(ServiceRequest):
    CustomAvailabilityZoneId: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBClusterBacktracksMessage(ServiceRequest):
    DBClusterIdentifier: String
    BacktrackIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


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
    IncludeShared: Optional[Boolean]


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
    IncludeAll: Optional[BooleanOptional]


class DescribeDBInstanceAutomatedBackupsMessage(ServiceRequest):
    DbiResourceId: Optional[String]
    DBInstanceIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    DBInstanceAutomatedBackupsArn: Optional[String]


class DescribeDBInstancesMessage(ServiceRequest):
    DBInstanceIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBLogFilesDetails(TypedDict, total=False):
    LogFileName: Optional[String]
    LastWritten: Optional[Long]
    Size: Optional[Long]


DescribeDBLogFilesList = List[DescribeDBLogFilesDetails]


class DescribeDBLogFilesMessage(ServiceRequest):
    DBInstanceIdentifier: String
    FilenameContains: Optional[String]
    FileLastWritten: Optional[Long]
    FileSize: Optional[Long]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBLogFilesResponse(TypedDict, total=False):
    DescribeDBLogFiles: Optional[DescribeDBLogFilesList]
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


class DescribeDBProxiesRequest(ServiceRequest):
    DBProxyName: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[MaxRecords]


class DescribeDBProxiesResponse(TypedDict, total=False):
    DBProxies: Optional[DBProxyList]
    Marker: Optional[String]


class DescribeDBProxyEndpointsRequest(ServiceRequest):
    DBProxyName: Optional[DBProxyName]
    DBProxyEndpointName: Optional[DBProxyEndpointName]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[MaxRecords]


class DescribeDBProxyEndpointsResponse(TypedDict, total=False):
    DBProxyEndpoints: Optional[DBProxyEndpointList]
    Marker: Optional[String]


class DescribeDBProxyTargetGroupsRequest(ServiceRequest):
    DBProxyName: String
    TargetGroupName: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[MaxRecords]


TargetGroupList = List[DBProxyTargetGroup]


class DescribeDBProxyTargetGroupsResponse(TypedDict, total=False):
    TargetGroups: Optional[TargetGroupList]
    Marker: Optional[String]


class DescribeDBProxyTargetsRequest(ServiceRequest):
    DBProxyName: String
    TargetGroupName: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[MaxRecords]


TargetList = List[DBProxyTarget]


class DescribeDBProxyTargetsResponse(TypedDict, total=False):
    Targets: Optional[TargetList]
    Marker: Optional[String]


class DescribeDBSecurityGroupsMessage(ServiceRequest):
    DBSecurityGroupName: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDBSnapshotAttributesMessage(ServiceRequest):
    DBSnapshotIdentifier: String


class DescribeDBSnapshotAttributesResult(TypedDict, total=False):
    DBSnapshotAttributesResult: Optional[DBSnapshotAttributesResult]


class DescribeDBSnapshotsMessage(ServiceRequest):
    DBInstanceIdentifier: Optional[String]
    DBSnapshotIdentifier: Optional[String]
    SnapshotType: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    IncludeShared: Optional[Boolean]
    IncludePublic: Optional[Boolean]
    DbiResourceId: Optional[String]


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


class DescribeExportTasksMessage(ServiceRequest):
    ExportTaskIdentifier: Optional[String]
    SourceArn: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[MaxRecords]


class DescribeGlobalClustersMessage(ServiceRequest):
    GlobalClusterIdentifier: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeInstallationMediaMessage(ServiceRequest):
    InstallationMediaId: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeOptionGroupOptionsMessage(ServiceRequest):
    EngineName: String
    MajorEngineVersion: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeOptionGroupsMessage(ServiceRequest):
    OptionGroupName: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    EngineName: Optional[String]
    MajorEngineVersion: Optional[String]


class DescribeOrderableDBInstanceOptionsMessage(ServiceRequest):
    Engine: String
    EngineVersion: Optional[String]
    DBInstanceClass: Optional[String]
    LicenseModel: Optional[String]
    AvailabilityZoneGroup: Optional[String]
    Vpc: Optional[BooleanOptional]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribePendingMaintenanceActionsMessage(ServiceRequest):
    ResourceIdentifier: Optional[String]
    Filters: Optional[FilterList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]


class DescribeReservedDBInstancesMessage(ServiceRequest):
    ReservedDBInstanceId: Optional[String]
    ReservedDBInstancesOfferingId: Optional[String]
    DBInstanceClass: Optional[String]
    Duration: Optional[String]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MultiAZ: Optional[BooleanOptional]
    LeaseId: Optional[String]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeReservedDBInstancesOfferingsMessage(ServiceRequest):
    ReservedDBInstancesOfferingId: Optional[String]
    DBInstanceClass: Optional[String]
    Duration: Optional[String]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MultiAZ: Optional[BooleanOptional]
    Filters: Optional[FilterList]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeSourceRegionsMessage(ServiceRequest):
    RegionName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    Filters: Optional[FilterList]


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
    SupportsStorageAutoscaling: Optional[Boolean]


ValidStorageOptionsList = List[ValidStorageOptions]


class ValidDBInstanceModificationsMessage(TypedDict, total=False):
    Storage: Optional[ValidStorageOptionsList]
    ValidProcessorFeatures: Optional[AvailableProcessorFeatureList]


class DescribeValidDBInstanceModificationsResult(TypedDict, total=False):
    ValidDBInstanceModificationsMessage: Optional[ValidDBInstanceModificationsMessage]


class DownloadDBLogFilePortionDetails(TypedDict, total=False):
    LogFileData: Optional[String]
    Marker: Optional[String]
    AdditionalDataPending: Optional[Boolean]


class DownloadDBLogFilePortionMessage(ServiceRequest):
    DBInstanceIdentifier: String
    LogFileName: String
    Marker: Optional[String]
    NumberOfLines: Optional[Integer]


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


class ExportTask(TypedDict, total=False):
    ExportTaskIdentifier: Optional[String]
    SourceArn: Optional[String]
    ExportOnly: Optional[StringList]
    SnapshotTime: Optional[TStamp]
    TaskStartTime: Optional[TStamp]
    TaskEndTime: Optional[TStamp]
    S3Bucket: Optional[String]
    S3Prefix: Optional[String]
    IamRoleArn: Optional[String]
    KmsKeyId: Optional[String]
    Status: Optional[String]
    PercentProgress: Optional[Integer]
    TotalExtractedDataInGB: Optional[Integer]
    FailureCause: Optional[String]
    WarningMessage: Optional[String]


ExportTasksList = List[ExportTask]


class ExportTasksMessage(TypedDict, total=False):
    Marker: Optional[String]
    ExportTasks: Optional[ExportTasksList]


class FailoverDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    TargetDBInstanceIdentifier: Optional[String]


class FailoverDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class FailoverGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: GlobalClusterIdentifier
    TargetDbClusterIdentifier: DBClusterIdentifier


class FailoverGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


GlobalClusterList = List[GlobalCluster]


class GlobalClustersMessage(TypedDict, total=False):
    Marker: Optional[String]
    GlobalClusters: Optional[GlobalClusterList]


class ImportInstallationMediaMessage(ServiceRequest):
    CustomAvailabilityZoneId: String
    Engine: String
    EngineVersion: String
    EngineInstallationMediaPath: String
    OSInstallationMediaPath: String


class InstallationMediaFailureCause(TypedDict, total=False):
    Message: Optional[String]


class InstallationMedia(TypedDict, total=False):
    InstallationMediaId: Optional[String]
    CustomAvailabilityZoneId: Optional[String]
    Engine: Optional[String]
    EngineVersion: Optional[String]
    EngineInstallationMediaPath: Optional[String]
    OSInstallationMediaPath: Optional[String]
    Status: Optional[String]
    FailureCause: Optional[InstallationMediaFailureCause]


InstallationMediaList = List[InstallationMedia]


class InstallationMediaMessage(TypedDict, total=False):
    Marker: Optional[String]
    InstallationMedia: Optional[InstallationMediaList]


KeyList = List[String]


class ListTagsForResourceMessage(ServiceRequest):
    ResourceName: String
    Filters: Optional[FilterList]


class MinimumEngineVersionPerAllowedValue(TypedDict, total=False):
    AllowedValue: Optional[String]
    MinimumEngineVersion: Optional[String]


MinimumEngineVersionPerAllowedValueList = List[MinimumEngineVersionPerAllowedValue]


class ModifyCertificatesMessage(ServiceRequest):
    CertificateIdentifier: Optional[String]
    RemoveCustomerOverride: Optional[BooleanOptional]


class ModifyCertificatesResult(TypedDict, total=False):
    Certificate: Optional[Certificate]


class ModifyCurrentDBClusterCapacityMessage(ServiceRequest):
    DBClusterIdentifier: String
    Capacity: Optional[IntegerOptional]
    SecondsBeforeTimeout: Optional[IntegerOptional]
    TimeoutAction: Optional[String]


class ModifyCustomDBEngineVersionMessage(ServiceRequest):
    Engine: CustomEngineName
    EngineVersion: CustomEngineVersion
    Description: Optional[Description]
    Status: Optional[CustomEngineVersionStatus]


class ModifyDBClusterEndpointMessage(ServiceRequest):
    DBClusterEndpointIdentifier: String
    EndpointType: Optional[String]
    StaticMembers: Optional[StringList]
    ExcludedMembers: Optional[StringList]


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
    BacktrackWindow: Optional[LongOptional]
    CloudwatchLogsExportConfiguration: Optional[CloudwatchLogsExportConfiguration]
    EngineVersion: Optional[String]
    AllowMajorVersionUpgrade: Optional[Boolean]
    DBInstanceParameterGroupName: Optional[String]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    ScalingConfiguration: Optional[ScalingConfiguration]
    DeletionProtection: Optional[BooleanOptional]
    EnableHttpEndpoint: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    EnableGlobalWriteForwarding: Optional[BooleanOptional]
    DBClusterInstanceClass: Optional[String]
    AllocatedStorage: Optional[IntegerOptional]
    StorageType: Optional[String]
    Iops: Optional[IntegerOptional]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]


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
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    CloudwatchLogsExportConfiguration: Optional[CloudwatchLogsExportConfiguration]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    UseDefaultProcessorFeatures: Optional[BooleanOptional]
    DeletionProtection: Optional[BooleanOptional]
    MaxAllocatedStorage: Optional[IntegerOptional]
    CertificateRotationRestart: Optional[BooleanOptional]
    ReplicaMode: Optional[ReplicaMode]
    EnableCustomerOwnedIp: Optional[BooleanOptional]
    AwsBackupRecoveryPointArn: Optional[AwsBackupRecoveryPointArn]
    AutomationMode: Optional[AutomationMode]
    ResumeFullAutomationModeMinutes: Optional[IntegerOptional]


class ModifyDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class ModifyDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    Parameters: ParametersList


class ModifyDBProxyEndpointRequest(ServiceRequest):
    DBProxyEndpointName: DBProxyEndpointName
    NewDBProxyEndpointName: Optional[DBProxyEndpointName]
    VpcSecurityGroupIds: Optional[StringList]


class ModifyDBProxyEndpointResponse(TypedDict, total=False):
    DBProxyEndpoint: Optional[DBProxyEndpoint]


class ModifyDBProxyRequest(ServiceRequest):
    DBProxyName: String
    NewDBProxyName: Optional[String]
    Auth: Optional[UserAuthConfigList]
    RequireTLS: Optional[BooleanOptional]
    IdleClientTimeout: Optional[IntegerOptional]
    DebugLogging: Optional[BooleanOptional]
    RoleArn: Optional[String]
    SecurityGroups: Optional[StringList]


class ModifyDBProxyResponse(TypedDict, total=False):
    DBProxy: Optional[DBProxy]


class ModifyDBProxyTargetGroupRequest(ServiceRequest):
    TargetGroupName: String
    DBProxyName: String
    ConnectionPoolConfig: Optional[ConnectionPoolConfiguration]
    NewName: Optional[String]


class ModifyDBProxyTargetGroupResponse(TypedDict, total=False):
    DBProxyTargetGroup: Optional[DBProxyTargetGroup]


class ModifyDBSnapshotAttributeMessage(ServiceRequest):
    DBSnapshotIdentifier: String
    AttributeName: String
    ValuesToAdd: Optional[AttributeValueList]
    ValuesToRemove: Optional[AttributeValueList]


class ModifyDBSnapshotAttributeResult(TypedDict, total=False):
    DBSnapshotAttributesResult: Optional[DBSnapshotAttributesResult]


class ModifyDBSnapshotMessage(ServiceRequest):
    DBSnapshotIdentifier: String
    EngineVersion: Optional[String]
    OptionGroupName: Optional[String]


class ModifyDBSnapshotResult(TypedDict, total=False):
    DBSnapshot: Optional[DBSnapshot]


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
    GlobalClusterIdentifier: Optional[String]
    NewGlobalClusterIdentifier: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    EngineVersion: Optional[String]
    AllowMajorVersionUpgrade: Optional[BooleanOptional]


class ModifyGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


OptionNamesList = List[String]
OptionSettingsList = List[OptionSetting]


class OptionConfiguration(TypedDict, total=False):
    OptionName: String
    Port: Optional[IntegerOptional]
    OptionVersion: Optional[String]
    DBSecurityGroupMemberships: Optional[DBSecurityGroupNameList]
    VpcSecurityGroupMemberships: Optional[VpcSecurityGroupIdList]
    OptionSettings: Optional[OptionSettingsList]


OptionConfigurationList = List[OptionConfiguration]


class ModifyOptionGroupMessage(ServiceRequest):
    OptionGroupName: String
    OptionsToInclude: Optional[OptionConfigurationList]
    OptionsToRemove: Optional[OptionNamesList]
    ApplyImmediately: Optional[Boolean]


class ModifyOptionGroupResult(TypedDict, total=False):
    OptionGroup: Optional[OptionGroup]


class OptionVersion(TypedDict, total=False):
    Version: Optional[String]
    IsDefault: Optional[Boolean]


OptionGroupOptionVersionsList = List[OptionVersion]


class OptionGroupOptionSetting(TypedDict, total=False):
    SettingName: Optional[String]
    SettingDescription: Optional[String]
    DefaultValue: Optional[String]
    ApplyType: Optional[String]
    AllowedValues: Optional[String]
    IsModifiable: Optional[Boolean]
    IsRequired: Optional[Boolean]
    MinimumEngineVersionPerAllowedValue: Optional[MinimumEngineVersionPerAllowedValueList]


OptionGroupOptionSettingsList = List[OptionGroupOptionSetting]
OptionsConflictsWith = List[String]
OptionsDependedOn = List[String]


class OptionGroupOption(TypedDict, total=False):
    Name: Optional[String]
    Description: Optional[String]
    EngineName: Optional[String]
    MajorEngineVersion: Optional[String]
    MinimumRequiredMinorEngineVersion: Optional[String]
    PortRequired: Optional[Boolean]
    DefaultPort: Optional[IntegerOptional]
    OptionsDependedOn: Optional[OptionsDependedOn]
    OptionsConflictsWith: Optional[OptionsConflictsWith]
    Persistent: Optional[Boolean]
    Permanent: Optional[Boolean]
    RequiresAutoMinorEngineVersionUpgrade: Optional[Boolean]
    VpcOnly: Optional[Boolean]
    SupportsOptionVersionDowngrade: Optional[BooleanOptional]
    OptionGroupOptionSettings: Optional[OptionGroupOptionSettingsList]
    OptionGroupOptionVersions: Optional[OptionGroupOptionVersionsList]


OptionGroupOptionsList = List[OptionGroupOption]


class OptionGroupOptionsMessage(TypedDict, total=False):
    OptionGroupOptions: Optional[OptionGroupOptionsList]
    Marker: Optional[String]


OptionGroupsList = List[OptionGroup]


class OptionGroups(TypedDict, total=False):
    OptionGroupsList: Optional[OptionGroupsList]
    Marker: Optional[String]


class OrderableDBInstanceOption(TypedDict, total=False):
    Engine: Optional[String]
    EngineVersion: Optional[String]
    DBInstanceClass: Optional[String]
    LicenseModel: Optional[String]
    AvailabilityZoneGroup: Optional[String]
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
    AvailableProcessorFeatures: Optional[AvailableProcessorFeatureList]
    SupportedEngineModes: Optional[EngineModeList]
    SupportsStorageAutoscaling: Optional[BooleanOptional]
    SupportsKerberosAuthentication: Optional[BooleanOptional]
    OutpostCapable: Optional[Boolean]
    SupportedActivityStreamModes: Optional[ActivityStreamModeList]
    SupportsGlobalDatabases: Optional[Boolean]
    SupportsClusters: Optional[Boolean]


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


class PromoteReadReplicaMessage(ServiceRequest):
    DBInstanceIdentifier: String
    BackupRetentionPeriod: Optional[IntegerOptional]
    PreferredBackupWindow: Optional[String]


class PromoteReadReplicaResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class PurchaseReservedDBInstancesOfferingMessage(ServiceRequest):
    ReservedDBInstancesOfferingId: String
    ReservedDBInstanceId: Optional[String]
    DBInstanceCount: Optional[IntegerOptional]
    Tags: Optional[TagList]


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedDBInstance(TypedDict, total=False):
    ReservedDBInstanceId: Optional[String]
    ReservedDBInstancesOfferingId: Optional[String]
    DBInstanceClass: Optional[String]
    StartTime: Optional[TStamp]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    DBInstanceCount: Optional[Integer]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MultiAZ: Optional[Boolean]
    State: Optional[String]
    RecurringCharges: Optional[RecurringChargeList]
    ReservedDBInstanceArn: Optional[String]
    LeaseId: Optional[String]


class PurchaseReservedDBInstancesOfferingResult(TypedDict, total=False):
    ReservedDBInstance: Optional[ReservedDBInstance]


class RebootDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class RebootDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class RebootDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    ForceFailover: Optional[BooleanOptional]


class RebootDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RegisterDBProxyTargetsRequest(ServiceRequest):
    DBProxyName: String
    TargetGroupName: Optional[String]
    DBInstanceIdentifiers: Optional[StringList]
    DBClusterIdentifiers: Optional[StringList]


class RegisterDBProxyTargetsResponse(TypedDict, total=False):
    DBProxyTargets: Optional[TargetList]


class RemoveFromGlobalClusterMessage(ServiceRequest):
    GlobalClusterIdentifier: Optional[String]
    DbClusterIdentifier: Optional[String]


class RemoveFromGlobalClusterResult(TypedDict, total=False):
    GlobalCluster: Optional[GlobalCluster]


class RemoveRoleFromDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String
    RoleArn: String
    FeatureName: Optional[String]


class RemoveRoleFromDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    RoleArn: String
    FeatureName: String


class RemoveSourceIdentifierFromSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SourceIdentifier: String


class RemoveSourceIdentifierFromSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class RemoveTagsFromResourceMessage(ServiceRequest):
    ResourceName: String
    TagKeys: KeyList


ReservedDBInstanceList = List[ReservedDBInstance]


class ReservedDBInstanceMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedDBInstances: Optional[ReservedDBInstanceList]


class ReservedDBInstancesOffering(TypedDict, total=False):
    ReservedDBInstancesOfferingId: Optional[String]
    DBInstanceClass: Optional[String]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    ProductDescription: Optional[String]
    OfferingType: Optional[String]
    MultiAZ: Optional[Boolean]
    RecurringCharges: Optional[RecurringChargeList]


ReservedDBInstancesOfferingList = List[ReservedDBInstancesOffering]


class ReservedDBInstancesOfferingMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedDBInstancesOfferings: Optional[ReservedDBInstancesOfferingList]


class ResetDBClusterParameterGroupMessage(ServiceRequest):
    DBClusterParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    Parameters: Optional[ParametersList]


class ResetDBParameterGroupMessage(ServiceRequest):
    DBParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    Parameters: Optional[ParametersList]


class RestoreDBClusterFromS3Message(ServiceRequest):
    AvailabilityZones: Optional[AvailabilityZones]
    BackupRetentionPeriod: Optional[IntegerOptional]
    CharacterSetName: Optional[String]
    DatabaseName: Optional[String]
    DBClusterIdentifier: String
    DBClusterParameterGroupName: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    DBSubnetGroupName: Optional[String]
    Engine: String
    EngineVersion: Optional[String]
    Port: Optional[IntegerOptional]
    MasterUsername: String
    MasterUserPassword: String
    OptionGroupName: Optional[String]
    PreferredBackupWindow: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    Tags: Optional[TagList]
    StorageEncrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    SourceEngine: String
    SourceEngineVersion: String
    S3BucketName: String
    S3Prefix: Optional[String]
    S3IngestionRoleArn: String
    BacktrackWindow: Optional[LongOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DeletionProtection: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]


class RestoreDBClusterFromS3Result(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


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
    BacktrackWindow: Optional[LongOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    EngineMode: Optional[String]
    ScalingConfiguration: Optional[ScalingConfiguration]
    DBClusterParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    DBClusterInstanceClass: Optional[String]
    StorageType: Optional[String]
    Iops: Optional[IntegerOptional]
    PubliclyAccessible: Optional[BooleanOptional]


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
    BacktrackWindow: Optional[LongOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    DBClusterParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    ScalingConfiguration: Optional[ScalingConfiguration]
    EngineMode: Optional[String]
    DBClusterInstanceClass: Optional[String]
    StorageType: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    Iops: Optional[IntegerOptional]


class RestoreDBClusterToPointInTimeResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class RestoreDBInstanceFromDBSnapshotMessage(ServiceRequest):
    DBInstanceIdentifier: String
    DBSnapshotIdentifier: String
    DBInstanceClass: Optional[String]
    Port: Optional[IntegerOptional]
    AvailabilityZone: Optional[String]
    DBSubnetGroupName: Optional[String]
    MultiAZ: Optional[BooleanOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    LicenseModel: Optional[String]
    DBName: Optional[String]
    Engine: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    Tags: Optional[TagList]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    TdeCredentialPassword: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Domain: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    DomainIAMRoleName: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    UseDefaultProcessorFeatures: Optional[BooleanOptional]
    DBParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    EnableCustomerOwnedIp: Optional[BooleanOptional]
    CustomIamInstanceProfile: Optional[String]
    BackupTarget: Optional[String]


class RestoreDBInstanceFromDBSnapshotResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RestoreDBInstanceFromS3Message(ServiceRequest):
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
    PubliclyAccessible: Optional[BooleanOptional]
    Tags: Optional[TagList]
    StorageType: Optional[String]
    StorageEncrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    MonitoringInterval: Optional[IntegerOptional]
    MonitoringRoleArn: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    SourceEngine: String
    SourceEngineVersion: String
    S3BucketName: String
    S3Prefix: Optional[String]
    S3IngestionRoleArn: String
    EnablePerformanceInsights: Optional[BooleanOptional]
    PerformanceInsightsKMSKeyId: Optional[String]
    PerformanceInsightsRetentionPeriod: Optional[IntegerOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    UseDefaultProcessorFeatures: Optional[BooleanOptional]
    DeletionProtection: Optional[BooleanOptional]
    MaxAllocatedStorage: Optional[IntegerOptional]


class RestoreDBInstanceFromS3Result(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RestoreDBInstanceToPointInTimeMessage(ServiceRequest):
    SourceDBInstanceIdentifier: Optional[String]
    TargetDBInstanceIdentifier: String
    RestoreTime: Optional[TStamp]
    UseLatestRestorableTime: Optional[Boolean]
    DBInstanceClass: Optional[String]
    Port: Optional[IntegerOptional]
    AvailabilityZone: Optional[String]
    DBSubnetGroupName: Optional[String]
    MultiAZ: Optional[BooleanOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    AutoMinorVersionUpgrade: Optional[BooleanOptional]
    LicenseModel: Optional[String]
    DBName: Optional[String]
    Engine: Optional[String]
    Iops: Optional[IntegerOptional]
    OptionGroupName: Optional[String]
    CopyTagsToSnapshot: Optional[BooleanOptional]
    Tags: Optional[TagList]
    StorageType: Optional[String]
    TdeCredentialArn: Optional[String]
    TdeCredentialPassword: Optional[String]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    Domain: Optional[String]
    DomainIAMRoleName: Optional[String]
    EnableIAMDatabaseAuthentication: Optional[BooleanOptional]
    EnableCloudwatchLogsExports: Optional[LogTypeList]
    ProcessorFeatures: Optional[ProcessorFeatureList]
    UseDefaultProcessorFeatures: Optional[BooleanOptional]
    DBParameterGroupName: Optional[String]
    DeletionProtection: Optional[BooleanOptional]
    SourceDbiResourceId: Optional[String]
    MaxAllocatedStorage: Optional[IntegerOptional]
    SourceDBInstanceAutomatedBackupsArn: Optional[String]
    EnableCustomerOwnedIp: Optional[BooleanOptional]
    CustomIamInstanceProfile: Optional[String]
    BackupTarget: Optional[String]


class RestoreDBInstanceToPointInTimeResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class RevokeDBSecurityGroupIngressMessage(ServiceRequest):
    DBSecurityGroupName: String
    CIDRIP: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupId: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


class RevokeDBSecurityGroupIngressResult(TypedDict, total=False):
    DBSecurityGroup: Optional[DBSecurityGroup]


class SourceRegion(TypedDict, total=False):
    RegionName: Optional[String]
    Endpoint: Optional[String]
    Status: Optional[String]
    SupportsDBInstanceAutomatedBackupsReplication: Optional[Boolean]


SourceRegionList = List[SourceRegion]


class SourceRegionMessage(TypedDict, total=False):
    Marker: Optional[String]
    SourceRegions: Optional[SourceRegionList]


class StartActivityStreamRequest(ServiceRequest):
    ResourceArn: String
    Mode: ActivityStreamMode
    KmsKeyId: String
    ApplyImmediately: Optional[BooleanOptional]
    EngineNativeAuditFieldsIncluded: Optional[BooleanOptional]


class StartActivityStreamResponse(TypedDict, total=False):
    KmsKeyId: Optional[String]
    KinesisStreamName: Optional[String]
    Status: Optional[ActivityStreamStatus]
    Mode: Optional[ActivityStreamMode]
    ApplyImmediately: Optional[Boolean]
    EngineNativeAuditFieldsIncluded: Optional[BooleanOptional]


class StartDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class StartDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class StartDBInstanceAutomatedBackupsReplicationMessage(ServiceRequest):
    SourceDBInstanceArn: String
    BackupRetentionPeriod: Optional[IntegerOptional]
    KmsKeyId: Optional[String]
    PreSignedUrl: Optional[String]
    SourceRegion: Optional[String]


class StartDBInstanceAutomatedBackupsReplicationResult(TypedDict, total=False):
    DBInstanceAutomatedBackup: Optional[DBInstanceAutomatedBackup]


class StartDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String


class StartDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class StartExportTaskMessage(ServiceRequest):
    ExportTaskIdentifier: String
    SourceArn: String
    S3BucketName: String
    IamRoleArn: String
    KmsKeyId: String
    S3Prefix: Optional[String]
    ExportOnly: Optional[StringList]


class StopActivityStreamRequest(ServiceRequest):
    ResourceArn: String
    ApplyImmediately: Optional[BooleanOptional]


class StopActivityStreamResponse(TypedDict, total=False):
    KmsKeyId: Optional[String]
    KinesisStreamName: Optional[String]
    Status: Optional[ActivityStreamStatus]


class StopDBClusterMessage(ServiceRequest):
    DBClusterIdentifier: String


class StopDBClusterResult(TypedDict, total=False):
    DBCluster: Optional[DBCluster]


class StopDBInstanceAutomatedBackupsReplicationMessage(ServiceRequest):
    SourceDBInstanceArn: String


class StopDBInstanceAutomatedBackupsReplicationResult(TypedDict, total=False):
    DBInstanceAutomatedBackup: Optional[DBInstanceAutomatedBackup]


class StopDBInstanceMessage(ServiceRequest):
    DBInstanceIdentifier: String
    DBSnapshotIdentifier: Optional[String]


class StopDBInstanceResult(TypedDict, total=False):
    DBInstance: Optional[DBInstance]


class TagListMessage(TypedDict, total=False):
    TagList: Optional[TagList]


class RdsApi:

    service = "rds"
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

    @handler("AddRoleToDBInstance")
    def add_role_to_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        role_arn: String,
        feature_name: String,
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

    @handler("AuthorizeDBSecurityGroupIngress")
    def authorize_db_security_group_ingress(
        self,
        context: RequestContext,
        db_security_group_name: String,
        cidrip: String = None,
        ec2_security_group_name: String = None,
        ec2_security_group_id: String = None,
        ec2_security_group_owner_id: String = None,
    ) -> AuthorizeDBSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("BacktrackDBCluster")
    def backtrack_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        backtrack_to: TStamp,
        force: BooleanOptional = None,
        use_earliest_time_on_point_in_time_unavailable: BooleanOptional = None,
    ) -> DBClusterBacktrack:
        raise NotImplementedError

    @handler("CancelExportTask")
    def cancel_export_task(
        self, context: RequestContext, export_task_identifier: String
    ) -> ExportTask:
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

    @handler("CopyDBSnapshot")
    def copy_db_snapshot(
        self,
        context: RequestContext,
        source_db_snapshot_identifier: String,
        target_db_snapshot_identifier: String,
        kms_key_id: String = None,
        tags: TagList = None,
        copy_tags: BooleanOptional = None,
        pre_signed_url: String = None,
        option_group_name: String = None,
        target_custom_availability_zone: String = None,
        source_region: String = None,
    ) -> CopyDBSnapshotResult:
        raise NotImplementedError

    @handler("CopyOptionGroup")
    def copy_option_group(
        self,
        context: RequestContext,
        source_option_group_identifier: String,
        target_option_group_identifier: String,
        target_option_group_description: String,
        tags: TagList = None,
    ) -> CopyOptionGroupResult:
        raise NotImplementedError

    @handler("CreateCustomAvailabilityZone")
    def create_custom_availability_zone(
        self,
        context: RequestContext,
        custom_availability_zone_name: String,
        existing_vpn_id: String = None,
        new_vpn_tunnel_name: String = None,
        vpn_tunnel_originator_ip: String = None,
    ) -> CreateCustomAvailabilityZoneResult:
        raise NotImplementedError

    @handler("CreateCustomDBEngineVersion")
    def create_custom_db_engine_version(
        self,
        context: RequestContext,
        engine: CustomEngineName,
        engine_version: CustomEngineVersion,
        database_installation_files_s3_bucket_name: BucketName,
        kms_key_id: KmsKeyIdOrArn,
        manifest: CustomDBEngineVersionManifest,
        database_installation_files_s3_prefix: String255 = None,
        description: Description = None,
        tags: TagList = None,
    ) -> DBEngineVersion:
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
        backtrack_window: LongOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        engine_mode: String = None,
        scaling_configuration: ScalingConfiguration = None,
        deletion_protection: BooleanOptional = None,
        global_cluster_identifier: String = None,
        enable_http_endpoint: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        enable_global_write_forwarding: BooleanOptional = None,
        db_cluster_instance_class: String = None,
        allocated_storage: IntegerOptional = None,
        storage_type: String = None,
        iops: IntegerOptional = None,
        publicly_accessible: BooleanOptional = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        monitoring_role_arn: String = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        performance_insights_retention_period: IntegerOptional = None,
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
    ) -> DBClusterEndpoint:
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
        nchar_character_set_name: String = None,
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
        performance_insights_retention_period: IntegerOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        processor_features: ProcessorFeatureList = None,
        deletion_protection: BooleanOptional = None,
        max_allocated_storage: IntegerOptional = None,
        enable_customer_owned_ip: BooleanOptional = None,
        custom_iam_instance_profile: String = None,
        backup_target: String = None,
    ) -> CreateDBInstanceResult:
        raise NotImplementedError

    @handler("CreateDBInstanceReadReplica")
    def create_db_instance_read_replica(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        source_db_instance_identifier: String,
        db_instance_class: String = None,
        availability_zone: String = None,
        port: IntegerOptional = None,
        multi_az: BooleanOptional = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        iops: IntegerOptional = None,
        option_group_name: String = None,
        db_parameter_group_name: String = None,
        publicly_accessible: BooleanOptional = None,
        tags: TagList = None,
        db_subnet_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        storage_type: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        monitoring_role_arn: String = None,
        kms_key_id: String = None,
        pre_signed_url: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        performance_insights_retention_period: IntegerOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        processor_features: ProcessorFeatureList = None,
        use_default_processor_features: BooleanOptional = None,
        deletion_protection: BooleanOptional = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        replica_mode: ReplicaMode = None,
        max_allocated_storage: IntegerOptional = None,
        custom_iam_instance_profile: String = None,
        source_region: String = None,
    ) -> CreateDBInstanceReadReplicaResult:
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

    @handler("CreateDBProxy")
    def create_db_proxy(
        self,
        context: RequestContext,
        db_proxy_name: String,
        engine_family: EngineFamily,
        auth: UserAuthConfigList,
        role_arn: String,
        vpc_subnet_ids: StringList,
        vpc_security_group_ids: StringList = None,
        require_tls: Boolean = None,
        idle_client_timeout: IntegerOptional = None,
        debug_logging: Boolean = None,
        tags: TagList = None,
    ) -> CreateDBProxyResponse:
        raise NotImplementedError

    @handler("CreateDBProxyEndpoint")
    def create_db_proxy_endpoint(
        self,
        context: RequestContext,
        db_proxy_name: DBProxyName,
        db_proxy_endpoint_name: DBProxyEndpointName,
        vpc_subnet_ids: StringList,
        vpc_security_group_ids: StringList = None,
        target_role: DBProxyEndpointTargetRole = None,
        tags: TagList = None,
    ) -> CreateDBProxyEndpointResponse:
        raise NotImplementedError

    @handler("CreateDBSecurityGroup")
    def create_db_security_group(
        self,
        context: RequestContext,
        db_security_group_name: String,
        db_security_group_description: String,
        tags: TagList = None,
    ) -> CreateDBSecurityGroupResult:
        raise NotImplementedError

    @handler("CreateDBSnapshot")
    def create_db_snapshot(
        self,
        context: RequestContext,
        db_snapshot_identifier: String,
        db_instance_identifier: String,
        tags: TagList = None,
    ) -> CreateDBSnapshotResult:
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
        global_cluster_identifier: String = None,
        source_db_cluster_identifier: String = None,
        engine: String = None,
        engine_version: String = None,
        deletion_protection: BooleanOptional = None,
        database_name: String = None,
        storage_encrypted: BooleanOptional = None,
    ) -> CreateGlobalClusterResult:
        raise NotImplementedError

    @handler("CreateOptionGroup")
    def create_option_group(
        self,
        context: RequestContext,
        option_group_name: String,
        engine_name: String,
        major_engine_version: String,
        option_group_description: String,
        tags: TagList = None,
    ) -> CreateOptionGroupResult:
        raise NotImplementedError

    @handler("DeleteCustomAvailabilityZone")
    def delete_custom_availability_zone(
        self, context: RequestContext, custom_availability_zone_id: String
    ) -> DeleteCustomAvailabilityZoneResult:
        raise NotImplementedError

    @handler("DeleteCustomDBEngineVersion")
    def delete_custom_db_engine_version(
        self, context: RequestContext, engine: CustomEngineName, engine_version: CustomEngineVersion
    ) -> DBEngineVersion:
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
    ) -> DBClusterEndpoint:
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
        delete_automated_backups: BooleanOptional = None,
    ) -> DeleteDBInstanceResult:
        raise NotImplementedError

    @handler("DeleteDBInstanceAutomatedBackup")
    def delete_db_instance_automated_backup(
        self,
        context: RequestContext,
        dbi_resource_id: String = None,
        db_instance_automated_backups_arn: String = None,
    ) -> DeleteDBInstanceAutomatedBackupResult:
        raise NotImplementedError

    @handler("DeleteDBParameterGroup")
    def delete_db_parameter_group(
        self, context: RequestContext, db_parameter_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDBProxy")
    def delete_db_proxy(
        self, context: RequestContext, db_proxy_name: String
    ) -> DeleteDBProxyResponse:
        raise NotImplementedError

    @handler("DeleteDBProxyEndpoint")
    def delete_db_proxy_endpoint(
        self, context: RequestContext, db_proxy_endpoint_name: DBProxyEndpointName
    ) -> DeleteDBProxyEndpointResponse:
        raise NotImplementedError

    @handler("DeleteDBSecurityGroup")
    def delete_db_security_group(
        self, context: RequestContext, db_security_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDBSnapshot")
    def delete_db_snapshot(
        self, context: RequestContext, db_snapshot_identifier: String
    ) -> DeleteDBSnapshotResult:
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
        self, context: RequestContext, global_cluster_identifier: String
    ) -> DeleteGlobalClusterResult:
        raise NotImplementedError

    @handler("DeleteInstallationMedia")
    def delete_installation_media(
        self, context: RequestContext, installation_media_id: String
    ) -> InstallationMedia:
        raise NotImplementedError

    @handler("DeleteOptionGroup")
    def delete_option_group(self, context: RequestContext, option_group_name: String) -> None:
        raise NotImplementedError

    @handler("DeregisterDBProxyTargets")
    def deregister_db_proxy_targets(
        self,
        context: RequestContext,
        db_proxy_name: String,
        target_group_name: String = None,
        db_instance_identifiers: StringList = None,
        db_cluster_identifiers: StringList = None,
    ) -> DeregisterDBProxyTargetsResponse:
        raise NotImplementedError

    @handler("DescribeAccountAttributes")
    def describe_account_attributes(
        self,
        context: RequestContext,
    ) -> AccountAttributesMessage:
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

    @handler("DescribeCustomAvailabilityZones")
    def describe_custom_availability_zones(
        self,
        context: RequestContext,
        custom_availability_zone_id: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> CustomAvailabilityZoneMessage:
        raise NotImplementedError

    @handler("DescribeDBClusterBacktracks")
    def describe_db_cluster_backtracks(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        backtrack_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBClusterBacktrackMessage:
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
        include_shared: Boolean = None,
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
        include_all: BooleanOptional = None,
    ) -> DBEngineVersionMessage:
        raise NotImplementedError

    @handler("DescribeDBInstanceAutomatedBackups")
    def describe_db_instance_automated_backups(
        self,
        context: RequestContext,
        dbi_resource_id: String = None,
        db_instance_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        db_instance_automated_backups_arn: String = None,
    ) -> DBInstanceAutomatedBackupMessage:
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

    @handler("DescribeDBLogFiles")
    def describe_db_log_files(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        filename_contains: String = None,
        file_last_written: Long = None,
        file_size: Long = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeDBLogFilesResponse:
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

    @handler("DescribeDBProxies")
    def describe_db_proxies(
        self,
        context: RequestContext,
        db_proxy_name: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: MaxRecords = None,
    ) -> DescribeDBProxiesResponse:
        raise NotImplementedError

    @handler("DescribeDBProxyEndpoints")
    def describe_db_proxy_endpoints(
        self,
        context: RequestContext,
        db_proxy_name: DBProxyName = None,
        db_proxy_endpoint_name: DBProxyEndpointName = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: MaxRecords = None,
    ) -> DescribeDBProxyEndpointsResponse:
        raise NotImplementedError

    @handler("DescribeDBProxyTargetGroups")
    def describe_db_proxy_target_groups(
        self,
        context: RequestContext,
        db_proxy_name: String,
        target_group_name: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: MaxRecords = None,
    ) -> DescribeDBProxyTargetGroupsResponse:
        raise NotImplementedError

    @handler("DescribeDBProxyTargets")
    def describe_db_proxy_targets(
        self,
        context: RequestContext,
        db_proxy_name: String,
        target_group_name: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: MaxRecords = None,
    ) -> DescribeDBProxyTargetsResponse:
        raise NotImplementedError

    @handler("DescribeDBSecurityGroups")
    def describe_db_security_groups(
        self,
        context: RequestContext,
        db_security_group_name: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DBSecurityGroupMessage:
        raise NotImplementedError

    @handler("DescribeDBSnapshotAttributes")
    def describe_db_snapshot_attributes(
        self, context: RequestContext, db_snapshot_identifier: String
    ) -> DescribeDBSnapshotAttributesResult:
        raise NotImplementedError

    @handler("DescribeDBSnapshots")
    def describe_db_snapshots(
        self,
        context: RequestContext,
        db_instance_identifier: String = None,
        db_snapshot_identifier: String = None,
        snapshot_type: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        include_shared: Boolean = None,
        include_public: Boolean = None,
        dbi_resource_id: String = None,
    ) -> DBSnapshotMessage:
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

    @handler("DescribeExportTasks")
    def describe_export_tasks(
        self,
        context: RequestContext,
        export_task_identifier: String = None,
        source_arn: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: MaxRecords = None,
    ) -> ExportTasksMessage:
        raise NotImplementedError

    @handler("DescribeGlobalClusters")
    def describe_global_clusters(
        self,
        context: RequestContext,
        global_cluster_identifier: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> GlobalClustersMessage:
        raise NotImplementedError

    @handler("DescribeInstallationMedia")
    def describe_installation_media(
        self,
        context: RequestContext,
        installation_media_id: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> InstallationMediaMessage:
        raise NotImplementedError

    @handler("DescribeOptionGroupOptions")
    def describe_option_group_options(
        self,
        context: RequestContext,
        engine_name: String,
        major_engine_version: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> OptionGroupOptionsMessage:
        raise NotImplementedError

    @handler("DescribeOptionGroups")
    def describe_option_groups(
        self,
        context: RequestContext,
        option_group_name: String = None,
        filters: FilterList = None,
        marker: String = None,
        max_records: IntegerOptional = None,
        engine_name: String = None,
        major_engine_version: String = None,
    ) -> OptionGroups:
        raise NotImplementedError

    @handler("DescribeOrderableDBInstanceOptions")
    def describe_orderable_db_instance_options(
        self,
        context: RequestContext,
        engine: String,
        engine_version: String = None,
        db_instance_class: String = None,
        license_model: String = None,
        availability_zone_group: String = None,
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

    @handler("DescribeReservedDBInstances")
    def describe_reserved_db_instances(
        self,
        context: RequestContext,
        reserved_db_instance_id: String = None,
        reserved_db_instances_offering_id: String = None,
        db_instance_class: String = None,
        duration: String = None,
        product_description: String = None,
        offering_type: String = None,
        multi_az: BooleanOptional = None,
        lease_id: String = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedDBInstanceMessage:
        raise NotImplementedError

    @handler("DescribeReservedDBInstancesOfferings")
    def describe_reserved_db_instances_offerings(
        self,
        context: RequestContext,
        reserved_db_instances_offering_id: String = None,
        db_instance_class: String = None,
        duration: String = None,
        product_description: String = None,
        offering_type: String = None,
        multi_az: BooleanOptional = None,
        filters: FilterList = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedDBInstancesOfferingMessage:
        raise NotImplementedError

    @handler("DescribeSourceRegions")
    def describe_source_regions(
        self,
        context: RequestContext,
        region_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        filters: FilterList = None,
    ) -> SourceRegionMessage:
        raise NotImplementedError

    @handler("DescribeValidDBInstanceModifications")
    def describe_valid_db_instance_modifications(
        self, context: RequestContext, db_instance_identifier: String
    ) -> DescribeValidDBInstanceModificationsResult:
        raise NotImplementedError

    @handler("DownloadDBLogFilePortion")
    def download_db_log_file_portion(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        log_file_name: String,
        marker: String = None,
        number_of_lines: Integer = None,
    ) -> DownloadDBLogFilePortionDetails:
        raise NotImplementedError

    @handler("FailoverDBCluster")
    def failover_db_cluster(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        target_db_instance_identifier: String = None,
    ) -> FailoverDBClusterResult:
        raise NotImplementedError

    @handler("FailoverGlobalCluster")
    def failover_global_cluster(
        self,
        context: RequestContext,
        global_cluster_identifier: GlobalClusterIdentifier,
        target_db_cluster_identifier: DBClusterIdentifier,
    ) -> FailoverGlobalClusterResult:
        raise NotImplementedError

    @handler("ImportInstallationMedia")
    def import_installation_media(
        self,
        context: RequestContext,
        custom_availability_zone_id: String,
        engine: String,
        engine_version: String,
        engine_installation_media_path: String,
        os_installation_media_path: String,
    ) -> InstallationMedia:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_name: String, filters: FilterList = None
    ) -> TagListMessage:
        raise NotImplementedError

    @handler("ModifyCertificates")
    def modify_certificates(
        self,
        context: RequestContext,
        certificate_identifier: String = None,
        remove_customer_override: BooleanOptional = None,
    ) -> ModifyCertificatesResult:
        raise NotImplementedError

    @handler("ModifyCurrentDBClusterCapacity")
    def modify_current_db_cluster_capacity(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        capacity: IntegerOptional = None,
        seconds_before_timeout: IntegerOptional = None,
        timeout_action: String = None,
    ) -> DBClusterCapacityInfo:
        raise NotImplementedError

    @handler("ModifyCustomDBEngineVersion")
    def modify_custom_db_engine_version(
        self,
        context: RequestContext,
        engine: CustomEngineName,
        engine_version: CustomEngineVersion,
        description: Description = None,
        status: CustomEngineVersionStatus = None,
    ) -> DBEngineVersion:
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
        backtrack_window: LongOptional = None,
        cloudwatch_logs_export_configuration: CloudwatchLogsExportConfiguration = None,
        engine_version: String = None,
        allow_major_version_upgrade: Boolean = None,
        db_instance_parameter_group_name: String = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        scaling_configuration: ScalingConfiguration = None,
        deletion_protection: BooleanOptional = None,
        enable_http_endpoint: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        enable_global_write_forwarding: BooleanOptional = None,
        db_cluster_instance_class: String = None,
        allocated_storage: IntegerOptional = None,
        storage_type: String = None,
        iops: IntegerOptional = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        monitoring_role_arn: String = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        performance_insights_retention_period: IntegerOptional = None,
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
    ) -> DBClusterEndpoint:
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
        performance_insights_retention_period: IntegerOptional = None,
        cloudwatch_logs_export_configuration: CloudwatchLogsExportConfiguration = None,
        processor_features: ProcessorFeatureList = None,
        use_default_processor_features: BooleanOptional = None,
        deletion_protection: BooleanOptional = None,
        max_allocated_storage: IntegerOptional = None,
        certificate_rotation_restart: BooleanOptional = None,
        replica_mode: ReplicaMode = None,
        enable_customer_owned_ip: BooleanOptional = None,
        aws_backup_recovery_point_arn: AwsBackupRecoveryPointArn = None,
        automation_mode: AutomationMode = None,
        resume_full_automation_mode_minutes: IntegerOptional = None,
    ) -> ModifyDBInstanceResult:
        raise NotImplementedError

    @handler("ModifyDBParameterGroup")
    def modify_db_parameter_group(
        self, context: RequestContext, db_parameter_group_name: String, parameters: ParametersList
    ) -> DBParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyDBProxy")
    def modify_db_proxy(
        self,
        context: RequestContext,
        db_proxy_name: String,
        new_db_proxy_name: String = None,
        auth: UserAuthConfigList = None,
        require_tls: BooleanOptional = None,
        idle_client_timeout: IntegerOptional = None,
        debug_logging: BooleanOptional = None,
        role_arn: String = None,
        security_groups: StringList = None,
    ) -> ModifyDBProxyResponse:
        raise NotImplementedError

    @handler("ModifyDBProxyEndpoint")
    def modify_db_proxy_endpoint(
        self,
        context: RequestContext,
        db_proxy_endpoint_name: DBProxyEndpointName,
        new_db_proxy_endpoint_name: DBProxyEndpointName = None,
        vpc_security_group_ids: StringList = None,
    ) -> ModifyDBProxyEndpointResponse:
        raise NotImplementedError

    @handler("ModifyDBProxyTargetGroup")
    def modify_db_proxy_target_group(
        self,
        context: RequestContext,
        target_group_name: String,
        db_proxy_name: String,
        connection_pool_config: ConnectionPoolConfiguration = None,
        new_name: String = None,
    ) -> ModifyDBProxyTargetGroupResponse:
        raise NotImplementedError

    @handler("ModifyDBSnapshot")
    def modify_db_snapshot(
        self,
        context: RequestContext,
        db_snapshot_identifier: String,
        engine_version: String = None,
        option_group_name: String = None,
    ) -> ModifyDBSnapshotResult:
        raise NotImplementedError

    @handler("ModifyDBSnapshotAttribute")
    def modify_db_snapshot_attribute(
        self,
        context: RequestContext,
        db_snapshot_identifier: String,
        attribute_name: String,
        values_to_add: AttributeValueList = None,
        values_to_remove: AttributeValueList = None,
    ) -> ModifyDBSnapshotAttributeResult:
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
        global_cluster_identifier: String = None,
        new_global_cluster_identifier: String = None,
        deletion_protection: BooleanOptional = None,
        engine_version: String = None,
        allow_major_version_upgrade: BooleanOptional = None,
    ) -> ModifyGlobalClusterResult:
        raise NotImplementedError

    @handler("ModifyOptionGroup")
    def modify_option_group(
        self,
        context: RequestContext,
        option_group_name: String,
        options_to_include: OptionConfigurationList = None,
        options_to_remove: OptionNamesList = None,
        apply_immediately: Boolean = None,
    ) -> ModifyOptionGroupResult:
        raise NotImplementedError

    @handler("PromoteReadReplica")
    def promote_read_replica(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        backup_retention_period: IntegerOptional = None,
        preferred_backup_window: String = None,
    ) -> PromoteReadReplicaResult:
        raise NotImplementedError

    @handler("PromoteReadReplicaDBCluster")
    def promote_read_replica_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> PromoteReadReplicaDBClusterResult:
        raise NotImplementedError

    @handler("PurchaseReservedDBInstancesOffering")
    def purchase_reserved_db_instances_offering(
        self,
        context: RequestContext,
        reserved_db_instances_offering_id: String,
        reserved_db_instance_id: String = None,
        db_instance_count: IntegerOptional = None,
        tags: TagList = None,
    ) -> PurchaseReservedDBInstancesOfferingResult:
        raise NotImplementedError

    @handler("RebootDBCluster")
    def reboot_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> RebootDBClusterResult:
        raise NotImplementedError

    @handler("RebootDBInstance")
    def reboot_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        force_failover: BooleanOptional = None,
    ) -> RebootDBInstanceResult:
        raise NotImplementedError

    @handler("RegisterDBProxyTargets")
    def register_db_proxy_targets(
        self,
        context: RequestContext,
        db_proxy_name: String,
        target_group_name: String = None,
        db_instance_identifiers: StringList = None,
        db_cluster_identifiers: StringList = None,
    ) -> RegisterDBProxyTargetsResponse:
        raise NotImplementedError

    @handler("RemoveFromGlobalCluster")
    def remove_from_global_cluster(
        self,
        context: RequestContext,
        global_cluster_identifier: String = None,
        db_cluster_identifier: String = None,
    ) -> RemoveFromGlobalClusterResult:
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

    @handler("RemoveRoleFromDBInstance")
    def remove_role_from_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        role_arn: String,
        feature_name: String,
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

    @handler("RestoreDBClusterFromS3")
    def restore_db_cluster_from_s3(
        self,
        context: RequestContext,
        db_cluster_identifier: String,
        engine: String,
        master_username: String,
        master_user_password: String,
        source_engine: String,
        source_engine_version: String,
        s3_bucket_name: String,
        s3_ingestion_role_arn: String,
        availability_zones: AvailabilityZones = None,
        backup_retention_period: IntegerOptional = None,
        character_set_name: String = None,
        database_name: String = None,
        db_cluster_parameter_group_name: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        db_subnet_group_name: String = None,
        engine_version: String = None,
        port: IntegerOptional = None,
        option_group_name: String = None,
        preferred_backup_window: String = None,
        preferred_maintenance_window: String = None,
        tags: TagList = None,
        storage_encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        s3_prefix: String = None,
        backtrack_window: LongOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        deletion_protection: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        domain: String = None,
        domain_iam_role_name: String = None,
    ) -> RestoreDBClusterFromS3Result:
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
        backtrack_window: LongOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        engine_mode: String = None,
        scaling_configuration: ScalingConfiguration = None,
        db_cluster_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        db_cluster_instance_class: String = None,
        storage_type: String = None,
        iops: IntegerOptional = None,
        publicly_accessible: BooleanOptional = None,
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
        backtrack_window: LongOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        db_cluster_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        scaling_configuration: ScalingConfiguration = None,
        engine_mode: String = None,
        db_cluster_instance_class: String = None,
        storage_type: String = None,
        publicly_accessible: BooleanOptional = None,
        iops: IntegerOptional = None,
    ) -> RestoreDBClusterToPointInTimeResult:
        raise NotImplementedError

    @handler("RestoreDBInstanceFromDBSnapshot")
    def restore_db_instance_from_db_snapshot(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        db_snapshot_identifier: String,
        db_instance_class: String = None,
        port: IntegerOptional = None,
        availability_zone: String = None,
        db_subnet_group_name: String = None,
        multi_az: BooleanOptional = None,
        publicly_accessible: BooleanOptional = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        license_model: String = None,
        db_name: String = None,
        engine: String = None,
        iops: IntegerOptional = None,
        option_group_name: String = None,
        tags: TagList = None,
        storage_type: String = None,
        tde_credential_arn: String = None,
        tde_credential_password: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        domain: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        domain_iam_role_name: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        processor_features: ProcessorFeatureList = None,
        use_default_processor_features: BooleanOptional = None,
        db_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        enable_customer_owned_ip: BooleanOptional = None,
        custom_iam_instance_profile: String = None,
        backup_target: String = None,
    ) -> RestoreDBInstanceFromDBSnapshotResult:
        raise NotImplementedError

    @handler("RestoreDBInstanceFromS3")
    def restore_db_instance_from_s3(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        db_instance_class: String,
        engine: String,
        source_engine: String,
        source_engine_version: String,
        s3_bucket_name: String,
        s3_ingestion_role_arn: String,
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
        publicly_accessible: BooleanOptional = None,
        tags: TagList = None,
        storage_type: String = None,
        storage_encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        monitoring_interval: IntegerOptional = None,
        monitoring_role_arn: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        s3_prefix: String = None,
        enable_performance_insights: BooleanOptional = None,
        performance_insights_kms_key_id: String = None,
        performance_insights_retention_period: IntegerOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        processor_features: ProcessorFeatureList = None,
        use_default_processor_features: BooleanOptional = None,
        deletion_protection: BooleanOptional = None,
        max_allocated_storage: IntegerOptional = None,
    ) -> RestoreDBInstanceFromS3Result:
        raise NotImplementedError

    @handler("RestoreDBInstanceToPointInTime")
    def restore_db_instance_to_point_in_time(
        self,
        context: RequestContext,
        target_db_instance_identifier: String,
        source_db_instance_identifier: String = None,
        restore_time: TStamp = None,
        use_latest_restorable_time: Boolean = None,
        db_instance_class: String = None,
        port: IntegerOptional = None,
        availability_zone: String = None,
        db_subnet_group_name: String = None,
        multi_az: BooleanOptional = None,
        publicly_accessible: BooleanOptional = None,
        auto_minor_version_upgrade: BooleanOptional = None,
        license_model: String = None,
        db_name: String = None,
        engine: String = None,
        iops: IntegerOptional = None,
        option_group_name: String = None,
        copy_tags_to_snapshot: BooleanOptional = None,
        tags: TagList = None,
        storage_type: String = None,
        tde_credential_arn: String = None,
        tde_credential_password: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        domain: String = None,
        domain_iam_role_name: String = None,
        enable_iam_database_authentication: BooleanOptional = None,
        enable_cloudwatch_logs_exports: LogTypeList = None,
        processor_features: ProcessorFeatureList = None,
        use_default_processor_features: BooleanOptional = None,
        db_parameter_group_name: String = None,
        deletion_protection: BooleanOptional = None,
        source_dbi_resource_id: String = None,
        max_allocated_storage: IntegerOptional = None,
        source_db_instance_automated_backups_arn: String = None,
        enable_customer_owned_ip: BooleanOptional = None,
        custom_iam_instance_profile: String = None,
        backup_target: String = None,
    ) -> RestoreDBInstanceToPointInTimeResult:
        raise NotImplementedError

    @handler("RevokeDBSecurityGroupIngress")
    def revoke_db_security_group_ingress(
        self,
        context: RequestContext,
        db_security_group_name: String,
        cidrip: String = None,
        ec2_security_group_name: String = None,
        ec2_security_group_id: String = None,
        ec2_security_group_owner_id: String = None,
    ) -> RevokeDBSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("StartActivityStream")
    def start_activity_stream(
        self,
        context: RequestContext,
        resource_arn: String,
        mode: ActivityStreamMode,
        kms_key_id: String,
        apply_immediately: BooleanOptional = None,
        engine_native_audit_fields_included: BooleanOptional = None,
    ) -> StartActivityStreamResponse:
        raise NotImplementedError

    @handler("StartDBCluster")
    def start_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> StartDBClusterResult:
        raise NotImplementedError

    @handler("StartDBInstance")
    def start_db_instance(
        self, context: RequestContext, db_instance_identifier: String
    ) -> StartDBInstanceResult:
        raise NotImplementedError

    @handler("StartDBInstanceAutomatedBackupsReplication")
    def start_db_instance_automated_backups_replication(
        self,
        context: RequestContext,
        source_db_instance_arn: String,
        backup_retention_period: IntegerOptional = None,
        kms_key_id: String = None,
        pre_signed_url: String = None,
        source_region: String = None,
    ) -> StartDBInstanceAutomatedBackupsReplicationResult:
        raise NotImplementedError

    @handler("StartExportTask")
    def start_export_task(
        self,
        context: RequestContext,
        export_task_identifier: String,
        source_arn: String,
        s3_bucket_name: String,
        iam_role_arn: String,
        kms_key_id: String,
        s3_prefix: String = None,
        export_only: StringList = None,
    ) -> ExportTask:
        raise NotImplementedError

    @handler("StopActivityStream")
    def stop_activity_stream(
        self,
        context: RequestContext,
        resource_arn: String,
        apply_immediately: BooleanOptional = None,
    ) -> StopActivityStreamResponse:
        raise NotImplementedError

    @handler("StopDBCluster")
    def stop_db_cluster(
        self, context: RequestContext, db_cluster_identifier: String
    ) -> StopDBClusterResult:
        raise NotImplementedError

    @handler("StopDBInstance")
    def stop_db_instance(
        self,
        context: RequestContext,
        db_instance_identifier: String,
        db_snapshot_identifier: String = None,
    ) -> StopDBInstanceResult:
        raise NotImplementedError

    @handler("StopDBInstanceAutomatedBackupsReplication")
    def stop_db_instance_automated_backups_replication(
        self, context: RequestContext, source_db_instance_arn: String
    ) -> StopDBInstanceAutomatedBackupsReplicationResult:
        raise NotImplementedError
