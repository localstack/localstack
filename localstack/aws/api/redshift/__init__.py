import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AuthenticationProfileNameString = str
Boolean = bool
BooleanOptional = bool
Double = float
DoubleOptional = float
Integer = int
IntegerOptional = int
PartnerIntegrationAccountId = str
PartnerIntegrationClusterIdentifier = str
PartnerIntegrationDatabaseName = str
PartnerIntegrationPartnerName = str
PartnerIntegrationStatusMessage = str
SensitiveString = str
String = str


class ActionType(str):
    restore_cluster = "restore-cluster"
    recommend_node_config = "recommend-node-config"
    resize_cluster = "resize-cluster"


class AquaConfigurationStatus(str):
    enabled = "enabled"
    disabled = "disabled"
    auto = "auto"


class AquaStatus(str):
    enabled = "enabled"
    disabled = "disabled"
    applying = "applying"


class AuthorizationStatus(str):
    Authorized = "Authorized"
    Revoking = "Revoking"


class DataShareStatus(str):
    ACTIVE = "ACTIVE"
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    DEAUTHORIZED = "DEAUTHORIZED"
    REJECTED = "REJECTED"
    AVAILABLE = "AVAILABLE"


class DataShareStatusForConsumer(str):
    ACTIVE = "ACTIVE"
    AVAILABLE = "AVAILABLE"


class DataShareStatusForProducer(str):
    ACTIVE = "ACTIVE"
    AUTHORIZED = "AUTHORIZED"
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    DEAUTHORIZED = "DEAUTHORIZED"
    REJECTED = "REJECTED"


class Mode(str):
    standard = "standard"
    high_performance = "high-performance"


class NodeConfigurationOptionsFilterName(str):
    NodeType = "NodeType"
    NumberOfNodes = "NumberOfNodes"
    EstimatedDiskUtilizationPercent = "EstimatedDiskUtilizationPercent"
    Mode = "Mode"


class OperatorType(str):
    eq = "eq"
    lt = "lt"
    gt = "gt"
    le = "le"
    ge = "ge"
    in_ = "in"
    between = "between"


class ParameterApplyType(str):
    static = "static"
    dynamic = "dynamic"


class PartnerIntegrationStatus(str):
    Active = "Active"
    Inactive = "Inactive"
    RuntimeFailure = "RuntimeFailure"
    ConnectionFailure = "ConnectionFailure"


class ReservedNodeExchangeActionType(str):
    restore_cluster = "restore-cluster"
    resize_cluster = "resize-cluster"


class ReservedNodeExchangeStatusType(str):
    REQUESTED = "REQUESTED"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    RETRYING = "RETRYING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ReservedNodeOfferingType(str):
    Regular = "Regular"
    Upgradable = "Upgradable"


class ScheduleState(str):
    MODIFYING = "MODIFYING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class ScheduledActionFilterName(str):
    cluster_identifier = "cluster-identifier"
    iam_role = "iam-role"


class ScheduledActionState(str):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class ScheduledActionTypeValues(str):
    ResizeCluster = "ResizeCluster"
    PauseCluster = "PauseCluster"
    ResumeCluster = "ResumeCluster"


class SnapshotAttributeToSortBy(str):
    SOURCE_TYPE = "SOURCE_TYPE"
    TOTAL_SIZE = "TOTAL_SIZE"
    CREATE_TIME = "CREATE_TIME"


class SortByOrder(str):
    ASC = "ASC"
    DESC = "DESC"


class SourceType(str):
    cluster = "cluster"
    cluster_parameter_group = "cluster-parameter-group"
    cluster_security_group = "cluster-security-group"
    cluster_snapshot = "cluster-snapshot"
    scheduled_action = "scheduled-action"


class TableRestoreStatusType(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class UsageLimitBreachAction(str):
    log = "log"
    emit_metric = "emit-metric"
    disable = "disable"


class UsageLimitFeatureType(str):
    spectrum = "spectrum"
    concurrency_scaling = "concurrency-scaling"


class UsageLimitLimitType(str):
    time = "time"
    data_scanned = "data-scanned"


class UsageLimitPeriod(str):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class AccessToClusterDeniedFault(ServiceException):
    pass


class AccessToSnapshotDeniedFault(ServiceException):
    pass


class AuthenticationProfileAlreadyExistsFault(ServiceException):
    pass


class AuthenticationProfileNotFoundFault(ServiceException):
    pass


class AuthenticationProfileQuotaExceededFault(ServiceException):
    pass


class AuthorizationAlreadyExistsFault(ServiceException):
    pass


class AuthorizationNotFoundFault(ServiceException):
    pass


class AuthorizationQuotaExceededFault(ServiceException):
    pass


class BatchDeleteRequestSizeExceededFault(ServiceException):
    pass


class BatchModifyClusterSnapshotsLimitExceededFault(ServiceException):
    pass


class BucketNotFoundFault(ServiceException):
    pass


class ClusterAlreadyExistsFault(ServiceException):
    pass


class ClusterNotFoundFault(ServiceException):
    pass


class ClusterOnLatestRevisionFault(ServiceException):
    pass


class ClusterParameterGroupAlreadyExistsFault(ServiceException):
    pass


class ClusterParameterGroupNotFoundFault(ServiceException):
    pass


class ClusterParameterGroupQuotaExceededFault(ServiceException):
    pass


class ClusterQuotaExceededFault(ServiceException):
    pass


class ClusterSecurityGroupAlreadyExistsFault(ServiceException):
    pass


class ClusterSecurityGroupNotFoundFault(ServiceException):
    pass


class ClusterSecurityGroupQuotaExceededFault(ServiceException):
    pass


class ClusterSnapshotAlreadyExistsFault(ServiceException):
    pass


class ClusterSnapshotNotFoundFault(ServiceException):
    pass


class ClusterSnapshotQuotaExceededFault(ServiceException):
    pass


class ClusterSubnetGroupAlreadyExistsFault(ServiceException):
    pass


class ClusterSubnetGroupNotFoundFault(ServiceException):
    pass


class ClusterSubnetGroupQuotaExceededFault(ServiceException):
    pass


class ClusterSubnetQuotaExceededFault(ServiceException):
    pass


class CopyToRegionDisabledFault(ServiceException):
    pass


class DependentServiceRequestThrottlingFault(ServiceException):
    pass


class DependentServiceUnavailableFault(ServiceException):
    pass


class EndpointAlreadyExistsFault(ServiceException):
    pass


class EndpointAuthorizationAlreadyExistsFault(ServiceException):
    pass


class EndpointAuthorizationNotFoundFault(ServiceException):
    pass


class EndpointAuthorizationsPerClusterLimitExceededFault(ServiceException):
    pass


class EndpointNotFoundFault(ServiceException):
    pass


class EndpointsPerAuthorizationLimitExceededFault(ServiceException):
    pass


class EndpointsPerClusterLimitExceededFault(ServiceException):
    pass


class EventSubscriptionQuotaExceededFault(ServiceException):
    pass


class HsmClientCertificateAlreadyExistsFault(ServiceException):
    pass


class HsmClientCertificateNotFoundFault(ServiceException):
    pass


class HsmClientCertificateQuotaExceededFault(ServiceException):
    pass


class HsmConfigurationAlreadyExistsFault(ServiceException):
    pass


class HsmConfigurationNotFoundFault(ServiceException):
    pass


class HsmConfigurationQuotaExceededFault(ServiceException):
    pass


class InProgressTableRestoreQuotaExceededFault(ServiceException):
    pass


class IncompatibleOrderableOptions(ServiceException):
    pass


class InsufficientClusterCapacityFault(ServiceException):
    pass


class InsufficientS3BucketPolicyFault(ServiceException):
    pass


class InvalidAuthenticationProfileRequestFault(ServiceException):
    pass


class InvalidAuthorizationStateFault(ServiceException):
    pass


class InvalidClusterParameterGroupStateFault(ServiceException):
    pass


class InvalidClusterSecurityGroupStateFault(ServiceException):
    pass


class InvalidClusterSnapshotScheduleStateFault(ServiceException):
    pass


class InvalidClusterSnapshotStateFault(ServiceException):
    pass


class InvalidClusterStateFault(ServiceException):
    pass


class InvalidClusterSubnetGroupStateFault(ServiceException):
    pass


class InvalidClusterSubnetStateFault(ServiceException):
    pass


class InvalidClusterTrackFault(ServiceException):
    pass


class InvalidDataShareFault(ServiceException):
    pass


class InvalidElasticIpFault(ServiceException):
    pass


class InvalidEndpointStateFault(ServiceException):
    pass


class InvalidHsmClientCertificateStateFault(ServiceException):
    pass


class InvalidHsmConfigurationStateFault(ServiceException):
    pass


class InvalidNamespaceFault(ServiceException):
    pass


class InvalidReservedNodeStateFault(ServiceException):
    pass


class InvalidRestoreFault(ServiceException):
    pass


class InvalidRetentionPeriodFault(ServiceException):
    pass


class InvalidS3BucketNameFault(ServiceException):
    pass


class InvalidS3KeyPrefixFault(ServiceException):
    pass


class InvalidScheduleFault(ServiceException):
    pass


class InvalidScheduledActionFault(ServiceException):
    pass


class InvalidSnapshotCopyGrantStateFault(ServiceException):
    pass


class InvalidSubnet(ServiceException):
    pass


class InvalidSubscriptionStateFault(ServiceException):
    pass


class InvalidTableRestoreArgumentFault(ServiceException):
    pass


class InvalidTagFault(ServiceException):
    pass


class InvalidUsageLimitFault(ServiceException):
    pass


class InvalidVPCNetworkStateFault(ServiceException):
    pass


class LimitExceededFault(ServiceException):
    pass


class NumberOfNodesPerClusterLimitExceededFault(ServiceException):
    pass


class NumberOfNodesQuotaExceededFault(ServiceException):
    pass


class PartnerNotFoundFault(ServiceException):
    pass


class ReservedNodeAlreadyExistsFault(ServiceException):
    pass


class ReservedNodeAlreadyMigratedFault(ServiceException):
    pass


class ReservedNodeExchangeNotFoundFault(ServiceException):
    pass


class ReservedNodeNotFoundFault(ServiceException):
    pass


class ReservedNodeOfferingNotFoundFault(ServiceException):
    pass


class ReservedNodeQuotaExceededFault(ServiceException):
    pass


class ResizeNotFoundFault(ServiceException):
    pass


class ResourceNotFoundFault(ServiceException):
    pass


class SNSInvalidTopicFault(ServiceException):
    pass


class SNSNoAuthorizationFault(ServiceException):
    pass


class SNSTopicArnNotFoundFault(ServiceException):
    pass


class ScheduleDefinitionTypeUnsupportedFault(ServiceException):
    pass


class ScheduledActionAlreadyExistsFault(ServiceException):
    pass


class ScheduledActionNotFoundFault(ServiceException):
    pass


class ScheduledActionQuotaExceededFault(ServiceException):
    pass


class ScheduledActionTypeUnsupportedFault(ServiceException):
    pass


class SnapshotCopyAlreadyDisabledFault(ServiceException):
    pass


class SnapshotCopyAlreadyEnabledFault(ServiceException):
    pass


class SnapshotCopyDisabledFault(ServiceException):
    pass


class SnapshotCopyGrantAlreadyExistsFault(ServiceException):
    pass


class SnapshotCopyGrantNotFoundFault(ServiceException):
    pass


class SnapshotCopyGrantQuotaExceededFault(ServiceException):
    pass


class SnapshotScheduleAlreadyExistsFault(ServiceException):
    pass


class SnapshotScheduleNotFoundFault(ServiceException):
    pass


class SnapshotScheduleQuotaExceededFault(ServiceException):
    pass


class SnapshotScheduleUpdateInProgressFault(ServiceException):
    pass


class SourceNotFoundFault(ServiceException):
    pass


class SubnetAlreadyInUse(ServiceException):
    pass


class SubscriptionAlreadyExistFault(ServiceException):
    pass


class SubscriptionCategoryNotFoundFault(ServiceException):
    pass


class SubscriptionEventIdNotFoundFault(ServiceException):
    pass


class SubscriptionNotFoundFault(ServiceException):
    pass


class SubscriptionSeverityNotFoundFault(ServiceException):
    pass


class TableLimitExceededFault(ServiceException):
    pass


class TableRestoreNotFoundFault(ServiceException):
    pass


class TagLimitExceededFault(ServiceException):
    pass


class UnauthorizedOperation(ServiceException):
    pass


class UnauthorizedPartnerIntegrationFault(ServiceException):
    pass


class UnknownSnapshotCopyRegionFault(ServiceException):
    pass


class UnsupportedOperationFault(ServiceException):
    pass


class UnsupportedOptionFault(ServiceException):
    pass


class UsageLimitAlreadyExistsFault(ServiceException):
    pass


class UsageLimitNotFoundFault(ServiceException):
    pass


class AcceptReservedNodeExchangeInputMessage(ServiceRequest):
    ReservedNodeId: String
    TargetReservedNodeOfferingId: String


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]
TStamp = datetime


class ReservedNode(TypedDict, total=False):
    ReservedNodeId: Optional[String]
    ReservedNodeOfferingId: Optional[String]
    NodeType: Optional[String]
    StartTime: Optional[TStamp]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    NodeCount: Optional[Integer]
    State: Optional[String]
    OfferingType: Optional[String]
    RecurringCharges: Optional[RecurringChargeList]
    ReservedNodeOfferingType: Optional[ReservedNodeOfferingType]


class AcceptReservedNodeExchangeOutputMessage(TypedDict, total=False):
    ExchangedReservedNode: Optional[ReservedNode]


class AttributeValueTarget(TypedDict, total=False):
    AttributeValue: Optional[String]


AttributeValueList = List[AttributeValueTarget]


class AccountAttribute(TypedDict, total=False):
    AttributeName: Optional[String]
    AttributeValues: Optional[AttributeValueList]


AttributeList = List[AccountAttribute]


class AccountAttributeList(TypedDict, total=False):
    AccountAttributes: Optional[AttributeList]


class AccountWithRestoreAccess(TypedDict, total=False):
    AccountId: Optional[String]
    AccountAlias: Optional[String]


AccountsWithRestoreAccessList = List[AccountWithRestoreAccess]


class AquaConfiguration(TypedDict, total=False):
    AquaStatus: Optional[AquaStatus]
    AquaConfigurationStatus: Optional[AquaConfigurationStatus]


class AssociateDataShareConsumerMessage(ServiceRequest):
    DataShareArn: String
    AssociateEntireAccount: Optional[BooleanOptional]
    ConsumerArn: Optional[String]


class ClusterAssociatedToSchedule(TypedDict, total=False):
    ClusterIdentifier: Optional[String]
    ScheduleAssociationState: Optional[ScheduleState]


AssociatedClusterList = List[ClusterAssociatedToSchedule]
AttributeNameList = List[String]


class AuthenticationProfile(TypedDict, total=False):
    AuthenticationProfileName: Optional[AuthenticationProfileNameString]
    AuthenticationProfileContent: Optional[String]


AuthenticationProfileList = List[AuthenticationProfile]


class AuthorizeClusterSecurityGroupIngressMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    CIDRIP: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


class Tag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


TagList = List[Tag]


class IPRange(TypedDict, total=False):
    Status: Optional[String]
    CIDRIP: Optional[String]
    Tags: Optional[TagList]


IPRangeList = List[IPRange]


class EC2SecurityGroup(TypedDict, total=False):
    Status: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]
    Tags: Optional[TagList]


EC2SecurityGroupList = List[EC2SecurityGroup]


class ClusterSecurityGroup(TypedDict, total=False):
    ClusterSecurityGroupName: Optional[String]
    Description: Optional[String]
    EC2SecurityGroups: Optional[EC2SecurityGroupList]
    IPRanges: Optional[IPRangeList]
    Tags: Optional[TagList]


class AuthorizeClusterSecurityGroupIngressResult(TypedDict, total=False):
    ClusterSecurityGroup: Optional[ClusterSecurityGroup]


class AuthorizeDataShareMessage(ServiceRequest):
    DataShareArn: String
    ConsumerIdentifier: String


VpcIdentifierList = List[String]


class AuthorizeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    Account: String
    VpcIds: Optional[VpcIdentifierList]


class AuthorizeSnapshotAccessMessage(ServiceRequest):
    SnapshotIdentifier: String
    SnapshotClusterIdentifier: Optional[String]
    AccountWithRestoreAccess: String


RestorableNodeTypeList = List[String]
Long = int


class Snapshot(TypedDict, total=False):
    SnapshotIdentifier: Optional[String]
    ClusterIdentifier: Optional[String]
    SnapshotCreateTime: Optional[TStamp]
    Status: Optional[String]
    Port: Optional[Integer]
    AvailabilityZone: Optional[String]
    ClusterCreateTime: Optional[TStamp]
    MasterUsername: Optional[String]
    ClusterVersion: Optional[String]
    EngineFullVersion: Optional[String]
    SnapshotType: Optional[String]
    NodeType: Optional[String]
    NumberOfNodes: Optional[Integer]
    DBName: Optional[String]
    VpcId: Optional[String]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    EncryptedWithHSM: Optional[Boolean]
    AccountsWithRestoreAccess: Optional[AccountsWithRestoreAccessList]
    OwnerAccount: Optional[String]
    TotalBackupSizeInMegaBytes: Optional[Double]
    ActualIncrementalBackupSizeInMegaBytes: Optional[Double]
    BackupProgressInMegaBytes: Optional[Double]
    CurrentBackupRateInMegaBytesPerSecond: Optional[Double]
    EstimatedSecondsToCompletion: Optional[Long]
    ElapsedTimeInSeconds: Optional[Long]
    SourceRegion: Optional[String]
    Tags: Optional[TagList]
    RestorableNodeTypes: Optional[RestorableNodeTypeList]
    EnhancedVpcRouting: Optional[Boolean]
    MaintenanceTrackName: Optional[String]
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    ManualSnapshotRemainingDays: Optional[IntegerOptional]
    SnapshotRetentionStartTime: Optional[TStamp]


class AuthorizeSnapshotAccessResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class SupportedPlatform(TypedDict, total=False):
    Name: Optional[String]


SupportedPlatformsList = List[SupportedPlatform]


class AvailabilityZone(TypedDict, total=False):
    Name: Optional[String]
    SupportedPlatforms: Optional[SupportedPlatformsList]


AvailabilityZoneList = List[AvailabilityZone]


class DeleteClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    SnapshotClusterIdentifier: Optional[String]


DeleteClusterSnapshotMessageList = List[DeleteClusterSnapshotMessage]


class BatchDeleteClusterSnapshotsRequest(ServiceRequest):
    Identifiers: DeleteClusterSnapshotMessageList


class SnapshotErrorMessage(TypedDict, total=False):
    SnapshotIdentifier: Optional[String]
    SnapshotClusterIdentifier: Optional[String]
    FailureCode: Optional[String]
    FailureReason: Optional[String]


BatchSnapshotOperationErrorList = List[SnapshotErrorMessage]
SnapshotIdentifierList = List[String]


class BatchDeleteClusterSnapshotsResult(TypedDict, total=False):
    Resources: Optional[SnapshotIdentifierList]
    Errors: Optional[BatchSnapshotOperationErrorList]


class BatchModifyClusterSnapshotsMessage(ServiceRequest):
    SnapshotIdentifierList: SnapshotIdentifierList
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    Force: Optional[Boolean]


BatchSnapshotOperationErrors = List[SnapshotErrorMessage]


class BatchModifyClusterSnapshotsOutputMessage(TypedDict, total=False):
    Resources: Optional[SnapshotIdentifierList]
    Errors: Optional[BatchSnapshotOperationErrors]


class CancelResizeMessage(ServiceRequest):
    ClusterIdentifier: String


class ReservedNodeExchangeStatus(TypedDict, total=False):
    ReservedNodeExchangeRequestId: Optional[String]
    Status: Optional[ReservedNodeExchangeStatusType]
    RequestTime: Optional[TStamp]
    SourceReservedNodeId: Optional[String]
    SourceReservedNodeType: Optional[String]
    SourceReservedNodeCount: Optional[Integer]
    TargetReservedNodeOfferingId: Optional[String]
    TargetReservedNodeType: Optional[String]
    TargetReservedNodeCount: Optional[Integer]


LongOptional = int


class ResizeInfo(TypedDict, total=False):
    ResizeType: Optional[String]
    AllowCancelResize: Optional[Boolean]


class DeferredMaintenanceWindow(TypedDict, total=False):
    DeferMaintenanceIdentifier: Optional[String]
    DeferMaintenanceStartTime: Optional[TStamp]
    DeferMaintenanceEndTime: Optional[TStamp]


DeferredMaintenanceWindowsList = List[DeferredMaintenanceWindow]
PendingActionsList = List[String]


class ClusterIamRole(TypedDict, total=False):
    IamRoleArn: Optional[String]
    ApplyStatus: Optional[String]


ClusterIamRoleList = List[ClusterIamRole]


class ElasticIpStatus(TypedDict, total=False):
    ElasticIp: Optional[String]
    Status: Optional[String]


class ClusterNode(TypedDict, total=False):
    NodeRole: Optional[String]
    PrivateIPAddress: Optional[String]
    PublicIPAddress: Optional[String]


ClusterNodesList = List[ClusterNode]


class ClusterSnapshotCopyStatus(TypedDict, total=False):
    DestinationRegion: Optional[String]
    RetentionPeriod: Optional[Long]
    ManualSnapshotRetentionPeriod: Optional[Integer]
    SnapshotCopyGrantName: Optional[String]


class HsmStatus(TypedDict, total=False):
    HsmClientCertificateIdentifier: Optional[String]
    HsmConfigurationIdentifier: Optional[String]
    Status: Optional[String]


class DataTransferProgress(TypedDict, total=False):
    Status: Optional[String]
    CurrentRateInMegaBytesPerSecond: Optional[DoubleOptional]
    TotalDataInMegaBytes: Optional[Long]
    DataTransferredInMegaBytes: Optional[Long]
    EstimatedTimeToCompletionInSeconds: Optional[LongOptional]
    ElapsedTimeInSeconds: Optional[LongOptional]


class RestoreStatus(TypedDict, total=False):
    Status: Optional[String]
    CurrentRestoreRateInMegaBytesPerSecond: Optional[Double]
    SnapshotSizeInMegaBytes: Optional[Long]
    ProgressInMegaBytes: Optional[Long]
    ElapsedTimeInSeconds: Optional[Long]
    EstimatedTimeToCompletionInSeconds: Optional[Long]


class PendingModifiedValues(TypedDict, total=False):
    MasterUserPassword: Optional[String]
    NodeType: Optional[String]
    NumberOfNodes: Optional[IntegerOptional]
    ClusterType: Optional[String]
    ClusterVersion: Optional[String]
    AutomatedSnapshotRetentionPeriod: Optional[IntegerOptional]
    ClusterIdentifier: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    EnhancedVpcRouting: Optional[BooleanOptional]
    MaintenanceTrackName: Optional[String]
    EncryptionType: Optional[String]


class ClusterParameterStatus(TypedDict, total=False):
    ParameterName: Optional[String]
    ParameterApplyStatus: Optional[String]
    ParameterApplyErrorDescription: Optional[String]


ClusterParameterStatusList = List[ClusterParameterStatus]


class ClusterParameterGroupStatus(TypedDict, total=False):
    ParameterGroupName: Optional[String]
    ParameterApplyStatus: Optional[String]
    ClusterParameterStatusList: Optional[ClusterParameterStatusList]


ClusterParameterGroupStatusList = List[ClusterParameterGroupStatus]


class VpcSecurityGroupMembership(TypedDict, total=False):
    VpcSecurityGroupId: Optional[String]
    Status: Optional[String]


VpcSecurityGroupMembershipList = List[VpcSecurityGroupMembership]


class ClusterSecurityGroupMembership(TypedDict, total=False):
    ClusterSecurityGroupName: Optional[String]
    Status: Optional[String]


ClusterSecurityGroupMembershipList = List[ClusterSecurityGroupMembership]


class NetworkInterface(TypedDict, total=False):
    NetworkInterfaceId: Optional[String]
    SubnetId: Optional[String]
    PrivateIpAddress: Optional[String]
    AvailabilityZone: Optional[String]


NetworkInterfaceList = List[NetworkInterface]


class VpcEndpoint(TypedDict, total=False):
    VpcEndpointId: Optional[String]
    VpcId: Optional[String]
    NetworkInterfaces: Optional[NetworkInterfaceList]


VpcEndpointsList = List[VpcEndpoint]


class Endpoint(TypedDict, total=False):
    Address: Optional[String]
    Port: Optional[Integer]
    VpcEndpoints: Optional[VpcEndpointsList]


class Cluster(TypedDict, total=False):
    ClusterIdentifier: Optional[String]
    NodeType: Optional[String]
    ClusterStatus: Optional[String]
    ClusterAvailabilityStatus: Optional[String]
    ModifyStatus: Optional[String]
    MasterUsername: Optional[String]
    DBName: Optional[String]
    Endpoint: Optional[Endpoint]
    ClusterCreateTime: Optional[TStamp]
    AutomatedSnapshotRetentionPeriod: Optional[Integer]
    ManualSnapshotRetentionPeriod: Optional[Integer]
    ClusterSecurityGroups: Optional[ClusterSecurityGroupMembershipList]
    VpcSecurityGroups: Optional[VpcSecurityGroupMembershipList]
    ClusterParameterGroups: Optional[ClusterParameterGroupStatusList]
    ClusterSubnetGroupName: Optional[String]
    VpcId: Optional[String]
    AvailabilityZone: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    PendingModifiedValues: Optional[PendingModifiedValues]
    ClusterVersion: Optional[String]
    AllowVersionUpgrade: Optional[Boolean]
    NumberOfNodes: Optional[Integer]
    PubliclyAccessible: Optional[Boolean]
    Encrypted: Optional[Boolean]
    RestoreStatus: Optional[RestoreStatus]
    DataTransferProgress: Optional[DataTransferProgress]
    HsmStatus: Optional[HsmStatus]
    ClusterSnapshotCopyStatus: Optional[ClusterSnapshotCopyStatus]
    ClusterPublicKey: Optional[String]
    ClusterNodes: Optional[ClusterNodesList]
    ElasticIpStatus: Optional[ElasticIpStatus]
    ClusterRevisionNumber: Optional[String]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnhancedVpcRouting: Optional[Boolean]
    IamRoles: Optional[ClusterIamRoleList]
    PendingActions: Optional[PendingActionsList]
    MaintenanceTrackName: Optional[String]
    ElasticResizeNumberOfNodeOptions: Optional[String]
    DeferredMaintenanceWindows: Optional[DeferredMaintenanceWindowsList]
    SnapshotScheduleIdentifier: Optional[String]
    SnapshotScheduleState: Optional[ScheduleState]
    ExpectedNextSnapshotScheduleTime: Optional[TStamp]
    ExpectedNextSnapshotScheduleTimeStatus: Optional[String]
    NextMaintenanceWindowStartTime: Optional[TStamp]
    ResizeInfo: Optional[ResizeInfo]
    AvailabilityZoneRelocationStatus: Optional[String]
    ClusterNamespaceArn: Optional[String]
    TotalStorageCapacityInMegaBytes: Optional[LongOptional]
    AquaConfiguration: Optional[AquaConfiguration]
    DefaultIamRoleArn: Optional[String]
    ReservedNodeExchangeStatus: Optional[ReservedNodeExchangeStatus]


class ClusterCredentials(TypedDict, total=False):
    DbUser: Optional[String]
    DbPassword: Optional[SensitiveString]
    Expiration: Optional[TStamp]


class RevisionTarget(TypedDict, total=False):
    DatabaseRevision: Optional[String]
    Description: Optional[String]
    DatabaseRevisionReleaseDate: Optional[TStamp]


RevisionTargetsList = List[RevisionTarget]


class ClusterDbRevision(TypedDict, total=False):
    ClusterIdentifier: Optional[String]
    CurrentDatabaseRevision: Optional[String]
    DatabaseRevisionReleaseDate: Optional[TStamp]
    RevisionTargets: Optional[RevisionTargetsList]


ClusterDbRevisionsList = List[ClusterDbRevision]


class ClusterDbRevisionsMessage(TypedDict, total=False):
    Marker: Optional[String]
    ClusterDbRevisions: Optional[ClusterDbRevisionsList]


ClusterList = List[Cluster]


class ClusterParameterGroup(TypedDict, total=False):
    ParameterGroupName: Optional[String]
    ParameterGroupFamily: Optional[String]
    Description: Optional[String]
    Tags: Optional[TagList]


class Parameter(TypedDict, total=False):
    ParameterName: Optional[String]
    ParameterValue: Optional[String]
    Description: Optional[String]
    Source: Optional[String]
    DataType: Optional[String]
    AllowedValues: Optional[String]
    ApplyType: Optional[ParameterApplyType]
    IsModifiable: Optional[Boolean]
    MinimumEngineVersion: Optional[String]


ParametersList = List[Parameter]


class ClusterParameterGroupDetails(TypedDict, total=False):
    Parameters: Optional[ParametersList]
    Marker: Optional[String]


class ClusterParameterGroupNameMessage(TypedDict, total=False):
    ParameterGroupName: Optional[String]
    ParameterGroupStatus: Optional[String]


ParameterGroupList = List[ClusterParameterGroup]


class ClusterParameterGroupsMessage(TypedDict, total=False):
    Marker: Optional[String]
    ParameterGroups: Optional[ParameterGroupList]


ClusterSecurityGroups = List[ClusterSecurityGroup]


class ClusterSecurityGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    ClusterSecurityGroups: Optional[ClusterSecurityGroups]


ClusterSecurityGroupNameList = List[String]


class Subnet(TypedDict, total=False):
    SubnetIdentifier: Optional[String]
    SubnetAvailabilityZone: Optional[AvailabilityZone]
    SubnetStatus: Optional[String]


SubnetList = List[Subnet]


class ClusterSubnetGroup(TypedDict, total=False):
    ClusterSubnetGroupName: Optional[String]
    Description: Optional[String]
    VpcId: Optional[String]
    SubnetGroupStatus: Optional[String]
    Subnets: Optional[SubnetList]
    Tags: Optional[TagList]


ClusterSubnetGroups = List[ClusterSubnetGroup]


class ClusterSubnetGroupMessage(TypedDict, total=False):
    Marker: Optional[String]
    ClusterSubnetGroups: Optional[ClusterSubnetGroups]


class ClusterVersion(TypedDict, total=False):
    ClusterVersion: Optional[String]
    ClusterParameterGroupFamily: Optional[String]
    Description: Optional[String]


ClusterVersionList = List[ClusterVersion]


class ClusterVersionsMessage(TypedDict, total=False):
    Marker: Optional[String]
    ClusterVersions: Optional[ClusterVersionList]


class ClustersMessage(TypedDict, total=False):
    Marker: Optional[String]
    Clusters: Optional[ClusterList]


class CopyClusterSnapshotMessage(ServiceRequest):
    SourceSnapshotIdentifier: String
    SourceSnapshotClusterIdentifier: Optional[String]
    TargetSnapshotIdentifier: String
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]


class CopyClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class CreateAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString
    AuthenticationProfileContent: String


class CreateAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: Optional[AuthenticationProfileNameString]
    AuthenticationProfileContent: Optional[String]


IamRoleArnList = List[String]
VpcSecurityGroupIdList = List[String]


class CreateClusterMessage(ServiceRequest):
    DBName: Optional[String]
    ClusterIdentifier: String
    ClusterType: Optional[String]
    NodeType: String
    MasterUsername: String
    MasterUserPassword: String
    ClusterSecurityGroups: Optional[ClusterSecurityGroupNameList]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    ClusterSubnetGroupName: Optional[String]
    AvailabilityZone: Optional[String]
    PreferredMaintenanceWindow: Optional[String]
    ClusterParameterGroupName: Optional[String]
    AutomatedSnapshotRetentionPeriod: Optional[IntegerOptional]
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    Port: Optional[IntegerOptional]
    ClusterVersion: Optional[String]
    AllowVersionUpgrade: Optional[BooleanOptional]
    NumberOfNodes: Optional[IntegerOptional]
    PubliclyAccessible: Optional[BooleanOptional]
    Encrypted: Optional[BooleanOptional]
    HsmClientCertificateIdentifier: Optional[String]
    HsmConfigurationIdentifier: Optional[String]
    ElasticIp: Optional[String]
    Tags: Optional[TagList]
    KmsKeyId: Optional[String]
    EnhancedVpcRouting: Optional[BooleanOptional]
    AdditionalInfo: Optional[String]
    IamRoles: Optional[IamRoleArnList]
    MaintenanceTrackName: Optional[String]
    SnapshotScheduleIdentifier: Optional[String]
    AvailabilityZoneRelocation: Optional[BooleanOptional]
    AquaConfigurationStatus: Optional[AquaConfigurationStatus]
    DefaultIamRoleArn: Optional[String]


class CreateClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    ParameterGroupFamily: String
    Description: String
    Tags: Optional[TagList]


class CreateClusterParameterGroupResult(TypedDict, total=False):
    ClusterParameterGroup: Optional[ClusterParameterGroup]


class CreateClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class CreateClusterSecurityGroupMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    Description: String
    Tags: Optional[TagList]


class CreateClusterSecurityGroupResult(TypedDict, total=False):
    ClusterSecurityGroup: Optional[ClusterSecurityGroup]


class CreateClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    ClusterIdentifier: String
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    Tags: Optional[TagList]


class CreateClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


SubnetIdentifierList = List[String]


class CreateClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String
    Description: String
    SubnetIds: SubnetIdentifierList
    Tags: Optional[TagList]


class CreateClusterSubnetGroupResult(TypedDict, total=False):
    ClusterSubnetGroup: Optional[ClusterSubnetGroup]


class CreateEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    ResourceOwner: Optional[String]
    EndpointName: String
    SubnetGroupName: String
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]


EventCategoriesList = List[String]
SourceIdsList = List[String]


class CreateEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: String
    SourceType: Optional[String]
    SourceIds: Optional[SourceIdsList]
    EventCategories: Optional[EventCategoriesList]
    Severity: Optional[String]
    Enabled: Optional[BooleanOptional]
    Tags: Optional[TagList]


class EventSubscription(TypedDict, total=False):
    CustomerAwsId: Optional[String]
    CustSubscriptionId: Optional[String]
    SnsTopicArn: Optional[String]
    Status: Optional[String]
    SubscriptionCreationTime: Optional[TStamp]
    SourceType: Optional[String]
    SourceIdsList: Optional[SourceIdsList]
    EventCategoriesList: Optional[EventCategoriesList]
    Severity: Optional[String]
    Enabled: Optional[Boolean]
    Tags: Optional[TagList]


class CreateEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class CreateHsmClientCertificateMessage(ServiceRequest):
    HsmClientCertificateIdentifier: String
    Tags: Optional[TagList]


class HsmClientCertificate(TypedDict, total=False):
    HsmClientCertificateIdentifier: Optional[String]
    HsmClientCertificatePublicKey: Optional[String]
    Tags: Optional[TagList]


class CreateHsmClientCertificateResult(TypedDict, total=False):
    HsmClientCertificate: Optional[HsmClientCertificate]


class CreateHsmConfigurationMessage(ServiceRequest):
    HsmConfigurationIdentifier: String
    Description: String
    HsmIpAddress: String
    HsmPartitionName: String
    HsmPartitionPassword: String
    HsmServerPublicCertificate: String
    Tags: Optional[TagList]


class HsmConfiguration(TypedDict, total=False):
    HsmConfigurationIdentifier: Optional[String]
    Description: Optional[String]
    HsmIpAddress: Optional[String]
    HsmPartitionName: Optional[String]
    Tags: Optional[TagList]


class CreateHsmConfigurationResult(TypedDict, total=False):
    HsmConfiguration: Optional[HsmConfiguration]


class ResumeClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class PauseClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class ResizeClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    ClusterType: Optional[String]
    NodeType: Optional[String]
    NumberOfNodes: Optional[IntegerOptional]
    Classic: Optional[BooleanOptional]
    ReservedNodeId: Optional[String]
    TargetReservedNodeOfferingId: Optional[String]


class ScheduledActionType(TypedDict, total=False):
    ResizeCluster: Optional[ResizeClusterMessage]
    PauseCluster: Optional[PauseClusterMessage]
    ResumeCluster: Optional[ResumeClusterMessage]


class CreateScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String
    TargetAction: ScheduledActionType
    Schedule: String
    IamRole: String
    ScheduledActionDescription: Optional[String]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Enable: Optional[BooleanOptional]


class CreateSnapshotCopyGrantMessage(ServiceRequest):
    SnapshotCopyGrantName: String
    KmsKeyId: Optional[String]
    Tags: Optional[TagList]


class SnapshotCopyGrant(TypedDict, total=False):
    SnapshotCopyGrantName: Optional[String]
    KmsKeyId: Optional[String]
    Tags: Optional[TagList]


class CreateSnapshotCopyGrantResult(TypedDict, total=False):
    SnapshotCopyGrant: Optional[SnapshotCopyGrant]


ScheduleDefinitionList = List[String]


class CreateSnapshotScheduleMessage(ServiceRequest):
    ScheduleDefinitions: Optional[ScheduleDefinitionList]
    ScheduleIdentifier: Optional[String]
    ScheduleDescription: Optional[String]
    Tags: Optional[TagList]
    DryRun: Optional[BooleanOptional]
    NextInvocations: Optional[IntegerOptional]


class CreateTagsMessage(ServiceRequest):
    ResourceName: String
    Tags: TagList


class CreateUsageLimitMessage(ServiceRequest):
    ClusterIdentifier: String
    FeatureType: UsageLimitFeatureType
    LimitType: UsageLimitLimitType
    Amount: Long
    Period: Optional[UsageLimitPeriod]
    BreachAction: Optional[UsageLimitBreachAction]
    Tags: Optional[TagList]


class CustomerStorageMessage(TypedDict, total=False):
    TotalBackupSizeInMegaBytes: Optional[Double]
    TotalProvisionedStorageInMegaBytes: Optional[Double]


class DataShareAssociation(TypedDict, total=False):
    ConsumerIdentifier: Optional[String]
    Status: Optional[DataShareStatus]
    CreatedDate: Optional[TStamp]
    StatusChangeDate: Optional[TStamp]


DataShareAssociationList = List[DataShareAssociation]


class DataShare(TypedDict, total=False):
    DataShareArn: Optional[String]
    ProducerArn: Optional[String]
    AllowPubliclyAccessibleConsumers: Optional[Boolean]
    DataShareAssociations: Optional[DataShareAssociationList]


DataShareList = List[DataShare]
DbGroupList = List[String]


class DeauthorizeDataShareMessage(ServiceRequest):
    DataShareArn: String
    ConsumerIdentifier: String


class DefaultClusterParameters(TypedDict, total=False):
    ParameterGroupFamily: Optional[String]
    Marker: Optional[String]
    Parameters: Optional[ParametersList]


class DeleteAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString


class DeleteAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: Optional[AuthenticationProfileNameString]


class DeleteClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    SkipFinalClusterSnapshot: Optional[Boolean]
    FinalClusterSnapshotIdentifier: Optional[String]
    FinalClusterSnapshotRetentionPeriod: Optional[IntegerOptional]


class DeleteClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String


class DeleteClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class DeleteClusterSecurityGroupMessage(ServiceRequest):
    ClusterSecurityGroupName: String


class DeleteClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class DeleteClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String


class DeleteEndpointAccessMessage(ServiceRequest):
    EndpointName: String


class DeleteEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String


class DeleteHsmClientCertificateMessage(ServiceRequest):
    HsmClientCertificateIdentifier: String


class DeleteHsmConfigurationMessage(ServiceRequest):
    HsmConfigurationIdentifier: String


class DeleteScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String


class DeleteSnapshotCopyGrantMessage(ServiceRequest):
    SnapshotCopyGrantName: String


class DeleteSnapshotScheduleMessage(ServiceRequest):
    ScheduleIdentifier: String


TagKeyList = List[String]


class DeleteTagsMessage(ServiceRequest):
    ResourceName: String
    TagKeys: TagKeyList


class DeleteUsageLimitMessage(ServiceRequest):
    UsageLimitId: String


class DescribeAccountAttributesMessage(ServiceRequest):
    AttributeNames: Optional[AttributeNameList]


class DescribeAuthenticationProfilesMessage(ServiceRequest):
    AuthenticationProfileName: Optional[AuthenticationProfileNameString]


class DescribeAuthenticationProfilesResult(TypedDict, total=False):
    AuthenticationProfiles: Optional[AuthenticationProfileList]


class DescribeClusterDbRevisionsMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


TagValueList = List[String]


class DescribeClusterParameterGroupsMessage(ServiceRequest):
    ParameterGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeClusterParametersMessage(ServiceRequest):
    ParameterGroupName: String
    Source: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeClusterSecurityGroupsMessage(ServiceRequest):
    ClusterSecurityGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class SnapshotSortingEntity(TypedDict, total=False):
    Attribute: SnapshotAttributeToSortBy
    SortOrder: Optional[SortByOrder]


SnapshotSortingEntityList = List[SnapshotSortingEntity]


class DescribeClusterSnapshotsMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    SnapshotIdentifier: Optional[String]
    SnapshotType: Optional[String]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    OwnerAccount: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]
    ClusterExists: Optional[BooleanOptional]
    SortingEntities: Optional[SnapshotSortingEntityList]


class DescribeClusterSubnetGroupsMessage(ServiceRequest):
    ClusterSubnetGroupName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeClusterTracksMessage(ServiceRequest):
    MaintenanceTrackName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeClusterVersionsMessage(ServiceRequest):
    ClusterVersion: Optional[String]
    ClusterParameterGroupFamily: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeClustersMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeDataSharesForConsumerMessage(ServiceRequest):
    ConsumerArn: Optional[String]
    Status: Optional[DataShareStatusForConsumer]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDataSharesForConsumerResult(TypedDict, total=False):
    DataShares: Optional[DataShareList]
    Marker: Optional[String]


class DescribeDataSharesForProducerMessage(ServiceRequest):
    ProducerArn: Optional[String]
    Status: Optional[DataShareStatusForProducer]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDataSharesForProducerResult(TypedDict, total=False):
    DataShares: Optional[DataShareList]
    Marker: Optional[String]


class DescribeDataSharesMessage(ServiceRequest):
    DataShareArn: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDataSharesResult(TypedDict, total=False):
    DataShares: Optional[DataShareList]
    Marker: Optional[String]


class DescribeDefaultClusterParametersMessage(ServiceRequest):
    ParameterGroupFamily: String
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeDefaultClusterParametersResult(TypedDict, total=False):
    DefaultClusterParameters: Optional[DefaultClusterParameters]


class DescribeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    ResourceOwner: Optional[String]
    EndpointName: Optional[String]
    VpcId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEndpointAuthorizationMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    Account: Optional[String]
    Grantee: Optional[BooleanOptional]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeEventCategoriesMessage(ServiceRequest):
    SourceType: Optional[String]


class DescribeEventSubscriptionsMessage(ServiceRequest):
    SubscriptionName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeEventsMessage(ServiceRequest):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Duration: Optional[IntegerOptional]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeHsmClientCertificatesMessage(ServiceRequest):
    HsmClientCertificateIdentifier: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeHsmConfigurationsMessage(ServiceRequest):
    HsmConfigurationIdentifier: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeLoggingStatusMessage(ServiceRequest):
    ClusterIdentifier: String


ValueStringList = List[String]


class NodeConfigurationOptionsFilter(TypedDict, total=False):
    Name: Optional[NodeConfigurationOptionsFilterName]
    Operator: Optional[OperatorType]
    Values: Optional[ValueStringList]


NodeConfigurationOptionsFilterList = List[NodeConfigurationOptionsFilter]


class DescribeNodeConfigurationOptionsMessage(ServiceRequest):
    ActionType: ActionType
    ClusterIdentifier: Optional[String]
    SnapshotIdentifier: Optional[String]
    OwnerAccount: Optional[String]
    Filters: Optional[NodeConfigurationOptionsFilterList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]


class DescribeOrderableClusterOptionsMessage(ServiceRequest):
    ClusterVersion: Optional[String]
    NodeType: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribePartnersInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: Optional[PartnerIntegrationDatabaseName]
    PartnerName: Optional[PartnerIntegrationPartnerName]


class PartnerIntegrationInfo(TypedDict, total=False):
    DatabaseName: Optional[PartnerIntegrationDatabaseName]
    PartnerName: Optional[PartnerIntegrationPartnerName]
    Status: Optional[PartnerIntegrationStatus]
    StatusMessage: Optional[PartnerIntegrationStatusMessage]
    CreatedAt: Optional[TStamp]
    UpdatedAt: Optional[TStamp]


PartnerIntegrationInfoList = List[PartnerIntegrationInfo]


class DescribePartnersOutputMessage(TypedDict, total=False):
    PartnerIntegrationInfoList: Optional[PartnerIntegrationInfoList]


class DescribeReservedNodeExchangeStatusInputMessage(ServiceRequest):
    ReservedNodeId: Optional[String]
    ReservedNodeExchangeRequestId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


ReservedNodeExchangeStatusList = List[ReservedNodeExchangeStatus]


class DescribeReservedNodeExchangeStatusOutputMessage(TypedDict, total=False):
    ReservedNodeExchangeStatusDetails: Optional[ReservedNodeExchangeStatusList]
    Marker: Optional[String]


class DescribeReservedNodeOfferingsMessage(ServiceRequest):
    ReservedNodeOfferingId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeReservedNodesMessage(ServiceRequest):
    ReservedNodeId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeResizeMessage(ServiceRequest):
    ClusterIdentifier: String


class ScheduledActionFilter(TypedDict, total=False):
    Name: ScheduledActionFilterName
    Values: ValueStringList


ScheduledActionFilterList = List[ScheduledActionFilter]


class DescribeScheduledActionsMessage(ServiceRequest):
    ScheduledActionName: Optional[String]
    TargetActionType: Optional[ScheduledActionTypeValues]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Active: Optional[BooleanOptional]
    Filters: Optional[ScheduledActionFilterList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]


class DescribeSnapshotCopyGrantsMessage(ServiceRequest):
    SnapshotCopyGrantName: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeSnapshotSchedulesMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    ScheduleIdentifier: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]
    Marker: Optional[String]
    MaxRecords: Optional[IntegerOptional]


ScheduledSnapshotTimeList = List[TStamp]


class SnapshotSchedule(TypedDict, total=False):
    ScheduleDefinitions: Optional[ScheduleDefinitionList]
    ScheduleIdentifier: Optional[String]
    ScheduleDescription: Optional[String]
    Tags: Optional[TagList]
    NextInvocations: Optional[ScheduledSnapshotTimeList]
    AssociatedClusterCount: Optional[IntegerOptional]
    AssociatedClusters: Optional[AssociatedClusterList]


SnapshotScheduleList = List[SnapshotSchedule]


class DescribeSnapshotSchedulesOutputMessage(TypedDict, total=False):
    SnapshotSchedules: Optional[SnapshotScheduleList]
    Marker: Optional[String]


class DescribeTableRestoreStatusMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    TableRestoreRequestId: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class DescribeTagsMessage(ServiceRequest):
    ResourceName: Optional[String]
    ResourceType: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DescribeUsageLimitsMessage(ServiceRequest):
    UsageLimitId: Optional[String]
    ClusterIdentifier: Optional[String]
    FeatureType: Optional[UsageLimitFeatureType]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]
    TagKeys: Optional[TagKeyList]
    TagValues: Optional[TagValueList]


class DisableLoggingMessage(ServiceRequest):
    ClusterIdentifier: String


class DisableSnapshotCopyMessage(ServiceRequest):
    ClusterIdentifier: String


class DisableSnapshotCopyResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class DisassociateDataShareConsumerMessage(ServiceRequest):
    DataShareArn: String
    DisassociateEntireAccount: Optional[BooleanOptional]
    ConsumerArn: Optional[String]


class SupportedOperation(TypedDict, total=False):
    OperationName: Optional[String]


SupportedOperationList = List[SupportedOperation]


class UpdateTarget(TypedDict, total=False):
    MaintenanceTrackName: Optional[String]
    DatabaseVersion: Optional[String]
    SupportedOperations: Optional[SupportedOperationList]


EligibleTracksToUpdateList = List[UpdateTarget]


class EnableLoggingMessage(ServiceRequest):
    ClusterIdentifier: String
    BucketName: String
    S3KeyPrefix: Optional[String]


class EnableSnapshotCopyMessage(ServiceRequest):
    ClusterIdentifier: String
    DestinationRegion: String
    RetentionPeriod: Optional[IntegerOptional]
    SnapshotCopyGrantName: Optional[String]
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]


class EnableSnapshotCopyResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class EndpointAccess(TypedDict, total=False):
    ClusterIdentifier: Optional[String]
    ResourceOwner: Optional[String]
    SubnetGroupName: Optional[String]
    EndpointStatus: Optional[String]
    EndpointName: Optional[String]
    EndpointCreateTime: Optional[TStamp]
    Port: Optional[Integer]
    Address: Optional[String]
    VpcSecurityGroups: Optional[VpcSecurityGroupMembershipList]
    VpcEndpoint: Optional[VpcEndpoint]


EndpointAccesses = List[EndpointAccess]


class EndpointAccessList(TypedDict, total=False):
    EndpointAccessList: Optional[EndpointAccesses]
    Marker: Optional[String]


class EndpointAuthorization(TypedDict, total=False):
    Grantor: Optional[String]
    Grantee: Optional[String]
    ClusterIdentifier: Optional[String]
    AuthorizeTime: Optional[TStamp]
    ClusterStatus: Optional[String]
    Status: Optional[AuthorizationStatus]
    AllowedAllVPCs: Optional[Boolean]
    AllowedVPCs: Optional[VpcIdentifierList]
    EndpointCount: Optional[Integer]


EndpointAuthorizations = List[EndpointAuthorization]


class EndpointAuthorizationList(TypedDict, total=False):
    EndpointAuthorizationList: Optional[EndpointAuthorizations]
    Marker: Optional[String]


class Event(TypedDict, total=False):
    SourceIdentifier: Optional[String]
    SourceType: Optional[SourceType]
    Message: Optional[String]
    EventCategories: Optional[EventCategoriesList]
    Severity: Optional[String]
    Date: Optional[TStamp]
    EventId: Optional[String]


class EventInfoMap(TypedDict, total=False):
    EventId: Optional[String]
    EventCategories: Optional[EventCategoriesList]
    EventDescription: Optional[String]
    Severity: Optional[String]


EventInfoMapList = List[EventInfoMap]


class EventCategoriesMap(TypedDict, total=False):
    SourceType: Optional[String]
    Events: Optional[EventInfoMapList]


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


class GetClusterCredentialsMessage(ServiceRequest):
    DbUser: String
    DbName: Optional[String]
    ClusterIdentifier: String
    DurationSeconds: Optional[IntegerOptional]
    AutoCreate: Optional[BooleanOptional]
    DbGroups: Optional[DbGroupList]


class GetReservedNodeExchangeConfigurationOptionsInputMessage(ServiceRequest):
    ActionType: ReservedNodeExchangeActionType
    ClusterIdentifier: Optional[String]
    SnapshotIdentifier: Optional[String]
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


class ReservedNodeOffering(TypedDict, total=False):
    ReservedNodeOfferingId: Optional[String]
    NodeType: Optional[String]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    OfferingType: Optional[String]
    RecurringCharges: Optional[RecurringChargeList]
    ReservedNodeOfferingType: Optional[ReservedNodeOfferingType]


class ReservedNodeConfigurationOption(TypedDict, total=False):
    SourceReservedNode: Optional[ReservedNode]
    TargetReservedNodeCount: Optional[Integer]
    TargetReservedNodeOffering: Optional[ReservedNodeOffering]


ReservedNodeConfigurationOptionList = List[ReservedNodeConfigurationOption]


class GetReservedNodeExchangeConfigurationOptionsOutputMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedNodeConfigurationOptionList: Optional[ReservedNodeConfigurationOptionList]


class GetReservedNodeExchangeOfferingsInputMessage(ServiceRequest):
    ReservedNodeId: String
    MaxRecords: Optional[IntegerOptional]
    Marker: Optional[String]


ReservedNodeOfferingList = List[ReservedNodeOffering]


class GetReservedNodeExchangeOfferingsOutputMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedNodeOfferings: Optional[ReservedNodeOfferingList]


HsmClientCertificateList = List[HsmClientCertificate]


class HsmClientCertificateMessage(TypedDict, total=False):
    Marker: Optional[String]
    HsmClientCertificates: Optional[HsmClientCertificateList]


HsmConfigurationList = List[HsmConfiguration]


class HsmConfigurationMessage(TypedDict, total=False):
    Marker: Optional[String]
    HsmConfigurations: Optional[HsmConfigurationList]


ImportTablesCompleted = List[String]
ImportTablesInProgress = List[String]
ImportTablesNotStarted = List[String]


class LoggingStatus(TypedDict, total=False):
    LoggingEnabled: Optional[Boolean]
    BucketName: Optional[String]
    S3KeyPrefix: Optional[String]
    LastSuccessfulDeliveryTime: Optional[TStamp]
    LastFailureTime: Optional[TStamp]
    LastFailureMessage: Optional[String]


class MaintenanceTrack(TypedDict, total=False):
    MaintenanceTrackName: Optional[String]
    DatabaseVersion: Optional[String]
    UpdateTargets: Optional[EligibleTracksToUpdateList]


class ModifyAquaInputMessage(ServiceRequest):
    ClusterIdentifier: String
    AquaConfigurationStatus: Optional[AquaConfigurationStatus]


class ModifyAquaOutputMessage(TypedDict, total=False):
    AquaConfiguration: Optional[AquaConfiguration]


class ModifyAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString
    AuthenticationProfileContent: String


class ModifyAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: Optional[AuthenticationProfileNameString]
    AuthenticationProfileContent: Optional[String]


class ModifyClusterDbRevisionMessage(ServiceRequest):
    ClusterIdentifier: String
    RevisionTarget: String


class ModifyClusterDbRevisionResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ModifyClusterIamRolesMessage(ServiceRequest):
    ClusterIdentifier: String
    AddIamRoles: Optional[IamRoleArnList]
    RemoveIamRoles: Optional[IamRoleArnList]
    DefaultIamRoleArn: Optional[String]


class ModifyClusterIamRolesResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ModifyClusterMaintenanceMessage(ServiceRequest):
    ClusterIdentifier: String
    DeferMaintenance: Optional[BooleanOptional]
    DeferMaintenanceIdentifier: Optional[String]
    DeferMaintenanceStartTime: Optional[TStamp]
    DeferMaintenanceEndTime: Optional[TStamp]
    DeferMaintenanceDuration: Optional[IntegerOptional]


class ModifyClusterMaintenanceResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ModifyClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    ClusterType: Optional[String]
    NodeType: Optional[String]
    NumberOfNodes: Optional[IntegerOptional]
    ClusterSecurityGroups: Optional[ClusterSecurityGroupNameList]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    MasterUserPassword: Optional[String]
    ClusterParameterGroupName: Optional[String]
    AutomatedSnapshotRetentionPeriod: Optional[IntegerOptional]
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    PreferredMaintenanceWindow: Optional[String]
    ClusterVersion: Optional[String]
    AllowVersionUpgrade: Optional[BooleanOptional]
    HsmClientCertificateIdentifier: Optional[String]
    HsmConfigurationIdentifier: Optional[String]
    NewClusterIdentifier: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    ElasticIp: Optional[String]
    EnhancedVpcRouting: Optional[BooleanOptional]
    MaintenanceTrackName: Optional[String]
    Encrypted: Optional[BooleanOptional]
    KmsKeyId: Optional[String]
    AvailabilityZoneRelocation: Optional[BooleanOptional]
    AvailabilityZone: Optional[String]
    Port: Optional[IntegerOptional]


class ModifyClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    Parameters: ParametersList


class ModifyClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ModifyClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    Force: Optional[Boolean]


class ModifyClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class ModifyClusterSnapshotScheduleMessage(ServiceRequest):
    ClusterIdentifier: String
    ScheduleIdentifier: Optional[String]
    DisassociateSchedule: Optional[BooleanOptional]


class ModifyClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String
    Description: Optional[String]
    SubnetIds: SubnetIdentifierList


class ModifyClusterSubnetGroupResult(TypedDict, total=False):
    ClusterSubnetGroup: Optional[ClusterSubnetGroup]


class ModifyEndpointAccessMessage(ServiceRequest):
    EndpointName: String
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]


class ModifyEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: Optional[String]
    SourceType: Optional[String]
    SourceIds: Optional[SourceIdsList]
    EventCategories: Optional[EventCategoriesList]
    Severity: Optional[String]
    Enabled: Optional[BooleanOptional]


class ModifyEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: Optional[EventSubscription]


class ModifyScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String
    TargetAction: Optional[ScheduledActionType]
    Schedule: Optional[String]
    IamRole: Optional[String]
    ScheduledActionDescription: Optional[String]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]
    Enable: Optional[BooleanOptional]


class ModifySnapshotCopyRetentionPeriodMessage(ServiceRequest):
    ClusterIdentifier: String
    RetentionPeriod: Integer
    Manual: Optional[Boolean]


class ModifySnapshotCopyRetentionPeriodResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ModifySnapshotScheduleMessage(ServiceRequest):
    ScheduleIdentifier: String
    ScheduleDefinitions: ScheduleDefinitionList


class ModifyUsageLimitMessage(ServiceRequest):
    UsageLimitId: String
    Amount: Optional[LongOptional]
    BreachAction: Optional[UsageLimitBreachAction]


class NodeConfigurationOption(TypedDict, total=False):
    NodeType: Optional[String]
    NumberOfNodes: Optional[Integer]
    EstimatedDiskUtilizationPercent: Optional[DoubleOptional]
    Mode: Optional[Mode]


NodeConfigurationOptionList = List[NodeConfigurationOption]


class NodeConfigurationOptionsMessage(TypedDict, total=False):
    NodeConfigurationOptionList: Optional[NodeConfigurationOptionList]
    Marker: Optional[String]


class OrderableClusterOption(TypedDict, total=False):
    ClusterVersion: Optional[String]
    ClusterType: Optional[String]
    NodeType: Optional[String]
    AvailabilityZones: Optional[AvailabilityZoneList]


OrderableClusterOptionsList = List[OrderableClusterOption]


class OrderableClusterOptionsMessage(TypedDict, total=False):
    OrderableClusterOptions: Optional[OrderableClusterOptionsList]
    Marker: Optional[String]


class PartnerIntegrationInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: PartnerIntegrationDatabaseName
    PartnerName: PartnerIntegrationPartnerName


class PartnerIntegrationOutputMessage(TypedDict, total=False):
    DatabaseName: Optional[PartnerIntegrationDatabaseName]
    PartnerName: Optional[PartnerIntegrationPartnerName]


class PauseClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class PurchaseReservedNodeOfferingMessage(ServiceRequest):
    ReservedNodeOfferingId: String
    NodeCount: Optional[IntegerOptional]


class PurchaseReservedNodeOfferingResult(TypedDict, total=False):
    ReservedNode: Optional[ReservedNode]


class RebootClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class RebootClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class RejectDataShareMessage(ServiceRequest):
    DataShareArn: String


ReservedNodeList = List[ReservedNode]


class ReservedNodeOfferingsMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedNodeOfferings: Optional[ReservedNodeOfferingList]


class ReservedNodesMessage(TypedDict, total=False):
    Marker: Optional[String]
    ReservedNodes: Optional[ReservedNodeList]


class ResetClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    ResetAllParameters: Optional[Boolean]
    Parameters: Optional[ParametersList]


class ResizeClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class ResizeProgressMessage(TypedDict, total=False):
    TargetNodeType: Optional[String]
    TargetNumberOfNodes: Optional[IntegerOptional]
    TargetClusterType: Optional[String]
    Status: Optional[String]
    ImportTablesCompleted: Optional[ImportTablesCompleted]
    ImportTablesInProgress: Optional[ImportTablesInProgress]
    ImportTablesNotStarted: Optional[ImportTablesNotStarted]
    AvgResizeRateInMegaBytesPerSecond: Optional[DoubleOptional]
    TotalResizeDataInMegaBytes: Optional[LongOptional]
    ProgressInMegaBytes: Optional[LongOptional]
    ElapsedTimeInSeconds: Optional[LongOptional]
    EstimatedTimeToCompletionInSeconds: Optional[LongOptional]
    ResizeType: Optional[String]
    Message: Optional[String]
    TargetEncryptionType: Optional[String]
    DataTransferProgressPercent: Optional[DoubleOptional]


class RestoreFromClusterSnapshotMessage(ServiceRequest):
    ClusterIdentifier: String
    SnapshotIdentifier: String
    SnapshotClusterIdentifier: Optional[String]
    Port: Optional[IntegerOptional]
    AvailabilityZone: Optional[String]
    AllowVersionUpgrade: Optional[BooleanOptional]
    ClusterSubnetGroupName: Optional[String]
    PubliclyAccessible: Optional[BooleanOptional]
    OwnerAccount: Optional[String]
    HsmClientCertificateIdentifier: Optional[String]
    HsmConfigurationIdentifier: Optional[String]
    ElasticIp: Optional[String]
    ClusterParameterGroupName: Optional[String]
    ClusterSecurityGroups: Optional[ClusterSecurityGroupNameList]
    VpcSecurityGroupIds: Optional[VpcSecurityGroupIdList]
    PreferredMaintenanceWindow: Optional[String]
    AutomatedSnapshotRetentionPeriod: Optional[IntegerOptional]
    ManualSnapshotRetentionPeriod: Optional[IntegerOptional]
    KmsKeyId: Optional[String]
    NodeType: Optional[String]
    EnhancedVpcRouting: Optional[BooleanOptional]
    AdditionalInfo: Optional[String]
    IamRoles: Optional[IamRoleArnList]
    MaintenanceTrackName: Optional[String]
    SnapshotScheduleIdentifier: Optional[String]
    NumberOfNodes: Optional[IntegerOptional]
    AvailabilityZoneRelocation: Optional[BooleanOptional]
    AquaConfigurationStatus: Optional[AquaConfigurationStatus]
    DefaultIamRoleArn: Optional[String]
    ReservedNodeId: Optional[String]
    TargetReservedNodeOfferingId: Optional[String]


class RestoreFromClusterSnapshotResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class RestoreTableFromClusterSnapshotMessage(ServiceRequest):
    ClusterIdentifier: String
    SnapshotIdentifier: String
    SourceDatabaseName: String
    SourceSchemaName: Optional[String]
    SourceTableName: String
    TargetDatabaseName: Optional[String]
    TargetSchemaName: Optional[String]
    NewTableName: String
    EnableCaseSensitiveIdentifier: Optional[BooleanOptional]


class TableRestoreStatus(TypedDict, total=False):
    TableRestoreRequestId: Optional[String]
    Status: Optional[TableRestoreStatusType]
    Message: Optional[String]
    RequestTime: Optional[TStamp]
    ProgressInMegaBytes: Optional[LongOptional]
    TotalDataInMegaBytes: Optional[LongOptional]
    ClusterIdentifier: Optional[String]
    SnapshotIdentifier: Optional[String]
    SourceDatabaseName: Optional[String]
    SourceSchemaName: Optional[String]
    SourceTableName: Optional[String]
    TargetDatabaseName: Optional[String]
    TargetSchemaName: Optional[String]
    NewTableName: Optional[String]


class RestoreTableFromClusterSnapshotResult(TypedDict, total=False):
    TableRestoreStatus: Optional[TableRestoreStatus]


class ResumeClusterResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


class RevokeClusterSecurityGroupIngressMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    CIDRIP: Optional[String]
    EC2SecurityGroupName: Optional[String]
    EC2SecurityGroupOwnerId: Optional[String]


class RevokeClusterSecurityGroupIngressResult(TypedDict, total=False):
    ClusterSecurityGroup: Optional[ClusterSecurityGroup]


class RevokeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: Optional[String]
    Account: Optional[String]
    VpcIds: Optional[VpcIdentifierList]
    Force: Optional[Boolean]


class RevokeSnapshotAccessMessage(ServiceRequest):
    SnapshotIdentifier: String
    SnapshotClusterIdentifier: Optional[String]
    AccountWithRestoreAccess: String


class RevokeSnapshotAccessResult(TypedDict, total=False):
    Snapshot: Optional[Snapshot]


class RotateEncryptionKeyMessage(ServiceRequest):
    ClusterIdentifier: String


class RotateEncryptionKeyResult(TypedDict, total=False):
    Cluster: Optional[Cluster]


ScheduledActionTimeList = List[TStamp]


class ScheduledAction(TypedDict, total=False):
    ScheduledActionName: Optional[String]
    TargetAction: Optional[ScheduledActionType]
    Schedule: Optional[String]
    IamRole: Optional[String]
    ScheduledActionDescription: Optional[String]
    State: Optional[ScheduledActionState]
    NextInvocations: Optional[ScheduledActionTimeList]
    StartTime: Optional[TStamp]
    EndTime: Optional[TStamp]


ScheduledActionList = List[ScheduledAction]


class ScheduledActionsMessage(TypedDict, total=False):
    Marker: Optional[String]
    ScheduledActions: Optional[ScheduledActionList]


SnapshotCopyGrantList = List[SnapshotCopyGrant]


class SnapshotCopyGrantMessage(TypedDict, total=False):
    Marker: Optional[String]
    SnapshotCopyGrants: Optional[SnapshotCopyGrantList]


SnapshotList = List[Snapshot]


class SnapshotMessage(TypedDict, total=False):
    Marker: Optional[String]
    Snapshots: Optional[SnapshotList]


TableRestoreStatusList = List[TableRestoreStatus]


class TableRestoreStatusMessage(TypedDict, total=False):
    TableRestoreStatusDetails: Optional[TableRestoreStatusList]
    Marker: Optional[String]


class TaggedResource(TypedDict, total=False):
    Tag: Optional[Tag]
    ResourceName: Optional[String]
    ResourceType: Optional[String]


TaggedResourceList = List[TaggedResource]


class TaggedResourceListMessage(TypedDict, total=False):
    TaggedResources: Optional[TaggedResourceList]
    Marker: Optional[String]


TrackList = List[MaintenanceTrack]


class TrackListMessage(TypedDict, total=False):
    MaintenanceTracks: Optional[TrackList]
    Marker: Optional[String]


class UpdatePartnerStatusInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: PartnerIntegrationDatabaseName
    PartnerName: PartnerIntegrationPartnerName
    Status: PartnerIntegrationStatus
    StatusMessage: Optional[PartnerIntegrationStatusMessage]


class UsageLimit(TypedDict, total=False):
    UsageLimitId: Optional[String]
    ClusterIdentifier: Optional[String]
    FeatureType: Optional[UsageLimitFeatureType]
    LimitType: Optional[UsageLimitLimitType]
    Amount: Optional[Long]
    Period: Optional[UsageLimitPeriod]
    BreachAction: Optional[UsageLimitBreachAction]
    Tags: Optional[TagList]


UsageLimits = List[UsageLimit]


class UsageLimitList(TypedDict, total=False):
    UsageLimits: Optional[UsageLimits]
    Marker: Optional[String]


class RedshiftApi:

    service = "redshift"
    version = "2012-12-01"

    @handler("AcceptReservedNodeExchange")
    def accept_reserved_node_exchange(
        self,
        context: RequestContext,
        reserved_node_id: String,
        target_reserved_node_offering_id: String,
    ) -> AcceptReservedNodeExchangeOutputMessage:
        raise NotImplementedError

    @handler("AddPartner")
    def add_partner(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName,
        partner_name: PartnerIntegrationPartnerName,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError

    @handler("AssociateDataShareConsumer")
    def associate_data_share_consumer(
        self,
        context: RequestContext,
        data_share_arn: String,
        associate_entire_account: BooleanOptional = None,
        consumer_arn: String = None,
    ) -> DataShare:
        raise NotImplementedError

    @handler("AuthorizeClusterSecurityGroupIngress")
    def authorize_cluster_security_group_ingress(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        cidrip: String = None,
        ec2_security_group_name: String = None,
        ec2_security_group_owner_id: String = None,
    ) -> AuthorizeClusterSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("AuthorizeDataShare")
    def authorize_data_share(
        self,
        context: RequestContext,
        data_share_arn: String,
        consumer_identifier: String,
    ) -> DataShare:
        raise NotImplementedError

    @handler("AuthorizeEndpointAccess")
    def authorize_endpoint_access(
        self,
        context: RequestContext,
        account: String,
        cluster_identifier: String = None,
        vpc_ids: VpcIdentifierList = None,
    ) -> EndpointAuthorization:
        raise NotImplementedError

    @handler("AuthorizeSnapshotAccess")
    def authorize_snapshot_access(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        account_with_restore_access: String,
        snapshot_cluster_identifier: String = None,
    ) -> AuthorizeSnapshotAccessResult:
        raise NotImplementedError

    @handler("BatchDeleteClusterSnapshots")
    def batch_delete_cluster_snapshots(
        self, context: RequestContext, identifiers: DeleteClusterSnapshotMessageList
    ) -> BatchDeleteClusterSnapshotsResult:
        raise NotImplementedError

    @handler("BatchModifyClusterSnapshots")
    def batch_modify_cluster_snapshots(
        self,
        context: RequestContext,
        snapshot_identifier_list: SnapshotIdentifierList,
        manual_snapshot_retention_period: IntegerOptional = None,
        force: Boolean = None,
    ) -> BatchModifyClusterSnapshotsOutputMessage:
        raise NotImplementedError

    @handler("CancelResize")
    def cancel_resize(
        self, context: RequestContext, cluster_identifier: String
    ) -> ResizeProgressMessage:
        raise NotImplementedError

    @handler("CopyClusterSnapshot")
    def copy_cluster_snapshot(
        self,
        context: RequestContext,
        source_snapshot_identifier: String,
        target_snapshot_identifier: String,
        source_snapshot_cluster_identifier: String = None,
        manual_snapshot_retention_period: IntegerOptional = None,
    ) -> CopyClusterSnapshotResult:
        raise NotImplementedError

    @handler("CreateAuthenticationProfile")
    def create_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
        authentication_profile_content: String,
    ) -> CreateAuthenticationProfileResult:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        node_type: String,
        master_username: String,
        master_user_password: String,
        db_name: String = None,
        cluster_type: String = None,
        cluster_security_groups: ClusterSecurityGroupNameList = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        cluster_subnet_group_name: String = None,
        availability_zone: String = None,
        preferred_maintenance_window: String = None,
        cluster_parameter_group_name: String = None,
        automated_snapshot_retention_period: IntegerOptional = None,
        manual_snapshot_retention_period: IntegerOptional = None,
        port: IntegerOptional = None,
        cluster_version: String = None,
        allow_version_upgrade: BooleanOptional = None,
        number_of_nodes: IntegerOptional = None,
        publicly_accessible: BooleanOptional = None,
        encrypted: BooleanOptional = None,
        hsm_client_certificate_identifier: String = None,
        hsm_configuration_identifier: String = None,
        elastic_ip: String = None,
        tags: TagList = None,
        kms_key_id: String = None,
        enhanced_vpc_routing: BooleanOptional = None,
        additional_info: String = None,
        iam_roles: IamRoleArnList = None,
        maintenance_track_name: String = None,
        snapshot_schedule_identifier: String = None,
        availability_zone_relocation: BooleanOptional = None,
        aqua_configuration_status: AquaConfigurationStatus = None,
        default_iam_role_arn: String = None,
    ) -> CreateClusterResult:
        raise NotImplementedError

    @handler("CreateClusterParameterGroup")
    def create_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        parameter_group_family: String,
        description: String,
        tags: TagList = None,
    ) -> CreateClusterParameterGroupResult:
        raise NotImplementedError

    @handler("CreateClusterSecurityGroup")
    def create_cluster_security_group(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        description: String,
        tags: TagList = None,
    ) -> CreateClusterSecurityGroupResult:
        raise NotImplementedError

    @handler("CreateClusterSnapshot")
    def create_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        cluster_identifier: String,
        manual_snapshot_retention_period: IntegerOptional = None,
        tags: TagList = None,
    ) -> CreateClusterSnapshotResult:
        raise NotImplementedError

    @handler("CreateClusterSubnetGroup")
    def create_cluster_subnet_group(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String,
        description: String,
        subnet_ids: SubnetIdentifierList,
        tags: TagList = None,
    ) -> CreateClusterSubnetGroupResult:
        raise NotImplementedError

    @handler("CreateEndpointAccess")
    def create_endpoint_access(
        self,
        context: RequestContext,
        endpoint_name: String,
        subnet_group_name: String,
        cluster_identifier: String = None,
        resource_owner: String = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("CreateEventSubscription")
    def create_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String,
        source_type: String = None,
        source_ids: SourceIdsList = None,
        event_categories: EventCategoriesList = None,
        severity: String = None,
        enabled: BooleanOptional = None,
        tags: TagList = None,
    ) -> CreateEventSubscriptionResult:
        raise NotImplementedError

    @handler("CreateHsmClientCertificate")
    def create_hsm_client_certificate(
        self,
        context: RequestContext,
        hsm_client_certificate_identifier: String,
        tags: TagList = None,
    ) -> CreateHsmClientCertificateResult:
        raise NotImplementedError

    @handler("CreateHsmConfiguration")
    def create_hsm_configuration(
        self,
        context: RequestContext,
        hsm_configuration_identifier: String,
        description: String,
        hsm_ip_address: String,
        hsm_partition_name: String,
        hsm_partition_password: String,
        hsm_server_public_certificate: String,
        tags: TagList = None,
    ) -> CreateHsmConfigurationResult:
        raise NotImplementedError

    @handler("CreateScheduledAction")
    def create_scheduled_action(
        self,
        context: RequestContext,
        scheduled_action_name: String,
        target_action: ScheduledActionType,
        schedule: String,
        iam_role: String,
        scheduled_action_description: String = None,
        start_time: TStamp = None,
        end_time: TStamp = None,
        enable: BooleanOptional = None,
    ) -> ScheduledAction:
        raise NotImplementedError

    @handler("CreateSnapshotCopyGrant")
    def create_snapshot_copy_grant(
        self,
        context: RequestContext,
        snapshot_copy_grant_name: String,
        kms_key_id: String = None,
        tags: TagList = None,
    ) -> CreateSnapshotCopyGrantResult:
        raise NotImplementedError

    @handler("CreateSnapshotSchedule")
    def create_snapshot_schedule(
        self,
        context: RequestContext,
        schedule_definitions: ScheduleDefinitionList = None,
        schedule_identifier: String = None,
        schedule_description: String = None,
        tags: TagList = None,
        dry_run: BooleanOptional = None,
        next_invocations: IntegerOptional = None,
    ) -> SnapshotSchedule:
        raise NotImplementedError

    @handler("CreateTags")
    def create_tags(self, context: RequestContext, resource_name: String, tags: TagList) -> None:
        raise NotImplementedError

    @handler("CreateUsageLimit")
    def create_usage_limit(
        self,
        context: RequestContext,
        cluster_identifier: String,
        feature_type: UsageLimitFeatureType,
        limit_type: UsageLimitLimitType,
        amount: Long,
        period: UsageLimitPeriod = None,
        breach_action: UsageLimitBreachAction = None,
        tags: TagList = None,
    ) -> UsageLimit:
        raise NotImplementedError

    @handler("DeauthorizeDataShare")
    def deauthorize_data_share(
        self,
        context: RequestContext,
        data_share_arn: String,
        consumer_identifier: String,
    ) -> DataShare:
        raise NotImplementedError

    @handler("DeleteAuthenticationProfile")
    def delete_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
    ) -> DeleteAuthenticationProfileResult:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        skip_final_cluster_snapshot: Boolean = None,
        final_cluster_snapshot_identifier: String = None,
        final_cluster_snapshot_retention_period: IntegerOptional = None,
    ) -> DeleteClusterResult:
        raise NotImplementedError

    @handler("DeleteClusterParameterGroup")
    def delete_cluster_parameter_group(
        self, context: RequestContext, parameter_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteClusterSecurityGroup")
    def delete_cluster_security_group(
        self, context: RequestContext, cluster_security_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteClusterSnapshot")
    def delete_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        snapshot_cluster_identifier: String = None,
    ) -> DeleteClusterSnapshotResult:
        raise NotImplementedError

    @handler("DeleteClusterSubnetGroup")
    def delete_cluster_subnet_group(
        self, context: RequestContext, cluster_subnet_group_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEndpointAccess")
    def delete_endpoint_access(
        self, context: RequestContext, endpoint_name: String
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("DeleteEventSubscription")
    def delete_event_subscription(self, context: RequestContext, subscription_name: String) -> None:
        raise NotImplementedError

    @handler("DeleteHsmClientCertificate")
    def delete_hsm_client_certificate(
        self, context: RequestContext, hsm_client_certificate_identifier: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteHsmConfiguration")
    def delete_hsm_configuration(
        self, context: RequestContext, hsm_configuration_identifier: String
    ) -> None:
        raise NotImplementedError

    @handler("DeletePartner")
    def delete_partner(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName,
        partner_name: PartnerIntegrationPartnerName,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError

    @handler("DeleteScheduledAction")
    def delete_scheduled_action(
        self, context: RequestContext, scheduled_action_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSnapshotCopyGrant")
    def delete_snapshot_copy_grant(
        self, context: RequestContext, snapshot_copy_grant_name: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSnapshotSchedule")
    def delete_snapshot_schedule(
        self, context: RequestContext, schedule_identifier: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(
        self, context: RequestContext, resource_name: String, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUsageLimit")
    def delete_usage_limit(self, context: RequestContext, usage_limit_id: String) -> None:
        raise NotImplementedError

    @handler("DescribeAccountAttributes")
    def describe_account_attributes(
        self, context: RequestContext, attribute_names: AttributeNameList = None
    ) -> AccountAttributeList:
        raise NotImplementedError

    @handler("DescribeAuthenticationProfiles")
    def describe_authentication_profiles(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString = None,
    ) -> DescribeAuthenticationProfilesResult:
        raise NotImplementedError

    @handler("DescribeClusterDbRevisions")
    def describe_cluster_db_revisions(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ClusterDbRevisionsMessage:
        raise NotImplementedError

    @handler("DescribeClusterParameterGroups")
    def describe_cluster_parameter_groups(
        self,
        context: RequestContext,
        parameter_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> ClusterParameterGroupsMessage:
        raise NotImplementedError

    @handler("DescribeClusterParameters")
    def describe_cluster_parameters(
        self,
        context: RequestContext,
        parameter_group_name: String,
        source: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ClusterParameterGroupDetails:
        raise NotImplementedError

    @handler("DescribeClusterSecurityGroups")
    def describe_cluster_security_groups(
        self,
        context: RequestContext,
        cluster_security_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> ClusterSecurityGroupMessage:
        raise NotImplementedError

    @handler("DescribeClusterSnapshots")
    def describe_cluster_snapshots(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        snapshot_identifier: String = None,
        snapshot_type: String = None,
        start_time: TStamp = None,
        end_time: TStamp = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        owner_account: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
        cluster_exists: BooleanOptional = None,
        sorting_entities: SnapshotSortingEntityList = None,
    ) -> SnapshotMessage:
        raise NotImplementedError

    @handler("DescribeClusterSubnetGroups")
    def describe_cluster_subnet_groups(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> ClusterSubnetGroupMessage:
        raise NotImplementedError

    @handler("DescribeClusterTracks")
    def describe_cluster_tracks(
        self,
        context: RequestContext,
        maintenance_track_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> TrackListMessage:
        raise NotImplementedError

    @handler("DescribeClusterVersions")
    def describe_cluster_versions(
        self,
        context: RequestContext,
        cluster_version: String = None,
        cluster_parameter_group_family: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ClusterVersionsMessage:
        raise NotImplementedError

    @handler("DescribeClusters")
    def describe_clusters(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> ClustersMessage:
        raise NotImplementedError

    @handler("DescribeDataShares")
    def describe_data_shares(
        self,
        context: RequestContext,
        data_share_arn: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeDataSharesResult:
        raise NotImplementedError

    @handler("DescribeDataSharesForConsumer")
    def describe_data_shares_for_consumer(
        self,
        context: RequestContext,
        consumer_arn: String = None,
        status: DataShareStatusForConsumer = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeDataSharesForConsumerResult:
        raise NotImplementedError

    @handler("DescribeDataSharesForProducer")
    def describe_data_shares_for_producer(
        self,
        context: RequestContext,
        producer_arn: String = None,
        status: DataShareStatusForProducer = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeDataSharesForProducerResult:
        raise NotImplementedError

    @handler("DescribeDefaultClusterParameters")
    def describe_default_cluster_parameters(
        self,
        context: RequestContext,
        parameter_group_family: String,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeDefaultClusterParametersResult:
        raise NotImplementedError

    @handler("DescribeEndpointAccess")
    def describe_endpoint_access(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        resource_owner: String = None,
        endpoint_name: String = None,
        vpc_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EndpointAccessList:
        raise NotImplementedError

    @handler("DescribeEndpointAuthorization")
    def describe_endpoint_authorization(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        account: String = None,
        grantee: BooleanOptional = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EndpointAuthorizationList:
        raise NotImplementedError

    @handler("DescribeEventCategories")
    def describe_event_categories(
        self, context: RequestContext, source_type: String = None
    ) -> EventCategoriesMessage:
        raise NotImplementedError

    @handler("DescribeEventSubscriptions")
    def describe_event_subscriptions(
        self,
        context: RequestContext,
        subscription_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
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
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> EventsMessage:
        raise NotImplementedError

    @handler("DescribeHsmClientCertificates")
    def describe_hsm_client_certificates(
        self,
        context: RequestContext,
        hsm_client_certificate_identifier: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> HsmClientCertificateMessage:
        raise NotImplementedError

    @handler("DescribeHsmConfigurations")
    def describe_hsm_configurations(
        self,
        context: RequestContext,
        hsm_configuration_identifier: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> HsmConfigurationMessage:
        raise NotImplementedError

    @handler("DescribeLoggingStatus")
    def describe_logging_status(
        self, context: RequestContext, cluster_identifier: String
    ) -> LoggingStatus:
        raise NotImplementedError

    @handler("DescribeNodeConfigurationOptions")
    def describe_node_configuration_options(
        self,
        context: RequestContext,
        action_type: ActionType,
        cluster_identifier: String = None,
        snapshot_identifier: String = None,
        owner_account: String = None,
        filters: NodeConfigurationOptionsFilterList = None,
        marker: String = None,
        max_records: IntegerOptional = None,
    ) -> NodeConfigurationOptionsMessage:
        raise NotImplementedError

    @handler("DescribeOrderableClusterOptions")
    def describe_orderable_cluster_options(
        self,
        context: RequestContext,
        cluster_version: String = None,
        node_type: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> OrderableClusterOptionsMessage:
        raise NotImplementedError

    @handler("DescribePartners")
    def describe_partners(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName = None,
        partner_name: PartnerIntegrationPartnerName = None,
    ) -> DescribePartnersOutputMessage:
        raise NotImplementedError

    @handler("DescribeReservedNodeExchangeStatus")
    def describe_reserved_node_exchange_status(
        self,
        context: RequestContext,
        reserved_node_id: String = None,
        reserved_node_exchange_request_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> DescribeReservedNodeExchangeStatusOutputMessage:
        raise NotImplementedError

    @handler("DescribeReservedNodeOfferings")
    def describe_reserved_node_offerings(
        self,
        context: RequestContext,
        reserved_node_offering_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedNodeOfferingsMessage:
        raise NotImplementedError

    @handler("DescribeReservedNodes")
    def describe_reserved_nodes(
        self,
        context: RequestContext,
        reserved_node_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> ReservedNodesMessage:
        raise NotImplementedError

    @handler("DescribeResize")
    def describe_resize(
        self, context: RequestContext, cluster_identifier: String
    ) -> ResizeProgressMessage:
        raise NotImplementedError

    @handler("DescribeScheduledActions")
    def describe_scheduled_actions(
        self,
        context: RequestContext,
        scheduled_action_name: String = None,
        target_action_type: ScheduledActionTypeValues = None,
        start_time: TStamp = None,
        end_time: TStamp = None,
        active: BooleanOptional = None,
        filters: ScheduledActionFilterList = None,
        marker: String = None,
        max_records: IntegerOptional = None,
    ) -> ScheduledActionsMessage:
        raise NotImplementedError

    @handler("DescribeSnapshotCopyGrants")
    def describe_snapshot_copy_grants(
        self,
        context: RequestContext,
        snapshot_copy_grant_name: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> SnapshotCopyGrantMessage:
        raise NotImplementedError

    @handler("DescribeSnapshotSchedules")
    def describe_snapshot_schedules(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        schedule_identifier: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
        marker: String = None,
        max_records: IntegerOptional = None,
    ) -> DescribeSnapshotSchedulesOutputMessage:
        raise NotImplementedError

    @handler("DescribeStorage")
    def describe_storage(
        self,
        context: RequestContext,
    ) -> CustomerStorageMessage:
        raise NotImplementedError

    @handler("DescribeTableRestoreStatus")
    def describe_table_restore_status(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        table_restore_request_id: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> TableRestoreStatusMessage:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self,
        context: RequestContext,
        resource_name: String = None,
        resource_type: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> TaggedResourceListMessage:
        raise NotImplementedError

    @handler("DescribeUsageLimits")
    def describe_usage_limits(
        self,
        context: RequestContext,
        usage_limit_id: String = None,
        cluster_identifier: String = None,
        feature_type: UsageLimitFeatureType = None,
        max_records: IntegerOptional = None,
        marker: String = None,
        tag_keys: TagKeyList = None,
        tag_values: TagValueList = None,
    ) -> UsageLimitList:
        raise NotImplementedError

    @handler("DisableLogging")
    def disable_logging(self, context: RequestContext, cluster_identifier: String) -> LoggingStatus:
        raise NotImplementedError

    @handler("DisableSnapshotCopy")
    def disable_snapshot_copy(
        self, context: RequestContext, cluster_identifier: String
    ) -> DisableSnapshotCopyResult:
        raise NotImplementedError

    @handler("DisassociateDataShareConsumer")
    def disassociate_data_share_consumer(
        self,
        context: RequestContext,
        data_share_arn: String,
        disassociate_entire_account: BooleanOptional = None,
        consumer_arn: String = None,
    ) -> DataShare:
        raise NotImplementedError

    @handler("EnableLogging")
    def enable_logging(
        self,
        context: RequestContext,
        cluster_identifier: String,
        bucket_name: String,
        s3_key_prefix: String = None,
    ) -> LoggingStatus:
        raise NotImplementedError

    @handler("EnableSnapshotCopy")
    def enable_snapshot_copy(
        self,
        context: RequestContext,
        cluster_identifier: String,
        destination_region: String,
        retention_period: IntegerOptional = None,
        snapshot_copy_grant_name: String = None,
        manual_snapshot_retention_period: IntegerOptional = None,
    ) -> EnableSnapshotCopyResult:
        raise NotImplementedError

    @handler("GetClusterCredentials")
    def get_cluster_credentials(
        self,
        context: RequestContext,
        db_user: String,
        cluster_identifier: String,
        db_name: String = None,
        duration_seconds: IntegerOptional = None,
        auto_create: BooleanOptional = None,
        db_groups: DbGroupList = None,
    ) -> ClusterCredentials:
        raise NotImplementedError

    @handler("GetReservedNodeExchangeConfigurationOptions")
    def get_reserved_node_exchange_configuration_options(
        self,
        context: RequestContext,
        action_type: ReservedNodeExchangeActionType,
        cluster_identifier: String = None,
        snapshot_identifier: String = None,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> GetReservedNodeExchangeConfigurationOptionsOutputMessage:
        raise NotImplementedError

    @handler("GetReservedNodeExchangeOfferings")
    def get_reserved_node_exchange_offerings(
        self,
        context: RequestContext,
        reserved_node_id: String,
        max_records: IntegerOptional = None,
        marker: String = None,
    ) -> GetReservedNodeExchangeOfferingsOutputMessage:
        raise NotImplementedError

    @handler("ModifyAquaConfiguration")
    def modify_aqua_configuration(
        self,
        context: RequestContext,
        cluster_identifier: String,
        aqua_configuration_status: AquaConfigurationStatus = None,
    ) -> ModifyAquaOutputMessage:
        raise NotImplementedError

    @handler("ModifyAuthenticationProfile")
    def modify_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
        authentication_profile_content: String,
    ) -> ModifyAuthenticationProfileResult:
        raise NotImplementedError

    @handler("ModifyCluster")
    def modify_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        cluster_type: String = None,
        node_type: String = None,
        number_of_nodes: IntegerOptional = None,
        cluster_security_groups: ClusterSecurityGroupNameList = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        master_user_password: String = None,
        cluster_parameter_group_name: String = None,
        automated_snapshot_retention_period: IntegerOptional = None,
        manual_snapshot_retention_period: IntegerOptional = None,
        preferred_maintenance_window: String = None,
        cluster_version: String = None,
        allow_version_upgrade: BooleanOptional = None,
        hsm_client_certificate_identifier: String = None,
        hsm_configuration_identifier: String = None,
        new_cluster_identifier: String = None,
        publicly_accessible: BooleanOptional = None,
        elastic_ip: String = None,
        enhanced_vpc_routing: BooleanOptional = None,
        maintenance_track_name: String = None,
        encrypted: BooleanOptional = None,
        kms_key_id: String = None,
        availability_zone_relocation: BooleanOptional = None,
        availability_zone: String = None,
        port: IntegerOptional = None,
    ) -> ModifyClusterResult:
        raise NotImplementedError

    @handler("ModifyClusterDbRevision")
    def modify_cluster_db_revision(
        self,
        context: RequestContext,
        cluster_identifier: String,
        revision_target: String,
    ) -> ModifyClusterDbRevisionResult:
        raise NotImplementedError

    @handler("ModifyClusterIamRoles")
    def modify_cluster_iam_roles(
        self,
        context: RequestContext,
        cluster_identifier: String,
        add_iam_roles: IamRoleArnList = None,
        remove_iam_roles: IamRoleArnList = None,
        default_iam_role_arn: String = None,
    ) -> ModifyClusterIamRolesResult:
        raise NotImplementedError

    @handler("ModifyClusterMaintenance")
    def modify_cluster_maintenance(
        self,
        context: RequestContext,
        cluster_identifier: String,
        defer_maintenance: BooleanOptional = None,
        defer_maintenance_identifier: String = None,
        defer_maintenance_start_time: TStamp = None,
        defer_maintenance_end_time: TStamp = None,
        defer_maintenance_duration: IntegerOptional = None,
    ) -> ModifyClusterMaintenanceResult:
        raise NotImplementedError

    @handler("ModifyClusterParameterGroup")
    def modify_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        parameters: ParametersList,
    ) -> ClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyClusterSnapshot")
    def modify_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        manual_snapshot_retention_period: IntegerOptional = None,
        force: Boolean = None,
    ) -> ModifyClusterSnapshotResult:
        raise NotImplementedError

    @handler("ModifyClusterSnapshotSchedule")
    def modify_cluster_snapshot_schedule(
        self,
        context: RequestContext,
        cluster_identifier: String,
        schedule_identifier: String = None,
        disassociate_schedule: BooleanOptional = None,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyClusterSubnetGroup")
    def modify_cluster_subnet_group(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String,
        subnet_ids: SubnetIdentifierList,
        description: String = None,
    ) -> ModifyClusterSubnetGroupResult:
        raise NotImplementedError

    @handler("ModifyEndpointAccess")
    def modify_endpoint_access(
        self,
        context: RequestContext,
        endpoint_name: String,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("ModifyEventSubscription")
    def modify_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String = None,
        source_type: String = None,
        source_ids: SourceIdsList = None,
        event_categories: EventCategoriesList = None,
        severity: String = None,
        enabled: BooleanOptional = None,
    ) -> ModifyEventSubscriptionResult:
        raise NotImplementedError

    @handler("ModifyScheduledAction")
    def modify_scheduled_action(
        self,
        context: RequestContext,
        scheduled_action_name: String,
        target_action: ScheduledActionType = None,
        schedule: String = None,
        iam_role: String = None,
        scheduled_action_description: String = None,
        start_time: TStamp = None,
        end_time: TStamp = None,
        enable: BooleanOptional = None,
    ) -> ScheduledAction:
        raise NotImplementedError

    @handler("ModifySnapshotCopyRetentionPeriod")
    def modify_snapshot_copy_retention_period(
        self,
        context: RequestContext,
        cluster_identifier: String,
        retention_period: Integer,
        manual: Boolean = None,
    ) -> ModifySnapshotCopyRetentionPeriodResult:
        raise NotImplementedError

    @handler("ModifySnapshotSchedule")
    def modify_snapshot_schedule(
        self,
        context: RequestContext,
        schedule_identifier: String,
        schedule_definitions: ScheduleDefinitionList,
    ) -> SnapshotSchedule:
        raise NotImplementedError

    @handler("ModifyUsageLimit")
    def modify_usage_limit(
        self,
        context: RequestContext,
        usage_limit_id: String,
        amount: LongOptional = None,
        breach_action: UsageLimitBreachAction = None,
    ) -> UsageLimit:
        raise NotImplementedError

    @handler("PauseCluster")
    def pause_cluster(
        self, context: RequestContext, cluster_identifier: String
    ) -> PauseClusterResult:
        raise NotImplementedError

    @handler("PurchaseReservedNodeOffering")
    def purchase_reserved_node_offering(
        self,
        context: RequestContext,
        reserved_node_offering_id: String,
        node_count: IntegerOptional = None,
    ) -> PurchaseReservedNodeOfferingResult:
        raise NotImplementedError

    @handler("RebootCluster")
    def reboot_cluster(
        self, context: RequestContext, cluster_identifier: String
    ) -> RebootClusterResult:
        raise NotImplementedError

    @handler("RejectDataShare")
    def reject_data_share(self, context: RequestContext, data_share_arn: String) -> DataShare:
        raise NotImplementedError

    @handler("ResetClusterParameterGroup")
    def reset_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        reset_all_parameters: Boolean = None,
        parameters: ParametersList = None,
    ) -> ClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ResizeCluster")
    def resize_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        cluster_type: String = None,
        node_type: String = None,
        number_of_nodes: IntegerOptional = None,
        classic: BooleanOptional = None,
        reserved_node_id: String = None,
        target_reserved_node_offering_id: String = None,
    ) -> ResizeClusterResult:
        raise NotImplementedError

    @handler("RestoreFromClusterSnapshot")
    def restore_from_cluster_snapshot(
        self,
        context: RequestContext,
        cluster_identifier: String,
        snapshot_identifier: String,
        snapshot_cluster_identifier: String = None,
        port: IntegerOptional = None,
        availability_zone: String = None,
        allow_version_upgrade: BooleanOptional = None,
        cluster_subnet_group_name: String = None,
        publicly_accessible: BooleanOptional = None,
        owner_account: String = None,
        hsm_client_certificate_identifier: String = None,
        hsm_configuration_identifier: String = None,
        elastic_ip: String = None,
        cluster_parameter_group_name: String = None,
        cluster_security_groups: ClusterSecurityGroupNameList = None,
        vpc_security_group_ids: VpcSecurityGroupIdList = None,
        preferred_maintenance_window: String = None,
        automated_snapshot_retention_period: IntegerOptional = None,
        manual_snapshot_retention_period: IntegerOptional = None,
        kms_key_id: String = None,
        node_type: String = None,
        enhanced_vpc_routing: BooleanOptional = None,
        additional_info: String = None,
        iam_roles: IamRoleArnList = None,
        maintenance_track_name: String = None,
        snapshot_schedule_identifier: String = None,
        number_of_nodes: IntegerOptional = None,
        availability_zone_relocation: BooleanOptional = None,
        aqua_configuration_status: AquaConfigurationStatus = None,
        default_iam_role_arn: String = None,
        reserved_node_id: String = None,
        target_reserved_node_offering_id: String = None,
    ) -> RestoreFromClusterSnapshotResult:
        raise NotImplementedError

    @handler("RestoreTableFromClusterSnapshot")
    def restore_table_from_cluster_snapshot(
        self,
        context: RequestContext,
        cluster_identifier: String,
        snapshot_identifier: String,
        source_database_name: String,
        source_table_name: String,
        new_table_name: String,
        source_schema_name: String = None,
        target_database_name: String = None,
        target_schema_name: String = None,
        enable_case_sensitive_identifier: BooleanOptional = None,
    ) -> RestoreTableFromClusterSnapshotResult:
        raise NotImplementedError

    @handler("ResumeCluster")
    def resume_cluster(
        self, context: RequestContext, cluster_identifier: String
    ) -> ResumeClusterResult:
        raise NotImplementedError

    @handler("RevokeClusterSecurityGroupIngress")
    def revoke_cluster_security_group_ingress(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        cidrip: String = None,
        ec2_security_group_name: String = None,
        ec2_security_group_owner_id: String = None,
    ) -> RevokeClusterSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("RevokeEndpointAccess")
    def revoke_endpoint_access(
        self,
        context: RequestContext,
        cluster_identifier: String = None,
        account: String = None,
        vpc_ids: VpcIdentifierList = None,
        force: Boolean = None,
    ) -> EndpointAuthorization:
        raise NotImplementedError

    @handler("RevokeSnapshotAccess")
    def revoke_snapshot_access(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        account_with_restore_access: String,
        snapshot_cluster_identifier: String = None,
    ) -> RevokeSnapshotAccessResult:
        raise NotImplementedError

    @handler("RotateEncryptionKey")
    def rotate_encryption_key(
        self, context: RequestContext, cluster_identifier: String
    ) -> RotateEncryptionKeyResult:
        raise NotImplementedError

    @handler("UpdatePartnerStatus")
    def update_partner_status(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName,
        partner_name: PartnerIntegrationPartnerName,
        status: PartnerIntegrationStatus,
        status_message: PartnerIntegrationStatusMessage = None,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError
