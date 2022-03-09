import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
BackendRole = str
Boolean = bool
ChangeProgressStageName = str
ChangeProgressStageStatus = str
CloudWatchLogsLogGroupArn = str
CommitMessage = str
ConnectionAlias = str
ConnectionId = str
ConnectionStatusMessage = str
DeploymentType = str
DescribePackagesFilterValue = str
Description = str
DomainId = str
DomainName = str
DomainNameFqdn = str
Double = float
DryRun = bool
ErrorMessage = str
ErrorType = str
GUID = str
IdentityPoolId = str
InstanceCount = int
InstanceRole = str
Integer = int
IntegerClass = int
Issue = str
KmsKeyId = str
LimitName = str
LimitValue = str
MaxResults = int
MaximumInstanceCount = int
Message = str
MinimumInstanceCount = int
NextToken = str
NonEmptyString = str
OwnerId = str
PackageDescription = str
PackageID = str
PackageName = str
PackageVersion = str
Password = str
PolicyDocument = str
ReferencePath = str
Region = str
ReservationToken = str
RoleArn = str
S3BucketName = str
S3Key = str
SAMLEntityId = str
SAMLMetadata = str
ScheduledAutoTuneDescription = str
ServiceUrl = str
StorageSubTypeName = str
StorageTypeName = str
String = str
TagKey = str
TagValue = str
TotalNumberOfStages = int
UIntValue = int
UpgradeName = str
UserPoolId = str
Username = str
VersionString = str


class AutoTuneDesiredState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class AutoTuneState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ENABLE_IN_PROGRESS = "ENABLE_IN_PROGRESS"
    DISABLE_IN_PROGRESS = "DISABLE_IN_PROGRESS"
    DISABLED_AND_ROLLBACK_SCHEDULED = "DISABLED_AND_ROLLBACK_SCHEDULED"
    DISABLED_AND_ROLLBACK_IN_PROGRESS = "DISABLED_AND_ROLLBACK_IN_PROGRESS"
    DISABLED_AND_ROLLBACK_COMPLETE = "DISABLED_AND_ROLLBACK_COMPLETE"
    DISABLED_AND_ROLLBACK_ERROR = "DISABLED_AND_ROLLBACK_ERROR"
    ERROR = "ERROR"


class AutoTuneType(str):
    SCHEDULED_ACTION = "SCHEDULED_ACTION"


class DeploymentStatus(str):
    PENDING_UPDATE = "PENDING_UPDATE"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    ELIGIBLE = "ELIGIBLE"


class DescribePackagesFilterName(str):
    PackageID = "PackageID"
    PackageName = "PackageName"
    PackageStatus = "PackageStatus"


class DomainPackageStatus(str):
    ASSOCIATING = "ASSOCIATING"
    ASSOCIATION_FAILED = "ASSOCIATION_FAILED"
    ACTIVE = "ACTIVE"
    DISSOCIATING = "DISSOCIATING"
    DISSOCIATION_FAILED = "DISSOCIATION_FAILED"


class EngineType(str):
    OpenSearch = "OpenSearch"
    Elasticsearch = "Elasticsearch"


class InboundConnectionStatusCode(str):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    APPROVED = "APPROVED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    REJECTING = "REJECTING"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class LogType(str):
    INDEX_SLOW_LOGS = "INDEX_SLOW_LOGS"
    SEARCH_SLOW_LOGS = "SEARCH_SLOW_LOGS"
    ES_APPLICATION_LOGS = "ES_APPLICATION_LOGS"
    AUDIT_LOGS = "AUDIT_LOGS"


class OpenSearchPartitionInstanceType(str):
    m3_medium_search = "m3.medium.search"
    m3_large_search = "m3.large.search"
    m3_xlarge_search = "m3.xlarge.search"
    m3_2xlarge_search = "m3.2xlarge.search"
    m4_large_search = "m4.large.search"
    m4_xlarge_search = "m4.xlarge.search"
    m4_2xlarge_search = "m4.2xlarge.search"
    m4_4xlarge_search = "m4.4xlarge.search"
    m4_10xlarge_search = "m4.10xlarge.search"
    m5_large_search = "m5.large.search"
    m5_xlarge_search = "m5.xlarge.search"
    m5_2xlarge_search = "m5.2xlarge.search"
    m5_4xlarge_search = "m5.4xlarge.search"
    m5_12xlarge_search = "m5.12xlarge.search"
    m5_24xlarge_search = "m5.24xlarge.search"
    r5_large_search = "r5.large.search"
    r5_xlarge_search = "r5.xlarge.search"
    r5_2xlarge_search = "r5.2xlarge.search"
    r5_4xlarge_search = "r5.4xlarge.search"
    r5_12xlarge_search = "r5.12xlarge.search"
    r5_24xlarge_search = "r5.24xlarge.search"
    c5_large_search = "c5.large.search"
    c5_xlarge_search = "c5.xlarge.search"
    c5_2xlarge_search = "c5.2xlarge.search"
    c5_4xlarge_search = "c5.4xlarge.search"
    c5_9xlarge_search = "c5.9xlarge.search"
    c5_18xlarge_search = "c5.18xlarge.search"
    t3_nano_search = "t3.nano.search"
    t3_micro_search = "t3.micro.search"
    t3_small_search = "t3.small.search"
    t3_medium_search = "t3.medium.search"
    t3_large_search = "t3.large.search"
    t3_xlarge_search = "t3.xlarge.search"
    t3_2xlarge_search = "t3.2xlarge.search"
    ultrawarm1_medium_search = "ultrawarm1.medium.search"
    ultrawarm1_large_search = "ultrawarm1.large.search"
    ultrawarm1_xlarge_search = "ultrawarm1.xlarge.search"
    t2_micro_search = "t2.micro.search"
    t2_small_search = "t2.small.search"
    t2_medium_search = "t2.medium.search"
    r3_large_search = "r3.large.search"
    r3_xlarge_search = "r3.xlarge.search"
    r3_2xlarge_search = "r3.2xlarge.search"
    r3_4xlarge_search = "r3.4xlarge.search"
    r3_8xlarge_search = "r3.8xlarge.search"
    i2_xlarge_search = "i2.xlarge.search"
    i2_2xlarge_search = "i2.2xlarge.search"
    d2_xlarge_search = "d2.xlarge.search"
    d2_2xlarge_search = "d2.2xlarge.search"
    d2_4xlarge_search = "d2.4xlarge.search"
    d2_8xlarge_search = "d2.8xlarge.search"
    c4_large_search = "c4.large.search"
    c4_xlarge_search = "c4.xlarge.search"
    c4_2xlarge_search = "c4.2xlarge.search"
    c4_4xlarge_search = "c4.4xlarge.search"
    c4_8xlarge_search = "c4.8xlarge.search"
    r4_large_search = "r4.large.search"
    r4_xlarge_search = "r4.xlarge.search"
    r4_2xlarge_search = "r4.2xlarge.search"
    r4_4xlarge_search = "r4.4xlarge.search"
    r4_8xlarge_search = "r4.8xlarge.search"
    r4_16xlarge_search = "r4.16xlarge.search"
    i3_large_search = "i3.large.search"
    i3_xlarge_search = "i3.xlarge.search"
    i3_2xlarge_search = "i3.2xlarge.search"
    i3_4xlarge_search = "i3.4xlarge.search"
    i3_8xlarge_search = "i3.8xlarge.search"
    i3_16xlarge_search = "i3.16xlarge.search"
    r6g_large_search = "r6g.large.search"
    r6g_xlarge_search = "r6g.xlarge.search"
    r6g_2xlarge_search = "r6g.2xlarge.search"
    r6g_4xlarge_search = "r6g.4xlarge.search"
    r6g_8xlarge_search = "r6g.8xlarge.search"
    r6g_12xlarge_search = "r6g.12xlarge.search"
    m6g_large_search = "m6g.large.search"
    m6g_xlarge_search = "m6g.xlarge.search"
    m6g_2xlarge_search = "m6g.2xlarge.search"
    m6g_4xlarge_search = "m6g.4xlarge.search"
    m6g_8xlarge_search = "m6g.8xlarge.search"
    m6g_12xlarge_search = "m6g.12xlarge.search"
    c6g_large_search = "c6g.large.search"
    c6g_xlarge_search = "c6g.xlarge.search"
    c6g_2xlarge_search = "c6g.2xlarge.search"
    c6g_4xlarge_search = "c6g.4xlarge.search"
    c6g_8xlarge_search = "c6g.8xlarge.search"
    c6g_12xlarge_search = "c6g.12xlarge.search"
    r6gd_large_search = "r6gd.large.search"
    r6gd_xlarge_search = "r6gd.xlarge.search"
    r6gd_2xlarge_search = "r6gd.2xlarge.search"
    r6gd_4xlarge_search = "r6gd.4xlarge.search"
    r6gd_8xlarge_search = "r6gd.8xlarge.search"
    r6gd_12xlarge_search = "r6gd.12xlarge.search"
    r6gd_16xlarge_search = "r6gd.16xlarge.search"
    t4g_small_search = "t4g.small.search"
    t4g_medium_search = "t4g.medium.search"


class OpenSearchWarmPartitionInstanceType(str):
    ultrawarm1_medium_search = "ultrawarm1.medium.search"
    ultrawarm1_large_search = "ultrawarm1.large.search"
    ultrawarm1_xlarge_search = "ultrawarm1.xlarge.search"


class OptionState(str):
    RequiresIndexDocuments = "RequiresIndexDocuments"
    Processing = "Processing"
    Active = "Active"


class OutboundConnectionStatusCode(str):
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    APPROVED = "APPROVED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    REJECTING = "REJECTING"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class OverallChangeStatus(str):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PackageStatus(str):
    COPYING = "COPYING"
    COPY_FAILED = "COPY_FAILED"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    AVAILABLE = "AVAILABLE"
    DELETING = "DELETING"
    DELETED = "DELETED"
    DELETE_FAILED = "DELETE_FAILED"


class PackageType(str):
    TXT_DICTIONARY = "TXT-DICTIONARY"


class ReservedInstancePaymentOption(str):
    ALL_UPFRONT = "ALL_UPFRONT"
    PARTIAL_UPFRONT = "PARTIAL_UPFRONT"
    NO_UPFRONT = "NO_UPFRONT"


class RollbackOnDisable(str):
    NO_ROLLBACK = "NO_ROLLBACK"
    DEFAULT_ROLLBACK = "DEFAULT_ROLLBACK"


class ScheduledAutoTuneActionType(str):
    JVM_HEAP_SIZE_TUNING = "JVM_HEAP_SIZE_TUNING"
    JVM_YOUNG_GEN_TUNING = "JVM_YOUNG_GEN_TUNING"


class ScheduledAutoTuneSeverityType(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TLSSecurityPolicy(str):
    Policy_Min_TLS_1_0_2019_07 = "Policy-Min-TLS-1-0-2019-07"
    Policy_Min_TLS_1_2_2019_07 = "Policy-Min-TLS-1-2-2019-07"


class TimeUnit(str):
    HOURS = "HOURS"


class UpgradeStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_WITH_ISSUES = "SUCCEEDED_WITH_ISSUES"
    FAILED = "FAILED"


class UpgradeStep(str):
    PRE_UPGRADE_CHECK = "PRE_UPGRADE_CHECK"
    SNAPSHOT = "SNAPSHOT"
    UPGRADE = "UPGRADE"


class VolumeType(str):
    standard = "standard"
    gp2 = "gp2"
    io1 = "io1"


class AccessDeniedException(ServiceException):
    pass


class BaseException(ServiceException):
    message: Optional[ErrorMessage]


class ConflictException(ServiceException):
    pass


class DisabledOperationException(ServiceException):
    pass


class InternalException(ServiceException):
    pass


class InvalidPaginationTokenException(ServiceException):
    pass


class InvalidTypeException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class ResourceAlreadyExistsException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class ValidationException(ServiceException):
    pass


class AWSDomainInformation(TypedDict, total=False):
    OwnerId: Optional[OwnerId]
    DomainName: DomainName
    Region: Optional[Region]


class AcceptInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class InboundConnectionStatus(TypedDict, total=False):
    StatusCode: Optional[InboundConnectionStatusCode]
    Message: Optional[ConnectionStatusMessage]


class DomainInformationContainer(TypedDict, total=False):
    AWSDomainInformation: Optional[AWSDomainInformation]


class InboundConnection(TypedDict, total=False):
    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionId: Optional[ConnectionId]
    ConnectionStatus: Optional[InboundConnectionStatus]


class AcceptInboundConnectionResponse(TypedDict, total=False):
    Connection: Optional[InboundConnection]


UpdateTimestamp = datetime


class OptionStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: OptionState
    PendingDeletion: Optional[Boolean]


class AccessPoliciesStatus(TypedDict, total=False):
    Options: PolicyDocument
    Status: OptionStatus


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class AddTagsRequest(ServiceRequest):
    ARN: ARN
    TagList: TagList


LimitValueList = List[LimitValue]


class AdditionalLimit(TypedDict, total=False):
    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


AdditionalLimitList = List[AdditionalLimit]
AdvancedOptions = Dict[String, String]


class AdvancedOptionsStatus(TypedDict, total=False):
    Options: AdvancedOptions
    Status: OptionStatus


DisableTimestamp = datetime


class SAMLIdp(TypedDict, total=False):
    MetadataContent: SAMLMetadata
    EntityId: SAMLEntityId


class SAMLOptionsOutput(TypedDict, total=False):
    Enabled: Optional[Boolean]
    Idp: Optional[SAMLIdp]
    SubjectKey: Optional[String]
    RolesKey: Optional[String]
    SessionTimeoutMinutes: Optional[IntegerClass]


class AdvancedSecurityOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    SAMLOptions: Optional[SAMLOptionsOutput]
    AnonymousAuthDisableDate: Optional[DisableTimestamp]
    AnonymousAuthEnabled: Optional[Boolean]


class SAMLOptionsInput(TypedDict, total=False):
    Enabled: Optional[Boolean]
    Idp: Optional[SAMLIdp]
    MasterUserName: Optional[Username]
    MasterBackendRole: Optional[BackendRole]
    SubjectKey: Optional[String]
    RolesKey: Optional[String]
    SessionTimeoutMinutes: Optional[IntegerClass]


class MasterUserOptions(TypedDict, total=False):
    MasterUserARN: Optional[ARN]
    MasterUserName: Optional[Username]
    MasterUserPassword: Optional[Password]


class AdvancedSecurityOptionsInput(TypedDict, total=False):
    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    MasterUserOptions: Optional[MasterUserOptions]
    SAMLOptions: Optional[SAMLOptionsInput]
    AnonymousAuthEnabled: Optional[Boolean]


class AdvancedSecurityOptionsStatus(TypedDict, total=False):
    Options: AdvancedSecurityOptions
    Status: OptionStatus


class AssociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName


class ErrorDetails(TypedDict, total=False):
    ErrorType: Optional[ErrorType]
    ErrorMessage: Optional[ErrorMessage]


LastUpdated = datetime


class DomainPackageDetails(TypedDict, total=False):
    PackageID: Optional[PackageID]
    PackageName: Optional[PackageName]
    PackageType: Optional[PackageType]
    LastUpdated: Optional[LastUpdated]
    DomainName: Optional[DomainName]
    DomainPackageStatus: Optional[DomainPackageStatus]
    PackageVersion: Optional[PackageVersion]
    ReferencePath: Optional[ReferencePath]
    ErrorDetails: Optional[ErrorDetails]


class AssociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: Optional[DomainPackageDetails]


AutoTuneDate = datetime


class ScheduledAutoTuneDetails(TypedDict, total=False):
    Date: Optional[AutoTuneDate]
    ActionType: Optional[ScheduledAutoTuneActionType]
    Action: Optional[ScheduledAutoTuneDescription]
    Severity: Optional[ScheduledAutoTuneSeverityType]


class AutoTuneDetails(TypedDict, total=False):
    ScheduledAutoTuneDetails: Optional[ScheduledAutoTuneDetails]


class AutoTune(TypedDict, total=False):
    AutoTuneType: Optional[AutoTuneType]
    AutoTuneDetails: Optional[AutoTuneDetails]


AutoTuneList = List[AutoTune]
DurationValue = int


class Duration(TypedDict, total=False):
    Value: Optional[DurationValue]
    Unit: Optional[TimeUnit]


StartAt = datetime


class AutoTuneMaintenanceSchedule(TypedDict, total=False):
    StartAt: Optional[StartAt]
    Duration: Optional[Duration]
    CronExpressionForRecurrence: Optional[String]


AutoTuneMaintenanceScheduleList = List[AutoTuneMaintenanceSchedule]


class AutoTuneOptions(TypedDict, total=False):
    DesiredState: Optional[AutoTuneDesiredState]
    RollbackOnDisable: Optional[RollbackOnDisable]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsInput(TypedDict, total=False):
    DesiredState: Optional[AutoTuneDesiredState]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsOutput(TypedDict, total=False):
    State: Optional[AutoTuneState]
    ErrorMessage: Optional[String]


class AutoTuneStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: AutoTuneState
    ErrorMessage: Optional[String]
    PendingDeletion: Optional[Boolean]


class AutoTuneOptionsStatus(TypedDict, total=False):
    Options: Optional[AutoTuneOptions]
    Status: Optional[AutoTuneStatus]


class CancelServiceSoftwareUpdateRequest(ServiceRequest):
    DomainName: DomainName


DeploymentCloseDateTimeStamp = datetime


class ServiceSoftwareOptions(TypedDict, total=False):
    CurrentVersion: Optional[String]
    NewVersion: Optional[String]
    UpdateAvailable: Optional[Boolean]
    Cancellable: Optional[Boolean]
    UpdateStatus: Optional[DeploymentStatus]
    Description: Optional[String]
    AutomatedUpdateDate: Optional[DeploymentCloseDateTimeStamp]
    OptionalDeployment: Optional[Boolean]


class CancelServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class ChangeProgressDetails(TypedDict, total=False):
    ChangeId: Optional[GUID]
    Message: Optional[Message]


class ChangeProgressStage(TypedDict, total=False):
    Name: Optional[ChangeProgressStageName]
    Status: Optional[ChangeProgressStageStatus]
    Description: Optional[Description]
    LastUpdated: Optional[LastUpdated]


ChangeProgressStageList = List[ChangeProgressStage]
StringList = List[String]


class ChangeProgressStatusDetails(TypedDict, total=False):
    ChangeId: Optional[GUID]
    StartTime: Optional[UpdateTimestamp]
    Status: Optional[OverallChangeStatus]
    PendingProperties: Optional[StringList]
    CompletedProperties: Optional[StringList]
    TotalNumberOfStages: Optional[TotalNumberOfStages]
    ChangeProgressStages: Optional[ChangeProgressStageList]


class ColdStorageOptions(TypedDict, total=False):
    Enabled: Boolean


class ZoneAwarenessConfig(TypedDict, total=False):
    AvailabilityZoneCount: Optional[IntegerClass]


class ClusterConfig(TypedDict, total=False):
    InstanceType: Optional[OpenSearchPartitionInstanceType]
    InstanceCount: Optional[IntegerClass]
    DedicatedMasterEnabled: Optional[Boolean]
    ZoneAwarenessEnabled: Optional[Boolean]
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig]
    DedicatedMasterType: Optional[OpenSearchPartitionInstanceType]
    DedicatedMasterCount: Optional[IntegerClass]
    WarmEnabled: Optional[Boolean]
    WarmType: Optional[OpenSearchWarmPartitionInstanceType]
    WarmCount: Optional[IntegerClass]
    ColdStorageOptions: Optional[ColdStorageOptions]


class ClusterConfigStatus(TypedDict, total=False):
    Options: ClusterConfig
    Status: OptionStatus


class CognitoOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    UserPoolId: Optional[UserPoolId]
    IdentityPoolId: Optional[IdentityPoolId]
    RoleArn: Optional[RoleArn]


class CognitoOptionsStatus(TypedDict, total=False):
    Options: CognitoOptions
    Status: OptionStatus


VersionList = List[VersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    SourceVersion: Optional[VersionString]
    TargetVersions: Optional[VersionList]


CompatibleVersionsList = List[CompatibleVersionsMap]


class DomainEndpointOptions(TypedDict, total=False):
    EnforceHTTPS: Optional[Boolean]
    TLSSecurityPolicy: Optional[TLSSecurityPolicy]
    CustomEndpointEnabled: Optional[Boolean]
    CustomEndpoint: Optional[DomainNameFqdn]
    CustomEndpointCertificateArn: Optional[ARN]


class LogPublishingOption(TypedDict, total=False):
    CloudWatchLogsLogGroupArn: Optional[CloudWatchLogsLogGroupArn]
    Enabled: Optional[Boolean]


LogPublishingOptions = Dict[LogType, LogPublishingOption]


class NodeToNodeEncryptionOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]


class EncryptionAtRestOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]


class VPCOptions(TypedDict, total=False):
    SubnetIds: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


class SnapshotOptions(TypedDict, total=False):
    AutomatedSnapshotStartHour: Optional[IntegerClass]


class EBSOptions(TypedDict, total=False):
    EBSEnabled: Optional[Boolean]
    VolumeType: Optional[VolumeType]
    VolumeSize: Optional[IntegerClass]
    Iops: Optional[IntegerClass]


class CreateDomainRequest(ServiceRequest):
    DomainName: DomainName
    EngineVersion: Optional[VersionString]
    ClusterConfig: Optional[ClusterConfig]
    EBSOptions: Optional[EBSOptions]
    AccessPolicies: Optional[PolicyDocument]
    SnapshotOptions: Optional[SnapshotOptions]
    VPCOptions: Optional[VPCOptions]
    CognitoOptions: Optional[CognitoOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    AdvancedOptions: Optional[AdvancedOptions]
    LogPublishingOptions: Optional[LogPublishingOptions]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    TagList: Optional[TagList]
    AutoTuneOptions: Optional[AutoTuneOptionsInput]


class VPCDerivedInfo(TypedDict, total=False):
    VPCId: Optional[String]
    SubnetIds: Optional[StringList]
    AvailabilityZones: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


EndpointsMap = Dict[String, ServiceUrl]


class DomainStatus(TypedDict, total=False):
    DomainId: DomainId
    DomainName: DomainName
    ARN: ARN
    Created: Optional[Boolean]
    Deleted: Optional[Boolean]
    Endpoint: Optional[ServiceUrl]
    Endpoints: Optional[EndpointsMap]
    Processing: Optional[Boolean]
    UpgradeProcessing: Optional[Boolean]
    EngineVersion: Optional[VersionString]
    ClusterConfig: ClusterConfig
    EBSOptions: Optional[EBSOptions]
    AccessPolicies: Optional[PolicyDocument]
    SnapshotOptions: Optional[SnapshotOptions]
    VPCOptions: Optional[VPCDerivedInfo]
    CognitoOptions: Optional[CognitoOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    AdvancedOptions: Optional[AdvancedOptions]
    LogPublishingOptions: Optional[LogPublishingOptions]
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptions]
    AutoTuneOptions: Optional[AutoTuneOptionsOutput]
    ChangeProgressDetails: Optional[ChangeProgressDetails]


class CreateDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[DomainStatus]


class CreateOutboundConnectionRequest(ServiceRequest):
    LocalDomainInfo: DomainInformationContainer
    RemoteDomainInfo: DomainInformationContainer
    ConnectionAlias: ConnectionAlias


class OutboundConnectionStatus(TypedDict, total=False):
    StatusCode: Optional[OutboundConnectionStatusCode]
    Message: Optional[ConnectionStatusMessage]


class CreateOutboundConnectionResponse(TypedDict, total=False):
    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundConnectionStatus]
    ConnectionId: Optional[ConnectionId]


class PackageSource(TypedDict, total=False):
    S3BucketName: Optional[S3BucketName]
    S3Key: Optional[S3Key]


class CreatePackageRequest(ServiceRequest):
    PackageName: PackageName
    PackageType: PackageType
    PackageDescription: Optional[PackageDescription]
    PackageSource: PackageSource


CreatedAt = datetime


class PackageDetails(TypedDict, total=False):
    PackageID: Optional[PackageID]
    PackageName: Optional[PackageName]
    PackageType: Optional[PackageType]
    PackageDescription: Optional[PackageDescription]
    PackageStatus: Optional[PackageStatus]
    CreatedAt: Optional[CreatedAt]
    LastUpdatedAt: Optional[LastUpdated]
    AvailablePackageVersion: Optional[PackageVersion]
    ErrorDetails: Optional[ErrorDetails]


class CreatePackageResponse(TypedDict, total=False):
    PackageDetails: Optional[PackageDetails]


class DeleteDomainRequest(ServiceRequest):
    DomainName: DomainName


class DeleteDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[DomainStatus]


class DeleteInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class DeleteInboundConnectionResponse(TypedDict, total=False):
    Connection: Optional[InboundConnection]


class DeleteOutboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class OutboundConnection(TypedDict, total=False):
    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionId: Optional[ConnectionId]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundConnectionStatus]


class DeleteOutboundConnectionResponse(TypedDict, total=False):
    Connection: Optional[OutboundConnection]


class DeletePackageRequest(ServiceRequest):
    PackageID: PackageID


class DeletePackageResponse(TypedDict, total=False):
    PackageDetails: Optional[PackageDetails]


class DescribeDomainAutoTunesRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeDomainAutoTunesResponse(TypedDict, total=False):
    AutoTunes: Optional[AutoTuneList]
    NextToken: Optional[NextToken]


class DescribeDomainChangeProgressRequest(ServiceRequest):
    DomainName: DomainName
    ChangeId: Optional[GUID]


class DescribeDomainChangeProgressResponse(TypedDict, total=False):
    ChangeProgressStatus: Optional[ChangeProgressStatusDetails]


class DescribeDomainConfigRequest(ServiceRequest):
    DomainName: DomainName


class DomainEndpointOptionsStatus(TypedDict, total=False):
    Options: DomainEndpointOptions
    Status: OptionStatus


class LogPublishingOptionsStatus(TypedDict, total=False):
    Options: Optional[LogPublishingOptions]
    Status: Optional[OptionStatus]


class NodeToNodeEncryptionOptionsStatus(TypedDict, total=False):
    Options: NodeToNodeEncryptionOptions
    Status: OptionStatus


class EncryptionAtRestOptionsStatus(TypedDict, total=False):
    Options: EncryptionAtRestOptions
    Status: OptionStatus


class VPCDerivedInfoStatus(TypedDict, total=False):
    Options: VPCDerivedInfo
    Status: OptionStatus


class SnapshotOptionsStatus(TypedDict, total=False):
    Options: SnapshotOptions
    Status: OptionStatus


class EBSOptionsStatus(TypedDict, total=False):
    Options: EBSOptions
    Status: OptionStatus


class VersionStatus(TypedDict, total=False):
    Options: VersionString
    Status: OptionStatus


class DomainConfig(TypedDict, total=False):
    EngineVersion: Optional[VersionStatus]
    ClusterConfig: Optional[ClusterConfigStatus]
    EBSOptions: Optional[EBSOptionsStatus]
    AccessPolicies: Optional[AccessPoliciesStatus]
    SnapshotOptions: Optional[SnapshotOptionsStatus]
    VPCOptions: Optional[VPCDerivedInfoStatus]
    CognitoOptions: Optional[CognitoOptionsStatus]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptionsStatus]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptionsStatus]
    AdvancedOptions: Optional[AdvancedOptionsStatus]
    LogPublishingOptions: Optional[LogPublishingOptionsStatus]
    DomainEndpointOptions: Optional[DomainEndpointOptionsStatus]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsStatus]
    AutoTuneOptions: Optional[AutoTuneOptionsStatus]
    ChangeProgressDetails: Optional[ChangeProgressDetails]


class DescribeDomainConfigResponse(TypedDict, total=False):
    DomainConfig: DomainConfig


class DescribeDomainRequest(ServiceRequest):
    DomainName: DomainName


class DescribeDomainResponse(TypedDict, total=False):
    DomainStatus: DomainStatus


DomainNameList = List[DomainName]


class DescribeDomainsRequest(ServiceRequest):
    DomainNames: DomainNameList


DomainStatusList = List[DomainStatus]


class DescribeDomainsResponse(TypedDict, total=False):
    DomainStatusList: DomainStatusList


ValueStringList = List[NonEmptyString]


class Filter(TypedDict, total=False):
    Name: Optional[NonEmptyString]
    Values: Optional[ValueStringList]


FilterList = List[Filter]


class DescribeInboundConnectionsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


InboundConnections = List[InboundConnection]


class DescribeInboundConnectionsResponse(TypedDict, total=False):
    Connections: Optional[InboundConnections]
    NextToken: Optional[NextToken]


class DescribeInstanceTypeLimitsRequest(ServiceRequest):
    DomainName: Optional[DomainName]
    InstanceType: OpenSearchPartitionInstanceType
    EngineVersion: VersionString


class InstanceCountLimits(TypedDict, total=False):
    MinimumInstanceCount: Optional[MinimumInstanceCount]
    MaximumInstanceCount: Optional[MaximumInstanceCount]


class InstanceLimits(TypedDict, total=False):
    InstanceCountLimits: Optional[InstanceCountLimits]


class StorageTypeLimit(TypedDict, total=False):
    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


StorageTypeLimitList = List[StorageTypeLimit]


class StorageType(TypedDict, total=False):
    StorageTypeName: Optional[StorageTypeName]
    StorageSubTypeName: Optional[StorageSubTypeName]
    StorageTypeLimits: Optional[StorageTypeLimitList]


StorageTypeList = List[StorageType]


class Limits(TypedDict, total=False):
    StorageTypes: Optional[StorageTypeList]
    InstanceLimits: Optional[InstanceLimits]
    AdditionalLimits: Optional[AdditionalLimitList]


LimitsByRole = Dict[InstanceRole, Limits]


class DescribeInstanceTypeLimitsResponse(TypedDict, total=False):
    LimitsByRole: Optional[LimitsByRole]


class DescribeOutboundConnectionsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


OutboundConnections = List[OutboundConnection]


class DescribeOutboundConnectionsResponse(TypedDict, total=False):
    Connections: Optional[OutboundConnections]
    NextToken: Optional[NextToken]


DescribePackagesFilterValues = List[DescribePackagesFilterValue]


class DescribePackagesFilter(TypedDict, total=False):
    Name: Optional[DescribePackagesFilterName]
    Value: Optional[DescribePackagesFilterValues]


DescribePackagesFilterList = List[DescribePackagesFilter]


class DescribePackagesRequest(ServiceRequest):
    Filters: Optional[DescribePackagesFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


PackageDetailsList = List[PackageDetails]


class DescribePackagesResponse(TypedDict, total=False):
    PackageDetailsList: Optional[PackageDetailsList]
    NextToken: Optional[String]


class DescribeReservedInstanceOfferingsRequest(ServiceRequest):
    ReservedInstanceOfferingId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedInstanceOffering(TypedDict, total=False):
    ReservedInstanceOfferingId: Optional[GUID]
    InstanceType: Optional[OpenSearchPartitionInstanceType]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    PaymentOption: Optional[ReservedInstancePaymentOption]
    RecurringCharges: Optional[RecurringChargeList]


ReservedInstanceOfferingList = List[ReservedInstanceOffering]


class DescribeReservedInstanceOfferingsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ReservedInstanceOfferings: Optional[ReservedInstanceOfferingList]


class DescribeReservedInstancesRequest(ServiceRequest):
    ReservedInstanceId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


Long = int


class ReservedInstance(TypedDict, total=False):
    ReservationName: Optional[ReservationToken]
    ReservedInstanceId: Optional[GUID]
    BillingSubscriptionId: Optional[Long]
    ReservedInstanceOfferingId: Optional[String]
    InstanceType: Optional[OpenSearchPartitionInstanceType]
    StartTime: Optional[UpdateTimestamp]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    InstanceCount: Optional[Integer]
    State: Optional[String]
    PaymentOption: Optional[ReservedInstancePaymentOption]
    RecurringCharges: Optional[RecurringChargeList]


ReservedInstanceList = List[ReservedInstance]


class DescribeReservedInstancesResponse(TypedDict, total=False):
    NextToken: Optional[String]
    ReservedInstances: Optional[ReservedInstanceList]


class DissociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName


class DissociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: Optional[DomainPackageDetails]


class DomainInfo(TypedDict, total=False):
    DomainName: Optional[DomainName]
    EngineType: Optional[EngineType]


DomainInfoList = List[DomainInfo]
DomainPackageDetailsList = List[DomainPackageDetails]


class DryRunResults(TypedDict, total=False):
    DeploymentType: Optional[DeploymentType]
    Message: Optional[Message]


class GetCompatibleVersionsRequest(ServiceRequest):
    DomainName: Optional[DomainName]


class GetCompatibleVersionsResponse(TypedDict, total=False):
    CompatibleVersions: Optional[CompatibleVersionsList]


class GetPackageVersionHistoryRequest(ServiceRequest):
    PackageID: PackageID
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class PackageVersionHistory(TypedDict, total=False):
    PackageVersion: Optional[PackageVersion]
    CommitMessage: Optional[CommitMessage]
    CreatedAt: Optional[CreatedAt]


PackageVersionHistoryList = List[PackageVersionHistory]


class GetPackageVersionHistoryResponse(TypedDict, total=False):
    PackageID: Optional[PackageID]
    PackageVersionHistoryList: Optional[PackageVersionHistoryList]
    NextToken: Optional[String]


class GetUpgradeHistoryRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


Issues = List[Issue]


class UpgradeStepItem(TypedDict, total=False):
    UpgradeStep: Optional[UpgradeStep]
    UpgradeStepStatus: Optional[UpgradeStatus]
    Issues: Optional[Issues]
    ProgressPercent: Optional[Double]


UpgradeStepsList = List[UpgradeStepItem]
StartTimestamp = datetime


class UpgradeHistory(TypedDict, total=False):
    UpgradeName: Optional[UpgradeName]
    StartTimestamp: Optional[StartTimestamp]
    UpgradeStatus: Optional[UpgradeStatus]
    StepsList: Optional[UpgradeStepsList]


UpgradeHistoryList = List[UpgradeHistory]


class GetUpgradeHistoryResponse(TypedDict, total=False):
    UpgradeHistories: Optional[UpgradeHistoryList]
    NextToken: Optional[String]


class GetUpgradeStatusRequest(ServiceRequest):
    DomainName: DomainName


class GetUpgradeStatusResponse(TypedDict, total=False):
    UpgradeStep: Optional[UpgradeStep]
    StepStatus: Optional[UpgradeStatus]
    UpgradeName: Optional[UpgradeName]


InstanceRoleList = List[InstanceRole]


class InstanceTypeDetails(TypedDict, total=False):
    InstanceType: Optional[OpenSearchPartitionInstanceType]
    EncryptionEnabled: Optional[Boolean]
    CognitoEnabled: Optional[Boolean]
    AppLogsEnabled: Optional[Boolean]
    AdvancedSecurityEnabled: Optional[Boolean]
    WarmEnabled: Optional[Boolean]
    InstanceRole: Optional[InstanceRoleList]


InstanceTypeDetailsList = List[InstanceTypeDetails]


class ListDomainNamesRequest(ServiceRequest):
    EngineType: Optional[EngineType]


class ListDomainNamesResponse(TypedDict, total=False):
    DomainNames: Optional[DomainInfoList]


class ListDomainsForPackageRequest(ServiceRequest):
    PackageID: PackageID
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDomainsForPackageResponse(TypedDict, total=False):
    DomainPackageDetailsList: Optional[DomainPackageDetailsList]
    NextToken: Optional[String]


class ListInstanceTypeDetailsRequest(ServiceRequest):
    EngineVersion: VersionString
    DomainName: Optional[DomainName]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListInstanceTypeDetailsResponse(TypedDict, total=False):
    InstanceTypeDetails: Optional[InstanceTypeDetailsList]
    NextToken: Optional[NextToken]


class ListPackagesForDomainRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListPackagesForDomainResponse(TypedDict, total=False):
    DomainPackageDetailsList: Optional[DomainPackageDetailsList]
    NextToken: Optional[String]


class ListTagsRequest(ServiceRequest):
    ARN: ARN


class ListTagsResponse(TypedDict, total=False):
    TagList: Optional[TagList]


class ListVersionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListVersionsResponse(TypedDict, total=False):
    Versions: Optional[VersionList]
    NextToken: Optional[NextToken]


class PurchaseReservedInstanceOfferingRequest(ServiceRequest):
    ReservedInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: Optional[InstanceCount]


class PurchaseReservedInstanceOfferingResponse(TypedDict, total=False):
    ReservedInstanceId: Optional[GUID]
    ReservationName: Optional[ReservationToken]


class RejectInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class RejectInboundConnectionResponse(TypedDict, total=False):
    Connection: Optional[InboundConnection]


class RemoveTagsRequest(ServiceRequest):
    ARN: ARN
    TagKeys: StringList


class StartServiceSoftwareUpdateRequest(ServiceRequest):
    DomainName: DomainName


class StartServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class UpdateDomainConfigRequest(ServiceRequest):
    DomainName: DomainName
    ClusterConfig: Optional[ClusterConfig]
    EBSOptions: Optional[EBSOptions]
    SnapshotOptions: Optional[SnapshotOptions]
    VPCOptions: Optional[VPCOptions]
    CognitoOptions: Optional[CognitoOptions]
    AdvancedOptions: Optional[AdvancedOptions]
    AccessPolicies: Optional[PolicyDocument]
    LogPublishingOptions: Optional[LogPublishingOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    AutoTuneOptions: Optional[AutoTuneOptions]
    DryRun: Optional[DryRun]


class UpdateDomainConfigResponse(TypedDict, total=False):
    DomainConfig: DomainConfig
    DryRunResults: Optional[DryRunResults]


class UpdatePackageRequest(ServiceRequest):
    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: Optional[PackageDescription]
    CommitMessage: Optional[CommitMessage]


class UpdatePackageResponse(TypedDict, total=False):
    PackageDetails: Optional[PackageDetails]


class UpgradeDomainRequest(ServiceRequest):
    DomainName: DomainName
    TargetVersion: VersionString
    PerformCheckOnly: Optional[Boolean]
    AdvancedOptions: Optional[AdvancedOptions]


class UpgradeDomainResponse(TypedDict, total=False):
    UpgradeId: Optional[String]
    DomainName: Optional[DomainName]
    TargetVersion: Optional[VersionString]
    PerformCheckOnly: Optional[Boolean]
    AdvancedOptions: Optional[AdvancedOptions]
    ChangeProgressDetails: Optional[ChangeProgressDetails]


class OpensearchApi:

    service = "opensearch"
    version = "2021-01-01"

    @handler("AcceptInboundConnection")
    def accept_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> AcceptInboundConnectionResponse:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        raise NotImplementedError

    @handler("AssociatePackage")
    def associate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> AssociatePackageResponse:
        raise NotImplementedError

    @handler("CancelServiceSoftwareUpdate")
    def cancel_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> CancelServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("CreateDomain")
    def create_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        engine_version: VersionString = None,
        cluster_config: ClusterConfig = None,
        ebs_options: EBSOptions = None,
        access_policies: PolicyDocument = None,
        snapshot_options: SnapshotOptions = None,
        vpc_options: VPCOptions = None,
        cognito_options: CognitoOptions = None,
        encryption_at_rest_options: EncryptionAtRestOptions = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions = None,
        advanced_options: AdvancedOptions = None,
        log_publishing_options: LogPublishingOptions = None,
        domain_endpoint_options: DomainEndpointOptions = None,
        advanced_security_options: AdvancedSecurityOptionsInput = None,
        tag_list: TagList = None,
        auto_tune_options: AutoTuneOptionsInput = None,
    ) -> CreateDomainResponse:
        raise NotImplementedError

    @handler("CreateOutboundConnection")
    def create_outbound_connection(
        self,
        context: RequestContext,
        local_domain_info: DomainInformationContainer,
        remote_domain_info: DomainInformationContainer,
        connection_alias: ConnectionAlias,
    ) -> CreateOutboundConnectionResponse:
        raise NotImplementedError

    @handler("CreatePackage")
    def create_package(
        self,
        context: RequestContext,
        package_name: PackageName,
        package_type: PackageType,
        package_source: PackageSource,
        package_description: PackageDescription = None,
    ) -> CreatePackageResponse:
        raise NotImplementedError

    @handler("DeleteDomain")
    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        raise NotImplementedError

    @handler("DeleteInboundConnection")
    def delete_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> DeleteInboundConnectionResponse:
        raise NotImplementedError

    @handler("DeleteOutboundConnection")
    def delete_outbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> DeleteOutboundConnectionResponse:
        raise NotImplementedError

    @handler("DeletePackage")
    def delete_package(
        self, context: RequestContext, package_id: PackageID
    ) -> DeletePackageResponse:
        raise NotImplementedError

    @handler("DescribeDomain")
    def describe_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainResponse:
        raise NotImplementedError

    @handler("DescribeDomainAutoTunes")
    def describe_domain_auto_tunes(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeDomainAutoTunesResponse:
        raise NotImplementedError

    @handler("DescribeDomainChangeProgress")
    def describe_domain_change_progress(
        self, context: RequestContext, domain_name: DomainName, change_id: GUID = None
    ) -> DescribeDomainChangeProgressResponse:
        raise NotImplementedError

    @handler("DescribeDomainConfig")
    def describe_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainConfigResponse:
        raise NotImplementedError

    @handler("DescribeDomains")
    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeDomainsResponse:
        raise NotImplementedError

    @handler("DescribeInboundConnections")
    def describe_inbound_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeInboundConnectionsResponse:
        raise NotImplementedError

    @handler("DescribeInstanceTypeLimits")
    def describe_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: OpenSearchPartitionInstanceType,
        engine_version: VersionString,
        domain_name: DomainName = None,
    ) -> DescribeInstanceTypeLimitsResponse:
        raise NotImplementedError

    @handler("DescribeOutboundConnections")
    def describe_outbound_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeOutboundConnectionsResponse:
        raise NotImplementedError

    @handler("DescribePackages")
    def describe_packages(
        self,
        context: RequestContext,
        filters: DescribePackagesFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribePackagesResponse:
        raise NotImplementedError

    @handler("DescribeReservedInstanceOfferings")
    def describe_reserved_instance_offerings(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedInstanceOfferingsResponse:
        raise NotImplementedError

    @handler("DescribeReservedInstances")
    def describe_reserved_instances(
        self,
        context: RequestContext,
        reserved_instance_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedInstancesResponse:
        raise NotImplementedError

    @handler("DissociatePackage")
    def dissociate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> DissociatePackageResponse:
        raise NotImplementedError

    @handler("GetCompatibleVersions")
    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleVersionsResponse:
        raise NotImplementedError

    @handler("GetPackageVersionHistory")
    def get_package_version_history(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetPackageVersionHistoryResponse:
        raise NotImplementedError

    @handler("GetUpgradeHistory")
    def get_upgrade_history(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetUpgradeHistoryResponse:
        raise NotImplementedError

    @handler("GetUpgradeStatus")
    def get_upgrade_status(
        self, context: RequestContext, domain_name: DomainName
    ) -> GetUpgradeStatusResponse:
        raise NotImplementedError

    @handler("ListDomainNames")
    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        raise NotImplementedError

    @handler("ListDomainsForPackage")
    def list_domains_for_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDomainsForPackageResponse:
        raise NotImplementedError

    @handler("ListInstanceTypeDetails")
    def list_instance_type_details(
        self,
        context: RequestContext,
        engine_version: VersionString,
        domain_name: DomainName = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListInstanceTypeDetailsResponse:
        raise NotImplementedError

    @handler("ListPackagesForDomain")
    def list_packages_for_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListPackagesForDomainResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, arn: ARN) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListVersions")
    def list_versions(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListVersionsResponse:
        raise NotImplementedError

    @handler("PurchaseReservedInstanceOffering")
    def purchase_reserved_instance_offering(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount = None,
    ) -> PurchaseReservedInstanceOfferingResponse:
        raise NotImplementedError

    @handler("RejectInboundConnection")
    def reject_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> RejectInboundConnectionResponse:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        raise NotImplementedError

    @handler("StartServiceSoftwareUpdate")
    def start_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> StartServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("UpdateDomainConfig")
    def update_domain_config(
        self,
        context: RequestContext,
        domain_name: DomainName,
        cluster_config: ClusterConfig = None,
        ebs_options: EBSOptions = None,
        snapshot_options: SnapshotOptions = None,
        vpc_options: VPCOptions = None,
        cognito_options: CognitoOptions = None,
        advanced_options: AdvancedOptions = None,
        access_policies: PolicyDocument = None,
        log_publishing_options: LogPublishingOptions = None,
        encryption_at_rest_options: EncryptionAtRestOptions = None,
        domain_endpoint_options: DomainEndpointOptions = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions = None,
        advanced_security_options: AdvancedSecurityOptionsInput = None,
        auto_tune_options: AutoTuneOptions = None,
        dry_run: DryRun = None,
    ) -> UpdateDomainConfigResponse:
        raise NotImplementedError

    @handler("UpdatePackage")
    def update_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        package_source: PackageSource,
        package_description: PackageDescription = None,
        commit_message: CommitMessage = None,
    ) -> UpdatePackageResponse:
        raise NotImplementedError

    @handler("UpgradeDomain")
    def upgrade_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        target_version: VersionString,
        perform_check_only: Boolean = None,
        advanced_options: AdvancedOptions = None,
    ) -> UpgradeDomainResponse:
        raise NotImplementedError
