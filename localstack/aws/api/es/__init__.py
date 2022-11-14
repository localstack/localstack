import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
AWSAccount = str
BackendRole = str
Boolean = bool
ChangeProgressStageName = str
ChangeProgressStageStatus = str
ClientToken = str
CloudWatchLogsLogGroupArn = str
CommitMessage = str
ConnectionAlias = str
CrossClusterSearchConnectionId = str
CrossClusterSearchConnectionStatusMessage = str
DeploymentType = str
DescribePackagesFilterValue = str
Description = str
DomainArn = str
DomainId = str
DomainName = str
DomainNameFqdn = str
Double = float
DryRun = bool
ElasticsearchVersionString = str
Endpoint = str
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
VpcEndpointId = str


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


class ESPartitionInstanceType(str):
    m3_medium_elasticsearch = "m3.medium.elasticsearch"
    m3_large_elasticsearch = "m3.large.elasticsearch"
    m3_xlarge_elasticsearch = "m3.xlarge.elasticsearch"
    m3_2xlarge_elasticsearch = "m3.2xlarge.elasticsearch"
    m4_large_elasticsearch = "m4.large.elasticsearch"
    m4_xlarge_elasticsearch = "m4.xlarge.elasticsearch"
    m4_2xlarge_elasticsearch = "m4.2xlarge.elasticsearch"
    m4_4xlarge_elasticsearch = "m4.4xlarge.elasticsearch"
    m4_10xlarge_elasticsearch = "m4.10xlarge.elasticsearch"
    m5_large_elasticsearch = "m5.large.elasticsearch"
    m5_xlarge_elasticsearch = "m5.xlarge.elasticsearch"
    m5_2xlarge_elasticsearch = "m5.2xlarge.elasticsearch"
    m5_4xlarge_elasticsearch = "m5.4xlarge.elasticsearch"
    m5_12xlarge_elasticsearch = "m5.12xlarge.elasticsearch"
    r5_large_elasticsearch = "r5.large.elasticsearch"
    r5_xlarge_elasticsearch = "r5.xlarge.elasticsearch"
    r5_2xlarge_elasticsearch = "r5.2xlarge.elasticsearch"
    r5_4xlarge_elasticsearch = "r5.4xlarge.elasticsearch"
    r5_12xlarge_elasticsearch = "r5.12xlarge.elasticsearch"
    c5_large_elasticsearch = "c5.large.elasticsearch"
    c5_xlarge_elasticsearch = "c5.xlarge.elasticsearch"
    c5_2xlarge_elasticsearch = "c5.2xlarge.elasticsearch"
    c5_4xlarge_elasticsearch = "c5.4xlarge.elasticsearch"
    c5_9xlarge_elasticsearch = "c5.9xlarge.elasticsearch"
    c5_18xlarge_elasticsearch = "c5.18xlarge.elasticsearch"
    ultrawarm1_medium_elasticsearch = "ultrawarm1.medium.elasticsearch"
    ultrawarm1_large_elasticsearch = "ultrawarm1.large.elasticsearch"
    t2_micro_elasticsearch = "t2.micro.elasticsearch"
    t2_small_elasticsearch = "t2.small.elasticsearch"
    t2_medium_elasticsearch = "t2.medium.elasticsearch"
    r3_large_elasticsearch = "r3.large.elasticsearch"
    r3_xlarge_elasticsearch = "r3.xlarge.elasticsearch"
    r3_2xlarge_elasticsearch = "r3.2xlarge.elasticsearch"
    r3_4xlarge_elasticsearch = "r3.4xlarge.elasticsearch"
    r3_8xlarge_elasticsearch = "r3.8xlarge.elasticsearch"
    i2_xlarge_elasticsearch = "i2.xlarge.elasticsearch"
    i2_2xlarge_elasticsearch = "i2.2xlarge.elasticsearch"
    d2_xlarge_elasticsearch = "d2.xlarge.elasticsearch"
    d2_2xlarge_elasticsearch = "d2.2xlarge.elasticsearch"
    d2_4xlarge_elasticsearch = "d2.4xlarge.elasticsearch"
    d2_8xlarge_elasticsearch = "d2.8xlarge.elasticsearch"
    c4_large_elasticsearch = "c4.large.elasticsearch"
    c4_xlarge_elasticsearch = "c4.xlarge.elasticsearch"
    c4_2xlarge_elasticsearch = "c4.2xlarge.elasticsearch"
    c4_4xlarge_elasticsearch = "c4.4xlarge.elasticsearch"
    c4_8xlarge_elasticsearch = "c4.8xlarge.elasticsearch"
    r4_large_elasticsearch = "r4.large.elasticsearch"
    r4_xlarge_elasticsearch = "r4.xlarge.elasticsearch"
    r4_2xlarge_elasticsearch = "r4.2xlarge.elasticsearch"
    r4_4xlarge_elasticsearch = "r4.4xlarge.elasticsearch"
    r4_8xlarge_elasticsearch = "r4.8xlarge.elasticsearch"
    r4_16xlarge_elasticsearch = "r4.16xlarge.elasticsearch"
    i3_large_elasticsearch = "i3.large.elasticsearch"
    i3_xlarge_elasticsearch = "i3.xlarge.elasticsearch"
    i3_2xlarge_elasticsearch = "i3.2xlarge.elasticsearch"
    i3_4xlarge_elasticsearch = "i3.4xlarge.elasticsearch"
    i3_8xlarge_elasticsearch = "i3.8xlarge.elasticsearch"
    i3_16xlarge_elasticsearch = "i3.16xlarge.elasticsearch"


class ESWarmPartitionInstanceType(str):
    ultrawarm1_medium_elasticsearch = "ultrawarm1.medium.elasticsearch"
    ultrawarm1_large_elasticsearch = "ultrawarm1.large.elasticsearch"


class EngineType(str):
    OpenSearch = "OpenSearch"
    Elasticsearch = "Elasticsearch"


class InboundCrossClusterSearchConnectionStatusCode(str):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    APPROVED = "APPROVED"
    REJECTING = "REJECTING"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class LogType(str):
    INDEX_SLOW_LOGS = "INDEX_SLOW_LOGS"
    SEARCH_SLOW_LOGS = "SEARCH_SLOW_LOGS"
    ES_APPLICATION_LOGS = "ES_APPLICATION_LOGS"
    AUDIT_LOGS = "AUDIT_LOGS"


class OptionState(str):
    RequiresIndexDocuments = "RequiresIndexDocuments"
    Processing = "Processing"
    Active = "Active"


class OutboundCrossClusterSearchConnectionStatusCode(str):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
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


class PrincipalType(str):
    AWS_ACCOUNT = "AWS_ACCOUNT"
    AWS_SERVICE = "AWS_SERVICE"


class ReservedElasticsearchInstancePaymentOption(str):
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
    gp3 = "gp3"


class VpcEndpointErrorCode(str):
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    SERVER_ERROR = "SERVER_ERROR"


class VpcEndpointStatus(str):
    CREATING = "CREATING"
    CREATE_FAILED = "CREATE_FAILED"
    ACTIVE = "ACTIVE"
    UPDATING = "UPDATING"
    UPDATE_FAILED = "UPDATE_FAILED"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 403


class BaseException(ServiceException):
    code: str = "BaseException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409


class DisabledOperationException(ServiceException):
    code: str = "DisabledOperationException"
    sender_fault: bool = False
    status_code: int = 409


class InternalException(ServiceException):
    code: str = "InternalException"
    sender_fault: bool = False
    status_code: int = 500


class InvalidPaginationTokenException(ServiceException):
    code: str = "InvalidPaginationTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTypeException(ServiceException):
    code: str = "InvalidTypeException"
    sender_fault: bool = False
    status_code: int = 409


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 409


class ResourceAlreadyExistsException(ServiceException):
    code: str = "ResourceAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 409


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 409


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


class AcceptInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class InboundCrossClusterSearchConnectionStatus(TypedDict, total=False):
    StatusCode: Optional[InboundCrossClusterSearchConnectionStatusCode]
    Message: Optional[CrossClusterSearchConnectionStatusMessage]


class DomainInformation(TypedDict, total=False):
    OwnerId: Optional[OwnerId]
    DomainName: DomainName
    Region: Optional[Region]


class InboundCrossClusterSearchConnection(TypedDict, total=False):
    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]
    ConnectionStatus: Optional[InboundCrossClusterSearchConnectionStatus]


class AcceptInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


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


class AuthorizeVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    Account: AWSAccount


class AuthorizedPrincipal(TypedDict, total=False):
    PrincipalType: Optional[PrincipalType]
    Principal: Optional[String]


class AuthorizeVpcEndpointAccessResponse(TypedDict, total=False):
    AuthorizedPrincipal: AuthorizedPrincipal


AuthorizedPrincipalList = List[AuthorizedPrincipal]
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


class CancelElasticsearchServiceSoftwareUpdateRequest(ServiceRequest):
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


class CancelElasticsearchServiceSoftwareUpdateResponse(TypedDict, total=False):
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


class CognitoOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    UserPoolId: Optional[UserPoolId]
    IdentityPoolId: Optional[IdentityPoolId]
    RoleArn: Optional[RoleArn]


class CognitoOptionsStatus(TypedDict, total=False):
    Options: CognitoOptions
    Status: OptionStatus


class ColdStorageOptions(TypedDict, total=False):
    Enabled: Boolean


ElasticsearchVersionList = List[ElasticsearchVersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    SourceVersion: Optional[ElasticsearchVersionString]
    TargetVersions: Optional[ElasticsearchVersionList]


CompatibleElasticsearchVersionsList = List[CompatibleVersionsMap]


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
    Throughput: Optional[IntegerClass]


class ZoneAwarenessConfig(TypedDict, total=False):
    AvailabilityZoneCount: Optional[IntegerClass]


class ElasticsearchClusterConfig(TypedDict, total=False):
    InstanceType: Optional[ESPartitionInstanceType]
    InstanceCount: Optional[IntegerClass]
    DedicatedMasterEnabled: Optional[Boolean]
    ZoneAwarenessEnabled: Optional[Boolean]
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig]
    DedicatedMasterType: Optional[ESPartitionInstanceType]
    DedicatedMasterCount: Optional[IntegerClass]
    WarmEnabled: Optional[Boolean]
    WarmType: Optional[ESWarmPartitionInstanceType]
    WarmCount: Optional[IntegerClass]
    ColdStorageOptions: Optional[ColdStorageOptions]


class CreateElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName
    ElasticsearchVersion: Optional[ElasticsearchVersionString]
    ElasticsearchClusterConfig: Optional[ElasticsearchClusterConfig]
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
    AutoTuneOptions: Optional[AutoTuneOptionsInput]
    TagList: Optional[TagList]


class VPCDerivedInfo(TypedDict, total=False):
    VPCId: Optional[String]
    SubnetIds: Optional[StringList]
    AvailabilityZones: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


EndpointsMap = Dict[String, ServiceUrl]


class ElasticsearchDomainStatus(TypedDict, total=False):
    DomainId: DomainId
    DomainName: DomainName
    ARN: ARN
    Created: Optional[Boolean]
    Deleted: Optional[Boolean]
    Endpoint: Optional[ServiceUrl]
    Endpoints: Optional[EndpointsMap]
    Processing: Optional[Boolean]
    UpgradeProcessing: Optional[Boolean]
    ElasticsearchVersion: Optional[ElasticsearchVersionString]
    ElasticsearchClusterConfig: ElasticsearchClusterConfig
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


class CreateElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[ElasticsearchDomainStatus]


class CreateOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    SourceDomainInfo: DomainInformation
    DestinationDomainInfo: DomainInformation
    ConnectionAlias: ConnectionAlias


class OutboundCrossClusterSearchConnectionStatus(TypedDict, total=False):
    StatusCode: Optional[OutboundCrossClusterSearchConnectionStatusCode]
    Message: Optional[CrossClusterSearchConnectionStatusMessage]


class CreateOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundCrossClusterSearchConnectionStatus]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]


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


class CreateVpcEndpointRequest(ServiceRequest):
    DomainArn: DomainArn
    VpcOptions: VPCOptions
    ClientToken: Optional[ClientToken]


class VpcEndpoint(TypedDict, total=False):
    VpcEndpointId: Optional[VpcEndpointId]
    VpcEndpointOwner: Optional[AWSAccount]
    DomainArn: Optional[DomainArn]
    VpcOptions: Optional[VPCDerivedInfo]
    Status: Optional[VpcEndpointStatus]
    Endpoint: Optional[Endpoint]


class CreateVpcEndpointResponse(TypedDict, total=False):
    VpcEndpoint: VpcEndpoint


class DeleteElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName


class DeleteElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[ElasticsearchDomainStatus]


class DeleteInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class DeleteInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


class DeleteOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class OutboundCrossClusterSearchConnection(TypedDict, total=False):
    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundCrossClusterSearchConnectionStatus]


class DeleteOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: Optional[OutboundCrossClusterSearchConnection]


class DeletePackageRequest(ServiceRequest):
    PackageID: PackageID


class DeletePackageResponse(TypedDict, total=False):
    PackageDetails: Optional[PackageDetails]


class DeleteVpcEndpointRequest(ServiceRequest):
    VpcEndpointId: VpcEndpointId


class VpcEndpointSummary(TypedDict, total=False):
    VpcEndpointId: Optional[VpcEndpointId]
    VpcEndpointOwner: Optional[String]
    DomainArn: Optional[DomainArn]
    Status: Optional[VpcEndpointStatus]


class DeleteVpcEndpointResponse(TypedDict, total=False):
    VpcEndpointSummary: VpcEndpointSummary


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


class DescribeElasticsearchDomainConfigRequest(ServiceRequest):
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


class ElasticsearchClusterConfigStatus(TypedDict, total=False):
    Options: ElasticsearchClusterConfig
    Status: OptionStatus


class ElasticsearchVersionStatus(TypedDict, total=False):
    Options: ElasticsearchVersionString
    Status: OptionStatus


class ElasticsearchDomainConfig(TypedDict, total=False):
    ElasticsearchVersion: Optional[ElasticsearchVersionStatus]
    ElasticsearchClusterConfig: Optional[ElasticsearchClusterConfigStatus]
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


class DescribeElasticsearchDomainConfigResponse(TypedDict, total=False):
    DomainConfig: ElasticsearchDomainConfig


class DescribeElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName


class DescribeElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: ElasticsearchDomainStatus


DomainNameList = List[DomainName]


class DescribeElasticsearchDomainsRequest(ServiceRequest):
    DomainNames: DomainNameList


ElasticsearchDomainStatusList = List[ElasticsearchDomainStatus]


class DescribeElasticsearchDomainsResponse(TypedDict, total=False):
    DomainStatusList: ElasticsearchDomainStatusList


class DescribeElasticsearchInstanceTypeLimitsRequest(ServiceRequest):
    DomainName: Optional[DomainName]
    InstanceType: ESPartitionInstanceType
    ElasticsearchVersion: ElasticsearchVersionString


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


class DescribeElasticsearchInstanceTypeLimitsResponse(TypedDict, total=False):
    LimitsByRole: Optional[LimitsByRole]


ValueStringList = List[NonEmptyString]


class Filter(TypedDict, total=False):
    Name: Optional[NonEmptyString]
    Values: Optional[ValueStringList]


FilterList = List[Filter]


class DescribeInboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


InboundCrossClusterSearchConnections = List[InboundCrossClusterSearchConnection]


class DescribeInboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    CrossClusterSearchConnections: Optional[InboundCrossClusterSearchConnections]
    NextToken: Optional[NextToken]


class DescribeOutboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


OutboundCrossClusterSearchConnections = List[OutboundCrossClusterSearchConnection]


class DescribeOutboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    CrossClusterSearchConnections: Optional[OutboundCrossClusterSearchConnections]
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


class DescribeReservedElasticsearchInstanceOfferingsRequest(ServiceRequest):
    ReservedElasticsearchInstanceOfferingId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedElasticsearchInstanceOffering(TypedDict, total=False):
    ReservedElasticsearchInstanceOfferingId: Optional[GUID]
    ElasticsearchInstanceType: Optional[ESPartitionInstanceType]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    PaymentOption: Optional[ReservedElasticsearchInstancePaymentOption]
    RecurringCharges: Optional[RecurringChargeList]


ReservedElasticsearchInstanceOfferingList = List[ReservedElasticsearchInstanceOffering]


class DescribeReservedElasticsearchInstanceOfferingsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ReservedElasticsearchInstanceOfferings: Optional[ReservedElasticsearchInstanceOfferingList]


class DescribeReservedElasticsearchInstancesRequest(ServiceRequest):
    ReservedElasticsearchInstanceId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ReservedElasticsearchInstance(TypedDict, total=False):
    ReservationName: Optional[ReservationToken]
    ReservedElasticsearchInstanceId: Optional[GUID]
    ReservedElasticsearchInstanceOfferingId: Optional[String]
    ElasticsearchInstanceType: Optional[ESPartitionInstanceType]
    StartTime: Optional[UpdateTimestamp]
    Duration: Optional[Integer]
    FixedPrice: Optional[Double]
    UsagePrice: Optional[Double]
    CurrencyCode: Optional[String]
    ElasticsearchInstanceCount: Optional[Integer]
    State: Optional[String]
    PaymentOption: Optional[ReservedElasticsearchInstancePaymentOption]
    RecurringCharges: Optional[RecurringChargeList]


ReservedElasticsearchInstanceList = List[ReservedElasticsearchInstance]


class DescribeReservedElasticsearchInstancesResponse(TypedDict, total=False):
    NextToken: Optional[String]
    ReservedElasticsearchInstances: Optional[ReservedElasticsearchInstanceList]


VpcEndpointIdList = List[VpcEndpointId]


class DescribeVpcEndpointsRequest(ServiceRequest):
    VpcEndpointIds: VpcEndpointIdList


class VpcEndpointError(TypedDict, total=False):
    VpcEndpointId: Optional[VpcEndpointId]
    ErrorCode: Optional[VpcEndpointErrorCode]
    ErrorMessage: Optional[String]


VpcEndpointErrorList = List[VpcEndpointError]
VpcEndpoints = List[VpcEndpoint]


class DescribeVpcEndpointsResponse(TypedDict, total=False):
    VpcEndpoints: VpcEndpoints
    VpcEndpointErrors: VpcEndpointErrorList


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


ElasticsearchInstanceTypeList = List[ESPartitionInstanceType]


class GetCompatibleElasticsearchVersionsRequest(ServiceRequest):
    DomainName: Optional[DomainName]


class GetCompatibleElasticsearchVersionsResponse(TypedDict, total=False):
    CompatibleElasticsearchVersions: Optional[CompatibleElasticsearchVersionsList]


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


class ListElasticsearchInstanceTypesRequest(ServiceRequest):
    ElasticsearchVersion: ElasticsearchVersionString
    DomainName: Optional[DomainName]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListElasticsearchInstanceTypesResponse(TypedDict, total=False):
    ElasticsearchInstanceTypes: Optional[ElasticsearchInstanceTypeList]
    NextToken: Optional[NextToken]


class ListElasticsearchVersionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListElasticsearchVersionsResponse(TypedDict, total=False):
    ElasticsearchVersions: Optional[ElasticsearchVersionList]
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


class ListVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    NextToken: Optional[NextToken]


class ListVpcEndpointAccessResponse(TypedDict, total=False):
    AuthorizedPrincipalList: AuthorizedPrincipalList
    NextToken: NextToken


class ListVpcEndpointsForDomainRequest(ServiceRequest):
    DomainName: DomainName
    NextToken: Optional[NextToken]


VpcEndpointSummaryList = List[VpcEndpointSummary]


class ListVpcEndpointsForDomainResponse(TypedDict, total=False):
    VpcEndpointSummaryList: VpcEndpointSummaryList
    NextToken: NextToken


class ListVpcEndpointsRequest(ServiceRequest):
    NextToken: Optional[NextToken]


class ListVpcEndpointsResponse(TypedDict, total=False):
    VpcEndpointSummaryList: VpcEndpointSummaryList
    NextToken: NextToken


class PurchaseReservedElasticsearchInstanceOfferingRequest(ServiceRequest):
    ReservedElasticsearchInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: Optional[InstanceCount]


class PurchaseReservedElasticsearchInstanceOfferingResponse(TypedDict, total=False):
    ReservedElasticsearchInstanceId: Optional[GUID]
    ReservationName: Optional[ReservationToken]


class RejectInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class RejectInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


class RemoveTagsRequest(ServiceRequest):
    ARN: ARN
    TagKeys: StringList


class RevokeVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    Account: AWSAccount


class RevokeVpcEndpointAccessResponse(TypedDict, total=False):
    pass


class StartElasticsearchServiceSoftwareUpdateRequest(ServiceRequest):
    DomainName: DomainName


class StartElasticsearchServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class UpdateElasticsearchDomainConfigRequest(ServiceRequest):
    DomainName: DomainName
    ElasticsearchClusterConfig: Optional[ElasticsearchClusterConfig]
    EBSOptions: Optional[EBSOptions]
    SnapshotOptions: Optional[SnapshotOptions]
    VPCOptions: Optional[VPCOptions]
    CognitoOptions: Optional[CognitoOptions]
    AdvancedOptions: Optional[AdvancedOptions]
    AccessPolicies: Optional[PolicyDocument]
    LogPublishingOptions: Optional[LogPublishingOptions]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    AutoTuneOptions: Optional[AutoTuneOptions]
    DryRun: Optional[DryRun]


class UpdateElasticsearchDomainConfigResponse(TypedDict, total=False):
    DomainConfig: ElasticsearchDomainConfig
    DryRunResults: Optional[DryRunResults]


class UpdatePackageRequest(ServiceRequest):
    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: Optional[PackageDescription]
    CommitMessage: Optional[CommitMessage]


class UpdatePackageResponse(TypedDict, total=False):
    PackageDetails: Optional[PackageDetails]


class UpdateVpcEndpointRequest(ServiceRequest):
    VpcEndpointId: VpcEndpointId
    VpcOptions: VPCOptions


class UpdateVpcEndpointResponse(TypedDict, total=False):
    VpcEndpoint: VpcEndpoint


class UpgradeElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName
    TargetVersion: ElasticsearchVersionString
    PerformCheckOnly: Optional[Boolean]


class UpgradeElasticsearchDomainResponse(TypedDict, total=False):
    DomainName: Optional[DomainName]
    TargetVersion: Optional[ElasticsearchVersionString]
    PerformCheckOnly: Optional[Boolean]
    ChangeProgressDetails: Optional[ChangeProgressDetails]


class EsApi:

    service = "es"
    version = "2015-01-01"

    @handler("AcceptInboundCrossClusterSearchConnection")
    def accept_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> AcceptInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        raise NotImplementedError

    @handler("AssociatePackage")
    def associate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> AssociatePackageResponse:
        raise NotImplementedError

    @handler("AuthorizeVpcEndpointAccess")
    def authorize_vpc_endpoint_access(
        self, context: RequestContext, domain_name: DomainName, account: AWSAccount
    ) -> AuthorizeVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("CancelElasticsearchServiceSoftwareUpdate")
    def cancel_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> CancelElasticsearchServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("CreateElasticsearchDomain")
    def create_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        elasticsearch_version: ElasticsearchVersionString = None,
        elasticsearch_cluster_config: ElasticsearchClusterConfig = None,
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
        auto_tune_options: AutoTuneOptionsInput = None,
        tag_list: TagList = None,
    ) -> CreateElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("CreateOutboundCrossClusterSearchConnection")
    def create_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        source_domain_info: DomainInformation,
        destination_domain_info: DomainInformation,
        connection_alias: ConnectionAlias,
    ) -> CreateOutboundCrossClusterSearchConnectionResponse:
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

    @handler("CreateVpcEndpoint")
    def create_vpc_endpoint(
        self,
        context: RequestContext,
        domain_arn: DomainArn,
        vpc_options: VPCOptions,
        client_token: ClientToken = None,
    ) -> CreateVpcEndpointResponse:
        raise NotImplementedError

    @handler("DeleteElasticsearchDomain")
    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("DeleteElasticsearchServiceRole")
    def delete_elasticsearch_service_role(
        self,
        context: RequestContext,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteInboundCrossClusterSearchConnection")
    def delete_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> DeleteInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("DeleteOutboundCrossClusterSearchConnection")
    def delete_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> DeleteOutboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("DeletePackage")
    def delete_package(
        self, context: RequestContext, package_id: PackageID
    ) -> DeletePackageResponse:
        raise NotImplementedError

    @handler("DeleteVpcEndpoint")
    def delete_vpc_endpoint(
        self, context: RequestContext, vpc_endpoint_id: VpcEndpointId
    ) -> DeleteVpcEndpointResponse:
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

    @handler("DescribeElasticsearchDomain")
    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchDomainConfig")
    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainConfigResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchDomains")
    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeElasticsearchDomainsResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchInstanceTypeLimits")
    def describe_elasticsearch_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: ESPartitionInstanceType,
        elasticsearch_version: ElasticsearchVersionString,
        domain_name: DomainName = None,
    ) -> DescribeElasticsearchInstanceTypeLimitsResponse:
        raise NotImplementedError

    @handler("DescribeInboundCrossClusterSearchConnections")
    def describe_inbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeInboundCrossClusterSearchConnectionsResponse:
        raise NotImplementedError

    @handler("DescribeOutboundCrossClusterSearchConnections")
    def describe_outbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeOutboundCrossClusterSearchConnectionsResponse:
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

    @handler("DescribeReservedElasticsearchInstanceOfferings")
    def describe_reserved_elasticsearch_instance_offerings(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedElasticsearchInstanceOfferingsResponse:
        raise NotImplementedError

    @handler("DescribeReservedElasticsearchInstances")
    def describe_reserved_elasticsearch_instances(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedElasticsearchInstancesResponse:
        raise NotImplementedError

    @handler("DescribeVpcEndpoints")
    def describe_vpc_endpoints(
        self, context: RequestContext, vpc_endpoint_ids: VpcEndpointIdList
    ) -> DescribeVpcEndpointsResponse:
        raise NotImplementedError

    @handler("DissociatePackage")
    def dissociate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> DissociatePackageResponse:
        raise NotImplementedError

    @handler("GetCompatibleElasticsearchVersions")
    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleElasticsearchVersionsResponse:
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

    @handler("ListElasticsearchInstanceTypes")
    def list_elasticsearch_instance_types(
        self,
        context: RequestContext,
        elasticsearch_version: ElasticsearchVersionString,
        domain_name: DomainName = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListElasticsearchInstanceTypesResponse:
        raise NotImplementedError

    @handler("ListElasticsearchVersions")
    def list_elasticsearch_versions(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListElasticsearchVersionsResponse:
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

    @handler("ListVpcEndpointAccess")
    def list_vpc_endpoint_access(
        self, context: RequestContext, domain_name: DomainName, next_token: NextToken = None
    ) -> ListVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("ListVpcEndpoints")
    def list_vpc_endpoints(
        self, context: RequestContext, next_token: NextToken = None
    ) -> ListVpcEndpointsResponse:
        raise NotImplementedError

    @handler("ListVpcEndpointsForDomain")
    def list_vpc_endpoints_for_domain(
        self, context: RequestContext, domain_name: DomainName, next_token: NextToken = None
    ) -> ListVpcEndpointsForDomainResponse:
        raise NotImplementedError

    @handler("PurchaseReservedElasticsearchInstanceOffering")
    def purchase_reserved_elasticsearch_instance_offering(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount = None,
    ) -> PurchaseReservedElasticsearchInstanceOfferingResponse:
        raise NotImplementedError

    @handler("RejectInboundCrossClusterSearchConnection")
    def reject_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> RejectInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        raise NotImplementedError

    @handler("RevokeVpcEndpointAccess")
    def revoke_vpc_endpoint_access(
        self, context: RequestContext, domain_name: DomainName, account: AWSAccount
    ) -> RevokeVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("StartElasticsearchServiceSoftwareUpdate")
    def start_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> StartElasticsearchServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("UpdateElasticsearchDomainConfig")
    def update_elasticsearch_domain_config(
        self,
        context: RequestContext,
        domain_name: DomainName,
        elasticsearch_cluster_config: ElasticsearchClusterConfig = None,
        ebs_options: EBSOptions = None,
        snapshot_options: SnapshotOptions = None,
        vpc_options: VPCOptions = None,
        cognito_options: CognitoOptions = None,
        advanced_options: AdvancedOptions = None,
        access_policies: PolicyDocument = None,
        log_publishing_options: LogPublishingOptions = None,
        domain_endpoint_options: DomainEndpointOptions = None,
        advanced_security_options: AdvancedSecurityOptionsInput = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions = None,
        encryption_at_rest_options: EncryptionAtRestOptions = None,
        auto_tune_options: AutoTuneOptions = None,
        dry_run: DryRun = None,
    ) -> UpdateElasticsearchDomainConfigResponse:
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

    @handler("UpdateVpcEndpoint")
    def update_vpc_endpoint(
        self, context: RequestContext, vpc_endpoint_id: VpcEndpointId, vpc_options: VPCOptions
    ) -> UpdateVpcEndpointResponse:
        raise NotImplementedError

    @handler("UpgradeElasticsearchDomain")
    def upgrade_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        target_version: ElasticsearchVersionString,
        perform_check_only: Boolean = None,
    ) -> UpgradeElasticsearchDomainResponse:
        raise NotImplementedError
