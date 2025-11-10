from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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


class AutoTuneDesiredState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class AutoTuneState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ENABLE_IN_PROGRESS = "ENABLE_IN_PROGRESS"
    DISABLE_IN_PROGRESS = "DISABLE_IN_PROGRESS"
    DISABLED_AND_ROLLBACK_SCHEDULED = "DISABLED_AND_ROLLBACK_SCHEDULED"
    DISABLED_AND_ROLLBACK_IN_PROGRESS = "DISABLED_AND_ROLLBACK_IN_PROGRESS"
    DISABLED_AND_ROLLBACK_COMPLETE = "DISABLED_AND_ROLLBACK_COMPLETE"
    DISABLED_AND_ROLLBACK_ERROR = "DISABLED_AND_ROLLBACK_ERROR"
    ERROR = "ERROR"


class AutoTuneType(StrEnum):
    SCHEDULED_ACTION = "SCHEDULED_ACTION"


class ConfigChangeStatus(StrEnum):
    Pending = "Pending"
    Initializing = "Initializing"
    Validating = "Validating"
    ValidationFailed = "ValidationFailed"
    ApplyingChanges = "ApplyingChanges"
    Completed = "Completed"
    PendingUserInput = "PendingUserInput"
    Cancelled = "Cancelled"


class DeploymentStatus(StrEnum):
    PENDING_UPDATE = "PENDING_UPDATE"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    ELIGIBLE = "ELIGIBLE"


class DescribePackagesFilterName(StrEnum):
    PackageID = "PackageID"
    PackageName = "PackageName"
    PackageStatus = "PackageStatus"


class DomainPackageStatus(StrEnum):
    ASSOCIATING = "ASSOCIATING"
    ASSOCIATION_FAILED = "ASSOCIATION_FAILED"
    ACTIVE = "ACTIVE"
    DISSOCIATING = "DISSOCIATING"
    DISSOCIATION_FAILED = "DISSOCIATION_FAILED"


class DomainProcessingStatusType(StrEnum):
    Creating = "Creating"
    Active = "Active"
    Modifying = "Modifying"
    UpgradingEngineVersion = "UpgradingEngineVersion"
    UpdatingServiceSoftware = "UpdatingServiceSoftware"
    Isolated = "Isolated"
    Deleting = "Deleting"


class ESPartitionInstanceType(StrEnum):
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


class ESWarmPartitionInstanceType(StrEnum):
    ultrawarm1_medium_elasticsearch = "ultrawarm1.medium.elasticsearch"
    ultrawarm1_large_elasticsearch = "ultrawarm1.large.elasticsearch"


class EngineType(StrEnum):
    OpenSearch = "OpenSearch"
    Elasticsearch = "Elasticsearch"


class InboundCrossClusterSearchConnectionStatusCode(StrEnum):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    APPROVED = "APPROVED"
    REJECTING = "REJECTING"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class InitiatedBy(StrEnum):
    CUSTOMER = "CUSTOMER"
    SERVICE = "SERVICE"


class LogType(StrEnum):
    INDEX_SLOW_LOGS = "INDEX_SLOW_LOGS"
    SEARCH_SLOW_LOGS = "SEARCH_SLOW_LOGS"
    ES_APPLICATION_LOGS = "ES_APPLICATION_LOGS"
    AUDIT_LOGS = "AUDIT_LOGS"


class OptionState(StrEnum):
    RequiresIndexDocuments = "RequiresIndexDocuments"
    Processing = "Processing"
    Active = "Active"


class OutboundCrossClusterSearchConnectionStatusCode(StrEnum):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class OverallChangeStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PackageStatus(StrEnum):
    COPYING = "COPYING"
    COPY_FAILED = "COPY_FAILED"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    AVAILABLE = "AVAILABLE"
    DELETING = "DELETING"
    DELETED = "DELETED"
    DELETE_FAILED = "DELETE_FAILED"


class PackageType(StrEnum):
    TXT_DICTIONARY = "TXT-DICTIONARY"


class PrincipalType(StrEnum):
    AWS_ACCOUNT = "AWS_ACCOUNT"
    AWS_SERVICE = "AWS_SERVICE"


class PropertyValueType(StrEnum):
    PLAIN_TEXT = "PLAIN_TEXT"
    STRINGIFIED_JSON = "STRINGIFIED_JSON"


class ReservedElasticsearchInstancePaymentOption(StrEnum):
    ALL_UPFRONT = "ALL_UPFRONT"
    PARTIAL_UPFRONT = "PARTIAL_UPFRONT"
    NO_UPFRONT = "NO_UPFRONT"


class RollbackOnDisable(StrEnum):
    NO_ROLLBACK = "NO_ROLLBACK"
    DEFAULT_ROLLBACK = "DEFAULT_ROLLBACK"


class ScheduledAutoTuneActionType(StrEnum):
    JVM_HEAP_SIZE_TUNING = "JVM_HEAP_SIZE_TUNING"
    JVM_YOUNG_GEN_TUNING = "JVM_YOUNG_GEN_TUNING"


class ScheduledAutoTuneSeverityType(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TLSSecurityPolicy(StrEnum):
    Policy_Min_TLS_1_0_2019_07 = "Policy-Min-TLS-1-0-2019-07"
    Policy_Min_TLS_1_2_2019_07 = "Policy-Min-TLS-1-2-2019-07"
    Policy_Min_TLS_1_2_PFS_2023_10 = "Policy-Min-TLS-1-2-PFS-2023-10"


class TimeUnit(StrEnum):
    HOURS = "HOURS"


class UpgradeStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_WITH_ISSUES = "SUCCEEDED_WITH_ISSUES"
    FAILED = "FAILED"


class UpgradeStep(StrEnum):
    PRE_UPGRADE_CHECK = "PRE_UPGRADE_CHECK"
    SNAPSHOT = "SNAPSHOT"
    UPGRADE = "UPGRADE"


class VolumeType(StrEnum):
    standard = "standard"
    gp2 = "gp2"
    io1 = "io1"
    gp3 = "gp3"


class VpcEndpointErrorCode(StrEnum):
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    SERVER_ERROR = "SERVER_ERROR"


class VpcEndpointStatus(StrEnum):
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
    StatusCode: InboundCrossClusterSearchConnectionStatusCode | None
    Message: CrossClusterSearchConnectionStatusMessage | None


class DomainInformation(TypedDict, total=False):
    OwnerId: OwnerId | None
    DomainName: DomainName
    Region: Region | None


class InboundCrossClusterSearchConnection(TypedDict, total=False):
    SourceDomainInfo: DomainInformation | None
    DestinationDomainInfo: DomainInformation | None
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId | None
    ConnectionStatus: InboundCrossClusterSearchConnectionStatus | None


class AcceptInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: InboundCrossClusterSearchConnection | None


UpdateTimestamp = datetime


class OptionStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: UIntValue | None
    State: OptionState
    PendingDeletion: Boolean | None


class AccessPoliciesStatus(TypedDict, total=False):
    Options: PolicyDocument
    Status: OptionStatus


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class AddTagsRequest(ServiceRequest):
    ARN: ARN
    TagList: TagList


LimitValueList = list[LimitValue]


class AdditionalLimit(TypedDict, total=False):
    LimitName: LimitName | None
    LimitValues: LimitValueList | None


AdditionalLimitList = list[AdditionalLimit]
AdvancedOptions = dict[String, String]


class AdvancedOptionsStatus(TypedDict, total=False):
    Options: AdvancedOptions
    Status: OptionStatus


DisableTimestamp = datetime


class SAMLIdp(TypedDict, total=False):
    MetadataContent: SAMLMetadata
    EntityId: SAMLEntityId


class SAMLOptionsOutput(TypedDict, total=False):
    Enabled: Boolean | None
    Idp: SAMLIdp | None
    SubjectKey: String | None
    RolesKey: String | None
    SessionTimeoutMinutes: IntegerClass | None


class AdvancedSecurityOptions(TypedDict, total=False):
    Enabled: Boolean | None
    InternalUserDatabaseEnabled: Boolean | None
    SAMLOptions: SAMLOptionsOutput | None
    AnonymousAuthDisableDate: DisableTimestamp | None
    AnonymousAuthEnabled: Boolean | None


class SAMLOptionsInput(TypedDict, total=False):
    Enabled: Boolean | None
    Idp: SAMLIdp | None
    MasterUserName: Username | None
    MasterBackendRole: BackendRole | None
    SubjectKey: String | None
    RolesKey: String | None
    SessionTimeoutMinutes: IntegerClass | None


class MasterUserOptions(TypedDict, total=False):
    MasterUserARN: ARN | None
    MasterUserName: Username | None
    MasterUserPassword: Password | None


class AdvancedSecurityOptionsInput(TypedDict, total=False):
    Enabled: Boolean | None
    InternalUserDatabaseEnabled: Boolean | None
    MasterUserOptions: MasterUserOptions | None
    SAMLOptions: SAMLOptionsInput | None
    AnonymousAuthEnabled: Boolean | None


class AdvancedSecurityOptionsStatus(TypedDict, total=False):
    Options: AdvancedSecurityOptions
    Status: OptionStatus


class AssociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName


class ErrorDetails(TypedDict, total=False):
    ErrorType: ErrorType | None
    ErrorMessage: ErrorMessage | None


LastUpdated = datetime


class DomainPackageDetails(TypedDict, total=False):
    PackageID: PackageID | None
    PackageName: PackageName | None
    PackageType: PackageType | None
    LastUpdated: LastUpdated | None
    DomainName: DomainName | None
    DomainPackageStatus: DomainPackageStatus | None
    PackageVersion: PackageVersion | None
    ReferencePath: ReferencePath | None
    ErrorDetails: ErrorDetails | None


class AssociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: DomainPackageDetails | None


class AuthorizeVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    Account: AWSAccount


class AuthorizedPrincipal(TypedDict, total=False):
    PrincipalType: PrincipalType | None
    Principal: String | None


class AuthorizeVpcEndpointAccessResponse(TypedDict, total=False):
    AuthorizedPrincipal: AuthorizedPrincipal


AuthorizedPrincipalList = list[AuthorizedPrincipal]
AutoTuneDate = datetime


class ScheduledAutoTuneDetails(TypedDict, total=False):
    Date: AutoTuneDate | None
    ActionType: ScheduledAutoTuneActionType | None
    Action: ScheduledAutoTuneDescription | None
    Severity: ScheduledAutoTuneSeverityType | None


class AutoTuneDetails(TypedDict, total=False):
    ScheduledAutoTuneDetails: ScheduledAutoTuneDetails | None


class AutoTune(TypedDict, total=False):
    AutoTuneType: AutoTuneType | None
    AutoTuneDetails: AutoTuneDetails | None


AutoTuneList = list[AutoTune]
DurationValue = int


class Duration(TypedDict, total=False):
    Value: DurationValue | None
    Unit: TimeUnit | None


StartAt = datetime


class AutoTuneMaintenanceSchedule(TypedDict, total=False):
    StartAt: StartAt | None
    Duration: Duration | None
    CronExpressionForRecurrence: String | None


AutoTuneMaintenanceScheduleList = list[AutoTuneMaintenanceSchedule]


class AutoTuneOptions(TypedDict, total=False):
    DesiredState: AutoTuneDesiredState | None
    RollbackOnDisable: RollbackOnDisable | None
    MaintenanceSchedules: AutoTuneMaintenanceScheduleList | None


class AutoTuneOptionsInput(TypedDict, total=False):
    DesiredState: AutoTuneDesiredState | None
    MaintenanceSchedules: AutoTuneMaintenanceScheduleList | None


class AutoTuneOptionsOutput(TypedDict, total=False):
    State: AutoTuneState | None
    ErrorMessage: String | None


class AutoTuneStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: UIntValue | None
    State: AutoTuneState
    ErrorMessage: String | None
    PendingDeletion: Boolean | None


class AutoTuneOptionsStatus(TypedDict, total=False):
    Options: AutoTuneOptions | None
    Status: AutoTuneStatus | None


class CancelDomainConfigChangeRequest(ServiceRequest):
    DomainName: DomainName
    DryRun: DryRun | None


class CancelledChangeProperty(TypedDict, total=False):
    PropertyName: String | None
    CancelledValue: String | None
    ActiveValue: String | None


CancelledChangePropertyList = list[CancelledChangeProperty]
GUIDList = list[GUID]


class CancelDomainConfigChangeResponse(TypedDict, total=False):
    DryRun: DryRun | None
    CancelledChangeIds: GUIDList | None
    CancelledChangeProperties: CancelledChangePropertyList | None


class CancelElasticsearchServiceSoftwareUpdateRequest(ServiceRequest):
    DomainName: DomainName


DeploymentCloseDateTimeStamp = datetime


class ServiceSoftwareOptions(TypedDict, total=False):
    CurrentVersion: String | None
    NewVersion: String | None
    UpdateAvailable: Boolean | None
    Cancellable: Boolean | None
    UpdateStatus: DeploymentStatus | None
    Description: String | None
    AutomatedUpdateDate: DeploymentCloseDateTimeStamp | None
    OptionalDeployment: Boolean | None


class CancelElasticsearchServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: ServiceSoftwareOptions | None


class ChangeProgressDetails(TypedDict, total=False):
    ChangeId: GUID | None
    Message: Message | None
    ConfigChangeStatus: ConfigChangeStatus | None
    StartTime: UpdateTimestamp | None
    LastUpdatedTime: UpdateTimestamp | None
    InitiatedBy: InitiatedBy | None


class ChangeProgressStage(TypedDict, total=False):
    Name: ChangeProgressStageName | None
    Status: ChangeProgressStageStatus | None
    Description: Description | None
    LastUpdated: LastUpdated | None


ChangeProgressStageList = list[ChangeProgressStage]
StringList = list[String]


class ChangeProgressStatusDetails(TypedDict, total=False):
    ChangeId: GUID | None
    StartTime: UpdateTimestamp | None
    Status: OverallChangeStatus | None
    PendingProperties: StringList | None
    CompletedProperties: StringList | None
    TotalNumberOfStages: TotalNumberOfStages | None
    ChangeProgressStages: ChangeProgressStageList | None
    ConfigChangeStatus: ConfigChangeStatus | None
    LastUpdatedTime: UpdateTimestamp | None
    InitiatedBy: InitiatedBy | None


class CognitoOptions(TypedDict, total=False):
    Enabled: Boolean | None
    UserPoolId: UserPoolId | None
    IdentityPoolId: IdentityPoolId | None
    RoleArn: RoleArn | None


class CognitoOptionsStatus(TypedDict, total=False):
    Options: CognitoOptions
    Status: OptionStatus


class ColdStorageOptions(TypedDict, total=False):
    Enabled: Boolean


ElasticsearchVersionList = list[ElasticsearchVersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    SourceVersion: ElasticsearchVersionString | None
    TargetVersions: ElasticsearchVersionList | None


CompatibleElasticsearchVersionsList = list[CompatibleVersionsMap]


class DomainEndpointOptions(TypedDict, total=False):
    EnforceHTTPS: Boolean | None
    TLSSecurityPolicy: TLSSecurityPolicy | None
    CustomEndpointEnabled: Boolean | None
    CustomEndpoint: DomainNameFqdn | None
    CustomEndpointCertificateArn: ARN | None


class LogPublishingOption(TypedDict, total=False):
    CloudWatchLogsLogGroupArn: CloudWatchLogsLogGroupArn | None
    Enabled: Boolean | None


LogPublishingOptions = dict[LogType, LogPublishingOption]


class NodeToNodeEncryptionOptions(TypedDict, total=False):
    Enabled: Boolean | None


class EncryptionAtRestOptions(TypedDict, total=False):
    Enabled: Boolean | None
    KmsKeyId: KmsKeyId | None


class VPCOptions(TypedDict, total=False):
    SubnetIds: StringList | None
    SecurityGroupIds: StringList | None


class SnapshotOptions(TypedDict, total=False):
    AutomatedSnapshotStartHour: IntegerClass | None


class EBSOptions(TypedDict, total=False):
    EBSEnabled: Boolean | None
    VolumeType: VolumeType | None
    VolumeSize: IntegerClass | None
    Iops: IntegerClass | None
    Throughput: IntegerClass | None


class ZoneAwarenessConfig(TypedDict, total=False):
    AvailabilityZoneCount: IntegerClass | None


class ElasticsearchClusterConfig(TypedDict, total=False):
    InstanceType: ESPartitionInstanceType | None
    InstanceCount: IntegerClass | None
    DedicatedMasterEnabled: Boolean | None
    ZoneAwarenessEnabled: Boolean | None
    ZoneAwarenessConfig: ZoneAwarenessConfig | None
    DedicatedMasterType: ESPartitionInstanceType | None
    DedicatedMasterCount: IntegerClass | None
    WarmEnabled: Boolean | None
    WarmType: ESWarmPartitionInstanceType | None
    WarmCount: IntegerClass | None
    ColdStorageOptions: ColdStorageOptions | None


class CreateElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName
    ElasticsearchVersion: ElasticsearchVersionString | None
    ElasticsearchClusterConfig: ElasticsearchClusterConfig | None
    EBSOptions: EBSOptions | None
    AccessPolicies: PolicyDocument | None
    SnapshotOptions: SnapshotOptions | None
    VPCOptions: VPCOptions | None
    CognitoOptions: CognitoOptions | None
    EncryptionAtRestOptions: EncryptionAtRestOptions | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptions | None
    AdvancedOptions: AdvancedOptions | None
    LogPublishingOptions: LogPublishingOptions | None
    DomainEndpointOptions: DomainEndpointOptions | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsInput | None
    AutoTuneOptions: AutoTuneOptionsInput | None
    TagList: TagList | None


class ModifyingProperties(TypedDict, total=False):
    Name: String | None
    ActiveValue: String | None
    PendingValue: String | None
    ValueType: PropertyValueType | None


ModifyingPropertiesList = list[ModifyingProperties]


class VPCDerivedInfo(TypedDict, total=False):
    VPCId: String | None
    SubnetIds: StringList | None
    AvailabilityZones: StringList | None
    SecurityGroupIds: StringList | None


EndpointsMap = dict[String, ServiceUrl]


class ElasticsearchDomainStatus(TypedDict, total=False):
    DomainId: DomainId
    DomainName: DomainName
    ARN: ARN
    Created: Boolean | None
    Deleted: Boolean | None
    Endpoint: ServiceUrl | None
    Endpoints: EndpointsMap | None
    Processing: Boolean | None
    UpgradeProcessing: Boolean | None
    ElasticsearchVersion: ElasticsearchVersionString | None
    ElasticsearchClusterConfig: ElasticsearchClusterConfig
    EBSOptions: EBSOptions | None
    AccessPolicies: PolicyDocument | None
    SnapshotOptions: SnapshotOptions | None
    VPCOptions: VPCDerivedInfo | None
    CognitoOptions: CognitoOptions | None
    EncryptionAtRestOptions: EncryptionAtRestOptions | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptions | None
    AdvancedOptions: AdvancedOptions | None
    LogPublishingOptions: LogPublishingOptions | None
    ServiceSoftwareOptions: ServiceSoftwareOptions | None
    DomainEndpointOptions: DomainEndpointOptions | None
    AdvancedSecurityOptions: AdvancedSecurityOptions | None
    AutoTuneOptions: AutoTuneOptionsOutput | None
    ChangeProgressDetails: ChangeProgressDetails | None
    DomainProcessingStatus: DomainProcessingStatusType | None
    ModifyingProperties: ModifyingPropertiesList | None


class CreateElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: ElasticsearchDomainStatus | None


class CreateOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    SourceDomainInfo: DomainInformation
    DestinationDomainInfo: DomainInformation
    ConnectionAlias: ConnectionAlias


class OutboundCrossClusterSearchConnectionStatus(TypedDict, total=False):
    StatusCode: OutboundCrossClusterSearchConnectionStatusCode | None
    Message: CrossClusterSearchConnectionStatusMessage | None


class CreateOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    SourceDomainInfo: DomainInformation | None
    DestinationDomainInfo: DomainInformation | None
    ConnectionAlias: ConnectionAlias | None
    ConnectionStatus: OutboundCrossClusterSearchConnectionStatus | None
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId | None


class PackageSource(TypedDict, total=False):
    S3BucketName: S3BucketName | None
    S3Key: S3Key | None


class CreatePackageRequest(ServiceRequest):
    PackageName: PackageName
    PackageType: PackageType
    PackageDescription: PackageDescription | None
    PackageSource: PackageSource


CreatedAt = datetime


class PackageDetails(TypedDict, total=False):
    PackageID: PackageID | None
    PackageName: PackageName | None
    PackageType: PackageType | None
    PackageDescription: PackageDescription | None
    PackageStatus: PackageStatus | None
    CreatedAt: CreatedAt | None
    LastUpdatedAt: LastUpdated | None
    AvailablePackageVersion: PackageVersion | None
    ErrorDetails: ErrorDetails | None


class CreatePackageResponse(TypedDict, total=False):
    PackageDetails: PackageDetails | None


class CreateVpcEndpointRequest(ServiceRequest):
    DomainArn: DomainArn
    VpcOptions: VPCOptions
    ClientToken: ClientToken | None


class VpcEndpoint(TypedDict, total=False):
    VpcEndpointId: VpcEndpointId | None
    VpcEndpointOwner: AWSAccount | None
    DomainArn: DomainArn | None
    VpcOptions: VPCDerivedInfo | None
    Status: VpcEndpointStatus | None
    Endpoint: Endpoint | None


class CreateVpcEndpointResponse(TypedDict, total=False):
    VpcEndpoint: VpcEndpoint


class DeleteElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName


class DeleteElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: ElasticsearchDomainStatus | None


class DeleteInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class DeleteInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: InboundCrossClusterSearchConnection | None


class DeleteOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class OutboundCrossClusterSearchConnection(TypedDict, total=False):
    SourceDomainInfo: DomainInformation | None
    DestinationDomainInfo: DomainInformation | None
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId | None
    ConnectionAlias: ConnectionAlias | None
    ConnectionStatus: OutboundCrossClusterSearchConnectionStatus | None


class DeleteOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: OutboundCrossClusterSearchConnection | None


class DeletePackageRequest(ServiceRequest):
    PackageID: PackageID


class DeletePackageResponse(TypedDict, total=False):
    PackageDetails: PackageDetails | None


class DeleteVpcEndpointRequest(ServiceRequest):
    VpcEndpointId: VpcEndpointId


class VpcEndpointSummary(TypedDict, total=False):
    VpcEndpointId: VpcEndpointId | None
    VpcEndpointOwner: String | None
    DomainArn: DomainArn | None
    Status: VpcEndpointStatus | None


class DeleteVpcEndpointResponse(TypedDict, total=False):
    VpcEndpointSummary: VpcEndpointSummary


class DescribeDomainAutoTunesRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class DescribeDomainAutoTunesResponse(TypedDict, total=False):
    AutoTunes: AutoTuneList | None
    NextToken: NextToken | None


class DescribeDomainChangeProgressRequest(ServiceRequest):
    DomainName: DomainName
    ChangeId: GUID | None


class DescribeDomainChangeProgressResponse(TypedDict, total=False):
    ChangeProgressStatus: ChangeProgressStatusDetails | None


class DescribeElasticsearchDomainConfigRequest(ServiceRequest):
    DomainName: DomainName


class DomainEndpointOptionsStatus(TypedDict, total=False):
    Options: DomainEndpointOptions
    Status: OptionStatus


class LogPublishingOptionsStatus(TypedDict, total=False):
    Options: LogPublishingOptions | None
    Status: OptionStatus | None


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
    ElasticsearchVersion: ElasticsearchVersionStatus | None
    ElasticsearchClusterConfig: ElasticsearchClusterConfigStatus | None
    EBSOptions: EBSOptionsStatus | None
    AccessPolicies: AccessPoliciesStatus | None
    SnapshotOptions: SnapshotOptionsStatus | None
    VPCOptions: VPCDerivedInfoStatus | None
    CognitoOptions: CognitoOptionsStatus | None
    EncryptionAtRestOptions: EncryptionAtRestOptionsStatus | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptionsStatus | None
    AdvancedOptions: AdvancedOptionsStatus | None
    LogPublishingOptions: LogPublishingOptionsStatus | None
    DomainEndpointOptions: DomainEndpointOptionsStatus | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsStatus | None
    AutoTuneOptions: AutoTuneOptionsStatus | None
    ChangeProgressDetails: ChangeProgressDetails | None
    ModifyingProperties: ModifyingPropertiesList | None


class DescribeElasticsearchDomainConfigResponse(TypedDict, total=False):
    DomainConfig: ElasticsearchDomainConfig


class DescribeElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName


class DescribeElasticsearchDomainResponse(TypedDict, total=False):
    DomainStatus: ElasticsearchDomainStatus


DomainNameList = list[DomainName]


class DescribeElasticsearchDomainsRequest(ServiceRequest):
    DomainNames: DomainNameList


ElasticsearchDomainStatusList = list[ElasticsearchDomainStatus]


class DescribeElasticsearchDomainsResponse(TypedDict, total=False):
    DomainStatusList: ElasticsearchDomainStatusList


class DescribeElasticsearchInstanceTypeLimitsRequest(ServiceRequest):
    DomainName: DomainName | None
    InstanceType: ESPartitionInstanceType
    ElasticsearchVersion: ElasticsearchVersionString


class InstanceCountLimits(TypedDict, total=False):
    MinimumInstanceCount: MinimumInstanceCount | None
    MaximumInstanceCount: MaximumInstanceCount | None


class InstanceLimits(TypedDict, total=False):
    InstanceCountLimits: InstanceCountLimits | None


class StorageTypeLimit(TypedDict, total=False):
    LimitName: LimitName | None
    LimitValues: LimitValueList | None


StorageTypeLimitList = list[StorageTypeLimit]


class StorageType(TypedDict, total=False):
    StorageTypeName: StorageTypeName | None
    StorageSubTypeName: StorageSubTypeName | None
    StorageTypeLimits: StorageTypeLimitList | None


StorageTypeList = list[StorageType]


class Limits(TypedDict, total=False):
    StorageTypes: StorageTypeList | None
    InstanceLimits: InstanceLimits | None
    AdditionalLimits: AdditionalLimitList | None


LimitsByRole = dict[InstanceRole, Limits]


class DescribeElasticsearchInstanceTypeLimitsResponse(TypedDict, total=False):
    LimitsByRole: LimitsByRole | None


ValueStringList = list[NonEmptyString]


class Filter(TypedDict, total=False):
    Name: NonEmptyString | None
    Values: ValueStringList | None


FilterList = list[Filter]


class DescribeInboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    Filters: FilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


InboundCrossClusterSearchConnections = list[InboundCrossClusterSearchConnection]


class DescribeInboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    CrossClusterSearchConnections: InboundCrossClusterSearchConnections | None
    NextToken: NextToken | None


class DescribeOutboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    Filters: FilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


OutboundCrossClusterSearchConnections = list[OutboundCrossClusterSearchConnection]


class DescribeOutboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    CrossClusterSearchConnections: OutboundCrossClusterSearchConnections | None
    NextToken: NextToken | None


DescribePackagesFilterValues = list[DescribePackagesFilterValue]


class DescribePackagesFilter(TypedDict, total=False):
    Name: DescribePackagesFilterName | None
    Value: DescribePackagesFilterValues | None


DescribePackagesFilterList = list[DescribePackagesFilter]


class DescribePackagesRequest(ServiceRequest):
    Filters: DescribePackagesFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


PackageDetailsList = list[PackageDetails]


class DescribePackagesResponse(TypedDict, total=False):
    PackageDetailsList: PackageDetailsList | None
    NextToken: String | None


class DescribeReservedElasticsearchInstanceOfferingsRequest(ServiceRequest):
    ReservedElasticsearchInstanceOfferingId: GUID | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Double | None
    RecurringChargeFrequency: String | None


RecurringChargeList = list[RecurringCharge]


class ReservedElasticsearchInstanceOffering(TypedDict, total=False):
    ReservedElasticsearchInstanceOfferingId: GUID | None
    ElasticsearchInstanceType: ESPartitionInstanceType | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    PaymentOption: ReservedElasticsearchInstancePaymentOption | None
    RecurringCharges: RecurringChargeList | None


ReservedElasticsearchInstanceOfferingList = list[ReservedElasticsearchInstanceOffering]


class DescribeReservedElasticsearchInstanceOfferingsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    ReservedElasticsearchInstanceOfferings: ReservedElasticsearchInstanceOfferingList | None


class DescribeReservedElasticsearchInstancesRequest(ServiceRequest):
    ReservedElasticsearchInstanceId: GUID | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ReservedElasticsearchInstance(TypedDict, total=False):
    ReservationName: ReservationToken | None
    ReservedElasticsearchInstanceId: GUID | None
    ReservedElasticsearchInstanceOfferingId: String | None
    ElasticsearchInstanceType: ESPartitionInstanceType | None
    StartTime: UpdateTimestamp | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    ElasticsearchInstanceCount: Integer | None
    State: String | None
    PaymentOption: ReservedElasticsearchInstancePaymentOption | None
    RecurringCharges: RecurringChargeList | None


ReservedElasticsearchInstanceList = list[ReservedElasticsearchInstance]


class DescribeReservedElasticsearchInstancesResponse(TypedDict, total=False):
    NextToken: String | None
    ReservedElasticsearchInstances: ReservedElasticsearchInstanceList | None


VpcEndpointIdList = list[VpcEndpointId]


class DescribeVpcEndpointsRequest(ServiceRequest):
    VpcEndpointIds: VpcEndpointIdList


class VpcEndpointError(TypedDict, total=False):
    VpcEndpointId: VpcEndpointId | None
    ErrorCode: VpcEndpointErrorCode | None
    ErrorMessage: String | None


VpcEndpointErrorList = list[VpcEndpointError]
VpcEndpoints = list[VpcEndpoint]


class DescribeVpcEndpointsResponse(TypedDict, total=False):
    VpcEndpoints: VpcEndpoints
    VpcEndpointErrors: VpcEndpointErrorList


class DissociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName


class DissociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: DomainPackageDetails | None


class DomainInfo(TypedDict, total=False):
    DomainName: DomainName | None
    EngineType: EngineType | None


DomainInfoList = list[DomainInfo]
DomainPackageDetailsList = list[DomainPackageDetails]


class DryRunResults(TypedDict, total=False):
    DeploymentType: DeploymentType | None
    Message: Message | None


ElasticsearchInstanceTypeList = list[ESPartitionInstanceType]


class GetCompatibleElasticsearchVersionsRequest(ServiceRequest):
    DomainName: DomainName | None


class GetCompatibleElasticsearchVersionsResponse(TypedDict, total=False):
    CompatibleElasticsearchVersions: CompatibleElasticsearchVersionsList | None


class GetPackageVersionHistoryRequest(ServiceRequest):
    PackageID: PackageID
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class PackageVersionHistory(TypedDict, total=False):
    PackageVersion: PackageVersion | None
    CommitMessage: CommitMessage | None
    CreatedAt: CreatedAt | None


PackageVersionHistoryList = list[PackageVersionHistory]


class GetPackageVersionHistoryResponse(TypedDict, total=False):
    PackageID: PackageID | None
    PackageVersionHistoryList: PackageVersionHistoryList | None
    NextToken: String | None


class GetUpgradeHistoryRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: MaxResults | None
    NextToken: NextToken | None


Issues = list[Issue]


class UpgradeStepItem(TypedDict, total=False):
    UpgradeStep: UpgradeStep | None
    UpgradeStepStatus: UpgradeStatus | None
    Issues: Issues | None
    ProgressPercent: Double | None


UpgradeStepsList = list[UpgradeStepItem]
StartTimestamp = datetime


class UpgradeHistory(TypedDict, total=False):
    UpgradeName: UpgradeName | None
    StartTimestamp: StartTimestamp | None
    UpgradeStatus: UpgradeStatus | None
    StepsList: UpgradeStepsList | None


UpgradeHistoryList = list[UpgradeHistory]


class GetUpgradeHistoryResponse(TypedDict, total=False):
    UpgradeHistories: UpgradeHistoryList | None
    NextToken: String | None


class GetUpgradeStatusRequest(ServiceRequest):
    DomainName: DomainName


class GetUpgradeStatusResponse(TypedDict, total=False):
    UpgradeStep: UpgradeStep | None
    StepStatus: UpgradeStatus | None
    UpgradeName: UpgradeName | None


class ListDomainNamesRequest(ServiceRequest):
    EngineType: EngineType | None


class ListDomainNamesResponse(TypedDict, total=False):
    DomainNames: DomainInfoList | None


class ListDomainsForPackageRequest(ServiceRequest):
    PackageID: PackageID
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListDomainsForPackageResponse(TypedDict, total=False):
    DomainPackageDetailsList: DomainPackageDetailsList | None
    NextToken: String | None


class ListElasticsearchInstanceTypesRequest(ServiceRequest):
    ElasticsearchVersion: ElasticsearchVersionString
    DomainName: DomainName | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListElasticsearchInstanceTypesResponse(TypedDict, total=False):
    ElasticsearchInstanceTypes: ElasticsearchInstanceTypeList | None
    NextToken: NextToken | None


class ListElasticsearchVersionsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListElasticsearchVersionsResponse(TypedDict, total=False):
    ElasticsearchVersions: ElasticsearchVersionList | None
    NextToken: NextToken | None


class ListPackagesForDomainRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListPackagesForDomainResponse(TypedDict, total=False):
    DomainPackageDetailsList: DomainPackageDetailsList | None
    NextToken: String | None


class ListTagsRequest(ServiceRequest):
    ARN: ARN


class ListTagsResponse(TypedDict, total=False):
    TagList: TagList | None


class ListVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    NextToken: NextToken | None


class ListVpcEndpointAccessResponse(TypedDict, total=False):
    AuthorizedPrincipalList: AuthorizedPrincipalList
    NextToken: NextToken


class ListVpcEndpointsForDomainRequest(ServiceRequest):
    DomainName: DomainName
    NextToken: NextToken | None


VpcEndpointSummaryList = list[VpcEndpointSummary]


class ListVpcEndpointsForDomainResponse(TypedDict, total=False):
    VpcEndpointSummaryList: VpcEndpointSummaryList
    NextToken: NextToken


class ListVpcEndpointsRequest(ServiceRequest):
    NextToken: NextToken | None


class ListVpcEndpointsResponse(TypedDict, total=False):
    VpcEndpointSummaryList: VpcEndpointSummaryList
    NextToken: NextToken


class PurchaseReservedElasticsearchInstanceOfferingRequest(ServiceRequest):
    ReservedElasticsearchInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: InstanceCount | None


class PurchaseReservedElasticsearchInstanceOfferingResponse(TypedDict, total=False):
    ReservedElasticsearchInstanceId: GUID | None
    ReservationName: ReservationToken | None


class RejectInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class RejectInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    CrossClusterSearchConnection: InboundCrossClusterSearchConnection | None


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
    ServiceSoftwareOptions: ServiceSoftwareOptions | None


class UpdateElasticsearchDomainConfigRequest(ServiceRequest):
    DomainName: DomainName
    ElasticsearchClusterConfig: ElasticsearchClusterConfig | None
    EBSOptions: EBSOptions | None
    SnapshotOptions: SnapshotOptions | None
    VPCOptions: VPCOptions | None
    CognitoOptions: CognitoOptions | None
    AdvancedOptions: AdvancedOptions | None
    AccessPolicies: PolicyDocument | None
    LogPublishingOptions: LogPublishingOptions | None
    DomainEndpointOptions: DomainEndpointOptions | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsInput | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptions | None
    EncryptionAtRestOptions: EncryptionAtRestOptions | None
    AutoTuneOptions: AutoTuneOptions | None
    DryRun: DryRun | None


class UpdateElasticsearchDomainConfigResponse(TypedDict, total=False):
    DomainConfig: ElasticsearchDomainConfig
    DryRunResults: DryRunResults | None


class UpdatePackageRequest(ServiceRequest):
    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: PackageDescription | None
    CommitMessage: CommitMessage | None


class UpdatePackageResponse(TypedDict, total=False):
    PackageDetails: PackageDetails | None


class UpdateVpcEndpointRequest(ServiceRequest):
    VpcEndpointId: VpcEndpointId
    VpcOptions: VPCOptions


class UpdateVpcEndpointResponse(TypedDict, total=False):
    VpcEndpoint: VpcEndpoint


class UpgradeElasticsearchDomainRequest(ServiceRequest):
    DomainName: DomainName
    TargetVersion: ElasticsearchVersionString
    PerformCheckOnly: Boolean | None


class UpgradeElasticsearchDomainResponse(TypedDict, total=False):
    DomainName: DomainName | None
    TargetVersion: ElasticsearchVersionString | None
    PerformCheckOnly: Boolean | None
    ChangeProgressDetails: ChangeProgressDetails | None


class EsApi:
    service: str = "es"
    version: str = "2015-01-01"

    @handler("AcceptInboundCrossClusterSearchConnection")
    def accept_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
        **kwargs,
    ) -> AcceptInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList, **kwargs) -> None:
        raise NotImplementedError

    @handler("AssociatePackage")
    def associate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName, **kwargs
    ) -> AssociatePackageResponse:
        raise NotImplementedError

    @handler("AuthorizeVpcEndpointAccess")
    def authorize_vpc_endpoint_access(
        self, context: RequestContext, domain_name: DomainName, account: AWSAccount, **kwargs
    ) -> AuthorizeVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("CancelDomainConfigChange")
    def cancel_domain_config_change(
        self,
        context: RequestContext,
        domain_name: DomainName,
        dry_run: DryRun | None = None,
        **kwargs,
    ) -> CancelDomainConfigChangeResponse:
        raise NotImplementedError

    @handler("CancelElasticsearchServiceSoftwareUpdate")
    def cancel_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> CancelElasticsearchServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("CreateElasticsearchDomain")
    def create_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        elasticsearch_version: ElasticsearchVersionString | None = None,
        elasticsearch_cluster_config: ElasticsearchClusterConfig | None = None,
        ebs_options: EBSOptions | None = None,
        access_policies: PolicyDocument | None = None,
        snapshot_options: SnapshotOptions | None = None,
        vpc_options: VPCOptions | None = None,
        cognito_options: CognitoOptions | None = None,
        encryption_at_rest_options: EncryptionAtRestOptions | None = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions | None = None,
        advanced_options: AdvancedOptions | None = None,
        log_publishing_options: LogPublishingOptions | None = None,
        domain_endpoint_options: DomainEndpointOptions | None = None,
        advanced_security_options: AdvancedSecurityOptionsInput | None = None,
        auto_tune_options: AutoTuneOptionsInput | None = None,
        tag_list: TagList | None = None,
        **kwargs,
    ) -> CreateElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("CreateOutboundCrossClusterSearchConnection")
    def create_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        source_domain_info: DomainInformation,
        destination_domain_info: DomainInformation,
        connection_alias: ConnectionAlias,
        **kwargs,
    ) -> CreateOutboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("CreatePackage")
    def create_package(
        self,
        context: RequestContext,
        package_name: PackageName,
        package_type: PackageType,
        package_source: PackageSource,
        package_description: PackageDescription | None = None,
        **kwargs,
    ) -> CreatePackageResponse:
        raise NotImplementedError

    @handler("CreateVpcEndpoint")
    def create_vpc_endpoint(
        self,
        context: RequestContext,
        domain_arn: DomainArn,
        vpc_options: VPCOptions,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> CreateVpcEndpointResponse:
        raise NotImplementedError

    @handler("DeleteElasticsearchDomain")
    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DeleteElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("DeleteElasticsearchServiceRole")
    def delete_elasticsearch_service_role(self, context: RequestContext, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteInboundCrossClusterSearchConnection")
    def delete_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
        **kwargs,
    ) -> DeleteInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("DeleteOutboundCrossClusterSearchConnection")
    def delete_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
        **kwargs,
    ) -> DeleteOutboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("DeletePackage")
    def delete_package(
        self, context: RequestContext, package_id: PackageID, **kwargs
    ) -> DeletePackageResponse:
        raise NotImplementedError

    @handler("DeleteVpcEndpoint")
    def delete_vpc_endpoint(
        self, context: RequestContext, vpc_endpoint_id: VpcEndpointId, **kwargs
    ) -> DeleteVpcEndpointResponse:
        raise NotImplementedError

    @handler("DescribeDomainAutoTunes")
    def describe_domain_auto_tunes(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeDomainAutoTunesResponse:
        raise NotImplementedError

    @handler("DescribeDomainChangeProgress")
    def describe_domain_change_progress(
        self,
        context: RequestContext,
        domain_name: DomainName,
        change_id: GUID | None = None,
        **kwargs,
    ) -> DescribeDomainChangeProgressResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchDomain")
    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeElasticsearchDomainResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchDomainConfig")
    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeElasticsearchDomainConfigResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchDomains")
    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList, **kwargs
    ) -> DescribeElasticsearchDomainsResponse:
        raise NotImplementedError

    @handler("DescribeElasticsearchInstanceTypeLimits")
    def describe_elasticsearch_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: ESPartitionInstanceType,
        elasticsearch_version: ElasticsearchVersionString,
        domain_name: DomainName | None = None,
        **kwargs,
    ) -> DescribeElasticsearchInstanceTypeLimitsResponse:
        raise NotImplementedError

    @handler("DescribeInboundCrossClusterSearchConnections")
    def describe_inbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeInboundCrossClusterSearchConnectionsResponse:
        raise NotImplementedError

    @handler("DescribeOutboundCrossClusterSearchConnections")
    def describe_outbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeOutboundCrossClusterSearchConnectionsResponse:
        raise NotImplementedError

    @handler("DescribePackages")
    def describe_packages(
        self,
        context: RequestContext,
        filters: DescribePackagesFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribePackagesResponse:
        raise NotImplementedError

    @handler("DescribeReservedElasticsearchInstanceOfferings")
    def describe_reserved_elasticsearch_instance_offerings(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeReservedElasticsearchInstanceOfferingsResponse:
        raise NotImplementedError

    @handler("DescribeReservedElasticsearchInstances")
    def describe_reserved_elasticsearch_instances(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_id: GUID | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeReservedElasticsearchInstancesResponse:
        raise NotImplementedError

    @handler("DescribeVpcEndpoints")
    def describe_vpc_endpoints(
        self, context: RequestContext, vpc_endpoint_ids: VpcEndpointIdList, **kwargs
    ) -> DescribeVpcEndpointsResponse:
        raise NotImplementedError

    @handler("DissociatePackage")
    def dissociate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName, **kwargs
    ) -> DissociatePackageResponse:
        raise NotImplementedError

    @handler("GetCompatibleElasticsearchVersions")
    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName | None = None, **kwargs
    ) -> GetCompatibleElasticsearchVersionsResponse:
        raise NotImplementedError

    @handler("GetPackageVersionHistory")
    def get_package_version_history(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetPackageVersionHistoryResponse:
        raise NotImplementedError

    @handler("GetUpgradeHistory")
    def get_upgrade_history(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetUpgradeHistoryResponse:
        raise NotImplementedError

    @handler("GetUpgradeStatus")
    def get_upgrade_status(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> GetUpgradeStatusResponse:
        raise NotImplementedError

    @handler("ListDomainNames")
    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType | None = None, **kwargs
    ) -> ListDomainNamesResponse:
        raise NotImplementedError

    @handler("ListDomainsForPackage")
    def list_domains_for_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDomainsForPackageResponse:
        raise NotImplementedError

    @handler("ListElasticsearchInstanceTypes")
    def list_elasticsearch_instance_types(
        self,
        context: RequestContext,
        elasticsearch_version: ElasticsearchVersionString,
        domain_name: DomainName | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListElasticsearchInstanceTypesResponse:
        raise NotImplementedError

    @handler("ListElasticsearchVersions")
    def list_elasticsearch_versions(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListElasticsearchVersionsResponse:
        raise NotImplementedError

    @handler("ListPackagesForDomain")
    def list_packages_for_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListPackagesForDomainResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, arn: ARN, **kwargs) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListVpcEndpointAccess")
    def list_vpc_endpoint_access(
        self,
        context: RequestContext,
        domain_name: DomainName,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("ListVpcEndpoints")
    def list_vpc_endpoints(
        self, context: RequestContext, next_token: NextToken | None = None, **kwargs
    ) -> ListVpcEndpointsResponse:
        raise NotImplementedError

    @handler("ListVpcEndpointsForDomain")
    def list_vpc_endpoints_for_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListVpcEndpointsForDomainResponse:
        raise NotImplementedError

    @handler("PurchaseReservedElasticsearchInstanceOffering")
    def purchase_reserved_elasticsearch_instance_offering(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount | None = None,
        **kwargs,
    ) -> PurchaseReservedElasticsearchInstanceOfferingResponse:
        raise NotImplementedError

    @handler("RejectInboundCrossClusterSearchConnection")
    def reject_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
        **kwargs,
    ) -> RejectInboundCrossClusterSearchConnectionResponse:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(
        self, context: RequestContext, arn: ARN, tag_keys: StringList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RevokeVpcEndpointAccess")
    def revoke_vpc_endpoint_access(
        self, context: RequestContext, domain_name: DomainName, account: AWSAccount, **kwargs
    ) -> RevokeVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("StartElasticsearchServiceSoftwareUpdate")
    def start_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> StartElasticsearchServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("UpdateElasticsearchDomainConfig")
    def update_elasticsearch_domain_config(
        self,
        context: RequestContext,
        domain_name: DomainName,
        elasticsearch_cluster_config: ElasticsearchClusterConfig | None = None,
        ebs_options: EBSOptions | None = None,
        snapshot_options: SnapshotOptions | None = None,
        vpc_options: VPCOptions | None = None,
        cognito_options: CognitoOptions | None = None,
        advanced_options: AdvancedOptions | None = None,
        access_policies: PolicyDocument | None = None,
        log_publishing_options: LogPublishingOptions | None = None,
        domain_endpoint_options: DomainEndpointOptions | None = None,
        advanced_security_options: AdvancedSecurityOptionsInput | None = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions | None = None,
        encryption_at_rest_options: EncryptionAtRestOptions | None = None,
        auto_tune_options: AutoTuneOptions | None = None,
        dry_run: DryRun | None = None,
        **kwargs,
    ) -> UpdateElasticsearchDomainConfigResponse:
        raise NotImplementedError

    @handler("UpdatePackage")
    def update_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        package_source: PackageSource,
        package_description: PackageDescription | None = None,
        commit_message: CommitMessage | None = None,
        **kwargs,
    ) -> UpdatePackageResponse:
        raise NotImplementedError

    @handler("UpdateVpcEndpoint")
    def update_vpc_endpoint(
        self,
        context: RequestContext,
        vpc_endpoint_id: VpcEndpointId,
        vpc_options: VPCOptions,
        **kwargs,
    ) -> UpdateVpcEndpointResponse:
        raise NotImplementedError

    @handler("UpgradeElasticsearchDomain")
    def upgrade_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        target_version: ElasticsearchVersionString,
        perform_check_only: Boolean | None = None,
        **kwargs,
    ) -> UpgradeElasticsearchDomainResponse:
        raise NotImplementedError
