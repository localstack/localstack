from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
AWSAccount = str
AppConfigValue = str
ApplicationName = str
AvailabilityZone = str
BackendRole = str
Boolean = bool
ChangeProgressStageName = str
ChangeProgressStageStatus = str
ClientToken = str
CloudWatchLogsLogGroupArn = str
CommitMessage = str
ConnectionAlias = str
ConnectionId = str
ConnectionStatusMessage = str
DataSourceDescription = str
DataSourceName = str
DeploymentType = str
DescribePackagesFilterValue = str
Description = str
DirectQueryDataSourceDescription = str
DirectQueryDataSourceName = str
DirectQueryDataSourceRoleArn = str
DomainArn = str
DomainId = str
DomainName = str
DomainNameFqdn = str
Double = float
DryRun = bool
Endpoint = str
EngineVersion = str
ErrorMessage = str
ErrorType = str
GUID = str
HostedZoneId = str
IAMFederationRolesKey = str
IAMFederationSubjectKey = str
Id = str
IdentityCenterApplicationARN = str
IdentityCenterInstanceARN = str
IdentityPoolId = str
IdentityStoreId = str
IndexName = str
InstanceCount = int
InstanceRole = str
InstanceTypeString = str
Integer = int
IntegerClass = int
Issue = str
KmsKeyArn = str
KmsKeyId = str
LicenseFilepath = str
LimitName = str
LimitValue = str
MaintenanceStatusMessage = str
MaxResults = int
MaximumInstanceCount = int
Message = str
MinimumInstanceCount = int
NextToken = str
NodeId = str
NonEmptyString = str
NumberOfAZs = str
NumberOfNodes = str
NumberOfShards = str
OwnerId = str
PackageDescription = str
PackageID = str
PackageName = str
PackageOwner = str
PackageUser = str
PackageVersion = str
Password = str
PluginClassName = str
PluginDescription = str
PluginName = str
PluginVersion = str
PolicyDocument = str
ReferencePath = str
Region = str
RequestId = str
ReservationToken = str
RoleArn = str
RolesKey = str
S3BucketName = str
S3Key = str
SAMLEntityId = str
SAMLMetadata = str
ScheduledAutoTuneDescription = str
ServiceUrl = str
StorageSubTypeName = str
StorageTypeName = str
String = str
SubjectKey = str
TagKey = str
TagValue = str
TotalNumberOfStages = int
UIntValue = int
UpgradeName = str
UserPoolId = str
Username = str
VersionString = str
VolumeSize = str
VpcEndpointId = str


class AWSServicePrincipal(StrEnum):
    application_opensearchservice_amazonaws_com = "application.opensearchservice.amazonaws.com"


class ActionSeverity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ActionStatus(StrEnum):
    PENDING_UPDATE = "PENDING_UPDATE"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    ELIGIBLE = "ELIGIBLE"


class ActionType(StrEnum):
    SERVICE_SOFTWARE_UPDATE = "SERVICE_SOFTWARE_UPDATE"
    JVM_HEAP_SIZE_TUNING = "JVM_HEAP_SIZE_TUNING"
    JVM_YOUNG_GEN_TUNING = "JVM_YOUNG_GEN_TUNING"


class AppConfigType(StrEnum):
    opensearchDashboards_dashboardAdmin_users = "opensearchDashboards.dashboardAdmin.users"
    opensearchDashboards_dashboardAdmin_groups = "opensearchDashboards.dashboardAdmin.groups"


class ApplicationStatus(StrEnum):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


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


class ConnectionMode(StrEnum):
    DIRECT = "DIRECT"
    VPC_ENDPOINT = "VPC_ENDPOINT"


class DataSourceStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


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
    PackageType = "PackageType"
    EngineVersion = "EngineVersion"
    PackageOwner = "PackageOwner"


class DomainHealth(StrEnum):
    Red = "Red"
    Yellow = "Yellow"
    Green = "Green"
    NotAvailable = "NotAvailable"


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


class DomainState(StrEnum):
    Active = "Active"
    Processing = "Processing"
    NotAvailable = "NotAvailable"


class DryRunMode(StrEnum):
    Basic = "Basic"
    Verbose = "Verbose"


class EngineType(StrEnum):
    OpenSearch = "OpenSearch"
    Elasticsearch = "Elasticsearch"


class IPAddressType(StrEnum):
    ipv4 = "ipv4"
    dualstack = "dualstack"


class InboundConnectionStatusCode(StrEnum):
    PENDING_ACCEPTANCE = "PENDING_ACCEPTANCE"
    APPROVED = "APPROVED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    REJECTING = "REJECTING"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class IndexStatus(StrEnum):
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    DELETED = "DELETED"


class InitiatedBy(StrEnum):
    CUSTOMER = "CUSTOMER"
    SERVICE = "SERVICE"


class LogType(StrEnum):
    INDEX_SLOW_LOGS = "INDEX_SLOW_LOGS"
    SEARCH_SLOW_LOGS = "SEARCH_SLOW_LOGS"
    ES_APPLICATION_LOGS = "ES_APPLICATION_LOGS"
    AUDIT_LOGS = "AUDIT_LOGS"


class MaintenanceStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class MaintenanceType(StrEnum):
    REBOOT_NODE = "REBOOT_NODE"
    RESTART_SEARCH_PROCESS = "RESTART_SEARCH_PROCESS"
    RESTART_DASHBOARD = "RESTART_DASHBOARD"


class MasterNodeStatus(StrEnum):
    Available = "Available"
    UnAvailable = "UnAvailable"


class NaturalLanguageQueryGenerationCurrentState(StrEnum):
    NOT_ENABLED = "NOT_ENABLED"
    ENABLE_COMPLETE = "ENABLE_COMPLETE"
    ENABLE_IN_PROGRESS = "ENABLE_IN_PROGRESS"
    ENABLE_FAILED = "ENABLE_FAILED"
    DISABLE_COMPLETE = "DISABLE_COMPLETE"
    DISABLE_IN_PROGRESS = "DISABLE_IN_PROGRESS"
    DISABLE_FAILED = "DISABLE_FAILED"


class NaturalLanguageQueryGenerationDesiredState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class NodeOptionsNodeType(StrEnum):
    coordinator = "coordinator"


class NodeStatus(StrEnum):
    Active = "Active"
    StandBy = "StandBy"
    NotAvailable = "NotAvailable"


class NodeType(StrEnum):
    Data = "Data"
    Ultrawarm = "Ultrawarm"
    Master = "Master"
    Warm = "Warm"


class OpenSearchPartitionInstanceType(StrEnum):
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
    or1_medium_search = "or1.medium.search"
    or1_large_search = "or1.large.search"
    or1_xlarge_search = "or1.xlarge.search"
    or1_2xlarge_search = "or1.2xlarge.search"
    or1_4xlarge_search = "or1.4xlarge.search"
    or1_8xlarge_search = "or1.8xlarge.search"
    or1_12xlarge_search = "or1.12xlarge.search"
    or1_16xlarge_search = "or1.16xlarge.search"
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


class OpenSearchWarmPartitionInstanceType(StrEnum):
    ultrawarm1_medium_search = "ultrawarm1.medium.search"
    ultrawarm1_large_search = "ultrawarm1.large.search"
    ultrawarm1_xlarge_search = "ultrawarm1.xlarge.search"


class OptionState(StrEnum):
    RequiresIndexDocuments = "RequiresIndexDocuments"
    Processing = "Processing"
    Active = "Active"


class OutboundConnectionStatusCode(StrEnum):
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


class OverallChangeStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PackageScopeOperationEnum(StrEnum):
    ADD = "ADD"
    OVERRIDE = "OVERRIDE"
    REMOVE = "REMOVE"


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
    ZIP_PLUGIN = "ZIP-PLUGIN"
    PACKAGE_LICENSE = "PACKAGE-LICENSE"
    PACKAGE_CONFIG = "PACKAGE-CONFIG"


class PrincipalType(StrEnum):
    AWS_ACCOUNT = "AWS_ACCOUNT"
    AWS_SERVICE = "AWS_SERVICE"


class PropertyValueType(StrEnum):
    PLAIN_TEXT = "PLAIN_TEXT"
    STRINGIFIED_JSON = "STRINGIFIED_JSON"


class RequirementLevel(StrEnum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    NONE = "NONE"


class ReservedInstancePaymentOption(StrEnum):
    ALL_UPFRONT = "ALL_UPFRONT"
    PARTIAL_UPFRONT = "PARTIAL_UPFRONT"
    NO_UPFRONT = "NO_UPFRONT"


class RolesKeyIdCOption(StrEnum):
    GroupName = "GroupName"
    GroupId = "GroupId"


class RollbackOnDisable(StrEnum):
    NO_ROLLBACK = "NO_ROLLBACK"
    DEFAULT_ROLLBACK = "DEFAULT_ROLLBACK"


class ScheduleAt(StrEnum):
    NOW = "NOW"
    TIMESTAMP = "TIMESTAMP"
    OFF_PEAK_WINDOW = "OFF_PEAK_WINDOW"


class ScheduledAutoTuneActionType(StrEnum):
    JVM_HEAP_SIZE_TUNING = "JVM_HEAP_SIZE_TUNING"
    JVM_YOUNG_GEN_TUNING = "JVM_YOUNG_GEN_TUNING"


class ScheduledAutoTuneSeverityType(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScheduledBy(StrEnum):
    CUSTOMER = "CUSTOMER"
    SYSTEM = "SYSTEM"


class SkipUnavailableStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class SubjectKeyIdCOption(StrEnum):
    UserName = "UserName"
    UserId = "UserId"
    Email = "Email"


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


class ZoneStatus(StrEnum):
    Active = "Active"
    StandBy = "StandBy"
    NotAvailable = "NotAvailable"


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


class DependencyFailureException(ServiceException):
    code: str = "DependencyFailureException"
    sender_fault: bool = False
    status_code: int = 424


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


Long = int
SlotList = list[Long]


class SlotNotAvailableException(ServiceException):
    code: str = "SlotNotAvailableException"
    sender_fault: bool = False
    status_code: int = 409
    SlotSuggestions: SlotList | None


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 429


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


class ServerlessVectorAcceleration(TypedDict, total=False):
    Enabled: Boolean | None


class S3VectorsEngine(TypedDict, total=False):
    Enabled: Boolean | None


class NaturalLanguageQueryGenerationOptionsInput(TypedDict, total=False):
    DesiredState: NaturalLanguageQueryGenerationDesiredState | None


class AIMLOptionsInput(TypedDict, total=False):
    NaturalLanguageQueryGenerationOptions: NaturalLanguageQueryGenerationOptionsInput | None
    S3VectorsEngine: S3VectorsEngine | None
    ServerlessVectorAcceleration: ServerlessVectorAcceleration | None


class NaturalLanguageQueryGenerationOptionsOutput(TypedDict, total=False):
    DesiredState: NaturalLanguageQueryGenerationDesiredState | None
    CurrentState: NaturalLanguageQueryGenerationCurrentState | None


class AIMLOptionsOutput(TypedDict, total=False):
    NaturalLanguageQueryGenerationOptions: NaturalLanguageQueryGenerationOptionsOutput | None
    S3VectorsEngine: S3VectorsEngine | None
    ServerlessVectorAcceleration: ServerlessVectorAcceleration | None


UpdateTimestamp = datetime


class OptionStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: UIntValue | None
    State: OptionState
    PendingDeletion: Boolean | None


class AIMLOptionsStatus(TypedDict, total=False):
    Options: AIMLOptionsOutput | None
    Status: OptionStatus | None


class AWSDomainInformation(TypedDict, total=False):
    OwnerId: OwnerId | None
    DomainName: DomainName
    Region: Region | None


class AcceptInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class InboundConnectionStatus(TypedDict, total=False):
    StatusCode: InboundConnectionStatusCode | None
    Message: ConnectionStatusMessage | None


class DomainInformationContainer(TypedDict, total=False):
    AWSDomainInformation: AWSDomainInformation | None


class InboundConnection(TypedDict, total=False):
    LocalDomainInfo: DomainInformationContainer | None
    RemoteDomainInfo: DomainInformationContainer | None
    ConnectionId: ConnectionId | None
    ConnectionStatus: InboundConnectionStatus | None
    ConnectionMode: ConnectionMode | None


class AcceptInboundConnectionResponse(TypedDict, total=False):
    Connection: InboundConnection | None


class AccessPoliciesStatus(TypedDict, total=False):
    Options: PolicyDocument
    Status: OptionStatus


class S3GlueDataCatalog(TypedDict, total=False):
    RoleArn: RoleArn | None


class DataSourceType(TypedDict, total=False):
    S3GlueDataCatalog: S3GlueDataCatalog | None


class AddDataSourceRequest(ServiceRequest):
    DomainName: DomainName
    Name: DataSourceName
    DataSourceType: DataSourceType
    Description: DataSourceDescription | None


class AddDataSourceResponse(TypedDict, total=False):
    Message: String | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]
DirectQueryOpenSearchARNList = list[ARN]


class SecurityLakeDirectQueryDataSource(TypedDict, total=False):
    RoleArn: DirectQueryDataSourceRoleArn


class CloudWatchDirectQueryDataSource(TypedDict, total=False):
    RoleArn: DirectQueryDataSourceRoleArn


class DirectQueryDataSourceType(TypedDict, total=False):
    CloudWatchLog: CloudWatchDirectQueryDataSource | None
    SecurityLake: SecurityLakeDirectQueryDataSource | None


class AddDirectQueryDataSourceRequest(ServiceRequest):
    DataSourceName: DirectQueryDataSourceName
    DataSourceType: DirectQueryDataSourceType
    Description: DirectQueryDataSourceDescription | None
    OpenSearchArns: DirectQueryOpenSearchARNList
    TagList: TagList | None


class AddDirectQueryDataSourceResponse(TypedDict, total=False):
    DataSourceArn: String | None


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


class IAMFederationOptionsOutput(TypedDict, total=False):
    Enabled: Boolean | None
    SubjectKey: IAMFederationSubjectKey | None
    RolesKey: IAMFederationRolesKey | None


class JWTOptionsOutput(TypedDict, total=False):
    Enabled: Boolean | None
    SubjectKey: String | None
    RolesKey: String | None
    PublicKey: String | None


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
    JWTOptions: JWTOptionsOutput | None
    IAMFederationOptions: IAMFederationOptionsOutput | None
    AnonymousAuthDisableDate: DisableTimestamp | None
    AnonymousAuthEnabled: Boolean | None


class IAMFederationOptionsInput(TypedDict, total=False):
    Enabled: Boolean | None
    SubjectKey: IAMFederationSubjectKey | None
    RolesKey: IAMFederationRolesKey | None


class JWTOptionsInput(TypedDict, total=False):
    Enabled: Boolean | None
    SubjectKey: SubjectKey | None
    RolesKey: RolesKey | None
    PublicKey: String | None


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
    JWTOptions: JWTOptionsInput | None
    IAMFederationOptions: IAMFederationOptionsInput | None
    AnonymousAuthEnabled: Boolean | None


class AdvancedSecurityOptionsStatus(TypedDict, total=False):
    Options: AdvancedSecurityOptions
    Status: OptionStatus


class AppConfig(TypedDict, total=False):
    key: AppConfigType | None
    value: AppConfigValue | None


AppConfigs = list[AppConfig]
ApplicationStatuses = list[ApplicationStatus]
Timestamp = datetime


class ApplicationSummary(TypedDict, total=False):
    id: Id | None
    arn: ARN | None
    name: ApplicationName | None
    endpoint: String | None
    status: ApplicationStatus | None
    createdAt: Timestamp | None
    lastUpdatedAt: Timestamp | None


ApplicationSummaries = list[ApplicationSummary]


class KeyStoreAccessOption(TypedDict, total=False):
    KeyAccessRoleArn: RoleArn | None
    KeyStoreAccessEnabled: Boolean


class PackageAssociationConfiguration(TypedDict, total=False):
    KeyStoreAccessOption: KeyStoreAccessOption | None


PackageIDList = list[PackageID]


class AssociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName
    PrerequisitePackageIDList: PackageIDList | None
    AssociationConfiguration: PackageAssociationConfiguration | None


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
    PrerequisitePackageIDList: PackageIDList | None
    ReferencePath: ReferencePath | None
    ErrorDetails: ErrorDetails | None
    AssociationConfiguration: PackageAssociationConfiguration | None


class AssociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: DomainPackageDetails | None


class PackageDetailsForAssociation(TypedDict, total=False):
    PackageID: PackageID
    PrerequisitePackageIDList: PackageIDList | None
    AssociationConfiguration: PackageAssociationConfiguration | None


PackageDetailsForAssociationList = list[PackageDetailsForAssociation]


class AssociatePackagesRequest(ServiceRequest):
    PackageList: PackageDetailsForAssociationList
    DomainName: DomainName


DomainPackageDetailsList = list[DomainPackageDetails]


class AssociatePackagesResponse(TypedDict, total=False):
    DomainPackageDetailsList: DomainPackageDetailsList | None


class AuthorizeVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    Account: AWSAccount | None
    Service: AWSServicePrincipal | None


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
    UseOffPeakWindow: Boolean | None


class AutoTuneOptionsInput(TypedDict, total=False):
    DesiredState: AutoTuneDesiredState | None
    MaintenanceSchedules: AutoTuneMaintenanceScheduleList | None
    UseOffPeakWindow: Boolean | None


class AutoTuneOptionsOutput(TypedDict, total=False):
    State: AutoTuneState | None
    ErrorMessage: String | None
    UseOffPeakWindow: Boolean | None


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


class AvailabilityZoneInfo(TypedDict, total=False):
    AvailabilityZoneName: AvailabilityZone | None
    ZoneStatus: ZoneStatus | None
    ConfiguredDataNodeCount: NumberOfNodes | None
    AvailableDataNodeCount: NumberOfNodes | None
    TotalShards: NumberOfShards | None
    TotalUnAssignedShards: NumberOfShards | None


AvailabilityZoneInfoList = list[AvailabilityZoneInfo]
AvailabilityZoneList = list[AvailabilityZone]


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
    CancelledChangeIds: GUIDList | None
    CancelledChangeProperties: CancelledChangePropertyList | None
    DryRun: DryRun | None


class CancelServiceSoftwareUpdateRequest(ServiceRequest):
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


class CancelServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: ServiceSoftwareOptions | None


class ChangeProgressDetails(TypedDict, total=False):
    ChangeId: GUID | None
    Message: Message | None
    ConfigChangeStatus: ConfigChangeStatus | None
    InitiatedBy: InitiatedBy | None
    StartTime: UpdateTimestamp | None
    LastUpdatedTime: UpdateTimestamp | None


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
    LastUpdatedTime: UpdateTimestamp | None
    ConfigChangeStatus: ConfigChangeStatus | None
    InitiatedBy: InitiatedBy | None


class NodeConfig(TypedDict, total=False):
    Enabled: Boolean | None
    Type: OpenSearchPartitionInstanceType | None
    Count: IntegerClass | None


class NodeOption(TypedDict, total=False):
    NodeType: NodeOptionsNodeType | None
    NodeConfig: NodeConfig | None


NodeOptionsList = list[NodeOption]


class ColdStorageOptions(TypedDict, total=False):
    Enabled: Boolean


class ZoneAwarenessConfig(TypedDict, total=False):
    AvailabilityZoneCount: IntegerClass | None


class ClusterConfig(TypedDict, total=False):
    InstanceType: OpenSearchPartitionInstanceType | None
    InstanceCount: IntegerClass | None
    DedicatedMasterEnabled: Boolean | None
    ZoneAwarenessEnabled: Boolean | None
    ZoneAwarenessConfig: ZoneAwarenessConfig | None
    DedicatedMasterType: OpenSearchPartitionInstanceType | None
    DedicatedMasterCount: IntegerClass | None
    WarmEnabled: Boolean | None
    WarmType: OpenSearchWarmPartitionInstanceType | None
    WarmCount: IntegerClass | None
    ColdStorageOptions: ColdStorageOptions | None
    MultiAZWithStandbyEnabled: Boolean | None
    NodeOptions: NodeOptionsList | None


class ClusterConfigStatus(TypedDict, total=False):
    Options: ClusterConfig
    Status: OptionStatus


class CognitoOptions(TypedDict, total=False):
    Enabled: Boolean | None
    UserPoolId: UserPoolId | None
    IdentityPoolId: IdentityPoolId | None
    RoleArn: RoleArn | None


class CognitoOptionsStatus(TypedDict, total=False):
    Options: CognitoOptions
    Status: OptionStatus


VersionList = list[VersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    SourceVersion: VersionString | None
    TargetVersions: VersionList | None


CompatibleVersionsList = list[CompatibleVersionsMap]


class CrossClusterSearchConnectionProperties(TypedDict, total=False):
    SkipUnavailable: SkipUnavailableStatus | None


class ConnectionProperties(TypedDict, total=False):
    Endpoint: Endpoint | None
    CrossClusterSearch: CrossClusterSearchConnectionProperties | None


class IamIdentityCenterOptionsInput(TypedDict, total=False):
    enabled: Boolean | None
    iamIdentityCenterInstanceArn: ARN | None
    iamRoleForIdentityCenterApplicationArn: RoleArn | None


class DataSource(TypedDict, total=False):
    dataSourceArn: ARN | None
    dataSourceDescription: DataSourceDescription | None


DataSources = list[DataSource]


class CreateApplicationRequest(ServiceRequest):
    clientToken: ClientToken | None
    name: ApplicationName
    dataSources: DataSources | None
    iamIdentityCenterOptions: IamIdentityCenterOptionsInput | None
    appConfigs: AppConfigs | None
    tagList: TagList | None
    kmsKeyArn: KmsKeyArn | None


class IamIdentityCenterOptions(TypedDict, total=False):
    enabled: Boolean | None
    iamIdentityCenterInstanceArn: ARN | None
    iamRoleForIdentityCenterApplicationArn: RoleArn | None
    iamIdentityCenterApplicationArn: ARN | None


class CreateApplicationResponse(TypedDict, total=False):
    id: Id | None
    name: ApplicationName | None
    arn: ARN | None
    dataSources: DataSources | None
    iamIdentityCenterOptions: IamIdentityCenterOptions | None
    appConfigs: AppConfigs | None
    tagList: TagList | None
    createdAt: Timestamp | None
    kmsKeyArn: KmsKeyArn | None


class SoftwareUpdateOptions(TypedDict, total=False):
    AutoSoftwareUpdateEnabled: Boolean | None


StartTimeMinutes = int
StartTimeHours = int


class WindowStartTime(TypedDict, total=False):
    Hours: StartTimeHours
    Minutes: StartTimeMinutes


class OffPeakWindow(TypedDict, total=False):
    WindowStartTime: WindowStartTime | None


class OffPeakWindowOptions(TypedDict, total=False):
    Enabled: Boolean | None
    OffPeakWindow: OffPeakWindow | None


class IdentityCenterOptionsInput(TypedDict, total=False):
    EnabledAPIAccess: Boolean | None
    IdentityCenterInstanceARN: IdentityCenterInstanceARN | None
    SubjectKey: SubjectKeyIdCOption | None
    RolesKey: RolesKeyIdCOption | None


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


class CreateDomainRequest(ServiceRequest):
    DomainName: DomainName
    EngineVersion: VersionString | None
    ClusterConfig: ClusterConfig | None
    EBSOptions: EBSOptions | None
    AccessPolicies: PolicyDocument | None
    IPAddressType: IPAddressType | None
    SnapshotOptions: SnapshotOptions | None
    VPCOptions: VPCOptions | None
    CognitoOptions: CognitoOptions | None
    EncryptionAtRestOptions: EncryptionAtRestOptions | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptions | None
    AdvancedOptions: AdvancedOptions | None
    LogPublishingOptions: LogPublishingOptions | None
    DomainEndpointOptions: DomainEndpointOptions | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsInput | None
    IdentityCenterOptions: IdentityCenterOptionsInput | None
    TagList: TagList | None
    AutoTuneOptions: AutoTuneOptionsInput | None
    OffPeakWindowOptions: OffPeakWindowOptions | None
    SoftwareUpdateOptions: SoftwareUpdateOptions | None
    AIMLOptions: AIMLOptionsInput | None


class ModifyingProperties(TypedDict, total=False):
    Name: String | None
    ActiveValue: String | None
    PendingValue: String | None
    ValueType: PropertyValueType | None


ModifyingPropertiesList = list[ModifyingProperties]


class IdentityCenterOptions(TypedDict, total=False):
    EnabledAPIAccess: Boolean | None
    IdentityCenterInstanceARN: IdentityCenterInstanceARN | None
    SubjectKey: SubjectKeyIdCOption | None
    RolesKey: RolesKeyIdCOption | None
    IdentityCenterApplicationARN: IdentityCenterApplicationARN | None
    IdentityStoreId: IdentityStoreId | None


class VPCDerivedInfo(TypedDict, total=False):
    VPCId: String | None
    SubnetIds: StringList | None
    AvailabilityZones: StringList | None
    SecurityGroupIds: StringList | None


EndpointsMap = dict[String, ServiceUrl]


class DomainStatus(TypedDict, total=False):
    DomainId: DomainId
    DomainName: DomainName
    ARN: ARN
    Created: Boolean | None
    Deleted: Boolean | None
    Endpoint: ServiceUrl | None
    EndpointV2: ServiceUrl | None
    Endpoints: EndpointsMap | None
    DomainEndpointV2HostedZoneId: HostedZoneId | None
    Processing: Boolean | None
    UpgradeProcessing: Boolean | None
    EngineVersion: VersionString | None
    ClusterConfig: ClusterConfig
    EBSOptions: EBSOptions | None
    AccessPolicies: PolicyDocument | None
    IPAddressType: IPAddressType | None
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
    IdentityCenterOptions: IdentityCenterOptions | None
    AutoTuneOptions: AutoTuneOptionsOutput | None
    ChangeProgressDetails: ChangeProgressDetails | None
    OffPeakWindowOptions: OffPeakWindowOptions | None
    SoftwareUpdateOptions: SoftwareUpdateOptions | None
    DomainProcessingStatus: DomainProcessingStatusType | None
    ModifyingProperties: ModifyingPropertiesList | None
    AIMLOptions: AIMLOptionsOutput | None


class CreateDomainResponse(TypedDict, total=False):
    DomainStatus: DomainStatus | None


class IndexSchema(TypedDict, total=False):
    pass


class CreateIndexRequest(ServiceRequest):
    DomainName: DomainName
    IndexName: IndexName
    IndexSchema: IndexSchema


class CreateIndexResponse(TypedDict, total=False):
    Status: IndexStatus


class CreateOutboundConnectionRequest(ServiceRequest):
    LocalDomainInfo: DomainInformationContainer
    RemoteDomainInfo: DomainInformationContainer
    ConnectionAlias: ConnectionAlias
    ConnectionMode: ConnectionMode | None
    ConnectionProperties: ConnectionProperties | None


class OutboundConnectionStatus(TypedDict, total=False):
    StatusCode: OutboundConnectionStatusCode | None
    Message: ConnectionStatusMessage | None


class CreateOutboundConnectionResponse(TypedDict, total=False):
    LocalDomainInfo: DomainInformationContainer | None
    RemoteDomainInfo: DomainInformationContainer | None
    ConnectionAlias: ConnectionAlias | None
    ConnectionStatus: OutboundConnectionStatus | None
    ConnectionId: ConnectionId | None
    ConnectionMode: ConnectionMode | None
    ConnectionProperties: ConnectionProperties | None


class PackageEncryptionOptions(TypedDict, total=False):
    KmsKeyIdentifier: KmsKeyId | None
    EncryptionEnabled: Boolean


class PackageVendingOptions(TypedDict, total=False):
    VendingEnabled: Boolean


class PackageConfiguration(TypedDict, total=False):
    LicenseRequirement: RequirementLevel
    LicenseFilepath: LicenseFilepath | None
    ConfigurationRequirement: RequirementLevel
    RequiresRestartForConfigurationUpdate: Boolean | None


class PackageSource(TypedDict, total=False):
    S3BucketName: S3BucketName | None
    S3Key: S3Key | None


class CreatePackageRequest(ServiceRequest):
    PackageName: PackageName
    PackageType: PackageType
    PackageDescription: PackageDescription | None
    PackageSource: PackageSource
    PackageConfiguration: PackageConfiguration | None
    EngineVersion: EngineVersion | None
    PackageVendingOptions: PackageVendingOptions | None
    PackageEncryptionOptions: PackageEncryptionOptions | None


PackageUserList = list[PackageUser]
UncompressedPluginSizeInBytes = int


class PluginProperties(TypedDict, total=False):
    Name: PluginName | None
    Description: PluginDescription | None
    Version: PluginVersion | None
    ClassName: PluginClassName | None
    UncompressedSizeInBytes: UncompressedPluginSizeInBytes | None


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
    EngineVersion: EngineVersion | None
    AvailablePluginProperties: PluginProperties | None
    AvailablePackageConfiguration: PackageConfiguration | None
    AllowListedUserList: PackageUserList | None
    PackageOwner: PackageOwner | None
    PackageVendingOptions: PackageVendingOptions | None
    PackageEncryptionOptions: PackageEncryptionOptions | None


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


class DataSourceDetails(TypedDict, total=False):
    DataSourceType: DataSourceType | None
    Name: DataSourceName | None
    Description: DataSourceDescription | None
    Status: DataSourceStatus | None


DataSourceList = list[DataSourceDetails]


class DeleteApplicationRequest(ServiceRequest):
    id: Id


class DeleteApplicationResponse(TypedDict, total=False):
    pass


class DeleteDataSourceRequest(ServiceRequest):
    DomainName: DomainName
    Name: DataSourceName


class DeleteDataSourceResponse(TypedDict, total=False):
    Message: String | None


class DeleteDirectQueryDataSourceRequest(ServiceRequest):
    DataSourceName: DirectQueryDataSourceName


class DeleteDomainRequest(ServiceRequest):
    DomainName: DomainName


class DeleteDomainResponse(TypedDict, total=False):
    DomainStatus: DomainStatus | None


class DeleteInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class DeleteInboundConnectionResponse(TypedDict, total=False):
    Connection: InboundConnection | None


class DeleteIndexRequest(ServiceRequest):
    DomainName: DomainName
    IndexName: IndexName


class DeleteIndexResponse(TypedDict, total=False):
    Status: IndexStatus


class DeleteOutboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class OutboundConnection(TypedDict, total=False):
    LocalDomainInfo: DomainInformationContainer | None
    RemoteDomainInfo: DomainInformationContainer | None
    ConnectionId: ConnectionId | None
    ConnectionAlias: ConnectionAlias | None
    ConnectionStatus: OutboundConnectionStatus | None
    ConnectionMode: ConnectionMode | None
    ConnectionProperties: ConnectionProperties | None


class DeleteOutboundConnectionResponse(TypedDict, total=False):
    Connection: OutboundConnection | None


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


class DescribeDomainConfigRequest(ServiceRequest):
    DomainName: DomainName


class SoftwareUpdateOptionsStatus(TypedDict, total=False):
    Options: SoftwareUpdateOptions | None
    Status: OptionStatus | None


class OffPeakWindowOptionsStatus(TypedDict, total=False):
    Options: OffPeakWindowOptions | None
    Status: OptionStatus | None


class IdentityCenterOptionsStatus(TypedDict, total=False):
    Options: IdentityCenterOptions
    Status: OptionStatus


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


class IPAddressTypeStatus(TypedDict, total=False):
    Options: IPAddressType
    Status: OptionStatus


class EBSOptionsStatus(TypedDict, total=False):
    Options: EBSOptions
    Status: OptionStatus


class VersionStatus(TypedDict, total=False):
    Options: VersionString
    Status: OptionStatus


class DomainConfig(TypedDict, total=False):
    EngineVersion: VersionStatus | None
    ClusterConfig: ClusterConfigStatus | None
    EBSOptions: EBSOptionsStatus | None
    AccessPolicies: AccessPoliciesStatus | None
    IPAddressType: IPAddressTypeStatus | None
    SnapshotOptions: SnapshotOptionsStatus | None
    VPCOptions: VPCDerivedInfoStatus | None
    CognitoOptions: CognitoOptionsStatus | None
    EncryptionAtRestOptions: EncryptionAtRestOptionsStatus | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptionsStatus | None
    AdvancedOptions: AdvancedOptionsStatus | None
    LogPublishingOptions: LogPublishingOptionsStatus | None
    DomainEndpointOptions: DomainEndpointOptionsStatus | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsStatus | None
    IdentityCenterOptions: IdentityCenterOptionsStatus | None
    AutoTuneOptions: AutoTuneOptionsStatus | None
    ChangeProgressDetails: ChangeProgressDetails | None
    OffPeakWindowOptions: OffPeakWindowOptionsStatus | None
    SoftwareUpdateOptions: SoftwareUpdateOptionsStatus | None
    ModifyingProperties: ModifyingPropertiesList | None
    AIMLOptions: AIMLOptionsStatus | None


class DescribeDomainConfigResponse(TypedDict, total=False):
    DomainConfig: DomainConfig


class DescribeDomainHealthRequest(ServiceRequest):
    DomainName: DomainName


class EnvironmentInfo(TypedDict, total=False):
    AvailabilityZoneInformation: AvailabilityZoneInfoList | None


EnvironmentInfoList = list[EnvironmentInfo]


class DescribeDomainHealthResponse(TypedDict, total=False):
    DomainState: DomainState | None
    AvailabilityZoneCount: NumberOfAZs | None
    ActiveAvailabilityZoneCount: NumberOfAZs | None
    StandByAvailabilityZoneCount: NumberOfAZs | None
    DataNodeCount: NumberOfNodes | None
    DedicatedMaster: Boolean | None
    MasterEligibleNodeCount: NumberOfNodes | None
    WarmNodeCount: NumberOfNodes | None
    MasterNode: MasterNodeStatus | None
    ClusterHealth: DomainHealth | None
    TotalShards: NumberOfShards | None
    TotalUnAssignedShards: NumberOfShards | None
    EnvironmentInformation: EnvironmentInfoList | None


class DescribeDomainNodesRequest(ServiceRequest):
    DomainName: DomainName


class DomainNodesStatus(TypedDict, total=False):
    NodeId: NodeId | None
    NodeType: NodeType | None
    AvailabilityZone: AvailabilityZone | None
    InstanceType: OpenSearchPartitionInstanceType | None
    NodeStatus: NodeStatus | None
    StorageType: StorageTypeName | None
    StorageVolumeType: VolumeType | None
    StorageSize: VolumeSize | None


DomainNodesStatusList = list[DomainNodesStatus]


class DescribeDomainNodesResponse(TypedDict, total=False):
    DomainNodesStatusList: DomainNodesStatusList | None


class DescribeDomainRequest(ServiceRequest):
    DomainName: DomainName


class DescribeDomainResponse(TypedDict, total=False):
    DomainStatus: DomainStatus


DomainNameList = list[DomainName]


class DescribeDomainsRequest(ServiceRequest):
    DomainNames: DomainNameList


DomainStatusList = list[DomainStatus]


class DescribeDomainsResponse(TypedDict, total=False):
    DomainStatusList: DomainStatusList


class DescribeDryRunProgressRequest(ServiceRequest):
    DomainName: DomainName
    DryRunId: GUID | None
    LoadDryRunConfig: Boolean | None


class DryRunResults(TypedDict, total=False):
    DeploymentType: DeploymentType | None
    Message: Message | None


class ValidationFailure(TypedDict, total=False):
    Code: String | None
    Message: String | None


ValidationFailures = list[ValidationFailure]


class DryRunProgressStatus(TypedDict, total=False):
    DryRunId: GUID
    DryRunStatus: String
    CreationDate: String
    UpdateDate: String
    ValidationFailures: ValidationFailures | None


class DescribeDryRunProgressResponse(TypedDict, total=False):
    DryRunProgressStatus: DryRunProgressStatus | None
    DryRunConfig: DomainStatus | None
    DryRunResults: DryRunResults | None


ValueStringList = list[NonEmptyString]


class Filter(TypedDict, total=False):
    Name: NonEmptyString | None
    Values: ValueStringList | None


FilterList = list[Filter]


class DescribeInboundConnectionsRequest(ServiceRequest):
    Filters: FilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


InboundConnections = list[InboundConnection]


class DescribeInboundConnectionsResponse(TypedDict, total=False):
    Connections: InboundConnections | None
    NextToken: NextToken | None


class DescribeInstanceTypeLimitsRequest(ServiceRequest):
    DomainName: DomainName | None
    InstanceType: OpenSearchPartitionInstanceType
    EngineVersion: VersionString


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


class DescribeInstanceTypeLimitsResponse(TypedDict, total=False):
    LimitsByRole: LimitsByRole | None


class DescribeOutboundConnectionsRequest(ServiceRequest):
    Filters: FilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


OutboundConnections = list[OutboundConnection]


class DescribeOutboundConnectionsResponse(TypedDict, total=False):
    Connections: OutboundConnections | None
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


class DescribeReservedInstanceOfferingsRequest(ServiceRequest):
    ReservedInstanceOfferingId: GUID | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Double | None
    RecurringChargeFrequency: String | None


RecurringChargeList = list[RecurringCharge]


class ReservedInstanceOffering(TypedDict, total=False):
    ReservedInstanceOfferingId: GUID | None
    InstanceType: OpenSearchPartitionInstanceType | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    PaymentOption: ReservedInstancePaymentOption | None
    RecurringCharges: RecurringChargeList | None


ReservedInstanceOfferingList = list[ReservedInstanceOffering]


class DescribeReservedInstanceOfferingsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    ReservedInstanceOfferings: ReservedInstanceOfferingList | None


class DescribeReservedInstancesRequest(ServiceRequest):
    ReservedInstanceId: GUID | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ReservedInstance(TypedDict, total=False):
    ReservationName: ReservationToken | None
    ReservedInstanceId: GUID | None
    BillingSubscriptionId: Long | None
    ReservedInstanceOfferingId: String | None
    InstanceType: OpenSearchPartitionInstanceType | None
    StartTime: UpdateTimestamp | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    InstanceCount: Integer | None
    State: String | None
    PaymentOption: ReservedInstancePaymentOption | None
    RecurringCharges: RecurringChargeList | None


ReservedInstanceList = list[ReservedInstance]


class DescribeReservedInstancesResponse(TypedDict, total=False):
    NextToken: String | None
    ReservedInstances: ReservedInstanceList | None


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


class DirectQueryDataSource(TypedDict, total=False):
    DataSourceName: DirectQueryDataSourceName | None
    DataSourceType: DirectQueryDataSourceType | None
    Description: DirectQueryDataSourceDescription | None
    OpenSearchArns: DirectQueryOpenSearchARNList | None
    DataSourceArn: String | None
    TagList: TagList | None


DirectQueryDataSourceList = list[DirectQueryDataSource]


class DissociatePackageRequest(ServiceRequest):
    PackageID: PackageID
    DomainName: DomainName


class DissociatePackageResponse(TypedDict, total=False):
    DomainPackageDetails: DomainPackageDetails | None


class DissociatePackagesRequest(ServiceRequest):
    PackageList: PackageIDList
    DomainName: DomainName


class DissociatePackagesResponse(TypedDict, total=False):
    DomainPackageDetailsList: DomainPackageDetailsList | None


class DomainInfo(TypedDict, total=False):
    DomainName: DomainName | None
    EngineType: EngineType | None


DomainInfoList = list[DomainInfo]


class DomainMaintenanceDetails(TypedDict, total=False):
    MaintenanceId: RequestId | None
    DomainName: DomainName | None
    Action: MaintenanceType | None
    NodeId: NodeId | None
    Status: MaintenanceStatus | None
    StatusMessage: MaintenanceStatusMessage | None
    CreatedAt: UpdateTimestamp | None
    UpdatedAt: UpdateTimestamp | None


DomainMaintenanceList = list[DomainMaintenanceDetails]


class GetApplicationRequest(ServiceRequest):
    id: Id


class GetApplicationResponse(TypedDict, total=False):
    id: Id | None
    arn: ARN | None
    name: ApplicationName | None
    endpoint: String | None
    status: ApplicationStatus | None
    iamIdentityCenterOptions: IamIdentityCenterOptions | None
    dataSources: DataSources | None
    appConfigs: AppConfigs | None
    createdAt: Timestamp | None
    lastUpdatedAt: Timestamp | None
    kmsKeyArn: KmsKeyArn | None


class GetCompatibleVersionsRequest(ServiceRequest):
    DomainName: DomainName | None


class GetCompatibleVersionsResponse(TypedDict, total=False):
    CompatibleVersions: CompatibleVersionsList | None


class GetDataSourceRequest(ServiceRequest):
    DomainName: DomainName
    Name: DataSourceName


class GetDataSourceResponse(TypedDict, total=False):
    DataSourceType: DataSourceType | None
    Name: DataSourceName | None
    Description: DataSourceDescription | None
    Status: DataSourceStatus | None


class GetDefaultApplicationSettingRequest(ServiceRequest):
    pass


class GetDefaultApplicationSettingResponse(TypedDict, total=False):
    applicationArn: ARN | None


class GetDirectQueryDataSourceRequest(ServiceRequest):
    DataSourceName: DirectQueryDataSourceName


class GetDirectQueryDataSourceResponse(TypedDict, total=False):
    DataSourceName: DirectQueryDataSourceName | None
    DataSourceType: DirectQueryDataSourceType | None
    Description: DirectQueryDataSourceDescription | None
    OpenSearchArns: DirectQueryOpenSearchARNList | None
    DataSourceArn: String | None


class GetDomainMaintenanceStatusRequest(ServiceRequest):
    DomainName: DomainName
    MaintenanceId: RequestId


class GetDomainMaintenanceStatusResponse(TypedDict, total=False):
    Status: MaintenanceStatus | None
    StatusMessage: MaintenanceStatusMessage | None
    NodeId: NodeId | None
    Action: MaintenanceType | None
    CreatedAt: UpdateTimestamp | None
    UpdatedAt: UpdateTimestamp | None


class GetIndexRequest(ServiceRequest):
    DomainName: DomainName
    IndexName: IndexName


class GetIndexResponse(TypedDict, total=False):
    IndexSchema: IndexSchema


class GetPackageVersionHistoryRequest(ServiceRequest):
    PackageID: PackageID
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class PackageVersionHistory(TypedDict, total=False):
    PackageVersion: PackageVersion | None
    CommitMessage: CommitMessage | None
    CreatedAt: CreatedAt | None
    PluginProperties: PluginProperties | None
    PackageConfiguration: PackageConfiguration | None


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


InstanceRoleList = list[InstanceRole]


class InstanceTypeDetails(TypedDict, total=False):
    InstanceType: OpenSearchPartitionInstanceType | None
    EncryptionEnabled: Boolean | None
    CognitoEnabled: Boolean | None
    AppLogsEnabled: Boolean | None
    AdvancedSecurityEnabled: Boolean | None
    WarmEnabled: Boolean | None
    InstanceRole: InstanceRoleList | None
    AvailabilityZones: AvailabilityZoneList | None


InstanceTypeDetailsList = list[InstanceTypeDetails]


class ListApplicationsRequest(ServiceRequest):
    nextToken: NextToken | None
    statuses: ApplicationStatuses | None
    maxResults: MaxResults | None


class ListApplicationsResponse(TypedDict, total=False):
    ApplicationSummaries: ApplicationSummaries | None
    nextToken: NextToken | None


class ListDataSourcesRequest(ServiceRequest):
    DomainName: DomainName


class ListDataSourcesResponse(TypedDict, total=False):
    DataSources: DataSourceList | None


class ListDirectQueryDataSourcesRequest(ServiceRequest):
    NextToken: NextToken | None


class ListDirectQueryDataSourcesResponse(TypedDict, total=False):
    NextToken: NextToken | None
    DirectQueryDataSources: DirectQueryDataSourceList | None


class ListDomainMaintenancesRequest(ServiceRequest):
    DomainName: DomainName
    Action: MaintenanceType | None
    Status: MaintenanceStatus | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListDomainMaintenancesResponse(TypedDict, total=False):
    DomainMaintenances: DomainMaintenanceList | None
    NextToken: NextToken | None


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


class ListInstanceTypeDetailsRequest(ServiceRequest):
    EngineVersion: VersionString
    DomainName: DomainName | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    RetrieveAZs: Boolean | None
    InstanceType: InstanceTypeString | None


class ListInstanceTypeDetailsResponse(TypedDict, total=False):
    InstanceTypeDetails: InstanceTypeDetailsList | None
    NextToken: NextToken | None


class ListPackagesForDomainRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListPackagesForDomainResponse(TypedDict, total=False):
    DomainPackageDetailsList: DomainPackageDetailsList | None
    NextToken: String | None


class ListScheduledActionsRequest(ServiceRequest):
    DomainName: DomainName
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ScheduledAction(TypedDict, total=False):
    Id: String
    Type: ActionType
    Severity: ActionSeverity
    ScheduledTime: Long
    Description: String | None
    ScheduledBy: ScheduledBy | None
    Status: ActionStatus | None
    Mandatory: Boolean | None
    Cancellable: Boolean | None


ScheduledActionsList = list[ScheduledAction]


class ListScheduledActionsResponse(TypedDict, total=False):
    ScheduledActions: ScheduledActionsList | None
    NextToken: NextToken | None


class ListTagsRequest(ServiceRequest):
    ARN: ARN


class ListTagsResponse(TypedDict, total=False):
    TagList: TagList | None


class ListVersionsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListVersionsResponse(TypedDict, total=False):
    Versions: VersionList | None
    NextToken: NextToken | None


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


class PurchaseReservedInstanceOfferingRequest(ServiceRequest):
    ReservedInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: InstanceCount | None


class PurchaseReservedInstanceOfferingResponse(TypedDict, total=False):
    ReservedInstanceId: GUID | None
    ReservationName: ReservationToken | None


class PutDefaultApplicationSettingRequest(ServiceRequest):
    applicationArn: ARN
    setAsDefault: Boolean


class PutDefaultApplicationSettingResponse(TypedDict, total=False):
    applicationArn: ARN | None


class RejectInboundConnectionRequest(ServiceRequest):
    ConnectionId: ConnectionId


class RejectInboundConnectionResponse(TypedDict, total=False):
    Connection: InboundConnection | None


class RemoveTagsRequest(ServiceRequest):
    ARN: ARN
    TagKeys: StringList


class RevokeVpcEndpointAccessRequest(ServiceRequest):
    DomainName: DomainName
    Account: AWSAccount | None
    Service: AWSServicePrincipal | None


class RevokeVpcEndpointAccessResponse(TypedDict, total=False):
    pass


class StartDomainMaintenanceRequest(ServiceRequest):
    DomainName: DomainName
    Action: MaintenanceType
    NodeId: NodeId | None


class StartDomainMaintenanceResponse(TypedDict, total=False):
    MaintenanceId: RequestId | None


class StartServiceSoftwareUpdateRequest(ServiceRequest):
    DomainName: DomainName
    ScheduleAt: ScheduleAt | None
    DesiredStartTime: Long | None


class StartServiceSoftwareUpdateResponse(TypedDict, total=False):
    ServiceSoftwareOptions: ServiceSoftwareOptions | None


class UpdateApplicationRequest(ServiceRequest):
    id: Id
    dataSources: DataSources | None
    appConfigs: AppConfigs | None


class UpdateApplicationResponse(TypedDict, total=False):
    id: Id | None
    name: ApplicationName | None
    arn: ARN | None
    dataSources: DataSources | None
    iamIdentityCenterOptions: IamIdentityCenterOptions | None
    appConfigs: AppConfigs | None
    createdAt: Timestamp | None
    lastUpdatedAt: Timestamp | None


class UpdateDataSourceRequest(ServiceRequest):
    DomainName: DomainName
    Name: DataSourceName
    DataSourceType: DataSourceType
    Description: DataSourceDescription | None
    Status: DataSourceStatus | None


class UpdateDataSourceResponse(TypedDict, total=False):
    Message: String | None


class UpdateDirectQueryDataSourceRequest(ServiceRequest):
    DataSourceName: DirectQueryDataSourceName
    DataSourceType: DirectQueryDataSourceType
    Description: DirectQueryDataSourceDescription | None
    OpenSearchArns: DirectQueryOpenSearchARNList


class UpdateDirectQueryDataSourceResponse(TypedDict, total=False):
    DataSourceArn: String | None


class UpdateDomainConfigRequest(ServiceRequest):
    DomainName: DomainName
    ClusterConfig: ClusterConfig | None
    EBSOptions: EBSOptions | None
    SnapshotOptions: SnapshotOptions | None
    VPCOptions: VPCOptions | None
    CognitoOptions: CognitoOptions | None
    AdvancedOptions: AdvancedOptions | None
    AccessPolicies: PolicyDocument | None
    IPAddressType: IPAddressType | None
    LogPublishingOptions: LogPublishingOptions | None
    EncryptionAtRestOptions: EncryptionAtRestOptions | None
    DomainEndpointOptions: DomainEndpointOptions | None
    NodeToNodeEncryptionOptions: NodeToNodeEncryptionOptions | None
    AdvancedSecurityOptions: AdvancedSecurityOptionsInput | None
    IdentityCenterOptions: IdentityCenterOptionsInput | None
    AutoTuneOptions: AutoTuneOptions | None
    DryRun: DryRun | None
    DryRunMode: DryRunMode | None
    OffPeakWindowOptions: OffPeakWindowOptions | None
    SoftwareUpdateOptions: SoftwareUpdateOptions | None
    AIMLOptions: AIMLOptionsInput | None


class UpdateDomainConfigResponse(TypedDict, total=False):
    DomainConfig: DomainConfig
    DryRunResults: DryRunResults | None
    DryRunProgressStatus: DryRunProgressStatus | None


class UpdateIndexRequest(ServiceRequest):
    DomainName: DomainName
    IndexName: IndexName
    IndexSchema: IndexSchema


class UpdateIndexResponse(TypedDict, total=False):
    Status: IndexStatus


class UpdatePackageRequest(ServiceRequest):
    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: PackageDescription | None
    CommitMessage: CommitMessage | None
    PackageConfiguration: PackageConfiguration | None
    PackageEncryptionOptions: PackageEncryptionOptions | None


class UpdatePackageResponse(TypedDict, total=False):
    PackageDetails: PackageDetails | None


class UpdatePackageScopeRequest(ServiceRequest):
    PackageID: PackageID
    Operation: PackageScopeOperationEnum
    PackageUserList: PackageUserList


class UpdatePackageScopeResponse(TypedDict, total=False):
    PackageID: PackageID | None
    Operation: PackageScopeOperationEnum | None
    PackageUserList: PackageUserList | None


class UpdateScheduledActionRequest(ServiceRequest):
    DomainName: DomainName
    ActionID: String
    ActionType: ActionType
    ScheduleAt: ScheduleAt
    DesiredStartTime: Long | None


class UpdateScheduledActionResponse(TypedDict, total=False):
    ScheduledAction: ScheduledAction | None


class UpdateVpcEndpointRequest(ServiceRequest):
    VpcEndpointId: VpcEndpointId
    VpcOptions: VPCOptions


class UpdateVpcEndpointResponse(TypedDict, total=False):
    VpcEndpoint: VpcEndpoint


class UpgradeDomainRequest(ServiceRequest):
    DomainName: DomainName
    TargetVersion: VersionString
    PerformCheckOnly: Boolean | None
    AdvancedOptions: AdvancedOptions | None


class UpgradeDomainResponse(TypedDict, total=False):
    UpgradeId: String | None
    DomainName: DomainName | None
    TargetVersion: VersionString | None
    PerformCheckOnly: Boolean | None
    AdvancedOptions: AdvancedOptions | None
    ChangeProgressDetails: ChangeProgressDetails | None


class OpensearchApi:
    service: str = "opensearch"
    version: str = "2021-01-01"

    @handler("AcceptInboundConnection")
    def accept_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId, **kwargs
    ) -> AcceptInboundConnectionResponse:
        raise NotImplementedError

    @handler("AddDataSource")
    def add_data_source(
        self,
        context: RequestContext,
        domain_name: DomainName,
        name: DataSourceName,
        data_source_type: DataSourceType,
        description: DataSourceDescription | None = None,
        **kwargs,
    ) -> AddDataSourceResponse:
        raise NotImplementedError

    @handler("AddDirectQueryDataSource")
    def add_direct_query_data_source(
        self,
        context: RequestContext,
        data_source_name: DirectQueryDataSourceName,
        data_source_type: DirectQueryDataSourceType,
        open_search_arns: DirectQueryOpenSearchARNList,
        description: DirectQueryDataSourceDescription | None = None,
        tag_list: TagList | None = None,
        **kwargs,
    ) -> AddDirectQueryDataSourceResponse:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList, **kwargs) -> None:
        raise NotImplementedError

    @handler("AssociatePackage")
    def associate_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        domain_name: DomainName,
        prerequisite_package_id_list: PackageIDList | None = None,
        association_configuration: PackageAssociationConfiguration | None = None,
        **kwargs,
    ) -> AssociatePackageResponse:
        raise NotImplementedError

    @handler("AssociatePackages")
    def associate_packages(
        self,
        context: RequestContext,
        package_list: PackageDetailsForAssociationList,
        domain_name: DomainName,
        **kwargs,
    ) -> AssociatePackagesResponse:
        raise NotImplementedError

    @handler("AuthorizeVpcEndpointAccess")
    def authorize_vpc_endpoint_access(
        self,
        context: RequestContext,
        domain_name: DomainName,
        account: AWSAccount | None = None,
        service: AWSServicePrincipal | None = None,
        **kwargs,
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

    @handler("CancelServiceSoftwareUpdate")
    def cancel_service_software_update(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> CancelServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("CreateApplication")
    def create_application(
        self,
        context: RequestContext,
        name: ApplicationName,
        client_token: ClientToken | None = None,
        data_sources: DataSources | None = None,
        iam_identity_center_options: IamIdentityCenterOptionsInput | None = None,
        app_configs: AppConfigs | None = None,
        tag_list: TagList | None = None,
        kms_key_arn: KmsKeyArn | None = None,
        **kwargs,
    ) -> CreateApplicationResponse:
        raise NotImplementedError

    @handler("CreateDomain")
    def create_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        engine_version: VersionString | None = None,
        cluster_config: ClusterConfig | None = None,
        ebs_options: EBSOptions | None = None,
        access_policies: PolicyDocument | None = None,
        ip_address_type: IPAddressType | None = None,
        snapshot_options: SnapshotOptions | None = None,
        vpc_options: VPCOptions | None = None,
        cognito_options: CognitoOptions | None = None,
        encryption_at_rest_options: EncryptionAtRestOptions | None = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions | None = None,
        advanced_options: AdvancedOptions | None = None,
        log_publishing_options: LogPublishingOptions | None = None,
        domain_endpoint_options: DomainEndpointOptions | None = None,
        advanced_security_options: AdvancedSecurityOptionsInput | None = None,
        identity_center_options: IdentityCenterOptionsInput | None = None,
        tag_list: TagList | None = None,
        auto_tune_options: AutoTuneOptionsInput | None = None,
        off_peak_window_options: OffPeakWindowOptions | None = None,
        software_update_options: SoftwareUpdateOptions | None = None,
        aiml_options: AIMLOptionsInput | None = None,
        **kwargs,
    ) -> CreateDomainResponse:
        raise NotImplementedError

    @handler("CreateIndex")
    def create_index(
        self,
        context: RequestContext,
        domain_name: DomainName,
        index_name: IndexName,
        index_schema: IndexSchema,
        **kwargs,
    ) -> CreateIndexResponse:
        raise NotImplementedError

    @handler("CreateOutboundConnection")
    def create_outbound_connection(
        self,
        context: RequestContext,
        local_domain_info: DomainInformationContainer,
        remote_domain_info: DomainInformationContainer,
        connection_alias: ConnectionAlias,
        connection_mode: ConnectionMode | None = None,
        connection_properties: ConnectionProperties | None = None,
        **kwargs,
    ) -> CreateOutboundConnectionResponse:
        raise NotImplementedError

    @handler("CreatePackage")
    def create_package(
        self,
        context: RequestContext,
        package_name: PackageName,
        package_type: PackageType,
        package_source: PackageSource,
        package_description: PackageDescription | None = None,
        package_configuration: PackageConfiguration | None = None,
        engine_version: EngineVersion | None = None,
        package_vending_options: PackageVendingOptions | None = None,
        package_encryption_options: PackageEncryptionOptions | None = None,
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

    @handler("DeleteApplication")
    def delete_application(
        self, context: RequestContext, id: Id, **kwargs
    ) -> DeleteApplicationResponse:
        raise NotImplementedError

    @handler("DeleteDataSource")
    def delete_data_source(
        self, context: RequestContext, domain_name: DomainName, name: DataSourceName, **kwargs
    ) -> DeleteDataSourceResponse:
        raise NotImplementedError

    @handler("DeleteDirectQueryDataSource")
    def delete_direct_query_data_source(
        self, context: RequestContext, data_source_name: DirectQueryDataSourceName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDomain")
    def delete_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DeleteDomainResponse:
        raise NotImplementedError

    @handler("DeleteInboundConnection")
    def delete_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId, **kwargs
    ) -> DeleteInboundConnectionResponse:
        raise NotImplementedError

    @handler("DeleteIndex")
    def delete_index(
        self, context: RequestContext, domain_name: DomainName, index_name: IndexName, **kwargs
    ) -> DeleteIndexResponse:
        raise NotImplementedError

    @handler("DeleteOutboundConnection")
    def delete_outbound_connection(
        self, context: RequestContext, connection_id: ConnectionId, **kwargs
    ) -> DeleteOutboundConnectionResponse:
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

    @handler("DescribeDomain")
    def describe_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainResponse:
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

    @handler("DescribeDomainConfig")
    def describe_domain_config(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainConfigResponse:
        raise NotImplementedError

    @handler("DescribeDomainHealth")
    def describe_domain_health(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainHealthResponse:
        raise NotImplementedError

    @handler("DescribeDomainNodes")
    def describe_domain_nodes(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainNodesResponse:
        raise NotImplementedError

    @handler("DescribeDomains")
    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList, **kwargs
    ) -> DescribeDomainsResponse:
        raise NotImplementedError

    @handler("DescribeDryRunProgress")
    def describe_dry_run_progress(
        self,
        context: RequestContext,
        domain_name: DomainName,
        dry_run_id: GUID | None = None,
        load_dry_run_config: Boolean | None = None,
        **kwargs,
    ) -> DescribeDryRunProgressResponse:
        raise NotImplementedError

    @handler("DescribeInboundConnections")
    def describe_inbound_connections(
        self,
        context: RequestContext,
        filters: FilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeInboundConnectionsResponse:
        raise NotImplementedError

    @handler("DescribeInstanceTypeLimits")
    def describe_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: OpenSearchPartitionInstanceType,
        engine_version: VersionString,
        domain_name: DomainName | None = None,
        **kwargs,
    ) -> DescribeInstanceTypeLimitsResponse:
        raise NotImplementedError

    @handler("DescribeOutboundConnections")
    def describe_outbound_connections(
        self,
        context: RequestContext,
        filters: FilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeOutboundConnectionsResponse:
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

    @handler("DescribeReservedInstanceOfferings")
    def describe_reserved_instance_offerings(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeReservedInstanceOfferingsResponse:
        raise NotImplementedError

    @handler("DescribeReservedInstances")
    def describe_reserved_instances(
        self,
        context: RequestContext,
        reserved_instance_id: GUID | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeReservedInstancesResponse:
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

    @handler("DissociatePackages")
    def dissociate_packages(
        self,
        context: RequestContext,
        package_list: PackageIDList,
        domain_name: DomainName,
        **kwargs,
    ) -> DissociatePackagesResponse:
        raise NotImplementedError

    @handler("GetApplication")
    def get_application(self, context: RequestContext, id: Id, **kwargs) -> GetApplicationResponse:
        raise NotImplementedError

    @handler("GetCompatibleVersions")
    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName | None = None, **kwargs
    ) -> GetCompatibleVersionsResponse:
        raise NotImplementedError

    @handler("GetDataSource")
    def get_data_source(
        self, context: RequestContext, domain_name: DomainName, name: DataSourceName, **kwargs
    ) -> GetDataSourceResponse:
        raise NotImplementedError

    @handler("GetDefaultApplicationSetting")
    def get_default_application_setting(
        self, context: RequestContext, **kwargs
    ) -> GetDefaultApplicationSettingResponse:
        raise NotImplementedError

    @handler("GetDirectQueryDataSource")
    def get_direct_query_data_source(
        self, context: RequestContext, data_source_name: DirectQueryDataSourceName, **kwargs
    ) -> GetDirectQueryDataSourceResponse:
        raise NotImplementedError

    @handler("GetDomainMaintenanceStatus")
    def get_domain_maintenance_status(
        self, context: RequestContext, domain_name: DomainName, maintenance_id: RequestId, **kwargs
    ) -> GetDomainMaintenanceStatusResponse:
        raise NotImplementedError

    @handler("GetIndex")
    def get_index(
        self, context: RequestContext, domain_name: DomainName, index_name: IndexName, **kwargs
    ) -> GetIndexResponse:
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

    @handler("ListApplications")
    def list_applications(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        statuses: ApplicationStatuses | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListApplicationsResponse:
        raise NotImplementedError

    @handler("ListDataSources")
    def list_data_sources(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> ListDataSourcesResponse:
        raise NotImplementedError

    @handler("ListDirectQueryDataSources")
    def list_direct_query_data_sources(
        self, context: RequestContext, next_token: NextToken | None = None, **kwargs
    ) -> ListDirectQueryDataSourcesResponse:
        raise NotImplementedError

    @handler("ListDomainMaintenances")
    def list_domain_maintenances(
        self,
        context: RequestContext,
        domain_name: DomainName,
        action: MaintenanceType | None = None,
        status: MaintenanceStatus | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDomainMaintenancesResponse:
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

    @handler("ListInstanceTypeDetails")
    def list_instance_type_details(
        self,
        context: RequestContext,
        engine_version: VersionString,
        domain_name: DomainName | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        retrieve_azs: Boolean | None = None,
        instance_type: InstanceTypeString | None = None,
        **kwargs,
    ) -> ListInstanceTypeDetailsResponse:
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

    @handler("ListScheduledActions")
    def list_scheduled_actions(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListScheduledActionsResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, arn: ARN, **kwargs) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListVersions")
    def list_versions(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListVersionsResponse:
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

    @handler("PurchaseReservedInstanceOffering")
    def purchase_reserved_instance_offering(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount | None = None,
        **kwargs,
    ) -> PurchaseReservedInstanceOfferingResponse:
        raise NotImplementedError

    @handler("PutDefaultApplicationSetting")
    def put_default_application_setting(
        self, context: RequestContext, application_arn: ARN, set_as_default: Boolean, **kwargs
    ) -> PutDefaultApplicationSettingResponse:
        raise NotImplementedError

    @handler("RejectInboundConnection")
    def reject_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId, **kwargs
    ) -> RejectInboundConnectionResponse:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(
        self, context: RequestContext, arn: ARN, tag_keys: StringList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RevokeVpcEndpointAccess")
    def revoke_vpc_endpoint_access(
        self,
        context: RequestContext,
        domain_name: DomainName,
        account: AWSAccount | None = None,
        service: AWSServicePrincipal | None = None,
        **kwargs,
    ) -> RevokeVpcEndpointAccessResponse:
        raise NotImplementedError

    @handler("StartDomainMaintenance")
    def start_domain_maintenance(
        self,
        context: RequestContext,
        domain_name: DomainName,
        action: MaintenanceType,
        node_id: NodeId | None = None,
        **kwargs,
    ) -> StartDomainMaintenanceResponse:
        raise NotImplementedError

    @handler("StartServiceSoftwareUpdate")
    def start_service_software_update(
        self,
        context: RequestContext,
        domain_name: DomainName,
        schedule_at: ScheduleAt | None = None,
        desired_start_time: Long | None = None,
        **kwargs,
    ) -> StartServiceSoftwareUpdateResponse:
        raise NotImplementedError

    @handler("UpdateApplication")
    def update_application(
        self,
        context: RequestContext,
        id: Id,
        data_sources: DataSources | None = None,
        app_configs: AppConfigs | None = None,
        **kwargs,
    ) -> UpdateApplicationResponse:
        raise NotImplementedError

    @handler("UpdateDataSource")
    def update_data_source(
        self,
        context: RequestContext,
        domain_name: DomainName,
        name: DataSourceName,
        data_source_type: DataSourceType,
        description: DataSourceDescription | None = None,
        status: DataSourceStatus | None = None,
        **kwargs,
    ) -> UpdateDataSourceResponse:
        raise NotImplementedError

    @handler("UpdateDirectQueryDataSource")
    def update_direct_query_data_source(
        self,
        context: RequestContext,
        data_source_name: DirectQueryDataSourceName,
        data_source_type: DirectQueryDataSourceType,
        open_search_arns: DirectQueryOpenSearchARNList,
        description: DirectQueryDataSourceDescription | None = None,
        **kwargs,
    ) -> UpdateDirectQueryDataSourceResponse:
        raise NotImplementedError

    @handler("UpdateDomainConfig")
    def update_domain_config(
        self,
        context: RequestContext,
        domain_name: DomainName,
        cluster_config: ClusterConfig | None = None,
        ebs_options: EBSOptions | None = None,
        snapshot_options: SnapshotOptions | None = None,
        vpc_options: VPCOptions | None = None,
        cognito_options: CognitoOptions | None = None,
        advanced_options: AdvancedOptions | None = None,
        access_policies: PolicyDocument | None = None,
        ip_address_type: IPAddressType | None = None,
        log_publishing_options: LogPublishingOptions | None = None,
        encryption_at_rest_options: EncryptionAtRestOptions | None = None,
        domain_endpoint_options: DomainEndpointOptions | None = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions | None = None,
        advanced_security_options: AdvancedSecurityOptionsInput | None = None,
        identity_center_options: IdentityCenterOptionsInput | None = None,
        auto_tune_options: AutoTuneOptions | None = None,
        dry_run: DryRun | None = None,
        dry_run_mode: DryRunMode | None = None,
        off_peak_window_options: OffPeakWindowOptions | None = None,
        software_update_options: SoftwareUpdateOptions | None = None,
        aiml_options: AIMLOptionsInput | None = None,
        **kwargs,
    ) -> UpdateDomainConfigResponse:
        raise NotImplementedError

    @handler("UpdateIndex")
    def update_index(
        self,
        context: RequestContext,
        domain_name: DomainName,
        index_name: IndexName,
        index_schema: IndexSchema,
        **kwargs,
    ) -> UpdateIndexResponse:
        raise NotImplementedError

    @handler("UpdatePackage")
    def update_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        package_source: PackageSource,
        package_description: PackageDescription | None = None,
        commit_message: CommitMessage | None = None,
        package_configuration: PackageConfiguration | None = None,
        package_encryption_options: PackageEncryptionOptions | None = None,
        **kwargs,
    ) -> UpdatePackageResponse:
        raise NotImplementedError

    @handler("UpdatePackageScope")
    def update_package_scope(
        self,
        context: RequestContext,
        package_id: PackageID,
        operation: PackageScopeOperationEnum,
        package_user_list: PackageUserList,
        **kwargs,
    ) -> UpdatePackageScopeResponse:
        raise NotImplementedError

    @handler("UpdateScheduledAction")
    def update_scheduled_action(
        self,
        context: RequestContext,
        domain_name: DomainName,
        action_id: String,
        action_type: ActionType,
        schedule_at: ScheduleAt,
        desired_start_time: Long | None = None,
        **kwargs,
    ) -> UpdateScheduledActionResponse:
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

    @handler("UpgradeDomain")
    def upgrade_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        target_version: VersionString,
        perform_check_only: Boolean | None = None,
        advanced_options: AdvancedOptions | None = None,
        **kwargs,
    ) -> UpgradeDomainResponse:
        raise NotImplementedError
