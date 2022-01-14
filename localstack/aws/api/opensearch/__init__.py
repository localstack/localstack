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
CloudWatchLogsLogGroupArn = str
CommitMessage = str
ConnectionAlias = str
ConnectionId = str
ConnectionStatusMessage = str
DeploymentType = str
DescribePackagesFilterValue = str
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
    """An error occurred because user does not have permissions to access the
    resource. Returns HTTP status code 403.
    """

    pass


class BaseException(ServiceException):
    """An error occurred while processing the request."""

    message: Optional[ErrorMessage]


class ConflictException(ServiceException):
    """An error occurred because the client attempts to remove a resource that
    is currently in use. Returns HTTP status code 409.
    """

    pass


class DisabledOperationException(ServiceException):
    """An error occured because the client wanted to access a not supported
    operation. Gives http status code of 409.
    """

    pass


class InternalException(ServiceException):
    """The request processing has failed because of an unknown error, exception
    or failure (the failure is internal to the service) . Gives http status
    code of 500.
    """

    pass


class InvalidPaginationTokenException(ServiceException):
    """The request processing has failed because of invalid pagination token
    provided by customer. Returns an HTTP status code of 400.
    """

    pass


class InvalidTypeException(ServiceException):
    """An exception for trying to create or access sub-resource that is either
    invalid or not supported. Gives http status code of 409.
    """

    pass


class LimitExceededException(ServiceException):
    """An exception for trying to create more than allowed resources or
    sub-resources. Gives http status code of 409.
    """

    pass


class ResourceAlreadyExistsException(ServiceException):
    """An exception for creating a resource that already exists. Gives http
    status code of 400.
    """

    pass


class ResourceNotFoundException(ServiceException):
    """An exception for accessing or deleting a resource that does not exist.
    Gives http status code of 400.
    """

    pass


class ValidationException(ServiceException):
    """An exception for missing / invalid input fields. Gives http status code
    of 400.
    """

    pass


class AWSDomainInformation(TypedDict, total=False):
    OwnerId: Optional[OwnerId]
    DomainName: DomainName
    Region: Optional[Region]


class AcceptInboundConnectionRequest(ServiceRequest):
    """Container for the parameters to the ``AcceptInboundConnection``
    operation.
    """

    ConnectionId: ConnectionId


class InboundConnectionStatus(TypedDict, total=False):
    """The connection status of an inbound cross-cluster connection."""

    StatusCode: Optional[InboundConnectionStatusCode]
    Message: Optional[ConnectionStatusMessage]


class DomainInformationContainer(TypedDict, total=False):
    AWSDomainInformation: Optional[AWSDomainInformation]


class InboundConnection(TypedDict, total=False):
    """Details of an inbound connection."""

    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionId: Optional[ConnectionId]
    ConnectionStatus: Optional[InboundConnectionStatus]


class AcceptInboundConnectionResponse(TypedDict, total=False):
    """The result of an ``AcceptInboundConnection`` operation. Contains details
    about the accepted inbound connection.
    """

    Connection: Optional[InboundConnection]


UpdateTimestamp = datetime


class OptionStatus(TypedDict, total=False):
    """Provides the current status of the entity."""

    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: OptionState
    PendingDeletion: Optional[Boolean]


class AccessPoliciesStatus(TypedDict, total=False):
    """The configured access rules for the domain's document and search
    endpoints, and the current status of those rules.
    """

    Options: PolicyDocument
    Status: OptionStatus


class Tag(TypedDict, total=False):
    """A key value pair for a resource tag."""

    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class AddTagsRequest(ServiceRequest):
    """Container for the parameters to the ``AddTags`` operation. Specifies the
    tags to attach to the domain.
    """

    ARN: ARN
    TagList: TagList


LimitValueList = List[LimitValue]


class AdditionalLimit(TypedDict, total=False):
    """List of limits that are specific to a given InstanceType and for each of
    its ``InstanceRole`` .
    """

    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


AdditionalLimitList = List[AdditionalLimit]
AdvancedOptions = Dict[String, String]


class AdvancedOptionsStatus(TypedDict, total=False):
    """Status of the advanced options for the specified domain. Currently, the
    following advanced options are available:

    -  Option to allow references to indices in an HTTP request body. Must
       be ``false`` when configuring access to individual sub-resources. By
       default, the value is ``true``. See `Advanced cluster
       parameters <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`__
       for more information.
    -  Option to specify the percentage of heap space allocated to field
       data. By default, this setting is unbounded.

    For more information, see `Advanced cluster
    parameters <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`__.
    """

    Options: AdvancedOptions
    Status: OptionStatus


DisableTimestamp = datetime


class SAMLIdp(TypedDict, total=False):
    """The SAML identity povider's information."""

    MetadataContent: SAMLMetadata
    EntityId: SAMLEntityId


class SAMLOptionsOutput(TypedDict, total=False):
    """Describes the SAML application configured for the domain."""

    Enabled: Optional[Boolean]
    Idp: Optional[SAMLIdp]
    SubjectKey: Optional[String]
    RolesKey: Optional[String]
    SessionTimeoutMinutes: Optional[IntegerClass]


class AdvancedSecurityOptions(TypedDict, total=False):
    """The advanced security configuration: whether advanced security is
    enabled, whether the internal database option is enabled.
    """

    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    SAMLOptions: Optional[SAMLOptionsOutput]
    AnonymousAuthDisableDate: Optional[DisableTimestamp]
    AnonymousAuthEnabled: Optional[Boolean]


class SAMLOptionsInput(TypedDict, total=False):
    """The SAML application configuration for the domain."""

    Enabled: Optional[Boolean]
    Idp: Optional[SAMLIdp]
    MasterUserName: Optional[Username]
    MasterBackendRole: Optional[BackendRole]
    SubjectKey: Optional[String]
    RolesKey: Optional[String]
    SessionTimeoutMinutes: Optional[IntegerClass]


class MasterUserOptions(TypedDict, total=False):
    """Credentials for the master user: username and password, ARN, or both."""

    MasterUserARN: Optional[ARN]
    MasterUserName: Optional[Username]
    MasterUserPassword: Optional[Password]


class AdvancedSecurityOptionsInput(TypedDict, total=False):
    """The advanced security configuration: whether advanced security is
    enabled, whether the internal database option is enabled, master
    username and password (if internal database is enabled), and master user
    ARN (if IAM is enabled).
    """

    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    MasterUserOptions: Optional[MasterUserOptions]
    SAMLOptions: Optional[SAMLOptionsInput]
    AnonymousAuthEnabled: Optional[Boolean]


class AdvancedSecurityOptionsStatus(TypedDict, total=False):
    """The status of advanced security options for the specified domain."""

    Options: AdvancedSecurityOptions
    Status: OptionStatus


class AssociatePackageRequest(ServiceRequest):
    """Container for the request parameters to the ``AssociatePackage``
    operation.
    """

    PackageID: PackageID
    DomainName: DomainName


class ErrorDetails(TypedDict, total=False):
    ErrorType: Optional[ErrorType]
    ErrorMessage: Optional[ErrorMessage]


LastUpdated = datetime


class DomainPackageDetails(TypedDict, total=False):
    """Information on a package associated with a domain."""

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
    """Container for the response returned by ``AssociatePackage`` operation."""

    DomainPackageDetails: Optional[DomainPackageDetails]


AutoTuneDate = datetime


class ScheduledAutoTuneDetails(TypedDict, total=False):
    """Specifies details about the scheduled Auto-Tune action. See `Auto-Tune
    for Amazon OpenSearch
    Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    Date: Optional[AutoTuneDate]
    ActionType: Optional[ScheduledAutoTuneActionType]
    Action: Optional[ScheduledAutoTuneDescription]
    Severity: Optional[ScheduledAutoTuneSeverityType]


class AutoTuneDetails(TypedDict, total=False):
    """Specifies details about the Auto-Tune action. See `Auto-Tune for Amazon
    OpenSearch
    Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    ScheduledAutoTuneDetails: Optional[ScheduledAutoTuneDetails]


class AutoTune(TypedDict, total=False):
    """Specifies the Auto-Tune type and Auto-Tune action details."""

    AutoTuneType: Optional[AutoTuneType]
    AutoTuneDetails: Optional[AutoTuneDetails]


AutoTuneList = List[AutoTune]
DurationValue = int


class Duration(TypedDict, total=False):
    """The maintenance schedule duration: duration value and duration unit. See
    `Auto-Tune for Amazon OpenSearch
    Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    Value: Optional[DurationValue]
    Unit: Optional[TimeUnit]


StartAt = datetime


class AutoTuneMaintenanceSchedule(TypedDict, total=False):
    """Specifies the Auto-Tune maintenance schedule. See `Auto-Tune for Amazon
    OpenSearch
    Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    StartAt: Optional[StartAt]
    Duration: Optional[Duration]
    CronExpressionForRecurrence: Optional[String]


AutoTuneMaintenanceScheduleList = List[AutoTuneMaintenanceSchedule]


class AutoTuneOptions(TypedDict, total=False):
    """The Auto-Tune options: the Auto-Tune desired state for the domain,
    rollback state when disabling Auto-Tune options and list of maintenance
    schedules.
    """

    DesiredState: Optional[AutoTuneDesiredState]
    RollbackOnDisable: Optional[RollbackOnDisable]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsInput(TypedDict, total=False):
    """The Auto-Tune options: the Auto-Tune desired state for the domain and
    list of maintenance schedules.
    """

    DesiredState: Optional[AutoTuneDesiredState]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsOutput(TypedDict, total=False):
    """The Auto-Tune options: the Auto-Tune desired state for the domain and
    list of maintenance schedules.
    """

    State: Optional[AutoTuneState]
    ErrorMessage: Optional[String]


class AutoTuneStatus(TypedDict, total=False):
    """Provides the current Auto-Tune status for the domain."""

    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: AutoTuneState
    ErrorMessage: Optional[String]
    PendingDeletion: Optional[Boolean]


class AutoTuneOptionsStatus(TypedDict, total=False):
    """The Auto-Tune status for the domain."""

    Options: Optional[AutoTuneOptions]
    Status: Optional[AutoTuneStatus]


class CancelServiceSoftwareUpdateRequest(ServiceRequest):
    """Container for the parameters to the ``CancelServiceSoftwareUpdate``
    operation. Specifies the name of the domain that you wish to cancel a
    service software update on.
    """

    DomainName: DomainName


DeploymentCloseDateTimeStamp = datetime


class ServiceSoftwareOptions(TypedDict, total=False):
    """The current options of an domain service software options."""

    CurrentVersion: Optional[String]
    NewVersion: Optional[String]
    UpdateAvailable: Optional[Boolean]
    Cancellable: Optional[Boolean]
    UpdateStatus: Optional[DeploymentStatus]
    Description: Optional[String]
    AutomatedUpdateDate: Optional[DeploymentCloseDateTimeStamp]
    OptionalDeployment: Optional[Boolean]


class CancelServiceSoftwareUpdateResponse(TypedDict, total=False):
    """The result of a ``CancelServiceSoftwareUpdate`` operation. Contains the
    status of the update.
    """

    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class ColdStorageOptions(TypedDict, total=False):
    """Specifies the configuration for cold storage options such as enabled"""

    Enabled: Boolean


class ZoneAwarenessConfig(TypedDict, total=False):
    """The zone awareness configuration for the domain cluster, such as the
    number of availability zones.
    """

    AvailabilityZoneCount: Optional[IntegerClass]


class ClusterConfig(TypedDict, total=False):
    """The configuration for the domain cluster, such as the type and number of
    instances.
    """

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
    """The configuration status for the specified domain."""

    Options: ClusterConfig
    Status: OptionStatus


class CognitoOptions(TypedDict, total=False):
    """Options to specify the Cognito user and identity pools for OpenSearch
    Dashboards authentication. For more information, see `Configuring Amazon
    Cognito authentication for OpenSearch
    Dashboards <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html>`__.
    """

    Enabled: Optional[Boolean]
    UserPoolId: Optional[UserPoolId]
    IdentityPoolId: Optional[IdentityPoolId]
    RoleArn: Optional[RoleArn]


class CognitoOptionsStatus(TypedDict, total=False):
    """The status of the Cognito options for the specified domain."""

    Options: CognitoOptions
    Status: OptionStatus


VersionList = List[VersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    """A map from an ``EngineVersion`` to a list of compatible
    ``EngineVersion`` s to which the domain can be upgraded.
    """

    SourceVersion: Optional[VersionString]
    TargetVersions: Optional[VersionList]


CompatibleVersionsList = List[CompatibleVersionsMap]


class DomainEndpointOptions(TypedDict, total=False):
    """Options to configure the endpoint for the domain."""

    EnforceHTTPS: Optional[Boolean]
    TLSSecurityPolicy: Optional[TLSSecurityPolicy]
    CustomEndpointEnabled: Optional[Boolean]
    CustomEndpoint: Optional[DomainNameFqdn]
    CustomEndpointCertificateArn: Optional[ARN]


class LogPublishingOption(TypedDict, total=False):
    """| Log Publishing option that is set for a given domain.
    | Attributes and their details:

    -  CloudWatchLogsLogGroupArn: ARN of the Cloudwatch log group to publish
       logs to.
    -  Enabled: Whether the log publishing for a given log type is enabled
       or not.
    """

    CloudWatchLogsLogGroupArn: Optional[CloudWatchLogsLogGroupArn]
    Enabled: Optional[Boolean]


LogPublishingOptions = Dict[LogType, LogPublishingOption]


class NodeToNodeEncryptionOptions(TypedDict, total=False):
    """The node-to-node encryption options."""

    Enabled: Optional[Boolean]


class EncryptionAtRestOptions(TypedDict, total=False):
    """Specifies encryption at rest options."""

    Enabled: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]


StringList = List[String]


class VPCOptions(TypedDict, total=False):
    """Options to specify the subnets and security groups for the VPC endpoint.
    For more information, see `Launching your Amazon OpenSearch Service
    domains using a
    VPC <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`__.
    """

    SubnetIds: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


class SnapshotOptions(TypedDict, total=False):
    """The time, in UTC format, when the service takes a daily automated
    snapshot of the specified domain. Default is ``0`` hours.
    """

    AutomatedSnapshotStartHour: Optional[IntegerClass]


class EBSOptions(TypedDict, total=False):
    """Options to enable, disable, and specify the properties of EBS storage
    volumes.
    """

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
    """Options to specify the subnets and security groups for the VPC endpoint.
    For more information, see `Launching your Amazon OpenSearch Service
    domains using a
    VPC <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`__.
    """

    VPCId: Optional[String]
    SubnetIds: Optional[StringList]
    AvailabilityZones: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


EndpointsMap = Dict[String, ServiceUrl]


class DomainStatus(TypedDict, total=False):
    """The current status of a domain."""

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


class CreateDomainResponse(TypedDict, total=False):
    """The result of a ``CreateDomain`` operation. Contains the status of the
    newly created Amazon OpenSearch Service domain.
    """

    DomainStatus: Optional[DomainStatus]


class CreateOutboundConnectionRequest(ServiceRequest):
    """Container for the parameters to the ``CreateOutboundConnection``
    operation.
    """

    LocalDomainInfo: DomainInformationContainer
    RemoteDomainInfo: DomainInformationContainer
    ConnectionAlias: ConnectionAlias


class OutboundConnectionStatus(TypedDict, total=False):
    """The connection status of an outbound cross-cluster connection."""

    StatusCode: Optional[OutboundConnectionStatusCode]
    Message: Optional[ConnectionStatusMessage]


class CreateOutboundConnectionResponse(TypedDict, total=False):
    """The result of a ``CreateOutboundConnection`` request. Contains the
    details about the newly created cross-cluster connection.
    """

    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundConnectionStatus]
    ConnectionId: Optional[ConnectionId]


class PackageSource(TypedDict, total=False):
    """The Amazon S3 location for importing the package specified as
    ``S3BucketName`` and ``S3Key``
    """

    S3BucketName: Optional[S3BucketName]
    S3Key: Optional[S3Key]


class CreatePackageRequest(ServiceRequest):
    """Container for request parameters to the ``CreatePackage`` operation."""

    PackageName: PackageName
    PackageType: PackageType
    PackageDescription: Optional[PackageDescription]
    PackageSource: PackageSource


CreatedAt = datetime


class PackageDetails(TypedDict, total=False):
    """Basic information about a package."""

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
    """Container for the response returned by the ``CreatePackage`` operation."""

    PackageDetails: Optional[PackageDetails]


class DeleteDomainRequest(ServiceRequest):
    """Container for the parameters to the ``DeleteDomain`` operation.
    Specifies the name of the domain you want to delete.
    """

    DomainName: DomainName


class DeleteDomainResponse(TypedDict, total=False):
    """The result of a ``DeleteDomain`` request. Contains the status of the
    pending deletion, or a "domain not found" error if the domain and all of
    its resources have been deleted.
    """

    DomainStatus: Optional[DomainStatus]


class DeleteInboundConnectionRequest(ServiceRequest):
    """Container for the parameters to the ``DeleteInboundConnection``
    operation.
    """

    ConnectionId: ConnectionId


class DeleteInboundConnectionResponse(TypedDict, total=False):
    """The result of a ``DeleteInboundConnection`` operation. Contains details
    about the deleted inbound connection.
    """

    Connection: Optional[InboundConnection]


class DeleteOutboundConnectionRequest(ServiceRequest):
    """Container for the parameters to the ``DeleteOutboundConnection``
    operation.
    """

    ConnectionId: ConnectionId


class OutboundConnection(TypedDict, total=False):
    """Specifies details about an outbound connection."""

    LocalDomainInfo: Optional[DomainInformationContainer]
    RemoteDomainInfo: Optional[DomainInformationContainer]
    ConnectionId: Optional[ConnectionId]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundConnectionStatus]


class DeleteOutboundConnectionResponse(TypedDict, total=False):
    """The result of a ``DeleteOutboundConnection`` operation. Contains details
    about the deleted outbound connection.
    """

    Connection: Optional[OutboundConnection]


class DeletePackageRequest(ServiceRequest):
    """Container for the request parameters to the ``DeletePackage`` operation."""

    PackageID: PackageID


class DeletePackageResponse(TypedDict, total=False):
    """Container for the response parameters to the ``DeletePackage``
    operation.
    """

    PackageDetails: Optional[PackageDetails]


class DescribeDomainAutoTunesRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeDomainAutoTunes``
    operation.
    """

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeDomainAutoTunesResponse(TypedDict, total=False):
    """The result of a ``DescribeDomainAutoTunes`` request. See `Auto-Tune for
    Amazon OpenSearch
    Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    AutoTunes: Optional[AutoTuneList]
    NextToken: Optional[NextToken]


class DescribeDomainConfigRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeDomainConfig`` operation.
    Specifies the domain name for which you want configuration information.
    """

    DomainName: DomainName


class DomainEndpointOptionsStatus(TypedDict, total=False):
    """The configured endpoint options for the domain and their current status."""

    Options: DomainEndpointOptions
    Status: OptionStatus


class LogPublishingOptionsStatus(TypedDict, total=False):
    """The configured log publishing options for the domain and their current
    status.
    """

    Options: Optional[LogPublishingOptions]
    Status: Optional[OptionStatus]


class NodeToNodeEncryptionOptionsStatus(TypedDict, total=False):
    """Status of the node-to-node encryption options for the specified domain."""

    Options: NodeToNodeEncryptionOptions
    Status: OptionStatus


class EncryptionAtRestOptionsStatus(TypedDict, total=False):
    """Status of the encryption At Rest options for the specified domain."""

    Options: EncryptionAtRestOptions
    Status: OptionStatus


class VPCDerivedInfoStatus(TypedDict, total=False):
    """Status of the VPC options for the specified domain."""

    Options: VPCDerivedInfo
    Status: OptionStatus


class SnapshotOptionsStatus(TypedDict, total=False):
    """Status of a daily automated snapshot."""

    Options: SnapshotOptions
    Status: OptionStatus


class EBSOptionsStatus(TypedDict, total=False):
    """Status of the EBS options for the specified domain."""

    Options: EBSOptions
    Status: OptionStatus


class VersionStatus(TypedDict, total=False):
    """The status of the OpenSearch version options for the specified
    OpenSearch domain.
    """

    Options: VersionString
    Status: OptionStatus


class DomainConfig(TypedDict, total=False):
    """The configuration of a domain."""

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


class DescribeDomainConfigResponse(TypedDict, total=False):
    """The result of a ``DescribeDomainConfig`` request. Contains the
    configuration information of the requested domain.
    """

    DomainConfig: DomainConfig


class DescribeDomainRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeDomain`` operation."""

    DomainName: DomainName


class DescribeDomainResponse(TypedDict, total=False):
    """The result of a ``DescribeDomain`` request. Contains the status of the
    domain specified in the request.
    """

    DomainStatus: DomainStatus


DomainNameList = List[DomainName]


class DescribeDomainsRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeDomains`` operation. By
    default, the API returns the status of all domains.
    """

    DomainNames: DomainNameList


DomainStatusList = List[DomainStatus]


class DescribeDomainsResponse(TypedDict, total=False):
    """The result of a ``DescribeDomains`` request. Contains the status of the
    specified domains or all domains owned by the account.
    """

    DomainStatusList: DomainStatusList


ValueStringList = List[NonEmptyString]


class Filter(TypedDict, total=False):
    """A filter used to limit results when describing inbound or outbound
    cross-cluster connections. Multiple values can be specified per filter.
    A cross-cluster connection must match at least one of the specified
    values for it to be returned from an operation.
    """

    Name: Optional[NonEmptyString]
    Values: Optional[ValueStringList]


FilterList = List[Filter]


class DescribeInboundConnectionsRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeInboundConnections``
    operation.
    """

    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


InboundConnections = List[InboundConnection]


class DescribeInboundConnectionsResponse(TypedDict, total=False):
    """The result of a ``DescribeInboundConnections`` request. Contains a list
    of connections matching the filter criteria.
    """

    Connections: Optional[InboundConnections]
    NextToken: Optional[NextToken]


class DescribeInstanceTypeLimitsRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeInstanceTypeLimits``
    operation.
    """

    DomainName: Optional[DomainName]
    InstanceType: OpenSearchPartitionInstanceType
    EngineVersion: VersionString


class InstanceCountLimits(TypedDict, total=False):
    """InstanceCountLimits represents the limits on the number of instances
    that can be created in Amazon OpenSearch Service for a given
    InstanceType.
    """

    MinimumInstanceCount: Optional[MinimumInstanceCount]
    MaximumInstanceCount: Optional[MaximumInstanceCount]


class InstanceLimits(TypedDict, total=False):
    """InstanceLimits represents the list of instance-related attributes that
    are available for a given InstanceType.
    """

    InstanceCountLimits: Optional[InstanceCountLimits]


class StorageTypeLimit(TypedDict, total=False):
    """Limits that are applicable for the given storage type."""

    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


StorageTypeLimitList = List[StorageTypeLimit]


class StorageType(TypedDict, total=False):
    """StorageTypes represents the list of storage-related types and their
    attributes that are available for a given InstanceType.
    """

    StorageTypeName: Optional[StorageTypeName]
    StorageSubTypeName: Optional[StorageSubTypeName]
    StorageTypeLimits: Optional[StorageTypeLimitList]


StorageTypeList = List[StorageType]


class Limits(TypedDict, total=False):
    """| Limits for a given InstanceType and for each of its roles.
    | Limits contains the following: ``StorageTypes``, ``InstanceLimits``,
      and ``AdditionalLimits``
    """

    StorageTypes: Optional[StorageTypeList]
    InstanceLimits: Optional[InstanceLimits]
    AdditionalLimits: Optional[AdditionalLimitList]


LimitsByRole = Dict[InstanceRole, Limits]


class DescribeInstanceTypeLimitsResponse(TypedDict, total=False):
    """Container for the parameters received from the
    ``DescribeInstanceTypeLimits`` operation.
    """

    LimitsByRole: Optional[LimitsByRole]


class DescribeOutboundConnectionsRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeOutboundConnections``
    operation.
    """

    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


OutboundConnections = List[OutboundConnection]


class DescribeOutboundConnectionsResponse(TypedDict, total=False):
    """The result of a ``DescribeOutboundConnections`` request. Contains the
    list of connections matching the filter criteria.
    """

    Connections: Optional[OutboundConnections]
    NextToken: Optional[NextToken]


DescribePackagesFilterValues = List[DescribePackagesFilterValue]


class DescribePackagesFilter(TypedDict, total=False):
    """A filter to apply to the ``DescribePackage`` response."""

    Name: Optional[DescribePackagesFilterName]
    Value: Optional[DescribePackagesFilterValues]


DescribePackagesFilterList = List[DescribePackagesFilter]


class DescribePackagesRequest(ServiceRequest):
    """Container for the request parameters to the ``DescribePackage``
    operation.
    """

    Filters: Optional[DescribePackagesFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


PackageDetailsList = List[PackageDetails]


class DescribePackagesResponse(TypedDict, total=False):
    """Container for the response returned by the ``DescribePackages``
    operation.
    """

    PackageDetailsList: Optional[PackageDetailsList]
    NextToken: Optional[String]


class DescribeReservedInstanceOfferingsRequest(ServiceRequest):
    """Container for parameters to ``DescribeReservedInstanceOfferings``"""

    ReservedInstanceOfferingId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class RecurringCharge(TypedDict, total=False):
    """Contains the specific price and frequency of a recurring charges for a
    reserved OpenSearch instance, or for a reserved OpenSearch instance
    offering.
    """

    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedInstanceOffering(TypedDict, total=False):
    """Details of a reserved OpenSearch instance offering."""

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
    """Container for results from ``DescribeReservedInstanceOfferings``"""

    NextToken: Optional[NextToken]
    ReservedInstanceOfferings: Optional[ReservedInstanceOfferingList]


class DescribeReservedInstancesRequest(ServiceRequest):
    """Container for parameters to ``DescribeReservedInstances``"""

    ReservedInstanceId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


Long = int


class ReservedInstance(TypedDict, total=False):
    """Details of a reserved OpenSearch instance."""

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
    """Container for results from ``DescribeReservedInstances``"""

    NextToken: Optional[String]
    ReservedInstances: Optional[ReservedInstanceList]


class DissociatePackageRequest(ServiceRequest):
    """Container for the request parameters to the ``DissociatePackage``
    operation.
    """

    PackageID: PackageID
    DomainName: DomainName


class DissociatePackageResponse(TypedDict, total=False):
    """Container for the response returned by ``DissociatePackage`` operation."""

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
    """Container for the request parameters to ``GetCompatibleVersions``
    operation.
    """

    DomainName: Optional[DomainName]


class GetCompatibleVersionsResponse(TypedDict, total=False):
    """Container for the response returned by the ``GetCompatibleVersions``
    operation.
    """

    CompatibleVersions: Optional[CompatibleVersionsList]


class GetPackageVersionHistoryRequest(ServiceRequest):
    """Container for the request parameters to the ``GetPackageVersionHistory``
    operation.
    """

    PackageID: PackageID
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class PackageVersionHistory(TypedDict, total=False):
    """Details of a package version."""

    PackageVersion: Optional[PackageVersion]
    CommitMessage: Optional[CommitMessage]
    CreatedAt: Optional[CreatedAt]


PackageVersionHistoryList = List[PackageVersionHistory]


class GetPackageVersionHistoryResponse(TypedDict, total=False):
    """Container for response returned by ``GetPackageVersionHistory``
    operation.
    """

    PackageID: Optional[PackageID]
    PackageVersionHistoryList: Optional[PackageVersionHistoryList]
    NextToken: Optional[String]


class GetUpgradeHistoryRequest(ServiceRequest):
    """Container for the request parameters to the ``GetUpgradeHistory``
    operation.
    """

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


Issues = List[Issue]


class UpgradeStepItem(TypedDict, total=False):
    """Represents a single step of the upgrade or upgrade eligibility check
    workflow.
    """

    UpgradeStep: Optional[UpgradeStep]
    UpgradeStepStatus: Optional[UpgradeStatus]
    Issues: Optional[Issues]
    ProgressPercent: Optional[Double]


UpgradeStepsList = List[UpgradeStepItem]
StartTimestamp = datetime


class UpgradeHistory(TypedDict, total=False):
    """History of the last 10 upgrades and upgrade eligibility checks."""

    UpgradeName: Optional[UpgradeName]
    StartTimestamp: Optional[StartTimestamp]
    UpgradeStatus: Optional[UpgradeStatus]
    StepsList: Optional[UpgradeStepsList]


UpgradeHistoryList = List[UpgradeHistory]


class GetUpgradeHistoryResponse(TypedDict, total=False):
    """Container for the response returned by the ``GetUpgradeHistory``
    operation.
    """

    UpgradeHistories: Optional[UpgradeHistoryList]
    NextToken: Optional[String]


class GetUpgradeStatusRequest(ServiceRequest):
    """Container for the request parameters to the ``GetUpgradeStatus``
    operation.
    """

    DomainName: DomainName


class GetUpgradeStatusResponse(TypedDict, total=False):
    """Container for the response returned by the ``GetUpgradeStatus``
    operation.
    """

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
    """Container for the parameters to the ``ListDomainNames`` operation."""

    EngineType: Optional[EngineType]


class ListDomainNamesResponse(TypedDict, total=False):
    """The result of a ``ListDomainNames`` operation. Contains the names of all
    domains owned by this account and their respective engine types.
    """

    DomainNames: Optional[DomainInfoList]


class ListDomainsForPackageRequest(ServiceRequest):
    """Container for the request parameters to the ``ListDomainsForPackage``
    operation.
    """

    PackageID: PackageID
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDomainsForPackageResponse(TypedDict, total=False):
    """Container for the response parameters to the ``ListDomainsForPackage``
    operation.
    """

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
    """Container for the request parameters to the ``ListPackagesForDomain``
    operation.
    """

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListPackagesForDomainResponse(TypedDict, total=False):
    """Container for the response parameters to the ``ListPackagesForDomain``
    operation.
    """

    DomainPackageDetailsList: Optional[DomainPackageDetailsList]
    NextToken: Optional[String]


class ListTagsRequest(ServiceRequest):
    """Container for the parameters to the ``ListTags`` operation. Specify the
    ``ARN`` of the domain that the tags you want to view are attached to.
    """

    ARN: ARN


class ListTagsResponse(TypedDict, total=False):
    """The result of a ``ListTags`` operation. Contains tags for all requested
    domains.
    """

    TagList: Optional[TagList]


class ListVersionsRequest(ServiceRequest):
    """Container for the parameters to the ``ListVersions`` operation.

    Use ``MaxResults`` to control the maximum number of results to retrieve
    in a single call.

    Use ``NextToken`` in response to retrieve more results. If the received
    response does not contain a NextToken, there are no more results to
    retrieve.
    """

    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListVersionsResponse(TypedDict, total=False):
    """Container for the parameters for response received from the
    ``ListVersions`` operation.
    """

    Versions: Optional[VersionList]
    NextToken: Optional[NextToken]


class PurchaseReservedInstanceOfferingRequest(ServiceRequest):
    """Container for parameters to ``PurchaseReservedInstanceOffering``"""

    ReservedInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: Optional[InstanceCount]


class PurchaseReservedInstanceOfferingResponse(TypedDict, total=False):
    """Represents the output of a ``PurchaseReservedInstanceOffering``
    operation.
    """

    ReservedInstanceId: Optional[GUID]
    ReservationName: Optional[ReservationToken]


class RejectInboundConnectionRequest(ServiceRequest):
    """Container for the parameters to the ``RejectInboundConnection``
    operation.
    """

    ConnectionId: ConnectionId


class RejectInboundConnectionResponse(TypedDict, total=False):
    """The result of a ``RejectInboundConnection`` operation. Contains details
    about the rejected inbound connection.
    """

    Connection: Optional[InboundConnection]


class RemoveTagsRequest(ServiceRequest):
    """Container for the parameters to the ``RemoveTags`` operation. Specify
    the ``ARN`` for the domain from which you want to remove the specified
    ``TagKey``.
    """

    ARN: ARN
    TagKeys: StringList


class StartServiceSoftwareUpdateRequest(ServiceRequest):
    """Container for the parameters to the ``StartServiceSoftwareUpdate``
    operation. Specifies the name of the domain to schedule a service
    software update for.
    """

    DomainName: DomainName


class StartServiceSoftwareUpdateResponse(TypedDict, total=False):
    """The result of a ``StartServiceSoftwareUpdate`` operation. Contains the
    status of the update.
    """

    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class UpdateDomainConfigRequest(ServiceRequest):
    """Container for the parameters to the ``UpdateDomain`` operation.
    Specifies the type and number of instances in the domain cluster.
    """

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
    """The result of an ``UpdateDomain`` request. Contains the status of the
    domain being updated.
    """

    DomainConfig: DomainConfig
    DryRunResults: Optional[DryRunResults]


class UpdatePackageRequest(ServiceRequest):
    """Container for request parameters to the ``UpdatePackage`` operation."""

    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: Optional[PackageDescription]
    CommitMessage: Optional[CommitMessage]


class UpdatePackageResponse(TypedDict, total=False):
    """Container for the response returned by the ``UpdatePackage`` operation."""

    PackageDetails: Optional[PackageDetails]


class UpgradeDomainRequest(ServiceRequest):
    """Container for the request parameters to ``UpgradeDomain`` operation."""

    DomainName: DomainName
    TargetVersion: VersionString
    PerformCheckOnly: Optional[Boolean]
    AdvancedOptions: Optional[AdvancedOptions]


class UpgradeDomainResponse(TypedDict, total=False):
    """Container for response returned by ``UpgradeDomain`` operation."""

    UpgradeId: Optional[String]
    DomainName: Optional[DomainName]
    TargetVersion: Optional[VersionString]
    PerformCheckOnly: Optional[Boolean]
    AdvancedOptions: Optional[AdvancedOptions]


class OpensearchApi:

    service = "opensearch"
    version = "2021-01-01"

    @handler("AcceptInboundConnection")
    def accept_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> AcceptInboundConnectionResponse:
        """Allows the remote domain owner to accept an inbound cross-cluster
        connection request.

        :param connection_id: The ID of the inbound connection you want to accept.
        :returns: AcceptInboundConnectionResponse
        :raises ResourceNotFoundException:
        :raises LimitExceededException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        """Attaches tags to an existing domain. Tags are a set of case-sensitive
        key value pairs. An domain can have up to 10 tags. See `Tagging Amazon
        OpenSearch Service
        domains <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains.html#managedomains-awsresorcetagging>`__
        for more information.

        :param arn: Specify the ``ARN`` of the domain you want to add tags to.
        :param tag_list: List of ``Tag`` to add to the domain.
        :raises BaseException:
        :raises LimitExceededException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("AssociatePackage")
    def associate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> AssociatePackageResponse:
        """Associates a package with an Amazon OpenSearch Service domain.

        :param package_id: Internal ID of the package to associate with a domain.
        :param domain_name: The name of the domain to associate the package with.
        :returns: AssociatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("CancelServiceSoftwareUpdate")
    def cancel_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> CancelServiceSoftwareUpdateResponse:
        """Cancels a scheduled service software update for an Amazon OpenSearch
        Service domain. You can only perform this operation before the
        ``AutomatedUpdateDate`` and when the ``UpdateStatus`` is in the
        ``PENDING_UPDATE`` state.

        :param domain_name: The name of the domain that you want to stop the latest service software
        update on.
        :returns: CancelServiceSoftwareUpdateResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
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
        """Creates a new Amazon OpenSearch Service domain. For more information,
        see `Creating and managing Amazon OpenSearch Service
        domains <http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html>`__
        in the *Amazon OpenSearch Service Developer Guide*.

        :param domain_name: The name of the Amazon OpenSearch Service domain you're creating.
        :param engine_version: String of format Elasticsearch_X.
        :param cluster_config: Configuration options for a domain.
        :param ebs_options: Options to enable, disable, and specify the type and size of EBS storage
        volumes.
        :param access_policies: IAM access policy as a JSON-formatted string.
        :param snapshot_options: Option to set time, in UTC format, of the daily automated snapshot.
        :param vpc_options: Options to specify the subnets and security groups for a VPC endpoint.
        :param cognito_options: Options to specify the Cognito user and identity pools for OpenSearch
        Dashboards authentication.
        :param encryption_at_rest_options: Options for encryption of data at rest.
        :param node_to_node_encryption_options: Node-to-node encryption options.
        :param advanced_options: Option to allow references to indices in an HTTP request body.
        :param log_publishing_options: Map of ``LogType`` and ``LogPublishingOption``, each containing options
        to publish a given type of OpenSearch log.
        :param domain_endpoint_options: Options to specify configurations that will be applied to the domain
        endpoint.
        :param advanced_security_options: Specifies advanced security options.
        :param tag_list: A list of ``Tag`` added during domain creation.
        :param auto_tune_options: Specifies Auto-Tune options.
        :returns: CreateDomainResponse
        :raises BaseException:
        :raises DisabledOperationException:
        :raises InternalException:
        :raises InvalidTypeException:
        :raises LimitExceededException:
        :raises ResourceAlreadyExistsException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("CreateOutboundConnection")
    def create_outbound_connection(
        self,
        context: RequestContext,
        local_domain_info: DomainInformationContainer,
        remote_domain_info: DomainInformationContainer,
        connection_alias: ConnectionAlias,
    ) -> CreateOutboundConnectionResponse:
        """Creates a new cross-cluster connection from a local OpenSearch domain to
        a remote OpenSearch domain.

        :param local_domain_info: The ``AWSDomainInformation`` for the local OpenSearch domain.
        :param remote_domain_info: The ``AWSDomainInformation`` for the remote OpenSearch domain.
        :param connection_alias: The connection alias used used by the customer for this cross-cluster
        connection.
        :returns: CreateOutboundConnectionResponse
        :raises LimitExceededException:
        :raises InternalException:
        :raises ResourceAlreadyExistsException:
        :raises DisabledOperationException:
        """
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
        """Create a package for use with Amazon OpenSearch Service domains.

        :param package_name: Unique identifier for the package.
        :param package_type: Type of package.
        :param package_source: The Amazon S3 location from which to import the package.
        :param package_description: Description of the package.
        :returns: CreatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises LimitExceededException:
        :raises InvalidTypeException:
        :raises ResourceAlreadyExistsException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DeleteDomain")
    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        """Permanently deletes the specified domain and all of its data. Once a
        domain is deleted, it cannot be recovered.

        :param domain_name: The name of the domain you want to permanently delete.
        :returns: DeleteDomainResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DeleteInboundConnection")
    def delete_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> DeleteInboundConnectionResponse:
        """Allows the remote domain owner to delete an existing inbound
        cross-cluster connection.

        :param connection_id: The ID of the inbound connection to permanently delete.
        :returns: DeleteInboundConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DeleteOutboundConnection")
    def delete_outbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> DeleteOutboundConnectionResponse:
        """Allows the local domain owner to delete an existing outbound
        cross-cluster connection.

        :param connection_id: The ID of the outbound connection you want to permanently delete.
        :returns: DeleteOutboundConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DeletePackage")
    def delete_package(
        self, context: RequestContext, package_id: PackageID
    ) -> DeletePackageResponse:
        """Deletes the package.

        :param package_id: The internal ID of the package you want to delete.
        :returns: DeletePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("DescribeDomain")
    def describe_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainResponse:
        """Returns domain configuration information about the specified domain,
        including the domain ID, domain endpoint, and domain ARN.

        :param domain_name: The name of the domain for which you want information.
        :returns: DescribeDomainResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeDomainAutoTunes")
    def describe_domain_auto_tunes(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeDomainAutoTunesResponse:
        """Provides scheduled Auto-Tune action details for the domain, such as
        Auto-Tune action type, description, severity, and scheduled date.

        :param domain_name: The domain name for which you want Auto-Tune action details.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken is sent in case the earlier API call results contain the
        NextToken.
        :returns: DescribeDomainAutoTunesResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeDomainConfig")
    def describe_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainConfigResponse:
        """Provides cluster configuration information about the specified domain,
        such as the state, creation date, update version, and update date for
        cluster options.

        :param domain_name: The domain you want to get information about.
        :returns: DescribeDomainConfigResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeDomains")
    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeDomainsResponse:
        """Returns domain configuration information about the specified domains,
        including the domain ID, domain endpoint, and domain ARN.

        :param domain_names: The domains for which you want information.
        :returns: DescribeDomainsResponse
        :raises BaseException:
        :raises InternalException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeInboundConnections")
    def describe_inbound_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeInboundConnectionsResponse:
        """Lists all the inbound cross-cluster connections for a remote domain.

        :param filters: A list of filters used to match properties for inbound cross-cluster
        connections.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: If more results are available and NextToken is present, make the next
        request to the same API with the received NextToken to paginate the
        remaining results.
        :returns: DescribeInboundConnectionsResponse
        :raises InvalidPaginationTokenException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DescribeInstanceTypeLimits")
    def describe_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: OpenSearchPartitionInstanceType,
        engine_version: VersionString,
        domain_name: DomainName = None,
    ) -> DescribeInstanceTypeLimitsResponse:
        """Describe the limits for a given instance type and OpenSearch or
        Elasticsearch version. When modifying an existing domain, specify the
        ``DomainName`` to see which limits you can modify.

        :param instance_type: The instance type for an OpenSearch cluster for which OpenSearch
        ``Limits`` are needed.
        :param engine_version: Version of OpenSearch for which ``Limits`` are needed.
        :param domain_name: The name of the domain you want to modify.
        :returns: DescribeInstanceTypeLimitsResponse
        :raises BaseException:
        :raises InternalException:
        :raises InvalidTypeException:
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeOutboundConnections")
    def describe_outbound_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeOutboundConnectionsResponse:
        """Lists all the outbound cross-cluster connections for a local domain.

        :param filters: A list of filters used to match properties for outbound cross-cluster
        connections.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken is sent in case the earlier API call results contain the
        NextToken parameter.
        :returns: DescribeOutboundConnectionsResponse
        :raises InvalidPaginationTokenException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DescribePackages")
    def describe_packages(
        self,
        context: RequestContext,
        filters: DescribePackagesFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribePackagesResponse:
        """Describes all packages available to Amazon OpenSearch Service domains.
        Includes options for filtering, limiting the number of results, and
        pagination.

        :param filters: Only returns packages that match the ``DescribePackagesFilterList``
        values.
        :param max_results: Limits results to a maximum number of packages.
        :param next_token: Used for pagination.
        :returns: DescribePackagesResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeReservedInstanceOfferings")
    def describe_reserved_instance_offerings(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedInstanceOfferingsResponse:
        """Lists available reserved OpenSearch instance offerings.

        :param reserved_instance_offering_id: The offering identifier filter value.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Provides an identifier to allow retrieval of paginated results.
        :returns: DescribeReservedInstanceOfferingsResponse
        :raises ResourceNotFoundException:
        :raises ValidationException:
        :raises DisabledOperationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeReservedInstances")
    def describe_reserved_instances(
        self,
        context: RequestContext,
        reserved_instance_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedInstancesResponse:
        """Returns information about reserved OpenSearch instances for this
        account.

        :param reserved_instance_id: The reserved instance identifier filter value.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Provides an identifier to allow retrieval of paginated results.
        :returns: DescribeReservedInstancesResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises ValidationException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DissociatePackage")
    def dissociate_package(
        self, context: RequestContext, package_id: PackageID, domain_name: DomainName
    ) -> DissociatePackageResponse:
        """Dissociates a package from the Amazon OpenSearch Service domain.

        :param package_id: The internal ID of the package to associate with a domain.
        :param domain_name: The name of the domain to associate the package with.
        :returns: DissociatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("GetCompatibleVersions")
    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleVersionsResponse:
        """Returns a list of upgrade-compatible versions of
        OpenSearch/Elasticsearch. You can optionally pass a ``DomainName`` to
        get all upgrade-compatible versions of OpenSearch/Elasticsearch for that
        specific domain.

        :param domain_name: The name of an domain.
        :returns: GetCompatibleVersionsResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("GetPackageVersionHistory")
    def get_package_version_history(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetPackageVersionHistoryResponse:
        """Returns a list of package versions, along with their creation time and
        commit message.

        :param package_id: Returns an audit history of package versions.
        :param max_results: Limits results to a maximum number of package versions.
        :param next_token: Used for pagination.
        :returns: GetPackageVersionHistoryResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("GetUpgradeHistory")
    def get_upgrade_history(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetUpgradeHistoryResponse:
        """Retrieves the complete history of the last 10 upgrades performed on the
        domain.

        :param domain_name: The name of an domain.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Paginated APIs accept the NextToken input to return the next page of
        results and provide a NextToken output in the response, which you can
        use to retrieve more results.
        :returns: GetUpgradeHistoryResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("GetUpgradeStatus")
    def get_upgrade_status(
        self, context: RequestContext, domain_name: DomainName
    ) -> GetUpgradeStatusResponse:
        """Retrieves the latest status of the last upgrade or upgrade eligibility
        check performed on the domain.

        :param domain_name: The name of an domain.
        :returns: GetUpgradeStatusResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListDomainNames")
    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        """Returns the names of all domains owned by the current user's account.

        :param engine_type: Optional parameter to filter the output by domain engine type.
        :returns: ListDomainNamesResponse
        :raises BaseException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("ListDomainsForPackage")
    def list_domains_for_package(
        self,
        context: RequestContext,
        package_id: PackageID,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDomainsForPackageResponse:
        """Lists all Amazon OpenSearch Service domains associated with the package.

        :param package_id: The package for which to list associated domains.
        :param max_results: Limits the results to a maximum number of domains.
        :param next_token: Used for pagination.
        :returns: ListDomainsForPackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
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
        """

        :param engine_version: .
        :param domain_name: The name of an domain.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Paginated APIs accept the NextToken input to return the next page of
        results and provide a NextToken output in the response, which you can
        use to retrieve more results.
        :returns: ListInstanceTypeDetailsResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("ListPackagesForDomain")
    def list_packages_for_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListPackagesForDomainResponse:
        """Lists all packages associated with the Amazon OpenSearch Service domain.

        :param domain_name: The name of the domain for which you want to list associated packages.
        :param max_results: Limits results to a maximum number of packages.
        :param next_token: Used for pagination.
        :returns: ListPackagesForDomainResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, arn: ARN) -> ListTagsResponse:
        """Returns all tags for the given domain.

        :param arn: Specify the ``ARN`` of the domain that the tags you want to view are
        attached to.
        :returns: ListTagsResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListVersions")
    def list_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListVersionsResponse:
        """List all supported versions of OpenSearch and Elasticsearch.

        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Paginated APIs accept the NextToken input to return the next page of
        results and provide a NextToken output in the response, which you can
        use to retrieve more results.
        :returns: ListVersionsResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("PurchaseReservedInstanceOffering")
    def purchase_reserved_instance_offering(
        self,
        context: RequestContext,
        reserved_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount = None,
    ) -> PurchaseReservedInstanceOfferingResponse:
        """Allows you to purchase reserved OpenSearch instances.

        :param reserved_instance_offering_id: The ID of the reserved OpenSearch instance offering to purchase.
        :param reservation_name: A customer-specified identifier to track this reservation.
        :param instance_count: The number of OpenSearch instances to reserve.
        :returns: PurchaseReservedInstanceOfferingResponse
        :raises ResourceNotFoundException:
        :raises ResourceAlreadyExistsException:
        :raises LimitExceededException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("RejectInboundConnection")
    def reject_inbound_connection(
        self, context: RequestContext, connection_id: ConnectionId
    ) -> RejectInboundConnectionResponse:
        """Allows the remote domain owner to reject an inbound cross-cluster
        connection request.

        :param connection_id: The ID of the inbound connection to reject.
        :returns: RejectInboundConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        """Removes the specified set of tags from the given domain.

        :param arn: The ``ARN`` of the domain from which you want to delete the specified
        tags.
        :param tag_keys: The ``TagKey`` list you want to remove from the domain.
        :raises BaseException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("StartServiceSoftwareUpdate")
    def start_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> StartServiceSoftwareUpdateResponse:
        """Schedules a service software update for an Amazon OpenSearch Service
        domain.

        :param domain_name: The name of the domain that you want to update to the latest service
        software.
        :returns: StartServiceSoftwareUpdateResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
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
        """Modifies the cluster configuration of the specified domain, such as
        setting the instance type and the number of instances.

        :param domain_name: The name of the domain you're updating.
        :param cluster_config: The type and number of instances to instantiate for the domain cluster.
        :param ebs_options: Specify the type and size of the EBS volume to use.
        :param snapshot_options: Option to set the time, in UTC format, for the daily automated snapshot.
        :param vpc_options: Options to specify the subnets and security groups for the VPC endpoint.
        :param cognito_options: Options to specify the Cognito user and identity pools for OpenSearch
        Dashboards authentication.
        :param advanced_options: Modifies the advanced option to allow references to indices in an HTTP
        request body.
        :param access_policies: IAM access policy as a JSON-formatted string.
        :param log_publishing_options: Map of ``LogType`` and ``LogPublishingOption``, each containing options
        to publish a given type of OpenSearch log.
        :param encryption_at_rest_options: Specifies encryption of data at rest options.
        :param domain_endpoint_options: Options to specify configuration that will be applied to the domain
        endpoint.
        :param node_to_node_encryption_options: Specifies node-to-node encryption options.
        :param advanced_security_options: Specifies advanced security options.
        :param auto_tune_options: Specifies Auto-Tune options.
        :param dry_run: This flag, when set to True, specifies whether the ``UpdateDomain``
        request should return the results of validation checks (DryRunResults)
        without actually applying the change.
        :returns: UpdateDomainConfigResponse
        :raises BaseException:
        :raises InternalException:
        :raises InvalidTypeException:
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
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
        """Updates a package for use with Amazon OpenSearch Service domains.

        :param package_id: The unique identifier for the package.
        :param package_source: The Amazon S3 location for importing the package specified as
        ``S3BucketName`` and ``S3Key``.
        :param package_description: A new description of the package.
        :param commit_message: A commit message for the new version which is shown as part of
        ``GetPackageVersionHistoryResponse``.
        :returns: UpdatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
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
        """Allows you to either upgrade your domain or perform an upgrade
        eligibility check to a compatible version of OpenSearch or
        Elasticsearch.

        :param domain_name: The name of an domain.
        :param target_version: The version of OpenSearch you intend to upgrade the domain to.
        :param perform_check_only: When true, indicates that an upgrade eligibility check needs to be
        performed.
        :param advanced_options: Exposes select native OpenSearch configuration values from
        ``opensearch.
        :returns: UpgradeDomainResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises ResourceAlreadyExistsException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError
