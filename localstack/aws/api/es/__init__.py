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
CrossClusterSearchConnectionId = str
CrossClusterSearchConnectionStatusMessage = str
DeploymentType = str
DescribePackagesFilterValue = str
DomainId = str
DomainName = str
DomainNameFqdn = str
Double = float
DryRun = bool
ElasticsearchVersionString = str
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


class AcceptInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    """Container for the parameters to the
    ``AcceptInboundCrossClusterSearchConnection`` operation.
    """

    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class InboundCrossClusterSearchConnectionStatus(TypedDict, total=False):
    """Specifies the coonection status of an inbound cross-cluster search
    connection.
    """

    StatusCode: Optional[InboundCrossClusterSearchConnectionStatusCode]
    Message: Optional[CrossClusterSearchConnectionStatusMessage]


class DomainInformation(TypedDict, total=False):
    OwnerId: Optional[OwnerId]
    DomainName: DomainName
    Region: Optional[Region]


class InboundCrossClusterSearchConnection(TypedDict, total=False):
    """Specifies details of an inbound connection."""

    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]
    ConnectionStatus: Optional[InboundCrossClusterSearchConnectionStatus]


class AcceptInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    """The result of a ``AcceptInboundCrossClusterSearchConnection`` operation.
    Contains details of accepted inbound connection.
    """

    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


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
    """Specifies a key value pair for a resource tag."""

    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class AddTagsRequest(ServiceRequest):
    """Container for the parameters to the ``AddTags`` operation. Specify the
    tags that you want to attach to the Elasticsearch domain.
    """

    ARN: ARN
    TagList: TagList


LimitValueList = List[LimitValue]


class AdditionalLimit(TypedDict, total=False):
    """List of limits that are specific to a given InstanceType and for each of
    it's ``InstanceRole`` .
    """

    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


AdditionalLimitList = List[AdditionalLimit]
AdvancedOptions = Dict[String, String]


class AdvancedOptionsStatus(TypedDict, total=False):
    """Status of the advanced options for the specified Elasticsearch domain.
    Currently, the following advanced options are available:

    -  Option to allow references to indices in an HTTP request body. Must
       be ``false`` when configuring access to individual sub-resources. By
       default, the value is ``true``. See `Configuration Advanced
       Options <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options>`__
       for more information.
    -  Option to specify the percentage of heap space that is allocated to
       field data. By default, this setting is unbounded.

    For more information, see `Configuring Advanced
    Options <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options>`__.
    """

    Options: AdvancedOptions
    Status: OptionStatus


DisableTimestamp = datetime


class SAMLIdp(TypedDict, total=False):
    """Specifies the SAML Identity Provider's information."""

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
    """Specifies the advanced security configuration: whether advanced security
    is enabled, whether the internal database option is enabled.
    """

    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    SAMLOptions: Optional[SAMLOptionsOutput]
    AnonymousAuthDisableDate: Optional[DisableTimestamp]
    AnonymousAuthEnabled: Optional[Boolean]


class SAMLOptionsInput(TypedDict, total=False):
    """Specifies the SAML application configuration for the domain."""

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
    """Specifies the advanced security configuration: whether advanced security
    is enabled, whether the internal database option is enabled, master
    username and password (if internal database is enabled), and master user
    ARN (if IAM is enabled).
    """

    Enabled: Optional[Boolean]
    InternalUserDatabaseEnabled: Optional[Boolean]
    MasterUserOptions: Optional[MasterUserOptions]
    SAMLOptions: Optional[SAMLOptionsInput]
    AnonymousAuthEnabled: Optional[Boolean]


class AdvancedSecurityOptionsStatus(TypedDict, total=False):
    """Specifies the status of advanced security options for the specified
    Elasticsearch domain.
    """

    Options: AdvancedSecurityOptions
    Status: OptionStatus


class AssociatePackageRequest(ServiceRequest):
    """Container for request parameters to ``AssociatePackage`` operation."""

    PackageID: PackageID
    DomainName: DomainName


class ErrorDetails(TypedDict, total=False):
    ErrorType: Optional[ErrorType]
    ErrorMessage: Optional[ErrorMessage]


LastUpdated = datetime


class DomainPackageDetails(TypedDict, total=False):
    """Information on a package that is associated with a domain."""

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
    """Container for response returned by ``AssociatePackage`` operation."""

    DomainPackageDetails: Optional[DomainPackageDetails]


AutoTuneDate = datetime


class ScheduledAutoTuneDetails(TypedDict, total=False):
    """Specifies details of the scheduled Auto-Tune action. See the `Developer
    Guide <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    Date: Optional[AutoTuneDate]
    ActionType: Optional[ScheduledAutoTuneActionType]
    Action: Optional[ScheduledAutoTuneDescription]
    Severity: Optional[ScheduledAutoTuneSeverityType]


class AutoTuneDetails(TypedDict, total=False):
    """Specifies details of the Auto-Tune action. See the `Developer
    Guide <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    ScheduledAutoTuneDetails: Optional[ScheduledAutoTuneDetails]


class AutoTune(TypedDict, total=False):
    """Specifies Auto-Tune type and Auto-Tune action details."""

    AutoTuneType: Optional[AutoTuneType]
    AutoTuneDetails: Optional[AutoTuneDetails]


AutoTuneList = List[AutoTune]
DurationValue = int


class Duration(TypedDict, total=False):
    """Specifies maintenance schedule duration: duration value and duration
    unit. See the `Developer
    Guide <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    Value: Optional[DurationValue]
    Unit: Optional[TimeUnit]


StartAt = datetime


class AutoTuneMaintenanceSchedule(TypedDict, total=False):
    """Specifies Auto-Tune maitenance schedule. See the `Developer
    Guide <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    StartAt: Optional[StartAt]
    Duration: Optional[Duration]
    CronExpressionForRecurrence: Optional[String]


AutoTuneMaintenanceScheduleList = List[AutoTuneMaintenanceSchedule]


class AutoTuneOptions(TypedDict, total=False):
    """Specifies the Auto-Tune options: the Auto-Tune desired state for the
    domain, rollback state when disabling Auto-Tune options and list of
    maintenance schedules.
    """

    DesiredState: Optional[AutoTuneDesiredState]
    RollbackOnDisable: Optional[RollbackOnDisable]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsInput(TypedDict, total=False):
    """Specifies the Auto-Tune options: the Auto-Tune desired state for the
    domain and list of maintenance schedules.
    """

    DesiredState: Optional[AutoTuneDesiredState]
    MaintenanceSchedules: Optional[AutoTuneMaintenanceScheduleList]


class AutoTuneOptionsOutput(TypedDict, total=False):
    """Specifies the Auto-Tune options: the Auto-Tune desired state for the
    domain and list of maintenance schedules.
    """

    State: Optional[AutoTuneState]
    ErrorMessage: Optional[String]


class AutoTuneStatus(TypedDict, total=False):
    """Provides the current status of the Auto-Tune options."""

    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: AutoTuneState
    ErrorMessage: Optional[String]
    PendingDeletion: Optional[Boolean]


class AutoTuneOptionsStatus(TypedDict, total=False):
    """Specifies the status of Auto-Tune options for the specified
    Elasticsearch domain.
    """

    Options: Optional[AutoTuneOptions]
    Status: Optional[AutoTuneStatus]


class CancelElasticsearchServiceSoftwareUpdateRequest(ServiceRequest):
    """Container for the parameters to the
    ``CancelElasticsearchServiceSoftwareUpdate`` operation. Specifies the
    name of the Elasticsearch domain that you wish to cancel a service
    software update on.
    """

    DomainName: DomainName


DeploymentCloseDateTimeStamp = datetime


class ServiceSoftwareOptions(TypedDict, total=False):
    """The current options of an Elasticsearch domain service software options."""

    CurrentVersion: Optional[String]
    NewVersion: Optional[String]
    UpdateAvailable: Optional[Boolean]
    Cancellable: Optional[Boolean]
    UpdateStatus: Optional[DeploymentStatus]
    Description: Optional[String]
    AutomatedUpdateDate: Optional[DeploymentCloseDateTimeStamp]
    OptionalDeployment: Optional[Boolean]


class CancelElasticsearchServiceSoftwareUpdateResponse(TypedDict, total=False):
    """The result of a ``CancelElasticsearchServiceSoftwareUpdate`` operation.
    Contains the status of the update.
    """

    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class CognitoOptions(TypedDict, total=False):
    """Options to specify the Cognito user and identity pools for Kibana
    authentication. For more information, see `Amazon Cognito Authentication
    for
    Kibana <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html>`__.
    """

    Enabled: Optional[Boolean]
    UserPoolId: Optional[UserPoolId]
    IdentityPoolId: Optional[IdentityPoolId]
    RoleArn: Optional[RoleArn]


class CognitoOptionsStatus(TypedDict, total=False):
    """Status of the Cognito options for the specified Elasticsearch domain."""

    Options: CognitoOptions
    Status: OptionStatus


class ColdStorageOptions(TypedDict, total=False):
    """Specifies the configuration for cold storage options such as enabled"""

    Enabled: Boolean


ElasticsearchVersionList = List[ElasticsearchVersionString]


class CompatibleVersionsMap(TypedDict, total=False):
    """A map from an ``ElasticsearchVersion`` to a list of compatible
    ``ElasticsearchVersion`` s to which the domain can be upgraded.
    """

    SourceVersion: Optional[ElasticsearchVersionString]
    TargetVersions: Optional[ElasticsearchVersionList]


CompatibleElasticsearchVersionsList = List[CompatibleVersionsMap]


class DomainEndpointOptions(TypedDict, total=False):
    """Options to configure endpoint for the Elasticsearch domain."""

    EnforceHTTPS: Optional[Boolean]
    TLSSecurityPolicy: Optional[TLSSecurityPolicy]
    CustomEndpointEnabled: Optional[Boolean]
    CustomEndpoint: Optional[DomainNameFqdn]
    CustomEndpointCertificateArn: Optional[ARN]


class LogPublishingOption(TypedDict, total=False):
    """| Log Publishing option that is set for given domain.
    | Attributes and their details:

    -  CloudWatchLogsLogGroupArn: ARN of the Cloudwatch log group to which
       log needs to be published.
    -  Enabled: Whether the log publishing for given log type is enabled or
       not
    """

    CloudWatchLogsLogGroupArn: Optional[CloudWatchLogsLogGroupArn]
    Enabled: Optional[Boolean]


LogPublishingOptions = Dict[LogType, LogPublishingOption]


class NodeToNodeEncryptionOptions(TypedDict, total=False):
    """Specifies the node-to-node encryption options."""

    Enabled: Optional[Boolean]


class EncryptionAtRestOptions(TypedDict, total=False):
    """Specifies the Encryption At Rest Options."""

    Enabled: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]


StringList = List[String]


class VPCOptions(TypedDict, total=False):
    """Options to specify the subnets and security groups for VPC endpoint. For
    more information, see `VPC Endpoints for Amazon Elasticsearch Service
    Domains <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html>`__.
    """

    SubnetIds: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


class SnapshotOptions(TypedDict, total=False):
    """Specifies the time, in UTC format, when the service takes a daily
    automated snapshot of the specified Elasticsearch domain. Default value
    is ``0`` hours.
    """

    AutomatedSnapshotStartHour: Optional[IntegerClass]


class EBSOptions(TypedDict, total=False):
    """Options to enable, disable, and specify the properties of EBS storage
    volumes. For more information, see `Configuring EBS-based
    Storage <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs>`__.
    """

    EBSEnabled: Optional[Boolean]
    VolumeType: Optional[VolumeType]
    VolumeSize: Optional[IntegerClass]
    Iops: Optional[IntegerClass]


class ZoneAwarenessConfig(TypedDict, total=False):
    """Specifies the zone awareness configuration for the domain cluster, such
    as the number of availability zones.
    """

    AvailabilityZoneCount: Optional[IntegerClass]


class ElasticsearchClusterConfig(TypedDict, total=False):
    """Specifies the configuration for the domain cluster, such as the type and
    number of instances.
    """

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
    """Options to specify the subnets and security groups for VPC endpoint. For
    more information, see `VPC Endpoints for Amazon Elasticsearch Service
    Domains <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html>`__.
    """

    VPCId: Optional[String]
    SubnetIds: Optional[StringList]
    AvailabilityZones: Optional[StringList]
    SecurityGroupIds: Optional[StringList]


EndpointsMap = Dict[String, ServiceUrl]


class ElasticsearchDomainStatus(TypedDict, total=False):
    """The current status of an Elasticsearch domain."""

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


class CreateElasticsearchDomainResponse(TypedDict, total=False):
    """The result of a ``CreateElasticsearchDomain`` operation. Contains the
    status of the newly created Elasticsearch domain.
    """

    DomainStatus: Optional[ElasticsearchDomainStatus]


class CreateOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    """Container for the parameters to the
    ``CreateOutboundCrossClusterSearchConnection`` operation.
    """

    SourceDomainInfo: DomainInformation
    DestinationDomainInfo: DomainInformation
    ConnectionAlias: ConnectionAlias


class OutboundCrossClusterSearchConnectionStatus(TypedDict, total=False):
    """Specifies the connection status of an outbound cross-cluster search
    connection.
    """

    StatusCode: Optional[OutboundCrossClusterSearchConnectionStatusCode]
    Message: Optional[CrossClusterSearchConnectionStatusMessage]


class CreateOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    """The result of a ``CreateOutboundCrossClusterSearchConnection`` request.
    Contains the details of the newly created cross-cluster search
    connection.
    """

    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundCrossClusterSearchConnectionStatus]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]


class PackageSource(TypedDict, total=False):
    """The S3 location for importing the package specified as ``S3BucketName``
    and ``S3Key``
    """

    S3BucketName: Optional[S3BucketName]
    S3Key: Optional[S3Key]


class CreatePackageRequest(ServiceRequest):
    """Container for request parameters to ``CreatePackage`` operation."""

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
    """Container for response returned by ``CreatePackage`` operation."""

    PackageDetails: Optional[PackageDetails]


class DeleteElasticsearchDomainRequest(ServiceRequest):
    """Container for the parameters to the ``DeleteElasticsearchDomain``
    operation. Specifies the name of the Elasticsearch domain that you want
    to delete.
    """

    DomainName: DomainName


class DeleteElasticsearchDomainResponse(TypedDict, total=False):
    """The result of a ``DeleteElasticsearchDomain`` request. Contains the
    status of the pending deletion, or no status if the domain and all of
    its resources have been deleted.
    """

    DomainStatus: Optional[ElasticsearchDomainStatus]


class DeleteInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    """Container for the parameters to the
    ``DeleteInboundCrossClusterSearchConnection`` operation.
    """

    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class DeleteInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    """The result of a ``DeleteInboundCrossClusterSearchConnection`` operation.
    Contains details of deleted inbound connection.
    """

    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


class DeleteOutboundCrossClusterSearchConnectionRequest(ServiceRequest):
    """Container for the parameters to the
    ``DeleteOutboundCrossClusterSearchConnection`` operation.
    """

    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class OutboundCrossClusterSearchConnection(TypedDict, total=False):
    """Specifies details of an outbound connection."""

    SourceDomainInfo: Optional[DomainInformation]
    DestinationDomainInfo: Optional[DomainInformation]
    CrossClusterSearchConnectionId: Optional[CrossClusterSearchConnectionId]
    ConnectionAlias: Optional[ConnectionAlias]
    ConnectionStatus: Optional[OutboundCrossClusterSearchConnectionStatus]


class DeleteOutboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    """The result of a ``DeleteOutboundCrossClusterSearchConnection``
    operation. Contains details of deleted outbound connection.
    """

    CrossClusterSearchConnection: Optional[OutboundCrossClusterSearchConnection]


class DeletePackageRequest(ServiceRequest):
    """Container for request parameters to ``DeletePackage`` operation."""

    PackageID: PackageID


class DeletePackageResponse(TypedDict, total=False):
    """Container for response parameters to ``DeletePackage`` operation."""

    PackageDetails: Optional[PackageDetails]


class DescribeDomainAutoTunesRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeDomainAutoTunes``
    operation.
    """

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeDomainAutoTunesResponse(TypedDict, total=False):
    """The result of ``DescribeDomainAutoTunes`` request. See the `Developer
    Guide <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html>`__
    for more information.
    """

    AutoTunes: Optional[AutoTuneList]
    NextToken: Optional[NextToken]


class DescribeElasticsearchDomainConfigRequest(ServiceRequest):
    """Container for the parameters to the
    ``DescribeElasticsearchDomainConfig`` operation. Specifies the domain
    name for which you want configuration information.
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
    """Status of the node-to-node encryption options for the specified
    Elasticsearch domain.
    """

    Options: NodeToNodeEncryptionOptions
    Status: OptionStatus


class EncryptionAtRestOptionsStatus(TypedDict, total=False):
    """Status of the Encryption At Rest options for the specified Elasticsearch
    domain.
    """

    Options: EncryptionAtRestOptions
    Status: OptionStatus


class VPCDerivedInfoStatus(TypedDict, total=False):
    """Status of the VPC options for the specified Elasticsearch domain."""

    Options: VPCDerivedInfo
    Status: OptionStatus


class SnapshotOptionsStatus(TypedDict, total=False):
    """Status of a daily automated snapshot."""

    Options: SnapshotOptions
    Status: OptionStatus


class EBSOptionsStatus(TypedDict, total=False):
    """Status of the EBS options for the specified Elasticsearch domain."""

    Options: EBSOptions
    Status: OptionStatus


class ElasticsearchClusterConfigStatus(TypedDict, total=False):
    """Specifies the configuration status for the specified Elasticsearch
    domain.
    """

    Options: ElasticsearchClusterConfig
    Status: OptionStatus


class ElasticsearchVersionStatus(TypedDict, total=False):
    """Status of the Elasticsearch version options for the specified
    Elasticsearch domain.
    """

    Options: ElasticsearchVersionString
    Status: OptionStatus


class ElasticsearchDomainConfig(TypedDict, total=False):
    """The configuration of an Elasticsearch domain."""

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


class DescribeElasticsearchDomainConfigResponse(TypedDict, total=False):
    """The result of a ``DescribeElasticsearchDomainConfig`` request. Contains
    the configuration information of the requested domain.
    """

    DomainConfig: ElasticsearchDomainConfig


class DescribeElasticsearchDomainRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeElasticsearchDomain``
    operation.
    """

    DomainName: DomainName


class DescribeElasticsearchDomainResponse(TypedDict, total=False):
    """The result of a ``DescribeElasticsearchDomain`` request. Contains the
    status of the domain specified in the request.
    """

    DomainStatus: ElasticsearchDomainStatus


DomainNameList = List[DomainName]


class DescribeElasticsearchDomainsRequest(ServiceRequest):
    """Container for the parameters to the ``DescribeElasticsearchDomains``
    operation. By default, the API returns the status of all Elasticsearch
    domains.
    """

    DomainNames: DomainNameList


ElasticsearchDomainStatusList = List[ElasticsearchDomainStatus]


class DescribeElasticsearchDomainsResponse(TypedDict, total=False):
    """The result of a ``DescribeElasticsearchDomains`` request. Contains the
    status of the specified domains or all domains owned by the account.
    """

    DomainStatusList: ElasticsearchDomainStatusList


class DescribeElasticsearchInstanceTypeLimitsRequest(ServiceRequest):
    """Container for the parameters to
    ``DescribeElasticsearchInstanceTypeLimits`` operation.
    """

    DomainName: Optional[DomainName]
    InstanceType: ESPartitionInstanceType
    ElasticsearchVersion: ElasticsearchVersionString


class InstanceCountLimits(TypedDict, total=False):
    """InstanceCountLimits represents the limits on number of instances that be
    created in Amazon Elasticsearch for given InstanceType.
    """

    MinimumInstanceCount: Optional[MinimumInstanceCount]
    MaximumInstanceCount: Optional[MaximumInstanceCount]


class InstanceLimits(TypedDict, total=False):
    """InstanceLimits represents the list of instance related attributes that
    are available for given InstanceType.
    """

    InstanceCountLimits: Optional[InstanceCountLimits]


class StorageTypeLimit(TypedDict, total=False):
    """Limits that are applicable for given storage type."""

    LimitName: Optional[LimitName]
    LimitValues: Optional[LimitValueList]


StorageTypeLimitList = List[StorageTypeLimit]


class StorageType(TypedDict, total=False):
    """StorageTypes represents the list of storage related types and their
    attributes that are available for given InstanceType.
    """

    StorageTypeName: Optional[StorageTypeName]
    StorageSubTypeName: Optional[StorageSubTypeName]
    StorageTypeLimits: Optional[StorageTypeLimitList]


StorageTypeList = List[StorageType]


class Limits(TypedDict, total=False):
    """| Limits for given InstanceType and for each of it's role.
    | Limits contains following ``StorageTypes,`` ``InstanceLimits`` and
      ``AdditionalLimits``
    """

    StorageTypes: Optional[StorageTypeList]
    InstanceLimits: Optional[InstanceLimits]
    AdditionalLimits: Optional[AdditionalLimitList]


LimitsByRole = Dict[InstanceRole, Limits]


class DescribeElasticsearchInstanceTypeLimitsResponse(TypedDict, total=False):
    """Container for the parameters received from
    ``DescribeElasticsearchInstanceTypeLimits`` operation.
    """

    LimitsByRole: Optional[LimitsByRole]


ValueStringList = List[NonEmptyString]


class Filter(TypedDict, total=False):
    """A filter used to limit results when describing inbound or outbound
    cross-cluster search connections. Multiple values can be specified per
    filter. A cross-cluster search connection must match at least one of the
    specified values for it to be returned from an operation.
    """

    Name: Optional[NonEmptyString]
    Values: Optional[ValueStringList]


FilterList = List[Filter]


class DescribeInboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    """Container for the parameters to the
    ``DescribeInboundCrossClusterSearchConnections`` operation.
    """

    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


InboundCrossClusterSearchConnections = List[InboundCrossClusterSearchConnection]


class DescribeInboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    """The result of a ``DescribeInboundCrossClusterSearchConnections``
    request. Contains the list of connections matching the filter criteria.
    """

    CrossClusterSearchConnections: Optional[InboundCrossClusterSearchConnections]
    NextToken: Optional[NextToken]


class DescribeOutboundCrossClusterSearchConnectionsRequest(ServiceRequest):
    """Container for the parameters to the
    ``DescribeOutboundCrossClusterSearchConnections`` operation.
    """

    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


OutboundCrossClusterSearchConnections = List[OutboundCrossClusterSearchConnection]


class DescribeOutboundCrossClusterSearchConnectionsResponse(TypedDict, total=False):
    """The result of a ``DescribeOutboundCrossClusterSearchConnections``
    request. Contains the list of connections matching the filter criteria.
    """

    CrossClusterSearchConnections: Optional[OutboundCrossClusterSearchConnections]
    NextToken: Optional[NextToken]


DescribePackagesFilterValues = List[DescribePackagesFilterValue]


class DescribePackagesFilter(TypedDict, total=False):
    """Filter to apply in ``DescribePackage`` response."""

    Name: Optional[DescribePackagesFilterName]
    Value: Optional[DescribePackagesFilterValues]


DescribePackagesFilterList = List[DescribePackagesFilter]


class DescribePackagesRequest(ServiceRequest):
    """Container for request parameters to ``DescribePackage`` operation."""

    Filters: Optional[DescribePackagesFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


PackageDetailsList = List[PackageDetails]


class DescribePackagesResponse(TypedDict, total=False):
    """Container for response returned by ``DescribePackages`` operation."""

    PackageDetailsList: Optional[PackageDetailsList]
    NextToken: Optional[String]


class DescribeReservedElasticsearchInstanceOfferingsRequest(ServiceRequest):
    """Container for parameters to
    ``DescribeReservedElasticsearchInstanceOfferings``
    """

    ReservedElasticsearchInstanceOfferingId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class RecurringCharge(TypedDict, total=False):
    """Contains the specific price and frequency of a recurring charges for a
    reserved Elasticsearch instance, or for a reserved Elasticsearch
    instance offering.
    """

    RecurringChargeAmount: Optional[Double]
    RecurringChargeFrequency: Optional[String]


RecurringChargeList = List[RecurringCharge]


class ReservedElasticsearchInstanceOffering(TypedDict, total=False):
    """Details of a reserved Elasticsearch instance offering."""

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
    """Container for results from
    ``DescribeReservedElasticsearchInstanceOfferings``
    """

    NextToken: Optional[NextToken]
    ReservedElasticsearchInstanceOfferings: Optional[ReservedElasticsearchInstanceOfferingList]


class DescribeReservedElasticsearchInstancesRequest(ServiceRequest):
    """Container for parameters to ``DescribeReservedElasticsearchInstances``"""

    ReservedElasticsearchInstanceId: Optional[GUID]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ReservedElasticsearchInstance(TypedDict, total=False):
    """Details of a reserved Elasticsearch instance."""

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
    """Container for results from ``DescribeReservedElasticsearchInstances``"""

    NextToken: Optional[String]
    ReservedElasticsearchInstances: Optional[ReservedElasticsearchInstanceList]


class DissociatePackageRequest(ServiceRequest):
    """Container for request parameters to ``DissociatePackage`` operation."""

    PackageID: PackageID
    DomainName: DomainName


class DissociatePackageResponse(TypedDict, total=False):
    """Container for response returned by ``DissociatePackage`` operation."""

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
    """Container for request parameters to
    ``GetCompatibleElasticsearchVersions`` operation.
    """

    DomainName: Optional[DomainName]


class GetCompatibleElasticsearchVersionsResponse(TypedDict, total=False):
    """Container for response returned by
    ``GetCompatibleElasticsearchVersions`` operation.
    """

    CompatibleElasticsearchVersions: Optional[CompatibleElasticsearchVersionsList]


class GetPackageVersionHistoryRequest(ServiceRequest):
    """Container for request parameters to ``GetPackageVersionHistory``
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
    """Container for request parameters to ``GetUpgradeHistory`` operation."""

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


Issues = List[Issue]


class UpgradeStepItem(TypedDict, total=False):
    """Represents a single step of the Upgrade or Upgrade Eligibility Check
    workflow.
    """

    UpgradeStep: Optional[UpgradeStep]
    UpgradeStepStatus: Optional[UpgradeStatus]
    Issues: Optional[Issues]
    ProgressPercent: Optional[Double]


UpgradeStepsList = List[UpgradeStepItem]
StartTimestamp = datetime


class UpgradeHistory(TypedDict, total=False):
    """History of the last 10 Upgrades and Upgrade Eligibility Checks."""

    UpgradeName: Optional[UpgradeName]
    StartTimestamp: Optional[StartTimestamp]
    UpgradeStatus: Optional[UpgradeStatus]
    StepsList: Optional[UpgradeStepsList]


UpgradeHistoryList = List[UpgradeHistory]


class GetUpgradeHistoryResponse(TypedDict, total=False):
    """Container for response returned by ``GetUpgradeHistory`` operation."""

    UpgradeHistories: Optional[UpgradeHistoryList]
    NextToken: Optional[String]


class GetUpgradeStatusRequest(ServiceRequest):
    """Container for request parameters to ``GetUpgradeStatus`` operation."""

    DomainName: DomainName


class GetUpgradeStatusResponse(TypedDict, total=False):
    """Container for response returned by ``GetUpgradeStatus`` operation."""

    UpgradeStep: Optional[UpgradeStep]
    StepStatus: Optional[UpgradeStatus]
    UpgradeName: Optional[UpgradeName]


class ListDomainNamesRequest(ServiceRequest):
    """Container for the parameters to the ``ListDomainNames`` operation."""

    EngineType: Optional[EngineType]


class ListDomainNamesResponse(TypedDict, total=False):
    """The result of a ``ListDomainNames`` operation. Contains the names of all
    domains owned by this account and their respective engine types.
    """

    DomainNames: Optional[DomainInfoList]


class ListDomainsForPackageRequest(ServiceRequest):
    """Container for request parameters to ``ListDomainsForPackage`` operation."""

    PackageID: PackageID
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDomainsForPackageResponse(TypedDict, total=False):
    """Container for response parameters to ``ListDomainsForPackage``
    operation.
    """

    DomainPackageDetailsList: Optional[DomainPackageDetailsList]
    NextToken: Optional[String]


class ListElasticsearchInstanceTypesRequest(ServiceRequest):
    """Container for the parameters to the ``ListElasticsearchInstanceTypes``
    operation.
    """

    ElasticsearchVersion: ElasticsearchVersionString
    DomainName: Optional[DomainName]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListElasticsearchInstanceTypesResponse(TypedDict, total=False):
    """Container for the parameters returned by
    ``ListElasticsearchInstanceTypes`` operation.
    """

    ElasticsearchInstanceTypes: Optional[ElasticsearchInstanceTypeList]
    NextToken: Optional[NextToken]


class ListElasticsearchVersionsRequest(ServiceRequest):
    """Container for the parameters to the ``ListElasticsearchVersions``
    operation.

    Use ``MaxResults`` to control the maximum number of results to retrieve
    in a single call.

    Use ``NextToken`` in response to retrieve more results. If the received
    response does not contain a NextToken, then there are no more results to
    retrieve.
    """

    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListElasticsearchVersionsResponse(TypedDict, total=False):
    """Container for the parameters for response received from
    ``ListElasticsearchVersions`` operation.
    """

    ElasticsearchVersions: Optional[ElasticsearchVersionList]
    NextToken: Optional[NextToken]


class ListPackagesForDomainRequest(ServiceRequest):
    """Container for request parameters to ``ListPackagesForDomain`` operation."""

    DomainName: DomainName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListPackagesForDomainResponse(TypedDict, total=False):
    """Container for response parameters to ``ListPackagesForDomain``
    operation.
    """

    DomainPackageDetailsList: Optional[DomainPackageDetailsList]
    NextToken: Optional[String]


class ListTagsRequest(ServiceRequest):
    """Container for the parameters to the ``ListTags`` operation. Specify the
    ``ARN`` for the Elasticsearch domain to which the tags are attached that
    you want to view are attached.
    """

    ARN: ARN


class ListTagsResponse(TypedDict, total=False):
    """The result of a ``ListTags`` operation. Contains tags for all requested
    Elasticsearch domains.
    """

    TagList: Optional[TagList]


class PurchaseReservedElasticsearchInstanceOfferingRequest(ServiceRequest):
    """Container for parameters to
    ``PurchaseReservedElasticsearchInstanceOffering``
    """

    ReservedElasticsearchInstanceOfferingId: GUID
    ReservationName: ReservationToken
    InstanceCount: Optional[InstanceCount]


class PurchaseReservedElasticsearchInstanceOfferingResponse(TypedDict, total=False):
    """Represents the output of a
    ``PurchaseReservedElasticsearchInstanceOffering`` operation.
    """

    ReservedElasticsearchInstanceId: Optional[GUID]
    ReservationName: Optional[ReservationToken]


class RejectInboundCrossClusterSearchConnectionRequest(ServiceRequest):
    """Container for the parameters to the
    ``RejectInboundCrossClusterSearchConnection`` operation.
    """

    CrossClusterSearchConnectionId: CrossClusterSearchConnectionId


class RejectInboundCrossClusterSearchConnectionResponse(TypedDict, total=False):
    """The result of a ``RejectInboundCrossClusterSearchConnection`` operation.
    Contains details of rejected inbound connection.
    """

    CrossClusterSearchConnection: Optional[InboundCrossClusterSearchConnection]


class RemoveTagsRequest(ServiceRequest):
    """Container for the parameters to the ``RemoveTags`` operation. Specify
    the ``ARN`` for the Elasticsearch domain from which you want to remove
    the specified ``TagKey``.
    """

    ARN: ARN
    TagKeys: StringList


class StartElasticsearchServiceSoftwareUpdateRequest(ServiceRequest):
    """Container for the parameters to the
    ``StartElasticsearchServiceSoftwareUpdate`` operation. Specifies the
    name of the Elasticsearch domain that you wish to schedule a service
    software update on.
    """

    DomainName: DomainName


class StartElasticsearchServiceSoftwareUpdateResponse(TypedDict, total=False):
    """The result of a ``StartElasticsearchServiceSoftwareUpdate`` operation.
    Contains the status of the update.
    """

    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]


class UpdateElasticsearchDomainConfigRequest(ServiceRequest):
    """Container for the parameters to the ``UpdateElasticsearchDomain``
    operation. Specifies the type and number of instances in the domain
    cluster.
    """

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
    """The result of an ``UpdateElasticsearchDomain`` request. Contains the
    status of the Elasticsearch domain being updated.
    """

    DomainConfig: ElasticsearchDomainConfig
    DryRunResults: Optional[DryRunResults]


class UpdatePackageRequest(ServiceRequest):
    """Container for request parameters to ``UpdatePackage`` operation."""

    PackageID: PackageID
    PackageSource: PackageSource
    PackageDescription: Optional[PackageDescription]
    CommitMessage: Optional[CommitMessage]


class UpdatePackageResponse(TypedDict, total=False):
    """Container for response returned by ``UpdatePackage`` operation."""

    PackageDetails: Optional[PackageDetails]


class UpgradeElasticsearchDomainRequest(ServiceRequest):
    """Container for request parameters to ``UpgradeElasticsearchDomain``
    operation.
    """

    DomainName: DomainName
    TargetVersion: ElasticsearchVersionString
    PerformCheckOnly: Optional[Boolean]


class UpgradeElasticsearchDomainResponse(TypedDict, total=False):
    """Container for response returned by ``UpgradeElasticsearchDomain``
    operation.
    """

    DomainName: Optional[DomainName]
    TargetVersion: Optional[ElasticsearchVersionString]
    PerformCheckOnly: Optional[Boolean]


class EsApi:

    service = "es"
    version = "2015-01-01"

    @handler("AcceptInboundCrossClusterSearchConnection")
    def accept_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> AcceptInboundCrossClusterSearchConnectionResponse:
        """Allows the destination domain owner to accept an inbound cross-cluster
        search connection request.

        :param cross_cluster_search_connection_id: The id of the inbound connection that you want to accept.
        :returns: AcceptInboundCrossClusterSearchConnectionResponse
        :raises ResourceNotFoundException:
        :raises LimitExceededException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        """Attaches tags to an existing Elasticsearch domain. Tags are a set of
        case-sensitive key value pairs. An Elasticsearch domain may have up to
        10 tags. See `Tagging Amazon Elasticsearch Service Domains for more
        information. <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-awsresorcetagging>`__

        :param arn: Specify the ``ARN`` for which you want to add the tags.
        :param tag_list: List of ``Tag`` that need to be added for the Elasticsearch domain.
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
        """Associates a package with an Amazon ES domain.

        :param package_id: Internal ID of the package that you want to associate with a domain.
        :param domain_name: Name of the domain that you want to associate the package with.
        :returns: AssociatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("CancelElasticsearchServiceSoftwareUpdate")
    def cancel_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> CancelElasticsearchServiceSoftwareUpdateResponse:
        """Cancels a scheduled service software update for an Amazon ES domain. You
        can only perform this operation before the ``AutomatedUpdateDate`` and
        when the ``UpdateStatus`` is in the ``PENDING_UPDATE`` state.

        :param domain_name: The name of the domain that you want to stop the latest service software
        update on.
        :returns: CancelElasticsearchServiceSoftwareUpdateResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
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
        """Creates a new Elasticsearch domain. For more information, see `Creating
        Elasticsearch
        Domains <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains>`__
        in the *Amazon Elasticsearch Service Developer Guide*.

        :param domain_name: The name of the Elasticsearch domain that you are creating.
        :param elasticsearch_version: String of format X.
        :param elasticsearch_cluster_config: Configuration options for an Elasticsearch domain.
        :param ebs_options: Options to enable, disable and specify the type and size of EBS storage
        volumes.
        :param access_policies: IAM access policy as a JSON-formatted string.
        :param snapshot_options: Option to set time, in UTC format, of the daily automated snapshot.
        :param vpc_options: Options to specify the subnets and security groups for VPC endpoint.
        :param cognito_options: Options to specify the Cognito user and identity pools for Kibana
        authentication.
        :param encryption_at_rest_options: Specifies the Encryption At Rest Options.
        :param node_to_node_encryption_options: Specifies the NodeToNodeEncryptionOptions.
        :param advanced_options: Option to allow references to indices in an HTTP request body.
        :param log_publishing_options: Map of ``LogType`` and ``LogPublishingOption``, each containing options
        to publish a given type of Elasticsearch log.
        :param domain_endpoint_options: Options to specify configuration that will be applied to the domain
        endpoint.
        :param advanced_security_options: Specifies advanced security options.
        :param auto_tune_options: Specifies Auto-Tune options.
        :param tag_list: A list of ``Tag`` added during domain creation.
        :returns: CreateElasticsearchDomainResponse
        :raises BaseException:
        :raises DisabledOperationException:
        :raises InternalException:
        :raises InvalidTypeException:
        :raises LimitExceededException:
        :raises ResourceAlreadyExistsException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("CreateOutboundCrossClusterSearchConnection")
    def create_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        source_domain_info: DomainInformation,
        destination_domain_info: DomainInformation,
        connection_alias: ConnectionAlias,
    ) -> CreateOutboundCrossClusterSearchConnectionResponse:
        """Creates a new cross-cluster search connection from a source domain to a
        destination domain.

        :param source_domain_info: Specifies the ``DomainInformation`` for the source Elasticsearch domain.
        :param destination_domain_info: Specifies the ``DomainInformation`` for the destination Elasticsearch
        domain.
        :param connection_alias: Specifies the connection alias that will be used by the customer for
        this connection.
        :returns: CreateOutboundCrossClusterSearchConnectionResponse
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
        """Create a package for use with Amazon ES domains.

        :param package_name: Unique identifier for the package.
        :param package_type: Type of package.
        :param package_source: The customer S3 location ``PackageSource`` for importing the package.
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

    @handler("DeleteElasticsearchDomain")
    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteElasticsearchDomainResponse:
        """Permanently deletes the specified Elasticsearch domain and all of its
        data. Once a domain is deleted, it cannot be recovered.

        :param domain_name: The name of the Elasticsearch domain that you want to permanently
        delete.
        :returns: DeleteElasticsearchDomainResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DeleteElasticsearchServiceRole")
    def delete_elasticsearch_service_role(
        self,
        context: RequestContext,
    ) -> None:
        """Deletes the service-linked role that Elasticsearch Service uses to
        manage and maintain VPC domains. Role deletion will fail if any existing
        VPC domains use the role. You must delete any such Elasticsearch domains
        before deleting the role. See `Deleting Elasticsearch Service
        Role <http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html#es-enabling-slr>`__
        in *VPC Endpoints for Amazon Elasticsearch Service Domains*.

        :raises BaseException:
        :raises InternalException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DeleteInboundCrossClusterSearchConnection")
    def delete_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> DeleteInboundCrossClusterSearchConnectionResponse:
        """Allows the destination domain owner to delete an existing inbound
        cross-cluster search connection.

        :param cross_cluster_search_connection_id: The id of the inbound connection that you want to permanently delete.
        :returns: DeleteInboundCrossClusterSearchConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DeleteOutboundCrossClusterSearchConnection")
    def delete_outbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> DeleteOutboundCrossClusterSearchConnectionResponse:
        """Allows the source domain owner to delete an existing outbound
        cross-cluster search connection.

        :param cross_cluster_search_connection_id: The id of the outbound connection that you want to permanently delete.
        :returns: DeleteOutboundCrossClusterSearchConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DeletePackage")
    def delete_package(
        self, context: RequestContext, package_id: PackageID
    ) -> DeletePackageResponse:
        """Delete the package.

        :param package_id: Internal ID of the package that you want to delete.
        :returns: DeletePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
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
        """Provides scheduled Auto-Tune action details for the Elasticsearch
        domain, such as Auto-Tune action type, description, severity, and
        scheduled date.

        :param domain_name: Specifies the domain name for which you want Auto-Tune action details.
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

    @handler("DescribeElasticsearchDomain")
    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainResponse:
        """Returns domain configuration information about the specified
        Elasticsearch domain, including the domain ID, domain endpoint, and
        domain ARN.

        :param domain_name: The name of the Elasticsearch domain for which you want information.
        :returns: DescribeElasticsearchDomainResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeElasticsearchDomainConfig")
    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainConfigResponse:
        """Provides cluster configuration information about the specified
        Elasticsearch domain, such as the state, creation date, update version,
        and update date for cluster options.

        :param domain_name: The Elasticsearch domain that you want to get information about.
        :returns: DescribeElasticsearchDomainConfigResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeElasticsearchDomains")
    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeElasticsearchDomainsResponse:
        """Returns domain configuration information about the specified
        Elasticsearch domains, including the domain ID, domain endpoint, and
        domain ARN.

        :param domain_names: The Elasticsearch domains for which you want information.
        :returns: DescribeElasticsearchDomainsResponse
        :raises BaseException:
        :raises InternalException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeElasticsearchInstanceTypeLimits")
    def describe_elasticsearch_instance_type_limits(
        self,
        context: RequestContext,
        instance_type: ESPartitionInstanceType,
        elasticsearch_version: ElasticsearchVersionString,
        domain_name: DomainName = None,
    ) -> DescribeElasticsearchInstanceTypeLimitsResponse:
        """Describe Elasticsearch Limits for a given InstanceType and
        ElasticsearchVersion. When modifying existing Domain, specify the
        ``DomainName`` to know what Limits are supported for modifying.

        :param instance_type: The instance type for an Elasticsearch cluster for which Elasticsearch
        ``Limits`` are needed.
        :param elasticsearch_version: Version of Elasticsearch for which ``Limits`` are needed.
        :param domain_name: DomainName represents the name of the Domain that we are trying to
        modify.
        :returns: DescribeElasticsearchInstanceTypeLimitsResponse
        :raises BaseException:
        :raises InternalException:
        :raises InvalidTypeException:
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("DescribeInboundCrossClusterSearchConnections")
    def describe_inbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeInboundCrossClusterSearchConnectionsResponse:
        """Lists all the inbound cross-cluster search connections for a destination
        domain.

        :param filters: A list of filters used to match properties for inbound cross-cluster
        search connection.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken is sent in case the earlier API call results contain the
        NextToken.
        :returns: DescribeInboundCrossClusterSearchConnectionsResponse
        :raises InvalidPaginationTokenException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("DescribeOutboundCrossClusterSearchConnections")
    def describe_outbound_cross_cluster_search_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeOutboundCrossClusterSearchConnectionsResponse:
        """Lists all the outbound cross-cluster search connections for a source
        domain.

        :param filters: A list of filters used to match properties for outbound cross-cluster
        search connection.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken is sent in case the earlier API call results contain the
        NextToken.
        :returns: DescribeOutboundCrossClusterSearchConnectionsResponse
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
        """Describes all packages available to Amazon ES. Includes options for
        filtering, limiting the number of results, and pagination.

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

    @handler("DescribeReservedElasticsearchInstanceOfferings")
    def describe_reserved_elasticsearch_instance_offerings(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedElasticsearchInstanceOfferingsResponse:
        """Lists available reserved Elasticsearch instance offerings.

        :param reserved_elasticsearch_instance_offering_id: The offering identifier filter value.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken should be sent in case if earlier API call produced result
        containing NextToken.
        :returns: DescribeReservedElasticsearchInstanceOfferingsResponse
        :raises ResourceNotFoundException:
        :raises ValidationException:
        :raises DisabledOperationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeReservedElasticsearchInstances")
    def describe_reserved_elasticsearch_instances(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_id: GUID = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeReservedElasticsearchInstancesResponse:
        """Returns information about reserved Elasticsearch instances for this
        account.

        :param reserved_elasticsearch_instance_id: The reserved instance identifier filter value.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken should be sent in case if earlier API call produced result
        containing NextToken.
        :returns: DescribeReservedElasticsearchInstancesResponse
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
        """Dissociates a package from the Amazon ES domain.

        :param package_id: Internal ID of the package that you want to associate with a domain.
        :param domain_name: Name of the domain that you want to associate the package with.
        :returns: DissociatePackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("GetCompatibleElasticsearchVersions")
    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleElasticsearchVersionsResponse:
        """Returns a list of upgrade compatible Elastisearch versions. You can
        optionally pass a ``DomainName`` to get all upgrade compatible
        Elasticsearch versions for that specific domain.

        :param domain_name: The name of an Elasticsearch domain.
        :returns: GetCompatibleElasticsearchVersionsResponse
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
        """Returns a list of versions of the package, along with their creation
        time and commit message.

        :param package_id: Returns an audit history of versions of the package.
        :param max_results: Limits results to a maximum number of versions.
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
        """Retrieves the complete history of the last 10 upgrades that were
        performed on the domain.

        :param domain_name: The name of an Elasticsearch domain.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Paginated APIs accepts NextToken input to returns next page results and
        provides a NextToken output in the response which can be used by the
        client to retrieve more results.
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
        check that was performed on the domain.

        :param domain_name: The name of an Elasticsearch domain.
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
        """Returns the name of all Elasticsearch domains owned by the current
        user's account.

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
        """Lists all Amazon ES domains associated with the package.

        :param package_id: The package for which to list domains.
        :param max_results: Limits results to a maximum number of domains.
        :param next_token: Used for pagination.
        :returns: ListDomainsForPackageResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises AccessDeniedException:
        :raises ValidationException:
        """
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
        """List all Elasticsearch instance types that are supported for given
        ElasticsearchVersion

        :param elasticsearch_version: Version of Elasticsearch for which list of supported elasticsearch
        instance types are needed.
        :param domain_name: DomainName represents the name of the Domain that we are trying to
        modify.
        :param max_results: Set this value to limit the number of results returned.
        :param next_token: NextToken should be sent in case if earlier API call produced result
        containing NextToken.
        :returns: ListElasticsearchInstanceTypesResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
        raise NotImplementedError

    @handler("ListElasticsearchVersions")
    def list_elasticsearch_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListElasticsearchVersionsResponse:
        """List all supported Elasticsearch versions

        :param max_results: Set this value to limit the number of results returned.
        :param next_token: Paginated APIs accepts NextToken input to returns next page results and
        provides a NextToken output in the response which can be used by the
        client to retrieve more results.
        :returns: ListElasticsearchVersionsResponse
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
        """Lists all packages associated with the Amazon ES domain.

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
        """Returns all tags for the given Elasticsearch domain.

        :param arn: Specify the ``ARN`` for the Elasticsearch domain to which the tags are
        attached that you want to view.
        :returns: ListTagsResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("PurchaseReservedElasticsearchInstanceOffering")
    def purchase_reserved_elasticsearch_instance_offering(
        self,
        context: RequestContext,
        reserved_elasticsearch_instance_offering_id: GUID,
        reservation_name: ReservationToken,
        instance_count: InstanceCount = None,
    ) -> PurchaseReservedElasticsearchInstanceOfferingResponse:
        """Allows you to purchase reserved Elasticsearch instances.

        :param reserved_elasticsearch_instance_offering_id: The ID of the reserved Elasticsearch instance offering to purchase.
        :param reservation_name: A customer-specified identifier to track this reservation.
        :param instance_count: The number of Elasticsearch instances to reserve.
        :returns: PurchaseReservedElasticsearchInstanceOfferingResponse
        :raises ResourceNotFoundException:
        :raises ResourceAlreadyExistsException:
        :raises LimitExceededException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("RejectInboundCrossClusterSearchConnection")
    def reject_inbound_cross_cluster_search_connection(
        self,
        context: RequestContext,
        cross_cluster_search_connection_id: CrossClusterSearchConnectionId,
    ) -> RejectInboundCrossClusterSearchConnectionResponse:
        """Allows the destination domain owner to reject an inbound cross-cluster
        search connection request.

        :param cross_cluster_search_connection_id: The id of the inbound connection that you want to reject.
        :returns: RejectInboundCrossClusterSearchConnectionResponse
        :raises ResourceNotFoundException:
        :raises DisabledOperationException:
        """
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        """Removes the specified set of tags from the specified Elasticsearch
        domain.

        :param arn: Specifies the ``ARN`` for the Elasticsearch domain from which you want
        to delete the specified tags.
        :param tag_keys: Specifies the ``TagKey`` list which you want to remove from the
        Elasticsearch domain.
        :raises BaseException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("StartElasticsearchServiceSoftwareUpdate")
    def start_elasticsearch_service_software_update(
        self, context: RequestContext, domain_name: DomainName
    ) -> StartElasticsearchServiceSoftwareUpdateResponse:
        """Schedules a service software update for an Amazon ES domain.

        :param domain_name: The name of the domain that you want to update to the latest service
        software.
        :returns: StartElasticsearchServiceSoftwareUpdateResponse
        :raises BaseException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        :raises ValidationException:
        """
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
        """Modifies the cluster configuration of the specified Elasticsearch
        domain, setting as setting the instance type and the number of
        instances.

        :param domain_name: The name of the Elasticsearch domain that you are updating.
        :param elasticsearch_cluster_config: The type and number of instances to instantiate for the domain cluster.
        :param ebs_options: Specify the type and size of the EBS volume that you want to use.
        :param snapshot_options: Option to set the time, in UTC format, for the daily automated snapshot.
        :param vpc_options: Options to specify the subnets and security groups for VPC endpoint.
        :param cognito_options: Options to specify the Cognito user and identity pools for Kibana
        authentication.
        :param advanced_options: Modifies the advanced option to allow references to indices in an HTTP
        request body.
        :param access_policies: IAM access policy as a JSON-formatted string.
        :param log_publishing_options: Map of ``LogType`` and ``LogPublishingOption``, each containing options
        to publish a given type of Elasticsearch log.
        :param domain_endpoint_options: Options to specify configuration that will be applied to the domain
        endpoint.
        :param advanced_security_options: Specifies advanced security options.
        :param node_to_node_encryption_options: Specifies the NodeToNodeEncryptionOptions.
        :param encryption_at_rest_options: Specifies the Encryption At Rest Options.
        :param auto_tune_options: Specifies Auto-Tune options.
        :param dry_run: This flag, when set to True, specifies whether the
        ``UpdateElasticsearchDomain`` request should return the results of
        validation checks without actually applying the change.
        :returns: UpdateElasticsearchDomainConfigResponse
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
        """Updates a package for use with Amazon ES domains.

        :param package_id: Unique identifier for the package.
        :param package_source: The S3 location for importing the package specified as ``S3BucketName``
        and ``S3Key``.
        :param package_description: New description of the package.
        :param commit_message: An info message for the new version which will be shown as part of
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

    @handler("UpgradeElasticsearchDomain")
    def upgrade_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        target_version: ElasticsearchVersionString,
        perform_check_only: Boolean = None,
    ) -> UpgradeElasticsearchDomainResponse:
        """Allows you to either upgrade your domain or perform an Upgrade
        eligibility check to a compatible Elasticsearch version.

        :param domain_name: The name of an Elasticsearch domain.
        :param target_version: The version of Elasticsearch that you intend to upgrade the domain to.
        :param perform_check_only: This flag, when set to True, indicates that an Upgrade Eligibility Check
        needs to be performed.
        :returns: UpgradeElasticsearchDomainResponse
        :raises BaseException:
        :raises ResourceNotFoundException:
        :raises ResourceAlreadyExistsException:
        :raises DisabledOperationException:
        :raises ValidationException:
        :raises InternalException:
        """
        raise NotImplementedError
