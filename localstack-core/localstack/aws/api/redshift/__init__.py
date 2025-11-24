from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AuthenticationProfileNameString = str
Boolean = bool
BooleanOptional = bool
CatalogNameString = str
CustomDomainCertificateArnString = str
CustomDomainNameString = str
Description = str
Double = float
DoubleOptional = float
IdcDisplayNameString = str
IdentityNamespaceString = str
InboundIntegrationArn = str
Integer = int
IntegerOptional = int
IntegrationArn = str
IntegrationDescription = str
IntegrationName = str
PartnerIntegrationAccountId = str
PartnerIntegrationClusterIdentifier = str
PartnerIntegrationDatabaseName = str
PartnerIntegrationPartnerName = str
PartnerIntegrationStatusMessage = str
RedshiftIdcApplicationName = str
S3KeyPrefixValue = str
SensitiveString = str
SourceArn = str
String = str
TargetArn = str


class ActionType(StrEnum):
    restore_cluster = "restore-cluster"
    recommend_node_config = "recommend-node-config"
    resize_cluster = "resize-cluster"


class ApplicationType(StrEnum):
    None_ = "None"
    Lakehouse = "Lakehouse"


class AquaConfigurationStatus(StrEnum):
    enabled = "enabled"
    disabled = "disabled"
    auto = "auto"


class AquaStatus(StrEnum):
    enabled = "enabled"
    disabled = "disabled"
    applying = "applying"


class AuthorizationStatus(StrEnum):
    Authorized = "Authorized"
    Revoking = "Revoking"


class DataShareStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    DEAUTHORIZED = "DEAUTHORIZED"
    REJECTED = "REJECTED"
    AVAILABLE = "AVAILABLE"


class DataShareStatusForConsumer(StrEnum):
    ACTIVE = "ACTIVE"
    AVAILABLE = "AVAILABLE"


class DataShareStatusForProducer(StrEnum):
    ACTIVE = "ACTIVE"
    AUTHORIZED = "AUTHORIZED"
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    DEAUTHORIZED = "DEAUTHORIZED"
    REJECTED = "REJECTED"


class DataShareType(StrEnum):
    INTERNAL = "INTERNAL"


class DescribeIntegrationsFilterName(StrEnum):
    integration_arn = "integration-arn"
    source_arn = "source-arn"
    source_types = "source-types"
    status = "status"


class ImpactRankingType(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class LakehouseIdcRegistration(StrEnum):
    Associate = "Associate"
    Disassociate = "Disassociate"


class LakehouseRegistration(StrEnum):
    Register = "Register"
    Deregister = "Deregister"


class LogDestinationType(StrEnum):
    s3 = "s3"
    cloudwatch = "cloudwatch"


class Mode(StrEnum):
    standard = "standard"
    high_performance = "high-performance"


class NamespaceRegistrationStatus(StrEnum):
    Registering = "Registering"
    Deregistering = "Deregistering"


class NodeConfigurationOptionsFilterName(StrEnum):
    NodeType = "NodeType"
    NumberOfNodes = "NumberOfNodes"
    EstimatedDiskUtilizationPercent = "EstimatedDiskUtilizationPercent"
    Mode = "Mode"


class OperatorType(StrEnum):
    eq = "eq"
    lt = "lt"
    gt = "gt"
    le = "le"
    ge = "ge"
    in_ = "in"
    between = "between"


class ParameterApplyType(StrEnum):
    static = "static"
    dynamic = "dynamic"


class PartnerIntegrationStatus(StrEnum):
    Active = "Active"
    Inactive = "Inactive"
    RuntimeFailure = "RuntimeFailure"
    ConnectionFailure = "ConnectionFailure"


class RecommendedActionType(StrEnum):
    SQL = "SQL"
    CLI = "CLI"


class ReservedNodeExchangeActionType(StrEnum):
    restore_cluster = "restore-cluster"
    resize_cluster = "resize-cluster"


class ReservedNodeExchangeStatusType(StrEnum):
    REQUESTED = "REQUESTED"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    RETRYING = "RETRYING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ReservedNodeOfferingType(StrEnum):
    Regular = "Regular"
    Upgradable = "Upgradable"


class ScheduleState(StrEnum):
    MODIFYING = "MODIFYING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class ScheduledActionFilterName(StrEnum):
    cluster_identifier = "cluster-identifier"
    iam_role = "iam-role"


class ScheduledActionState(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class ScheduledActionTypeValues(StrEnum):
    ResizeCluster = "ResizeCluster"
    PauseCluster = "PauseCluster"
    ResumeCluster = "ResumeCluster"


class ServiceAuthorization(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class SnapshotAttributeToSortBy(StrEnum):
    SOURCE_TYPE = "SOURCE_TYPE"
    TOTAL_SIZE = "TOTAL_SIZE"
    CREATE_TIME = "CREATE_TIME"


class SortByOrder(StrEnum):
    ASC = "ASC"
    DESC = "DESC"


class SourceType(StrEnum):
    cluster = "cluster"
    cluster_parameter_group = "cluster-parameter-group"
    cluster_security_group = "cluster-security-group"
    cluster_snapshot = "cluster-snapshot"
    scheduled_action = "scheduled-action"


class TableRestoreStatusType(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class UsageLimitBreachAction(StrEnum):
    log = "log"
    emit_metric = "emit-metric"
    disable = "disable"


class UsageLimitFeatureType(StrEnum):
    spectrum = "spectrum"
    concurrency_scaling = "concurrency-scaling"
    cross_region_datasharing = "cross-region-datasharing"


class UsageLimitLimitType(StrEnum):
    time = "time"
    data_scanned = "data-scanned"


class UsageLimitPeriod(StrEnum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class ZeroETLIntegrationStatus(StrEnum):
    creating = "creating"
    active = "active"
    modifying = "modifying"
    failed = "failed"
    deleting = "deleting"
    syncing = "syncing"
    needs_attention = "needs_attention"


class AccessToClusterDeniedFault(ServiceException):
    code: str = "AccessToClusterDenied"
    sender_fault: bool = True
    status_code: int = 400


class AccessToSnapshotDeniedFault(ServiceException):
    code: str = "AccessToSnapshotDenied"
    sender_fault: bool = True
    status_code: int = 400


class AuthenticationProfileAlreadyExistsFault(ServiceException):
    code: str = "AuthenticationProfileAlreadyExistsFault"
    sender_fault: bool = True
    status_code: int = 400


class AuthenticationProfileNotFoundFault(ServiceException):
    code: str = "AuthenticationProfileNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class AuthenticationProfileQuotaExceededFault(ServiceException):
    code: str = "AuthenticationProfileQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class AuthorizationAlreadyExistsFault(ServiceException):
    code: str = "AuthorizationAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class AuthorizationNotFoundFault(ServiceException):
    code: str = "AuthorizationNotFound"
    sender_fault: bool = True
    status_code: int = 404


class AuthorizationQuotaExceededFault(ServiceException):
    code: str = "AuthorizationQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class BatchDeleteRequestSizeExceededFault(ServiceException):
    code: str = "BatchDeleteRequestSizeExceeded"
    sender_fault: bool = True
    status_code: int = 400


class BatchModifyClusterSnapshotsLimitExceededFault(ServiceException):
    code: str = "BatchModifyClusterSnapshotsLimitExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class BucketNotFoundFault(ServiceException):
    code: str = "BucketNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class ClusterAlreadyExistsFault(ServiceException):
    code: str = "ClusterAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ClusterNotFoundFault(ServiceException):
    code: str = "ClusterNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ClusterOnLatestRevisionFault(ServiceException):
    code: str = "ClusterOnLatestRevision"
    sender_fault: bool = True
    status_code: int = 400


class ClusterParameterGroupAlreadyExistsFault(ServiceException):
    code: str = "ClusterParameterGroupAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ClusterParameterGroupNotFoundFault(ServiceException):
    code: str = "ClusterParameterGroupNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ClusterParameterGroupQuotaExceededFault(ServiceException):
    code: str = "ClusterParameterGroupQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ClusterQuotaExceededFault(ServiceException):
    code: str = "ClusterQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSecurityGroupAlreadyExistsFault(ServiceException):
    code: str = "ClusterSecurityGroupAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSecurityGroupNotFoundFault(ServiceException):
    code: str = "ClusterSecurityGroupNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ClusterSecurityGroupQuotaExceededFault(ServiceException):
    code: str = "QuotaExceeded.ClusterSecurityGroup"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSnapshotAlreadyExistsFault(ServiceException):
    code: str = "ClusterSnapshotAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSnapshotNotFoundFault(ServiceException):
    code: str = "ClusterSnapshotNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ClusterSnapshotQuotaExceededFault(ServiceException):
    code: str = "ClusterSnapshotQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSubnetGroupAlreadyExistsFault(ServiceException):
    code: str = "ClusterSubnetGroupAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSubnetGroupNotFoundFault(ServiceException):
    code: str = "ClusterSubnetGroupNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSubnetGroupQuotaExceededFault(ServiceException):
    code: str = "ClusterSubnetGroupQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ClusterSubnetQuotaExceededFault(ServiceException):
    code: str = "ClusterSubnetQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class ConflictPolicyUpdateFault(ServiceException):
    code: str = "ConflictPolicyUpdateFault"
    sender_fault: bool = True
    status_code: int = 409


class CopyToRegionDisabledFault(ServiceException):
    code: str = "CopyToRegionDisabledFault"
    sender_fault: bool = True
    status_code: int = 400


class CustomCnameAssociationFault(ServiceException):
    code: str = "CustomCnameAssociationFault"
    sender_fault: bool = True
    status_code: int = 400


class CustomDomainAssociationNotFoundFault(ServiceException):
    code: str = "CustomDomainAssociationNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class DependentServiceAccessDeniedFault(ServiceException):
    code: str = "DependentServiceAccessDenied"
    sender_fault: bool = True
    status_code: int = 403


class DependentServiceRequestThrottlingFault(ServiceException):
    code: str = "DependentServiceRequestThrottlingFault"
    sender_fault: bool = True
    status_code: int = 400


class DependentServiceUnavailableFault(ServiceException):
    code: str = "DependentServiceUnavailableFault"
    sender_fault: bool = True
    status_code: int = 400


class EndpointAlreadyExistsFault(ServiceException):
    code: str = "EndpointAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class EndpointAuthorizationAlreadyExistsFault(ServiceException):
    code: str = "EndpointAuthorizationAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class EndpointAuthorizationNotFoundFault(ServiceException):
    code: str = "EndpointAuthorizationNotFound"
    sender_fault: bool = True
    status_code: int = 404


class EndpointAuthorizationsPerClusterLimitExceededFault(ServiceException):
    code: str = "EndpointAuthorizationsPerClusterLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class EndpointNotFoundFault(ServiceException):
    code: str = "EndpointNotFound"
    sender_fault: bool = True
    status_code: int = 404


class EndpointsPerAuthorizationLimitExceededFault(ServiceException):
    code: str = "EndpointsPerAuthorizationLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class EndpointsPerClusterLimitExceededFault(ServiceException):
    code: str = "EndpointsPerClusterLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class EventSubscriptionQuotaExceededFault(ServiceException):
    code: str = "EventSubscriptionQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class HsmClientCertificateAlreadyExistsFault(ServiceException):
    code: str = "HsmClientCertificateAlreadyExistsFault"
    sender_fault: bool = True
    status_code: int = 400


class HsmClientCertificateNotFoundFault(ServiceException):
    code: str = "HsmClientCertificateNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class HsmClientCertificateQuotaExceededFault(ServiceException):
    code: str = "HsmClientCertificateQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class HsmConfigurationAlreadyExistsFault(ServiceException):
    code: str = "HsmConfigurationAlreadyExistsFault"
    sender_fault: bool = True
    status_code: int = 400


class HsmConfigurationNotFoundFault(ServiceException):
    code: str = "HsmConfigurationNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class HsmConfigurationQuotaExceededFault(ServiceException):
    code: str = "HsmConfigurationQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class InProgressTableRestoreQuotaExceededFault(ServiceException):
    code: str = "InProgressTableRestoreQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class IncompatibleOrderableOptions(ServiceException):
    code: str = "IncompatibleOrderableOptions"
    sender_fault: bool = True
    status_code: int = 400


class InsufficientClusterCapacityFault(ServiceException):
    code: str = "InsufficientClusterCapacity"
    sender_fault: bool = True
    status_code: int = 400


class InsufficientS3BucketPolicyFault(ServiceException):
    code: str = "InsufficientS3BucketPolicyFault"
    sender_fault: bool = True
    status_code: int = 400


class IntegrationAlreadyExistsFault(ServiceException):
    code: str = "IntegrationAlreadyExistsFault"
    sender_fault: bool = True
    status_code: int = 400


class IntegrationConflictOperationFault(ServiceException):
    code: str = "IntegrationConflictOperationFault"
    sender_fault: bool = True
    status_code: int = 400


class IntegrationConflictStateFault(ServiceException):
    code: str = "IntegrationConflictStateFault"
    sender_fault: bool = True
    status_code: int = 400


class IntegrationNotFoundFault(ServiceException):
    code: str = "IntegrationNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class IntegrationQuotaExceededFault(ServiceException):
    code: str = "IntegrationQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class IntegrationSourceNotFoundFault(ServiceException):
    code: str = "IntegrationSourceNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class IntegrationTargetNotFoundFault(ServiceException):
    code: str = "IntegrationTargetNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class InvalidAuthenticationProfileRequestFault(ServiceException):
    code: str = "InvalidAuthenticationProfileRequestFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidAuthorizationStateFault(ServiceException):
    code: str = "InvalidAuthorizationState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterParameterGroupStateFault(ServiceException):
    code: str = "InvalidClusterParameterGroupState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterSecurityGroupStateFault(ServiceException):
    code: str = "InvalidClusterSecurityGroupState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterSnapshotScheduleStateFault(ServiceException):
    code: str = "InvalidClusterSnapshotScheduleState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterSnapshotStateFault(ServiceException):
    code: str = "InvalidClusterSnapshotState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterStateFault(ServiceException):
    code: str = "InvalidClusterState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterSubnetGroupStateFault(ServiceException):
    code: str = "InvalidClusterSubnetGroupStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterSubnetStateFault(ServiceException):
    code: str = "InvalidClusterSubnetStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidClusterTrackFault(ServiceException):
    code: str = "InvalidClusterTrack"
    sender_fault: bool = True
    status_code: int = 400


class InvalidDataShareFault(ServiceException):
    code: str = "InvalidDataShareFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidElasticIpFault(ServiceException):
    code: str = "InvalidElasticIpFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidEndpointStateFault(ServiceException):
    code: str = "InvalidEndpointState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidHsmClientCertificateStateFault(ServiceException):
    code: str = "InvalidHsmClientCertificateStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidHsmConfigurationStateFault(ServiceException):
    code: str = "InvalidHsmConfigurationStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidNamespaceFault(ServiceException):
    code: str = "InvalidNamespaceFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidPolicyFault(ServiceException):
    code: str = "InvalidPolicyFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidReservedNodeStateFault(ServiceException):
    code: str = "InvalidReservedNodeState"
    sender_fault: bool = True
    status_code: int = 400


class InvalidRestoreFault(ServiceException):
    code: str = "InvalidRestore"
    sender_fault: bool = True
    status_code: int = 406


class InvalidRetentionPeriodFault(ServiceException):
    code: str = "InvalidRetentionPeriodFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidS3BucketNameFault(ServiceException):
    code: str = "InvalidS3BucketNameFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidS3KeyPrefixFault(ServiceException):
    code: str = "InvalidS3KeyPrefixFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidScheduleFault(ServiceException):
    code: str = "InvalidSchedule"
    sender_fault: bool = True
    status_code: int = 400


class InvalidScheduledActionFault(ServiceException):
    code: str = "InvalidScheduledAction"
    sender_fault: bool = True
    status_code: int = 400


class InvalidSnapshotCopyGrantStateFault(ServiceException):
    code: str = "InvalidSnapshotCopyGrantStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidSubnet(ServiceException):
    code: str = "InvalidSubnet"
    sender_fault: bool = True
    status_code: int = 400


class InvalidSubscriptionStateFault(ServiceException):
    code: str = "InvalidSubscriptionStateFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidTableRestoreArgumentFault(ServiceException):
    code: str = "InvalidTableRestoreArgument"
    sender_fault: bool = True
    status_code: int = 400


class InvalidTagFault(ServiceException):
    code: str = "InvalidTagFault"
    sender_fault: bool = True
    status_code: int = 400


class InvalidUsageLimitFault(ServiceException):
    code: str = "InvalidUsageLimit"
    sender_fault: bool = True
    status_code: int = 400


class InvalidVPCNetworkStateFault(ServiceException):
    code: str = "InvalidVPCNetworkStateFault"
    sender_fault: bool = True
    status_code: int = 400


class Ipv6CidrBlockNotFoundFault(ServiceException):
    code: str = "Ipv6CidrBlockNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededFault(ServiceException):
    code: str = "LimitExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class NumberOfNodesPerClusterLimitExceededFault(ServiceException):
    code: str = "NumberOfNodesPerClusterLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class NumberOfNodesQuotaExceededFault(ServiceException):
    code: str = "NumberOfNodesQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class PartnerNotFoundFault(ServiceException):
    code: str = "PartnerNotFound"
    sender_fault: bool = True
    status_code: int = 404


class RedshiftIdcApplicationAlreadyExistsFault(ServiceException):
    code: str = "RedshiftIdcApplicationAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class RedshiftIdcApplicationNotExistsFault(ServiceException):
    code: str = "RedshiftIdcApplicationNotExists"
    sender_fault: bool = True
    status_code: int = 404


class RedshiftIdcApplicationQuotaExceededFault(ServiceException):
    code: str = "RedshiftIdcApplicationQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class RedshiftInvalidParameterFault(ServiceException):
    code: str = "RedshiftInvalidParameter"
    sender_fault: bool = True
    status_code: int = 400


class ReservedNodeAlreadyExistsFault(ServiceException):
    code: str = "ReservedNodeAlreadyExists"
    sender_fault: bool = True
    status_code: int = 404


class ReservedNodeAlreadyMigratedFault(ServiceException):
    code: str = "ReservedNodeAlreadyMigrated"
    sender_fault: bool = True
    status_code: int = 400


class ReservedNodeExchangeNotFoundFault(ServiceException):
    code: str = "ReservedNodeExchangeNotFond"
    sender_fault: bool = True
    status_code: int = 404


class ReservedNodeNotFoundFault(ServiceException):
    code: str = "ReservedNodeNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ReservedNodeOfferingNotFoundFault(ServiceException):
    code: str = "ReservedNodeOfferingNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ReservedNodeQuotaExceededFault(ServiceException):
    code: str = "ReservedNodeQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ResizeNotFoundFault(ServiceException):
    code: str = "ResizeNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ResourceNotFoundFault(ServiceException):
    code: str = "ResourceNotFoundFault"
    sender_fault: bool = True
    status_code: int = 404


class SNSInvalidTopicFault(ServiceException):
    code: str = "SNSInvalidTopic"
    sender_fault: bool = True
    status_code: int = 400


class SNSNoAuthorizationFault(ServiceException):
    code: str = "SNSNoAuthorization"
    sender_fault: bool = True
    status_code: int = 400


class SNSTopicArnNotFoundFault(ServiceException):
    code: str = "SNSTopicArnNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ScheduleDefinitionTypeUnsupportedFault(ServiceException):
    code: str = "ScheduleDefinitionTypeUnsupported"
    sender_fault: bool = True
    status_code: int = 400


class ScheduledActionAlreadyExistsFault(ServiceException):
    code: str = "ScheduledActionAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ScheduledActionNotFoundFault(ServiceException):
    code: str = "ScheduledActionNotFound"
    sender_fault: bool = True
    status_code: int = 400


class ScheduledActionQuotaExceededFault(ServiceException):
    code: str = "ScheduledActionQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ScheduledActionTypeUnsupportedFault(ServiceException):
    code: str = "ScheduledActionTypeUnsupported"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyAlreadyDisabledFault(ServiceException):
    code: str = "SnapshotCopyAlreadyDisabledFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyAlreadyEnabledFault(ServiceException):
    code: str = "SnapshotCopyAlreadyEnabledFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyDisabledFault(ServiceException):
    code: str = "SnapshotCopyDisabledFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyGrantAlreadyExistsFault(ServiceException):
    code: str = "SnapshotCopyGrantAlreadyExistsFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyGrantNotFoundFault(ServiceException):
    code: str = "SnapshotCopyGrantNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotCopyGrantQuotaExceededFault(ServiceException):
    code: str = "SnapshotCopyGrantQuotaExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotScheduleAlreadyExistsFault(ServiceException):
    code: str = "SnapshotScheduleAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotScheduleNotFoundFault(ServiceException):
    code: str = "SnapshotScheduleNotFound"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotScheduleQuotaExceededFault(ServiceException):
    code: str = "SnapshotScheduleQuotaExceeded"
    sender_fault: bool = True
    status_code: int = 400


class SnapshotScheduleUpdateInProgressFault(ServiceException):
    code: str = "SnapshotScheduleUpdateInProgress"
    sender_fault: bool = True
    status_code: int = 400


class SourceNotFoundFault(ServiceException):
    code: str = "SourceNotFound"
    sender_fault: bool = True
    status_code: int = 404


class SubnetAlreadyInUse(ServiceException):
    code: str = "SubnetAlreadyInUse"
    sender_fault: bool = True
    status_code: int = 400


class SubscriptionAlreadyExistFault(ServiceException):
    code: str = "SubscriptionAlreadyExist"
    sender_fault: bool = True
    status_code: int = 400


class SubscriptionCategoryNotFoundFault(ServiceException):
    code: str = "SubscriptionCategoryNotFound"
    sender_fault: bool = True
    status_code: int = 404


class SubscriptionEventIdNotFoundFault(ServiceException):
    code: str = "SubscriptionEventIdNotFound"
    sender_fault: bool = True
    status_code: int = 404


class SubscriptionNotFoundFault(ServiceException):
    code: str = "SubscriptionNotFound"
    sender_fault: bool = True
    status_code: int = 404


class SubscriptionSeverityNotFoundFault(ServiceException):
    code: str = "SubscriptionSeverityNotFound"
    sender_fault: bool = True
    status_code: int = 404


class TableLimitExceededFault(ServiceException):
    code: str = "TableLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class TableRestoreNotFoundFault(ServiceException):
    code: str = "TableRestoreNotFoundFault"
    sender_fault: bool = True
    status_code: int = 400


class TagLimitExceededFault(ServiceException):
    code: str = "TagLimitExceededFault"
    sender_fault: bool = True
    status_code: int = 400


class UnauthorizedOperation(ServiceException):
    code: str = "UnauthorizedOperation"
    sender_fault: bool = True
    status_code: int = 400


class UnauthorizedPartnerIntegrationFault(ServiceException):
    code: str = "UnauthorizedPartnerIntegration"
    sender_fault: bool = True
    status_code: int = 401


class UnknownSnapshotCopyRegionFault(ServiceException):
    code: str = "UnknownSnapshotCopyRegionFault"
    sender_fault: bool = True
    status_code: int = 404


class UnsupportedOperationFault(ServiceException):
    code: str = "UnsupportedOperation"
    sender_fault: bool = True
    status_code: int = 400


class UnsupportedOptionFault(ServiceException):
    code: str = "UnsupportedOptionFault"
    sender_fault: bool = True
    status_code: int = 400


class UsageLimitAlreadyExistsFault(ServiceException):
    code: str = "UsageLimitAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class UsageLimitNotFoundFault(ServiceException):
    code: str = "UsageLimitNotFound"
    sender_fault: bool = True
    status_code: int = 404


class AcceptReservedNodeExchangeInputMessage(ServiceRequest):
    ReservedNodeId: String
    TargetReservedNodeOfferingId: String


class RecurringCharge(TypedDict, total=False):
    RecurringChargeAmount: Double | None
    RecurringChargeFrequency: String | None


RecurringChargeList = list[RecurringCharge]
TStamp = datetime


class ReservedNode(TypedDict, total=False):
    ReservedNodeId: String | None
    ReservedNodeOfferingId: String | None
    NodeType: String | None
    StartTime: TStamp | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    NodeCount: Integer | None
    State: String | None
    OfferingType: String | None
    RecurringCharges: RecurringChargeList | None
    ReservedNodeOfferingType: ReservedNodeOfferingType | None


class AcceptReservedNodeExchangeOutputMessage(TypedDict, total=False):
    ExchangedReservedNode: ReservedNode | None


class AttributeValueTarget(TypedDict, total=False):
    AttributeValue: String | None


AttributeValueList = list[AttributeValueTarget]


class AccountAttribute(TypedDict, total=False):
    AttributeName: String | None
    AttributeValues: AttributeValueList | None


AttributeList = list[AccountAttribute]


class AccountAttributeList(TypedDict, total=False):
    AccountAttributes: AttributeList | None


class AccountWithRestoreAccess(TypedDict, total=False):
    AccountId: String | None
    AccountAlias: String | None


AccountsWithRestoreAccessList = list[AccountWithRestoreAccess]


class AquaConfiguration(TypedDict, total=False):
    AquaStatus: AquaStatus | None
    AquaConfigurationStatus: AquaConfigurationStatus | None


class AssociateDataShareConsumerMessage(ServiceRequest):
    DataShareArn: String
    AssociateEntireAccount: BooleanOptional | None
    ConsumerArn: String | None
    ConsumerRegion: String | None
    AllowWrites: BooleanOptional | None


class ClusterAssociatedToSchedule(TypedDict, total=False):
    ClusterIdentifier: String | None
    ScheduleAssociationState: ScheduleState | None


AssociatedClusterList = list[ClusterAssociatedToSchedule]


class CertificateAssociation(TypedDict, total=False):
    CustomDomainName: String | None
    ClusterIdentifier: String | None


CertificateAssociationList = list[CertificateAssociation]


class Association(TypedDict, total=False):
    CustomDomainCertificateArn: String | None
    CustomDomainCertificateExpiryDate: TStamp | None
    CertificateAssociations: CertificateAssociationList | None


AssociationList = list[Association]
AttributeNameList = list[String]


class AuthenticationProfile(TypedDict, total=False):
    AuthenticationProfileName: AuthenticationProfileNameString | None
    AuthenticationProfileContent: String | None


AuthenticationProfileList = list[AuthenticationProfile]


class AuthorizeClusterSecurityGroupIngressMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    CIDRIP: String | None
    EC2SecurityGroupName: String | None
    EC2SecurityGroupOwnerId: String | None


class Tag(TypedDict, total=False):
    Key: String | None
    Value: String | None


TagList = list[Tag]


class IPRange(TypedDict, total=False):
    Status: String | None
    CIDRIP: String | None
    Tags: TagList | None


IPRangeList = list[IPRange]


class EC2SecurityGroup(TypedDict, total=False):
    Status: String | None
    EC2SecurityGroupName: String | None
    EC2SecurityGroupOwnerId: String | None
    Tags: TagList | None


EC2SecurityGroupList = list[EC2SecurityGroup]


class ClusterSecurityGroup(TypedDict, total=False):
    ClusterSecurityGroupName: String | None
    Description: String | None
    EC2SecurityGroups: EC2SecurityGroupList | None
    IPRanges: IPRangeList | None
    Tags: TagList | None


class AuthorizeClusterSecurityGroupIngressResult(TypedDict, total=False):
    ClusterSecurityGroup: ClusterSecurityGroup | None


class AuthorizeDataShareMessage(ServiceRequest):
    DataShareArn: String
    ConsumerIdentifier: String
    AllowWrites: BooleanOptional | None


VpcIdentifierList = list[String]


class AuthorizeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: String | None
    Account: String
    VpcIds: VpcIdentifierList | None


class AuthorizeSnapshotAccessMessage(ServiceRequest):
    SnapshotIdentifier: String | None
    SnapshotArn: String | None
    SnapshotClusterIdentifier: String | None
    AccountWithRestoreAccess: String


RestorableNodeTypeList = list[String]
Long = int


class Snapshot(TypedDict, total=False):
    SnapshotIdentifier: String | None
    ClusterIdentifier: String | None
    SnapshotCreateTime: TStamp | None
    Status: String | None
    Port: Integer | None
    AvailabilityZone: String | None
    ClusterCreateTime: TStamp | None
    MasterUsername: String | None
    ClusterVersion: String | None
    EngineFullVersion: String | None
    SnapshotType: String | None
    NodeType: String | None
    NumberOfNodes: Integer | None
    DBName: String | None
    VpcId: String | None
    Encrypted: Boolean | None
    KmsKeyId: String | None
    EncryptedWithHSM: Boolean | None
    AccountsWithRestoreAccess: AccountsWithRestoreAccessList | None
    OwnerAccount: String | None
    TotalBackupSizeInMegaBytes: Double | None
    ActualIncrementalBackupSizeInMegaBytes: Double | None
    BackupProgressInMegaBytes: Double | None
    CurrentBackupRateInMegaBytesPerSecond: Double | None
    EstimatedSecondsToCompletion: Long | None
    ElapsedTimeInSeconds: Long | None
    SourceRegion: String | None
    Tags: TagList | None
    RestorableNodeTypes: RestorableNodeTypeList | None
    EnhancedVpcRouting: Boolean | None
    MaintenanceTrackName: String | None
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    ManualSnapshotRemainingDays: IntegerOptional | None
    SnapshotRetentionStartTime: TStamp | None
    MasterPasswordSecretArn: String | None
    MasterPasswordSecretKmsKeyId: String | None
    SnapshotArn: String | None


class AuthorizeSnapshotAccessResult(TypedDict, total=False):
    Snapshot: Snapshot | None


AuthorizedAudienceList = list[String]


class AuthorizedTokenIssuer(TypedDict, total=False):
    TrustedTokenIssuerArn: String | None
    AuthorizedAudiencesList: AuthorizedAudienceList | None


AuthorizedTokenIssuerList = list[AuthorizedTokenIssuer]


class SupportedPlatform(TypedDict, total=False):
    Name: String | None


SupportedPlatformsList = list[SupportedPlatform]


class AvailabilityZone(TypedDict, total=False):
    Name: String | None
    SupportedPlatforms: SupportedPlatformsList | None


AvailabilityZoneList = list[AvailabilityZone]


class DeleteClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    SnapshotClusterIdentifier: String | None


DeleteClusterSnapshotMessageList = list[DeleteClusterSnapshotMessage]


class BatchDeleteClusterSnapshotsRequest(ServiceRequest):
    Identifiers: DeleteClusterSnapshotMessageList


class SnapshotErrorMessage(TypedDict, total=False):
    SnapshotIdentifier: String | None
    SnapshotClusterIdentifier: String | None
    FailureCode: String | None
    FailureReason: String | None


BatchSnapshotOperationErrorList = list[SnapshotErrorMessage]
SnapshotIdentifierList = list[String]


class BatchDeleteClusterSnapshotsResult(TypedDict, total=False):
    Resources: SnapshotIdentifierList | None
    Errors: BatchSnapshotOperationErrorList | None


class BatchModifyClusterSnapshotsMessage(ServiceRequest):
    SnapshotIdentifierList: SnapshotIdentifierList
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    Force: Boolean | None


BatchSnapshotOperationErrors = list[SnapshotErrorMessage]


class BatchModifyClusterSnapshotsOutputMessage(TypedDict, total=False):
    Resources: SnapshotIdentifierList | None
    Errors: BatchSnapshotOperationErrors | None


class CancelResizeMessage(ServiceRequest):
    ClusterIdentifier: String


class ClusterNode(TypedDict, total=False):
    NodeRole: String | None
    PrivateIPAddress: String | None
    PublicIPAddress: String | None


ClusterNodesList = list[ClusterNode]


class SecondaryClusterInfo(TypedDict, total=False):
    AvailabilityZone: String | None
    ClusterNodes: ClusterNodesList | None


class ReservedNodeExchangeStatus(TypedDict, total=False):
    ReservedNodeExchangeRequestId: String | None
    Status: ReservedNodeExchangeStatusType | None
    RequestTime: TStamp | None
    SourceReservedNodeId: String | None
    SourceReservedNodeType: String | None
    SourceReservedNodeCount: Integer | None
    TargetReservedNodeOfferingId: String | None
    TargetReservedNodeType: String | None
    TargetReservedNodeCount: Integer | None


LongOptional = int


class ResizeInfo(TypedDict, total=False):
    ResizeType: String | None
    AllowCancelResize: Boolean | None


class DeferredMaintenanceWindow(TypedDict, total=False):
    DeferMaintenanceIdentifier: String | None
    DeferMaintenanceStartTime: TStamp | None
    DeferMaintenanceEndTime: TStamp | None


DeferredMaintenanceWindowsList = list[DeferredMaintenanceWindow]
PendingActionsList = list[String]


class ClusterIamRole(TypedDict, total=False):
    IamRoleArn: String | None
    ApplyStatus: String | None


ClusterIamRoleList = list[ClusterIamRole]


class ElasticIpStatus(TypedDict, total=False):
    ElasticIp: String | None
    Status: String | None


class ClusterSnapshotCopyStatus(TypedDict, total=False):
    DestinationRegion: String | None
    RetentionPeriod: Long | None
    ManualSnapshotRetentionPeriod: Integer | None
    SnapshotCopyGrantName: String | None


class HsmStatus(TypedDict, total=False):
    HsmClientCertificateIdentifier: String | None
    HsmConfigurationIdentifier: String | None
    Status: String | None


class DataTransferProgress(TypedDict, total=False):
    Status: String | None
    CurrentRateInMegaBytesPerSecond: DoubleOptional | None
    TotalDataInMegaBytes: Long | None
    DataTransferredInMegaBytes: Long | None
    EstimatedTimeToCompletionInSeconds: LongOptional | None
    ElapsedTimeInSeconds: LongOptional | None


class RestoreStatus(TypedDict, total=False):
    Status: String | None
    CurrentRestoreRateInMegaBytesPerSecond: Double | None
    SnapshotSizeInMegaBytes: Long | None
    ProgressInMegaBytes: Long | None
    ElapsedTimeInSeconds: Long | None
    EstimatedTimeToCompletionInSeconds: Long | None


class PendingModifiedValues(TypedDict, total=False):
    MasterUserPassword: SensitiveString | None
    NodeType: String | None
    NumberOfNodes: IntegerOptional | None
    ClusterType: String | None
    ClusterVersion: String | None
    AutomatedSnapshotRetentionPeriod: IntegerOptional | None
    ClusterIdentifier: String | None
    PubliclyAccessible: BooleanOptional | None
    EnhancedVpcRouting: BooleanOptional | None
    MaintenanceTrackName: String | None
    EncryptionType: String | None


class ClusterParameterStatus(TypedDict, total=False):
    ParameterName: String | None
    ParameterApplyStatus: String | None
    ParameterApplyErrorDescription: String | None


ClusterParameterStatusList = list[ClusterParameterStatus]


class ClusterParameterGroupStatus(TypedDict, total=False):
    ParameterGroupName: String | None
    ParameterApplyStatus: String | None
    ClusterParameterStatusList: ClusterParameterStatusList | None


ClusterParameterGroupStatusList = list[ClusterParameterGroupStatus]


class VpcSecurityGroupMembership(TypedDict, total=False):
    VpcSecurityGroupId: String | None
    Status: String | None


VpcSecurityGroupMembershipList = list[VpcSecurityGroupMembership]


class ClusterSecurityGroupMembership(TypedDict, total=False):
    ClusterSecurityGroupName: String | None
    Status: String | None


ClusterSecurityGroupMembershipList = list[ClusterSecurityGroupMembership]


class NetworkInterface(TypedDict, total=False):
    NetworkInterfaceId: String | None
    SubnetId: String | None
    PrivateIpAddress: String | None
    AvailabilityZone: String | None
    Ipv6Address: String | None


NetworkInterfaceList = list[NetworkInterface]


class VpcEndpoint(TypedDict, total=False):
    VpcEndpointId: String | None
    VpcId: String | None
    NetworkInterfaces: NetworkInterfaceList | None


VpcEndpointsList = list[VpcEndpoint]


class Endpoint(TypedDict, total=False):
    Address: String | None
    Port: Integer | None
    VpcEndpoints: VpcEndpointsList | None


class Cluster(TypedDict, total=False):
    ClusterIdentifier: String | None
    NodeType: String | None
    ClusterStatus: String | None
    ClusterAvailabilityStatus: String | None
    ModifyStatus: String | None
    MasterUsername: String | None
    DBName: String | None
    Endpoint: Endpoint | None
    ClusterCreateTime: TStamp | None
    AutomatedSnapshotRetentionPeriod: Integer | None
    ManualSnapshotRetentionPeriod: Integer | None
    ClusterSecurityGroups: ClusterSecurityGroupMembershipList | None
    VpcSecurityGroups: VpcSecurityGroupMembershipList | None
    ClusterParameterGroups: ClusterParameterGroupStatusList | None
    ClusterSubnetGroupName: String | None
    VpcId: String | None
    AvailabilityZone: String | None
    PreferredMaintenanceWindow: String | None
    PendingModifiedValues: PendingModifiedValues | None
    ClusterVersion: String | None
    AllowVersionUpgrade: Boolean | None
    NumberOfNodes: Integer | None
    PubliclyAccessible: Boolean | None
    Encrypted: Boolean | None
    RestoreStatus: RestoreStatus | None
    DataTransferProgress: DataTransferProgress | None
    HsmStatus: HsmStatus | None
    ClusterSnapshotCopyStatus: ClusterSnapshotCopyStatus | None
    ClusterPublicKey: String | None
    ClusterNodes: ClusterNodesList | None
    ElasticIpStatus: ElasticIpStatus | None
    ClusterRevisionNumber: String | None
    Tags: TagList | None
    KmsKeyId: String | None
    EnhancedVpcRouting: Boolean | None
    IamRoles: ClusterIamRoleList | None
    PendingActions: PendingActionsList | None
    MaintenanceTrackName: String | None
    ElasticResizeNumberOfNodeOptions: String | None
    DeferredMaintenanceWindows: DeferredMaintenanceWindowsList | None
    SnapshotScheduleIdentifier: String | None
    SnapshotScheduleState: ScheduleState | None
    ExpectedNextSnapshotScheduleTime: TStamp | None
    ExpectedNextSnapshotScheduleTimeStatus: String | None
    NextMaintenanceWindowStartTime: TStamp | None
    ResizeInfo: ResizeInfo | None
    AvailabilityZoneRelocationStatus: String | None
    ClusterNamespaceArn: String | None
    TotalStorageCapacityInMegaBytes: LongOptional | None
    AquaConfiguration: AquaConfiguration | None
    DefaultIamRoleArn: String | None
    ReservedNodeExchangeStatus: ReservedNodeExchangeStatus | None
    CustomDomainName: String | None
    CustomDomainCertificateArn: String | None
    CustomDomainCertificateExpiryDate: TStamp | None
    MasterPasswordSecretArn: String | None
    MasterPasswordSecretKmsKeyId: String | None
    IpAddressType: String | None
    MultiAZ: String | None
    MultiAZSecondary: SecondaryClusterInfo | None
    LakehouseRegistrationStatus: String | None
    CatalogArn: String | None


class ClusterCredentials(TypedDict, total=False):
    DbUser: String | None
    DbPassword: SensitiveString | None
    Expiration: TStamp | None


class RevisionTarget(TypedDict, total=False):
    DatabaseRevision: String | None
    Description: String | None
    DatabaseRevisionReleaseDate: TStamp | None


RevisionTargetsList = list[RevisionTarget]


class ClusterDbRevision(TypedDict, total=False):
    ClusterIdentifier: String | None
    CurrentDatabaseRevision: String | None
    DatabaseRevisionReleaseDate: TStamp | None
    RevisionTargets: RevisionTargetsList | None


ClusterDbRevisionsList = list[ClusterDbRevision]


class ClusterDbRevisionsMessage(TypedDict, total=False):
    Marker: String | None
    ClusterDbRevisions: ClusterDbRevisionsList | None


class ClusterExtendedCredentials(TypedDict, total=False):
    DbUser: String | None
    DbPassword: SensitiveString | None
    Expiration: TStamp | None
    NextRefreshTime: TStamp | None


ClusterIdentifierList = list[String]
ClusterList = list[Cluster]


class ClusterParameterGroup(TypedDict, total=False):
    ParameterGroupName: String | None
    ParameterGroupFamily: String | None
    Description: String | None
    Tags: TagList | None


class Parameter(TypedDict, total=False):
    ParameterName: String | None
    ParameterValue: String | None
    Description: String | None
    Source: String | None
    DataType: String | None
    AllowedValues: String | None
    ApplyType: ParameterApplyType | None
    IsModifiable: Boolean | None
    MinimumEngineVersion: String | None


ParametersList = list[Parameter]


class ClusterParameterGroupDetails(TypedDict, total=False):
    Parameters: ParametersList | None
    Marker: String | None


class ClusterParameterGroupNameMessage(TypedDict, total=False):
    ParameterGroupName: String | None
    ParameterGroupStatus: String | None


ParameterGroupList = list[ClusterParameterGroup]


class ClusterParameterGroupsMessage(TypedDict, total=False):
    Marker: String | None
    ParameterGroups: ParameterGroupList | None


ClusterSecurityGroups = list[ClusterSecurityGroup]


class ClusterSecurityGroupMessage(TypedDict, total=False):
    Marker: String | None
    ClusterSecurityGroups: ClusterSecurityGroups | None


ClusterSecurityGroupNameList = list[String]
ValueStringList = list[String]


class Subnet(TypedDict, total=False):
    SubnetIdentifier: String | None
    SubnetAvailabilityZone: AvailabilityZone | None
    SubnetStatus: String | None


SubnetList = list[Subnet]


class ClusterSubnetGroup(TypedDict, total=False):
    ClusterSubnetGroupName: String | None
    Description: String | None
    VpcId: String | None
    SubnetGroupStatus: String | None
    Subnets: SubnetList | None
    Tags: TagList | None
    SupportedClusterIpAddressTypes: ValueStringList | None


ClusterSubnetGroups = list[ClusterSubnetGroup]


class ClusterSubnetGroupMessage(TypedDict, total=False):
    Marker: String | None
    ClusterSubnetGroups: ClusterSubnetGroups | None


class ClusterVersion(TypedDict, total=False):
    ClusterVersion: String | None
    ClusterParameterGroupFamily: String | None
    Description: String | None


ClusterVersionList = list[ClusterVersion]


class ClusterVersionsMessage(TypedDict, total=False):
    Marker: String | None
    ClusterVersions: ClusterVersionList | None


class ClustersMessage(TypedDict, total=False):
    Marker: String | None
    Clusters: ClusterList | None


class Connect(TypedDict, total=False):
    Authorization: ServiceAuthorization


ConsumerIdentifierList = list[String]


class CopyClusterSnapshotMessage(ServiceRequest):
    SourceSnapshotIdentifier: String
    SourceSnapshotClusterIdentifier: String | None
    TargetSnapshotIdentifier: String
    ManualSnapshotRetentionPeriod: IntegerOptional | None


class CopyClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Snapshot | None


class CreateAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString
    AuthenticationProfileContent: String


class CreateAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: AuthenticationProfileNameString | None
    AuthenticationProfileContent: String | None


IamRoleArnList = list[String]
VpcSecurityGroupIdList = list[String]


class CreateClusterMessage(ServiceRequest):
    DBName: String | None
    ClusterIdentifier: String
    ClusterType: String | None
    NodeType: String
    MasterUsername: String
    MasterUserPassword: SensitiveString | None
    ClusterSecurityGroups: ClusterSecurityGroupNameList | None
    VpcSecurityGroupIds: VpcSecurityGroupIdList | None
    ClusterSubnetGroupName: String | None
    AvailabilityZone: String | None
    PreferredMaintenanceWindow: String | None
    ClusterParameterGroupName: String | None
    AutomatedSnapshotRetentionPeriod: IntegerOptional | None
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    Port: IntegerOptional | None
    ClusterVersion: String | None
    AllowVersionUpgrade: BooleanOptional | None
    NumberOfNodes: IntegerOptional | None
    PubliclyAccessible: BooleanOptional | None
    Encrypted: BooleanOptional | None
    HsmClientCertificateIdentifier: String | None
    HsmConfigurationIdentifier: String | None
    ElasticIp: String | None
    Tags: TagList | None
    KmsKeyId: String | None
    EnhancedVpcRouting: BooleanOptional | None
    AdditionalInfo: String | None
    IamRoles: IamRoleArnList | None
    MaintenanceTrackName: String | None
    SnapshotScheduleIdentifier: String | None
    AvailabilityZoneRelocation: BooleanOptional | None
    AquaConfigurationStatus: AquaConfigurationStatus | None
    DefaultIamRoleArn: String | None
    LoadSampleData: String | None
    ManageMasterPassword: BooleanOptional | None
    MasterPasswordSecretKmsKeyId: String | None
    IpAddressType: String | None
    MultiAZ: BooleanOptional | None
    RedshiftIdcApplicationArn: String | None
    CatalogName: CatalogNameString | None


class CreateClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    ParameterGroupFamily: String
    Description: String
    Tags: TagList | None


class CreateClusterParameterGroupResult(TypedDict, total=False):
    ClusterParameterGroup: ClusterParameterGroup | None


class CreateClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class CreateClusterSecurityGroupMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    Description: String
    Tags: TagList | None


class CreateClusterSecurityGroupResult(TypedDict, total=False):
    ClusterSecurityGroup: ClusterSecurityGroup | None


class CreateClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    ClusterIdentifier: String
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    Tags: TagList | None


class CreateClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Snapshot | None


SubnetIdentifierList = list[String]


class CreateClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String
    Description: String
    SubnetIds: SubnetIdentifierList
    Tags: TagList | None


class CreateClusterSubnetGroupResult(TypedDict, total=False):
    ClusterSubnetGroup: ClusterSubnetGroup | None


class CreateCustomDomainAssociationMessage(ServiceRequest):
    CustomDomainName: CustomDomainNameString
    CustomDomainCertificateArn: CustomDomainCertificateArnString
    ClusterIdentifier: String


class CreateCustomDomainAssociationResult(TypedDict, total=False):
    CustomDomainName: CustomDomainNameString | None
    CustomDomainCertificateArn: CustomDomainCertificateArnString | None
    ClusterIdentifier: String | None
    CustomDomainCertExpiryTime: String | None


class CreateEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: String | None
    ResourceOwner: String | None
    EndpointName: String
    SubnetGroupName: String
    VpcSecurityGroupIds: VpcSecurityGroupIdList | None


EventCategoriesList = list[String]
SourceIdsList = list[String]


class CreateEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: String
    SourceType: String | None
    SourceIds: SourceIdsList | None
    EventCategories: EventCategoriesList | None
    Severity: String | None
    Enabled: BooleanOptional | None
    Tags: TagList | None


class EventSubscription(TypedDict, total=False):
    CustomerAwsId: String | None
    CustSubscriptionId: String | None
    SnsTopicArn: String | None
    Status: String | None
    SubscriptionCreationTime: TStamp | None
    SourceType: String | None
    SourceIdsList: SourceIdsList | None
    EventCategoriesList: EventCategoriesList | None
    Severity: String | None
    Enabled: Boolean | None
    Tags: TagList | None


class CreateEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: EventSubscription | None


class CreateHsmClientCertificateMessage(ServiceRequest):
    HsmClientCertificateIdentifier: String
    Tags: TagList | None


class HsmClientCertificate(TypedDict, total=False):
    HsmClientCertificateIdentifier: String | None
    HsmClientCertificatePublicKey: String | None
    Tags: TagList | None


class CreateHsmClientCertificateResult(TypedDict, total=False):
    HsmClientCertificate: HsmClientCertificate | None


class CreateHsmConfigurationMessage(ServiceRequest):
    HsmConfigurationIdentifier: String
    Description: String
    HsmIpAddress: String
    HsmPartitionName: String
    HsmPartitionPassword: String
    HsmServerPublicCertificate: String
    Tags: TagList | None


class HsmConfiguration(TypedDict, total=False):
    HsmConfigurationIdentifier: String | None
    Description: String | None
    HsmIpAddress: String | None
    HsmPartitionName: String | None
    Tags: TagList | None


class CreateHsmConfigurationResult(TypedDict, total=False):
    HsmConfiguration: HsmConfiguration | None


EncryptionContextMap = dict[String, String]


class CreateIntegrationMessage(ServiceRequest):
    SourceArn: SourceArn
    TargetArn: TargetArn
    IntegrationName: IntegrationName
    KMSKeyId: String | None
    TagList: TagList | None
    AdditionalEncryptionContext: EncryptionContextMap | None
    Description: IntegrationDescription | None


TagKeyList = list[String]


class RedshiftScopeUnion(TypedDict, total=False):
    Connect: Connect | None


RedshiftServiceIntegrations = list[RedshiftScopeUnion]


class ReadWriteAccess(TypedDict, total=False):
    Authorization: ServiceAuthorization


class S3AccessGrantsScopeUnion(TypedDict, total=False):
    ReadWriteAccess: ReadWriteAccess | None


S3AccessGrantsServiceIntegrations = list[S3AccessGrantsScopeUnion]


class LakeFormationQuery(TypedDict, total=False):
    Authorization: ServiceAuthorization


class LakeFormationScopeUnion(TypedDict, total=False):
    LakeFormationQuery: LakeFormationQuery | None


LakeFormationServiceIntegrations = list[LakeFormationScopeUnion]


class ServiceIntegrationsUnion(TypedDict, total=False):
    LakeFormation: LakeFormationServiceIntegrations | None
    S3AccessGrants: S3AccessGrantsServiceIntegrations | None
    Redshift: RedshiftServiceIntegrations | None


ServiceIntegrationList = list[ServiceIntegrationsUnion]


class CreateRedshiftIdcApplicationMessage(ServiceRequest):
    IdcInstanceArn: String
    RedshiftIdcApplicationName: RedshiftIdcApplicationName
    IdentityNamespace: IdentityNamespaceString | None
    IdcDisplayName: IdcDisplayNameString
    IamRoleArn: String
    AuthorizedTokenIssuerList: AuthorizedTokenIssuerList | None
    ServiceIntegrations: ServiceIntegrationList | None
    ApplicationType: ApplicationType | None
    Tags: TagList | None
    SsoTagKeys: TagKeyList | None


class RedshiftIdcApplication(TypedDict, total=False):
    IdcInstanceArn: String | None
    RedshiftIdcApplicationName: RedshiftIdcApplicationName | None
    RedshiftIdcApplicationArn: String | None
    IdentityNamespace: IdentityNamespaceString | None
    IdcDisplayName: IdcDisplayNameString | None
    IamRoleArn: String | None
    IdcManagedApplicationArn: String | None
    IdcOnboardStatus: String | None
    AuthorizedTokenIssuerList: AuthorizedTokenIssuerList | None
    ServiceIntegrations: ServiceIntegrationList | None
    ApplicationType: ApplicationType | None
    Tags: TagList | None
    SsoTagKeys: TagKeyList | None


class CreateRedshiftIdcApplicationResult(TypedDict, total=False):
    RedshiftIdcApplication: RedshiftIdcApplication | None


class ResumeClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class PauseClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class ResizeClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    ClusterType: String | None
    NodeType: String | None
    NumberOfNodes: IntegerOptional | None
    Classic: BooleanOptional | None
    ReservedNodeId: String | None
    TargetReservedNodeOfferingId: String | None


class ScheduledActionType(TypedDict, total=False):
    ResizeCluster: ResizeClusterMessage | None
    PauseCluster: PauseClusterMessage | None
    ResumeCluster: ResumeClusterMessage | None


class CreateScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String
    TargetAction: ScheduledActionType
    Schedule: String
    IamRole: String
    ScheduledActionDescription: String | None
    StartTime: TStamp | None
    EndTime: TStamp | None
    Enable: BooleanOptional | None


class CreateSnapshotCopyGrantMessage(ServiceRequest):
    SnapshotCopyGrantName: String
    KmsKeyId: String | None
    Tags: TagList | None


class SnapshotCopyGrant(TypedDict, total=False):
    SnapshotCopyGrantName: String | None
    KmsKeyId: String | None
    Tags: TagList | None


class CreateSnapshotCopyGrantResult(TypedDict, total=False):
    SnapshotCopyGrant: SnapshotCopyGrant | None


ScheduleDefinitionList = list[String]


class CreateSnapshotScheduleMessage(ServiceRequest):
    ScheduleDefinitions: ScheduleDefinitionList | None
    ScheduleIdentifier: String | None
    ScheduleDescription: String | None
    Tags: TagList | None
    DryRun: BooleanOptional | None
    NextInvocations: IntegerOptional | None


class CreateTagsMessage(ServiceRequest):
    ResourceName: String
    Tags: TagList


class CreateUsageLimitMessage(ServiceRequest):
    ClusterIdentifier: String
    FeatureType: UsageLimitFeatureType
    LimitType: UsageLimitLimitType
    Amount: Long
    Period: UsageLimitPeriod | None
    BreachAction: UsageLimitBreachAction | None
    Tags: TagList | None


class CustomDomainAssociationsMessage(TypedDict, total=False):
    Marker: String | None
    Associations: AssociationList | None


class CustomerStorageMessage(TypedDict, total=False):
    TotalBackupSizeInMegaBytes: Double | None
    TotalProvisionedStorageInMegaBytes: Double | None


class DataShareAssociation(TypedDict, total=False):
    ConsumerIdentifier: String | None
    Status: DataShareStatus | None
    ConsumerRegion: String | None
    CreatedDate: TStamp | None
    StatusChangeDate: TStamp | None
    ProducerAllowedWrites: BooleanOptional | None
    ConsumerAcceptedWrites: BooleanOptional | None


DataShareAssociationList = list[DataShareAssociation]


class DataShare(TypedDict, total=False):
    DataShareArn: String | None
    ProducerArn: String | None
    AllowPubliclyAccessibleConsumers: Boolean | None
    DataShareAssociations: DataShareAssociationList | None
    ManagedBy: String | None
    DataShareType: DataShareType | None


DataShareList = list[DataShare]
DbGroupList = list[String]


class DeauthorizeDataShareMessage(ServiceRequest):
    DataShareArn: String
    ConsumerIdentifier: String


class DefaultClusterParameters(TypedDict, total=False):
    ParameterGroupFamily: String | None
    Marker: String | None
    Parameters: ParametersList | None


class DeleteAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString


class DeleteAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: AuthenticationProfileNameString | None


class DeleteClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    SkipFinalClusterSnapshot: Boolean | None
    FinalClusterSnapshotIdentifier: String | None
    FinalClusterSnapshotRetentionPeriod: IntegerOptional | None


class DeleteClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String


class DeleteClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class DeleteClusterSecurityGroupMessage(ServiceRequest):
    ClusterSecurityGroupName: String


class DeleteClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Snapshot | None


class DeleteClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String


class DeleteCustomDomainAssociationMessage(ServiceRequest):
    ClusterIdentifier: String
    CustomDomainName: CustomDomainNameString


class DeleteEndpointAccessMessage(ServiceRequest):
    EndpointName: String


class DeleteEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String


class DeleteHsmClientCertificateMessage(ServiceRequest):
    HsmClientCertificateIdentifier: String


class DeleteHsmConfigurationMessage(ServiceRequest):
    HsmConfigurationIdentifier: String


class DeleteIntegrationMessage(ServiceRequest):
    IntegrationArn: IntegrationArn


class DeleteRedshiftIdcApplicationMessage(ServiceRequest):
    RedshiftIdcApplicationArn: String


class DeleteResourcePolicyMessage(ServiceRequest):
    ResourceArn: String


class DeleteScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String


class DeleteSnapshotCopyGrantMessage(ServiceRequest):
    SnapshotCopyGrantName: String


class DeleteSnapshotScheduleMessage(ServiceRequest):
    ScheduleIdentifier: String


class DeleteTagsMessage(ServiceRequest):
    ResourceName: String
    TagKeys: TagKeyList


class DeleteUsageLimitMessage(ServiceRequest):
    UsageLimitId: String


class ProvisionedIdentifier(TypedDict, total=False):
    ClusterIdentifier: String


class ServerlessIdentifier(TypedDict, total=False):
    NamespaceIdentifier: String
    WorkgroupIdentifier: String


class NamespaceIdentifierUnion(TypedDict, total=False):
    ServerlessIdentifier: ServerlessIdentifier | None
    ProvisionedIdentifier: ProvisionedIdentifier | None


class DeregisterNamespaceInputMessage(ServiceRequest):
    NamespaceIdentifier: NamespaceIdentifierUnion
    ConsumerIdentifiers: ConsumerIdentifierList


class DeregisterNamespaceOutputMessage(TypedDict, total=False):
    Status: NamespaceRegistrationStatus | None


class DescribeAccountAttributesMessage(ServiceRequest):
    AttributeNames: AttributeNameList | None


class DescribeAuthenticationProfilesMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString | None


class DescribeAuthenticationProfilesResult(TypedDict, total=False):
    AuthenticationProfiles: AuthenticationProfileList | None


class DescribeClusterDbRevisionsMessage(ServiceRequest):
    ClusterIdentifier: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


TagValueList = list[String]


class DescribeClusterParameterGroupsMessage(ServiceRequest):
    ParameterGroupName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeClusterParametersMessage(ServiceRequest):
    ParameterGroupName: String
    Source: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeClusterSecurityGroupsMessage(ServiceRequest):
    ClusterSecurityGroupName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class SnapshotSortingEntity(TypedDict, total=False):
    Attribute: SnapshotAttributeToSortBy
    SortOrder: SortByOrder | None


SnapshotSortingEntityList = list[SnapshotSortingEntity]


class DescribeClusterSnapshotsMessage(ServiceRequest):
    ClusterIdentifier: String | None
    SnapshotIdentifier: String | None
    SnapshotArn: String | None
    SnapshotType: String | None
    StartTime: TStamp | None
    EndTime: TStamp | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    OwnerAccount: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None
    ClusterExists: BooleanOptional | None
    SortingEntities: SnapshotSortingEntityList | None


class DescribeClusterSubnetGroupsMessage(ServiceRequest):
    ClusterSubnetGroupName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeClusterTracksMessage(ServiceRequest):
    MaintenanceTrackName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeClusterVersionsMessage(ServiceRequest):
    ClusterVersion: String | None
    ClusterParameterGroupFamily: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeClustersMessage(ServiceRequest):
    ClusterIdentifier: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeCustomDomainAssociationsMessage(ServiceRequest):
    CustomDomainName: CustomDomainNameString | None
    CustomDomainCertificateArn: CustomDomainCertificateArnString | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeDataSharesForConsumerMessage(ServiceRequest):
    ConsumerArn: String | None
    Status: DataShareStatusForConsumer | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeDataSharesForConsumerResult(TypedDict, total=False):
    DataShares: DataShareList | None
    Marker: String | None


class DescribeDataSharesForProducerMessage(ServiceRequest):
    ProducerArn: String | None
    Status: DataShareStatusForProducer | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeDataSharesForProducerResult(TypedDict, total=False):
    DataShares: DataShareList | None
    Marker: String | None


class DescribeDataSharesMessage(ServiceRequest):
    DataShareArn: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeDataSharesResult(TypedDict, total=False):
    DataShares: DataShareList | None
    Marker: String | None


class DescribeDefaultClusterParametersMessage(ServiceRequest):
    ParameterGroupFamily: String
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeDefaultClusterParametersResult(TypedDict, total=False):
    DefaultClusterParameters: DefaultClusterParameters | None


class DescribeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: String | None
    ResourceOwner: String | None
    EndpointName: String | None
    VpcId: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeEndpointAuthorizationMessage(ServiceRequest):
    ClusterIdentifier: String | None
    Account: String | None
    Grantee: BooleanOptional | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeEventCategoriesMessage(ServiceRequest):
    SourceType: String | None


class DescribeEventSubscriptionsMessage(ServiceRequest):
    SubscriptionName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeEventsMessage(ServiceRequest):
    SourceIdentifier: String | None
    SourceType: SourceType | None
    StartTime: TStamp | None
    EndTime: TStamp | None
    Duration: IntegerOptional | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeHsmClientCertificatesMessage(ServiceRequest):
    HsmClientCertificateIdentifier: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeHsmConfigurationsMessage(ServiceRequest):
    HsmConfigurationIdentifier: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeInboundIntegrationsMessage(ServiceRequest):
    IntegrationArn: InboundIntegrationArn | None
    TargetArn: TargetArn | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


DescribeIntegrationsFilterValueList = list[String]


class DescribeIntegrationsFilter(TypedDict, total=False):
    Name: DescribeIntegrationsFilterName
    Values: DescribeIntegrationsFilterValueList


DescribeIntegrationsFilterList = list[DescribeIntegrationsFilter]


class DescribeIntegrationsMessage(ServiceRequest):
    IntegrationArn: IntegrationArn | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    Filters: DescribeIntegrationsFilterList | None


class DescribeLoggingStatusMessage(ServiceRequest):
    ClusterIdentifier: String


class NodeConfigurationOptionsFilter(TypedDict, total=False):
    Name: NodeConfigurationOptionsFilterName | None
    Operator: OperatorType | None
    Values: ValueStringList | None


NodeConfigurationOptionsFilterList = list[NodeConfigurationOptionsFilter]


class DescribeNodeConfigurationOptionsMessage(ServiceRequest):
    ActionType: ActionType
    ClusterIdentifier: String | None
    SnapshotIdentifier: String | None
    SnapshotArn: String | None
    OwnerAccount: String | None
    Filters: NodeConfigurationOptionsFilterList | None
    Marker: String | None
    MaxRecords: IntegerOptional | None


class DescribeOrderableClusterOptionsMessage(ServiceRequest):
    ClusterVersion: String | None
    NodeType: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribePartnersInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: PartnerIntegrationDatabaseName | None
    PartnerName: PartnerIntegrationPartnerName | None


class PartnerIntegrationInfo(TypedDict, total=False):
    DatabaseName: PartnerIntegrationDatabaseName | None
    PartnerName: PartnerIntegrationPartnerName | None
    Status: PartnerIntegrationStatus | None
    StatusMessage: PartnerIntegrationStatusMessage | None
    CreatedAt: TStamp | None
    UpdatedAt: TStamp | None


PartnerIntegrationInfoList = list[PartnerIntegrationInfo]


class DescribePartnersOutputMessage(TypedDict, total=False):
    PartnerIntegrationInfoList: PartnerIntegrationInfoList | None


class DescribeRedshiftIdcApplicationsMessage(ServiceRequest):
    RedshiftIdcApplicationArn: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


RedshiftIdcApplicationList = list[RedshiftIdcApplication]


class DescribeRedshiftIdcApplicationsResult(TypedDict, total=False):
    RedshiftIdcApplications: RedshiftIdcApplicationList | None
    Marker: String | None


class DescribeReservedNodeExchangeStatusInputMessage(ServiceRequest):
    ReservedNodeId: String | None
    ReservedNodeExchangeRequestId: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


ReservedNodeExchangeStatusList = list[ReservedNodeExchangeStatus]


class DescribeReservedNodeExchangeStatusOutputMessage(TypedDict, total=False):
    ReservedNodeExchangeStatusDetails: ReservedNodeExchangeStatusList | None
    Marker: String | None


class DescribeReservedNodeOfferingsMessage(ServiceRequest):
    ReservedNodeOfferingId: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeReservedNodesMessage(ServiceRequest):
    ReservedNodeId: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeResizeMessage(ServiceRequest):
    ClusterIdentifier: String


class ScheduledActionFilter(TypedDict, total=False):
    Name: ScheduledActionFilterName
    Values: ValueStringList


ScheduledActionFilterList = list[ScheduledActionFilter]


class DescribeScheduledActionsMessage(ServiceRequest):
    ScheduledActionName: String | None
    TargetActionType: ScheduledActionTypeValues | None
    StartTime: TStamp | None
    EndTime: TStamp | None
    Active: BooleanOptional | None
    Filters: ScheduledActionFilterList | None
    Marker: String | None
    MaxRecords: IntegerOptional | None


class DescribeSnapshotCopyGrantsMessage(ServiceRequest):
    SnapshotCopyGrantName: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeSnapshotSchedulesMessage(ServiceRequest):
    ClusterIdentifier: String | None
    ScheduleIdentifier: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None
    Marker: String | None
    MaxRecords: IntegerOptional | None


ScheduledSnapshotTimeList = list[TStamp]


class SnapshotSchedule(TypedDict, total=False):
    ScheduleDefinitions: ScheduleDefinitionList | None
    ScheduleIdentifier: String | None
    ScheduleDescription: String | None
    Tags: TagList | None
    NextInvocations: ScheduledSnapshotTimeList | None
    AssociatedClusterCount: IntegerOptional | None
    AssociatedClusters: AssociatedClusterList | None


SnapshotScheduleList = list[SnapshotSchedule]


class DescribeSnapshotSchedulesOutputMessage(TypedDict, total=False):
    SnapshotSchedules: SnapshotScheduleList | None
    Marker: String | None


class DescribeTableRestoreStatusMessage(ServiceRequest):
    ClusterIdentifier: String | None
    TableRestoreRequestId: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class DescribeTagsMessage(ServiceRequest):
    ResourceName: String | None
    ResourceType: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DescribeUsageLimitsMessage(ServiceRequest):
    UsageLimitId: String | None
    ClusterIdentifier: String | None
    FeatureType: UsageLimitFeatureType | None
    MaxRecords: IntegerOptional | None
    Marker: String | None
    TagKeys: TagKeyList | None
    TagValues: TagValueList | None


class DisableLoggingMessage(ServiceRequest):
    ClusterIdentifier: String


class DisableSnapshotCopyMessage(ServiceRequest):
    ClusterIdentifier: String


class DisableSnapshotCopyResult(TypedDict, total=False):
    Cluster: Cluster | None


class DisassociateDataShareConsumerMessage(ServiceRequest):
    DataShareArn: String
    DisassociateEntireAccount: BooleanOptional | None
    ConsumerArn: String | None
    ConsumerRegion: String | None


class SupportedOperation(TypedDict, total=False):
    OperationName: String | None


SupportedOperationList = list[SupportedOperation]


class UpdateTarget(TypedDict, total=False):
    MaintenanceTrackName: String | None
    DatabaseVersion: String | None
    SupportedOperations: SupportedOperationList | None


EligibleTracksToUpdateList = list[UpdateTarget]
LogTypeList = list[String]


class EnableLoggingMessage(ServiceRequest):
    ClusterIdentifier: String
    BucketName: String | None
    S3KeyPrefix: S3KeyPrefixValue | None
    LogDestinationType: LogDestinationType | None
    LogExports: LogTypeList | None


class EnableSnapshotCopyMessage(ServiceRequest):
    ClusterIdentifier: String
    DestinationRegion: String
    RetentionPeriod: IntegerOptional | None
    SnapshotCopyGrantName: String | None
    ManualSnapshotRetentionPeriod: IntegerOptional | None


class EnableSnapshotCopyResult(TypedDict, total=False):
    Cluster: Cluster | None


class EndpointAccess(TypedDict, total=False):
    ClusterIdentifier: String | None
    ResourceOwner: String | None
    SubnetGroupName: String | None
    EndpointStatus: String | None
    EndpointName: String | None
    EndpointCreateTime: TStamp | None
    Port: Integer | None
    Address: String | None
    VpcSecurityGroups: VpcSecurityGroupMembershipList | None
    VpcEndpoint: VpcEndpoint | None


EndpointAccesses = list[EndpointAccess]


class EndpointAccessList(TypedDict, total=False):
    EndpointAccessList: EndpointAccesses | None
    Marker: String | None


class EndpointAuthorization(TypedDict, total=False):
    Grantor: String | None
    Grantee: String | None
    ClusterIdentifier: String | None
    AuthorizeTime: TStamp | None
    ClusterStatus: String | None
    Status: AuthorizationStatus | None
    AllowedAllVPCs: Boolean | None
    AllowedVPCs: VpcIdentifierList | None
    EndpointCount: Integer | None


EndpointAuthorizations = list[EndpointAuthorization]


class EndpointAuthorizationList(TypedDict, total=False):
    EndpointAuthorizationList: EndpointAuthorizations | None
    Marker: String | None


class Event(TypedDict, total=False):
    SourceIdentifier: String | None
    SourceType: SourceType | None
    Message: String | None
    EventCategories: EventCategoriesList | None
    Severity: String | None
    Date: TStamp | None
    EventId: String | None


class EventInfoMap(TypedDict, total=False):
    EventId: String | None
    EventCategories: EventCategoriesList | None
    EventDescription: String | None
    Severity: String | None


EventInfoMapList = list[EventInfoMap]


class EventCategoriesMap(TypedDict, total=False):
    SourceType: String | None
    Events: EventInfoMapList | None


EventCategoriesMapList = list[EventCategoriesMap]


class EventCategoriesMessage(TypedDict, total=False):
    EventCategoriesMapList: EventCategoriesMapList | None


EventList = list[Event]
EventSubscriptionsList = list[EventSubscription]


class EventSubscriptionsMessage(TypedDict, total=False):
    Marker: String | None
    EventSubscriptionsList: EventSubscriptionsList | None


class EventsMessage(TypedDict, total=False):
    Marker: String | None
    Events: EventList | None


class FailoverPrimaryComputeInputMessage(ServiceRequest):
    ClusterIdentifier: String


class FailoverPrimaryComputeResult(TypedDict, total=False):
    Cluster: Cluster | None


class GetClusterCredentialsMessage(ServiceRequest):
    DbUser: String
    DbName: String | None
    ClusterIdentifier: String | None
    DurationSeconds: IntegerOptional | None
    AutoCreate: BooleanOptional | None
    DbGroups: DbGroupList | None
    CustomDomainName: String | None


class GetClusterCredentialsWithIAMMessage(ServiceRequest):
    DbName: String | None
    ClusterIdentifier: String | None
    DurationSeconds: IntegerOptional | None
    CustomDomainName: String | None


class GetIdentityCenterAuthTokenRequest(ServiceRequest):
    ClusterIds: ClusterIdentifierList


class GetIdentityCenterAuthTokenResponse(TypedDict, total=False):
    Token: SensitiveString | None
    ExpirationTime: TStamp | None


class GetReservedNodeExchangeConfigurationOptionsInputMessage(ServiceRequest):
    ActionType: ReservedNodeExchangeActionType
    ClusterIdentifier: String | None
    SnapshotIdentifier: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class ReservedNodeOffering(TypedDict, total=False):
    ReservedNodeOfferingId: String | None
    NodeType: String | None
    Duration: Integer | None
    FixedPrice: Double | None
    UsagePrice: Double | None
    CurrencyCode: String | None
    OfferingType: String | None
    RecurringCharges: RecurringChargeList | None
    ReservedNodeOfferingType: ReservedNodeOfferingType | None


class ReservedNodeConfigurationOption(TypedDict, total=False):
    SourceReservedNode: ReservedNode | None
    TargetReservedNodeCount: Integer | None
    TargetReservedNodeOffering: ReservedNodeOffering | None


ReservedNodeConfigurationOptionList = list[ReservedNodeConfigurationOption]


class GetReservedNodeExchangeConfigurationOptionsOutputMessage(TypedDict, total=False):
    Marker: String | None
    ReservedNodeConfigurationOptionList: ReservedNodeConfigurationOptionList | None


class GetReservedNodeExchangeOfferingsInputMessage(ServiceRequest):
    ReservedNodeId: String
    MaxRecords: IntegerOptional | None
    Marker: String | None


ReservedNodeOfferingList = list[ReservedNodeOffering]


class GetReservedNodeExchangeOfferingsOutputMessage(TypedDict, total=False):
    Marker: String | None
    ReservedNodeOfferings: ReservedNodeOfferingList | None


class GetResourcePolicyMessage(ServiceRequest):
    ResourceArn: String


class ResourcePolicy(TypedDict, total=False):
    ResourceArn: String | None
    Policy: String | None


class GetResourcePolicyResult(TypedDict, total=False):
    ResourcePolicy: ResourcePolicy | None


HsmClientCertificateList = list[HsmClientCertificate]


class HsmClientCertificateMessage(TypedDict, total=False):
    Marker: String | None
    HsmClientCertificates: HsmClientCertificateList | None


HsmConfigurationList = list[HsmConfiguration]


class HsmConfigurationMessage(TypedDict, total=False):
    Marker: String | None
    HsmConfigurations: HsmConfigurationList | None


ImportTablesCompleted = list[String]
ImportTablesInProgress = list[String]
ImportTablesNotStarted = list[String]


class IntegrationError(TypedDict, total=False):
    ErrorCode: String
    ErrorMessage: String | None


IntegrationErrorList = list[IntegrationError]


class InboundIntegration(TypedDict, total=False):
    IntegrationArn: InboundIntegrationArn | None
    SourceArn: String | None
    TargetArn: TargetArn | None
    Status: ZeroETLIntegrationStatus | None
    Errors: IntegrationErrorList | None
    CreateTime: TStamp | None


InboundIntegrationList = list[InboundIntegration]


class InboundIntegrationsMessage(TypedDict, total=False):
    Marker: String | None
    InboundIntegrations: InboundIntegrationList | None


class Integration(TypedDict, total=False):
    IntegrationArn: IntegrationArn | None
    IntegrationName: IntegrationName | None
    SourceArn: SourceArn | None
    TargetArn: TargetArn | None
    Status: ZeroETLIntegrationStatus | None
    Errors: IntegrationErrorList | None
    CreateTime: TStamp | None
    Description: Description | None
    KMSKeyId: String | None
    AdditionalEncryptionContext: EncryptionContextMap | None
    Tags: TagList | None


IntegrationList = list[Integration]


class IntegrationsMessage(TypedDict, total=False):
    Marker: String | None
    Integrations: IntegrationList | None


class LakehouseConfiguration(TypedDict, total=False):
    ClusterIdentifier: String | None
    LakehouseIdcApplicationArn: String | None
    LakehouseRegistrationStatus: String | None
    CatalogArn: String | None


class ListRecommendationsMessage(ServiceRequest):
    ClusterIdentifier: String | None
    NamespaceArn: String | None
    MaxRecords: IntegerOptional | None
    Marker: String | None


class ReferenceLink(TypedDict, total=False):
    Text: String | None
    Link: String | None


ReferenceLinkList = list[ReferenceLink]


class RecommendedAction(TypedDict, total=False):
    Text: String | None
    Database: String | None
    Command: String | None
    Type: RecommendedActionType | None


RecommendedActionList = list[RecommendedAction]


class Recommendation(TypedDict, total=False):
    Id: String | None
    ClusterIdentifier: String | None
    NamespaceArn: String | None
    CreatedAt: TStamp | None
    RecommendationType: String | None
    Title: String | None
    Description: String | None
    Observation: String | None
    ImpactRanking: ImpactRankingType | None
    RecommendationText: String | None
    RecommendedActions: RecommendedActionList | None
    ReferenceLinks: ReferenceLinkList | None


RecommendationList = list[Recommendation]


class ListRecommendationsResult(TypedDict, total=False):
    Recommendations: RecommendationList | None
    Marker: String | None


class LoggingStatus(TypedDict, total=False):
    LoggingEnabled: Boolean | None
    BucketName: String | None
    S3KeyPrefix: S3KeyPrefixValue | None
    LastSuccessfulDeliveryTime: TStamp | None
    LastFailureTime: TStamp | None
    LastFailureMessage: String | None
    LogDestinationType: LogDestinationType | None
    LogExports: LogTypeList | None


class MaintenanceTrack(TypedDict, total=False):
    MaintenanceTrackName: String | None
    DatabaseVersion: String | None
    UpdateTargets: EligibleTracksToUpdateList | None


class ModifyAquaInputMessage(ServiceRequest):
    ClusterIdentifier: String
    AquaConfigurationStatus: AquaConfigurationStatus | None


class ModifyAquaOutputMessage(TypedDict, total=False):
    AquaConfiguration: AquaConfiguration | None


class ModifyAuthenticationProfileMessage(ServiceRequest):
    AuthenticationProfileName: AuthenticationProfileNameString
    AuthenticationProfileContent: String


class ModifyAuthenticationProfileResult(TypedDict, total=False):
    AuthenticationProfileName: AuthenticationProfileNameString | None
    AuthenticationProfileContent: String | None


class ModifyClusterDbRevisionMessage(ServiceRequest):
    ClusterIdentifier: String
    RevisionTarget: String


class ModifyClusterDbRevisionResult(TypedDict, total=False):
    Cluster: Cluster | None


class ModifyClusterIamRolesMessage(ServiceRequest):
    ClusterIdentifier: String
    AddIamRoles: IamRoleArnList | None
    RemoveIamRoles: IamRoleArnList | None
    DefaultIamRoleArn: String | None


class ModifyClusterIamRolesResult(TypedDict, total=False):
    Cluster: Cluster | None


class ModifyClusterMaintenanceMessage(ServiceRequest):
    ClusterIdentifier: String
    DeferMaintenance: BooleanOptional | None
    DeferMaintenanceIdentifier: String | None
    DeferMaintenanceStartTime: TStamp | None
    DeferMaintenanceEndTime: TStamp | None
    DeferMaintenanceDuration: IntegerOptional | None


class ModifyClusterMaintenanceResult(TypedDict, total=False):
    Cluster: Cluster | None


class ModifyClusterMessage(ServiceRequest):
    ClusterIdentifier: String
    ClusterType: String | None
    NodeType: String | None
    NumberOfNodes: IntegerOptional | None
    ClusterSecurityGroups: ClusterSecurityGroupNameList | None
    VpcSecurityGroupIds: VpcSecurityGroupIdList | None
    MasterUserPassword: SensitiveString | None
    ClusterParameterGroupName: String | None
    AutomatedSnapshotRetentionPeriod: IntegerOptional | None
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    PreferredMaintenanceWindow: String | None
    ClusterVersion: String | None
    AllowVersionUpgrade: BooleanOptional | None
    HsmClientCertificateIdentifier: String | None
    HsmConfigurationIdentifier: String | None
    NewClusterIdentifier: String | None
    PubliclyAccessible: BooleanOptional | None
    ElasticIp: String | None
    EnhancedVpcRouting: BooleanOptional | None
    MaintenanceTrackName: String | None
    Encrypted: BooleanOptional | None
    KmsKeyId: String | None
    AvailabilityZoneRelocation: BooleanOptional | None
    AvailabilityZone: String | None
    Port: IntegerOptional | None
    ManageMasterPassword: BooleanOptional | None
    MasterPasswordSecretKmsKeyId: String | None
    IpAddressType: String | None
    MultiAZ: BooleanOptional | None


class ModifyClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    Parameters: ParametersList


class ModifyClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class ModifyClusterSnapshotMessage(ServiceRequest):
    SnapshotIdentifier: String
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    Force: Boolean | None


class ModifyClusterSnapshotResult(TypedDict, total=False):
    Snapshot: Snapshot | None


class ModifyClusterSnapshotScheduleMessage(ServiceRequest):
    ClusterIdentifier: String
    ScheduleIdentifier: String | None
    DisassociateSchedule: BooleanOptional | None


class ModifyClusterSubnetGroupMessage(ServiceRequest):
    ClusterSubnetGroupName: String
    Description: String | None
    SubnetIds: SubnetIdentifierList


class ModifyClusterSubnetGroupResult(TypedDict, total=False):
    ClusterSubnetGroup: ClusterSubnetGroup | None


class ModifyCustomDomainAssociationMessage(ServiceRequest):
    CustomDomainName: CustomDomainNameString
    CustomDomainCertificateArn: CustomDomainCertificateArnString
    ClusterIdentifier: String


class ModifyCustomDomainAssociationResult(TypedDict, total=False):
    CustomDomainName: CustomDomainNameString | None
    CustomDomainCertificateArn: CustomDomainCertificateArnString | None
    ClusterIdentifier: String | None
    CustomDomainCertExpiryTime: String | None


class ModifyEndpointAccessMessage(ServiceRequest):
    EndpointName: String
    VpcSecurityGroupIds: VpcSecurityGroupIdList | None


class ModifyEventSubscriptionMessage(ServiceRequest):
    SubscriptionName: String
    SnsTopicArn: String | None
    SourceType: String | None
    SourceIds: SourceIdsList | None
    EventCategories: EventCategoriesList | None
    Severity: String | None
    Enabled: BooleanOptional | None


class ModifyEventSubscriptionResult(TypedDict, total=False):
    EventSubscription: EventSubscription | None


class ModifyIntegrationMessage(ServiceRequest):
    IntegrationArn: IntegrationArn
    Description: IntegrationDescription | None
    IntegrationName: IntegrationName | None


class ModifyLakehouseConfigurationMessage(ServiceRequest):
    ClusterIdentifier: String
    LakehouseRegistration: LakehouseRegistration | None
    CatalogName: CatalogNameString | None
    LakehouseIdcRegistration: LakehouseIdcRegistration | None
    LakehouseIdcApplicationArn: String | None
    DryRun: BooleanOptional | None


class ModifyRedshiftIdcApplicationMessage(ServiceRequest):
    RedshiftIdcApplicationArn: String
    IdentityNamespace: IdentityNamespaceString | None
    IamRoleArn: String | None
    IdcDisplayName: IdcDisplayNameString | None
    AuthorizedTokenIssuerList: AuthorizedTokenIssuerList | None
    ServiceIntegrations: ServiceIntegrationList | None


class ModifyRedshiftIdcApplicationResult(TypedDict, total=False):
    RedshiftIdcApplication: RedshiftIdcApplication | None


class ModifyScheduledActionMessage(ServiceRequest):
    ScheduledActionName: String
    TargetAction: ScheduledActionType | None
    Schedule: String | None
    IamRole: String | None
    ScheduledActionDescription: String | None
    StartTime: TStamp | None
    EndTime: TStamp | None
    Enable: BooleanOptional | None


class ModifySnapshotCopyRetentionPeriodMessage(ServiceRequest):
    ClusterIdentifier: String
    RetentionPeriod: Integer
    Manual: Boolean | None


class ModifySnapshotCopyRetentionPeriodResult(TypedDict, total=False):
    Cluster: Cluster | None


class ModifySnapshotScheduleMessage(ServiceRequest):
    ScheduleIdentifier: String
    ScheduleDefinitions: ScheduleDefinitionList


class ModifyUsageLimitMessage(ServiceRequest):
    UsageLimitId: String
    Amount: LongOptional | None
    BreachAction: UsageLimitBreachAction | None


class NodeConfigurationOption(TypedDict, total=False):
    NodeType: String | None
    NumberOfNodes: Integer | None
    EstimatedDiskUtilizationPercent: DoubleOptional | None
    Mode: Mode | None


NodeConfigurationOptionList = list[NodeConfigurationOption]


class NodeConfigurationOptionsMessage(TypedDict, total=False):
    NodeConfigurationOptionList: NodeConfigurationOptionList | None
    Marker: String | None


class OrderableClusterOption(TypedDict, total=False):
    ClusterVersion: String | None
    ClusterType: String | None
    NodeType: String | None
    AvailabilityZones: AvailabilityZoneList | None


OrderableClusterOptionsList = list[OrderableClusterOption]


class OrderableClusterOptionsMessage(TypedDict, total=False):
    OrderableClusterOptions: OrderableClusterOptionsList | None
    Marker: String | None


class PartnerIntegrationInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: PartnerIntegrationDatabaseName
    PartnerName: PartnerIntegrationPartnerName


class PartnerIntegrationOutputMessage(TypedDict, total=False):
    DatabaseName: PartnerIntegrationDatabaseName | None
    PartnerName: PartnerIntegrationPartnerName | None


class PauseClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class PurchaseReservedNodeOfferingMessage(ServiceRequest):
    ReservedNodeOfferingId: String
    NodeCount: IntegerOptional | None


class PurchaseReservedNodeOfferingResult(TypedDict, total=False):
    ReservedNode: ReservedNode | None


class PutResourcePolicyMessage(ServiceRequest):
    ResourceArn: String
    Policy: String


class PutResourcePolicyResult(TypedDict, total=False):
    ResourcePolicy: ResourcePolicy | None


class RebootClusterMessage(ServiceRequest):
    ClusterIdentifier: String


class RebootClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class RegisterNamespaceInputMessage(ServiceRequest):
    NamespaceIdentifier: NamespaceIdentifierUnion
    ConsumerIdentifiers: ConsumerIdentifierList


class RegisterNamespaceOutputMessage(TypedDict, total=False):
    Status: NamespaceRegistrationStatus | None


class RejectDataShareMessage(ServiceRequest):
    DataShareArn: String


ReservedNodeList = list[ReservedNode]


class ReservedNodeOfferingsMessage(TypedDict, total=False):
    Marker: String | None
    ReservedNodeOfferings: ReservedNodeOfferingList | None


class ReservedNodesMessage(TypedDict, total=False):
    Marker: String | None
    ReservedNodes: ReservedNodeList | None


class ResetClusterParameterGroupMessage(ServiceRequest):
    ParameterGroupName: String
    ResetAllParameters: Boolean | None
    Parameters: ParametersList | None


class ResizeClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class ResizeProgressMessage(TypedDict, total=False):
    TargetNodeType: String | None
    TargetNumberOfNodes: IntegerOptional | None
    TargetClusterType: String | None
    Status: String | None
    ImportTablesCompleted: ImportTablesCompleted | None
    ImportTablesInProgress: ImportTablesInProgress | None
    ImportTablesNotStarted: ImportTablesNotStarted | None
    AvgResizeRateInMegaBytesPerSecond: DoubleOptional | None
    TotalResizeDataInMegaBytes: LongOptional | None
    ProgressInMegaBytes: LongOptional | None
    ElapsedTimeInSeconds: LongOptional | None
    EstimatedTimeToCompletionInSeconds: LongOptional | None
    ResizeType: String | None
    Message: String | None
    TargetEncryptionType: String | None
    DataTransferProgressPercent: DoubleOptional | None


class RestoreFromClusterSnapshotMessage(ServiceRequest):
    ClusterIdentifier: String
    SnapshotIdentifier: String | None
    SnapshotArn: String | None
    SnapshotClusterIdentifier: String | None
    Port: IntegerOptional | None
    AvailabilityZone: String | None
    AllowVersionUpgrade: BooleanOptional | None
    ClusterSubnetGroupName: String | None
    PubliclyAccessible: BooleanOptional | None
    OwnerAccount: String | None
    HsmClientCertificateIdentifier: String | None
    HsmConfigurationIdentifier: String | None
    ElasticIp: String | None
    ClusterParameterGroupName: String | None
    ClusterSecurityGroups: ClusterSecurityGroupNameList | None
    VpcSecurityGroupIds: VpcSecurityGroupIdList | None
    PreferredMaintenanceWindow: String | None
    AutomatedSnapshotRetentionPeriod: IntegerOptional | None
    ManualSnapshotRetentionPeriod: IntegerOptional | None
    KmsKeyId: String | None
    NodeType: String | None
    EnhancedVpcRouting: BooleanOptional | None
    AdditionalInfo: String | None
    IamRoles: IamRoleArnList | None
    MaintenanceTrackName: String | None
    SnapshotScheduleIdentifier: String | None
    NumberOfNodes: IntegerOptional | None
    AvailabilityZoneRelocation: BooleanOptional | None
    AquaConfigurationStatus: AquaConfigurationStatus | None
    DefaultIamRoleArn: String | None
    ReservedNodeId: String | None
    TargetReservedNodeOfferingId: String | None
    Encrypted: BooleanOptional | None
    ManageMasterPassword: BooleanOptional | None
    MasterPasswordSecretKmsKeyId: String | None
    IpAddressType: String | None
    MultiAZ: BooleanOptional | None
    CatalogName: CatalogNameString | None
    RedshiftIdcApplicationArn: String | None


class RestoreFromClusterSnapshotResult(TypedDict, total=False):
    Cluster: Cluster | None


class RestoreTableFromClusterSnapshotMessage(ServiceRequest):
    ClusterIdentifier: String
    SnapshotIdentifier: String
    SourceDatabaseName: String
    SourceSchemaName: String | None
    SourceTableName: String
    TargetDatabaseName: String | None
    TargetSchemaName: String | None
    NewTableName: String
    EnableCaseSensitiveIdentifier: BooleanOptional | None


class TableRestoreStatus(TypedDict, total=False):
    TableRestoreRequestId: String | None
    Status: TableRestoreStatusType | None
    Message: String | None
    RequestTime: TStamp | None
    ProgressInMegaBytes: LongOptional | None
    TotalDataInMegaBytes: LongOptional | None
    ClusterIdentifier: String | None
    SnapshotIdentifier: String | None
    SourceDatabaseName: String | None
    SourceSchemaName: String | None
    SourceTableName: String | None
    TargetDatabaseName: String | None
    TargetSchemaName: String | None
    NewTableName: String | None


class RestoreTableFromClusterSnapshotResult(TypedDict, total=False):
    TableRestoreStatus: TableRestoreStatus | None


class ResumeClusterResult(TypedDict, total=False):
    Cluster: Cluster | None


class RevokeClusterSecurityGroupIngressMessage(ServiceRequest):
    ClusterSecurityGroupName: String
    CIDRIP: String | None
    EC2SecurityGroupName: String | None
    EC2SecurityGroupOwnerId: String | None


class RevokeClusterSecurityGroupIngressResult(TypedDict, total=False):
    ClusterSecurityGroup: ClusterSecurityGroup | None


class RevokeEndpointAccessMessage(ServiceRequest):
    ClusterIdentifier: String | None
    Account: String | None
    VpcIds: VpcIdentifierList | None
    Force: Boolean | None


class RevokeSnapshotAccessMessage(ServiceRequest):
    SnapshotIdentifier: String | None
    SnapshotArn: String | None
    SnapshotClusterIdentifier: String | None
    AccountWithRestoreAccess: String


class RevokeSnapshotAccessResult(TypedDict, total=False):
    Snapshot: Snapshot | None


class RotateEncryptionKeyMessage(ServiceRequest):
    ClusterIdentifier: String


class RotateEncryptionKeyResult(TypedDict, total=False):
    Cluster: Cluster | None


ScheduledActionTimeList = list[TStamp]


class ScheduledAction(TypedDict, total=False):
    ScheduledActionName: String | None
    TargetAction: ScheduledActionType | None
    Schedule: String | None
    IamRole: String | None
    ScheduledActionDescription: String | None
    State: ScheduledActionState | None
    NextInvocations: ScheduledActionTimeList | None
    StartTime: TStamp | None
    EndTime: TStamp | None


ScheduledActionList = list[ScheduledAction]


class ScheduledActionsMessage(TypedDict, total=False):
    Marker: String | None
    ScheduledActions: ScheduledActionList | None


SnapshotCopyGrantList = list[SnapshotCopyGrant]


class SnapshotCopyGrantMessage(TypedDict, total=False):
    Marker: String | None
    SnapshotCopyGrants: SnapshotCopyGrantList | None


SnapshotList = list[Snapshot]


class SnapshotMessage(TypedDict, total=False):
    Marker: String | None
    Snapshots: SnapshotList | None


TableRestoreStatusList = list[TableRestoreStatus]


class TableRestoreStatusMessage(TypedDict, total=False):
    TableRestoreStatusDetails: TableRestoreStatusList | None
    Marker: String | None


class TaggedResource(TypedDict, total=False):
    Tag: Tag | None
    ResourceName: String | None
    ResourceType: String | None


TaggedResourceList = list[TaggedResource]


class TaggedResourceListMessage(TypedDict, total=False):
    TaggedResources: TaggedResourceList | None
    Marker: String | None


TrackList = list[MaintenanceTrack]


class TrackListMessage(TypedDict, total=False):
    MaintenanceTracks: TrackList | None
    Marker: String | None


class UpdatePartnerStatusInputMessage(ServiceRequest):
    AccountId: PartnerIntegrationAccountId
    ClusterIdentifier: PartnerIntegrationClusterIdentifier
    DatabaseName: PartnerIntegrationDatabaseName
    PartnerName: PartnerIntegrationPartnerName
    Status: PartnerIntegrationStatus
    StatusMessage: PartnerIntegrationStatusMessage | None


class UsageLimit(TypedDict, total=False):
    UsageLimitId: String | None
    ClusterIdentifier: String | None
    FeatureType: UsageLimitFeatureType | None
    LimitType: UsageLimitLimitType | None
    Amount: Long | None
    Period: UsageLimitPeriod | None
    BreachAction: UsageLimitBreachAction | None
    Tags: TagList | None


UsageLimits = list[UsageLimit]


class UsageLimitList(TypedDict, total=False):
    UsageLimits: UsageLimits | None
    Marker: String | None


class RedshiftApi:
    service: str = "redshift"
    version: str = "2012-12-01"

    @handler("AcceptReservedNodeExchange")
    def accept_reserved_node_exchange(
        self,
        context: RequestContext,
        reserved_node_id: String,
        target_reserved_node_offering_id: String,
        **kwargs,
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
        **kwargs,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError

    @handler("AssociateDataShareConsumer")
    def associate_data_share_consumer(
        self,
        context: RequestContext,
        data_share_arn: String,
        associate_entire_account: BooleanOptional | None = None,
        consumer_arn: String | None = None,
        consumer_region: String | None = None,
        allow_writes: BooleanOptional | None = None,
        **kwargs,
    ) -> DataShare:
        raise NotImplementedError

    @handler("AuthorizeClusterSecurityGroupIngress")
    def authorize_cluster_security_group_ingress(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        cidrip: String | None = None,
        ec2_security_group_name: String | None = None,
        ec2_security_group_owner_id: String | None = None,
        **kwargs,
    ) -> AuthorizeClusterSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("AuthorizeDataShare")
    def authorize_data_share(
        self,
        context: RequestContext,
        data_share_arn: String,
        consumer_identifier: String,
        allow_writes: BooleanOptional | None = None,
        **kwargs,
    ) -> DataShare:
        raise NotImplementedError

    @handler("AuthorizeEndpointAccess")
    def authorize_endpoint_access(
        self,
        context: RequestContext,
        account: String,
        cluster_identifier: String | None = None,
        vpc_ids: VpcIdentifierList | None = None,
        **kwargs,
    ) -> EndpointAuthorization:
        raise NotImplementedError

    @handler("AuthorizeSnapshotAccess")
    def authorize_snapshot_access(
        self,
        context: RequestContext,
        account_with_restore_access: String,
        snapshot_identifier: String | None = None,
        snapshot_arn: String | None = None,
        snapshot_cluster_identifier: String | None = None,
        **kwargs,
    ) -> AuthorizeSnapshotAccessResult:
        raise NotImplementedError

    @handler("BatchDeleteClusterSnapshots")
    def batch_delete_cluster_snapshots(
        self, context: RequestContext, identifiers: DeleteClusterSnapshotMessageList, **kwargs
    ) -> BatchDeleteClusterSnapshotsResult:
        raise NotImplementedError

    @handler("BatchModifyClusterSnapshots")
    def batch_modify_cluster_snapshots(
        self,
        context: RequestContext,
        snapshot_identifier_list: SnapshotIdentifierList,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> BatchModifyClusterSnapshotsOutputMessage:
        raise NotImplementedError

    @handler("CancelResize")
    def cancel_resize(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> ResizeProgressMessage:
        raise NotImplementedError

    @handler("CopyClusterSnapshot")
    def copy_cluster_snapshot(
        self,
        context: RequestContext,
        source_snapshot_identifier: String,
        target_snapshot_identifier: String,
        source_snapshot_cluster_identifier: String | None = None,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        **kwargs,
    ) -> CopyClusterSnapshotResult:
        raise NotImplementedError

    @handler("CreateAuthenticationProfile")
    def create_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
        authentication_profile_content: String,
        **kwargs,
    ) -> CreateAuthenticationProfileResult:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        node_type: String,
        master_username: String,
        db_name: String | None = None,
        cluster_type: String | None = None,
        master_user_password: SensitiveString | None = None,
        cluster_security_groups: ClusterSecurityGroupNameList | None = None,
        vpc_security_group_ids: VpcSecurityGroupIdList | None = None,
        cluster_subnet_group_name: String | None = None,
        availability_zone: String | None = None,
        preferred_maintenance_window: String | None = None,
        cluster_parameter_group_name: String | None = None,
        automated_snapshot_retention_period: IntegerOptional | None = None,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        port: IntegerOptional | None = None,
        cluster_version: String | None = None,
        allow_version_upgrade: BooleanOptional | None = None,
        number_of_nodes: IntegerOptional | None = None,
        publicly_accessible: BooleanOptional | None = None,
        encrypted: BooleanOptional | None = None,
        hsm_client_certificate_identifier: String | None = None,
        hsm_configuration_identifier: String | None = None,
        elastic_ip: String | None = None,
        tags: TagList | None = None,
        kms_key_id: String | None = None,
        enhanced_vpc_routing: BooleanOptional | None = None,
        additional_info: String | None = None,
        iam_roles: IamRoleArnList | None = None,
        maintenance_track_name: String | None = None,
        snapshot_schedule_identifier: String | None = None,
        availability_zone_relocation: BooleanOptional | None = None,
        aqua_configuration_status: AquaConfigurationStatus | None = None,
        default_iam_role_arn: String | None = None,
        load_sample_data: String | None = None,
        manage_master_password: BooleanOptional | None = None,
        master_password_secret_kms_key_id: String | None = None,
        ip_address_type: String | None = None,
        multi_az: BooleanOptional | None = None,
        redshift_idc_application_arn: String | None = None,
        catalog_name: CatalogNameString | None = None,
        **kwargs,
    ) -> CreateClusterResult:
        raise NotImplementedError

    @handler("CreateClusterParameterGroup")
    def create_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        parameter_group_family: String,
        description: String,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateClusterParameterGroupResult:
        raise NotImplementedError

    @handler("CreateClusterSecurityGroup")
    def create_cluster_security_group(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        description: String,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateClusterSecurityGroupResult:
        raise NotImplementedError

    @handler("CreateClusterSnapshot")
    def create_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        cluster_identifier: String,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateClusterSnapshotResult:
        raise NotImplementedError

    @handler("CreateClusterSubnetGroup")
    def create_cluster_subnet_group(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String,
        description: String,
        subnet_ids: SubnetIdentifierList,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateClusterSubnetGroupResult:
        raise NotImplementedError

    @handler("CreateCustomDomainAssociation")
    def create_custom_domain_association(
        self,
        context: RequestContext,
        custom_domain_name: CustomDomainNameString,
        custom_domain_certificate_arn: CustomDomainCertificateArnString,
        cluster_identifier: String,
        **kwargs,
    ) -> CreateCustomDomainAssociationResult:
        raise NotImplementedError

    @handler("CreateEndpointAccess")
    def create_endpoint_access(
        self,
        context: RequestContext,
        endpoint_name: String,
        subnet_group_name: String,
        cluster_identifier: String | None = None,
        resource_owner: String | None = None,
        vpc_security_group_ids: VpcSecurityGroupIdList | None = None,
        **kwargs,
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("CreateEventSubscription")
    def create_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String,
        source_type: String | None = None,
        source_ids: SourceIdsList | None = None,
        event_categories: EventCategoriesList | None = None,
        severity: String | None = None,
        enabled: BooleanOptional | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateEventSubscriptionResult:
        raise NotImplementedError

    @handler("CreateHsmClientCertificate")
    def create_hsm_client_certificate(
        self,
        context: RequestContext,
        hsm_client_certificate_identifier: String,
        tags: TagList | None = None,
        **kwargs,
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
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateHsmConfigurationResult:
        raise NotImplementedError

    @handler("CreateIntegration")
    def create_integration(
        self,
        context: RequestContext,
        source_arn: SourceArn,
        target_arn: TargetArn,
        integration_name: IntegrationName,
        kms_key_id: String | None = None,
        tag_list: TagList | None = None,
        additional_encryption_context: EncryptionContextMap | None = None,
        description: IntegrationDescription | None = None,
        **kwargs,
    ) -> Integration:
        raise NotImplementedError

    @handler("CreateRedshiftIdcApplication")
    def create_redshift_idc_application(
        self,
        context: RequestContext,
        idc_instance_arn: String,
        redshift_idc_application_name: RedshiftIdcApplicationName,
        idc_display_name: IdcDisplayNameString,
        iam_role_arn: String,
        identity_namespace: IdentityNamespaceString | None = None,
        authorized_token_issuer_list: AuthorizedTokenIssuerList | None = None,
        service_integrations: ServiceIntegrationList | None = None,
        application_type: ApplicationType | None = None,
        tags: TagList | None = None,
        sso_tag_keys: TagKeyList | None = None,
        **kwargs,
    ) -> CreateRedshiftIdcApplicationResult:
        raise NotImplementedError

    @handler("CreateScheduledAction")
    def create_scheduled_action(
        self,
        context: RequestContext,
        scheduled_action_name: String,
        target_action: ScheduledActionType,
        schedule: String,
        iam_role: String,
        scheduled_action_description: String | None = None,
        start_time: TStamp | None = None,
        end_time: TStamp | None = None,
        enable: BooleanOptional | None = None,
        **kwargs,
    ) -> ScheduledAction:
        raise NotImplementedError

    @handler("CreateSnapshotCopyGrant")
    def create_snapshot_copy_grant(
        self,
        context: RequestContext,
        snapshot_copy_grant_name: String,
        kms_key_id: String | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateSnapshotCopyGrantResult:
        raise NotImplementedError

    @handler("CreateSnapshotSchedule")
    def create_snapshot_schedule(
        self,
        context: RequestContext,
        schedule_definitions: ScheduleDefinitionList | None = None,
        schedule_identifier: String | None = None,
        schedule_description: String | None = None,
        tags: TagList | None = None,
        dry_run: BooleanOptional | None = None,
        next_invocations: IntegerOptional | None = None,
        **kwargs,
    ) -> SnapshotSchedule:
        raise NotImplementedError

    @handler("CreateTags")
    def create_tags(
        self, context: RequestContext, resource_name: String, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CreateUsageLimit")
    def create_usage_limit(
        self,
        context: RequestContext,
        cluster_identifier: String,
        feature_type: UsageLimitFeatureType,
        limit_type: UsageLimitLimitType,
        amount: Long,
        period: UsageLimitPeriod | None = None,
        breach_action: UsageLimitBreachAction | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> UsageLimit:
        raise NotImplementedError

    @handler("DeauthorizeDataShare")
    def deauthorize_data_share(
        self, context: RequestContext, data_share_arn: String, consumer_identifier: String, **kwargs
    ) -> DataShare:
        raise NotImplementedError

    @handler("DeleteAuthenticationProfile")
    def delete_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
        **kwargs,
    ) -> DeleteAuthenticationProfileResult:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        skip_final_cluster_snapshot: Boolean | None = None,
        final_cluster_snapshot_identifier: String | None = None,
        final_cluster_snapshot_retention_period: IntegerOptional | None = None,
        **kwargs,
    ) -> DeleteClusterResult:
        raise NotImplementedError

    @handler("DeleteClusterParameterGroup")
    def delete_cluster_parameter_group(
        self, context: RequestContext, parameter_group_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteClusterSecurityGroup")
    def delete_cluster_security_group(
        self, context: RequestContext, cluster_security_group_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteClusterSnapshot")
    def delete_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        snapshot_cluster_identifier: String | None = None,
        **kwargs,
    ) -> DeleteClusterSnapshotResult:
        raise NotImplementedError

    @handler("DeleteClusterSubnetGroup")
    def delete_cluster_subnet_group(
        self, context: RequestContext, cluster_subnet_group_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCustomDomainAssociation")
    def delete_custom_domain_association(
        self,
        context: RequestContext,
        cluster_identifier: String,
        custom_domain_name: CustomDomainNameString,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEndpointAccess")
    def delete_endpoint_access(
        self, context: RequestContext, endpoint_name: String, **kwargs
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("DeleteEventSubscription")
    def delete_event_subscription(
        self, context: RequestContext, subscription_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteHsmClientCertificate")
    def delete_hsm_client_certificate(
        self, context: RequestContext, hsm_client_certificate_identifier: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteHsmConfiguration")
    def delete_hsm_configuration(
        self, context: RequestContext, hsm_configuration_identifier: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIntegration")
    def delete_integration(
        self, context: RequestContext, integration_arn: IntegrationArn, **kwargs
    ) -> Integration:
        raise NotImplementedError

    @handler("DeletePartner")
    def delete_partner(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName,
        partner_name: PartnerIntegrationPartnerName,
        **kwargs,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError

    @handler("DeleteRedshiftIdcApplication")
    def delete_redshift_idc_application(
        self, context: RequestContext, redshift_idc_application_arn: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self, context: RequestContext, resource_arn: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteScheduledAction")
    def delete_scheduled_action(
        self, context: RequestContext, scheduled_action_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSnapshotCopyGrant")
    def delete_snapshot_copy_grant(
        self, context: RequestContext, snapshot_copy_grant_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSnapshotSchedule")
    def delete_snapshot_schedule(
        self, context: RequestContext, schedule_identifier: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(
        self, context: RequestContext, resource_name: String, tag_keys: TagKeyList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUsageLimit")
    def delete_usage_limit(self, context: RequestContext, usage_limit_id: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeregisterNamespace")
    def deregister_namespace(
        self,
        context: RequestContext,
        namespace_identifier: NamespaceIdentifierUnion,
        consumer_identifiers: ConsumerIdentifierList,
        **kwargs,
    ) -> DeregisterNamespaceOutputMessage:
        raise NotImplementedError

    @handler("DescribeAccountAttributes")
    def describe_account_attributes(
        self, context: RequestContext, attribute_names: AttributeNameList | None = None, **kwargs
    ) -> AccountAttributeList:
        raise NotImplementedError

    @handler("DescribeAuthenticationProfiles")
    def describe_authentication_profiles(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString | None = None,
        **kwargs,
    ) -> DescribeAuthenticationProfilesResult:
        raise NotImplementedError

    @handler("DescribeClusterDbRevisions")
    def describe_cluster_db_revisions(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ClusterDbRevisionsMessage:
        raise NotImplementedError

    @handler("DescribeClusterParameterGroups")
    def describe_cluster_parameter_groups(
        self,
        context: RequestContext,
        parameter_group_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> ClusterParameterGroupsMessage:
        raise NotImplementedError

    @handler("DescribeClusterParameters")
    def describe_cluster_parameters(
        self,
        context: RequestContext,
        parameter_group_name: String,
        source: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ClusterParameterGroupDetails:
        raise NotImplementedError

    @handler("DescribeClusterSecurityGroups")
    def describe_cluster_security_groups(
        self,
        context: RequestContext,
        cluster_security_group_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> ClusterSecurityGroupMessage:
        raise NotImplementedError

    @handler("DescribeClusterSnapshots")
    def describe_cluster_snapshots(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        snapshot_identifier: String | None = None,
        snapshot_arn: String | None = None,
        snapshot_type: String | None = None,
        start_time: TStamp | None = None,
        end_time: TStamp | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        owner_account: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        cluster_exists: BooleanOptional | None = None,
        sorting_entities: SnapshotSortingEntityList | None = None,
        **kwargs,
    ) -> SnapshotMessage:
        raise NotImplementedError

    @handler("DescribeClusterSubnetGroups")
    def describe_cluster_subnet_groups(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> ClusterSubnetGroupMessage:
        raise NotImplementedError

    @handler("DescribeClusterTracks")
    def describe_cluster_tracks(
        self,
        context: RequestContext,
        maintenance_track_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> TrackListMessage:
        raise NotImplementedError

    @handler("DescribeClusterVersions")
    def describe_cluster_versions(
        self,
        context: RequestContext,
        cluster_version: String | None = None,
        cluster_parameter_group_family: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ClusterVersionsMessage:
        raise NotImplementedError

    @handler("DescribeClusters")
    def describe_clusters(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> ClustersMessage:
        raise NotImplementedError

    @handler("DescribeCustomDomainAssociations")
    def describe_custom_domain_associations(
        self,
        context: RequestContext,
        custom_domain_name: CustomDomainNameString | None = None,
        custom_domain_certificate_arn: CustomDomainCertificateArnString | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> CustomDomainAssociationsMessage:
        raise NotImplementedError

    @handler("DescribeDataShares")
    def describe_data_shares(
        self,
        context: RequestContext,
        data_share_arn: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeDataSharesResult:
        raise NotImplementedError

    @handler("DescribeDataSharesForConsumer")
    def describe_data_shares_for_consumer(
        self,
        context: RequestContext,
        consumer_arn: String | None = None,
        status: DataShareStatusForConsumer | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeDataSharesForConsumerResult:
        raise NotImplementedError

    @handler("DescribeDataSharesForProducer")
    def describe_data_shares_for_producer(
        self,
        context: RequestContext,
        producer_arn: String | None = None,
        status: DataShareStatusForProducer | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeDataSharesForProducerResult:
        raise NotImplementedError

    @handler("DescribeDefaultClusterParameters")
    def describe_default_cluster_parameters(
        self,
        context: RequestContext,
        parameter_group_family: String,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeDefaultClusterParametersResult:
        raise NotImplementedError

    @handler("DescribeEndpointAccess")
    def describe_endpoint_access(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        resource_owner: String | None = None,
        endpoint_name: String | None = None,
        vpc_id: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> EndpointAccessList:
        raise NotImplementedError

    @handler("DescribeEndpointAuthorization")
    def describe_endpoint_authorization(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        account: String | None = None,
        grantee: BooleanOptional | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> EndpointAuthorizationList:
        raise NotImplementedError

    @handler("DescribeEventCategories")
    def describe_event_categories(
        self, context: RequestContext, source_type: String | None = None, **kwargs
    ) -> EventCategoriesMessage:
        raise NotImplementedError

    @handler("DescribeEventSubscriptions")
    def describe_event_subscriptions(
        self,
        context: RequestContext,
        subscription_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> EventSubscriptionsMessage:
        raise NotImplementedError

    @handler("DescribeEvents")
    def describe_events(
        self,
        context: RequestContext,
        source_identifier: String | None = None,
        source_type: SourceType | None = None,
        start_time: TStamp | None = None,
        end_time: TStamp | None = None,
        duration: IntegerOptional | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> EventsMessage:
        raise NotImplementedError

    @handler("DescribeHsmClientCertificates")
    def describe_hsm_client_certificates(
        self,
        context: RequestContext,
        hsm_client_certificate_identifier: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> HsmClientCertificateMessage:
        raise NotImplementedError

    @handler("DescribeHsmConfigurations")
    def describe_hsm_configurations(
        self,
        context: RequestContext,
        hsm_configuration_identifier: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> HsmConfigurationMessage:
        raise NotImplementedError

    @handler("DescribeInboundIntegrations")
    def describe_inbound_integrations(
        self,
        context: RequestContext,
        integration_arn: InboundIntegrationArn | None = None,
        target_arn: TargetArn | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> InboundIntegrationsMessage:
        raise NotImplementedError

    @handler("DescribeIntegrations")
    def describe_integrations(
        self,
        context: RequestContext,
        integration_arn: IntegrationArn | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        filters: DescribeIntegrationsFilterList | None = None,
        **kwargs,
    ) -> IntegrationsMessage:
        raise NotImplementedError

    @handler("DescribeLoggingStatus")
    def describe_logging_status(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> LoggingStatus:
        raise NotImplementedError

    @handler("DescribeNodeConfigurationOptions")
    def describe_node_configuration_options(
        self,
        context: RequestContext,
        action_type: ActionType,
        cluster_identifier: String | None = None,
        snapshot_identifier: String | None = None,
        snapshot_arn: String | None = None,
        owner_account: String | None = None,
        filters: NodeConfigurationOptionsFilterList | None = None,
        marker: String | None = None,
        max_records: IntegerOptional | None = None,
        **kwargs,
    ) -> NodeConfigurationOptionsMessage:
        raise NotImplementedError

    @handler("DescribeOrderableClusterOptions")
    def describe_orderable_cluster_options(
        self,
        context: RequestContext,
        cluster_version: String | None = None,
        node_type: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> OrderableClusterOptionsMessage:
        raise NotImplementedError

    @handler("DescribePartners")
    def describe_partners(
        self,
        context: RequestContext,
        account_id: PartnerIntegrationAccountId,
        cluster_identifier: PartnerIntegrationClusterIdentifier,
        database_name: PartnerIntegrationDatabaseName | None = None,
        partner_name: PartnerIntegrationPartnerName | None = None,
        **kwargs,
    ) -> DescribePartnersOutputMessage:
        raise NotImplementedError

    @handler("DescribeRedshiftIdcApplications")
    def describe_redshift_idc_applications(
        self,
        context: RequestContext,
        redshift_idc_application_arn: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeRedshiftIdcApplicationsResult:
        raise NotImplementedError

    @handler("DescribeReservedNodeExchangeStatus")
    def describe_reserved_node_exchange_status(
        self,
        context: RequestContext,
        reserved_node_id: String | None = None,
        reserved_node_exchange_request_id: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> DescribeReservedNodeExchangeStatusOutputMessage:
        raise NotImplementedError

    @handler("DescribeReservedNodeOfferings")
    def describe_reserved_node_offerings(
        self,
        context: RequestContext,
        reserved_node_offering_id: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ReservedNodeOfferingsMessage:
        raise NotImplementedError

    @handler("DescribeReservedNodes")
    def describe_reserved_nodes(
        self,
        context: RequestContext,
        reserved_node_id: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ReservedNodesMessage:
        raise NotImplementedError

    @handler("DescribeResize")
    def describe_resize(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> ResizeProgressMessage:
        raise NotImplementedError

    @handler("DescribeScheduledActions")
    def describe_scheduled_actions(
        self,
        context: RequestContext,
        scheduled_action_name: String | None = None,
        target_action_type: ScheduledActionTypeValues | None = None,
        start_time: TStamp | None = None,
        end_time: TStamp | None = None,
        active: BooleanOptional | None = None,
        filters: ScheduledActionFilterList | None = None,
        marker: String | None = None,
        max_records: IntegerOptional | None = None,
        **kwargs,
    ) -> ScheduledActionsMessage:
        raise NotImplementedError

    @handler("DescribeSnapshotCopyGrants")
    def describe_snapshot_copy_grants(
        self,
        context: RequestContext,
        snapshot_copy_grant_name: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> SnapshotCopyGrantMessage:
        raise NotImplementedError

    @handler("DescribeSnapshotSchedules")
    def describe_snapshot_schedules(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        schedule_identifier: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        marker: String | None = None,
        max_records: IntegerOptional | None = None,
        **kwargs,
    ) -> DescribeSnapshotSchedulesOutputMessage:
        raise NotImplementedError

    @handler("DescribeStorage")
    def describe_storage(self, context: RequestContext, **kwargs) -> CustomerStorageMessage:
        raise NotImplementedError

    @handler("DescribeTableRestoreStatus")
    def describe_table_restore_status(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        table_restore_request_id: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> TableRestoreStatusMessage:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self,
        context: RequestContext,
        resource_name: String | None = None,
        resource_type: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> TaggedResourceListMessage:
        raise NotImplementedError

    @handler("DescribeUsageLimits")
    def describe_usage_limits(
        self,
        context: RequestContext,
        usage_limit_id: String | None = None,
        cluster_identifier: String | None = None,
        feature_type: UsageLimitFeatureType | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        tag_keys: TagKeyList | None = None,
        tag_values: TagValueList | None = None,
        **kwargs,
    ) -> UsageLimitList:
        raise NotImplementedError

    @handler("DisableLogging")
    def disable_logging(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> LoggingStatus:
        raise NotImplementedError

    @handler("DisableSnapshotCopy")
    def disable_snapshot_copy(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> DisableSnapshotCopyResult:
        raise NotImplementedError

    @handler("DisassociateDataShareConsumer")
    def disassociate_data_share_consumer(
        self,
        context: RequestContext,
        data_share_arn: String,
        disassociate_entire_account: BooleanOptional | None = None,
        consumer_arn: String | None = None,
        consumer_region: String | None = None,
        **kwargs,
    ) -> DataShare:
        raise NotImplementedError

    @handler("EnableLogging")
    def enable_logging(
        self,
        context: RequestContext,
        cluster_identifier: String,
        bucket_name: String | None = None,
        s3_key_prefix: S3KeyPrefixValue | None = None,
        log_destination_type: LogDestinationType | None = None,
        log_exports: LogTypeList | None = None,
        **kwargs,
    ) -> LoggingStatus:
        raise NotImplementedError

    @handler("EnableSnapshotCopy")
    def enable_snapshot_copy(
        self,
        context: RequestContext,
        cluster_identifier: String,
        destination_region: String,
        retention_period: IntegerOptional | None = None,
        snapshot_copy_grant_name: String | None = None,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        **kwargs,
    ) -> EnableSnapshotCopyResult:
        raise NotImplementedError

    @handler("FailoverPrimaryCompute")
    def failover_primary_compute(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> FailoverPrimaryComputeResult:
        raise NotImplementedError

    @handler("GetClusterCredentials")
    def get_cluster_credentials(
        self,
        context: RequestContext,
        db_user: String,
        db_name: String | None = None,
        cluster_identifier: String | None = None,
        duration_seconds: IntegerOptional | None = None,
        auto_create: BooleanOptional | None = None,
        db_groups: DbGroupList | None = None,
        custom_domain_name: String | None = None,
        **kwargs,
    ) -> ClusterCredentials:
        raise NotImplementedError

    @handler("GetClusterCredentialsWithIAM")
    def get_cluster_credentials_with_iam(
        self,
        context: RequestContext,
        db_name: String | None = None,
        cluster_identifier: String | None = None,
        duration_seconds: IntegerOptional | None = None,
        custom_domain_name: String | None = None,
        **kwargs,
    ) -> ClusterExtendedCredentials:
        raise NotImplementedError

    @handler("GetIdentityCenterAuthToken")
    def get_identity_center_auth_token(
        self, context: RequestContext, cluster_ids: ClusterIdentifierList, **kwargs
    ) -> GetIdentityCenterAuthTokenResponse:
        raise NotImplementedError

    @handler("GetReservedNodeExchangeConfigurationOptions")
    def get_reserved_node_exchange_configuration_options(
        self,
        context: RequestContext,
        action_type: ReservedNodeExchangeActionType,
        cluster_identifier: String | None = None,
        snapshot_identifier: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> GetReservedNodeExchangeConfigurationOptionsOutputMessage:
        raise NotImplementedError

    @handler("GetReservedNodeExchangeOfferings")
    def get_reserved_node_exchange_offerings(
        self,
        context: RequestContext,
        reserved_node_id: String,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> GetReservedNodeExchangeOfferingsOutputMessage:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, resource_arn: String, **kwargs
    ) -> GetResourcePolicyResult:
        raise NotImplementedError

    @handler("ListRecommendations")
    def list_recommendations(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        namespace_arn: String | None = None,
        max_records: IntegerOptional | None = None,
        marker: String | None = None,
        **kwargs,
    ) -> ListRecommendationsResult:
        raise NotImplementedError

    @handler("ModifyAquaConfiguration")
    def modify_aqua_configuration(
        self,
        context: RequestContext,
        cluster_identifier: String,
        aqua_configuration_status: AquaConfigurationStatus | None = None,
        **kwargs,
    ) -> ModifyAquaOutputMessage:
        raise NotImplementedError

    @handler("ModifyAuthenticationProfile")
    def modify_authentication_profile(
        self,
        context: RequestContext,
        authentication_profile_name: AuthenticationProfileNameString,
        authentication_profile_content: String,
        **kwargs,
    ) -> ModifyAuthenticationProfileResult:
        raise NotImplementedError

    @handler("ModifyCluster")
    def modify_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        cluster_type: String | None = None,
        node_type: String | None = None,
        number_of_nodes: IntegerOptional | None = None,
        cluster_security_groups: ClusterSecurityGroupNameList | None = None,
        vpc_security_group_ids: VpcSecurityGroupIdList | None = None,
        master_user_password: SensitiveString | None = None,
        cluster_parameter_group_name: String | None = None,
        automated_snapshot_retention_period: IntegerOptional | None = None,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        preferred_maintenance_window: String | None = None,
        cluster_version: String | None = None,
        allow_version_upgrade: BooleanOptional | None = None,
        hsm_client_certificate_identifier: String | None = None,
        hsm_configuration_identifier: String | None = None,
        new_cluster_identifier: String | None = None,
        publicly_accessible: BooleanOptional | None = None,
        elastic_ip: String | None = None,
        enhanced_vpc_routing: BooleanOptional | None = None,
        maintenance_track_name: String | None = None,
        encrypted: BooleanOptional | None = None,
        kms_key_id: String | None = None,
        availability_zone_relocation: BooleanOptional | None = None,
        availability_zone: String | None = None,
        port: IntegerOptional | None = None,
        manage_master_password: BooleanOptional | None = None,
        master_password_secret_kms_key_id: String | None = None,
        ip_address_type: String | None = None,
        multi_az: BooleanOptional | None = None,
        **kwargs,
    ) -> ModifyClusterResult:
        raise NotImplementedError

    @handler("ModifyClusterDbRevision")
    def modify_cluster_db_revision(
        self, context: RequestContext, cluster_identifier: String, revision_target: String, **kwargs
    ) -> ModifyClusterDbRevisionResult:
        raise NotImplementedError

    @handler("ModifyClusterIamRoles")
    def modify_cluster_iam_roles(
        self,
        context: RequestContext,
        cluster_identifier: String,
        add_iam_roles: IamRoleArnList | None = None,
        remove_iam_roles: IamRoleArnList | None = None,
        default_iam_role_arn: String | None = None,
        **kwargs,
    ) -> ModifyClusterIamRolesResult:
        raise NotImplementedError

    @handler("ModifyClusterMaintenance")
    def modify_cluster_maintenance(
        self,
        context: RequestContext,
        cluster_identifier: String,
        defer_maintenance: BooleanOptional | None = None,
        defer_maintenance_identifier: String | None = None,
        defer_maintenance_start_time: TStamp | None = None,
        defer_maintenance_end_time: TStamp | None = None,
        defer_maintenance_duration: IntegerOptional | None = None,
        **kwargs,
    ) -> ModifyClusterMaintenanceResult:
        raise NotImplementedError

    @handler("ModifyClusterParameterGroup")
    def modify_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        parameters: ParametersList,
        **kwargs,
    ) -> ClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ModifyClusterSnapshot")
    def modify_cluster_snapshot(
        self,
        context: RequestContext,
        snapshot_identifier: String,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> ModifyClusterSnapshotResult:
        raise NotImplementedError

    @handler("ModifyClusterSnapshotSchedule")
    def modify_cluster_snapshot_schedule(
        self,
        context: RequestContext,
        cluster_identifier: String,
        schedule_identifier: String | None = None,
        disassociate_schedule: BooleanOptional | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyClusterSubnetGroup")
    def modify_cluster_subnet_group(
        self,
        context: RequestContext,
        cluster_subnet_group_name: String,
        subnet_ids: SubnetIdentifierList,
        description: String | None = None,
        **kwargs,
    ) -> ModifyClusterSubnetGroupResult:
        raise NotImplementedError

    @handler("ModifyCustomDomainAssociation")
    def modify_custom_domain_association(
        self,
        context: RequestContext,
        custom_domain_name: CustomDomainNameString,
        custom_domain_certificate_arn: CustomDomainCertificateArnString,
        cluster_identifier: String,
        **kwargs,
    ) -> ModifyCustomDomainAssociationResult:
        raise NotImplementedError

    @handler("ModifyEndpointAccess")
    def modify_endpoint_access(
        self,
        context: RequestContext,
        endpoint_name: String,
        vpc_security_group_ids: VpcSecurityGroupIdList | None = None,
        **kwargs,
    ) -> EndpointAccess:
        raise NotImplementedError

    @handler("ModifyEventSubscription")
    def modify_event_subscription(
        self,
        context: RequestContext,
        subscription_name: String,
        sns_topic_arn: String | None = None,
        source_type: String | None = None,
        source_ids: SourceIdsList | None = None,
        event_categories: EventCategoriesList | None = None,
        severity: String | None = None,
        enabled: BooleanOptional | None = None,
        **kwargs,
    ) -> ModifyEventSubscriptionResult:
        raise NotImplementedError

    @handler("ModifyIntegration")
    def modify_integration(
        self,
        context: RequestContext,
        integration_arn: IntegrationArn,
        description: IntegrationDescription | None = None,
        integration_name: IntegrationName | None = None,
        **kwargs,
    ) -> Integration:
        raise NotImplementedError

    @handler("ModifyLakehouseConfiguration")
    def modify_lakehouse_configuration(
        self,
        context: RequestContext,
        cluster_identifier: String,
        lakehouse_registration: LakehouseRegistration | None = None,
        catalog_name: CatalogNameString | None = None,
        lakehouse_idc_registration: LakehouseIdcRegistration | None = None,
        lakehouse_idc_application_arn: String | None = None,
        dry_run: BooleanOptional | None = None,
        **kwargs,
    ) -> LakehouseConfiguration:
        raise NotImplementedError

    @handler("ModifyRedshiftIdcApplication")
    def modify_redshift_idc_application(
        self,
        context: RequestContext,
        redshift_idc_application_arn: String,
        identity_namespace: IdentityNamespaceString | None = None,
        iam_role_arn: String | None = None,
        idc_display_name: IdcDisplayNameString | None = None,
        authorized_token_issuer_list: AuthorizedTokenIssuerList | None = None,
        service_integrations: ServiceIntegrationList | None = None,
        **kwargs,
    ) -> ModifyRedshiftIdcApplicationResult:
        raise NotImplementedError

    @handler("ModifyScheduledAction")
    def modify_scheduled_action(
        self,
        context: RequestContext,
        scheduled_action_name: String,
        target_action: ScheduledActionType | None = None,
        schedule: String | None = None,
        iam_role: String | None = None,
        scheduled_action_description: String | None = None,
        start_time: TStamp | None = None,
        end_time: TStamp | None = None,
        enable: BooleanOptional | None = None,
        **kwargs,
    ) -> ScheduledAction:
        raise NotImplementedError

    @handler("ModifySnapshotCopyRetentionPeriod")
    def modify_snapshot_copy_retention_period(
        self,
        context: RequestContext,
        cluster_identifier: String,
        retention_period: Integer,
        manual: Boolean | None = None,
        **kwargs,
    ) -> ModifySnapshotCopyRetentionPeriodResult:
        raise NotImplementedError

    @handler("ModifySnapshotSchedule")
    def modify_snapshot_schedule(
        self,
        context: RequestContext,
        schedule_identifier: String,
        schedule_definitions: ScheduleDefinitionList,
        **kwargs,
    ) -> SnapshotSchedule:
        raise NotImplementedError

    @handler("ModifyUsageLimit")
    def modify_usage_limit(
        self,
        context: RequestContext,
        usage_limit_id: String,
        amount: LongOptional | None = None,
        breach_action: UsageLimitBreachAction | None = None,
        **kwargs,
    ) -> UsageLimit:
        raise NotImplementedError

    @handler("PauseCluster")
    def pause_cluster(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> PauseClusterResult:
        raise NotImplementedError

    @handler("PurchaseReservedNodeOffering")
    def purchase_reserved_node_offering(
        self,
        context: RequestContext,
        reserved_node_offering_id: String,
        node_count: IntegerOptional | None = None,
        **kwargs,
    ) -> PurchaseReservedNodeOfferingResult:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self, context: RequestContext, resource_arn: String, policy: String, **kwargs
    ) -> PutResourcePolicyResult:
        raise NotImplementedError

    @handler("RebootCluster")
    def reboot_cluster(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> RebootClusterResult:
        raise NotImplementedError

    @handler("RegisterNamespace")
    def register_namespace(
        self,
        context: RequestContext,
        namespace_identifier: NamespaceIdentifierUnion,
        consumer_identifiers: ConsumerIdentifierList,
        **kwargs,
    ) -> RegisterNamespaceOutputMessage:
        raise NotImplementedError

    @handler("RejectDataShare")
    def reject_data_share(
        self, context: RequestContext, data_share_arn: String, **kwargs
    ) -> DataShare:
        raise NotImplementedError

    @handler("ResetClusterParameterGroup")
    def reset_cluster_parameter_group(
        self,
        context: RequestContext,
        parameter_group_name: String,
        reset_all_parameters: Boolean | None = None,
        parameters: ParametersList | None = None,
        **kwargs,
    ) -> ClusterParameterGroupNameMessage:
        raise NotImplementedError

    @handler("ResizeCluster")
    def resize_cluster(
        self,
        context: RequestContext,
        cluster_identifier: String,
        cluster_type: String | None = None,
        node_type: String | None = None,
        number_of_nodes: IntegerOptional | None = None,
        classic: BooleanOptional | None = None,
        reserved_node_id: String | None = None,
        target_reserved_node_offering_id: String | None = None,
        **kwargs,
    ) -> ResizeClusterResult:
        raise NotImplementedError

    @handler("RestoreFromClusterSnapshot")
    def restore_from_cluster_snapshot(
        self,
        context: RequestContext,
        cluster_identifier: String,
        snapshot_identifier: String | None = None,
        snapshot_arn: String | None = None,
        snapshot_cluster_identifier: String | None = None,
        port: IntegerOptional | None = None,
        availability_zone: String | None = None,
        allow_version_upgrade: BooleanOptional | None = None,
        cluster_subnet_group_name: String | None = None,
        publicly_accessible: BooleanOptional | None = None,
        owner_account: String | None = None,
        hsm_client_certificate_identifier: String | None = None,
        hsm_configuration_identifier: String | None = None,
        elastic_ip: String | None = None,
        cluster_parameter_group_name: String | None = None,
        cluster_security_groups: ClusterSecurityGroupNameList | None = None,
        vpc_security_group_ids: VpcSecurityGroupIdList | None = None,
        preferred_maintenance_window: String | None = None,
        automated_snapshot_retention_period: IntegerOptional | None = None,
        manual_snapshot_retention_period: IntegerOptional | None = None,
        kms_key_id: String | None = None,
        node_type: String | None = None,
        enhanced_vpc_routing: BooleanOptional | None = None,
        additional_info: String | None = None,
        iam_roles: IamRoleArnList | None = None,
        maintenance_track_name: String | None = None,
        snapshot_schedule_identifier: String | None = None,
        number_of_nodes: IntegerOptional | None = None,
        availability_zone_relocation: BooleanOptional | None = None,
        aqua_configuration_status: AquaConfigurationStatus | None = None,
        default_iam_role_arn: String | None = None,
        reserved_node_id: String | None = None,
        target_reserved_node_offering_id: String | None = None,
        encrypted: BooleanOptional | None = None,
        manage_master_password: BooleanOptional | None = None,
        master_password_secret_kms_key_id: String | None = None,
        ip_address_type: String | None = None,
        multi_az: BooleanOptional | None = None,
        catalog_name: CatalogNameString | None = None,
        redshift_idc_application_arn: String | None = None,
        **kwargs,
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
        source_schema_name: String | None = None,
        target_database_name: String | None = None,
        target_schema_name: String | None = None,
        enable_case_sensitive_identifier: BooleanOptional | None = None,
        **kwargs,
    ) -> RestoreTableFromClusterSnapshotResult:
        raise NotImplementedError

    @handler("ResumeCluster")
    def resume_cluster(
        self, context: RequestContext, cluster_identifier: String, **kwargs
    ) -> ResumeClusterResult:
        raise NotImplementedError

    @handler("RevokeClusterSecurityGroupIngress")
    def revoke_cluster_security_group_ingress(
        self,
        context: RequestContext,
        cluster_security_group_name: String,
        cidrip: String | None = None,
        ec2_security_group_name: String | None = None,
        ec2_security_group_owner_id: String | None = None,
        **kwargs,
    ) -> RevokeClusterSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("RevokeEndpointAccess")
    def revoke_endpoint_access(
        self,
        context: RequestContext,
        cluster_identifier: String | None = None,
        account: String | None = None,
        vpc_ids: VpcIdentifierList | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> EndpointAuthorization:
        raise NotImplementedError

    @handler("RevokeSnapshotAccess")
    def revoke_snapshot_access(
        self,
        context: RequestContext,
        account_with_restore_access: String,
        snapshot_identifier: String | None = None,
        snapshot_arn: String | None = None,
        snapshot_cluster_identifier: String | None = None,
        **kwargs,
    ) -> RevokeSnapshotAccessResult:
        raise NotImplementedError

    @handler("RotateEncryptionKey")
    def rotate_encryption_key(
        self, context: RequestContext, cluster_identifier: String, **kwargs
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
        status_message: PartnerIntegrationStatusMessage | None = None,
        **kwargs,
    ) -> PartnerIntegrationOutputMessage:
        raise NotImplementedError
