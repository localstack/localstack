from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AcceptTermsAndConditions = bool
Account = str
AccountGateStatusReason = str
AccountsUrl = str
AfterContext = str
AfterValue = str
AllowedValue = str
Arn = str
AutoDeploymentNullable = bool
AutoUpdate = bool
BeforeContext = str
BeforeValue = str
BoxedInteger = int
BoxedMaxResults = int
CapabilitiesReason = str
CausingEntity = str
ChangeSetId = str
ChangeSetName = str
ChangeSetNameOrId = str
ChangeSetStatusReason = str
ClientRequestToken = str
ClientToken = str
ConfigurationSchema = str
ConnectionArn = str
Description = str
DetectionReason = str
DisableRollback = bool
DriftedStackInstancesCount = int
EnableStackCreation = bool
EnableTerminationProtection = bool
ErrorCode = str
ErrorMessage = str
EventId = str
ExecutionRoleName = str
ExecutionStatusReason = str
ExportName = str
ExportValue = str
FailedStackInstancesCount = int
FailureToleranceCount = int
FailureTolerancePercentage = int
GeneratedTemplateId = str
GeneratedTemplateName = str
HookInvocationCount = int
HookResultId = str
HookStatusReason = str
HookTargetTypeName = str
HookType = str
HookTypeConfigurationVersionId = str
HookTypeName = str
HookTypeVersionId = str
ImportExistingResources = bool
InProgressStackInstancesCount = int
InSyncStackInstancesCount = int
IncludeNestedStacks = bool
IncludePropertyValues = bool
IsActivated = bool
IsDefaultConfiguration = bool
IsDefaultVersion = bool
JazzResourceIdentifierPropertyKey = str
JazzResourceIdentifierPropertyValue = str
Key = str
LimitName = str
LimitValue = int
LogGroupName = str
LogicalIdHierarchy = str
LogicalResourceId = str
ManagedByStack = bool
ManagedExecutionNullable = bool
MaxConcurrentCount = int
MaxConcurrentPercentage = int
MaxResults = int
Metadata = str
MonitoringTimeInMinutes = int
NextToken = str
NoEcho = bool
NotificationARN = str
NumberOfResources = int
OperationResultFilterValues = str
OptionalSecureUrl = str
OrganizationalUnitId = str
OutputKey = str
OutputValue = str
ParameterKey = str
ParameterType = str
ParameterValue = str
PercentageCompleted = float
PhysicalResourceId = str
PrivateTypeArn = str
Properties = str
PropertyDescription = str
PropertyName = str
PropertyPath = str
PropertyValue = str
PublicVersionNumber = str
PublisherId = str
PublisherName = str
PublisherProfile = str
Reason = str
RefreshAllResources = bool
Region = str
RegistrationToken = str
RequestToken = str
RequiredProperty = bool
ResourceIdentifier = str
ResourceIdentifierPropertyKey = str
ResourceIdentifierPropertyValue = str
ResourceModel = str
ResourceProperties = str
ResourcePropertyPath = str
ResourceScanId = str
ResourceScanStatusReason = str
ResourceScannerMaxResults = int
ResourceSignalUniqueId = str
ResourceStatusReason = str
ResourceToSkip = str
ResourceType = str
ResourceTypeFilter = str
ResourceTypePrefix = str
ResourcesFailed = int
ResourcesPending = int
ResourcesProcessing = int
ResourcesRead = int
ResourcesScanned = int
ResourcesSucceeded = int
RetainExceptOnCreate = bool
RetainStacks = bool
RetainStacksNullable = bool
RetainStacksOnAccountRemovalNullable = bool
RoleARN = str
RoleArn = str
S3Bucket = str
S3Url = str
StackDriftDetectionId = str
StackDriftDetectionStatusReason = str
StackId = str
StackIdsUrl = str
StackInstanceFilterValues = str
StackName = str
StackNameOrId = str
StackPolicyBody = str
StackPolicyDuringUpdateBody = str
StackPolicyDuringUpdateURL = str
StackPolicyURL = str
StackRefactorId = str
StackRefactorResourceIdentifier = str
StackRefactorStatusReason = str
StackSetARN = str
StackSetId = str
StackSetName = str
StackSetNameOrId = str
StackSetOperationStatusReason = str
StackStatusReason = str
StatusMessage = str
SupportedMajorVersion = int
TagKey = str
TagValue = str
TemplateBody = str
TemplateDescription = str
TemplateStatusReason = str
TemplateURL = str
ThirdPartyTypeArn = str
TimeoutMinutes = int
TotalStackInstancesCount = int
TotalWarnings = int
TransformName = str
TreatUnrecognizedResourceTypesAsWarnings = bool
Type = str
TypeArn = str
TypeConfiguration = str
TypeConfigurationAlias = str
TypeConfigurationArn = str
TypeHierarchy = str
TypeName = str
TypeNamePrefix = str
TypeSchema = str
TypeTestsStatusDescription = str
TypeVersionId = str
Url = str
UsePreviousTemplate = bool
UsePreviousValue = bool
Value = str
Version = str


class AccountFilterType(StrEnum):
    NONE = "NONE"
    INTERSECTION = "INTERSECTION"
    DIFFERENCE = "DIFFERENCE"
    UNION = "UNION"


class AccountGateStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class AttributeChangeType(StrEnum):
    Add = "Add"
    Remove = "Remove"
    Modify = "Modify"


class CallAs(StrEnum):
    SELF = "SELF"
    DELEGATED_ADMIN = "DELEGATED_ADMIN"


class Capability(StrEnum):
    CAPABILITY_IAM = "CAPABILITY_IAM"
    CAPABILITY_NAMED_IAM = "CAPABILITY_NAMED_IAM"
    CAPABILITY_AUTO_EXPAND = "CAPABILITY_AUTO_EXPAND"


class Category(StrEnum):
    REGISTERED = "REGISTERED"
    ACTIVATED = "ACTIVATED"
    THIRD_PARTY = "THIRD_PARTY"
    AWS_TYPES = "AWS_TYPES"


class ChangeAction(StrEnum):
    Add = "Add"
    Modify = "Modify"
    Remove = "Remove"
    Import = "Import"
    Dynamic = "Dynamic"


class ChangeSetHooksStatus(StrEnum):
    PLANNING = "PLANNING"
    PLANNED = "PLANNED"
    UNAVAILABLE = "UNAVAILABLE"


class ChangeSetStatus(StrEnum):
    CREATE_PENDING = "CREATE_PENDING"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    DELETE_PENDING = "DELETE_PENDING"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    DELETE_FAILED = "DELETE_FAILED"
    FAILED = "FAILED"


class ChangeSetType(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    IMPORT = "IMPORT"


class ChangeSource(StrEnum):
    ResourceReference = "ResourceReference"
    ParameterReference = "ParameterReference"
    ResourceAttribute = "ResourceAttribute"
    DirectModification = "DirectModification"
    Automatic = "Automatic"


class ChangeType(StrEnum):
    Resource = "Resource"


class ConcurrencyMode(StrEnum):
    STRICT_FAILURE_TOLERANCE = "STRICT_FAILURE_TOLERANCE"
    SOFT_FAILURE_TOLERANCE = "SOFT_FAILURE_TOLERANCE"


class DeletionMode(StrEnum):
    STANDARD = "STANDARD"
    FORCE_DELETE_STACK = "FORCE_DELETE_STACK"


class DeprecatedStatus(StrEnum):
    LIVE = "LIVE"
    DEPRECATED = "DEPRECATED"


class DetailedStatus(StrEnum):
    CONFIGURATION_COMPLETE = "CONFIGURATION_COMPLETE"
    VALIDATION_FAILED = "VALIDATION_FAILED"


class DifferenceType(StrEnum):
    ADD = "ADD"
    REMOVE = "REMOVE"
    NOT_EQUAL = "NOT_EQUAL"


class EvaluationType(StrEnum):
    Static = "Static"
    Dynamic = "Dynamic"


class ExecutionStatus(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    AVAILABLE = "AVAILABLE"
    EXECUTE_IN_PROGRESS = "EXECUTE_IN_PROGRESS"
    EXECUTE_COMPLETE = "EXECUTE_COMPLETE"
    EXECUTE_FAILED = "EXECUTE_FAILED"
    OBSOLETE = "OBSOLETE"


class GeneratedTemplateDeletionPolicy(StrEnum):
    DELETE = "DELETE"
    RETAIN = "RETAIN"


class GeneratedTemplateResourceStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETE = "COMPLETE"


class GeneratedTemplateStatus(StrEnum):
    CREATE_PENDING = "CREATE_PENDING"
    UPDATE_PENDING = "UPDATE_PENDING"
    DELETE_PENDING = "DELETE_PENDING"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETE = "COMPLETE"


class GeneratedTemplateUpdateReplacePolicy(StrEnum):
    DELETE = "DELETE"
    RETAIN = "RETAIN"


class HandlerErrorCode(StrEnum):
    NotUpdatable = "NotUpdatable"
    InvalidRequest = "InvalidRequest"
    AccessDenied = "AccessDenied"
    InvalidCredentials = "InvalidCredentials"
    AlreadyExists = "AlreadyExists"
    NotFound = "NotFound"
    ResourceConflict = "ResourceConflict"
    Throttling = "Throttling"
    ServiceLimitExceeded = "ServiceLimitExceeded"
    NotStabilized = "NotStabilized"
    GeneralServiceException = "GeneralServiceException"
    ServiceInternalError = "ServiceInternalError"
    NetworkFailure = "NetworkFailure"
    InternalFailure = "InternalFailure"
    InvalidTypeConfiguration = "InvalidTypeConfiguration"
    HandlerInternalFailure = "HandlerInternalFailure"
    NonCompliant = "NonCompliant"
    Unknown = "Unknown"
    UnsupportedTarget = "UnsupportedTarget"


class HookFailureMode(StrEnum):
    FAIL = "FAIL"
    WARN = "WARN"


class HookInvocationPoint(StrEnum):
    PRE_PROVISION = "PRE_PROVISION"


class HookStatus(StrEnum):
    HOOK_IN_PROGRESS = "HOOK_IN_PROGRESS"
    HOOK_COMPLETE_SUCCEEDED = "HOOK_COMPLETE_SUCCEEDED"
    HOOK_COMPLETE_FAILED = "HOOK_COMPLETE_FAILED"
    HOOK_FAILED = "HOOK_FAILED"


class HookTargetType(StrEnum):
    RESOURCE = "RESOURCE"


class IdentityProvider(StrEnum):
    AWS_Marketplace = "AWS_Marketplace"
    GitHub = "GitHub"
    Bitbucket = "Bitbucket"


class ListHookResultsTargetType(StrEnum):
    CHANGE_SET = "CHANGE_SET"
    STACK = "STACK"
    RESOURCE = "RESOURCE"
    CLOUD_CONTROL = "CLOUD_CONTROL"


class OnFailure(StrEnum):
    DO_NOTHING = "DO_NOTHING"
    ROLLBACK = "ROLLBACK"
    DELETE = "DELETE"


class OnStackFailure(StrEnum):
    DO_NOTHING = "DO_NOTHING"
    ROLLBACK = "ROLLBACK"
    DELETE = "DELETE"


class OperationResultFilterName(StrEnum):
    OPERATION_RESULT_STATUS = "OPERATION_RESULT_STATUS"


class OperationStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class OrganizationStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    DISABLED_PERMANENTLY = "DISABLED_PERMANENTLY"


class PermissionModels(StrEnum):
    SERVICE_MANAGED = "SERVICE_MANAGED"
    SELF_MANAGED = "SELF_MANAGED"


class PolicyAction(StrEnum):
    Delete = "Delete"
    Retain = "Retain"
    Snapshot = "Snapshot"
    ReplaceAndDelete = "ReplaceAndDelete"
    ReplaceAndRetain = "ReplaceAndRetain"
    ReplaceAndSnapshot = "ReplaceAndSnapshot"


class ProvisioningType(StrEnum):
    NON_PROVISIONABLE = "NON_PROVISIONABLE"
    IMMUTABLE = "IMMUTABLE"
    FULLY_MUTABLE = "FULLY_MUTABLE"


class PublisherStatus(StrEnum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


class RegionConcurrencyType(StrEnum):
    SEQUENTIAL = "SEQUENTIAL"
    PARALLEL = "PARALLEL"


class RegistrationStatus(StrEnum):
    COMPLETE = "COMPLETE"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"


class RegistryType(StrEnum):
    RESOURCE = "RESOURCE"
    MODULE = "MODULE"
    HOOK = "HOOK"


class Replacement(StrEnum):
    True_ = "True"
    False_ = "False"
    Conditional = "Conditional"


class RequiresRecreation(StrEnum):
    Never = "Never"
    Conditionally = "Conditionally"
    Always = "Always"


class ResourceAttribute(StrEnum):
    Properties = "Properties"
    Metadata = "Metadata"
    CreationPolicy = "CreationPolicy"
    UpdatePolicy = "UpdatePolicy"
    DeletionPolicy = "DeletionPolicy"
    UpdateReplacePolicy = "UpdateReplacePolicy"
    Tags = "Tags"


class ResourceScanStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETE = "COMPLETE"
    EXPIRED = "EXPIRED"


class ResourceSignalStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class ResourceStatus(StrEnum):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    DELETE_SKIPPED = "DELETE_SKIPPED"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"
    UPDATE_COMPLETE = "UPDATE_COMPLETE"
    IMPORT_FAILED = "IMPORT_FAILED"
    IMPORT_COMPLETE = "IMPORT_COMPLETE"
    IMPORT_IN_PROGRESS = "IMPORT_IN_PROGRESS"
    IMPORT_ROLLBACK_IN_PROGRESS = "IMPORT_ROLLBACK_IN_PROGRESS"
    IMPORT_ROLLBACK_FAILED = "IMPORT_ROLLBACK_FAILED"
    IMPORT_ROLLBACK_COMPLETE = "IMPORT_ROLLBACK_COMPLETE"
    EXPORT_FAILED = "EXPORT_FAILED"
    EXPORT_COMPLETE = "EXPORT_COMPLETE"
    EXPORT_IN_PROGRESS = "EXPORT_IN_PROGRESS"
    EXPORT_ROLLBACK_IN_PROGRESS = "EXPORT_ROLLBACK_IN_PROGRESS"
    EXPORT_ROLLBACK_FAILED = "EXPORT_ROLLBACK_FAILED"
    EXPORT_ROLLBACK_COMPLETE = "EXPORT_ROLLBACK_COMPLETE"
    UPDATE_ROLLBACK_IN_PROGRESS = "UPDATE_ROLLBACK_IN_PROGRESS"
    UPDATE_ROLLBACK_COMPLETE = "UPDATE_ROLLBACK_COMPLETE"
    UPDATE_ROLLBACK_FAILED = "UPDATE_ROLLBACK_FAILED"
    ROLLBACK_IN_PROGRESS = "ROLLBACK_IN_PROGRESS"
    ROLLBACK_COMPLETE = "ROLLBACK_COMPLETE"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class ScanType(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"


class StackDriftDetectionStatus(StrEnum):
    DETECTION_IN_PROGRESS = "DETECTION_IN_PROGRESS"
    DETECTION_FAILED = "DETECTION_FAILED"
    DETECTION_COMPLETE = "DETECTION_COMPLETE"


class StackDriftStatus(StrEnum):
    DRIFTED = "DRIFTED"
    IN_SYNC = "IN_SYNC"
    UNKNOWN = "UNKNOWN"
    NOT_CHECKED = "NOT_CHECKED"


class StackInstanceDetailedStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INOPERABLE = "INOPERABLE"
    SKIPPED_SUSPENDED_ACCOUNT = "SKIPPED_SUSPENDED_ACCOUNT"
    FAILED_IMPORT = "FAILED_IMPORT"


class StackInstanceFilterName(StrEnum):
    DETAILED_STATUS = "DETAILED_STATUS"
    LAST_OPERATION_ID = "LAST_OPERATION_ID"
    DRIFT_STATUS = "DRIFT_STATUS"


class StackInstanceStatus(StrEnum):
    CURRENT = "CURRENT"
    OUTDATED = "OUTDATED"
    INOPERABLE = "INOPERABLE"


class StackRefactorActionEntity(StrEnum):
    RESOURCE = "RESOURCE"
    STACK = "STACK"


class StackRefactorActionType(StrEnum):
    MOVE = "MOVE"
    CREATE = "CREATE"


class StackRefactorDetection(StrEnum):
    AUTO = "AUTO"
    MANUAL = "MANUAL"


class StackRefactorExecutionStatus(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    AVAILABLE = "AVAILABLE"
    OBSOLETE = "OBSOLETE"
    EXECUTE_IN_PROGRESS = "EXECUTE_IN_PROGRESS"
    EXECUTE_COMPLETE = "EXECUTE_COMPLETE"
    EXECUTE_FAILED = "EXECUTE_FAILED"
    ROLLBACK_IN_PROGRESS = "ROLLBACK_IN_PROGRESS"
    ROLLBACK_COMPLETE = "ROLLBACK_COMPLETE"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class StackRefactorStatus(StrEnum):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    DELETE_FAILED = "DELETE_FAILED"


class StackResourceDriftStatus(StrEnum):
    IN_SYNC = "IN_SYNC"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    NOT_CHECKED = "NOT_CHECKED"


class StackSetDriftDetectionStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    IN_PROGRESS = "IN_PROGRESS"
    STOPPED = "STOPPED"


class StackSetDriftStatus(StrEnum):
    DRIFTED = "DRIFTED"
    IN_SYNC = "IN_SYNC"
    NOT_CHECKED = "NOT_CHECKED"


class StackSetOperationAction(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    DETECT_DRIFT = "DETECT_DRIFT"


class StackSetOperationResultStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StackSetOperationStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    QUEUED = "QUEUED"


class StackSetStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"


class StackStatus(StrEnum):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    ROLLBACK_IN_PROGRESS = "ROLLBACK_IN_PROGRESS"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    ROLLBACK_COMPLETE = "ROLLBACK_COMPLETE"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_COMPLETE_CLEANUP_IN_PROGRESS = "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"
    UPDATE_COMPLETE = "UPDATE_COMPLETE"
    UPDATE_FAILED = "UPDATE_FAILED"
    UPDATE_ROLLBACK_IN_PROGRESS = "UPDATE_ROLLBACK_IN_PROGRESS"
    UPDATE_ROLLBACK_FAILED = "UPDATE_ROLLBACK_FAILED"
    UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS = "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS"
    UPDATE_ROLLBACK_COMPLETE = "UPDATE_ROLLBACK_COMPLETE"
    REVIEW_IN_PROGRESS = "REVIEW_IN_PROGRESS"
    IMPORT_IN_PROGRESS = "IMPORT_IN_PROGRESS"
    IMPORT_COMPLETE = "IMPORT_COMPLETE"
    IMPORT_ROLLBACK_IN_PROGRESS = "IMPORT_ROLLBACK_IN_PROGRESS"
    IMPORT_ROLLBACK_FAILED = "IMPORT_ROLLBACK_FAILED"
    IMPORT_ROLLBACK_COMPLETE = "IMPORT_ROLLBACK_COMPLETE"


class TemplateFormat(StrEnum):
    JSON = "JSON"
    YAML = "YAML"


class TemplateStage(StrEnum):
    Original = "Original"
    Processed = "Processed"


class ThirdPartyType(StrEnum):
    RESOURCE = "RESOURCE"
    MODULE = "MODULE"
    HOOK = "HOOK"


class TypeTestsStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    NOT_TESTED = "NOT_TESTED"


class VersionBump(StrEnum):
    MAJOR = "MAJOR"
    MINOR = "MINOR"


class Visibility(StrEnum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"


class WarningType(StrEnum):
    MUTUALLY_EXCLUSIVE_PROPERTIES = "MUTUALLY_EXCLUSIVE_PROPERTIES"
    UNSUPPORTED_PROPERTIES = "UNSUPPORTED_PROPERTIES"
    MUTUALLY_EXCLUSIVE_TYPES = "MUTUALLY_EXCLUSIVE_TYPES"


class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExistsException"
    sender_fault: bool = True
    status_code: int = 400


class CFNRegistryException(ServiceException):
    code: str = "CFNRegistryException"
    sender_fault: bool = True
    status_code: int = 400


class ChangeSetNotFoundException(ServiceException):
    code: str = "ChangeSetNotFound"
    sender_fault: bool = True
    status_code: int = 404


class ConcurrentResourcesLimitExceededException(ServiceException):
    code: str = "ConcurrentResourcesLimitExceeded"
    sender_fault: bool = True
    status_code: int = 429


class CreatedButModifiedException(ServiceException):
    code: str = "CreatedButModifiedException"
    sender_fault: bool = True
    status_code: int = 409


class GeneratedTemplateNotFoundException(ServiceException):
    code: str = "GeneratedTemplateNotFound"
    sender_fault: bool = True
    status_code: int = 404


class HookResultNotFoundException(ServiceException):
    code: str = "HookResultNotFound"
    sender_fault: bool = True
    status_code: int = 404


class InsufficientCapabilitiesException(ServiceException):
    code: str = "InsufficientCapabilitiesException"
    sender_fault: bool = True
    status_code: int = 400


class InvalidChangeSetStatusException(ServiceException):
    code: str = "InvalidChangeSetStatus"
    sender_fault: bool = True
    status_code: int = 400


class InvalidOperationException(ServiceException):
    code: str = "InvalidOperationException"
    sender_fault: bool = True
    status_code: int = 400


class InvalidStateTransitionException(ServiceException):
    code: str = "InvalidStateTransition"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = True
    status_code: int = 400


class NameAlreadyExistsException(ServiceException):
    code: str = "NameAlreadyExistsException"
    sender_fault: bool = True
    status_code: int = 409


class OperationIdAlreadyExistsException(ServiceException):
    code: str = "OperationIdAlreadyExistsException"
    sender_fault: bool = True
    status_code: int = 409


class OperationInProgressException(ServiceException):
    code: str = "OperationInProgressException"
    sender_fault: bool = True
    status_code: int = 409


class OperationNotFoundException(ServiceException):
    code: str = "OperationNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class OperationStatusCheckFailedException(ServiceException):
    code: str = "ConditionalCheckFailed"
    sender_fault: bool = True
    status_code: int = 400


class ResourceScanInProgressException(ServiceException):
    code: str = "ResourceScanInProgress"
    sender_fault: bool = True
    status_code: int = 400


class ResourceScanLimitExceededException(ServiceException):
    code: str = "ResourceScanLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class ResourceScanNotFoundException(ServiceException):
    code: str = "ResourceScanNotFound"
    sender_fault: bool = True
    status_code: int = 400


class StackInstanceNotFoundException(ServiceException):
    code: str = "StackInstanceNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class StackNotFoundException(ServiceException):
    code: str = "StackNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class StackRefactorNotFoundException(ServiceException):
    code: str = "StackRefactorNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class StackSetNotEmptyException(ServiceException):
    code: str = "StackSetNotEmptyException"
    sender_fault: bool = True
    status_code: int = 409


class StackSetNotFoundException(ServiceException):
    code: str = "StackSetNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class StaleRequestException(ServiceException):
    code: str = "StaleRequestException"
    sender_fault: bool = True
    status_code: int = 409


class TokenAlreadyExistsException(ServiceException):
    code: str = "TokenAlreadyExistsException"
    sender_fault: bool = True
    status_code: int = 400


class TypeConfigurationNotFoundException(ServiceException):
    code: str = "TypeConfigurationNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class TypeNotFoundException(ServiceException):
    code: str = "TypeNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class AccountGateResult(TypedDict, total=False):
    Status: Optional[AccountGateStatus]
    StatusReason: Optional[AccountGateStatusReason]


class AccountLimit(TypedDict, total=False):
    Name: Optional[LimitName]
    Value: Optional[LimitValue]


AccountLimitList = List[AccountLimit]
AccountList = List[Account]


class ActivateOrganizationsAccessInput(ServiceRequest):
    pass


class ActivateOrganizationsAccessOutput(TypedDict, total=False):
    pass


MajorVersion = int


class LoggingConfig(TypedDict, total=False):
    LogRoleArn: RoleArn
    LogGroupName: LogGroupName


class ActivateTypeInput(ServiceRequest):
    Type: Optional[ThirdPartyType]
    PublicTypeArn: Optional[ThirdPartyTypeArn]
    PublisherId: Optional[PublisherId]
    TypeName: Optional[TypeName]
    TypeNameAlias: Optional[TypeName]
    AutoUpdate: Optional[AutoUpdate]
    LoggingConfig: Optional[LoggingConfig]
    ExecutionRoleArn: Optional[RoleArn]
    VersionBump: Optional[VersionBump]
    MajorVersion: Optional[MajorVersion]


class ActivateTypeOutput(TypedDict, total=False):
    Arn: Optional[PrivateTypeArn]


AllowedValues = List[AllowedValue]


class AutoDeployment(TypedDict, total=False):
    Enabled: Optional[AutoDeploymentNullable]
    RetainStacksOnAccountRemoval: Optional[RetainStacksOnAccountRemovalNullable]


class TypeConfigurationIdentifier(TypedDict, total=False):
    TypeArn: Optional[TypeArn]
    TypeConfigurationAlias: Optional[TypeConfigurationAlias]
    TypeConfigurationArn: Optional[TypeConfigurationArn]
    Type: Optional[ThirdPartyType]
    TypeName: Optional[TypeName]


class BatchDescribeTypeConfigurationsError(TypedDict, total=False):
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]
    TypeConfigurationIdentifier: Optional[TypeConfigurationIdentifier]


BatchDescribeTypeConfigurationsErrors = List[BatchDescribeTypeConfigurationsError]
TypeConfigurationIdentifiers = List[TypeConfigurationIdentifier]


class BatchDescribeTypeConfigurationsInput(ServiceRequest):
    TypeConfigurationIdentifiers: TypeConfigurationIdentifiers


Timestamp = datetime


class TypeConfigurationDetails(TypedDict, total=False):
    Arn: Optional[TypeConfigurationArn]
    Alias: Optional[TypeConfigurationAlias]
    Configuration: Optional[TypeConfiguration]
    LastUpdated: Optional[Timestamp]
    TypeArn: Optional[TypeArn]
    TypeName: Optional[TypeName]
    IsDefaultConfiguration: Optional[IsDefaultConfiguration]


TypeConfigurationDetailsList = List[TypeConfigurationDetails]
UnprocessedTypeConfigurations = List[TypeConfigurationIdentifier]


class BatchDescribeTypeConfigurationsOutput(TypedDict, total=False):
    Errors: Optional[BatchDescribeTypeConfigurationsErrors]
    UnprocessedTypeConfigurations: Optional[UnprocessedTypeConfigurations]
    TypeConfigurations: Optional[TypeConfigurationDetailsList]


class CancelUpdateStackInput(ServiceRequest):
    StackName: StackName
    ClientRequestToken: Optional[ClientRequestToken]


Capabilities = List[Capability]


class ModuleInfo(TypedDict, total=False):
    TypeHierarchy: Optional[TypeHierarchy]
    LogicalIdHierarchy: Optional[LogicalIdHierarchy]


class ResourceTargetDefinition(TypedDict, total=False):
    Attribute: Optional[ResourceAttribute]
    Name: Optional[PropertyName]
    RequiresRecreation: Optional[RequiresRecreation]
    Path: Optional[ResourcePropertyPath]
    BeforeValue: Optional[BeforeValue]
    AfterValue: Optional[AfterValue]
    AttributeChangeType: Optional[AttributeChangeType]


class ResourceChangeDetail(TypedDict, total=False):
    Target: Optional[ResourceTargetDefinition]
    Evaluation: Optional[EvaluationType]
    ChangeSource: Optional[ChangeSource]
    CausingEntity: Optional[CausingEntity]


ResourceChangeDetails = List[ResourceChangeDetail]
Scope = List[ResourceAttribute]


class ResourceChange(TypedDict, total=False):
    PolicyAction: Optional[PolicyAction]
    Action: Optional[ChangeAction]
    LogicalResourceId: Optional[LogicalResourceId]
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: Optional[ResourceType]
    Replacement: Optional[Replacement]
    Scope: Optional[Scope]
    Details: Optional[ResourceChangeDetails]
    ChangeSetId: Optional[ChangeSetId]
    ModuleInfo: Optional[ModuleInfo]
    BeforeContext: Optional[BeforeContext]
    AfterContext: Optional[AfterContext]


class Change(TypedDict, total=False):
    Type: Optional[ChangeType]
    HookInvocationCount: Optional[HookInvocationCount]
    ResourceChange: Optional[ResourceChange]


class ChangeSetHookResourceTargetDetails(TypedDict, total=False):
    LogicalResourceId: Optional[LogicalResourceId]
    ResourceType: Optional[HookTargetTypeName]
    ResourceAction: Optional[ChangeAction]


class ChangeSetHookTargetDetails(TypedDict, total=False):
    TargetType: Optional[HookTargetType]
    ResourceTargetDetails: Optional[ChangeSetHookResourceTargetDetails]


class ChangeSetHook(TypedDict, total=False):
    InvocationPoint: Optional[HookInvocationPoint]
    FailureMode: Optional[HookFailureMode]
    TypeName: Optional[HookTypeName]
    TypeVersionId: Optional[HookTypeVersionId]
    TypeConfigurationVersionId: Optional[HookTypeConfigurationVersionId]
    TargetDetails: Optional[ChangeSetHookTargetDetails]


ChangeSetHooks = List[ChangeSetHook]
CreationTime = datetime


class ChangeSetSummary(TypedDict, total=False):
    StackId: Optional[StackId]
    StackName: Optional[StackName]
    ChangeSetId: Optional[ChangeSetId]
    ChangeSetName: Optional[ChangeSetName]
    ExecutionStatus: Optional[ExecutionStatus]
    Status: Optional[ChangeSetStatus]
    StatusReason: Optional[ChangeSetStatusReason]
    CreationTime: Optional[CreationTime]
    Description: Optional[Description]
    IncludeNestedStacks: Optional[IncludeNestedStacks]
    ParentChangeSetId: Optional[ChangeSetId]
    RootChangeSetId: Optional[ChangeSetId]
    ImportExistingResources: Optional[ImportExistingResources]


ChangeSetSummaries = List[ChangeSetSummary]
Changes = List[Change]
ResourcesToSkip = List[ResourceToSkip]


class ContinueUpdateRollbackInput(ServiceRequest):
    StackName: StackNameOrId
    RoleARN: Optional[RoleARN]
    ResourcesToSkip: Optional[ResourcesToSkip]
    ClientRequestToken: Optional[ClientRequestToken]


class ContinueUpdateRollbackOutput(TypedDict, total=False):
    pass


ResourceIdentifierProperties = Dict[ResourceIdentifierPropertyKey, ResourceIdentifierPropertyValue]


class ResourceToImport(TypedDict, total=False):
    ResourceType: ResourceType
    LogicalResourceId: LogicalResourceId
    ResourceIdentifier: ResourceIdentifierProperties


ResourcesToImport = List[ResourceToImport]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


Tags = List[Tag]
NotificationARNs = List[NotificationARN]


class RollbackTrigger(TypedDict, total=False):
    Arn: Arn
    Type: Type


RollbackTriggers = List[RollbackTrigger]


class RollbackConfiguration(TypedDict, total=False):
    RollbackTriggers: Optional[RollbackTriggers]
    MonitoringTimeInMinutes: Optional[MonitoringTimeInMinutes]


ResourceTypes = List[ResourceType]


class Parameter(TypedDict, total=False):
    ParameterKey: Optional[ParameterKey]
    ParameterValue: Optional[ParameterValue]
    UsePreviousValue: Optional[UsePreviousValue]
    ResolvedValue: Optional[ParameterValue]


Parameters = List[Parameter]


class CreateChangeSetInput(ServiceRequest):
    StackName: StackNameOrId
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    UsePreviousTemplate: Optional[UsePreviousTemplate]
    Parameters: Optional[Parameters]
    Capabilities: Optional[Capabilities]
    ResourceTypes: Optional[ResourceTypes]
    RoleARN: Optional[RoleARN]
    RollbackConfiguration: Optional[RollbackConfiguration]
    NotificationARNs: Optional[NotificationARNs]
    Tags: Optional[Tags]
    ChangeSetName: ChangeSetName
    ClientToken: Optional[ClientToken]
    Description: Optional[Description]
    ChangeSetType: Optional[ChangeSetType]
    ResourcesToImport: Optional[ResourcesToImport]
    IncludeNestedStacks: Optional[IncludeNestedStacks]
    OnStackFailure: Optional[OnStackFailure]
    ImportExistingResources: Optional[ImportExistingResources]


class CreateChangeSetOutput(TypedDict, total=False):
    Id: Optional[ChangeSetId]
    StackId: Optional[StackId]


class TemplateConfiguration(TypedDict, total=False):
    DeletionPolicy: Optional[GeneratedTemplateDeletionPolicy]
    UpdateReplacePolicy: Optional[GeneratedTemplateUpdateReplacePolicy]


class ResourceDefinition(TypedDict, total=False):
    ResourceType: ResourceType
    LogicalResourceId: Optional[LogicalResourceId]
    ResourceIdentifier: ResourceIdentifierProperties


ResourceDefinitions = List[ResourceDefinition]


class CreateGeneratedTemplateInput(ServiceRequest):
    Resources: Optional[ResourceDefinitions]
    GeneratedTemplateName: GeneratedTemplateName
    StackName: Optional[StackName]
    TemplateConfiguration: Optional[TemplateConfiguration]


class CreateGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: Optional[GeneratedTemplateId]


class CreateStackInput(ServiceRequest):
    StackName: StackName
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    Parameters: Optional[Parameters]
    DisableRollback: Optional[DisableRollback]
    RollbackConfiguration: Optional[RollbackConfiguration]
    TimeoutInMinutes: Optional[TimeoutMinutes]
    NotificationARNs: Optional[NotificationARNs]
    Capabilities: Optional[Capabilities]
    ResourceTypes: Optional[ResourceTypes]
    RoleARN: Optional[RoleARN]
    OnFailure: Optional[OnFailure]
    StackPolicyBody: Optional[StackPolicyBody]
    StackPolicyURL: Optional[StackPolicyURL]
    Tags: Optional[Tags]
    ClientRequestToken: Optional[ClientRequestToken]
    EnableTerminationProtection: Optional[EnableTerminationProtection]
    RetainExceptOnCreate: Optional[RetainExceptOnCreate]


RegionList = List[Region]


class StackSetOperationPreferences(TypedDict, total=False):
    RegionConcurrencyType: Optional[RegionConcurrencyType]
    RegionOrder: Optional[RegionList]
    FailureToleranceCount: Optional[FailureToleranceCount]
    FailureTolerancePercentage: Optional[FailureTolerancePercentage]
    MaxConcurrentCount: Optional[MaxConcurrentCount]
    MaxConcurrentPercentage: Optional[MaxConcurrentPercentage]
    ConcurrencyMode: Optional[ConcurrencyMode]


OrganizationalUnitIdList = List[OrganizationalUnitId]


class DeploymentTargets(TypedDict, total=False):
    Accounts: Optional[AccountList]
    AccountsUrl: Optional[AccountsUrl]
    OrganizationalUnitIds: Optional[OrganizationalUnitIdList]
    AccountFilterType: Optional[AccountFilterType]


class CreateStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    Accounts: Optional[AccountList]
    DeploymentTargets: Optional[DeploymentTargets]
    Regions: RegionList
    ParameterOverrides: Optional[Parameters]
    OperationPreferences: Optional[StackSetOperationPreferences]
    OperationId: Optional[ClientRequestToken]
    CallAs: Optional[CallAs]


class CreateStackInstancesOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


class CreateStackOutput(TypedDict, total=False):
    StackId: Optional[StackId]


class StackDefinition(TypedDict, total=False):
    StackName: Optional[StackName]
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]


StackDefinitions = List[StackDefinition]


class ResourceLocation(TypedDict, total=False):
    StackName: StackName
    LogicalResourceId: LogicalResourceId


class ResourceMapping(TypedDict, total=False):
    Source: ResourceLocation
    Destination: ResourceLocation


ResourceMappings = List[ResourceMapping]


class CreateStackRefactorInput(ServiceRequest):
    Description: Optional[Description]
    EnableStackCreation: Optional[EnableStackCreation]
    ResourceMappings: Optional[ResourceMappings]
    StackDefinitions: StackDefinitions


class CreateStackRefactorOutput(TypedDict, total=False):
    StackRefactorId: StackRefactorId


class ManagedExecution(TypedDict, total=False):
    Active: Optional[ManagedExecutionNullable]


class CreateStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    Description: Optional[Description]
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    StackId: Optional[StackId]
    Parameters: Optional[Parameters]
    Capabilities: Optional[Capabilities]
    Tags: Optional[Tags]
    AdministrationRoleARN: Optional[RoleARN]
    ExecutionRoleName: Optional[ExecutionRoleName]
    PermissionModel: Optional[PermissionModels]
    AutoDeployment: Optional[AutoDeployment]
    CallAs: Optional[CallAs]
    ClientRequestToken: Optional[ClientRequestToken]
    ManagedExecution: Optional[ManagedExecution]


class CreateStackSetOutput(TypedDict, total=False):
    StackSetId: Optional[StackSetId]


class DeactivateOrganizationsAccessInput(ServiceRequest):
    pass


class DeactivateOrganizationsAccessOutput(TypedDict, total=False):
    pass


class DeactivateTypeInput(ServiceRequest):
    TypeName: Optional[TypeName]
    Type: Optional[ThirdPartyType]
    Arn: Optional[PrivateTypeArn]


class DeactivateTypeOutput(TypedDict, total=False):
    pass


class DeleteChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: Optional[StackNameOrId]


class DeleteChangeSetOutput(TypedDict, total=False):
    pass


class DeleteGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName


RetainResources = List[LogicalResourceId]


class DeleteStackInput(ServiceRequest):
    StackName: StackName
    RetainResources: Optional[RetainResources]
    RoleARN: Optional[RoleARN]
    ClientRequestToken: Optional[ClientRequestToken]
    DeletionMode: Optional[DeletionMode]


class DeleteStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    Accounts: Optional[AccountList]
    DeploymentTargets: Optional[DeploymentTargets]
    Regions: RegionList
    OperationPreferences: Optional[StackSetOperationPreferences]
    RetainStacks: RetainStacks
    OperationId: Optional[ClientRequestToken]
    CallAs: Optional[CallAs]


class DeleteStackInstancesOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


class DeleteStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    CallAs: Optional[CallAs]


class DeleteStackSetOutput(TypedDict, total=False):
    pass


DeletionTime = datetime


class DeregisterTypeInput(ServiceRequest):
    Arn: Optional[PrivateTypeArn]
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    VersionId: Optional[TypeVersionId]


class DeregisterTypeOutput(TypedDict, total=False):
    pass


class DescribeAccountLimitsInput(ServiceRequest):
    NextToken: Optional[NextToken]


class DescribeAccountLimitsOutput(TypedDict, total=False):
    AccountLimits: Optional[AccountLimitList]
    NextToken: Optional[NextToken]


class DescribeChangeSetHooksInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: Optional[StackNameOrId]
    NextToken: Optional[NextToken]
    LogicalResourceId: Optional[LogicalResourceId]


class DescribeChangeSetHooksOutput(TypedDict, total=False):
    ChangeSetId: Optional[ChangeSetId]
    ChangeSetName: Optional[ChangeSetName]
    Hooks: Optional[ChangeSetHooks]
    Status: Optional[ChangeSetHooksStatus]
    NextToken: Optional[NextToken]
    StackId: Optional[StackId]
    StackName: Optional[StackName]


class DescribeChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: Optional[StackNameOrId]
    NextToken: Optional[NextToken]
    IncludePropertyValues: Optional[IncludePropertyValues]


class DescribeChangeSetOutput(TypedDict, total=False):
    ChangeSetName: Optional[ChangeSetName]
    ChangeSetId: Optional[ChangeSetId]
    StackId: Optional[StackId]
    StackName: Optional[StackName]
    Description: Optional[Description]
    Parameters: Optional[Parameters]
    CreationTime: Optional[CreationTime]
    ExecutionStatus: Optional[ExecutionStatus]
    Status: Optional[ChangeSetStatus]
    StatusReason: Optional[ChangeSetStatusReason]
    NotificationARNs: Optional[NotificationARNs]
    RollbackConfiguration: Optional[RollbackConfiguration]
    Capabilities: Optional[Capabilities]
    Tags: Optional[Tags]
    Changes: Optional[Changes]
    NextToken: Optional[NextToken]
    IncludeNestedStacks: Optional[IncludeNestedStacks]
    ParentChangeSetId: Optional[ChangeSetId]
    RootChangeSetId: Optional[ChangeSetId]
    OnStackFailure: Optional[OnStackFailure]
    ImportExistingResources: Optional[ImportExistingResources]


class DescribeGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName


class TemplateProgress(TypedDict, total=False):
    ResourcesSucceeded: Optional[ResourcesSucceeded]
    ResourcesFailed: Optional[ResourcesFailed]
    ResourcesProcessing: Optional[ResourcesProcessing]
    ResourcesPending: Optional[ResourcesPending]


LastUpdatedTime = datetime


class WarningProperty(TypedDict, total=False):
    PropertyPath: Optional[PropertyPath]
    Required: Optional[RequiredProperty]
    Description: Optional[PropertyDescription]


WarningProperties = List[WarningProperty]


class WarningDetail(TypedDict, total=False):
    Type: Optional[WarningType]
    Properties: Optional[WarningProperties]


WarningDetails = List[WarningDetail]


class ResourceDetail(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    LogicalResourceId: Optional[LogicalResourceId]
    ResourceIdentifier: Optional[ResourceIdentifierProperties]
    ResourceStatus: Optional[GeneratedTemplateResourceStatus]
    ResourceStatusReason: Optional[ResourceStatusReason]
    Warnings: Optional[WarningDetails]


ResourceDetails = List[ResourceDetail]


class DescribeGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: Optional[GeneratedTemplateId]
    GeneratedTemplateName: Optional[GeneratedTemplateName]
    Resources: Optional[ResourceDetails]
    Status: Optional[GeneratedTemplateStatus]
    StatusReason: Optional[TemplateStatusReason]
    CreationTime: Optional[CreationTime]
    LastUpdatedTime: Optional[LastUpdatedTime]
    Progress: Optional[TemplateProgress]
    StackId: Optional[StackId]
    TemplateConfiguration: Optional[TemplateConfiguration]
    TotalWarnings: Optional[TotalWarnings]


class DescribeOrganizationsAccessInput(ServiceRequest):
    CallAs: Optional[CallAs]


class DescribeOrganizationsAccessOutput(TypedDict, total=False):
    Status: Optional[OrganizationStatus]


class DescribePublisherInput(ServiceRequest):
    PublisherId: Optional[PublisherId]


class DescribePublisherOutput(TypedDict, total=False):
    PublisherId: Optional[PublisherId]
    PublisherStatus: Optional[PublisherStatus]
    IdentityProvider: Optional[IdentityProvider]
    PublisherProfile: Optional[PublisherProfile]


class DescribeResourceScanInput(ServiceRequest):
    ResourceScanId: ResourceScanId


ResourceTypeFilters = List[ResourceTypeFilter]


class ScanFilter(TypedDict, total=False):
    Types: Optional[ResourceTypeFilters]


ScanFilters = List[ScanFilter]


class DescribeResourceScanOutput(TypedDict, total=False):
    ResourceScanId: Optional[ResourceScanId]
    Status: Optional[ResourceScanStatus]
    StatusReason: Optional[ResourceScanStatusReason]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    PercentageCompleted: Optional[PercentageCompleted]
    ResourceTypes: Optional[ResourceTypes]
    ResourcesScanned: Optional[ResourcesScanned]
    ResourcesRead: Optional[ResourcesRead]
    ScanFilters: Optional[ScanFilters]


class DescribeStackDriftDetectionStatusInput(ServiceRequest):
    StackDriftDetectionId: StackDriftDetectionId


class DescribeStackDriftDetectionStatusOutput(TypedDict, total=False):
    StackId: StackId
    StackDriftDetectionId: StackDriftDetectionId
    StackDriftStatus: Optional[StackDriftStatus]
    DetectionStatus: StackDriftDetectionStatus
    DetectionStatusReason: Optional[StackDriftDetectionStatusReason]
    DriftedStackResourceCount: Optional[BoxedInteger]
    Timestamp: Timestamp


class DescribeStackEventsInput(ServiceRequest):
    StackName: Optional[StackName]
    NextToken: Optional[NextToken]


class StackEvent(TypedDict, total=False):
    StackId: StackId
    EventId: EventId
    StackName: StackName
    LogicalResourceId: Optional[LogicalResourceId]
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: Optional[ResourceType]
    Timestamp: Timestamp
    ResourceStatus: Optional[ResourceStatus]
    ResourceStatusReason: Optional[ResourceStatusReason]
    ResourceProperties: Optional[ResourceProperties]
    ClientRequestToken: Optional[ClientRequestToken]
    HookType: Optional[HookType]
    HookStatus: Optional[HookStatus]
    HookStatusReason: Optional[HookStatusReason]
    HookInvocationPoint: Optional[HookInvocationPoint]
    HookFailureMode: Optional[HookFailureMode]
    DetailedStatus: Optional[DetailedStatus]


StackEvents = List[StackEvent]


class DescribeStackEventsOutput(TypedDict, total=False):
    StackEvents: Optional[StackEvents]
    NextToken: Optional[NextToken]


class DescribeStackInstanceInput(ServiceRequest):
    StackSetName: StackSetName
    StackInstanceAccount: Account
    StackInstanceRegion: Region
    CallAs: Optional[CallAs]


class StackInstanceComprehensiveStatus(TypedDict, total=False):
    DetailedStatus: Optional[StackInstanceDetailedStatus]


class StackInstance(TypedDict, total=False):
    StackSetId: Optional[StackSetId]
    Region: Optional[Region]
    Account: Optional[Account]
    StackId: Optional[StackId]
    ParameterOverrides: Optional[Parameters]
    Status: Optional[StackInstanceStatus]
    StackInstanceStatus: Optional[StackInstanceComprehensiveStatus]
    StatusReason: Optional[Reason]
    OrganizationalUnitId: Optional[OrganizationalUnitId]
    DriftStatus: Optional[StackDriftStatus]
    LastDriftCheckTimestamp: Optional[Timestamp]
    LastOperationId: Optional[ClientRequestToken]


class DescribeStackInstanceOutput(TypedDict, total=False):
    StackInstance: Optional[StackInstance]


class DescribeStackRefactorInput(ServiceRequest):
    StackRefactorId: StackRefactorId


StackIds = List[StackId]


class DescribeStackRefactorOutput(TypedDict, total=False):
    Description: Optional[Description]
    StackRefactorId: Optional[StackRefactorId]
    StackIds: Optional[StackIds]
    ExecutionStatus: Optional[StackRefactorExecutionStatus]
    ExecutionStatusReason: Optional[ExecutionStatusReason]
    Status: Optional[StackRefactorStatus]
    StatusReason: Optional[StackRefactorStatusReason]


StackResourceDriftStatusFilters = List[StackResourceDriftStatus]


class DescribeStackResourceDriftsInput(ServiceRequest):
    StackName: StackNameOrId
    StackResourceDriftStatusFilters: Optional[StackResourceDriftStatusFilters]
    NextToken: Optional[NextToken]
    MaxResults: Optional[BoxedMaxResults]


class PropertyDifference(TypedDict, total=False):
    PropertyPath: PropertyPath
    ExpectedValue: PropertyValue
    ActualValue: PropertyValue
    DifferenceType: DifferenceType


PropertyDifferences = List[PropertyDifference]


class PhysicalResourceIdContextKeyValuePair(TypedDict, total=False):
    Key: Key
    Value: Value


PhysicalResourceIdContext = List[PhysicalResourceIdContextKeyValuePair]


class StackResourceDrift(TypedDict, total=False):
    StackId: StackId
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: Optional[PhysicalResourceId]
    PhysicalResourceIdContext: Optional[PhysicalResourceIdContext]
    ResourceType: ResourceType
    ExpectedProperties: Optional[Properties]
    ActualProperties: Optional[Properties]
    PropertyDifferences: Optional[PropertyDifferences]
    StackResourceDriftStatus: StackResourceDriftStatus
    Timestamp: Timestamp
    ModuleInfo: Optional[ModuleInfo]


StackResourceDrifts = List[StackResourceDrift]


class DescribeStackResourceDriftsOutput(TypedDict, total=False):
    StackResourceDrifts: StackResourceDrifts
    NextToken: Optional[NextToken]


class DescribeStackResourceInput(ServiceRequest):
    StackName: StackName
    LogicalResourceId: LogicalResourceId


class StackResourceDriftInformation(TypedDict, total=False):
    StackResourceDriftStatus: StackResourceDriftStatus
    LastCheckTimestamp: Optional[Timestamp]


class StackResourceDetail(TypedDict, total=False):
    StackName: Optional[StackName]
    StackId: Optional[StackId]
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: ResourceType
    LastUpdatedTimestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: Optional[ResourceStatusReason]
    Description: Optional[Description]
    Metadata: Optional[Metadata]
    DriftInformation: Optional[StackResourceDriftInformation]
    ModuleInfo: Optional[ModuleInfo]


class DescribeStackResourceOutput(TypedDict, total=False):
    StackResourceDetail: Optional[StackResourceDetail]


class DescribeStackResourcesInput(ServiceRequest):
    StackName: Optional[StackName]
    LogicalResourceId: Optional[LogicalResourceId]
    PhysicalResourceId: Optional[PhysicalResourceId]


class StackResource(TypedDict, total=False):
    StackName: Optional[StackName]
    StackId: Optional[StackId]
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: ResourceType
    Timestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: Optional[ResourceStatusReason]
    Description: Optional[Description]
    DriftInformation: Optional[StackResourceDriftInformation]
    ModuleInfo: Optional[ModuleInfo]


StackResources = List[StackResource]


class DescribeStackResourcesOutput(TypedDict, total=False):
    StackResources: Optional[StackResources]


class DescribeStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    CallAs: Optional[CallAs]


class DescribeStackSetOperationInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    CallAs: Optional[CallAs]


class StackSetOperationStatusDetails(TypedDict, total=False):
    FailedStackInstancesCount: Optional[FailedStackInstancesCount]


class StackSetDriftDetectionDetails(TypedDict, total=False):
    DriftStatus: Optional[StackSetDriftStatus]
    DriftDetectionStatus: Optional[StackSetDriftDetectionStatus]
    LastDriftCheckTimestamp: Optional[Timestamp]
    TotalStackInstancesCount: Optional[TotalStackInstancesCount]
    DriftedStackInstancesCount: Optional[DriftedStackInstancesCount]
    InSyncStackInstancesCount: Optional[InSyncStackInstancesCount]
    InProgressStackInstancesCount: Optional[InProgressStackInstancesCount]
    FailedStackInstancesCount: Optional[FailedStackInstancesCount]


class StackSetOperation(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]
    StackSetId: Optional[StackSetId]
    Action: Optional[StackSetOperationAction]
    Status: Optional[StackSetOperationStatus]
    OperationPreferences: Optional[StackSetOperationPreferences]
    RetainStacks: Optional[RetainStacksNullable]
    AdministrationRoleARN: Optional[RoleARN]
    ExecutionRoleName: Optional[ExecutionRoleName]
    CreationTimestamp: Optional[Timestamp]
    EndTimestamp: Optional[Timestamp]
    DeploymentTargets: Optional[DeploymentTargets]
    StackSetDriftDetectionDetails: Optional[StackSetDriftDetectionDetails]
    StatusReason: Optional[StackSetOperationStatusReason]
    StatusDetails: Optional[StackSetOperationStatusDetails]


class DescribeStackSetOperationOutput(TypedDict, total=False):
    StackSetOperation: Optional[StackSetOperation]


class StackSet(TypedDict, total=False):
    StackSetName: Optional[StackSetName]
    StackSetId: Optional[StackSetId]
    Description: Optional[Description]
    Status: Optional[StackSetStatus]
    TemplateBody: Optional[TemplateBody]
    Parameters: Optional[Parameters]
    Capabilities: Optional[Capabilities]
    Tags: Optional[Tags]
    StackSetARN: Optional[StackSetARN]
    AdministrationRoleARN: Optional[RoleARN]
    ExecutionRoleName: Optional[ExecutionRoleName]
    StackSetDriftDetectionDetails: Optional[StackSetDriftDetectionDetails]
    AutoDeployment: Optional[AutoDeployment]
    PermissionModel: Optional[PermissionModels]
    OrganizationalUnitIds: Optional[OrganizationalUnitIdList]
    ManagedExecution: Optional[ManagedExecution]
    Regions: Optional[RegionList]


class DescribeStackSetOutput(TypedDict, total=False):
    StackSet: Optional[StackSet]


class DescribeStacksInput(ServiceRequest):
    StackName: Optional[StackName]
    NextToken: Optional[NextToken]


class StackDriftInformation(TypedDict, total=False):
    StackDriftStatus: StackDriftStatus
    LastCheckTimestamp: Optional[Timestamp]


class Output(TypedDict, total=False):
    OutputKey: Optional[OutputKey]
    OutputValue: Optional[OutputValue]
    Description: Optional[Description]
    ExportName: Optional[ExportName]


Outputs = List[Output]


class Stack(TypedDict, total=False):
    StackId: Optional[StackId]
    StackName: StackName
    ChangeSetId: Optional[ChangeSetId]
    Description: Optional[Description]
    Parameters: Optional[Parameters]
    CreationTime: CreationTime
    DeletionTime: Optional[DeletionTime]
    LastUpdatedTime: Optional[LastUpdatedTime]
    RollbackConfiguration: Optional[RollbackConfiguration]
    StackStatus: StackStatus
    StackStatusReason: Optional[StackStatusReason]
    DisableRollback: Optional[DisableRollback]
    NotificationARNs: Optional[NotificationARNs]
    TimeoutInMinutes: Optional[TimeoutMinutes]
    Capabilities: Optional[Capabilities]
    Outputs: Optional[Outputs]
    RoleARN: Optional[RoleARN]
    Tags: Optional[Tags]
    EnableTerminationProtection: Optional[EnableTerminationProtection]
    ParentId: Optional[StackId]
    RootId: Optional[StackId]
    DriftInformation: Optional[StackDriftInformation]
    RetainExceptOnCreate: Optional[RetainExceptOnCreate]
    DeletionMode: Optional[DeletionMode]
    DetailedStatus: Optional[DetailedStatus]


Stacks = List[Stack]


class DescribeStacksOutput(TypedDict, total=False):
    Stacks: Optional[Stacks]
    NextToken: Optional[NextToken]


class DescribeTypeInput(ServiceRequest):
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    Arn: Optional[TypeArn]
    VersionId: Optional[TypeVersionId]
    PublisherId: Optional[PublisherId]
    PublicVersionNumber: Optional[PublicVersionNumber]


SupportedMajorVersions = List[SupportedMajorVersion]


class RequiredActivatedType(TypedDict, total=False):
    TypeNameAlias: Optional[TypeName]
    OriginalTypeName: Optional[TypeName]
    PublisherId: Optional[PublisherId]
    SupportedMajorVersions: Optional[SupportedMajorVersions]


RequiredActivatedTypes = List[RequiredActivatedType]


class DescribeTypeOutput(TypedDict, total=False):
    Arn: Optional[TypeArn]
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    DefaultVersionId: Optional[TypeVersionId]
    IsDefaultVersion: Optional[IsDefaultVersion]
    TypeTestsStatus: Optional[TypeTestsStatus]
    TypeTestsStatusDescription: Optional[TypeTestsStatusDescription]
    Description: Optional[Description]
    Schema: Optional[TypeSchema]
    ProvisioningType: Optional[ProvisioningType]
    DeprecatedStatus: Optional[DeprecatedStatus]
    LoggingConfig: Optional[LoggingConfig]
    RequiredActivatedTypes: Optional[RequiredActivatedTypes]
    ExecutionRoleArn: Optional[RoleArn]
    Visibility: Optional[Visibility]
    SourceUrl: Optional[OptionalSecureUrl]
    DocumentationUrl: Optional[OptionalSecureUrl]
    LastUpdated: Optional[Timestamp]
    TimeCreated: Optional[Timestamp]
    ConfigurationSchema: Optional[ConfigurationSchema]
    PublisherId: Optional[PublisherId]
    OriginalTypeName: Optional[TypeName]
    OriginalTypeArn: Optional[TypeArn]
    PublicVersionNumber: Optional[PublicVersionNumber]
    LatestPublicVersion: Optional[PublicVersionNumber]
    IsActivated: Optional[IsActivated]
    AutoUpdate: Optional[AutoUpdate]


class DescribeTypeRegistrationInput(ServiceRequest):
    RegistrationToken: RegistrationToken


class DescribeTypeRegistrationOutput(TypedDict, total=False):
    ProgressStatus: Optional[RegistrationStatus]
    Description: Optional[Description]
    TypeArn: Optional[TypeArn]
    TypeVersionArn: Optional[TypeArn]


LogicalResourceIds = List[LogicalResourceId]


class DetectStackDriftInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceIds: Optional[LogicalResourceIds]


class DetectStackDriftOutput(TypedDict, total=False):
    StackDriftDetectionId: StackDriftDetectionId


class DetectStackResourceDriftInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceId: LogicalResourceId


class DetectStackResourceDriftOutput(TypedDict, total=False):
    StackResourceDrift: StackResourceDrift


class DetectStackSetDriftInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    OperationPreferences: Optional[StackSetOperationPreferences]
    OperationId: Optional[ClientRequestToken]
    CallAs: Optional[CallAs]


class DetectStackSetDriftOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


class EstimateTemplateCostInput(ServiceRequest):
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    Parameters: Optional[Parameters]


class EstimateTemplateCostOutput(TypedDict, total=False):
    Url: Optional[Url]


class ExecuteChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: Optional[StackNameOrId]
    ClientRequestToken: Optional[ClientRequestToken]
    DisableRollback: Optional[DisableRollback]
    RetainExceptOnCreate: Optional[RetainExceptOnCreate]


class ExecuteChangeSetOutput(TypedDict, total=False):
    pass


class ExecuteStackRefactorInput(ServiceRequest):
    StackRefactorId: StackRefactorId


class Export(TypedDict, total=False):
    ExportingStackId: Optional[StackId]
    Name: Optional[ExportName]
    Value: Optional[ExportValue]


Exports = List[Export]


class GetGeneratedTemplateInput(ServiceRequest):
    Format: Optional[TemplateFormat]
    GeneratedTemplateName: GeneratedTemplateName


class GetGeneratedTemplateOutput(TypedDict, total=False):
    Status: Optional[GeneratedTemplateStatus]
    TemplateBody: Optional[TemplateBody]


class GetStackPolicyInput(ServiceRequest):
    StackName: StackName


class GetStackPolicyOutput(TypedDict, total=False):
    StackPolicyBody: Optional[StackPolicyBody]


class GetTemplateInput(ServiceRequest):
    StackName: Optional[StackName]
    ChangeSetName: Optional[ChangeSetNameOrId]
    TemplateStage: Optional[TemplateStage]


StageList = List[TemplateStage]


class GetTemplateOutput(TypedDict, total=False):
    TemplateBody: Optional[TemplateBody]
    StagesAvailable: Optional[StageList]


class TemplateSummaryConfig(TypedDict, total=False):
    TreatUnrecognizedResourceTypesAsWarnings: Optional[TreatUnrecognizedResourceTypesAsWarnings]


class GetTemplateSummaryInput(ServiceRequest):
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    StackName: Optional[StackNameOrId]
    StackSetName: Optional[StackSetNameOrId]
    CallAs: Optional[CallAs]
    TemplateSummaryConfig: Optional[TemplateSummaryConfig]


class Warnings(TypedDict, total=False):
    UnrecognizedResourceTypes: Optional[ResourceTypes]


ResourceIdentifiers = List[ResourceIdentifierPropertyKey]


class ResourceIdentifierSummary(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    LogicalResourceIds: Optional[LogicalResourceIds]
    ResourceIdentifiers: Optional[ResourceIdentifiers]


ResourceIdentifierSummaries = List[ResourceIdentifierSummary]
TransformsList = List[TransformName]


class ParameterConstraints(TypedDict, total=False):
    AllowedValues: Optional[AllowedValues]


class ParameterDeclaration(TypedDict, total=False):
    ParameterKey: Optional[ParameterKey]
    DefaultValue: Optional[ParameterValue]
    ParameterType: Optional[ParameterType]
    NoEcho: Optional[NoEcho]
    Description: Optional[Description]
    ParameterConstraints: Optional[ParameterConstraints]


ParameterDeclarations = List[ParameterDeclaration]


class GetTemplateSummaryOutput(TypedDict, total=False):
    Parameters: Optional[ParameterDeclarations]
    Description: Optional[Description]
    Capabilities: Optional[Capabilities]
    CapabilitiesReason: Optional[CapabilitiesReason]
    ResourceTypes: Optional[ResourceTypes]
    Version: Optional[Version]
    Metadata: Optional[Metadata]
    DeclaredTransforms: Optional[TransformsList]
    ResourceIdentifierSummaries: Optional[ResourceIdentifierSummaries]
    Warnings: Optional[Warnings]


class HookResultSummary(TypedDict, total=False):
    InvocationPoint: Optional[HookInvocationPoint]
    FailureMode: Optional[HookFailureMode]
    TypeName: Optional[HookTypeName]
    TypeVersionId: Optional[HookTypeVersionId]
    TypeConfigurationVersionId: Optional[HookTypeConfigurationVersionId]
    Status: Optional[HookStatus]
    HookStatusReason: Optional[HookStatusReason]


HookResultSummaries = List[HookResultSummary]
StackIdList = List[StackId]


class ImportStacksToStackSetInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    StackIds: Optional[StackIdList]
    StackIdsUrl: Optional[StackIdsUrl]
    OrganizationalUnitIds: Optional[OrganizationalUnitIdList]
    OperationPreferences: Optional[StackSetOperationPreferences]
    OperationId: Optional[ClientRequestToken]
    CallAs: Optional[CallAs]


class ImportStacksToStackSetOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


Imports = List[StackName]
JazzLogicalResourceIds = List[LogicalResourceId]
JazzResourceIdentifierProperties = Dict[
    JazzResourceIdentifierPropertyKey, JazzResourceIdentifierPropertyValue
]


class ListChangeSetsInput(ServiceRequest):
    StackName: StackNameOrId
    NextToken: Optional[NextToken]


class ListChangeSetsOutput(TypedDict, total=False):
    Summaries: Optional[ChangeSetSummaries]
    NextToken: Optional[NextToken]


class ListExportsInput(ServiceRequest):
    NextToken: Optional[NextToken]


class ListExportsOutput(TypedDict, total=False):
    Exports: Optional[Exports]
    NextToken: Optional[NextToken]


class ListGeneratedTemplatesInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class TemplateSummary(TypedDict, total=False):
    GeneratedTemplateId: Optional[GeneratedTemplateId]
    GeneratedTemplateName: Optional[GeneratedTemplateName]
    Status: Optional[GeneratedTemplateStatus]
    StatusReason: Optional[TemplateStatusReason]
    CreationTime: Optional[CreationTime]
    LastUpdatedTime: Optional[LastUpdatedTime]
    NumberOfResources: Optional[NumberOfResources]


TemplateSummaries = List[TemplateSummary]


class ListGeneratedTemplatesOutput(TypedDict, total=False):
    Summaries: Optional[TemplateSummaries]
    NextToken: Optional[NextToken]


class ListHookResultsInput(ServiceRequest):
    TargetType: ListHookResultsTargetType
    TargetId: HookResultId
    NextToken: Optional[NextToken]


class ListHookResultsOutput(TypedDict, total=False):
    TargetType: Optional[ListHookResultsTargetType]
    TargetId: Optional[HookResultId]
    HookResults: Optional[HookResultSummaries]
    NextToken: Optional[NextToken]


class ListImportsInput(ServiceRequest):
    ExportName: ExportName
    NextToken: Optional[NextToken]


class ListImportsOutput(TypedDict, total=False):
    Imports: Optional[Imports]
    NextToken: Optional[NextToken]


class ScannedResourceIdentifier(TypedDict, total=False):
    ResourceType: ResourceType
    ResourceIdentifier: JazzResourceIdentifierProperties


ScannedResourceIdentifiers = List[ScannedResourceIdentifier]


class ListResourceScanRelatedResourcesInput(ServiceRequest):
    ResourceScanId: ResourceScanId
    Resources: ScannedResourceIdentifiers
    NextToken: Optional[NextToken]
    MaxResults: Optional[BoxedMaxResults]


class ScannedResource(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    ResourceIdentifier: Optional[JazzResourceIdentifierProperties]
    ManagedByStack: Optional[ManagedByStack]


RelatedResources = List[ScannedResource]


class ListResourceScanRelatedResourcesOutput(TypedDict, total=False):
    RelatedResources: Optional[RelatedResources]
    NextToken: Optional[NextToken]


class ListResourceScanResourcesInput(ServiceRequest):
    ResourceScanId: ResourceScanId
    ResourceIdentifier: Optional[ResourceIdentifier]
    ResourceTypePrefix: Optional[ResourceTypePrefix]
    TagKey: Optional[TagKey]
    TagValue: Optional[TagValue]
    NextToken: Optional[NextToken]
    MaxResults: Optional[ResourceScannerMaxResults]


ScannedResources = List[ScannedResource]


class ListResourceScanResourcesOutput(TypedDict, total=False):
    Resources: Optional[ScannedResources]
    NextToken: Optional[NextToken]


class ListResourceScansInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[ResourceScannerMaxResults]
    ScanTypeFilter: Optional[ScanType]


class ResourceScanSummary(TypedDict, total=False):
    ResourceScanId: Optional[ResourceScanId]
    Status: Optional[ResourceScanStatus]
    StatusReason: Optional[ResourceScanStatusReason]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    PercentageCompleted: Optional[PercentageCompleted]
    ScanType: Optional[ScanType]


ResourceScanSummaries = List[ResourceScanSummary]


class ListResourceScansOutput(TypedDict, total=False):
    ResourceScanSummaries: Optional[ResourceScanSummaries]
    NextToken: Optional[NextToken]


class ListStackInstanceResourceDriftsInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    StackInstanceResourceDriftStatuses: Optional[StackResourceDriftStatusFilters]
    StackInstanceAccount: Account
    StackInstanceRegion: Region
    OperationId: ClientRequestToken
    CallAs: Optional[CallAs]


class StackInstanceResourceDriftsSummary(TypedDict, total=False):
    StackId: StackId
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: Optional[PhysicalResourceId]
    PhysicalResourceIdContext: Optional[PhysicalResourceIdContext]
    ResourceType: ResourceType
    PropertyDifferences: Optional[PropertyDifferences]
    StackResourceDriftStatus: StackResourceDriftStatus
    Timestamp: Timestamp


StackInstanceResourceDriftsSummaries = List[StackInstanceResourceDriftsSummary]


class ListStackInstanceResourceDriftsOutput(TypedDict, total=False):
    Summaries: Optional[StackInstanceResourceDriftsSummaries]
    NextToken: Optional[NextToken]


class StackInstanceFilter(TypedDict, total=False):
    Name: Optional[StackInstanceFilterName]
    Values: Optional[StackInstanceFilterValues]


StackInstanceFilters = List[StackInstanceFilter]


class ListStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    Filters: Optional[StackInstanceFilters]
    StackInstanceAccount: Optional[Account]
    StackInstanceRegion: Optional[Region]
    CallAs: Optional[CallAs]


class StackInstanceSummary(TypedDict, total=False):
    StackSetId: Optional[StackSetId]
    Region: Optional[Region]
    Account: Optional[Account]
    StackId: Optional[StackId]
    Status: Optional[StackInstanceStatus]
    StatusReason: Optional[Reason]
    StackInstanceStatus: Optional[StackInstanceComprehensiveStatus]
    OrganizationalUnitId: Optional[OrganizationalUnitId]
    DriftStatus: Optional[StackDriftStatus]
    LastDriftCheckTimestamp: Optional[Timestamp]
    LastOperationId: Optional[ClientRequestToken]


StackInstanceSummaries = List[StackInstanceSummary]


class ListStackInstancesOutput(TypedDict, total=False):
    Summaries: Optional[StackInstanceSummaries]
    NextToken: Optional[NextToken]


class ListStackRefactorActionsInput(ServiceRequest):
    StackRefactorId: StackRefactorId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


StackRefactorUntagResources = List[TagKey]
StackRefactorTagResources = List[Tag]


class StackRefactorAction(TypedDict, total=False):
    Action: Optional[StackRefactorActionType]
    Entity: Optional[StackRefactorActionEntity]
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceIdentifier: Optional[StackRefactorResourceIdentifier]
    Description: Optional[Description]
    Detection: Optional[StackRefactorDetection]
    DetectionReason: Optional[DetectionReason]
    TagResources: Optional[StackRefactorTagResources]
    UntagResources: Optional[StackRefactorUntagResources]
    ResourceMapping: Optional[ResourceMapping]


StackRefactorActions = List[StackRefactorAction]


class ListStackRefactorActionsOutput(TypedDict, total=False):
    StackRefactorActions: StackRefactorActions
    NextToken: Optional[NextToken]


StackRefactorExecutionStatusFilter = List[StackRefactorExecutionStatus]


class ListStackRefactorsInput(ServiceRequest):
    ExecutionStatusFilter: Optional[StackRefactorExecutionStatusFilter]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class StackRefactorSummary(TypedDict, total=False):
    StackRefactorId: Optional[StackRefactorId]
    Description: Optional[Description]
    ExecutionStatus: Optional[StackRefactorExecutionStatus]
    ExecutionStatusReason: Optional[ExecutionStatusReason]
    Status: Optional[StackRefactorStatus]
    StatusReason: Optional[StackRefactorStatusReason]


StackRefactorSummaries = List[StackRefactorSummary]


class ListStackRefactorsOutput(TypedDict, total=False):
    StackRefactorSummaries: StackRefactorSummaries
    NextToken: Optional[NextToken]


class ListStackResourcesInput(ServiceRequest):
    StackName: StackName
    NextToken: Optional[NextToken]


class StackResourceDriftInformationSummary(TypedDict, total=False):
    StackResourceDriftStatus: StackResourceDriftStatus
    LastCheckTimestamp: Optional[Timestamp]


class StackResourceSummary(TypedDict, total=False):
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: ResourceType
    LastUpdatedTimestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: Optional[ResourceStatusReason]
    DriftInformation: Optional[StackResourceDriftInformationSummary]
    ModuleInfo: Optional[ModuleInfo]


StackResourceSummaries = List[StackResourceSummary]


class ListStackResourcesOutput(TypedDict, total=False):
    StackResourceSummaries: Optional[StackResourceSummaries]
    NextToken: Optional[NextToken]


class ListStackSetAutoDeploymentTargetsInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CallAs: Optional[CallAs]


class StackSetAutoDeploymentTargetSummary(TypedDict, total=False):
    OrganizationalUnitId: Optional[OrganizationalUnitId]
    Regions: Optional[RegionList]


StackSetAutoDeploymentTargetSummaries = List[StackSetAutoDeploymentTargetSummary]


class ListStackSetAutoDeploymentTargetsOutput(TypedDict, total=False):
    Summaries: Optional[StackSetAutoDeploymentTargetSummaries]
    NextToken: Optional[NextToken]


class OperationResultFilter(TypedDict, total=False):
    Name: Optional[OperationResultFilterName]
    Values: Optional[OperationResultFilterValues]


OperationResultFilters = List[OperationResultFilter]


class ListStackSetOperationResultsInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CallAs: Optional[CallAs]
    Filters: Optional[OperationResultFilters]


class StackSetOperationResultSummary(TypedDict, total=False):
    Account: Optional[Account]
    Region: Optional[Region]
    Status: Optional[StackSetOperationResultStatus]
    StatusReason: Optional[Reason]
    AccountGateResult: Optional[AccountGateResult]
    OrganizationalUnitId: Optional[OrganizationalUnitId]


StackSetOperationResultSummaries = List[StackSetOperationResultSummary]


class ListStackSetOperationResultsOutput(TypedDict, total=False):
    Summaries: Optional[StackSetOperationResultSummaries]
    NextToken: Optional[NextToken]


class ListStackSetOperationsInput(ServiceRequest):
    StackSetName: StackSetName
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CallAs: Optional[CallAs]


class StackSetOperationSummary(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]
    Action: Optional[StackSetOperationAction]
    Status: Optional[StackSetOperationStatus]
    CreationTimestamp: Optional[Timestamp]
    EndTimestamp: Optional[Timestamp]
    StatusReason: Optional[StackSetOperationStatusReason]
    StatusDetails: Optional[StackSetOperationStatusDetails]
    OperationPreferences: Optional[StackSetOperationPreferences]


StackSetOperationSummaries = List[StackSetOperationSummary]


class ListStackSetOperationsOutput(TypedDict, total=False):
    Summaries: Optional[StackSetOperationSummaries]
    NextToken: Optional[NextToken]


class ListStackSetsInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    Status: Optional[StackSetStatus]
    CallAs: Optional[CallAs]


class StackSetSummary(TypedDict, total=False):
    StackSetName: Optional[StackSetName]
    StackSetId: Optional[StackSetId]
    Description: Optional[Description]
    Status: Optional[StackSetStatus]
    AutoDeployment: Optional[AutoDeployment]
    PermissionModel: Optional[PermissionModels]
    DriftStatus: Optional[StackDriftStatus]
    LastDriftCheckTimestamp: Optional[Timestamp]
    ManagedExecution: Optional[ManagedExecution]


StackSetSummaries = List[StackSetSummary]


class ListStackSetsOutput(TypedDict, total=False):
    Summaries: Optional[StackSetSummaries]
    NextToken: Optional[NextToken]


StackStatusFilter = List[StackStatus]


class ListStacksInput(ServiceRequest):
    NextToken: Optional[NextToken]
    StackStatusFilter: Optional[StackStatusFilter]


class StackDriftInformationSummary(TypedDict, total=False):
    StackDriftStatus: StackDriftStatus
    LastCheckTimestamp: Optional[Timestamp]


class StackSummary(TypedDict, total=False):
    StackId: Optional[StackId]
    StackName: StackName
    TemplateDescription: Optional[TemplateDescription]
    CreationTime: CreationTime
    LastUpdatedTime: Optional[LastUpdatedTime]
    DeletionTime: Optional[DeletionTime]
    StackStatus: StackStatus
    StackStatusReason: Optional[StackStatusReason]
    ParentId: Optional[StackId]
    RootId: Optional[StackId]
    DriftInformation: Optional[StackDriftInformationSummary]


StackSummaries = List[StackSummary]


class ListStacksOutput(TypedDict, total=False):
    StackSummaries: Optional[StackSummaries]
    NextToken: Optional[NextToken]


class ListTypeRegistrationsInput(ServiceRequest):
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    TypeArn: Optional[TypeArn]
    RegistrationStatusFilter: Optional[RegistrationStatus]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


RegistrationTokenList = List[RegistrationToken]


class ListTypeRegistrationsOutput(TypedDict, total=False):
    RegistrationTokenList: Optional[RegistrationTokenList]
    NextToken: Optional[NextToken]


class ListTypeVersionsInput(ServiceRequest):
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    Arn: Optional[TypeArn]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    DeprecatedStatus: Optional[DeprecatedStatus]
    PublisherId: Optional[PublisherId]


class TypeVersionSummary(TypedDict, total=False):
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    VersionId: Optional[TypeVersionId]
    IsDefaultVersion: Optional[IsDefaultVersion]
    Arn: Optional[TypeArn]
    TimeCreated: Optional[Timestamp]
    Description: Optional[Description]
    PublicVersionNumber: Optional[PublicVersionNumber]


TypeVersionSummaries = List[TypeVersionSummary]


class ListTypeVersionsOutput(TypedDict, total=False):
    TypeVersionSummaries: Optional[TypeVersionSummaries]
    NextToken: Optional[NextToken]


class TypeFilters(TypedDict, total=False):
    Category: Optional[Category]
    PublisherId: Optional[PublisherId]
    TypeNamePrefix: Optional[TypeNamePrefix]


class ListTypesInput(ServiceRequest):
    Visibility: Optional[Visibility]
    ProvisioningType: Optional[ProvisioningType]
    DeprecatedStatus: Optional[DeprecatedStatus]
    Type: Optional[RegistryType]
    Filters: Optional[TypeFilters]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class TypeSummary(TypedDict, total=False):
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    DefaultVersionId: Optional[TypeVersionId]
    TypeArn: Optional[TypeArn]
    LastUpdated: Optional[Timestamp]
    Description: Optional[Description]
    PublisherId: Optional[PublisherId]
    OriginalTypeName: Optional[TypeName]
    PublicVersionNumber: Optional[PublicVersionNumber]
    LatestPublicVersion: Optional[PublicVersionNumber]
    PublisherIdentity: Optional[IdentityProvider]
    PublisherName: Optional[PublisherName]
    IsActivated: Optional[IsActivated]


TypeSummaries = List[TypeSummary]


class ListTypesOutput(TypedDict, total=False):
    TypeSummaries: Optional[TypeSummaries]
    NextToken: Optional[NextToken]


class PublishTypeInput(ServiceRequest):
    Type: Optional[ThirdPartyType]
    Arn: Optional[PrivateTypeArn]
    TypeName: Optional[TypeName]
    PublicVersionNumber: Optional[PublicVersionNumber]


class PublishTypeOutput(TypedDict, total=False):
    PublicTypeArn: Optional[TypeArn]


class RecordHandlerProgressInput(ServiceRequest):
    BearerToken: ClientToken
    OperationStatus: OperationStatus
    CurrentOperationStatus: Optional[OperationStatus]
    StatusMessage: Optional[StatusMessage]
    ErrorCode: Optional[HandlerErrorCode]
    ResourceModel: Optional[ResourceModel]
    ClientRequestToken: Optional[ClientRequestToken]


class RecordHandlerProgressOutput(TypedDict, total=False):
    pass


class RegisterPublisherInput(ServiceRequest):
    AcceptTermsAndConditions: Optional[AcceptTermsAndConditions]
    ConnectionArn: Optional[ConnectionArn]


class RegisterPublisherOutput(TypedDict, total=False):
    PublisherId: Optional[PublisherId]


class RegisterTypeInput(ServiceRequest):
    Type: Optional[RegistryType]
    TypeName: TypeName
    SchemaHandlerPackage: S3Url
    LoggingConfig: Optional[LoggingConfig]
    ExecutionRoleArn: Optional[RoleArn]
    ClientRequestToken: Optional[RequestToken]


class RegisterTypeOutput(TypedDict, total=False):
    RegistrationToken: Optional[RegistrationToken]


class RollbackStackInput(ServiceRequest):
    StackName: StackNameOrId
    RoleARN: Optional[RoleARN]
    ClientRequestToken: Optional[ClientRequestToken]
    RetainExceptOnCreate: Optional[RetainExceptOnCreate]


class RollbackStackOutput(TypedDict, total=False):
    StackId: Optional[StackId]


class SetStackPolicyInput(ServiceRequest):
    StackName: StackName
    StackPolicyBody: Optional[StackPolicyBody]
    StackPolicyURL: Optional[StackPolicyURL]


class SetTypeConfigurationInput(ServiceRequest):
    TypeArn: Optional[TypeArn]
    Configuration: TypeConfiguration
    ConfigurationAlias: Optional[TypeConfigurationAlias]
    TypeName: Optional[TypeName]
    Type: Optional[ThirdPartyType]


class SetTypeConfigurationOutput(TypedDict, total=False):
    ConfigurationArn: Optional[TypeConfigurationArn]


class SetTypeDefaultVersionInput(ServiceRequest):
    Arn: Optional[PrivateTypeArn]
    Type: Optional[RegistryType]
    TypeName: Optional[TypeName]
    VersionId: Optional[TypeVersionId]


class SetTypeDefaultVersionOutput(TypedDict, total=False):
    pass


class SignalResourceInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceId: LogicalResourceId
    UniqueId: ResourceSignalUniqueId
    Status: ResourceSignalStatus


class StartResourceScanInput(ServiceRequest):
    ClientRequestToken: Optional[ClientRequestToken]
    ScanFilters: Optional[ScanFilters]


class StartResourceScanOutput(TypedDict, total=False):
    ResourceScanId: Optional[ResourceScanId]


class StopStackSetOperationInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    CallAs: Optional[CallAs]


class StopStackSetOperationOutput(TypedDict, total=False):
    pass


class TemplateParameter(TypedDict, total=False):
    ParameterKey: Optional[ParameterKey]
    DefaultValue: Optional[ParameterValue]
    NoEcho: Optional[NoEcho]
    Description: Optional[Description]


TemplateParameters = List[TemplateParameter]


class TestTypeInput(ServiceRequest):
    Arn: Optional[TypeArn]
    Type: Optional[ThirdPartyType]
    TypeName: Optional[TypeName]
    VersionId: Optional[TypeVersionId]
    LogDeliveryBucket: Optional[S3Bucket]


class TestTypeOutput(TypedDict, total=False):
    TypeVersionArn: Optional[TypeArn]


class UpdateGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName
    NewGeneratedTemplateName: Optional[GeneratedTemplateName]
    AddResources: Optional[ResourceDefinitions]
    RemoveResources: Optional[JazzLogicalResourceIds]
    RefreshAllResources: Optional[RefreshAllResources]
    TemplateConfiguration: Optional[TemplateConfiguration]


class UpdateGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: Optional[GeneratedTemplateId]


class UpdateStackInput(ServiceRequest):
    StackName: StackName
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    UsePreviousTemplate: Optional[UsePreviousTemplate]
    StackPolicyDuringUpdateBody: Optional[StackPolicyDuringUpdateBody]
    StackPolicyDuringUpdateURL: Optional[StackPolicyDuringUpdateURL]
    Parameters: Optional[Parameters]
    Capabilities: Optional[Capabilities]
    ResourceTypes: Optional[ResourceTypes]
    RoleARN: Optional[RoleARN]
    RollbackConfiguration: Optional[RollbackConfiguration]
    StackPolicyBody: Optional[StackPolicyBody]
    StackPolicyURL: Optional[StackPolicyURL]
    NotificationARNs: Optional[NotificationARNs]
    Tags: Optional[Tags]
    DisableRollback: Optional[DisableRollback]
    ClientRequestToken: Optional[ClientRequestToken]
    RetainExceptOnCreate: Optional[RetainExceptOnCreate]


class UpdateStackInstancesInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    Accounts: Optional[AccountList]
    DeploymentTargets: Optional[DeploymentTargets]
    Regions: RegionList
    ParameterOverrides: Optional[Parameters]
    OperationPreferences: Optional[StackSetOperationPreferences]
    OperationId: Optional[ClientRequestToken]
    CallAs: Optional[CallAs]


class UpdateStackInstancesOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


class UpdateStackOutput(TypedDict, total=False):
    StackId: Optional[StackId]


class UpdateStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    Description: Optional[Description]
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    UsePreviousTemplate: Optional[UsePreviousTemplate]
    Parameters: Optional[Parameters]
    Capabilities: Optional[Capabilities]
    Tags: Optional[Tags]
    OperationPreferences: Optional[StackSetOperationPreferences]
    AdministrationRoleARN: Optional[RoleARN]
    ExecutionRoleName: Optional[ExecutionRoleName]
    DeploymentTargets: Optional[DeploymentTargets]
    PermissionModel: Optional[PermissionModels]
    AutoDeployment: Optional[AutoDeployment]
    OperationId: Optional[ClientRequestToken]
    Accounts: Optional[AccountList]
    Regions: Optional[RegionList]
    CallAs: Optional[CallAs]
    ManagedExecution: Optional[ManagedExecution]


class UpdateStackSetOutput(TypedDict, total=False):
    OperationId: Optional[ClientRequestToken]


class UpdateTerminationProtectionInput(ServiceRequest):
    EnableTerminationProtection: EnableTerminationProtection
    StackName: StackNameOrId


class UpdateTerminationProtectionOutput(TypedDict, total=False):
    StackId: Optional[StackId]


class ValidateTemplateInput(ServiceRequest):
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]


class ValidateTemplateOutput(TypedDict, total=False):
    Parameters: Optional[TemplateParameters]
    Description: Optional[Description]
    Capabilities: Optional[Capabilities]
    CapabilitiesReason: Optional[CapabilitiesReason]
    DeclaredTransforms: Optional[TransformsList]


class CloudformationApi:
    service = "cloudformation"
    version = "2010-05-15"

    @handler("ActivateOrganizationsAccess")
    def activate_organizations_access(
        self, context: RequestContext, **kwargs
    ) -> ActivateOrganizationsAccessOutput:
        raise NotImplementedError

    @handler("ActivateType", expand=False)
    def activate_type(
        self, context: RequestContext, request: ActivateTypeInput, **kwargs
    ) -> ActivateTypeOutput:
        raise NotImplementedError

    @handler("BatchDescribeTypeConfigurations")
    def batch_describe_type_configurations(
        self,
        context: RequestContext,
        type_configuration_identifiers: TypeConfigurationIdentifiers,
        **kwargs,
    ) -> BatchDescribeTypeConfigurationsOutput:
        raise NotImplementedError

    @handler("CancelUpdateStack")
    def cancel_update_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        client_request_token: ClientRequestToken | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ContinueUpdateRollback")
    def continue_update_rollback(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        role_arn: RoleARN | None = None,
        resources_to_skip: ResourcesToSkip | None = None,
        client_request_token: ClientRequestToken | None = None,
        **kwargs,
    ) -> ContinueUpdateRollbackOutput:
        raise NotImplementedError

    @handler("CreateChangeSet")
    def create_change_set(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        change_set_name: ChangeSetName,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        use_previous_template: UsePreviousTemplate | None = None,
        parameters: Parameters | None = None,
        capabilities: Capabilities | None = None,
        resource_types: ResourceTypes | None = None,
        role_arn: RoleARN | None = None,
        rollback_configuration: RollbackConfiguration | None = None,
        notification_arns: NotificationARNs | None = None,
        tags: Tags | None = None,
        client_token: ClientToken | None = None,
        description: Description | None = None,
        change_set_type: ChangeSetType | None = None,
        resources_to_import: ResourcesToImport | None = None,
        include_nested_stacks: IncludeNestedStacks | None = None,
        on_stack_failure: OnStackFailure | None = None,
        import_existing_resources: ImportExistingResources | None = None,
        **kwargs,
    ) -> CreateChangeSetOutput:
        raise NotImplementedError

    @handler("CreateGeneratedTemplate")
    def create_generated_template(
        self,
        context: RequestContext,
        generated_template_name: GeneratedTemplateName,
        resources: ResourceDefinitions | None = None,
        stack_name: StackName | None = None,
        template_configuration: TemplateConfiguration | None = None,
        **kwargs,
    ) -> CreateGeneratedTemplateOutput:
        raise NotImplementedError

    @handler("CreateStack")
    def create_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        parameters: Parameters | None = None,
        disable_rollback: DisableRollback | None = None,
        rollback_configuration: RollbackConfiguration | None = None,
        timeout_in_minutes: TimeoutMinutes | None = None,
        notification_arns: NotificationARNs | None = None,
        capabilities: Capabilities | None = None,
        resource_types: ResourceTypes | None = None,
        role_arn: RoleARN | None = None,
        on_failure: OnFailure | None = None,
        stack_policy_body: StackPolicyBody | None = None,
        stack_policy_url: StackPolicyURL | None = None,
        tags: Tags | None = None,
        client_request_token: ClientRequestToken | None = None,
        enable_termination_protection: EnableTerminationProtection | None = None,
        retain_except_on_create: RetainExceptOnCreate | None = None,
        **kwargs,
    ) -> CreateStackOutput:
        raise NotImplementedError

    @handler("CreateStackInstances")
    def create_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        regions: RegionList,
        accounts: AccountList | None = None,
        deployment_targets: DeploymentTargets | None = None,
        parameter_overrides: Parameters | None = None,
        operation_preferences: StackSetOperationPreferences | None = None,
        operation_id: ClientRequestToken | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> CreateStackInstancesOutput:
        raise NotImplementedError

    @handler("CreateStackRefactor")
    def create_stack_refactor(
        self,
        context: RequestContext,
        stack_definitions: StackDefinitions,
        description: Description | None = None,
        enable_stack_creation: EnableStackCreation | None = None,
        resource_mappings: ResourceMappings | None = None,
        **kwargs,
    ) -> CreateStackRefactorOutput:
        raise NotImplementedError

    @handler("CreateStackSet")
    def create_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        description: Description | None = None,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        stack_id: StackId | None = None,
        parameters: Parameters | None = None,
        capabilities: Capabilities | None = None,
        tags: Tags | None = None,
        administration_role_arn: RoleARN | None = None,
        execution_role_name: ExecutionRoleName | None = None,
        permission_model: PermissionModels | None = None,
        auto_deployment: AutoDeployment | None = None,
        call_as: CallAs | None = None,
        client_request_token: ClientRequestToken | None = None,
        managed_execution: ManagedExecution | None = None,
        **kwargs,
    ) -> CreateStackSetOutput:
        raise NotImplementedError

    @handler("DeactivateOrganizationsAccess")
    def deactivate_organizations_access(
        self, context: RequestContext, **kwargs
    ) -> DeactivateOrganizationsAccessOutput:
        raise NotImplementedError

    @handler("DeactivateType", expand=False)
    def deactivate_type(
        self, context: RequestContext, request: DeactivateTypeInput, **kwargs
    ) -> DeactivateTypeOutput:
        raise NotImplementedError

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        **kwargs,
    ) -> DeleteChangeSetOutput:
        raise NotImplementedError

    @handler("DeleteGeneratedTemplate")
    def delete_generated_template(
        self, context: RequestContext, generated_template_name: GeneratedTemplateName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStack")
    def delete_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        retain_resources: RetainResources | None = None,
        role_arn: RoleARN | None = None,
        client_request_token: ClientRequestToken | None = None,
        deletion_mode: DeletionMode | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStackInstances")
    def delete_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        regions: RegionList,
        retain_stacks: RetainStacks,
        accounts: AccountList | None = None,
        deployment_targets: DeploymentTargets | None = None,
        operation_preferences: StackSetOperationPreferences | None = None,
        operation_id: ClientRequestToken | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DeleteStackInstancesOutput:
        raise NotImplementedError

    @handler("DeleteStackSet")
    def delete_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DeleteStackSetOutput:
        raise NotImplementedError

    @handler("DeregisterType", expand=False)
    def deregister_type(
        self, context: RequestContext, request: DeregisterTypeInput, **kwargs
    ) -> DeregisterTypeOutput:
        raise NotImplementedError

    @handler("DescribeAccountLimits")
    def describe_account_limits(
        self, context: RequestContext, next_token: NextToken | None = None, **kwargs
    ) -> DescribeAccountLimitsOutput:
        raise NotImplementedError

    @handler("DescribeChangeSet")
    def describe_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        next_token: NextToken | None = None,
        include_property_values: IncludePropertyValues | None = None,
        **kwargs,
    ) -> DescribeChangeSetOutput:
        raise NotImplementedError

    @handler("DescribeChangeSetHooks")
    def describe_change_set_hooks(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        next_token: NextToken | None = None,
        logical_resource_id: LogicalResourceId | None = None,
        **kwargs,
    ) -> DescribeChangeSetHooksOutput:
        raise NotImplementedError

    @handler("DescribeGeneratedTemplate")
    def describe_generated_template(
        self, context: RequestContext, generated_template_name: GeneratedTemplateName, **kwargs
    ) -> DescribeGeneratedTemplateOutput:
        raise NotImplementedError

    @handler("DescribeOrganizationsAccess")
    def describe_organizations_access(
        self, context: RequestContext, call_as: CallAs | None = None, **kwargs
    ) -> DescribeOrganizationsAccessOutput:
        raise NotImplementedError

    @handler("DescribePublisher")
    def describe_publisher(
        self, context: RequestContext, publisher_id: PublisherId | None = None, **kwargs
    ) -> DescribePublisherOutput:
        raise NotImplementedError

    @handler("DescribeResourceScan")
    def describe_resource_scan(
        self, context: RequestContext, resource_scan_id: ResourceScanId, **kwargs
    ) -> DescribeResourceScanOutput:
        raise NotImplementedError

    @handler("DescribeStackDriftDetectionStatus")
    def describe_stack_drift_detection_status(
        self, context: RequestContext, stack_drift_detection_id: StackDriftDetectionId, **kwargs
    ) -> DescribeStackDriftDetectionStatusOutput:
        raise NotImplementedError

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self,
        context: RequestContext,
        stack_name: StackName | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeStackEventsOutput:
        raise NotImplementedError

    @handler("DescribeStackInstance")
    def describe_stack_instance(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        stack_instance_account: Account,
        stack_instance_region: Region,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DescribeStackInstanceOutput:
        raise NotImplementedError

    @handler("DescribeStackRefactor")
    def describe_stack_refactor(
        self, context: RequestContext, stack_refactor_id: StackRefactorId, **kwargs
    ) -> DescribeStackRefactorOutput:
        raise NotImplementedError

    @handler("DescribeStackResource")
    def describe_stack_resource(
        self,
        context: RequestContext,
        stack_name: StackName,
        logical_resource_id: LogicalResourceId,
        **kwargs,
    ) -> DescribeStackResourceOutput:
        raise NotImplementedError

    @handler("DescribeStackResourceDrifts")
    def describe_stack_resource_drifts(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        stack_resource_drift_status_filters: StackResourceDriftStatusFilters | None = None,
        next_token: NextToken | None = None,
        max_results: BoxedMaxResults | None = None,
        **kwargs,
    ) -> DescribeStackResourceDriftsOutput:
        raise NotImplementedError

    @handler("DescribeStackResources")
    def describe_stack_resources(
        self,
        context: RequestContext,
        stack_name: StackName | None = None,
        logical_resource_id: LogicalResourceId | None = None,
        physical_resource_id: PhysicalResourceId | None = None,
        **kwargs,
    ) -> DescribeStackResourcesOutput:
        raise NotImplementedError

    @handler("DescribeStackSet")
    def describe_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DescribeStackSetOutput:
        raise NotImplementedError

    @handler("DescribeStackSetOperation")
    def describe_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DescribeStackSetOperationOutput:
        raise NotImplementedError

    @handler("DescribeStacks")
    def describe_stacks(
        self,
        context: RequestContext,
        stack_name: StackName | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeStacksOutput:
        raise NotImplementedError

    @handler("DescribeType", expand=False)
    def describe_type(
        self, context: RequestContext, request: DescribeTypeInput, **kwargs
    ) -> DescribeTypeOutput:
        raise NotImplementedError

    @handler("DescribeTypeRegistration")
    def describe_type_registration(
        self, context: RequestContext, registration_token: RegistrationToken, **kwargs
    ) -> DescribeTypeRegistrationOutput:
        raise NotImplementedError

    @handler("DetectStackDrift")
    def detect_stack_drift(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        logical_resource_ids: LogicalResourceIds | None = None,
        **kwargs,
    ) -> DetectStackDriftOutput:
        raise NotImplementedError

    @handler("DetectStackResourceDrift")
    def detect_stack_resource_drift(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        logical_resource_id: LogicalResourceId,
        **kwargs,
    ) -> DetectStackResourceDriftOutput:
        raise NotImplementedError

    @handler("DetectStackSetDrift")
    def detect_stack_set_drift(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        operation_preferences: StackSetOperationPreferences | None = None,
        operation_id: ClientRequestToken | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> DetectStackSetDriftOutput:
        raise NotImplementedError

    @handler("EstimateTemplateCost")
    def estimate_template_cost(
        self,
        context: RequestContext,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        parameters: Parameters | None = None,
        **kwargs,
    ) -> EstimateTemplateCostOutput:
        raise NotImplementedError

    @handler("ExecuteChangeSet")
    def execute_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        client_request_token: ClientRequestToken | None = None,
        disable_rollback: DisableRollback | None = None,
        retain_except_on_create: RetainExceptOnCreate | None = None,
        **kwargs,
    ) -> ExecuteChangeSetOutput:
        raise NotImplementedError

    @handler("ExecuteStackRefactor")
    def execute_stack_refactor(
        self, context: RequestContext, stack_refactor_id: StackRefactorId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("GetGeneratedTemplate")
    def get_generated_template(
        self,
        context: RequestContext,
        generated_template_name: GeneratedTemplateName,
        format: TemplateFormat | None = None,
        **kwargs,
    ) -> GetGeneratedTemplateOutput:
        raise NotImplementedError

    @handler("GetStackPolicy")
    def get_stack_policy(
        self, context: RequestContext, stack_name: StackName, **kwargs
    ) -> GetStackPolicyOutput:
        raise NotImplementedError

    @handler("GetTemplate")
    def get_template(
        self,
        context: RequestContext,
        stack_name: StackName | None = None,
        change_set_name: ChangeSetNameOrId | None = None,
        template_stage: TemplateStage | None = None,
        **kwargs,
    ) -> GetTemplateOutput:
        raise NotImplementedError

    @handler("GetTemplateSummary")
    def get_template_summary(
        self,
        context: RequestContext,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        stack_name: StackNameOrId | None = None,
        stack_set_name: StackSetNameOrId | None = None,
        call_as: CallAs | None = None,
        template_summary_config: TemplateSummaryConfig | None = None,
        **kwargs,
    ) -> GetTemplateSummaryOutput:
        raise NotImplementedError

    @handler("ImportStacksToStackSet")
    def import_stacks_to_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        stack_ids: StackIdList | None = None,
        stack_ids_url: StackIdsUrl | None = None,
        organizational_unit_ids: OrganizationalUnitIdList | None = None,
        operation_preferences: StackSetOperationPreferences | None = None,
        operation_id: ClientRequestToken | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ImportStacksToStackSetOutput:
        raise NotImplementedError

    @handler("ListChangeSets")
    def list_change_sets(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListChangeSetsOutput:
        raise NotImplementedError

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken | None = None, **kwargs
    ) -> ListExportsOutput:
        raise NotImplementedError

    @handler("ListGeneratedTemplates")
    def list_generated_templates(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListGeneratedTemplatesOutput:
        raise NotImplementedError

    @handler("ListHookResults")
    def list_hook_results(
        self,
        context: RequestContext,
        target_type: ListHookResultsTargetType,
        target_id: HookResultId,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListHookResultsOutput:
        raise NotImplementedError

    @handler("ListImports")
    def list_imports(
        self,
        context: RequestContext,
        export_name: ExportName,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListImportsOutput:
        raise NotImplementedError

    @handler("ListResourceScanRelatedResources")
    def list_resource_scan_related_resources(
        self,
        context: RequestContext,
        resource_scan_id: ResourceScanId,
        resources: ScannedResourceIdentifiers,
        next_token: NextToken | None = None,
        max_results: BoxedMaxResults | None = None,
        **kwargs,
    ) -> ListResourceScanRelatedResourcesOutput:
        raise NotImplementedError

    @handler("ListResourceScanResources")
    def list_resource_scan_resources(
        self,
        context: RequestContext,
        resource_scan_id: ResourceScanId,
        resource_identifier: ResourceIdentifier | None = None,
        resource_type_prefix: ResourceTypePrefix | None = None,
        tag_key: TagKey | None = None,
        tag_value: TagValue | None = None,
        next_token: NextToken | None = None,
        max_results: ResourceScannerMaxResults | None = None,
        **kwargs,
    ) -> ListResourceScanResourcesOutput:
        raise NotImplementedError

    @handler("ListResourceScans")
    def list_resource_scans(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: ResourceScannerMaxResults | None = None,
        scan_type_filter: ScanType | None = None,
        **kwargs,
    ) -> ListResourceScansOutput:
        raise NotImplementedError

    @handler("ListStackInstanceResourceDrifts")
    def list_stack_instance_resource_drifts(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        stack_instance_account: Account,
        stack_instance_region: Region,
        operation_id: ClientRequestToken,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        stack_instance_resource_drift_statuses: StackResourceDriftStatusFilters | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ListStackInstanceResourceDriftsOutput:
        raise NotImplementedError

    @handler("ListStackInstances")
    def list_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        filters: StackInstanceFilters | None = None,
        stack_instance_account: Account | None = None,
        stack_instance_region: Region | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ListStackInstancesOutput:
        raise NotImplementedError

    @handler("ListStackRefactorActions")
    def list_stack_refactor_actions(
        self,
        context: RequestContext,
        stack_refactor_id: StackRefactorId,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListStackRefactorActionsOutput:
        raise NotImplementedError

    @handler("ListStackRefactors")
    def list_stack_refactors(
        self,
        context: RequestContext,
        execution_status_filter: StackRefactorExecutionStatusFilter | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListStackRefactorsOutput:
        raise NotImplementedError

    @handler("ListStackResources")
    def list_stack_resources(
        self,
        context: RequestContext,
        stack_name: StackName,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListStackResourcesOutput:
        raise NotImplementedError

    @handler("ListStackSetAutoDeploymentTargets")
    def list_stack_set_auto_deployment_targets(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ListStackSetAutoDeploymentTargetsOutput:
        raise NotImplementedError

    @handler("ListStackSetOperationResults")
    def list_stack_set_operation_results(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        call_as: CallAs | None = None,
        filters: OperationResultFilters | None = None,
        **kwargs,
    ) -> ListStackSetOperationResultsOutput:
        raise NotImplementedError

    @handler("ListStackSetOperations")
    def list_stack_set_operations(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ListStackSetOperationsOutput:
        raise NotImplementedError

    @handler("ListStackSets")
    def list_stack_sets(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        status: StackSetStatus | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> ListStackSetsOutput:
        raise NotImplementedError

    @handler("ListStacks")
    def list_stacks(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        stack_status_filter: StackStatusFilter | None = None,
        **kwargs,
    ) -> ListStacksOutput:
        raise NotImplementedError

    @handler("ListTypeRegistrations", expand=False)
    def list_type_registrations(
        self, context: RequestContext, request: ListTypeRegistrationsInput, **kwargs
    ) -> ListTypeRegistrationsOutput:
        raise NotImplementedError

    @handler("ListTypeVersions", expand=False)
    def list_type_versions(
        self, context: RequestContext, request: ListTypeVersionsInput, **kwargs
    ) -> ListTypeVersionsOutput:
        raise NotImplementedError

    @handler("ListTypes", expand=False)
    def list_types(
        self, context: RequestContext, request: ListTypesInput, **kwargs
    ) -> ListTypesOutput:
        raise NotImplementedError

    @handler("PublishType", expand=False)
    def publish_type(
        self, context: RequestContext, request: PublishTypeInput, **kwargs
    ) -> PublishTypeOutput:
        raise NotImplementedError

    @handler("RecordHandlerProgress")
    def record_handler_progress(
        self,
        context: RequestContext,
        bearer_token: ClientToken,
        operation_status: OperationStatus,
        current_operation_status: OperationStatus | None = None,
        status_message: StatusMessage | None = None,
        error_code: HandlerErrorCode | None = None,
        resource_model: ResourceModel | None = None,
        client_request_token: ClientRequestToken | None = None,
        **kwargs,
    ) -> RecordHandlerProgressOutput:
        raise NotImplementedError

    @handler("RegisterPublisher")
    def register_publisher(
        self,
        context: RequestContext,
        accept_terms_and_conditions: AcceptTermsAndConditions | None = None,
        connection_arn: ConnectionArn | None = None,
        **kwargs,
    ) -> RegisterPublisherOutput:
        raise NotImplementedError

    @handler("RegisterType", expand=False)
    def register_type(
        self, context: RequestContext, request: RegisterTypeInput, **kwargs
    ) -> RegisterTypeOutput:
        raise NotImplementedError

    @handler("RollbackStack")
    def rollback_stack(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        role_arn: RoleARN | None = None,
        client_request_token: ClientRequestToken | None = None,
        retain_except_on_create: RetainExceptOnCreate | None = None,
        **kwargs,
    ) -> RollbackStackOutput:
        raise NotImplementedError

    @handler("SetStackPolicy")
    def set_stack_policy(
        self,
        context: RequestContext,
        stack_name: StackName,
        stack_policy_body: StackPolicyBody | None = None,
        stack_policy_url: StackPolicyURL | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SetTypeConfiguration", expand=False)
    def set_type_configuration(
        self, context: RequestContext, request: SetTypeConfigurationInput, **kwargs
    ) -> SetTypeConfigurationOutput:
        raise NotImplementedError

    @handler("SetTypeDefaultVersion", expand=False)
    def set_type_default_version(
        self, context: RequestContext, request: SetTypeDefaultVersionInput, **kwargs
    ) -> SetTypeDefaultVersionOutput:
        raise NotImplementedError

    @handler("SignalResource")
    def signal_resource(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        logical_resource_id: LogicalResourceId,
        unique_id: ResourceSignalUniqueId,
        status: ResourceSignalStatus,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StartResourceScan")
    def start_resource_scan(
        self,
        context: RequestContext,
        client_request_token: ClientRequestToken | None = None,
        scan_filters: ScanFilters | None = None,
        **kwargs,
    ) -> StartResourceScanOutput:
        raise NotImplementedError

    @handler("StopStackSetOperation")
    def stop_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> StopStackSetOperationOutput:
        raise NotImplementedError

    @handler("TestType", expand=False)
    def test_type(
        self, context: RequestContext, request: TestTypeInput, **kwargs
    ) -> TestTypeOutput:
        raise NotImplementedError

    @handler("UpdateGeneratedTemplate")
    def update_generated_template(
        self,
        context: RequestContext,
        generated_template_name: GeneratedTemplateName,
        new_generated_template_name: GeneratedTemplateName | None = None,
        add_resources: ResourceDefinitions | None = None,
        remove_resources: JazzLogicalResourceIds | None = None,
        refresh_all_resources: RefreshAllResources | None = None,
        template_configuration: TemplateConfiguration | None = None,
        **kwargs,
    ) -> UpdateGeneratedTemplateOutput:
        raise NotImplementedError

    @handler("UpdateStack")
    def update_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        use_previous_template: UsePreviousTemplate | None = None,
        stack_policy_during_update_body: StackPolicyDuringUpdateBody | None = None,
        stack_policy_during_update_url: StackPolicyDuringUpdateURL | None = None,
        parameters: Parameters | None = None,
        capabilities: Capabilities | None = None,
        resource_types: ResourceTypes | None = None,
        role_arn: RoleARN | None = None,
        rollback_configuration: RollbackConfiguration | None = None,
        stack_policy_body: StackPolicyBody | None = None,
        stack_policy_url: StackPolicyURL | None = None,
        notification_arns: NotificationARNs | None = None,
        tags: Tags | None = None,
        disable_rollback: DisableRollback | None = None,
        client_request_token: ClientRequestToken | None = None,
        retain_except_on_create: RetainExceptOnCreate | None = None,
        **kwargs,
    ) -> UpdateStackOutput:
        raise NotImplementedError

    @handler("UpdateStackInstances")
    def update_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        regions: RegionList,
        accounts: AccountList | None = None,
        deployment_targets: DeploymentTargets | None = None,
        parameter_overrides: Parameters | None = None,
        operation_preferences: StackSetOperationPreferences | None = None,
        operation_id: ClientRequestToken | None = None,
        call_as: CallAs | None = None,
        **kwargs,
    ) -> UpdateStackInstancesOutput:
        raise NotImplementedError

    @handler("UpdateStackSet")
    def update_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        description: Description | None = None,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        use_previous_template: UsePreviousTemplate | None = None,
        parameters: Parameters | None = None,
        capabilities: Capabilities | None = None,
        tags: Tags | None = None,
        operation_preferences: StackSetOperationPreferences | None = None,
        administration_role_arn: RoleARN | None = None,
        execution_role_name: ExecutionRoleName | None = None,
        deployment_targets: DeploymentTargets | None = None,
        permission_model: PermissionModels | None = None,
        auto_deployment: AutoDeployment | None = None,
        operation_id: ClientRequestToken | None = None,
        accounts: AccountList | None = None,
        regions: RegionList | None = None,
        call_as: CallAs | None = None,
        managed_execution: ManagedExecution | None = None,
        **kwargs,
    ) -> UpdateStackSetOutput:
        raise NotImplementedError

    @handler("UpdateTerminationProtection")
    def update_termination_protection(
        self,
        context: RequestContext,
        enable_termination_protection: EnableTerminationProtection,
        stack_name: StackNameOrId,
        **kwargs,
    ) -> UpdateTerminationProtectionOutput:
        raise NotImplementedError

    @handler("ValidateTemplate")
    def validate_template(
        self,
        context: RequestContext,
        template_body: TemplateBody | None = None,
        template_url: TemplateURL | None = None,
        **kwargs,
    ) -> ValidateTemplateOutput:
        raise NotImplementedError
