from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AcceptTermsAndConditions = bool
Account = str
AccountGateStatusReason = str
AccountsUrl = str
AfterContext = str
AfterValue = str
AllowedValue = str
AnnotationName = str
AnnotationRemediationLink = str
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
FailedEventsFilter = bool
FailedStackInstancesCount = int
FailureToleranceCount = int
FailureTolerancePercentage = int
GeneratedTemplateId = str
GeneratedTemplateName = str
HookInvocationCount = int
HookInvocationId = str
HookResultId = str
HookStatusReason = str
HookTargetId = str
HookTargetTypeName = str
HookType = str
HookTypeArn = str
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
OperationId = str
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
PreviousDeploymentContext = str
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
RemediationMessageRemediationMessage = str
RemediationMessageStatusMessage = str
RequestToken = str
RequiredProperty = bool
ResourceDriftActualValue = str
ResourceDriftPreviousValue = str
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
StackResourceDriftStatusReason = str
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
ValidationName = str
ValidationPath = str
ValidationStatusReason = str
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


class AfterValueFrom(StrEnum):
    TEMPLATE = "TEMPLATE"


class AnnotationSeverityLevel(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnnotationStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class AttributeChangeType(StrEnum):
    Add = "Add"
    Remove = "Remove"
    Modify = "Modify"
    SyncWithActual = "SyncWithActual"


class BeaconStackOperationStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class BeforeValueFrom(StrEnum):
    PREVIOUS_DEPLOYMENT_STATE = "PREVIOUS_DEPLOYMENT_STATE"
    ACTUAL_STATE = "ACTUAL_STATE"


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
    SyncWithActual = "SyncWithActual"


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
    NoModification = "NoModification"


class ChangeType(StrEnum):
    Resource = "Resource"


class ConcurrencyMode(StrEnum):
    STRICT_FAILURE_TOLERANCE = "STRICT_FAILURE_TOLERANCE"
    SOFT_FAILURE_TOLERANCE = "SOFT_FAILURE_TOLERANCE"


class DeletionMode(StrEnum):
    STANDARD = "STANDARD"
    FORCE_DELETE_STACK = "FORCE_DELETE_STACK"


class DeploymentMode(StrEnum):
    REVERT_DRIFT = "REVERT_DRIFT"


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


class DriftIgnoredReason(StrEnum):
    MANAGED_BY_AWS = "MANAGED_BY_AWS"
    WRITE_ONLY_PROPERTY = "WRITE_ONLY_PROPERTY"


class EvaluationType(StrEnum):
    Static = "Static"
    Dynamic = "Dynamic"


class EventType(StrEnum):
    STACK_EVENT = "STACK_EVENT"
    PROGRESS_EVENT = "PROGRESS_EVENT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    PROVISIONING_ERROR = "PROVISIONING_ERROR"
    HOOK_INVOCATION_ERROR = "HOOK_INVOCATION_ERROR"


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


class HookTargetAction(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    IMPORT = "IMPORT"


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


class OperationType(StrEnum):
    CREATE_STACK = "CREATE_STACK"
    UPDATE_STACK = "UPDATE_STACK"
    DELETE_STACK = "DELETE_STACK"
    CONTINUE_ROLLBACK = "CONTINUE_ROLLBACK"
    ROLLBACK = "ROLLBACK"
    CREATE_CHANGESET = "CREATE_CHANGESET"


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
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


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


class ValidationStatus(StrEnum):
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


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
    EXCLUDED_PROPERTIES = "EXCLUDED_PROPERTIES"
    EXCLUDED_RESOURCES = "EXCLUDED_RESOURCES"


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
    Status: AccountGateStatus | None
    StatusReason: AccountGateStatusReason | None


class AccountLimit(TypedDict, total=False):
    Name: LimitName | None
    Value: LimitValue | None


AccountLimitList = list[AccountLimit]
AccountList = list[Account]


class ActivateOrganizationsAccessInput(ServiceRequest):
    pass


class ActivateOrganizationsAccessOutput(TypedDict, total=False):
    pass


MajorVersion = int


class LoggingConfig(TypedDict, total=False):
    LogRoleArn: RoleArn
    LogGroupName: LogGroupName


class ActivateTypeInput(ServiceRequest):
    Type: ThirdPartyType | None
    PublicTypeArn: ThirdPartyTypeArn | None
    PublisherId: PublisherId | None
    TypeName: TypeName | None
    TypeNameAlias: TypeName | None
    AutoUpdate: AutoUpdate | None
    LoggingConfig: LoggingConfig | None
    ExecutionRoleArn: RoleArn | None
    VersionBump: VersionBump | None
    MajorVersion: MajorVersion | None


class ActivateTypeOutput(TypedDict, total=False):
    Arn: PrivateTypeArn | None


AllowedValues = list[AllowedValue]


class Annotation(TypedDict, total=False):
    AnnotationName: AnnotationName | None
    Status: AnnotationStatus | None
    StatusMessage: RemediationMessageStatusMessage | None
    RemediationMessage: RemediationMessageRemediationMessage | None
    RemediationLink: AnnotationRemediationLink | None
    SeverityLevel: AnnotationSeverityLevel | None


AnnotationList = list[Annotation]
StackSetARNList = list[StackSetARN]


class AutoDeployment(TypedDict, total=False):
    Enabled: AutoDeploymentNullable | None
    RetainStacksOnAccountRemoval: RetainStacksOnAccountRemovalNullable | None
    DependsOn: StackSetARNList | None


class TypeConfigurationIdentifier(TypedDict, total=False):
    TypeArn: TypeArn | None
    TypeConfigurationAlias: TypeConfigurationAlias | None
    TypeConfigurationArn: TypeConfigurationArn | None
    Type: ThirdPartyType | None
    TypeName: TypeName | None


class BatchDescribeTypeConfigurationsError(TypedDict, total=False):
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None
    TypeConfigurationIdentifier: TypeConfigurationIdentifier | None


BatchDescribeTypeConfigurationsErrors = list[BatchDescribeTypeConfigurationsError]
TypeConfigurationIdentifiers = list[TypeConfigurationIdentifier]


class BatchDescribeTypeConfigurationsInput(ServiceRequest):
    TypeConfigurationIdentifiers: TypeConfigurationIdentifiers


Timestamp = datetime


class TypeConfigurationDetails(TypedDict, total=False):
    Arn: TypeConfigurationArn | None
    Alias: TypeConfigurationAlias | None
    Configuration: TypeConfiguration | None
    LastUpdated: Timestamp | None
    TypeArn: TypeArn | None
    TypeName: TypeName | None
    IsDefaultConfiguration: IsDefaultConfiguration | None


TypeConfigurationDetailsList = list[TypeConfigurationDetails]
UnprocessedTypeConfigurations = list[TypeConfigurationIdentifier]


class BatchDescribeTypeConfigurationsOutput(TypedDict, total=False):
    Errors: BatchDescribeTypeConfigurationsErrors | None
    UnprocessedTypeConfigurations: UnprocessedTypeConfigurations | None
    TypeConfigurations: TypeConfigurationDetailsList | None


class CancelUpdateStackInput(ServiceRequest):
    StackName: StackName
    ClientRequestToken: ClientRequestToken | None


Capabilities = list[Capability]


class ModuleInfo(TypedDict, total=False):
    TypeHierarchy: TypeHierarchy | None
    LogicalIdHierarchy: LogicalIdHierarchy | None


class LiveResourceDrift(TypedDict, total=False):
    PreviousValue: ResourceDriftPreviousValue | None
    ActualValue: ResourceDriftActualValue | None
    DriftDetectionTimestamp: Timestamp | None


class ResourceTargetDefinition(TypedDict, total=False):
    Attribute: ResourceAttribute | None
    Name: PropertyName | None
    RequiresRecreation: RequiresRecreation | None
    Path: ResourcePropertyPath | None
    BeforeValue: BeforeValue | None
    AfterValue: AfterValue | None
    BeforeValueFrom: BeforeValueFrom | None
    AfterValueFrom: AfterValueFrom | None
    Drift: LiveResourceDrift | None
    AttributeChangeType: AttributeChangeType | None


class ResourceChangeDetail(TypedDict, total=False):
    Target: ResourceTargetDefinition | None
    Evaluation: EvaluationType | None
    ChangeSource: ChangeSource | None
    CausingEntity: CausingEntity | None


ResourceChangeDetails = list[ResourceChangeDetail]


class ResourceDriftIgnoredAttribute(TypedDict, total=False):
    Path: ResourcePropertyPath | None
    Reason: DriftIgnoredReason | None


ResourceDriftIgnoredAttributes = list[ResourceDriftIgnoredAttribute]
Scope = list[ResourceAttribute]


class ResourceChange(TypedDict, total=False):
    PolicyAction: PolicyAction | None
    Action: ChangeAction | None
    LogicalResourceId: LogicalResourceId | None
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType | None
    Replacement: Replacement | None
    Scope: Scope | None
    ResourceDriftStatus: StackResourceDriftStatus | None
    ResourceDriftIgnoredAttributes: ResourceDriftIgnoredAttributes | None
    Details: ResourceChangeDetails | None
    ChangeSetId: ChangeSetId | None
    ModuleInfo: ModuleInfo | None
    BeforeContext: BeforeContext | None
    AfterContext: AfterContext | None
    PreviousDeploymentContext: PreviousDeploymentContext | None


class Change(TypedDict, total=False):
    Type: ChangeType | None
    HookInvocationCount: HookInvocationCount | None
    ResourceChange: ResourceChange | None


class ChangeSetHookResourceTargetDetails(TypedDict, total=False):
    LogicalResourceId: LogicalResourceId | None
    ResourceType: HookTargetTypeName | None
    ResourceAction: ChangeAction | None


class ChangeSetHookTargetDetails(TypedDict, total=False):
    TargetType: HookTargetType | None
    ResourceTargetDetails: ChangeSetHookResourceTargetDetails | None


class ChangeSetHook(TypedDict, total=False):
    InvocationPoint: HookInvocationPoint | None
    FailureMode: HookFailureMode | None
    TypeName: HookTypeName | None
    TypeVersionId: HookTypeVersionId | None
    TypeConfigurationVersionId: HookTypeConfigurationVersionId | None
    TargetDetails: ChangeSetHookTargetDetails | None


ChangeSetHooks = list[ChangeSetHook]
CreationTime = datetime


class ChangeSetSummary(TypedDict, total=False):
    StackId: StackId | None
    StackName: StackName | None
    ChangeSetId: ChangeSetId | None
    ChangeSetName: ChangeSetName | None
    ExecutionStatus: ExecutionStatus | None
    Status: ChangeSetStatus | None
    StatusReason: ChangeSetStatusReason | None
    CreationTime: CreationTime | None
    Description: Description | None
    IncludeNestedStacks: IncludeNestedStacks | None
    ParentChangeSetId: ChangeSetId | None
    RootChangeSetId: ChangeSetId | None
    ImportExistingResources: ImportExistingResources | None


ChangeSetSummaries = list[ChangeSetSummary]
Changes = list[Change]
ResourcesToSkip = list[ResourceToSkip]


class ContinueUpdateRollbackInput(ServiceRequest):
    StackName: StackNameOrId
    RoleARN: RoleARN | None
    ResourcesToSkip: ResourcesToSkip | None
    ClientRequestToken: ClientRequestToken | None


class ContinueUpdateRollbackOutput(TypedDict, total=False):
    pass


ResourceIdentifierProperties = dict[ResourceIdentifierPropertyKey, ResourceIdentifierPropertyValue]


class ResourceToImport(TypedDict, total=False):
    ResourceType: ResourceType
    LogicalResourceId: LogicalResourceId
    ResourceIdentifier: ResourceIdentifierProperties


ResourcesToImport = list[ResourceToImport]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


Tags = list[Tag]
NotificationARNs = list[NotificationARN]


class RollbackTrigger(TypedDict, total=False):
    Arn: Arn
    Type: Type


RollbackTriggers = list[RollbackTrigger]


class RollbackConfiguration(TypedDict, total=False):
    RollbackTriggers: RollbackTriggers | None
    MonitoringTimeInMinutes: MonitoringTimeInMinutes | None


ResourceTypes = list[ResourceType]


class Parameter(TypedDict, total=False):
    ParameterKey: ParameterKey | None
    ParameterValue: ParameterValue | None
    UsePreviousValue: UsePreviousValue | None
    ResolvedValue: ParameterValue | None


Parameters = list[Parameter]


class CreateChangeSetInput(ServiceRequest):
    StackName: StackNameOrId
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    UsePreviousTemplate: UsePreviousTemplate | None
    Parameters: Parameters | None
    Capabilities: Capabilities | None
    ResourceTypes: ResourceTypes | None
    RoleARN: RoleARN | None
    RollbackConfiguration: RollbackConfiguration | None
    NotificationARNs: NotificationARNs | None
    Tags: Tags | None
    ChangeSetName: ChangeSetName
    ClientToken: ClientToken | None
    Description: Description | None
    ChangeSetType: ChangeSetType | None
    ResourcesToImport: ResourcesToImport | None
    IncludeNestedStacks: IncludeNestedStacks | None
    OnStackFailure: OnStackFailure | None
    ImportExistingResources: ImportExistingResources | None
    DeploymentMode: DeploymentMode | None


class CreateChangeSetOutput(TypedDict, total=False):
    Id: ChangeSetId | None
    StackId: StackId | None


class TemplateConfiguration(TypedDict, total=False):
    DeletionPolicy: GeneratedTemplateDeletionPolicy | None
    UpdateReplacePolicy: GeneratedTemplateUpdateReplacePolicy | None


class ResourceDefinition(TypedDict, total=False):
    ResourceType: ResourceType
    LogicalResourceId: LogicalResourceId | None
    ResourceIdentifier: ResourceIdentifierProperties


ResourceDefinitions = list[ResourceDefinition]


class CreateGeneratedTemplateInput(ServiceRequest):
    Resources: ResourceDefinitions | None
    GeneratedTemplateName: GeneratedTemplateName
    StackName: StackName | None
    TemplateConfiguration: TemplateConfiguration | None


class CreateGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: GeneratedTemplateId | None


class CreateStackInput(ServiceRequest):
    StackName: StackName
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    Parameters: Parameters | None
    DisableRollback: DisableRollback | None
    RollbackConfiguration: RollbackConfiguration | None
    TimeoutInMinutes: TimeoutMinutes | None
    NotificationARNs: NotificationARNs | None
    Capabilities: Capabilities | None
    ResourceTypes: ResourceTypes | None
    RoleARN: RoleARN | None
    OnFailure: OnFailure | None
    StackPolicyBody: StackPolicyBody | None
    StackPolicyURL: StackPolicyURL | None
    Tags: Tags | None
    ClientRequestToken: ClientRequestToken | None
    EnableTerminationProtection: EnableTerminationProtection | None
    RetainExceptOnCreate: RetainExceptOnCreate | None


RegionList = list[Region]


class StackSetOperationPreferences(TypedDict, total=False):
    RegionConcurrencyType: RegionConcurrencyType | None
    RegionOrder: RegionList | None
    FailureToleranceCount: FailureToleranceCount | None
    FailureTolerancePercentage: FailureTolerancePercentage | None
    MaxConcurrentCount: MaxConcurrentCount | None
    MaxConcurrentPercentage: MaxConcurrentPercentage | None
    ConcurrencyMode: ConcurrencyMode | None


OrganizationalUnitIdList = list[OrganizationalUnitId]


class DeploymentTargets(TypedDict, total=False):
    Accounts: AccountList | None
    AccountsUrl: AccountsUrl | None
    OrganizationalUnitIds: OrganizationalUnitIdList | None
    AccountFilterType: AccountFilterType | None


class CreateStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    Accounts: AccountList | None
    DeploymentTargets: DeploymentTargets | None
    Regions: RegionList
    ParameterOverrides: Parameters | None
    OperationPreferences: StackSetOperationPreferences | None
    OperationId: ClientRequestToken | None
    CallAs: CallAs | None


class CreateStackInstancesOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


class CreateStackOutput(TypedDict, total=False):
    StackId: StackId | None
    OperationId: OperationId | None


class StackDefinition(TypedDict, total=False):
    StackName: StackName | None
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None


StackDefinitions = list[StackDefinition]


class ResourceLocation(TypedDict, total=False):
    StackName: StackName
    LogicalResourceId: LogicalResourceId


class ResourceMapping(TypedDict, total=False):
    Source: ResourceLocation
    Destination: ResourceLocation


ResourceMappings = list[ResourceMapping]


class CreateStackRefactorInput(ServiceRequest):
    Description: Description | None
    EnableStackCreation: EnableStackCreation | None
    ResourceMappings: ResourceMappings | None
    StackDefinitions: StackDefinitions


class CreateStackRefactorOutput(TypedDict, total=False):
    StackRefactorId: StackRefactorId


class ManagedExecution(TypedDict, total=False):
    Active: ManagedExecutionNullable | None


class CreateStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    Description: Description | None
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    StackId: StackId | None
    Parameters: Parameters | None
    Capabilities: Capabilities | None
    Tags: Tags | None
    AdministrationRoleARN: RoleARN | None
    ExecutionRoleName: ExecutionRoleName | None
    PermissionModel: PermissionModels | None
    AutoDeployment: AutoDeployment | None
    CallAs: CallAs | None
    ClientRequestToken: ClientRequestToken | None
    ManagedExecution: ManagedExecution | None


class CreateStackSetOutput(TypedDict, total=False):
    StackSetId: StackSetId | None


class DeactivateOrganizationsAccessInput(ServiceRequest):
    pass


class DeactivateOrganizationsAccessOutput(TypedDict, total=False):
    pass


class DeactivateTypeInput(ServiceRequest):
    TypeName: TypeName | None
    Type: ThirdPartyType | None
    Arn: PrivateTypeArn | None


class DeactivateTypeOutput(TypedDict, total=False):
    pass


class DeleteChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: StackNameOrId | None


class DeleteChangeSetOutput(TypedDict, total=False):
    pass


class DeleteGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName


RetainResources = list[LogicalResourceId]


class DeleteStackInput(ServiceRequest):
    StackName: StackName
    RetainResources: RetainResources | None
    RoleARN: RoleARN | None
    ClientRequestToken: ClientRequestToken | None
    DeletionMode: DeletionMode | None


class DeleteStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    Accounts: AccountList | None
    DeploymentTargets: DeploymentTargets | None
    Regions: RegionList
    OperationPreferences: StackSetOperationPreferences | None
    RetainStacks: RetainStacks
    OperationId: ClientRequestToken | None
    CallAs: CallAs | None


class DeleteStackInstancesOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


class DeleteStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    CallAs: CallAs | None


class DeleteStackSetOutput(TypedDict, total=False):
    pass


DeletionTime = datetime


class DeregisterTypeInput(ServiceRequest):
    Arn: PrivateTypeArn | None
    Type: RegistryType | None
    TypeName: TypeName | None
    VersionId: TypeVersionId | None


class DeregisterTypeOutput(TypedDict, total=False):
    pass


class DescribeAccountLimitsInput(ServiceRequest):
    NextToken: NextToken | None


class DescribeAccountLimitsOutput(TypedDict, total=False):
    AccountLimits: AccountLimitList | None
    NextToken: NextToken | None


class DescribeChangeSetHooksInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: StackNameOrId | None
    NextToken: NextToken | None
    LogicalResourceId: LogicalResourceId | None


class DescribeChangeSetHooksOutput(TypedDict, total=False):
    ChangeSetId: ChangeSetId | None
    ChangeSetName: ChangeSetName | None
    Hooks: ChangeSetHooks | None
    Status: ChangeSetHooksStatus | None
    NextToken: NextToken | None
    StackId: StackId | None
    StackName: StackName | None


class DescribeChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: StackNameOrId | None
    NextToken: NextToken | None
    IncludePropertyValues: IncludePropertyValues | None


class DescribeChangeSetOutput(TypedDict, total=False):
    ChangeSetName: ChangeSetName | None
    ChangeSetId: ChangeSetId | None
    StackId: StackId | None
    StackName: StackName | None
    Description: Description | None
    Parameters: Parameters | None
    CreationTime: CreationTime | None
    ExecutionStatus: ExecutionStatus | None
    Status: ChangeSetStatus | None
    StatusReason: ChangeSetStatusReason | None
    StackDriftStatus: StackDriftStatus | None
    NotificationARNs: NotificationARNs | None
    RollbackConfiguration: RollbackConfiguration | None
    Capabilities: Capabilities | None
    Tags: Tags | None
    Changes: Changes | None
    NextToken: NextToken | None
    IncludeNestedStacks: IncludeNestedStacks | None
    ParentChangeSetId: ChangeSetId | None
    RootChangeSetId: ChangeSetId | None
    OnStackFailure: OnStackFailure | None
    ImportExistingResources: ImportExistingResources | None
    DeploymentMode: DeploymentMode | None


class EventFilter(TypedDict, total=False):
    FailedEvents: FailedEventsFilter | None


class DescribeEventsInput(ServiceRequest):
    StackName: StackNameOrId | None
    ChangeSetName: ChangeSetNameOrId | None
    OperationId: OperationId | None
    Filters: EventFilter | None
    NextToken: NextToken | None


class OperationEvent(TypedDict, total=False):
    EventId: EventId | None
    StackId: StackId | None
    OperationId: OperationId | None
    OperationType: OperationType | None
    OperationStatus: BeaconStackOperationStatus | None
    EventType: EventType | None
    LogicalResourceId: LogicalResourceId | None
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType | None
    Timestamp: Timestamp | None
    StartTime: Timestamp | None
    EndTime: Timestamp | None
    ResourceStatus: ResourceStatus | None
    ResourceStatusReason: ResourceStatusReason | None
    ResourceProperties: ResourceProperties | None
    ClientRequestToken: ClientRequestToken | None
    HookType: HookType | None
    HookStatus: HookStatus | None
    HookStatusReason: HookStatusReason | None
    HookInvocationPoint: HookInvocationPoint | None
    HookFailureMode: HookFailureMode | None
    DetailedStatus: DetailedStatus | None
    ValidationFailureMode: HookFailureMode | None
    ValidationName: ValidationName | None
    ValidationStatus: ValidationStatus | None
    ValidationStatusReason: ValidationStatusReason | None
    ValidationPath: ValidationPath | None


OperationEvents = list[OperationEvent]


class DescribeEventsOutput(TypedDict, total=False):
    OperationEvents: OperationEvents | None
    NextToken: NextToken | None


class DescribeGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName


class TemplateProgress(TypedDict, total=False):
    ResourcesSucceeded: ResourcesSucceeded | None
    ResourcesFailed: ResourcesFailed | None
    ResourcesProcessing: ResourcesProcessing | None
    ResourcesPending: ResourcesPending | None


LastUpdatedTime = datetime


class WarningProperty(TypedDict, total=False):
    PropertyPath: PropertyPath | None
    Required: RequiredProperty | None
    Description: PropertyDescription | None


WarningProperties = list[WarningProperty]


class WarningDetail(TypedDict, total=False):
    Type: WarningType | None
    Properties: WarningProperties | None


WarningDetails = list[WarningDetail]


class ResourceDetail(TypedDict, total=False):
    ResourceType: ResourceType | None
    LogicalResourceId: LogicalResourceId | None
    ResourceIdentifier: ResourceIdentifierProperties | None
    ResourceStatus: GeneratedTemplateResourceStatus | None
    ResourceStatusReason: ResourceStatusReason | None
    Warnings: WarningDetails | None


ResourceDetails = list[ResourceDetail]


class DescribeGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: GeneratedTemplateId | None
    GeneratedTemplateName: GeneratedTemplateName | None
    Resources: ResourceDetails | None
    Status: GeneratedTemplateStatus | None
    StatusReason: TemplateStatusReason | None
    CreationTime: CreationTime | None
    LastUpdatedTime: LastUpdatedTime | None
    Progress: TemplateProgress | None
    StackId: StackId | None
    TemplateConfiguration: TemplateConfiguration | None
    TotalWarnings: TotalWarnings | None


class DescribeOrganizationsAccessInput(ServiceRequest):
    CallAs: CallAs | None


class DescribeOrganizationsAccessOutput(TypedDict, total=False):
    Status: OrganizationStatus | None


class DescribePublisherInput(ServiceRequest):
    PublisherId: PublisherId | None


class DescribePublisherOutput(TypedDict, total=False):
    PublisherId: PublisherId | None
    PublisherStatus: PublisherStatus | None
    IdentityProvider: IdentityProvider | None
    PublisherProfile: PublisherProfile | None


class DescribeResourceScanInput(ServiceRequest):
    ResourceScanId: ResourceScanId


ResourceTypeFilters = list[ResourceTypeFilter]


class ScanFilter(TypedDict, total=False):
    Types: ResourceTypeFilters | None


ScanFilters = list[ScanFilter]


class DescribeResourceScanOutput(TypedDict, total=False):
    ResourceScanId: ResourceScanId | None
    Status: ResourceScanStatus | None
    StatusReason: ResourceScanStatusReason | None
    StartTime: Timestamp | None
    EndTime: Timestamp | None
    PercentageCompleted: PercentageCompleted | None
    ResourceTypes: ResourceTypes | None
    ResourcesScanned: ResourcesScanned | None
    ResourcesRead: ResourcesRead | None
    ScanFilters: ScanFilters | None


class DescribeStackDriftDetectionStatusInput(ServiceRequest):
    StackDriftDetectionId: StackDriftDetectionId


class DescribeStackDriftDetectionStatusOutput(TypedDict, total=False):
    StackId: StackId
    StackDriftDetectionId: StackDriftDetectionId
    StackDriftStatus: StackDriftStatus | None
    DetectionStatus: StackDriftDetectionStatus
    DetectionStatusReason: StackDriftDetectionStatusReason | None
    DriftedStackResourceCount: BoxedInteger | None
    Timestamp: Timestamp


class DescribeStackEventsInput(ServiceRequest):
    StackName: StackName
    NextToken: NextToken | None


class StackEvent(TypedDict, total=False):
    StackId: StackId
    EventId: EventId
    StackName: StackName
    OperationId: OperationId | None
    LogicalResourceId: LogicalResourceId | None
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType | None
    Timestamp: Timestamp
    ResourceStatus: ResourceStatus | None
    ResourceStatusReason: ResourceStatusReason | None
    ResourceProperties: ResourceProperties | None
    ClientRequestToken: ClientRequestToken | None
    HookType: HookType | None
    HookStatus: HookStatus | None
    HookStatusReason: HookStatusReason | None
    HookInvocationPoint: HookInvocationPoint | None
    HookInvocationId: HookInvocationId | None
    HookFailureMode: HookFailureMode | None
    DetailedStatus: DetailedStatus | None


StackEvents = list[StackEvent]


class DescribeStackEventsOutput(TypedDict, total=False):
    StackEvents: StackEvents | None
    NextToken: NextToken | None


class DescribeStackInstanceInput(ServiceRequest):
    StackSetName: StackSetName
    StackInstanceAccount: Account
    StackInstanceRegion: Region
    CallAs: CallAs | None


class StackInstanceComprehensiveStatus(TypedDict, total=False):
    DetailedStatus: StackInstanceDetailedStatus | None


class StackInstance(TypedDict, total=False):
    StackSetId: StackSetId | None
    Region: Region | None
    Account: Account | None
    StackId: StackId | None
    ParameterOverrides: Parameters | None
    Status: StackInstanceStatus | None
    StackInstanceStatus: StackInstanceComprehensiveStatus | None
    StatusReason: Reason | None
    OrganizationalUnitId: OrganizationalUnitId | None
    DriftStatus: StackDriftStatus | None
    LastDriftCheckTimestamp: Timestamp | None
    LastOperationId: ClientRequestToken | None


class DescribeStackInstanceOutput(TypedDict, total=False):
    StackInstance: StackInstance | None


class DescribeStackRefactorInput(ServiceRequest):
    StackRefactorId: StackRefactorId


StackIds = list[StackId]


class DescribeStackRefactorOutput(TypedDict, total=False):
    Description: Description | None
    StackRefactorId: StackRefactorId | None
    StackIds: StackIds | None
    ExecutionStatus: StackRefactorExecutionStatus | None
    ExecutionStatusReason: ExecutionStatusReason | None
    Status: StackRefactorStatus | None
    StatusReason: StackRefactorStatusReason | None


StackResourceDriftStatusFilters = list[StackResourceDriftStatus]


class DescribeStackResourceDriftsInput(ServiceRequest):
    StackName: StackNameOrId
    StackResourceDriftStatusFilters: StackResourceDriftStatusFilters | None
    NextToken: NextToken | None
    MaxResults: BoxedMaxResults | None


class PropertyDifference(TypedDict, total=False):
    PropertyPath: PropertyPath
    ExpectedValue: PropertyValue
    ActualValue: PropertyValue
    DifferenceType: DifferenceType


PropertyDifferences = list[PropertyDifference]


class PhysicalResourceIdContextKeyValuePair(TypedDict, total=False):
    Key: Key
    Value: Value


PhysicalResourceIdContext = list[PhysicalResourceIdContextKeyValuePair]


class StackResourceDrift(TypedDict, total=False):
    StackId: StackId
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: PhysicalResourceId | None
    PhysicalResourceIdContext: PhysicalResourceIdContext | None
    ResourceType: ResourceType
    ExpectedProperties: Properties | None
    ActualProperties: Properties | None
    PropertyDifferences: PropertyDifferences | None
    StackResourceDriftStatus: StackResourceDriftStatus
    Timestamp: Timestamp
    ModuleInfo: ModuleInfo | None
    DriftStatusReason: StackResourceDriftStatusReason | None


StackResourceDrifts = list[StackResourceDrift]


class DescribeStackResourceDriftsOutput(TypedDict, total=False):
    StackResourceDrifts: StackResourceDrifts
    NextToken: NextToken | None


class DescribeStackResourceInput(ServiceRequest):
    StackName: StackName
    LogicalResourceId: LogicalResourceId


class StackResourceDriftInformation(TypedDict, total=False):
    StackResourceDriftStatus: StackResourceDriftStatus
    LastCheckTimestamp: Timestamp | None


class StackResourceDetail(TypedDict, total=False):
    StackName: StackName | None
    StackId: StackId | None
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType
    LastUpdatedTimestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: ResourceStatusReason | None
    Description: Description | None
    Metadata: Metadata | None
    DriftInformation: StackResourceDriftInformation | None
    ModuleInfo: ModuleInfo | None


class DescribeStackResourceOutput(TypedDict, total=False):
    StackResourceDetail: StackResourceDetail | None


class DescribeStackResourcesInput(ServiceRequest):
    StackName: StackName | None
    LogicalResourceId: LogicalResourceId | None
    PhysicalResourceId: PhysicalResourceId | None


class StackResource(TypedDict, total=False):
    StackName: StackName | None
    StackId: StackId | None
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType
    Timestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: ResourceStatusReason | None
    Description: Description | None
    DriftInformation: StackResourceDriftInformation | None
    ModuleInfo: ModuleInfo | None


StackResources = list[StackResource]


class DescribeStackResourcesOutput(TypedDict, total=False):
    StackResources: StackResources | None


class DescribeStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    CallAs: CallAs | None


class DescribeStackSetOperationInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    CallAs: CallAs | None


class StackSetOperationStatusDetails(TypedDict, total=False):
    FailedStackInstancesCount: FailedStackInstancesCount | None


class StackSetDriftDetectionDetails(TypedDict, total=False):
    DriftStatus: StackSetDriftStatus | None
    DriftDetectionStatus: StackSetDriftDetectionStatus | None
    LastDriftCheckTimestamp: Timestamp | None
    TotalStackInstancesCount: TotalStackInstancesCount | None
    DriftedStackInstancesCount: DriftedStackInstancesCount | None
    InSyncStackInstancesCount: InSyncStackInstancesCount | None
    InProgressStackInstancesCount: InProgressStackInstancesCount | None
    FailedStackInstancesCount: FailedStackInstancesCount | None


class StackSetOperation(TypedDict, total=False):
    OperationId: ClientRequestToken | None
    StackSetId: StackSetId | None
    Action: StackSetOperationAction | None
    Status: StackSetOperationStatus | None
    OperationPreferences: StackSetOperationPreferences | None
    RetainStacks: RetainStacksNullable | None
    AdministrationRoleARN: RoleARN | None
    ExecutionRoleName: ExecutionRoleName | None
    CreationTimestamp: Timestamp | None
    EndTimestamp: Timestamp | None
    DeploymentTargets: DeploymentTargets | None
    StackSetDriftDetectionDetails: StackSetDriftDetectionDetails | None
    StatusReason: StackSetOperationStatusReason | None
    StatusDetails: StackSetOperationStatusDetails | None


class DescribeStackSetOperationOutput(TypedDict, total=False):
    StackSetOperation: StackSetOperation | None


class StackSet(TypedDict, total=False):
    StackSetName: StackSetName | None
    StackSetId: StackSetId | None
    Description: Description | None
    Status: StackSetStatus | None
    TemplateBody: TemplateBody | None
    Parameters: Parameters | None
    Capabilities: Capabilities | None
    Tags: Tags | None
    StackSetARN: StackSetARN | None
    AdministrationRoleARN: RoleARN | None
    ExecutionRoleName: ExecutionRoleName | None
    StackSetDriftDetectionDetails: StackSetDriftDetectionDetails | None
    AutoDeployment: AutoDeployment | None
    PermissionModel: PermissionModels | None
    OrganizationalUnitIds: OrganizationalUnitIdList | None
    ManagedExecution: ManagedExecution | None
    Regions: RegionList | None


class DescribeStackSetOutput(TypedDict, total=False):
    StackSet: StackSet | None


class DescribeStacksInput(ServiceRequest):
    StackName: StackName | None
    NextToken: NextToken | None


class OperationEntry(TypedDict, total=False):
    OperationType: OperationType | None
    OperationId: OperationId | None


LastOperations = list[OperationEntry]


class StackDriftInformation(TypedDict, total=False):
    StackDriftStatus: StackDriftStatus
    LastCheckTimestamp: Timestamp | None


class Output(TypedDict, total=False):
    OutputKey: OutputKey | None
    OutputValue: OutputValue | None
    Description: Description | None
    ExportName: ExportName | None


Outputs = list[Output]


class Stack(TypedDict, total=False):
    StackId: StackId | None
    StackName: StackName
    ChangeSetId: ChangeSetId | None
    Description: Description | None
    Parameters: Parameters | None
    CreationTime: CreationTime
    DeletionTime: DeletionTime | None
    LastUpdatedTime: LastUpdatedTime | None
    RollbackConfiguration: RollbackConfiguration | None
    StackStatus: StackStatus
    StackStatusReason: StackStatusReason | None
    DisableRollback: DisableRollback | None
    NotificationARNs: NotificationARNs | None
    TimeoutInMinutes: TimeoutMinutes | None
    Capabilities: Capabilities | None
    Outputs: Outputs | None
    RoleARN: RoleARN | None
    Tags: Tags | None
    EnableTerminationProtection: EnableTerminationProtection | None
    ParentId: StackId | None
    RootId: StackId | None
    DriftInformation: StackDriftInformation | None
    RetainExceptOnCreate: RetainExceptOnCreate | None
    DeletionMode: DeletionMode | None
    DetailedStatus: DetailedStatus | None
    LastOperations: LastOperations | None


Stacks = list[Stack]


class DescribeStacksOutput(TypedDict, total=False):
    Stacks: Stacks | None
    NextToken: NextToken | None


class DescribeTypeInput(ServiceRequest):
    Type: RegistryType | None
    TypeName: TypeName | None
    Arn: TypeArn | None
    VersionId: TypeVersionId | None
    PublisherId: PublisherId | None
    PublicVersionNumber: PublicVersionNumber | None


SupportedMajorVersions = list[SupportedMajorVersion]


class RequiredActivatedType(TypedDict, total=False):
    TypeNameAlias: TypeName | None
    OriginalTypeName: TypeName | None
    PublisherId: PublisherId | None
    SupportedMajorVersions: SupportedMajorVersions | None


RequiredActivatedTypes = list[RequiredActivatedType]


class DescribeTypeOutput(TypedDict, total=False):
    Arn: TypeArn | None
    Type: RegistryType | None
    TypeName: TypeName | None
    DefaultVersionId: TypeVersionId | None
    IsDefaultVersion: IsDefaultVersion | None
    TypeTestsStatus: TypeTestsStatus | None
    TypeTestsStatusDescription: TypeTestsStatusDescription | None
    Description: Description | None
    Schema: TypeSchema | None
    ProvisioningType: ProvisioningType | None
    DeprecatedStatus: DeprecatedStatus | None
    LoggingConfig: LoggingConfig | None
    RequiredActivatedTypes: RequiredActivatedTypes | None
    ExecutionRoleArn: RoleArn | None
    Visibility: Visibility | None
    SourceUrl: OptionalSecureUrl | None
    DocumentationUrl: OptionalSecureUrl | None
    LastUpdated: Timestamp | None
    TimeCreated: Timestamp | None
    ConfigurationSchema: ConfigurationSchema | None
    PublisherId: PublisherId | None
    OriginalTypeName: TypeName | None
    OriginalTypeArn: TypeArn | None
    PublicVersionNumber: PublicVersionNumber | None
    LatestPublicVersion: PublicVersionNumber | None
    IsActivated: IsActivated | None
    AutoUpdate: AutoUpdate | None


class DescribeTypeRegistrationInput(ServiceRequest):
    RegistrationToken: RegistrationToken


class DescribeTypeRegistrationOutput(TypedDict, total=False):
    ProgressStatus: RegistrationStatus | None
    Description: Description | None
    TypeArn: TypeArn | None
    TypeVersionArn: TypeArn | None


LogicalResourceIds = list[LogicalResourceId]


class DetectStackDriftInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceIds: LogicalResourceIds | None


class DetectStackDriftOutput(TypedDict, total=False):
    StackDriftDetectionId: StackDriftDetectionId


class DetectStackResourceDriftInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceId: LogicalResourceId


class DetectStackResourceDriftOutput(TypedDict, total=False):
    StackResourceDrift: StackResourceDrift


class DetectStackSetDriftInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    OperationPreferences: StackSetOperationPreferences | None
    OperationId: ClientRequestToken | None
    CallAs: CallAs | None


class DetectStackSetDriftOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


class EstimateTemplateCostInput(ServiceRequest):
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    Parameters: Parameters | None


class EstimateTemplateCostOutput(TypedDict, total=False):
    Url: Url | None


class ExecuteChangeSetInput(ServiceRequest):
    ChangeSetName: ChangeSetNameOrId
    StackName: StackNameOrId | None
    ClientRequestToken: ClientRequestToken | None
    DisableRollback: DisableRollback | None
    RetainExceptOnCreate: RetainExceptOnCreate | None


class ExecuteChangeSetOutput(TypedDict, total=False):
    pass


class ExecuteStackRefactorInput(ServiceRequest):
    StackRefactorId: StackRefactorId


class Export(TypedDict, total=False):
    ExportingStackId: StackId | None
    Name: ExportName | None
    Value: ExportValue | None


Exports = list[Export]


class GetGeneratedTemplateInput(ServiceRequest):
    Format: TemplateFormat | None
    GeneratedTemplateName: GeneratedTemplateName


class GetGeneratedTemplateOutput(TypedDict, total=False):
    Status: GeneratedTemplateStatus | None
    TemplateBody: TemplateBody | None


class GetHookResultInput(ServiceRequest):
    HookResultId: HookInvocationId | None


class HookTarget(TypedDict, total=False):
    TargetType: HookTargetType
    TargetTypeName: HookTargetTypeName
    TargetId: HookTargetId
    Action: HookTargetAction


class GetHookResultOutput(TypedDict, total=False):
    HookResultId: HookInvocationId | None
    InvocationPoint: HookInvocationPoint | None
    FailureMode: HookFailureMode | None
    TypeName: HookTypeName | None
    OriginalTypeName: HookTypeName | None
    TypeVersionId: HookTypeVersionId | None
    TypeConfigurationVersionId: HookTypeConfigurationVersionId | None
    TypeArn: HookTypeArn | None
    Status: HookStatus | None
    HookStatusReason: HookStatusReason | None
    InvokedAt: Timestamp | None
    Target: HookTarget | None
    Annotations: AnnotationList | None


class GetStackPolicyInput(ServiceRequest):
    StackName: StackName


class GetStackPolicyOutput(TypedDict, total=False):
    StackPolicyBody: StackPolicyBody | None


class GetTemplateInput(ServiceRequest):
    StackName: StackName | None
    ChangeSetName: ChangeSetNameOrId | None
    TemplateStage: TemplateStage | None


StageList = list[TemplateStage]


class GetTemplateOutput(TypedDict, total=False):
    TemplateBody: TemplateBody | None
    StagesAvailable: StageList | None


class TemplateSummaryConfig(TypedDict, total=False):
    TreatUnrecognizedResourceTypesAsWarnings: TreatUnrecognizedResourceTypesAsWarnings | None


class GetTemplateSummaryInput(ServiceRequest):
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    StackName: StackNameOrId | None
    StackSetName: StackSetNameOrId | None
    CallAs: CallAs | None
    TemplateSummaryConfig: TemplateSummaryConfig | None


class Warnings(TypedDict, total=False):
    UnrecognizedResourceTypes: ResourceTypes | None


ResourceIdentifiers = list[ResourceIdentifierPropertyKey]


class ResourceIdentifierSummary(TypedDict, total=False):
    ResourceType: ResourceType | None
    LogicalResourceIds: LogicalResourceIds | None
    ResourceIdentifiers: ResourceIdentifiers | None


ResourceIdentifierSummaries = list[ResourceIdentifierSummary]
TransformsList = list[TransformName]


class ParameterConstraints(TypedDict, total=False):
    AllowedValues: AllowedValues | None


class ParameterDeclaration(TypedDict, total=False):
    ParameterKey: ParameterKey | None
    DefaultValue: ParameterValue | None
    ParameterType: ParameterType | None
    NoEcho: NoEcho | None
    Description: Description | None
    ParameterConstraints: ParameterConstraints | None


ParameterDeclarations = list[ParameterDeclaration]


class GetTemplateSummaryOutput(TypedDict, total=False):
    Parameters: ParameterDeclarations | None
    Description: Description | None
    Capabilities: Capabilities | None
    CapabilitiesReason: CapabilitiesReason | None
    ResourceTypes: ResourceTypes | None
    Version: Version | None
    Metadata: Metadata | None
    DeclaredTransforms: TransformsList | None
    ResourceIdentifierSummaries: ResourceIdentifierSummaries | None
    Warnings: Warnings | None


class HookResultSummary(TypedDict, total=False):
    HookResultId: HookInvocationId | None
    InvocationPoint: HookInvocationPoint | None
    FailureMode: HookFailureMode | None
    TypeName: HookTypeName | None
    TypeVersionId: HookTypeVersionId | None
    TypeConfigurationVersionId: HookTypeConfigurationVersionId | None
    Status: HookStatus | None
    HookStatusReason: HookStatusReason | None
    InvokedAt: Timestamp | None
    TargetType: ListHookResultsTargetType | None
    TargetId: HookResultId | None
    TypeArn: HookTypeArn | None
    HookExecutionTarget: HookResultId | None


HookResultSummaries = list[HookResultSummary]
StackIdList = list[StackId]


class ImportStacksToStackSetInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    StackIds: StackIdList | None
    StackIdsUrl: StackIdsUrl | None
    OrganizationalUnitIds: OrganizationalUnitIdList | None
    OperationPreferences: StackSetOperationPreferences | None
    OperationId: ClientRequestToken | None
    CallAs: CallAs | None


class ImportStacksToStackSetOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


Imports = list[StackName]
JazzLogicalResourceIds = list[LogicalResourceId]
JazzResourceIdentifierProperties = dict[
    JazzResourceIdentifierPropertyKey, JazzResourceIdentifierPropertyValue
]


class ListChangeSetsInput(ServiceRequest):
    StackName: StackNameOrId
    NextToken: NextToken | None


class ListChangeSetsOutput(TypedDict, total=False):
    Summaries: ChangeSetSummaries | None
    NextToken: NextToken | None


class ListExportsInput(ServiceRequest):
    NextToken: NextToken | None


class ListExportsOutput(TypedDict, total=False):
    Exports: Exports | None
    NextToken: NextToken | None


class ListGeneratedTemplatesInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class TemplateSummary(TypedDict, total=False):
    GeneratedTemplateId: GeneratedTemplateId | None
    GeneratedTemplateName: GeneratedTemplateName | None
    Status: GeneratedTemplateStatus | None
    StatusReason: TemplateStatusReason | None
    CreationTime: CreationTime | None
    LastUpdatedTime: LastUpdatedTime | None
    NumberOfResources: NumberOfResources | None


TemplateSummaries = list[TemplateSummary]


class ListGeneratedTemplatesOutput(TypedDict, total=False):
    Summaries: TemplateSummaries | None
    NextToken: NextToken | None


class ListHookResultsInput(ServiceRequest):
    TargetType: ListHookResultsTargetType | None
    TargetId: HookResultId | None
    TypeArn: HookTypeArn | None
    Status: HookStatus | None
    NextToken: NextToken | None


class ListHookResultsOutput(TypedDict, total=False):
    TargetType: ListHookResultsTargetType | None
    TargetId: HookResultId | None
    HookResults: HookResultSummaries | None
    NextToken: NextToken | None


class ListImportsInput(ServiceRequest):
    ExportName: ExportName
    NextToken: NextToken | None


class ListImportsOutput(TypedDict, total=False):
    Imports: Imports | None
    NextToken: NextToken | None


class ScannedResourceIdentifier(TypedDict, total=False):
    ResourceType: ResourceType
    ResourceIdentifier: JazzResourceIdentifierProperties


ScannedResourceIdentifiers = list[ScannedResourceIdentifier]


class ListResourceScanRelatedResourcesInput(ServiceRequest):
    ResourceScanId: ResourceScanId
    Resources: ScannedResourceIdentifiers
    NextToken: NextToken | None
    MaxResults: BoxedMaxResults | None


class ScannedResource(TypedDict, total=False):
    ResourceType: ResourceType | None
    ResourceIdentifier: JazzResourceIdentifierProperties | None
    ManagedByStack: ManagedByStack | None


RelatedResources = list[ScannedResource]


class ListResourceScanRelatedResourcesOutput(TypedDict, total=False):
    RelatedResources: RelatedResources | None
    NextToken: NextToken | None


class ListResourceScanResourcesInput(ServiceRequest):
    ResourceScanId: ResourceScanId
    ResourceIdentifier: ResourceIdentifier | None
    ResourceTypePrefix: ResourceTypePrefix | None
    TagKey: TagKey | None
    TagValue: TagValue | None
    NextToken: NextToken | None
    MaxResults: ResourceScannerMaxResults | None


ScannedResources = list[ScannedResource]


class ListResourceScanResourcesOutput(TypedDict, total=False):
    Resources: ScannedResources | None
    NextToken: NextToken | None


class ListResourceScansInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: ResourceScannerMaxResults | None
    ScanTypeFilter: ScanType | None


class ResourceScanSummary(TypedDict, total=False):
    ResourceScanId: ResourceScanId | None
    Status: ResourceScanStatus | None
    StatusReason: ResourceScanStatusReason | None
    StartTime: Timestamp | None
    EndTime: Timestamp | None
    PercentageCompleted: PercentageCompleted | None
    ScanType: ScanType | None


ResourceScanSummaries = list[ResourceScanSummary]


class ListResourceScansOutput(TypedDict, total=False):
    ResourceScanSummaries: ResourceScanSummaries | None
    NextToken: NextToken | None


class ListStackInstanceResourceDriftsInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    StackInstanceResourceDriftStatuses: StackResourceDriftStatusFilters | None
    StackInstanceAccount: Account
    StackInstanceRegion: Region
    OperationId: ClientRequestToken
    CallAs: CallAs | None


class StackInstanceResourceDriftsSummary(TypedDict, total=False):
    StackId: StackId
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: PhysicalResourceId | None
    PhysicalResourceIdContext: PhysicalResourceIdContext | None
    ResourceType: ResourceType
    PropertyDifferences: PropertyDifferences | None
    StackResourceDriftStatus: StackResourceDriftStatus
    Timestamp: Timestamp


StackInstanceResourceDriftsSummaries = list[StackInstanceResourceDriftsSummary]


class ListStackInstanceResourceDriftsOutput(TypedDict, total=False):
    Summaries: StackInstanceResourceDriftsSummaries | None
    NextToken: NextToken | None


class StackInstanceFilter(TypedDict, total=False):
    Name: StackInstanceFilterName | None
    Values: StackInstanceFilterValues | None


StackInstanceFilters = list[StackInstanceFilter]


class ListStackInstancesInput(ServiceRequest):
    StackSetName: StackSetName
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    Filters: StackInstanceFilters | None
    StackInstanceAccount: Account | None
    StackInstanceRegion: Region | None
    CallAs: CallAs | None


class StackInstanceSummary(TypedDict, total=False):
    StackSetId: StackSetId | None
    Region: Region | None
    Account: Account | None
    StackId: StackId | None
    Status: StackInstanceStatus | None
    StatusReason: Reason | None
    StackInstanceStatus: StackInstanceComprehensiveStatus | None
    OrganizationalUnitId: OrganizationalUnitId | None
    DriftStatus: StackDriftStatus | None
    LastDriftCheckTimestamp: Timestamp | None
    LastOperationId: ClientRequestToken | None


StackInstanceSummaries = list[StackInstanceSummary]


class ListStackInstancesOutput(TypedDict, total=False):
    Summaries: StackInstanceSummaries | None
    NextToken: NextToken | None


class ListStackRefactorActionsInput(ServiceRequest):
    StackRefactorId: StackRefactorId
    NextToken: NextToken | None
    MaxResults: MaxResults | None


StackRefactorUntagResources = list[TagKey]
StackRefactorTagResources = list[Tag]


class StackRefactorAction(TypedDict, total=False):
    Action: StackRefactorActionType | None
    Entity: StackRefactorActionEntity | None
    PhysicalResourceId: PhysicalResourceId | None
    ResourceIdentifier: StackRefactorResourceIdentifier | None
    Description: Description | None
    Detection: StackRefactorDetection | None
    DetectionReason: DetectionReason | None
    TagResources: StackRefactorTagResources | None
    UntagResources: StackRefactorUntagResources | None
    ResourceMapping: ResourceMapping | None


StackRefactorActions = list[StackRefactorAction]


class ListStackRefactorActionsOutput(TypedDict, total=False):
    StackRefactorActions: StackRefactorActions
    NextToken: NextToken | None


StackRefactorExecutionStatusFilter = list[StackRefactorExecutionStatus]


class ListStackRefactorsInput(ServiceRequest):
    ExecutionStatusFilter: StackRefactorExecutionStatusFilter | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class StackRefactorSummary(TypedDict, total=False):
    StackRefactorId: StackRefactorId | None
    Description: Description | None
    ExecutionStatus: StackRefactorExecutionStatus | None
    ExecutionStatusReason: ExecutionStatusReason | None
    Status: StackRefactorStatus | None
    StatusReason: StackRefactorStatusReason | None


StackRefactorSummaries = list[StackRefactorSummary]


class ListStackRefactorsOutput(TypedDict, total=False):
    StackRefactorSummaries: StackRefactorSummaries
    NextToken: NextToken | None


class ListStackResourcesInput(ServiceRequest):
    StackName: StackName
    NextToken: NextToken | None


class StackResourceDriftInformationSummary(TypedDict, total=False):
    StackResourceDriftStatus: StackResourceDriftStatus
    LastCheckTimestamp: Timestamp | None


class StackResourceSummary(TypedDict, total=False):
    LogicalResourceId: LogicalResourceId
    PhysicalResourceId: PhysicalResourceId | None
    ResourceType: ResourceType
    LastUpdatedTimestamp: Timestamp
    ResourceStatus: ResourceStatus
    ResourceStatusReason: ResourceStatusReason | None
    DriftInformation: StackResourceDriftInformationSummary | None
    ModuleInfo: ModuleInfo | None


StackResourceSummaries = list[StackResourceSummary]


class ListStackResourcesOutput(TypedDict, total=False):
    StackResourceSummaries: StackResourceSummaries | None
    NextToken: NextToken | None


class ListStackSetAutoDeploymentTargetsInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    CallAs: CallAs | None


class StackSetAutoDeploymentTargetSummary(TypedDict, total=False):
    OrganizationalUnitId: OrganizationalUnitId | None
    Regions: RegionList | None


StackSetAutoDeploymentTargetSummaries = list[StackSetAutoDeploymentTargetSummary]


class ListStackSetAutoDeploymentTargetsOutput(TypedDict, total=False):
    Summaries: StackSetAutoDeploymentTargetSummaries | None
    NextToken: NextToken | None


class OperationResultFilter(TypedDict, total=False):
    Name: OperationResultFilterName | None
    Values: OperationResultFilterValues | None


OperationResultFilters = list[OperationResultFilter]


class ListStackSetOperationResultsInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    CallAs: CallAs | None
    Filters: OperationResultFilters | None


class StackSetOperationResultSummary(TypedDict, total=False):
    Account: Account | None
    Region: Region | None
    Status: StackSetOperationResultStatus | None
    StatusReason: Reason | None
    AccountGateResult: AccountGateResult | None
    OrganizationalUnitId: OrganizationalUnitId | None


StackSetOperationResultSummaries = list[StackSetOperationResultSummary]


class ListStackSetOperationResultsOutput(TypedDict, total=False):
    Summaries: StackSetOperationResultSummaries | None
    NextToken: NextToken | None


class ListStackSetOperationsInput(ServiceRequest):
    StackSetName: StackSetName
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    CallAs: CallAs | None


class StackSetOperationSummary(TypedDict, total=False):
    OperationId: ClientRequestToken | None
    Action: StackSetOperationAction | None
    Status: StackSetOperationStatus | None
    CreationTimestamp: Timestamp | None
    EndTimestamp: Timestamp | None
    StatusReason: StackSetOperationStatusReason | None
    StatusDetails: StackSetOperationStatusDetails | None
    OperationPreferences: StackSetOperationPreferences | None


StackSetOperationSummaries = list[StackSetOperationSummary]


class ListStackSetOperationsOutput(TypedDict, total=False):
    Summaries: StackSetOperationSummaries | None
    NextToken: NextToken | None


class ListStackSetsInput(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    Status: StackSetStatus | None
    CallAs: CallAs | None


class StackSetSummary(TypedDict, total=False):
    StackSetName: StackSetName | None
    StackSetId: StackSetId | None
    Description: Description | None
    Status: StackSetStatus | None
    AutoDeployment: AutoDeployment | None
    PermissionModel: PermissionModels | None
    DriftStatus: StackDriftStatus | None
    LastDriftCheckTimestamp: Timestamp | None
    ManagedExecution: ManagedExecution | None


StackSetSummaries = list[StackSetSummary]


class ListStackSetsOutput(TypedDict, total=False):
    Summaries: StackSetSummaries | None
    NextToken: NextToken | None


StackStatusFilter = list[StackStatus]


class ListStacksInput(ServiceRequest):
    NextToken: NextToken | None
    StackStatusFilter: StackStatusFilter | None


class StackDriftInformationSummary(TypedDict, total=False):
    StackDriftStatus: StackDriftStatus
    LastCheckTimestamp: Timestamp | None


class StackSummary(TypedDict, total=False):
    StackId: StackId | None
    StackName: StackName
    TemplateDescription: TemplateDescription | None
    CreationTime: CreationTime
    LastUpdatedTime: LastUpdatedTime | None
    DeletionTime: DeletionTime | None
    StackStatus: StackStatus
    StackStatusReason: StackStatusReason | None
    ParentId: StackId | None
    RootId: StackId | None
    DriftInformation: StackDriftInformationSummary | None
    LastOperations: LastOperations | None


StackSummaries = list[StackSummary]


class ListStacksOutput(TypedDict, total=False):
    StackSummaries: StackSummaries | None
    NextToken: NextToken | None


class ListTypeRegistrationsInput(ServiceRequest):
    Type: RegistryType | None
    TypeName: TypeName | None
    TypeArn: TypeArn | None
    RegistrationStatusFilter: RegistrationStatus | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


RegistrationTokenList = list[RegistrationToken]


class ListTypeRegistrationsOutput(TypedDict, total=False):
    RegistrationTokenList: RegistrationTokenList | None
    NextToken: NextToken | None


class ListTypeVersionsInput(ServiceRequest):
    Type: RegistryType | None
    TypeName: TypeName | None
    Arn: TypeArn | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    DeprecatedStatus: DeprecatedStatus | None
    PublisherId: PublisherId | None


class TypeVersionSummary(TypedDict, total=False):
    Type: RegistryType | None
    TypeName: TypeName | None
    VersionId: TypeVersionId | None
    IsDefaultVersion: IsDefaultVersion | None
    Arn: TypeArn | None
    TimeCreated: Timestamp | None
    Description: Description | None
    PublicVersionNumber: PublicVersionNumber | None


TypeVersionSummaries = list[TypeVersionSummary]


class ListTypeVersionsOutput(TypedDict, total=False):
    TypeVersionSummaries: TypeVersionSummaries | None
    NextToken: NextToken | None


class TypeFilters(TypedDict, total=False):
    Category: Category | None
    PublisherId: PublisherId | None
    TypeNamePrefix: TypeNamePrefix | None


class ListTypesInput(ServiceRequest):
    Visibility: Visibility | None
    ProvisioningType: ProvisioningType | None
    DeprecatedStatus: DeprecatedStatus | None
    Type: RegistryType | None
    Filters: TypeFilters | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class TypeSummary(TypedDict, total=False):
    Type: RegistryType | None
    TypeName: TypeName | None
    DefaultVersionId: TypeVersionId | None
    TypeArn: TypeArn | None
    LastUpdated: Timestamp | None
    Description: Description | None
    PublisherId: PublisherId | None
    OriginalTypeName: TypeName | None
    PublicVersionNumber: PublicVersionNumber | None
    LatestPublicVersion: PublicVersionNumber | None
    PublisherIdentity: IdentityProvider | None
    PublisherName: PublisherName | None
    IsActivated: IsActivated | None


TypeSummaries = list[TypeSummary]


class ListTypesOutput(TypedDict, total=False):
    TypeSummaries: TypeSummaries | None
    NextToken: NextToken | None


class PublishTypeInput(ServiceRequest):
    Type: ThirdPartyType | None
    Arn: PrivateTypeArn | None
    TypeName: TypeName | None
    PublicVersionNumber: PublicVersionNumber | None


class PublishTypeOutput(TypedDict, total=False):
    PublicTypeArn: TypeArn | None


class RecordHandlerProgressInput(ServiceRequest):
    BearerToken: ClientToken
    OperationStatus: OperationStatus
    CurrentOperationStatus: OperationStatus | None
    StatusMessage: StatusMessage | None
    ErrorCode: HandlerErrorCode | None
    ResourceModel: ResourceModel | None
    ClientRequestToken: ClientRequestToken | None


class RecordHandlerProgressOutput(TypedDict, total=False):
    pass


class RegisterPublisherInput(ServiceRequest):
    AcceptTermsAndConditions: AcceptTermsAndConditions | None
    ConnectionArn: ConnectionArn | None


class RegisterPublisherOutput(TypedDict, total=False):
    PublisherId: PublisherId | None


class RegisterTypeInput(ServiceRequest):
    Type: RegistryType | None
    TypeName: TypeName
    SchemaHandlerPackage: S3Url
    LoggingConfig: LoggingConfig | None
    ExecutionRoleArn: RoleArn | None
    ClientRequestToken: RequestToken | None


class RegisterTypeOutput(TypedDict, total=False):
    RegistrationToken: RegistrationToken | None


class RollbackStackInput(ServiceRequest):
    StackName: StackNameOrId
    RoleARN: RoleARN | None
    ClientRequestToken: ClientRequestToken | None
    RetainExceptOnCreate: RetainExceptOnCreate | None


class RollbackStackOutput(TypedDict, total=False):
    StackId: StackId | None
    OperationId: OperationId | None


class SetStackPolicyInput(ServiceRequest):
    StackName: StackName
    StackPolicyBody: StackPolicyBody | None
    StackPolicyURL: StackPolicyURL | None


class SetTypeConfigurationInput(ServiceRequest):
    TypeArn: TypeArn | None
    Configuration: TypeConfiguration
    ConfigurationAlias: TypeConfigurationAlias | None
    TypeName: TypeName | None
    Type: ThirdPartyType | None


class SetTypeConfigurationOutput(TypedDict, total=False):
    ConfigurationArn: TypeConfigurationArn | None


class SetTypeDefaultVersionInput(ServiceRequest):
    Arn: PrivateTypeArn | None
    Type: RegistryType | None
    TypeName: TypeName | None
    VersionId: TypeVersionId | None


class SetTypeDefaultVersionOutput(TypedDict, total=False):
    pass


class SignalResourceInput(ServiceRequest):
    StackName: StackNameOrId
    LogicalResourceId: LogicalResourceId
    UniqueId: ResourceSignalUniqueId
    Status: ResourceSignalStatus


class StartResourceScanInput(ServiceRequest):
    ClientRequestToken: ClientRequestToken | None
    ScanFilters: ScanFilters | None


class StartResourceScanOutput(TypedDict, total=False):
    ResourceScanId: ResourceScanId | None


class StopStackSetOperationInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    CallAs: CallAs | None


class StopStackSetOperationOutput(TypedDict, total=False):
    pass


class TemplateParameter(TypedDict, total=False):
    ParameterKey: ParameterKey | None
    DefaultValue: ParameterValue | None
    NoEcho: NoEcho | None
    Description: Description | None


TemplateParameters = list[TemplateParameter]


class TestTypeInput(ServiceRequest):
    Arn: TypeArn | None
    Type: ThirdPartyType | None
    TypeName: TypeName | None
    VersionId: TypeVersionId | None
    LogDeliveryBucket: S3Bucket | None


class TestTypeOutput(TypedDict, total=False):
    TypeVersionArn: TypeArn | None


class UpdateGeneratedTemplateInput(ServiceRequest):
    GeneratedTemplateName: GeneratedTemplateName
    NewGeneratedTemplateName: GeneratedTemplateName | None
    AddResources: ResourceDefinitions | None
    RemoveResources: JazzLogicalResourceIds | None
    RefreshAllResources: RefreshAllResources | None
    TemplateConfiguration: TemplateConfiguration | None


class UpdateGeneratedTemplateOutput(TypedDict, total=False):
    GeneratedTemplateId: GeneratedTemplateId | None


class UpdateStackInput(ServiceRequest):
    StackName: StackName
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    UsePreviousTemplate: UsePreviousTemplate | None
    StackPolicyDuringUpdateBody: StackPolicyDuringUpdateBody | None
    StackPolicyDuringUpdateURL: StackPolicyDuringUpdateURL | None
    Parameters: Parameters | None
    Capabilities: Capabilities | None
    ResourceTypes: ResourceTypes | None
    RoleARN: RoleARN | None
    RollbackConfiguration: RollbackConfiguration | None
    StackPolicyBody: StackPolicyBody | None
    StackPolicyURL: StackPolicyURL | None
    NotificationARNs: NotificationARNs | None
    Tags: Tags | None
    DisableRollback: DisableRollback | None
    ClientRequestToken: ClientRequestToken | None
    RetainExceptOnCreate: RetainExceptOnCreate | None


class UpdateStackInstancesInput(ServiceRequest):
    StackSetName: StackSetNameOrId
    Accounts: AccountList | None
    DeploymentTargets: DeploymentTargets | None
    Regions: RegionList
    ParameterOverrides: Parameters | None
    OperationPreferences: StackSetOperationPreferences | None
    OperationId: ClientRequestToken | None
    CallAs: CallAs | None


class UpdateStackInstancesOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


class UpdateStackOutput(TypedDict, total=False):
    StackId: StackId | None
    OperationId: OperationId | None


class UpdateStackSetInput(ServiceRequest):
    StackSetName: StackSetName
    Description: Description | None
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None
    UsePreviousTemplate: UsePreviousTemplate | None
    Parameters: Parameters | None
    Capabilities: Capabilities | None
    Tags: Tags | None
    OperationPreferences: StackSetOperationPreferences | None
    AdministrationRoleARN: RoleARN | None
    ExecutionRoleName: ExecutionRoleName | None
    DeploymentTargets: DeploymentTargets | None
    PermissionModel: PermissionModels | None
    AutoDeployment: AutoDeployment | None
    OperationId: ClientRequestToken | None
    Accounts: AccountList | None
    Regions: RegionList | None
    CallAs: CallAs | None
    ManagedExecution: ManagedExecution | None


class UpdateStackSetOutput(TypedDict, total=False):
    OperationId: ClientRequestToken | None


class UpdateTerminationProtectionInput(ServiceRequest):
    EnableTerminationProtection: EnableTerminationProtection
    StackName: StackNameOrId


class UpdateTerminationProtectionOutput(TypedDict, total=False):
    StackId: StackId | None


class ValidateTemplateInput(ServiceRequest):
    TemplateBody: TemplateBody | None
    TemplateURL: TemplateURL | None


class ValidateTemplateOutput(TypedDict, total=False):
    Parameters: TemplateParameters | None
    Description: Description | None
    Capabilities: Capabilities | None
    CapabilitiesReason: CapabilitiesReason | None
    DeclaredTransforms: TransformsList | None


class CloudformationApi:
    service: str = "cloudformation"
    version: str = "2010-05-15"

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
        deployment_mode: DeploymentMode | None = None,
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

    @handler("DescribeEvents")
    def describe_events(
        self,
        context: RequestContext,
        stack_name: StackNameOrId | None = None,
        change_set_name: ChangeSetNameOrId | None = None,
        operation_id: OperationId | None = None,
        filters: EventFilter | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeEventsOutput:
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
        stack_name: StackName,
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

    @handler("GetHookResult")
    def get_hook_result(
        self, context: RequestContext, hook_result_id: HookInvocationId | None = None, **kwargs
    ) -> GetHookResultOutput:
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
        target_type: ListHookResultsTargetType | None = None,
        target_id: HookResultId | None = None,
        type_arn: HookTypeArn | None = None,
        status: HookStatus | None = None,
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
