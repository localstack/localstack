import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AcceptTermsAndConditions = bool
Account = str
AccountGateStatusReason = str
AccountsUrl = str
AllowedValue = str
Arn = str
AutoDeploymentNullable = bool
AutoUpdate = bool
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
DisableRollback = bool
DriftedStackInstancesCount = int
EnableTerminationProtection = bool
ErrorCode = str
ErrorMessage = str
EventId = str
ExecutionRoleName = str
ExportName = str
ExportValue = str
FailedStackInstancesCount = int
FailureToleranceCount = int
FailureTolerancePercentage = int
HookInvocationCount = int
HookStatusReason = str
HookTargetTypeName = str
HookType = str
HookTypeConfigurationVersionId = str
HookTypeName = str
HookTypeVersionId = str
InProgressStackInstancesCount = int
InSyncStackInstancesCount = int
IncludeNestedStacks = bool
IsActivated = bool
IsDefaultConfiguration = bool
IsDefaultVersion = bool
Key = str
LimitName = str
LimitValue = int
LogGroupName = str
LogicalIdHierarchy = str
LogicalResourceId = str
ManagedExecutionNullable = bool
MaxConcurrentCount = int
MaxConcurrentPercentage = int
MaxResults = int
Metadata = str
MonitoringTimeInMinutes = int
NextToken = str
NoEcho = bool
NotificationARN = str
OptionalSecureUrl = str
OrganizationalUnitId = str
OutputKey = str
OutputValue = str
ParameterKey = str
ParameterType = str
ParameterValue = str
PhysicalResourceId = str
PrivateTypeArn = str
Properties = str
PropertyName = str
PropertyPath = str
PropertyValue = str
PublicVersionNumber = str
PublisherId = str
PublisherName = str
PublisherProfile = str
Reason = str
Region = str
RegistrationToken = str
RequestToken = str
ResourceIdentifierPropertyKey = str
ResourceIdentifierPropertyValue = str
ResourceModel = str
ResourceProperties = str
ResourceSignalUniqueId = str
ResourceStatusReason = str
ResourceToSkip = str
ResourceType = str
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
StackSetARN = str
StackSetId = str
StackSetName = str
StackSetNameOrId = str
StackStatusReason = str
StatusMessage = str
SupportedMajorVersion = int
TagKey = str
TagValue = str
TemplateBody = str
TemplateDescription = str
TemplateURL = str
ThirdPartyTypeArn = str
TimeoutMinutes = int
TotalStackInstancesCount = int
TransformName = str
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


class AccountGateStatus(str):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class CallAs(str):
    SELF = "SELF"
    DELEGATED_ADMIN = "DELEGATED_ADMIN"


class Capability(str):
    CAPABILITY_IAM = "CAPABILITY_IAM"
    CAPABILITY_NAMED_IAM = "CAPABILITY_NAMED_IAM"
    CAPABILITY_AUTO_EXPAND = "CAPABILITY_AUTO_EXPAND"


class Category(str):
    REGISTERED = "REGISTERED"
    ACTIVATED = "ACTIVATED"
    THIRD_PARTY = "THIRD_PARTY"
    AWS_TYPES = "AWS_TYPES"


class ChangeAction(str):
    Add = "Add"
    Modify = "Modify"
    Remove = "Remove"
    Import = "Import"
    Dynamic = "Dynamic"


class ChangeSetHooksStatus(str):
    PLANNING = "PLANNING"
    PLANNED = "PLANNED"
    UNAVAILABLE = "UNAVAILABLE"


class ChangeSetStatus(str):
    CREATE_PENDING = "CREATE_PENDING"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    DELETE_PENDING = "DELETE_PENDING"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    DELETE_FAILED = "DELETE_FAILED"
    FAILED = "FAILED"


class ChangeSetType(str):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    IMPORT = "IMPORT"


class ChangeSource(str):
    ResourceReference = "ResourceReference"
    ParameterReference = "ParameterReference"
    ResourceAttribute = "ResourceAttribute"
    DirectModification = "DirectModification"
    Automatic = "Automatic"


class ChangeType(str):
    Resource = "Resource"


class DeprecatedStatus(str):
    LIVE = "LIVE"
    DEPRECATED = "DEPRECATED"


class DifferenceType(str):
    ADD = "ADD"
    REMOVE = "REMOVE"
    NOT_EQUAL = "NOT_EQUAL"


class EvaluationType(str):
    Static = "Static"
    Dynamic = "Dynamic"


class ExecutionStatus(str):
    UNAVAILABLE = "UNAVAILABLE"
    AVAILABLE = "AVAILABLE"
    EXECUTE_IN_PROGRESS = "EXECUTE_IN_PROGRESS"
    EXECUTE_COMPLETE = "EXECUTE_COMPLETE"
    EXECUTE_FAILED = "EXECUTE_FAILED"
    OBSOLETE = "OBSOLETE"


class HandlerErrorCode(str):
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


class HookFailureMode(str):
    FAIL = "FAIL"
    WARN = "WARN"


class HookInvocationPoint(str):
    PRE_PROVISION = "PRE_PROVISION"


class HookStatus(str):
    HOOK_IN_PROGRESS = "HOOK_IN_PROGRESS"
    HOOK_COMPLETE_SUCCEEDED = "HOOK_COMPLETE_SUCCEEDED"
    HOOK_COMPLETE_FAILED = "HOOK_COMPLETE_FAILED"
    HOOK_FAILED = "HOOK_FAILED"


class HookTargetType(str):
    RESOURCE = "RESOURCE"


class IdentityProvider(str):
    AWS_Marketplace = "AWS_Marketplace"
    GitHub = "GitHub"
    Bitbucket = "Bitbucket"


class OnFailure(str):
    DO_NOTHING = "DO_NOTHING"
    ROLLBACK = "ROLLBACK"
    DELETE = "DELETE"


class OperationStatus(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class PermissionModels(str):
    SERVICE_MANAGED = "SERVICE_MANAGED"
    SELF_MANAGED = "SELF_MANAGED"


class ProvisioningType(str):
    NON_PROVISIONABLE = "NON_PROVISIONABLE"
    IMMUTABLE = "IMMUTABLE"
    FULLY_MUTABLE = "FULLY_MUTABLE"


class PublisherStatus(str):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


class RegionConcurrencyType(str):
    SEQUENTIAL = "SEQUENTIAL"
    PARALLEL = "PARALLEL"


class RegistrationStatus(str):
    COMPLETE = "COMPLETE"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"


class RegistryType(str):
    RESOURCE = "RESOURCE"
    MODULE = "MODULE"
    HOOK = "HOOK"


class Replacement(str):
    True_ = "True"
    False_ = "False"
    Conditional = "Conditional"


class RequiresRecreation(str):
    Never = "Never"
    Conditionally = "Conditionally"
    Always = "Always"


class ResourceAttribute(str):
    Properties = "Properties"
    Metadata = "Metadata"
    CreationPolicy = "CreationPolicy"
    UpdatePolicy = "UpdatePolicy"
    DeletionPolicy = "DeletionPolicy"
    Tags = "Tags"


class ResourceSignalStatus(str):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class ResourceStatus(str):
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
    UPDATE_ROLLBACK_IN_PROGRESS = "UPDATE_ROLLBACK_IN_PROGRESS"
    UPDATE_ROLLBACK_COMPLETE = "UPDATE_ROLLBACK_COMPLETE"
    UPDATE_ROLLBACK_FAILED = "UPDATE_ROLLBACK_FAILED"
    ROLLBACK_IN_PROGRESS = "ROLLBACK_IN_PROGRESS"
    ROLLBACK_COMPLETE = "ROLLBACK_COMPLETE"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class StackDriftDetectionStatus(str):
    DETECTION_IN_PROGRESS = "DETECTION_IN_PROGRESS"
    DETECTION_FAILED = "DETECTION_FAILED"
    DETECTION_COMPLETE = "DETECTION_COMPLETE"


class StackDriftStatus(str):
    DRIFTED = "DRIFTED"
    IN_SYNC = "IN_SYNC"
    UNKNOWN = "UNKNOWN"
    NOT_CHECKED = "NOT_CHECKED"


class StackInstanceDetailedStatus(str):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INOPERABLE = "INOPERABLE"


class StackInstanceFilterName(str):
    DETAILED_STATUS = "DETAILED_STATUS"


class StackInstanceStatus(str):
    CURRENT = "CURRENT"
    OUTDATED = "OUTDATED"
    INOPERABLE = "INOPERABLE"


class StackResourceDriftStatus(str):
    IN_SYNC = "IN_SYNC"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    NOT_CHECKED = "NOT_CHECKED"


class StackSetDriftDetectionStatus(str):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    IN_PROGRESS = "IN_PROGRESS"
    STOPPED = "STOPPED"


class StackSetDriftStatus(str):
    DRIFTED = "DRIFTED"
    IN_SYNC = "IN_SYNC"
    NOT_CHECKED = "NOT_CHECKED"


class StackSetOperationAction(str):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    DETECT_DRIFT = "DETECT_DRIFT"


class StackSetOperationResultStatus(str):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StackSetOperationStatus(str):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    QUEUED = "QUEUED"


class StackSetStatus(str):
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"


class StackStatus(str):
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


class TemplateStage(str):
    Original = "Original"
    Processed = "Processed"


class ThirdPartyType(str):
    RESOURCE = "RESOURCE"
    MODULE = "MODULE"
    HOOK = "HOOK"


class TypeTestsStatus(str):
    PASSED = "PASSED"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    NOT_TESTED = "NOT_TESTED"


class VersionBump(str):
    MAJOR = "MAJOR"
    MINOR = "MINOR"


class Visibility(str):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"


class AlreadyExistsException(ServiceException):
    pass


class CFNRegistryException(ServiceException):
    Message: Optional[ErrorMessage]


class ChangeSetNotFoundException(ServiceException):
    pass


class CreatedButModifiedException(ServiceException):
    pass


class InsufficientCapabilitiesException(ServiceException):
    pass


class InvalidChangeSetStatusException(ServiceException):
    pass


class InvalidOperationException(ServiceException):
    pass


class InvalidStateTransitionException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class NameAlreadyExistsException(ServiceException):
    pass


class OperationIdAlreadyExistsException(ServiceException):
    pass


class OperationInProgressException(ServiceException):
    pass


class OperationNotFoundException(ServiceException):
    pass


class OperationStatusCheckFailedException(ServiceException):
    pass


class StackInstanceNotFoundException(ServiceException):
    pass


class StackNotFoundException(ServiceException):
    pass


class StackSetNotEmptyException(ServiceException):
    pass


class StackSetNotFoundException(ServiceException):
    pass


class StaleRequestException(ServiceException):
    pass


class TokenAlreadyExistsException(ServiceException):
    pass


class TypeConfigurationNotFoundException(ServiceException):
    pass


class TypeNotFoundException(ServiceException):
    pass


class AccountGateResult(TypedDict, total=False):
    Status: Optional[AccountGateStatus]
    StatusReason: Optional[AccountGateStatusReason]


class AccountLimit(TypedDict, total=False):
    Name: Optional[LimitName]
    Value: Optional[LimitValue]


AccountLimitList = List[AccountLimit]
AccountList = List[Account]
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


class ResourceChangeDetail(TypedDict, total=False):
    Target: Optional[ResourceTargetDefinition]
    Evaluation: Optional[EvaluationType]
    ChangeSource: Optional[ChangeSource]
    CausingEntity: Optional[CausingEntity]


ResourceChangeDetails = List[ResourceChangeDetail]
Scope = List[ResourceAttribute]


class ResourceChange(TypedDict, total=False):
    Action: Optional[ChangeAction]
    LogicalResourceId: Optional[LogicalResourceId]
    PhysicalResourceId: Optional[PhysicalResourceId]
    ResourceType: Optional[ResourceType]
    Replacement: Optional[Replacement]
    Scope: Optional[Scope]
    Details: Optional[ResourceChangeDetails]
    ChangeSetId: Optional[ChangeSetId]
    ModuleInfo: Optional[ModuleInfo]


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


class CreateChangeSetOutput(TypedDict, total=False):
    Id: Optional[ChangeSetId]
    StackId: Optional[StackId]


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


RegionList = List[Region]


class StackSetOperationPreferences(TypedDict, total=False):
    RegionConcurrencyType: Optional[RegionConcurrencyType]
    RegionOrder: Optional[RegionList]
    FailureToleranceCount: Optional[FailureToleranceCount]
    FailureTolerancePercentage: Optional[FailureTolerancePercentage]
    MaxConcurrentCount: Optional[MaxConcurrentCount]
    MaxConcurrentPercentage: Optional[MaxConcurrentPercentage]


OrganizationalUnitIdList = List[OrganizationalUnitId]


class DeploymentTargets(TypedDict, total=False):
    Accounts: Optional[AccountList]
    AccountsUrl: Optional[AccountsUrl]
    OrganizationalUnitIds: Optional[OrganizationalUnitIdList]


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


RetainResources = List[LogicalResourceId]


class DeleteStackInput(ServiceRequest):
    StackName: StackName
    RetainResources: Optional[RetainResources]
    RoleARN: Optional[RoleARN]
    ClientRequestToken: Optional[ClientRequestToken]


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


class DescribePublisherInput(ServiceRequest):
    PublisherId: Optional[PublisherId]


class DescribePublisherOutput(TypedDict, total=False):
    PublisherId: Optional[PublisherId]
    PublisherStatus: Optional[PublisherStatus]
    IdentityProvider: Optional[IdentityProvider]
    PublisherProfile: Optional[PublisherProfile]


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


class DescribeStackInstanceOutput(TypedDict, total=False):
    StackInstance: Optional[StackInstance]


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
LastUpdatedTime = datetime


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


class ExecuteChangeSetOutput(TypedDict, total=False):
    pass


class Export(TypedDict, total=False):
    ExportingStackId: Optional[StackId]
    Name: Optional[ExportName]
    Value: Optional[ExportValue]


Exports = List[Export]


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


class GetTemplateSummaryInput(ServiceRequest):
    TemplateBody: Optional[TemplateBody]
    TemplateURL: Optional[TemplateURL]
    StackName: Optional[StackNameOrId]
    StackSetName: Optional[StackSetNameOrId]
    CallAs: Optional[CallAs]


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


class ListImportsInput(ServiceRequest):
    ExportName: ExportName
    NextToken: Optional[NextToken]


class ListImportsOutput(TypedDict, total=False):
    Imports: Optional[Imports]
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


StackInstanceSummaries = List[StackInstanceSummary]


class ListStackInstancesOutput(TypedDict, total=False):
    Summaries: Optional[StackInstanceSummaries]
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


class ListStackSetOperationResultsInput(ServiceRequest):
    StackSetName: StackSetName
    OperationId: ClientRequestToken
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CallAs: Optional[CallAs]


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

    @handler("ActivateType", expand=False)
    def activate_type(
        self, context: RequestContext, request: ActivateTypeInput
    ) -> ActivateTypeOutput:
        raise NotImplementedError

    @handler("BatchDescribeTypeConfigurations")
    def batch_describe_type_configurations(
        self, context: RequestContext, type_configuration_identifiers: TypeConfigurationIdentifiers
    ) -> BatchDescribeTypeConfigurationsOutput:
        raise NotImplementedError

    @handler("CancelUpdateStack")
    def cancel_update_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        client_request_token: ClientRequestToken = None,
    ) -> None:
        raise NotImplementedError

    @handler("ContinueUpdateRollback")
    def continue_update_rollback(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        role_arn: RoleARN = None,
        resources_to_skip: ResourcesToSkip = None,
        client_request_token: ClientRequestToken = None,
    ) -> ContinueUpdateRollbackOutput:
        raise NotImplementedError

    @handler("CreateChangeSet")
    def create_change_set(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        change_set_name: ChangeSetName,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        use_previous_template: UsePreviousTemplate = None,
        parameters: Parameters = None,
        capabilities: Capabilities = None,
        resource_types: ResourceTypes = None,
        role_arn: RoleARN = None,
        rollback_configuration: RollbackConfiguration = None,
        notification_arns: NotificationARNs = None,
        tags: Tags = None,
        client_token: ClientToken = None,
        description: Description = None,
        change_set_type: ChangeSetType = None,
        resources_to_import: ResourcesToImport = None,
        include_nested_stacks: IncludeNestedStacks = None,
    ) -> CreateChangeSetOutput:
        raise NotImplementedError

    @handler("CreateStack")
    def create_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        parameters: Parameters = None,
        disable_rollback: DisableRollback = None,
        rollback_configuration: RollbackConfiguration = None,
        timeout_in_minutes: TimeoutMinutes = None,
        notification_arns: NotificationARNs = None,
        capabilities: Capabilities = None,
        resource_types: ResourceTypes = None,
        role_arn: RoleARN = None,
        on_failure: OnFailure = None,
        stack_policy_body: StackPolicyBody = None,
        stack_policy_url: StackPolicyURL = None,
        tags: Tags = None,
        client_request_token: ClientRequestToken = None,
        enable_termination_protection: EnableTerminationProtection = None,
    ) -> CreateStackOutput:
        raise NotImplementedError

    @handler("CreateStackInstances")
    def create_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        regions: RegionList,
        accounts: AccountList = None,
        deployment_targets: DeploymentTargets = None,
        parameter_overrides: Parameters = None,
        operation_preferences: StackSetOperationPreferences = None,
        operation_id: ClientRequestToken = None,
        call_as: CallAs = None,
    ) -> CreateStackInstancesOutput:
        raise NotImplementedError

    @handler("CreateStackSet")
    def create_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        description: Description = None,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        stack_id: StackId = None,
        parameters: Parameters = None,
        capabilities: Capabilities = None,
        tags: Tags = None,
        administration_role_arn: RoleARN = None,
        execution_role_name: ExecutionRoleName = None,
        permission_model: PermissionModels = None,
        auto_deployment: AutoDeployment = None,
        call_as: CallAs = None,
        client_request_token: ClientRequestToken = None,
        managed_execution: ManagedExecution = None,
    ) -> CreateStackSetOutput:
        raise NotImplementedError

    @handler("DeactivateType", expand=False)
    def deactivate_type(
        self, context: RequestContext, request: DeactivateTypeInput
    ) -> DeactivateTypeOutput:
        raise NotImplementedError

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
    ) -> DeleteChangeSetOutput:
        raise NotImplementedError

    @handler("DeleteStack")
    def delete_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        retain_resources: RetainResources = None,
        role_arn: RoleARN = None,
        client_request_token: ClientRequestToken = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStackInstances")
    def delete_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        regions: RegionList,
        retain_stacks: RetainStacks,
        accounts: AccountList = None,
        deployment_targets: DeploymentTargets = None,
        operation_preferences: StackSetOperationPreferences = None,
        operation_id: ClientRequestToken = None,
        call_as: CallAs = None,
    ) -> DeleteStackInstancesOutput:
        raise NotImplementedError

    @handler("DeleteStackSet")
    def delete_stack_set(
        self, context: RequestContext, stack_set_name: StackSetName, call_as: CallAs = None
    ) -> DeleteStackSetOutput:
        raise NotImplementedError

    @handler("DeregisterType", expand=False)
    def deregister_type(
        self, context: RequestContext, request: DeregisterTypeInput
    ) -> DeregisterTypeOutput:
        raise NotImplementedError

    @handler("DescribeAccountLimits")
    def describe_account_limits(
        self, context: RequestContext, next_token: NextToken = None
    ) -> DescribeAccountLimitsOutput:
        raise NotImplementedError

    @handler("DescribeChangeSet")
    def describe_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        next_token: NextToken = None,
    ) -> DescribeChangeSetOutput:
        raise NotImplementedError

    @handler("DescribeChangeSetHooks")
    def describe_change_set_hooks(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        next_token: NextToken = None,
        logical_resource_id: LogicalResourceId = None,
    ) -> DescribeChangeSetHooksOutput:
        raise NotImplementedError

    @handler("DescribePublisher")
    def describe_publisher(
        self, context: RequestContext, publisher_id: PublisherId = None
    ) -> DescribePublisherOutput:
        raise NotImplementedError

    @handler("DescribeStackDriftDetectionStatus")
    def describe_stack_drift_detection_status(
        self, context: RequestContext, stack_drift_detection_id: StackDriftDetectionId
    ) -> DescribeStackDriftDetectionStatusOutput:
        raise NotImplementedError

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self, context: RequestContext, stack_name: StackName = None, next_token: NextToken = None
    ) -> DescribeStackEventsOutput:
        raise NotImplementedError

    @handler("DescribeStackInstance")
    def describe_stack_instance(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        stack_instance_account: Account,
        stack_instance_region: Region,
        call_as: CallAs = None,
    ) -> DescribeStackInstanceOutput:
        raise NotImplementedError

    @handler("DescribeStackResource")
    def describe_stack_resource(
        self, context: RequestContext, stack_name: StackName, logical_resource_id: LogicalResourceId
    ) -> DescribeStackResourceOutput:
        raise NotImplementedError

    @handler("DescribeStackResourceDrifts")
    def describe_stack_resource_drifts(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        stack_resource_drift_status_filters: StackResourceDriftStatusFilters = None,
        next_token: NextToken = None,
        max_results: BoxedMaxResults = None,
    ) -> DescribeStackResourceDriftsOutput:
        raise NotImplementedError

    @handler("DescribeStackResources")
    def describe_stack_resources(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        logical_resource_id: LogicalResourceId = None,
        physical_resource_id: PhysicalResourceId = None,
    ) -> DescribeStackResourcesOutput:
        raise NotImplementedError

    @handler("DescribeStackSet")
    def describe_stack_set(
        self, context: RequestContext, stack_set_name: StackSetName, call_as: CallAs = None
    ) -> DescribeStackSetOutput:
        raise NotImplementedError

    @handler("DescribeStackSetOperation")
    def describe_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs = None,
    ) -> DescribeStackSetOperationOutput:
        raise NotImplementedError

    @handler("DescribeStacks")
    def describe_stacks(
        self, context: RequestContext, stack_name: StackName = None, next_token: NextToken = None
    ) -> DescribeStacksOutput:
        raise NotImplementedError

    @handler("DescribeType", expand=False)
    def describe_type(
        self, context: RequestContext, request: DescribeTypeInput
    ) -> DescribeTypeOutput:
        raise NotImplementedError

    @handler("DescribeTypeRegistration")
    def describe_type_registration(
        self, context: RequestContext, registration_token: RegistrationToken
    ) -> DescribeTypeRegistrationOutput:
        raise NotImplementedError

    @handler("DetectStackDrift")
    def detect_stack_drift(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        logical_resource_ids: LogicalResourceIds = None,
    ) -> DetectStackDriftOutput:
        raise NotImplementedError

    @handler("DetectStackResourceDrift")
    def detect_stack_resource_drift(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        logical_resource_id: LogicalResourceId,
    ) -> DetectStackResourceDriftOutput:
        raise NotImplementedError

    @handler("DetectStackSetDrift")
    def detect_stack_set_drift(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        operation_preferences: StackSetOperationPreferences = None,
        operation_id: ClientRequestToken = None,
        call_as: CallAs = None,
    ) -> DetectStackSetDriftOutput:
        raise NotImplementedError

    @handler("EstimateTemplateCost")
    def estimate_template_cost(
        self,
        context: RequestContext,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        parameters: Parameters = None,
    ) -> EstimateTemplateCostOutput:
        raise NotImplementedError

    @handler("ExecuteChangeSet")
    def execute_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        client_request_token: ClientRequestToken = None,
        disable_rollback: DisableRollback = None,
    ) -> ExecuteChangeSetOutput:
        raise NotImplementedError

    @handler("GetStackPolicy")
    def get_stack_policy(
        self, context: RequestContext, stack_name: StackName
    ) -> GetStackPolicyOutput:
        raise NotImplementedError

    @handler("GetTemplate")
    def get_template(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        change_set_name: ChangeSetNameOrId = None,
        template_stage: TemplateStage = None,
    ) -> GetTemplateOutput:
        raise NotImplementedError

    @handler("GetTemplateSummary")
    def get_template_summary(
        self,
        context: RequestContext,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        stack_name: StackNameOrId = None,
        stack_set_name: StackSetNameOrId = None,
        call_as: CallAs = None,
    ) -> GetTemplateSummaryOutput:
        raise NotImplementedError

    @handler("ImportStacksToStackSet")
    def import_stacks_to_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        stack_ids: StackIdList = None,
        stack_ids_url: StackIdsUrl = None,
        organizational_unit_ids: OrganizationalUnitIdList = None,
        operation_preferences: StackSetOperationPreferences = None,
        operation_id: ClientRequestToken = None,
        call_as: CallAs = None,
    ) -> ImportStacksToStackSetOutput:
        raise NotImplementedError

    @handler("ListChangeSets")
    def list_change_sets(
        self, context: RequestContext, stack_name: StackNameOrId, next_token: NextToken = None
    ) -> ListChangeSetsOutput:
        raise NotImplementedError

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken = None
    ) -> ListExportsOutput:
        raise NotImplementedError

    @handler("ListImports")
    def list_imports(
        self, context: RequestContext, export_name: ExportName, next_token: NextToken = None
    ) -> ListImportsOutput:
        raise NotImplementedError

    @handler("ListStackInstances")
    def list_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filters: StackInstanceFilters = None,
        stack_instance_account: Account = None,
        stack_instance_region: Region = None,
        call_as: CallAs = None,
    ) -> ListStackInstancesOutput:
        raise NotImplementedError

    @handler("ListStackResources")
    def list_stack_resources(
        self, context: RequestContext, stack_name: StackName, next_token: NextToken = None
    ) -> ListStackResourcesOutput:
        raise NotImplementedError

    @handler("ListStackSetOperationResults")
    def list_stack_set_operation_results(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        call_as: CallAs = None,
    ) -> ListStackSetOperationResultsOutput:
        raise NotImplementedError

    @handler("ListStackSetOperations")
    def list_stack_set_operations(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        call_as: CallAs = None,
    ) -> ListStackSetOperationsOutput:
        raise NotImplementedError

    @handler("ListStackSets")
    def list_stack_sets(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        status: StackSetStatus = None,
        call_as: CallAs = None,
    ) -> ListStackSetsOutput:
        raise NotImplementedError

    @handler("ListStacks")
    def list_stacks(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        stack_status_filter: StackStatusFilter = None,
    ) -> ListStacksOutput:
        raise NotImplementedError

    @handler("ListTypeRegistrations", expand=False)
    def list_type_registrations(
        self, context: RequestContext, request: ListTypeRegistrationsInput
    ) -> ListTypeRegistrationsOutput:
        raise NotImplementedError

    @handler("ListTypeVersions", expand=False)
    def list_type_versions(
        self, context: RequestContext, request: ListTypeVersionsInput
    ) -> ListTypeVersionsOutput:
        raise NotImplementedError

    @handler("ListTypes", expand=False)
    def list_types(self, context: RequestContext, request: ListTypesInput) -> ListTypesOutput:
        raise NotImplementedError

    @handler("PublishType", expand=False)
    def publish_type(self, context: RequestContext, request: PublishTypeInput) -> PublishTypeOutput:
        raise NotImplementedError

    @handler("RecordHandlerProgress")
    def record_handler_progress(
        self,
        context: RequestContext,
        bearer_token: ClientToken,
        operation_status: OperationStatus,
        current_operation_status: OperationStatus = None,
        status_message: StatusMessage = None,
        error_code: HandlerErrorCode = None,
        resource_model: ResourceModel = None,
        client_request_token: ClientRequestToken = None,
    ) -> RecordHandlerProgressOutput:
        raise NotImplementedError

    @handler("RegisterPublisher")
    def register_publisher(
        self,
        context: RequestContext,
        accept_terms_and_conditions: AcceptTermsAndConditions = None,
        connection_arn: ConnectionArn = None,
    ) -> RegisterPublisherOutput:
        raise NotImplementedError

    @handler("RegisterType", expand=False)
    def register_type(
        self, context: RequestContext, request: RegisterTypeInput
    ) -> RegisterTypeOutput:
        raise NotImplementedError

    @handler("RollbackStack")
    def rollback_stack(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        role_arn: RoleARN = None,
        client_request_token: ClientRequestToken = None,
    ) -> RollbackStackOutput:
        raise NotImplementedError

    @handler("SetStackPolicy")
    def set_stack_policy(
        self,
        context: RequestContext,
        stack_name: StackName,
        stack_policy_body: StackPolicyBody = None,
        stack_policy_url: StackPolicyURL = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetTypeConfiguration", expand=False)
    def set_type_configuration(
        self, context: RequestContext, request: SetTypeConfigurationInput
    ) -> SetTypeConfigurationOutput:
        raise NotImplementedError

    @handler("SetTypeDefaultVersion", expand=False)
    def set_type_default_version(
        self, context: RequestContext, request: SetTypeDefaultVersionInput
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
    ) -> None:
        raise NotImplementedError

    @handler("StopStackSetOperation")
    def stop_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs = None,
    ) -> StopStackSetOperationOutput:
        raise NotImplementedError

    @handler("TestType", expand=False)
    def test_type(self, context: RequestContext, request: TestTypeInput) -> TestTypeOutput:
        raise NotImplementedError

    @handler("UpdateStack")
    def update_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        use_previous_template: UsePreviousTemplate = None,
        stack_policy_during_update_body: StackPolicyDuringUpdateBody = None,
        stack_policy_during_update_url: StackPolicyDuringUpdateURL = None,
        parameters: Parameters = None,
        capabilities: Capabilities = None,
        resource_types: ResourceTypes = None,
        role_arn: RoleARN = None,
        rollback_configuration: RollbackConfiguration = None,
        stack_policy_body: StackPolicyBody = None,
        stack_policy_url: StackPolicyURL = None,
        notification_arns: NotificationARNs = None,
        tags: Tags = None,
        disable_rollback: DisableRollback = None,
        client_request_token: ClientRequestToken = None,
    ) -> UpdateStackOutput:
        raise NotImplementedError

    @handler("UpdateStackInstances")
    def update_stack_instances(
        self,
        context: RequestContext,
        stack_set_name: StackSetNameOrId,
        regions: RegionList,
        accounts: AccountList = None,
        deployment_targets: DeploymentTargets = None,
        parameter_overrides: Parameters = None,
        operation_preferences: StackSetOperationPreferences = None,
        operation_id: ClientRequestToken = None,
        call_as: CallAs = None,
    ) -> UpdateStackInstancesOutput:
        raise NotImplementedError

    @handler("UpdateStackSet")
    def update_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        description: Description = None,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
        use_previous_template: UsePreviousTemplate = None,
        parameters: Parameters = None,
        capabilities: Capabilities = None,
        tags: Tags = None,
        operation_preferences: StackSetOperationPreferences = None,
        administration_role_arn: RoleARN = None,
        execution_role_name: ExecutionRoleName = None,
        deployment_targets: DeploymentTargets = None,
        permission_model: PermissionModels = None,
        auto_deployment: AutoDeployment = None,
        operation_id: ClientRequestToken = None,
        accounts: AccountList = None,
        regions: RegionList = None,
        call_as: CallAs = None,
        managed_execution: ManagedExecution = None,
    ) -> UpdateStackSetOutput:
        raise NotImplementedError

    @handler("UpdateTerminationProtection")
    def update_termination_protection(
        self,
        context: RequestContext,
        enable_termination_protection: EnableTerminationProtection,
        stack_name: StackNameOrId,
    ) -> UpdateTerminationProtectionOutput:
        raise NotImplementedError

    @handler("ValidateTemplate")
    def validate_template(
        self,
        context: RequestContext,
        template_body: TemplateBody = None,
        template_url: TemplateURL = None,
    ) -> ValidateTemplateOutput:
        raise NotImplementedError
