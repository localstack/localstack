from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessKeyIdType = str
AccessKeySecretType = str
AccessRequestId = str
Account = str
AccountId = str
ActivationCode = str
ActivationDescription = str
ActivationId = str
AgentErrorCode = str
AgentType = str
AgentVersion = str
AggregatorSchemaOnly = bool
AlarmName = str
AllowedPattern = str
ApplyOnlyAtCronInterval = bool
ApproveAfterDays = int
Architecture = str
AssociationExecutionFilterValue = str
AssociationExecutionId = str
AssociationExecutionTargetsFilterValue = str
AssociationFilterValue = str
AssociationId = str
AssociationName = str
AssociationResourceId = str
AssociationResourceType = str
AssociationVersion = str
AttachmentHash = str
AttachmentIdentifier = str
AttachmentName = str
AttachmentUrl = str
AttachmentsSourceValue = str
AttributeName = str
AttributeValue = str
AutomationActionName = str
AutomationExecutionFilterValue = str
AutomationExecutionId = str
AutomationParameterKey = str
AutomationParameterValue = str
AutomationTargetParameterName = str
BaselineDescription = str
BaselineId = str
BaselineName = str
BatchErrorMessage = str
Boolean = bool
CalendarNameOrARN = str
Category = str
ChangeDetailsValue = str
ChangeRequestName = str
ClientToken = str
CloudWatchLogGroupName = str
CloudWatchOutputEnabled = bool
CommandFilterValue = str
CommandId = str
CommandMaxResults = int
CommandPluginName = str
CommandPluginOutput = str
Comment = str
CompletedCount = int
ComplianceExecutionId = str
ComplianceExecutionType = str
ComplianceFilterValue = str
ComplianceItemContentHash = str
ComplianceItemId = str
ComplianceItemTitle = str
ComplianceResourceId = str
ComplianceResourceType = str
ComplianceStringFilterKey = str
ComplianceSummaryCount = int
ComplianceTypeName = str
ComputerName = str
DefaultBaseline = bool
DefaultInstanceName = str
DeliveryTimedOutCount = int
DescribeInstancePropertiesMaxResults = int
DescriptionInDocument = str
DocumentARN = str
DocumentAuthor = str
DocumentContent = str
DocumentDisplayName = str
DocumentFilterValue = str
DocumentHash = str
DocumentKeyValuesFilterKey = str
DocumentKeyValuesFilterValue = str
DocumentName = str
DocumentOwner = str
DocumentParameterDefaultValue = str
DocumentParameterDescrption = str
DocumentParameterName = str
DocumentPermissionMaxResults = int
DocumentReviewComment = str
DocumentSchemaVersion = str
DocumentSha1 = str
DocumentStatusInformation = str
DocumentVersion = str
DocumentVersionName = str
DocumentVersionNumber = str
DryRun = bool
Duration = int
EffectiveInstanceAssociationMaxResults = int
ErrorCount = int
ExcludeAccount = str
ExecutionPreviewId = str
ExecutionRoleName = str
GetInventorySchemaMaxResults = int
GetOpsMetadataMaxResults = int
GetParametersByPathMaxResults = int
IPAddress = str
ISO8601String = str
IamRole = str
IdempotencyToken = str
InstallOverrideList = str
InstanceAssociationExecutionSummary = str
InstanceCount = int
InstanceId = str
InstanceInformationFilterValue = str
InstanceInformationStringFilterKey = str
InstanceName = str
InstancePatchStateFilterKey = str
InstancePatchStateFilterValue = str
InstancePropertyFilterValue = str
InstancePropertyStringFilterKey = str
InstanceRole = str
InstanceState = str
InstanceStatus = str
InstanceTagName = str
InstanceType = str
InstancesCount = int
Integer = int
InventoryAggregatorExpression = str
InventoryDeletionLastStatusMessage = str
InventoryFilterKey = str
InventoryFilterValue = str
InventoryGroupName = str
InventoryItemAttributeName = str
InventoryItemCaptureTime = str
InventoryItemContentHash = str
InventoryItemSchemaVersion = str
InventoryItemTypeName = str
InventoryItemTypeNameFilter = str
InventoryResultEntityId = str
InventoryResultItemKey = str
InventoryTypeDisplayName = str
InvocationTraceOutput = str
IpAddress = str
IsSubTypeSchema = bool
KeyName = str
LastResourceDataSyncMessage = str
ListOpsMetadataMaxResults = int
MaintenanceWindowAllowUnassociatedTargets = bool
MaintenanceWindowCutoff = int
MaintenanceWindowDescription = str
MaintenanceWindowDurationHours = int
MaintenanceWindowEnabled = bool
MaintenanceWindowExecutionId = str
MaintenanceWindowExecutionStatusDetails = str
MaintenanceWindowExecutionTaskExecutionId = str
MaintenanceWindowExecutionTaskId = str
MaintenanceWindowExecutionTaskInvocationId = str
MaintenanceWindowExecutionTaskInvocationParameters = str
MaintenanceWindowFilterKey = str
MaintenanceWindowFilterValue = str
MaintenanceWindowId = str
MaintenanceWindowLambdaClientContext = str
MaintenanceWindowLambdaQualifier = str
MaintenanceWindowMaxResults = int
MaintenanceWindowName = str
MaintenanceWindowOffset = int
MaintenanceWindowSchedule = str
MaintenanceWindowSearchMaxResults = int
MaintenanceWindowStepFunctionsInput = str
MaintenanceWindowStepFunctionsName = str
MaintenanceWindowStringDateTime = str
MaintenanceWindowTargetId = str
MaintenanceWindowTaskArn = str
MaintenanceWindowTaskId = str
MaintenanceWindowTaskParameterName = str
MaintenanceWindowTaskParameterValue = str
MaintenanceWindowTaskPriority = int
MaintenanceWindowTaskTargetId = str
MaintenanceWindowTimezone = str
ManagedInstanceId = str
MaxConcurrency = str
MaxErrors = str
MaxResults = int
MaxResultsEC2Compatible = int
MaxSessionDuration = str
MetadataKey = str
MetadataValueString = str
NextToken = str
NodeAccountId = str
NodeFilterValue = str
NodeId = str
NodeOrganizationalUnitId = str
NodeOrganizationalUnitPath = str
NodeRegion = str
NotificationArn = str
OpsAggregatorType = str
OpsAggregatorValue = str
OpsAggregatorValueKey = str
OpsDataAttributeName = str
OpsDataTypeName = str
OpsEntityId = str
OpsEntityItemCaptureTime = str
OpsEntityItemKey = str
OpsFilterKey = str
OpsFilterValue = str
OpsItemAccountId = str
OpsItemArn = str
OpsItemCategory = str
OpsItemDataKey = str
OpsItemDataValueString = str
OpsItemDescription = str
OpsItemEventFilterValue = str
OpsItemEventMaxResults = int
OpsItemFilterValue = str
OpsItemId = str
OpsItemMaxResults = int
OpsItemPriority = int
OpsItemRelatedItemAssociationId = str
OpsItemRelatedItemAssociationResourceType = str
OpsItemRelatedItemAssociationResourceUri = str
OpsItemRelatedItemAssociationType = str
OpsItemRelatedItemsFilterValue = str
OpsItemRelatedItemsMaxResults = int
OpsItemSeverity = str
OpsItemSource = str
OpsItemTitle = str
OpsItemType = str
OpsMetadataArn = str
OpsMetadataFilterKey = str
OpsMetadataFilterValue = str
OpsMetadataResourceId = str
OutputSourceId = str
OutputSourceType = str
OwnerInformation = str
PSParameterName = str
PSParameterSelector = str
PSParameterValue = str
ParameterDataType = str
ParameterDescription = str
ParameterKeyId = str
ParameterLabel = str
ParameterName = str
ParameterPolicies = str
ParameterStringFilterKey = str
ParameterStringFilterValue = str
ParameterStringQueryOption = str
ParameterValue = str
ParametersFilterValue = str
PatchAdvisoryId = str
PatchArch = str
PatchAvailableSecurityUpdateCount = int
PatchBaselineMaxResults = int
PatchBugzillaId = str
PatchCVEId = str
PatchCVEIds = str
PatchClassification = str
PatchComplianceMaxResults = int
PatchContentUrl = str
PatchCriticalNonCompliantCount = int
PatchDescription = str
PatchEpoch = int
PatchFailedCount = int
PatchFilterValue = str
PatchGroup = str
PatchId = str
PatchInstalledCount = int
PatchInstalledOtherCount = int
PatchInstalledPendingRebootCount = int
PatchInstalledRejectedCount = int
PatchKbNumber = str
PatchLanguage = str
PatchMissingCount = int
PatchMsrcNumber = str
PatchMsrcSeverity = str
PatchName = str
PatchNotApplicableCount = int
PatchOrchestratorFilterKey = str
PatchOrchestratorFilterValue = str
PatchOtherNonCompliantCount = int
PatchProduct = str
PatchProductFamily = str
PatchRelease = str
PatchRepository = str
PatchSecurityNonCompliantCount = int
PatchSeverity = str
PatchSourceConfiguration = str
PatchSourceName = str
PatchSourceProduct = str
PatchStringDateTime = str
PatchTitle = str
PatchUnreportedNotApplicableCount = int
PatchVendor = str
PatchVersion = str
PlatformName = str
PlatformVersion = str
Policy = str
PolicyHash = str
PolicyId = str
Product = str
PutInventoryMessage = str
Region = str
RegistrationLimit = int
RegistrationMetadataKey = str
RegistrationMetadataValue = str
RegistrationsCount = int
RemainingCount = int
RequireType = str
ResourceArnString = str
ResourceCount = int
ResourceCountByStatus = str
ResourceDataSyncAWSKMSKeyARN = str
ResourceDataSyncDestinationDataSharingType = str
ResourceDataSyncEnableAllOpsDataSources = bool
ResourceDataSyncIncludeFutureRegions = bool
ResourceDataSyncName = str
ResourceDataSyncOrganizationSourceType = str
ResourceDataSyncOrganizationalUnitId = str
ResourceDataSyncS3BucketName = str
ResourceDataSyncS3Prefix = str
ResourceDataSyncS3Region = str
ResourceDataSyncSourceRegion = str
ResourceDataSyncSourceType = str
ResourceDataSyncState = str
ResourceDataSyncType = str
ResourceId = str
ResourcePolicyMaxResults = int
ResponseCode = int
Reviewer = str
S3BucketName = str
S3KeyPrefix = str
S3Region = str
ScheduleExpression = str
ScheduleOffset = int
ServiceRole = str
ServiceSettingId = str
ServiceSettingValue = str
SessionDetails = str
SessionFilterValue = str
SessionId = str
SessionManagerCloudWatchOutputUrl = str
SessionManagerParameterName = str
SessionManagerParameterValue = str
SessionManagerS3OutputUrl = str
SessionMaxResults = int
SessionOwner = str
SessionReason = str
SessionTarget = str
SessionTokenType = str
SharedDocumentVersion = str
SnapshotDownloadUrl = str
SnapshotId = str
SourceId = str
StandardErrorContent = str
StandardOutputContent = str
StatusAdditionalInfo = str
StatusDetails = str
StatusMessage = str
StatusName = str
StepExecutionFilterValue = str
StreamUrl = str
String = str
String1to256 = str
StringDateTime = str
TagKey = str
TagValue = str
TargetCount = int
TargetKey = str
TargetLocationsURL = str
TargetMapKey = str
TargetMapValue = str
TargetType = str
TargetValue = str
TimeoutSeconds = int
TokenValue = str
TotalCount = int
UUID = str
Url = str
ValidNextStep = str
Version = str


class AccessRequestStatus(StrEnum):
    Approved = "Approved"
    Rejected = "Rejected"
    Revoked = "Revoked"
    Expired = "Expired"
    Pending = "Pending"


class AccessType(StrEnum):
    Standard = "Standard"
    JustInTime = "JustInTime"


class AssociationComplianceSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNSPECIFIED = "UNSPECIFIED"


class AssociationExecutionFilterKey(StrEnum):
    ExecutionId = "ExecutionId"
    Status = "Status"
    CreatedTime = "CreatedTime"


class AssociationExecutionTargetsFilterKey(StrEnum):
    Status = "Status"
    ResourceId = "ResourceId"
    ResourceType = "ResourceType"


class AssociationFilterKey(StrEnum):
    InstanceId = "InstanceId"
    Name = "Name"
    AssociationId = "AssociationId"
    AssociationStatusName = "AssociationStatusName"
    LastExecutedBefore = "LastExecutedBefore"
    LastExecutedAfter = "LastExecutedAfter"
    AssociationName = "AssociationName"
    ResourceGroupName = "ResourceGroupName"


class AssociationFilterOperatorType(StrEnum):
    EQUAL = "EQUAL"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN = "GREATER_THAN"


class AssociationStatusName(StrEnum):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"


class AssociationSyncCompliance(StrEnum):
    AUTO = "AUTO"
    MANUAL = "MANUAL"


class AttachmentHashType(StrEnum):
    Sha256 = "Sha256"


class AttachmentsSourceKey(StrEnum):
    SourceUrl = "SourceUrl"
    S3FileUrl = "S3FileUrl"
    AttachmentReference = "AttachmentReference"


class AutomationExecutionFilterKey(StrEnum):
    DocumentNamePrefix = "DocumentNamePrefix"
    ExecutionStatus = "ExecutionStatus"
    ExecutionId = "ExecutionId"
    ParentExecutionId = "ParentExecutionId"
    CurrentAction = "CurrentAction"
    StartTimeBefore = "StartTimeBefore"
    StartTimeAfter = "StartTimeAfter"
    AutomationType = "AutomationType"
    TagKey = "TagKey"
    TargetResourceGroup = "TargetResourceGroup"
    AutomationSubtype = "AutomationSubtype"
    OpsItemId = "OpsItemId"


class AutomationExecutionStatus(StrEnum):
    Pending = "Pending"
    InProgress = "InProgress"
    Waiting = "Waiting"
    Success = "Success"
    TimedOut = "TimedOut"
    Cancelling = "Cancelling"
    Cancelled = "Cancelled"
    Failed = "Failed"
    PendingApproval = "PendingApproval"
    Approved = "Approved"
    Rejected = "Rejected"
    Scheduled = "Scheduled"
    RunbookInProgress = "RunbookInProgress"
    PendingChangeCalendarOverride = "PendingChangeCalendarOverride"
    ChangeCalendarOverrideApproved = "ChangeCalendarOverrideApproved"
    ChangeCalendarOverrideRejected = "ChangeCalendarOverrideRejected"
    CompletedWithSuccess = "CompletedWithSuccess"
    CompletedWithFailure = "CompletedWithFailure"
    Exited = "Exited"


class AutomationSubtype(StrEnum):
    ChangeRequest = "ChangeRequest"
    AccessRequest = "AccessRequest"


class AutomationType(StrEnum):
    CrossAccount = "CrossAccount"
    Local = "Local"


class CalendarState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class CommandFilterKey(StrEnum):
    InvokedAfter = "InvokedAfter"
    InvokedBefore = "InvokedBefore"
    Status = "Status"
    ExecutionStage = "ExecutionStage"
    DocumentName = "DocumentName"


class CommandInvocationStatus(StrEnum):
    Pending = "Pending"
    InProgress = "InProgress"
    Delayed = "Delayed"
    Success = "Success"
    Cancelled = "Cancelled"
    TimedOut = "TimedOut"
    Failed = "Failed"
    Cancelling = "Cancelling"


class CommandPluginStatus(StrEnum):
    Pending = "Pending"
    InProgress = "InProgress"
    Success = "Success"
    TimedOut = "TimedOut"
    Cancelled = "Cancelled"
    Failed = "Failed"


class CommandStatus(StrEnum):
    Pending = "Pending"
    InProgress = "InProgress"
    Success = "Success"
    Cancelled = "Cancelled"
    Failed = "Failed"
    TimedOut = "TimedOut"
    Cancelling = "Cancelling"


class ComplianceQueryOperatorType(StrEnum):
    EQUAL = "EQUAL"
    NOT_EQUAL = "NOT_EQUAL"
    BEGIN_WITH = "BEGIN_WITH"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN = "GREATER_THAN"


class ComplianceSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNSPECIFIED = "UNSPECIFIED"


class ComplianceStatus(StrEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class ComplianceUploadType(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class ConnectionStatus(StrEnum):
    connected = "connected"
    notconnected = "notconnected"


class DescribeActivationsFilterKeys(StrEnum):
    ActivationIds = "ActivationIds"
    DefaultInstanceName = "DefaultInstanceName"
    IamRole = "IamRole"


class DocumentFilterKey(StrEnum):
    Name = "Name"
    Owner = "Owner"
    PlatformTypes = "PlatformTypes"
    DocumentType = "DocumentType"


class DocumentFormat(StrEnum):
    YAML = "YAML"
    JSON = "JSON"
    TEXT = "TEXT"


class DocumentHashType(StrEnum):
    Sha256 = "Sha256"
    Sha1 = "Sha1"


class DocumentMetadataEnum(StrEnum):
    DocumentReviews = "DocumentReviews"


class DocumentParameterType(StrEnum):
    String = "String"
    StringList = "StringList"


class DocumentPermissionType(StrEnum):
    Share = "Share"


class DocumentReviewAction(StrEnum):
    SendForReview = "SendForReview"
    UpdateReview = "UpdateReview"
    Approve = "Approve"
    Reject = "Reject"


class DocumentReviewCommentType(StrEnum):
    Comment = "Comment"


class DocumentStatus(StrEnum):
    Creating = "Creating"
    Active = "Active"
    Updating = "Updating"
    Deleting = "Deleting"
    Failed = "Failed"


class DocumentType(StrEnum):
    Command = "Command"
    Policy = "Policy"
    Automation = "Automation"
    Session = "Session"
    Package = "Package"
    ApplicationConfiguration = "ApplicationConfiguration"
    ApplicationConfigurationSchema = "ApplicationConfigurationSchema"
    DeploymentStrategy = "DeploymentStrategy"
    ChangeCalendar = "ChangeCalendar"
    Automation_ChangeTemplate = "Automation.ChangeTemplate"
    ProblemAnalysis = "ProblemAnalysis"
    ProblemAnalysisTemplate = "ProblemAnalysisTemplate"
    CloudFormation = "CloudFormation"
    ConformancePackTemplate = "ConformancePackTemplate"
    QuickSetup = "QuickSetup"
    ManualApprovalPolicy = "ManualApprovalPolicy"
    AutoApprovalPolicy = "AutoApprovalPolicy"


class ExecutionMode(StrEnum):
    Auto = "Auto"
    Interactive = "Interactive"


class ExecutionPreviewStatus(StrEnum):
    Pending = "Pending"
    InProgress = "InProgress"
    Success = "Success"
    Failed = "Failed"


class ExternalAlarmState(StrEnum):
    UNKNOWN = "UNKNOWN"
    ALARM = "ALARM"


class Fault(StrEnum):
    Client = "Client"
    Server = "Server"
    Unknown = "Unknown"


class ImpactType(StrEnum):
    Mutating = "Mutating"
    NonMutating = "NonMutating"
    Undetermined = "Undetermined"


class InstanceInformationFilterKey(StrEnum):
    InstanceIds = "InstanceIds"
    AgentVersion = "AgentVersion"
    PingStatus = "PingStatus"
    PlatformTypes = "PlatformTypes"
    ActivationIds = "ActivationIds"
    IamRole = "IamRole"
    ResourceType = "ResourceType"
    AssociationStatus = "AssociationStatus"


class InstancePatchStateOperatorType(StrEnum):
    Equal = "Equal"
    NotEqual = "NotEqual"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"


class InstancePropertyFilterKey(StrEnum):
    InstanceIds = "InstanceIds"
    AgentVersion = "AgentVersion"
    PingStatus = "PingStatus"
    PlatformTypes = "PlatformTypes"
    DocumentName = "DocumentName"
    ActivationIds = "ActivationIds"
    IamRole = "IamRole"
    ResourceType = "ResourceType"
    AssociationStatus = "AssociationStatus"


class InstancePropertyFilterOperator(StrEnum):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"


class InventoryAttributeDataType(StrEnum):
    string = "string"
    number = "number"


class InventoryDeletionStatus(StrEnum):
    InProgress = "InProgress"
    Complete = "Complete"


class InventoryQueryOperatorType(StrEnum):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    Exists = "Exists"


class InventorySchemaDeleteOption(StrEnum):
    DisableSchema = "DisableSchema"
    DeleteSchema = "DeleteSchema"


class LastResourceDataSyncStatus(StrEnum):
    Successful = "Successful"
    Failed = "Failed"
    InProgress = "InProgress"


class MaintenanceWindowExecutionStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    SKIPPED_OVERLAPPING = "SKIPPED_OVERLAPPING"


class MaintenanceWindowResourceType(StrEnum):
    INSTANCE = "INSTANCE"
    RESOURCE_GROUP = "RESOURCE_GROUP"


class MaintenanceWindowTaskCutoffBehavior(StrEnum):
    CONTINUE_TASK = "CONTINUE_TASK"
    CANCEL_TASK = "CANCEL_TASK"


class MaintenanceWindowTaskType(StrEnum):
    RUN_COMMAND = "RUN_COMMAND"
    AUTOMATION = "AUTOMATION"
    STEP_FUNCTIONS = "STEP_FUNCTIONS"
    LAMBDA = "LAMBDA"


class ManagedStatus(StrEnum):
    All = "All"
    Managed = "Managed"
    Unmanaged = "Unmanaged"


class NodeAggregatorType(StrEnum):
    Count = "Count"


class NodeAttributeName(StrEnum):
    AgentVersion = "AgentVersion"
    PlatformName = "PlatformName"
    PlatformType = "PlatformType"
    PlatformVersion = "PlatformVersion"
    Region = "Region"
    ResourceType = "ResourceType"


class NodeFilterKey(StrEnum):
    AgentType = "AgentType"
    AgentVersion = "AgentVersion"
    ComputerName = "ComputerName"
    InstanceId = "InstanceId"
    InstanceStatus = "InstanceStatus"
    IpAddress = "IpAddress"
    ManagedStatus = "ManagedStatus"
    PlatformName = "PlatformName"
    PlatformType = "PlatformType"
    PlatformVersion = "PlatformVersion"
    ResourceType = "ResourceType"
    OrganizationalUnitId = "OrganizationalUnitId"
    OrganizationalUnitPath = "OrganizationalUnitPath"
    Region = "Region"
    AccountId = "AccountId"


class NodeFilterOperatorType(StrEnum):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"


class NodeTypeName(StrEnum):
    Instance = "Instance"


class NotificationEvent(StrEnum):
    All = "All"
    InProgress = "InProgress"
    Success = "Success"
    TimedOut = "TimedOut"
    Cancelled = "Cancelled"
    Failed = "Failed"


class NotificationType(StrEnum):
    Command = "Command"
    Invocation = "Invocation"


class OperatingSystem(StrEnum):
    WINDOWS = "WINDOWS"
    AMAZON_LINUX = "AMAZON_LINUX"
    AMAZON_LINUX_2 = "AMAZON_LINUX_2"
    AMAZON_LINUX_2022 = "AMAZON_LINUX_2022"
    UBUNTU = "UBUNTU"
    REDHAT_ENTERPRISE_LINUX = "REDHAT_ENTERPRISE_LINUX"
    SUSE = "SUSE"
    CENTOS = "CENTOS"
    ORACLE_LINUX = "ORACLE_LINUX"
    DEBIAN = "DEBIAN"
    MACOS = "MACOS"
    RASPBIAN = "RASPBIAN"
    ROCKY_LINUX = "ROCKY_LINUX"
    ALMA_LINUX = "ALMA_LINUX"
    AMAZON_LINUX_2023 = "AMAZON_LINUX_2023"


class OpsFilterOperatorType(StrEnum):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    Exists = "Exists"


class OpsItemDataType(StrEnum):
    SearchableString = "SearchableString"
    String = "String"


class OpsItemEventFilterKey(StrEnum):
    OpsItemId = "OpsItemId"


class OpsItemEventFilterOperator(StrEnum):
    Equal = "Equal"


class OpsItemFilterKey(StrEnum):
    Status = "Status"
    CreatedBy = "CreatedBy"
    Source = "Source"
    Priority = "Priority"
    Title = "Title"
    OpsItemId = "OpsItemId"
    CreatedTime = "CreatedTime"
    LastModifiedTime = "LastModifiedTime"
    ActualStartTime = "ActualStartTime"
    ActualEndTime = "ActualEndTime"
    PlannedStartTime = "PlannedStartTime"
    PlannedEndTime = "PlannedEndTime"
    OperationalData = "OperationalData"
    OperationalDataKey = "OperationalDataKey"
    OperationalDataValue = "OperationalDataValue"
    ResourceId = "ResourceId"
    AutomationId = "AutomationId"
    Category = "Category"
    Severity = "Severity"
    OpsItemType = "OpsItemType"
    AccessRequestByRequesterArn = "AccessRequestByRequesterArn"
    AccessRequestByRequesterId = "AccessRequestByRequesterId"
    AccessRequestByApproverArn = "AccessRequestByApproverArn"
    AccessRequestByApproverId = "AccessRequestByApproverId"
    AccessRequestBySourceAccountId = "AccessRequestBySourceAccountId"
    AccessRequestBySourceOpsItemId = "AccessRequestBySourceOpsItemId"
    AccessRequestBySourceRegion = "AccessRequestBySourceRegion"
    AccessRequestByIsReplica = "AccessRequestByIsReplica"
    AccessRequestByTargetResourceId = "AccessRequestByTargetResourceId"
    ChangeRequestByRequesterArn = "ChangeRequestByRequesterArn"
    ChangeRequestByRequesterName = "ChangeRequestByRequesterName"
    ChangeRequestByApproverArn = "ChangeRequestByApproverArn"
    ChangeRequestByApproverName = "ChangeRequestByApproverName"
    ChangeRequestByTemplate = "ChangeRequestByTemplate"
    ChangeRequestByTargetsResourceGroup = "ChangeRequestByTargetsResourceGroup"
    InsightByType = "InsightByType"
    AccountId = "AccountId"


class OpsItemFilterOperator(StrEnum):
    Equal = "Equal"
    Contains = "Contains"
    GreaterThan = "GreaterThan"
    LessThan = "LessThan"


class OpsItemRelatedItemsFilterKey(StrEnum):
    ResourceType = "ResourceType"
    AssociationId = "AssociationId"
    ResourceUri = "ResourceUri"


class OpsItemRelatedItemsFilterOperator(StrEnum):
    Equal = "Equal"


class OpsItemStatus(StrEnum):
    Open = "Open"
    InProgress = "InProgress"
    Resolved = "Resolved"
    Pending = "Pending"
    TimedOut = "TimedOut"
    Cancelling = "Cancelling"
    Cancelled = "Cancelled"
    Failed = "Failed"
    CompletedWithSuccess = "CompletedWithSuccess"
    CompletedWithFailure = "CompletedWithFailure"
    Scheduled = "Scheduled"
    RunbookInProgress = "RunbookInProgress"
    PendingChangeCalendarOverride = "PendingChangeCalendarOverride"
    ChangeCalendarOverrideApproved = "ChangeCalendarOverrideApproved"
    ChangeCalendarOverrideRejected = "ChangeCalendarOverrideRejected"
    PendingApproval = "PendingApproval"
    Approved = "Approved"
    Revoked = "Revoked"
    Rejected = "Rejected"
    Closed = "Closed"


class ParameterTier(StrEnum):
    Standard = "Standard"
    Advanced = "Advanced"
    Intelligent_Tiering = "Intelligent-Tiering"


class ParameterType(StrEnum):
    String = "String"
    StringList = "StringList"
    SecureString = "SecureString"


class ParametersFilterKey(StrEnum):
    Name = "Name"
    Type = "Type"
    KeyId = "KeyId"


class PatchAction(StrEnum):
    ALLOW_AS_DEPENDENCY = "ALLOW_AS_DEPENDENCY"
    BLOCK = "BLOCK"


class PatchComplianceDataState(StrEnum):
    INSTALLED = "INSTALLED"
    INSTALLED_OTHER = "INSTALLED_OTHER"
    INSTALLED_PENDING_REBOOT = "INSTALLED_PENDING_REBOOT"
    INSTALLED_REJECTED = "INSTALLED_REJECTED"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"
    AVAILABLE_SECURITY_UPDATE = "AVAILABLE_SECURITY_UPDATE"


class PatchComplianceLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNSPECIFIED = "UNSPECIFIED"


class PatchComplianceStatus(StrEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class PatchDeploymentStatus(StrEnum):
    APPROVED = "APPROVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXPLICIT_APPROVED = "EXPLICIT_APPROVED"
    EXPLICIT_REJECTED = "EXPLICIT_REJECTED"


class PatchFilterKey(StrEnum):
    ARCH = "ARCH"
    ADVISORY_ID = "ADVISORY_ID"
    BUGZILLA_ID = "BUGZILLA_ID"
    PATCH_SET = "PATCH_SET"
    PRODUCT = "PRODUCT"
    PRODUCT_FAMILY = "PRODUCT_FAMILY"
    CLASSIFICATION = "CLASSIFICATION"
    CVE_ID = "CVE_ID"
    EPOCH = "EPOCH"
    MSRC_SEVERITY = "MSRC_SEVERITY"
    NAME = "NAME"
    PATCH_ID = "PATCH_ID"
    SECTION = "SECTION"
    PRIORITY = "PRIORITY"
    REPOSITORY = "REPOSITORY"
    RELEASE = "RELEASE"
    SEVERITY = "SEVERITY"
    SECURITY = "SECURITY"
    VERSION = "VERSION"


class PatchOperationType(StrEnum):
    Scan = "Scan"
    Install = "Install"


class PatchProperty(StrEnum):
    PRODUCT = "PRODUCT"
    PRODUCT_FAMILY = "PRODUCT_FAMILY"
    CLASSIFICATION = "CLASSIFICATION"
    MSRC_SEVERITY = "MSRC_SEVERITY"
    PRIORITY = "PRIORITY"
    SEVERITY = "SEVERITY"


class PatchSet(StrEnum):
    OS = "OS"
    APPLICATION = "APPLICATION"


class PingStatus(StrEnum):
    Online = "Online"
    ConnectionLost = "ConnectionLost"
    Inactive = "Inactive"


class PlatformType(StrEnum):
    Windows = "Windows"
    Linux = "Linux"
    MacOS = "MacOS"


class RebootOption(StrEnum):
    RebootIfNeeded = "RebootIfNeeded"
    NoReboot = "NoReboot"


class ResourceDataSyncS3Format(StrEnum):
    JsonSerDe = "JsonSerDe"


class ResourceType(StrEnum):
    ManagedInstance = "ManagedInstance"
    EC2Instance = "EC2Instance"


class ResourceTypeForTagging(StrEnum):
    Document = "Document"
    ManagedInstance = "ManagedInstance"
    MaintenanceWindow = "MaintenanceWindow"
    Parameter = "Parameter"
    PatchBaseline = "PatchBaseline"
    OpsItem = "OpsItem"
    OpsMetadata = "OpsMetadata"
    Automation = "Automation"
    Association = "Association"


class ReviewStatus(StrEnum):
    APPROVED = "APPROVED"
    NOT_REVIEWED = "NOT_REVIEWED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"


class SessionFilterKey(StrEnum):
    InvokedAfter = "InvokedAfter"
    InvokedBefore = "InvokedBefore"
    Target = "Target"
    Owner = "Owner"
    Status = "Status"
    SessionId = "SessionId"
    AccessType = "AccessType"


class SessionState(StrEnum):
    Active = "Active"
    History = "History"


class SessionStatus(StrEnum):
    Connected = "Connected"
    Connecting = "Connecting"
    Disconnected = "Disconnected"
    Terminated = "Terminated"
    Terminating = "Terminating"
    Failed = "Failed"


class SignalType(StrEnum):
    Approve = "Approve"
    Reject = "Reject"
    StartStep = "StartStep"
    StopStep = "StopStep"
    Resume = "Resume"
    Revoke = "Revoke"


class SourceType(StrEnum):
    AWS_EC2_Instance = "AWS::EC2::Instance"
    AWS_IoT_Thing = "AWS::IoT::Thing"
    AWS_SSM_ManagedInstance = "AWS::SSM::ManagedInstance"


class StepExecutionFilterKey(StrEnum):
    StartTimeBefore = "StartTimeBefore"
    StartTimeAfter = "StartTimeAfter"
    StepExecutionStatus = "StepExecutionStatus"
    StepExecutionId = "StepExecutionId"
    StepName = "StepName"
    Action = "Action"
    ParentStepExecutionId = "ParentStepExecutionId"
    ParentStepIteration = "ParentStepIteration"
    ParentStepIteratorValue = "ParentStepIteratorValue"


class StopType(StrEnum):
    Complete = "Complete"
    Cancel = "Cancel"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class AssociatedInstances(ServiceException):
    code: str = "AssociatedInstances"
    sender_fault: bool = False
    status_code: int = 400


class AssociationAlreadyExists(ServiceException):
    code: str = "AssociationAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class AssociationDoesNotExist(ServiceException):
    code: str = "AssociationDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class AssociationExecutionDoesNotExist(ServiceException):
    code: str = "AssociationExecutionDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class AssociationLimitExceeded(ServiceException):
    code: str = "AssociationLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class AssociationVersionLimitExceeded(ServiceException):
    code: str = "AssociationVersionLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class AutomationDefinitionNotApprovedException(ServiceException):
    code: str = "AutomationDefinitionNotApprovedException"
    sender_fault: bool = False
    status_code: int = 400


class AutomationDefinitionNotFoundException(ServiceException):
    code: str = "AutomationDefinitionNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class AutomationDefinitionVersionNotFoundException(ServiceException):
    code: str = "AutomationDefinitionVersionNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class AutomationExecutionLimitExceededException(ServiceException):
    code: str = "AutomationExecutionLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class AutomationExecutionNotFoundException(ServiceException):
    code: str = "AutomationExecutionNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class AutomationStepNotFoundException(ServiceException):
    code: str = "AutomationStepNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ComplianceTypeCountLimitExceededException(ServiceException):
    code: str = "ComplianceTypeCountLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class CustomSchemaCountLimitExceededException(ServiceException):
    code: str = "CustomSchemaCountLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class DocumentAlreadyExists(ServiceException):
    code: str = "DocumentAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class DocumentLimitExceeded(ServiceException):
    code: str = "DocumentLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class DocumentPermissionLimit(ServiceException):
    code: str = "DocumentPermissionLimit"
    sender_fault: bool = False
    status_code: int = 400


class DocumentVersionLimitExceeded(ServiceException):
    code: str = "DocumentVersionLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class DoesNotExistException(ServiceException):
    code: str = "DoesNotExistException"
    sender_fault: bool = False
    status_code: int = 400


class DuplicateDocumentContent(ServiceException):
    code: str = "DuplicateDocumentContent"
    sender_fault: bool = False
    status_code: int = 400


class DuplicateDocumentVersionName(ServiceException):
    code: str = "DuplicateDocumentVersionName"
    sender_fault: bool = False
    status_code: int = 400


class DuplicateInstanceId(ServiceException):
    code: str = "DuplicateInstanceId"
    sender_fault: bool = False
    status_code: int = 400


class FeatureNotAvailableException(ServiceException):
    code: str = "FeatureNotAvailableException"
    sender_fault: bool = False
    status_code: int = 400


class HierarchyLevelLimitExceededException(ServiceException):
    code: str = "HierarchyLevelLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class HierarchyTypeMismatchException(ServiceException):
    code: str = "HierarchyTypeMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class IdempotentParameterMismatch(ServiceException):
    code: str = "IdempotentParameterMismatch"
    sender_fault: bool = False
    status_code: int = 400


class IncompatiblePolicyException(ServiceException):
    code: str = "IncompatiblePolicyException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServerError(ServiceException):
    code: str = "InternalServerError"
    sender_fault: bool = False
    status_code: int = 400


class InvalidActivation(ServiceException):
    code: str = "InvalidActivation"
    sender_fault: bool = False
    status_code: int = 400


class InvalidActivationId(ServiceException):
    code: str = "InvalidActivationId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAggregatorException(ServiceException):
    code: str = "InvalidAggregatorException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAllowedPatternException(ServiceException):
    code: str = "InvalidAllowedPatternException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAssociation(ServiceException):
    code: str = "InvalidAssociation"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAssociationVersion(ServiceException):
    code: str = "InvalidAssociationVersion"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAutomationExecutionParametersException(ServiceException):
    code: str = "InvalidAutomationExecutionParametersException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAutomationSignalException(ServiceException):
    code: str = "InvalidAutomationSignalException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAutomationStatusUpdateException(ServiceException):
    code: str = "InvalidAutomationStatusUpdateException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidCommandId(ServiceException):
    code: str = "InvalidCommandId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDeleteInventoryParametersException(ServiceException):
    code: str = "InvalidDeleteInventoryParametersException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDeletionIdException(ServiceException):
    code: str = "InvalidDeletionIdException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocument(ServiceException):
    code: str = "InvalidDocument"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocumentContent(ServiceException):
    code: str = "InvalidDocumentContent"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocumentOperation(ServiceException):
    code: str = "InvalidDocumentOperation"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocumentSchemaVersion(ServiceException):
    code: str = "InvalidDocumentSchemaVersion"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocumentType(ServiceException):
    code: str = "InvalidDocumentType"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDocumentVersion(ServiceException):
    code: str = "InvalidDocumentVersion"
    sender_fault: bool = False
    status_code: int = 400


class InvalidFilter(ServiceException):
    code: str = "InvalidFilter"
    sender_fault: bool = False
    status_code: int = 400


class InvalidFilterKey(ServiceException):
    code: str = "InvalidFilterKey"
    sender_fault: bool = False
    status_code: int = 400


class InvalidFilterOption(ServiceException):
    code: str = "InvalidFilterOption"
    sender_fault: bool = False
    status_code: int = 400


class InvalidFilterValue(ServiceException):
    code: str = "InvalidFilterValue"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInstanceId(ServiceException):
    code: str = "InvalidInstanceId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInstanceInformationFilterValue(ServiceException):
    code: str = "InvalidInstanceInformationFilterValue"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInstancePropertyFilterValue(ServiceException):
    code: str = "InvalidInstancePropertyFilterValue"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInventoryGroupException(ServiceException):
    code: str = "InvalidInventoryGroupException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInventoryItemContextException(ServiceException):
    code: str = "InvalidInventoryItemContextException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidInventoryRequestException(ServiceException):
    code: str = "InvalidInventoryRequestException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidItemContentException(ServiceException):
    code: str = "InvalidItemContentException"
    sender_fault: bool = False
    status_code: int = 400
    TypeName: InventoryItemTypeName | None


class InvalidKeyId(ServiceException):
    code: str = "InvalidKeyId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextToken(ServiceException):
    code: str = "InvalidNextToken"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNotificationConfig(ServiceException):
    code: str = "InvalidNotificationConfig"
    sender_fault: bool = False
    status_code: int = 400


class InvalidOptionException(ServiceException):
    code: str = "InvalidOptionException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidOutputFolder(ServiceException):
    code: str = "InvalidOutputFolder"
    sender_fault: bool = False
    status_code: int = 400


class InvalidOutputLocation(ServiceException):
    code: str = "InvalidOutputLocation"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameters(ServiceException):
    code: str = "InvalidParameters"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPermissionType(ServiceException):
    code: str = "InvalidPermissionType"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPluginName(ServiceException):
    code: str = "InvalidPluginName"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPolicyAttributeException(ServiceException):
    code: str = "InvalidPolicyAttributeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPolicyTypeException(ServiceException):
    code: str = "InvalidPolicyTypeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResourceId(ServiceException):
    code: str = "InvalidResourceId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResourceType(ServiceException):
    code: str = "InvalidResourceType"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResultAttributeException(ServiceException):
    code: str = "InvalidResultAttributeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRole(ServiceException):
    code: str = "InvalidRole"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSchedule(ServiceException):
    code: str = "InvalidSchedule"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTag(ServiceException):
    code: str = "InvalidTag"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTarget(ServiceException):
    code: str = "InvalidTarget"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTargetMaps(ServiceException):
    code: str = "InvalidTargetMaps"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTypeNameException(ServiceException):
    code: str = "InvalidTypeNameException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidUpdate(ServiceException):
    code: str = "InvalidUpdate"
    sender_fault: bool = False
    status_code: int = 400


class InvocationDoesNotExist(ServiceException):
    code: str = "InvocationDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class ItemContentMismatchException(ServiceException):
    code: str = "ItemContentMismatchException"
    sender_fault: bool = False
    status_code: int = 400
    TypeName: InventoryItemTypeName | None


class ItemSizeLimitExceededException(ServiceException):
    code: str = "ItemSizeLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    TypeName: InventoryItemTypeName | None


class MalformedResourcePolicyDocumentException(ServiceException):
    code: str = "MalformedResourcePolicyDocumentException"
    sender_fault: bool = False
    status_code: int = 400


class MaxDocumentSizeExceeded(ServiceException):
    code: str = "MaxDocumentSizeExceeded"
    sender_fault: bool = False
    status_code: int = 400


class NoLongerSupportedException(ServiceException):
    code: str = "NoLongerSupportedException"
    sender_fault: bool = False
    status_code: int = 400


class OpsItemAccessDeniedException(ServiceException):
    code: str = "OpsItemAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class OpsItemAlreadyExistsException(ServiceException):
    code: str = "OpsItemAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400
    OpsItemId: String | None


class OpsItemConflictException(ServiceException):
    code: str = "OpsItemConflictException"
    sender_fault: bool = False
    status_code: int = 400


OpsItemParameterNamesList = list[String]


class OpsItemInvalidParameterException(ServiceException):
    code: str = "OpsItemInvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400
    ParameterNames: OpsItemParameterNamesList | None


class OpsItemLimitExceededException(ServiceException):
    code: str = "OpsItemLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceTypes: OpsItemParameterNamesList | None
    Limit: Integer | None
    LimitType: String | None


class OpsItemNotFoundException(ServiceException):
    code: str = "OpsItemNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class OpsItemRelatedItemAlreadyExistsException(ServiceException):
    code: str = "OpsItemRelatedItemAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceUri: OpsItemRelatedItemAssociationResourceUri | None
    OpsItemId: OpsItemId | None


class OpsItemRelatedItemAssociationNotFoundException(ServiceException):
    code: str = "OpsItemRelatedItemAssociationNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataAlreadyExistsException(ServiceException):
    code: str = "OpsMetadataAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataInvalidArgumentException(ServiceException):
    code: str = "OpsMetadataInvalidArgumentException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataKeyLimitExceededException(ServiceException):
    code: str = "OpsMetadataKeyLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataLimitExceededException(ServiceException):
    code: str = "OpsMetadataLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataNotFoundException(ServiceException):
    code: str = "OpsMetadataNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class OpsMetadataTooManyUpdatesException(ServiceException):
    code: str = "OpsMetadataTooManyUpdatesException"
    sender_fault: bool = False
    status_code: int = 400


class ParameterAlreadyExists(ServiceException):
    code: str = "ParameterAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class ParameterLimitExceeded(ServiceException):
    code: str = "ParameterLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ParameterMaxVersionLimitExceeded(ServiceException):
    code: str = "ParameterMaxVersionLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ParameterNotFound(ServiceException):
    code: str = "ParameterNotFound"
    sender_fault: bool = False
    status_code: int = 400


class ParameterPatternMismatchException(ServiceException):
    code: str = "ParameterPatternMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class ParameterVersionLabelLimitExceeded(ServiceException):
    code: str = "ParameterVersionLabelLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ParameterVersionNotFound(ServiceException):
    code: str = "ParameterVersionNotFound"
    sender_fault: bool = False
    status_code: int = 400


class PoliciesLimitExceededException(ServiceException):
    code: str = "PoliciesLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceDataSyncAlreadyExistsException(ServiceException):
    code: str = "ResourceDataSyncAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400
    SyncName: ResourceDataSyncName | None


class ResourceDataSyncConflictException(ServiceException):
    code: str = "ResourceDataSyncConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceDataSyncCountExceededException(ServiceException):
    code: str = "ResourceDataSyncCountExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceDataSyncInvalidConfigurationException(ServiceException):
    code: str = "ResourceDataSyncInvalidConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceDataSyncNotFoundException(ServiceException):
    code: str = "ResourceDataSyncNotFoundException"
    sender_fault: bool = False
    status_code: int = 400
    SyncName: ResourceDataSyncName | None
    SyncType: ResourceDataSyncType | None


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceLimitExceededException(ServiceException):
    code: str = "ResourceLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourcePolicyConflictException(ServiceException):
    code: str = "ResourcePolicyConflictException"
    sender_fault: bool = False
    status_code: int = 400


ResourcePolicyParameterNamesList = list[String]


class ResourcePolicyInvalidParameterException(ServiceException):
    code: str = "ResourcePolicyInvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400
    ParameterNames: ResourcePolicyParameterNamesList | None


class ResourcePolicyLimitExceededException(ServiceException):
    code: str = "ResourcePolicyLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    Limit: Integer | None
    LimitType: String | None


class ResourcePolicyNotFoundException(ServiceException):
    code: str = "ResourcePolicyNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceId: String | None
    ResourceType: String | None
    QuotaCode: String
    ServiceCode: String


class ServiceSettingNotFound(ServiceException):
    code: str = "ServiceSettingNotFound"
    sender_fault: bool = False
    status_code: int = 400


class StatusUnchanged(ServiceException):
    code: str = "StatusUnchanged"
    sender_fault: bool = False
    status_code: int = 400


class SubTypeCountLimitExceededException(ServiceException):
    code: str = "SubTypeCountLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class TargetInUseException(ServiceException):
    code: str = "TargetInUseException"
    sender_fault: bool = False
    status_code: int = 400


class TargetNotConnected(ServiceException):
    code: str = "TargetNotConnected"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400
    QuotaCode: String | None
    ServiceCode: String | None


class TooManyTagsError(ServiceException):
    code: str = "TooManyTagsError"
    sender_fault: bool = False
    status_code: int = 400


class TooManyUpdates(ServiceException):
    code: str = "TooManyUpdates"
    sender_fault: bool = False
    status_code: int = 400


class TotalSizeLimitExceededException(ServiceException):
    code: str = "TotalSizeLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedCalendarException(ServiceException):
    code: str = "UnsupportedCalendarException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedFeatureRequiredException(ServiceException):
    code: str = "UnsupportedFeatureRequiredException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedInventoryItemContextException(ServiceException):
    code: str = "UnsupportedInventoryItemContextException"
    sender_fault: bool = False
    status_code: int = 400
    TypeName: InventoryItemTypeName | None


class UnsupportedInventorySchemaVersionException(ServiceException):
    code: str = "UnsupportedInventorySchemaVersionException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedOperatingSystem(ServiceException):
    code: str = "UnsupportedOperatingSystem"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedOperationException(ServiceException):
    code: str = "UnsupportedOperationException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedParameterType(ServiceException):
    code: str = "UnsupportedParameterType"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedPlatformType(ServiceException):
    code: str = "UnsupportedPlatformType"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400
    ReasonCode: String | None


AccountIdList = list[AccountId]


class AccountSharingInfo(TypedDict, total=False):
    AccountId: AccountId | None
    SharedDocumentVersion: SharedDocumentVersion | None


AccountSharingInfoList = list[AccountSharingInfo]
Accounts = list[Account]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]
CreatedDate = datetime
ExpirationDate = datetime


class Activation(TypedDict, total=False):
    ActivationId: ActivationId | None
    Description: ActivationDescription | None
    DefaultInstanceName: DefaultInstanceName | None
    IamRole: IamRole | None
    RegistrationLimit: RegistrationLimit | None
    RegistrationsCount: RegistrationsCount | None
    ExpirationDate: ExpirationDate | None
    Expired: Boolean | None
    CreatedDate: CreatedDate | None
    Tags: TagList | None


ActivationList = list[Activation]


class AddTagsToResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId
    Tags: TagList


class AddTagsToResourceResult(TypedDict, total=False):
    pass


class Alarm(TypedDict, total=False):
    Name: AlarmName


AlarmList = list[Alarm]


class AlarmConfiguration(TypedDict, total=False):
    IgnorePollAlarmFailure: Boolean | None
    Alarms: AlarmList


class AlarmStateInformation(TypedDict, total=False):
    Name: AlarmName
    State: ExternalAlarmState


AlarmStateInformationList = list[AlarmStateInformation]


class AssociateOpsItemRelatedItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    AssociationType: OpsItemRelatedItemAssociationType
    ResourceType: OpsItemRelatedItemAssociationResourceType
    ResourceUri: OpsItemRelatedItemAssociationResourceUri


class AssociateOpsItemRelatedItemResponse(TypedDict, total=False):
    AssociationId: OpsItemRelatedItemAssociationId | None


TargetMapValueList = list[TargetMapValue]
TargetMap = dict[TargetMapKey, TargetMapValueList]
TargetMaps = list[TargetMap]
AssociationStatusAggregatedCount = dict[StatusName, InstanceCount]


class AssociationOverview(TypedDict, total=False):
    Status: StatusName | None
    DetailedStatus: StatusName | None
    AssociationStatusAggregatedCount: AssociationStatusAggregatedCount | None


DateTime = datetime
TargetValues = list[TargetValue]


class Target(TypedDict, total=False):
    Key: TargetKey | None
    Values: TargetValues | None


Targets = list[Target]


class Association(TypedDict, total=False):
    Name: DocumentARN | None
    InstanceId: InstanceId | None
    AssociationId: AssociationId | None
    AssociationVersion: AssociationVersion | None
    DocumentVersion: DocumentVersion | None
    Targets: Targets | None
    LastExecutionDate: DateTime | None
    Overview: AssociationOverview | None
    ScheduleExpression: ScheduleExpression | None
    AssociationName: AssociationName | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None


ExcludeAccounts = list[ExcludeAccount]
Regions = list[Region]


class TargetLocation(TypedDict, total=False):
    Accounts: Accounts | None
    Regions: Regions | None
    TargetLocationMaxConcurrency: MaxConcurrency | None
    TargetLocationMaxErrors: MaxErrors | None
    ExecutionRoleName: ExecutionRoleName | None
    TargetLocationAlarmConfiguration: AlarmConfiguration | None
    IncludeChildOrganizationUnits: Boolean | None
    ExcludeAccounts: ExcludeAccounts | None
    Targets: Targets | None
    TargetsMaxConcurrency: MaxConcurrency | None
    TargetsMaxErrors: MaxErrors | None


TargetLocations = list[TargetLocation]
CalendarNameOrARNList = list[CalendarNameOrARN]


class S3OutputLocation(TypedDict, total=False):
    OutputS3Region: S3Region | None
    OutputS3BucketName: S3BucketName | None
    OutputS3KeyPrefix: S3KeyPrefix | None


class InstanceAssociationOutputLocation(TypedDict, total=False):
    S3Location: S3OutputLocation | None


ParameterValueList = list[ParameterValue]
Parameters = dict[ParameterName, ParameterValueList]


class AssociationStatus(TypedDict, total=False):
    Date: DateTime
    Name: AssociationStatusName
    Message: StatusMessage
    AdditionalInfo: StatusAdditionalInfo | None


class AssociationDescription(TypedDict, total=False):
    Name: DocumentARN | None
    InstanceId: InstanceId | None
    AssociationVersion: AssociationVersion | None
    Date: DateTime | None
    LastUpdateAssociationDate: DateTime | None
    Status: AssociationStatus | None
    Overview: AssociationOverview | None
    DocumentVersion: DocumentVersion | None
    AutomationTargetParameterName: AutomationTargetParameterName | None
    Parameters: Parameters | None
    AssociationId: AssociationId | None
    Targets: Targets | None
    ScheduleExpression: ScheduleExpression | None
    OutputLocation: InstanceAssociationOutputLocation | None
    LastExecutionDate: DateTime | None
    LastSuccessfulExecutionDate: DateTime | None
    AssociationName: AssociationName | None
    MaxErrors: MaxErrors | None
    MaxConcurrency: MaxConcurrency | None
    ComplianceSeverity: AssociationComplianceSeverity | None
    SyncCompliance: AssociationSyncCompliance | None
    ApplyOnlyAtCronInterval: ApplyOnlyAtCronInterval | None
    CalendarNames: CalendarNameOrARNList | None
    TargetLocations: TargetLocations | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None


AssociationDescriptionList = list[AssociationDescription]


class AssociationExecution(TypedDict, total=False):
    AssociationId: AssociationId | None
    AssociationVersion: AssociationVersion | None
    ExecutionId: AssociationExecutionId | None
    Status: StatusName | None
    DetailedStatus: StatusName | None
    CreatedTime: DateTime | None
    LastExecutionDate: DateTime | None
    ResourceCountByStatus: ResourceCountByStatus | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None


class AssociationExecutionFilter(TypedDict, total=False):
    Key: AssociationExecutionFilterKey
    Value: AssociationExecutionFilterValue
    Type: AssociationFilterOperatorType


AssociationExecutionFilterList = list[AssociationExecutionFilter]


class OutputSource(TypedDict, total=False):
    OutputSourceId: OutputSourceId | None
    OutputSourceType: OutputSourceType | None


class AssociationExecutionTarget(TypedDict, total=False):
    AssociationId: AssociationId | None
    AssociationVersion: AssociationVersion | None
    ExecutionId: AssociationExecutionId | None
    ResourceId: AssociationResourceId | None
    ResourceType: AssociationResourceType | None
    Status: StatusName | None
    DetailedStatus: StatusName | None
    LastExecutionDate: DateTime | None
    OutputSource: OutputSource | None


class AssociationExecutionTargetsFilter(TypedDict, total=False):
    Key: AssociationExecutionTargetsFilterKey
    Value: AssociationExecutionTargetsFilterValue


AssociationExecutionTargetsFilterList = list[AssociationExecutionTargetsFilter]
AssociationExecutionTargetsList = list[AssociationExecutionTarget]
AssociationExecutionsList = list[AssociationExecution]


class AssociationFilter(TypedDict, total=False):
    key: AssociationFilterKey
    value: AssociationFilterValue


AssociationFilterList = list[AssociationFilter]
AssociationIdList = list[AssociationId]
AssociationList = list[Association]


class AssociationVersionInfo(TypedDict, total=False):
    AssociationId: AssociationId | None
    AssociationVersion: AssociationVersion | None
    CreatedDate: DateTime | None
    Name: DocumentARN | None
    DocumentVersion: DocumentVersion | None
    Parameters: Parameters | None
    Targets: Targets | None
    ScheduleExpression: ScheduleExpression | None
    OutputLocation: InstanceAssociationOutputLocation | None
    AssociationName: AssociationName | None
    MaxErrors: MaxErrors | None
    MaxConcurrency: MaxConcurrency | None
    ComplianceSeverity: AssociationComplianceSeverity | None
    SyncCompliance: AssociationSyncCompliance | None
    ApplyOnlyAtCronInterval: ApplyOnlyAtCronInterval | None
    CalendarNames: CalendarNameOrARNList | None
    TargetLocations: TargetLocations | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None


AssociationVersionList = list[AssociationVersionInfo]
ContentLength = int


class AttachmentContent(TypedDict, total=False):
    Name: AttachmentName | None
    Size: ContentLength | None
    Hash: AttachmentHash | None
    HashType: AttachmentHashType | None
    Url: AttachmentUrl | None


AttachmentContentList = list[AttachmentContent]


class AttachmentInformation(TypedDict, total=False):
    Name: AttachmentName | None


AttachmentInformationList = list[AttachmentInformation]
AttachmentsSourceValues = list[AttachmentsSourceValue]


class AttachmentsSource(TypedDict, total=False):
    Key: AttachmentsSourceKey | None
    Values: AttachmentsSourceValues | None
    Name: AttachmentIdentifier | None


AttachmentsSourceList = list[AttachmentsSource]
AutomationParameterValueList = list[AutomationParameterValue]
AutomationParameterMap = dict[AutomationParameterKey, AutomationParameterValueList]


class Runbook(TypedDict, total=False):
    DocumentName: DocumentARN
    DocumentVersion: DocumentVersion | None
    Parameters: AutomationParameterMap | None
    TargetParameterName: AutomationParameterKey | None
    Targets: Targets | None
    TargetMaps: TargetMaps | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    TargetLocations: TargetLocations | None


Runbooks = list[Runbook]


class ProgressCounters(TypedDict, total=False):
    TotalSteps: Integer | None
    SuccessSteps: Integer | None
    FailedSteps: Integer | None
    CancelledSteps: Integer | None
    TimedOutSteps: Integer | None


TargetParameterList = list[ParameterValue]


class ResolvedTargets(TypedDict, total=False):
    ParameterValues: TargetParameterList | None
    Truncated: Boolean | None


class ParentStepDetails(TypedDict, total=False):
    StepExecutionId: String | None
    StepName: String | None
    Action: AutomationActionName | None
    Iteration: Integer | None
    IteratorValue: String | None


ValidNextStepList = list[ValidNextStep]


class FailureDetails(TypedDict, total=False):
    FailureStage: String | None
    FailureType: String | None
    Details: AutomationParameterMap | None


NormalStringMap = dict[String, String]
Long = int


class StepExecution(TypedDict, total=False):
    StepName: String | None
    Action: AutomationActionName | None
    TimeoutSeconds: Long | None
    OnFailure: String | None
    MaxAttempts: Integer | None
    ExecutionStartTime: DateTime | None
    ExecutionEndTime: DateTime | None
    StepStatus: AutomationExecutionStatus | None
    ResponseCode: String | None
    Inputs: NormalStringMap | None
    Outputs: AutomationParameterMap | None
    Response: String | None
    FailureMessage: String | None
    FailureDetails: FailureDetails | None
    StepExecutionId: String | None
    OverriddenParameters: AutomationParameterMap | None
    IsEnd: Boolean | None
    NextStep: String | None
    IsCritical: Boolean | None
    ValidNextSteps: ValidNextStepList | None
    Targets: Targets | None
    TargetLocation: TargetLocation | None
    TriggeredAlarms: AlarmStateInformationList | None
    ParentStepDetails: ParentStepDetails | None


StepExecutionList = list[StepExecution]


class AutomationExecution(TypedDict, total=False):
    AutomationExecutionId: AutomationExecutionId | None
    DocumentName: DocumentName | None
    DocumentVersion: DocumentVersion | None
    ExecutionStartTime: DateTime | None
    ExecutionEndTime: DateTime | None
    AutomationExecutionStatus: AutomationExecutionStatus | None
    StepExecutions: StepExecutionList | None
    StepExecutionsTruncated: Boolean | None
    Parameters: AutomationParameterMap | None
    Outputs: AutomationParameterMap | None
    FailureMessage: String | None
    Mode: ExecutionMode | None
    ParentAutomationExecutionId: AutomationExecutionId | None
    ExecutedBy: String | None
    CurrentStepName: String | None
    CurrentAction: String | None
    TargetParameterName: AutomationParameterKey | None
    Targets: Targets | None
    TargetMaps: TargetMaps | None
    ResolvedTargets: ResolvedTargets | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    Target: String | None
    TargetLocations: TargetLocations | None
    ProgressCounters: ProgressCounters | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None
    TargetLocationsURL: TargetLocationsURL | None
    AutomationSubtype: AutomationSubtype | None
    ScheduledTime: DateTime | None
    Runbooks: Runbooks | None
    OpsItemId: String | None
    AssociationId: String | None
    ChangeRequestName: ChangeRequestName | None
    Variables: AutomationParameterMap | None


AutomationExecutionFilterValueList = list[AutomationExecutionFilterValue]


class AutomationExecutionFilter(TypedDict, total=False):
    Key: AutomationExecutionFilterKey
    Values: AutomationExecutionFilterValueList


AutomationExecutionFilterList = list[AutomationExecutionFilter]


class AutomationExecutionInputs(TypedDict, total=False):
    Parameters: AutomationParameterMap | None
    TargetParameterName: AutomationParameterKey | None
    Targets: Targets | None
    TargetMaps: TargetMaps | None
    TargetLocations: TargetLocations | None
    TargetLocationsURL: TargetLocationsURL | None


class AutomationExecutionMetadata(TypedDict, total=False):
    AutomationExecutionId: AutomationExecutionId | None
    DocumentName: DocumentName | None
    DocumentVersion: DocumentVersion | None
    AutomationExecutionStatus: AutomationExecutionStatus | None
    ExecutionStartTime: DateTime | None
    ExecutionEndTime: DateTime | None
    ExecutedBy: String | None
    LogFile: String | None
    Outputs: AutomationParameterMap | None
    Mode: ExecutionMode | None
    ParentAutomationExecutionId: AutomationExecutionId | None
    CurrentStepName: String | None
    CurrentAction: String | None
    FailureMessage: String | None
    TargetParameterName: AutomationParameterKey | None
    Targets: Targets | None
    TargetMaps: TargetMaps | None
    ResolvedTargets: ResolvedTargets | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    Target: String | None
    AutomationType: AutomationType | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None
    TargetLocationsURL: TargetLocationsURL | None
    AutomationSubtype: AutomationSubtype | None
    ScheduledTime: DateTime | None
    Runbooks: Runbooks | None
    OpsItemId: String | None
    AssociationId: String | None
    ChangeRequestName: ChangeRequestName | None


AutomationExecutionMetadataList = list[AutomationExecutionMetadata]


class TargetPreview(TypedDict, total=False):
    Count: Integer | None
    TargetType: String | None


TargetPreviewList = list[TargetPreview]
RegionList = list[Region]
StepPreviewMap = dict[ImpactType, Integer]


class AutomationExecutionPreview(TypedDict, total=False):
    StepPreviews: StepPreviewMap | None
    Regions: RegionList | None
    TargetPreviews: TargetPreviewList | None
    TotalAccounts: Integer | None


PatchSourceProductList = list[PatchSourceProduct]


class PatchSource(TypedDict, total=False):
    Name: PatchSourceName
    Products: PatchSourceProductList
    Configuration: PatchSourceConfiguration


PatchSourceList = list[PatchSource]
PatchIdList = list[PatchId]
PatchFilterValueList = list[PatchFilterValue]


class PatchFilter(TypedDict, total=False):
    Key: PatchFilterKey
    Values: PatchFilterValueList


PatchFilterList = list[PatchFilter]


class PatchFilterGroup(TypedDict, total=False):
    PatchFilters: PatchFilterList


class PatchRule(TypedDict, total=False):
    PatchFilterGroup: PatchFilterGroup
    ComplianceLevel: PatchComplianceLevel | None
    ApproveAfterDays: ApproveAfterDays | None
    ApproveUntilDate: PatchStringDateTime | None
    EnableNonSecurity: Boolean | None


PatchRuleList = list[PatchRule]


class PatchRuleGroup(TypedDict, total=False):
    PatchRules: PatchRuleList


class BaselineOverride(TypedDict, total=False):
    OperatingSystem: OperatingSystem | None
    GlobalFilters: PatchFilterGroup | None
    ApprovalRules: PatchRuleGroup | None
    ApprovedPatches: PatchIdList | None
    ApprovedPatchesComplianceLevel: PatchComplianceLevel | None
    RejectedPatches: PatchIdList | None
    RejectedPatchesAction: PatchAction | None
    ApprovedPatchesEnableNonSecurity: Boolean | None
    Sources: PatchSourceList | None
    AvailableSecurityUpdatesComplianceStatus: PatchComplianceStatus | None


InstanceIdList = list[InstanceId]


class CancelCommandRequest(ServiceRequest):
    CommandId: CommandId
    InstanceIds: InstanceIdList | None


class CancelCommandResult(TypedDict, total=False):
    pass


class CancelMaintenanceWindowExecutionRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId


class CancelMaintenanceWindowExecutionResult(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None


CategoryEnumList = list[Category]
CategoryList = list[Category]


class CloudWatchOutputConfig(TypedDict, total=False):
    CloudWatchLogGroupName: CloudWatchLogGroupName | None
    CloudWatchOutputEnabled: CloudWatchOutputEnabled | None


NotificationEventList = list[NotificationEvent]


class NotificationConfig(TypedDict, total=False):
    NotificationArn: NotificationArn | None
    NotificationEvents: NotificationEventList | None
    NotificationType: NotificationType | None


class Command(TypedDict, total=False):
    CommandId: CommandId | None
    DocumentName: DocumentName | None
    DocumentVersion: DocumentVersion | None
    Comment: Comment | None
    ExpiresAfter: DateTime | None
    Parameters: Parameters | None
    InstanceIds: InstanceIdList | None
    Targets: Targets | None
    RequestedDateTime: DateTime | None
    Status: CommandStatus | None
    StatusDetails: StatusDetails | None
    OutputS3Region: S3Region | None
    OutputS3BucketName: S3BucketName | None
    OutputS3KeyPrefix: S3KeyPrefix | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    TargetCount: TargetCount | None
    CompletedCount: CompletedCount | None
    ErrorCount: ErrorCount | None
    DeliveryTimedOutCount: DeliveryTimedOutCount | None
    ServiceRole: ServiceRole | None
    NotificationConfig: NotificationConfig | None
    CloudWatchOutputConfig: CloudWatchOutputConfig | None
    TimeoutSeconds: TimeoutSeconds | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None


class CommandFilter(TypedDict, total=False):
    key: CommandFilterKey
    value: CommandFilterValue


CommandFilterList = list[CommandFilter]


class CommandPlugin(TypedDict, total=False):
    Name: CommandPluginName | None
    Status: CommandPluginStatus | None
    StatusDetails: StatusDetails | None
    ResponseCode: ResponseCode | None
    ResponseStartDateTime: DateTime | None
    ResponseFinishDateTime: DateTime | None
    Output: CommandPluginOutput | None
    StandardOutputUrl: Url | None
    StandardErrorUrl: Url | None
    OutputS3Region: S3Region | None
    OutputS3BucketName: S3BucketName | None
    OutputS3KeyPrefix: S3KeyPrefix | None


CommandPluginList = list[CommandPlugin]


class CommandInvocation(TypedDict, total=False):
    CommandId: CommandId | None
    InstanceId: InstanceId | None
    InstanceName: InstanceTagName | None
    Comment: Comment | None
    DocumentName: DocumentName | None
    DocumentVersion: DocumentVersion | None
    RequestedDateTime: DateTime | None
    Status: CommandInvocationStatus | None
    StatusDetails: StatusDetails | None
    TraceOutput: InvocationTraceOutput | None
    StandardOutputUrl: Url | None
    StandardErrorUrl: Url | None
    CommandPlugins: CommandPluginList | None
    ServiceRole: ServiceRole | None
    NotificationConfig: NotificationConfig | None
    CloudWatchOutputConfig: CloudWatchOutputConfig | None


CommandInvocationList = list[CommandInvocation]
CommandList = list[Command]


class ComplianceExecutionSummary(TypedDict, total=False):
    ExecutionTime: DateTime
    ExecutionId: ComplianceExecutionId | None
    ExecutionType: ComplianceExecutionType | None


ComplianceItemDetails = dict[AttributeName, AttributeValue]


class ComplianceItem(TypedDict, total=False):
    ComplianceType: ComplianceTypeName | None
    ResourceType: ComplianceResourceType | None
    ResourceId: ComplianceResourceId | None
    Id: ComplianceItemId | None
    Title: ComplianceItemTitle | None
    Status: ComplianceStatus | None
    Severity: ComplianceSeverity | None
    ExecutionSummary: ComplianceExecutionSummary | None
    Details: ComplianceItemDetails | None


class ComplianceItemEntry(TypedDict, total=False):
    Id: ComplianceItemId | None
    Title: ComplianceItemTitle | None
    Severity: ComplianceSeverity
    Status: ComplianceStatus
    Details: ComplianceItemDetails | None


ComplianceItemEntryList = list[ComplianceItemEntry]
ComplianceItemList = list[ComplianceItem]
ComplianceResourceIdList = list[ComplianceResourceId]
ComplianceResourceTypeList = list[ComplianceResourceType]
ComplianceStringFilterValueList = list[ComplianceFilterValue]


class ComplianceStringFilter(TypedDict, total=False):
    Key: ComplianceStringFilterKey | None
    Values: ComplianceStringFilterValueList | None
    Type: ComplianceQueryOperatorType | None


ComplianceStringFilterList = list[ComplianceStringFilter]


class SeveritySummary(TypedDict, total=False):
    CriticalCount: ComplianceSummaryCount | None
    HighCount: ComplianceSummaryCount | None
    MediumCount: ComplianceSummaryCount | None
    LowCount: ComplianceSummaryCount | None
    InformationalCount: ComplianceSummaryCount | None
    UnspecifiedCount: ComplianceSummaryCount | None


class NonCompliantSummary(TypedDict, total=False):
    NonCompliantCount: ComplianceSummaryCount | None
    SeveritySummary: SeveritySummary | None


class CompliantSummary(TypedDict, total=False):
    CompliantCount: ComplianceSummaryCount | None
    SeveritySummary: SeveritySummary | None


class ComplianceSummaryItem(TypedDict, total=False):
    ComplianceType: ComplianceTypeName | None
    CompliantSummary: CompliantSummary | None
    NonCompliantSummary: NonCompliantSummary | None


ComplianceSummaryItemList = list[ComplianceSummaryItem]


class RegistrationMetadataItem(TypedDict, total=False):
    Key: RegistrationMetadataKey
    Value: RegistrationMetadataValue


RegistrationMetadataList = list[RegistrationMetadataItem]


class CreateActivationRequest(ServiceRequest):
    Description: ActivationDescription | None
    DefaultInstanceName: DefaultInstanceName | None
    IamRole: IamRole
    RegistrationLimit: RegistrationLimit | None
    ExpirationDate: ExpirationDate | None
    Tags: TagList | None
    RegistrationMetadata: RegistrationMetadataList | None


class CreateActivationResult(TypedDict, total=False):
    ActivationId: ActivationId | None
    ActivationCode: ActivationCode | None


class CreateAssociationBatchRequestEntry(TypedDict, total=False):
    Name: DocumentARN
    InstanceId: InstanceId | None
    Parameters: Parameters | None
    AutomationTargetParameterName: AutomationTargetParameterName | None
    DocumentVersion: DocumentVersion | None
    Targets: Targets | None
    ScheduleExpression: ScheduleExpression | None
    OutputLocation: InstanceAssociationOutputLocation | None
    AssociationName: AssociationName | None
    MaxErrors: MaxErrors | None
    MaxConcurrency: MaxConcurrency | None
    ComplianceSeverity: AssociationComplianceSeverity | None
    SyncCompliance: AssociationSyncCompliance | None
    ApplyOnlyAtCronInterval: ApplyOnlyAtCronInterval | None
    CalendarNames: CalendarNameOrARNList | None
    TargetLocations: TargetLocations | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None
    AlarmConfiguration: AlarmConfiguration | None


CreateAssociationBatchRequestEntries = list[CreateAssociationBatchRequestEntry]


class CreateAssociationBatchRequest(ServiceRequest):
    Entries: CreateAssociationBatchRequestEntries


class FailedCreateAssociation(TypedDict, total=False):
    Entry: CreateAssociationBatchRequestEntry | None
    Message: BatchErrorMessage | None
    Fault: Fault | None


FailedCreateAssociationList = list[FailedCreateAssociation]


class CreateAssociationBatchResult(TypedDict, total=False):
    Successful: AssociationDescriptionList | None
    Failed: FailedCreateAssociationList | None


class CreateAssociationRequest(ServiceRequest):
    Name: DocumentARN
    DocumentVersion: DocumentVersion | None
    InstanceId: InstanceId | None
    Parameters: Parameters | None
    Targets: Targets | None
    ScheduleExpression: ScheduleExpression | None
    OutputLocation: InstanceAssociationOutputLocation | None
    AssociationName: AssociationName | None
    AutomationTargetParameterName: AutomationTargetParameterName | None
    MaxErrors: MaxErrors | None
    MaxConcurrency: MaxConcurrency | None
    ComplianceSeverity: AssociationComplianceSeverity | None
    SyncCompliance: AssociationSyncCompliance | None
    ApplyOnlyAtCronInterval: ApplyOnlyAtCronInterval | None
    CalendarNames: CalendarNameOrARNList | None
    TargetLocations: TargetLocations | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None
    Tags: TagList | None
    AlarmConfiguration: AlarmConfiguration | None


class CreateAssociationResult(TypedDict, total=False):
    AssociationDescription: AssociationDescription | None


class DocumentRequires(TypedDict, total=False):
    Name: DocumentARN
    Version: DocumentVersion | None
    RequireType: RequireType | None
    VersionName: DocumentVersionName | None


DocumentRequiresList = list[DocumentRequires]


class CreateDocumentRequest(ServiceRequest):
    Content: DocumentContent
    Requires: DocumentRequiresList | None
    Attachments: AttachmentsSourceList | None
    Name: DocumentName
    DisplayName: DocumentDisplayName | None
    VersionName: DocumentVersionName | None
    DocumentType: DocumentType | None
    DocumentFormat: DocumentFormat | None
    TargetType: TargetType | None
    Tags: TagList | None


class ReviewInformation(TypedDict, total=False):
    ReviewedTime: DateTime | None
    Status: ReviewStatus | None
    Reviewer: Reviewer | None


ReviewInformationList = list[ReviewInformation]
PlatformTypeList = list[PlatformType]


class DocumentParameter(TypedDict, total=False):
    Name: DocumentParameterName | None
    Type: DocumentParameterType | None
    Description: DocumentParameterDescrption | None
    DefaultValue: DocumentParameterDefaultValue | None


DocumentParameterList = list[DocumentParameter]


class DocumentDescription(TypedDict, total=False):
    Sha1: DocumentSha1 | None
    Hash: DocumentHash | None
    HashType: DocumentHashType | None
    Name: DocumentARN | None
    DisplayName: DocumentDisplayName | None
    VersionName: DocumentVersionName | None
    Owner: DocumentOwner | None
    CreatedDate: DateTime | None
    Status: DocumentStatus | None
    StatusInformation: DocumentStatusInformation | None
    DocumentVersion: DocumentVersion | None
    Description: DescriptionInDocument | None
    Parameters: DocumentParameterList | None
    PlatformTypes: PlatformTypeList | None
    DocumentType: DocumentType | None
    SchemaVersion: DocumentSchemaVersion | None
    LatestVersion: DocumentVersion | None
    DefaultVersion: DocumentVersion | None
    DocumentFormat: DocumentFormat | None
    TargetType: TargetType | None
    Tags: TagList | None
    AttachmentsInformation: AttachmentInformationList | None
    Requires: DocumentRequiresList | None
    Author: DocumentAuthor | None
    ReviewInformation: ReviewInformationList | None
    ApprovedVersion: DocumentVersion | None
    PendingReviewVersion: DocumentVersion | None
    ReviewStatus: ReviewStatus | None
    Category: CategoryList | None
    CategoryEnum: CategoryEnumList | None


class CreateDocumentResult(TypedDict, total=False):
    DocumentDescription: DocumentDescription | None


class CreateMaintenanceWindowRequest(ServiceRequest):
    Name: MaintenanceWindowName
    Description: MaintenanceWindowDescription | None
    StartDate: MaintenanceWindowStringDateTime | None
    EndDate: MaintenanceWindowStringDateTime | None
    Schedule: MaintenanceWindowSchedule
    ScheduleTimezone: MaintenanceWindowTimezone | None
    ScheduleOffset: MaintenanceWindowOffset | None
    Duration: MaintenanceWindowDurationHours
    Cutoff: MaintenanceWindowCutoff
    AllowUnassociatedTargets: MaintenanceWindowAllowUnassociatedTargets
    ClientToken: ClientToken | None
    Tags: TagList | None


class CreateMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None


class RelatedOpsItem(TypedDict, total=False):
    OpsItemId: String


RelatedOpsItems = list[RelatedOpsItem]


class OpsItemNotification(TypedDict, total=False):
    Arn: String | None


OpsItemNotifications = list[OpsItemNotification]


class OpsItemDataValue(TypedDict, total=False):
    Value: OpsItemDataValueString | None
    Type: OpsItemDataType | None


OpsItemOperationalData = dict[OpsItemDataKey, OpsItemDataValue]


class CreateOpsItemRequest(ServiceRequest):
    Description: OpsItemDescription
    OpsItemType: OpsItemType | None
    OperationalData: OpsItemOperationalData | None
    Notifications: OpsItemNotifications | None
    Priority: OpsItemPriority | None
    RelatedOpsItems: RelatedOpsItems | None
    Source: OpsItemSource
    Title: OpsItemTitle
    Tags: TagList | None
    Category: OpsItemCategory | None
    Severity: OpsItemSeverity | None
    ActualStartTime: DateTime | None
    ActualEndTime: DateTime | None
    PlannedStartTime: DateTime | None
    PlannedEndTime: DateTime | None
    AccountId: OpsItemAccountId | None


class CreateOpsItemResponse(TypedDict, total=False):
    OpsItemId: String | None
    OpsItemArn: OpsItemArn | None


class MetadataValue(TypedDict, total=False):
    Value: MetadataValueString | None


MetadataMap = dict[MetadataKey, MetadataValue]


class CreateOpsMetadataRequest(ServiceRequest):
    ResourceId: OpsMetadataResourceId
    Metadata: MetadataMap | None
    Tags: TagList | None


class CreateOpsMetadataResult(TypedDict, total=False):
    OpsMetadataArn: OpsMetadataArn | None


class CreatePatchBaselineRequest(ServiceRequest):
    OperatingSystem: OperatingSystem | None
    Name: BaselineName
    GlobalFilters: PatchFilterGroup | None
    ApprovalRules: PatchRuleGroup | None
    ApprovedPatches: PatchIdList | None
    ApprovedPatchesComplianceLevel: PatchComplianceLevel | None
    ApprovedPatchesEnableNonSecurity: Boolean | None
    RejectedPatches: PatchIdList | None
    RejectedPatchesAction: PatchAction | None
    Description: BaselineDescription | None
    Sources: PatchSourceList | None
    AvailableSecurityUpdatesComplianceStatus: PatchComplianceStatus | None
    ClientToken: ClientToken | None
    Tags: TagList | None


class CreatePatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None


ResourceDataSyncSourceRegionList = list[ResourceDataSyncSourceRegion]


class ResourceDataSyncOrganizationalUnit(TypedDict, total=False):
    OrganizationalUnitId: ResourceDataSyncOrganizationalUnitId | None


ResourceDataSyncOrganizationalUnitList = list[ResourceDataSyncOrganizationalUnit]


class ResourceDataSyncAwsOrganizationsSource(TypedDict, total=False):
    OrganizationSourceType: ResourceDataSyncOrganizationSourceType
    OrganizationalUnits: ResourceDataSyncOrganizationalUnitList | None


class ResourceDataSyncSource(TypedDict, total=False):
    SourceType: ResourceDataSyncSourceType
    AwsOrganizationsSource: ResourceDataSyncAwsOrganizationsSource | None
    SourceRegions: ResourceDataSyncSourceRegionList
    IncludeFutureRegions: ResourceDataSyncIncludeFutureRegions | None
    EnableAllOpsDataSources: ResourceDataSyncEnableAllOpsDataSources | None


class ResourceDataSyncDestinationDataSharing(TypedDict, total=False):
    DestinationDataSharingType: ResourceDataSyncDestinationDataSharingType | None


class ResourceDataSyncS3Destination(TypedDict, total=False):
    BucketName: ResourceDataSyncS3BucketName
    Prefix: ResourceDataSyncS3Prefix | None
    SyncFormat: ResourceDataSyncS3Format
    Region: ResourceDataSyncS3Region
    AWSKMSKeyARN: ResourceDataSyncAWSKMSKeyARN | None
    DestinationDataSharing: ResourceDataSyncDestinationDataSharing | None


class CreateResourceDataSyncRequest(ServiceRequest):
    SyncName: ResourceDataSyncName
    S3Destination: ResourceDataSyncS3Destination | None
    SyncType: ResourceDataSyncType | None
    SyncSource: ResourceDataSyncSource | None


class CreateResourceDataSyncResult(TypedDict, total=False):
    pass


class Credentials(TypedDict, total=False):
    AccessKeyId: AccessKeyIdType
    SecretAccessKey: AccessKeySecretType
    SessionToken: SessionTokenType
    ExpirationTime: DateTime


class DeleteActivationRequest(ServiceRequest):
    ActivationId: ActivationId


class DeleteActivationResult(TypedDict, total=False):
    pass


class DeleteAssociationRequest(ServiceRequest):
    Name: DocumentARN | None
    InstanceId: InstanceId | None
    AssociationId: AssociationId | None


class DeleteAssociationResult(TypedDict, total=False):
    pass


class DeleteDocumentRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: DocumentVersion | None
    VersionName: DocumentVersionName | None
    Force: Boolean | None


class DeleteDocumentResult(TypedDict, total=False):
    pass


class DeleteInventoryRequest(ServiceRequest):
    TypeName: InventoryItemTypeName
    SchemaDeleteOption: InventorySchemaDeleteOption | None
    DryRun: DryRun | None
    ClientToken: UUID | None


class InventoryDeletionSummaryItem(TypedDict, total=False):
    Version: InventoryItemSchemaVersion | None
    Count: ResourceCount | None
    RemainingCount: RemainingCount | None


InventoryDeletionSummaryItems = list[InventoryDeletionSummaryItem]


class InventoryDeletionSummary(TypedDict, total=False):
    TotalCount: TotalCount | None
    RemainingCount: RemainingCount | None
    SummaryItems: InventoryDeletionSummaryItems | None


class DeleteInventoryResult(TypedDict, total=False):
    DeletionId: UUID | None
    TypeName: InventoryItemTypeName | None
    DeletionSummary: InventoryDeletionSummary | None


class DeleteMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId


class DeleteMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None


class DeleteOpsItemRequest(ServiceRequest):
    OpsItemId: OpsItemId


class DeleteOpsItemResponse(TypedDict, total=False):
    pass


class DeleteOpsMetadataRequest(ServiceRequest):
    OpsMetadataArn: OpsMetadataArn


class DeleteOpsMetadataResult(TypedDict, total=False):
    pass


class DeleteParameterRequest(ServiceRequest):
    Name: PSParameterName


class DeleteParameterResult(TypedDict, total=False):
    pass


ParameterNameList = list[PSParameterName]


class DeleteParametersRequest(ServiceRequest):
    Names: ParameterNameList


class DeleteParametersResult(TypedDict, total=False):
    DeletedParameters: ParameterNameList | None
    InvalidParameters: ParameterNameList | None


class DeletePatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


class DeletePatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None


class DeleteResourceDataSyncRequest(ServiceRequest):
    SyncName: ResourceDataSyncName
    SyncType: ResourceDataSyncType | None


class DeleteResourceDataSyncResult(TypedDict, total=False):
    pass


class DeleteResourcePolicyRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    PolicyId: PolicyId
    PolicyHash: PolicyHash


class DeleteResourcePolicyResponse(TypedDict, total=False):
    pass


class DeregisterManagedInstanceRequest(ServiceRequest):
    InstanceId: ManagedInstanceId


class DeregisterManagedInstanceResult(TypedDict, total=False):
    pass


class DeregisterPatchBaselineForPatchGroupRequest(ServiceRequest):
    BaselineId: BaselineId
    PatchGroup: PatchGroup


class DeregisterPatchBaselineForPatchGroupResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    PatchGroup: PatchGroup | None


class DeregisterTargetFromMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTargetId: MaintenanceWindowTargetId
    Safe: Boolean | None


class DeregisterTargetFromMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTargetId: MaintenanceWindowTargetId | None


class DeregisterTaskFromMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId


class DeregisterTaskFromMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTaskId: MaintenanceWindowTaskId | None


StringList = list[String]


class DescribeActivationsFilter(TypedDict, total=False):
    FilterKey: DescribeActivationsFilterKeys | None
    FilterValues: StringList | None


DescribeActivationsFilterList = list[DescribeActivationsFilter]


class DescribeActivationsRequest(ServiceRequest):
    Filters: DescribeActivationsFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class DescribeActivationsResult(TypedDict, total=False):
    ActivationList: ActivationList | None
    NextToken: NextToken | None


class DescribeAssociationExecutionTargetsRequest(ServiceRequest):
    AssociationId: AssociationId
    ExecutionId: AssociationExecutionId
    Filters: AssociationExecutionTargetsFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class DescribeAssociationExecutionTargetsResult(TypedDict, total=False):
    AssociationExecutionTargets: AssociationExecutionTargetsList | None
    NextToken: NextToken | None


class DescribeAssociationExecutionsRequest(ServiceRequest):
    AssociationId: AssociationId
    Filters: AssociationExecutionFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class DescribeAssociationExecutionsResult(TypedDict, total=False):
    AssociationExecutions: AssociationExecutionsList | None
    NextToken: NextToken | None


class DescribeAssociationRequest(ServiceRequest):
    Name: DocumentARN | None
    InstanceId: InstanceId | None
    AssociationId: AssociationId | None
    AssociationVersion: AssociationVersion | None


class DescribeAssociationResult(TypedDict, total=False):
    AssociationDescription: AssociationDescription | None


class DescribeAutomationExecutionsRequest(ServiceRequest):
    Filters: AutomationExecutionFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class DescribeAutomationExecutionsResult(TypedDict, total=False):
    AutomationExecutionMetadataList: AutomationExecutionMetadataList | None
    NextToken: NextToken | None


StepExecutionFilterValueList = list[StepExecutionFilterValue]


class StepExecutionFilter(TypedDict, total=False):
    Key: StepExecutionFilterKey
    Values: StepExecutionFilterValueList


StepExecutionFilterList = list[StepExecutionFilter]


class DescribeAutomationStepExecutionsRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    Filters: StepExecutionFilterList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    ReverseOrder: Boolean | None


class DescribeAutomationStepExecutionsResult(TypedDict, total=False):
    StepExecutions: StepExecutionList | None
    NextToken: NextToken | None


PatchOrchestratorFilterValues = list[PatchOrchestratorFilterValue]


class PatchOrchestratorFilter(TypedDict, total=False):
    Key: PatchOrchestratorFilterKey | None
    Values: PatchOrchestratorFilterValues | None


PatchOrchestratorFilterList = list[PatchOrchestratorFilter]


class DescribeAvailablePatchesRequest(ServiceRequest):
    Filters: PatchOrchestratorFilterList | None
    MaxResults: PatchBaselineMaxResults | None
    NextToken: NextToken | None


PatchCVEIdList = list[PatchCVEId]
PatchBugzillaIdList = list[PatchBugzillaId]
PatchAdvisoryIdList = list[PatchAdvisoryId]


class Patch(TypedDict, total=False):
    Id: PatchId | None
    ReleaseDate: DateTime | None
    Title: PatchTitle | None
    Description: PatchDescription | None
    ContentUrl: PatchContentUrl | None
    Vendor: PatchVendor | None
    ProductFamily: PatchProductFamily | None
    Product: PatchProduct | None
    Classification: PatchClassification | None
    MsrcSeverity: PatchMsrcSeverity | None
    KbNumber: PatchKbNumber | None
    MsrcNumber: PatchMsrcNumber | None
    Language: PatchLanguage | None
    AdvisoryIds: PatchAdvisoryIdList | None
    BugzillaIds: PatchBugzillaIdList | None
    CVEIds: PatchCVEIdList | None
    Name: PatchName | None
    Epoch: PatchEpoch | None
    Version: PatchVersion | None
    Release: PatchRelease | None
    Arch: PatchArch | None
    Severity: PatchSeverity | None
    Repository: PatchRepository | None


PatchList = list[Patch]


class DescribeAvailablePatchesResult(TypedDict, total=False):
    Patches: PatchList | None
    NextToken: NextToken | None


class DescribeDocumentPermissionRequest(ServiceRequest):
    Name: DocumentName
    PermissionType: DocumentPermissionType
    MaxResults: DocumentPermissionMaxResults | None
    NextToken: NextToken | None


class DescribeDocumentPermissionResponse(TypedDict, total=False):
    AccountIds: AccountIdList | None
    AccountSharingInfoList: AccountSharingInfoList | None
    NextToken: NextToken | None


class DescribeDocumentRequest(ServiceRequest):
    Name: DocumentARN
    DocumentVersion: DocumentVersion | None
    VersionName: DocumentVersionName | None


class DescribeDocumentResult(TypedDict, total=False):
    Document: DocumentDescription | None


class DescribeEffectiveInstanceAssociationsRequest(ServiceRequest):
    InstanceId: InstanceId
    MaxResults: EffectiveInstanceAssociationMaxResults | None
    NextToken: NextToken | None


class InstanceAssociation(TypedDict, total=False):
    AssociationId: AssociationId | None
    InstanceId: InstanceId | None
    Content: DocumentContent | None
    AssociationVersion: AssociationVersion | None


InstanceAssociationList = list[InstanceAssociation]


class DescribeEffectiveInstanceAssociationsResult(TypedDict, total=False):
    Associations: InstanceAssociationList | None
    NextToken: NextToken | None


class DescribeEffectivePatchesForPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId
    MaxResults: PatchBaselineMaxResults | None
    NextToken: NextToken | None


class PatchStatus(TypedDict, total=False):
    DeploymentStatus: PatchDeploymentStatus | None
    ComplianceLevel: PatchComplianceLevel | None
    ApprovalDate: DateTime | None


class EffectivePatch(TypedDict, total=False):
    Patch: Patch | None
    PatchStatus: PatchStatus | None


EffectivePatchList = list[EffectivePatch]


class DescribeEffectivePatchesForPatchBaselineResult(TypedDict, total=False):
    EffectivePatches: EffectivePatchList | None
    NextToken: NextToken | None


class DescribeInstanceAssociationsStatusRequest(ServiceRequest):
    InstanceId: InstanceId
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class S3OutputUrl(TypedDict, total=False):
    OutputUrl: Url | None


class InstanceAssociationOutputUrl(TypedDict, total=False):
    S3OutputUrl: S3OutputUrl | None


class InstanceAssociationStatusInfo(TypedDict, total=False):
    AssociationId: AssociationId | None
    Name: DocumentARN | None
    DocumentVersion: DocumentVersion | None
    AssociationVersion: AssociationVersion | None
    InstanceId: InstanceId | None
    ExecutionDate: DateTime | None
    Status: StatusName | None
    DetailedStatus: StatusName | None
    ExecutionSummary: InstanceAssociationExecutionSummary | None
    ErrorCode: AgentErrorCode | None
    OutputUrl: InstanceAssociationOutputUrl | None
    AssociationName: AssociationName | None


InstanceAssociationStatusInfos = list[InstanceAssociationStatusInfo]


class DescribeInstanceAssociationsStatusResult(TypedDict, total=False):
    InstanceAssociationStatusInfos: InstanceAssociationStatusInfos | None
    NextToken: NextToken | None


InstanceInformationFilterValueSet = list[InstanceInformationFilterValue]


class InstanceInformationStringFilter(TypedDict, total=False):
    Key: InstanceInformationStringFilterKey
    Values: InstanceInformationFilterValueSet


InstanceInformationStringFilterList = list[InstanceInformationStringFilter]


class InstanceInformationFilter(TypedDict, total=False):
    key: InstanceInformationFilterKey
    valueSet: InstanceInformationFilterValueSet


InstanceInformationFilterList = list[InstanceInformationFilter]


class DescribeInstanceInformationRequest(ServiceRequest):
    InstanceInformationFilterList: InstanceInformationFilterList | None
    Filters: InstanceInformationStringFilterList | None
    MaxResults: MaxResultsEC2Compatible | None
    NextToken: NextToken | None


InstanceAssociationStatusAggregatedCount = dict[StatusName, InstanceCount]


class InstanceAggregatedAssociationOverview(TypedDict, total=False):
    DetailedStatus: StatusName | None
    InstanceAssociationStatusAggregatedCount: InstanceAssociationStatusAggregatedCount | None


class InstanceInformation(TypedDict, total=False):
    InstanceId: InstanceId | None
    PingStatus: PingStatus | None
    LastPingDateTime: DateTime | None
    AgentVersion: Version | None
    IsLatestVersion: Boolean | None
    PlatformType: PlatformType | None
    PlatformName: String | None
    PlatformVersion: String | None
    ActivationId: ActivationId | None
    IamRole: IamRole | None
    RegistrationDate: DateTime | None
    ResourceType: ResourceType | None
    Name: String | None
    IPAddress: IPAddress | None
    ComputerName: ComputerName | None
    AssociationStatus: StatusName | None
    LastAssociationExecutionDate: DateTime | None
    LastSuccessfulAssociationExecutionDate: DateTime | None
    AssociationOverview: InstanceAggregatedAssociationOverview | None
    SourceId: SourceId | None
    SourceType: SourceType | None


InstanceInformationList = list[InstanceInformation]


class DescribeInstanceInformationResult(TypedDict, total=False):
    InstanceInformationList: InstanceInformationList | None
    NextToken: NextToken | None


InstancePatchStateFilterValues = list[InstancePatchStateFilterValue]


class InstancePatchStateFilter(TypedDict, total=False):
    Key: InstancePatchStateFilterKey
    Values: InstancePatchStateFilterValues
    Type: InstancePatchStateOperatorType


InstancePatchStateFilterList = list[InstancePatchStateFilter]


class DescribeInstancePatchStatesForPatchGroupRequest(ServiceRequest):
    PatchGroup: PatchGroup
    Filters: InstancePatchStateFilterList | None
    NextToken: NextToken | None
    MaxResults: PatchComplianceMaxResults | None


class InstancePatchState(TypedDict, total=False):
    InstanceId: InstanceId
    PatchGroup: PatchGroup
    BaselineId: BaselineId
    SnapshotId: SnapshotId | None
    InstallOverrideList: InstallOverrideList | None
    OwnerInformation: OwnerInformation | None
    InstalledCount: PatchInstalledCount | None
    InstalledOtherCount: PatchInstalledOtherCount | None
    InstalledPendingRebootCount: PatchInstalledPendingRebootCount | None
    InstalledRejectedCount: PatchInstalledRejectedCount | None
    MissingCount: PatchMissingCount | None
    FailedCount: PatchFailedCount | None
    UnreportedNotApplicableCount: PatchUnreportedNotApplicableCount | None
    NotApplicableCount: PatchNotApplicableCount | None
    AvailableSecurityUpdateCount: PatchAvailableSecurityUpdateCount | None
    OperationStartTime: DateTime
    OperationEndTime: DateTime
    Operation: PatchOperationType
    LastNoRebootInstallOperationTime: DateTime | None
    RebootOption: RebootOption | None
    CriticalNonCompliantCount: PatchCriticalNonCompliantCount | None
    SecurityNonCompliantCount: PatchSecurityNonCompliantCount | None
    OtherNonCompliantCount: PatchOtherNonCompliantCount | None


InstancePatchStatesList = list[InstancePatchState]


class DescribeInstancePatchStatesForPatchGroupResult(TypedDict, total=False):
    InstancePatchStates: InstancePatchStatesList | None
    NextToken: NextToken | None


class DescribeInstancePatchStatesRequest(ServiceRequest):
    InstanceIds: InstanceIdList
    NextToken: NextToken | None
    MaxResults: PatchComplianceMaxResults | None


InstancePatchStateList = list[InstancePatchState]


class DescribeInstancePatchStatesResult(TypedDict, total=False):
    InstancePatchStates: InstancePatchStateList | None
    NextToken: NextToken | None


class DescribeInstancePatchesRequest(ServiceRequest):
    InstanceId: InstanceId
    Filters: PatchOrchestratorFilterList | None
    NextToken: NextToken | None
    MaxResults: PatchComplianceMaxResults | None


class PatchComplianceData(TypedDict, total=False):
    Title: PatchTitle
    KBId: PatchKbNumber
    Classification: PatchClassification
    Severity: PatchSeverity
    State: PatchComplianceDataState
    InstalledTime: DateTime
    CVEIds: PatchCVEIds | None


PatchComplianceDataList = list[PatchComplianceData]


class DescribeInstancePatchesResult(TypedDict, total=False):
    Patches: PatchComplianceDataList | None
    NextToken: NextToken | None


InstancePropertyFilterValueSet = list[InstancePropertyFilterValue]


class InstancePropertyStringFilter(TypedDict, total=False):
    Key: InstancePropertyStringFilterKey
    Values: InstancePropertyFilterValueSet
    Operator: InstancePropertyFilterOperator | None


InstancePropertyStringFilterList = list[InstancePropertyStringFilter]


class InstancePropertyFilter(TypedDict, total=False):
    key: InstancePropertyFilterKey
    valueSet: InstancePropertyFilterValueSet


InstancePropertyFilterList = list[InstancePropertyFilter]


class DescribeInstancePropertiesRequest(ServiceRequest):
    InstancePropertyFilterList: InstancePropertyFilterList | None
    FiltersWithOperator: InstancePropertyStringFilterList | None
    MaxResults: DescribeInstancePropertiesMaxResults | None
    NextToken: NextToken | None


class InstanceProperty(TypedDict, total=False):
    Name: InstanceName | None
    InstanceId: InstanceId | None
    InstanceType: InstanceType | None
    InstanceRole: InstanceRole | None
    KeyName: KeyName | None
    InstanceState: InstanceState | None
    Architecture: Architecture | None
    IPAddress: IPAddress | None
    LaunchTime: DateTime | None
    PingStatus: PingStatus | None
    LastPingDateTime: DateTime | None
    AgentVersion: Version | None
    PlatformType: PlatformType | None
    PlatformName: PlatformName | None
    PlatformVersion: PlatformVersion | None
    ActivationId: ActivationId | None
    IamRole: IamRole | None
    RegistrationDate: DateTime | None
    ResourceType: String | None
    ComputerName: ComputerName | None
    AssociationStatus: StatusName | None
    LastAssociationExecutionDate: DateTime | None
    LastSuccessfulAssociationExecutionDate: DateTime | None
    AssociationOverview: InstanceAggregatedAssociationOverview | None
    SourceId: SourceId | None
    SourceType: SourceType | None


InstanceProperties = list[InstanceProperty]


class DescribeInstancePropertiesResult(TypedDict, total=False):
    InstanceProperties: InstanceProperties | None
    NextToken: NextToken | None


class DescribeInventoryDeletionsRequest(ServiceRequest):
    DeletionId: UUID | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


InventoryDeletionLastStatusUpdateTime = datetime
InventoryDeletionStartTime = datetime


class InventoryDeletionStatusItem(TypedDict, total=False):
    DeletionId: UUID | None
    TypeName: InventoryItemTypeName | None
    DeletionStartTime: InventoryDeletionStartTime | None
    LastStatus: InventoryDeletionStatus | None
    LastStatusMessage: InventoryDeletionLastStatusMessage | None
    DeletionSummary: InventoryDeletionSummary | None
    LastStatusUpdateTime: InventoryDeletionLastStatusUpdateTime | None


InventoryDeletionsList = list[InventoryDeletionStatusItem]


class DescribeInventoryDeletionsResult(TypedDict, total=False):
    InventoryDeletions: InventoryDeletionsList | None
    NextToken: NextToken | None


MaintenanceWindowFilterValues = list[MaintenanceWindowFilterValue]


class MaintenanceWindowFilter(TypedDict, total=False):
    Key: MaintenanceWindowFilterKey | None
    Values: MaintenanceWindowFilterValues | None


MaintenanceWindowFilterList = list[MaintenanceWindowFilter]


class DescribeMaintenanceWindowExecutionTaskInvocationsRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowExecutionTaskInvocationIdentity(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None
    TaskExecutionId: MaintenanceWindowExecutionTaskId | None
    InvocationId: MaintenanceWindowExecutionTaskInvocationId | None
    ExecutionId: MaintenanceWindowExecutionTaskExecutionId | None
    TaskType: MaintenanceWindowTaskType | None
    Parameters: MaintenanceWindowExecutionTaskInvocationParameters | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None
    OwnerInformation: OwnerInformation | None
    WindowTargetId: MaintenanceWindowTaskTargetId | None


MaintenanceWindowExecutionTaskInvocationIdentityList = list[
    MaintenanceWindowExecutionTaskInvocationIdentity
]


class DescribeMaintenanceWindowExecutionTaskInvocationsResult(TypedDict, total=False):
    WindowExecutionTaskInvocationIdentities: (
        MaintenanceWindowExecutionTaskInvocationIdentityList | None
    )
    NextToken: NextToken | None


class DescribeMaintenanceWindowExecutionTasksRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowExecutionTaskIdentity(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None
    TaskExecutionId: MaintenanceWindowExecutionTaskId | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None
    TaskArn: MaintenanceWindowTaskArn | None
    TaskType: MaintenanceWindowTaskType | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None


MaintenanceWindowExecutionTaskIdentityList = list[MaintenanceWindowExecutionTaskIdentity]


class DescribeMaintenanceWindowExecutionTasksResult(TypedDict, total=False):
    WindowExecutionTaskIdentities: MaintenanceWindowExecutionTaskIdentityList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowExecutionsRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowExecution(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowExecutionId: MaintenanceWindowExecutionId | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None


MaintenanceWindowExecutionList = list[MaintenanceWindowExecution]


class DescribeMaintenanceWindowExecutionsResult(TypedDict, total=False):
    WindowExecutions: MaintenanceWindowExecutionList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowScheduleRequest(ServiceRequest):
    WindowId: MaintenanceWindowId | None
    Targets: Targets | None
    ResourceType: MaintenanceWindowResourceType | None
    Filters: PatchOrchestratorFilterList | None
    MaxResults: MaintenanceWindowSearchMaxResults | None
    NextToken: NextToken | None


class ScheduledWindowExecution(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    Name: MaintenanceWindowName | None
    ExecutionTime: MaintenanceWindowStringDateTime | None


ScheduledWindowExecutionList = list[ScheduledWindowExecution]


class DescribeMaintenanceWindowScheduleResult(TypedDict, total=False):
    ScheduledWindowExecutions: ScheduledWindowExecutionList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowTargetsRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowTarget(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTargetId: MaintenanceWindowTargetId | None
    ResourceType: MaintenanceWindowResourceType | None
    Targets: Targets | None
    OwnerInformation: OwnerInformation | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None


MaintenanceWindowTargetList = list[MaintenanceWindowTarget]


class DescribeMaintenanceWindowTargetsResult(TypedDict, total=False):
    Targets: MaintenanceWindowTargetList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowTasksRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class LoggingInfo(TypedDict, total=False):
    S3BucketName: S3BucketName
    S3KeyPrefix: S3KeyPrefix | None
    S3Region: S3Region


MaintenanceWindowTaskParameterValueList = list[MaintenanceWindowTaskParameterValue]


class MaintenanceWindowTaskParameterValueExpression(TypedDict, total=False):
    Values: MaintenanceWindowTaskParameterValueList | None


MaintenanceWindowTaskParameters = dict[
    MaintenanceWindowTaskParameterName, MaintenanceWindowTaskParameterValueExpression
]


class MaintenanceWindowTask(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTaskId: MaintenanceWindowTaskId | None
    TaskArn: MaintenanceWindowTaskArn | None
    Type: MaintenanceWindowTaskType | None
    Targets: Targets | None
    TaskParameters: MaintenanceWindowTaskParameters | None
    Priority: MaintenanceWindowTaskPriority | None
    LoggingInfo: LoggingInfo | None
    ServiceRoleArn: ServiceRole | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    CutoffBehavior: MaintenanceWindowTaskCutoffBehavior | None
    AlarmConfiguration: AlarmConfiguration | None


MaintenanceWindowTaskList = list[MaintenanceWindowTask]


class DescribeMaintenanceWindowTasksResult(TypedDict, total=False):
    Tasks: MaintenanceWindowTaskList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowsForTargetRequest(ServiceRequest):
    Targets: Targets
    ResourceType: MaintenanceWindowResourceType
    MaxResults: MaintenanceWindowSearchMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowIdentityForTarget(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    Name: MaintenanceWindowName | None


MaintenanceWindowsForTargetList = list[MaintenanceWindowIdentityForTarget]


class DescribeMaintenanceWindowsForTargetResult(TypedDict, total=False):
    WindowIdentities: MaintenanceWindowsForTargetList | None
    NextToken: NextToken | None


class DescribeMaintenanceWindowsRequest(ServiceRequest):
    Filters: MaintenanceWindowFilterList | None
    MaxResults: MaintenanceWindowMaxResults | None
    NextToken: NextToken | None


class MaintenanceWindowIdentity(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    Enabled: MaintenanceWindowEnabled | None
    Duration: MaintenanceWindowDurationHours | None
    Cutoff: MaintenanceWindowCutoff | None
    Schedule: MaintenanceWindowSchedule | None
    ScheduleTimezone: MaintenanceWindowTimezone | None
    ScheduleOffset: MaintenanceWindowOffset | None
    EndDate: MaintenanceWindowStringDateTime | None
    StartDate: MaintenanceWindowStringDateTime | None
    NextExecutionTime: MaintenanceWindowStringDateTime | None


MaintenanceWindowIdentityList = list[MaintenanceWindowIdentity]


class DescribeMaintenanceWindowsResult(TypedDict, total=False):
    WindowIdentities: MaintenanceWindowIdentityList | None
    NextToken: NextToken | None


OpsItemFilterValues = list[OpsItemFilterValue]


class OpsItemFilter(TypedDict, total=False):
    Key: OpsItemFilterKey
    Values: OpsItemFilterValues
    Operator: OpsItemFilterOperator


OpsItemFilters = list[OpsItemFilter]


class DescribeOpsItemsRequest(ServiceRequest):
    OpsItemFilters: OpsItemFilters | None
    MaxResults: OpsItemMaxResults | None
    NextToken: String | None


class OpsItemSummary(TypedDict, total=False):
    CreatedBy: String | None
    CreatedTime: DateTime | None
    LastModifiedBy: String | None
    LastModifiedTime: DateTime | None
    Priority: OpsItemPriority | None
    Source: OpsItemSource | None
    Status: OpsItemStatus | None
    OpsItemId: OpsItemId | None
    Title: OpsItemTitle | None
    OperationalData: OpsItemOperationalData | None
    Category: OpsItemCategory | None
    Severity: OpsItemSeverity | None
    OpsItemType: OpsItemType | None
    ActualStartTime: DateTime | None
    ActualEndTime: DateTime | None
    PlannedStartTime: DateTime | None
    PlannedEndTime: DateTime | None


OpsItemSummaries = list[OpsItemSummary]


class DescribeOpsItemsResponse(TypedDict, total=False):
    NextToken: String | None
    OpsItemSummaries: OpsItemSummaries | None


ParameterStringFilterValueList = list[ParameterStringFilterValue]


class ParameterStringFilter(TypedDict, total=False):
    Key: ParameterStringFilterKey
    Option: ParameterStringQueryOption | None
    Values: ParameterStringFilterValueList | None


ParameterStringFilterList = list[ParameterStringFilter]
ParametersFilterValueList = list[ParametersFilterValue]


class ParametersFilter(TypedDict, total=False):
    Key: ParametersFilterKey
    Values: ParametersFilterValueList


ParametersFilterList = list[ParametersFilter]


class DescribeParametersRequest(ServiceRequest):
    Filters: ParametersFilterList | None
    ParameterFilters: ParameterStringFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Shared: Boolean | None


class ParameterInlinePolicy(TypedDict, total=False):
    PolicyText: String | None
    PolicyType: String | None
    PolicyStatus: String | None


ParameterPolicyList = list[ParameterInlinePolicy]
PSParameterVersion = int


class ParameterMetadata(TypedDict, total=False):
    Name: PSParameterName | None
    ARN: String | None
    Type: ParameterType | None
    KeyId: ParameterKeyId | None
    LastModifiedDate: DateTime | None
    LastModifiedUser: String | None
    Description: ParameterDescription | None
    AllowedPattern: AllowedPattern | None
    Version: PSParameterVersion | None
    Tier: ParameterTier | None
    Policies: ParameterPolicyList | None
    DataType: ParameterDataType | None


ParameterMetadataList = list[ParameterMetadata]


class DescribeParametersResult(TypedDict, total=False):
    Parameters: ParameterMetadataList | None
    NextToken: NextToken | None


class DescribePatchBaselinesRequest(ServiceRequest):
    Filters: PatchOrchestratorFilterList | None
    MaxResults: PatchBaselineMaxResults | None
    NextToken: NextToken | None


class PatchBaselineIdentity(TypedDict, total=False):
    BaselineId: BaselineId | None
    BaselineName: BaselineName | None
    OperatingSystem: OperatingSystem | None
    BaselineDescription: BaselineDescription | None
    DefaultBaseline: DefaultBaseline | None


PatchBaselineIdentityList = list[PatchBaselineIdentity]


class DescribePatchBaselinesResult(TypedDict, total=False):
    BaselineIdentities: PatchBaselineIdentityList | None
    NextToken: NextToken | None


class DescribePatchGroupStateRequest(ServiceRequest):
    PatchGroup: PatchGroup


class DescribePatchGroupStateResult(TypedDict, total=False):
    Instances: Integer | None
    InstancesWithInstalledPatches: Integer | None
    InstancesWithInstalledOtherPatches: Integer | None
    InstancesWithInstalledPendingRebootPatches: InstancesCount | None
    InstancesWithInstalledRejectedPatches: InstancesCount | None
    InstancesWithMissingPatches: Integer | None
    InstancesWithFailedPatches: Integer | None
    InstancesWithNotApplicablePatches: Integer | None
    InstancesWithUnreportedNotApplicablePatches: Integer | None
    InstancesWithCriticalNonCompliantPatches: InstancesCount | None
    InstancesWithSecurityNonCompliantPatches: InstancesCount | None
    InstancesWithOtherNonCompliantPatches: InstancesCount | None
    InstancesWithAvailableSecurityUpdates: Integer | None


class DescribePatchGroupsRequest(ServiceRequest):
    MaxResults: PatchBaselineMaxResults | None
    Filters: PatchOrchestratorFilterList | None
    NextToken: NextToken | None


class PatchGroupPatchBaselineMapping(TypedDict, total=False):
    PatchGroup: PatchGroup | None
    BaselineIdentity: PatchBaselineIdentity | None


PatchGroupPatchBaselineMappingList = list[PatchGroupPatchBaselineMapping]


class DescribePatchGroupsResult(TypedDict, total=False):
    Mappings: PatchGroupPatchBaselineMappingList | None
    NextToken: NextToken | None


class DescribePatchPropertiesRequest(ServiceRequest):
    OperatingSystem: OperatingSystem
    Property: PatchProperty
    PatchSet: PatchSet | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


PatchPropertyEntry = dict[AttributeName, AttributeValue]
PatchPropertiesList = list[PatchPropertyEntry]


class DescribePatchPropertiesResult(TypedDict, total=False):
    Properties: PatchPropertiesList | None
    NextToken: NextToken | None


class SessionFilter(TypedDict, total=False):
    key: SessionFilterKey
    value: SessionFilterValue


SessionFilterList = list[SessionFilter]


class DescribeSessionsRequest(ServiceRequest):
    State: SessionState
    MaxResults: SessionMaxResults | None
    NextToken: NextToken | None
    Filters: SessionFilterList | None


class SessionManagerOutputUrl(TypedDict, total=False):
    S3OutputUrl: SessionManagerS3OutputUrl | None
    CloudWatchOutputUrl: SessionManagerCloudWatchOutputUrl | None


class Session(TypedDict, total=False):
    SessionId: SessionId | None
    Target: SessionTarget | None
    Status: SessionStatus | None
    StartDate: DateTime | None
    EndDate: DateTime | None
    DocumentName: DocumentName | None
    Owner: SessionOwner | None
    Reason: SessionReason | None
    Details: SessionDetails | None
    OutputUrl: SessionManagerOutputUrl | None
    MaxSessionDuration: MaxSessionDuration | None
    AccessType: AccessType | None


SessionList = list[Session]


class DescribeSessionsResponse(TypedDict, total=False):
    Sessions: SessionList | None
    NextToken: NextToken | None


class DisassociateOpsItemRelatedItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    AssociationId: OpsItemRelatedItemAssociationId


class DisassociateOpsItemRelatedItemResponse(TypedDict, total=False):
    pass


class DocumentDefaultVersionDescription(TypedDict, total=False):
    Name: DocumentName | None
    DefaultVersion: DocumentVersion | None
    DefaultVersionName: DocumentVersionName | None


class DocumentFilter(TypedDict, total=False):
    key: DocumentFilterKey
    value: DocumentFilterValue


DocumentFilterList = list[DocumentFilter]


class DocumentIdentifier(TypedDict, total=False):
    Name: DocumentARN | None
    CreatedDate: DateTime | None
    DisplayName: DocumentDisplayName | None
    Owner: DocumentOwner | None
    VersionName: DocumentVersionName | None
    PlatformTypes: PlatformTypeList | None
    DocumentVersion: DocumentVersion | None
    DocumentType: DocumentType | None
    SchemaVersion: DocumentSchemaVersion | None
    DocumentFormat: DocumentFormat | None
    TargetType: TargetType | None
    Tags: TagList | None
    Requires: DocumentRequiresList | None
    ReviewStatus: ReviewStatus | None
    Author: DocumentAuthor | None


DocumentIdentifierList = list[DocumentIdentifier]
DocumentKeyValuesFilterValues = list[DocumentKeyValuesFilterValue]


class DocumentKeyValuesFilter(TypedDict, total=False):
    Key: DocumentKeyValuesFilterKey | None
    Values: DocumentKeyValuesFilterValues | None


DocumentKeyValuesFilterList = list[DocumentKeyValuesFilter]


class DocumentReviewCommentSource(TypedDict, total=False):
    Type: DocumentReviewCommentType | None
    Content: DocumentReviewComment | None


DocumentReviewCommentList = list[DocumentReviewCommentSource]


class DocumentReviewerResponseSource(TypedDict, total=False):
    CreateTime: DateTime | None
    UpdatedTime: DateTime | None
    ReviewStatus: ReviewStatus | None
    Comment: DocumentReviewCommentList | None
    Reviewer: Reviewer | None


DocumentReviewerResponseList = list[DocumentReviewerResponseSource]


class DocumentMetadataResponseInfo(TypedDict, total=False):
    ReviewerResponse: DocumentReviewerResponseList | None


class DocumentReviews(TypedDict, total=False):
    Action: DocumentReviewAction
    Comment: DocumentReviewCommentList | None


class DocumentVersionInfo(TypedDict, total=False):
    Name: DocumentName | None
    DisplayName: DocumentDisplayName | None
    DocumentVersion: DocumentVersion | None
    VersionName: DocumentVersionName | None
    CreatedDate: DateTime | None
    IsDefaultVersion: Boolean | None
    DocumentFormat: DocumentFormat | None
    Status: DocumentStatus | None
    StatusInformation: DocumentStatusInformation | None
    ReviewStatus: ReviewStatus | None


DocumentVersionList = list[DocumentVersionInfo]


class ExecutionInputs(TypedDict, total=False):
    Automation: AutomationExecutionInputs | None


class ExecutionPreview(TypedDict, total=False):
    Automation: AutomationExecutionPreview | None


class GetAccessTokenRequest(ServiceRequest):
    AccessRequestId: AccessRequestId


class GetAccessTokenResponse(TypedDict, total=False):
    Credentials: Credentials | None
    AccessRequestStatus: AccessRequestStatus | None


class GetAutomationExecutionRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId


class GetAutomationExecutionResult(TypedDict, total=False):
    AutomationExecution: AutomationExecution | None


class GetCalendarStateRequest(ServiceRequest):
    CalendarNames: CalendarNameOrARNList
    AtTime: ISO8601String | None


class GetCalendarStateResponse(TypedDict, total=False):
    State: CalendarState | None
    AtTime: ISO8601String | None
    NextTransitionTime: ISO8601String | None


class GetCommandInvocationRequest(ServiceRequest):
    CommandId: CommandId
    InstanceId: InstanceId
    PluginName: CommandPluginName | None


class GetCommandInvocationResult(TypedDict, total=False):
    CommandId: CommandId | None
    InstanceId: InstanceId | None
    Comment: Comment | None
    DocumentName: DocumentName | None
    DocumentVersion: DocumentVersion | None
    PluginName: CommandPluginName | None
    ResponseCode: ResponseCode | None
    ExecutionStartDateTime: StringDateTime | None
    ExecutionElapsedTime: StringDateTime | None
    ExecutionEndDateTime: StringDateTime | None
    Status: CommandInvocationStatus | None
    StatusDetails: StatusDetails | None
    StandardOutputContent: StandardOutputContent | None
    StandardOutputUrl: Url | None
    StandardErrorContent: StandardErrorContent | None
    StandardErrorUrl: Url | None
    CloudWatchOutputConfig: CloudWatchOutputConfig | None


class GetConnectionStatusRequest(ServiceRequest):
    Target: SessionTarget


class GetConnectionStatusResponse(TypedDict, total=False):
    Target: SessionTarget | None
    Status: ConnectionStatus | None


class GetDefaultPatchBaselineRequest(ServiceRequest):
    OperatingSystem: OperatingSystem | None


class GetDefaultPatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    OperatingSystem: OperatingSystem | None


class GetDeployablePatchSnapshotForInstanceRequest(ServiceRequest):
    InstanceId: InstanceId
    SnapshotId: SnapshotId
    BaselineOverride: BaselineOverride | None
    UseS3DualStackEndpoint: Boolean | None


class GetDeployablePatchSnapshotForInstanceResult(TypedDict, total=False):
    InstanceId: InstanceId | None
    SnapshotId: SnapshotId | None
    SnapshotDownloadUrl: SnapshotDownloadUrl | None
    Product: Product | None


class GetDocumentRequest(ServiceRequest):
    Name: DocumentARN
    VersionName: DocumentVersionName | None
    DocumentVersion: DocumentVersion | None
    DocumentFormat: DocumentFormat | None


class GetDocumentResult(TypedDict, total=False):
    Name: DocumentARN | None
    CreatedDate: DateTime | None
    DisplayName: DocumentDisplayName | None
    VersionName: DocumentVersionName | None
    DocumentVersion: DocumentVersion | None
    Status: DocumentStatus | None
    StatusInformation: DocumentStatusInformation | None
    Content: DocumentContent | None
    DocumentType: DocumentType | None
    DocumentFormat: DocumentFormat | None
    Requires: DocumentRequiresList | None
    AttachmentsContent: AttachmentContentList | None
    ReviewStatus: ReviewStatus | None


class GetExecutionPreviewRequest(ServiceRequest):
    ExecutionPreviewId: ExecutionPreviewId


class GetExecutionPreviewResponse(TypedDict, total=False):
    ExecutionPreviewId: ExecutionPreviewId | None
    EndedAt: DateTime | None
    Status: ExecutionPreviewStatus | None
    StatusMessage: String | None
    ExecutionPreview: ExecutionPreview | None


class ResultAttribute(TypedDict, total=False):
    TypeName: InventoryItemTypeName


ResultAttributeList = list[ResultAttribute]
InventoryFilterValueList = list[InventoryFilterValue]


class InventoryFilter(TypedDict, total=False):
    Key: InventoryFilterKey
    Values: InventoryFilterValueList
    Type: InventoryQueryOperatorType | None


InventoryFilterList = list[InventoryFilter]


class InventoryGroup(TypedDict, total=False):
    Name: InventoryGroupName
    Filters: InventoryFilterList


InventoryGroupList = list[InventoryGroup]
InventoryAggregatorList = list["InventoryAggregator"]


class InventoryAggregator(TypedDict, total=False):
    Expression: InventoryAggregatorExpression | None
    Aggregators: InventoryAggregatorList | None
    Groups: InventoryGroupList | None


class GetInventoryRequest(ServiceRequest):
    Filters: InventoryFilterList | None
    Aggregators: InventoryAggregatorList | None
    ResultAttributes: ResultAttributeList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


InventoryItemEntry = dict[AttributeName, AttributeValue]
InventoryItemEntryList = list[InventoryItemEntry]


class InventoryResultItem(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    SchemaVersion: InventoryItemSchemaVersion
    CaptureTime: InventoryItemCaptureTime | None
    ContentHash: InventoryItemContentHash | None
    Content: InventoryItemEntryList


InventoryResultItemMap = dict[InventoryResultItemKey, InventoryResultItem]


class InventoryResultEntity(TypedDict, total=False):
    Id: InventoryResultEntityId | None
    Data: InventoryResultItemMap | None


InventoryResultEntityList = list[InventoryResultEntity]


class GetInventoryResult(TypedDict, total=False):
    Entities: InventoryResultEntityList | None
    NextToken: NextToken | None


class GetInventorySchemaRequest(ServiceRequest):
    TypeName: InventoryItemTypeNameFilter | None
    NextToken: NextToken | None
    MaxResults: GetInventorySchemaMaxResults | None
    Aggregator: AggregatorSchemaOnly | None
    SubType: IsSubTypeSchema | None


class InventoryItemAttribute(TypedDict, total=False):
    Name: InventoryItemAttributeName
    DataType: InventoryAttributeDataType


InventoryItemAttributeList = list[InventoryItemAttribute]


class InventoryItemSchema(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    Version: InventoryItemSchemaVersion | None
    Attributes: InventoryItemAttributeList
    DisplayName: InventoryTypeDisplayName | None


InventoryItemSchemaResultList = list[InventoryItemSchema]


class GetInventorySchemaResult(TypedDict, total=False):
    Schemas: InventoryItemSchemaResultList | None
    NextToken: NextToken | None


class GetMaintenanceWindowExecutionRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId


MaintenanceWindowExecutionTaskIdList = list[MaintenanceWindowExecutionTaskId]


class GetMaintenanceWindowExecutionResult(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None
    TaskIds: MaintenanceWindowExecutionTaskIdList | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None


class GetMaintenanceWindowExecutionTaskInvocationRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId
    InvocationId: MaintenanceWindowExecutionTaskInvocationId


class GetMaintenanceWindowExecutionTaskInvocationResult(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None
    TaskExecutionId: MaintenanceWindowExecutionTaskId | None
    InvocationId: MaintenanceWindowExecutionTaskInvocationId | None
    ExecutionId: MaintenanceWindowExecutionTaskExecutionId | None
    TaskType: MaintenanceWindowTaskType | None
    Parameters: MaintenanceWindowExecutionTaskInvocationParameters | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None
    OwnerInformation: OwnerInformation | None
    WindowTargetId: MaintenanceWindowTaskTargetId | None


class GetMaintenanceWindowExecutionTaskRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId


MaintenanceWindowTaskParametersList = list[MaintenanceWindowTaskParameters]


class GetMaintenanceWindowExecutionTaskResult(TypedDict, total=False):
    WindowExecutionId: MaintenanceWindowExecutionId | None
    TaskExecutionId: MaintenanceWindowExecutionTaskId | None
    TaskArn: MaintenanceWindowTaskArn | None
    ServiceRole: ServiceRole | None
    Type: MaintenanceWindowTaskType | None
    TaskParameters: MaintenanceWindowTaskParametersList | None
    Priority: MaintenanceWindowTaskPriority | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    Status: MaintenanceWindowExecutionStatus | None
    StatusDetails: MaintenanceWindowExecutionStatusDetails | None
    StartTime: DateTime | None
    EndTime: DateTime | None
    AlarmConfiguration: AlarmConfiguration | None
    TriggeredAlarms: AlarmStateInformationList | None


class GetMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId


class GetMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    StartDate: MaintenanceWindowStringDateTime | None
    EndDate: MaintenanceWindowStringDateTime | None
    Schedule: MaintenanceWindowSchedule | None
    ScheduleTimezone: MaintenanceWindowTimezone | None
    ScheduleOffset: MaintenanceWindowOffset | None
    NextExecutionTime: MaintenanceWindowStringDateTime | None
    Duration: MaintenanceWindowDurationHours | None
    Cutoff: MaintenanceWindowCutoff | None
    AllowUnassociatedTargets: MaintenanceWindowAllowUnassociatedTargets | None
    Enabled: MaintenanceWindowEnabled | None
    CreatedDate: DateTime | None
    ModifiedDate: DateTime | None


class GetMaintenanceWindowTaskRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId


MaintenanceWindowLambdaPayload = bytes


class MaintenanceWindowLambdaParameters(TypedDict, total=False):
    ClientContext: MaintenanceWindowLambdaClientContext | None
    Qualifier: MaintenanceWindowLambdaQualifier | None
    Payload: MaintenanceWindowLambdaPayload | None


class MaintenanceWindowStepFunctionsParameters(TypedDict, total=False):
    Input: MaintenanceWindowStepFunctionsInput | None
    Name: MaintenanceWindowStepFunctionsName | None


class MaintenanceWindowAutomationParameters(TypedDict, total=False):
    DocumentVersion: DocumentVersion | None
    Parameters: AutomationParameterMap | None


class MaintenanceWindowRunCommandParameters(TypedDict, total=False):
    Comment: Comment | None
    CloudWatchOutputConfig: CloudWatchOutputConfig | None
    DocumentHash: DocumentHash | None
    DocumentHashType: DocumentHashType | None
    DocumentVersion: DocumentVersion | None
    NotificationConfig: NotificationConfig | None
    OutputS3BucketName: S3BucketName | None
    OutputS3KeyPrefix: S3KeyPrefix | None
    Parameters: Parameters | None
    ServiceRoleArn: ServiceRole | None
    TimeoutSeconds: TimeoutSeconds | None


class MaintenanceWindowTaskInvocationParameters(TypedDict, total=False):
    RunCommand: MaintenanceWindowRunCommandParameters | None
    Automation: MaintenanceWindowAutomationParameters | None
    StepFunctions: MaintenanceWindowStepFunctionsParameters | None
    Lambda: MaintenanceWindowLambdaParameters | None


class GetMaintenanceWindowTaskResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTaskId: MaintenanceWindowTaskId | None
    Targets: Targets | None
    TaskArn: MaintenanceWindowTaskArn | None
    ServiceRoleArn: ServiceRole | None
    TaskType: MaintenanceWindowTaskType | None
    TaskParameters: MaintenanceWindowTaskParameters | None
    TaskInvocationParameters: MaintenanceWindowTaskInvocationParameters | None
    Priority: MaintenanceWindowTaskPriority | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    LoggingInfo: LoggingInfo | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    CutoffBehavior: MaintenanceWindowTaskCutoffBehavior | None
    AlarmConfiguration: AlarmConfiguration | None


class GetOpsItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    OpsItemArn: OpsItemArn | None


class OpsItem(TypedDict, total=False):
    CreatedBy: String | None
    OpsItemType: OpsItemType | None
    CreatedTime: DateTime | None
    Description: OpsItemDescription | None
    LastModifiedBy: String | None
    LastModifiedTime: DateTime | None
    Notifications: OpsItemNotifications | None
    Priority: OpsItemPriority | None
    RelatedOpsItems: RelatedOpsItems | None
    Status: OpsItemStatus | None
    OpsItemId: OpsItemId | None
    Version: String | None
    Title: OpsItemTitle | None
    Source: OpsItemSource | None
    OperationalData: OpsItemOperationalData | None
    Category: OpsItemCategory | None
    Severity: OpsItemSeverity | None
    ActualStartTime: DateTime | None
    ActualEndTime: DateTime | None
    PlannedStartTime: DateTime | None
    PlannedEndTime: DateTime | None
    OpsItemArn: OpsItemArn | None


class GetOpsItemResponse(TypedDict, total=False):
    OpsItem: OpsItem | None


class GetOpsMetadataRequest(ServiceRequest):
    OpsMetadataArn: OpsMetadataArn
    MaxResults: GetOpsMetadataMaxResults | None
    NextToken: NextToken | None


class GetOpsMetadataResult(TypedDict, total=False):
    ResourceId: OpsMetadataResourceId | None
    Metadata: MetadataMap | None
    NextToken: NextToken | None


class OpsResultAttribute(TypedDict, total=False):
    TypeName: OpsDataTypeName


OpsResultAttributeList = list[OpsResultAttribute]
OpsAggregatorList = list["OpsAggregator"]
OpsFilterValueList = list[OpsFilterValue]


class OpsFilter(TypedDict, total=False):
    Key: OpsFilterKey
    Values: OpsFilterValueList
    Type: OpsFilterOperatorType | None


OpsFilterList = list[OpsFilter]
OpsAggregatorValueMap = dict[OpsAggregatorValueKey, OpsAggregatorValue]


class OpsAggregator(TypedDict, total=False):
    AggregatorType: OpsAggregatorType | None
    TypeName: OpsDataTypeName | None
    AttributeName: OpsDataAttributeName | None
    Values: OpsAggregatorValueMap | None
    Filters: OpsFilterList | None
    Aggregators: OpsAggregatorList | None


class GetOpsSummaryRequest(ServiceRequest):
    SyncName: ResourceDataSyncName | None
    Filters: OpsFilterList | None
    Aggregators: OpsAggregatorList | None
    ResultAttributes: OpsResultAttributeList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


OpsEntityItemEntry = dict[AttributeName, AttributeValue]
OpsEntityItemEntryList = list[OpsEntityItemEntry]


class OpsEntityItem(TypedDict, total=False):
    CaptureTime: OpsEntityItemCaptureTime | None
    Content: OpsEntityItemEntryList | None


OpsEntityItemMap = dict[OpsEntityItemKey, OpsEntityItem]


class OpsEntity(TypedDict, total=False):
    Id: OpsEntityId | None
    Data: OpsEntityItemMap | None


OpsEntityList = list[OpsEntity]


class GetOpsSummaryResult(TypedDict, total=False):
    Entities: OpsEntityList | None
    NextToken: NextToken | None


class GetParameterHistoryRequest(ServiceRequest):
    Name: PSParameterName
    WithDecryption: Boolean | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


ParameterLabelList = list[ParameterLabel]


class ParameterHistory(TypedDict, total=False):
    Name: PSParameterName | None
    Type: ParameterType | None
    KeyId: ParameterKeyId | None
    LastModifiedDate: DateTime | None
    LastModifiedUser: String | None
    Description: ParameterDescription | None
    Value: PSParameterValue | None
    AllowedPattern: AllowedPattern | None
    Version: PSParameterVersion | None
    Labels: ParameterLabelList | None
    Tier: ParameterTier | None
    Policies: ParameterPolicyList | None
    DataType: ParameterDataType | None


ParameterHistoryList = list[ParameterHistory]


class GetParameterHistoryResult(TypedDict, total=False):
    Parameters: ParameterHistoryList | None
    NextToken: NextToken | None


class GetParameterRequest(ServiceRequest):
    Name: PSParameterName
    WithDecryption: Boolean | None


class Parameter(TypedDict, total=False):
    Name: PSParameterName | None
    Type: ParameterType | None
    Value: PSParameterValue | None
    Version: PSParameterVersion | None
    Selector: PSParameterSelector | None
    SourceResult: String | None
    LastModifiedDate: DateTime | None
    ARN: String | None
    DataType: ParameterDataType | None


class GetParameterResult(TypedDict, total=False):
    Parameter: Parameter | None


class GetParametersByPathRequest(ServiceRequest):
    Path: PSParameterName
    Recursive: Boolean | None
    ParameterFilters: ParameterStringFilterList | None
    WithDecryption: Boolean | None
    MaxResults: GetParametersByPathMaxResults | None
    NextToken: NextToken | None


ParameterList = list[Parameter]


class GetParametersByPathResult(TypedDict, total=False):
    Parameters: ParameterList | None
    NextToken: NextToken | None


class GetParametersRequest(ServiceRequest):
    Names: ParameterNameList
    WithDecryption: Boolean | None


class GetParametersResult(TypedDict, total=False):
    Parameters: ParameterList | None
    InvalidParameters: ParameterNameList | None


class GetPatchBaselineForPatchGroupRequest(ServiceRequest):
    PatchGroup: PatchGroup
    OperatingSystem: OperatingSystem | None


class GetPatchBaselineForPatchGroupResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    PatchGroup: PatchGroup | None
    OperatingSystem: OperatingSystem | None


class GetPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


PatchGroupList = list[PatchGroup]


class GetPatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    Name: BaselineName | None
    OperatingSystem: OperatingSystem | None
    GlobalFilters: PatchFilterGroup | None
    ApprovalRules: PatchRuleGroup | None
    ApprovedPatches: PatchIdList | None
    ApprovedPatchesComplianceLevel: PatchComplianceLevel | None
    ApprovedPatchesEnableNonSecurity: Boolean | None
    RejectedPatches: PatchIdList | None
    RejectedPatchesAction: PatchAction | None
    PatchGroups: PatchGroupList | None
    CreatedDate: DateTime | None
    ModifiedDate: DateTime | None
    Description: BaselineDescription | None
    Sources: PatchSourceList | None
    AvailableSecurityUpdatesComplianceStatus: PatchComplianceStatus | None


class GetResourcePoliciesRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    NextToken: String | None
    MaxResults: ResourcePolicyMaxResults | None


class GetResourcePoliciesResponseEntry(TypedDict, total=False):
    PolicyId: PolicyId | None
    PolicyHash: PolicyHash | None
    Policy: Policy | None


GetResourcePoliciesResponseEntries = list[GetResourcePoliciesResponseEntry]


class GetResourcePoliciesResponse(TypedDict, total=False):
    NextToken: String | None
    Policies: GetResourcePoliciesResponseEntries | None


class GetServiceSettingRequest(ServiceRequest):
    SettingId: ServiceSettingId


class ServiceSetting(TypedDict, total=False):
    SettingId: ServiceSettingId | None
    SettingValue: ServiceSettingValue | None
    LastModifiedDate: DateTime | None
    LastModifiedUser: String | None
    ARN: String | None
    Status: String | None


class GetServiceSettingResult(TypedDict, total=False):
    ServiceSetting: ServiceSetting | None


class InstanceInfo(TypedDict, total=False):
    AgentType: AgentType | None
    AgentVersion: AgentVersion | None
    ComputerName: ComputerName | None
    InstanceStatus: InstanceStatus | None
    IpAddress: IpAddress | None
    ManagedStatus: ManagedStatus | None
    PlatformType: PlatformType | None
    PlatformName: PlatformName | None
    PlatformVersion: PlatformVersion | None
    ResourceType: ResourceType | None


InventoryItemContentContext = dict[AttributeName, AttributeValue]


class InventoryItem(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    SchemaVersion: InventoryItemSchemaVersion
    CaptureTime: InventoryItemCaptureTime
    ContentHash: InventoryItemContentHash | None
    Content: InventoryItemEntryList | None
    Context: InventoryItemContentContext | None


InventoryItemList = list[InventoryItem]
KeyList = list[TagKey]


class LabelParameterVersionRequest(ServiceRequest):
    Name: PSParameterName
    ParameterVersion: PSParameterVersion | None
    Labels: ParameterLabelList


class LabelParameterVersionResult(TypedDict, total=False):
    InvalidLabels: ParameterLabelList | None
    ParameterVersion: PSParameterVersion | None


LastResourceDataSyncTime = datetime
LastSuccessfulResourceDataSyncTime = datetime


class ListAssociationVersionsRequest(ServiceRequest):
    AssociationId: AssociationId
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListAssociationVersionsResult(TypedDict, total=False):
    AssociationVersions: AssociationVersionList | None
    NextToken: NextToken | None


class ListAssociationsRequest(ServiceRequest):
    AssociationFilterList: AssociationFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListAssociationsResult(TypedDict, total=False):
    Associations: AssociationList | None
    NextToken: NextToken | None


class ListCommandInvocationsRequest(ServiceRequest):
    CommandId: CommandId | None
    InstanceId: InstanceId | None
    MaxResults: CommandMaxResults | None
    NextToken: NextToken | None
    Filters: CommandFilterList | None
    Details: Boolean | None


class ListCommandInvocationsResult(TypedDict, total=False):
    CommandInvocations: CommandInvocationList | None
    NextToken: NextToken | None


class ListCommandsRequest(ServiceRequest):
    CommandId: CommandId | None
    InstanceId: InstanceId | None
    MaxResults: CommandMaxResults | None
    NextToken: NextToken | None
    Filters: CommandFilterList | None


class ListCommandsResult(TypedDict, total=False):
    Commands: CommandList | None
    NextToken: NextToken | None


class ListComplianceItemsRequest(ServiceRequest):
    Filters: ComplianceStringFilterList | None
    ResourceIds: ComplianceResourceIdList | None
    ResourceTypes: ComplianceResourceTypeList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListComplianceItemsResult(TypedDict, total=False):
    ComplianceItems: ComplianceItemList | None
    NextToken: NextToken | None


class ListComplianceSummariesRequest(ServiceRequest):
    Filters: ComplianceStringFilterList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListComplianceSummariesResult(TypedDict, total=False):
    ComplianceSummaryItems: ComplianceSummaryItemList | None
    NextToken: NextToken | None


class ListDocumentMetadataHistoryRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: DocumentVersion | None
    Metadata: DocumentMetadataEnum
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListDocumentMetadataHistoryResponse(TypedDict, total=False):
    Name: DocumentName | None
    DocumentVersion: DocumentVersion | None
    Author: DocumentAuthor | None
    Metadata: DocumentMetadataResponseInfo | None
    NextToken: NextToken | None


class ListDocumentVersionsRequest(ServiceRequest):
    Name: DocumentARN
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListDocumentVersionsResult(TypedDict, total=False):
    DocumentVersions: DocumentVersionList | None
    NextToken: NextToken | None


class ListDocumentsRequest(ServiceRequest):
    DocumentFilterList: DocumentFilterList | None
    Filters: DocumentKeyValuesFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListDocumentsResult(TypedDict, total=False):
    DocumentIdentifiers: DocumentIdentifierList | None
    NextToken: NextToken | None


class ListInventoryEntriesRequest(ServiceRequest):
    InstanceId: InstanceId
    TypeName: InventoryItemTypeName
    Filters: InventoryFilterList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListInventoryEntriesResult(TypedDict, total=False):
    TypeName: InventoryItemTypeName | None
    InstanceId: InstanceId | None
    SchemaVersion: InventoryItemSchemaVersion | None
    CaptureTime: InventoryItemCaptureTime | None
    Entries: InventoryItemEntryList | None
    NextToken: NextToken | None


NodeFilterValueList = list[NodeFilterValue]


class NodeFilter(TypedDict, total=False):
    Key: NodeFilterKey
    Values: NodeFilterValueList
    Type: NodeFilterOperatorType | None


NodeFilterList = list[NodeFilter]


class ListNodesRequest(ServiceRequest):
    SyncName: ResourceDataSyncName | None
    Filters: NodeFilterList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class NodeType(TypedDict, total=False):
    Instance: InstanceInfo | None


class NodeOwnerInfo(TypedDict, total=False):
    AccountId: NodeAccountId | None
    OrganizationalUnitId: NodeOrganizationalUnitId | None
    OrganizationalUnitPath: NodeOrganizationalUnitPath | None


NodeCaptureTime = datetime


class Node(TypedDict, total=False):
    CaptureTime: NodeCaptureTime | None
    Id: NodeId | None
    Owner: NodeOwnerInfo | None
    Region: NodeRegion | None
    NodeType: NodeType | None


NodeList = list[Node]


class ListNodesResult(TypedDict, total=False):
    Nodes: NodeList | None
    NextToken: NextToken | None


NodeAggregatorList = list["NodeAggregator"]


class NodeAggregator(TypedDict, total=False):
    AggregatorType: NodeAggregatorType
    TypeName: NodeTypeName
    AttributeName: NodeAttributeName
    Aggregators: NodeAggregatorList | None


class ListNodesSummaryRequest(ServiceRequest):
    SyncName: ResourceDataSyncName | None
    Filters: NodeFilterList | None
    Aggregators: NodeAggregatorList
    NextToken: NextToken | None
    MaxResults: MaxResults | None


NodeSummary = dict[AttributeName, AttributeValue]
NodeSummaryList = list[NodeSummary]


class ListNodesSummaryResult(TypedDict, total=False):
    Summary: NodeSummaryList | None
    NextToken: NextToken | None


OpsItemEventFilterValues = list[OpsItemEventFilterValue]


class OpsItemEventFilter(TypedDict, total=False):
    Key: OpsItemEventFilterKey
    Values: OpsItemEventFilterValues
    Operator: OpsItemEventFilterOperator


OpsItemEventFilters = list[OpsItemEventFilter]


class ListOpsItemEventsRequest(ServiceRequest):
    Filters: OpsItemEventFilters | None
    MaxResults: OpsItemEventMaxResults | None
    NextToken: String | None


class OpsItemIdentity(TypedDict, total=False):
    Arn: String | None


class OpsItemEventSummary(TypedDict, total=False):
    OpsItemId: String | None
    EventId: String | None
    Source: String | None
    DetailType: String | None
    Detail: String | None
    CreatedBy: OpsItemIdentity | None
    CreatedTime: DateTime | None


OpsItemEventSummaries = list[OpsItemEventSummary]


class ListOpsItemEventsResponse(TypedDict, total=False):
    NextToken: String | None
    Summaries: OpsItemEventSummaries | None


OpsItemRelatedItemsFilterValues = list[OpsItemRelatedItemsFilterValue]


class OpsItemRelatedItemsFilter(TypedDict, total=False):
    Key: OpsItemRelatedItemsFilterKey
    Values: OpsItemRelatedItemsFilterValues
    Operator: OpsItemRelatedItemsFilterOperator


OpsItemRelatedItemsFilters = list[OpsItemRelatedItemsFilter]


class ListOpsItemRelatedItemsRequest(ServiceRequest):
    OpsItemId: OpsItemId | None
    Filters: OpsItemRelatedItemsFilters | None
    MaxResults: OpsItemRelatedItemsMaxResults | None
    NextToken: String | None


class OpsItemRelatedItemSummary(TypedDict, total=False):
    OpsItemId: OpsItemId | None
    AssociationId: OpsItemRelatedItemAssociationId | None
    ResourceType: OpsItemRelatedItemAssociationResourceType | None
    AssociationType: OpsItemRelatedItemAssociationType | None
    ResourceUri: OpsItemRelatedItemAssociationResourceUri | None
    CreatedBy: OpsItemIdentity | None
    CreatedTime: DateTime | None
    LastModifiedBy: OpsItemIdentity | None
    LastModifiedTime: DateTime | None


OpsItemRelatedItemSummaries = list[OpsItemRelatedItemSummary]


class ListOpsItemRelatedItemsResponse(TypedDict, total=False):
    NextToken: String | None
    Summaries: OpsItemRelatedItemSummaries | None


OpsMetadataFilterValueList = list[OpsMetadataFilterValue]


class OpsMetadataFilter(TypedDict, total=False):
    Key: OpsMetadataFilterKey
    Values: OpsMetadataFilterValueList


OpsMetadataFilterList = list[OpsMetadataFilter]


class ListOpsMetadataRequest(ServiceRequest):
    Filters: OpsMetadataFilterList | None
    MaxResults: ListOpsMetadataMaxResults | None
    NextToken: NextToken | None


class OpsMetadata(TypedDict, total=False):
    ResourceId: OpsMetadataResourceId | None
    OpsMetadataArn: OpsMetadataArn | None
    LastModifiedDate: DateTime | None
    LastModifiedUser: String | None
    CreationDate: DateTime | None


OpsMetadataList = list[OpsMetadata]


class ListOpsMetadataResult(TypedDict, total=False):
    OpsMetadataList: OpsMetadataList | None
    NextToken: NextToken | None


class ListResourceComplianceSummariesRequest(ServiceRequest):
    Filters: ComplianceStringFilterList | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ResourceComplianceSummaryItem(TypedDict, total=False):
    ComplianceType: ComplianceTypeName | None
    ResourceType: ComplianceResourceType | None
    ResourceId: ComplianceResourceId | None
    Status: ComplianceStatus | None
    OverallSeverity: ComplianceSeverity | None
    ExecutionSummary: ComplianceExecutionSummary | None
    CompliantSummary: CompliantSummary | None
    NonCompliantSummary: NonCompliantSummary | None


ResourceComplianceSummaryItemList = list[ResourceComplianceSummaryItem]


class ListResourceComplianceSummariesResult(TypedDict, total=False):
    ResourceComplianceSummaryItems: ResourceComplianceSummaryItemList | None
    NextToken: NextToken | None


class ListResourceDataSyncRequest(ServiceRequest):
    SyncType: ResourceDataSyncType | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


ResourceDataSyncCreatedTime = datetime
ResourceDataSyncLastModifiedTime = datetime


class ResourceDataSyncSourceWithState(TypedDict, total=False):
    SourceType: ResourceDataSyncSourceType | None
    AwsOrganizationsSource: ResourceDataSyncAwsOrganizationsSource | None
    SourceRegions: ResourceDataSyncSourceRegionList | None
    IncludeFutureRegions: ResourceDataSyncIncludeFutureRegions | None
    State: ResourceDataSyncState | None
    EnableAllOpsDataSources: ResourceDataSyncEnableAllOpsDataSources | None


class ResourceDataSyncItem(TypedDict, total=False):
    SyncName: ResourceDataSyncName | None
    SyncType: ResourceDataSyncType | None
    SyncSource: ResourceDataSyncSourceWithState | None
    S3Destination: ResourceDataSyncS3Destination | None
    LastSyncTime: LastResourceDataSyncTime | None
    LastSuccessfulSyncTime: LastSuccessfulResourceDataSyncTime | None
    SyncLastModifiedTime: ResourceDataSyncLastModifiedTime | None
    LastStatus: LastResourceDataSyncStatus | None
    SyncCreatedTime: ResourceDataSyncCreatedTime | None
    LastSyncStatusMessage: LastResourceDataSyncMessage | None


ResourceDataSyncItemList = list[ResourceDataSyncItem]


class ListResourceDataSyncResult(TypedDict, total=False):
    ResourceDataSyncItems: ResourceDataSyncItemList | None
    NextToken: NextToken | None


class ListTagsForResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId


class ListTagsForResourceResult(TypedDict, total=False):
    TagList: TagList | None


MetadataKeysToDeleteList = list[MetadataKey]


class ModifyDocumentPermissionRequest(ServiceRequest):
    Name: DocumentName
    PermissionType: DocumentPermissionType
    AccountIdsToAdd: AccountIdList | None
    AccountIdsToRemove: AccountIdList | None
    SharedDocumentVersion: SharedDocumentVersion | None


class ModifyDocumentPermissionResponse(TypedDict, total=False):
    pass


OpsItemOpsDataKeysList = list[String]


class PutComplianceItemsRequest(ServiceRequest):
    ResourceId: ComplianceResourceId
    ResourceType: ComplianceResourceType
    ComplianceType: ComplianceTypeName
    ExecutionSummary: ComplianceExecutionSummary
    Items: ComplianceItemEntryList
    ItemContentHash: ComplianceItemContentHash | None
    UploadType: ComplianceUploadType | None


class PutComplianceItemsResult(TypedDict, total=False):
    pass


class PutInventoryRequest(ServiceRequest):
    InstanceId: InstanceId
    Items: InventoryItemList


class PutInventoryResult(TypedDict, total=False):
    Message: PutInventoryMessage | None


class PutParameterRequest(ServiceRequest):
    Name: PSParameterName
    Description: ParameterDescription | None
    Value: PSParameterValue
    Type: ParameterType | None
    KeyId: ParameterKeyId | None
    Overwrite: Boolean | None
    AllowedPattern: AllowedPattern | None
    Tags: TagList | None
    Tier: ParameterTier | None
    Policies: ParameterPolicies | None
    DataType: ParameterDataType | None


class PutParameterResult(TypedDict, total=False):
    Version: PSParameterVersion | None
    Tier: ParameterTier | None


class PutResourcePolicyRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    Policy: Policy
    PolicyId: PolicyId | None
    PolicyHash: PolicyHash | None


class PutResourcePolicyResponse(TypedDict, total=False):
    PolicyId: PolicyId | None
    PolicyHash: PolicyHash | None


class RegisterDefaultPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


class RegisterDefaultPatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None


class RegisterPatchBaselineForPatchGroupRequest(ServiceRequest):
    BaselineId: BaselineId
    PatchGroup: PatchGroup


class RegisterPatchBaselineForPatchGroupResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    PatchGroup: PatchGroup | None


class RegisterTargetWithMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    ResourceType: MaintenanceWindowResourceType
    Targets: Targets
    OwnerInformation: OwnerInformation | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    ClientToken: ClientToken | None


class RegisterTargetWithMaintenanceWindowResult(TypedDict, total=False):
    WindowTargetId: MaintenanceWindowTargetId | None


class RegisterTaskWithMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Targets: Targets | None
    TaskArn: MaintenanceWindowTaskArn
    ServiceRoleArn: ServiceRole | None
    TaskType: MaintenanceWindowTaskType
    TaskParameters: MaintenanceWindowTaskParameters | None
    TaskInvocationParameters: MaintenanceWindowTaskInvocationParameters | None
    Priority: MaintenanceWindowTaskPriority | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    LoggingInfo: LoggingInfo | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    ClientToken: ClientToken | None
    CutoffBehavior: MaintenanceWindowTaskCutoffBehavior | None
    AlarmConfiguration: AlarmConfiguration | None


class RegisterTaskWithMaintenanceWindowResult(TypedDict, total=False):
    WindowTaskId: MaintenanceWindowTaskId | None


class RemoveTagsFromResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId
    TagKeys: KeyList


class RemoveTagsFromResourceResult(TypedDict, total=False):
    pass


class ResetServiceSettingRequest(ServiceRequest):
    SettingId: ServiceSettingId


class ResetServiceSettingResult(TypedDict, total=False):
    ServiceSetting: ServiceSetting | None


class ResumeSessionRequest(ServiceRequest):
    SessionId: SessionId


class ResumeSessionResponse(TypedDict, total=False):
    SessionId: SessionId | None
    TokenValue: TokenValue | None
    StreamUrl: StreamUrl | None


class SendAutomationSignalRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    SignalType: SignalType
    Payload: AutomationParameterMap | None


class SendAutomationSignalResult(TypedDict, total=False):
    pass


class SendCommandRequest(ServiceRequest):
    InstanceIds: InstanceIdList | None
    Targets: Targets | None
    DocumentName: DocumentARN
    DocumentVersion: DocumentVersion | None
    DocumentHash: DocumentHash | None
    DocumentHashType: DocumentHashType | None
    TimeoutSeconds: TimeoutSeconds | None
    Comment: Comment | None
    Parameters: Parameters | None
    OutputS3Region: S3Region | None
    OutputS3BucketName: S3BucketName | None
    OutputS3KeyPrefix: S3KeyPrefix | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    ServiceRoleArn: ServiceRole | None
    NotificationConfig: NotificationConfig | None
    CloudWatchOutputConfig: CloudWatchOutputConfig | None
    AlarmConfiguration: AlarmConfiguration | None


class SendCommandResult(TypedDict, total=False):
    Command: Command | None


SessionManagerParameterValueList = list[SessionManagerParameterValue]
SessionManagerParameters = dict[SessionManagerParameterName, SessionManagerParameterValueList]


class StartAccessRequestRequest(ServiceRequest):
    Reason: String1to256
    Targets: Targets
    Tags: TagList | None


class StartAccessRequestResponse(TypedDict, total=False):
    AccessRequestId: AccessRequestId | None


class StartAssociationsOnceRequest(ServiceRequest):
    AssociationIds: AssociationIdList


class StartAssociationsOnceResult(TypedDict, total=False):
    pass


class StartAutomationExecutionRequest(ServiceRequest):
    DocumentName: DocumentARN
    DocumentVersion: DocumentVersion | None
    Parameters: AutomationParameterMap | None
    ClientToken: IdempotencyToken | None
    Mode: ExecutionMode | None
    TargetParameterName: AutomationParameterKey | None
    Targets: Targets | None
    TargetMaps: TargetMaps | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    TargetLocations: TargetLocations | None
    Tags: TagList | None
    AlarmConfiguration: AlarmConfiguration | None
    TargetLocationsURL: TargetLocationsURL | None


class StartAutomationExecutionResult(TypedDict, total=False):
    AutomationExecutionId: AutomationExecutionId | None


class StartChangeRequestExecutionRequest(ServiceRequest):
    ScheduledTime: DateTime | None
    DocumentName: DocumentARN
    DocumentVersion: DocumentVersion | None
    Parameters: AutomationParameterMap | None
    ChangeRequestName: ChangeRequestName | None
    ClientToken: IdempotencyToken | None
    AutoApprove: Boolean | None
    Runbooks: Runbooks
    Tags: TagList | None
    ScheduledEndTime: DateTime | None
    ChangeDetails: ChangeDetailsValue | None


class StartChangeRequestExecutionResult(TypedDict, total=False):
    AutomationExecutionId: AutomationExecutionId | None


class StartExecutionPreviewRequest(ServiceRequest):
    DocumentName: DocumentName
    DocumentVersion: DocumentVersion | None
    ExecutionInputs: ExecutionInputs | None


class StartExecutionPreviewResponse(TypedDict, total=False):
    ExecutionPreviewId: ExecutionPreviewId | None


class StartSessionRequest(ServiceRequest):
    Target: SessionTarget
    DocumentName: DocumentARN | None
    Reason: SessionReason | None
    Parameters: SessionManagerParameters | None


class StartSessionResponse(TypedDict, total=False):
    SessionId: SessionId | None
    TokenValue: TokenValue | None
    StreamUrl: StreamUrl | None


class StopAutomationExecutionRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    Type: StopType | None


class StopAutomationExecutionResult(TypedDict, total=False):
    pass


class TerminateSessionRequest(ServiceRequest):
    SessionId: SessionId


class TerminateSessionResponse(TypedDict, total=False):
    SessionId: SessionId | None


class UnlabelParameterVersionRequest(ServiceRequest):
    Name: PSParameterName
    ParameterVersion: PSParameterVersion
    Labels: ParameterLabelList


class UnlabelParameterVersionResult(TypedDict, total=False):
    RemovedLabels: ParameterLabelList | None
    InvalidLabels: ParameterLabelList | None


class UpdateAssociationRequest(ServiceRequest):
    AssociationId: AssociationId
    Parameters: Parameters | None
    DocumentVersion: DocumentVersion | None
    ScheduleExpression: ScheduleExpression | None
    OutputLocation: InstanceAssociationOutputLocation | None
    Name: DocumentARN | None
    Targets: Targets | None
    AssociationName: AssociationName | None
    AssociationVersion: AssociationVersion | None
    AutomationTargetParameterName: AutomationTargetParameterName | None
    MaxErrors: MaxErrors | None
    MaxConcurrency: MaxConcurrency | None
    ComplianceSeverity: AssociationComplianceSeverity | None
    SyncCompliance: AssociationSyncCompliance | None
    ApplyOnlyAtCronInterval: ApplyOnlyAtCronInterval | None
    CalendarNames: CalendarNameOrARNList | None
    TargetLocations: TargetLocations | None
    ScheduleOffset: ScheduleOffset | None
    Duration: Duration | None
    TargetMaps: TargetMaps | None
    AlarmConfiguration: AlarmConfiguration | None


class UpdateAssociationResult(TypedDict, total=False):
    AssociationDescription: AssociationDescription | None


class UpdateAssociationStatusRequest(ServiceRequest):
    Name: DocumentARN
    InstanceId: InstanceId
    AssociationStatus: AssociationStatus


class UpdateAssociationStatusResult(TypedDict, total=False):
    AssociationDescription: AssociationDescription | None


class UpdateDocumentDefaultVersionRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: DocumentVersionNumber


class UpdateDocumentDefaultVersionResult(TypedDict, total=False):
    Description: DocumentDefaultVersionDescription | None


class UpdateDocumentMetadataRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: DocumentVersion | None
    DocumentReviews: DocumentReviews


class UpdateDocumentMetadataResponse(TypedDict, total=False):
    pass


class UpdateDocumentRequest(ServiceRequest):
    Content: DocumentContent
    Attachments: AttachmentsSourceList | None
    Name: DocumentName
    DisplayName: DocumentDisplayName | None
    VersionName: DocumentVersionName | None
    DocumentVersion: DocumentVersion | None
    DocumentFormat: DocumentFormat | None
    TargetType: TargetType | None


class UpdateDocumentResult(TypedDict, total=False):
    DocumentDescription: DocumentDescription | None


class UpdateMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    StartDate: MaintenanceWindowStringDateTime | None
    EndDate: MaintenanceWindowStringDateTime | None
    Schedule: MaintenanceWindowSchedule | None
    ScheduleTimezone: MaintenanceWindowTimezone | None
    ScheduleOffset: MaintenanceWindowOffset | None
    Duration: MaintenanceWindowDurationHours | None
    Cutoff: MaintenanceWindowCutoff | None
    AllowUnassociatedTargets: MaintenanceWindowAllowUnassociatedTargets | None
    Enabled: MaintenanceWindowEnabled | None
    Replace: Boolean | None


class UpdateMaintenanceWindowResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    StartDate: MaintenanceWindowStringDateTime | None
    EndDate: MaintenanceWindowStringDateTime | None
    Schedule: MaintenanceWindowSchedule | None
    ScheduleTimezone: MaintenanceWindowTimezone | None
    ScheduleOffset: MaintenanceWindowOffset | None
    Duration: MaintenanceWindowDurationHours | None
    Cutoff: MaintenanceWindowCutoff | None
    AllowUnassociatedTargets: MaintenanceWindowAllowUnassociatedTargets | None
    Enabled: MaintenanceWindowEnabled | None


class UpdateMaintenanceWindowTargetRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTargetId: MaintenanceWindowTargetId
    Targets: Targets | None
    OwnerInformation: OwnerInformation | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    Replace: Boolean | None


class UpdateMaintenanceWindowTargetResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTargetId: MaintenanceWindowTargetId | None
    Targets: Targets | None
    OwnerInformation: OwnerInformation | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None


class UpdateMaintenanceWindowTaskRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId
    Targets: Targets | None
    TaskArn: MaintenanceWindowTaskArn | None
    ServiceRoleArn: ServiceRole | None
    TaskParameters: MaintenanceWindowTaskParameters | None
    TaskInvocationParameters: MaintenanceWindowTaskInvocationParameters | None
    Priority: MaintenanceWindowTaskPriority | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    LoggingInfo: LoggingInfo | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    Replace: Boolean | None
    CutoffBehavior: MaintenanceWindowTaskCutoffBehavior | None
    AlarmConfiguration: AlarmConfiguration | None


class UpdateMaintenanceWindowTaskResult(TypedDict, total=False):
    WindowId: MaintenanceWindowId | None
    WindowTaskId: MaintenanceWindowTaskId | None
    Targets: Targets | None
    TaskArn: MaintenanceWindowTaskArn | None
    ServiceRoleArn: ServiceRole | None
    TaskParameters: MaintenanceWindowTaskParameters | None
    TaskInvocationParameters: MaintenanceWindowTaskInvocationParameters | None
    Priority: MaintenanceWindowTaskPriority | None
    MaxConcurrency: MaxConcurrency | None
    MaxErrors: MaxErrors | None
    LoggingInfo: LoggingInfo | None
    Name: MaintenanceWindowName | None
    Description: MaintenanceWindowDescription | None
    CutoffBehavior: MaintenanceWindowTaskCutoffBehavior | None
    AlarmConfiguration: AlarmConfiguration | None


class UpdateManagedInstanceRoleRequest(ServiceRequest):
    InstanceId: ManagedInstanceId
    IamRole: IamRole


class UpdateManagedInstanceRoleResult(TypedDict, total=False):
    pass


class UpdateOpsItemRequest(ServiceRequest):
    Description: OpsItemDescription | None
    OperationalData: OpsItemOperationalData | None
    OperationalDataToDelete: OpsItemOpsDataKeysList | None
    Notifications: OpsItemNotifications | None
    Priority: OpsItemPriority | None
    RelatedOpsItems: RelatedOpsItems | None
    Status: OpsItemStatus | None
    OpsItemId: OpsItemId
    Title: OpsItemTitle | None
    Category: OpsItemCategory | None
    Severity: OpsItemSeverity | None
    ActualStartTime: DateTime | None
    ActualEndTime: DateTime | None
    PlannedStartTime: DateTime | None
    PlannedEndTime: DateTime | None
    OpsItemArn: OpsItemArn | None


class UpdateOpsItemResponse(TypedDict, total=False):
    pass


class UpdateOpsMetadataRequest(ServiceRequest):
    OpsMetadataArn: OpsMetadataArn
    MetadataToUpdate: MetadataMap | None
    KeysToDelete: MetadataKeysToDeleteList | None


class UpdateOpsMetadataResult(TypedDict, total=False):
    OpsMetadataArn: OpsMetadataArn | None


class UpdatePatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId
    Name: BaselineName | None
    GlobalFilters: PatchFilterGroup | None
    ApprovalRules: PatchRuleGroup | None
    ApprovedPatches: PatchIdList | None
    ApprovedPatchesComplianceLevel: PatchComplianceLevel | None
    ApprovedPatchesEnableNonSecurity: Boolean | None
    RejectedPatches: PatchIdList | None
    RejectedPatchesAction: PatchAction | None
    Description: BaselineDescription | None
    Sources: PatchSourceList | None
    AvailableSecurityUpdatesComplianceStatus: PatchComplianceStatus | None
    Replace: Boolean | None


class UpdatePatchBaselineResult(TypedDict, total=False):
    BaselineId: BaselineId | None
    Name: BaselineName | None
    OperatingSystem: OperatingSystem | None
    GlobalFilters: PatchFilterGroup | None
    ApprovalRules: PatchRuleGroup | None
    ApprovedPatches: PatchIdList | None
    ApprovedPatchesComplianceLevel: PatchComplianceLevel | None
    ApprovedPatchesEnableNonSecurity: Boolean | None
    RejectedPatches: PatchIdList | None
    RejectedPatchesAction: PatchAction | None
    CreatedDate: DateTime | None
    ModifiedDate: DateTime | None
    Description: BaselineDescription | None
    Sources: PatchSourceList | None
    AvailableSecurityUpdatesComplianceStatus: PatchComplianceStatus | None


class UpdateResourceDataSyncRequest(ServiceRequest):
    SyncName: ResourceDataSyncName
    SyncType: ResourceDataSyncType
    SyncSource: ResourceDataSyncSource


class UpdateResourceDataSyncResult(TypedDict, total=False):
    pass


class UpdateServiceSettingRequest(ServiceRequest):
    SettingId: ServiceSettingId
    SettingValue: ServiceSettingValue


class UpdateServiceSettingResult(TypedDict, total=False):
    pass


class SsmApi:
    service: str = "ssm"
    version: str = "2014-11-06"

    @handler("AddTagsToResource")
    def add_tags_to_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
        tags: TagList,
        **kwargs,
    ) -> AddTagsToResourceResult:
        raise NotImplementedError

    @handler("AssociateOpsItemRelatedItem")
    def associate_ops_item_related_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        association_type: OpsItemRelatedItemAssociationType,
        resource_type: OpsItemRelatedItemAssociationResourceType,
        resource_uri: OpsItemRelatedItemAssociationResourceUri,
        **kwargs,
    ) -> AssociateOpsItemRelatedItemResponse:
        raise NotImplementedError

    @handler("CancelCommand")
    def cancel_command(
        self,
        context: RequestContext,
        command_id: CommandId,
        instance_ids: InstanceIdList | None = None,
        **kwargs,
    ) -> CancelCommandResult:
        raise NotImplementedError

    @handler("CancelMaintenanceWindowExecution")
    def cancel_maintenance_window_execution(
        self, context: RequestContext, window_execution_id: MaintenanceWindowExecutionId, **kwargs
    ) -> CancelMaintenanceWindowExecutionResult:
        raise NotImplementedError

    @handler("CreateActivation")
    def create_activation(
        self,
        context: RequestContext,
        iam_role: IamRole,
        description: ActivationDescription | None = None,
        default_instance_name: DefaultInstanceName | None = None,
        registration_limit: RegistrationLimit | None = None,
        expiration_date: ExpirationDate | None = None,
        tags: TagList | None = None,
        registration_metadata: RegistrationMetadataList | None = None,
        **kwargs,
    ) -> CreateActivationResult:
        raise NotImplementedError

    @handler("CreateAssociation")
    def create_association(
        self,
        context: RequestContext,
        name: DocumentARN,
        document_version: DocumentVersion | None = None,
        instance_id: InstanceId | None = None,
        parameters: Parameters | None = None,
        targets: Targets | None = None,
        schedule_expression: ScheduleExpression | None = None,
        output_location: InstanceAssociationOutputLocation | None = None,
        association_name: AssociationName | None = None,
        automation_target_parameter_name: AutomationTargetParameterName | None = None,
        max_errors: MaxErrors | None = None,
        max_concurrency: MaxConcurrency | None = None,
        compliance_severity: AssociationComplianceSeverity | None = None,
        sync_compliance: AssociationSyncCompliance | None = None,
        apply_only_at_cron_interval: ApplyOnlyAtCronInterval | None = None,
        calendar_names: CalendarNameOrARNList | None = None,
        target_locations: TargetLocations | None = None,
        schedule_offset: ScheduleOffset | None = None,
        duration: Duration | None = None,
        target_maps: TargetMaps | None = None,
        tags: TagList | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        **kwargs,
    ) -> CreateAssociationResult:
        raise NotImplementedError

    @handler("CreateAssociationBatch")
    def create_association_batch(
        self, context: RequestContext, entries: CreateAssociationBatchRequestEntries, **kwargs
    ) -> CreateAssociationBatchResult:
        raise NotImplementedError

    @handler("CreateDocument")
    def create_document(
        self,
        context: RequestContext,
        content: DocumentContent,
        name: DocumentName,
        requires: DocumentRequiresList | None = None,
        attachments: AttachmentsSourceList | None = None,
        display_name: DocumentDisplayName | None = None,
        version_name: DocumentVersionName | None = None,
        document_type: DocumentType | None = None,
        document_format: DocumentFormat | None = None,
        target_type: TargetType | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateDocumentResult:
        raise NotImplementedError

    @handler("CreateMaintenanceWindow")
    def create_maintenance_window(
        self,
        context: RequestContext,
        name: MaintenanceWindowName,
        schedule: MaintenanceWindowSchedule,
        duration: MaintenanceWindowDurationHours,
        cutoff: MaintenanceWindowCutoff,
        allow_unassociated_targets: MaintenanceWindowAllowUnassociatedTargets,
        description: MaintenanceWindowDescription | None = None,
        start_date: MaintenanceWindowStringDateTime | None = None,
        end_date: MaintenanceWindowStringDateTime | None = None,
        schedule_timezone: MaintenanceWindowTimezone | None = None,
        schedule_offset: MaintenanceWindowOffset | None = None,
        client_token: ClientToken | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateMaintenanceWindowResult:
        raise NotImplementedError

    @handler("CreateOpsItem")
    def create_ops_item(
        self,
        context: RequestContext,
        description: OpsItemDescription,
        source: OpsItemSource,
        title: OpsItemTitle,
        ops_item_type: OpsItemType | None = None,
        operational_data: OpsItemOperationalData | None = None,
        notifications: OpsItemNotifications | None = None,
        priority: OpsItemPriority | None = None,
        related_ops_items: RelatedOpsItems | None = None,
        tags: TagList | None = None,
        category: OpsItemCategory | None = None,
        severity: OpsItemSeverity | None = None,
        actual_start_time: DateTime | None = None,
        actual_end_time: DateTime | None = None,
        planned_start_time: DateTime | None = None,
        planned_end_time: DateTime | None = None,
        account_id: OpsItemAccountId | None = None,
        **kwargs,
    ) -> CreateOpsItemResponse:
        raise NotImplementedError

    @handler("CreateOpsMetadata")
    def create_ops_metadata(
        self,
        context: RequestContext,
        resource_id: OpsMetadataResourceId,
        metadata: MetadataMap | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateOpsMetadataResult:
        raise NotImplementedError

    @handler("CreatePatchBaseline")
    def create_patch_baseline(
        self,
        context: RequestContext,
        name: BaselineName,
        operating_system: OperatingSystem | None = None,
        global_filters: PatchFilterGroup | None = None,
        approval_rules: PatchRuleGroup | None = None,
        approved_patches: PatchIdList | None = None,
        approved_patches_compliance_level: PatchComplianceLevel | None = None,
        approved_patches_enable_non_security: Boolean | None = None,
        rejected_patches: PatchIdList | None = None,
        rejected_patches_action: PatchAction | None = None,
        description: BaselineDescription | None = None,
        sources: PatchSourceList | None = None,
        available_security_updates_compliance_status: PatchComplianceStatus | None = None,
        client_token: ClientToken | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreatePatchBaselineResult:
        raise NotImplementedError

    @handler("CreateResourceDataSync")
    def create_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        s3_destination: ResourceDataSyncS3Destination | None = None,
        sync_type: ResourceDataSyncType | None = None,
        sync_source: ResourceDataSyncSource | None = None,
        **kwargs,
    ) -> CreateResourceDataSyncResult:
        raise NotImplementedError

    @handler("DeleteActivation")
    def delete_activation(
        self, context: RequestContext, activation_id: ActivationId, **kwargs
    ) -> DeleteActivationResult:
        raise NotImplementedError

    @handler("DeleteAssociation")
    def delete_association(
        self,
        context: RequestContext,
        name: DocumentARN | None = None,
        instance_id: InstanceId | None = None,
        association_id: AssociationId | None = None,
        **kwargs,
    ) -> DeleteAssociationResult:
        raise NotImplementedError

    @handler("DeleteDocument")
    def delete_document(
        self,
        context: RequestContext,
        name: DocumentName,
        document_version: DocumentVersion | None = None,
        version_name: DocumentVersionName | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> DeleteDocumentResult:
        raise NotImplementedError

    @handler("DeleteInventory")
    def delete_inventory(
        self,
        context: RequestContext,
        type_name: InventoryItemTypeName,
        schema_delete_option: InventorySchemaDeleteOption | None = None,
        dry_run: DryRun | None = None,
        client_token: UUID | None = None,
        **kwargs,
    ) -> DeleteInventoryResult:
        raise NotImplementedError

    @handler("DeleteMaintenanceWindow")
    def delete_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId, **kwargs
    ) -> DeleteMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DeleteOpsItem")
    def delete_ops_item(
        self, context: RequestContext, ops_item_id: OpsItemId, **kwargs
    ) -> DeleteOpsItemResponse:
        raise NotImplementedError

    @handler("DeleteOpsMetadata")
    def delete_ops_metadata(
        self, context: RequestContext, ops_metadata_arn: OpsMetadataArn, **kwargs
    ) -> DeleteOpsMetadataResult:
        raise NotImplementedError

    @handler("DeleteParameter")
    def delete_parameter(
        self, context: RequestContext, name: PSParameterName, **kwargs
    ) -> DeleteParameterResult:
        raise NotImplementedError

    @handler("DeleteParameters")
    def delete_parameters(
        self, context: RequestContext, names: ParameterNameList, **kwargs
    ) -> DeleteParametersResult:
        raise NotImplementedError

    @handler("DeletePatchBaseline")
    def delete_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId, **kwargs
    ) -> DeletePatchBaselineResult:
        raise NotImplementedError

    @handler("DeleteResourceDataSync")
    def delete_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        sync_type: ResourceDataSyncType | None = None,
        **kwargs,
    ) -> DeleteResourceDataSyncResult:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        policy_id: PolicyId,
        policy_hash: PolicyHash,
        **kwargs,
    ) -> DeleteResourcePolicyResponse:
        raise NotImplementedError

    @handler("DeregisterManagedInstance")
    def deregister_managed_instance(
        self, context: RequestContext, instance_id: ManagedInstanceId, **kwargs
    ) -> DeregisterManagedInstanceResult:
        raise NotImplementedError

    @handler("DeregisterPatchBaselineForPatchGroup")
    def deregister_patch_baseline_for_patch_group(
        self, context: RequestContext, baseline_id: BaselineId, patch_group: PatchGroup, **kwargs
    ) -> DeregisterPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("DeregisterTargetFromMaintenanceWindow")
    def deregister_target_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        safe: Boolean | None = None,
        **kwargs,
    ) -> DeregisterTargetFromMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DeregisterTaskFromMaintenanceWindow")
    def deregister_task_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        **kwargs,
    ) -> DeregisterTaskFromMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DescribeActivations")
    def describe_activations(
        self,
        context: RequestContext,
        filters: DescribeActivationsFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeActivationsResult:
        raise NotImplementedError

    @handler("DescribeAssociation")
    def describe_association(
        self,
        context: RequestContext,
        name: DocumentARN | None = None,
        instance_id: InstanceId | None = None,
        association_id: AssociationId | None = None,
        association_version: AssociationVersion | None = None,
        **kwargs,
    ) -> DescribeAssociationResult:
        raise NotImplementedError

    @handler("DescribeAssociationExecutionTargets")
    def describe_association_execution_targets(
        self,
        context: RequestContext,
        association_id: AssociationId,
        execution_id: AssociationExecutionId,
        filters: AssociationExecutionTargetsFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAssociationExecutionTargetsResult:
        raise NotImplementedError

    @handler("DescribeAssociationExecutions")
    def describe_association_executions(
        self,
        context: RequestContext,
        association_id: AssociationId,
        filters: AssociationExecutionFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAssociationExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAutomationExecutions")
    def describe_automation_executions(
        self,
        context: RequestContext,
        filters: AutomationExecutionFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAutomationExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAutomationStepExecutions")
    def describe_automation_step_executions(
        self,
        context: RequestContext,
        automation_execution_id: AutomationExecutionId,
        filters: StepExecutionFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        reverse_order: Boolean | None = None,
        **kwargs,
    ) -> DescribeAutomationStepExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAvailablePatches")
    def describe_available_patches(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList | None = None,
        max_results: PatchBaselineMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAvailablePatchesResult:
        raise NotImplementedError

    @handler("DescribeDocument")
    def describe_document(
        self,
        context: RequestContext,
        name: DocumentARN,
        document_version: DocumentVersion | None = None,
        version_name: DocumentVersionName | None = None,
        **kwargs,
    ) -> DescribeDocumentResult:
        raise NotImplementedError

    @handler("DescribeDocumentPermission")
    def describe_document_permission(
        self,
        context: RequestContext,
        name: DocumentName,
        permission_type: DocumentPermissionType,
        max_results: DocumentPermissionMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeDocumentPermissionResponse:
        raise NotImplementedError

    @handler("DescribeEffectiveInstanceAssociations")
    def describe_effective_instance_associations(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        max_results: EffectiveInstanceAssociationMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeEffectiveInstanceAssociationsResult:
        raise NotImplementedError

    @handler("DescribeEffectivePatchesForPatchBaseline")
    def describe_effective_patches_for_patch_baseline(
        self,
        context: RequestContext,
        baseline_id: BaselineId,
        max_results: PatchBaselineMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeEffectivePatchesForPatchBaselineResult:
        raise NotImplementedError

    @handler("DescribeInstanceAssociationsStatus")
    def describe_instance_associations_status(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeInstanceAssociationsStatusResult:
        raise NotImplementedError

    @handler("DescribeInstanceInformation")
    def describe_instance_information(
        self,
        context: RequestContext,
        instance_information_filter_list: InstanceInformationFilterList | None = None,
        filters: InstanceInformationStringFilterList | None = None,
        max_results: MaxResultsEC2Compatible | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeInstanceInformationResult:
        raise NotImplementedError

    @handler("DescribeInstancePatchStates")
    def describe_instance_patch_states(
        self,
        context: RequestContext,
        instance_ids: InstanceIdList,
        next_token: NextToken | None = None,
        max_results: PatchComplianceMaxResults | None = None,
        **kwargs,
    ) -> DescribeInstancePatchStatesResult:
        raise NotImplementedError

    @handler("DescribeInstancePatchStatesForPatchGroup")
    def describe_instance_patch_states_for_patch_group(
        self,
        context: RequestContext,
        patch_group: PatchGroup,
        filters: InstancePatchStateFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: PatchComplianceMaxResults | None = None,
        **kwargs,
    ) -> DescribeInstancePatchStatesForPatchGroupResult:
        raise NotImplementedError

    @handler("DescribeInstancePatches")
    def describe_instance_patches(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        filters: PatchOrchestratorFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: PatchComplianceMaxResults | None = None,
        **kwargs,
    ) -> DescribeInstancePatchesResult:
        raise NotImplementedError

    @handler("DescribeInstanceProperties")
    def describe_instance_properties(
        self,
        context: RequestContext,
        instance_property_filter_list: InstancePropertyFilterList | None = None,
        filters_with_operator: InstancePropertyStringFilterList | None = None,
        max_results: DescribeInstancePropertiesMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeInstancePropertiesResult:
        raise NotImplementedError

    @handler("DescribeInventoryDeletions")
    def describe_inventory_deletions(
        self,
        context: RequestContext,
        deletion_id: UUID | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> DescribeInventoryDeletionsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutionTaskInvocations")
    def describe_maintenance_window_execution_task_invocations(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowExecutionTaskInvocationsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutionTasks")
    def describe_maintenance_window_execution_tasks(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowExecutionTasksResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutions")
    def describe_maintenance_window_executions(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowExecutionsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowSchedule")
    def describe_maintenance_window_schedule(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId | None = None,
        targets: Targets | None = None,
        resource_type: MaintenanceWindowResourceType | None = None,
        filters: PatchOrchestratorFilterList | None = None,
        max_results: MaintenanceWindowSearchMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowScheduleResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowTargets")
    def describe_maintenance_window_targets(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTargetsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowTasks")
    def describe_maintenance_window_tasks(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTasksResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindows")
    def describe_maintenance_windows(
        self,
        context: RequestContext,
        filters: MaintenanceWindowFilterList | None = None,
        max_results: MaintenanceWindowMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowsForTarget")
    def describe_maintenance_windows_for_target(
        self,
        context: RequestContext,
        targets: Targets,
        resource_type: MaintenanceWindowResourceType,
        max_results: MaintenanceWindowSearchMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowsForTargetResult:
        raise NotImplementedError

    @handler("DescribeOpsItems")
    def describe_ops_items(
        self,
        context: RequestContext,
        ops_item_filters: OpsItemFilters | None = None,
        max_results: OpsItemMaxResults | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeOpsItemsResponse:
        raise NotImplementedError

    @handler("DescribeParameters")
    def describe_parameters(
        self,
        context: RequestContext,
        filters: ParametersFilterList | None = None,
        parameter_filters: ParameterStringFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        shared: Boolean | None = None,
        **kwargs,
    ) -> DescribeParametersResult:
        raise NotImplementedError

    @handler("DescribePatchBaselines")
    def describe_patch_baselines(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList | None = None,
        max_results: PatchBaselineMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribePatchBaselinesResult:
        raise NotImplementedError

    @handler("DescribePatchGroupState")
    def describe_patch_group_state(
        self, context: RequestContext, patch_group: PatchGroup, **kwargs
    ) -> DescribePatchGroupStateResult:
        raise NotImplementedError

    @handler("DescribePatchGroups")
    def describe_patch_groups(
        self,
        context: RequestContext,
        max_results: PatchBaselineMaxResults | None = None,
        filters: PatchOrchestratorFilterList | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribePatchGroupsResult:
        raise NotImplementedError

    @handler("DescribePatchProperties")
    def describe_patch_properties(
        self,
        context: RequestContext,
        operating_system: OperatingSystem,
        property: PatchProperty,
        patch_set: PatchSet | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribePatchPropertiesResult:
        raise NotImplementedError

    @handler("DescribeSessions")
    def describe_sessions(
        self,
        context: RequestContext,
        state: SessionState,
        max_results: SessionMaxResults | None = None,
        next_token: NextToken | None = None,
        filters: SessionFilterList | None = None,
        **kwargs,
    ) -> DescribeSessionsResponse:
        raise NotImplementedError

    @handler("DisassociateOpsItemRelatedItem")
    def disassociate_ops_item_related_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        association_id: OpsItemRelatedItemAssociationId,
        **kwargs,
    ) -> DisassociateOpsItemRelatedItemResponse:
        raise NotImplementedError

    @handler("GetAccessToken")
    def get_access_token(
        self, context: RequestContext, access_request_id: AccessRequestId, **kwargs
    ) -> GetAccessTokenResponse:
        raise NotImplementedError

    @handler("GetAutomationExecution")
    def get_automation_execution(
        self, context: RequestContext, automation_execution_id: AutomationExecutionId, **kwargs
    ) -> GetAutomationExecutionResult:
        raise NotImplementedError

    @handler("GetCalendarState")
    def get_calendar_state(
        self,
        context: RequestContext,
        calendar_names: CalendarNameOrARNList,
        at_time: ISO8601String | None = None,
        **kwargs,
    ) -> GetCalendarStateResponse:
        raise NotImplementedError

    @handler("GetCommandInvocation")
    def get_command_invocation(
        self,
        context: RequestContext,
        command_id: CommandId,
        instance_id: InstanceId,
        plugin_name: CommandPluginName | None = None,
        **kwargs,
    ) -> GetCommandInvocationResult:
        raise NotImplementedError

    @handler("GetConnectionStatus")
    def get_connection_status(
        self, context: RequestContext, target: SessionTarget, **kwargs
    ) -> GetConnectionStatusResponse:
        raise NotImplementedError

    @handler("GetDefaultPatchBaseline")
    def get_default_patch_baseline(
        self, context: RequestContext, operating_system: OperatingSystem | None = None, **kwargs
    ) -> GetDefaultPatchBaselineResult:
        raise NotImplementedError

    @handler("GetDeployablePatchSnapshotForInstance")
    def get_deployable_patch_snapshot_for_instance(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        snapshot_id: SnapshotId,
        baseline_override: BaselineOverride | None = None,
        use_s3_dual_stack_endpoint: Boolean | None = None,
        **kwargs,
    ) -> GetDeployablePatchSnapshotForInstanceResult:
        raise NotImplementedError

    @handler("GetDocument")
    def get_document(
        self,
        context: RequestContext,
        name: DocumentARN,
        version_name: DocumentVersionName | None = None,
        document_version: DocumentVersion | None = None,
        document_format: DocumentFormat | None = None,
        **kwargs,
    ) -> GetDocumentResult:
        raise NotImplementedError

    @handler("GetExecutionPreview")
    def get_execution_preview(
        self, context: RequestContext, execution_preview_id: ExecutionPreviewId, **kwargs
    ) -> GetExecutionPreviewResponse:
        raise NotImplementedError

    @handler("GetInventory")
    def get_inventory(
        self,
        context: RequestContext,
        filters: InventoryFilterList | None = None,
        aggregators: InventoryAggregatorList | None = None,
        result_attributes: ResultAttributeList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> GetInventoryResult:
        raise NotImplementedError

    @handler("GetInventorySchema")
    def get_inventory_schema(
        self,
        context: RequestContext,
        type_name: InventoryItemTypeNameFilter | None = None,
        next_token: NextToken | None = None,
        max_results: GetInventorySchemaMaxResults | None = None,
        aggregator: AggregatorSchemaOnly | None = None,
        sub_type: IsSubTypeSchema | None = None,
        **kwargs,
    ) -> GetInventorySchemaResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindow")
    def get_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId, **kwargs
    ) -> GetMaintenanceWindowResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecution")
    def get_maintenance_window_execution(
        self, context: RequestContext, window_execution_id: MaintenanceWindowExecutionId, **kwargs
    ) -> GetMaintenanceWindowExecutionResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecutionTask")
    def get_maintenance_window_execution_task(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
        **kwargs,
    ) -> GetMaintenanceWindowExecutionTaskResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecutionTaskInvocation")
    def get_maintenance_window_execution_task_invocation(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
        invocation_id: MaintenanceWindowExecutionTaskInvocationId,
        **kwargs,
    ) -> GetMaintenanceWindowExecutionTaskInvocationResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowTask")
    def get_maintenance_window_task(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        **kwargs,
    ) -> GetMaintenanceWindowTaskResult:
        raise NotImplementedError

    @handler("GetOpsItem")
    def get_ops_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        ops_item_arn: OpsItemArn | None = None,
        **kwargs,
    ) -> GetOpsItemResponse:
        raise NotImplementedError

    @handler("GetOpsMetadata")
    def get_ops_metadata(
        self,
        context: RequestContext,
        ops_metadata_arn: OpsMetadataArn,
        max_results: GetOpsMetadataMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetOpsMetadataResult:
        raise NotImplementedError

    @handler("GetOpsSummary")
    def get_ops_summary(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName | None = None,
        filters: OpsFilterList | None = None,
        aggregators: OpsAggregatorList | None = None,
        result_attributes: OpsResultAttributeList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> GetOpsSummaryResult:
        raise NotImplementedError

    @handler("GetParameter")
    def get_parameter(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean | None = None,
        **kwargs,
    ) -> GetParameterResult:
        raise NotImplementedError

    @handler("GetParameterHistory")
    def get_parameter_history(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetParameterHistoryResult:
        raise NotImplementedError

    @handler("GetParameters")
    def get_parameters(
        self,
        context: RequestContext,
        names: ParameterNameList,
        with_decryption: Boolean | None = None,
        **kwargs,
    ) -> GetParametersResult:
        raise NotImplementedError

    @handler("GetParametersByPath")
    def get_parameters_by_path(
        self,
        context: RequestContext,
        path: PSParameterName,
        recursive: Boolean | None = None,
        parameter_filters: ParameterStringFilterList | None = None,
        with_decryption: Boolean | None = None,
        max_results: GetParametersByPathMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetParametersByPathResult:
        raise NotImplementedError

    @handler("GetPatchBaseline")
    def get_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId, **kwargs
    ) -> GetPatchBaselineResult:
        raise NotImplementedError

    @handler("GetPatchBaselineForPatchGroup")
    def get_patch_baseline_for_patch_group(
        self,
        context: RequestContext,
        patch_group: PatchGroup,
        operating_system: OperatingSystem | None = None,
        **kwargs,
    ) -> GetPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("GetResourcePolicies")
    def get_resource_policies(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: String | None = None,
        max_results: ResourcePolicyMaxResults | None = None,
        **kwargs,
    ) -> GetResourcePoliciesResponse:
        raise NotImplementedError

    @handler("GetServiceSetting")
    def get_service_setting(
        self, context: RequestContext, setting_id: ServiceSettingId, **kwargs
    ) -> GetServiceSettingResult:
        raise NotImplementedError

    @handler("LabelParameterVersion")
    def label_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        labels: ParameterLabelList,
        parameter_version: PSParameterVersion | None = None,
        **kwargs,
    ) -> LabelParameterVersionResult:
        raise NotImplementedError

    @handler("ListAssociationVersions")
    def list_association_versions(
        self,
        context: RequestContext,
        association_id: AssociationId,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListAssociationVersionsResult:
        raise NotImplementedError

    @handler("ListAssociations")
    def list_associations(
        self,
        context: RequestContext,
        association_filter_list: AssociationFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListAssociationsResult:
        raise NotImplementedError

    @handler("ListCommandInvocations")
    def list_command_invocations(
        self,
        context: RequestContext,
        command_id: CommandId | None = None,
        instance_id: InstanceId | None = None,
        max_results: CommandMaxResults | None = None,
        next_token: NextToken | None = None,
        filters: CommandFilterList | None = None,
        details: Boolean | None = None,
        **kwargs,
    ) -> ListCommandInvocationsResult:
        raise NotImplementedError

    @handler("ListCommands")
    def list_commands(
        self,
        context: RequestContext,
        command_id: CommandId | None = None,
        instance_id: InstanceId | None = None,
        max_results: CommandMaxResults | None = None,
        next_token: NextToken | None = None,
        filters: CommandFilterList | None = None,
        **kwargs,
    ) -> ListCommandsResult:
        raise NotImplementedError

    @handler("ListComplianceItems")
    def list_compliance_items(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList | None = None,
        resource_ids: ComplianceResourceIdList | None = None,
        resource_types: ComplianceResourceTypeList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListComplianceItemsResult:
        raise NotImplementedError

    @handler("ListComplianceSummaries")
    def list_compliance_summaries(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListComplianceSummariesResult:
        raise NotImplementedError

    @handler("ListDocumentMetadataHistory")
    def list_document_metadata_history(
        self,
        context: RequestContext,
        name: DocumentName,
        metadata: DocumentMetadataEnum,
        document_version: DocumentVersion | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListDocumentMetadataHistoryResponse:
        raise NotImplementedError

    @handler("ListDocumentVersions")
    def list_document_versions(
        self,
        context: RequestContext,
        name: DocumentARN,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDocumentVersionsResult:
        raise NotImplementedError

    @handler("ListDocuments")
    def list_documents(
        self,
        context: RequestContext,
        document_filter_list: DocumentFilterList | None = None,
        filters: DocumentKeyValuesFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDocumentsResult:
        raise NotImplementedError

    @handler("ListInventoryEntries")
    def list_inventory_entries(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        type_name: InventoryItemTypeName,
        filters: InventoryFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListInventoryEntriesResult:
        raise NotImplementedError

    @handler("ListNodes")
    def list_nodes(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName | None = None,
        filters: NodeFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListNodesResult:
        raise NotImplementedError

    @handler("ListNodesSummary")
    def list_nodes_summary(
        self,
        context: RequestContext,
        aggregators: NodeAggregatorList,
        sync_name: ResourceDataSyncName | None = None,
        filters: NodeFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListNodesSummaryResult:
        raise NotImplementedError

    @handler("ListOpsItemEvents")
    def list_ops_item_events(
        self,
        context: RequestContext,
        filters: OpsItemEventFilters | None = None,
        max_results: OpsItemEventMaxResults | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> ListOpsItemEventsResponse:
        raise NotImplementedError

    @handler("ListOpsItemRelatedItems")
    def list_ops_item_related_items(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId | None = None,
        filters: OpsItemRelatedItemsFilters | None = None,
        max_results: OpsItemRelatedItemsMaxResults | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> ListOpsItemRelatedItemsResponse:
        raise NotImplementedError

    @handler("ListOpsMetadata")
    def list_ops_metadata(
        self,
        context: RequestContext,
        filters: OpsMetadataFilterList | None = None,
        max_results: ListOpsMetadataMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListOpsMetadataResult:
        raise NotImplementedError

    @handler("ListResourceComplianceSummaries")
    def list_resource_compliance_summaries(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListResourceComplianceSummariesResult:
        raise NotImplementedError

    @handler("ListResourceDataSync")
    def list_resource_data_sync(
        self,
        context: RequestContext,
        sync_type: ResourceDataSyncType | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListResourceDataSyncResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
        **kwargs,
    ) -> ListTagsForResourceResult:
        raise NotImplementedError

    @handler("ModifyDocumentPermission")
    def modify_document_permission(
        self,
        context: RequestContext,
        name: DocumentName,
        permission_type: DocumentPermissionType,
        account_ids_to_add: AccountIdList | None = None,
        account_ids_to_remove: AccountIdList | None = None,
        shared_document_version: SharedDocumentVersion | None = None,
        **kwargs,
    ) -> ModifyDocumentPermissionResponse:
        raise NotImplementedError

    @handler("PutComplianceItems")
    def put_compliance_items(
        self,
        context: RequestContext,
        resource_id: ComplianceResourceId,
        resource_type: ComplianceResourceType,
        compliance_type: ComplianceTypeName,
        execution_summary: ComplianceExecutionSummary,
        items: ComplianceItemEntryList,
        item_content_hash: ComplianceItemContentHash | None = None,
        upload_type: ComplianceUploadType | None = None,
        **kwargs,
    ) -> PutComplianceItemsResult:
        raise NotImplementedError

    @handler("PutInventory")
    def put_inventory(
        self, context: RequestContext, instance_id: InstanceId, items: InventoryItemList, **kwargs
    ) -> PutInventoryResult:
        raise NotImplementedError

    @handler("PutParameter", expand=False)
    def put_parameter(
        self, context: RequestContext, request: PutParameterRequest, **kwargs
    ) -> PutParameterResult:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        policy: Policy,
        policy_id: PolicyId | None = None,
        policy_hash: PolicyHash | None = None,
        **kwargs,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("RegisterDefaultPatchBaseline")
    def register_default_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId, **kwargs
    ) -> RegisterDefaultPatchBaselineResult:
        raise NotImplementedError

    @handler("RegisterPatchBaselineForPatchGroup")
    def register_patch_baseline_for_patch_group(
        self, context: RequestContext, baseline_id: BaselineId, patch_group: PatchGroup, **kwargs
    ) -> RegisterPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("RegisterTargetWithMaintenanceWindow")
    def register_target_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        resource_type: MaintenanceWindowResourceType,
        targets: Targets,
        owner_information: OwnerInformation | None = None,
        name: MaintenanceWindowName | None = None,
        description: MaintenanceWindowDescription | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> RegisterTargetWithMaintenanceWindowResult:
        raise NotImplementedError

    @handler("RegisterTaskWithMaintenanceWindow")
    def register_task_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        task_arn: MaintenanceWindowTaskArn,
        task_type: MaintenanceWindowTaskType,
        targets: Targets | None = None,
        service_role_arn: ServiceRole | None = None,
        task_parameters: MaintenanceWindowTaskParameters | None = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters | None = None,
        priority: MaintenanceWindowTaskPriority | None = None,
        max_concurrency: MaxConcurrency | None = None,
        max_errors: MaxErrors | None = None,
        logging_info: LoggingInfo | None = None,
        name: MaintenanceWindowName | None = None,
        description: MaintenanceWindowDescription | None = None,
        client_token: ClientToken | None = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        **kwargs,
    ) -> RegisterTaskWithMaintenanceWindowResult:
        raise NotImplementedError

    @handler("RemoveTagsFromResource")
    def remove_tags_from_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
        tag_keys: KeyList,
        **kwargs,
    ) -> RemoveTagsFromResourceResult:
        raise NotImplementedError

    @handler("ResetServiceSetting")
    def reset_service_setting(
        self, context: RequestContext, setting_id: ServiceSettingId, **kwargs
    ) -> ResetServiceSettingResult:
        raise NotImplementedError

    @handler("ResumeSession")
    def resume_session(
        self, context: RequestContext, session_id: SessionId, **kwargs
    ) -> ResumeSessionResponse:
        raise NotImplementedError

    @handler("SendAutomationSignal")
    def send_automation_signal(
        self,
        context: RequestContext,
        automation_execution_id: AutomationExecutionId,
        signal_type: SignalType,
        payload: AutomationParameterMap | None = None,
        **kwargs,
    ) -> SendAutomationSignalResult:
        raise NotImplementedError

    @handler("SendCommand")
    def send_command(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        instance_ids: InstanceIdList | None = None,
        targets: Targets | None = None,
        document_version: DocumentVersion | None = None,
        document_hash: DocumentHash | None = None,
        document_hash_type: DocumentHashType | None = None,
        timeout_seconds: TimeoutSeconds | None = None,
        comment: Comment | None = None,
        parameters: Parameters | None = None,
        output_s3_region: S3Region | None = None,
        output_s3_bucket_name: S3BucketName | None = None,
        output_s3_key_prefix: S3KeyPrefix | None = None,
        max_concurrency: MaxConcurrency | None = None,
        max_errors: MaxErrors | None = None,
        service_role_arn: ServiceRole | None = None,
        notification_config: NotificationConfig | None = None,
        cloud_watch_output_config: CloudWatchOutputConfig | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        **kwargs,
    ) -> SendCommandResult:
        raise NotImplementedError

    @handler("StartAccessRequest")
    def start_access_request(
        self,
        context: RequestContext,
        reason: String1to256,
        targets: Targets,
        tags: TagList | None = None,
        **kwargs,
    ) -> StartAccessRequestResponse:
        raise NotImplementedError

    @handler("StartAssociationsOnce")
    def start_associations_once(
        self, context: RequestContext, association_ids: AssociationIdList, **kwargs
    ) -> StartAssociationsOnceResult:
        raise NotImplementedError

    @handler("StartAutomationExecution")
    def start_automation_execution(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        document_version: DocumentVersion | None = None,
        parameters: AutomationParameterMap | None = None,
        client_token: IdempotencyToken | None = None,
        mode: ExecutionMode | None = None,
        target_parameter_name: AutomationParameterKey | None = None,
        targets: Targets | None = None,
        target_maps: TargetMaps | None = None,
        max_concurrency: MaxConcurrency | None = None,
        max_errors: MaxErrors | None = None,
        target_locations: TargetLocations | None = None,
        tags: TagList | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        target_locations_url: TargetLocationsURL | None = None,
        **kwargs,
    ) -> StartAutomationExecutionResult:
        raise NotImplementedError

    @handler("StartChangeRequestExecution")
    def start_change_request_execution(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        runbooks: Runbooks,
        scheduled_time: DateTime | None = None,
        document_version: DocumentVersion | None = None,
        parameters: AutomationParameterMap | None = None,
        change_request_name: ChangeRequestName | None = None,
        client_token: IdempotencyToken | None = None,
        auto_approve: Boolean | None = None,
        tags: TagList | None = None,
        scheduled_end_time: DateTime | None = None,
        change_details: ChangeDetailsValue | None = None,
        **kwargs,
    ) -> StartChangeRequestExecutionResult:
        raise NotImplementedError

    @handler("StartExecutionPreview")
    def start_execution_preview(
        self,
        context: RequestContext,
        document_name: DocumentName,
        document_version: DocumentVersion | None = None,
        execution_inputs: ExecutionInputs | None = None,
        **kwargs,
    ) -> StartExecutionPreviewResponse:
        raise NotImplementedError

    @handler("StartSession")
    def start_session(
        self,
        context: RequestContext,
        target: SessionTarget,
        document_name: DocumentARN | None = None,
        reason: SessionReason | None = None,
        parameters: SessionManagerParameters | None = None,
        **kwargs,
    ) -> StartSessionResponse:
        raise NotImplementedError

    @handler("StopAutomationExecution", expand=False)
    def stop_automation_execution(
        self, context: RequestContext, request: StopAutomationExecutionRequest, **kwargs
    ) -> StopAutomationExecutionResult:
        raise NotImplementedError

    @handler("TerminateSession")
    def terminate_session(
        self, context: RequestContext, session_id: SessionId, **kwargs
    ) -> TerminateSessionResponse:
        raise NotImplementedError

    @handler("UnlabelParameterVersion")
    def unlabel_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        parameter_version: PSParameterVersion,
        labels: ParameterLabelList,
        **kwargs,
    ) -> UnlabelParameterVersionResult:
        raise NotImplementedError

    @handler("UpdateAssociation")
    def update_association(
        self,
        context: RequestContext,
        association_id: AssociationId,
        parameters: Parameters | None = None,
        document_version: DocumentVersion | None = None,
        schedule_expression: ScheduleExpression | None = None,
        output_location: InstanceAssociationOutputLocation | None = None,
        name: DocumentARN | None = None,
        targets: Targets | None = None,
        association_name: AssociationName | None = None,
        association_version: AssociationVersion | None = None,
        automation_target_parameter_name: AutomationTargetParameterName | None = None,
        max_errors: MaxErrors | None = None,
        max_concurrency: MaxConcurrency | None = None,
        compliance_severity: AssociationComplianceSeverity | None = None,
        sync_compliance: AssociationSyncCompliance | None = None,
        apply_only_at_cron_interval: ApplyOnlyAtCronInterval | None = None,
        calendar_names: CalendarNameOrARNList | None = None,
        target_locations: TargetLocations | None = None,
        schedule_offset: ScheduleOffset | None = None,
        duration: Duration | None = None,
        target_maps: TargetMaps | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        **kwargs,
    ) -> UpdateAssociationResult:
        raise NotImplementedError

    @handler("UpdateAssociationStatus")
    def update_association_status(
        self,
        context: RequestContext,
        name: DocumentARN,
        instance_id: InstanceId,
        association_status: AssociationStatus,
        **kwargs,
    ) -> UpdateAssociationStatusResult:
        raise NotImplementedError

    @handler("UpdateDocument")
    def update_document(
        self,
        context: RequestContext,
        content: DocumentContent,
        name: DocumentName,
        attachments: AttachmentsSourceList | None = None,
        display_name: DocumentDisplayName | None = None,
        version_name: DocumentVersionName | None = None,
        document_version: DocumentVersion | None = None,
        document_format: DocumentFormat | None = None,
        target_type: TargetType | None = None,
        **kwargs,
    ) -> UpdateDocumentResult:
        raise NotImplementedError

    @handler("UpdateDocumentDefaultVersion")
    def update_document_default_version(
        self,
        context: RequestContext,
        name: DocumentName,
        document_version: DocumentVersionNumber,
        **kwargs,
    ) -> UpdateDocumentDefaultVersionResult:
        raise NotImplementedError

    @handler("UpdateDocumentMetadata")
    def update_document_metadata(
        self,
        context: RequestContext,
        name: DocumentName,
        document_reviews: DocumentReviews,
        document_version: DocumentVersion | None = None,
        **kwargs,
    ) -> UpdateDocumentMetadataResponse:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindow")
    def update_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        name: MaintenanceWindowName | None = None,
        description: MaintenanceWindowDescription | None = None,
        start_date: MaintenanceWindowStringDateTime | None = None,
        end_date: MaintenanceWindowStringDateTime | None = None,
        schedule: MaintenanceWindowSchedule | None = None,
        schedule_timezone: MaintenanceWindowTimezone | None = None,
        schedule_offset: MaintenanceWindowOffset | None = None,
        duration: MaintenanceWindowDurationHours | None = None,
        cutoff: MaintenanceWindowCutoff | None = None,
        allow_unassociated_targets: MaintenanceWindowAllowUnassociatedTargets | None = None,
        enabled: MaintenanceWindowEnabled | None = None,
        replace: Boolean | None = None,
        **kwargs,
    ) -> UpdateMaintenanceWindowResult:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindowTarget")
    def update_maintenance_window_target(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        targets: Targets | None = None,
        owner_information: OwnerInformation | None = None,
        name: MaintenanceWindowName | None = None,
        description: MaintenanceWindowDescription | None = None,
        replace: Boolean | None = None,
        **kwargs,
    ) -> UpdateMaintenanceWindowTargetResult:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindowTask")
    def update_maintenance_window_task(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        targets: Targets | None = None,
        task_arn: MaintenanceWindowTaskArn | None = None,
        service_role_arn: ServiceRole | None = None,
        task_parameters: MaintenanceWindowTaskParameters | None = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters | None = None,
        priority: MaintenanceWindowTaskPriority | None = None,
        max_concurrency: MaxConcurrency | None = None,
        max_errors: MaxErrors | None = None,
        logging_info: LoggingInfo | None = None,
        name: MaintenanceWindowName | None = None,
        description: MaintenanceWindowDescription | None = None,
        replace: Boolean | None = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior | None = None,
        alarm_configuration: AlarmConfiguration | None = None,
        **kwargs,
    ) -> UpdateMaintenanceWindowTaskResult:
        raise NotImplementedError

    @handler("UpdateManagedInstanceRole")
    def update_managed_instance_role(
        self, context: RequestContext, instance_id: ManagedInstanceId, iam_role: IamRole, **kwargs
    ) -> UpdateManagedInstanceRoleResult:
        raise NotImplementedError

    @handler("UpdateOpsItem")
    def update_ops_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        description: OpsItemDescription | None = None,
        operational_data: OpsItemOperationalData | None = None,
        operational_data_to_delete: OpsItemOpsDataKeysList | None = None,
        notifications: OpsItemNotifications | None = None,
        priority: OpsItemPriority | None = None,
        related_ops_items: RelatedOpsItems | None = None,
        status: OpsItemStatus | None = None,
        title: OpsItemTitle | None = None,
        category: OpsItemCategory | None = None,
        severity: OpsItemSeverity | None = None,
        actual_start_time: DateTime | None = None,
        actual_end_time: DateTime | None = None,
        planned_start_time: DateTime | None = None,
        planned_end_time: DateTime | None = None,
        ops_item_arn: OpsItemArn | None = None,
        **kwargs,
    ) -> UpdateOpsItemResponse:
        raise NotImplementedError

    @handler("UpdateOpsMetadata")
    def update_ops_metadata(
        self,
        context: RequestContext,
        ops_metadata_arn: OpsMetadataArn,
        metadata_to_update: MetadataMap | None = None,
        keys_to_delete: MetadataKeysToDeleteList | None = None,
        **kwargs,
    ) -> UpdateOpsMetadataResult:
        raise NotImplementedError

    @handler("UpdatePatchBaseline")
    def update_patch_baseline(
        self,
        context: RequestContext,
        baseline_id: BaselineId,
        name: BaselineName | None = None,
        global_filters: PatchFilterGroup | None = None,
        approval_rules: PatchRuleGroup | None = None,
        approved_patches: PatchIdList | None = None,
        approved_patches_compliance_level: PatchComplianceLevel | None = None,
        approved_patches_enable_non_security: Boolean | None = None,
        rejected_patches: PatchIdList | None = None,
        rejected_patches_action: PatchAction | None = None,
        description: BaselineDescription | None = None,
        sources: PatchSourceList | None = None,
        available_security_updates_compliance_status: PatchComplianceStatus | None = None,
        replace: Boolean | None = None,
        **kwargs,
    ) -> UpdatePatchBaselineResult:
        raise NotImplementedError

    @handler("UpdateResourceDataSync")
    def update_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        sync_type: ResourceDataSyncType,
        sync_source: ResourceDataSyncSource,
        **kwargs,
    ) -> UpdateResourceDataSyncResult:
        raise NotImplementedError

    @handler("UpdateServiceSetting")
    def update_service_setting(
        self,
        context: RequestContext,
        setting_id: ServiceSettingId,
        setting_value: ServiceSettingValue,
        **kwargs,
    ) -> UpdateServiceSettingResult:
        raise NotImplementedError
