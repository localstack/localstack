from datetime import datetime
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Account = str
AccountId = str
ActivationCode = str
ActivationDescription = str
ActivationId = str
AgentErrorCode = str
AggregatorSchemaOnly = bool
AlarmName = str
AllowedPattern = str
ApplyOnlyAtCronInterval = bool
ApproveAfterDays = int
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
EffectiveInstanceAssociationMaxResults = int
ErrorCount = int
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
InstancePatchStateFilterKey = str
InstancePatchStateFilterValue = str
InstanceTagName = str
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
IsSubTypeSchema = bool
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
StringDateTime = str
TagKey = str
TagValue = str
TargetCount = int
TargetKey = str
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


class AssociationComplianceSeverity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNSPECIFIED = "UNSPECIFIED"


class AssociationExecutionFilterKey(str):
    ExecutionId = "ExecutionId"
    Status = "Status"
    CreatedTime = "CreatedTime"


class AssociationExecutionTargetsFilterKey(str):
    Status = "Status"
    ResourceId = "ResourceId"
    ResourceType = "ResourceType"


class AssociationFilterKey(str):
    InstanceId = "InstanceId"
    Name = "Name"
    AssociationId = "AssociationId"
    AssociationStatusName = "AssociationStatusName"
    LastExecutedBefore = "LastExecutedBefore"
    LastExecutedAfter = "LastExecutedAfter"
    AssociationName = "AssociationName"
    ResourceGroupName = "ResourceGroupName"


class AssociationFilterOperatorType(str):
    EQUAL = "EQUAL"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN = "GREATER_THAN"


class AssociationStatusName(str):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"


class AssociationSyncCompliance(str):
    AUTO = "AUTO"
    MANUAL = "MANUAL"


class AttachmentHashType(str):
    Sha256 = "Sha256"


class AttachmentsSourceKey(str):
    SourceUrl = "SourceUrl"
    S3FileUrl = "S3FileUrl"
    AttachmentReference = "AttachmentReference"


class AutomationExecutionFilterKey(str):
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


class AutomationExecutionStatus(str):
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


class AutomationSubtype(str):
    ChangeRequest = "ChangeRequest"


class AutomationType(str):
    CrossAccount = "CrossAccount"
    Local = "Local"


class CalendarState(str):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class CommandFilterKey(str):
    InvokedAfter = "InvokedAfter"
    InvokedBefore = "InvokedBefore"
    Status = "Status"
    ExecutionStage = "ExecutionStage"
    DocumentName = "DocumentName"


class CommandInvocationStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Delayed = "Delayed"
    Success = "Success"
    Cancelled = "Cancelled"
    TimedOut = "TimedOut"
    Failed = "Failed"
    Cancelling = "Cancelling"


class CommandPluginStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Success = "Success"
    TimedOut = "TimedOut"
    Cancelled = "Cancelled"
    Failed = "Failed"


class CommandStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Success = "Success"
    Cancelled = "Cancelled"
    Failed = "Failed"
    TimedOut = "TimedOut"
    Cancelling = "Cancelling"


class ComplianceQueryOperatorType(str):
    EQUAL = "EQUAL"
    NOT_EQUAL = "NOT_EQUAL"
    BEGIN_WITH = "BEGIN_WITH"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN = "GREATER_THAN"


class ComplianceSeverity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNSPECIFIED = "UNSPECIFIED"


class ComplianceStatus(str):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class ComplianceUploadType(str):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class ConnectionStatus(str):
    connected = "connected"
    notconnected = "notconnected"


class DescribeActivationsFilterKeys(str):
    ActivationIds = "ActivationIds"
    DefaultInstanceName = "DefaultInstanceName"
    IamRole = "IamRole"


class DocumentFilterKey(str):
    Name = "Name"
    Owner = "Owner"
    PlatformTypes = "PlatformTypes"
    DocumentType = "DocumentType"


class DocumentFormat(str):
    YAML = "YAML"
    JSON = "JSON"
    TEXT = "TEXT"


class DocumentHashType(str):
    Sha256 = "Sha256"
    Sha1 = "Sha1"


class DocumentMetadataEnum(str):
    DocumentReviews = "DocumentReviews"


class DocumentParameterType(str):
    String = "String"
    StringList = "StringList"


class DocumentPermissionType(str):
    Share = "Share"


class DocumentReviewAction(str):
    SendForReview = "SendForReview"
    UpdateReview = "UpdateReview"
    Approve = "Approve"
    Reject = "Reject"


class DocumentReviewCommentType(str):
    Comment = "Comment"


class DocumentStatus(str):
    Creating = "Creating"
    Active = "Active"
    Updating = "Updating"
    Deleting = "Deleting"
    Failed = "Failed"


class DocumentType(str):
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


class ExecutionMode(str):
    Auto = "Auto"
    Interactive = "Interactive"


class ExternalAlarmState(str):
    UNKNOWN = "UNKNOWN"
    ALARM = "ALARM"


class Fault(str):
    Client = "Client"
    Server = "Server"
    Unknown = "Unknown"


class InstanceInformationFilterKey(str):
    InstanceIds = "InstanceIds"
    AgentVersion = "AgentVersion"
    PingStatus = "PingStatus"
    PlatformTypes = "PlatformTypes"
    ActivationIds = "ActivationIds"
    IamRole = "IamRole"
    ResourceType = "ResourceType"
    AssociationStatus = "AssociationStatus"


class InstancePatchStateOperatorType(str):
    Equal = "Equal"
    NotEqual = "NotEqual"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"


class InventoryAttributeDataType(str):
    string = "string"
    number = "number"


class InventoryDeletionStatus(str):
    InProgress = "InProgress"
    Complete = "Complete"


class InventoryQueryOperatorType(str):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    Exists = "Exists"


class InventorySchemaDeleteOption(str):
    DisableSchema = "DisableSchema"
    DeleteSchema = "DeleteSchema"


class LastResourceDataSyncStatus(str):
    Successful = "Successful"
    Failed = "Failed"
    InProgress = "InProgress"


class MaintenanceWindowExecutionStatus(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    SKIPPED_OVERLAPPING = "SKIPPED_OVERLAPPING"


class MaintenanceWindowResourceType(str):
    INSTANCE = "INSTANCE"
    RESOURCE_GROUP = "RESOURCE_GROUP"


class MaintenanceWindowTaskCutoffBehavior(str):
    CONTINUE_TASK = "CONTINUE_TASK"
    CANCEL_TASK = "CANCEL_TASK"


class MaintenanceWindowTaskType(str):
    RUN_COMMAND = "RUN_COMMAND"
    AUTOMATION = "AUTOMATION"
    STEP_FUNCTIONS = "STEP_FUNCTIONS"
    LAMBDA = "LAMBDA"


class NotificationEvent(str):
    All = "All"
    InProgress = "InProgress"
    Success = "Success"
    TimedOut = "TimedOut"
    Cancelled = "Cancelled"
    Failed = "Failed"


class NotificationType(str):
    Command = "Command"
    Invocation = "Invocation"


class OperatingSystem(str):
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


class OpsFilterOperatorType(str):
    Equal = "Equal"
    NotEqual = "NotEqual"
    BeginWith = "BeginWith"
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    Exists = "Exists"


class OpsItemDataType(str):
    SearchableString = "SearchableString"
    String = "String"


class OpsItemEventFilterKey(str):
    OpsItemId = "OpsItemId"


class OpsItemEventFilterOperator(str):
    Equal = "Equal"


class OpsItemFilterKey(str):
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
    ChangeRequestByRequesterArn = "ChangeRequestByRequesterArn"
    ChangeRequestByRequesterName = "ChangeRequestByRequesterName"
    ChangeRequestByApproverArn = "ChangeRequestByApproverArn"
    ChangeRequestByApproverName = "ChangeRequestByApproverName"
    ChangeRequestByTemplate = "ChangeRequestByTemplate"
    ChangeRequestByTargetsResourceGroup = "ChangeRequestByTargetsResourceGroup"
    InsightByType = "InsightByType"
    AccountId = "AccountId"


class OpsItemFilterOperator(str):
    Equal = "Equal"
    Contains = "Contains"
    GreaterThan = "GreaterThan"
    LessThan = "LessThan"


class OpsItemRelatedItemsFilterKey(str):
    ResourceType = "ResourceType"
    AssociationId = "AssociationId"
    ResourceUri = "ResourceUri"


class OpsItemRelatedItemsFilterOperator(str):
    Equal = "Equal"


class OpsItemStatus(str):
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
    Rejected = "Rejected"
    Closed = "Closed"


class ParameterTier(str):
    Standard = "Standard"
    Advanced = "Advanced"
    Intelligent_Tiering = "Intelligent-Tiering"


class ParameterType(str):
    String = "String"
    StringList = "StringList"
    SecureString = "SecureString"


class ParametersFilterKey(str):
    Name = "Name"
    Type = "Type"
    KeyId = "KeyId"


class PatchAction(str):
    ALLOW_AS_DEPENDENCY = "ALLOW_AS_DEPENDENCY"
    BLOCK = "BLOCK"


class PatchComplianceDataState(str):
    INSTALLED = "INSTALLED"
    INSTALLED_OTHER = "INSTALLED_OTHER"
    INSTALLED_PENDING_REBOOT = "INSTALLED_PENDING_REBOOT"
    INSTALLED_REJECTED = "INSTALLED_REJECTED"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"


class PatchComplianceLevel(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNSPECIFIED = "UNSPECIFIED"


class PatchDeploymentStatus(str):
    APPROVED = "APPROVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXPLICIT_APPROVED = "EXPLICIT_APPROVED"
    EXPLICIT_REJECTED = "EXPLICIT_REJECTED"


class PatchFilterKey(str):
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


class PatchOperationType(str):
    Scan = "Scan"
    Install = "Install"


class PatchProperty(str):
    PRODUCT = "PRODUCT"
    PRODUCT_FAMILY = "PRODUCT_FAMILY"
    CLASSIFICATION = "CLASSIFICATION"
    MSRC_SEVERITY = "MSRC_SEVERITY"
    PRIORITY = "PRIORITY"
    SEVERITY = "SEVERITY"


class PatchSet(str):
    OS = "OS"
    APPLICATION = "APPLICATION"


class PingStatus(str):
    Online = "Online"
    ConnectionLost = "ConnectionLost"
    Inactive = "Inactive"


class PlatformType(str):
    Windows = "Windows"
    Linux = "Linux"
    MacOS = "MacOS"


class RebootOption(str):
    RebootIfNeeded = "RebootIfNeeded"
    NoReboot = "NoReboot"


class ResourceDataSyncS3Format(str):
    JsonSerDe = "JsonSerDe"


class ResourceType(str):
    ManagedInstance = "ManagedInstance"
    EC2Instance = "EC2Instance"


class ResourceTypeForTagging(str):
    Document = "Document"
    ManagedInstance = "ManagedInstance"
    MaintenanceWindow = "MaintenanceWindow"
    Parameter = "Parameter"
    PatchBaseline = "PatchBaseline"
    OpsItem = "OpsItem"
    OpsMetadata = "OpsMetadata"
    Automation = "Automation"
    Association = "Association"


class ReviewStatus(str):
    APPROVED = "APPROVED"
    NOT_REVIEWED = "NOT_REVIEWED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"


class SessionFilterKey(str):
    InvokedAfter = "InvokedAfter"
    InvokedBefore = "InvokedBefore"
    Target = "Target"
    Owner = "Owner"
    Status = "Status"
    SessionId = "SessionId"


class SessionState(str):
    Active = "Active"
    History = "History"


class SessionStatus(str):
    Connected = "Connected"
    Connecting = "Connecting"
    Disconnected = "Disconnected"
    Terminated = "Terminated"
    Terminating = "Terminating"
    Failed = "Failed"


class SignalType(str):
    Approve = "Approve"
    Reject = "Reject"
    StartStep = "StartStep"
    StopStep = "StopStep"
    Resume = "Resume"


class SourceType(str):
    AWS_EC2_Instance = "AWS::EC2::Instance"
    AWS_IoT_Thing = "AWS::IoT::Thing"
    AWS_SSM_ManagedInstance = "AWS::SSM::ManagedInstance"


class StepExecutionFilterKey(str):
    StartTimeBefore = "StartTimeBefore"
    StartTimeAfter = "StartTimeAfter"
    StepExecutionStatus = "StepExecutionStatus"
    StepExecutionId = "StepExecutionId"
    StepName = "StepName"
    Action = "Action"
    ParentStepExecutionId = "ParentStepExecutionId"
    ParentStepIteration = "ParentStepIteration"
    ParentStepIteratorValue = "ParentStepIteratorValue"


class StopType(str):
    Complete = "Complete"
    Cancel = "Cancel"


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
    TypeName: Optional[InventoryItemTypeName]


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
    TypeName: Optional[InventoryItemTypeName]


class ItemSizeLimitExceededException(ServiceException):
    code: str = "ItemSizeLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    TypeName: Optional[InventoryItemTypeName]


class MaxDocumentSizeExceeded(ServiceException):
    code: str = "MaxDocumentSizeExceeded"
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
    OpsItemId: Optional[String]


class OpsItemConflictException(ServiceException):
    code: str = "OpsItemConflictException"
    sender_fault: bool = False
    status_code: int = 400


OpsItemParameterNamesList = List[String]


class OpsItemInvalidParameterException(ServiceException):
    code: str = "OpsItemInvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400
    ParameterNames: Optional[OpsItemParameterNamesList]


class OpsItemLimitExceededException(ServiceException):
    code: str = "OpsItemLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceTypes: Optional[OpsItemParameterNamesList]
    Limit: Optional[Integer]
    LimitType: Optional[String]


class OpsItemNotFoundException(ServiceException):
    code: str = "OpsItemNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class OpsItemRelatedItemAlreadyExistsException(ServiceException):
    code: str = "OpsItemRelatedItemAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceUri: Optional[OpsItemRelatedItemAssociationResourceUri]
    OpsItemId: Optional[OpsItemId]


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
    SyncName: Optional[ResourceDataSyncName]


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
    SyncName: Optional[ResourceDataSyncName]
    SyncType: Optional[ResourceDataSyncType]


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceLimitExceededException(ServiceException):
    code: str = "ResourceLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourcePolicyConflictException(ServiceException):
    code: str = "ResourcePolicyConflictException"
    sender_fault: bool = False
    status_code: int = 400


ResourcePolicyParameterNamesList = List[String]


class ResourcePolicyInvalidParameterException(ServiceException):
    code: str = "ResourcePolicyInvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400
    ParameterNames: Optional[ResourcePolicyParameterNamesList]


class ResourcePolicyLimitExceededException(ServiceException):
    code: str = "ResourcePolicyLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    Limit: Optional[Integer]
    LimitType: Optional[String]


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
    TypeName: Optional[InventoryItemTypeName]


class UnsupportedInventorySchemaVersionException(ServiceException):
    code: str = "UnsupportedInventorySchemaVersionException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedOperatingSystem(ServiceException):
    code: str = "UnsupportedOperatingSystem"
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


AccountIdList = List[AccountId]


class AccountSharingInfo(TypedDict, total=False):
    AccountId: Optional[AccountId]
    SharedDocumentVersion: Optional[SharedDocumentVersion]


AccountSharingInfoList = List[AccountSharingInfo]
Accounts = List[Account]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]
CreatedDate = datetime
ExpirationDate = datetime


class Activation(TypedDict, total=False):
    ActivationId: Optional[ActivationId]
    Description: Optional[ActivationDescription]
    DefaultInstanceName: Optional[DefaultInstanceName]
    IamRole: Optional[IamRole]
    RegistrationLimit: Optional[RegistrationLimit]
    RegistrationsCount: Optional[RegistrationsCount]
    ExpirationDate: Optional[ExpirationDate]
    Expired: Optional[Boolean]
    CreatedDate: Optional[CreatedDate]
    Tags: Optional[TagList]


ActivationList = List[Activation]


class AddTagsToResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId
    Tags: TagList


class AddTagsToResourceResult(TypedDict, total=False):
    pass


class Alarm(TypedDict, total=False):
    Name: AlarmName


AlarmList = List[Alarm]


class AlarmConfiguration(TypedDict, total=False):
    IgnorePollAlarmFailure: Optional[Boolean]
    Alarms: AlarmList


class AlarmStateInformation(TypedDict, total=False):
    Name: AlarmName
    State: ExternalAlarmState


AlarmStateInformationList = List[AlarmStateInformation]


class AssociateOpsItemRelatedItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    AssociationType: OpsItemRelatedItemAssociationType
    ResourceType: OpsItemRelatedItemAssociationResourceType
    ResourceUri: OpsItemRelatedItemAssociationResourceUri


class AssociateOpsItemRelatedItemResponse(TypedDict, total=False):
    AssociationId: Optional[OpsItemRelatedItemAssociationId]


TargetMapValueList = List[TargetMapValue]
TargetMap = Dict[TargetMapKey, TargetMapValueList]
TargetMaps = List[TargetMap]
AssociationStatusAggregatedCount = Dict[StatusName, InstanceCount]


class AssociationOverview(TypedDict, total=False):
    Status: Optional[StatusName]
    DetailedStatus: Optional[StatusName]
    AssociationStatusAggregatedCount: Optional[AssociationStatusAggregatedCount]


DateTime = datetime
TargetValues = List[TargetValue]


class Target(TypedDict, total=False):
    Key: Optional[TargetKey]
    Values: Optional[TargetValues]


Targets = List[Target]


class Association(TypedDict, total=False):
    Name: Optional[DocumentARN]
    InstanceId: Optional[InstanceId]
    AssociationId: Optional[AssociationId]
    AssociationVersion: Optional[AssociationVersion]
    DocumentVersion: Optional[DocumentVersion]
    Targets: Optional[Targets]
    LastExecutionDate: Optional[DateTime]
    Overview: Optional[AssociationOverview]
    ScheduleExpression: Optional[ScheduleExpression]
    AssociationName: Optional[AssociationName]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]


Regions = List[Region]


class TargetLocation(TypedDict, total=False):
    Accounts: Optional[Accounts]
    Regions: Optional[Regions]
    TargetLocationMaxConcurrency: Optional[MaxConcurrency]
    TargetLocationMaxErrors: Optional[MaxErrors]
    ExecutionRoleName: Optional[ExecutionRoleName]
    TargetLocationAlarmConfiguration: Optional[AlarmConfiguration]


TargetLocations = List[TargetLocation]
CalendarNameOrARNList = List[CalendarNameOrARN]


class S3OutputLocation(TypedDict, total=False):
    OutputS3Region: Optional[S3Region]
    OutputS3BucketName: Optional[S3BucketName]
    OutputS3KeyPrefix: Optional[S3KeyPrefix]


class InstanceAssociationOutputLocation(TypedDict, total=False):
    S3Location: Optional[S3OutputLocation]


ParameterValueList = List[ParameterValue]
Parameters = Dict[ParameterName, ParameterValueList]


class AssociationStatus(TypedDict, total=False):
    Date: DateTime
    Name: AssociationStatusName
    Message: StatusMessage
    AdditionalInfo: Optional[StatusAdditionalInfo]


class AssociationDescription(TypedDict, total=False):
    Name: Optional[DocumentARN]
    InstanceId: Optional[InstanceId]
    AssociationVersion: Optional[AssociationVersion]
    Date: Optional[DateTime]
    LastUpdateAssociationDate: Optional[DateTime]
    Status: Optional[AssociationStatus]
    Overview: Optional[AssociationOverview]
    DocumentVersion: Optional[DocumentVersion]
    AutomationTargetParameterName: Optional[AutomationTargetParameterName]
    Parameters: Optional[Parameters]
    AssociationId: Optional[AssociationId]
    Targets: Optional[Targets]
    ScheduleExpression: Optional[ScheduleExpression]
    OutputLocation: Optional[InstanceAssociationOutputLocation]
    LastExecutionDate: Optional[DateTime]
    LastSuccessfulExecutionDate: Optional[DateTime]
    AssociationName: Optional[AssociationName]
    MaxErrors: Optional[MaxErrors]
    MaxConcurrency: Optional[MaxConcurrency]
    ComplianceSeverity: Optional[AssociationComplianceSeverity]
    SyncCompliance: Optional[AssociationSyncCompliance]
    ApplyOnlyAtCronInterval: Optional[ApplyOnlyAtCronInterval]
    CalendarNames: Optional[CalendarNameOrARNList]
    TargetLocations: Optional[TargetLocations]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]


AssociationDescriptionList = List[AssociationDescription]


class AssociationExecution(TypedDict, total=False):
    AssociationId: Optional[AssociationId]
    AssociationVersion: Optional[AssociationVersion]
    ExecutionId: Optional[AssociationExecutionId]
    Status: Optional[StatusName]
    DetailedStatus: Optional[StatusName]
    CreatedTime: Optional[DateTime]
    LastExecutionDate: Optional[DateTime]
    ResourceCountByStatus: Optional[ResourceCountByStatus]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]


class AssociationExecutionFilter(TypedDict, total=False):
    Key: AssociationExecutionFilterKey
    Value: AssociationExecutionFilterValue
    Type: AssociationFilterOperatorType


AssociationExecutionFilterList = List[AssociationExecutionFilter]


class OutputSource(TypedDict, total=False):
    OutputSourceId: Optional[OutputSourceId]
    OutputSourceType: Optional[OutputSourceType]


class AssociationExecutionTarget(TypedDict, total=False):
    AssociationId: Optional[AssociationId]
    AssociationVersion: Optional[AssociationVersion]
    ExecutionId: Optional[AssociationExecutionId]
    ResourceId: Optional[AssociationResourceId]
    ResourceType: Optional[AssociationResourceType]
    Status: Optional[StatusName]
    DetailedStatus: Optional[StatusName]
    LastExecutionDate: Optional[DateTime]
    OutputSource: Optional[OutputSource]


class AssociationExecutionTargetsFilter(TypedDict, total=False):
    Key: AssociationExecutionTargetsFilterKey
    Value: AssociationExecutionTargetsFilterValue


AssociationExecutionTargetsFilterList = List[AssociationExecutionTargetsFilter]
AssociationExecutionTargetsList = List[AssociationExecutionTarget]
AssociationExecutionsList = List[AssociationExecution]


class AssociationFilter(TypedDict, total=False):
    key: AssociationFilterKey
    value: AssociationFilterValue


AssociationFilterList = List[AssociationFilter]
AssociationIdList = List[AssociationId]
AssociationList = List[Association]


class AssociationVersionInfo(TypedDict, total=False):
    AssociationId: Optional[AssociationId]
    AssociationVersion: Optional[AssociationVersion]
    CreatedDate: Optional[DateTime]
    Name: Optional[DocumentARN]
    DocumentVersion: Optional[DocumentVersion]
    Parameters: Optional[Parameters]
    Targets: Optional[Targets]
    ScheduleExpression: Optional[ScheduleExpression]
    OutputLocation: Optional[InstanceAssociationOutputLocation]
    AssociationName: Optional[AssociationName]
    MaxErrors: Optional[MaxErrors]
    MaxConcurrency: Optional[MaxConcurrency]
    ComplianceSeverity: Optional[AssociationComplianceSeverity]
    SyncCompliance: Optional[AssociationSyncCompliance]
    ApplyOnlyAtCronInterval: Optional[ApplyOnlyAtCronInterval]
    CalendarNames: Optional[CalendarNameOrARNList]
    TargetLocations: Optional[TargetLocations]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]


AssociationVersionList = List[AssociationVersionInfo]
ContentLength = int


class AttachmentContent(TypedDict, total=False):
    Name: Optional[AttachmentName]
    Size: Optional[ContentLength]
    Hash: Optional[AttachmentHash]
    HashType: Optional[AttachmentHashType]
    Url: Optional[AttachmentUrl]


AttachmentContentList = List[AttachmentContent]


class AttachmentInformation(TypedDict, total=False):
    Name: Optional[AttachmentName]


AttachmentInformationList = List[AttachmentInformation]
AttachmentsSourceValues = List[AttachmentsSourceValue]


class AttachmentsSource(TypedDict, total=False):
    Key: Optional[AttachmentsSourceKey]
    Values: Optional[AttachmentsSourceValues]
    Name: Optional[AttachmentIdentifier]


AttachmentsSourceList = List[AttachmentsSource]
AutomationParameterValueList = List[AutomationParameterValue]
AutomationParameterMap = Dict[AutomationParameterKey, AutomationParameterValueList]


class Runbook(TypedDict, total=False):
    DocumentName: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    Parameters: Optional[AutomationParameterMap]
    TargetParameterName: Optional[AutomationParameterKey]
    Targets: Optional[Targets]
    TargetMaps: Optional[TargetMaps]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    TargetLocations: Optional[TargetLocations]


Runbooks = List[Runbook]


class ProgressCounters(TypedDict, total=False):
    TotalSteps: Optional[Integer]
    SuccessSteps: Optional[Integer]
    FailedSteps: Optional[Integer]
    CancelledSteps: Optional[Integer]
    TimedOutSteps: Optional[Integer]


TargetParameterList = List[ParameterValue]


class ResolvedTargets(TypedDict, total=False):
    ParameterValues: Optional[TargetParameterList]
    Truncated: Optional[Boolean]


class ParentStepDetails(TypedDict, total=False):
    StepExecutionId: Optional[String]
    StepName: Optional[String]
    Action: Optional[AutomationActionName]
    Iteration: Optional[Integer]
    IteratorValue: Optional[String]


ValidNextStepList = List[ValidNextStep]


class FailureDetails(TypedDict, total=False):
    FailureStage: Optional[String]
    FailureType: Optional[String]
    Details: Optional[AutomationParameterMap]


NormalStringMap = Dict[String, String]
Long = int


class StepExecution(TypedDict, total=False):
    StepName: Optional[String]
    Action: Optional[AutomationActionName]
    TimeoutSeconds: Optional[Long]
    OnFailure: Optional[String]
    MaxAttempts: Optional[Integer]
    ExecutionStartTime: Optional[DateTime]
    ExecutionEndTime: Optional[DateTime]
    StepStatus: Optional[AutomationExecutionStatus]
    ResponseCode: Optional[String]
    Inputs: Optional[NormalStringMap]
    Outputs: Optional[AutomationParameterMap]
    Response: Optional[String]
    FailureMessage: Optional[String]
    FailureDetails: Optional[FailureDetails]
    StepExecutionId: Optional[String]
    OverriddenParameters: Optional[AutomationParameterMap]
    IsEnd: Optional[Boolean]
    NextStep: Optional[String]
    IsCritical: Optional[Boolean]
    ValidNextSteps: Optional[ValidNextStepList]
    Targets: Optional[Targets]
    TargetLocation: Optional[TargetLocation]
    TriggeredAlarms: Optional[AlarmStateInformationList]
    ParentStepDetails: Optional[ParentStepDetails]


StepExecutionList = List[StepExecution]


class AutomationExecution(TypedDict, total=False):
    AutomationExecutionId: Optional[AutomationExecutionId]
    DocumentName: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    ExecutionStartTime: Optional[DateTime]
    ExecutionEndTime: Optional[DateTime]
    AutomationExecutionStatus: Optional[AutomationExecutionStatus]
    StepExecutions: Optional[StepExecutionList]
    StepExecutionsTruncated: Optional[Boolean]
    Parameters: Optional[AutomationParameterMap]
    Outputs: Optional[AutomationParameterMap]
    FailureMessage: Optional[String]
    Mode: Optional[ExecutionMode]
    ParentAutomationExecutionId: Optional[AutomationExecutionId]
    ExecutedBy: Optional[String]
    CurrentStepName: Optional[String]
    CurrentAction: Optional[String]
    TargetParameterName: Optional[AutomationParameterKey]
    Targets: Optional[Targets]
    TargetMaps: Optional[TargetMaps]
    ResolvedTargets: Optional[ResolvedTargets]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    Target: Optional[String]
    TargetLocations: Optional[TargetLocations]
    ProgressCounters: Optional[ProgressCounters]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]
    AutomationSubtype: Optional[AutomationSubtype]
    ScheduledTime: Optional[DateTime]
    Runbooks: Optional[Runbooks]
    OpsItemId: Optional[String]
    AssociationId: Optional[String]
    ChangeRequestName: Optional[ChangeRequestName]
    Variables: Optional[AutomationParameterMap]


AutomationExecutionFilterValueList = List[AutomationExecutionFilterValue]


class AutomationExecutionFilter(TypedDict, total=False):
    Key: AutomationExecutionFilterKey
    Values: AutomationExecutionFilterValueList


AutomationExecutionFilterList = List[AutomationExecutionFilter]


class AutomationExecutionMetadata(TypedDict, total=False):
    AutomationExecutionId: Optional[AutomationExecutionId]
    DocumentName: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    AutomationExecutionStatus: Optional[AutomationExecutionStatus]
    ExecutionStartTime: Optional[DateTime]
    ExecutionEndTime: Optional[DateTime]
    ExecutedBy: Optional[String]
    LogFile: Optional[String]
    Outputs: Optional[AutomationParameterMap]
    Mode: Optional[ExecutionMode]
    ParentAutomationExecutionId: Optional[AutomationExecutionId]
    CurrentStepName: Optional[String]
    CurrentAction: Optional[String]
    FailureMessage: Optional[String]
    TargetParameterName: Optional[AutomationParameterKey]
    Targets: Optional[Targets]
    TargetMaps: Optional[TargetMaps]
    ResolvedTargets: Optional[ResolvedTargets]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    Target: Optional[String]
    AutomationType: Optional[AutomationType]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]
    AutomationSubtype: Optional[AutomationSubtype]
    ScheduledTime: Optional[DateTime]
    Runbooks: Optional[Runbooks]
    OpsItemId: Optional[String]
    AssociationId: Optional[String]
    ChangeRequestName: Optional[ChangeRequestName]


AutomationExecutionMetadataList = List[AutomationExecutionMetadata]
PatchSourceProductList = List[PatchSourceProduct]


class PatchSource(TypedDict, total=False):
    Name: PatchSourceName
    Products: PatchSourceProductList
    Configuration: PatchSourceConfiguration


PatchSourceList = List[PatchSource]
PatchIdList = List[PatchId]
PatchFilterValueList = List[PatchFilterValue]


class PatchFilter(TypedDict, total=False):
    Key: PatchFilterKey
    Values: PatchFilterValueList


PatchFilterList = List[PatchFilter]


class PatchFilterGroup(TypedDict, total=False):
    PatchFilters: PatchFilterList


class PatchRule(TypedDict, total=False):
    PatchFilterGroup: PatchFilterGroup
    ComplianceLevel: Optional[PatchComplianceLevel]
    ApproveAfterDays: Optional[ApproveAfterDays]
    ApproveUntilDate: Optional[PatchStringDateTime]
    EnableNonSecurity: Optional[Boolean]


PatchRuleList = List[PatchRule]


class PatchRuleGroup(TypedDict, total=False):
    PatchRules: PatchRuleList


class BaselineOverride(TypedDict, total=False):
    OperatingSystem: Optional[OperatingSystem]
    GlobalFilters: Optional[PatchFilterGroup]
    ApprovalRules: Optional[PatchRuleGroup]
    ApprovedPatches: Optional[PatchIdList]
    ApprovedPatchesComplianceLevel: Optional[PatchComplianceLevel]
    RejectedPatches: Optional[PatchIdList]
    RejectedPatchesAction: Optional[PatchAction]
    ApprovedPatchesEnableNonSecurity: Optional[Boolean]
    Sources: Optional[PatchSourceList]


InstanceIdList = List[InstanceId]


class CancelCommandRequest(ServiceRequest):
    CommandId: CommandId
    InstanceIds: Optional[InstanceIdList]


class CancelCommandResult(TypedDict, total=False):
    pass


class CancelMaintenanceWindowExecutionRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId


class CancelMaintenanceWindowExecutionResult(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]


CategoryEnumList = List[Category]
CategoryList = List[Category]


class CloudWatchOutputConfig(TypedDict, total=False):
    CloudWatchLogGroupName: Optional[CloudWatchLogGroupName]
    CloudWatchOutputEnabled: Optional[CloudWatchOutputEnabled]


NotificationEventList = List[NotificationEvent]


class NotificationConfig(TypedDict, total=False):
    NotificationArn: Optional[NotificationArn]
    NotificationEvents: Optional[NotificationEventList]
    NotificationType: Optional[NotificationType]


class Command(TypedDict, total=False):
    CommandId: Optional[CommandId]
    DocumentName: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    Comment: Optional[Comment]
    ExpiresAfter: Optional[DateTime]
    Parameters: Optional[Parameters]
    InstanceIds: Optional[InstanceIdList]
    Targets: Optional[Targets]
    RequestedDateTime: Optional[DateTime]
    Status: Optional[CommandStatus]
    StatusDetails: Optional[StatusDetails]
    OutputS3Region: Optional[S3Region]
    OutputS3BucketName: Optional[S3BucketName]
    OutputS3KeyPrefix: Optional[S3KeyPrefix]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    TargetCount: Optional[TargetCount]
    CompletedCount: Optional[CompletedCount]
    ErrorCount: Optional[ErrorCount]
    DeliveryTimedOutCount: Optional[DeliveryTimedOutCount]
    ServiceRole: Optional[ServiceRole]
    NotificationConfig: Optional[NotificationConfig]
    CloudWatchOutputConfig: Optional[CloudWatchOutputConfig]
    TimeoutSeconds: Optional[TimeoutSeconds]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]


class CommandFilter(TypedDict, total=False):
    key: CommandFilterKey
    value: CommandFilterValue


CommandFilterList = List[CommandFilter]


class CommandPlugin(TypedDict, total=False):
    Name: Optional[CommandPluginName]
    Status: Optional[CommandPluginStatus]
    StatusDetails: Optional[StatusDetails]
    ResponseCode: Optional[ResponseCode]
    ResponseStartDateTime: Optional[DateTime]
    ResponseFinishDateTime: Optional[DateTime]
    Output: Optional[CommandPluginOutput]
    StandardOutputUrl: Optional[Url]
    StandardErrorUrl: Optional[Url]
    OutputS3Region: Optional[S3Region]
    OutputS3BucketName: Optional[S3BucketName]
    OutputS3KeyPrefix: Optional[S3KeyPrefix]


CommandPluginList = List[CommandPlugin]


class CommandInvocation(TypedDict, total=False):
    CommandId: Optional[CommandId]
    InstanceId: Optional[InstanceId]
    InstanceName: Optional[InstanceTagName]
    Comment: Optional[Comment]
    DocumentName: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    RequestedDateTime: Optional[DateTime]
    Status: Optional[CommandInvocationStatus]
    StatusDetails: Optional[StatusDetails]
    TraceOutput: Optional[InvocationTraceOutput]
    StandardOutputUrl: Optional[Url]
    StandardErrorUrl: Optional[Url]
    CommandPlugins: Optional[CommandPluginList]
    ServiceRole: Optional[ServiceRole]
    NotificationConfig: Optional[NotificationConfig]
    CloudWatchOutputConfig: Optional[CloudWatchOutputConfig]


CommandInvocationList = List[CommandInvocation]
CommandList = List[Command]


class ComplianceExecutionSummary(TypedDict, total=False):
    ExecutionTime: DateTime
    ExecutionId: Optional[ComplianceExecutionId]
    ExecutionType: Optional[ComplianceExecutionType]


ComplianceItemDetails = Dict[AttributeName, AttributeValue]


class ComplianceItem(TypedDict, total=False):
    ComplianceType: Optional[ComplianceTypeName]
    ResourceType: Optional[ComplianceResourceType]
    ResourceId: Optional[ComplianceResourceId]
    Id: Optional[ComplianceItemId]
    Title: Optional[ComplianceItemTitle]
    Status: Optional[ComplianceStatus]
    Severity: Optional[ComplianceSeverity]
    ExecutionSummary: Optional[ComplianceExecutionSummary]
    Details: Optional[ComplianceItemDetails]


class ComplianceItemEntry(TypedDict, total=False):
    Id: Optional[ComplianceItemId]
    Title: Optional[ComplianceItemTitle]
    Severity: ComplianceSeverity
    Status: ComplianceStatus
    Details: Optional[ComplianceItemDetails]


ComplianceItemEntryList = List[ComplianceItemEntry]
ComplianceItemList = List[ComplianceItem]
ComplianceResourceIdList = List[ComplianceResourceId]
ComplianceResourceTypeList = List[ComplianceResourceType]
ComplianceStringFilterValueList = List[ComplianceFilterValue]


class ComplianceStringFilter(TypedDict, total=False):
    Key: Optional[ComplianceStringFilterKey]
    Values: Optional[ComplianceStringFilterValueList]
    Type: Optional[ComplianceQueryOperatorType]


ComplianceStringFilterList = List[ComplianceStringFilter]


class SeveritySummary(TypedDict, total=False):
    CriticalCount: Optional[ComplianceSummaryCount]
    HighCount: Optional[ComplianceSummaryCount]
    MediumCount: Optional[ComplianceSummaryCount]
    LowCount: Optional[ComplianceSummaryCount]
    InformationalCount: Optional[ComplianceSummaryCount]
    UnspecifiedCount: Optional[ComplianceSummaryCount]


class NonCompliantSummary(TypedDict, total=False):
    NonCompliantCount: Optional[ComplianceSummaryCount]
    SeveritySummary: Optional[SeveritySummary]


class CompliantSummary(TypedDict, total=False):
    CompliantCount: Optional[ComplianceSummaryCount]
    SeveritySummary: Optional[SeveritySummary]


class ComplianceSummaryItem(TypedDict, total=False):
    ComplianceType: Optional[ComplianceTypeName]
    CompliantSummary: Optional[CompliantSummary]
    NonCompliantSummary: Optional[NonCompliantSummary]


ComplianceSummaryItemList = List[ComplianceSummaryItem]


class RegistrationMetadataItem(TypedDict, total=False):
    Key: RegistrationMetadataKey
    Value: RegistrationMetadataValue


RegistrationMetadataList = List[RegistrationMetadataItem]


class CreateActivationRequest(ServiceRequest):
    Description: Optional[ActivationDescription]
    DefaultInstanceName: Optional[DefaultInstanceName]
    IamRole: IamRole
    RegistrationLimit: Optional[RegistrationLimit]
    ExpirationDate: Optional[ExpirationDate]
    Tags: Optional[TagList]
    RegistrationMetadata: Optional[RegistrationMetadataList]


class CreateActivationResult(TypedDict, total=False):
    ActivationId: Optional[ActivationId]
    ActivationCode: Optional[ActivationCode]


class CreateAssociationBatchRequestEntry(TypedDict, total=False):
    Name: DocumentARN
    InstanceId: Optional[InstanceId]
    Parameters: Optional[Parameters]
    AutomationTargetParameterName: Optional[AutomationTargetParameterName]
    DocumentVersion: Optional[DocumentVersion]
    Targets: Optional[Targets]
    ScheduleExpression: Optional[ScheduleExpression]
    OutputLocation: Optional[InstanceAssociationOutputLocation]
    AssociationName: Optional[AssociationName]
    MaxErrors: Optional[MaxErrors]
    MaxConcurrency: Optional[MaxConcurrency]
    ComplianceSeverity: Optional[AssociationComplianceSeverity]
    SyncCompliance: Optional[AssociationSyncCompliance]
    ApplyOnlyAtCronInterval: Optional[ApplyOnlyAtCronInterval]
    CalendarNames: Optional[CalendarNameOrARNList]
    TargetLocations: Optional[TargetLocations]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]
    AlarmConfiguration: Optional[AlarmConfiguration]


CreateAssociationBatchRequestEntries = List[CreateAssociationBatchRequestEntry]


class CreateAssociationBatchRequest(ServiceRequest):
    Entries: CreateAssociationBatchRequestEntries


class FailedCreateAssociation(TypedDict, total=False):
    Entry: Optional[CreateAssociationBatchRequestEntry]
    Message: Optional[BatchErrorMessage]
    Fault: Optional[Fault]


FailedCreateAssociationList = List[FailedCreateAssociation]


class CreateAssociationBatchResult(TypedDict, total=False):
    Successful: Optional[AssociationDescriptionList]
    Failed: Optional[FailedCreateAssociationList]


class CreateAssociationRequest(ServiceRequest):
    Name: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    InstanceId: Optional[InstanceId]
    Parameters: Optional[Parameters]
    Targets: Optional[Targets]
    ScheduleExpression: Optional[ScheduleExpression]
    OutputLocation: Optional[InstanceAssociationOutputLocation]
    AssociationName: Optional[AssociationName]
    AutomationTargetParameterName: Optional[AutomationTargetParameterName]
    MaxErrors: Optional[MaxErrors]
    MaxConcurrency: Optional[MaxConcurrency]
    ComplianceSeverity: Optional[AssociationComplianceSeverity]
    SyncCompliance: Optional[AssociationSyncCompliance]
    ApplyOnlyAtCronInterval: Optional[ApplyOnlyAtCronInterval]
    CalendarNames: Optional[CalendarNameOrARNList]
    TargetLocations: Optional[TargetLocations]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]
    Tags: Optional[TagList]
    AlarmConfiguration: Optional[AlarmConfiguration]


class CreateAssociationResult(TypedDict, total=False):
    AssociationDescription: Optional[AssociationDescription]


class DocumentRequires(TypedDict, total=False):
    Name: DocumentARN
    Version: Optional[DocumentVersion]
    RequireType: Optional[RequireType]
    VersionName: Optional[DocumentVersionName]


DocumentRequiresList = List[DocumentRequires]


class CreateDocumentRequest(ServiceRequest):
    Content: DocumentContent
    Requires: Optional[DocumentRequiresList]
    Attachments: Optional[AttachmentsSourceList]
    Name: DocumentName
    DisplayName: Optional[DocumentDisplayName]
    VersionName: Optional[DocumentVersionName]
    DocumentType: Optional[DocumentType]
    DocumentFormat: Optional[DocumentFormat]
    TargetType: Optional[TargetType]
    Tags: Optional[TagList]


class ReviewInformation(TypedDict, total=False):
    ReviewedTime: Optional[DateTime]
    Status: Optional[ReviewStatus]
    Reviewer: Optional[Reviewer]


ReviewInformationList = List[ReviewInformation]
PlatformTypeList = List[PlatformType]


class DocumentParameter(TypedDict, total=False):
    Name: Optional[DocumentParameterName]
    Type: Optional[DocumentParameterType]
    Description: Optional[DocumentParameterDescrption]
    DefaultValue: Optional[DocumentParameterDefaultValue]


DocumentParameterList = List[DocumentParameter]


class DocumentDescription(TypedDict, total=False):
    Sha1: Optional[DocumentSha1]
    Hash: Optional[DocumentHash]
    HashType: Optional[DocumentHashType]
    Name: Optional[DocumentARN]
    DisplayName: Optional[DocumentDisplayName]
    VersionName: Optional[DocumentVersionName]
    Owner: Optional[DocumentOwner]
    CreatedDate: Optional[DateTime]
    Status: Optional[DocumentStatus]
    StatusInformation: Optional[DocumentStatusInformation]
    DocumentVersion: Optional[DocumentVersion]
    Description: Optional[DescriptionInDocument]
    Parameters: Optional[DocumentParameterList]
    PlatformTypes: Optional[PlatformTypeList]
    DocumentType: Optional[DocumentType]
    SchemaVersion: Optional[DocumentSchemaVersion]
    LatestVersion: Optional[DocumentVersion]
    DefaultVersion: Optional[DocumentVersion]
    DocumentFormat: Optional[DocumentFormat]
    TargetType: Optional[TargetType]
    Tags: Optional[TagList]
    AttachmentsInformation: Optional[AttachmentInformationList]
    Requires: Optional[DocumentRequiresList]
    Author: Optional[DocumentAuthor]
    ReviewInformation: Optional[ReviewInformationList]
    ApprovedVersion: Optional[DocumentVersion]
    PendingReviewVersion: Optional[DocumentVersion]
    ReviewStatus: Optional[ReviewStatus]
    Category: Optional[CategoryList]
    CategoryEnum: Optional[CategoryEnumList]


class CreateDocumentResult(TypedDict, total=False):
    DocumentDescription: Optional[DocumentDescription]


class CreateMaintenanceWindowRequest(ServiceRequest):
    Name: MaintenanceWindowName
    Description: Optional[MaintenanceWindowDescription]
    StartDate: Optional[MaintenanceWindowStringDateTime]
    EndDate: Optional[MaintenanceWindowStringDateTime]
    Schedule: MaintenanceWindowSchedule
    ScheduleTimezone: Optional[MaintenanceWindowTimezone]
    ScheduleOffset: Optional[MaintenanceWindowOffset]
    Duration: MaintenanceWindowDurationHours
    Cutoff: MaintenanceWindowCutoff
    AllowUnassociatedTargets: MaintenanceWindowAllowUnassociatedTargets
    ClientToken: Optional[ClientToken]
    Tags: Optional[TagList]


class CreateMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]


class RelatedOpsItem(TypedDict, total=False):
    OpsItemId: String


RelatedOpsItems = List[RelatedOpsItem]


class OpsItemNotification(TypedDict, total=False):
    Arn: Optional[String]


OpsItemNotifications = List[OpsItemNotification]


class OpsItemDataValue(TypedDict, total=False):
    Value: Optional[OpsItemDataValueString]
    Type: Optional[OpsItemDataType]


OpsItemOperationalData = Dict[OpsItemDataKey, OpsItemDataValue]


class CreateOpsItemRequest(ServiceRequest):
    Description: OpsItemDescription
    OpsItemType: Optional[OpsItemType]
    OperationalData: Optional[OpsItemOperationalData]
    Notifications: Optional[OpsItemNotifications]
    Priority: Optional[OpsItemPriority]
    RelatedOpsItems: Optional[RelatedOpsItems]
    Source: OpsItemSource
    Title: OpsItemTitle
    Tags: Optional[TagList]
    Category: Optional[OpsItemCategory]
    Severity: Optional[OpsItemSeverity]
    ActualStartTime: Optional[DateTime]
    ActualEndTime: Optional[DateTime]
    PlannedStartTime: Optional[DateTime]
    PlannedEndTime: Optional[DateTime]
    AccountId: Optional[OpsItemAccountId]


class CreateOpsItemResponse(TypedDict, total=False):
    OpsItemId: Optional[String]
    OpsItemArn: Optional[OpsItemArn]


class MetadataValue(TypedDict, total=False):
    Value: Optional[MetadataValueString]


MetadataMap = Dict[MetadataKey, MetadataValue]


class CreateOpsMetadataRequest(ServiceRequest):
    ResourceId: OpsMetadataResourceId
    Metadata: Optional[MetadataMap]
    Tags: Optional[TagList]


class CreateOpsMetadataResult(TypedDict, total=False):
    OpsMetadataArn: Optional[OpsMetadataArn]


class CreatePatchBaselineRequest(ServiceRequest):
    OperatingSystem: Optional[OperatingSystem]
    Name: BaselineName
    GlobalFilters: Optional[PatchFilterGroup]
    ApprovalRules: Optional[PatchRuleGroup]
    ApprovedPatches: Optional[PatchIdList]
    ApprovedPatchesComplianceLevel: Optional[PatchComplianceLevel]
    ApprovedPatchesEnableNonSecurity: Optional[Boolean]
    RejectedPatches: Optional[PatchIdList]
    RejectedPatchesAction: Optional[PatchAction]
    Description: Optional[BaselineDescription]
    Sources: Optional[PatchSourceList]
    ClientToken: Optional[ClientToken]
    Tags: Optional[TagList]


class CreatePatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]


ResourceDataSyncSourceRegionList = List[ResourceDataSyncSourceRegion]


class ResourceDataSyncOrganizationalUnit(TypedDict, total=False):
    OrganizationalUnitId: Optional[ResourceDataSyncOrganizationalUnitId]


ResourceDataSyncOrganizationalUnitList = List[ResourceDataSyncOrganizationalUnit]


class ResourceDataSyncAwsOrganizationsSource(TypedDict, total=False):
    OrganizationSourceType: ResourceDataSyncOrganizationSourceType
    OrganizationalUnits: Optional[ResourceDataSyncOrganizationalUnitList]


class ResourceDataSyncSource(TypedDict, total=False):
    SourceType: ResourceDataSyncSourceType
    AwsOrganizationsSource: Optional[ResourceDataSyncAwsOrganizationsSource]
    SourceRegions: ResourceDataSyncSourceRegionList
    IncludeFutureRegions: Optional[ResourceDataSyncIncludeFutureRegions]
    EnableAllOpsDataSources: Optional[ResourceDataSyncEnableAllOpsDataSources]


class ResourceDataSyncDestinationDataSharing(TypedDict, total=False):
    DestinationDataSharingType: Optional[ResourceDataSyncDestinationDataSharingType]


class ResourceDataSyncS3Destination(TypedDict, total=False):
    BucketName: ResourceDataSyncS3BucketName
    Prefix: Optional[ResourceDataSyncS3Prefix]
    SyncFormat: ResourceDataSyncS3Format
    Region: ResourceDataSyncS3Region
    AWSKMSKeyARN: Optional[ResourceDataSyncAWSKMSKeyARN]
    DestinationDataSharing: Optional[ResourceDataSyncDestinationDataSharing]


class CreateResourceDataSyncRequest(ServiceRequest):
    SyncName: ResourceDataSyncName
    S3Destination: Optional[ResourceDataSyncS3Destination]
    SyncType: Optional[ResourceDataSyncType]
    SyncSource: Optional[ResourceDataSyncSource]


class CreateResourceDataSyncResult(TypedDict, total=False):
    pass


class DeleteActivationRequest(ServiceRequest):
    ActivationId: ActivationId


class DeleteActivationResult(TypedDict, total=False):
    pass


class DeleteAssociationRequest(ServiceRequest):
    Name: Optional[DocumentARN]
    InstanceId: Optional[InstanceId]
    AssociationId: Optional[AssociationId]


class DeleteAssociationResult(TypedDict, total=False):
    pass


class DeleteDocumentRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: Optional[DocumentVersion]
    VersionName: Optional[DocumentVersionName]
    Force: Optional[Boolean]


class DeleteDocumentResult(TypedDict, total=False):
    pass


class DeleteInventoryRequest(ServiceRequest):
    TypeName: InventoryItemTypeName
    SchemaDeleteOption: Optional[InventorySchemaDeleteOption]
    DryRun: Optional[DryRun]
    ClientToken: Optional[UUID]


class InventoryDeletionSummaryItem(TypedDict, total=False):
    Version: Optional[InventoryItemSchemaVersion]
    Count: Optional[ResourceCount]
    RemainingCount: Optional[RemainingCount]


InventoryDeletionSummaryItems = List[InventoryDeletionSummaryItem]


class InventoryDeletionSummary(TypedDict, total=False):
    TotalCount: Optional[TotalCount]
    RemainingCount: Optional[RemainingCount]
    SummaryItems: Optional[InventoryDeletionSummaryItems]


class DeleteInventoryResult(TypedDict, total=False):
    DeletionId: Optional[UUID]
    TypeName: Optional[InventoryItemTypeName]
    DeletionSummary: Optional[InventoryDeletionSummary]


class DeleteMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId


class DeleteMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]


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


ParameterNameList = List[PSParameterName]


class DeleteParametersRequest(ServiceRequest):
    Names: ParameterNameList


class DeleteParametersResult(TypedDict, total=False):
    DeletedParameters: Optional[ParameterNameList]
    InvalidParameters: Optional[ParameterNameList]


class DeletePatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


class DeletePatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]


class DeleteResourceDataSyncRequest(ServiceRequest):
    SyncName: ResourceDataSyncName
    SyncType: Optional[ResourceDataSyncType]


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
    BaselineId: Optional[BaselineId]
    PatchGroup: Optional[PatchGroup]


class DeregisterTargetFromMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTargetId: MaintenanceWindowTargetId
    Safe: Optional[Boolean]


class DeregisterTargetFromMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTargetId: Optional[MaintenanceWindowTargetId]


class DeregisterTaskFromMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId


class DeregisterTaskFromMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTaskId: Optional[MaintenanceWindowTaskId]


StringList = List[String]


class DescribeActivationsFilter(TypedDict, total=False):
    FilterKey: Optional[DescribeActivationsFilterKeys]
    FilterValues: Optional[StringList]


DescribeActivationsFilterList = List[DescribeActivationsFilter]


class DescribeActivationsRequest(ServiceRequest):
    Filters: Optional[DescribeActivationsFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeActivationsResult(TypedDict, total=False):
    ActivationList: Optional[ActivationList]
    NextToken: Optional[NextToken]


class DescribeAssociationExecutionTargetsRequest(ServiceRequest):
    AssociationId: AssociationId
    ExecutionId: AssociationExecutionId
    Filters: Optional[AssociationExecutionTargetsFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeAssociationExecutionTargetsResult(TypedDict, total=False):
    AssociationExecutionTargets: Optional[AssociationExecutionTargetsList]
    NextToken: Optional[NextToken]


class DescribeAssociationExecutionsRequest(ServiceRequest):
    AssociationId: AssociationId
    Filters: Optional[AssociationExecutionFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeAssociationExecutionsResult(TypedDict, total=False):
    AssociationExecutions: Optional[AssociationExecutionsList]
    NextToken: Optional[NextToken]


class DescribeAssociationRequest(ServiceRequest):
    Name: Optional[DocumentARN]
    InstanceId: Optional[InstanceId]
    AssociationId: Optional[AssociationId]
    AssociationVersion: Optional[AssociationVersion]


class DescribeAssociationResult(TypedDict, total=False):
    AssociationDescription: Optional[AssociationDescription]


class DescribeAutomationExecutionsRequest(ServiceRequest):
    Filters: Optional[AutomationExecutionFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class DescribeAutomationExecutionsResult(TypedDict, total=False):
    AutomationExecutionMetadataList: Optional[AutomationExecutionMetadataList]
    NextToken: Optional[NextToken]


StepExecutionFilterValueList = List[StepExecutionFilterValue]


class StepExecutionFilter(TypedDict, total=False):
    Key: StepExecutionFilterKey
    Values: StepExecutionFilterValueList


StepExecutionFilterList = List[StepExecutionFilter]


class DescribeAutomationStepExecutionsRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    Filters: Optional[StepExecutionFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ReverseOrder: Optional[Boolean]


class DescribeAutomationStepExecutionsResult(TypedDict, total=False):
    StepExecutions: Optional[StepExecutionList]
    NextToken: Optional[NextToken]


PatchOrchestratorFilterValues = List[PatchOrchestratorFilterValue]


class PatchOrchestratorFilter(TypedDict, total=False):
    Key: Optional[PatchOrchestratorFilterKey]
    Values: Optional[PatchOrchestratorFilterValues]


PatchOrchestratorFilterList = List[PatchOrchestratorFilter]


class DescribeAvailablePatchesRequest(ServiceRequest):
    Filters: Optional[PatchOrchestratorFilterList]
    MaxResults: Optional[PatchBaselineMaxResults]
    NextToken: Optional[NextToken]


PatchCVEIdList = List[PatchCVEId]
PatchBugzillaIdList = List[PatchBugzillaId]
PatchAdvisoryIdList = List[PatchAdvisoryId]


class Patch(TypedDict, total=False):
    Id: Optional[PatchId]
    ReleaseDate: Optional[DateTime]
    Title: Optional[PatchTitle]
    Description: Optional[PatchDescription]
    ContentUrl: Optional[PatchContentUrl]
    Vendor: Optional[PatchVendor]
    ProductFamily: Optional[PatchProductFamily]
    Product: Optional[PatchProduct]
    Classification: Optional[PatchClassification]
    MsrcSeverity: Optional[PatchMsrcSeverity]
    KbNumber: Optional[PatchKbNumber]
    MsrcNumber: Optional[PatchMsrcNumber]
    Language: Optional[PatchLanguage]
    AdvisoryIds: Optional[PatchAdvisoryIdList]
    BugzillaIds: Optional[PatchBugzillaIdList]
    CVEIds: Optional[PatchCVEIdList]
    Name: Optional[PatchName]
    Epoch: Optional[PatchEpoch]
    Version: Optional[PatchVersion]
    Release: Optional[PatchRelease]
    Arch: Optional[PatchArch]
    Severity: Optional[PatchSeverity]
    Repository: Optional[PatchRepository]


PatchList = List[Patch]


class DescribeAvailablePatchesResult(TypedDict, total=False):
    Patches: Optional[PatchList]
    NextToken: Optional[NextToken]


class DescribeDocumentPermissionRequest(ServiceRequest):
    Name: DocumentName
    PermissionType: DocumentPermissionType
    MaxResults: Optional[DocumentPermissionMaxResults]
    NextToken: Optional[NextToken]


class DescribeDocumentPermissionResponse(TypedDict, total=False):
    AccountIds: Optional[AccountIdList]
    AccountSharingInfoList: Optional[AccountSharingInfoList]
    NextToken: Optional[NextToken]


class DescribeDocumentRequest(ServiceRequest):
    Name: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    VersionName: Optional[DocumentVersionName]


class DescribeDocumentResult(TypedDict, total=False):
    Document: Optional[DocumentDescription]


class DescribeEffectiveInstanceAssociationsRequest(ServiceRequest):
    InstanceId: InstanceId
    MaxResults: Optional[EffectiveInstanceAssociationMaxResults]
    NextToken: Optional[NextToken]


class InstanceAssociation(TypedDict, total=False):
    AssociationId: Optional[AssociationId]
    InstanceId: Optional[InstanceId]
    Content: Optional[DocumentContent]
    AssociationVersion: Optional[AssociationVersion]


InstanceAssociationList = List[InstanceAssociation]


class DescribeEffectiveInstanceAssociationsResult(TypedDict, total=False):
    Associations: Optional[InstanceAssociationList]
    NextToken: Optional[NextToken]


class DescribeEffectivePatchesForPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId
    MaxResults: Optional[PatchBaselineMaxResults]
    NextToken: Optional[NextToken]


class PatchStatus(TypedDict, total=False):
    DeploymentStatus: Optional[PatchDeploymentStatus]
    ComplianceLevel: Optional[PatchComplianceLevel]
    ApprovalDate: Optional[DateTime]


class EffectivePatch(TypedDict, total=False):
    Patch: Optional[Patch]
    PatchStatus: Optional[PatchStatus]


EffectivePatchList = List[EffectivePatch]


class DescribeEffectivePatchesForPatchBaselineResult(TypedDict, total=False):
    EffectivePatches: Optional[EffectivePatchList]
    NextToken: Optional[NextToken]


class DescribeInstanceAssociationsStatusRequest(ServiceRequest):
    InstanceId: InstanceId
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class S3OutputUrl(TypedDict, total=False):
    OutputUrl: Optional[Url]


class InstanceAssociationOutputUrl(TypedDict, total=False):
    S3OutputUrl: Optional[S3OutputUrl]


class InstanceAssociationStatusInfo(TypedDict, total=False):
    AssociationId: Optional[AssociationId]
    Name: Optional[DocumentARN]
    DocumentVersion: Optional[DocumentVersion]
    AssociationVersion: Optional[AssociationVersion]
    InstanceId: Optional[InstanceId]
    ExecutionDate: Optional[DateTime]
    Status: Optional[StatusName]
    DetailedStatus: Optional[StatusName]
    ExecutionSummary: Optional[InstanceAssociationExecutionSummary]
    ErrorCode: Optional[AgentErrorCode]
    OutputUrl: Optional[InstanceAssociationOutputUrl]
    AssociationName: Optional[AssociationName]


InstanceAssociationStatusInfos = List[InstanceAssociationStatusInfo]


class DescribeInstanceAssociationsStatusResult(TypedDict, total=False):
    InstanceAssociationStatusInfos: Optional[InstanceAssociationStatusInfos]
    NextToken: Optional[NextToken]


InstanceInformationFilterValueSet = List[InstanceInformationFilterValue]


class InstanceInformationStringFilter(TypedDict, total=False):
    Key: InstanceInformationStringFilterKey
    Values: InstanceInformationFilterValueSet


InstanceInformationStringFilterList = List[InstanceInformationStringFilter]


class InstanceInformationFilter(TypedDict, total=False):
    key: InstanceInformationFilterKey
    valueSet: InstanceInformationFilterValueSet


InstanceInformationFilterList = List[InstanceInformationFilter]


class DescribeInstanceInformationRequest(ServiceRequest):
    InstanceInformationFilterList: Optional[InstanceInformationFilterList]
    Filters: Optional[InstanceInformationStringFilterList]
    MaxResults: Optional[MaxResultsEC2Compatible]
    NextToken: Optional[NextToken]


InstanceAssociationStatusAggregatedCount = Dict[StatusName, InstanceCount]


class InstanceAggregatedAssociationOverview(TypedDict, total=False):
    DetailedStatus: Optional[StatusName]
    InstanceAssociationStatusAggregatedCount: Optional[InstanceAssociationStatusAggregatedCount]


class InstanceInformation(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    PingStatus: Optional[PingStatus]
    LastPingDateTime: Optional[DateTime]
    AgentVersion: Optional[Version]
    IsLatestVersion: Optional[Boolean]
    PlatformType: Optional[PlatformType]
    PlatformName: Optional[String]
    PlatformVersion: Optional[String]
    ActivationId: Optional[ActivationId]
    IamRole: Optional[IamRole]
    RegistrationDate: Optional[DateTime]
    ResourceType: Optional[ResourceType]
    Name: Optional[String]
    IPAddress: Optional[IPAddress]
    ComputerName: Optional[ComputerName]
    AssociationStatus: Optional[StatusName]
    LastAssociationExecutionDate: Optional[DateTime]
    LastSuccessfulAssociationExecutionDate: Optional[DateTime]
    AssociationOverview: Optional[InstanceAggregatedAssociationOverview]
    SourceId: Optional[SourceId]
    SourceType: Optional[SourceType]


InstanceInformationList = List[InstanceInformation]


class DescribeInstanceInformationResult(TypedDict, total=False):
    InstanceInformationList: Optional[InstanceInformationList]
    NextToken: Optional[NextToken]


InstancePatchStateFilterValues = List[InstancePatchStateFilterValue]


class InstancePatchStateFilter(TypedDict, total=False):
    Key: InstancePatchStateFilterKey
    Values: InstancePatchStateFilterValues
    Type: InstancePatchStateOperatorType


InstancePatchStateFilterList = List[InstancePatchStateFilter]


class DescribeInstancePatchStatesForPatchGroupRequest(ServiceRequest):
    PatchGroup: PatchGroup
    Filters: Optional[InstancePatchStateFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[PatchComplianceMaxResults]


class InstancePatchState(TypedDict, total=False):
    InstanceId: InstanceId
    PatchGroup: PatchGroup
    BaselineId: BaselineId
    SnapshotId: Optional[SnapshotId]
    InstallOverrideList: Optional[InstallOverrideList]
    OwnerInformation: Optional[OwnerInformation]
    InstalledCount: Optional[PatchInstalledCount]
    InstalledOtherCount: Optional[PatchInstalledOtherCount]
    InstalledPendingRebootCount: Optional[PatchInstalledPendingRebootCount]
    InstalledRejectedCount: Optional[PatchInstalledRejectedCount]
    MissingCount: Optional[PatchMissingCount]
    FailedCount: Optional[PatchFailedCount]
    UnreportedNotApplicableCount: Optional[PatchUnreportedNotApplicableCount]
    NotApplicableCount: Optional[PatchNotApplicableCount]
    OperationStartTime: DateTime
    OperationEndTime: DateTime
    Operation: PatchOperationType
    LastNoRebootInstallOperationTime: Optional[DateTime]
    RebootOption: Optional[RebootOption]
    CriticalNonCompliantCount: Optional[PatchCriticalNonCompliantCount]
    SecurityNonCompliantCount: Optional[PatchSecurityNonCompliantCount]
    OtherNonCompliantCount: Optional[PatchOtherNonCompliantCount]


InstancePatchStatesList = List[InstancePatchState]


class DescribeInstancePatchStatesForPatchGroupResult(TypedDict, total=False):
    InstancePatchStates: Optional[InstancePatchStatesList]
    NextToken: Optional[NextToken]


class DescribeInstancePatchStatesRequest(ServiceRequest):
    InstanceIds: InstanceIdList
    NextToken: Optional[NextToken]
    MaxResults: Optional[PatchComplianceMaxResults]


InstancePatchStateList = List[InstancePatchState]


class DescribeInstancePatchStatesResult(TypedDict, total=False):
    InstancePatchStates: Optional[InstancePatchStateList]
    NextToken: Optional[NextToken]


class DescribeInstancePatchesRequest(ServiceRequest):
    InstanceId: InstanceId
    Filters: Optional[PatchOrchestratorFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[PatchComplianceMaxResults]


class PatchComplianceData(TypedDict, total=False):
    Title: PatchTitle
    KBId: PatchKbNumber
    Classification: PatchClassification
    Severity: PatchSeverity
    State: PatchComplianceDataState
    InstalledTime: DateTime
    CVEIds: Optional[PatchCVEIds]


PatchComplianceDataList = List[PatchComplianceData]


class DescribeInstancePatchesResult(TypedDict, total=False):
    Patches: Optional[PatchComplianceDataList]
    NextToken: Optional[NextToken]


class DescribeInventoryDeletionsRequest(ServiceRequest):
    DeletionId: Optional[UUID]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


InventoryDeletionLastStatusUpdateTime = datetime
InventoryDeletionStartTime = datetime


class InventoryDeletionStatusItem(TypedDict, total=False):
    DeletionId: Optional[UUID]
    TypeName: Optional[InventoryItemTypeName]
    DeletionStartTime: Optional[InventoryDeletionStartTime]
    LastStatus: Optional[InventoryDeletionStatus]
    LastStatusMessage: Optional[InventoryDeletionLastStatusMessage]
    DeletionSummary: Optional[InventoryDeletionSummary]
    LastStatusUpdateTime: Optional[InventoryDeletionLastStatusUpdateTime]


InventoryDeletionsList = List[InventoryDeletionStatusItem]


class DescribeInventoryDeletionsResult(TypedDict, total=False):
    InventoryDeletions: Optional[InventoryDeletionsList]
    NextToken: Optional[NextToken]


MaintenanceWindowFilterValues = List[MaintenanceWindowFilterValue]


class MaintenanceWindowFilter(TypedDict, total=False):
    Key: Optional[MaintenanceWindowFilterKey]
    Values: Optional[MaintenanceWindowFilterValues]


MaintenanceWindowFilterList = List[MaintenanceWindowFilter]


class DescribeMaintenanceWindowExecutionTaskInvocationsRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowExecutionTaskInvocationIdentity(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    TaskExecutionId: Optional[MaintenanceWindowExecutionTaskId]
    InvocationId: Optional[MaintenanceWindowExecutionTaskInvocationId]
    ExecutionId: Optional[MaintenanceWindowExecutionTaskExecutionId]
    TaskType: Optional[MaintenanceWindowTaskType]
    Parameters: Optional[MaintenanceWindowExecutionTaskInvocationParameters]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    OwnerInformation: Optional[OwnerInformation]
    WindowTargetId: Optional[MaintenanceWindowTaskTargetId]


MaintenanceWindowExecutionTaskInvocationIdentityList = List[
    MaintenanceWindowExecutionTaskInvocationIdentity
]


class DescribeMaintenanceWindowExecutionTaskInvocationsResult(TypedDict, total=False):
    WindowExecutionTaskInvocationIdentities: Optional[
        MaintenanceWindowExecutionTaskInvocationIdentityList
    ]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowExecutionTasksRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowExecutionTaskIdentity(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    TaskExecutionId: Optional[MaintenanceWindowExecutionTaskId]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    TaskType: Optional[MaintenanceWindowTaskType]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]


MaintenanceWindowExecutionTaskIdentityList = List[MaintenanceWindowExecutionTaskIdentity]


class DescribeMaintenanceWindowExecutionTasksResult(TypedDict, total=False):
    WindowExecutionTaskIdentities: Optional[MaintenanceWindowExecutionTaskIdentityList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowExecutionsRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowExecution(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]


MaintenanceWindowExecutionList = List[MaintenanceWindowExecution]


class DescribeMaintenanceWindowExecutionsResult(TypedDict, total=False):
    WindowExecutions: Optional[MaintenanceWindowExecutionList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowScheduleRequest(ServiceRequest):
    WindowId: Optional[MaintenanceWindowId]
    Targets: Optional[Targets]
    ResourceType: Optional[MaintenanceWindowResourceType]
    Filters: Optional[PatchOrchestratorFilterList]
    MaxResults: Optional[MaintenanceWindowSearchMaxResults]
    NextToken: Optional[NextToken]


class ScheduledWindowExecution(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    Name: Optional[MaintenanceWindowName]
    ExecutionTime: Optional[MaintenanceWindowStringDateTime]


ScheduledWindowExecutionList = List[ScheduledWindowExecution]


class DescribeMaintenanceWindowScheduleResult(TypedDict, total=False):
    ScheduledWindowExecutions: Optional[ScheduledWindowExecutionList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowTargetsRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowTarget(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTargetId: Optional[MaintenanceWindowTargetId]
    ResourceType: Optional[MaintenanceWindowResourceType]
    Targets: Optional[Targets]
    OwnerInformation: Optional[OwnerInformation]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]


MaintenanceWindowTargetList = List[MaintenanceWindowTarget]


class DescribeMaintenanceWindowTargetsResult(TypedDict, total=False):
    Targets: Optional[MaintenanceWindowTargetList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowTasksRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class LoggingInfo(TypedDict, total=False):
    S3BucketName: S3BucketName
    S3KeyPrefix: Optional[S3KeyPrefix]
    S3Region: S3Region


MaintenanceWindowTaskParameterValueList = List[MaintenanceWindowTaskParameterValue]


class MaintenanceWindowTaskParameterValueExpression(TypedDict, total=False):
    Values: Optional[MaintenanceWindowTaskParameterValueList]


MaintenanceWindowTaskParameters = Dict[
    MaintenanceWindowTaskParameterName, MaintenanceWindowTaskParameterValueExpression
]


class MaintenanceWindowTask(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTaskId: Optional[MaintenanceWindowTaskId]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    Type: Optional[MaintenanceWindowTaskType]
    Targets: Optional[Targets]
    TaskParameters: Optional[MaintenanceWindowTaskParameters]
    Priority: Optional[MaintenanceWindowTaskPriority]
    LoggingInfo: Optional[LoggingInfo]
    ServiceRoleArn: Optional[ServiceRole]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    CutoffBehavior: Optional[MaintenanceWindowTaskCutoffBehavior]
    AlarmConfiguration: Optional[AlarmConfiguration]


MaintenanceWindowTaskList = List[MaintenanceWindowTask]


class DescribeMaintenanceWindowTasksResult(TypedDict, total=False):
    Tasks: Optional[MaintenanceWindowTaskList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowsForTargetRequest(ServiceRequest):
    Targets: Targets
    ResourceType: MaintenanceWindowResourceType
    MaxResults: Optional[MaintenanceWindowSearchMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowIdentityForTarget(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    Name: Optional[MaintenanceWindowName]


MaintenanceWindowsForTargetList = List[MaintenanceWindowIdentityForTarget]


class DescribeMaintenanceWindowsForTargetResult(TypedDict, total=False):
    WindowIdentities: Optional[MaintenanceWindowsForTargetList]
    NextToken: Optional[NextToken]


class DescribeMaintenanceWindowsRequest(ServiceRequest):
    Filters: Optional[MaintenanceWindowFilterList]
    MaxResults: Optional[MaintenanceWindowMaxResults]
    NextToken: Optional[NextToken]


class MaintenanceWindowIdentity(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    Enabled: Optional[MaintenanceWindowEnabled]
    Duration: Optional[MaintenanceWindowDurationHours]
    Cutoff: Optional[MaintenanceWindowCutoff]
    Schedule: Optional[MaintenanceWindowSchedule]
    ScheduleTimezone: Optional[MaintenanceWindowTimezone]
    ScheduleOffset: Optional[MaintenanceWindowOffset]
    EndDate: Optional[MaintenanceWindowStringDateTime]
    StartDate: Optional[MaintenanceWindowStringDateTime]
    NextExecutionTime: Optional[MaintenanceWindowStringDateTime]


MaintenanceWindowIdentityList = List[MaintenanceWindowIdentity]


class DescribeMaintenanceWindowsResult(TypedDict, total=False):
    WindowIdentities: Optional[MaintenanceWindowIdentityList]
    NextToken: Optional[NextToken]


OpsItemFilterValues = List[OpsItemFilterValue]


class OpsItemFilter(TypedDict, total=False):
    Key: OpsItemFilterKey
    Values: OpsItemFilterValues
    Operator: OpsItemFilterOperator


OpsItemFilters = List[OpsItemFilter]


class DescribeOpsItemsRequest(ServiceRequest):
    OpsItemFilters: Optional[OpsItemFilters]
    MaxResults: Optional[OpsItemMaxResults]
    NextToken: Optional[String]


class OpsItemSummary(TypedDict, total=False):
    CreatedBy: Optional[String]
    CreatedTime: Optional[DateTime]
    LastModifiedBy: Optional[String]
    LastModifiedTime: Optional[DateTime]
    Priority: Optional[OpsItemPriority]
    Source: Optional[OpsItemSource]
    Status: Optional[OpsItemStatus]
    OpsItemId: Optional[OpsItemId]
    Title: Optional[OpsItemTitle]
    OperationalData: Optional[OpsItemOperationalData]
    Category: Optional[OpsItemCategory]
    Severity: Optional[OpsItemSeverity]
    OpsItemType: Optional[OpsItemType]
    ActualStartTime: Optional[DateTime]
    ActualEndTime: Optional[DateTime]
    PlannedStartTime: Optional[DateTime]
    PlannedEndTime: Optional[DateTime]


OpsItemSummaries = List[OpsItemSummary]


class DescribeOpsItemsResponse(TypedDict, total=False):
    NextToken: Optional[String]
    OpsItemSummaries: Optional[OpsItemSummaries]


ParameterStringFilterValueList = List[ParameterStringFilterValue]


class ParameterStringFilter(TypedDict, total=False):
    Key: ParameterStringFilterKey
    Option: Optional[ParameterStringQueryOption]
    Values: Optional[ParameterStringFilterValueList]


ParameterStringFilterList = List[ParameterStringFilter]
ParametersFilterValueList = List[ParametersFilterValue]


class ParametersFilter(TypedDict, total=False):
    Key: ParametersFilterKey
    Values: ParametersFilterValueList


ParametersFilterList = List[ParametersFilter]


class DescribeParametersRequest(ServiceRequest):
    Filters: Optional[ParametersFilterList]
    ParameterFilters: Optional[ParameterStringFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ParameterInlinePolicy(TypedDict, total=False):
    PolicyText: Optional[String]
    PolicyType: Optional[String]
    PolicyStatus: Optional[String]


ParameterPolicyList = List[ParameterInlinePolicy]
PSParameterVersion = int


class ParameterMetadata(TypedDict, total=False):
    Name: Optional[PSParameterName]
    Type: Optional[ParameterType]
    KeyId: Optional[ParameterKeyId]
    LastModifiedDate: Optional[DateTime]
    LastModifiedUser: Optional[String]
    Description: Optional[ParameterDescription]
    AllowedPattern: Optional[AllowedPattern]
    Version: Optional[PSParameterVersion]
    Tier: Optional[ParameterTier]
    Policies: Optional[ParameterPolicyList]
    DataType: Optional[ParameterDataType]


ParameterMetadataList = List[ParameterMetadata]


class DescribeParametersResult(TypedDict, total=False):
    Parameters: Optional[ParameterMetadataList]
    NextToken: Optional[NextToken]


class DescribePatchBaselinesRequest(ServiceRequest):
    Filters: Optional[PatchOrchestratorFilterList]
    MaxResults: Optional[PatchBaselineMaxResults]
    NextToken: Optional[NextToken]


class PatchBaselineIdentity(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    BaselineName: Optional[BaselineName]
    OperatingSystem: Optional[OperatingSystem]
    BaselineDescription: Optional[BaselineDescription]
    DefaultBaseline: Optional[DefaultBaseline]


PatchBaselineIdentityList = List[PatchBaselineIdentity]


class DescribePatchBaselinesResult(TypedDict, total=False):
    BaselineIdentities: Optional[PatchBaselineIdentityList]
    NextToken: Optional[NextToken]


class DescribePatchGroupStateRequest(ServiceRequest):
    PatchGroup: PatchGroup


class DescribePatchGroupStateResult(TypedDict, total=False):
    Instances: Optional[Integer]
    InstancesWithInstalledPatches: Optional[Integer]
    InstancesWithInstalledOtherPatches: Optional[Integer]
    InstancesWithInstalledPendingRebootPatches: Optional[InstancesCount]
    InstancesWithInstalledRejectedPatches: Optional[InstancesCount]
    InstancesWithMissingPatches: Optional[Integer]
    InstancesWithFailedPatches: Optional[Integer]
    InstancesWithNotApplicablePatches: Optional[Integer]
    InstancesWithUnreportedNotApplicablePatches: Optional[Integer]
    InstancesWithCriticalNonCompliantPatches: Optional[InstancesCount]
    InstancesWithSecurityNonCompliantPatches: Optional[InstancesCount]
    InstancesWithOtherNonCompliantPatches: Optional[InstancesCount]


class DescribePatchGroupsRequest(ServiceRequest):
    MaxResults: Optional[PatchBaselineMaxResults]
    Filters: Optional[PatchOrchestratorFilterList]
    NextToken: Optional[NextToken]


class PatchGroupPatchBaselineMapping(TypedDict, total=False):
    PatchGroup: Optional[PatchGroup]
    BaselineIdentity: Optional[PatchBaselineIdentity]


PatchGroupPatchBaselineMappingList = List[PatchGroupPatchBaselineMapping]


class DescribePatchGroupsResult(TypedDict, total=False):
    Mappings: Optional[PatchGroupPatchBaselineMappingList]
    NextToken: Optional[NextToken]


class DescribePatchPropertiesRequest(ServiceRequest):
    OperatingSystem: OperatingSystem
    Property: PatchProperty
    PatchSet: Optional[PatchSet]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


PatchPropertyEntry = Dict[AttributeName, AttributeValue]
PatchPropertiesList = List[PatchPropertyEntry]


class DescribePatchPropertiesResult(TypedDict, total=False):
    Properties: Optional[PatchPropertiesList]
    NextToken: Optional[NextToken]


class SessionFilter(TypedDict, total=False):
    key: SessionFilterKey
    value: SessionFilterValue


SessionFilterList = List[SessionFilter]


class DescribeSessionsRequest(ServiceRequest):
    State: SessionState
    MaxResults: Optional[SessionMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[SessionFilterList]


class SessionManagerOutputUrl(TypedDict, total=False):
    S3OutputUrl: Optional[SessionManagerS3OutputUrl]
    CloudWatchOutputUrl: Optional[SessionManagerCloudWatchOutputUrl]


class Session(TypedDict, total=False):
    SessionId: Optional[SessionId]
    Target: Optional[SessionTarget]
    Status: Optional[SessionStatus]
    StartDate: Optional[DateTime]
    EndDate: Optional[DateTime]
    DocumentName: Optional[DocumentName]
    Owner: Optional[SessionOwner]
    Reason: Optional[SessionReason]
    Details: Optional[SessionDetails]
    OutputUrl: Optional[SessionManagerOutputUrl]
    MaxSessionDuration: Optional[MaxSessionDuration]


SessionList = List[Session]


class DescribeSessionsResponse(TypedDict, total=False):
    Sessions: Optional[SessionList]
    NextToken: Optional[NextToken]


class DisassociateOpsItemRelatedItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    AssociationId: OpsItemRelatedItemAssociationId


class DisassociateOpsItemRelatedItemResponse(TypedDict, total=False):
    pass


class DocumentDefaultVersionDescription(TypedDict, total=False):
    Name: Optional[DocumentName]
    DefaultVersion: Optional[DocumentVersion]
    DefaultVersionName: Optional[DocumentVersionName]


class DocumentFilter(TypedDict, total=False):
    key: DocumentFilterKey
    value: DocumentFilterValue


DocumentFilterList = List[DocumentFilter]


class DocumentIdentifier(TypedDict, total=False):
    Name: Optional[DocumentARN]
    CreatedDate: Optional[DateTime]
    DisplayName: Optional[DocumentDisplayName]
    Owner: Optional[DocumentOwner]
    VersionName: Optional[DocumentVersionName]
    PlatformTypes: Optional[PlatformTypeList]
    DocumentVersion: Optional[DocumentVersion]
    DocumentType: Optional[DocumentType]
    SchemaVersion: Optional[DocumentSchemaVersion]
    DocumentFormat: Optional[DocumentFormat]
    TargetType: Optional[TargetType]
    Tags: Optional[TagList]
    Requires: Optional[DocumentRequiresList]
    ReviewStatus: Optional[ReviewStatus]
    Author: Optional[DocumentAuthor]


DocumentIdentifierList = List[DocumentIdentifier]
DocumentKeyValuesFilterValues = List[DocumentKeyValuesFilterValue]


class DocumentKeyValuesFilter(TypedDict, total=False):
    Key: Optional[DocumentKeyValuesFilterKey]
    Values: Optional[DocumentKeyValuesFilterValues]


DocumentKeyValuesFilterList = List[DocumentKeyValuesFilter]


class DocumentReviewCommentSource(TypedDict, total=False):
    Type: Optional[DocumentReviewCommentType]
    Content: Optional[DocumentReviewComment]


DocumentReviewCommentList = List[DocumentReviewCommentSource]


class DocumentReviewerResponseSource(TypedDict, total=False):
    CreateTime: Optional[DateTime]
    UpdatedTime: Optional[DateTime]
    ReviewStatus: Optional[ReviewStatus]
    Comment: Optional[DocumentReviewCommentList]
    Reviewer: Optional[Reviewer]


DocumentReviewerResponseList = List[DocumentReviewerResponseSource]


class DocumentMetadataResponseInfo(TypedDict, total=False):
    ReviewerResponse: Optional[DocumentReviewerResponseList]


class DocumentReviews(TypedDict, total=False):
    Action: DocumentReviewAction
    Comment: Optional[DocumentReviewCommentList]


class DocumentVersionInfo(TypedDict, total=False):
    Name: Optional[DocumentName]
    DisplayName: Optional[DocumentDisplayName]
    DocumentVersion: Optional[DocumentVersion]
    VersionName: Optional[DocumentVersionName]
    CreatedDate: Optional[DateTime]
    IsDefaultVersion: Optional[Boolean]
    DocumentFormat: Optional[DocumentFormat]
    Status: Optional[DocumentStatus]
    StatusInformation: Optional[DocumentStatusInformation]
    ReviewStatus: Optional[ReviewStatus]


DocumentVersionList = List[DocumentVersionInfo]


class GetAutomationExecutionRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId


class GetAutomationExecutionResult(TypedDict, total=False):
    AutomationExecution: Optional[AutomationExecution]


class GetCalendarStateRequest(ServiceRequest):
    CalendarNames: CalendarNameOrARNList
    AtTime: Optional[ISO8601String]


class GetCalendarStateResponse(TypedDict, total=False):
    State: Optional[CalendarState]
    AtTime: Optional[ISO8601String]
    NextTransitionTime: Optional[ISO8601String]


class GetCommandInvocationRequest(ServiceRequest):
    CommandId: CommandId
    InstanceId: InstanceId
    PluginName: Optional[CommandPluginName]


class GetCommandInvocationResult(TypedDict, total=False):
    CommandId: Optional[CommandId]
    InstanceId: Optional[InstanceId]
    Comment: Optional[Comment]
    DocumentName: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    PluginName: Optional[CommandPluginName]
    ResponseCode: Optional[ResponseCode]
    ExecutionStartDateTime: Optional[StringDateTime]
    ExecutionElapsedTime: Optional[StringDateTime]
    ExecutionEndDateTime: Optional[StringDateTime]
    Status: Optional[CommandInvocationStatus]
    StatusDetails: Optional[StatusDetails]
    StandardOutputContent: Optional[StandardOutputContent]
    StandardOutputUrl: Optional[Url]
    StandardErrorContent: Optional[StandardErrorContent]
    StandardErrorUrl: Optional[Url]
    CloudWatchOutputConfig: Optional[CloudWatchOutputConfig]


class GetConnectionStatusRequest(ServiceRequest):
    Target: SessionTarget


class GetConnectionStatusResponse(TypedDict, total=False):
    Target: Optional[SessionTarget]
    Status: Optional[ConnectionStatus]


class GetDefaultPatchBaselineRequest(ServiceRequest):
    OperatingSystem: Optional[OperatingSystem]


class GetDefaultPatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    OperatingSystem: Optional[OperatingSystem]


class GetDeployablePatchSnapshotForInstanceRequest(ServiceRequest):
    InstanceId: InstanceId
    SnapshotId: SnapshotId
    BaselineOverride: Optional[BaselineOverride]


class GetDeployablePatchSnapshotForInstanceResult(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    SnapshotId: Optional[SnapshotId]
    SnapshotDownloadUrl: Optional[SnapshotDownloadUrl]
    Product: Optional[Product]


class GetDocumentRequest(ServiceRequest):
    Name: DocumentARN
    VersionName: Optional[DocumentVersionName]
    DocumentVersion: Optional[DocumentVersion]
    DocumentFormat: Optional[DocumentFormat]


class GetDocumentResult(TypedDict, total=False):
    Name: Optional[DocumentARN]
    CreatedDate: Optional[DateTime]
    DisplayName: Optional[DocumentDisplayName]
    VersionName: Optional[DocumentVersionName]
    DocumentVersion: Optional[DocumentVersion]
    Status: Optional[DocumentStatus]
    StatusInformation: Optional[DocumentStatusInformation]
    Content: Optional[DocumentContent]
    DocumentType: Optional[DocumentType]
    DocumentFormat: Optional[DocumentFormat]
    Requires: Optional[DocumentRequiresList]
    AttachmentsContent: Optional[AttachmentContentList]
    ReviewStatus: Optional[ReviewStatus]


class ResultAttribute(TypedDict, total=False):
    TypeName: InventoryItemTypeName


ResultAttributeList = List[ResultAttribute]
InventoryFilterValueList = List[InventoryFilterValue]


class InventoryFilter(TypedDict, total=False):
    Key: InventoryFilterKey
    Values: InventoryFilterValueList
    Type: Optional[InventoryQueryOperatorType]


InventoryFilterList = List[InventoryFilter]


class InventoryGroup(TypedDict, total=False):
    Name: InventoryGroupName
    Filters: InventoryFilterList


InventoryGroupList = List[InventoryGroup]
InventoryAggregatorList = List["InventoryAggregator"]


class InventoryAggregator(TypedDict, total=False):
    Expression: Optional[InventoryAggregatorExpression]
    Aggregators: Optional[InventoryAggregatorList]
    Groups: Optional[InventoryGroupList]


class GetInventoryRequest(ServiceRequest):
    Filters: Optional[InventoryFilterList]
    Aggregators: Optional[InventoryAggregatorList]
    ResultAttributes: Optional[ResultAttributeList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


InventoryItemEntry = Dict[AttributeName, AttributeValue]
InventoryItemEntryList = List[InventoryItemEntry]


class InventoryResultItem(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    SchemaVersion: InventoryItemSchemaVersion
    CaptureTime: Optional[InventoryItemCaptureTime]
    ContentHash: Optional[InventoryItemContentHash]
    Content: InventoryItemEntryList


InventoryResultItemMap = Dict[InventoryResultItemKey, InventoryResultItem]


class InventoryResultEntity(TypedDict, total=False):
    Id: Optional[InventoryResultEntityId]
    Data: Optional[InventoryResultItemMap]


InventoryResultEntityList = List[InventoryResultEntity]


class GetInventoryResult(TypedDict, total=False):
    Entities: Optional[InventoryResultEntityList]
    NextToken: Optional[NextToken]


class GetInventorySchemaRequest(ServiceRequest):
    TypeName: Optional[InventoryItemTypeNameFilter]
    NextToken: Optional[NextToken]
    MaxResults: Optional[GetInventorySchemaMaxResults]
    Aggregator: Optional[AggregatorSchemaOnly]
    SubType: Optional[IsSubTypeSchema]


class InventoryItemAttribute(TypedDict, total=False):
    Name: InventoryItemAttributeName
    DataType: InventoryAttributeDataType


InventoryItemAttributeList = List[InventoryItemAttribute]


class InventoryItemSchema(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    Version: Optional[InventoryItemSchemaVersion]
    Attributes: InventoryItemAttributeList
    DisplayName: Optional[InventoryTypeDisplayName]


InventoryItemSchemaResultList = List[InventoryItemSchema]


class GetInventorySchemaResult(TypedDict, total=False):
    Schemas: Optional[InventoryItemSchemaResultList]
    NextToken: Optional[NextToken]


class GetMaintenanceWindowExecutionRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId


MaintenanceWindowExecutionTaskIdList = List[MaintenanceWindowExecutionTaskId]


class GetMaintenanceWindowExecutionResult(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    TaskIds: Optional[MaintenanceWindowExecutionTaskIdList]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]


class GetMaintenanceWindowExecutionTaskInvocationRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId
    InvocationId: MaintenanceWindowExecutionTaskInvocationId


class GetMaintenanceWindowExecutionTaskInvocationResult(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    TaskExecutionId: Optional[MaintenanceWindowExecutionTaskId]
    InvocationId: Optional[MaintenanceWindowExecutionTaskInvocationId]
    ExecutionId: Optional[MaintenanceWindowExecutionTaskExecutionId]
    TaskType: Optional[MaintenanceWindowTaskType]
    Parameters: Optional[MaintenanceWindowExecutionTaskInvocationParameters]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    OwnerInformation: Optional[OwnerInformation]
    WindowTargetId: Optional[MaintenanceWindowTaskTargetId]


class GetMaintenanceWindowExecutionTaskRequest(ServiceRequest):
    WindowExecutionId: MaintenanceWindowExecutionId
    TaskId: MaintenanceWindowExecutionTaskId


MaintenanceWindowTaskParametersList = List[MaintenanceWindowTaskParameters]


class GetMaintenanceWindowExecutionTaskResult(TypedDict, total=False):
    WindowExecutionId: Optional[MaintenanceWindowExecutionId]
    TaskExecutionId: Optional[MaintenanceWindowExecutionTaskId]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    ServiceRole: Optional[ServiceRole]
    Type: Optional[MaintenanceWindowTaskType]
    TaskParameters: Optional[MaintenanceWindowTaskParametersList]
    Priority: Optional[MaintenanceWindowTaskPriority]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    Status: Optional[MaintenanceWindowExecutionStatus]
    StatusDetails: Optional[MaintenanceWindowExecutionStatusDetails]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    AlarmConfiguration: Optional[AlarmConfiguration]
    TriggeredAlarms: Optional[AlarmStateInformationList]


class GetMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId


class GetMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    StartDate: Optional[MaintenanceWindowStringDateTime]
    EndDate: Optional[MaintenanceWindowStringDateTime]
    Schedule: Optional[MaintenanceWindowSchedule]
    ScheduleTimezone: Optional[MaintenanceWindowTimezone]
    ScheduleOffset: Optional[MaintenanceWindowOffset]
    NextExecutionTime: Optional[MaintenanceWindowStringDateTime]
    Duration: Optional[MaintenanceWindowDurationHours]
    Cutoff: Optional[MaintenanceWindowCutoff]
    AllowUnassociatedTargets: Optional[MaintenanceWindowAllowUnassociatedTargets]
    Enabled: Optional[MaintenanceWindowEnabled]
    CreatedDate: Optional[DateTime]
    ModifiedDate: Optional[DateTime]


class GetMaintenanceWindowTaskRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId


MaintenanceWindowLambdaPayload = bytes


class MaintenanceWindowLambdaParameters(TypedDict, total=False):
    ClientContext: Optional[MaintenanceWindowLambdaClientContext]
    Qualifier: Optional[MaintenanceWindowLambdaQualifier]
    Payload: Optional[MaintenanceWindowLambdaPayload]


class MaintenanceWindowStepFunctionsParameters(TypedDict, total=False):
    Input: Optional[MaintenanceWindowStepFunctionsInput]
    Name: Optional[MaintenanceWindowStepFunctionsName]


class MaintenanceWindowAutomationParameters(TypedDict, total=False):
    DocumentVersion: Optional[DocumentVersion]
    Parameters: Optional[AutomationParameterMap]


class MaintenanceWindowRunCommandParameters(TypedDict, total=False):
    Comment: Optional[Comment]
    CloudWatchOutputConfig: Optional[CloudWatchOutputConfig]
    DocumentHash: Optional[DocumentHash]
    DocumentHashType: Optional[DocumentHashType]
    DocumentVersion: Optional[DocumentVersion]
    NotificationConfig: Optional[NotificationConfig]
    OutputS3BucketName: Optional[S3BucketName]
    OutputS3KeyPrefix: Optional[S3KeyPrefix]
    Parameters: Optional[Parameters]
    ServiceRoleArn: Optional[ServiceRole]
    TimeoutSeconds: Optional[TimeoutSeconds]


class MaintenanceWindowTaskInvocationParameters(TypedDict, total=False):
    RunCommand: Optional[MaintenanceWindowRunCommandParameters]
    Automation: Optional[MaintenanceWindowAutomationParameters]
    StepFunctions: Optional[MaintenanceWindowStepFunctionsParameters]
    Lambda: Optional[MaintenanceWindowLambdaParameters]


class GetMaintenanceWindowTaskResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTaskId: Optional[MaintenanceWindowTaskId]
    Targets: Optional[Targets]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    ServiceRoleArn: Optional[ServiceRole]
    TaskType: Optional[MaintenanceWindowTaskType]
    TaskParameters: Optional[MaintenanceWindowTaskParameters]
    TaskInvocationParameters: Optional[MaintenanceWindowTaskInvocationParameters]
    Priority: Optional[MaintenanceWindowTaskPriority]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    LoggingInfo: Optional[LoggingInfo]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    CutoffBehavior: Optional[MaintenanceWindowTaskCutoffBehavior]
    AlarmConfiguration: Optional[AlarmConfiguration]


class GetOpsItemRequest(ServiceRequest):
    OpsItemId: OpsItemId
    OpsItemArn: Optional[OpsItemArn]


class OpsItem(TypedDict, total=False):
    CreatedBy: Optional[String]
    OpsItemType: Optional[OpsItemType]
    CreatedTime: Optional[DateTime]
    Description: Optional[OpsItemDescription]
    LastModifiedBy: Optional[String]
    LastModifiedTime: Optional[DateTime]
    Notifications: Optional[OpsItemNotifications]
    Priority: Optional[OpsItemPriority]
    RelatedOpsItems: Optional[RelatedOpsItems]
    Status: Optional[OpsItemStatus]
    OpsItemId: Optional[OpsItemId]
    Version: Optional[String]
    Title: Optional[OpsItemTitle]
    Source: Optional[OpsItemSource]
    OperationalData: Optional[OpsItemOperationalData]
    Category: Optional[OpsItemCategory]
    Severity: Optional[OpsItemSeverity]
    ActualStartTime: Optional[DateTime]
    ActualEndTime: Optional[DateTime]
    PlannedStartTime: Optional[DateTime]
    PlannedEndTime: Optional[DateTime]
    OpsItemArn: Optional[OpsItemArn]


class GetOpsItemResponse(TypedDict, total=False):
    OpsItem: Optional[OpsItem]


class GetOpsMetadataRequest(ServiceRequest):
    OpsMetadataArn: OpsMetadataArn
    MaxResults: Optional[GetOpsMetadataMaxResults]
    NextToken: Optional[NextToken]


class GetOpsMetadataResult(TypedDict, total=False):
    ResourceId: Optional[OpsMetadataResourceId]
    Metadata: Optional[MetadataMap]
    NextToken: Optional[NextToken]


class OpsResultAttribute(TypedDict, total=False):
    TypeName: OpsDataTypeName


OpsResultAttributeList = List[OpsResultAttribute]
OpsAggregatorList = List["OpsAggregator"]
OpsFilterValueList = List[OpsFilterValue]


class OpsFilter(TypedDict, total=False):
    Key: OpsFilterKey
    Values: OpsFilterValueList
    Type: Optional[OpsFilterOperatorType]


OpsFilterList = List[OpsFilter]
OpsAggregatorValueMap = Dict[OpsAggregatorValueKey, OpsAggregatorValue]


class OpsAggregator(TypedDict, total=False):
    AggregatorType: Optional[OpsAggregatorType]
    TypeName: Optional[OpsDataTypeName]
    AttributeName: Optional[OpsDataAttributeName]
    Values: Optional[OpsAggregatorValueMap]
    Filters: Optional[OpsFilterList]
    Aggregators: Optional[OpsAggregatorList]


class GetOpsSummaryRequest(ServiceRequest):
    SyncName: Optional[ResourceDataSyncName]
    Filters: Optional[OpsFilterList]
    Aggregators: Optional[OpsAggregatorList]
    ResultAttributes: Optional[OpsResultAttributeList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


OpsEntityItemEntry = Dict[AttributeName, AttributeValue]
OpsEntityItemEntryList = List[OpsEntityItemEntry]


class OpsEntityItem(TypedDict, total=False):
    CaptureTime: Optional[OpsEntityItemCaptureTime]
    Content: Optional[OpsEntityItemEntryList]


OpsEntityItemMap = Dict[OpsEntityItemKey, OpsEntityItem]


class OpsEntity(TypedDict, total=False):
    Id: Optional[OpsEntityId]
    Data: Optional[OpsEntityItemMap]


OpsEntityList = List[OpsEntity]


class GetOpsSummaryResult(TypedDict, total=False):
    Entities: Optional[OpsEntityList]
    NextToken: Optional[NextToken]


class GetParameterHistoryRequest(ServiceRequest):
    Name: PSParameterName
    WithDecryption: Optional[Boolean]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


ParameterLabelList = List[ParameterLabel]


class ParameterHistory(TypedDict, total=False):
    Name: Optional[PSParameterName]
    Type: Optional[ParameterType]
    KeyId: Optional[ParameterKeyId]
    LastModifiedDate: Optional[DateTime]
    LastModifiedUser: Optional[String]
    Description: Optional[ParameterDescription]
    Value: Optional[PSParameterValue]
    AllowedPattern: Optional[AllowedPattern]
    Version: Optional[PSParameterVersion]
    Labels: Optional[ParameterLabelList]
    Tier: Optional[ParameterTier]
    Policies: Optional[ParameterPolicyList]
    DataType: Optional[ParameterDataType]


ParameterHistoryList = List[ParameterHistory]


class GetParameterHistoryResult(TypedDict, total=False):
    Parameters: Optional[ParameterHistoryList]
    NextToken: Optional[NextToken]


class GetParameterRequest(ServiceRequest):
    Name: PSParameterName
    WithDecryption: Optional[Boolean]


class Parameter(TypedDict, total=False):
    Name: Optional[PSParameterName]
    Type: Optional[ParameterType]
    Value: Optional[PSParameterValue]
    Version: Optional[PSParameterVersion]
    Selector: Optional[PSParameterSelector]
    SourceResult: Optional[String]
    LastModifiedDate: Optional[DateTime]
    ARN: Optional[String]
    DataType: Optional[ParameterDataType]


class GetParameterResult(TypedDict, total=False):
    Parameter: Optional[Parameter]


class GetParametersByPathRequest(ServiceRequest):
    Path: PSParameterName
    Recursive: Optional[Boolean]
    ParameterFilters: Optional[ParameterStringFilterList]
    WithDecryption: Optional[Boolean]
    MaxResults: Optional[GetParametersByPathMaxResults]
    NextToken: Optional[NextToken]


ParameterList = List[Parameter]


class GetParametersByPathResult(TypedDict, total=False):
    Parameters: Optional[ParameterList]
    NextToken: Optional[NextToken]


class GetParametersRequest(ServiceRequest):
    Names: ParameterNameList
    WithDecryption: Optional[Boolean]


class GetParametersResult(TypedDict, total=False):
    Parameters: Optional[ParameterList]
    InvalidParameters: Optional[ParameterNameList]


class GetPatchBaselineForPatchGroupRequest(ServiceRequest):
    PatchGroup: PatchGroup
    OperatingSystem: Optional[OperatingSystem]


class GetPatchBaselineForPatchGroupResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    PatchGroup: Optional[PatchGroup]
    OperatingSystem: Optional[OperatingSystem]


class GetPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


PatchGroupList = List[PatchGroup]


class GetPatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    Name: Optional[BaselineName]
    OperatingSystem: Optional[OperatingSystem]
    GlobalFilters: Optional[PatchFilterGroup]
    ApprovalRules: Optional[PatchRuleGroup]
    ApprovedPatches: Optional[PatchIdList]
    ApprovedPatchesComplianceLevel: Optional[PatchComplianceLevel]
    ApprovedPatchesEnableNonSecurity: Optional[Boolean]
    RejectedPatches: Optional[PatchIdList]
    RejectedPatchesAction: Optional[PatchAction]
    PatchGroups: Optional[PatchGroupList]
    CreatedDate: Optional[DateTime]
    ModifiedDate: Optional[DateTime]
    Description: Optional[BaselineDescription]
    Sources: Optional[PatchSourceList]


class GetResourcePoliciesRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    NextToken: Optional[String]
    MaxResults: Optional[ResourcePolicyMaxResults]


class GetResourcePoliciesResponseEntry(TypedDict, total=False):
    PolicyId: Optional[PolicyId]
    PolicyHash: Optional[PolicyHash]
    Policy: Optional[Policy]


GetResourcePoliciesResponseEntries = List[GetResourcePoliciesResponseEntry]


class GetResourcePoliciesResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Policies: Optional[GetResourcePoliciesResponseEntries]


class GetServiceSettingRequest(ServiceRequest):
    SettingId: ServiceSettingId


class ServiceSetting(TypedDict, total=False):
    SettingId: Optional[ServiceSettingId]
    SettingValue: Optional[ServiceSettingValue]
    LastModifiedDate: Optional[DateTime]
    LastModifiedUser: Optional[String]
    ARN: Optional[String]
    Status: Optional[String]


class GetServiceSettingResult(TypedDict, total=False):
    ServiceSetting: Optional[ServiceSetting]


InventoryItemContentContext = Dict[AttributeName, AttributeValue]


class InventoryItem(TypedDict, total=False):
    TypeName: InventoryItemTypeName
    SchemaVersion: InventoryItemSchemaVersion
    CaptureTime: InventoryItemCaptureTime
    ContentHash: Optional[InventoryItemContentHash]
    Content: Optional[InventoryItemEntryList]
    Context: Optional[InventoryItemContentContext]


InventoryItemList = List[InventoryItem]
KeyList = List[TagKey]


class LabelParameterVersionRequest(ServiceRequest):
    Name: PSParameterName
    ParameterVersion: Optional[PSParameterVersion]
    Labels: ParameterLabelList


class LabelParameterVersionResult(TypedDict, total=False):
    InvalidLabels: Optional[ParameterLabelList]
    ParameterVersion: Optional[PSParameterVersion]


LastResourceDataSyncTime = datetime
LastSuccessfulResourceDataSyncTime = datetime


class ListAssociationVersionsRequest(ServiceRequest):
    AssociationId: AssociationId
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListAssociationVersionsResult(TypedDict, total=False):
    AssociationVersions: Optional[AssociationVersionList]
    NextToken: Optional[NextToken]


class ListAssociationsRequest(ServiceRequest):
    AssociationFilterList: Optional[AssociationFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListAssociationsResult(TypedDict, total=False):
    Associations: Optional[AssociationList]
    NextToken: Optional[NextToken]


class ListCommandInvocationsRequest(ServiceRequest):
    CommandId: Optional[CommandId]
    InstanceId: Optional[InstanceId]
    MaxResults: Optional[CommandMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[CommandFilterList]
    Details: Optional[Boolean]


class ListCommandInvocationsResult(TypedDict, total=False):
    CommandInvocations: Optional[CommandInvocationList]
    NextToken: Optional[NextToken]


class ListCommandsRequest(ServiceRequest):
    CommandId: Optional[CommandId]
    InstanceId: Optional[InstanceId]
    MaxResults: Optional[CommandMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[CommandFilterList]


class ListCommandsResult(TypedDict, total=False):
    Commands: Optional[CommandList]
    NextToken: Optional[NextToken]


class ListComplianceItemsRequest(ServiceRequest):
    Filters: Optional[ComplianceStringFilterList]
    ResourceIds: Optional[ComplianceResourceIdList]
    ResourceTypes: Optional[ComplianceResourceTypeList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListComplianceItemsResult(TypedDict, total=False):
    ComplianceItems: Optional[ComplianceItemList]
    NextToken: Optional[NextToken]


class ListComplianceSummariesRequest(ServiceRequest):
    Filters: Optional[ComplianceStringFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListComplianceSummariesResult(TypedDict, total=False):
    ComplianceSummaryItems: Optional[ComplianceSummaryItemList]
    NextToken: Optional[NextToken]


class ListDocumentMetadataHistoryRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: Optional[DocumentVersion]
    Metadata: DocumentMetadataEnum
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListDocumentMetadataHistoryResponse(TypedDict, total=False):
    Name: Optional[DocumentName]
    DocumentVersion: Optional[DocumentVersion]
    Author: Optional[DocumentAuthor]
    Metadata: Optional[DocumentMetadataResponseInfo]
    NextToken: Optional[NextToken]


class ListDocumentVersionsRequest(ServiceRequest):
    Name: DocumentARN
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDocumentVersionsResult(TypedDict, total=False):
    DocumentVersions: Optional[DocumentVersionList]
    NextToken: Optional[NextToken]


class ListDocumentsRequest(ServiceRequest):
    DocumentFilterList: Optional[DocumentFilterList]
    Filters: Optional[DocumentKeyValuesFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDocumentsResult(TypedDict, total=False):
    DocumentIdentifiers: Optional[DocumentIdentifierList]
    NextToken: Optional[NextToken]


class ListInventoryEntriesRequest(ServiceRequest):
    InstanceId: InstanceId
    TypeName: InventoryItemTypeName
    Filters: Optional[InventoryFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListInventoryEntriesResult(TypedDict, total=False):
    TypeName: Optional[InventoryItemTypeName]
    InstanceId: Optional[InstanceId]
    SchemaVersion: Optional[InventoryItemSchemaVersion]
    CaptureTime: Optional[InventoryItemCaptureTime]
    Entries: Optional[InventoryItemEntryList]
    NextToken: Optional[NextToken]


OpsItemEventFilterValues = List[OpsItemEventFilterValue]


class OpsItemEventFilter(TypedDict, total=False):
    Key: OpsItemEventFilterKey
    Values: OpsItemEventFilterValues
    Operator: OpsItemEventFilterOperator


OpsItemEventFilters = List[OpsItemEventFilter]


class ListOpsItemEventsRequest(ServiceRequest):
    Filters: Optional[OpsItemEventFilters]
    MaxResults: Optional[OpsItemEventMaxResults]
    NextToken: Optional[String]


class OpsItemIdentity(TypedDict, total=False):
    Arn: Optional[String]


class OpsItemEventSummary(TypedDict, total=False):
    OpsItemId: Optional[String]
    EventId: Optional[String]
    Source: Optional[String]
    DetailType: Optional[String]
    Detail: Optional[String]
    CreatedBy: Optional[OpsItemIdentity]
    CreatedTime: Optional[DateTime]


OpsItemEventSummaries = List[OpsItemEventSummary]


class ListOpsItemEventsResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Summaries: Optional[OpsItemEventSummaries]


OpsItemRelatedItemsFilterValues = List[OpsItemRelatedItemsFilterValue]


class OpsItemRelatedItemsFilter(TypedDict, total=False):
    Key: OpsItemRelatedItemsFilterKey
    Values: OpsItemRelatedItemsFilterValues
    Operator: OpsItemRelatedItemsFilterOperator


OpsItemRelatedItemsFilters = List[OpsItemRelatedItemsFilter]


class ListOpsItemRelatedItemsRequest(ServiceRequest):
    OpsItemId: Optional[OpsItemId]
    Filters: Optional[OpsItemRelatedItemsFilters]
    MaxResults: Optional[OpsItemRelatedItemsMaxResults]
    NextToken: Optional[String]


class OpsItemRelatedItemSummary(TypedDict, total=False):
    OpsItemId: Optional[OpsItemId]
    AssociationId: Optional[OpsItemRelatedItemAssociationId]
    ResourceType: Optional[OpsItemRelatedItemAssociationResourceType]
    AssociationType: Optional[OpsItemRelatedItemAssociationType]
    ResourceUri: Optional[OpsItemRelatedItemAssociationResourceUri]
    CreatedBy: Optional[OpsItemIdentity]
    CreatedTime: Optional[DateTime]
    LastModifiedBy: Optional[OpsItemIdentity]
    LastModifiedTime: Optional[DateTime]


OpsItemRelatedItemSummaries = List[OpsItemRelatedItemSummary]


class ListOpsItemRelatedItemsResponse(TypedDict, total=False):
    NextToken: Optional[String]
    Summaries: Optional[OpsItemRelatedItemSummaries]


OpsMetadataFilterValueList = List[OpsMetadataFilterValue]


class OpsMetadataFilter(TypedDict, total=False):
    Key: OpsMetadataFilterKey
    Values: OpsMetadataFilterValueList


OpsMetadataFilterList = List[OpsMetadataFilter]


class ListOpsMetadataRequest(ServiceRequest):
    Filters: Optional[OpsMetadataFilterList]
    MaxResults: Optional[ListOpsMetadataMaxResults]
    NextToken: Optional[NextToken]


class OpsMetadata(TypedDict, total=False):
    ResourceId: Optional[OpsMetadataResourceId]
    OpsMetadataArn: Optional[OpsMetadataArn]
    LastModifiedDate: Optional[DateTime]
    LastModifiedUser: Optional[String]
    CreationDate: Optional[DateTime]


OpsMetadataList = List[OpsMetadata]


class ListOpsMetadataResult(TypedDict, total=False):
    OpsMetadataList: Optional[OpsMetadataList]
    NextToken: Optional[NextToken]


class ListResourceComplianceSummariesRequest(ServiceRequest):
    Filters: Optional[ComplianceStringFilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ResourceComplianceSummaryItem(TypedDict, total=False):
    ComplianceType: Optional[ComplianceTypeName]
    ResourceType: Optional[ComplianceResourceType]
    ResourceId: Optional[ComplianceResourceId]
    Status: Optional[ComplianceStatus]
    OverallSeverity: Optional[ComplianceSeverity]
    ExecutionSummary: Optional[ComplianceExecutionSummary]
    CompliantSummary: Optional[CompliantSummary]
    NonCompliantSummary: Optional[NonCompliantSummary]


ResourceComplianceSummaryItemList = List[ResourceComplianceSummaryItem]


class ListResourceComplianceSummariesResult(TypedDict, total=False):
    ResourceComplianceSummaryItems: Optional[ResourceComplianceSummaryItemList]
    NextToken: Optional[NextToken]


class ListResourceDataSyncRequest(ServiceRequest):
    SyncType: Optional[ResourceDataSyncType]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


ResourceDataSyncCreatedTime = datetime
ResourceDataSyncLastModifiedTime = datetime


class ResourceDataSyncSourceWithState(TypedDict, total=False):
    SourceType: Optional[ResourceDataSyncSourceType]
    AwsOrganizationsSource: Optional[ResourceDataSyncAwsOrganizationsSource]
    SourceRegions: Optional[ResourceDataSyncSourceRegionList]
    IncludeFutureRegions: Optional[ResourceDataSyncIncludeFutureRegions]
    State: Optional[ResourceDataSyncState]
    EnableAllOpsDataSources: Optional[ResourceDataSyncEnableAllOpsDataSources]


class ResourceDataSyncItem(TypedDict, total=False):
    SyncName: Optional[ResourceDataSyncName]
    SyncType: Optional[ResourceDataSyncType]
    SyncSource: Optional[ResourceDataSyncSourceWithState]
    S3Destination: Optional[ResourceDataSyncS3Destination]
    LastSyncTime: Optional[LastResourceDataSyncTime]
    LastSuccessfulSyncTime: Optional[LastSuccessfulResourceDataSyncTime]
    SyncLastModifiedTime: Optional[ResourceDataSyncLastModifiedTime]
    LastStatus: Optional[LastResourceDataSyncStatus]
    SyncCreatedTime: Optional[ResourceDataSyncCreatedTime]
    LastSyncStatusMessage: Optional[LastResourceDataSyncMessage]


ResourceDataSyncItemList = List[ResourceDataSyncItem]


class ListResourceDataSyncResult(TypedDict, total=False):
    ResourceDataSyncItems: Optional[ResourceDataSyncItemList]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId


class ListTagsForResourceResult(TypedDict, total=False):
    TagList: Optional[TagList]


MetadataKeysToDeleteList = List[MetadataKey]


class ModifyDocumentPermissionRequest(ServiceRequest):
    Name: DocumentName
    PermissionType: DocumentPermissionType
    AccountIdsToAdd: Optional[AccountIdList]
    AccountIdsToRemove: Optional[AccountIdList]
    SharedDocumentVersion: Optional[SharedDocumentVersion]


class ModifyDocumentPermissionResponse(TypedDict, total=False):
    pass


OpsItemOpsDataKeysList = List[String]


class PutComplianceItemsRequest(ServiceRequest):
    ResourceId: ComplianceResourceId
    ResourceType: ComplianceResourceType
    ComplianceType: ComplianceTypeName
    ExecutionSummary: ComplianceExecutionSummary
    Items: ComplianceItemEntryList
    ItemContentHash: Optional[ComplianceItemContentHash]
    UploadType: Optional[ComplianceUploadType]


class PutComplianceItemsResult(TypedDict, total=False):
    pass


class PutInventoryRequest(ServiceRequest):
    InstanceId: InstanceId
    Items: InventoryItemList


class PutInventoryResult(TypedDict, total=False):
    Message: Optional[PutInventoryMessage]


class PutParameterRequest(ServiceRequest):
    Name: PSParameterName
    Description: Optional[ParameterDescription]
    Value: PSParameterValue
    Type: Optional[ParameterType]
    KeyId: Optional[ParameterKeyId]
    Overwrite: Optional[Boolean]
    AllowedPattern: Optional[AllowedPattern]
    Tags: Optional[TagList]
    Tier: Optional[ParameterTier]
    Policies: Optional[ParameterPolicies]
    DataType: Optional[ParameterDataType]


class PutParameterResult(TypedDict, total=False):
    Version: Optional[PSParameterVersion]
    Tier: Optional[ParameterTier]


class PutResourcePolicyRequest(ServiceRequest):
    ResourceArn: ResourceArnString
    Policy: Policy
    PolicyId: Optional[PolicyId]
    PolicyHash: Optional[PolicyHash]


class PutResourcePolicyResponse(TypedDict, total=False):
    PolicyId: Optional[PolicyId]
    PolicyHash: Optional[PolicyHash]


class RegisterDefaultPatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId


class RegisterDefaultPatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]


class RegisterPatchBaselineForPatchGroupRequest(ServiceRequest):
    BaselineId: BaselineId
    PatchGroup: PatchGroup


class RegisterPatchBaselineForPatchGroupResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    PatchGroup: Optional[PatchGroup]


class RegisterTargetWithMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    ResourceType: MaintenanceWindowResourceType
    Targets: Targets
    OwnerInformation: Optional[OwnerInformation]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    ClientToken: Optional[ClientToken]


class RegisterTargetWithMaintenanceWindowResult(TypedDict, total=False):
    WindowTargetId: Optional[MaintenanceWindowTargetId]


class RegisterTaskWithMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Targets: Optional[Targets]
    TaskArn: MaintenanceWindowTaskArn
    ServiceRoleArn: Optional[ServiceRole]
    TaskType: MaintenanceWindowTaskType
    TaskParameters: Optional[MaintenanceWindowTaskParameters]
    TaskInvocationParameters: Optional[MaintenanceWindowTaskInvocationParameters]
    Priority: Optional[MaintenanceWindowTaskPriority]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    LoggingInfo: Optional[LoggingInfo]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    ClientToken: Optional[ClientToken]
    CutoffBehavior: Optional[MaintenanceWindowTaskCutoffBehavior]
    AlarmConfiguration: Optional[AlarmConfiguration]


class RegisterTaskWithMaintenanceWindowResult(TypedDict, total=False):
    WindowTaskId: Optional[MaintenanceWindowTaskId]


class RemoveTagsFromResourceRequest(ServiceRequest):
    ResourceType: ResourceTypeForTagging
    ResourceId: ResourceId
    TagKeys: KeyList


class RemoveTagsFromResourceResult(TypedDict, total=False):
    pass


class ResetServiceSettingRequest(ServiceRequest):
    SettingId: ServiceSettingId


class ResetServiceSettingResult(TypedDict, total=False):
    ServiceSetting: Optional[ServiceSetting]


class ResumeSessionRequest(ServiceRequest):
    SessionId: SessionId


class ResumeSessionResponse(TypedDict, total=False):
    SessionId: Optional[SessionId]
    TokenValue: Optional[TokenValue]
    StreamUrl: Optional[StreamUrl]


class SendAutomationSignalRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    SignalType: SignalType
    Payload: Optional[AutomationParameterMap]


class SendAutomationSignalResult(TypedDict, total=False):
    pass


class SendCommandRequest(ServiceRequest):
    InstanceIds: Optional[InstanceIdList]
    Targets: Optional[Targets]
    DocumentName: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    DocumentHash: Optional[DocumentHash]
    DocumentHashType: Optional[DocumentHashType]
    TimeoutSeconds: Optional[TimeoutSeconds]
    Comment: Optional[Comment]
    Parameters: Optional[Parameters]
    OutputS3Region: Optional[S3Region]
    OutputS3BucketName: Optional[S3BucketName]
    OutputS3KeyPrefix: Optional[S3KeyPrefix]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    ServiceRoleArn: Optional[ServiceRole]
    NotificationConfig: Optional[NotificationConfig]
    CloudWatchOutputConfig: Optional[CloudWatchOutputConfig]
    AlarmConfiguration: Optional[AlarmConfiguration]


class SendCommandResult(TypedDict, total=False):
    Command: Optional[Command]


SessionManagerParameterValueList = List[SessionManagerParameterValue]
SessionManagerParameters = Dict[SessionManagerParameterName, SessionManagerParameterValueList]


class StartAssociationsOnceRequest(ServiceRequest):
    AssociationIds: AssociationIdList


class StartAssociationsOnceResult(TypedDict, total=False):
    pass


class StartAutomationExecutionRequest(ServiceRequest):
    DocumentName: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    Parameters: Optional[AutomationParameterMap]
    ClientToken: Optional[IdempotencyToken]
    Mode: Optional[ExecutionMode]
    TargetParameterName: Optional[AutomationParameterKey]
    Targets: Optional[Targets]
    TargetMaps: Optional[TargetMaps]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    TargetLocations: Optional[TargetLocations]
    Tags: Optional[TagList]
    AlarmConfiguration: Optional[AlarmConfiguration]


class StartAutomationExecutionResult(TypedDict, total=False):
    AutomationExecutionId: Optional[AutomationExecutionId]


class StartChangeRequestExecutionRequest(ServiceRequest):
    ScheduledTime: Optional[DateTime]
    DocumentName: DocumentARN
    DocumentVersion: Optional[DocumentVersion]
    Parameters: Optional[AutomationParameterMap]
    ChangeRequestName: Optional[ChangeRequestName]
    ClientToken: Optional[IdempotencyToken]
    AutoApprove: Optional[Boolean]
    Runbooks: Runbooks
    Tags: Optional[TagList]
    ScheduledEndTime: Optional[DateTime]
    ChangeDetails: Optional[ChangeDetailsValue]


class StartChangeRequestExecutionResult(TypedDict, total=False):
    AutomationExecutionId: Optional[AutomationExecutionId]


class StartSessionRequest(ServiceRequest):
    Target: SessionTarget
    DocumentName: Optional[DocumentARN]
    Reason: Optional[SessionReason]
    Parameters: Optional[SessionManagerParameters]


class StartSessionResponse(TypedDict, total=False):
    SessionId: Optional[SessionId]
    TokenValue: Optional[TokenValue]
    StreamUrl: Optional[StreamUrl]


class StopAutomationExecutionRequest(ServiceRequest):
    AutomationExecutionId: AutomationExecutionId
    Type: Optional[StopType]


class StopAutomationExecutionResult(TypedDict, total=False):
    pass


class TerminateSessionRequest(ServiceRequest):
    SessionId: SessionId


class TerminateSessionResponse(TypedDict, total=False):
    SessionId: Optional[SessionId]


class UnlabelParameterVersionRequest(ServiceRequest):
    Name: PSParameterName
    ParameterVersion: PSParameterVersion
    Labels: ParameterLabelList


class UnlabelParameterVersionResult(TypedDict, total=False):
    RemovedLabels: Optional[ParameterLabelList]
    InvalidLabels: Optional[ParameterLabelList]


class UpdateAssociationRequest(ServiceRequest):
    AssociationId: AssociationId
    Parameters: Optional[Parameters]
    DocumentVersion: Optional[DocumentVersion]
    ScheduleExpression: Optional[ScheduleExpression]
    OutputLocation: Optional[InstanceAssociationOutputLocation]
    Name: Optional[DocumentARN]
    Targets: Optional[Targets]
    AssociationName: Optional[AssociationName]
    AssociationVersion: Optional[AssociationVersion]
    AutomationTargetParameterName: Optional[AutomationTargetParameterName]
    MaxErrors: Optional[MaxErrors]
    MaxConcurrency: Optional[MaxConcurrency]
    ComplianceSeverity: Optional[AssociationComplianceSeverity]
    SyncCompliance: Optional[AssociationSyncCompliance]
    ApplyOnlyAtCronInterval: Optional[ApplyOnlyAtCronInterval]
    CalendarNames: Optional[CalendarNameOrARNList]
    TargetLocations: Optional[TargetLocations]
    ScheduleOffset: Optional[ScheduleOffset]
    TargetMaps: Optional[TargetMaps]
    AlarmConfiguration: Optional[AlarmConfiguration]


class UpdateAssociationResult(TypedDict, total=False):
    AssociationDescription: Optional[AssociationDescription]


class UpdateAssociationStatusRequest(ServiceRequest):
    Name: DocumentARN
    InstanceId: InstanceId
    AssociationStatus: AssociationStatus


class UpdateAssociationStatusResult(TypedDict, total=False):
    AssociationDescription: Optional[AssociationDescription]


class UpdateDocumentDefaultVersionRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: DocumentVersionNumber


class UpdateDocumentDefaultVersionResult(TypedDict, total=False):
    Description: Optional[DocumentDefaultVersionDescription]


class UpdateDocumentMetadataRequest(ServiceRequest):
    Name: DocumentName
    DocumentVersion: Optional[DocumentVersion]
    DocumentReviews: DocumentReviews


class UpdateDocumentMetadataResponse(TypedDict, total=False):
    pass


class UpdateDocumentRequest(ServiceRequest):
    Content: DocumentContent
    Attachments: Optional[AttachmentsSourceList]
    Name: DocumentName
    DisplayName: Optional[DocumentDisplayName]
    VersionName: Optional[DocumentVersionName]
    DocumentVersion: Optional[DocumentVersion]
    DocumentFormat: Optional[DocumentFormat]
    TargetType: Optional[TargetType]


class UpdateDocumentResult(TypedDict, total=False):
    DocumentDescription: Optional[DocumentDescription]


class UpdateMaintenanceWindowRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    StartDate: Optional[MaintenanceWindowStringDateTime]
    EndDate: Optional[MaintenanceWindowStringDateTime]
    Schedule: Optional[MaintenanceWindowSchedule]
    ScheduleTimezone: Optional[MaintenanceWindowTimezone]
    ScheduleOffset: Optional[MaintenanceWindowOffset]
    Duration: Optional[MaintenanceWindowDurationHours]
    Cutoff: Optional[MaintenanceWindowCutoff]
    AllowUnassociatedTargets: Optional[MaintenanceWindowAllowUnassociatedTargets]
    Enabled: Optional[MaintenanceWindowEnabled]
    Replace: Optional[Boolean]


class UpdateMaintenanceWindowResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    StartDate: Optional[MaintenanceWindowStringDateTime]
    EndDate: Optional[MaintenanceWindowStringDateTime]
    Schedule: Optional[MaintenanceWindowSchedule]
    ScheduleTimezone: Optional[MaintenanceWindowTimezone]
    ScheduleOffset: Optional[MaintenanceWindowOffset]
    Duration: Optional[MaintenanceWindowDurationHours]
    Cutoff: Optional[MaintenanceWindowCutoff]
    AllowUnassociatedTargets: Optional[MaintenanceWindowAllowUnassociatedTargets]
    Enabled: Optional[MaintenanceWindowEnabled]


class UpdateMaintenanceWindowTargetRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTargetId: MaintenanceWindowTargetId
    Targets: Optional[Targets]
    OwnerInformation: Optional[OwnerInformation]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    Replace: Optional[Boolean]


class UpdateMaintenanceWindowTargetResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTargetId: Optional[MaintenanceWindowTargetId]
    Targets: Optional[Targets]
    OwnerInformation: Optional[OwnerInformation]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]


class UpdateMaintenanceWindowTaskRequest(ServiceRequest):
    WindowId: MaintenanceWindowId
    WindowTaskId: MaintenanceWindowTaskId
    Targets: Optional[Targets]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    ServiceRoleArn: Optional[ServiceRole]
    TaskParameters: Optional[MaintenanceWindowTaskParameters]
    TaskInvocationParameters: Optional[MaintenanceWindowTaskInvocationParameters]
    Priority: Optional[MaintenanceWindowTaskPriority]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    LoggingInfo: Optional[LoggingInfo]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    Replace: Optional[Boolean]
    CutoffBehavior: Optional[MaintenanceWindowTaskCutoffBehavior]
    AlarmConfiguration: Optional[AlarmConfiguration]


class UpdateMaintenanceWindowTaskResult(TypedDict, total=False):
    WindowId: Optional[MaintenanceWindowId]
    WindowTaskId: Optional[MaintenanceWindowTaskId]
    Targets: Optional[Targets]
    TaskArn: Optional[MaintenanceWindowTaskArn]
    ServiceRoleArn: Optional[ServiceRole]
    TaskParameters: Optional[MaintenanceWindowTaskParameters]
    TaskInvocationParameters: Optional[MaintenanceWindowTaskInvocationParameters]
    Priority: Optional[MaintenanceWindowTaskPriority]
    MaxConcurrency: Optional[MaxConcurrency]
    MaxErrors: Optional[MaxErrors]
    LoggingInfo: Optional[LoggingInfo]
    Name: Optional[MaintenanceWindowName]
    Description: Optional[MaintenanceWindowDescription]
    CutoffBehavior: Optional[MaintenanceWindowTaskCutoffBehavior]
    AlarmConfiguration: Optional[AlarmConfiguration]


class UpdateManagedInstanceRoleRequest(ServiceRequest):
    InstanceId: ManagedInstanceId
    IamRole: IamRole


class UpdateManagedInstanceRoleResult(TypedDict, total=False):
    pass


class UpdateOpsItemRequest(ServiceRequest):
    Description: Optional[OpsItemDescription]
    OperationalData: Optional[OpsItemOperationalData]
    OperationalDataToDelete: Optional[OpsItemOpsDataKeysList]
    Notifications: Optional[OpsItemNotifications]
    Priority: Optional[OpsItemPriority]
    RelatedOpsItems: Optional[RelatedOpsItems]
    Status: Optional[OpsItemStatus]
    OpsItemId: OpsItemId
    Title: Optional[OpsItemTitle]
    Category: Optional[OpsItemCategory]
    Severity: Optional[OpsItemSeverity]
    ActualStartTime: Optional[DateTime]
    ActualEndTime: Optional[DateTime]
    PlannedStartTime: Optional[DateTime]
    PlannedEndTime: Optional[DateTime]
    OpsItemArn: Optional[OpsItemArn]


class UpdateOpsItemResponse(TypedDict, total=False):
    pass


class UpdateOpsMetadataRequest(ServiceRequest):
    OpsMetadataArn: OpsMetadataArn
    MetadataToUpdate: Optional[MetadataMap]
    KeysToDelete: Optional[MetadataKeysToDeleteList]


class UpdateOpsMetadataResult(TypedDict, total=False):
    OpsMetadataArn: Optional[OpsMetadataArn]


class UpdatePatchBaselineRequest(ServiceRequest):
    BaselineId: BaselineId
    Name: Optional[BaselineName]
    GlobalFilters: Optional[PatchFilterGroup]
    ApprovalRules: Optional[PatchRuleGroup]
    ApprovedPatches: Optional[PatchIdList]
    ApprovedPatchesComplianceLevel: Optional[PatchComplianceLevel]
    ApprovedPatchesEnableNonSecurity: Optional[Boolean]
    RejectedPatches: Optional[PatchIdList]
    RejectedPatchesAction: Optional[PatchAction]
    Description: Optional[BaselineDescription]
    Sources: Optional[PatchSourceList]
    Replace: Optional[Boolean]


class UpdatePatchBaselineResult(TypedDict, total=False):
    BaselineId: Optional[BaselineId]
    Name: Optional[BaselineName]
    OperatingSystem: Optional[OperatingSystem]
    GlobalFilters: Optional[PatchFilterGroup]
    ApprovalRules: Optional[PatchRuleGroup]
    ApprovedPatches: Optional[PatchIdList]
    ApprovedPatchesComplianceLevel: Optional[PatchComplianceLevel]
    ApprovedPatchesEnableNonSecurity: Optional[Boolean]
    RejectedPatches: Optional[PatchIdList]
    RejectedPatchesAction: Optional[PatchAction]
    CreatedDate: Optional[DateTime]
    ModifiedDate: Optional[DateTime]
    Description: Optional[BaselineDescription]
    Sources: Optional[PatchSourceList]


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
    service = "ssm"
    version = "2014-11-06"

    @handler("AddTagsToResource")
    def add_tags_to_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
        tags: TagList,
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
    ) -> AssociateOpsItemRelatedItemResponse:
        raise NotImplementedError

    @handler("CancelCommand")
    def cancel_command(
        self, context: RequestContext, command_id: CommandId, instance_ids: InstanceIdList = None
    ) -> CancelCommandResult:
        raise NotImplementedError

    @handler("CancelMaintenanceWindowExecution")
    def cancel_maintenance_window_execution(
        self, context: RequestContext, window_execution_id: MaintenanceWindowExecutionId
    ) -> CancelMaintenanceWindowExecutionResult:
        raise NotImplementedError

    @handler("CreateActivation")
    def create_activation(
        self,
        context: RequestContext,
        iam_role: IamRole,
        description: ActivationDescription = None,
        default_instance_name: DefaultInstanceName = None,
        registration_limit: RegistrationLimit = None,
        expiration_date: ExpirationDate = None,
        tags: TagList = None,
        registration_metadata: RegistrationMetadataList = None,
    ) -> CreateActivationResult:
        raise NotImplementedError

    @handler("CreateAssociation")
    def create_association(
        self,
        context: RequestContext,
        name: DocumentARN,
        document_version: DocumentVersion = None,
        instance_id: InstanceId = None,
        parameters: Parameters = None,
        targets: Targets = None,
        schedule_expression: ScheduleExpression = None,
        output_location: InstanceAssociationOutputLocation = None,
        association_name: AssociationName = None,
        automation_target_parameter_name: AutomationTargetParameterName = None,
        max_errors: MaxErrors = None,
        max_concurrency: MaxConcurrency = None,
        compliance_severity: AssociationComplianceSeverity = None,
        sync_compliance: AssociationSyncCompliance = None,
        apply_only_at_cron_interval: ApplyOnlyAtCronInterval = None,
        calendar_names: CalendarNameOrARNList = None,
        target_locations: TargetLocations = None,
        schedule_offset: ScheduleOffset = None,
        target_maps: TargetMaps = None,
        tags: TagList = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> CreateAssociationResult:
        raise NotImplementedError

    @handler("CreateAssociationBatch")
    def create_association_batch(
        self, context: RequestContext, entries: CreateAssociationBatchRequestEntries
    ) -> CreateAssociationBatchResult:
        raise NotImplementedError

    @handler("CreateDocument")
    def create_document(
        self,
        context: RequestContext,
        content: DocumentContent,
        name: DocumentName,
        requires: DocumentRequiresList = None,
        attachments: AttachmentsSourceList = None,
        display_name: DocumentDisplayName = None,
        version_name: DocumentVersionName = None,
        document_type: DocumentType = None,
        document_format: DocumentFormat = None,
        target_type: TargetType = None,
        tags: TagList = None,
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
        description: MaintenanceWindowDescription = None,
        start_date: MaintenanceWindowStringDateTime = None,
        end_date: MaintenanceWindowStringDateTime = None,
        schedule_timezone: MaintenanceWindowTimezone = None,
        schedule_offset: MaintenanceWindowOffset = None,
        client_token: ClientToken = None,
        tags: TagList = None,
    ) -> CreateMaintenanceWindowResult:
        raise NotImplementedError

    @handler("CreateOpsItem")
    def create_ops_item(
        self,
        context: RequestContext,
        description: OpsItemDescription,
        source: OpsItemSource,
        title: OpsItemTitle,
        ops_item_type: OpsItemType = None,
        operational_data: OpsItemOperationalData = None,
        notifications: OpsItemNotifications = None,
        priority: OpsItemPriority = None,
        related_ops_items: RelatedOpsItems = None,
        tags: TagList = None,
        category: OpsItemCategory = None,
        severity: OpsItemSeverity = None,
        actual_start_time: DateTime = None,
        actual_end_time: DateTime = None,
        planned_start_time: DateTime = None,
        planned_end_time: DateTime = None,
        account_id: OpsItemAccountId = None,
    ) -> CreateOpsItemResponse:
        raise NotImplementedError

    @handler("CreateOpsMetadata")
    def create_ops_metadata(
        self,
        context: RequestContext,
        resource_id: OpsMetadataResourceId,
        metadata: MetadataMap = None,
        tags: TagList = None,
    ) -> CreateOpsMetadataResult:
        raise NotImplementedError

    @handler("CreatePatchBaseline")
    def create_patch_baseline(
        self,
        context: RequestContext,
        name: BaselineName,
        operating_system: OperatingSystem = None,
        global_filters: PatchFilterGroup = None,
        approval_rules: PatchRuleGroup = None,
        approved_patches: PatchIdList = None,
        approved_patches_compliance_level: PatchComplianceLevel = None,
        approved_patches_enable_non_security: Boolean = None,
        rejected_patches: PatchIdList = None,
        rejected_patches_action: PatchAction = None,
        description: BaselineDescription = None,
        sources: PatchSourceList = None,
        client_token: ClientToken = None,
        tags: TagList = None,
    ) -> CreatePatchBaselineResult:
        raise NotImplementedError

    @handler("CreateResourceDataSync")
    def create_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        s3_destination: ResourceDataSyncS3Destination = None,
        sync_type: ResourceDataSyncType = None,
        sync_source: ResourceDataSyncSource = None,
    ) -> CreateResourceDataSyncResult:
        raise NotImplementedError

    @handler("DeleteActivation")
    def delete_activation(
        self, context: RequestContext, activation_id: ActivationId
    ) -> DeleteActivationResult:
        raise NotImplementedError

    @handler("DeleteAssociation")
    def delete_association(
        self,
        context: RequestContext,
        name: DocumentARN = None,
        instance_id: InstanceId = None,
        association_id: AssociationId = None,
    ) -> DeleteAssociationResult:
        raise NotImplementedError

    @handler("DeleteDocument")
    def delete_document(
        self,
        context: RequestContext,
        name: DocumentName,
        document_version: DocumentVersion = None,
        version_name: DocumentVersionName = None,
        force: Boolean = None,
    ) -> DeleteDocumentResult:
        raise NotImplementedError

    @handler("DeleteInventory")
    def delete_inventory(
        self,
        context: RequestContext,
        type_name: InventoryItemTypeName,
        schema_delete_option: InventorySchemaDeleteOption = None,
        dry_run: DryRun = None,
        client_token: UUID = None,
    ) -> DeleteInventoryResult:
        raise NotImplementedError

    @handler("DeleteMaintenanceWindow")
    def delete_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId
    ) -> DeleteMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DeleteOpsItem")
    def delete_ops_item(
        self, context: RequestContext, ops_item_id: OpsItemId
    ) -> DeleteOpsItemResponse:
        raise NotImplementedError

    @handler("DeleteOpsMetadata")
    def delete_ops_metadata(
        self, context: RequestContext, ops_metadata_arn: OpsMetadataArn
    ) -> DeleteOpsMetadataResult:
        raise NotImplementedError

    @handler("DeleteParameter")
    def delete_parameter(
        self, context: RequestContext, name: PSParameterName
    ) -> DeleteParameterResult:
        raise NotImplementedError

    @handler("DeleteParameters")
    def delete_parameters(
        self, context: RequestContext, names: ParameterNameList
    ) -> DeleteParametersResult:
        raise NotImplementedError

    @handler("DeletePatchBaseline")
    def delete_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId
    ) -> DeletePatchBaselineResult:
        raise NotImplementedError

    @handler("DeleteResourceDataSync")
    def delete_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        sync_type: ResourceDataSyncType = None,
    ) -> DeleteResourceDataSyncResult:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        policy_id: PolicyId,
        policy_hash: PolicyHash,
    ) -> DeleteResourcePolicyResponse:
        raise NotImplementedError

    @handler("DeregisterManagedInstance")
    def deregister_managed_instance(
        self, context: RequestContext, instance_id: ManagedInstanceId
    ) -> DeregisterManagedInstanceResult:
        raise NotImplementedError

    @handler("DeregisterPatchBaselineForPatchGroup")
    def deregister_patch_baseline_for_patch_group(
        self, context: RequestContext, baseline_id: BaselineId, patch_group: PatchGroup
    ) -> DeregisterPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("DeregisterTargetFromMaintenanceWindow")
    def deregister_target_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        safe: Boolean = None,
    ) -> DeregisterTargetFromMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DeregisterTaskFromMaintenanceWindow")
    def deregister_task_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
    ) -> DeregisterTaskFromMaintenanceWindowResult:
        raise NotImplementedError

    @handler("DescribeActivations")
    def describe_activations(
        self,
        context: RequestContext,
        filters: DescribeActivationsFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeActivationsResult:
        raise NotImplementedError

    @handler("DescribeAssociation")
    def describe_association(
        self,
        context: RequestContext,
        name: DocumentARN = None,
        instance_id: InstanceId = None,
        association_id: AssociationId = None,
        association_version: AssociationVersion = None,
    ) -> DescribeAssociationResult:
        raise NotImplementedError

    @handler("DescribeAssociationExecutionTargets")
    def describe_association_execution_targets(
        self,
        context: RequestContext,
        association_id: AssociationId,
        execution_id: AssociationExecutionId,
        filters: AssociationExecutionTargetsFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeAssociationExecutionTargetsResult:
        raise NotImplementedError

    @handler("DescribeAssociationExecutions")
    def describe_association_executions(
        self,
        context: RequestContext,
        association_id: AssociationId,
        filters: AssociationExecutionFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeAssociationExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAutomationExecutions")
    def describe_automation_executions(
        self,
        context: RequestContext,
        filters: AutomationExecutionFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeAutomationExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAutomationStepExecutions")
    def describe_automation_step_executions(
        self,
        context: RequestContext,
        automation_execution_id: AutomationExecutionId,
        filters: StepExecutionFilterList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        reverse_order: Boolean = None,
    ) -> DescribeAutomationStepExecutionsResult:
        raise NotImplementedError

    @handler("DescribeAvailablePatches")
    def describe_available_patches(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList = None,
        max_results: PatchBaselineMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeAvailablePatchesResult:
        raise NotImplementedError

    @handler("DescribeDocument")
    def describe_document(
        self,
        context: RequestContext,
        name: DocumentARN,
        document_version: DocumentVersion = None,
        version_name: DocumentVersionName = None,
    ) -> DescribeDocumentResult:
        raise NotImplementedError

    @handler("DescribeDocumentPermission")
    def describe_document_permission(
        self,
        context: RequestContext,
        name: DocumentName,
        permission_type: DocumentPermissionType,
        max_results: DocumentPermissionMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeDocumentPermissionResponse:
        raise NotImplementedError

    @handler("DescribeEffectiveInstanceAssociations")
    def describe_effective_instance_associations(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        max_results: EffectiveInstanceAssociationMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeEffectiveInstanceAssociationsResult:
        raise NotImplementedError

    @handler("DescribeEffectivePatchesForPatchBaseline")
    def describe_effective_patches_for_patch_baseline(
        self,
        context: RequestContext,
        baseline_id: BaselineId,
        max_results: PatchBaselineMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeEffectivePatchesForPatchBaselineResult:
        raise NotImplementedError

    @handler("DescribeInstanceAssociationsStatus")
    def describe_instance_associations_status(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeInstanceAssociationsStatusResult:
        raise NotImplementedError

    @handler("DescribeInstanceInformation")
    def describe_instance_information(
        self,
        context: RequestContext,
        instance_information_filter_list: InstanceInformationFilterList = None,
        filters: InstanceInformationStringFilterList = None,
        max_results: MaxResultsEC2Compatible = None,
        next_token: NextToken = None,
    ) -> DescribeInstanceInformationResult:
        raise NotImplementedError

    @handler("DescribeInstancePatchStates")
    def describe_instance_patch_states(
        self,
        context: RequestContext,
        instance_ids: InstanceIdList,
        next_token: NextToken = None,
        max_results: PatchComplianceMaxResults = None,
    ) -> DescribeInstancePatchStatesResult:
        raise NotImplementedError

    @handler("DescribeInstancePatchStatesForPatchGroup")
    def describe_instance_patch_states_for_patch_group(
        self,
        context: RequestContext,
        patch_group: PatchGroup,
        filters: InstancePatchStateFilterList = None,
        next_token: NextToken = None,
        max_results: PatchComplianceMaxResults = None,
    ) -> DescribeInstancePatchStatesForPatchGroupResult:
        raise NotImplementedError

    @handler("DescribeInstancePatches")
    def describe_instance_patches(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        filters: PatchOrchestratorFilterList = None,
        next_token: NextToken = None,
        max_results: PatchComplianceMaxResults = None,
    ) -> DescribeInstancePatchesResult:
        raise NotImplementedError

    @handler("DescribeInventoryDeletions")
    def describe_inventory_deletions(
        self,
        context: RequestContext,
        deletion_id: UUID = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribeInventoryDeletionsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutionTaskInvocations")
    def describe_maintenance_window_execution_task_invocations(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowExecutionTaskInvocationsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutionTasks")
    def describe_maintenance_window_execution_tasks(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowExecutionTasksResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowExecutions")
    def describe_maintenance_window_executions(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowExecutionsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowSchedule")
    def describe_maintenance_window_schedule(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId = None,
        targets: Targets = None,
        resource_type: MaintenanceWindowResourceType = None,
        filters: PatchOrchestratorFilterList = None,
        max_results: MaintenanceWindowSearchMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowScheduleResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowTargets")
    def describe_maintenance_window_targets(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowTargetsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowTasks")
    def describe_maintenance_window_tasks(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowTasksResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindows")
    def describe_maintenance_windows(
        self,
        context: RequestContext,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowsResult:
        raise NotImplementedError

    @handler("DescribeMaintenanceWindowsForTarget")
    def describe_maintenance_windows_for_target(
        self,
        context: RequestContext,
        targets: Targets,
        resource_type: MaintenanceWindowResourceType,
        max_results: MaintenanceWindowSearchMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeMaintenanceWindowsForTargetResult:
        raise NotImplementedError

    @handler("DescribeOpsItems")
    def describe_ops_items(
        self,
        context: RequestContext,
        ops_item_filters: OpsItemFilters = None,
        max_results: OpsItemMaxResults = None,
        next_token: String = None,
    ) -> DescribeOpsItemsResponse:
        raise NotImplementedError

    @handler("DescribeParameters")
    def describe_parameters(
        self,
        context: RequestContext,
        filters: ParametersFilterList = None,
        parameter_filters: ParameterStringFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeParametersResult:
        raise NotImplementedError

    @handler("DescribePatchBaselines")
    def describe_patch_baselines(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList = None,
        max_results: PatchBaselineMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribePatchBaselinesResult:
        raise NotImplementedError

    @handler("DescribePatchGroupState")
    def describe_patch_group_state(
        self, context: RequestContext, patch_group: PatchGroup
    ) -> DescribePatchGroupStateResult:
        raise NotImplementedError

    @handler("DescribePatchGroups")
    def describe_patch_groups(
        self,
        context: RequestContext,
        max_results: PatchBaselineMaxResults = None,
        filters: PatchOrchestratorFilterList = None,
        next_token: NextToken = None,
    ) -> DescribePatchGroupsResult:
        raise NotImplementedError

    @handler("DescribePatchProperties")
    def describe_patch_properties(
        self,
        context: RequestContext,
        operating_system: OperatingSystem,
        property: PatchProperty,
        patch_set: PatchSet = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> DescribePatchPropertiesResult:
        raise NotImplementedError

    @handler("DescribeSessions")
    def describe_sessions(
        self,
        context: RequestContext,
        state: SessionState,
        max_results: SessionMaxResults = None,
        next_token: NextToken = None,
        filters: SessionFilterList = None,
    ) -> DescribeSessionsResponse:
        raise NotImplementedError

    @handler("DisassociateOpsItemRelatedItem")
    def disassociate_ops_item_related_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        association_id: OpsItemRelatedItemAssociationId,
    ) -> DisassociateOpsItemRelatedItemResponse:
        raise NotImplementedError

    @handler("GetAutomationExecution")
    def get_automation_execution(
        self, context: RequestContext, automation_execution_id: AutomationExecutionId
    ) -> GetAutomationExecutionResult:
        raise NotImplementedError

    @handler("GetCalendarState")
    def get_calendar_state(
        self,
        context: RequestContext,
        calendar_names: CalendarNameOrARNList,
        at_time: ISO8601String = None,
    ) -> GetCalendarStateResponse:
        raise NotImplementedError

    @handler("GetCommandInvocation")
    def get_command_invocation(
        self,
        context: RequestContext,
        command_id: CommandId,
        instance_id: InstanceId,
        plugin_name: CommandPluginName = None,
    ) -> GetCommandInvocationResult:
        raise NotImplementedError

    @handler("GetConnectionStatus")
    def get_connection_status(
        self, context: RequestContext, target: SessionTarget
    ) -> GetConnectionStatusResponse:
        raise NotImplementedError

    @handler("GetDefaultPatchBaseline")
    def get_default_patch_baseline(
        self, context: RequestContext, operating_system: OperatingSystem = None
    ) -> GetDefaultPatchBaselineResult:
        raise NotImplementedError

    @handler("GetDeployablePatchSnapshotForInstance")
    def get_deployable_patch_snapshot_for_instance(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        snapshot_id: SnapshotId,
        baseline_override: BaselineOverride = None,
    ) -> GetDeployablePatchSnapshotForInstanceResult:
        raise NotImplementedError

    @handler("GetDocument")
    def get_document(
        self,
        context: RequestContext,
        name: DocumentARN,
        version_name: DocumentVersionName = None,
        document_version: DocumentVersion = None,
        document_format: DocumentFormat = None,
    ) -> GetDocumentResult:
        raise NotImplementedError

    @handler("GetInventory")
    def get_inventory(
        self,
        context: RequestContext,
        filters: InventoryFilterList = None,
        aggregators: InventoryAggregatorList = None,
        result_attributes: ResultAttributeList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> GetInventoryResult:
        raise NotImplementedError

    @handler("GetInventorySchema")
    def get_inventory_schema(
        self,
        context: RequestContext,
        type_name: InventoryItemTypeNameFilter = None,
        next_token: NextToken = None,
        max_results: GetInventorySchemaMaxResults = None,
        aggregator: AggregatorSchemaOnly = None,
        sub_type: IsSubTypeSchema = None,
    ) -> GetInventorySchemaResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindow")
    def get_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId
    ) -> GetMaintenanceWindowResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecution")
    def get_maintenance_window_execution(
        self, context: RequestContext, window_execution_id: MaintenanceWindowExecutionId
    ) -> GetMaintenanceWindowExecutionResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecutionTask")
    def get_maintenance_window_execution_task(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
    ) -> GetMaintenanceWindowExecutionTaskResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowExecutionTaskInvocation")
    def get_maintenance_window_execution_task_invocation(
        self,
        context: RequestContext,
        window_execution_id: MaintenanceWindowExecutionId,
        task_id: MaintenanceWindowExecutionTaskId,
        invocation_id: MaintenanceWindowExecutionTaskInvocationId,
    ) -> GetMaintenanceWindowExecutionTaskInvocationResult:
        raise NotImplementedError

    @handler("GetMaintenanceWindowTask")
    def get_maintenance_window_task(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
    ) -> GetMaintenanceWindowTaskResult:
        raise NotImplementedError

    @handler("GetOpsItem")
    def get_ops_item(
        self, context: RequestContext, ops_item_id: OpsItemId, ops_item_arn: OpsItemArn = None
    ) -> GetOpsItemResponse:
        raise NotImplementedError

    @handler("GetOpsMetadata")
    def get_ops_metadata(
        self,
        context: RequestContext,
        ops_metadata_arn: OpsMetadataArn,
        max_results: GetOpsMetadataMaxResults = None,
        next_token: NextToken = None,
    ) -> GetOpsMetadataResult:
        raise NotImplementedError

    @handler("GetOpsSummary")
    def get_ops_summary(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName = None,
        filters: OpsFilterList = None,
        aggregators: OpsAggregatorList = None,
        result_attributes: OpsResultAttributeList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> GetOpsSummaryResult:
        raise NotImplementedError

    @handler("GetParameter")
    def get_parameter(
        self, context: RequestContext, name: PSParameterName, with_decryption: Boolean = None
    ) -> GetParameterResult:
        raise NotImplementedError

    @handler("GetParameterHistory")
    def get_parameter_history(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetParameterHistoryResult:
        raise NotImplementedError

    @handler("GetParameters")
    def get_parameters(
        self, context: RequestContext, names: ParameterNameList, with_decryption: Boolean = None
    ) -> GetParametersResult:
        raise NotImplementedError

    @handler("GetParametersByPath")
    def get_parameters_by_path(
        self,
        context: RequestContext,
        path: PSParameterName,
        recursive: Boolean = None,
        parameter_filters: ParameterStringFilterList = None,
        with_decryption: Boolean = None,
        max_results: GetParametersByPathMaxResults = None,
        next_token: NextToken = None,
    ) -> GetParametersByPathResult:
        raise NotImplementedError

    @handler("GetPatchBaseline")
    def get_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId
    ) -> GetPatchBaselineResult:
        raise NotImplementedError

    @handler("GetPatchBaselineForPatchGroup")
    def get_patch_baseline_for_patch_group(
        self,
        context: RequestContext,
        patch_group: PatchGroup,
        operating_system: OperatingSystem = None,
    ) -> GetPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("GetResourcePolicies")
    def get_resource_policies(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: String = None,
        max_results: ResourcePolicyMaxResults = None,
    ) -> GetResourcePoliciesResponse:
        raise NotImplementedError

    @handler("GetServiceSetting")
    def get_service_setting(
        self, context: RequestContext, setting_id: ServiceSettingId
    ) -> GetServiceSettingResult:
        raise NotImplementedError

    @handler("LabelParameterVersion")
    def label_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        labels: ParameterLabelList,
        parameter_version: PSParameterVersion = None,
    ) -> LabelParameterVersionResult:
        raise NotImplementedError

    @handler("ListAssociationVersions")
    def list_association_versions(
        self,
        context: RequestContext,
        association_id: AssociationId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListAssociationVersionsResult:
        raise NotImplementedError

    @handler("ListAssociations")
    def list_associations(
        self,
        context: RequestContext,
        association_filter_list: AssociationFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListAssociationsResult:
        raise NotImplementedError

    @handler("ListCommandInvocations")
    def list_command_invocations(
        self,
        context: RequestContext,
        command_id: CommandId = None,
        instance_id: InstanceId = None,
        max_results: CommandMaxResults = None,
        next_token: NextToken = None,
        filters: CommandFilterList = None,
        details: Boolean = None,
    ) -> ListCommandInvocationsResult:
        raise NotImplementedError

    @handler("ListCommands")
    def list_commands(
        self,
        context: RequestContext,
        command_id: CommandId = None,
        instance_id: InstanceId = None,
        max_results: CommandMaxResults = None,
        next_token: NextToken = None,
        filters: CommandFilterList = None,
    ) -> ListCommandsResult:
        raise NotImplementedError

    @handler("ListComplianceItems")
    def list_compliance_items(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList = None,
        resource_ids: ComplianceResourceIdList = None,
        resource_types: ComplianceResourceTypeList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListComplianceItemsResult:
        raise NotImplementedError

    @handler("ListComplianceSummaries")
    def list_compliance_summaries(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListComplianceSummariesResult:
        raise NotImplementedError

    @handler("ListDocumentMetadataHistory")
    def list_document_metadata_history(
        self,
        context: RequestContext,
        name: DocumentName,
        metadata: DocumentMetadataEnum,
        document_version: DocumentVersion = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDocumentMetadataHistoryResponse:
        raise NotImplementedError

    @handler("ListDocumentVersions")
    def list_document_versions(
        self,
        context: RequestContext,
        name: DocumentARN,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDocumentVersionsResult:
        raise NotImplementedError

    @handler("ListDocuments")
    def list_documents(
        self,
        context: RequestContext,
        document_filter_list: DocumentFilterList = None,
        filters: DocumentKeyValuesFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListDocumentsResult:
        raise NotImplementedError

    @handler("ListInventoryEntries")
    def list_inventory_entries(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        type_name: InventoryItemTypeName,
        filters: InventoryFilterList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListInventoryEntriesResult:
        raise NotImplementedError

    @handler("ListOpsItemEvents")
    def list_ops_item_events(
        self,
        context: RequestContext,
        filters: OpsItemEventFilters = None,
        max_results: OpsItemEventMaxResults = None,
        next_token: String = None,
    ) -> ListOpsItemEventsResponse:
        raise NotImplementedError

    @handler("ListOpsItemRelatedItems")
    def list_ops_item_related_items(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId = None,
        filters: OpsItemRelatedItemsFilters = None,
        max_results: OpsItemRelatedItemsMaxResults = None,
        next_token: String = None,
    ) -> ListOpsItemRelatedItemsResponse:
        raise NotImplementedError

    @handler("ListOpsMetadata")
    def list_ops_metadata(
        self,
        context: RequestContext,
        filters: OpsMetadataFilterList = None,
        max_results: ListOpsMetadataMaxResults = None,
        next_token: NextToken = None,
    ) -> ListOpsMetadataResult:
        raise NotImplementedError

    @handler("ListResourceComplianceSummaries")
    def list_resource_compliance_summaries(
        self,
        context: RequestContext,
        filters: ComplianceStringFilterList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListResourceComplianceSummariesResult:
        raise NotImplementedError

    @handler("ListResourceDataSync")
    def list_resource_data_sync(
        self,
        context: RequestContext,
        sync_type: ResourceDataSyncType = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListResourceDataSyncResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
    ) -> ListTagsForResourceResult:
        raise NotImplementedError

    @handler("ModifyDocumentPermission")
    def modify_document_permission(
        self,
        context: RequestContext,
        name: DocumentName,
        permission_type: DocumentPermissionType,
        account_ids_to_add: AccountIdList = None,
        account_ids_to_remove: AccountIdList = None,
        shared_document_version: SharedDocumentVersion = None,
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
        item_content_hash: ComplianceItemContentHash = None,
        upload_type: ComplianceUploadType = None,
    ) -> PutComplianceItemsResult:
        raise NotImplementedError

    @handler("PutInventory")
    def put_inventory(
        self, context: RequestContext, instance_id: InstanceId, items: InventoryItemList
    ) -> PutInventoryResult:
        raise NotImplementedError

    @handler("PutParameter", expand=False)
    def put_parameter(
        self, context: RequestContext, request: PutParameterRequest
    ) -> PutParameterResult:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        policy: Policy,
        policy_id: PolicyId = None,
        policy_hash: PolicyHash = None,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("RegisterDefaultPatchBaseline")
    def register_default_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId
    ) -> RegisterDefaultPatchBaselineResult:
        raise NotImplementedError

    @handler("RegisterPatchBaselineForPatchGroup")
    def register_patch_baseline_for_patch_group(
        self, context: RequestContext, baseline_id: BaselineId, patch_group: PatchGroup
    ) -> RegisterPatchBaselineForPatchGroupResult:
        raise NotImplementedError

    @handler("RegisterTargetWithMaintenanceWindow")
    def register_target_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        resource_type: MaintenanceWindowResourceType,
        targets: Targets,
        owner_information: OwnerInformation = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
    ) -> RegisterTargetWithMaintenanceWindowResult:
        raise NotImplementedError

    @handler("RegisterTaskWithMaintenanceWindow")
    def register_task_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        task_arn: MaintenanceWindowTaskArn,
        task_type: MaintenanceWindowTaskType,
        targets: Targets = None,
        service_role_arn: ServiceRole = None,
        task_parameters: MaintenanceWindowTaskParameters = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters = None,
        priority: MaintenanceWindowTaskPriority = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        logging_info: LoggingInfo = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> RegisterTaskWithMaintenanceWindowResult:
        raise NotImplementedError

    @handler("RemoveTagsFromResource")
    def remove_tags_from_resource(
        self,
        context: RequestContext,
        resource_type: ResourceTypeForTagging,
        resource_id: ResourceId,
        tag_keys: KeyList,
    ) -> RemoveTagsFromResourceResult:
        raise NotImplementedError

    @handler("ResetServiceSetting")
    def reset_service_setting(
        self, context: RequestContext, setting_id: ServiceSettingId
    ) -> ResetServiceSettingResult:
        raise NotImplementedError

    @handler("ResumeSession")
    def resume_session(
        self, context: RequestContext, session_id: SessionId
    ) -> ResumeSessionResponse:
        raise NotImplementedError

    @handler("SendAutomationSignal")
    def send_automation_signal(
        self,
        context: RequestContext,
        automation_execution_id: AutomationExecutionId,
        signal_type: SignalType,
        payload: AutomationParameterMap = None,
    ) -> SendAutomationSignalResult:
        raise NotImplementedError

    @handler("SendCommand")
    def send_command(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        instance_ids: InstanceIdList = None,
        targets: Targets = None,
        document_version: DocumentVersion = None,
        document_hash: DocumentHash = None,
        document_hash_type: DocumentHashType = None,
        timeout_seconds: TimeoutSeconds = None,
        comment: Comment = None,
        parameters: Parameters = None,
        output_s3_region: S3Region = None,
        output_s3_bucket_name: S3BucketName = None,
        output_s3_key_prefix: S3KeyPrefix = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        service_role_arn: ServiceRole = None,
        notification_config: NotificationConfig = None,
        cloud_watch_output_config: CloudWatchOutputConfig = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> SendCommandResult:
        raise NotImplementedError

    @handler("StartAssociationsOnce")
    def start_associations_once(
        self, context: RequestContext, association_ids: AssociationIdList
    ) -> StartAssociationsOnceResult:
        raise NotImplementedError

    @handler("StartAutomationExecution")
    def start_automation_execution(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        document_version: DocumentVersion = None,
        parameters: AutomationParameterMap = None,
        client_token: IdempotencyToken = None,
        mode: ExecutionMode = None,
        target_parameter_name: AutomationParameterKey = None,
        targets: Targets = None,
        target_maps: TargetMaps = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        target_locations: TargetLocations = None,
        tags: TagList = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> StartAutomationExecutionResult:
        raise NotImplementedError

    @handler("StartChangeRequestExecution")
    def start_change_request_execution(
        self,
        context: RequestContext,
        document_name: DocumentARN,
        runbooks: Runbooks,
        scheduled_time: DateTime = None,
        document_version: DocumentVersion = None,
        parameters: AutomationParameterMap = None,
        change_request_name: ChangeRequestName = None,
        client_token: IdempotencyToken = None,
        auto_approve: Boolean = None,
        tags: TagList = None,
        scheduled_end_time: DateTime = None,
        change_details: ChangeDetailsValue = None,
    ) -> StartChangeRequestExecutionResult:
        raise NotImplementedError

    @handler("StartSession")
    def start_session(
        self,
        context: RequestContext,
        target: SessionTarget,
        document_name: DocumentARN = None,
        reason: SessionReason = None,
        parameters: SessionManagerParameters = None,
    ) -> StartSessionResponse:
        raise NotImplementedError

    @handler("StopAutomationExecution", expand=False)
    def stop_automation_execution(
        self, context: RequestContext, request: StopAutomationExecutionRequest
    ) -> StopAutomationExecutionResult:
        raise NotImplementedError

    @handler("TerminateSession")
    def terminate_session(
        self, context: RequestContext, session_id: SessionId
    ) -> TerminateSessionResponse:
        raise NotImplementedError

    @handler("UnlabelParameterVersion")
    def unlabel_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        parameter_version: PSParameterVersion,
        labels: ParameterLabelList,
    ) -> UnlabelParameterVersionResult:
        raise NotImplementedError

    @handler("UpdateAssociation")
    def update_association(
        self,
        context: RequestContext,
        association_id: AssociationId,
        parameters: Parameters = None,
        document_version: DocumentVersion = None,
        schedule_expression: ScheduleExpression = None,
        output_location: InstanceAssociationOutputLocation = None,
        name: DocumentARN = None,
        targets: Targets = None,
        association_name: AssociationName = None,
        association_version: AssociationVersion = None,
        automation_target_parameter_name: AutomationTargetParameterName = None,
        max_errors: MaxErrors = None,
        max_concurrency: MaxConcurrency = None,
        compliance_severity: AssociationComplianceSeverity = None,
        sync_compliance: AssociationSyncCompliance = None,
        apply_only_at_cron_interval: ApplyOnlyAtCronInterval = None,
        calendar_names: CalendarNameOrARNList = None,
        target_locations: TargetLocations = None,
        schedule_offset: ScheduleOffset = None,
        target_maps: TargetMaps = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> UpdateAssociationResult:
        raise NotImplementedError

    @handler("UpdateAssociationStatus")
    def update_association_status(
        self,
        context: RequestContext,
        name: DocumentARN,
        instance_id: InstanceId,
        association_status: AssociationStatus,
    ) -> UpdateAssociationStatusResult:
        raise NotImplementedError

    @handler("UpdateDocument")
    def update_document(
        self,
        context: RequestContext,
        content: DocumentContent,
        name: DocumentName,
        attachments: AttachmentsSourceList = None,
        display_name: DocumentDisplayName = None,
        version_name: DocumentVersionName = None,
        document_version: DocumentVersion = None,
        document_format: DocumentFormat = None,
        target_type: TargetType = None,
    ) -> UpdateDocumentResult:
        raise NotImplementedError

    @handler("UpdateDocumentDefaultVersion")
    def update_document_default_version(
        self, context: RequestContext, name: DocumentName, document_version: DocumentVersionNumber
    ) -> UpdateDocumentDefaultVersionResult:
        raise NotImplementedError

    @handler("UpdateDocumentMetadata")
    def update_document_metadata(
        self,
        context: RequestContext,
        name: DocumentName,
        document_reviews: DocumentReviews,
        document_version: DocumentVersion = None,
    ) -> UpdateDocumentMetadataResponse:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindow")
    def update_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        start_date: MaintenanceWindowStringDateTime = None,
        end_date: MaintenanceWindowStringDateTime = None,
        schedule: MaintenanceWindowSchedule = None,
        schedule_timezone: MaintenanceWindowTimezone = None,
        schedule_offset: MaintenanceWindowOffset = None,
        duration: MaintenanceWindowDurationHours = None,
        cutoff: MaintenanceWindowCutoff = None,
        allow_unassociated_targets: MaintenanceWindowAllowUnassociatedTargets = None,
        enabled: MaintenanceWindowEnabled = None,
        replace: Boolean = None,
    ) -> UpdateMaintenanceWindowResult:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindowTarget")
    def update_maintenance_window_target(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        targets: Targets = None,
        owner_information: OwnerInformation = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        replace: Boolean = None,
    ) -> UpdateMaintenanceWindowTargetResult:
        raise NotImplementedError

    @handler("UpdateMaintenanceWindowTask")
    def update_maintenance_window_task(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        targets: Targets = None,
        task_arn: MaintenanceWindowTaskArn = None,
        service_role_arn: ServiceRole = None,
        task_parameters: MaintenanceWindowTaskParameters = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters = None,
        priority: MaintenanceWindowTaskPriority = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        logging_info: LoggingInfo = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        replace: Boolean = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior = None,
        alarm_configuration: AlarmConfiguration = None,
    ) -> UpdateMaintenanceWindowTaskResult:
        raise NotImplementedError

    @handler("UpdateManagedInstanceRole")
    def update_managed_instance_role(
        self, context: RequestContext, instance_id: ManagedInstanceId, iam_role: IamRole
    ) -> UpdateManagedInstanceRoleResult:
        raise NotImplementedError

    @handler("UpdateOpsItem")
    def update_ops_item(
        self,
        context: RequestContext,
        ops_item_id: OpsItemId,
        description: OpsItemDescription = None,
        operational_data: OpsItemOperationalData = None,
        operational_data_to_delete: OpsItemOpsDataKeysList = None,
        notifications: OpsItemNotifications = None,
        priority: OpsItemPriority = None,
        related_ops_items: RelatedOpsItems = None,
        status: OpsItemStatus = None,
        title: OpsItemTitle = None,
        category: OpsItemCategory = None,
        severity: OpsItemSeverity = None,
        actual_start_time: DateTime = None,
        actual_end_time: DateTime = None,
        planned_start_time: DateTime = None,
        planned_end_time: DateTime = None,
        ops_item_arn: OpsItemArn = None,
    ) -> UpdateOpsItemResponse:
        raise NotImplementedError

    @handler("UpdateOpsMetadata")
    def update_ops_metadata(
        self,
        context: RequestContext,
        ops_metadata_arn: OpsMetadataArn,
        metadata_to_update: MetadataMap = None,
        keys_to_delete: MetadataKeysToDeleteList = None,
    ) -> UpdateOpsMetadataResult:
        raise NotImplementedError

    @handler("UpdatePatchBaseline")
    def update_patch_baseline(
        self,
        context: RequestContext,
        baseline_id: BaselineId,
        name: BaselineName = None,
        global_filters: PatchFilterGroup = None,
        approval_rules: PatchRuleGroup = None,
        approved_patches: PatchIdList = None,
        approved_patches_compliance_level: PatchComplianceLevel = None,
        approved_patches_enable_non_security: Boolean = None,
        rejected_patches: PatchIdList = None,
        rejected_patches_action: PatchAction = None,
        description: BaselineDescription = None,
        sources: PatchSourceList = None,
        replace: Boolean = None,
    ) -> UpdatePatchBaselineResult:
        raise NotImplementedError

    @handler("UpdateResourceDataSync")
    def update_resource_data_sync(
        self,
        context: RequestContext,
        sync_name: ResourceDataSyncName,
        sync_type: ResourceDataSyncType,
        sync_source: ResourceDataSyncSource,
    ) -> UpdateResourceDataSyncResult:
        raise NotImplementedError

    @handler("UpdateServiceSetting")
    def update_service_setting(
        self,
        context: RequestContext,
        setting_id: ServiceSettingId,
        setting_value: ServiceSettingValue,
    ) -> UpdateServiceSettingResult:
        raise NotImplementedError
