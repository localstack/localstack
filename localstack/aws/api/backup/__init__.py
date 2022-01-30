import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
AccountId = str
BackupOptionKey = str
BackupOptionValue = str
BackupPlanName = str
BackupRuleName = str
BackupSelectionName = str
BackupVaultName = str
Boolean = bool
ConditionKey = str
ConditionValue = str
ControlName = str
CronExpression = str
FrameworkDescription = str
FrameworkName = str
GlobalSettingsName = str
GlobalSettingsValue = str
IAMPolicy = str
IAMRoleArn = str
IsEnabled = bool
MaxFrameworkInputs = int
MaxResults = int
MetadataKey = str
MetadataValue = str
ParameterName = str
ParameterValue = str
ReportJobId = str
ReportPlanDescription = str
ReportPlanName = str
ResourceType = str
RestoreJobId = str
TagKey = str
TagValue = str
boolean = bool
integer = int
string = str


class BackupJobState(str):
    CREATED = "CREATED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    ABORTING = "ABORTING"
    ABORTED = "ABORTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class BackupVaultEvent(str):
    BACKUP_JOB_STARTED = "BACKUP_JOB_STARTED"
    BACKUP_JOB_COMPLETED = "BACKUP_JOB_COMPLETED"
    BACKUP_JOB_SUCCESSFUL = "BACKUP_JOB_SUCCESSFUL"
    BACKUP_JOB_FAILED = "BACKUP_JOB_FAILED"
    BACKUP_JOB_EXPIRED = "BACKUP_JOB_EXPIRED"
    RESTORE_JOB_STARTED = "RESTORE_JOB_STARTED"
    RESTORE_JOB_COMPLETED = "RESTORE_JOB_COMPLETED"
    RESTORE_JOB_SUCCESSFUL = "RESTORE_JOB_SUCCESSFUL"
    RESTORE_JOB_FAILED = "RESTORE_JOB_FAILED"
    COPY_JOB_STARTED = "COPY_JOB_STARTED"
    COPY_JOB_SUCCESSFUL = "COPY_JOB_SUCCESSFUL"
    COPY_JOB_FAILED = "COPY_JOB_FAILED"
    RECOVERY_POINT_MODIFIED = "RECOVERY_POINT_MODIFIED"
    BACKUP_PLAN_CREATED = "BACKUP_PLAN_CREATED"
    BACKUP_PLAN_MODIFIED = "BACKUP_PLAN_MODIFIED"
    S3_BACKUP_OBJECT_FAILED = "S3_BACKUP_OBJECT_FAILED"
    S3_RESTORE_OBJECT_FAILED = "S3_RESTORE_OBJECT_FAILED"


class ConditionType(str):
    STRINGEQUALS = "STRINGEQUALS"


class CopyJobState(str):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RecoveryPointStatus(str):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    DELETING = "DELETING"
    EXPIRED = "EXPIRED"


class RestoreJobStatus(str):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class StorageClass(str):
    WARM = "WARM"
    COLD = "COLD"
    DELETED = "DELETED"


class AlreadyExistsException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    CreatorRequestId: Optional[string]
    Arn: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class ConflictException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class DependencyFailureException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class InvalidParameterValueException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class InvalidRequestException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class InvalidResourceStateException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class LimitExceededException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class MissingParameterValueException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class ResourceNotFoundException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


class ServiceUnavailableException(ServiceException):
    Code: Optional[string]
    Message: Optional[string]
    Type: Optional[string]
    Context: Optional[string]


BackupOptions = Dict[BackupOptionKey, BackupOptionValue]


class AdvancedBackupSetting(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    BackupOptions: Optional[BackupOptions]


AdvancedBackupSettings = List[AdvancedBackupSetting]
Long = int
timestamp = datetime


class RecoveryPointCreator(TypedDict, total=False):
    BackupPlanId: Optional[string]
    BackupPlanArn: Optional[ARN]
    BackupPlanVersion: Optional[string]
    BackupRuleId: Optional[string]


class BackupJob(TypedDict, total=False):
    AccountId: Optional[AccountId]
    BackupJobId: Optional[string]
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    RecoveryPointArn: Optional[ARN]
    ResourceArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    State: Optional[BackupJobState]
    StatusMessage: Optional[string]
    PercentDone: Optional[string]
    BackupSizeInBytes: Optional[Long]
    IamRoleArn: Optional[IAMRoleArn]
    CreatedBy: Optional[RecoveryPointCreator]
    ExpectedCompletionDate: Optional[timestamp]
    StartBy: Optional[timestamp]
    ResourceType: Optional[ResourceType]
    BytesTransferred: Optional[Long]
    BackupOptions: Optional[BackupOptions]
    BackupType: Optional[string]


BackupJobsList = List[BackupJob]


class Lifecycle(TypedDict, total=False):
    MoveToColdStorageAfterDays: Optional[Long]
    DeleteAfterDays: Optional[Long]


class CopyAction(TypedDict, total=False):
    Lifecycle: Optional[Lifecycle]
    DestinationBackupVaultArn: ARN


CopyActions = List[CopyAction]
Tags = Dict[TagKey, TagValue]
WindowMinutes = int


class BackupRule(TypedDict, total=False):
    RuleName: BackupRuleName
    TargetBackupVaultName: BackupVaultName
    ScheduleExpression: Optional[CronExpression]
    StartWindowMinutes: Optional[WindowMinutes]
    CompletionWindowMinutes: Optional[WindowMinutes]
    Lifecycle: Optional[Lifecycle]
    RecoveryPointTags: Optional[Tags]
    RuleId: Optional[string]
    CopyActions: Optional[CopyActions]
    EnableContinuousBackup: Optional[Boolean]


BackupRules = List[BackupRule]


class BackupPlan(TypedDict, total=False):
    BackupPlanName: BackupPlanName
    Rules: BackupRules
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


class BackupRuleInput(TypedDict, total=False):
    RuleName: BackupRuleName
    TargetBackupVaultName: BackupVaultName
    ScheduleExpression: Optional[CronExpression]
    StartWindowMinutes: Optional[WindowMinutes]
    CompletionWindowMinutes: Optional[WindowMinutes]
    Lifecycle: Optional[Lifecycle]
    RecoveryPointTags: Optional[Tags]
    CopyActions: Optional[CopyActions]
    EnableContinuousBackup: Optional[Boolean]


BackupRulesInput = List[BackupRuleInput]


class BackupPlanInput(TypedDict, total=False):
    BackupPlanName: BackupPlanName
    Rules: BackupRulesInput
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


class BackupPlanTemplatesListMember(TypedDict, total=False):
    BackupPlanTemplateId: Optional[string]
    BackupPlanTemplateName: Optional[string]


BackupPlanTemplatesList = List[BackupPlanTemplatesListMember]


class BackupPlansListMember(TypedDict, total=False):
    BackupPlanArn: Optional[ARN]
    BackupPlanId: Optional[string]
    CreationDate: Optional[timestamp]
    DeletionDate: Optional[timestamp]
    VersionId: Optional[string]
    BackupPlanName: Optional[BackupPlanName]
    CreatorRequestId: Optional[string]
    LastExecutionDate: Optional[timestamp]
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


BackupPlanVersionsList = List[BackupPlansListMember]
BackupPlansList = List[BackupPlansListMember]


class ConditionParameter(TypedDict, total=False):
    ConditionKey: Optional[ConditionKey]
    ConditionValue: Optional[ConditionValue]


ConditionParameters = List[ConditionParameter]


class Conditions(TypedDict, total=False):
    StringEquals: Optional[ConditionParameters]
    StringNotEquals: Optional[ConditionParameters]
    StringLike: Optional[ConditionParameters]
    StringNotLike: Optional[ConditionParameters]


ResourceArns = List[ARN]


class Condition(TypedDict, total=False):
    ConditionType: ConditionType
    ConditionKey: ConditionKey
    ConditionValue: ConditionValue


ListOfTags = List[Condition]


class BackupSelection(TypedDict, total=False):
    SelectionName: BackupSelectionName
    IamRoleArn: IAMRoleArn
    Resources: Optional[ResourceArns]
    ListOfTags: Optional[ListOfTags]
    NotResources: Optional[ResourceArns]
    Conditions: Optional[Conditions]


class BackupSelectionsListMember(TypedDict, total=False):
    SelectionId: Optional[string]
    SelectionName: Optional[BackupSelectionName]
    BackupPlanId: Optional[string]
    CreationDate: Optional[timestamp]
    CreatorRequestId: Optional[string]
    IamRoleArn: Optional[IAMRoleArn]


BackupSelectionsList = List[BackupSelectionsListMember]
BackupVaultEvents = List[BackupVaultEvent]
long = int


class BackupVaultListMember(TypedDict, total=False):
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    EncryptionKeyArn: Optional[ARN]
    CreatorRequestId: Optional[string]
    NumberOfRecoveryPoints: Optional[long]
    Locked: Optional[Boolean]
    MinRetentionDays: Optional[Long]
    MaxRetentionDays: Optional[Long]
    LockDate: Optional[timestamp]


BackupVaultList = List[BackupVaultListMember]


class CalculatedLifecycle(TypedDict, total=False):
    MoveToColdStorageAt: Optional[timestamp]
    DeleteAt: Optional[timestamp]


ComplianceResourceIdList = List[string]


class ControlInputParameter(TypedDict, total=False):
    ParameterName: Optional[ParameterName]
    ParameterValue: Optional[ParameterValue]


ControlInputParameters = List[ControlInputParameter]
stringMap = Dict[string, string]
ResourceTypeList = List[ARN]


class ControlScope(TypedDict, total=False):
    ComplianceResourceIds: Optional[ComplianceResourceIdList]
    ComplianceResourceTypes: Optional[ResourceTypeList]
    Tags: Optional[stringMap]


class CopyJob(TypedDict, total=False):
    AccountId: Optional[AccountId]
    CopyJobId: Optional[string]
    SourceBackupVaultArn: Optional[ARN]
    SourceRecoveryPointArn: Optional[ARN]
    DestinationBackupVaultArn: Optional[ARN]
    DestinationRecoveryPointArn: Optional[ARN]
    ResourceArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    State: Optional[CopyJobState]
    StatusMessage: Optional[string]
    BackupSizeInBytes: Optional[Long]
    IamRoleArn: Optional[IAMRoleArn]
    CreatedBy: Optional[RecoveryPointCreator]
    ResourceType: Optional[ResourceType]


CopyJobsList = List[CopyJob]


class CreateBackupPlanInput(ServiceRequest):
    BackupPlan: BackupPlanInput
    BackupPlanTags: Optional[Tags]
    CreatorRequestId: Optional[string]


class CreateBackupPlanOutput(TypedDict, total=False):
    BackupPlanId: Optional[string]
    BackupPlanArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    VersionId: Optional[string]
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


class CreateBackupSelectionInput(ServiceRequest):
    BackupPlanId: string
    BackupSelection: BackupSelection
    CreatorRequestId: Optional[string]


class CreateBackupSelectionOutput(TypedDict, total=False):
    SelectionId: Optional[string]
    BackupPlanId: Optional[string]
    CreationDate: Optional[timestamp]


class CreateBackupVaultInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    BackupVaultTags: Optional[Tags]
    EncryptionKeyArn: Optional[ARN]
    CreatorRequestId: Optional[string]


class CreateBackupVaultOutput(TypedDict, total=False):
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    CreationDate: Optional[timestamp]


class FrameworkControl(TypedDict, total=False):
    ControlName: ControlName
    ControlInputParameters: Optional[ControlInputParameters]
    ControlScope: Optional[ControlScope]


FrameworkControls = List[FrameworkControl]


class CreateFrameworkInput(ServiceRequest):
    FrameworkName: FrameworkName
    FrameworkDescription: Optional[FrameworkDescription]
    FrameworkControls: FrameworkControls
    IdempotencyToken: Optional[string]
    FrameworkTags: Optional[stringMap]


class CreateFrameworkOutput(TypedDict, total=False):
    FrameworkName: Optional[FrameworkName]
    FrameworkArn: Optional[ARN]


stringList = List[string]


class ReportSetting(TypedDict, total=False):
    ReportTemplate: string
    FrameworkArns: Optional[stringList]
    NumberOfFrameworks: Optional[integer]


FormatList = List[string]


class ReportDeliveryChannel(TypedDict, total=False):
    S3BucketName: string
    S3KeyPrefix: Optional[string]
    Formats: Optional[FormatList]


class CreateReportPlanInput(ServiceRequest):
    ReportPlanName: ReportPlanName
    ReportPlanDescription: Optional[ReportPlanDescription]
    ReportDeliveryChannel: ReportDeliveryChannel
    ReportSetting: ReportSetting
    ReportPlanTags: Optional[stringMap]
    IdempotencyToken: Optional[string]


class CreateReportPlanOutput(TypedDict, total=False):
    ReportPlanName: Optional[ReportPlanName]
    ReportPlanArn: Optional[ARN]
    CreationTime: Optional[timestamp]


class DeleteBackupPlanInput(ServiceRequest):
    BackupPlanId: string


class DeleteBackupPlanOutput(TypedDict, total=False):
    BackupPlanId: Optional[string]
    BackupPlanArn: Optional[ARN]
    DeletionDate: Optional[timestamp]
    VersionId: Optional[string]


class DeleteBackupSelectionInput(ServiceRequest):
    BackupPlanId: string
    SelectionId: string


class DeleteBackupVaultAccessPolicyInput(ServiceRequest):
    BackupVaultName: BackupVaultName


class DeleteBackupVaultInput(ServiceRequest):
    BackupVaultName: string


class DeleteBackupVaultLockConfigurationInput(ServiceRequest):
    BackupVaultName: BackupVaultName


class DeleteBackupVaultNotificationsInput(ServiceRequest):
    BackupVaultName: BackupVaultName


class DeleteFrameworkInput(ServiceRequest):
    FrameworkName: FrameworkName


class DeleteRecoveryPointInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    RecoveryPointArn: ARN


class DeleteReportPlanInput(ServiceRequest):
    ReportPlanName: ReportPlanName


class DescribeBackupJobInput(ServiceRequest):
    BackupJobId: string


class DescribeBackupJobOutput(TypedDict, total=False):
    AccountId: Optional[AccountId]
    BackupJobId: Optional[string]
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    RecoveryPointArn: Optional[ARN]
    ResourceArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    State: Optional[BackupJobState]
    StatusMessage: Optional[string]
    PercentDone: Optional[string]
    BackupSizeInBytes: Optional[Long]
    IamRoleArn: Optional[IAMRoleArn]
    CreatedBy: Optional[RecoveryPointCreator]
    ResourceType: Optional[ResourceType]
    BytesTransferred: Optional[Long]
    ExpectedCompletionDate: Optional[timestamp]
    StartBy: Optional[timestamp]
    BackupOptions: Optional[BackupOptions]
    BackupType: Optional[string]


class DescribeBackupVaultInput(ServiceRequest):
    BackupVaultName: string


class DescribeBackupVaultOutput(TypedDict, total=False):
    BackupVaultName: Optional[string]
    BackupVaultArn: Optional[ARN]
    EncryptionKeyArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CreatorRequestId: Optional[string]
    NumberOfRecoveryPoints: Optional[long]
    Locked: Optional[Boolean]
    MinRetentionDays: Optional[Long]
    MaxRetentionDays: Optional[Long]
    LockDate: Optional[timestamp]


class DescribeCopyJobInput(ServiceRequest):
    CopyJobId: string


class DescribeCopyJobOutput(TypedDict, total=False):
    CopyJob: Optional[CopyJob]


class DescribeFrameworkInput(ServiceRequest):
    FrameworkName: FrameworkName


class DescribeFrameworkOutput(TypedDict, total=False):
    FrameworkName: Optional[FrameworkName]
    FrameworkArn: Optional[ARN]
    FrameworkDescription: Optional[FrameworkDescription]
    FrameworkControls: Optional[FrameworkControls]
    CreationTime: Optional[timestamp]
    DeploymentStatus: Optional[string]
    FrameworkStatus: Optional[string]
    IdempotencyToken: Optional[string]


class DescribeGlobalSettingsInput(ServiceRequest):
    pass


GlobalSettings = Dict[GlobalSettingsName, GlobalSettingsValue]


class DescribeGlobalSettingsOutput(TypedDict, total=False):
    GlobalSettings: Optional[GlobalSettings]
    LastUpdateTime: Optional[timestamp]


class DescribeProtectedResourceInput(ServiceRequest):
    ResourceArn: ARN


class DescribeProtectedResourceOutput(TypedDict, total=False):
    ResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]
    LastBackupTime: Optional[timestamp]


class DescribeRecoveryPointInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    RecoveryPointArn: ARN


class DescribeRecoveryPointOutput(TypedDict, total=False):
    RecoveryPointArn: Optional[ARN]
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    SourceBackupVaultArn: Optional[ARN]
    ResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]
    CreatedBy: Optional[RecoveryPointCreator]
    IamRoleArn: Optional[IAMRoleArn]
    Status: Optional[RecoveryPointStatus]
    StatusMessage: Optional[string]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    BackupSizeInBytes: Optional[Long]
    CalculatedLifecycle: Optional[CalculatedLifecycle]
    Lifecycle: Optional[Lifecycle]
    EncryptionKeyArn: Optional[ARN]
    IsEncrypted: Optional[boolean]
    StorageClass: Optional[StorageClass]
    LastRestoreTime: Optional[timestamp]


class DescribeRegionSettingsInput(ServiceRequest):
    pass


ResourceTypeManagementPreference = Dict[ResourceType, IsEnabled]
ResourceTypeOptInPreference = Dict[ResourceType, IsEnabled]


class DescribeRegionSettingsOutput(TypedDict, total=False):
    ResourceTypeOptInPreference: Optional[ResourceTypeOptInPreference]
    ResourceTypeManagementPreference: Optional[ResourceTypeManagementPreference]


class DescribeReportJobInput(ServiceRequest):
    ReportJobId: ReportJobId


class ReportDestination(TypedDict, total=False):
    S3BucketName: Optional[string]
    S3Keys: Optional[stringList]


class ReportJob(TypedDict, total=False):
    ReportJobId: Optional[ReportJobId]
    ReportPlanArn: Optional[ARN]
    ReportTemplate: Optional[string]
    CreationTime: Optional[timestamp]
    CompletionTime: Optional[timestamp]
    Status: Optional[string]
    StatusMessage: Optional[string]
    ReportDestination: Optional[ReportDestination]


class DescribeReportJobOutput(TypedDict, total=False):
    ReportJob: Optional[ReportJob]


class DescribeReportPlanInput(ServiceRequest):
    ReportPlanName: ReportPlanName


class ReportPlan(TypedDict, total=False):
    ReportPlanArn: Optional[ARN]
    ReportPlanName: Optional[ReportPlanName]
    ReportPlanDescription: Optional[ReportPlanDescription]
    ReportSetting: Optional[ReportSetting]
    ReportDeliveryChannel: Optional[ReportDeliveryChannel]
    DeploymentStatus: Optional[string]
    CreationTime: Optional[timestamp]
    LastAttemptedExecutionTime: Optional[timestamp]
    LastSuccessfulExecutionTime: Optional[timestamp]


class DescribeReportPlanOutput(TypedDict, total=False):
    ReportPlan: Optional[ReportPlan]


class DescribeRestoreJobInput(ServiceRequest):
    RestoreJobId: RestoreJobId


class DescribeRestoreJobOutput(TypedDict, total=False):
    AccountId: Optional[AccountId]
    RestoreJobId: Optional[string]
    RecoveryPointArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    Status: Optional[RestoreJobStatus]
    StatusMessage: Optional[string]
    PercentDone: Optional[string]
    BackupSizeInBytes: Optional[Long]
    IamRoleArn: Optional[IAMRoleArn]
    ExpectedCompletionTimeMinutes: Optional[Long]
    CreatedResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]


class DisassociateRecoveryPointInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    RecoveryPointArn: ARN


class ExportBackupPlanTemplateInput(ServiceRequest):
    BackupPlanId: string


class ExportBackupPlanTemplateOutput(TypedDict, total=False):
    BackupPlanTemplateJson: Optional[string]


class Framework(TypedDict, total=False):
    FrameworkName: Optional[FrameworkName]
    FrameworkArn: Optional[ARN]
    FrameworkDescription: Optional[FrameworkDescription]
    NumberOfControls: Optional[integer]
    CreationTime: Optional[timestamp]
    DeploymentStatus: Optional[string]


FrameworkList = List[Framework]


class GetBackupPlanFromJSONInput(ServiceRequest):
    BackupPlanTemplateJson: string


class GetBackupPlanFromJSONOutput(TypedDict, total=False):
    BackupPlan: Optional[BackupPlan]


class GetBackupPlanFromTemplateInput(ServiceRequest):
    BackupPlanTemplateId: string


class GetBackupPlanFromTemplateOutput(TypedDict, total=False):
    BackupPlanDocument: Optional[BackupPlan]


class GetBackupPlanInput(ServiceRequest):
    BackupPlanId: string
    VersionId: Optional[string]


class GetBackupPlanOutput(TypedDict, total=False):
    BackupPlan: Optional[BackupPlan]
    BackupPlanId: Optional[string]
    BackupPlanArn: Optional[ARN]
    VersionId: Optional[string]
    CreatorRequestId: Optional[string]
    CreationDate: Optional[timestamp]
    DeletionDate: Optional[timestamp]
    LastExecutionDate: Optional[timestamp]
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


class GetBackupSelectionInput(ServiceRequest):
    BackupPlanId: string
    SelectionId: string


class GetBackupSelectionOutput(TypedDict, total=False):
    BackupSelection: Optional[BackupSelection]
    SelectionId: Optional[string]
    BackupPlanId: Optional[string]
    CreationDate: Optional[timestamp]
    CreatorRequestId: Optional[string]


class GetBackupVaultAccessPolicyInput(ServiceRequest):
    BackupVaultName: BackupVaultName


class GetBackupVaultAccessPolicyOutput(TypedDict, total=False):
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    Policy: Optional[IAMPolicy]


class GetBackupVaultNotificationsInput(ServiceRequest):
    BackupVaultName: BackupVaultName


class GetBackupVaultNotificationsOutput(TypedDict, total=False):
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    SNSTopicArn: Optional[ARN]
    BackupVaultEvents: Optional[BackupVaultEvents]


class GetRecoveryPointRestoreMetadataInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    RecoveryPointArn: ARN


Metadata = Dict[MetadataKey, MetadataValue]


class GetRecoveryPointRestoreMetadataOutput(TypedDict, total=False):
    BackupVaultArn: Optional[ARN]
    RecoveryPointArn: Optional[ARN]
    RestoreMetadata: Optional[Metadata]


ResourceTypes = List[ResourceType]


class GetSupportedResourceTypesOutput(TypedDict, total=False):
    ResourceTypes: Optional[ResourceTypes]


class ListBackupJobsInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]
    ByResourceArn: Optional[ARN]
    ByState: Optional[BackupJobState]
    ByBackupVaultName: Optional[BackupVaultName]
    ByCreatedBefore: Optional[timestamp]
    ByCreatedAfter: Optional[timestamp]
    ByResourceType: Optional[ResourceType]
    ByAccountId: Optional[AccountId]


class ListBackupJobsOutput(TypedDict, total=False):
    BackupJobs: Optional[BackupJobsList]
    NextToken: Optional[string]


class ListBackupPlanTemplatesInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ListBackupPlanTemplatesOutput(TypedDict, total=False):
    NextToken: Optional[string]
    BackupPlanTemplatesList: Optional[BackupPlanTemplatesList]


class ListBackupPlanVersionsInput(ServiceRequest):
    BackupPlanId: string
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ListBackupPlanVersionsOutput(TypedDict, total=False):
    NextToken: Optional[string]
    BackupPlanVersionsList: Optional[BackupPlanVersionsList]


class ListBackupPlansInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]
    IncludeDeleted: Optional[Boolean]


class ListBackupPlansOutput(TypedDict, total=False):
    NextToken: Optional[string]
    BackupPlansList: Optional[BackupPlansList]


class ListBackupSelectionsInput(ServiceRequest):
    BackupPlanId: string
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ListBackupSelectionsOutput(TypedDict, total=False):
    NextToken: Optional[string]
    BackupSelectionsList: Optional[BackupSelectionsList]


class ListBackupVaultsInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ListBackupVaultsOutput(TypedDict, total=False):
    BackupVaultList: Optional[BackupVaultList]
    NextToken: Optional[string]


class ListCopyJobsInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]
    ByResourceArn: Optional[ARN]
    ByState: Optional[CopyJobState]
    ByCreatedBefore: Optional[timestamp]
    ByCreatedAfter: Optional[timestamp]
    ByResourceType: Optional[ResourceType]
    ByDestinationVaultArn: Optional[string]
    ByAccountId: Optional[AccountId]


class ListCopyJobsOutput(TypedDict, total=False):
    CopyJobs: Optional[CopyJobsList]
    NextToken: Optional[string]


class ListFrameworksInput(ServiceRequest):
    MaxResults: Optional[MaxFrameworkInputs]
    NextToken: Optional[string]


class ListFrameworksOutput(TypedDict, total=False):
    Frameworks: Optional[FrameworkList]
    NextToken: Optional[string]


class ListProtectedResourcesInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ProtectedResource(TypedDict, total=False):
    ResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]
    LastBackupTime: Optional[timestamp]


ProtectedResourcesList = List[ProtectedResource]


class ListProtectedResourcesOutput(TypedDict, total=False):
    Results: Optional[ProtectedResourcesList]
    NextToken: Optional[string]


class ListRecoveryPointsByBackupVaultInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]
    ByResourceArn: Optional[ARN]
    ByResourceType: Optional[ResourceType]
    ByBackupPlanId: Optional[string]
    ByCreatedBefore: Optional[timestamp]
    ByCreatedAfter: Optional[timestamp]


class RecoveryPointByBackupVault(TypedDict, total=False):
    RecoveryPointArn: Optional[ARN]
    BackupVaultName: Optional[BackupVaultName]
    BackupVaultArn: Optional[ARN]
    SourceBackupVaultArn: Optional[ARN]
    ResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]
    CreatedBy: Optional[RecoveryPointCreator]
    IamRoleArn: Optional[IAMRoleArn]
    Status: Optional[RecoveryPointStatus]
    StatusMessage: Optional[string]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    BackupSizeInBytes: Optional[Long]
    CalculatedLifecycle: Optional[CalculatedLifecycle]
    Lifecycle: Optional[Lifecycle]
    EncryptionKeyArn: Optional[ARN]
    IsEncrypted: Optional[boolean]
    LastRestoreTime: Optional[timestamp]


RecoveryPointByBackupVaultList = List[RecoveryPointByBackupVault]


class ListRecoveryPointsByBackupVaultOutput(TypedDict, total=False):
    NextToken: Optional[string]
    RecoveryPoints: Optional[RecoveryPointByBackupVaultList]


class ListRecoveryPointsByResourceInput(ServiceRequest):
    ResourceArn: ARN
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class RecoveryPointByResource(TypedDict, total=False):
    RecoveryPointArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    Status: Optional[RecoveryPointStatus]
    StatusMessage: Optional[string]
    EncryptionKeyArn: Optional[ARN]
    BackupSizeBytes: Optional[Long]
    BackupVaultName: Optional[BackupVaultName]


RecoveryPointByResourceList = List[RecoveryPointByResource]


class ListRecoveryPointsByResourceOutput(TypedDict, total=False):
    NextToken: Optional[string]
    RecoveryPoints: Optional[RecoveryPointByResourceList]


class ListReportJobsInput(ServiceRequest):
    ByReportPlanName: Optional[ReportPlanName]
    ByCreationBefore: Optional[timestamp]
    ByCreationAfter: Optional[timestamp]
    ByStatus: Optional[string]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[string]


ReportJobList = List[ReportJob]


class ListReportJobsOutput(TypedDict, total=False):
    ReportJobs: Optional[ReportJobList]
    NextToken: Optional[string]


class ListReportPlansInput(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[string]


ReportPlanList = List[ReportPlan]


class ListReportPlansOutput(TypedDict, total=False):
    ReportPlans: Optional[ReportPlanList]
    NextToken: Optional[string]


class ListRestoreJobsInput(ServiceRequest):
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]
    ByAccountId: Optional[AccountId]
    ByCreatedBefore: Optional[timestamp]
    ByCreatedAfter: Optional[timestamp]
    ByStatus: Optional[RestoreJobStatus]


class RestoreJobsListMember(TypedDict, total=False):
    AccountId: Optional[AccountId]
    RestoreJobId: Optional[string]
    RecoveryPointArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    CompletionDate: Optional[timestamp]
    Status: Optional[RestoreJobStatus]
    StatusMessage: Optional[string]
    PercentDone: Optional[string]
    BackupSizeInBytes: Optional[Long]
    IamRoleArn: Optional[IAMRoleArn]
    ExpectedCompletionTimeMinutes: Optional[Long]
    CreatedResourceArn: Optional[ARN]
    ResourceType: Optional[ResourceType]


RestoreJobsList = List[RestoreJobsListMember]


class ListRestoreJobsOutput(TypedDict, total=False):
    RestoreJobs: Optional[RestoreJobsList]
    NextToken: Optional[string]


class ListTagsInput(ServiceRequest):
    ResourceArn: ARN
    NextToken: Optional[string]
    MaxResults: Optional[MaxResults]


class ListTagsOutput(TypedDict, total=False):
    NextToken: Optional[string]
    Tags: Optional[Tags]


class PutBackupVaultAccessPolicyInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    Policy: Optional[IAMPolicy]


class PutBackupVaultLockConfigurationInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    MinRetentionDays: Optional[Long]
    MaxRetentionDays: Optional[Long]
    ChangeableForDays: Optional[Long]


class PutBackupVaultNotificationsInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    SNSTopicArn: ARN
    BackupVaultEvents: BackupVaultEvents


class StartBackupJobInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    ResourceArn: ARN
    IamRoleArn: IAMRoleArn
    IdempotencyToken: Optional[string]
    StartWindowMinutes: Optional[WindowMinutes]
    CompleteWindowMinutes: Optional[WindowMinutes]
    Lifecycle: Optional[Lifecycle]
    RecoveryPointTags: Optional[Tags]
    BackupOptions: Optional[BackupOptions]


class StartBackupJobOutput(TypedDict, total=False):
    BackupJobId: Optional[string]
    RecoveryPointArn: Optional[ARN]
    CreationDate: Optional[timestamp]


class StartCopyJobInput(ServiceRequest):
    RecoveryPointArn: ARN
    SourceBackupVaultName: BackupVaultName
    DestinationBackupVaultArn: ARN
    IamRoleArn: IAMRoleArn
    IdempotencyToken: Optional[string]
    Lifecycle: Optional[Lifecycle]


class StartCopyJobOutput(TypedDict, total=False):
    CopyJobId: Optional[string]
    CreationDate: Optional[timestamp]


class StartReportJobInput(ServiceRequest):
    ReportPlanName: ReportPlanName
    IdempotencyToken: Optional[string]


class StartReportJobOutput(TypedDict, total=False):
    ReportJobId: Optional[ReportJobId]


class StartRestoreJobInput(ServiceRequest):
    RecoveryPointArn: ARN
    Metadata: Metadata
    IamRoleArn: IAMRoleArn
    IdempotencyToken: Optional[string]
    ResourceType: Optional[ResourceType]


class StartRestoreJobOutput(TypedDict, total=False):
    RestoreJobId: Optional[RestoreJobId]


class StopBackupJobInput(ServiceRequest):
    BackupJobId: string


TagKeyList = List[string]


class TagResourceInput(ServiceRequest):
    ResourceArn: ARN
    Tags: Tags


class UntagResourceInput(ServiceRequest):
    ResourceArn: ARN
    TagKeyList: TagKeyList


class UpdateBackupPlanInput(ServiceRequest):
    BackupPlanId: string
    BackupPlan: BackupPlanInput


class UpdateBackupPlanOutput(TypedDict, total=False):
    BackupPlanId: Optional[string]
    BackupPlanArn: Optional[ARN]
    CreationDate: Optional[timestamp]
    VersionId: Optional[string]
    AdvancedBackupSettings: Optional[AdvancedBackupSettings]


class UpdateFrameworkInput(ServiceRequest):
    FrameworkName: FrameworkName
    FrameworkDescription: Optional[FrameworkDescription]
    FrameworkControls: Optional[FrameworkControls]
    IdempotencyToken: Optional[string]


class UpdateFrameworkOutput(TypedDict, total=False):
    FrameworkName: Optional[FrameworkName]
    FrameworkArn: Optional[ARN]
    CreationTime: Optional[timestamp]


class UpdateGlobalSettingsInput(ServiceRequest):
    GlobalSettings: Optional[GlobalSettings]


class UpdateRecoveryPointLifecycleInput(ServiceRequest):
    BackupVaultName: BackupVaultName
    RecoveryPointArn: ARN
    Lifecycle: Optional[Lifecycle]


class UpdateRecoveryPointLifecycleOutput(TypedDict, total=False):
    BackupVaultArn: Optional[ARN]
    RecoveryPointArn: Optional[ARN]
    Lifecycle: Optional[Lifecycle]
    CalculatedLifecycle: Optional[CalculatedLifecycle]


class UpdateRegionSettingsInput(ServiceRequest):
    ResourceTypeOptInPreference: Optional[ResourceTypeOptInPreference]
    ResourceTypeManagementPreference: Optional[ResourceTypeManagementPreference]


class UpdateReportPlanInput(ServiceRequest):
    ReportPlanName: ReportPlanName
    ReportPlanDescription: Optional[ReportPlanDescription]
    ReportDeliveryChannel: Optional[ReportDeliveryChannel]
    ReportSetting: Optional[ReportSetting]
    IdempotencyToken: Optional[string]


class UpdateReportPlanOutput(TypedDict, total=False):
    ReportPlanName: Optional[ReportPlanName]
    ReportPlanArn: Optional[ARN]
    CreationTime: Optional[timestamp]


class BackupApi:

    service = "backup"
    version = "2018-11-15"

    @handler("CreateBackupPlan")
    def create_backup_plan(
        self,
        context: RequestContext,
        backup_plan: BackupPlanInput,
        backup_plan_tags: Tags = None,
        creator_request_id: string = None,
    ) -> CreateBackupPlanOutput:
        raise NotImplementedError

    @handler("CreateBackupSelection")
    def create_backup_selection(
        self,
        context: RequestContext,
        backup_plan_id: string,
        backup_selection: BackupSelection,
        creator_request_id: string = None,
    ) -> CreateBackupSelectionOutput:
        raise NotImplementedError

    @handler("CreateBackupVault")
    def create_backup_vault(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        backup_vault_tags: Tags = None,
        encryption_key_arn: ARN = None,
        creator_request_id: string = None,
    ) -> CreateBackupVaultOutput:
        raise NotImplementedError

    @handler("CreateFramework")
    def create_framework(
        self,
        context: RequestContext,
        framework_name: FrameworkName,
        framework_controls: FrameworkControls,
        framework_description: FrameworkDescription = None,
        idempotency_token: string = None,
        framework_tags: stringMap = None,
    ) -> CreateFrameworkOutput:
        raise NotImplementedError

    @handler("CreateReportPlan")
    def create_report_plan(
        self,
        context: RequestContext,
        report_plan_name: ReportPlanName,
        report_delivery_channel: ReportDeliveryChannel,
        report_setting: ReportSetting,
        report_plan_description: ReportPlanDescription = None,
        report_plan_tags: stringMap = None,
        idempotency_token: string = None,
    ) -> CreateReportPlanOutput:
        raise NotImplementedError

    @handler("DeleteBackupPlan")
    def delete_backup_plan(
        self, context: RequestContext, backup_plan_id: string
    ) -> DeleteBackupPlanOutput:
        raise NotImplementedError

    @handler("DeleteBackupSelection")
    def delete_backup_selection(
        self, context: RequestContext, backup_plan_id: string, selection_id: string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBackupVault")
    def delete_backup_vault(self, context: RequestContext, backup_vault_name: string) -> None:
        raise NotImplementedError

    @handler("DeleteBackupVaultAccessPolicy")
    def delete_backup_vault_access_policy(
        self, context: RequestContext, backup_vault_name: BackupVaultName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBackupVaultLockConfiguration")
    def delete_backup_vault_lock_configuration(
        self, context: RequestContext, backup_vault_name: BackupVaultName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBackupVaultNotifications")
    def delete_backup_vault_notifications(
        self, context: RequestContext, backup_vault_name: BackupVaultName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFramework")
    def delete_framework(self, context: RequestContext, framework_name: FrameworkName) -> None:
        raise NotImplementedError

    @handler("DeleteRecoveryPoint")
    def delete_recovery_point(
        self, context: RequestContext, backup_vault_name: BackupVaultName, recovery_point_arn: ARN
    ) -> None:
        raise NotImplementedError

    @handler("DeleteReportPlan")
    def delete_report_plan(self, context: RequestContext, report_plan_name: ReportPlanName) -> None:
        raise NotImplementedError

    @handler("DescribeBackupJob")
    def describe_backup_job(
        self, context: RequestContext, backup_job_id: string
    ) -> DescribeBackupJobOutput:
        raise NotImplementedError

    @handler("DescribeBackupVault")
    def describe_backup_vault(
        self, context: RequestContext, backup_vault_name: string
    ) -> DescribeBackupVaultOutput:
        raise NotImplementedError

    @handler("DescribeCopyJob")
    def describe_copy_job(
        self, context: RequestContext, copy_job_id: string
    ) -> DescribeCopyJobOutput:
        raise NotImplementedError

    @handler("DescribeFramework")
    def describe_framework(
        self, context: RequestContext, framework_name: FrameworkName
    ) -> DescribeFrameworkOutput:
        raise NotImplementedError

    @handler("DescribeGlobalSettings")
    def describe_global_settings(
        self,
        context: RequestContext,
    ) -> DescribeGlobalSettingsOutput:
        raise NotImplementedError

    @handler("DescribeProtectedResource")
    def describe_protected_resource(
        self, context: RequestContext, resource_arn: ARN
    ) -> DescribeProtectedResourceOutput:
        raise NotImplementedError

    @handler("DescribeRecoveryPoint")
    def describe_recovery_point(
        self, context: RequestContext, backup_vault_name: BackupVaultName, recovery_point_arn: ARN
    ) -> DescribeRecoveryPointOutput:
        raise NotImplementedError

    @handler("DescribeRegionSettings")
    def describe_region_settings(
        self,
        context: RequestContext,
    ) -> DescribeRegionSettingsOutput:
        raise NotImplementedError

    @handler("DescribeReportJob")
    def describe_report_job(
        self, context: RequestContext, report_job_id: ReportJobId
    ) -> DescribeReportJobOutput:
        raise NotImplementedError

    @handler("DescribeReportPlan")
    def describe_report_plan(
        self, context: RequestContext, report_plan_name: ReportPlanName
    ) -> DescribeReportPlanOutput:
        raise NotImplementedError

    @handler("DescribeRestoreJob")
    def describe_restore_job(
        self, context: RequestContext, restore_job_id: RestoreJobId
    ) -> DescribeRestoreJobOutput:
        raise NotImplementedError

    @handler("DisassociateRecoveryPoint")
    def disassociate_recovery_point(
        self, context: RequestContext, backup_vault_name: BackupVaultName, recovery_point_arn: ARN
    ) -> None:
        raise NotImplementedError

    @handler("ExportBackupPlanTemplate")
    def export_backup_plan_template(
        self, context: RequestContext, backup_plan_id: string
    ) -> ExportBackupPlanTemplateOutput:
        raise NotImplementedError

    @handler("GetBackupPlan")
    def get_backup_plan(
        self, context: RequestContext, backup_plan_id: string, version_id: string = None
    ) -> GetBackupPlanOutput:
        raise NotImplementedError

    @handler("GetBackupPlanFromJSON")
    def get_backup_plan_from_json(
        self, context: RequestContext, backup_plan_template_json: string
    ) -> GetBackupPlanFromJSONOutput:
        raise NotImplementedError

    @handler("GetBackupPlanFromTemplate")
    def get_backup_plan_from_template(
        self, context: RequestContext, backup_plan_template_id: string
    ) -> GetBackupPlanFromTemplateOutput:
        raise NotImplementedError

    @handler("GetBackupSelection")
    def get_backup_selection(
        self, context: RequestContext, backup_plan_id: string, selection_id: string
    ) -> GetBackupSelectionOutput:
        raise NotImplementedError

    @handler("GetBackupVaultAccessPolicy")
    def get_backup_vault_access_policy(
        self, context: RequestContext, backup_vault_name: BackupVaultName
    ) -> GetBackupVaultAccessPolicyOutput:
        raise NotImplementedError

    @handler("GetBackupVaultNotifications")
    def get_backup_vault_notifications(
        self, context: RequestContext, backup_vault_name: BackupVaultName
    ) -> GetBackupVaultNotificationsOutput:
        raise NotImplementedError

    @handler("GetRecoveryPointRestoreMetadata")
    def get_recovery_point_restore_metadata(
        self, context: RequestContext, backup_vault_name: BackupVaultName, recovery_point_arn: ARN
    ) -> GetRecoveryPointRestoreMetadataOutput:
        raise NotImplementedError

    @handler("GetSupportedResourceTypes")
    def get_supported_resource_types(
        self,
        context: RequestContext,
    ) -> GetSupportedResourceTypesOutput:
        raise NotImplementedError

    @handler("ListBackupJobs")
    def list_backup_jobs(
        self,
        context: RequestContext,
        next_token: string = None,
        max_results: MaxResults = None,
        by_resource_arn: ARN = None,
        by_state: BackupJobState = None,
        by_backup_vault_name: BackupVaultName = None,
        by_created_before: timestamp = None,
        by_created_after: timestamp = None,
        by_resource_type: ResourceType = None,
        by_account_id: AccountId = None,
    ) -> ListBackupJobsOutput:
        raise NotImplementedError

    @handler("ListBackupPlanTemplates")
    def list_backup_plan_templates(
        self, context: RequestContext, next_token: string = None, max_results: MaxResults = None
    ) -> ListBackupPlanTemplatesOutput:
        raise NotImplementedError

    @handler("ListBackupPlanVersions")
    def list_backup_plan_versions(
        self,
        context: RequestContext,
        backup_plan_id: string,
        next_token: string = None,
        max_results: MaxResults = None,
    ) -> ListBackupPlanVersionsOutput:
        raise NotImplementedError

    @handler("ListBackupPlans")
    def list_backup_plans(
        self,
        context: RequestContext,
        next_token: string = None,
        max_results: MaxResults = None,
        include_deleted: Boolean = None,
    ) -> ListBackupPlansOutput:
        raise NotImplementedError

    @handler("ListBackupSelections")
    def list_backup_selections(
        self,
        context: RequestContext,
        backup_plan_id: string,
        next_token: string = None,
        max_results: MaxResults = None,
    ) -> ListBackupSelectionsOutput:
        raise NotImplementedError

    @handler("ListBackupVaults")
    def list_backup_vaults(
        self, context: RequestContext, next_token: string = None, max_results: MaxResults = None
    ) -> ListBackupVaultsOutput:
        raise NotImplementedError

    @handler("ListCopyJobs")
    def list_copy_jobs(
        self,
        context: RequestContext,
        next_token: string = None,
        max_results: MaxResults = None,
        by_resource_arn: ARN = None,
        by_state: CopyJobState = None,
        by_created_before: timestamp = None,
        by_created_after: timestamp = None,
        by_resource_type: ResourceType = None,
        by_destination_vault_arn: string = None,
        by_account_id: AccountId = None,
    ) -> ListCopyJobsOutput:
        raise NotImplementedError

    @handler("ListFrameworks")
    def list_frameworks(
        self,
        context: RequestContext,
        max_results: MaxFrameworkInputs = None,
        next_token: string = None,
    ) -> ListFrameworksOutput:
        raise NotImplementedError

    @handler("ListProtectedResources")
    def list_protected_resources(
        self, context: RequestContext, next_token: string = None, max_results: MaxResults = None
    ) -> ListProtectedResourcesOutput:
        raise NotImplementedError

    @handler("ListRecoveryPointsByBackupVault")
    def list_recovery_points_by_backup_vault(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        next_token: string = None,
        max_results: MaxResults = None,
        by_resource_arn: ARN = None,
        by_resource_type: ResourceType = None,
        by_backup_plan_id: string = None,
        by_created_before: timestamp = None,
        by_created_after: timestamp = None,
    ) -> ListRecoveryPointsByBackupVaultOutput:
        raise NotImplementedError

    @handler("ListRecoveryPointsByResource")
    def list_recovery_points_by_resource(
        self,
        context: RequestContext,
        resource_arn: ARN,
        next_token: string = None,
        max_results: MaxResults = None,
    ) -> ListRecoveryPointsByResourceOutput:
        raise NotImplementedError

    @handler("ListReportJobs")
    def list_report_jobs(
        self,
        context: RequestContext,
        by_report_plan_name: ReportPlanName = None,
        by_creation_before: timestamp = None,
        by_creation_after: timestamp = None,
        by_status: string = None,
        max_results: MaxResults = None,
        next_token: string = None,
    ) -> ListReportJobsOutput:
        raise NotImplementedError

    @handler("ListReportPlans")
    def list_report_plans(
        self, context: RequestContext, max_results: MaxResults = None, next_token: string = None
    ) -> ListReportPlansOutput:
        raise NotImplementedError

    @handler("ListRestoreJobs")
    def list_restore_jobs(
        self,
        context: RequestContext,
        next_token: string = None,
        max_results: MaxResults = None,
        by_account_id: AccountId = None,
        by_created_before: timestamp = None,
        by_created_after: timestamp = None,
        by_status: RestoreJobStatus = None,
    ) -> ListRestoreJobsOutput:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(
        self,
        context: RequestContext,
        resource_arn: ARN,
        next_token: string = None,
        max_results: MaxResults = None,
    ) -> ListTagsOutput:
        raise NotImplementedError

    @handler("PutBackupVaultAccessPolicy")
    def put_backup_vault_access_policy(
        self, context: RequestContext, backup_vault_name: BackupVaultName, policy: IAMPolicy = None
    ) -> None:
        raise NotImplementedError

    @handler("PutBackupVaultLockConfiguration")
    def put_backup_vault_lock_configuration(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        min_retention_days: Long = None,
        max_retention_days: Long = None,
        changeable_for_days: Long = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutBackupVaultNotifications")
    def put_backup_vault_notifications(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        sns_topic_arn: ARN,
        backup_vault_events: BackupVaultEvents,
    ) -> None:
        raise NotImplementedError

    @handler("StartBackupJob")
    def start_backup_job(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        resource_arn: ARN,
        iam_role_arn: IAMRoleArn,
        idempotency_token: string = None,
        start_window_minutes: WindowMinutes = None,
        complete_window_minutes: WindowMinutes = None,
        lifecycle: Lifecycle = None,
        recovery_point_tags: Tags = None,
        backup_options: BackupOptions = None,
    ) -> StartBackupJobOutput:
        raise NotImplementedError

    @handler("StartCopyJob")
    def start_copy_job(
        self,
        context: RequestContext,
        recovery_point_arn: ARN,
        source_backup_vault_name: BackupVaultName,
        destination_backup_vault_arn: ARN,
        iam_role_arn: IAMRoleArn,
        idempotency_token: string = None,
        lifecycle: Lifecycle = None,
    ) -> StartCopyJobOutput:
        raise NotImplementedError

    @handler("StartReportJob")
    def start_report_job(
        self,
        context: RequestContext,
        report_plan_name: ReportPlanName,
        idempotency_token: string = None,
    ) -> StartReportJobOutput:
        raise NotImplementedError

    @handler("StartRestoreJob")
    def start_restore_job(
        self,
        context: RequestContext,
        recovery_point_arn: ARN,
        metadata: Metadata,
        iam_role_arn: IAMRoleArn,
        idempotency_token: string = None,
        resource_type: ResourceType = None,
    ) -> StartRestoreJobOutput:
        raise NotImplementedError

    @handler("StopBackupJob")
    def stop_backup_job(self, context: RequestContext, backup_job_id: string) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource_arn: ARN, tags: Tags) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ARN, tag_key_list: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("UpdateBackupPlan")
    def update_backup_plan(
        self, context: RequestContext, backup_plan_id: string, backup_plan: BackupPlanInput
    ) -> UpdateBackupPlanOutput:
        raise NotImplementedError

    @handler("UpdateFramework")
    def update_framework(
        self,
        context: RequestContext,
        framework_name: FrameworkName,
        framework_description: FrameworkDescription = None,
        framework_controls: FrameworkControls = None,
        idempotency_token: string = None,
    ) -> UpdateFrameworkOutput:
        raise NotImplementedError

    @handler("UpdateGlobalSettings")
    def update_global_settings(
        self, context: RequestContext, global_settings: GlobalSettings = None
    ) -> None:
        raise NotImplementedError

    @handler("UpdateRecoveryPointLifecycle")
    def update_recovery_point_lifecycle(
        self,
        context: RequestContext,
        backup_vault_name: BackupVaultName,
        recovery_point_arn: ARN,
        lifecycle: Lifecycle = None,
    ) -> UpdateRecoveryPointLifecycleOutput:
        raise NotImplementedError

    @handler("UpdateRegionSettings")
    def update_region_settings(
        self,
        context: RequestContext,
        resource_type_opt_in_preference: ResourceTypeOptInPreference = None,
        resource_type_management_preference: ResourceTypeManagementPreference = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateReportPlan")
    def update_report_plan(
        self,
        context: RequestContext,
        report_plan_name: ReportPlanName,
        report_plan_description: ReportPlanDescription = None,
        report_delivery_channel: ReportDeliveryChannel = None,
        report_setting: ReportSetting = None,
        idempotency_token: string = None,
    ) -> UpdateReportPlanOutput:
        raise NotImplementedError
