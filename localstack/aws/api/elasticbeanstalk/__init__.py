import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
AbortableOperationInProgress = bool
ApplicationArn = str
ApplicationName = str
ApplicationVersionArn = str
ApplicationVersionProccess = bool
AutoCreateApplication = bool
BoxedBoolean = bool
BoxedInt = int
BranchName = str
BranchOrder = int
Cause = str
CnameAvailability = bool
ConfigurationOptionDefaultValue = str
ConfigurationOptionName = str
ConfigurationOptionPossibleValue = str
ConfigurationOptionSeverity = str
ConfigurationOptionValue = str
ConfigurationTemplateName = str
DNSCname = str
DNSCnamePrefix = str
DeleteSourceBundle = bool
Description = str
Ec2InstanceId = str
EndpointURL = str
EnvironmentArn = str
EnvironmentId = str
EnvironmentName = str
EventMessage = str
ExceptionMessage = str
FileTypeExtension = str
ForceTerminate = bool
GroupName = str
ImageId = str
IncludeDeleted = bool
InstanceId = str
Integer = int
LoadAverageValue = float
Maintainer = str
ManagedActionHistoryMaxItems = int
MaxRecords = int
Message = str
NextToken = str
NonEmptyString = str
NullableDouble = float
NullableInteger = int
OperatingSystemName = str
OperatingSystemVersion = str
OperationsRole = str
OptionNamespace = str
OptionRestrictionMaxLength = int
OptionRestrictionMaxValue = int
OptionRestrictionMinValue = int
PlatformArn = str
PlatformBranchLifecycleState = str
PlatformBranchMaxRecords = int
PlatformCategory = str
PlatformFilterOperator = str
PlatformFilterType = str
PlatformFilterValue = str
PlatformLifecycleState = str
PlatformMaxRecords = int
PlatformName = str
PlatformOwner = str
PlatformVersion = str
RegexLabel = str
RegexPattern = str
RequestCount = int
RequestId = str
ResourceArn = str
ResourceId = str
ResourceName = str
S3Bucket = str
S3Key = str
SearchFilterAttribute = str
SearchFilterOperator = str
SearchFilterValue = str
SolutionStackName = str
SourceLocation = str
String = str
SupportedAddon = str
SupportedTier = str
TagKey = str
TagValue = str
TerminateEnvForce = bool
TerminateEnvironmentResources = bool
Token = str
UserDefinedOption = bool
ValidationMessageString = str
VersionLabel = str
VirtualizationType = str


class ActionHistoryStatus(str):
    Completed = "Completed"
    Failed = "Failed"
    Unknown = "Unknown"


class ActionStatus(str):
    Scheduled = "Scheduled"
    Pending = "Pending"
    Running = "Running"
    Unknown = "Unknown"


class ActionType(str):
    InstanceRefresh = "InstanceRefresh"
    PlatformUpdate = "PlatformUpdate"
    Unknown = "Unknown"


class ApplicationVersionStatus(str):
    Processed = "Processed"
    Unprocessed = "Unprocessed"
    Failed = "Failed"
    Processing = "Processing"
    Building = "Building"


class ComputeType(str):
    BUILD_GENERAL1_SMALL = "BUILD_GENERAL1_SMALL"
    BUILD_GENERAL1_MEDIUM = "BUILD_GENERAL1_MEDIUM"
    BUILD_GENERAL1_LARGE = "BUILD_GENERAL1_LARGE"


class ConfigurationDeploymentStatus(str):
    deployed = "deployed"
    pending = "pending"
    failed = "failed"


class ConfigurationOptionValueType(str):
    Scalar = "Scalar"
    List = "List"


class EnvironmentHealth(str):
    Green = "Green"
    Yellow = "Yellow"
    Red = "Red"
    Grey = "Grey"


class EnvironmentHealthAttribute(str):
    Status = "Status"
    Color = "Color"
    Causes = "Causes"
    ApplicationMetrics = "ApplicationMetrics"
    InstancesHealth = "InstancesHealth"
    All = "All"
    HealthStatus = "HealthStatus"
    RefreshedAt = "RefreshedAt"


class EnvironmentHealthStatus(str):
    NoData = "NoData"
    Unknown = "Unknown"
    Pending = "Pending"
    Ok = "Ok"
    Info = "Info"
    Warning = "Warning"
    Degraded = "Degraded"
    Severe = "Severe"
    Suspended = "Suspended"


class EnvironmentInfoType(str):
    tail = "tail"
    bundle = "bundle"


class EnvironmentStatus(str):
    Aborting = "Aborting"
    Launching = "Launching"
    Updating = "Updating"
    LinkingFrom = "LinkingFrom"
    LinkingTo = "LinkingTo"
    Ready = "Ready"
    Terminating = "Terminating"
    Terminated = "Terminated"


class EventSeverity(str):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"


class FailureType(str):
    UpdateCancelled = "UpdateCancelled"
    CancellationFailed = "CancellationFailed"
    RollbackFailed = "RollbackFailed"
    RollbackSuccessful = "RollbackSuccessful"
    InternalFailure = "InternalFailure"
    InvalidEnvironmentState = "InvalidEnvironmentState"
    PermissionsError = "PermissionsError"


class InstancesHealthAttribute(str):
    HealthStatus = "HealthStatus"
    Color = "Color"
    Causes = "Causes"
    ApplicationMetrics = "ApplicationMetrics"
    RefreshedAt = "RefreshedAt"
    LaunchedAt = "LaunchedAt"
    System = "System"
    Deployment = "Deployment"
    AvailabilityZone = "AvailabilityZone"
    InstanceType = "InstanceType"
    All = "All"


class PlatformStatus(str):
    Creating = "Creating"
    Failed = "Failed"
    Ready = "Ready"
    Deleting = "Deleting"
    Deleted = "Deleted"


class SourceRepository(str):
    CodeCommit = "CodeCommit"
    S3 = "S3"


class SourceType(str):
    Git = "Git"
    Zip = "Zip"


class ValidationSeverity(str):
    error = "error"
    warning = "warning"


class CodeBuildNotInServiceRegionException(ServiceException):
    pass


class ElasticBeanstalkServiceException(ServiceException):
    message: Optional[ExceptionMessage]


class InsufficientPrivilegesException(ServiceException):
    pass


class InvalidRequestException(ServiceException):
    pass


class ManagedActionInvalidStateException(ServiceException):
    pass


class OperationInProgressException(ServiceException):
    pass


class PlatformVersionStillReferencedException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class ResourceTypeNotSupportedException(ServiceException):
    pass


class S3LocationNotInServiceRegionException(ServiceException):
    pass


class S3SubscriptionRequiredException(ServiceException):
    pass


class SourceBundleDeletionException(ServiceException):
    pass


class TooManyApplicationVersionsException(ServiceException):
    pass


class TooManyApplicationsException(ServiceException):
    pass


class TooManyBucketsException(ServiceException):
    pass


class TooManyConfigurationTemplatesException(ServiceException):
    pass


class TooManyEnvironmentsException(ServiceException):
    pass


class TooManyPlatformsException(ServiceException):
    pass


class TooManyTagsException(ServiceException):
    pass


class AbortEnvironmentUpdateMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]


class MaxAgeRule(TypedDict, total=False):
    Enabled: BoxedBoolean
    MaxAgeInDays: Optional[BoxedInt]
    DeleteSourceFromS3: Optional[BoxedBoolean]


class MaxCountRule(TypedDict, total=False):
    Enabled: BoxedBoolean
    MaxCount: Optional[BoxedInt]
    DeleteSourceFromS3: Optional[BoxedBoolean]


class ApplicationVersionLifecycleConfig(TypedDict, total=False):
    MaxCountRule: Optional[MaxCountRule]
    MaxAgeRule: Optional[MaxAgeRule]


class ApplicationResourceLifecycleConfig(TypedDict, total=False):
    ServiceRole: Optional[String]
    VersionLifecycleConfig: Optional[ApplicationVersionLifecycleConfig]


ConfigurationTemplateNamesList = List[ConfigurationTemplateName]
VersionLabelsList = List[VersionLabel]
UpdateDate = datetime
CreationDate = datetime


class ApplicationDescription(TypedDict, total=False):
    ApplicationArn: Optional[ApplicationArn]
    ApplicationName: Optional[ApplicationName]
    Description: Optional[Description]
    DateCreated: Optional[CreationDate]
    DateUpdated: Optional[UpdateDate]
    Versions: Optional[VersionLabelsList]
    ConfigurationTemplates: Optional[ConfigurationTemplateNamesList]
    ResourceLifecycleConfig: Optional[ApplicationResourceLifecycleConfig]


ApplicationDescriptionList = List[ApplicationDescription]


class ApplicationDescriptionMessage(TypedDict, total=False):
    Application: Optional[ApplicationDescription]


class ApplicationDescriptionsMessage(TypedDict, total=False):
    Applications: Optional[ApplicationDescriptionList]


class Latency(TypedDict, total=False):
    P999: Optional[NullableDouble]
    P99: Optional[NullableDouble]
    P95: Optional[NullableDouble]
    P90: Optional[NullableDouble]
    P85: Optional[NullableDouble]
    P75: Optional[NullableDouble]
    P50: Optional[NullableDouble]
    P10: Optional[NullableDouble]


class StatusCodes(TypedDict, total=False):
    Status2xx: Optional[NullableInteger]
    Status3xx: Optional[NullableInteger]
    Status4xx: Optional[NullableInteger]
    Status5xx: Optional[NullableInteger]


class ApplicationMetrics(TypedDict, total=False):
    Duration: Optional[NullableInteger]
    RequestCount: Optional[RequestCount]
    StatusCodes: Optional[StatusCodes]
    Latency: Optional[Latency]


ApplicationNamesList = List[ApplicationName]


class ApplicationResourceLifecycleDescriptionMessage(TypedDict, total=False):
    ApplicationName: Optional[ApplicationName]
    ResourceLifecycleConfig: Optional[ApplicationResourceLifecycleConfig]


class S3Location(TypedDict, total=False):
    S3Bucket: Optional[S3Bucket]
    S3Key: Optional[S3Key]


class SourceBuildInformation(TypedDict, total=False):
    SourceType: SourceType
    SourceRepository: SourceRepository
    SourceLocation: SourceLocation


class ApplicationVersionDescription(TypedDict, total=False):
    ApplicationVersionArn: Optional[ApplicationVersionArn]
    ApplicationName: Optional[ApplicationName]
    Description: Optional[Description]
    VersionLabel: Optional[VersionLabel]
    SourceBuildInformation: Optional[SourceBuildInformation]
    BuildArn: Optional[String]
    SourceBundle: Optional[S3Location]
    DateCreated: Optional[CreationDate]
    DateUpdated: Optional[UpdateDate]
    Status: Optional[ApplicationVersionStatus]


ApplicationVersionDescriptionList = List[ApplicationVersionDescription]


class ApplicationVersionDescriptionMessage(TypedDict, total=False):
    ApplicationVersion: Optional[ApplicationVersionDescription]


class ApplicationVersionDescriptionsMessage(TypedDict, total=False):
    ApplicationVersions: Optional[ApplicationVersionDescriptionList]
    NextToken: Optional[Token]


class ApplyEnvironmentManagedActionRequest(ServiceRequest):
    EnvironmentName: Optional[String]
    EnvironmentId: Optional[String]
    ActionId: String


class ApplyEnvironmentManagedActionResult(TypedDict, total=False):
    ActionId: Optional[String]
    ActionDescription: Optional[String]
    ActionType: Optional[ActionType]
    Status: Optional[String]


class AssociateEnvironmentOperationsRoleMessage(ServiceRequest):
    EnvironmentName: EnvironmentName
    OperationsRole: OperationsRole


class AutoScalingGroup(TypedDict, total=False):
    Name: Optional[ResourceId]


AutoScalingGroupList = List[AutoScalingGroup]
SolutionStackFileTypeList = List[FileTypeExtension]


class SolutionStackDescription(TypedDict, total=False):
    SolutionStackName: Optional[SolutionStackName]
    PermittedFileTypes: Optional[SolutionStackFileTypeList]


AvailableSolutionStackDetailsList = List[SolutionStackDescription]
AvailableSolutionStackNamesList = List[SolutionStackName]


class BuildConfiguration(TypedDict, total=False):
    ArtifactName: Optional[String]
    CodeBuildServiceRole: NonEmptyString
    ComputeType: Optional[ComputeType]
    Image: NonEmptyString
    TimeoutInMinutes: Optional[BoxedInt]


class Builder(TypedDict, total=False):
    ARN: Optional[ARN]


class CPUUtilization(TypedDict, total=False):
    User: Optional[NullableDouble]
    Nice: Optional[NullableDouble]
    System: Optional[NullableDouble]
    Idle: Optional[NullableDouble]
    IOWait: Optional[NullableDouble]
    IRQ: Optional[NullableDouble]
    SoftIRQ: Optional[NullableDouble]
    Privileged: Optional[NullableDouble]


Causes = List[Cause]


class CheckDNSAvailabilityMessage(ServiceRequest):
    CNAMEPrefix: DNSCnamePrefix


class CheckDNSAvailabilityResultMessage(TypedDict, total=False):
    Available: Optional[CnameAvailability]
    FullyQualifiedCNAME: Optional[DNSCname]


VersionLabels = List[VersionLabel]


class ComposeEnvironmentsMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    GroupName: Optional[GroupName]
    VersionLabels: Optional[VersionLabels]


class OptionRestrictionRegex(TypedDict, total=False):
    Pattern: Optional[RegexPattern]
    Label: Optional[RegexLabel]


ConfigurationOptionPossibleValues = List[ConfigurationOptionPossibleValue]


class ConfigurationOptionDescription(TypedDict, total=False):
    Namespace: Optional[OptionNamespace]
    Name: Optional[ConfigurationOptionName]
    DefaultValue: Optional[ConfigurationOptionDefaultValue]
    ChangeSeverity: Optional[ConfigurationOptionSeverity]
    UserDefined: Optional[UserDefinedOption]
    ValueType: Optional[ConfigurationOptionValueType]
    ValueOptions: Optional[ConfigurationOptionPossibleValues]
    MinValue: Optional[OptionRestrictionMinValue]
    MaxValue: Optional[OptionRestrictionMaxValue]
    MaxLength: Optional[OptionRestrictionMaxLength]
    Regex: Optional[OptionRestrictionRegex]


ConfigurationOptionDescriptionsList = List[ConfigurationOptionDescription]


class ConfigurationOptionSetting(TypedDict, total=False):
    ResourceName: Optional[ResourceName]
    Namespace: Optional[OptionNamespace]
    OptionName: Optional[ConfigurationOptionName]
    Value: Optional[ConfigurationOptionValue]


ConfigurationOptionSettingsList = List[ConfigurationOptionSetting]


class ConfigurationOptionsDescription(TypedDict, total=False):
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    Options: Optional[ConfigurationOptionDescriptionsList]


class ConfigurationSettingsDescription(TypedDict, total=False):
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    ApplicationName: Optional[ApplicationName]
    TemplateName: Optional[ConfigurationTemplateName]
    Description: Optional[Description]
    EnvironmentName: Optional[EnvironmentName]
    DeploymentStatus: Optional[ConfigurationDeploymentStatus]
    DateCreated: Optional[CreationDate]
    DateUpdated: Optional[UpdateDate]
    OptionSettings: Optional[ConfigurationOptionSettingsList]


ConfigurationSettingsDescriptionList = List[ConfigurationSettingsDescription]


class ConfigurationSettingsDescriptions(TypedDict, total=False):
    ConfigurationSettings: Optional[ConfigurationSettingsDescriptionList]


class ValidationMessage(TypedDict, total=False):
    Message: Optional[ValidationMessageString]
    Severity: Optional[ValidationSeverity]
    Namespace: Optional[OptionNamespace]
    OptionName: Optional[ConfigurationOptionName]


ValidationMessagesList = List[ValidationMessage]


class ConfigurationSettingsValidationMessages(TypedDict, total=False):
    Messages: Optional[ValidationMessagesList]


class Tag(TypedDict, total=False):
    Key: Optional[TagKey]
    Value: Optional[TagValue]


Tags = List[Tag]


class CreateApplicationMessage(ServiceRequest):
    ApplicationName: ApplicationName
    Description: Optional[Description]
    ResourceLifecycleConfig: Optional[ApplicationResourceLifecycleConfig]
    Tags: Optional[Tags]


class CreateApplicationVersionMessage(ServiceRequest):
    ApplicationName: ApplicationName
    VersionLabel: VersionLabel
    Description: Optional[Description]
    SourceBuildInformation: Optional[SourceBuildInformation]
    SourceBundle: Optional[S3Location]
    BuildConfiguration: Optional[BuildConfiguration]
    AutoCreateApplication: Optional[AutoCreateApplication]
    Process: Optional[ApplicationVersionProccess]
    Tags: Optional[Tags]


class SourceConfiguration(TypedDict, total=False):
    ApplicationName: Optional[ApplicationName]
    TemplateName: Optional[ConfigurationTemplateName]


class CreateConfigurationTemplateMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TemplateName: ConfigurationTemplateName
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    SourceConfiguration: Optional[SourceConfiguration]
    EnvironmentId: Optional[EnvironmentId]
    Description: Optional[Description]
    OptionSettings: Optional[ConfigurationOptionSettingsList]
    Tags: Optional[Tags]


class OptionSpecification(TypedDict, total=False):
    ResourceName: Optional[ResourceName]
    Namespace: Optional[OptionNamespace]
    OptionName: Optional[ConfigurationOptionName]


OptionsSpecifierList = List[OptionSpecification]


class EnvironmentTier(TypedDict, total=False):
    Name: Optional[String]
    Type: Optional[String]
    Version: Optional[String]


class CreateEnvironmentMessage(ServiceRequest):
    ApplicationName: ApplicationName
    EnvironmentName: Optional[EnvironmentName]
    GroupName: Optional[GroupName]
    Description: Optional[Description]
    CNAMEPrefix: Optional[DNSCnamePrefix]
    Tier: Optional[EnvironmentTier]
    Tags: Optional[Tags]
    VersionLabel: Optional[VersionLabel]
    TemplateName: Optional[ConfigurationTemplateName]
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    OptionSettings: Optional[ConfigurationOptionSettingsList]
    OptionsToRemove: Optional[OptionsSpecifierList]
    OperationsRole: Optional[OperationsRole]


class CreatePlatformVersionRequest(ServiceRequest):
    PlatformName: PlatformName
    PlatformVersion: PlatformVersion
    PlatformDefinitionBundle: S3Location
    EnvironmentName: Optional[EnvironmentName]
    OptionSettings: Optional[ConfigurationOptionSettingsList]
    Tags: Optional[Tags]


SupportedAddonList = List[SupportedAddon]
SupportedTierList = List[SupportedTier]


class PlatformSummary(TypedDict, total=False):
    PlatformArn: Optional[PlatformArn]
    PlatformOwner: Optional[PlatformOwner]
    PlatformStatus: Optional[PlatformStatus]
    PlatformCategory: Optional[PlatformCategory]
    OperatingSystemName: Optional[OperatingSystemName]
    OperatingSystemVersion: Optional[OperatingSystemVersion]
    SupportedTierList: Optional[SupportedTierList]
    SupportedAddonList: Optional[SupportedAddonList]
    PlatformLifecycleState: Optional[PlatformLifecycleState]
    PlatformVersion: Optional[PlatformVersion]
    PlatformBranchName: Optional[BranchName]
    PlatformBranchLifecycleState: Optional[PlatformBranchLifecycleState]


class CreatePlatformVersionResult(TypedDict, total=False):
    PlatformSummary: Optional[PlatformSummary]
    Builder: Optional[Builder]


class CreateStorageLocationResultMessage(TypedDict, total=False):
    S3Bucket: Optional[S3Bucket]


class CustomAmi(TypedDict, total=False):
    VirtualizationType: Optional[VirtualizationType]
    ImageId: Optional[ImageId]


CustomAmiList = List[CustomAmi]


class DeleteApplicationMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TerminateEnvByForce: Optional[TerminateEnvForce]


class DeleteApplicationVersionMessage(ServiceRequest):
    ApplicationName: ApplicationName
    VersionLabel: VersionLabel
    DeleteSourceBundle: Optional[DeleteSourceBundle]


class DeleteConfigurationTemplateMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TemplateName: ConfigurationTemplateName


class DeleteEnvironmentConfigurationMessage(ServiceRequest):
    ApplicationName: ApplicationName
    EnvironmentName: EnvironmentName


class DeletePlatformVersionRequest(ServiceRequest):
    PlatformArn: Optional[PlatformArn]


class DeletePlatformVersionResult(TypedDict, total=False):
    PlatformSummary: Optional[PlatformSummary]


DeploymentTimestamp = datetime
NullableLong = int


class Deployment(TypedDict, total=False):
    VersionLabel: Optional[String]
    DeploymentId: Optional[NullableLong]
    Status: Optional[String]
    DeploymentTime: Optional[DeploymentTimestamp]


class ResourceQuota(TypedDict, total=False):
    Maximum: Optional[BoxedInt]


class ResourceQuotas(TypedDict, total=False):
    ApplicationQuota: Optional[ResourceQuota]
    ApplicationVersionQuota: Optional[ResourceQuota]
    EnvironmentQuota: Optional[ResourceQuota]
    ConfigurationTemplateQuota: Optional[ResourceQuota]
    CustomPlatformQuota: Optional[ResourceQuota]


class DescribeAccountAttributesResult(TypedDict, total=False):
    ResourceQuotas: Optional[ResourceQuotas]


class DescribeApplicationVersionsMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    VersionLabels: Optional[VersionLabelsList]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[Token]


class DescribeApplicationsMessage(ServiceRequest):
    ApplicationNames: Optional[ApplicationNamesList]


class DescribeConfigurationOptionsMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    TemplateName: Optional[ConfigurationTemplateName]
    EnvironmentName: Optional[EnvironmentName]
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    Options: Optional[OptionsSpecifierList]


class DescribeConfigurationSettingsMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TemplateName: Optional[ConfigurationTemplateName]
    EnvironmentName: Optional[EnvironmentName]


EnvironmentHealthAttributes = List[EnvironmentHealthAttribute]


class DescribeEnvironmentHealthRequest(ServiceRequest):
    EnvironmentName: Optional[EnvironmentName]
    EnvironmentId: Optional[EnvironmentId]
    AttributeNames: Optional[EnvironmentHealthAttributes]


RefreshedAt = datetime


class InstanceHealthSummary(TypedDict, total=False):
    NoData: Optional[NullableInteger]
    Unknown: Optional[NullableInteger]
    Pending: Optional[NullableInteger]
    Ok: Optional[NullableInteger]
    Info: Optional[NullableInteger]
    Warning: Optional[NullableInteger]
    Degraded: Optional[NullableInteger]
    Severe: Optional[NullableInteger]


class DescribeEnvironmentHealthResult(TypedDict, total=False):
    EnvironmentName: Optional[EnvironmentName]
    HealthStatus: Optional[String]
    Status: Optional[EnvironmentHealth]
    Color: Optional[String]
    Causes: Optional[Causes]
    ApplicationMetrics: Optional[ApplicationMetrics]
    InstancesHealth: Optional[InstanceHealthSummary]
    RefreshedAt: Optional[RefreshedAt]


class DescribeEnvironmentManagedActionHistoryRequest(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    NextToken: Optional[String]
    MaxItems: Optional[ManagedActionHistoryMaxItems]


Timestamp = datetime


class ManagedActionHistoryItem(TypedDict, total=False):
    ActionId: Optional[String]
    ActionType: Optional[ActionType]
    ActionDescription: Optional[String]
    FailureType: Optional[FailureType]
    Status: Optional[ActionHistoryStatus]
    FailureDescription: Optional[String]
    ExecutedTime: Optional[Timestamp]
    FinishedTime: Optional[Timestamp]


ManagedActionHistoryItems = List[ManagedActionHistoryItem]


class DescribeEnvironmentManagedActionHistoryResult(TypedDict, total=False):
    ManagedActionHistoryItems: Optional[ManagedActionHistoryItems]
    NextToken: Optional[String]


class DescribeEnvironmentManagedActionsRequest(ServiceRequest):
    EnvironmentName: Optional[String]
    EnvironmentId: Optional[String]
    Status: Optional[ActionStatus]


class ManagedAction(TypedDict, total=False):
    ActionId: Optional[String]
    ActionDescription: Optional[String]
    ActionType: Optional[ActionType]
    Status: Optional[ActionStatus]
    WindowStartTime: Optional[Timestamp]


ManagedActions = List[ManagedAction]


class DescribeEnvironmentManagedActionsResult(TypedDict, total=False):
    ManagedActions: Optional[ManagedActions]


class DescribeEnvironmentResourcesMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]


IncludeDeletedBackTo = datetime
EnvironmentNamesList = List[EnvironmentName]
EnvironmentIdList = List[EnvironmentId]


class DescribeEnvironmentsMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    VersionLabel: Optional[VersionLabel]
    EnvironmentIds: Optional[EnvironmentIdList]
    EnvironmentNames: Optional[EnvironmentNamesList]
    IncludeDeleted: Optional[IncludeDeleted]
    IncludedDeletedBackTo: Optional[IncludeDeletedBackTo]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[Token]


TimeFilterEnd = datetime
TimeFilterStart = datetime


class DescribeEventsMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    VersionLabel: Optional[VersionLabel]
    TemplateName: Optional[ConfigurationTemplateName]
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    PlatformArn: Optional[PlatformArn]
    RequestId: Optional[RequestId]
    Severity: Optional[EventSeverity]
    StartTime: Optional[TimeFilterStart]
    EndTime: Optional[TimeFilterEnd]
    MaxRecords: Optional[MaxRecords]
    NextToken: Optional[Token]


InstancesHealthAttributes = List[InstancesHealthAttribute]


class DescribeInstancesHealthRequest(ServiceRequest):
    EnvironmentName: Optional[EnvironmentName]
    EnvironmentId: Optional[EnvironmentId]
    AttributeNames: Optional[InstancesHealthAttributes]
    NextToken: Optional[NextToken]


LoadAverage = List[LoadAverageValue]


class SystemStatus(TypedDict, total=False):
    CPUUtilization: Optional[CPUUtilization]
    LoadAverage: Optional[LoadAverage]


LaunchedAt = datetime


class SingleInstanceHealth(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    HealthStatus: Optional[String]
    Color: Optional[String]
    Causes: Optional[Causes]
    LaunchedAt: Optional[LaunchedAt]
    ApplicationMetrics: Optional[ApplicationMetrics]
    System: Optional[SystemStatus]
    Deployment: Optional[Deployment]
    AvailabilityZone: Optional[String]
    InstanceType: Optional[String]


InstanceHealthList = List[SingleInstanceHealth]


class DescribeInstancesHealthResult(TypedDict, total=False):
    InstanceHealthList: Optional[InstanceHealthList]
    RefreshedAt: Optional[RefreshedAt]
    NextToken: Optional[NextToken]


class DescribePlatformVersionRequest(ServiceRequest):
    PlatformArn: Optional[PlatformArn]


class PlatformFramework(TypedDict, total=False):
    Name: Optional[String]
    Version: Optional[String]


PlatformFrameworks = List[PlatformFramework]


class PlatformProgrammingLanguage(TypedDict, total=False):
    Name: Optional[String]
    Version: Optional[String]


PlatformProgrammingLanguages = List[PlatformProgrammingLanguage]


class PlatformDescription(TypedDict, total=False):
    PlatformArn: Optional[PlatformArn]
    PlatformOwner: Optional[PlatformOwner]
    PlatformName: Optional[PlatformName]
    PlatformVersion: Optional[PlatformVersion]
    SolutionStackName: Optional[SolutionStackName]
    PlatformStatus: Optional[PlatformStatus]
    DateCreated: Optional[CreationDate]
    DateUpdated: Optional[UpdateDate]
    PlatformCategory: Optional[PlatformCategory]
    Description: Optional[Description]
    Maintainer: Optional[Maintainer]
    OperatingSystemName: Optional[OperatingSystemName]
    OperatingSystemVersion: Optional[OperatingSystemVersion]
    ProgrammingLanguages: Optional[PlatformProgrammingLanguages]
    Frameworks: Optional[PlatformFrameworks]
    CustomAmiList: Optional[CustomAmiList]
    SupportedTierList: Optional[SupportedTierList]
    SupportedAddonList: Optional[SupportedAddonList]
    PlatformLifecycleState: Optional[PlatformLifecycleState]
    PlatformBranchName: Optional[BranchName]
    PlatformBranchLifecycleState: Optional[PlatformBranchLifecycleState]


class DescribePlatformVersionResult(TypedDict, total=False):
    PlatformDescription: Optional[PlatformDescription]


class DisassociateEnvironmentOperationsRoleMessage(ServiceRequest):
    EnvironmentName: EnvironmentName


class EnvironmentLink(TypedDict, total=False):
    LinkName: Optional[String]
    EnvironmentName: Optional[String]


EnvironmentLinks = List[EnvironmentLink]


class Listener(TypedDict, total=False):
    Protocol: Optional[String]
    Port: Optional[Integer]


LoadBalancerListenersDescription = List[Listener]


class LoadBalancerDescription(TypedDict, total=False):
    LoadBalancerName: Optional[String]
    Domain: Optional[String]
    Listeners: Optional[LoadBalancerListenersDescription]


class EnvironmentResourcesDescription(TypedDict, total=False):
    LoadBalancer: Optional[LoadBalancerDescription]


class EnvironmentDescription(TypedDict, total=False):
    EnvironmentName: Optional[EnvironmentName]
    EnvironmentId: Optional[EnvironmentId]
    ApplicationName: Optional[ApplicationName]
    VersionLabel: Optional[VersionLabel]
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    TemplateName: Optional[ConfigurationTemplateName]
    Description: Optional[Description]
    EndpointURL: Optional[EndpointURL]
    CNAME: Optional[DNSCname]
    DateCreated: Optional[CreationDate]
    DateUpdated: Optional[UpdateDate]
    Status: Optional[EnvironmentStatus]
    AbortableOperationInProgress: Optional[AbortableOperationInProgress]
    Health: Optional[EnvironmentHealth]
    HealthStatus: Optional[EnvironmentHealthStatus]
    Resources: Optional[EnvironmentResourcesDescription]
    Tier: Optional[EnvironmentTier]
    EnvironmentLinks: Optional[EnvironmentLinks]
    EnvironmentArn: Optional[EnvironmentArn]
    OperationsRole: Optional[OperationsRole]


EnvironmentDescriptionsList = List[EnvironmentDescription]


class EnvironmentDescriptionsMessage(TypedDict, total=False):
    Environments: Optional[EnvironmentDescriptionsList]
    NextToken: Optional[Token]


SampleTimestamp = datetime


class EnvironmentInfoDescription(TypedDict, total=False):
    InfoType: Optional[EnvironmentInfoType]
    Ec2InstanceId: Optional[Ec2InstanceId]
    SampleTimestamp: Optional[SampleTimestamp]
    Message: Optional[Message]


EnvironmentInfoDescriptionList = List[EnvironmentInfoDescription]


class Queue(TypedDict, total=False):
    Name: Optional[String]
    URL: Optional[String]


QueueList = List[Queue]


class Trigger(TypedDict, total=False):
    Name: Optional[ResourceId]


TriggerList = List[Trigger]


class LoadBalancer(TypedDict, total=False):
    Name: Optional[ResourceId]


LoadBalancerList = List[LoadBalancer]


class LaunchTemplate(TypedDict, total=False):
    Id: Optional[ResourceId]


LaunchTemplateList = List[LaunchTemplate]


class LaunchConfiguration(TypedDict, total=False):
    Name: Optional[ResourceId]


LaunchConfigurationList = List[LaunchConfiguration]


class Instance(TypedDict, total=False):
    Id: Optional[ResourceId]


InstanceList = List[Instance]


class EnvironmentResourceDescription(TypedDict, total=False):
    EnvironmentName: Optional[EnvironmentName]
    AutoScalingGroups: Optional[AutoScalingGroupList]
    Instances: Optional[InstanceList]
    LaunchConfigurations: Optional[LaunchConfigurationList]
    LaunchTemplates: Optional[LaunchTemplateList]
    LoadBalancers: Optional[LoadBalancerList]
    Triggers: Optional[TriggerList]
    Queues: Optional[QueueList]


class EnvironmentResourceDescriptionsMessage(TypedDict, total=False):
    EnvironmentResources: Optional[EnvironmentResourceDescription]


EventDate = datetime


class EventDescription(TypedDict, total=False):
    EventDate: Optional[EventDate]
    Message: Optional[EventMessage]
    ApplicationName: Optional[ApplicationName]
    VersionLabel: Optional[VersionLabel]
    TemplateName: Optional[ConfigurationTemplateName]
    EnvironmentName: Optional[EnvironmentName]
    PlatformArn: Optional[PlatformArn]
    RequestId: Optional[RequestId]
    Severity: Optional[EventSeverity]


EventDescriptionList = List[EventDescription]


class EventDescriptionsMessage(TypedDict, total=False):
    Events: Optional[EventDescriptionList]
    NextToken: Optional[Token]


class ListAvailableSolutionStacksResultMessage(TypedDict, total=False):
    SolutionStacks: Optional[AvailableSolutionStackNamesList]
    SolutionStackDetails: Optional[AvailableSolutionStackDetailsList]


SearchFilterValues = List[SearchFilterValue]


class SearchFilter(TypedDict, total=False):
    Attribute: Optional[SearchFilterAttribute]
    Operator: Optional[SearchFilterOperator]
    Values: Optional[SearchFilterValues]


SearchFilters = List[SearchFilter]


class ListPlatformBranchesRequest(ServiceRequest):
    Filters: Optional[SearchFilters]
    MaxRecords: Optional[PlatformBranchMaxRecords]
    NextToken: Optional[Token]


class PlatformBranchSummary(TypedDict, total=False):
    PlatformName: Optional[PlatformName]
    BranchName: Optional[BranchName]
    LifecycleState: Optional[PlatformBranchLifecycleState]
    BranchOrder: Optional[BranchOrder]
    SupportedTierList: Optional[SupportedTierList]


PlatformBranchSummaryList = List[PlatformBranchSummary]


class ListPlatformBranchesResult(TypedDict, total=False):
    PlatformBranchSummaryList: Optional[PlatformBranchSummaryList]
    NextToken: Optional[Token]


PlatformFilterValueList = List[PlatformFilterValue]


class PlatformFilter(TypedDict, total=False):
    Type: Optional[PlatformFilterType]
    Operator: Optional[PlatformFilterOperator]
    Values: Optional[PlatformFilterValueList]


PlatformFilters = List[PlatformFilter]


class ListPlatformVersionsRequest(ServiceRequest):
    Filters: Optional[PlatformFilters]
    MaxRecords: Optional[PlatformMaxRecords]
    NextToken: Optional[Token]


PlatformSummaryList = List[PlatformSummary]


class ListPlatformVersionsResult(TypedDict, total=False):
    PlatformSummaryList: Optional[PlatformSummaryList]
    NextToken: Optional[Token]


class ListTagsForResourceMessage(ServiceRequest):
    ResourceArn: ResourceArn


class RebuildEnvironmentMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]


class RequestEnvironmentInfoMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    InfoType: EnvironmentInfoType


TagList = List[Tag]


class ResourceTagsDescriptionMessage(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]
    ResourceTags: Optional[TagList]


class RestartAppServerMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]


class RetrieveEnvironmentInfoMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    InfoType: EnvironmentInfoType


class RetrieveEnvironmentInfoResultMessage(TypedDict, total=False):
    EnvironmentInfo: Optional[EnvironmentInfoDescriptionList]


class SwapEnvironmentCNAMEsMessage(ServiceRequest):
    SourceEnvironmentId: Optional[EnvironmentId]
    SourceEnvironmentName: Optional[EnvironmentName]
    DestinationEnvironmentId: Optional[EnvironmentId]
    DestinationEnvironmentName: Optional[EnvironmentName]


TagKeyList = List[TagKey]


class TerminateEnvironmentMessage(ServiceRequest):
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    TerminateResources: Optional[TerminateEnvironmentResources]
    ForceTerminate: Optional[ForceTerminate]


class UpdateApplicationMessage(ServiceRequest):
    ApplicationName: ApplicationName
    Description: Optional[Description]


class UpdateApplicationResourceLifecycleMessage(ServiceRequest):
    ApplicationName: ApplicationName
    ResourceLifecycleConfig: ApplicationResourceLifecycleConfig


class UpdateApplicationVersionMessage(ServiceRequest):
    ApplicationName: ApplicationName
    VersionLabel: VersionLabel
    Description: Optional[Description]


class UpdateConfigurationTemplateMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TemplateName: ConfigurationTemplateName
    Description: Optional[Description]
    OptionSettings: Optional[ConfigurationOptionSettingsList]
    OptionsToRemove: Optional[OptionsSpecifierList]


class UpdateEnvironmentMessage(ServiceRequest):
    ApplicationName: Optional[ApplicationName]
    EnvironmentId: Optional[EnvironmentId]
    EnvironmentName: Optional[EnvironmentName]
    GroupName: Optional[GroupName]
    Description: Optional[Description]
    Tier: Optional[EnvironmentTier]
    VersionLabel: Optional[VersionLabel]
    TemplateName: Optional[ConfigurationTemplateName]
    SolutionStackName: Optional[SolutionStackName]
    PlatformArn: Optional[PlatformArn]
    OptionSettings: Optional[ConfigurationOptionSettingsList]
    OptionsToRemove: Optional[OptionsSpecifierList]


class UpdateTagsForResourceMessage(ServiceRequest):
    ResourceArn: ResourceArn
    TagsToAdd: Optional[TagList]
    TagsToRemove: Optional[TagKeyList]


class ValidateConfigurationSettingsMessage(ServiceRequest):
    ApplicationName: ApplicationName
    TemplateName: Optional[ConfigurationTemplateName]
    EnvironmentName: Optional[EnvironmentName]
    OptionSettings: ConfigurationOptionSettingsList


class ElasticbeanstalkApi:

    service = "elasticbeanstalk"
    version = "2010-12-01"

    @handler("AbortEnvironmentUpdate")
    def abort_environment_update(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> None:
        raise NotImplementedError

    @handler("ApplyEnvironmentManagedAction")
    def apply_environment_managed_action(
        self,
        context: RequestContext,
        action_id: String,
        environment_name: String = None,
        environment_id: String = None,
    ) -> ApplyEnvironmentManagedActionResult:
        raise NotImplementedError

    @handler("AssociateEnvironmentOperationsRole")
    def associate_environment_operations_role(
        self,
        context: RequestContext,
        environment_name: EnvironmentName,
        operations_role: OperationsRole,
    ) -> None:
        raise NotImplementedError

    @handler("CheckDNSAvailability")
    def check_dns_availability(
        self, context: RequestContext, cname_prefix: DNSCnamePrefix
    ) -> CheckDNSAvailabilityResultMessage:
        raise NotImplementedError

    @handler("ComposeEnvironments")
    def compose_environments(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        group_name: GroupName = None,
        version_labels: VersionLabels = None,
    ) -> EnvironmentDescriptionsMessage:
        raise NotImplementedError

    @handler("CreateApplication")
    def create_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        description: Description = None,
        resource_lifecycle_config: ApplicationResourceLifecycleConfig = None,
        tags: Tags = None,
    ) -> ApplicationDescriptionMessage:
        raise NotImplementedError

    @handler("CreateApplicationVersion")
    def create_application_version(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        version_label: VersionLabel,
        description: Description = None,
        source_build_information: SourceBuildInformation = None,
        source_bundle: S3Location = None,
        build_configuration: BuildConfiguration = None,
        auto_create_application: AutoCreateApplication = None,
        process: ApplicationVersionProccess = None,
        tags: Tags = None,
    ) -> ApplicationVersionDescriptionMessage:
        raise NotImplementedError

    @handler("CreateConfigurationTemplate")
    def create_configuration_template(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        template_name: ConfigurationTemplateName,
        solution_stack_name: SolutionStackName = None,
        platform_arn: PlatformArn = None,
        source_configuration: SourceConfiguration = None,
        environment_id: EnvironmentId = None,
        description: Description = None,
        option_settings: ConfigurationOptionSettingsList = None,
        tags: Tags = None,
    ) -> ConfigurationSettingsDescription:
        raise NotImplementedError

    @handler("CreateEnvironment")
    def create_environment(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        environment_name: EnvironmentName = None,
        group_name: GroupName = None,
        description: Description = None,
        cname_prefix: DNSCnamePrefix = None,
        tier: EnvironmentTier = None,
        tags: Tags = None,
        version_label: VersionLabel = None,
        template_name: ConfigurationTemplateName = None,
        solution_stack_name: SolutionStackName = None,
        platform_arn: PlatformArn = None,
        option_settings: ConfigurationOptionSettingsList = None,
        options_to_remove: OptionsSpecifierList = None,
        operations_role: OperationsRole = None,
    ) -> EnvironmentDescription:
        raise NotImplementedError

    @handler("CreatePlatformVersion")
    def create_platform_version(
        self,
        context: RequestContext,
        platform_name: PlatformName,
        platform_version: PlatformVersion,
        platform_definition_bundle: S3Location,
        environment_name: EnvironmentName = None,
        option_settings: ConfigurationOptionSettingsList = None,
        tags: Tags = None,
    ) -> CreatePlatformVersionResult:
        raise NotImplementedError

    @handler("CreateStorageLocation")
    def create_storage_location(
        self,
        context: RequestContext,
    ) -> CreateStorageLocationResultMessage:
        raise NotImplementedError

    @handler("DeleteApplication")
    def delete_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        terminate_env_by_force: TerminateEnvForce = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteApplicationVersion")
    def delete_application_version(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        version_label: VersionLabel,
        delete_source_bundle: DeleteSourceBundle = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationTemplate")
    def delete_configuration_template(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        template_name: ConfigurationTemplateName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEnvironmentConfiguration")
    def delete_environment_configuration(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        environment_name: EnvironmentName,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePlatformVersion")
    def delete_platform_version(
        self, context: RequestContext, platform_arn: PlatformArn = None
    ) -> DeletePlatformVersionResult:
        raise NotImplementedError

    @handler("DescribeAccountAttributes")
    def describe_account_attributes(
        self,
        context: RequestContext,
    ) -> DescribeAccountAttributesResult:
        raise NotImplementedError

    @handler("DescribeApplicationVersions")
    def describe_application_versions(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        version_labels: VersionLabelsList = None,
        max_records: MaxRecords = None,
        next_token: Token = None,
    ) -> ApplicationVersionDescriptionsMessage:
        raise NotImplementedError

    @handler("DescribeApplications")
    def describe_applications(
        self, context: RequestContext, application_names: ApplicationNamesList = None
    ) -> ApplicationDescriptionsMessage:
        raise NotImplementedError

    @handler("DescribeConfigurationOptions")
    def describe_configuration_options(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        template_name: ConfigurationTemplateName = None,
        environment_name: EnvironmentName = None,
        solution_stack_name: SolutionStackName = None,
        platform_arn: PlatformArn = None,
        options: OptionsSpecifierList = None,
    ) -> ConfigurationOptionsDescription:
        raise NotImplementedError

    @handler("DescribeConfigurationSettings")
    def describe_configuration_settings(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        template_name: ConfigurationTemplateName = None,
        environment_name: EnvironmentName = None,
    ) -> ConfigurationSettingsDescriptions:
        raise NotImplementedError

    @handler("DescribeEnvironmentHealth")
    def describe_environment_health(
        self,
        context: RequestContext,
        environment_name: EnvironmentName = None,
        environment_id: EnvironmentId = None,
        attribute_names: EnvironmentHealthAttributes = None,
    ) -> DescribeEnvironmentHealthResult:
        raise NotImplementedError

    @handler("DescribeEnvironmentManagedActionHistory")
    def describe_environment_managed_action_history(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
        next_token: String = None,
        max_items: ManagedActionHistoryMaxItems = None,
    ) -> DescribeEnvironmentManagedActionHistoryResult:
        raise NotImplementedError

    @handler("DescribeEnvironmentManagedActions")
    def describe_environment_managed_actions(
        self,
        context: RequestContext,
        environment_name: String = None,
        environment_id: String = None,
        status: ActionStatus = None,
    ) -> DescribeEnvironmentManagedActionsResult:
        raise NotImplementedError

    @handler("DescribeEnvironmentResources")
    def describe_environment_resources(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> EnvironmentResourceDescriptionsMessage:
        raise NotImplementedError

    @handler("DescribeEnvironments")
    def describe_environments(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        version_label: VersionLabel = None,
        environment_ids: EnvironmentIdList = None,
        environment_names: EnvironmentNamesList = None,
        include_deleted: IncludeDeleted = None,
        included_deleted_back_to: IncludeDeletedBackTo = None,
        max_records: MaxRecords = None,
        next_token: Token = None,
    ) -> EnvironmentDescriptionsMessage:
        raise NotImplementedError

    @handler("DescribeEvents")
    def describe_events(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        version_label: VersionLabel = None,
        template_name: ConfigurationTemplateName = None,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
        platform_arn: PlatformArn = None,
        request_id: RequestId = None,
        severity: EventSeverity = None,
        start_time: TimeFilterStart = None,
        end_time: TimeFilterEnd = None,
        max_records: MaxRecords = None,
        next_token: Token = None,
    ) -> EventDescriptionsMessage:
        raise NotImplementedError

    @handler("DescribeInstancesHealth")
    def describe_instances_health(
        self,
        context: RequestContext,
        environment_name: EnvironmentName = None,
        environment_id: EnvironmentId = None,
        attribute_names: InstancesHealthAttributes = None,
        next_token: NextToken = None,
    ) -> DescribeInstancesHealthResult:
        raise NotImplementedError

    @handler("DescribePlatformVersion")
    def describe_platform_version(
        self, context: RequestContext, platform_arn: PlatformArn = None
    ) -> DescribePlatformVersionResult:
        raise NotImplementedError

    @handler("DisassociateEnvironmentOperationsRole")
    def disassociate_environment_operations_role(
        self, context: RequestContext, environment_name: EnvironmentName
    ) -> None:
        raise NotImplementedError

    @handler("ListAvailableSolutionStacks")
    def list_available_solution_stacks(
        self,
        context: RequestContext,
    ) -> ListAvailableSolutionStacksResultMessage:
        raise NotImplementedError

    @handler("ListPlatformBranches")
    def list_platform_branches(
        self,
        context: RequestContext,
        filters: SearchFilters = None,
        max_records: PlatformBranchMaxRecords = None,
        next_token: Token = None,
    ) -> ListPlatformBranchesResult:
        raise NotImplementedError

    @handler("ListPlatformVersions")
    def list_platform_versions(
        self,
        context: RequestContext,
        filters: PlatformFilters = None,
        max_records: PlatformMaxRecords = None,
        next_token: Token = None,
    ) -> ListPlatformVersionsResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> ResourceTagsDescriptionMessage:
        raise NotImplementedError

    @handler("RebuildEnvironment")
    def rebuild_environment(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> None:
        raise NotImplementedError

    @handler("RequestEnvironmentInfo")
    def request_environment_info(
        self,
        context: RequestContext,
        info_type: EnvironmentInfoType,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> None:
        raise NotImplementedError

    @handler("RestartAppServer")
    def restart_app_server(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> None:
        raise NotImplementedError

    @handler("RetrieveEnvironmentInfo")
    def retrieve_environment_info(
        self,
        context: RequestContext,
        info_type: EnvironmentInfoType,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
    ) -> RetrieveEnvironmentInfoResultMessage:
        raise NotImplementedError

    @handler("SwapEnvironmentCNAMEs")
    def swap_environment_cnam_es(
        self,
        context: RequestContext,
        source_environment_id: EnvironmentId = None,
        source_environment_name: EnvironmentName = None,
        destination_environment_id: EnvironmentId = None,
        destination_environment_name: EnvironmentName = None,
    ) -> None:
        raise NotImplementedError

    @handler("TerminateEnvironment")
    def terminate_environment(
        self,
        context: RequestContext,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
        terminate_resources: TerminateEnvironmentResources = None,
        force_terminate: ForceTerminate = None,
    ) -> EnvironmentDescription:
        raise NotImplementedError

    @handler("UpdateApplication")
    def update_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        description: Description = None,
    ) -> ApplicationDescriptionMessage:
        raise NotImplementedError

    @handler("UpdateApplicationResourceLifecycle")
    def update_application_resource_lifecycle(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        resource_lifecycle_config: ApplicationResourceLifecycleConfig,
    ) -> ApplicationResourceLifecycleDescriptionMessage:
        raise NotImplementedError

    @handler("UpdateApplicationVersion")
    def update_application_version(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        version_label: VersionLabel,
        description: Description = None,
    ) -> ApplicationVersionDescriptionMessage:
        raise NotImplementedError

    @handler("UpdateConfigurationTemplate")
    def update_configuration_template(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        template_name: ConfigurationTemplateName,
        description: Description = None,
        option_settings: ConfigurationOptionSettingsList = None,
        options_to_remove: OptionsSpecifierList = None,
    ) -> ConfigurationSettingsDescription:
        raise NotImplementedError

    @handler("UpdateEnvironment")
    def update_environment(
        self,
        context: RequestContext,
        application_name: ApplicationName = None,
        environment_id: EnvironmentId = None,
        environment_name: EnvironmentName = None,
        group_name: GroupName = None,
        description: Description = None,
        tier: EnvironmentTier = None,
        version_label: VersionLabel = None,
        template_name: ConfigurationTemplateName = None,
        solution_stack_name: SolutionStackName = None,
        platform_arn: PlatformArn = None,
        option_settings: ConfigurationOptionSettingsList = None,
        options_to_remove: OptionsSpecifierList = None,
    ) -> EnvironmentDescription:
        raise NotImplementedError

    @handler("UpdateTagsForResource")
    def update_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArn,
        tags_to_add: TagList = None,
        tags_to_remove: TagKeyList = None,
    ) -> None:
        raise NotImplementedError

    @handler("ValidateConfigurationSettings")
    def validate_configuration_settings(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        option_settings: ConfigurationOptionSettingsList,
        template_name: ConfigurationTemplateName = None,
        environment_name: EnvironmentName = None,
    ) -> ConfigurationSettingsValidationMessages:
        raise NotImplementedError
