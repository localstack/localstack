import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Accept = str
AccountId = str
ActionArn = str
AlarmName = str
AlgorithmArn = str
AlgorithmImage = str
AppArn = str
AppImageConfigArn = str
AppImageConfigName = str
AppManaged = bool
AppName = str
ApprovalDescription = str
ArnOrName = str
ArtifactArn = str
ArtifactDigest = str
AssociationEntityArn = str
AthenaCatalog = str
AthenaDatabase = str
AthenaQueryString = str
AthenaWorkGroup = str
AttributeName = str
AutoGenerateEndpointName = bool
AutoMLFailureReason = str
AutoMLJobArn = str
AutoMLJobName = str
AutoMLMaxResults = int
AutoMLNameContains = str
BillableTimeInSeconds = int
BlockedReason = str
Boolean = bool
Branch = str
BucketName = str
CallbackToken = str
CandidateDefinitionNotebookLocation = str
CandidateName = str
CandidateStepArn = str
CandidateStepName = str
CapacitySizeValue = int
Catalog = str
Cents = int
CertifyForMarketplace = bool
ChannelName = str
Cidr = str
ClientId = str
ClientSecret = str
ClientToken = str
CodeRepositoryArn = str
CodeRepositoryContains = str
CodeRepositoryNameContains = str
CodeRepositoryNameOrUrl = str
CognitoUserGroup = str
CognitoUserPool = str
CollectionName = str
CompilationJobArn = str
CompilerOptions = str
ConfigKey = str
ConfigValue = str
ContainerArgument = str
ContainerEntrypointString = str
ContainerHostname = str
ContainerImage = str
ContentDigest = str
ContentType = str
ContextArn = str
CsvContentType = str
CustomerMetadataKey = str
CustomerMetadataValue = str
DataExplorationNotebookLocation = str
DataInputConfig = str
Database = str
DefaultGid = int
DefaultUid = int
Description = str
DestinationS3Uri = str
DeviceArn = str
DeviceDescription = str
DeviceFleetArn = str
DeviceFleetDescription = str
DeviceName = str
DirectoryPath = str
DisableProfiler = bool
DisassociateAdditionalCodeRepositories = bool
DisassociateDefaultCodeRepository = bool
DisassociateNotebookInstanceAcceleratorTypes = bool
DisassociateNotebookInstanceLifecycleConfig = bool
Dollars = int
DomainArn = str
DomainId = str
DomainName = str
DoubleParameterValue = float
EdgePackagingJobArn = str
EdgePresetDeploymentArtifact = str
EdgeVersion = str
EfsUid = str
EnableCapture = bool
EnableIotRoleAlias = bool
EndpointArn = str
EndpointConfigArn = str
EndpointConfigName = str
EndpointConfigNameContains = str
EndpointName = str
EndpointNameContains = str
EntityDescription = str
EntityName = str
EnvironmentKey = str
EnvironmentValue = str
ExitMessage = str
ExperimentArn = str
ExperimentDescription = str
ExperimentEntityName = str
ExperimentEntityNameOrArn = str
ExperimentSourceArn = str
ExpiresInSeconds = int
ExplainabilityLocation = str
FailureReason = str
FeatureGroupArn = str
FeatureGroupMaxResults = int
FeatureGroupName = str
FeatureGroupNameContains = str
FeatureName = str
FileSystemId = str
FilterValue = str
Float = float
FlowDefinitionArn = str
FlowDefinitionName = str
FlowDefinitionTaskAvailabilityLifetimeInSeconds = int
FlowDefinitionTaskCount = int
FlowDefinitionTaskDescription = str
FlowDefinitionTaskKeyword = str
FlowDefinitionTaskTimeLimitInSeconds = int
FlowDefinitionTaskTitle = str
FrameworkVersion = str
GenerateCandidateDefinitionsOnly = bool
GitConfigUrl = str
Group = str
HumanLoopActivationConditions = str
HumanTaskUiArn = str
HumanTaskUiName = str
HyperParameterKey = str
HyperParameterTrainingJobDefinitionName = str
HyperParameterTuningJobArn = str
HyperParameterTuningJobName = str
HyperParameterValue = str
IdempotencyToken = str
ImageArn = str
ImageBaseImage = str
ImageContainerImage = str
ImageDeleteProperty = str
ImageDescription = str
ImageDigest = str
ImageDisplayName = str
ImageName = str
ImageNameContains = str
ImageUri = str
ImageVersionArn = str
ImageVersionNumber = int
InferenceImage = str
InferenceSpecificationName = str
InitialNumberOfUsers = int
InitialTaskCount = int
Integer = int
IntegerValue = int
InvocationsMaxRetries = int
InvocationsTimeoutInSeconds = int
IotRoleAlias = str
JobDurationInSeconds = int
JobReferenceCode = str
JobReferenceCodeContains = str
JsonContentType = str
JsonPath = str
KernelDisplayName = str
KernelName = str
Key = str
KmsKeyId = str
LabelAttributeName = str
LabelCounter = int
LabelingJobAlgorithmSpecificationArn = str
LabelingJobArn = str
LabelingJobName = str
LambdaFunctionArn = str
LineageGroupArn = str
LineageGroupNameOrArn = str
ListMaxResults = int
ListTagsMaxResults = int
MaxAutoMLJobRuntimeInSeconds = int
MaxCandidates = int
MaxConcurrentInvocationsPerInstance = int
MaxConcurrentTaskCount = int
MaxConcurrentTransforms = int
MaxHumanLabeledObjectCount = int
MaxNumberOfTests = int
MaxNumberOfTrainingJobs = int
MaxParallelExecutionSteps = int
MaxParallelOfTests = int
MaxParallelTrainingJobs = int
MaxPayloadInMB = int
MaxPercentageOfInputDatasetLabeled = int
MaxResults = int
MaxRuntimeInSeconds = int
MaxRuntimePerTrainingJobInSeconds = int
MaxWaitTimeInSeconds = int
MaximumExecutionTimeoutInSeconds = int
MaximumRetryAttempts = int
MediaType = str
MetadataPropertyValue = str
MetricName = str
MetricRegex = str
MetricValue = float
ModelArn = str
ModelInsightsLocation = str
ModelName = str
ModelNameContains = str
ModelPackageArn = str
ModelPackageGroupArn = str
ModelPackageVersion = int
MonitoringJobDefinitionArn = str
MonitoringJobDefinitionName = str
MonitoringMaxRuntimeInSeconds = int
MonitoringS3Uri = str
MonitoringScheduleArn = str
MonitoringScheduleName = str
MonitoringTimeOffsetString = str
MountPath = str
NameContains = str
NeoVpcSecurityGroupId = str
NeoVpcSubnetId = str
NetworkInterfaceId = str
NextToken = str
NotebookInstanceArn = str
NotebookInstanceLifecycleConfigArn = str
NotebookInstanceLifecycleConfigContent = str
NotebookInstanceLifecycleConfigName = str
NotebookInstanceLifecycleConfigNameContains = str
NotebookInstanceName = str
NotebookInstanceNameContains = str
NotebookInstanceUrl = str
NotebookInstanceVolumeSizeInGB = int
NotificationTopicArn = str
NumberOfHumanWorkersPerDataObject = int
ObjectiveStatusCounter = int
OidcEndpoint = str
OptionalDouble = float
OptionalInteger = int
OptionalVolumeSizeInGB = int
PaginationToken = str
ParameterKey = str
ParameterName = str
ParameterValue = str
PipelineArn = str
PipelineDefinition = str
PipelineDescription = str
PipelineExecutionArn = str
PipelineExecutionDescription = str
PipelineExecutionFailureReason = str
PipelineExecutionName = str
PipelineName = str
PipelineParameterName = str
PlatformIdentifier = str
PolicyString = str
PresignedDomainUrl = str
ProbabilityThresholdAttribute = float
ProcessingEnvironmentKey = str
ProcessingEnvironmentValue = str
ProcessingInstanceCount = int
ProcessingJobArn = str
ProcessingJobName = str
ProcessingLocalPath = str
ProcessingMaxRuntimeInSeconds = int
ProcessingVolumeSizeInGB = int
ProductId = str
ProjectArn = str
ProjectEntityName = str
ProjectId = str
PropertyNameHint = str
ProvisionedProductStatusMessage = str
ProvisioningParameterKey = str
ProvisioningParameterValue = str
QueryLineageMaxDepth = int
QueryLineageMaxResults = int
RecommendationJobArn = str
RecommendationJobDescription = str
RecommendationJobName = str
RedshiftClusterId = str
RedshiftDatabase = str
RedshiftQueryString = str
RedshiftUserName = str
RepositoryCredentialsProviderArn = str
ResourceArn = str
ResourceId = str
ResourcePolicyString = str
ResourcePropertyName = str
ResponseMIMEType = str
RoleArn = str
RuleConfigurationName = str
S3Uri = str
SamplingPercentage = int
ScheduleExpression = str
SecretArn = str
SecurityGroupId = str
ServerlessMaxConcurrency = int
ServerlessMemorySizeInMB = int
ServiceCatalogEntityId = str
SessionExpirationDurationInSeconds = int
SingleSignOnUserIdentifier = str
SnsTopicArn = str
SourceType = str
SourceUri = str
SpawnRate = int
StatusDetails = str
StatusMessage = str
StepDescription = str
StepDisplayName = str
StepName = str
String = str
String1024 = str
String128 = str
String200 = str
String2048 = str
String256 = str
String3072 = str
String40 = str
String64 = str
String8192 = str
StringParameterValue = str
StudioLifecycleConfigArn = str
StudioLifecycleConfigContent = str
StudioLifecycleConfigName = str
SubnetId = str
Success = bool
TableName = str
TagKey = str
TagValue = str
TargetAttributeName = str
TargetObjectiveMetricValue = float
TaskAvailabilityLifetimeInSeconds = int
TaskCount = int
TaskDescription = str
TaskInput = str
TaskKeyword = str
TaskTimeLimitInSeconds = int
TaskTitle = str
TemplateContent = str
TemplateContentSha256 = str
TemplateUrl = str
TenthFractionsOfACent = int
TerminationWaitInSeconds = int
ThingName = str
TrafficDurationInSeconds = int
TrainingEnvironmentKey = str
TrainingEnvironmentValue = str
TrainingInstanceCount = int
TrainingJobArn = str
TrainingJobName = str
TrainingJobStatusCounter = int
TrainingTimeInSeconds = int
TransformEnvironmentKey = str
TransformEnvironmentValue = str
TransformInstanceCount = int
TransformJobArn = str
TransformJobName = str
TrialArn = str
TrialComponentArn = str
TrialComponentArtifactValue = str
TrialComponentKey256 = str
TrialComponentKey64 = str
TrialComponentSourceArn = str
TrialComponentStatusMessage = str
TrialSourceArn = str
Url = str
UserProfileArn = str
UserProfileName = str
VariantName = str
VariantStatusMessage = str
VariantWeight = float
VersionId = str
VersionedArnOrName = str
VolumeSizeInGB = int
VpcId = str
WaitIntervalInSeconds = int
WorkforceArn = str
WorkforceName = str
WorkteamArn = str
WorkteamName = str


class ActionStatus(str):
    Unknown = "Unknown"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class AlgorithmSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class AlgorithmStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Deleting = "Deleting"


class AppImageConfigSortKey(str):
    CreationTime = "CreationTime"
    LastModifiedTime = "LastModifiedTime"
    Name = "Name"


class AppInstanceType(str):
    system = "system"
    ml_t3_micro = "ml.t3.micro"
    ml_t3_small = "ml.t3.small"
    ml_t3_medium = "ml.t3.medium"
    ml_t3_large = "ml.t3.large"
    ml_t3_xlarge = "ml.t3.xlarge"
    ml_t3_2xlarge = "ml.t3.2xlarge"
    ml_m5_large = "ml.m5.large"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_8xlarge = "ml.m5.8xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_16xlarge = "ml.m5.16xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_m5d_large = "ml.m5d.large"
    ml_m5d_xlarge = "ml.m5d.xlarge"
    ml_m5d_2xlarge = "ml.m5d.2xlarge"
    ml_m5d_4xlarge = "ml.m5d.4xlarge"
    ml_m5d_8xlarge = "ml.m5d.8xlarge"
    ml_m5d_12xlarge = "ml.m5d.12xlarge"
    ml_m5d_16xlarge = "ml.m5d.16xlarge"
    ml_m5d_24xlarge = "ml.m5d.24xlarge"
    ml_c5_large = "ml.c5.large"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_12xlarge = "ml.c5.12xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_c5_24xlarge = "ml.c5.24xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_p3dn_24xlarge = "ml.p3dn.24xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"
    ml_r5_large = "ml.r5.large"
    ml_r5_xlarge = "ml.r5.xlarge"
    ml_r5_2xlarge = "ml.r5.2xlarge"
    ml_r5_4xlarge = "ml.r5.4xlarge"
    ml_r5_8xlarge = "ml.r5.8xlarge"
    ml_r5_12xlarge = "ml.r5.12xlarge"
    ml_r5_16xlarge = "ml.r5.16xlarge"
    ml_r5_24xlarge = "ml.r5.24xlarge"


class AppNetworkAccessType(str):
    PublicInternetOnly = "PublicInternetOnly"
    VpcOnly = "VpcOnly"


class AppSecurityGroupManagement(str):
    Service = "Service"
    Customer = "Customer"


class AppSortKey(str):
    CreationTime = "CreationTime"


class AppStatus(str):
    Deleted = "Deleted"
    Deleting = "Deleting"
    Failed = "Failed"
    InService = "InService"
    Pending = "Pending"


class AppType(str):
    JupyterServer = "JupyterServer"
    KernelGateway = "KernelGateway"
    TensorBoard = "TensorBoard"
    RStudioServerPro = "RStudioServerPro"
    RSessionGateway = "RSessionGateway"


class ArtifactSourceIdType(str):
    MD5Hash = "MD5Hash"
    S3ETag = "S3ETag"
    S3Version = "S3Version"
    Custom = "Custom"


class AssemblyType(str):
    None_ = "None"
    Line = "Line"


class AssociationEdgeType(str):
    ContributedTo = "ContributedTo"
    AssociatedWith = "AssociatedWith"
    DerivedFrom = "DerivedFrom"
    Produced = "Produced"


class AthenaResultCompressionType(str):
    GZIP = "GZIP"
    SNAPPY = "SNAPPY"
    ZLIB = "ZLIB"


class AthenaResultFormat(str):
    PARQUET = "PARQUET"
    ORC = "ORC"
    AVRO = "AVRO"
    JSON = "JSON"
    TEXTFILE = "TEXTFILE"


class AuthMode(str):
    SSO = "SSO"
    IAM = "IAM"


class AutoMLJobObjectiveType(str):
    Maximize = "Maximize"
    Minimize = "Minimize"


class AutoMLJobSecondaryStatus(str):
    Starting = "Starting"
    AnalyzingData = "AnalyzingData"
    FeatureEngineering = "FeatureEngineering"
    ModelTuning = "ModelTuning"
    MaxCandidatesReached = "MaxCandidatesReached"
    Failed = "Failed"
    Stopped = "Stopped"
    MaxAutoMLJobRuntimeReached = "MaxAutoMLJobRuntimeReached"
    Stopping = "Stopping"
    CandidateDefinitionsGenerated = "CandidateDefinitionsGenerated"
    GeneratingExplainabilityReport = "GeneratingExplainabilityReport"
    Completed = "Completed"
    ExplainabilityError = "ExplainabilityError"
    DeployingModel = "DeployingModel"
    ModelDeploymentError = "ModelDeploymentError"
    GeneratingModelInsightsReport = "GeneratingModelInsightsReport"
    ModelInsightsError = "ModelInsightsError"


class AutoMLJobStatus(str):
    Completed = "Completed"
    InProgress = "InProgress"
    Failed = "Failed"
    Stopped = "Stopped"
    Stopping = "Stopping"


class AutoMLMetricEnum(str):
    Accuracy = "Accuracy"
    MSE = "MSE"
    F1 = "F1"
    F1macro = "F1macro"
    AUC = "AUC"


class AutoMLS3DataType(str):
    ManifestFile = "ManifestFile"
    S3Prefix = "S3Prefix"


class AutoMLSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class AutoMLSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class AwsManagedHumanLoopRequestSource(str):
    AWS_Rekognition_DetectModerationLabels_Image_V3 = (
        "AWS/Rekognition/DetectModerationLabels/Image/V3"
    )
    AWS_Textract_AnalyzeDocument_Forms_V1 = "AWS/Textract/AnalyzeDocument/Forms/V1"


class BatchStrategy(str):
    MultiRecord = "MultiRecord"
    SingleRecord = "SingleRecord"


class BooleanOperator(str):
    And = "And"
    Or = "Or"


class CandidateSortBy(str):
    CreationTime = "CreationTime"
    Status = "Status"
    FinalObjectiveMetricValue = "FinalObjectiveMetricValue"


class CandidateStatus(str):
    Completed = "Completed"
    InProgress = "InProgress"
    Failed = "Failed"
    Stopped = "Stopped"
    Stopping = "Stopping"


class CandidateStepType(str):
    AWS_SageMaker_TrainingJob = "AWS::SageMaker::TrainingJob"
    AWS_SageMaker_TransformJob = "AWS::SageMaker::TransformJob"
    AWS_SageMaker_ProcessingJob = "AWS::SageMaker::ProcessingJob"


class CapacitySizeType(str):
    INSTANCE_COUNT = "INSTANCE_COUNT"
    CAPACITY_PERCENT = "CAPACITY_PERCENT"


class CaptureMode(str):
    Input = "Input"
    Output = "Output"


class CaptureStatus(str):
    Started = "Started"
    Stopped = "Stopped"


class CodeRepositorySortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"
    LastModifiedTime = "LastModifiedTime"


class CodeRepositorySortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class CompilationJobStatus(str):
    INPROGRESS = "INPROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STARTING = "STARTING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class CompressionType(str):
    None_ = "None"
    Gzip = "Gzip"


class ConditionOutcome(str):
    True_ = "True"
    False_ = "False"


class ContainerMode(str):
    SingleModel = "SingleModel"
    MultiModel = "MultiModel"


class ContentClassifier(str):
    FreeOfPersonallyIdentifiableInformation = "FreeOfPersonallyIdentifiableInformation"
    FreeOfAdultContent = "FreeOfAdultContent"


class DataDistributionType(str):
    FullyReplicated = "FullyReplicated"
    ShardedByS3Key = "ShardedByS3Key"


class DetailedAlgorithmStatus(str):
    NotStarted = "NotStarted"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"


class DetailedModelPackageStatus(str):
    NotStarted = "NotStarted"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"


class DirectInternetAccess(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class Direction(str):
    Both = "Both"
    Ascendants = "Ascendants"
    Descendants = "Descendants"


class DomainStatus(str):
    Deleting = "Deleting"
    Failed = "Failed"
    InService = "InService"
    Pending = "Pending"
    Updating = "Updating"
    Update_Failed = "Update_Failed"
    Delete_Failed = "Delete_Failed"


class EdgePackagingJobStatus(str):
    STARTING = "STARTING"
    INPROGRESS = "INPROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class EdgePresetDeploymentStatus(str):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EdgePresetDeploymentType(str):
    GreengrassV2Component = "GreengrassV2Component"


class EndpointConfigSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"


class EndpointSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class EndpointStatus(str):
    OutOfService = "OutOfService"
    Creating = "Creating"
    Updating = "Updating"
    SystemUpdating = "SystemUpdating"
    RollingBack = "RollingBack"
    InService = "InService"
    Deleting = "Deleting"
    Failed = "Failed"


class ExecutionStatus(str):
    Pending = "Pending"
    Completed = "Completed"
    CompletedWithViolations = "CompletedWithViolations"
    InProgress = "InProgress"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class FeatureGroupSortBy(str):
    Name = "Name"
    FeatureGroupStatus = "FeatureGroupStatus"
    OfflineStoreStatus = "OfflineStoreStatus"
    CreationTime = "CreationTime"


class FeatureGroupSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class FeatureGroupStatus(str):
    Creating = "Creating"
    Created = "Created"
    CreateFailed = "CreateFailed"
    Deleting = "Deleting"
    DeleteFailed = "DeleteFailed"


class FeatureType(str):
    Integral = "Integral"
    Fractional = "Fractional"
    String = "String"


class FileSystemAccessMode(str):
    rw = "rw"
    ro = "ro"


class FileSystemType(str):
    EFS = "EFS"
    FSxLustre = "FSxLustre"


class FlowDefinitionStatus(str):
    Initializing = "Initializing"
    Active = "Active"
    Failed = "Failed"
    Deleting = "Deleting"


class Framework(str):
    TENSORFLOW = "TENSORFLOW"
    KERAS = "KERAS"
    MXNET = "MXNET"
    ONNX = "ONNX"
    PYTORCH = "PYTORCH"
    XGBOOST = "XGBOOST"
    TFLITE = "TFLITE"
    DARKNET = "DARKNET"
    SKLEARN = "SKLEARN"


class HumanTaskUiStatus(str):
    Active = "Active"
    Deleting = "Deleting"


class HyperParameterScalingType(str):
    Auto = "Auto"
    Linear = "Linear"
    Logarithmic = "Logarithmic"
    ReverseLogarithmic = "ReverseLogarithmic"


class HyperParameterTuningJobObjectiveType(str):
    Maximize = "Maximize"
    Minimize = "Minimize"


class HyperParameterTuningJobSortByOptions(str):
    Name = "Name"
    Status = "Status"
    CreationTime = "CreationTime"


class HyperParameterTuningJobStatus(str):
    Completed = "Completed"
    InProgress = "InProgress"
    Failed = "Failed"
    Stopped = "Stopped"
    Stopping = "Stopping"


class HyperParameterTuningJobStrategyType(str):
    Bayesian = "Bayesian"
    Random = "Random"


class HyperParameterTuningJobWarmStartType(str):
    IdenticalDataAndAlgorithm = "IdenticalDataAndAlgorithm"
    TransferLearning = "TransferLearning"


class ImageSortBy(str):
    CREATION_TIME = "CREATION_TIME"
    LAST_MODIFIED_TIME = "LAST_MODIFIED_TIME"
    IMAGE_NAME = "IMAGE_NAME"


class ImageSortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class ImageStatus(str):
    CREATING = "CREATING"
    CREATED = "CREATED"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATING = "UPDATING"
    UPDATE_FAILED = "UPDATE_FAILED"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"


class ImageVersionSortBy(str):
    CREATION_TIME = "CREATION_TIME"
    LAST_MODIFIED_TIME = "LAST_MODIFIED_TIME"
    VERSION = "VERSION"


class ImageVersionSortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class ImageVersionStatus(str):
    CREATING = "CREATING"
    CREATED = "CREATED"
    CREATE_FAILED = "CREATE_FAILED"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"


class InferenceExecutionMode(str):
    Serial = "Serial"
    Direct = "Direct"


class InputMode(str):
    Pipe = "Pipe"
    File = "File"


class InstanceType(str):
    ml_t2_medium = "ml.t2.medium"
    ml_t2_large = "ml.t2.large"
    ml_t2_xlarge = "ml.t2.xlarge"
    ml_t2_2xlarge = "ml.t2.2xlarge"
    ml_t3_medium = "ml.t3.medium"
    ml_t3_large = "ml.t3.large"
    ml_t3_xlarge = "ml.t3.xlarge"
    ml_t3_2xlarge = "ml.t3.2xlarge"
    ml_m4_xlarge = "ml.m4.xlarge"
    ml_m4_2xlarge = "ml.m4.2xlarge"
    ml_m4_4xlarge = "ml.m4.4xlarge"
    ml_m4_10xlarge = "ml.m4.10xlarge"
    ml_m4_16xlarge = "ml.m4.16xlarge"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_m5d_large = "ml.m5d.large"
    ml_m5d_xlarge = "ml.m5d.xlarge"
    ml_m5d_2xlarge = "ml.m5d.2xlarge"
    ml_m5d_4xlarge = "ml.m5d.4xlarge"
    ml_m5d_8xlarge = "ml.m5d.8xlarge"
    ml_m5d_12xlarge = "ml.m5d.12xlarge"
    ml_m5d_16xlarge = "ml.m5d.16xlarge"
    ml_m5d_24xlarge = "ml.m5d.24xlarge"
    ml_c4_xlarge = "ml.c4.xlarge"
    ml_c4_2xlarge = "ml.c4.2xlarge"
    ml_c4_4xlarge = "ml.c4.4xlarge"
    ml_c4_8xlarge = "ml.c4.8xlarge"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_c5d_xlarge = "ml.c5d.xlarge"
    ml_c5d_2xlarge = "ml.c5d.2xlarge"
    ml_c5d_4xlarge = "ml.c5d.4xlarge"
    ml_c5d_9xlarge = "ml.c5d.9xlarge"
    ml_c5d_18xlarge = "ml.c5d.18xlarge"
    ml_p2_xlarge = "ml.p2.xlarge"
    ml_p2_8xlarge = "ml.p2.8xlarge"
    ml_p2_16xlarge = "ml.p2.16xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_p3dn_24xlarge = "ml.p3dn.24xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"
    ml_r5_large = "ml.r5.large"
    ml_r5_xlarge = "ml.r5.xlarge"
    ml_r5_2xlarge = "ml.r5.2xlarge"
    ml_r5_4xlarge = "ml.r5.4xlarge"
    ml_r5_8xlarge = "ml.r5.8xlarge"
    ml_r5_12xlarge = "ml.r5.12xlarge"
    ml_r5_16xlarge = "ml.r5.16xlarge"
    ml_r5_24xlarge = "ml.r5.24xlarge"


class JoinSource(str):
    Input = "Input"
    None_ = "None"


class LabelingJobStatus(str):
    Initializing = "Initializing"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class LineageType(str):
    TrialComponent = "TrialComponent"
    Artifact = "Artifact"
    Context = "Context"
    Action = "Action"


class ListCompilationJobsSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class ListDeviceFleetsSortBy(str):
    NAME = "NAME"
    CREATION_TIME = "CREATION_TIME"
    LAST_MODIFIED_TIME = "LAST_MODIFIED_TIME"


class ListEdgePackagingJobsSortBy(str):
    NAME = "NAME"
    MODEL_NAME = "MODEL_NAME"
    CREATION_TIME = "CREATION_TIME"
    LAST_MODIFIED_TIME = "LAST_MODIFIED_TIME"
    STATUS = "STATUS"


class ListInferenceRecommendationsJobsSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class ListLabelingJobsForWorkteamSortByOptions(str):
    CreationTime = "CreationTime"


class ListWorkforcesSortByOptions(str):
    Name = "Name"
    CreateDate = "CreateDate"


class ListWorkteamsSortByOptions(str):
    Name = "Name"
    CreateDate = "CreateDate"


class MetricSetSource(str):
    Train = "Train"
    Validation = "Validation"
    Test = "Test"


class ModelApprovalStatus(str):
    Approved = "Approved"
    Rejected = "Rejected"
    PendingManualApproval = "PendingManualApproval"


class ModelCacheSetting(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ModelMetadataFilterType(str):
    Domain = "Domain"
    Framework = "Framework"
    Task = "Task"
    FrameworkVersion = "FrameworkVersion"


class ModelPackageGroupSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class ModelPackageGroupStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Deleting = "Deleting"
    DeleteFailed = "DeleteFailed"


class ModelPackageSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class ModelPackageStatus(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Deleting = "Deleting"


class ModelPackageType(str):
    Versioned = "Versioned"
    Unversioned = "Unversioned"
    Both = "Both"


class ModelSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"


class MonitoringExecutionSortKey(str):
    CreationTime = "CreationTime"
    ScheduledTime = "ScheduledTime"
    Status = "Status"


class MonitoringJobDefinitionSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"


class MonitoringProblemType(str):
    BinaryClassification = "BinaryClassification"
    MulticlassClassification = "MulticlassClassification"
    Regression = "Regression"


class MonitoringScheduleSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class MonitoringType(str):
    DataQuality = "DataQuality"
    ModelQuality = "ModelQuality"
    ModelBias = "ModelBias"
    ModelExplainability = "ModelExplainability"


class NotebookInstanceAcceleratorType(str):
    ml_eia1_medium = "ml.eia1.medium"
    ml_eia1_large = "ml.eia1.large"
    ml_eia1_xlarge = "ml.eia1.xlarge"
    ml_eia2_medium = "ml.eia2.medium"
    ml_eia2_large = "ml.eia2.large"
    ml_eia2_xlarge = "ml.eia2.xlarge"


class NotebookInstanceLifecycleConfigSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"
    LastModifiedTime = "LastModifiedTime"


class NotebookInstanceLifecycleConfigSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class NotebookInstanceSortKey(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class NotebookInstanceSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class NotebookInstanceStatus(str):
    Pending = "Pending"
    InService = "InService"
    Stopping = "Stopping"
    Stopped = "Stopped"
    Failed = "Failed"
    Deleting = "Deleting"
    Updating = "Updating"


class NotebookOutputOption(str):
    Allowed = "Allowed"
    Disabled = "Disabled"


class ObjectiveStatus(str):
    Succeeded = "Succeeded"
    Pending = "Pending"
    Failed = "Failed"


class OfflineStoreStatusValue(str):
    Active = "Active"
    Blocked = "Blocked"
    Disabled = "Disabled"


class Operator(str):
    Equals = "Equals"
    NotEquals = "NotEquals"
    GreaterThan = "GreaterThan"
    GreaterThanOrEqualTo = "GreaterThanOrEqualTo"
    LessThan = "LessThan"
    LessThanOrEqualTo = "LessThanOrEqualTo"
    Contains = "Contains"
    Exists = "Exists"
    NotExists = "NotExists"
    In = "In"


class OrderKey(str):
    Ascending = "Ascending"
    Descending = "Descending"


class ParameterType(str):
    Integer = "Integer"
    Continuous = "Continuous"
    Categorical = "Categorical"
    FreeText = "FreeText"


class PipelineExecutionStatus(str):
    Executing = "Executing"
    Stopping = "Stopping"
    Stopped = "Stopped"
    Failed = "Failed"
    Succeeded = "Succeeded"


class PipelineStatus(str):
    Active = "Active"


class ProblemType(str):
    BinaryClassification = "BinaryClassification"
    MulticlassClassification = "MulticlassClassification"
    Regression = "Regression"


class ProcessingInstanceType(str):
    ml_t3_medium = "ml.t3.medium"
    ml_t3_large = "ml.t3.large"
    ml_t3_xlarge = "ml.t3.xlarge"
    ml_t3_2xlarge = "ml.t3.2xlarge"
    ml_m4_xlarge = "ml.m4.xlarge"
    ml_m4_2xlarge = "ml.m4.2xlarge"
    ml_m4_4xlarge = "ml.m4.4xlarge"
    ml_m4_10xlarge = "ml.m4.10xlarge"
    ml_m4_16xlarge = "ml.m4.16xlarge"
    ml_c4_xlarge = "ml.c4.xlarge"
    ml_c4_2xlarge = "ml.c4.2xlarge"
    ml_c4_4xlarge = "ml.c4.4xlarge"
    ml_c4_8xlarge = "ml.c4.8xlarge"
    ml_p2_xlarge = "ml.p2.xlarge"
    ml_p2_8xlarge = "ml.p2.8xlarge"
    ml_p2_16xlarge = "ml.p2.16xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_m5_large = "ml.m5.large"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_r5_large = "ml.r5.large"
    ml_r5_xlarge = "ml.r5.xlarge"
    ml_r5_2xlarge = "ml.r5.2xlarge"
    ml_r5_4xlarge = "ml.r5.4xlarge"
    ml_r5_8xlarge = "ml.r5.8xlarge"
    ml_r5_12xlarge = "ml.r5.12xlarge"
    ml_r5_16xlarge = "ml.r5.16xlarge"
    ml_r5_24xlarge = "ml.r5.24xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"


class ProcessingJobStatus(str):
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class ProcessingS3CompressionType(str):
    None_ = "None"
    Gzip = "Gzip"


class ProcessingS3DataDistributionType(str):
    FullyReplicated = "FullyReplicated"
    ShardedByS3Key = "ShardedByS3Key"


class ProcessingS3DataType(str):
    ManifestFile = "ManifestFile"
    S3Prefix = "S3Prefix"


class ProcessingS3InputMode(str):
    Pipe = "Pipe"
    File = "File"


class ProcessingS3UploadMode(str):
    Continuous = "Continuous"
    EndOfJob = "EndOfJob"


class ProductionVariantAcceleratorType(str):
    ml_eia1_medium = "ml.eia1.medium"
    ml_eia1_large = "ml.eia1.large"
    ml_eia1_xlarge = "ml.eia1.xlarge"
    ml_eia2_medium = "ml.eia2.medium"
    ml_eia2_large = "ml.eia2.large"
    ml_eia2_xlarge = "ml.eia2.xlarge"


class ProductionVariantInstanceType(str):
    ml_t2_medium = "ml.t2.medium"
    ml_t2_large = "ml.t2.large"
    ml_t2_xlarge = "ml.t2.xlarge"
    ml_t2_2xlarge = "ml.t2.2xlarge"
    ml_m4_xlarge = "ml.m4.xlarge"
    ml_m4_2xlarge = "ml.m4.2xlarge"
    ml_m4_4xlarge = "ml.m4.4xlarge"
    ml_m4_10xlarge = "ml.m4.10xlarge"
    ml_m4_16xlarge = "ml.m4.16xlarge"
    ml_m5_large = "ml.m5.large"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_m5d_large = "ml.m5d.large"
    ml_m5d_xlarge = "ml.m5d.xlarge"
    ml_m5d_2xlarge = "ml.m5d.2xlarge"
    ml_m5d_4xlarge = "ml.m5d.4xlarge"
    ml_m5d_12xlarge = "ml.m5d.12xlarge"
    ml_m5d_24xlarge = "ml.m5d.24xlarge"
    ml_c4_large = "ml.c4.large"
    ml_c4_xlarge = "ml.c4.xlarge"
    ml_c4_2xlarge = "ml.c4.2xlarge"
    ml_c4_4xlarge = "ml.c4.4xlarge"
    ml_c4_8xlarge = "ml.c4.8xlarge"
    ml_p2_xlarge = "ml.p2.xlarge"
    ml_p2_8xlarge = "ml.p2.8xlarge"
    ml_p2_16xlarge = "ml.p2.16xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_c5_large = "ml.c5.large"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_c5d_large = "ml.c5d.large"
    ml_c5d_xlarge = "ml.c5d.xlarge"
    ml_c5d_2xlarge = "ml.c5d.2xlarge"
    ml_c5d_4xlarge = "ml.c5d.4xlarge"
    ml_c5d_9xlarge = "ml.c5d.9xlarge"
    ml_c5d_18xlarge = "ml.c5d.18xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"
    ml_r5_large = "ml.r5.large"
    ml_r5_xlarge = "ml.r5.xlarge"
    ml_r5_2xlarge = "ml.r5.2xlarge"
    ml_r5_4xlarge = "ml.r5.4xlarge"
    ml_r5_12xlarge = "ml.r5.12xlarge"
    ml_r5_24xlarge = "ml.r5.24xlarge"
    ml_r5d_large = "ml.r5d.large"
    ml_r5d_xlarge = "ml.r5d.xlarge"
    ml_r5d_2xlarge = "ml.r5d.2xlarge"
    ml_r5d_4xlarge = "ml.r5d.4xlarge"
    ml_r5d_12xlarge = "ml.r5d.12xlarge"
    ml_r5d_24xlarge = "ml.r5d.24xlarge"
    ml_inf1_xlarge = "ml.inf1.xlarge"
    ml_inf1_2xlarge = "ml.inf1.2xlarge"
    ml_inf1_6xlarge = "ml.inf1.6xlarge"
    ml_inf1_24xlarge = "ml.inf1.24xlarge"


class ProfilingStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ProjectSortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class ProjectSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class ProjectStatus(str):
    Pending = "Pending"
    CreateInProgress = "CreateInProgress"
    CreateCompleted = "CreateCompleted"
    CreateFailed = "CreateFailed"
    DeleteInProgress = "DeleteInProgress"
    DeleteFailed = "DeleteFailed"
    DeleteCompleted = "DeleteCompleted"
    UpdateInProgress = "UpdateInProgress"
    UpdateCompleted = "UpdateCompleted"
    UpdateFailed = "UpdateFailed"


class RStudioServerProAccessStatus(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class RStudioServerProUserGroup(str):
    R_STUDIO_ADMIN = "R_STUDIO_ADMIN"
    R_STUDIO_USER = "R_STUDIO_USER"


class RecommendationJobStatus(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class RecommendationJobType(str):
    Default = "Default"
    Advanced = "Advanced"


class RecordWrapper(str):
    None_ = "None"
    RecordIO = "RecordIO"


class RedshiftResultCompressionType(str):
    None_ = "None"
    GZIP = "GZIP"
    BZIP2 = "BZIP2"
    ZSTD = "ZSTD"
    SNAPPY = "SNAPPY"


class RedshiftResultFormat(str):
    PARQUET = "PARQUET"
    CSV = "CSV"


class RepositoryAccessMode(str):
    Platform = "Platform"
    Vpc = "Vpc"


class ResourceType(str):
    TrainingJob = "TrainingJob"
    Experiment = "Experiment"
    ExperimentTrial = "ExperimentTrial"
    ExperimentTrialComponent = "ExperimentTrialComponent"
    Endpoint = "Endpoint"
    ModelPackage = "ModelPackage"
    ModelPackageGroup = "ModelPackageGroup"
    Pipeline = "Pipeline"
    PipelineExecution = "PipelineExecution"
    FeatureGroup = "FeatureGroup"
    Project = "Project"


class RetentionType(str):
    Retain = "Retain"
    Delete = "Delete"


class RootAccess(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class RuleEvaluationStatus(str):
    InProgress = "InProgress"
    NoIssuesFound = "NoIssuesFound"
    IssuesFound = "IssuesFound"
    Error = "Error"
    Stopping = "Stopping"
    Stopped = "Stopped"


class S3DataDistribution(str):
    FullyReplicated = "FullyReplicated"
    ShardedByS3Key = "ShardedByS3Key"


class S3DataType(str):
    ManifestFile = "ManifestFile"
    S3Prefix = "S3Prefix"
    AugmentedManifestFile = "AugmentedManifestFile"


class SagemakerServicecatalogStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ScheduleStatus(str):
    Pending = "Pending"
    Failed = "Failed"
    Scheduled = "Scheduled"
    Stopped = "Stopped"


class SearchSortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class SecondaryStatus(str):
    Starting = "Starting"
    LaunchingMLInstances = "LaunchingMLInstances"
    PreparingTrainingStack = "PreparingTrainingStack"
    Downloading = "Downloading"
    DownloadingTrainingImage = "DownloadingTrainingImage"
    Training = "Training"
    Uploading = "Uploading"
    Stopping = "Stopping"
    Stopped = "Stopped"
    MaxRuntimeExceeded = "MaxRuntimeExceeded"
    Completed = "Completed"
    Failed = "Failed"
    Interrupted = "Interrupted"
    MaxWaitTimeExceeded = "MaxWaitTimeExceeded"
    Updating = "Updating"
    Restarting = "Restarting"


class SortActionsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortArtifactsBy(str):
    CreationTime = "CreationTime"


class SortAssociationsBy(str):
    SourceArn = "SourceArn"
    DestinationArn = "DestinationArn"
    SourceType = "SourceType"
    DestinationType = "DestinationType"
    CreationTime = "CreationTime"


class SortBy(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"


class SortContextsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortExperimentsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortLineageGroupsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortOrder(str):
    Ascending = "Ascending"
    Descending = "Descending"


class SortPipelineExecutionsBy(str):
    CreationTime = "CreationTime"
    PipelineExecutionArn = "PipelineExecutionArn"


class SortPipelinesBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortTrialComponentsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SortTrialsBy(str):
    Name = "Name"
    CreationTime = "CreationTime"


class SplitType(str):
    None_ = "None"
    Line = "Line"
    RecordIO = "RecordIO"
    TFRecord = "TFRecord"


class StepStatus(str):
    Starting = "Starting"
    Executing = "Executing"
    Stopping = "Stopping"
    Stopped = "Stopped"
    Failed = "Failed"
    Succeeded = "Succeeded"


class StudioLifecycleConfigAppType(str):
    JupyterServer = "JupyterServer"
    KernelGateway = "KernelGateway"


class StudioLifecycleConfigSortKey(str):
    CreationTime = "CreationTime"
    LastModifiedTime = "LastModifiedTime"
    Name = "Name"


class TargetDevice(str):
    lambda_ = "lambda"
    ml_m4 = "ml_m4"
    ml_m5 = "ml_m5"
    ml_c4 = "ml_c4"
    ml_c5 = "ml_c5"
    ml_p2 = "ml_p2"
    ml_p3 = "ml_p3"
    ml_g4dn = "ml_g4dn"
    ml_inf1 = "ml_inf1"
    ml_eia2 = "ml_eia2"
    jetson_tx1 = "jetson_tx1"
    jetson_tx2 = "jetson_tx2"
    jetson_nano = "jetson_nano"
    jetson_xavier = "jetson_xavier"
    rasp3b = "rasp3b"
    imx8qm = "imx8qm"
    deeplens = "deeplens"
    rk3399 = "rk3399"
    rk3288 = "rk3288"
    aisage = "aisage"
    sbe_c = "sbe_c"
    qcs605 = "qcs605"
    qcs603 = "qcs603"
    sitara_am57x = "sitara_am57x"
    amba_cv2 = "amba_cv2"
    amba_cv22 = "amba_cv22"
    amba_cv25 = "amba_cv25"
    x86_win32 = "x86_win32"
    x86_win64 = "x86_win64"
    coreml = "coreml"
    jacinto_tda4vm = "jacinto_tda4vm"
    imx8mplus = "imx8mplus"


class TargetPlatformAccelerator(str):
    INTEL_GRAPHICS = "INTEL_GRAPHICS"
    MALI = "MALI"
    NVIDIA = "NVIDIA"
    NNA = "NNA"


class TargetPlatformArch(str):
    X86_64 = "X86_64"
    X86 = "X86"
    ARM64 = "ARM64"
    ARM_EABI = "ARM_EABI"
    ARM_EABIHF = "ARM_EABIHF"


class TargetPlatformOs(str):
    ANDROID = "ANDROID"
    LINUX = "LINUX"


class TrafficRoutingConfigType(str):
    ALL_AT_ONCE = "ALL_AT_ONCE"
    CANARY = "CANARY"
    LINEAR = "LINEAR"


class TrafficType(str):
    PHASES = "PHASES"


class TrainingInputMode(str):
    Pipe = "Pipe"
    File = "File"
    FastFile = "FastFile"


class TrainingInstanceType(str):
    ml_m4_xlarge = "ml.m4.xlarge"
    ml_m4_2xlarge = "ml.m4.2xlarge"
    ml_m4_4xlarge = "ml.m4.4xlarge"
    ml_m4_10xlarge = "ml.m4.10xlarge"
    ml_m4_16xlarge = "ml.m4.16xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"
    ml_m5_large = "ml.m5.large"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_c4_xlarge = "ml.c4.xlarge"
    ml_c4_2xlarge = "ml.c4.2xlarge"
    ml_c4_4xlarge = "ml.c4.4xlarge"
    ml_c4_8xlarge = "ml.c4.8xlarge"
    ml_p2_xlarge = "ml.p2.xlarge"
    ml_p2_8xlarge = "ml.p2.8xlarge"
    ml_p2_16xlarge = "ml.p2.16xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_p3dn_24xlarge = "ml.p3dn.24xlarge"
    ml_p4d_24xlarge = "ml.p4d.24xlarge"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_c5n_xlarge = "ml.c5n.xlarge"
    ml_c5n_2xlarge = "ml.c5n.2xlarge"
    ml_c5n_4xlarge = "ml.c5n.4xlarge"
    ml_c5n_9xlarge = "ml.c5n.9xlarge"
    ml_c5n_18xlarge = "ml.c5n.18xlarge"
    ml_g5_xlarge = "ml.g5.xlarge"
    ml_g5_2xlarge = "ml.g5.2xlarge"
    ml_g5_4xlarge = "ml.g5.4xlarge"
    ml_g5_8xlarge = "ml.g5.8xlarge"
    ml_g5_16xlarge = "ml.g5.16xlarge"
    ml_g5_12xlarge = "ml.g5.12xlarge"
    ml_g5_24xlarge = "ml.g5.24xlarge"
    ml_g5_48xlarge = "ml.g5.48xlarge"


class TrainingJobEarlyStoppingType(str):
    Off = "Off"
    Auto = "Auto"


class TrainingJobSortByOptions(str):
    Name = "Name"
    CreationTime = "CreationTime"
    Status = "Status"
    FinalObjectiveMetricValue = "FinalObjectiveMetricValue"


class TrainingJobStatus(str):
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class TransformInstanceType(str):
    ml_m4_xlarge = "ml.m4.xlarge"
    ml_m4_2xlarge = "ml.m4.2xlarge"
    ml_m4_4xlarge = "ml.m4.4xlarge"
    ml_m4_10xlarge = "ml.m4.10xlarge"
    ml_m4_16xlarge = "ml.m4.16xlarge"
    ml_c4_xlarge = "ml.c4.xlarge"
    ml_c4_2xlarge = "ml.c4.2xlarge"
    ml_c4_4xlarge = "ml.c4.4xlarge"
    ml_c4_8xlarge = "ml.c4.8xlarge"
    ml_p2_xlarge = "ml.p2.xlarge"
    ml_p2_8xlarge = "ml.p2.8xlarge"
    ml_p2_16xlarge = "ml.p2.16xlarge"
    ml_p3_2xlarge = "ml.p3.2xlarge"
    ml_p3_8xlarge = "ml.p3.8xlarge"
    ml_p3_16xlarge = "ml.p3.16xlarge"
    ml_c5_xlarge = "ml.c5.xlarge"
    ml_c5_2xlarge = "ml.c5.2xlarge"
    ml_c5_4xlarge = "ml.c5.4xlarge"
    ml_c5_9xlarge = "ml.c5.9xlarge"
    ml_c5_18xlarge = "ml.c5.18xlarge"
    ml_m5_large = "ml.m5.large"
    ml_m5_xlarge = "ml.m5.xlarge"
    ml_m5_2xlarge = "ml.m5.2xlarge"
    ml_m5_4xlarge = "ml.m5.4xlarge"
    ml_m5_12xlarge = "ml.m5.12xlarge"
    ml_m5_24xlarge = "ml.m5.24xlarge"
    ml_g4dn_xlarge = "ml.g4dn.xlarge"
    ml_g4dn_2xlarge = "ml.g4dn.2xlarge"
    ml_g4dn_4xlarge = "ml.g4dn.4xlarge"
    ml_g4dn_8xlarge = "ml.g4dn.8xlarge"
    ml_g4dn_12xlarge = "ml.g4dn.12xlarge"
    ml_g4dn_16xlarge = "ml.g4dn.16xlarge"


class TransformJobStatus(str):
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class TrialComponentPrimaryStatus(str):
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Stopping = "Stopping"
    Stopped = "Stopped"


class UserProfileSortKey(str):
    CreationTime = "CreationTime"
    LastModifiedTime = "LastModifiedTime"


class UserProfileStatus(str):
    Deleting = "Deleting"
    Failed = "Failed"
    InService = "InService"
    Pending = "Pending"
    Updating = "Updating"
    Update_Failed = "Update_Failed"
    Delete_Failed = "Delete_Failed"


class VariantPropertyType(str):
    DesiredInstanceCount = "DesiredInstanceCount"
    DesiredWeight = "DesiredWeight"
    DataCaptureConfig = "DataCaptureConfig"


class VariantStatus(str):
    Creating = "Creating"
    Updating = "Updating"
    Deleting = "Deleting"
    ActivatingTraffic = "ActivatingTraffic"
    Baking = "Baking"


class ConflictException(ServiceException):
    Message: Optional[FailureReason]


class ResourceInUse(ServiceException):
    Message: Optional[FailureReason]


class ResourceLimitExceeded(ServiceException):
    Message: Optional[FailureReason]


class ResourceNotFound(ServiceException):
    Message: Optional[FailureReason]


class ActionSource(TypedDict, total=False):
    SourceUri: String2048
    SourceType: Optional[String256]
    SourceId: Optional[String256]


Timestamp = datetime


class ActionSummary(TypedDict, total=False):
    ActionArn: Optional[ActionArn]
    ActionName: Optional[ExperimentEntityName]
    Source: Optional[ActionSource]
    ActionType: Optional[String64]
    Status: Optional[ActionStatus]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


ActionSummaries = List[ActionSummary]


class AddAssociationRequest(ServiceRequest):
    SourceArn: AssociationEntityArn
    DestinationArn: AssociationEntityArn
    AssociationType: Optional[AssociationEdgeType]


class AddAssociationResponse(TypedDict, total=False):
    SourceArn: Optional[AssociationEntityArn]
    DestinationArn: Optional[AssociationEntityArn]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class AddTagsInput(ServiceRequest):
    ResourceArn: ResourceArn
    Tags: TagList


class AddTagsOutput(TypedDict, total=False):
    Tags: Optional[TagList]


AdditionalCodeRepositoryNamesOrUrls = List[CodeRepositoryNameOrUrl]
ResponseMIMETypes = List[ResponseMIMEType]
ContentTypes = List[ContentType]
RealtimeInferenceInstanceTypes = List[ProductionVariantInstanceType]
TransformInstanceTypes = List[TransformInstanceType]


class ModelInput(TypedDict, total=False):
    DataInputConfig: DataInputConfig


EnvironmentMap = Dict[EnvironmentKey, EnvironmentValue]


class ModelPackageContainerDefinition(TypedDict, total=False):
    ContainerHostname: Optional[ContainerHostname]
    Image: ContainerImage
    ImageDigest: Optional[ImageDigest]
    ModelDataUrl: Optional[Url]
    ProductId: Optional[ProductId]
    Environment: Optional[EnvironmentMap]
    ModelInput: Optional[ModelInput]
    Framework: Optional[String]
    FrameworkVersion: Optional[FrameworkVersion]
    NearestModelName: Optional[String]


ModelPackageContainerDefinitionList = List[ModelPackageContainerDefinition]


class AdditionalInferenceSpecificationDefinition(TypedDict, total=False):
    Name: EntityName
    Description: Optional[EntityDescription]
    Containers: ModelPackageContainerDefinitionList
    SupportedTransformInstanceTypes: Optional[TransformInstanceTypes]
    SupportedRealtimeInferenceInstanceTypes: Optional[RealtimeInferenceInstanceTypes]
    SupportedContentTypes: Optional[ContentTypes]
    SupportedResponseMIMETypes: Optional[ResponseMIMETypes]


AdditionalInferenceSpecifications = List[AdditionalInferenceSpecificationDefinition]
Long = int


class AgentVersion(TypedDict, total=False):
    Version: EdgeVersion
    AgentCount: Long


AgentVersions = List[AgentVersion]


class Alarm(TypedDict, total=False):
    AlarmName: Optional[AlarmName]


AlarmList = List[Alarm]


class MetricDefinition(TypedDict, total=False):
    Name: MetricName
    Regex: MetricRegex


MetricDefinitionList = List[MetricDefinition]


class AlgorithmSpecification(TypedDict, total=False):
    TrainingImage: Optional[AlgorithmImage]
    AlgorithmName: Optional[ArnOrName]
    TrainingInputMode: TrainingInputMode
    MetricDefinitions: Optional[MetricDefinitionList]
    EnableSageMakerMetricsTimeSeries: Optional[Boolean]


class AlgorithmStatusItem(TypedDict, total=False):
    Name: EntityName
    Status: DetailedAlgorithmStatus
    FailureReason: Optional[String]


AlgorithmStatusItemList = List[AlgorithmStatusItem]


class AlgorithmStatusDetails(TypedDict, total=False):
    ValidationStatuses: Optional[AlgorithmStatusItemList]
    ImageScanStatuses: Optional[AlgorithmStatusItemList]


CreationTime = datetime


class AlgorithmSummary(TypedDict, total=False):
    AlgorithmName: EntityName
    AlgorithmArn: AlgorithmArn
    AlgorithmDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    AlgorithmStatus: AlgorithmStatus


AlgorithmSummaryList = List[AlgorithmSummary]


class TransformResources(TypedDict, total=False):
    InstanceType: TransformInstanceType
    InstanceCount: TransformInstanceCount
    VolumeKmsKeyId: Optional[KmsKeyId]


class TransformOutput(TypedDict, total=False):
    S3OutputPath: S3Uri
    Accept: Optional[Accept]
    AssembleWith: Optional[AssemblyType]
    KmsKeyId: Optional[KmsKeyId]


class TransformS3DataSource(TypedDict, total=False):
    S3DataType: S3DataType
    S3Uri: S3Uri


class TransformDataSource(TypedDict, total=False):
    S3DataSource: TransformS3DataSource


class TransformInput(TypedDict, total=False):
    DataSource: TransformDataSource
    ContentType: Optional[ContentType]
    CompressionType: Optional[CompressionType]
    SplitType: Optional[SplitType]


TransformEnvironmentMap = Dict[TransformEnvironmentKey, TransformEnvironmentValue]


class TransformJobDefinition(TypedDict, total=False):
    MaxConcurrentTransforms: Optional[MaxConcurrentTransforms]
    MaxPayloadInMB: Optional[MaxPayloadInMB]
    BatchStrategy: Optional[BatchStrategy]
    Environment: Optional[TransformEnvironmentMap]
    TransformInput: TransformInput
    TransformOutput: TransformOutput
    TransformResources: TransformResources


class StoppingCondition(TypedDict, total=False):
    MaxRuntimeInSeconds: Optional[MaxRuntimeInSeconds]
    MaxWaitTimeInSeconds: Optional[MaxWaitTimeInSeconds]


class ResourceConfig(TypedDict, total=False):
    InstanceType: TrainingInstanceType
    InstanceCount: TrainingInstanceCount
    VolumeSizeInGB: VolumeSizeInGB
    VolumeKmsKeyId: Optional[KmsKeyId]


class OutputDataConfig(TypedDict, total=False):
    KmsKeyId: Optional[KmsKeyId]
    S3OutputPath: S3Uri


Seed = int


class ShuffleConfig(TypedDict, total=False):
    Seed: Seed


class FileSystemDataSource(TypedDict, total=False):
    FileSystemId: FileSystemId
    FileSystemAccessMode: FileSystemAccessMode
    FileSystemType: FileSystemType
    DirectoryPath: DirectoryPath


AttributeNames = List[AttributeName]


class S3DataSource(TypedDict, total=False):
    S3DataType: S3DataType
    S3Uri: S3Uri
    S3DataDistributionType: Optional[S3DataDistribution]
    AttributeNames: Optional[AttributeNames]


class DataSource(TypedDict, total=False):
    S3DataSource: Optional[S3DataSource]
    FileSystemDataSource: Optional[FileSystemDataSource]


class Channel(TypedDict, total=False):
    ChannelName: ChannelName
    DataSource: DataSource
    ContentType: Optional[ContentType]
    CompressionType: Optional[CompressionType]
    RecordWrapperType: Optional[RecordWrapper]
    InputMode: Optional[TrainingInputMode]
    ShuffleConfig: Optional[ShuffleConfig]


InputDataConfig = List[Channel]
HyperParameters = Dict[HyperParameterKey, HyperParameterValue]


class TrainingJobDefinition(TypedDict, total=False):
    TrainingInputMode: TrainingInputMode
    HyperParameters: Optional[HyperParameters]
    InputDataConfig: InputDataConfig
    OutputDataConfig: OutputDataConfig
    ResourceConfig: ResourceConfig
    StoppingCondition: StoppingCondition


class AlgorithmValidationProfile(TypedDict, total=False):
    ProfileName: EntityName
    TrainingJobDefinition: TrainingJobDefinition
    TransformJobDefinition: Optional[TransformJobDefinition]


AlgorithmValidationProfiles = List[AlgorithmValidationProfile]


class AlgorithmValidationSpecification(TypedDict, total=False):
    ValidationRole: RoleArn
    ValidationProfiles: AlgorithmValidationProfiles


class AnnotationConsolidationConfig(TypedDict, total=False):
    AnnotationConsolidationLambdaArn: LambdaFunctionArn


class AppDetails(TypedDict, total=False):
    DomainId: Optional[DomainId]
    UserProfileName: Optional[UserProfileName]
    AppType: Optional[AppType]
    AppName: Optional[AppName]
    Status: Optional[AppStatus]
    CreationTime: Optional[CreationTime]


class FileSystemConfig(TypedDict, total=False):
    MountPath: Optional[MountPath]
    DefaultUid: Optional[DefaultUid]
    DefaultGid: Optional[DefaultGid]


class KernelSpec(TypedDict, total=False):
    Name: KernelName
    DisplayName: Optional[KernelDisplayName]


KernelSpecs = List[KernelSpec]


class KernelGatewayImageConfig(TypedDict, total=False):
    KernelSpecs: KernelSpecs
    FileSystemConfig: Optional[FileSystemConfig]


class AppImageConfigDetails(TypedDict, total=False):
    AppImageConfigArn: Optional[AppImageConfigArn]
    AppImageConfigName: Optional[AppImageConfigName]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    KernelGatewayImageConfig: Optional[KernelGatewayImageConfig]


AppImageConfigList = List[AppImageConfigDetails]
AppList = List[AppDetails]
ContainerArguments = List[ContainerArgument]
ContainerEntrypoint = List[ContainerEntrypointString]


class AppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ContainerEntrypoint: Optional[ContainerEntrypoint]
    ContainerArguments: Optional[ContainerArguments]


class ArtifactSourceType(TypedDict, total=False):
    SourceIdType: ArtifactSourceIdType
    Value: String256


ArtifactSourceTypes = List[ArtifactSourceType]


class ArtifactSource(TypedDict, total=False):
    SourceUri: String2048
    SourceTypes: Optional[ArtifactSourceTypes]


class ArtifactSummary(TypedDict, total=False):
    ArtifactArn: Optional[ArtifactArn]
    ArtifactName: Optional[ExperimentEntityName]
    Source: Optional[ArtifactSource]
    ArtifactType: Optional[String256]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


ArtifactSummaries = List[ArtifactSummary]


class AssociateTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityName
    TrialName: ExperimentEntityName


class AssociateTrialComponentResponse(TypedDict, total=False):
    TrialComponentArn: Optional[TrialComponentArn]
    TrialArn: Optional[TrialArn]


class UserContext(TypedDict, total=False):
    UserProfileArn: Optional[String]
    UserProfileName: Optional[String]
    DomainId: Optional[String]


class AssociationSummary(TypedDict, total=False):
    SourceArn: Optional[AssociationEntityArn]
    DestinationArn: Optional[AssociationEntityArn]
    SourceType: Optional[String256]
    DestinationType: Optional[String256]
    AssociationType: Optional[AssociationEdgeType]
    SourceName: Optional[ExperimentEntityName]
    DestinationName: Optional[ExperimentEntityName]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]


AssociationSummaries = List[AssociationSummary]


class AsyncInferenceClientConfig(TypedDict, total=False):
    MaxConcurrentInvocationsPerInstance: Optional[MaxConcurrentInvocationsPerInstance]


class AsyncInferenceNotificationConfig(TypedDict, total=False):
    SuccessTopic: Optional[SnsTopicArn]
    ErrorTopic: Optional[SnsTopicArn]


class AsyncInferenceOutputConfig(TypedDict, total=False):
    KmsKeyId: Optional[KmsKeyId]
    S3OutputPath: DestinationS3Uri
    NotificationConfig: Optional[AsyncInferenceNotificationConfig]


class AsyncInferenceConfig(TypedDict, total=False):
    ClientConfig: Optional[AsyncInferenceClientConfig]
    OutputConfig: AsyncInferenceOutputConfig


class AthenaDatasetDefinition(TypedDict, total=False):
    Catalog: AthenaCatalog
    Database: AthenaDatabase
    QueryString: AthenaQueryString
    WorkGroup: Optional[AthenaWorkGroup]
    OutputS3Uri: S3Uri
    KmsKeyId: Optional[KmsKeyId]
    OutputFormat: AthenaResultFormat
    OutputCompression: Optional[AthenaResultCompressionType]


class MetricDatum(TypedDict, total=False):
    MetricName: Optional[AutoMLMetricEnum]
    Value: Optional[Float]
    Set: Optional[MetricSetSource]


MetricDataList = List[MetricDatum]


class CandidateArtifactLocations(TypedDict, total=False):
    Explainability: ExplainabilityLocation
    ModelInsights: Optional[ModelInsightsLocation]


class CandidateProperties(TypedDict, total=False):
    CandidateArtifactLocations: Optional[CandidateArtifactLocations]
    CandidateMetrics: Optional[MetricDataList]


class AutoMLContainerDefinition(TypedDict, total=False):
    Image: ContainerImage
    ModelDataUrl: Url
    Environment: Optional[EnvironmentMap]


AutoMLContainerDefinitions = List[AutoMLContainerDefinition]


class AutoMLCandidateStep(TypedDict, total=False):
    CandidateStepType: CandidateStepType
    CandidateStepArn: CandidateStepArn
    CandidateStepName: CandidateStepName


CandidateSteps = List[AutoMLCandidateStep]


class FinalAutoMLJobObjectiveMetric(TypedDict, total=False):
    Type: Optional[AutoMLJobObjectiveType]
    MetricName: AutoMLMetricEnum
    Value: MetricValue


class AutoMLCandidate(TypedDict, total=False):
    CandidateName: CandidateName
    FinalAutoMLJobObjectiveMetric: Optional[FinalAutoMLJobObjectiveMetric]
    ObjectiveStatus: ObjectiveStatus
    CandidateSteps: CandidateSteps
    CandidateStatus: CandidateStatus
    InferenceContainers: Optional[AutoMLContainerDefinitions]
    CreationTime: Timestamp
    EndTime: Optional[Timestamp]
    LastModifiedTime: Timestamp
    FailureReason: Optional[AutoMLFailureReason]
    CandidateProperties: Optional[CandidateProperties]


AutoMLCandidates = List[AutoMLCandidate]


class AutoMLS3DataSource(TypedDict, total=False):
    S3DataType: AutoMLS3DataType
    S3Uri: S3Uri


class AutoMLDataSource(TypedDict, total=False):
    S3DataSource: AutoMLS3DataSource


class AutoMLChannel(TypedDict, total=False):
    DataSource: AutoMLDataSource
    CompressionType: Optional[CompressionType]
    TargetAttributeName: TargetAttributeName
    ContentType: Optional[ContentType]


AutoMLInputDataConfig = List[AutoMLChannel]


class AutoMLJobArtifacts(TypedDict, total=False):
    CandidateDefinitionNotebookLocation: Optional[CandidateDefinitionNotebookLocation]
    DataExplorationNotebookLocation: Optional[DataExplorationNotebookLocation]


class AutoMLJobCompletionCriteria(TypedDict, total=False):
    MaxCandidates: Optional[MaxCandidates]
    MaxRuntimePerTrainingJobInSeconds: Optional[MaxRuntimePerTrainingJobInSeconds]
    MaxAutoMLJobRuntimeInSeconds: Optional[MaxAutoMLJobRuntimeInSeconds]


Subnets = List[SubnetId]
VpcSecurityGroupIds = List[SecurityGroupId]


class VpcConfig(TypedDict, total=False):
    SecurityGroupIds: VpcSecurityGroupIds
    Subnets: Subnets


class AutoMLSecurityConfig(TypedDict, total=False):
    VolumeKmsKeyId: Optional[KmsKeyId]
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    VpcConfig: Optional[VpcConfig]


class AutoMLJobConfig(TypedDict, total=False):
    CompletionCriteria: Optional[AutoMLJobCompletionCriteria]
    SecurityConfig: Optional[AutoMLSecurityConfig]


class AutoMLJobObjective(TypedDict, total=False):
    MetricName: AutoMLMetricEnum


class AutoMLPartialFailureReason(TypedDict, total=False):
    PartialFailureMessage: Optional[AutoMLFailureReason]


AutoMLPartialFailureReasons = List[AutoMLPartialFailureReason]


class AutoMLJobSummary(TypedDict, total=False):
    AutoMLJobName: AutoMLJobName
    AutoMLJobArn: AutoMLJobArn
    AutoMLJobStatus: AutoMLJobStatus
    AutoMLJobSecondaryStatus: AutoMLJobSecondaryStatus
    CreationTime: Timestamp
    EndTime: Optional[Timestamp]
    LastModifiedTime: Timestamp
    FailureReason: Optional[AutoMLFailureReason]
    PartialFailureReasons: Optional[AutoMLPartialFailureReasons]


AutoMLJobSummaries = List[AutoMLJobSummary]


class AutoMLOutputDataConfig(TypedDict, total=False):
    KmsKeyId: Optional[KmsKeyId]
    S3OutputPath: S3Uri


class AutoRollbackConfig(TypedDict, total=False):
    Alarms: Optional[AlarmList]


class BatchDescribeModelPackageError(TypedDict, total=False):
    ErrorCode: String
    ErrorResponse: String


BatchDescribeModelPackageErrorMap = Dict[ModelPackageArn, BatchDescribeModelPackageError]
ModelPackageArnList = List[ModelPackageArn]


class BatchDescribeModelPackageInput(ServiceRequest):
    ModelPackageArnList: ModelPackageArnList


class InferenceSpecification(TypedDict, total=False):
    Containers: ModelPackageContainerDefinitionList
    SupportedTransformInstanceTypes: Optional[TransformInstanceTypes]
    SupportedRealtimeInferenceInstanceTypes: Optional[RealtimeInferenceInstanceTypes]
    SupportedContentTypes: ContentTypes
    SupportedResponseMIMETypes: ResponseMIMETypes


class BatchDescribeModelPackageSummary(TypedDict, total=False):
    ModelPackageGroupName: EntityName
    ModelPackageVersion: Optional[ModelPackageVersion]
    ModelPackageArn: ModelPackageArn
    ModelPackageDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    InferenceSpecification: InferenceSpecification
    ModelPackageStatus: ModelPackageStatus
    ModelApprovalStatus: Optional[ModelApprovalStatus]


ModelPackageSummaries = Dict[ModelPackageArn, BatchDescribeModelPackageSummary]


class BatchDescribeModelPackageOutput(TypedDict, total=False):
    ModelPackageSummaries: Optional[ModelPackageSummaries]
    BatchDescribeModelPackageErrorMap: Optional[BatchDescribeModelPackageErrorMap]


class MetricsSource(TypedDict, total=False):
    ContentType: ContentType
    ContentDigest: Optional[ContentDigest]
    S3Uri: S3Uri


class Bias(TypedDict, total=False):
    Report: Optional[MetricsSource]
    PreTrainingReport: Optional[MetricsSource]
    PostTrainingReport: Optional[MetricsSource]


class CapacitySize(TypedDict, total=False):
    Type: CapacitySizeType
    Value: CapacitySizeValue


class TrafficRoutingConfig(TypedDict, total=False):
    Type: TrafficRoutingConfigType
    WaitIntervalInSeconds: WaitIntervalInSeconds
    CanarySize: Optional[CapacitySize]
    LinearStepSize: Optional[CapacitySize]


class BlueGreenUpdatePolicy(TypedDict, total=False):
    TrafficRoutingConfiguration: TrafficRoutingConfig
    TerminationWaitInSeconds: Optional[TerminationWaitInSeconds]
    MaximumExecutionTimeoutInSeconds: Optional[MaximumExecutionTimeoutInSeconds]


class CacheHitResult(TypedDict, total=False):
    SourcePipelineExecutionArn: Optional[PipelineExecutionArn]


class OutputParameter(TypedDict, total=False):
    Name: String256
    Value: String1024


OutputParameterList = List[OutputParameter]


class CallbackStepMetadata(TypedDict, total=False):
    CallbackToken: Optional[CallbackToken]
    SqsQueueUrl: Optional[String256]
    OutputParameters: Optional[OutputParameterList]


JsonContentTypes = List[JsonContentType]
CsvContentTypes = List[CsvContentType]


class CaptureContentTypeHeader(TypedDict, total=False):
    CsvContentTypes: Optional[CsvContentTypes]
    JsonContentTypes: Optional[JsonContentTypes]


class CaptureOption(TypedDict, total=False):
    CaptureMode: CaptureMode


CaptureOptionList = List[CaptureOption]
CategoricalParameterRangeValues = List[String128]


class CategoricalParameter(TypedDict, total=False):
    Name: String64
    Value: CategoricalParameterRangeValues


ParameterValues = List[ParameterValue]


class CategoricalParameterRange(TypedDict, total=False):
    Name: ParameterKey
    Values: ParameterValues


class CategoricalParameterRangeSpecification(TypedDict, total=False):
    Values: ParameterValues


CategoricalParameterRanges = List[CategoricalParameterRange]
CategoricalParameters = List[CategoricalParameter]
InputModes = List[TrainingInputMode]
CompressionTypes = List[CompressionType]


class ChannelSpecification(TypedDict, total=False):
    Name: ChannelName
    Description: Optional[EntityDescription]
    IsRequired: Optional[Boolean]
    SupportedContentTypes: ContentTypes
    SupportedCompressionTypes: Optional[CompressionTypes]
    SupportedInputModes: InputModes


ChannelSpecifications = List[ChannelSpecification]


class CheckpointConfig(TypedDict, total=False):
    S3Uri: S3Uri
    LocalPath: Optional[DirectoryPath]


Cidrs = List[Cidr]


class ClarifyCheckStepMetadata(TypedDict, total=False):
    CheckType: Optional[String256]
    BaselineUsedForDriftCheckConstraints: Optional[String1024]
    CalculatedBaselineConstraints: Optional[String1024]
    ModelPackageGroupName: Optional[String256]
    ViolationReport: Optional[String1024]
    CheckJobArn: Optional[String256]
    SkipCheck: Optional[Boolean]
    RegisterNewBaseline: Optional[Boolean]


class GitConfig(TypedDict, total=False):
    RepositoryUrl: GitConfigUrl
    Branch: Optional[Branch]
    SecretArn: Optional[SecretArn]


LastModifiedTime = datetime


class CodeRepositorySummary(TypedDict, total=False):
    CodeRepositoryName: EntityName
    CodeRepositoryArn: CodeRepositoryArn
    CreationTime: CreationTime
    LastModifiedTime: LastModifiedTime
    GitConfig: Optional[GitConfig]


CodeRepositorySummaryList = List[CodeRepositorySummary]


class CognitoConfig(TypedDict, total=False):
    UserPool: CognitoUserPool
    ClientId: ClientId


class CognitoMemberDefinition(TypedDict, total=False):
    UserPool: CognitoUserPool
    UserGroup: CognitoUserGroup
    ClientId: ClientId


CollectionParameters = Dict[ConfigKey, ConfigValue]


class CollectionConfiguration(TypedDict, total=False):
    CollectionName: Optional[CollectionName]
    CollectionParameters: Optional[CollectionParameters]


CollectionConfigurations = List[CollectionConfiguration]


class CompilationJobSummary(TypedDict, total=False):
    CompilationJobName: EntityName
    CompilationJobArn: CompilationJobArn
    CreationTime: CreationTime
    CompilationStartTime: Optional[Timestamp]
    CompilationEndTime: Optional[Timestamp]
    CompilationTargetDevice: Optional[TargetDevice]
    CompilationTargetPlatformOs: Optional[TargetPlatformOs]
    CompilationTargetPlatformArch: Optional[TargetPlatformArch]
    CompilationTargetPlatformAccelerator: Optional[TargetPlatformAccelerator]
    LastModifiedTime: Optional[LastModifiedTime]
    CompilationJobStatus: CompilationJobStatus


CompilationJobSummaries = List[CompilationJobSummary]


class ConditionStepMetadata(TypedDict, total=False):
    Outcome: Optional[ConditionOutcome]


class MultiModelConfig(TypedDict, total=False):
    ModelCacheSetting: Optional[ModelCacheSetting]


class RepositoryAuthConfig(TypedDict, total=False):
    RepositoryCredentialsProviderArn: RepositoryCredentialsProviderArn


class ImageConfig(TypedDict, total=False):
    RepositoryAccessMode: RepositoryAccessMode
    RepositoryAuthConfig: Optional[RepositoryAuthConfig]


class ContainerDefinition(TypedDict, total=False):
    ContainerHostname: Optional[ContainerHostname]
    Image: Optional[ContainerImage]
    ImageConfig: Optional[ImageConfig]
    Mode: Optional[ContainerMode]
    ModelDataUrl: Optional[Url]
    Environment: Optional[EnvironmentMap]
    ModelPackageName: Optional[VersionedArnOrName]
    InferenceSpecificationName: Optional[InferenceSpecificationName]
    MultiModelConfig: Optional[MultiModelConfig]


ContainerDefinitionList = List[ContainerDefinition]
ContentClassifiers = List[ContentClassifier]


class ContextSource(TypedDict, total=False):
    SourceUri: String2048
    SourceType: Optional[String256]
    SourceId: Optional[String256]


class ContextSummary(TypedDict, total=False):
    ContextArn: Optional[ContextArn]
    ContextName: Optional[ExperimentEntityName]
    Source: Optional[ContextSource]
    ContextType: Optional[String256]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


ContextSummaries = List[ContextSummary]


class ContinuousParameterRange(TypedDict, total=False):
    Name: ParameterKey
    MinValue: ParameterValue
    MaxValue: ParameterValue
    ScalingType: Optional[HyperParameterScalingType]


class ContinuousParameterRangeSpecification(TypedDict, total=False):
    MinValue: ParameterValue
    MaxValue: ParameterValue


ContinuousParameterRanges = List[ContinuousParameterRange]


class MetadataProperties(TypedDict, total=False):
    CommitId: Optional[MetadataPropertyValue]
    Repository: Optional[MetadataPropertyValue]
    GeneratedBy: Optional[MetadataPropertyValue]
    ProjectId: Optional[MetadataPropertyValue]


LineageEntityParameters = Dict[StringParameterValue, StringParameterValue]


class CreateActionRequest(ServiceRequest):
    ActionName: ExperimentEntityName
    Source: ActionSource
    ActionType: String256
    Description: Optional[ExperimentDescription]
    Status: Optional[ActionStatus]
    Properties: Optional[LineageEntityParameters]
    MetadataProperties: Optional[MetadataProperties]
    Tags: Optional[TagList]


class CreateActionResponse(TypedDict, total=False):
    ActionArn: Optional[ActionArn]


class HyperParameterTuningJobObjective(TypedDict, total=False):
    Type: HyperParameterTuningJobObjectiveType
    MetricName: MetricName


HyperParameterTuningJobObjectives = List[HyperParameterTuningJobObjective]
TrainingInstanceTypes = List[TrainingInstanceType]


class IntegerParameterRangeSpecification(TypedDict, total=False):
    MinValue: ParameterValue
    MaxValue: ParameterValue


class ParameterRange(TypedDict, total=False):
    IntegerParameterRangeSpecification: Optional[IntegerParameterRangeSpecification]
    ContinuousParameterRangeSpecification: Optional[ContinuousParameterRangeSpecification]
    CategoricalParameterRangeSpecification: Optional[CategoricalParameterRangeSpecification]


class HyperParameterSpecification(TypedDict, total=False):
    Name: ParameterName
    Description: Optional[EntityDescription]
    Type: ParameterType
    Range: Optional[ParameterRange]
    IsTunable: Optional[Boolean]
    IsRequired: Optional[Boolean]
    DefaultValue: Optional[HyperParameterValue]


HyperParameterSpecifications = List[HyperParameterSpecification]


class TrainingSpecification(TypedDict, total=False):
    TrainingImage: ContainerImage
    TrainingImageDigest: Optional[ImageDigest]
    SupportedHyperParameters: Optional[HyperParameterSpecifications]
    SupportedTrainingInstanceTypes: TrainingInstanceTypes
    SupportsDistributedTraining: Optional[Boolean]
    MetricDefinitions: Optional[MetricDefinitionList]
    TrainingChannels: ChannelSpecifications
    SupportedTuningJobObjectiveMetrics: Optional[HyperParameterTuningJobObjectives]


class CreateAlgorithmInput(ServiceRequest):
    AlgorithmName: EntityName
    AlgorithmDescription: Optional[EntityDescription]
    TrainingSpecification: TrainingSpecification
    InferenceSpecification: Optional[InferenceSpecification]
    ValidationSpecification: Optional[AlgorithmValidationSpecification]
    CertifyForMarketplace: Optional[CertifyForMarketplace]
    Tags: Optional[TagList]


class CreateAlgorithmOutput(TypedDict, total=False):
    AlgorithmArn: AlgorithmArn


class CreateAppImageConfigRequest(ServiceRequest):
    AppImageConfigName: AppImageConfigName
    Tags: Optional[TagList]
    KernelGatewayImageConfig: Optional[KernelGatewayImageConfig]


class CreateAppImageConfigResponse(TypedDict, total=False):
    AppImageConfigArn: Optional[AppImageConfigArn]


class ResourceSpec(TypedDict, total=False):
    SageMakerImageArn: Optional[ImageArn]
    SageMakerImageVersionArn: Optional[ImageVersionArn]
    InstanceType: Optional[AppInstanceType]
    LifecycleConfigArn: Optional[StudioLifecycleConfigArn]


class CreateAppRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    AppType: AppType
    AppName: AppName
    Tags: Optional[TagList]
    ResourceSpec: Optional[ResourceSpec]


class CreateAppResponse(TypedDict, total=False):
    AppArn: Optional[AppArn]


class CreateArtifactRequest(ServiceRequest):
    ArtifactName: Optional[ExperimentEntityName]
    Source: ArtifactSource
    ArtifactType: String256
    Properties: Optional[LineageEntityParameters]
    MetadataProperties: Optional[MetadataProperties]
    Tags: Optional[TagList]


class CreateArtifactResponse(TypedDict, total=False):
    ArtifactArn: Optional[ArtifactArn]


class ModelDeployConfig(TypedDict, total=False):
    AutoGenerateEndpointName: Optional[AutoGenerateEndpointName]
    EndpointName: Optional[EndpointName]


class CreateAutoMLJobRequest(ServiceRequest):
    AutoMLJobName: AutoMLJobName
    InputDataConfig: AutoMLInputDataConfig
    OutputDataConfig: AutoMLOutputDataConfig
    ProblemType: Optional[ProblemType]
    AutoMLJobObjective: Optional[AutoMLJobObjective]
    AutoMLJobConfig: Optional[AutoMLJobConfig]
    RoleArn: RoleArn
    GenerateCandidateDefinitionsOnly: Optional[GenerateCandidateDefinitionsOnly]
    Tags: Optional[TagList]
    ModelDeployConfig: Optional[ModelDeployConfig]


class CreateAutoMLJobResponse(TypedDict, total=False):
    AutoMLJobArn: AutoMLJobArn


class CreateCodeRepositoryInput(ServiceRequest):
    CodeRepositoryName: EntityName
    GitConfig: GitConfig
    Tags: Optional[TagList]


class CreateCodeRepositoryOutput(TypedDict, total=False):
    CodeRepositoryArn: CodeRepositoryArn


NeoVpcSubnets = List[NeoVpcSubnetId]
NeoVpcSecurityGroupIds = List[NeoVpcSecurityGroupId]


class NeoVpcConfig(TypedDict, total=False):
    SecurityGroupIds: NeoVpcSecurityGroupIds
    Subnets: NeoVpcSubnets


class TargetPlatform(TypedDict, total=False):
    Os: TargetPlatformOs
    Arch: TargetPlatformArch
    Accelerator: Optional[TargetPlatformAccelerator]


class OutputConfig(TypedDict, total=False):
    S3OutputLocation: S3Uri
    TargetDevice: Optional[TargetDevice]
    TargetPlatform: Optional[TargetPlatform]
    CompilerOptions: Optional[CompilerOptions]
    KmsKeyId: Optional[KmsKeyId]


class InputConfig(TypedDict, total=False):
    S3Uri: S3Uri
    DataInputConfig: DataInputConfig
    Framework: Framework
    FrameworkVersion: Optional[FrameworkVersion]


class CreateCompilationJobRequest(ServiceRequest):
    CompilationJobName: EntityName
    RoleArn: RoleArn
    ModelPackageVersionArn: Optional[ModelPackageArn]
    InputConfig: Optional[InputConfig]
    OutputConfig: OutputConfig
    VpcConfig: Optional[NeoVpcConfig]
    StoppingCondition: StoppingCondition
    Tags: Optional[TagList]


class CreateCompilationJobResponse(TypedDict, total=False):
    CompilationJobArn: CompilationJobArn


class CreateContextRequest(ServiceRequest):
    ContextName: ExperimentEntityName
    Source: ContextSource
    ContextType: String256
    Description: Optional[ExperimentDescription]
    Properties: Optional[LineageEntityParameters]
    Tags: Optional[TagList]


class CreateContextResponse(TypedDict, total=False):
    ContextArn: Optional[ContextArn]


class MonitoringStoppingCondition(TypedDict, total=False):
    MaxRuntimeInSeconds: MonitoringMaxRuntimeInSeconds


class MonitoringNetworkConfig(TypedDict, total=False):
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableNetworkIsolation: Optional[Boolean]
    VpcConfig: Optional[VpcConfig]


class MonitoringClusterConfig(TypedDict, total=False):
    InstanceCount: ProcessingInstanceCount
    InstanceType: ProcessingInstanceType
    VolumeSizeInGB: ProcessingVolumeSizeInGB
    VolumeKmsKeyId: Optional[KmsKeyId]


class MonitoringResources(TypedDict, total=False):
    ClusterConfig: MonitoringClusterConfig


class MonitoringS3Output(TypedDict, total=False):
    S3Uri: MonitoringS3Uri
    LocalPath: ProcessingLocalPath
    S3UploadMode: Optional[ProcessingS3UploadMode]


class MonitoringOutput(TypedDict, total=False):
    S3Output: MonitoringS3Output


MonitoringOutputs = List[MonitoringOutput]


class MonitoringOutputConfig(TypedDict, total=False):
    MonitoringOutputs: MonitoringOutputs
    KmsKeyId: Optional[KmsKeyId]


class EndpointInput(TypedDict, total=False):
    EndpointName: EndpointName
    LocalPath: ProcessingLocalPath
    S3InputMode: Optional[ProcessingS3InputMode]
    S3DataDistributionType: Optional[ProcessingS3DataDistributionType]
    FeaturesAttribute: Optional[String]
    InferenceAttribute: Optional[String]
    ProbabilityAttribute: Optional[String]
    ProbabilityThresholdAttribute: Optional[ProbabilityThresholdAttribute]
    StartTimeOffset: Optional[MonitoringTimeOffsetString]
    EndTimeOffset: Optional[MonitoringTimeOffsetString]


class DataQualityJobInput(TypedDict, total=False):
    EndpointInput: EndpointInput


MonitoringEnvironmentMap = Dict[ProcessingEnvironmentKey, ProcessingEnvironmentValue]
MonitoringContainerArguments = List[ContainerArgument]


class DataQualityAppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ContainerEntrypoint: Optional[ContainerEntrypoint]
    ContainerArguments: Optional[MonitoringContainerArguments]
    RecordPreprocessorSourceUri: Optional[S3Uri]
    PostAnalyticsProcessorSourceUri: Optional[S3Uri]
    Environment: Optional[MonitoringEnvironmentMap]


class MonitoringStatisticsResource(TypedDict, total=False):
    S3Uri: Optional[S3Uri]


class MonitoringConstraintsResource(TypedDict, total=False):
    S3Uri: Optional[S3Uri]


class DataQualityBaselineConfig(TypedDict, total=False):
    BaseliningJobName: Optional[ProcessingJobName]
    ConstraintsResource: Optional[MonitoringConstraintsResource]
    StatisticsResource: Optional[MonitoringStatisticsResource]


class CreateDataQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName
    DataQualityBaselineConfig: Optional[DataQualityBaselineConfig]
    DataQualityAppSpecification: DataQualityAppSpecification
    DataQualityJobInput: DataQualityJobInput
    DataQualityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]
    Tags: Optional[TagList]


class CreateDataQualityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn


class EdgeOutputConfig(TypedDict, total=False):
    S3OutputLocation: S3Uri
    KmsKeyId: Optional[KmsKeyId]
    PresetDeploymentType: Optional[EdgePresetDeploymentType]
    PresetDeploymentConfig: Optional[String]


class CreateDeviceFleetRequest(ServiceRequest):
    DeviceFleetName: EntityName
    RoleArn: Optional[RoleArn]
    Description: Optional[DeviceFleetDescription]
    OutputConfig: EdgeOutputConfig
    Tags: Optional[TagList]
    EnableIotRoleAlias: Optional[EnableIotRoleAlias]


class RStudioServerProDomainSettings(TypedDict, total=False):
    DomainExecutionRoleArn: RoleArn
    RStudioConnectUrl: Optional[String]
    RStudioPackageManagerUrl: Optional[String]
    DefaultResourceSpec: Optional[ResourceSpec]


DomainSecurityGroupIds = List[SecurityGroupId]


class DomainSettings(TypedDict, total=False):
    SecurityGroupIds: Optional[DomainSecurityGroupIds]
    RStudioServerProDomainSettings: Optional[RStudioServerProDomainSettings]


class RSessionAppSettings(TypedDict, total=False):
    pass


class RStudioServerProAppSettings(TypedDict, total=False):
    AccessStatus: Optional[RStudioServerProAccessStatus]
    UserGroup: Optional[RStudioServerProUserGroup]


class TensorBoardAppSettings(TypedDict, total=False):
    DefaultResourceSpec: Optional[ResourceSpec]


LifecycleConfigArns = List[StudioLifecycleConfigArn]


class CustomImage(TypedDict, total=False):
    ImageName: ImageName
    ImageVersionNumber: Optional[ImageVersionNumber]
    AppImageConfigName: AppImageConfigName


CustomImages = List[CustomImage]


class KernelGatewayAppSettings(TypedDict, total=False):
    DefaultResourceSpec: Optional[ResourceSpec]
    CustomImages: Optional[CustomImages]
    LifecycleConfigArns: Optional[LifecycleConfigArns]


class JupyterServerAppSettings(TypedDict, total=False):
    DefaultResourceSpec: Optional[ResourceSpec]
    LifecycleConfigArns: Optional[LifecycleConfigArns]


class SharingSettings(TypedDict, total=False):
    NotebookOutputOption: Optional[NotebookOutputOption]
    S3OutputPath: Optional[S3Uri]
    S3KmsKeyId: Optional[KmsKeyId]


SecurityGroupIds = List[SecurityGroupId]


class UserSettings(TypedDict, total=False):
    ExecutionRole: Optional[RoleArn]
    SecurityGroups: Optional[SecurityGroupIds]
    SharingSettings: Optional[SharingSettings]
    JupyterServerAppSettings: Optional[JupyterServerAppSettings]
    KernelGatewayAppSettings: Optional[KernelGatewayAppSettings]
    TensorBoardAppSettings: Optional[TensorBoardAppSettings]
    RStudioServerProAppSettings: Optional[RStudioServerProAppSettings]
    RSessionAppSettings: Optional[RSessionAppSettings]


class CreateDomainRequest(ServiceRequest):
    DomainName: DomainName
    AuthMode: AuthMode
    DefaultUserSettings: UserSettings
    SubnetIds: Subnets
    VpcId: VpcId
    Tags: Optional[TagList]
    AppNetworkAccessType: Optional[AppNetworkAccessType]
    HomeEfsFileSystemKmsKeyId: Optional[KmsKeyId]
    KmsKeyId: Optional[KmsKeyId]
    AppSecurityGroupManagement: Optional[AppSecurityGroupManagement]
    DomainSettings: Optional[DomainSettings]


class CreateDomainResponse(TypedDict, total=False):
    DomainArn: Optional[DomainArn]
    Url: Optional[String1024]


class CreateEdgePackagingJobRequest(ServiceRequest):
    EdgePackagingJobName: EntityName
    CompilationJobName: EntityName
    ModelName: EntityName
    ModelVersion: EdgeVersion
    RoleArn: RoleArn
    OutputConfig: EdgeOutputConfig
    ResourceKey: Optional[KmsKeyId]
    Tags: Optional[TagList]


class DataCaptureConfig(TypedDict, total=False):
    EnableCapture: Optional[EnableCapture]
    InitialSamplingPercentage: SamplingPercentage
    DestinationS3Uri: DestinationS3Uri
    KmsKeyId: Optional[KmsKeyId]
    CaptureOptions: CaptureOptionList
    CaptureContentTypeHeader: Optional[CaptureContentTypeHeader]


class ProductionVariantServerlessConfig(TypedDict, total=False):
    MemorySizeInMB: ServerlessMemorySizeInMB
    MaxConcurrency: ServerlessMaxConcurrency


class ProductionVariantCoreDumpConfig(TypedDict, total=False):
    DestinationS3Uri: DestinationS3Uri
    KmsKeyId: Optional[KmsKeyId]


class ProductionVariant(TypedDict, total=False):
    VariantName: VariantName
    ModelName: ModelName
    InitialInstanceCount: Optional[InitialTaskCount]
    InstanceType: Optional[ProductionVariantInstanceType]
    InitialVariantWeight: Optional[VariantWeight]
    AcceleratorType: Optional[ProductionVariantAcceleratorType]
    CoreDumpConfig: Optional[ProductionVariantCoreDumpConfig]
    ServerlessConfig: Optional[ProductionVariantServerlessConfig]


ProductionVariantList = List[ProductionVariant]


class CreateEndpointConfigInput(ServiceRequest):
    EndpointConfigName: EndpointConfigName
    ProductionVariants: ProductionVariantList
    DataCaptureConfig: Optional[DataCaptureConfig]
    Tags: Optional[TagList]
    KmsKeyId: Optional[KmsKeyId]
    AsyncInferenceConfig: Optional[AsyncInferenceConfig]


class CreateEndpointConfigOutput(TypedDict, total=False):
    EndpointConfigArn: EndpointConfigArn


class DeploymentConfig(TypedDict, total=False):
    BlueGreenUpdatePolicy: BlueGreenUpdatePolicy
    AutoRollbackConfiguration: Optional[AutoRollbackConfig]


class CreateEndpointInput(ServiceRequest):
    EndpointName: EndpointName
    EndpointConfigName: EndpointConfigName
    DeploymentConfig: Optional[DeploymentConfig]
    Tags: Optional[TagList]


class CreateEndpointOutput(TypedDict, total=False):
    EndpointArn: EndpointArn


class CreateExperimentRequest(ServiceRequest):
    ExperimentName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]
    Description: Optional[ExperimentDescription]
    Tags: Optional[TagList]


class CreateExperimentResponse(TypedDict, total=False):
    ExperimentArn: Optional[ExperimentArn]


class DataCatalogConfig(TypedDict, total=False):
    TableName: TableName
    Catalog: Catalog
    Database: Database


class S3StorageConfig(TypedDict, total=False):
    S3Uri: S3Uri
    KmsKeyId: Optional[KmsKeyId]
    ResolvedOutputS3Uri: Optional[S3Uri]


class OfflineStoreConfig(TypedDict, total=False):
    S3StorageConfig: S3StorageConfig
    DisableGlueTableCreation: Optional[Boolean]
    DataCatalogConfig: Optional[DataCatalogConfig]


class OnlineStoreSecurityConfig(TypedDict, total=False):
    KmsKeyId: Optional[KmsKeyId]


class OnlineStoreConfig(TypedDict, total=False):
    SecurityConfig: Optional[OnlineStoreSecurityConfig]
    EnableOnlineStore: Optional[Boolean]


class FeatureDefinition(TypedDict, total=False):
    FeatureName: Optional[FeatureName]
    FeatureType: Optional[FeatureType]


FeatureDefinitions = List[FeatureDefinition]


class CreateFeatureGroupRequest(ServiceRequest):
    FeatureGroupName: FeatureGroupName
    RecordIdentifierFeatureName: FeatureName
    EventTimeFeatureName: FeatureName
    FeatureDefinitions: FeatureDefinitions
    OnlineStoreConfig: Optional[OnlineStoreConfig]
    OfflineStoreConfig: Optional[OfflineStoreConfig]
    RoleArn: Optional[RoleArn]
    Description: Optional[Description]
    Tags: Optional[TagList]


class CreateFeatureGroupResponse(TypedDict, total=False):
    FeatureGroupArn: FeatureGroupArn


class FlowDefinitionOutputConfig(TypedDict, total=False):
    S3OutputPath: S3Uri
    KmsKeyId: Optional[KmsKeyId]


class USD(TypedDict, total=False):
    Dollars: Optional[Dollars]
    Cents: Optional[Cents]
    TenthFractionsOfACent: Optional[TenthFractionsOfACent]


class PublicWorkforceTaskPrice(TypedDict, total=False):
    AmountInUsd: Optional[USD]


FlowDefinitionTaskKeywords = List[FlowDefinitionTaskKeyword]


class HumanLoopConfig(TypedDict, total=False):
    WorkteamArn: WorkteamArn
    HumanTaskUiArn: HumanTaskUiArn
    TaskTitle: FlowDefinitionTaskTitle
    TaskDescription: FlowDefinitionTaskDescription
    TaskCount: FlowDefinitionTaskCount
    TaskAvailabilityLifetimeInSeconds: Optional[FlowDefinitionTaskAvailabilityLifetimeInSeconds]
    TaskTimeLimitInSeconds: Optional[FlowDefinitionTaskTimeLimitInSeconds]
    TaskKeywords: Optional[FlowDefinitionTaskKeywords]
    PublicWorkforceTaskPrice: Optional[PublicWorkforceTaskPrice]


class HumanLoopActivationConditionsConfig(TypedDict, total=False):
    HumanLoopActivationConditions: HumanLoopActivationConditions


class HumanLoopActivationConfig(TypedDict, total=False):
    HumanLoopActivationConditionsConfig: HumanLoopActivationConditionsConfig


class HumanLoopRequestSource(TypedDict, total=False):
    AwsManagedHumanLoopRequestSource: AwsManagedHumanLoopRequestSource


class CreateFlowDefinitionRequest(ServiceRequest):
    FlowDefinitionName: FlowDefinitionName
    HumanLoopRequestSource: Optional[HumanLoopRequestSource]
    HumanLoopActivationConfig: Optional[HumanLoopActivationConfig]
    HumanLoopConfig: HumanLoopConfig
    OutputConfig: FlowDefinitionOutputConfig
    RoleArn: RoleArn
    Tags: Optional[TagList]


class CreateFlowDefinitionResponse(TypedDict, total=False):
    FlowDefinitionArn: FlowDefinitionArn


class UiTemplate(TypedDict, total=False):
    Content: TemplateContent


class CreateHumanTaskUiRequest(ServiceRequest):
    HumanTaskUiName: HumanTaskUiName
    UiTemplate: UiTemplate
    Tags: Optional[TagList]


class CreateHumanTaskUiResponse(TypedDict, total=False):
    HumanTaskUiArn: HumanTaskUiArn


class ParentHyperParameterTuningJob(TypedDict, total=False):
    HyperParameterTuningJobName: Optional[HyperParameterTuningJobName]


ParentHyperParameterTuningJobs = List[ParentHyperParameterTuningJob]


class HyperParameterTuningJobWarmStartConfig(TypedDict, total=False):
    ParentHyperParameterTuningJobs: ParentHyperParameterTuningJobs
    WarmStartType: HyperParameterTuningJobWarmStartType


class RetryStrategy(TypedDict, total=False):
    MaximumRetryAttempts: MaximumRetryAttempts


class HyperParameterAlgorithmSpecification(TypedDict, total=False):
    TrainingImage: Optional[AlgorithmImage]
    TrainingInputMode: TrainingInputMode
    AlgorithmName: Optional[ArnOrName]
    MetricDefinitions: Optional[MetricDefinitionList]


class IntegerParameterRange(TypedDict, total=False):
    Name: ParameterKey
    MinValue: ParameterValue
    MaxValue: ParameterValue
    ScalingType: Optional[HyperParameterScalingType]


IntegerParameterRanges = List[IntegerParameterRange]


class ParameterRanges(TypedDict, total=False):
    IntegerParameterRanges: Optional[IntegerParameterRanges]
    ContinuousParameterRanges: Optional[ContinuousParameterRanges]
    CategoricalParameterRanges: Optional[CategoricalParameterRanges]


class HyperParameterTrainingJobDefinition(TypedDict, total=False):
    DefinitionName: Optional[HyperParameterTrainingJobDefinitionName]
    TuningObjective: Optional[HyperParameterTuningJobObjective]
    HyperParameterRanges: Optional[ParameterRanges]
    StaticHyperParameters: Optional[HyperParameters]
    AlgorithmSpecification: HyperParameterAlgorithmSpecification
    RoleArn: RoleArn
    InputDataConfig: Optional[InputDataConfig]
    VpcConfig: Optional[VpcConfig]
    OutputDataConfig: OutputDataConfig
    ResourceConfig: ResourceConfig
    StoppingCondition: StoppingCondition
    EnableNetworkIsolation: Optional[Boolean]
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableManagedSpotTraining: Optional[Boolean]
    CheckpointConfig: Optional[CheckpointConfig]
    RetryStrategy: Optional[RetryStrategy]


HyperParameterTrainingJobDefinitions = List[HyperParameterTrainingJobDefinition]


class TuningJobCompletionCriteria(TypedDict, total=False):
    TargetObjectiveMetricValue: TargetObjectiveMetricValue


class ResourceLimits(TypedDict, total=False):
    MaxNumberOfTrainingJobs: MaxNumberOfTrainingJobs
    MaxParallelTrainingJobs: MaxParallelTrainingJobs


class HyperParameterTuningJobConfig(TypedDict, total=False):
    Strategy: HyperParameterTuningJobStrategyType
    HyperParameterTuningJobObjective: Optional[HyperParameterTuningJobObjective]
    ResourceLimits: ResourceLimits
    ParameterRanges: Optional[ParameterRanges]
    TrainingJobEarlyStoppingType: Optional[TrainingJobEarlyStoppingType]
    TuningJobCompletionCriteria: Optional[TuningJobCompletionCriteria]


class CreateHyperParameterTuningJobRequest(ServiceRequest):
    HyperParameterTuningJobName: HyperParameterTuningJobName
    HyperParameterTuningJobConfig: HyperParameterTuningJobConfig
    TrainingJobDefinition: Optional[HyperParameterTrainingJobDefinition]
    TrainingJobDefinitions: Optional[HyperParameterTrainingJobDefinitions]
    WarmStartConfig: Optional[HyperParameterTuningJobWarmStartConfig]
    Tags: Optional[TagList]


class CreateHyperParameterTuningJobResponse(TypedDict, total=False):
    HyperParameterTuningJobArn: HyperParameterTuningJobArn


class CreateImageRequest(ServiceRequest):
    Description: Optional[ImageDescription]
    DisplayName: Optional[ImageDisplayName]
    ImageName: ImageName
    RoleArn: RoleArn
    Tags: Optional[TagList]


class CreateImageResponse(TypedDict, total=False):
    ImageArn: Optional[ImageArn]


class CreateImageVersionRequest(ServiceRequest):
    BaseImage: ImageBaseImage
    ClientToken: ClientToken
    ImageName: ImageName


class CreateImageVersionResponse(TypedDict, total=False):
    ImageVersionArn: Optional[ImageVersionArn]


class ModelLatencyThreshold(TypedDict, total=False):
    Percentile: Optional[String64]
    ValueInMilliseconds: Optional[Integer]


ModelLatencyThresholds = List[ModelLatencyThreshold]


class RecommendationJobStoppingConditions(TypedDict, total=False):
    MaxInvocations: Optional[Integer]
    ModelLatencyThresholds: Optional[ModelLatencyThresholds]


class EnvironmentParameterRanges(TypedDict, total=False):
    CategoricalParameterRanges: Optional[CategoricalParameters]


class EndpointInputConfiguration(TypedDict, total=False):
    InstanceType: ProductionVariantInstanceType
    InferenceSpecificationName: Optional[InferenceSpecificationName]
    EnvironmentParameterRanges: Optional[EnvironmentParameterRanges]


EndpointInputConfigurations = List[EndpointInputConfiguration]


class RecommendationJobResourceLimit(TypedDict, total=False):
    MaxNumberOfTests: Optional[MaxNumberOfTests]
    MaxParallelOfTests: Optional[MaxParallelOfTests]


class Phase(TypedDict, total=False):
    InitialNumberOfUsers: Optional[InitialNumberOfUsers]
    SpawnRate: Optional[SpawnRate]
    DurationInSeconds: Optional[TrafficDurationInSeconds]


Phases = List[Phase]


class TrafficPattern(TypedDict, total=False):
    TrafficType: Optional[TrafficType]
    Phases: Optional[Phases]


class RecommendationJobInputConfig(TypedDict, total=False):
    ModelPackageVersionArn: ModelPackageArn
    JobDurationInSeconds: Optional[JobDurationInSeconds]
    TrafficPattern: Optional[TrafficPattern]
    ResourceLimit: Optional[RecommendationJobResourceLimit]
    EndpointConfigurations: Optional[EndpointInputConfigurations]


class CreateInferenceRecommendationsJobRequest(ServiceRequest):
    JobName: RecommendationJobName
    JobType: RecommendationJobType
    RoleArn: RoleArn
    InputConfig: RecommendationJobInputConfig
    JobDescription: Optional[RecommendationJobDescription]
    StoppingConditions: Optional[RecommendationJobStoppingConditions]
    Tags: Optional[TagList]


class CreateInferenceRecommendationsJobResponse(TypedDict, total=False):
    JobArn: RecommendationJobArn


TaskKeywords = List[TaskKeyword]


class UiConfig(TypedDict, total=False):
    UiTemplateS3Uri: Optional[S3Uri]
    HumanTaskUiArn: Optional[HumanTaskUiArn]


class HumanTaskConfig(TypedDict, total=False):
    WorkteamArn: WorkteamArn
    UiConfig: UiConfig
    PreHumanTaskLambdaArn: LambdaFunctionArn
    TaskKeywords: Optional[TaskKeywords]
    TaskTitle: TaskTitle
    TaskDescription: TaskDescription
    NumberOfHumanWorkersPerDataObject: NumberOfHumanWorkersPerDataObject
    TaskTimeLimitInSeconds: TaskTimeLimitInSeconds
    TaskAvailabilityLifetimeInSeconds: Optional[TaskAvailabilityLifetimeInSeconds]
    MaxConcurrentTaskCount: Optional[MaxConcurrentTaskCount]
    AnnotationConsolidationConfig: AnnotationConsolidationConfig
    PublicWorkforceTaskPrice: Optional[PublicWorkforceTaskPrice]


class LabelingJobResourceConfig(TypedDict, total=False):
    VolumeKmsKeyId: Optional[KmsKeyId]


class LabelingJobAlgorithmsConfig(TypedDict, total=False):
    LabelingJobAlgorithmSpecificationArn: LabelingJobAlgorithmSpecificationArn
    InitialActiveLearningModelArn: Optional[ModelArn]
    LabelingJobResourceConfig: Optional[LabelingJobResourceConfig]


class LabelingJobStoppingConditions(TypedDict, total=False):
    MaxHumanLabeledObjectCount: Optional[MaxHumanLabeledObjectCount]
    MaxPercentageOfInputDatasetLabeled: Optional[MaxPercentageOfInputDatasetLabeled]


class LabelingJobOutputConfig(TypedDict, total=False):
    S3OutputPath: S3Uri
    KmsKeyId: Optional[KmsKeyId]
    SnsTopicArn: Optional[SnsTopicArn]


class LabelingJobDataAttributes(TypedDict, total=False):
    ContentClassifiers: Optional[ContentClassifiers]


class LabelingJobSnsDataSource(TypedDict, total=False):
    SnsTopicArn: SnsTopicArn


class LabelingJobS3DataSource(TypedDict, total=False):
    ManifestS3Uri: S3Uri


class LabelingJobDataSource(TypedDict, total=False):
    S3DataSource: Optional[LabelingJobS3DataSource]
    SnsDataSource: Optional[LabelingJobSnsDataSource]


class LabelingJobInputConfig(TypedDict, total=False):
    DataSource: LabelingJobDataSource
    DataAttributes: Optional[LabelingJobDataAttributes]


class CreateLabelingJobRequest(ServiceRequest):
    LabelingJobName: LabelingJobName
    LabelAttributeName: LabelAttributeName
    InputConfig: LabelingJobInputConfig
    OutputConfig: LabelingJobOutputConfig
    RoleArn: RoleArn
    LabelCategoryConfigS3Uri: Optional[S3Uri]
    StoppingConditions: Optional[LabelingJobStoppingConditions]
    LabelingJobAlgorithmsConfig: Optional[LabelingJobAlgorithmsConfig]
    HumanTaskConfig: HumanTaskConfig
    Tags: Optional[TagList]


class CreateLabelingJobResponse(TypedDict, total=False):
    LabelingJobArn: LabelingJobArn


class MonitoringGroundTruthS3Input(TypedDict, total=False):
    S3Uri: Optional[MonitoringS3Uri]


class ModelBiasJobInput(TypedDict, total=False):
    EndpointInput: EndpointInput
    GroundTruthS3Input: MonitoringGroundTruthS3Input


class ModelBiasAppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ConfigUri: S3Uri
    Environment: Optional[MonitoringEnvironmentMap]


class ModelBiasBaselineConfig(TypedDict, total=False):
    BaseliningJobName: Optional[ProcessingJobName]
    ConstraintsResource: Optional[MonitoringConstraintsResource]


class CreateModelBiasJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName
    ModelBiasBaselineConfig: Optional[ModelBiasBaselineConfig]
    ModelBiasAppSpecification: ModelBiasAppSpecification
    ModelBiasJobInput: ModelBiasJobInput
    ModelBiasJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]
    Tags: Optional[TagList]


class CreateModelBiasJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn


class ModelExplainabilityJobInput(TypedDict, total=False):
    EndpointInput: EndpointInput


class ModelExplainabilityAppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ConfigUri: S3Uri
    Environment: Optional[MonitoringEnvironmentMap]


class ModelExplainabilityBaselineConfig(TypedDict, total=False):
    BaseliningJobName: Optional[ProcessingJobName]
    ConstraintsResource: Optional[MonitoringConstraintsResource]


class CreateModelExplainabilityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName
    ModelExplainabilityBaselineConfig: Optional[ModelExplainabilityBaselineConfig]
    ModelExplainabilityAppSpecification: ModelExplainabilityAppSpecification
    ModelExplainabilityJobInput: ModelExplainabilityJobInput
    ModelExplainabilityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]
    Tags: Optional[TagList]


class CreateModelExplainabilityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn


class InferenceExecutionConfig(TypedDict, total=False):
    Mode: InferenceExecutionMode


class CreateModelInput(ServiceRequest):
    ModelName: ModelName
    PrimaryContainer: Optional[ContainerDefinition]
    Containers: Optional[ContainerDefinitionList]
    InferenceExecutionConfig: Optional[InferenceExecutionConfig]
    ExecutionRoleArn: RoleArn
    Tags: Optional[TagList]
    VpcConfig: Optional[VpcConfig]
    EnableNetworkIsolation: Optional[Boolean]


class CreateModelOutput(TypedDict, total=False):
    ModelArn: ModelArn


class CreateModelPackageGroupInput(ServiceRequest):
    ModelPackageGroupName: EntityName
    ModelPackageGroupDescription: Optional[EntityDescription]
    Tags: Optional[TagList]


class CreateModelPackageGroupOutput(TypedDict, total=False):
    ModelPackageGroupArn: ModelPackageGroupArn


class DriftCheckModelDataQuality(TypedDict, total=False):
    Statistics: Optional[MetricsSource]
    Constraints: Optional[MetricsSource]


class DriftCheckModelQuality(TypedDict, total=False):
    Statistics: Optional[MetricsSource]
    Constraints: Optional[MetricsSource]


class FileSource(TypedDict, total=False):
    ContentType: Optional[ContentType]
    ContentDigest: Optional[ContentDigest]
    S3Uri: S3Uri


class DriftCheckExplainability(TypedDict, total=False):
    Constraints: Optional[MetricsSource]
    ConfigFile: Optional[FileSource]


class DriftCheckBias(TypedDict, total=False):
    ConfigFile: Optional[FileSource]
    PreTrainingConstraints: Optional[MetricsSource]
    PostTrainingConstraints: Optional[MetricsSource]


class DriftCheckBaselines(TypedDict, total=False):
    Bias: Optional[DriftCheckBias]
    Explainability: Optional[DriftCheckExplainability]
    ModelQuality: Optional[DriftCheckModelQuality]
    ModelDataQuality: Optional[DriftCheckModelDataQuality]


CustomerMetadataMap = Dict[CustomerMetadataKey, CustomerMetadataValue]


class Explainability(TypedDict, total=False):
    Report: Optional[MetricsSource]


class ModelDataQuality(TypedDict, total=False):
    Statistics: Optional[MetricsSource]
    Constraints: Optional[MetricsSource]


class ModelQuality(TypedDict, total=False):
    Statistics: Optional[MetricsSource]
    Constraints: Optional[MetricsSource]


class ModelMetrics(TypedDict, total=False):
    ModelQuality: Optional[ModelQuality]
    ModelDataQuality: Optional[ModelDataQuality]
    Bias: Optional[Bias]
    Explainability: Optional[Explainability]


class SourceAlgorithm(TypedDict, total=False):
    ModelDataUrl: Optional[Url]
    AlgorithmName: ArnOrName


SourceAlgorithmList = List[SourceAlgorithm]


class SourceAlgorithmSpecification(TypedDict, total=False):
    SourceAlgorithms: SourceAlgorithmList


class ModelPackageValidationProfile(TypedDict, total=False):
    ProfileName: EntityName
    TransformJobDefinition: TransformJobDefinition


ModelPackageValidationProfiles = List[ModelPackageValidationProfile]


class ModelPackageValidationSpecification(TypedDict, total=False):
    ValidationRole: RoleArn
    ValidationProfiles: ModelPackageValidationProfiles


class CreateModelPackageInput(ServiceRequest):
    ModelPackageName: Optional[EntityName]
    ModelPackageGroupName: Optional[ArnOrName]
    ModelPackageDescription: Optional[EntityDescription]
    InferenceSpecification: Optional[InferenceSpecification]
    ValidationSpecification: Optional[ModelPackageValidationSpecification]
    SourceAlgorithmSpecification: Optional[SourceAlgorithmSpecification]
    CertifyForMarketplace: Optional[CertifyForMarketplace]
    Tags: Optional[TagList]
    ModelApprovalStatus: Optional[ModelApprovalStatus]
    MetadataProperties: Optional[MetadataProperties]
    ModelMetrics: Optional[ModelMetrics]
    ClientToken: Optional[ClientToken]
    CustomerMetadataProperties: Optional[CustomerMetadataMap]
    DriftCheckBaselines: Optional[DriftCheckBaselines]
    Domain: Optional[String]
    Task: Optional[String]
    SamplePayloadUrl: Optional[S3Uri]
    AdditionalInferenceSpecifications: Optional[AdditionalInferenceSpecifications]


class CreateModelPackageOutput(TypedDict, total=False):
    ModelPackageArn: ModelPackageArn


class ModelQualityJobInput(TypedDict, total=False):
    EndpointInput: EndpointInput
    GroundTruthS3Input: MonitoringGroundTruthS3Input


class ModelQualityAppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ContainerEntrypoint: Optional[ContainerEntrypoint]
    ContainerArguments: Optional[MonitoringContainerArguments]
    RecordPreprocessorSourceUri: Optional[S3Uri]
    PostAnalyticsProcessorSourceUri: Optional[S3Uri]
    ProblemType: Optional[MonitoringProblemType]
    Environment: Optional[MonitoringEnvironmentMap]


class ModelQualityBaselineConfig(TypedDict, total=False):
    BaseliningJobName: Optional[ProcessingJobName]
    ConstraintsResource: Optional[MonitoringConstraintsResource]


class CreateModelQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName
    ModelQualityBaselineConfig: Optional[ModelQualityBaselineConfig]
    ModelQualityAppSpecification: ModelQualityAppSpecification
    ModelQualityJobInput: ModelQualityJobInput
    ModelQualityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]
    Tags: Optional[TagList]


class CreateModelQualityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn


class NetworkConfig(TypedDict, total=False):
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableNetworkIsolation: Optional[Boolean]
    VpcConfig: Optional[VpcConfig]


class MonitoringAppSpecification(TypedDict, total=False):
    ImageUri: ImageUri
    ContainerEntrypoint: Optional[ContainerEntrypoint]
    ContainerArguments: Optional[MonitoringContainerArguments]
    RecordPreprocessorSourceUri: Optional[S3Uri]
    PostAnalyticsProcessorSourceUri: Optional[S3Uri]


class MonitoringInput(TypedDict, total=False):
    EndpointInput: EndpointInput


MonitoringInputs = List[MonitoringInput]


class MonitoringBaselineConfig(TypedDict, total=False):
    BaseliningJobName: Optional[ProcessingJobName]
    ConstraintsResource: Optional[MonitoringConstraintsResource]
    StatisticsResource: Optional[MonitoringStatisticsResource]


class MonitoringJobDefinition(TypedDict, total=False):
    BaselineConfig: Optional[MonitoringBaselineConfig]
    MonitoringInputs: MonitoringInputs
    MonitoringOutputConfig: MonitoringOutputConfig
    MonitoringResources: MonitoringResources
    MonitoringAppSpecification: MonitoringAppSpecification
    StoppingCondition: Optional[MonitoringStoppingCondition]
    Environment: Optional[MonitoringEnvironmentMap]
    NetworkConfig: Optional[NetworkConfig]
    RoleArn: RoleArn


class ScheduleConfig(TypedDict, total=False):
    ScheduleExpression: ScheduleExpression


class MonitoringScheduleConfig(TypedDict, total=False):
    ScheduleConfig: Optional[ScheduleConfig]
    MonitoringJobDefinition: Optional[MonitoringJobDefinition]
    MonitoringJobDefinitionName: Optional[MonitoringJobDefinitionName]
    MonitoringType: Optional[MonitoringType]


class CreateMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName
    MonitoringScheduleConfig: MonitoringScheduleConfig
    Tags: Optional[TagList]


class CreateMonitoringScheduleResponse(TypedDict, total=False):
    MonitoringScheduleArn: MonitoringScheduleArn


NotebookInstanceAcceleratorTypes = List[NotebookInstanceAcceleratorType]


class CreateNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName
    InstanceType: InstanceType
    SubnetId: Optional[SubnetId]
    SecurityGroupIds: Optional[SecurityGroupIds]
    RoleArn: RoleArn
    KmsKeyId: Optional[KmsKeyId]
    Tags: Optional[TagList]
    LifecycleConfigName: Optional[NotebookInstanceLifecycleConfigName]
    DirectInternetAccess: Optional[DirectInternetAccess]
    VolumeSizeInGB: Optional[NotebookInstanceVolumeSizeInGB]
    AcceleratorTypes: Optional[NotebookInstanceAcceleratorTypes]
    DefaultCodeRepository: Optional[CodeRepositoryNameOrUrl]
    AdditionalCodeRepositories: Optional[AdditionalCodeRepositoryNamesOrUrls]
    RootAccess: Optional[RootAccess]
    PlatformIdentifier: Optional[PlatformIdentifier]


class NotebookInstanceLifecycleHook(TypedDict, total=False):
    Content: Optional[NotebookInstanceLifecycleConfigContent]


NotebookInstanceLifecycleConfigList = List[NotebookInstanceLifecycleHook]


class CreateNotebookInstanceLifecycleConfigInput(ServiceRequest):
    NotebookInstanceLifecycleConfigName: NotebookInstanceLifecycleConfigName
    OnCreate: Optional[NotebookInstanceLifecycleConfigList]
    OnStart: Optional[NotebookInstanceLifecycleConfigList]


class CreateNotebookInstanceLifecycleConfigOutput(TypedDict, total=False):
    NotebookInstanceLifecycleConfigArn: Optional[NotebookInstanceLifecycleConfigArn]


class CreateNotebookInstanceOutput(TypedDict, total=False):
    NotebookInstanceArn: Optional[NotebookInstanceArn]


class ParallelismConfiguration(TypedDict, total=False):
    MaxParallelExecutionSteps: MaxParallelExecutionSteps


class PipelineDefinitionS3Location(TypedDict, total=False):
    Bucket: BucketName
    ObjectKey: Key
    VersionId: Optional[VersionId]


class CreatePipelineRequest(ServiceRequest):
    PipelineName: PipelineName
    PipelineDisplayName: Optional[PipelineName]
    PipelineDefinition: Optional[PipelineDefinition]
    PipelineDefinitionS3Location: Optional[PipelineDefinitionS3Location]
    PipelineDescription: Optional[PipelineDescription]
    ClientRequestToken: IdempotencyToken
    RoleArn: RoleArn
    Tags: Optional[TagList]
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class CreatePipelineResponse(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]


class CreatePresignedDomainUrlRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    SessionExpirationDurationInSeconds: Optional[SessionExpirationDurationInSeconds]
    ExpiresInSeconds: Optional[ExpiresInSeconds]


class CreatePresignedDomainUrlResponse(TypedDict, total=False):
    AuthorizedUrl: Optional[PresignedDomainUrl]


class CreatePresignedNotebookInstanceUrlInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName
    SessionExpirationDurationInSeconds: Optional[SessionExpirationDurationInSeconds]


class CreatePresignedNotebookInstanceUrlOutput(TypedDict, total=False):
    AuthorizedUrl: Optional[NotebookInstanceUrl]


class ExperimentConfig(TypedDict, total=False):
    ExperimentName: Optional[ExperimentEntityName]
    TrialName: Optional[ExperimentEntityName]
    TrialComponentDisplayName: Optional[ExperimentEntityName]


ProcessingEnvironmentMap = Dict[ProcessingEnvironmentKey, ProcessingEnvironmentValue]


class ProcessingStoppingCondition(TypedDict, total=False):
    MaxRuntimeInSeconds: ProcessingMaxRuntimeInSeconds


class ProcessingClusterConfig(TypedDict, total=False):
    InstanceCount: ProcessingInstanceCount
    InstanceType: ProcessingInstanceType
    VolumeSizeInGB: ProcessingVolumeSizeInGB
    VolumeKmsKeyId: Optional[KmsKeyId]


class ProcessingResources(TypedDict, total=False):
    ClusterConfig: ProcessingClusterConfig


class ProcessingFeatureStoreOutput(TypedDict, total=False):
    FeatureGroupName: FeatureGroupName


class ProcessingS3Output(TypedDict, total=False):
    S3Uri: S3Uri
    LocalPath: ProcessingLocalPath
    S3UploadMode: ProcessingS3UploadMode


class ProcessingOutput(TypedDict, total=False):
    OutputName: String
    S3Output: Optional[ProcessingS3Output]
    FeatureStoreOutput: Optional[ProcessingFeatureStoreOutput]
    AppManaged: Optional[AppManaged]


ProcessingOutputs = List[ProcessingOutput]


class ProcessingOutputConfig(TypedDict, total=False):
    Outputs: ProcessingOutputs
    KmsKeyId: Optional[KmsKeyId]


class RedshiftDatasetDefinition(TypedDict, total=False):
    ClusterId: RedshiftClusterId
    Database: RedshiftDatabase
    DbUser: RedshiftUserName
    QueryString: RedshiftQueryString
    ClusterRoleArn: RoleArn
    OutputS3Uri: S3Uri
    KmsKeyId: Optional[KmsKeyId]
    OutputFormat: RedshiftResultFormat
    OutputCompression: Optional[RedshiftResultCompressionType]


class DatasetDefinition(TypedDict, total=False):
    AthenaDatasetDefinition: Optional[AthenaDatasetDefinition]
    RedshiftDatasetDefinition: Optional[RedshiftDatasetDefinition]
    LocalPath: Optional[ProcessingLocalPath]
    DataDistributionType: Optional[DataDistributionType]
    InputMode: Optional[InputMode]


class ProcessingS3Input(TypedDict, total=False):
    S3Uri: S3Uri
    LocalPath: Optional[ProcessingLocalPath]
    S3DataType: ProcessingS3DataType
    S3InputMode: Optional[ProcessingS3InputMode]
    S3DataDistributionType: Optional[ProcessingS3DataDistributionType]
    S3CompressionType: Optional[ProcessingS3CompressionType]


class ProcessingInput(TypedDict, total=False):
    InputName: String
    AppManaged: Optional[AppManaged]
    S3Input: Optional[ProcessingS3Input]
    DatasetDefinition: Optional[DatasetDefinition]


ProcessingInputs = List[ProcessingInput]


class CreateProcessingJobRequest(ServiceRequest):
    ProcessingInputs: Optional[ProcessingInputs]
    ProcessingOutputConfig: Optional[ProcessingOutputConfig]
    ProcessingJobName: ProcessingJobName
    ProcessingResources: ProcessingResources
    StoppingCondition: Optional[ProcessingStoppingCondition]
    AppSpecification: AppSpecification
    Environment: Optional[ProcessingEnvironmentMap]
    NetworkConfig: Optional[NetworkConfig]
    RoleArn: RoleArn
    Tags: Optional[TagList]
    ExperimentConfig: Optional[ExperimentConfig]


class CreateProcessingJobResponse(TypedDict, total=False):
    ProcessingJobArn: ProcessingJobArn


class ProvisioningParameter(TypedDict, total=False):
    Key: Optional[ProvisioningParameterKey]
    Value: Optional[ProvisioningParameterValue]


ProvisioningParameters = List[ProvisioningParameter]


class ServiceCatalogProvisioningDetails(TypedDict, total=False):
    ProductId: ServiceCatalogEntityId
    ProvisioningArtifactId: Optional[ServiceCatalogEntityId]
    PathId: Optional[ServiceCatalogEntityId]
    ProvisioningParameters: Optional[ProvisioningParameters]


class CreateProjectInput(ServiceRequest):
    ProjectName: ProjectEntityName
    ProjectDescription: Optional[EntityDescription]
    ServiceCatalogProvisioningDetails: ServiceCatalogProvisioningDetails
    Tags: Optional[TagList]


class CreateProjectOutput(TypedDict, total=False):
    ProjectArn: ProjectArn
    ProjectId: ProjectId


class CreateStudioLifecycleConfigRequest(ServiceRequest):
    StudioLifecycleConfigName: StudioLifecycleConfigName
    StudioLifecycleConfigContent: StudioLifecycleConfigContent
    StudioLifecycleConfigAppType: StudioLifecycleConfigAppType
    Tags: Optional[TagList]


class CreateStudioLifecycleConfigResponse(TypedDict, total=False):
    StudioLifecycleConfigArn: Optional[StudioLifecycleConfigArn]


TrainingEnvironmentMap = Dict[TrainingEnvironmentKey, TrainingEnvironmentValue]
RuleParameters = Dict[ConfigKey, ConfigValue]


class ProfilerRuleConfiguration(TypedDict, total=False):
    RuleConfigurationName: RuleConfigurationName
    LocalPath: Optional[DirectoryPath]
    S3OutputPath: Optional[S3Uri]
    RuleEvaluatorImage: AlgorithmImage
    InstanceType: Optional[ProcessingInstanceType]
    VolumeSizeInGB: Optional[OptionalVolumeSizeInGB]
    RuleParameters: Optional[RuleParameters]


ProfilerRuleConfigurations = List[ProfilerRuleConfiguration]
ProfilingParameters = Dict[ConfigKey, ConfigValue]
ProfilingIntervalInMilliseconds = int


class ProfilerConfig(TypedDict, total=False):
    S3OutputPath: S3Uri
    ProfilingIntervalInMilliseconds: Optional[ProfilingIntervalInMilliseconds]
    ProfilingParameters: Optional[ProfilingParameters]


class TensorBoardOutputConfig(TypedDict, total=False):
    LocalPath: Optional[DirectoryPath]
    S3OutputPath: S3Uri


class DebugRuleConfiguration(TypedDict, total=False):
    RuleConfigurationName: RuleConfigurationName
    LocalPath: Optional[DirectoryPath]
    S3OutputPath: Optional[S3Uri]
    RuleEvaluatorImage: AlgorithmImage
    InstanceType: Optional[ProcessingInstanceType]
    VolumeSizeInGB: Optional[OptionalVolumeSizeInGB]
    RuleParameters: Optional[RuleParameters]


DebugRuleConfigurations = List[DebugRuleConfiguration]
HookParameters = Dict[ConfigKey, ConfigValue]


class DebugHookConfig(TypedDict, total=False):
    LocalPath: Optional[DirectoryPath]
    S3OutputPath: S3Uri
    HookParameters: Optional[HookParameters]
    CollectionConfigurations: Optional[CollectionConfigurations]


class CreateTrainingJobRequest(ServiceRequest):
    TrainingJobName: TrainingJobName
    HyperParameters: Optional[HyperParameters]
    AlgorithmSpecification: AlgorithmSpecification
    RoleArn: RoleArn
    InputDataConfig: Optional[InputDataConfig]
    OutputDataConfig: OutputDataConfig
    ResourceConfig: ResourceConfig
    VpcConfig: Optional[VpcConfig]
    StoppingCondition: StoppingCondition
    Tags: Optional[TagList]
    EnableNetworkIsolation: Optional[Boolean]
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableManagedSpotTraining: Optional[Boolean]
    CheckpointConfig: Optional[CheckpointConfig]
    DebugHookConfig: Optional[DebugHookConfig]
    DebugRuleConfigurations: Optional[DebugRuleConfigurations]
    TensorBoardOutputConfig: Optional[TensorBoardOutputConfig]
    ExperimentConfig: Optional[ExperimentConfig]
    ProfilerConfig: Optional[ProfilerConfig]
    ProfilerRuleConfigurations: Optional[ProfilerRuleConfigurations]
    Environment: Optional[TrainingEnvironmentMap]
    RetryStrategy: Optional[RetryStrategy]


class CreateTrainingJobResponse(TypedDict, total=False):
    TrainingJobArn: TrainingJobArn


class DataProcessing(TypedDict, total=False):
    InputFilter: Optional[JsonPath]
    OutputFilter: Optional[JsonPath]
    JoinSource: Optional[JoinSource]


class ModelClientConfig(TypedDict, total=False):
    InvocationsTimeoutInSeconds: Optional[InvocationsTimeoutInSeconds]
    InvocationsMaxRetries: Optional[InvocationsMaxRetries]


class CreateTransformJobRequest(ServiceRequest):
    TransformJobName: TransformJobName
    ModelName: ModelName
    MaxConcurrentTransforms: Optional[MaxConcurrentTransforms]
    ModelClientConfig: Optional[ModelClientConfig]
    MaxPayloadInMB: Optional[MaxPayloadInMB]
    BatchStrategy: Optional[BatchStrategy]
    Environment: Optional[TransformEnvironmentMap]
    TransformInput: TransformInput
    TransformOutput: TransformOutput
    TransformResources: TransformResources
    DataProcessing: Optional[DataProcessing]
    Tags: Optional[TagList]
    ExperimentConfig: Optional[ExperimentConfig]


class CreateTransformJobResponse(TypedDict, total=False):
    TransformJobArn: TransformJobArn


class TrialComponentArtifact(TypedDict, total=False):
    MediaType: Optional[MediaType]
    Value: TrialComponentArtifactValue


TrialComponentArtifacts = Dict[TrialComponentKey64, TrialComponentArtifact]


class TrialComponentParameterValue(TypedDict, total=False):
    StringValue: Optional[StringParameterValue]
    NumberValue: Optional[DoubleParameterValue]


TrialComponentParameters = Dict[TrialComponentKey256, TrialComponentParameterValue]


class TrialComponentStatus(TypedDict, total=False):
    PrimaryStatus: Optional[TrialComponentPrimaryStatus]
    Message: Optional[TrialComponentStatusMessage]


class CreateTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]
    Status: Optional[TrialComponentStatus]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Parameters: Optional[TrialComponentParameters]
    InputArtifacts: Optional[TrialComponentArtifacts]
    OutputArtifacts: Optional[TrialComponentArtifacts]
    MetadataProperties: Optional[MetadataProperties]
    Tags: Optional[TagList]


class CreateTrialComponentResponse(TypedDict, total=False):
    TrialComponentArn: Optional[TrialComponentArn]


class CreateTrialRequest(ServiceRequest):
    TrialName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]
    ExperimentName: ExperimentEntityName
    MetadataProperties: Optional[MetadataProperties]
    Tags: Optional[TagList]


class CreateTrialResponse(TypedDict, total=False):
    TrialArn: Optional[TrialArn]


class CreateUserProfileRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    SingleSignOnUserIdentifier: Optional[SingleSignOnUserIdentifier]
    SingleSignOnUserValue: Optional[String256]
    Tags: Optional[TagList]
    UserSettings: Optional[UserSettings]


class CreateUserProfileResponse(TypedDict, total=False):
    UserProfileArn: Optional[UserProfileArn]


class SourceIpConfig(TypedDict, total=False):
    Cidrs: Cidrs


class OidcConfig(TypedDict, total=False):
    ClientId: ClientId
    ClientSecret: ClientSecret
    Issuer: OidcEndpoint
    AuthorizationEndpoint: OidcEndpoint
    TokenEndpoint: OidcEndpoint
    UserInfoEndpoint: OidcEndpoint
    LogoutEndpoint: OidcEndpoint
    JwksUri: OidcEndpoint


class CreateWorkforceRequest(ServiceRequest):
    CognitoConfig: Optional[CognitoConfig]
    OidcConfig: Optional[OidcConfig]
    SourceIpConfig: Optional[SourceIpConfig]
    WorkforceName: WorkforceName
    Tags: Optional[TagList]


class CreateWorkforceResponse(TypedDict, total=False):
    WorkforceArn: WorkforceArn


class NotificationConfiguration(TypedDict, total=False):
    NotificationTopicArn: Optional[NotificationTopicArn]


Groups = List[Group]


class OidcMemberDefinition(TypedDict, total=False):
    Groups: Groups


class MemberDefinition(TypedDict, total=False):
    CognitoMemberDefinition: Optional[CognitoMemberDefinition]
    OidcMemberDefinition: Optional[OidcMemberDefinition]


MemberDefinitions = List[MemberDefinition]


class CreateWorkteamRequest(ServiceRequest):
    WorkteamName: WorkteamName
    WorkforceName: Optional[WorkforceName]
    MemberDefinitions: MemberDefinitions
    Description: String200
    NotificationConfiguration: Optional[NotificationConfiguration]
    Tags: Optional[TagList]


class CreateWorkteamResponse(TypedDict, total=False):
    WorkteamArn: Optional[WorkteamArn]


CustomerMetadataKeyList = List[CustomerMetadataKey]


class DataCaptureConfigSummary(TypedDict, total=False):
    EnableCapture: EnableCapture
    CaptureStatus: CaptureStatus
    CurrentSamplingPercentage: SamplingPercentage
    DestinationS3Uri: DestinationS3Uri
    KmsKeyId: KmsKeyId


class DebugRuleEvaluationStatus(TypedDict, total=False):
    RuleConfigurationName: Optional[RuleConfigurationName]
    RuleEvaluationJobArn: Optional[ProcessingJobArn]
    RuleEvaluationStatus: Optional[RuleEvaluationStatus]
    StatusDetails: Optional[StatusDetails]
    LastModifiedTime: Optional[Timestamp]


DebugRuleEvaluationStatuses = List[DebugRuleEvaluationStatus]


class DeleteActionRequest(ServiceRequest):
    ActionName: ExperimentEntityName


class DeleteActionResponse(TypedDict, total=False):
    ActionArn: Optional[ActionArn]


class DeleteAlgorithmInput(ServiceRequest):
    AlgorithmName: EntityName


class DeleteAppImageConfigRequest(ServiceRequest):
    AppImageConfigName: AppImageConfigName


class DeleteAppRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    AppType: AppType
    AppName: AppName


class DeleteArtifactRequest(ServiceRequest):
    ArtifactArn: Optional[ArtifactArn]
    Source: Optional[ArtifactSource]


class DeleteArtifactResponse(TypedDict, total=False):
    ArtifactArn: Optional[ArtifactArn]


class DeleteAssociationRequest(ServiceRequest):
    SourceArn: AssociationEntityArn
    DestinationArn: AssociationEntityArn


class DeleteAssociationResponse(TypedDict, total=False):
    SourceArn: Optional[AssociationEntityArn]
    DestinationArn: Optional[AssociationEntityArn]


class DeleteCodeRepositoryInput(ServiceRequest):
    CodeRepositoryName: EntityName


class DeleteContextRequest(ServiceRequest):
    ContextName: ExperimentEntityName


class DeleteContextResponse(TypedDict, total=False):
    ContextArn: Optional[ContextArn]


class DeleteDataQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DeleteDeviceFleetRequest(ServiceRequest):
    DeviceFleetName: EntityName


class RetentionPolicy(TypedDict, total=False):
    HomeEfsFileSystem: Optional[RetentionType]


class DeleteDomainRequest(ServiceRequest):
    DomainId: DomainId
    RetentionPolicy: Optional[RetentionPolicy]


class DeleteEndpointConfigInput(ServiceRequest):
    EndpointConfigName: EndpointConfigName


class DeleteEndpointInput(ServiceRequest):
    EndpointName: EndpointName


class DeleteExperimentRequest(ServiceRequest):
    ExperimentName: ExperimentEntityName


class DeleteExperimentResponse(TypedDict, total=False):
    ExperimentArn: Optional[ExperimentArn]


class DeleteFeatureGroupRequest(ServiceRequest):
    FeatureGroupName: FeatureGroupName


class DeleteFlowDefinitionRequest(ServiceRequest):
    FlowDefinitionName: FlowDefinitionName


class DeleteFlowDefinitionResponse(TypedDict, total=False):
    pass


class DeleteHumanTaskUiRequest(ServiceRequest):
    HumanTaskUiName: HumanTaskUiName


class DeleteHumanTaskUiResponse(TypedDict, total=False):
    pass


class DeleteImageRequest(ServiceRequest):
    ImageName: ImageName


class DeleteImageResponse(TypedDict, total=False):
    pass


class DeleteImageVersionRequest(ServiceRequest):
    ImageName: ImageName
    Version: ImageVersionNumber


class DeleteImageVersionResponse(TypedDict, total=False):
    pass


class DeleteModelBiasJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DeleteModelExplainabilityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DeleteModelInput(ServiceRequest):
    ModelName: ModelName


class DeleteModelPackageGroupInput(ServiceRequest):
    ModelPackageGroupName: ArnOrName


class DeleteModelPackageGroupPolicyInput(ServiceRequest):
    ModelPackageGroupName: EntityName


class DeleteModelPackageInput(ServiceRequest):
    ModelPackageName: VersionedArnOrName


class DeleteModelQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DeleteMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName


class DeleteNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName


class DeleteNotebookInstanceLifecycleConfigInput(ServiceRequest):
    NotebookInstanceLifecycleConfigName: NotebookInstanceLifecycleConfigName


class DeletePipelineRequest(ServiceRequest):
    PipelineName: PipelineName
    ClientRequestToken: IdempotencyToken


class DeletePipelineResponse(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]


class DeleteProjectInput(ServiceRequest):
    ProjectName: ProjectEntityName


class DeleteStudioLifecycleConfigRequest(ServiceRequest):
    StudioLifecycleConfigName: StudioLifecycleConfigName


TagKeyList = List[TagKey]


class DeleteTagsInput(ServiceRequest):
    ResourceArn: ResourceArn
    TagKeys: TagKeyList


class DeleteTagsOutput(TypedDict, total=False):
    pass


class DeleteTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityName


class DeleteTrialComponentResponse(TypedDict, total=False):
    TrialComponentArn: Optional[TrialComponentArn]


class DeleteTrialRequest(ServiceRequest):
    TrialName: ExperimentEntityName


class DeleteTrialResponse(TypedDict, total=False):
    TrialArn: Optional[TrialArn]


class DeleteUserProfileRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName


class DeleteWorkforceRequest(ServiceRequest):
    WorkforceName: WorkforceName


class DeleteWorkforceResponse(TypedDict, total=False):
    pass


class DeleteWorkteamRequest(ServiceRequest):
    WorkteamName: WorkteamName


class DeleteWorkteamResponse(TypedDict, total=False):
    Success: Success


class DeployedImage(TypedDict, total=False):
    SpecifiedImage: Optional[ContainerImage]
    ResolvedImage: Optional[ContainerImage]
    ResolutionTime: Optional[Timestamp]


DeployedImages = List[DeployedImage]
DeviceNames = List[DeviceName]


class DeregisterDevicesRequest(ServiceRequest):
    DeviceFleetName: EntityName
    DeviceNames: DeviceNames


class DescribeActionRequest(ServiceRequest):
    ActionName: ExperimentEntityName


class DescribeActionResponse(TypedDict, total=False):
    ActionName: Optional[ExperimentEntityNameOrArn]
    ActionArn: Optional[ActionArn]
    Source: Optional[ActionSource]
    ActionType: Optional[String256]
    Description: Optional[ExperimentDescription]
    Status: Optional[ActionStatus]
    Properties: Optional[LineageEntityParameters]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]
    LineageGroupArn: Optional[LineageGroupArn]


class DescribeAlgorithmInput(ServiceRequest):
    AlgorithmName: ArnOrName


class DescribeAlgorithmOutput(TypedDict, total=False):
    AlgorithmName: EntityName
    AlgorithmArn: AlgorithmArn
    AlgorithmDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    TrainingSpecification: TrainingSpecification
    InferenceSpecification: Optional[InferenceSpecification]
    ValidationSpecification: Optional[AlgorithmValidationSpecification]
    AlgorithmStatus: AlgorithmStatus
    AlgorithmStatusDetails: AlgorithmStatusDetails
    ProductId: Optional[ProductId]
    CertifyForMarketplace: Optional[CertifyForMarketplace]


class DescribeAppImageConfigRequest(ServiceRequest):
    AppImageConfigName: AppImageConfigName


class DescribeAppImageConfigResponse(TypedDict, total=False):
    AppImageConfigArn: Optional[AppImageConfigArn]
    AppImageConfigName: Optional[AppImageConfigName]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    KernelGatewayImageConfig: Optional[KernelGatewayImageConfig]


class DescribeAppRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    AppType: AppType
    AppName: AppName


class DescribeAppResponse(TypedDict, total=False):
    AppArn: Optional[AppArn]
    AppType: Optional[AppType]
    AppName: Optional[AppName]
    DomainId: Optional[DomainId]
    UserProfileName: Optional[UserProfileName]
    Status: Optional[AppStatus]
    LastHealthCheckTimestamp: Optional[Timestamp]
    LastUserActivityTimestamp: Optional[Timestamp]
    CreationTime: Optional[CreationTime]
    FailureReason: Optional[FailureReason]
    ResourceSpec: Optional[ResourceSpec]


class DescribeArtifactRequest(ServiceRequest):
    ArtifactArn: ArtifactArn


class DescribeArtifactResponse(TypedDict, total=False):
    ArtifactName: Optional[ExperimentEntityNameOrArn]
    ArtifactArn: Optional[ArtifactArn]
    Source: Optional[ArtifactSource]
    ArtifactType: Optional[String256]
    Properties: Optional[LineageEntityParameters]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]
    LineageGroupArn: Optional[LineageGroupArn]


class DescribeAutoMLJobRequest(ServiceRequest):
    AutoMLJobName: AutoMLJobName


class ModelDeployResult(TypedDict, total=False):
    EndpointName: Optional[EndpointName]


class ResolvedAttributes(TypedDict, total=False):
    AutoMLJobObjective: Optional[AutoMLJobObjective]
    ProblemType: Optional[ProblemType]
    CompletionCriteria: Optional[AutoMLJobCompletionCriteria]


class DescribeAutoMLJobResponse(TypedDict, total=False):
    AutoMLJobName: AutoMLJobName
    AutoMLJobArn: AutoMLJobArn
    InputDataConfig: AutoMLInputDataConfig
    OutputDataConfig: AutoMLOutputDataConfig
    RoleArn: RoleArn
    AutoMLJobObjective: Optional[AutoMLJobObjective]
    ProblemType: Optional[ProblemType]
    AutoMLJobConfig: Optional[AutoMLJobConfig]
    CreationTime: Timestamp
    EndTime: Optional[Timestamp]
    LastModifiedTime: Timestamp
    FailureReason: Optional[AutoMLFailureReason]
    PartialFailureReasons: Optional[AutoMLPartialFailureReasons]
    BestCandidate: Optional[AutoMLCandidate]
    AutoMLJobStatus: AutoMLJobStatus
    AutoMLJobSecondaryStatus: AutoMLJobSecondaryStatus
    GenerateCandidateDefinitionsOnly: Optional[GenerateCandidateDefinitionsOnly]
    AutoMLJobArtifacts: Optional[AutoMLJobArtifacts]
    ResolvedAttributes: Optional[ResolvedAttributes]
    ModelDeployConfig: Optional[ModelDeployConfig]
    ModelDeployResult: Optional[ModelDeployResult]


class DescribeCodeRepositoryInput(ServiceRequest):
    CodeRepositoryName: EntityName


class DescribeCodeRepositoryOutput(TypedDict, total=False):
    CodeRepositoryName: EntityName
    CodeRepositoryArn: CodeRepositoryArn
    CreationTime: CreationTime
    LastModifiedTime: LastModifiedTime
    GitConfig: Optional[GitConfig]


class DescribeCompilationJobRequest(ServiceRequest):
    CompilationJobName: EntityName


class ModelDigests(TypedDict, total=False):
    ArtifactDigest: Optional[ArtifactDigest]


class ModelArtifacts(TypedDict, total=False):
    S3ModelArtifacts: S3Uri


class DescribeCompilationJobResponse(TypedDict, total=False):
    CompilationJobName: EntityName
    CompilationJobArn: CompilationJobArn
    CompilationJobStatus: CompilationJobStatus
    CompilationStartTime: Optional[Timestamp]
    CompilationEndTime: Optional[Timestamp]
    StoppingCondition: StoppingCondition
    InferenceImage: Optional[InferenceImage]
    ModelPackageVersionArn: Optional[ModelPackageArn]
    CreationTime: CreationTime
    LastModifiedTime: LastModifiedTime
    FailureReason: FailureReason
    ModelArtifacts: ModelArtifacts
    ModelDigests: Optional[ModelDigests]
    RoleArn: RoleArn
    InputConfig: InputConfig
    OutputConfig: OutputConfig
    VpcConfig: Optional[NeoVpcConfig]


class DescribeContextRequest(ServiceRequest):
    ContextName: ExperimentEntityNameOrArn


class DescribeContextResponse(TypedDict, total=False):
    ContextName: Optional[ExperimentEntityName]
    ContextArn: Optional[ContextArn]
    Source: Optional[ContextSource]
    ContextType: Optional[String256]
    Description: Optional[ExperimentDescription]
    Properties: Optional[LineageEntityParameters]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    LineageGroupArn: Optional[LineageGroupArn]


class DescribeDataQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DescribeDataQualityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn
    JobDefinitionName: MonitoringJobDefinitionName
    CreationTime: Timestamp
    DataQualityBaselineConfig: Optional[DataQualityBaselineConfig]
    DataQualityAppSpecification: DataQualityAppSpecification
    DataQualityJobInput: DataQualityJobInput
    DataQualityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]


class DescribeDeviceFleetRequest(ServiceRequest):
    DeviceFleetName: EntityName


class DescribeDeviceFleetResponse(TypedDict, total=False):
    DeviceFleetName: EntityName
    DeviceFleetArn: DeviceFleetArn
    OutputConfig: EdgeOutputConfig
    Description: Optional[DeviceFleetDescription]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    RoleArn: Optional[RoleArn]
    IotRoleAlias: Optional[IotRoleAlias]


class DescribeDeviceRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    DeviceName: EntityName
    DeviceFleetName: EntityName


class EdgeModel(TypedDict, total=False):
    ModelName: EntityName
    ModelVersion: EdgeVersion
    LatestSampleTime: Optional[Timestamp]
    LatestInference: Optional[Timestamp]


EdgeModels = List[EdgeModel]


class DescribeDeviceResponse(TypedDict, total=False):
    DeviceArn: Optional[DeviceArn]
    DeviceName: EntityName
    Description: Optional[DeviceDescription]
    DeviceFleetName: EntityName
    IotThingName: Optional[ThingName]
    RegistrationTime: Timestamp
    LatestHeartbeat: Optional[Timestamp]
    Models: Optional[EdgeModels]
    MaxModels: Optional[Integer]
    NextToken: Optional[NextToken]
    AgentVersion: Optional[EdgeVersion]


class DescribeDomainRequest(ServiceRequest):
    DomainId: DomainId


class DescribeDomainResponse(TypedDict, total=False):
    DomainArn: Optional[DomainArn]
    DomainId: Optional[DomainId]
    DomainName: Optional[DomainName]
    HomeEfsFileSystemId: Optional[ResourceId]
    SingleSignOnManagedApplicationInstanceId: Optional[String256]
    Status: Optional[DomainStatus]
    CreationTime: Optional[CreationTime]
    LastModifiedTime: Optional[LastModifiedTime]
    FailureReason: Optional[FailureReason]
    AuthMode: Optional[AuthMode]
    DefaultUserSettings: Optional[UserSettings]
    AppNetworkAccessType: Optional[AppNetworkAccessType]
    HomeEfsFileSystemKmsKeyId: Optional[KmsKeyId]
    SubnetIds: Optional[Subnets]
    Url: Optional[String1024]
    VpcId: Optional[VpcId]
    KmsKeyId: Optional[KmsKeyId]
    DomainSettings: Optional[DomainSettings]
    AppSecurityGroupManagement: Optional[AppSecurityGroupManagement]
    SecurityGroupIdForDomainBoundary: Optional[SecurityGroupId]


class DescribeEdgePackagingJobRequest(ServiceRequest):
    EdgePackagingJobName: EntityName


class EdgePresetDeploymentOutput(TypedDict, total=False):
    Type: EdgePresetDeploymentType
    Artifact: Optional[EdgePresetDeploymentArtifact]
    Status: Optional[EdgePresetDeploymentStatus]
    StatusMessage: Optional[String]


class DescribeEdgePackagingJobResponse(TypedDict, total=False):
    EdgePackagingJobArn: EdgePackagingJobArn
    EdgePackagingJobName: EntityName
    CompilationJobName: Optional[EntityName]
    ModelName: Optional[EntityName]
    ModelVersion: Optional[EdgeVersion]
    RoleArn: Optional[RoleArn]
    OutputConfig: Optional[EdgeOutputConfig]
    ResourceKey: Optional[KmsKeyId]
    EdgePackagingJobStatus: EdgePackagingJobStatus
    EdgePackagingJobStatusMessage: Optional[String]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    ModelArtifact: Optional[S3Uri]
    ModelSignature: Optional[String]
    PresetDeploymentOutput: Optional[EdgePresetDeploymentOutput]


class DescribeEndpointConfigInput(ServiceRequest):
    EndpointConfigName: EndpointConfigName


class DescribeEndpointConfigOutput(TypedDict, total=False):
    EndpointConfigName: EndpointConfigName
    EndpointConfigArn: EndpointConfigArn
    ProductionVariants: ProductionVariantList
    DataCaptureConfig: Optional[DataCaptureConfig]
    KmsKeyId: Optional[KmsKeyId]
    CreationTime: Timestamp
    AsyncInferenceConfig: Optional[AsyncInferenceConfig]


class DescribeEndpointInput(ServiceRequest):
    EndpointName: EndpointName


class ProductionVariantStatus(TypedDict, total=False):
    Status: VariantStatus
    StatusMessage: Optional[VariantStatusMessage]
    StartTime: Optional[Timestamp]


ProductionVariantStatusList = List[ProductionVariantStatus]


class PendingProductionVariantSummary(TypedDict, total=False):
    VariantName: VariantName
    DeployedImages: Optional[DeployedImages]
    CurrentWeight: Optional[VariantWeight]
    DesiredWeight: Optional[VariantWeight]
    CurrentInstanceCount: Optional[TaskCount]
    DesiredInstanceCount: Optional[TaskCount]
    InstanceType: Optional[ProductionVariantInstanceType]
    AcceleratorType: Optional[ProductionVariantAcceleratorType]
    VariantStatus: Optional[ProductionVariantStatusList]
    CurrentServerlessConfig: Optional[ProductionVariantServerlessConfig]
    DesiredServerlessConfig: Optional[ProductionVariantServerlessConfig]


PendingProductionVariantSummaryList = List[PendingProductionVariantSummary]


class PendingDeploymentSummary(TypedDict, total=False):
    EndpointConfigName: EndpointConfigName
    ProductionVariants: Optional[PendingProductionVariantSummaryList]
    StartTime: Optional[Timestamp]


class ProductionVariantSummary(TypedDict, total=False):
    VariantName: VariantName
    DeployedImages: Optional[DeployedImages]
    CurrentWeight: Optional[VariantWeight]
    DesiredWeight: Optional[VariantWeight]
    CurrentInstanceCount: Optional[TaskCount]
    DesiredInstanceCount: Optional[TaskCount]
    VariantStatus: Optional[ProductionVariantStatusList]
    CurrentServerlessConfig: Optional[ProductionVariantServerlessConfig]
    DesiredServerlessConfig: Optional[ProductionVariantServerlessConfig]


ProductionVariantSummaryList = List[ProductionVariantSummary]


class DescribeEndpointOutput(TypedDict, total=False):
    EndpointName: EndpointName
    EndpointArn: EndpointArn
    EndpointConfigName: EndpointConfigName
    ProductionVariants: Optional[ProductionVariantSummaryList]
    DataCaptureConfig: Optional[DataCaptureConfigSummary]
    EndpointStatus: EndpointStatus
    FailureReason: Optional[FailureReason]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    LastDeploymentConfig: Optional[DeploymentConfig]
    AsyncInferenceConfig: Optional[AsyncInferenceConfig]
    PendingDeploymentSummary: Optional[PendingDeploymentSummary]


class DescribeExperimentRequest(ServiceRequest):
    ExperimentName: ExperimentEntityName


class ExperimentSource(TypedDict, total=False):
    SourceArn: ExperimentSourceArn
    SourceType: Optional[SourceType]


class DescribeExperimentResponse(TypedDict, total=False):
    ExperimentName: Optional[ExperimentEntityName]
    ExperimentArn: Optional[ExperimentArn]
    DisplayName: Optional[ExperimentEntityName]
    Source: Optional[ExperimentSource]
    Description: Optional[ExperimentDescription]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]


class DescribeFeatureGroupRequest(ServiceRequest):
    FeatureGroupName: FeatureGroupName
    NextToken: Optional[NextToken]


class OfflineStoreStatus(TypedDict, total=False):
    Status: OfflineStoreStatusValue
    BlockedReason: Optional[BlockedReason]


class DescribeFeatureGroupResponse(TypedDict, total=False):
    FeatureGroupArn: FeatureGroupArn
    FeatureGroupName: FeatureGroupName
    RecordIdentifierFeatureName: FeatureName
    EventTimeFeatureName: FeatureName
    FeatureDefinitions: FeatureDefinitions
    CreationTime: CreationTime
    OnlineStoreConfig: Optional[OnlineStoreConfig]
    OfflineStoreConfig: Optional[OfflineStoreConfig]
    RoleArn: Optional[RoleArn]
    FeatureGroupStatus: Optional[FeatureGroupStatus]
    OfflineStoreStatus: Optional[OfflineStoreStatus]
    FailureReason: Optional[FailureReason]
    Description: Optional[Description]
    NextToken: NextToken


class DescribeFlowDefinitionRequest(ServiceRequest):
    FlowDefinitionName: FlowDefinitionName


class DescribeFlowDefinitionResponse(TypedDict, total=False):
    FlowDefinitionArn: FlowDefinitionArn
    FlowDefinitionName: FlowDefinitionName
    FlowDefinitionStatus: FlowDefinitionStatus
    CreationTime: Timestamp
    HumanLoopRequestSource: Optional[HumanLoopRequestSource]
    HumanLoopActivationConfig: Optional[HumanLoopActivationConfig]
    HumanLoopConfig: HumanLoopConfig
    OutputConfig: FlowDefinitionOutputConfig
    RoleArn: RoleArn
    FailureReason: Optional[FailureReason]


class DescribeHumanTaskUiRequest(ServiceRequest):
    HumanTaskUiName: HumanTaskUiName


class UiTemplateInfo(TypedDict, total=False):
    Url: Optional[TemplateUrl]
    ContentSha256: Optional[TemplateContentSha256]


class DescribeHumanTaskUiResponse(TypedDict, total=False):
    HumanTaskUiArn: HumanTaskUiArn
    HumanTaskUiName: HumanTaskUiName
    HumanTaskUiStatus: Optional[HumanTaskUiStatus]
    CreationTime: Timestamp
    UiTemplate: UiTemplateInfo


class DescribeHyperParameterTuningJobRequest(ServiceRequest):
    HyperParameterTuningJobName: HyperParameterTuningJobName


class FinalHyperParameterTuningJobObjectiveMetric(TypedDict, total=False):
    Type: Optional[HyperParameterTuningJobObjectiveType]
    MetricName: MetricName
    Value: MetricValue


class HyperParameterTrainingJobSummary(TypedDict, total=False):
    TrainingJobDefinitionName: Optional[HyperParameterTrainingJobDefinitionName]
    TrainingJobName: TrainingJobName
    TrainingJobArn: TrainingJobArn
    TuningJobName: Optional[HyperParameterTuningJobName]
    CreationTime: Timestamp
    TrainingStartTime: Optional[Timestamp]
    TrainingEndTime: Optional[Timestamp]
    TrainingJobStatus: TrainingJobStatus
    TunedHyperParameters: HyperParameters
    FailureReason: Optional[FailureReason]
    FinalHyperParameterTuningJobObjectiveMetric: Optional[
        FinalHyperParameterTuningJobObjectiveMetric
    ]
    ObjectiveStatus: Optional[ObjectiveStatus]


class ObjectiveStatusCounters(TypedDict, total=False):
    Succeeded: Optional[ObjectiveStatusCounter]
    Pending: Optional[ObjectiveStatusCounter]
    Failed: Optional[ObjectiveStatusCounter]


class TrainingJobStatusCounters(TypedDict, total=False):
    Completed: Optional[TrainingJobStatusCounter]
    InProgress: Optional[TrainingJobStatusCounter]
    RetryableError: Optional[TrainingJobStatusCounter]
    NonRetryableError: Optional[TrainingJobStatusCounter]
    Stopped: Optional[TrainingJobStatusCounter]


class DescribeHyperParameterTuningJobResponse(TypedDict, total=False):
    HyperParameterTuningJobName: HyperParameterTuningJobName
    HyperParameterTuningJobArn: HyperParameterTuningJobArn
    HyperParameterTuningJobConfig: HyperParameterTuningJobConfig
    TrainingJobDefinition: Optional[HyperParameterTrainingJobDefinition]
    TrainingJobDefinitions: Optional[HyperParameterTrainingJobDefinitions]
    HyperParameterTuningJobStatus: HyperParameterTuningJobStatus
    CreationTime: Timestamp
    HyperParameterTuningEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    TrainingJobStatusCounters: TrainingJobStatusCounters
    ObjectiveStatusCounters: ObjectiveStatusCounters
    BestTrainingJob: Optional[HyperParameterTrainingJobSummary]
    OverallBestTrainingJob: Optional[HyperParameterTrainingJobSummary]
    WarmStartConfig: Optional[HyperParameterTuningJobWarmStartConfig]
    FailureReason: Optional[FailureReason]


class DescribeImageRequest(ServiceRequest):
    ImageName: ImageName


class DescribeImageResponse(TypedDict, total=False):
    CreationTime: Optional[Timestamp]
    Description: Optional[ImageDescription]
    DisplayName: Optional[ImageDisplayName]
    FailureReason: Optional[FailureReason]
    ImageArn: Optional[ImageArn]
    ImageName: Optional[ImageName]
    ImageStatus: Optional[ImageStatus]
    LastModifiedTime: Optional[Timestamp]
    RoleArn: Optional[RoleArn]


class DescribeImageVersionRequest(ServiceRequest):
    ImageName: ImageName
    Version: Optional[ImageVersionNumber]


class DescribeImageVersionResponse(TypedDict, total=False):
    BaseImage: Optional[ImageBaseImage]
    ContainerImage: Optional[ImageContainerImage]
    CreationTime: Optional[Timestamp]
    FailureReason: Optional[FailureReason]
    ImageArn: Optional[ImageArn]
    ImageVersionArn: Optional[ImageVersionArn]
    ImageVersionStatus: Optional[ImageVersionStatus]
    LastModifiedTime: Optional[Timestamp]
    Version: Optional[ImageVersionNumber]


class DescribeInferenceRecommendationsJobRequest(ServiceRequest):
    JobName: RecommendationJobName


class EnvironmentParameter(TypedDict, total=False):
    Key: String
    ValueType: String
    Value: String


EnvironmentParameters = List[EnvironmentParameter]


class ModelConfiguration(TypedDict, total=False):
    InferenceSpecificationName: Optional[InferenceSpecificationName]
    EnvironmentParameters: Optional[EnvironmentParameters]


class EndpointOutputConfiguration(TypedDict, total=False):
    EndpointName: String
    VariantName: String
    InstanceType: ProductionVariantInstanceType
    InitialInstanceCount: Integer


class RecommendationMetrics(TypedDict, total=False):
    CostPerHour: Float
    CostPerInference: Float
    MaxInvocations: Integer
    ModelLatency: Integer


class InferenceRecommendation(TypedDict, total=False):
    Metrics: RecommendationMetrics
    EndpointConfiguration: EndpointOutputConfiguration
    ModelConfiguration: ModelConfiguration


InferenceRecommendations = List[InferenceRecommendation]


class DescribeInferenceRecommendationsJobResponse(TypedDict, total=False):
    JobName: RecommendationJobName
    JobDescription: Optional[RecommendationJobDescription]
    JobType: RecommendationJobType
    JobArn: RecommendationJobArn
    RoleArn: RoleArn
    Status: RecommendationJobStatus
    CreationTime: CreationTime
    CompletionTime: Optional[Timestamp]
    LastModifiedTime: LastModifiedTime
    FailureReason: Optional[FailureReason]
    InputConfig: RecommendationJobInputConfig
    StoppingConditions: Optional[RecommendationJobStoppingConditions]
    InferenceRecommendations: Optional[InferenceRecommendations]


class DescribeLabelingJobRequest(ServiceRequest):
    LabelingJobName: LabelingJobName


class LabelingJobOutput(TypedDict, total=False):
    OutputDatasetS3Uri: S3Uri
    FinalActiveLearningModelArn: Optional[ModelArn]


class LabelCounters(TypedDict, total=False):
    TotalLabeled: Optional[LabelCounter]
    HumanLabeled: Optional[LabelCounter]
    MachineLabeled: Optional[LabelCounter]
    FailedNonRetryableError: Optional[LabelCounter]
    Unlabeled: Optional[LabelCounter]


class DescribeLabelingJobResponse(TypedDict, total=False):
    LabelingJobStatus: LabelingJobStatus
    LabelCounters: LabelCounters
    FailureReason: Optional[FailureReason]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    JobReferenceCode: JobReferenceCode
    LabelingJobName: LabelingJobName
    LabelingJobArn: LabelingJobArn
    LabelAttributeName: Optional[LabelAttributeName]
    InputConfig: LabelingJobInputConfig
    OutputConfig: LabelingJobOutputConfig
    RoleArn: RoleArn
    LabelCategoryConfigS3Uri: Optional[S3Uri]
    StoppingConditions: Optional[LabelingJobStoppingConditions]
    LabelingJobAlgorithmsConfig: Optional[LabelingJobAlgorithmsConfig]
    HumanTaskConfig: HumanTaskConfig
    Tags: Optional[TagList]
    LabelingJobOutput: Optional[LabelingJobOutput]


class DescribeLineageGroupRequest(ServiceRequest):
    LineageGroupName: ExperimentEntityName


class DescribeLineageGroupResponse(TypedDict, total=False):
    LineageGroupName: Optional[ExperimentEntityName]
    LineageGroupArn: Optional[LineageGroupArn]
    DisplayName: Optional[ExperimentEntityName]
    Description: Optional[ExperimentDescription]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]


class DescribeModelBiasJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DescribeModelBiasJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn
    JobDefinitionName: MonitoringJobDefinitionName
    CreationTime: Timestamp
    ModelBiasBaselineConfig: Optional[ModelBiasBaselineConfig]
    ModelBiasAppSpecification: ModelBiasAppSpecification
    ModelBiasJobInput: ModelBiasJobInput
    ModelBiasJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]


class DescribeModelExplainabilityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DescribeModelExplainabilityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn
    JobDefinitionName: MonitoringJobDefinitionName
    CreationTime: Timestamp
    ModelExplainabilityBaselineConfig: Optional[ModelExplainabilityBaselineConfig]
    ModelExplainabilityAppSpecification: ModelExplainabilityAppSpecification
    ModelExplainabilityJobInput: ModelExplainabilityJobInput
    ModelExplainabilityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]


class DescribeModelInput(ServiceRequest):
    ModelName: ModelName


class DescribeModelOutput(TypedDict, total=False):
    ModelName: ModelName
    PrimaryContainer: Optional[ContainerDefinition]
    Containers: Optional[ContainerDefinitionList]
    InferenceExecutionConfig: Optional[InferenceExecutionConfig]
    ExecutionRoleArn: RoleArn
    VpcConfig: Optional[VpcConfig]
    CreationTime: Timestamp
    ModelArn: ModelArn
    EnableNetworkIsolation: Optional[Boolean]


class DescribeModelPackageGroupInput(ServiceRequest):
    ModelPackageGroupName: ArnOrName


class DescribeModelPackageGroupOutput(TypedDict, total=False):
    ModelPackageGroupName: EntityName
    ModelPackageGroupArn: ModelPackageGroupArn
    ModelPackageGroupDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    CreatedBy: UserContext
    ModelPackageGroupStatus: ModelPackageGroupStatus


class DescribeModelPackageInput(ServiceRequest):
    ModelPackageName: VersionedArnOrName


class ModelPackageStatusItem(TypedDict, total=False):
    Name: EntityName
    Status: DetailedModelPackageStatus
    FailureReason: Optional[String]


ModelPackageStatusItemList = List[ModelPackageStatusItem]


class ModelPackageStatusDetails(TypedDict, total=False):
    ValidationStatuses: ModelPackageStatusItemList
    ImageScanStatuses: Optional[ModelPackageStatusItemList]


class DescribeModelPackageOutput(TypedDict, total=False):
    ModelPackageName: EntityName
    ModelPackageGroupName: Optional[EntityName]
    ModelPackageVersion: Optional[ModelPackageVersion]
    ModelPackageArn: ModelPackageArn
    ModelPackageDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    InferenceSpecification: Optional[InferenceSpecification]
    SourceAlgorithmSpecification: Optional[SourceAlgorithmSpecification]
    ValidationSpecification: Optional[ModelPackageValidationSpecification]
    ModelPackageStatus: ModelPackageStatus
    ModelPackageStatusDetails: ModelPackageStatusDetails
    CertifyForMarketplace: Optional[CertifyForMarketplace]
    ModelApprovalStatus: Optional[ModelApprovalStatus]
    CreatedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]
    ModelMetrics: Optional[ModelMetrics]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    ApprovalDescription: Optional[ApprovalDescription]
    CustomerMetadataProperties: Optional[CustomerMetadataMap]
    DriftCheckBaselines: Optional[DriftCheckBaselines]
    Domain: Optional[String]
    Task: Optional[String]
    SamplePayloadUrl: Optional[String]
    AdditionalInferenceSpecifications: Optional[AdditionalInferenceSpecifications]


class DescribeModelQualityJobDefinitionRequest(ServiceRequest):
    JobDefinitionName: MonitoringJobDefinitionName


class DescribeModelQualityJobDefinitionResponse(TypedDict, total=False):
    JobDefinitionArn: MonitoringJobDefinitionArn
    JobDefinitionName: MonitoringJobDefinitionName
    CreationTime: Timestamp
    ModelQualityBaselineConfig: Optional[ModelQualityBaselineConfig]
    ModelQualityAppSpecification: ModelQualityAppSpecification
    ModelQualityJobInput: ModelQualityJobInput
    ModelQualityJobOutputConfig: MonitoringOutputConfig
    JobResources: MonitoringResources
    NetworkConfig: Optional[MonitoringNetworkConfig]
    RoleArn: RoleArn
    StoppingCondition: Optional[MonitoringStoppingCondition]


class DescribeMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName


class MonitoringExecutionSummary(TypedDict, total=False):
    MonitoringScheduleName: MonitoringScheduleName
    ScheduledTime: Timestamp
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    MonitoringExecutionStatus: ExecutionStatus
    ProcessingJobArn: Optional[ProcessingJobArn]
    EndpointName: Optional[EndpointName]
    FailureReason: Optional[FailureReason]
    MonitoringJobDefinitionName: Optional[MonitoringJobDefinitionName]
    MonitoringType: Optional[MonitoringType]


class DescribeMonitoringScheduleResponse(TypedDict, total=False):
    MonitoringScheduleArn: MonitoringScheduleArn
    MonitoringScheduleName: MonitoringScheduleName
    MonitoringScheduleStatus: ScheduleStatus
    MonitoringType: Optional[MonitoringType]
    FailureReason: Optional[FailureReason]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    MonitoringScheduleConfig: MonitoringScheduleConfig
    EndpointName: Optional[EndpointName]
    LastMonitoringExecutionSummary: Optional[MonitoringExecutionSummary]


class DescribeNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName


class DescribeNotebookInstanceLifecycleConfigInput(ServiceRequest):
    NotebookInstanceLifecycleConfigName: NotebookInstanceLifecycleConfigName


class DescribeNotebookInstanceLifecycleConfigOutput(TypedDict, total=False):
    NotebookInstanceLifecycleConfigArn: Optional[NotebookInstanceLifecycleConfigArn]
    NotebookInstanceLifecycleConfigName: Optional[NotebookInstanceLifecycleConfigName]
    OnCreate: Optional[NotebookInstanceLifecycleConfigList]
    OnStart: Optional[NotebookInstanceLifecycleConfigList]
    LastModifiedTime: Optional[LastModifiedTime]
    CreationTime: Optional[CreationTime]


class DescribeNotebookInstanceOutput(TypedDict, total=False):
    NotebookInstanceArn: Optional[NotebookInstanceArn]
    NotebookInstanceName: Optional[NotebookInstanceName]
    NotebookInstanceStatus: Optional[NotebookInstanceStatus]
    FailureReason: Optional[FailureReason]
    Url: Optional[NotebookInstanceUrl]
    InstanceType: Optional[InstanceType]
    SubnetId: Optional[SubnetId]
    SecurityGroups: Optional[SecurityGroupIds]
    RoleArn: Optional[RoleArn]
    KmsKeyId: Optional[KmsKeyId]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    LastModifiedTime: Optional[LastModifiedTime]
    CreationTime: Optional[CreationTime]
    NotebookInstanceLifecycleConfigName: Optional[NotebookInstanceLifecycleConfigName]
    DirectInternetAccess: Optional[DirectInternetAccess]
    VolumeSizeInGB: Optional[NotebookInstanceVolumeSizeInGB]
    AcceleratorTypes: Optional[NotebookInstanceAcceleratorTypes]
    DefaultCodeRepository: Optional[CodeRepositoryNameOrUrl]
    AdditionalCodeRepositories: Optional[AdditionalCodeRepositoryNamesOrUrls]
    RootAccess: Optional[RootAccess]
    PlatformIdentifier: Optional[PlatformIdentifier]


class DescribePipelineDefinitionForExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn


class DescribePipelineDefinitionForExecutionResponse(TypedDict, total=False):
    PipelineDefinition: Optional[PipelineDefinition]
    CreationTime: Optional[Timestamp]


class DescribePipelineExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn


class PipelineExperimentConfig(TypedDict, total=False):
    ExperimentName: Optional[ExperimentEntityName]
    TrialName: Optional[ExperimentEntityName]


class DescribePipelineExecutionResponse(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]
    PipelineExecutionArn: Optional[PipelineExecutionArn]
    PipelineExecutionDisplayName: Optional[PipelineExecutionName]
    PipelineExecutionStatus: Optional[PipelineExecutionStatus]
    PipelineExecutionDescription: Optional[PipelineExecutionDescription]
    PipelineExperimentConfig: Optional[PipelineExperimentConfig]
    FailureReason: Optional[PipelineExecutionFailureReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedBy: Optional[UserContext]
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class DescribePipelineRequest(ServiceRequest):
    PipelineName: PipelineName


class DescribePipelineResponse(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]
    PipelineName: Optional[PipelineName]
    PipelineDisplayName: Optional[PipelineName]
    PipelineDefinition: Optional[PipelineDefinition]
    PipelineDescription: Optional[PipelineDescription]
    RoleArn: Optional[RoleArn]
    PipelineStatus: Optional[PipelineStatus]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastRunTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedBy: Optional[UserContext]
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class DescribeProcessingJobRequest(ServiceRequest):
    ProcessingJobName: ProcessingJobName


class DescribeProcessingJobResponse(TypedDict, total=False):
    ProcessingInputs: Optional[ProcessingInputs]
    ProcessingOutputConfig: Optional[ProcessingOutputConfig]
    ProcessingJobName: ProcessingJobName
    ProcessingResources: ProcessingResources
    StoppingCondition: Optional[ProcessingStoppingCondition]
    AppSpecification: AppSpecification
    Environment: Optional[ProcessingEnvironmentMap]
    NetworkConfig: Optional[NetworkConfig]
    RoleArn: Optional[RoleArn]
    ExperimentConfig: Optional[ExperimentConfig]
    ProcessingJobArn: ProcessingJobArn
    ProcessingJobStatus: ProcessingJobStatus
    ExitMessage: Optional[ExitMessage]
    FailureReason: Optional[FailureReason]
    ProcessingEndTime: Optional[Timestamp]
    ProcessingStartTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    CreationTime: Timestamp
    MonitoringScheduleArn: Optional[MonitoringScheduleArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    TrainingJobArn: Optional[TrainingJobArn]


class DescribeProjectInput(ServiceRequest):
    ProjectName: ProjectEntityName


class ServiceCatalogProvisionedProductDetails(TypedDict, total=False):
    ProvisionedProductId: Optional[ServiceCatalogEntityId]
    ProvisionedProductStatusMessage: Optional[ProvisionedProductStatusMessage]


class DescribeProjectOutput(TypedDict, total=False):
    ProjectArn: ProjectArn
    ProjectName: ProjectEntityName
    ProjectId: ProjectId
    ProjectDescription: Optional[EntityDescription]
    ServiceCatalogProvisioningDetails: ServiceCatalogProvisioningDetails
    ServiceCatalogProvisionedProductDetails: Optional[ServiceCatalogProvisionedProductDetails]
    ProjectStatus: ProjectStatus
    CreatedBy: Optional[UserContext]
    CreationTime: Timestamp
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]


class DescribeStudioLifecycleConfigRequest(ServiceRequest):
    StudioLifecycleConfigName: StudioLifecycleConfigName


class DescribeStudioLifecycleConfigResponse(TypedDict, total=False):
    StudioLifecycleConfigArn: Optional[StudioLifecycleConfigArn]
    StudioLifecycleConfigName: Optional[StudioLifecycleConfigName]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    StudioLifecycleConfigContent: Optional[StudioLifecycleConfigContent]
    StudioLifecycleConfigAppType: Optional[StudioLifecycleConfigAppType]


class DescribeSubscribedWorkteamRequest(ServiceRequest):
    WorkteamArn: WorkteamArn


class SubscribedWorkteam(TypedDict, total=False):
    WorkteamArn: WorkteamArn
    MarketplaceTitle: Optional[String200]
    SellerName: Optional[String]
    MarketplaceDescription: Optional[String200]
    ListingId: Optional[String]


class DescribeSubscribedWorkteamResponse(TypedDict, total=False):
    SubscribedWorkteam: SubscribedWorkteam


class DescribeTrainingJobRequest(ServiceRequest):
    TrainingJobName: TrainingJobName


class ProfilerRuleEvaluationStatus(TypedDict, total=False):
    RuleConfigurationName: Optional[RuleConfigurationName]
    RuleEvaluationJobArn: Optional[ProcessingJobArn]
    RuleEvaluationStatus: Optional[RuleEvaluationStatus]
    StatusDetails: Optional[StatusDetails]
    LastModifiedTime: Optional[Timestamp]


ProfilerRuleEvaluationStatuses = List[ProfilerRuleEvaluationStatus]


class MetricData(TypedDict, total=False):
    MetricName: Optional[MetricName]
    Value: Optional[Float]
    Timestamp: Optional[Timestamp]


FinalMetricDataList = List[MetricData]


class SecondaryStatusTransition(TypedDict, total=False):
    Status: SecondaryStatus
    StartTime: Timestamp
    EndTime: Optional[Timestamp]
    StatusMessage: Optional[StatusMessage]


SecondaryStatusTransitions = List[SecondaryStatusTransition]


class DescribeTrainingJobResponse(TypedDict, total=False):
    TrainingJobName: TrainingJobName
    TrainingJobArn: TrainingJobArn
    TuningJobArn: Optional[HyperParameterTuningJobArn]
    LabelingJobArn: Optional[LabelingJobArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    ModelArtifacts: ModelArtifacts
    TrainingJobStatus: TrainingJobStatus
    SecondaryStatus: SecondaryStatus
    FailureReason: Optional[FailureReason]
    HyperParameters: Optional[HyperParameters]
    AlgorithmSpecification: AlgorithmSpecification
    RoleArn: Optional[RoleArn]
    InputDataConfig: Optional[InputDataConfig]
    OutputDataConfig: Optional[OutputDataConfig]
    ResourceConfig: ResourceConfig
    VpcConfig: Optional[VpcConfig]
    StoppingCondition: StoppingCondition
    CreationTime: Timestamp
    TrainingStartTime: Optional[Timestamp]
    TrainingEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    SecondaryStatusTransitions: Optional[SecondaryStatusTransitions]
    FinalMetricDataList: Optional[FinalMetricDataList]
    EnableNetworkIsolation: Optional[Boolean]
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableManagedSpotTraining: Optional[Boolean]
    CheckpointConfig: Optional[CheckpointConfig]
    TrainingTimeInSeconds: Optional[TrainingTimeInSeconds]
    BillableTimeInSeconds: Optional[BillableTimeInSeconds]
    DebugHookConfig: Optional[DebugHookConfig]
    ExperimentConfig: Optional[ExperimentConfig]
    DebugRuleConfigurations: Optional[DebugRuleConfigurations]
    TensorBoardOutputConfig: Optional[TensorBoardOutputConfig]
    DebugRuleEvaluationStatuses: Optional[DebugRuleEvaluationStatuses]
    ProfilerConfig: Optional[ProfilerConfig]
    ProfilerRuleConfigurations: Optional[ProfilerRuleConfigurations]
    ProfilerRuleEvaluationStatuses: Optional[ProfilerRuleEvaluationStatuses]
    ProfilingStatus: Optional[ProfilingStatus]
    RetryStrategy: Optional[RetryStrategy]
    Environment: Optional[TrainingEnvironmentMap]


class DescribeTransformJobRequest(ServiceRequest):
    TransformJobName: TransformJobName


class DescribeTransformJobResponse(TypedDict, total=False):
    TransformJobName: TransformJobName
    TransformJobArn: TransformJobArn
    TransformJobStatus: TransformJobStatus
    FailureReason: Optional[FailureReason]
    ModelName: ModelName
    MaxConcurrentTransforms: Optional[MaxConcurrentTransforms]
    ModelClientConfig: Optional[ModelClientConfig]
    MaxPayloadInMB: Optional[MaxPayloadInMB]
    BatchStrategy: Optional[BatchStrategy]
    Environment: Optional[TransformEnvironmentMap]
    TransformInput: TransformInput
    TransformOutput: Optional[TransformOutput]
    TransformResources: TransformResources
    CreationTime: Timestamp
    TransformStartTime: Optional[Timestamp]
    TransformEndTime: Optional[Timestamp]
    LabelingJobArn: Optional[LabelingJobArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    DataProcessing: Optional[DataProcessing]
    ExperimentConfig: Optional[ExperimentConfig]


class DescribeTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityNameOrArn


class TrialComponentMetricSummary(TypedDict, total=False):
    MetricName: Optional[MetricName]
    SourceArn: Optional[TrialComponentSourceArn]
    TimeStamp: Optional[Timestamp]
    Max: Optional[OptionalDouble]
    Min: Optional[OptionalDouble]
    Last: Optional[OptionalDouble]
    Count: Optional[OptionalInteger]
    Avg: Optional[OptionalDouble]
    StdDev: Optional[OptionalDouble]


TrialComponentMetricSummaries = List[TrialComponentMetricSummary]


class TrialComponentSource(TypedDict, total=False):
    SourceArn: TrialComponentSourceArn
    SourceType: Optional[SourceType]


class DescribeTrialComponentResponse(TypedDict, total=False):
    TrialComponentName: Optional[ExperimentEntityName]
    TrialComponentArn: Optional[TrialComponentArn]
    DisplayName: Optional[ExperimentEntityName]
    Source: Optional[TrialComponentSource]
    Status: Optional[TrialComponentStatus]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    Parameters: Optional[TrialComponentParameters]
    InputArtifacts: Optional[TrialComponentArtifacts]
    OutputArtifacts: Optional[TrialComponentArtifacts]
    MetadataProperties: Optional[MetadataProperties]
    Metrics: Optional[TrialComponentMetricSummaries]
    LineageGroupArn: Optional[LineageGroupArn]


class DescribeTrialRequest(ServiceRequest):
    TrialName: ExperimentEntityName


class TrialSource(TypedDict, total=False):
    SourceArn: TrialSourceArn
    SourceType: Optional[SourceType]


class DescribeTrialResponse(TypedDict, total=False):
    TrialName: Optional[ExperimentEntityName]
    TrialArn: Optional[TrialArn]
    DisplayName: Optional[ExperimentEntityName]
    ExperimentName: Optional[ExperimentEntityName]
    Source: Optional[TrialSource]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]


class DescribeUserProfileRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName


class DescribeUserProfileResponse(TypedDict, total=False):
    DomainId: Optional[DomainId]
    UserProfileArn: Optional[UserProfileArn]
    UserProfileName: Optional[UserProfileName]
    HomeEfsFileSystemUid: Optional[EfsUid]
    Status: Optional[UserProfileStatus]
    LastModifiedTime: Optional[LastModifiedTime]
    CreationTime: Optional[CreationTime]
    FailureReason: Optional[FailureReason]
    SingleSignOnUserIdentifier: Optional[SingleSignOnUserIdentifier]
    SingleSignOnUserValue: Optional[String256]
    UserSettings: Optional[UserSettings]


class DescribeWorkforceRequest(ServiceRequest):
    WorkforceName: WorkforceName


class OidcConfigForResponse(TypedDict, total=False):
    ClientId: Optional[ClientId]
    Issuer: Optional[OidcEndpoint]
    AuthorizationEndpoint: Optional[OidcEndpoint]
    TokenEndpoint: Optional[OidcEndpoint]
    UserInfoEndpoint: Optional[OidcEndpoint]
    LogoutEndpoint: Optional[OidcEndpoint]
    JwksUri: Optional[OidcEndpoint]


class Workforce(TypedDict, total=False):
    WorkforceName: WorkforceName
    WorkforceArn: WorkforceArn
    LastUpdatedDate: Optional[Timestamp]
    SourceIpConfig: Optional[SourceIpConfig]
    SubDomain: Optional[String]
    CognitoConfig: Optional[CognitoConfig]
    OidcConfig: Optional[OidcConfigForResponse]
    CreateDate: Optional[Timestamp]


class DescribeWorkforceResponse(TypedDict, total=False):
    Workforce: Workforce


class DescribeWorkteamRequest(ServiceRequest):
    WorkteamName: WorkteamName


ProductListings = List[String]


class Workteam(TypedDict, total=False):
    WorkteamName: WorkteamName
    MemberDefinitions: MemberDefinitions
    WorkteamArn: WorkteamArn
    WorkforceArn: Optional[WorkforceArn]
    ProductListingIds: Optional[ProductListings]
    Description: String200
    SubDomain: Optional[String]
    CreateDate: Optional[Timestamp]
    LastUpdatedDate: Optional[Timestamp]
    NotificationConfiguration: Optional[NotificationConfiguration]


class DescribeWorkteamResponse(TypedDict, total=False):
    Workteam: Workteam


class DesiredWeightAndCapacity(TypedDict, total=False):
    VariantName: VariantName
    DesiredWeight: Optional[VariantWeight]
    DesiredInstanceCount: Optional[TaskCount]


DesiredWeightAndCapacityList = List[DesiredWeightAndCapacity]


class Device(TypedDict, total=False):
    DeviceName: DeviceName
    Description: Optional[DeviceDescription]
    IotThingName: Optional[ThingName]


class DeviceFleetSummary(TypedDict, total=False):
    DeviceFleetArn: DeviceFleetArn
    DeviceFleetName: EntityName
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


DeviceFleetSummaries = List[DeviceFleetSummary]


class DeviceStats(TypedDict, total=False):
    ConnectedDeviceCount: Long
    RegisteredDeviceCount: Long


class EdgeModelSummary(TypedDict, total=False):
    ModelName: EntityName
    ModelVersion: EdgeVersion


EdgeModelSummaries = List[EdgeModelSummary]


class DeviceSummary(TypedDict, total=False):
    DeviceName: EntityName
    DeviceArn: DeviceArn
    Description: Optional[DeviceDescription]
    DeviceFleetName: Optional[EntityName]
    IotThingName: Optional[ThingName]
    RegistrationTime: Optional[Timestamp]
    LatestHeartbeat: Optional[Timestamp]
    Models: Optional[EdgeModelSummaries]
    AgentVersion: Optional[EdgeVersion]


DeviceSummaries = List[DeviceSummary]
Devices = List[Device]


class DisableSagemakerServicecatalogPortfolioInput(ServiceRequest):
    pass


class DisableSagemakerServicecatalogPortfolioOutput(TypedDict, total=False):
    pass


class DisassociateTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityName
    TrialName: ExperimentEntityName


class DisassociateTrialComponentResponse(TypedDict, total=False):
    TrialComponentArn: Optional[TrialComponentArn]
    TrialArn: Optional[TrialArn]


class DomainDetails(TypedDict, total=False):
    DomainArn: Optional[DomainArn]
    DomainId: Optional[DomainId]
    DomainName: Optional[DomainName]
    Status: Optional[DomainStatus]
    CreationTime: Optional[CreationTime]
    LastModifiedTime: Optional[LastModifiedTime]
    Url: Optional[String1024]


DomainList = List[DomainDetails]


class RStudioServerProDomainSettingsForUpdate(TypedDict, total=False):
    DomainExecutionRoleArn: RoleArn
    DefaultResourceSpec: Optional[ResourceSpec]


class DomainSettingsForUpdate(TypedDict, total=False):
    RStudioServerProDomainSettingsForUpdate: Optional[RStudioServerProDomainSettingsForUpdate]


class EMRStepMetadata(TypedDict, total=False):
    ClusterId: Optional[String256]
    StepId: Optional[String256]
    StepName: Optional[String256]
    LogFilePath: Optional[String1024]


class Edge(TypedDict, total=False):
    SourceArn: Optional[AssociationEntityArn]
    DestinationArn: Optional[AssociationEntityArn]
    AssociationType: Optional[AssociationEdgeType]


class EdgeModelStat(TypedDict, total=False):
    ModelName: EntityName
    ModelVersion: EdgeVersion
    OfflineDeviceCount: Long
    ConnectedDeviceCount: Long
    ActiveDeviceCount: Long
    SamplingDeviceCount: Long


EdgeModelStats = List[EdgeModelStat]


class EdgePackagingJobSummary(TypedDict, total=False):
    EdgePackagingJobArn: EdgePackagingJobArn
    EdgePackagingJobName: EntityName
    EdgePackagingJobStatus: EdgePackagingJobStatus
    CompilationJobName: Optional[EntityName]
    ModelName: Optional[EntityName]
    ModelVersion: Optional[EdgeVersion]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


EdgePackagingJobSummaries = List[EdgePackagingJobSummary]
Edges = List[Edge]


class EnableSagemakerServicecatalogPortfolioInput(ServiceRequest):
    pass


class EnableSagemakerServicecatalogPortfolioOutput(TypedDict, total=False):
    pass


class MonitoringSchedule(TypedDict, total=False):
    MonitoringScheduleArn: Optional[MonitoringScheduleArn]
    MonitoringScheduleName: Optional[MonitoringScheduleName]
    MonitoringScheduleStatus: Optional[ScheduleStatus]
    MonitoringType: Optional[MonitoringType]
    FailureReason: Optional[FailureReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    MonitoringScheduleConfig: Optional[MonitoringScheduleConfig]
    EndpointName: Optional[EndpointName]
    LastMonitoringExecutionSummary: Optional[MonitoringExecutionSummary]
    Tags: Optional[TagList]


MonitoringScheduleList = List[MonitoringSchedule]


class Endpoint(TypedDict, total=False):
    EndpointName: EndpointName
    EndpointArn: EndpointArn
    EndpointConfigName: EndpointConfigName
    ProductionVariants: Optional[ProductionVariantSummaryList]
    DataCaptureConfig: Optional[DataCaptureConfigSummary]
    EndpointStatus: EndpointStatus
    FailureReason: Optional[FailureReason]
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    MonitoringSchedules: Optional[MonitoringScheduleList]
    Tags: Optional[TagList]


class EndpointConfigSummary(TypedDict, total=False):
    EndpointConfigName: EndpointConfigName
    EndpointConfigArn: EndpointConfigArn
    CreationTime: Timestamp


EndpointConfigSummaryList = List[EndpointConfigSummary]


class EndpointSummary(TypedDict, total=False):
    EndpointName: EndpointName
    EndpointArn: EndpointArn
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    EndpointStatus: EndpointStatus


EndpointSummaryList = List[EndpointSummary]


class Experiment(TypedDict, total=False):
    ExperimentName: Optional[ExperimentEntityName]
    ExperimentArn: Optional[ExperimentArn]
    DisplayName: Optional[ExperimentEntityName]
    Source: Optional[ExperimentSource]
    Description: Optional[ExperimentDescription]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    Tags: Optional[TagList]


class ExperimentSummary(TypedDict, total=False):
    ExperimentArn: Optional[ExperimentArn]
    ExperimentName: Optional[ExperimentEntityName]
    DisplayName: Optional[ExperimentEntityName]
    ExperimentSource: Optional[ExperimentSource]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


ExperimentSummaries = List[ExperimentSummary]


class FailStepMetadata(TypedDict, total=False):
    ErrorMessage: Optional[String3072]


class FeatureGroup(TypedDict, total=False):
    FeatureGroupArn: Optional[FeatureGroupArn]
    FeatureGroupName: Optional[FeatureGroupName]
    RecordIdentifierFeatureName: Optional[FeatureName]
    EventTimeFeatureName: Optional[FeatureName]
    FeatureDefinitions: Optional[FeatureDefinitions]
    CreationTime: Optional[CreationTime]
    OnlineStoreConfig: Optional[OnlineStoreConfig]
    OfflineStoreConfig: Optional[OfflineStoreConfig]
    RoleArn: Optional[RoleArn]
    FeatureGroupStatus: Optional[FeatureGroupStatus]
    OfflineStoreStatus: Optional[OfflineStoreStatus]
    FailureReason: Optional[FailureReason]
    Description: Optional[Description]
    Tags: Optional[TagList]


class FeatureGroupSummary(TypedDict, total=False):
    FeatureGroupName: FeatureGroupName
    FeatureGroupArn: FeatureGroupArn
    CreationTime: Timestamp
    FeatureGroupStatus: Optional[FeatureGroupStatus]
    OfflineStoreStatus: Optional[OfflineStoreStatus]


FeatureGroupSummaries = List[FeatureGroupSummary]


class Filter(TypedDict, total=False):
    Name: ResourcePropertyName
    Operator: Optional[Operator]
    Value: Optional[FilterValue]


FilterList = List[Filter]


class FlowDefinitionSummary(TypedDict, total=False):
    FlowDefinitionName: FlowDefinitionName
    FlowDefinitionArn: FlowDefinitionArn
    FlowDefinitionStatus: FlowDefinitionStatus
    CreationTime: Timestamp
    FailureReason: Optional[FailureReason]


FlowDefinitionSummaries = List[FlowDefinitionSummary]


class GetDeviceFleetReportRequest(ServiceRequest):
    DeviceFleetName: EntityName


class GetDeviceFleetReportResponse(TypedDict, total=False):
    DeviceFleetArn: DeviceFleetArn
    DeviceFleetName: EntityName
    OutputConfig: Optional[EdgeOutputConfig]
    Description: Optional[DeviceFleetDescription]
    ReportGenerated: Optional[Timestamp]
    DeviceStats: Optional[DeviceStats]
    AgentVersions: Optional[AgentVersions]
    ModelStats: Optional[EdgeModelStats]


class GetLineageGroupPolicyRequest(ServiceRequest):
    LineageGroupName: LineageGroupNameOrArn


class GetLineageGroupPolicyResponse(TypedDict, total=False):
    LineageGroupArn: Optional[LineageGroupArn]
    ResourcePolicy: Optional[ResourcePolicyString]


class GetModelPackageGroupPolicyInput(ServiceRequest):
    ModelPackageGroupName: EntityName


class GetModelPackageGroupPolicyOutput(TypedDict, total=False):
    ResourcePolicy: PolicyString


class GetSagemakerServicecatalogPortfolioStatusInput(ServiceRequest):
    pass


class GetSagemakerServicecatalogPortfolioStatusOutput(TypedDict, total=False):
    Status: Optional[SagemakerServicecatalogStatus]


class PropertyNameQuery(TypedDict, total=False):
    PropertyNameHint: PropertyNameHint


class SuggestionQuery(TypedDict, total=False):
    PropertyNameQuery: Optional[PropertyNameQuery]


class GetSearchSuggestionsRequest(ServiceRequest):
    Resource: ResourceType
    SuggestionQuery: Optional[SuggestionQuery]


class PropertyNameSuggestion(TypedDict, total=False):
    PropertyName: Optional[ResourcePropertyName]


PropertyNameSuggestionList = List[PropertyNameSuggestion]


class GetSearchSuggestionsResponse(TypedDict, total=False):
    PropertyNameSuggestions: Optional[PropertyNameSuggestionList]


class GitConfigForUpdate(TypedDict, total=False):
    SecretArn: Optional[SecretArn]


class HumanTaskUiSummary(TypedDict, total=False):
    HumanTaskUiName: HumanTaskUiName
    HumanTaskUiArn: HumanTaskUiArn
    CreationTime: Timestamp


HumanTaskUiSummaries = List[HumanTaskUiSummary]
HyperParameterTrainingJobSummaries = List[HyperParameterTrainingJobSummary]


class HyperParameterTuningJobSummary(TypedDict, total=False):
    HyperParameterTuningJobName: HyperParameterTuningJobName
    HyperParameterTuningJobArn: HyperParameterTuningJobArn
    HyperParameterTuningJobStatus: HyperParameterTuningJobStatus
    Strategy: HyperParameterTuningJobStrategyType
    CreationTime: Timestamp
    HyperParameterTuningEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    TrainingJobStatusCounters: TrainingJobStatusCounters
    ObjectiveStatusCounters: ObjectiveStatusCounters
    ResourceLimits: Optional[ResourceLimits]


HyperParameterTuningJobSummaries = List[HyperParameterTuningJobSummary]


class Image(TypedDict, total=False):
    CreationTime: Timestamp
    Description: Optional[ImageDescription]
    DisplayName: Optional[ImageDisplayName]
    FailureReason: Optional[FailureReason]
    ImageArn: ImageArn
    ImageName: ImageName
    ImageStatus: ImageStatus
    LastModifiedTime: Timestamp


ImageDeletePropertyList = List[ImageDeleteProperty]


class ImageVersion(TypedDict, total=False):
    CreationTime: Timestamp
    FailureReason: Optional[FailureReason]
    ImageArn: ImageArn
    ImageVersionArn: ImageVersionArn
    ImageVersionStatus: ImageVersionStatus
    LastModifiedTime: Timestamp
    Version: ImageVersionNumber


ImageVersions = List[ImageVersion]
Images = List[Image]


class InferenceRecommendationsJob(TypedDict, total=False):
    JobName: RecommendationJobName
    JobDescription: RecommendationJobDescription
    JobType: RecommendationJobType
    JobArn: RecommendationJobArn
    Status: RecommendationJobStatus
    CreationTime: CreationTime
    CompletionTime: Optional[Timestamp]
    RoleArn: RoleArn
    LastModifiedTime: LastModifiedTime
    FailureReason: Optional[FailureReason]


InferenceRecommendationsJobs = List[InferenceRecommendationsJob]


class LabelCountersForWorkteam(TypedDict, total=False):
    HumanLabeled: Optional[LabelCounter]
    PendingHuman: Optional[LabelCounter]
    Total: Optional[LabelCounter]


class LabelingJobForWorkteamSummary(TypedDict, total=False):
    LabelingJobName: Optional[LabelingJobName]
    JobReferenceCode: JobReferenceCode
    WorkRequesterAccountId: AccountId
    CreationTime: Timestamp
    LabelCounters: Optional[LabelCountersForWorkteam]
    NumberOfHumanWorkersPerDataObject: Optional[NumberOfHumanWorkersPerDataObject]


LabelingJobForWorkteamSummaryList = List[LabelingJobForWorkteamSummary]


class LabelingJobSummary(TypedDict, total=False):
    LabelingJobName: LabelingJobName
    LabelingJobArn: LabelingJobArn
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    LabelingJobStatus: LabelingJobStatus
    LabelCounters: LabelCounters
    WorkteamArn: WorkteamArn
    PreHumanTaskLambdaArn: LambdaFunctionArn
    AnnotationConsolidationLambdaArn: Optional[LambdaFunctionArn]
    FailureReason: Optional[FailureReason]
    LabelingJobOutput: Optional[LabelingJobOutput]
    InputConfig: Optional[LabelingJobInputConfig]


LabelingJobSummaryList = List[LabelingJobSummary]


class LambdaStepMetadata(TypedDict, total=False):
    Arn: Optional[String256]
    OutputParameters: Optional[OutputParameterList]


class LineageGroupSummary(TypedDict, total=False):
    LineageGroupArn: Optional[LineageGroupArn]
    LineageGroupName: Optional[ExperimentEntityName]
    DisplayName: Optional[ExperimentEntityName]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


LineageGroupSummaries = List[LineageGroupSummary]


class ListActionsRequest(ServiceRequest):
    SourceUri: Optional[SourceUri]
    ActionType: Optional[String256]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortActionsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListActionsResponse(TypedDict, total=False):
    ActionSummaries: Optional[ActionSummaries]
    NextToken: Optional[NextToken]


class ListAlgorithmsInput(ServiceRequest):
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    NextToken: Optional[NextToken]
    SortBy: Optional[AlgorithmSortBy]
    SortOrder: Optional[SortOrder]


class ListAlgorithmsOutput(TypedDict, total=False):
    AlgorithmSummaryList: AlgorithmSummaryList
    NextToken: Optional[NextToken]


class ListAppImageConfigsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    NameContains: Optional[AppImageConfigName]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]
    ModifiedTimeBefore: Optional[Timestamp]
    ModifiedTimeAfter: Optional[Timestamp]
    SortBy: Optional[AppImageConfigSortKey]
    SortOrder: Optional[SortOrder]


class ListAppImageConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    AppImageConfigs: Optional[AppImageConfigList]


class ListAppsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortOrder: Optional[SortOrder]
    SortBy: Optional[AppSortKey]
    DomainIdEquals: Optional[DomainId]
    UserProfileNameEquals: Optional[UserProfileName]


class ListAppsResponse(TypedDict, total=False):
    Apps: Optional[AppList]
    NextToken: Optional[NextToken]


class ListArtifactsRequest(ServiceRequest):
    SourceUri: Optional[SourceUri]
    ArtifactType: Optional[String256]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortArtifactsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListArtifactsResponse(TypedDict, total=False):
    ArtifactSummaries: Optional[ArtifactSummaries]
    NextToken: Optional[NextToken]


class ListAssociationsRequest(ServiceRequest):
    SourceArn: Optional[AssociationEntityArn]
    DestinationArn: Optional[AssociationEntityArn]
    SourceType: Optional[String256]
    DestinationType: Optional[String256]
    AssociationType: Optional[AssociationEdgeType]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortAssociationsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListAssociationsResponse(TypedDict, total=False):
    AssociationSummaries: Optional[AssociationSummaries]
    NextToken: Optional[NextToken]


class ListAutoMLJobsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[AutoMLNameContains]
    StatusEquals: Optional[AutoMLJobStatus]
    SortOrder: Optional[AutoMLSortOrder]
    SortBy: Optional[AutoMLSortBy]
    MaxResults: Optional[AutoMLMaxResults]
    NextToken: Optional[NextToken]


class ListAutoMLJobsResponse(TypedDict, total=False):
    AutoMLJobSummaries: AutoMLJobSummaries
    NextToken: Optional[NextToken]


class ListCandidatesForAutoMLJobRequest(ServiceRequest):
    AutoMLJobName: AutoMLJobName
    StatusEquals: Optional[CandidateStatus]
    CandidateNameEquals: Optional[CandidateName]
    SortOrder: Optional[AutoMLSortOrder]
    SortBy: Optional[CandidateSortBy]
    MaxResults: Optional[AutoMLMaxResults]
    NextToken: Optional[NextToken]


class ListCandidatesForAutoMLJobResponse(TypedDict, total=False):
    Candidates: AutoMLCandidates
    NextToken: Optional[NextToken]


class ListCodeRepositoriesInput(ServiceRequest):
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[CodeRepositoryNameContains]
    NextToken: Optional[NextToken]
    SortBy: Optional[CodeRepositorySortBy]
    SortOrder: Optional[CodeRepositorySortOrder]


class ListCodeRepositoriesOutput(TypedDict, total=False):
    CodeRepositorySummaryList: CodeRepositorySummaryList
    NextToken: Optional[NextToken]


class ListCompilationJobsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    LastModifiedTimeAfter: Optional[LastModifiedTime]
    LastModifiedTimeBefore: Optional[LastModifiedTime]
    NameContains: Optional[NameContains]
    StatusEquals: Optional[CompilationJobStatus]
    SortBy: Optional[ListCompilationJobsSortBy]
    SortOrder: Optional[SortOrder]


class ListCompilationJobsResponse(TypedDict, total=False):
    CompilationJobSummaries: CompilationJobSummaries
    NextToken: Optional[NextToken]


class ListContextsRequest(ServiceRequest):
    SourceUri: Optional[SourceUri]
    ContextType: Optional[String256]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortContextsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListContextsResponse(TypedDict, total=False):
    ContextSummaries: Optional[ContextSummaries]
    NextToken: Optional[NextToken]


class ListDataQualityJobDefinitionsRequest(ServiceRequest):
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringJobDefinitionSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class MonitoringJobDefinitionSummary(TypedDict, total=False):
    MonitoringJobDefinitionName: MonitoringJobDefinitionName
    MonitoringJobDefinitionArn: MonitoringJobDefinitionArn
    CreationTime: Timestamp
    EndpointName: EndpointName


MonitoringJobDefinitionSummaryList = List[MonitoringJobDefinitionSummary]


class ListDataQualityJobDefinitionsResponse(TypedDict, total=False):
    JobDefinitionSummaries: MonitoringJobDefinitionSummaryList
    NextToken: Optional[NextToken]


class ListDeviceFleetsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListMaxResults]
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[NameContains]
    SortBy: Optional[ListDeviceFleetsSortBy]
    SortOrder: Optional[SortOrder]


class ListDeviceFleetsResponse(TypedDict, total=False):
    DeviceFleetSummaries: DeviceFleetSummaries
    NextToken: Optional[NextToken]


class ListDevicesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListMaxResults]
    LatestHeartbeatAfter: Optional[Timestamp]
    ModelName: Optional[EntityName]
    DeviceFleetName: Optional[EntityName]


class ListDevicesResponse(TypedDict, total=False):
    DeviceSummaries: DeviceSummaries
    NextToken: Optional[NextToken]


class ListDomainsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListDomainsResponse(TypedDict, total=False):
    Domains: Optional[DomainList]
    NextToken: Optional[NextToken]


class ListEdgePackagingJobsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListMaxResults]
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[NameContains]
    ModelNameContains: Optional[NameContains]
    StatusEquals: Optional[EdgePackagingJobStatus]
    SortBy: Optional[ListEdgePackagingJobsSortBy]
    SortOrder: Optional[SortOrder]


class ListEdgePackagingJobsResponse(TypedDict, total=False):
    EdgePackagingJobSummaries: EdgePackagingJobSummaries
    NextToken: Optional[NextToken]


class ListEndpointConfigsInput(ServiceRequest):
    SortBy: Optional[EndpointConfigSortKey]
    SortOrder: Optional[OrderKey]
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[EndpointConfigNameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class ListEndpointConfigsOutput(TypedDict, total=False):
    EndpointConfigs: EndpointConfigSummaryList
    NextToken: Optional[PaginationToken]


class ListEndpointsInput(ServiceRequest):
    SortBy: Optional[EndpointSortKey]
    SortOrder: Optional[OrderKey]
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[EndpointNameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    StatusEquals: Optional[EndpointStatus]


class ListEndpointsOutput(TypedDict, total=False):
    Endpoints: EndpointSummaryList
    NextToken: Optional[PaginationToken]


class ListExperimentsRequest(ServiceRequest):
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortExperimentsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListExperimentsResponse(TypedDict, total=False):
    ExperimentSummaries: Optional[ExperimentSummaries]
    NextToken: Optional[NextToken]


class ListFeatureGroupsRequest(ServiceRequest):
    NameContains: Optional[FeatureGroupNameContains]
    FeatureGroupStatusEquals: Optional[FeatureGroupStatus]
    OfflineStoreStatusEquals: Optional[OfflineStoreStatusValue]
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    SortOrder: Optional[FeatureGroupSortOrder]
    SortBy: Optional[FeatureGroupSortBy]
    MaxResults: Optional[FeatureGroupMaxResults]
    NextToken: Optional[NextToken]


class ListFeatureGroupsResponse(TypedDict, total=False):
    FeatureGroupSummaries: FeatureGroupSummaries
    NextToken: NextToken


class ListFlowDefinitionsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListFlowDefinitionsResponse(TypedDict, total=False):
    FlowDefinitionSummaries: FlowDefinitionSummaries
    NextToken: Optional[NextToken]


class ListHumanTaskUisRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListHumanTaskUisResponse(TypedDict, total=False):
    HumanTaskUiSummaries: HumanTaskUiSummaries
    NextToken: Optional[NextToken]


class ListHyperParameterTuningJobsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortBy: Optional[HyperParameterTuningJobSortByOptions]
    SortOrder: Optional[SortOrder]
    NameContains: Optional[NameContains]
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    StatusEquals: Optional[HyperParameterTuningJobStatus]


class ListHyperParameterTuningJobsResponse(TypedDict, total=False):
    HyperParameterTuningJobSummaries: HyperParameterTuningJobSummaries
    NextToken: Optional[NextToken]


class ListImageVersionsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    ImageName: ImageName
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    SortBy: Optional[ImageVersionSortBy]
    SortOrder: Optional[ImageVersionSortOrder]


class ListImageVersionsResponse(TypedDict, total=False):
    ImageVersions: Optional[ImageVersions]
    NextToken: Optional[NextToken]


class ListImagesRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[ImageNameContains]
    NextToken: Optional[NextToken]
    SortBy: Optional[ImageSortBy]
    SortOrder: Optional[ImageSortOrder]


class ListImagesResponse(TypedDict, total=False):
    Images: Optional[Images]
    NextToken: Optional[NextToken]


class ListInferenceRecommendationsJobsRequest(ServiceRequest):
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    LastModifiedTimeAfter: Optional[LastModifiedTime]
    LastModifiedTimeBefore: Optional[LastModifiedTime]
    NameContains: Optional[NameContains]
    StatusEquals: Optional[RecommendationJobStatus]
    SortBy: Optional[ListInferenceRecommendationsJobsSortBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListInferenceRecommendationsJobsResponse(TypedDict, total=False):
    InferenceRecommendationsJobs: InferenceRecommendationsJobs
    NextToken: Optional[NextToken]


class ListLabelingJobsForWorkteamRequest(ServiceRequest):
    WorkteamArn: WorkteamArn
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    JobReferenceCodeContains: Optional[JobReferenceCodeContains]
    SortBy: Optional[ListLabelingJobsForWorkteamSortByOptions]
    SortOrder: Optional[SortOrder]


class ListLabelingJobsForWorkteamResponse(TypedDict, total=False):
    LabelingJobSummaryList: LabelingJobForWorkteamSummaryList
    NextToken: Optional[NextToken]


class ListLabelingJobsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    NameContains: Optional[NameContains]
    SortBy: Optional[SortBy]
    SortOrder: Optional[SortOrder]
    StatusEquals: Optional[LabelingJobStatus]


class ListLabelingJobsResponse(TypedDict, total=False):
    LabelingJobSummaryList: Optional[LabelingJobSummaryList]
    NextToken: Optional[NextToken]


ListLineageEntityParameterKey = List[StringParameterValue]


class ListLineageGroupsRequest(ServiceRequest):
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortLineageGroupsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListLineageGroupsResponse(TypedDict, total=False):
    LineageGroupSummaries: Optional[LineageGroupSummaries]
    NextToken: Optional[NextToken]


class ListModelBiasJobDefinitionsRequest(ServiceRequest):
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringJobDefinitionSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class ListModelBiasJobDefinitionsResponse(TypedDict, total=False):
    JobDefinitionSummaries: MonitoringJobDefinitionSummaryList
    NextToken: Optional[NextToken]


class ListModelExplainabilityJobDefinitionsRequest(ServiceRequest):
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringJobDefinitionSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class ListModelExplainabilityJobDefinitionsResponse(TypedDict, total=False):
    JobDefinitionSummaries: MonitoringJobDefinitionSummaryList
    NextToken: Optional[NextToken]


class ModelMetadataFilter(TypedDict, total=False):
    Name: ModelMetadataFilterType
    Value: String256


ModelMetadataFilters = List[ModelMetadataFilter]


class ModelMetadataSearchExpression(TypedDict, total=False):
    Filters: Optional[ModelMetadataFilters]


class ListModelMetadataRequest(ServiceRequest):
    SearchExpression: Optional[ModelMetadataSearchExpression]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ModelMetadataSummary(TypedDict, total=False):
    Domain: String
    Framework: String
    Task: String
    Model: String
    FrameworkVersion: String


ModelMetadataSummaries = List[ModelMetadataSummary]


class ListModelMetadataResponse(TypedDict, total=False):
    ModelMetadataSummaries: ModelMetadataSummaries
    NextToken: Optional[NextToken]


class ListModelPackageGroupsInput(ServiceRequest):
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    NextToken: Optional[NextToken]
    SortBy: Optional[ModelPackageGroupSortBy]
    SortOrder: Optional[SortOrder]


class ModelPackageGroupSummary(TypedDict, total=False):
    ModelPackageGroupName: EntityName
    ModelPackageGroupArn: ModelPackageGroupArn
    ModelPackageGroupDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    ModelPackageGroupStatus: ModelPackageGroupStatus


ModelPackageGroupSummaryList = List[ModelPackageGroupSummary]


class ListModelPackageGroupsOutput(TypedDict, total=False):
    ModelPackageGroupSummaryList: ModelPackageGroupSummaryList
    NextToken: Optional[NextToken]


class ListModelPackagesInput(ServiceRequest):
    CreationTimeAfter: Optional[CreationTime]
    CreationTimeBefore: Optional[CreationTime]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    ModelApprovalStatus: Optional[ModelApprovalStatus]
    ModelPackageGroupName: Optional[ArnOrName]
    ModelPackageType: Optional[ModelPackageType]
    NextToken: Optional[NextToken]
    SortBy: Optional[ModelPackageSortBy]
    SortOrder: Optional[SortOrder]


class ModelPackageSummary(TypedDict, total=False):
    ModelPackageName: EntityName
    ModelPackageGroupName: Optional[EntityName]
    ModelPackageVersion: Optional[ModelPackageVersion]
    ModelPackageArn: ModelPackageArn
    ModelPackageDescription: Optional[EntityDescription]
    CreationTime: CreationTime
    ModelPackageStatus: ModelPackageStatus
    ModelApprovalStatus: Optional[ModelApprovalStatus]


ModelPackageSummaryList = List[ModelPackageSummary]


class ListModelPackagesOutput(TypedDict, total=False):
    ModelPackageSummaryList: ModelPackageSummaryList
    NextToken: Optional[NextToken]


class ListModelQualityJobDefinitionsRequest(ServiceRequest):
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringJobDefinitionSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class ListModelQualityJobDefinitionsResponse(TypedDict, total=False):
    JobDefinitionSummaries: MonitoringJobDefinitionSummaryList
    NextToken: Optional[NextToken]


class ListModelsInput(ServiceRequest):
    SortBy: Optional[ModelSortKey]
    SortOrder: Optional[OrderKey]
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[ModelNameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]


class ModelSummary(TypedDict, total=False):
    ModelName: ModelName
    ModelArn: ModelArn
    CreationTime: Timestamp


ModelSummaryList = List[ModelSummary]


class ListModelsOutput(TypedDict, total=False):
    Models: ModelSummaryList
    NextToken: Optional[PaginationToken]


class ListMonitoringExecutionsRequest(ServiceRequest):
    MonitoringScheduleName: Optional[MonitoringScheduleName]
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringExecutionSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ScheduledTimeBefore: Optional[Timestamp]
    ScheduledTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    StatusEquals: Optional[ExecutionStatus]
    MonitoringJobDefinitionName: Optional[MonitoringJobDefinitionName]
    MonitoringTypeEquals: Optional[MonitoringType]


MonitoringExecutionSummaryList = List[MonitoringExecutionSummary]


class ListMonitoringExecutionsResponse(TypedDict, total=False):
    MonitoringExecutionSummaries: MonitoringExecutionSummaryList
    NextToken: Optional[NextToken]


class ListMonitoringSchedulesRequest(ServiceRequest):
    EndpointName: Optional[EndpointName]
    SortBy: Optional[MonitoringScheduleSortKey]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[NameContains]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    StatusEquals: Optional[ScheduleStatus]
    MonitoringJobDefinitionName: Optional[MonitoringJobDefinitionName]
    MonitoringTypeEquals: Optional[MonitoringType]


class MonitoringScheduleSummary(TypedDict, total=False):
    MonitoringScheduleName: MonitoringScheduleName
    MonitoringScheduleArn: MonitoringScheduleArn
    CreationTime: Timestamp
    LastModifiedTime: Timestamp
    MonitoringScheduleStatus: ScheduleStatus
    EndpointName: Optional[EndpointName]
    MonitoringJobDefinitionName: Optional[MonitoringJobDefinitionName]
    MonitoringType: Optional[MonitoringType]


MonitoringScheduleSummaryList = List[MonitoringScheduleSummary]


class ListMonitoringSchedulesResponse(TypedDict, total=False):
    MonitoringScheduleSummaries: MonitoringScheduleSummaryList
    NextToken: Optional[NextToken]


class ListNotebookInstanceLifecycleConfigsInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortBy: Optional[NotebookInstanceLifecycleConfigSortKey]
    SortOrder: Optional[NotebookInstanceLifecycleConfigSortOrder]
    NameContains: Optional[NotebookInstanceLifecycleConfigNameContains]
    CreationTimeBefore: Optional[CreationTime]
    CreationTimeAfter: Optional[CreationTime]
    LastModifiedTimeBefore: Optional[LastModifiedTime]
    LastModifiedTimeAfter: Optional[LastModifiedTime]


class NotebookInstanceLifecycleConfigSummary(TypedDict, total=False):
    NotebookInstanceLifecycleConfigName: NotebookInstanceLifecycleConfigName
    NotebookInstanceLifecycleConfigArn: NotebookInstanceLifecycleConfigArn
    CreationTime: Optional[CreationTime]
    LastModifiedTime: Optional[LastModifiedTime]


NotebookInstanceLifecycleConfigSummaryList = List[NotebookInstanceLifecycleConfigSummary]


class ListNotebookInstanceLifecycleConfigsOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    NotebookInstanceLifecycleConfigs: Optional[NotebookInstanceLifecycleConfigSummaryList]


class ListNotebookInstancesInput(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortBy: Optional[NotebookInstanceSortKey]
    SortOrder: Optional[NotebookInstanceSortOrder]
    NameContains: Optional[NotebookInstanceNameContains]
    CreationTimeBefore: Optional[CreationTime]
    CreationTimeAfter: Optional[CreationTime]
    LastModifiedTimeBefore: Optional[LastModifiedTime]
    LastModifiedTimeAfter: Optional[LastModifiedTime]
    StatusEquals: Optional[NotebookInstanceStatus]
    NotebookInstanceLifecycleConfigNameContains: Optional[NotebookInstanceLifecycleConfigName]
    DefaultCodeRepositoryContains: Optional[CodeRepositoryContains]
    AdditionalCodeRepositoryEquals: Optional[CodeRepositoryNameOrUrl]


class NotebookInstanceSummary(TypedDict, total=False):
    NotebookInstanceName: NotebookInstanceName
    NotebookInstanceArn: NotebookInstanceArn
    NotebookInstanceStatus: Optional[NotebookInstanceStatus]
    Url: Optional[NotebookInstanceUrl]
    InstanceType: Optional[InstanceType]
    CreationTime: Optional[CreationTime]
    LastModifiedTime: Optional[LastModifiedTime]
    NotebookInstanceLifecycleConfigName: Optional[NotebookInstanceLifecycleConfigName]
    DefaultCodeRepository: Optional[CodeRepositoryNameOrUrl]
    AdditionalCodeRepositories: Optional[AdditionalCodeRepositoryNamesOrUrls]


NotebookInstanceSummaryList = List[NotebookInstanceSummary]


class ListNotebookInstancesOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    NotebookInstances: Optional[NotebookInstanceSummaryList]


class ListPipelineExecutionStepsRequest(ServiceRequest):
    PipelineExecutionArn: Optional[PipelineExecutionArn]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortOrder: Optional[SortOrder]


class QualityCheckStepMetadata(TypedDict, total=False):
    CheckType: Optional[String256]
    BaselineUsedForDriftCheckStatistics: Optional[String1024]
    BaselineUsedForDriftCheckConstraints: Optional[String1024]
    CalculatedBaselineStatistics: Optional[String1024]
    CalculatedBaselineConstraints: Optional[String1024]
    ModelPackageGroupName: Optional[String256]
    ViolationReport: Optional[String1024]
    CheckJobArn: Optional[String256]
    SkipCheck: Optional[Boolean]
    RegisterNewBaseline: Optional[Boolean]


class RegisterModelStepMetadata(TypedDict, total=False):
    Arn: Optional[String256]


class ModelStepMetadata(TypedDict, total=False):
    Arn: Optional[String256]


class TuningJobStepMetaData(TypedDict, total=False):
    Arn: Optional[HyperParameterTuningJobArn]


class TransformJobStepMetadata(TypedDict, total=False):
    Arn: Optional[TransformJobArn]


class ProcessingJobStepMetadata(TypedDict, total=False):
    Arn: Optional[ProcessingJobArn]


class TrainingJobStepMetadata(TypedDict, total=False):
    Arn: Optional[TrainingJobArn]


class PipelineExecutionStepMetadata(TypedDict, total=False):
    TrainingJob: Optional[TrainingJobStepMetadata]
    ProcessingJob: Optional[ProcessingJobStepMetadata]
    TransformJob: Optional[TransformJobStepMetadata]
    TuningJob: Optional[TuningJobStepMetaData]
    Model: Optional[ModelStepMetadata]
    RegisterModel: Optional[RegisterModelStepMetadata]
    Condition: Optional[ConditionStepMetadata]
    Callback: Optional[CallbackStepMetadata]
    Lambda: Optional[LambdaStepMetadata]
    QualityCheck: Optional[QualityCheckStepMetadata]
    ClarifyCheck: Optional[ClarifyCheckStepMetadata]
    EMR: Optional[EMRStepMetadata]
    Fail: Optional[FailStepMetadata]


class PipelineExecutionStep(TypedDict, total=False):
    StepName: Optional[StepName]
    StepDisplayName: Optional[StepDisplayName]
    StepDescription: Optional[StepDescription]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    StepStatus: Optional[StepStatus]
    CacheHitResult: Optional[CacheHitResult]
    AttemptCount: Optional[IntegerValue]
    FailureReason: Optional[FailureReason]
    Metadata: Optional[PipelineExecutionStepMetadata]


PipelineExecutionStepList = List[PipelineExecutionStep]


class ListPipelineExecutionStepsResponse(TypedDict, total=False):
    PipelineExecutionSteps: Optional[PipelineExecutionStepList]
    NextToken: Optional[NextToken]


class ListPipelineExecutionsRequest(ServiceRequest):
    PipelineName: PipelineName
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortPipelineExecutionsBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class PipelineExecutionSummary(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]
    StartTime: Optional[Timestamp]
    PipelineExecutionStatus: Optional[PipelineExecutionStatus]
    PipelineExecutionDescription: Optional[PipelineExecutionDescription]
    PipelineExecutionDisplayName: Optional[PipelineExecutionName]
    PipelineExecutionFailureReason: Optional[String3072]


PipelineExecutionSummaryList = List[PipelineExecutionSummary]


class ListPipelineExecutionsResponse(TypedDict, total=False):
    PipelineExecutionSummaries: Optional[PipelineExecutionSummaryList]
    NextToken: Optional[NextToken]


class ListPipelineParametersForExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class Parameter(TypedDict, total=False):
    Name: PipelineParameterName
    Value: String1024


ParameterList = List[Parameter]


class ListPipelineParametersForExecutionResponse(TypedDict, total=False):
    PipelineParameters: Optional[ParameterList]
    NextToken: Optional[NextToken]


class ListPipelinesRequest(ServiceRequest):
    PipelineNamePrefix: Optional[PipelineName]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortPipelinesBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class PipelineSummary(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]
    PipelineName: Optional[PipelineName]
    PipelineDisplayName: Optional[PipelineName]
    PipelineDescription: Optional[PipelineDescription]
    RoleArn: Optional[RoleArn]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastExecutionTime: Optional[Timestamp]


PipelineSummaryList = List[PipelineSummary]


class ListPipelinesResponse(TypedDict, total=False):
    PipelineSummaries: Optional[PipelineSummaryList]
    NextToken: Optional[NextToken]


class ListProcessingJobsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[String]
    StatusEquals: Optional[ProcessingJobStatus]
    SortBy: Optional[SortBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ProcessingJobSummary(TypedDict, total=False):
    ProcessingJobName: ProcessingJobName
    ProcessingJobArn: ProcessingJobArn
    CreationTime: Timestamp
    ProcessingEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    ProcessingJobStatus: ProcessingJobStatus
    FailureReason: Optional[FailureReason]
    ExitMessage: Optional[ExitMessage]


ProcessingJobSummaries = List[ProcessingJobSummary]


class ListProcessingJobsResponse(TypedDict, total=False):
    ProcessingJobSummaries: ProcessingJobSummaries
    NextToken: Optional[NextToken]


class ListProjectsInput(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[ProjectEntityName]
    NextToken: Optional[NextToken]
    SortBy: Optional[ProjectSortBy]
    SortOrder: Optional[ProjectSortOrder]


class ProjectSummary(TypedDict, total=False):
    ProjectName: ProjectEntityName
    ProjectDescription: Optional[EntityDescription]
    ProjectArn: ProjectArn
    ProjectId: ProjectId
    CreationTime: Timestamp
    ProjectStatus: ProjectStatus


ProjectSummaryList = List[ProjectSummary]


class ListProjectsOutput(TypedDict, total=False):
    ProjectSummaryList: ProjectSummaryList
    NextToken: Optional[NextToken]


class ListStudioLifecycleConfigsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    NameContains: Optional[StudioLifecycleConfigName]
    AppTypeEquals: Optional[StudioLifecycleConfigAppType]
    CreationTimeBefore: Optional[Timestamp]
    CreationTimeAfter: Optional[Timestamp]
    ModifiedTimeBefore: Optional[Timestamp]
    ModifiedTimeAfter: Optional[Timestamp]
    SortBy: Optional[StudioLifecycleConfigSortKey]
    SortOrder: Optional[SortOrder]


class StudioLifecycleConfigDetails(TypedDict, total=False):
    StudioLifecycleConfigArn: Optional[StudioLifecycleConfigArn]
    StudioLifecycleConfigName: Optional[StudioLifecycleConfigName]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    StudioLifecycleConfigAppType: Optional[StudioLifecycleConfigAppType]


StudioLifecycleConfigsList = List[StudioLifecycleConfigDetails]


class ListStudioLifecycleConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    StudioLifecycleConfigs: Optional[StudioLifecycleConfigsList]


class ListSubscribedWorkteamsRequest(ServiceRequest):
    NameContains: Optional[WorkteamName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


SubscribedWorkteams = List[SubscribedWorkteam]


class ListSubscribedWorkteamsResponse(TypedDict, total=False):
    SubscribedWorkteams: SubscribedWorkteams
    NextToken: Optional[NextToken]


class ListTagsInput(ServiceRequest):
    ResourceArn: ResourceArn
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListTagsMaxResults]


class ListTagsOutput(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[NextToken]


class ListTrainingJobsForHyperParameterTuningJobRequest(ServiceRequest):
    HyperParameterTuningJobName: HyperParameterTuningJobName
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    StatusEquals: Optional[TrainingJobStatus]
    SortBy: Optional[TrainingJobSortByOptions]
    SortOrder: Optional[SortOrder]


class ListTrainingJobsForHyperParameterTuningJobResponse(TypedDict, total=False):
    TrainingJobSummaries: HyperParameterTrainingJobSummaries
    NextToken: Optional[NextToken]


class ListTrainingJobsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[NameContains]
    StatusEquals: Optional[TrainingJobStatus]
    SortBy: Optional[SortBy]
    SortOrder: Optional[SortOrder]


class TrainingJobSummary(TypedDict, total=False):
    TrainingJobName: TrainingJobName
    TrainingJobArn: TrainingJobArn
    CreationTime: Timestamp
    TrainingEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    TrainingJobStatus: TrainingJobStatus


TrainingJobSummaries = List[TrainingJobSummary]


class ListTrainingJobsResponse(TypedDict, total=False):
    TrainingJobSummaries: TrainingJobSummaries
    NextToken: Optional[NextToken]


class ListTransformJobsRequest(ServiceRequest):
    CreationTimeAfter: Optional[Timestamp]
    CreationTimeBefore: Optional[Timestamp]
    LastModifiedTimeAfter: Optional[Timestamp]
    LastModifiedTimeBefore: Optional[Timestamp]
    NameContains: Optional[NameContains]
    StatusEquals: Optional[TransformJobStatus]
    SortBy: Optional[SortBy]
    SortOrder: Optional[SortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class TransformJobSummary(TypedDict, total=False):
    TransformJobName: TransformJobName
    TransformJobArn: TransformJobArn
    CreationTime: Timestamp
    TransformEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    TransformJobStatus: TransformJobStatus
    FailureReason: Optional[FailureReason]


TransformJobSummaries = List[TransformJobSummary]


class ListTransformJobsResponse(TypedDict, total=False):
    TransformJobSummaries: TransformJobSummaries
    NextToken: Optional[NextToken]


ListTrialComponentKey256 = List[TrialComponentKey256]


class ListTrialComponentsRequest(ServiceRequest):
    ExperimentName: Optional[ExperimentEntityName]
    TrialName: Optional[ExperimentEntityName]
    SourceArn: Optional[String256]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortTrialComponentsBy]
    SortOrder: Optional[SortOrder]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class TrialComponentSummary(TypedDict, total=False):
    TrialComponentName: Optional[ExperimentEntityName]
    TrialComponentArn: Optional[TrialComponentArn]
    DisplayName: Optional[ExperimentEntityName]
    TrialComponentSource: Optional[TrialComponentSource]
    Status: Optional[TrialComponentStatus]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]


TrialComponentSummaries = List[TrialComponentSummary]


class ListTrialComponentsResponse(TypedDict, total=False):
    TrialComponentSummaries: Optional[TrialComponentSummaries]
    NextToken: Optional[NextToken]


class ListTrialsRequest(ServiceRequest):
    ExperimentName: Optional[ExperimentEntityName]
    TrialComponentName: Optional[ExperimentEntityName]
    CreatedAfter: Optional[Timestamp]
    CreatedBefore: Optional[Timestamp]
    SortBy: Optional[SortTrialsBy]
    SortOrder: Optional[SortOrder]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class TrialSummary(TypedDict, total=False):
    TrialArn: Optional[TrialArn]
    TrialName: Optional[ExperimentEntityName]
    DisplayName: Optional[ExperimentEntityName]
    TrialSource: Optional[TrialSource]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


TrialSummaries = List[TrialSummary]


class ListTrialsResponse(TypedDict, total=False):
    TrialSummaries: Optional[TrialSummaries]
    NextToken: Optional[NextToken]


class ListUserProfilesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    SortOrder: Optional[SortOrder]
    SortBy: Optional[UserProfileSortKey]
    DomainIdEquals: Optional[DomainId]
    UserProfileNameContains: Optional[UserProfileName]


class UserProfileDetails(TypedDict, total=False):
    DomainId: Optional[DomainId]
    UserProfileName: Optional[UserProfileName]
    Status: Optional[UserProfileStatus]
    CreationTime: Optional[CreationTime]
    LastModifiedTime: Optional[LastModifiedTime]


UserProfileList = List[UserProfileDetails]


class ListUserProfilesResponse(TypedDict, total=False):
    UserProfiles: Optional[UserProfileList]
    NextToken: Optional[NextToken]


class ListWorkforcesRequest(ServiceRequest):
    SortBy: Optional[ListWorkforcesSortByOptions]
    SortOrder: Optional[SortOrder]
    NameContains: Optional[WorkforceName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


Workforces = List[Workforce]


class ListWorkforcesResponse(TypedDict, total=False):
    Workforces: Workforces
    NextToken: Optional[NextToken]


class ListWorkteamsRequest(ServiceRequest):
    SortBy: Optional[ListWorkteamsSortByOptions]
    SortOrder: Optional[SortOrder]
    NameContains: Optional[WorkteamName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


Workteams = List[Workteam]


class ListWorkteamsResponse(TypedDict, total=False):
    Workteams: Workteams
    NextToken: Optional[NextToken]


class ModelPackage(TypedDict, total=False):
    ModelPackageName: Optional[EntityName]
    ModelPackageGroupName: Optional[EntityName]
    ModelPackageVersion: Optional[ModelPackageVersion]
    ModelPackageArn: Optional[ModelPackageArn]
    ModelPackageDescription: Optional[EntityDescription]
    CreationTime: Optional[CreationTime]
    InferenceSpecification: Optional[InferenceSpecification]
    SourceAlgorithmSpecification: Optional[SourceAlgorithmSpecification]
    ValidationSpecification: Optional[ModelPackageValidationSpecification]
    ModelPackageStatus: Optional[ModelPackageStatus]
    ModelPackageStatusDetails: Optional[ModelPackageStatusDetails]
    CertifyForMarketplace: Optional[CertifyForMarketplace]
    ModelApprovalStatus: Optional[ModelApprovalStatus]
    CreatedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]
    ModelMetrics: Optional[ModelMetrics]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    ApprovalDescription: Optional[ApprovalDescription]
    Domain: Optional[String]
    Task: Optional[String]
    SamplePayloadUrl: Optional[String]
    AdditionalInferenceSpecifications: Optional[AdditionalInferenceSpecifications]
    Tags: Optional[TagList]
    CustomerMetadataProperties: Optional[CustomerMetadataMap]
    DriftCheckBaselines: Optional[DriftCheckBaselines]


class ModelPackageGroup(TypedDict, total=False):
    ModelPackageGroupName: Optional[EntityName]
    ModelPackageGroupArn: Optional[ModelPackageGroupArn]
    ModelPackageGroupDescription: Optional[EntityDescription]
    CreationTime: Optional[CreationTime]
    CreatedBy: Optional[UserContext]
    ModelPackageGroupStatus: Optional[ModelPackageGroupStatus]
    Tags: Optional[TagList]


class NestedFilters(TypedDict, total=False):
    NestedPropertyName: ResourcePropertyName
    Filters: FilterList


NestedFiltersList = List[NestedFilters]


class Parent(TypedDict, total=False):
    TrialName: Optional[ExperimentEntityName]
    ExperimentName: Optional[ExperimentEntityName]


Parents = List[Parent]


class Pipeline(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]
    PipelineName: Optional[PipelineName]
    PipelineDisplayName: Optional[PipelineName]
    PipelineDescription: Optional[PipelineDescription]
    RoleArn: Optional[RoleArn]
    PipelineStatus: Optional[PipelineStatus]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastRunTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedBy: Optional[UserContext]
    ParallelismConfiguration: Optional[ParallelismConfiguration]
    Tags: Optional[TagList]


class PipelineExecution(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]
    PipelineExecutionArn: Optional[PipelineExecutionArn]
    PipelineExecutionDisplayName: Optional[PipelineExecutionName]
    PipelineExecutionStatus: Optional[PipelineExecutionStatus]
    PipelineExecutionDescription: Optional[PipelineExecutionDescription]
    PipelineExperimentConfig: Optional[PipelineExperimentConfig]
    FailureReason: Optional[PipelineExecutionFailureReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedBy: Optional[UserContext]
    ParallelismConfiguration: Optional[ParallelismConfiguration]
    PipelineParameters: Optional[ParameterList]


class ProcessingJob(TypedDict, total=False):
    ProcessingInputs: Optional[ProcessingInputs]
    ProcessingOutputConfig: Optional[ProcessingOutputConfig]
    ProcessingJobName: Optional[ProcessingJobName]
    ProcessingResources: Optional[ProcessingResources]
    StoppingCondition: Optional[ProcessingStoppingCondition]
    AppSpecification: Optional[AppSpecification]
    Environment: Optional[ProcessingEnvironmentMap]
    NetworkConfig: Optional[NetworkConfig]
    RoleArn: Optional[RoleArn]
    ExperimentConfig: Optional[ExperimentConfig]
    ProcessingJobArn: Optional[ProcessingJobArn]
    ProcessingJobStatus: Optional[ProcessingJobStatus]
    ExitMessage: Optional[ExitMessage]
    FailureReason: Optional[FailureReason]
    ProcessingEndTime: Optional[Timestamp]
    ProcessingStartTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    CreationTime: Optional[Timestamp]
    MonitoringScheduleArn: Optional[MonitoringScheduleArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    TrainingJobArn: Optional[TrainingJobArn]
    Tags: Optional[TagList]


class ProfilerConfigForUpdate(TypedDict, total=False):
    S3OutputPath: Optional[S3Uri]
    ProfilingIntervalInMilliseconds: Optional[ProfilingIntervalInMilliseconds]
    ProfilingParameters: Optional[ProfilingParameters]
    DisableProfiler: Optional[DisableProfiler]


class Project(TypedDict, total=False):
    ProjectArn: Optional[ProjectArn]
    ProjectName: Optional[ProjectEntityName]
    ProjectId: Optional[ProjectId]
    ProjectDescription: Optional[EntityDescription]
    ServiceCatalogProvisioningDetails: Optional[ServiceCatalogProvisioningDetails]
    ServiceCatalogProvisionedProductDetails: Optional[ServiceCatalogProvisionedProductDetails]
    ProjectStatus: Optional[ProjectStatus]
    CreatedBy: Optional[UserContext]
    CreationTime: Optional[Timestamp]
    Tags: Optional[TagList]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]


class PutModelPackageGroupPolicyInput(ServiceRequest):
    ModelPackageGroupName: EntityName
    ResourcePolicy: PolicyString


class PutModelPackageGroupPolicyOutput(TypedDict, total=False):
    ModelPackageGroupArn: ModelPackageGroupArn


QueryProperties = Dict[String256, String256]
QueryLineageTypes = List[LineageType]
QueryTypes = List[String40]


class QueryFilters(TypedDict, total=False):
    Types: Optional[QueryTypes]
    LineageTypes: Optional[QueryLineageTypes]
    CreatedBefore: Optional[Timestamp]
    CreatedAfter: Optional[Timestamp]
    ModifiedBefore: Optional[Timestamp]
    ModifiedAfter: Optional[Timestamp]
    Properties: Optional[QueryProperties]


QueryLineageStartArns = List[AssociationEntityArn]


class QueryLineageRequest(ServiceRequest):
    StartArns: QueryLineageStartArns
    Direction: Optional[Direction]
    IncludeEdges: Optional[Boolean]
    Filters: Optional[QueryFilters]
    MaxDepth: Optional[QueryLineageMaxDepth]
    MaxResults: Optional[QueryLineageMaxResults]
    NextToken: Optional[String8192]


class Vertex(TypedDict, total=False):
    Arn: Optional[AssociationEntityArn]
    Type: Optional[String40]
    LineageType: Optional[LineageType]


Vertices = List[Vertex]


class QueryLineageResponse(TypedDict, total=False):
    Vertices: Optional[Vertices]
    Edges: Optional[Edges]
    NextToken: Optional[String8192]


class RegisterDevicesRequest(ServiceRequest):
    DeviceFleetName: EntityName
    Devices: Devices
    Tags: Optional[TagList]


class RenderableTask(TypedDict, total=False):
    Input: TaskInput


class RenderUiTemplateRequest(ServiceRequest):
    UiTemplate: Optional[UiTemplate]
    Task: RenderableTask
    RoleArn: RoleArn
    HumanTaskUiArn: Optional[HumanTaskUiArn]


class RenderingError(TypedDict, total=False):
    Code: String
    Message: String


RenderingErrorList = List[RenderingError]


class RenderUiTemplateResponse(TypedDict, total=False):
    RenderedContent: String
    Errors: RenderingErrorList


class RetryPipelineExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn
    ClientRequestToken: IdempotencyToken
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class RetryPipelineExecutionResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class SearchExpression(TypedDict, total=False):
    Filters: Optional["FilterList"]
    NestedFilters: Optional["NestedFiltersList"]
    SubExpressions: Optional["SearchExpressionList"]
    Operator: Optional["BooleanOperator"]


SearchExpressionList = List[SearchExpression]


class TransformJob(TypedDict, total=False):
    TransformJobName: Optional[TransformJobName]
    TransformJobArn: Optional[TransformJobArn]
    TransformJobStatus: Optional[TransformJobStatus]
    FailureReason: Optional[FailureReason]
    ModelName: Optional[ModelName]
    MaxConcurrentTransforms: Optional[MaxConcurrentTransforms]
    ModelClientConfig: Optional[ModelClientConfig]
    MaxPayloadInMB: Optional[MaxPayloadInMB]
    BatchStrategy: Optional[BatchStrategy]
    Environment: Optional[TransformEnvironmentMap]
    TransformInput: Optional[TransformInput]
    TransformOutput: Optional[TransformOutput]
    TransformResources: Optional[TransformResources]
    CreationTime: Optional[Timestamp]
    TransformStartTime: Optional[Timestamp]
    TransformEndTime: Optional[Timestamp]
    LabelingJobArn: Optional[LabelingJobArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    DataProcessing: Optional[DataProcessing]
    ExperimentConfig: Optional[ExperimentConfig]
    Tags: Optional[TagList]


class TrainingJob(TypedDict, total=False):
    TrainingJobName: Optional[TrainingJobName]
    TrainingJobArn: Optional[TrainingJobArn]
    TuningJobArn: Optional[HyperParameterTuningJobArn]
    LabelingJobArn: Optional[LabelingJobArn]
    AutoMLJobArn: Optional[AutoMLJobArn]
    ModelArtifacts: Optional[ModelArtifacts]
    TrainingJobStatus: Optional[TrainingJobStatus]
    SecondaryStatus: Optional[SecondaryStatus]
    FailureReason: Optional[FailureReason]
    HyperParameters: Optional[HyperParameters]
    AlgorithmSpecification: Optional[AlgorithmSpecification]
    RoleArn: Optional[RoleArn]
    InputDataConfig: Optional[InputDataConfig]
    OutputDataConfig: Optional[OutputDataConfig]
    ResourceConfig: Optional[ResourceConfig]
    VpcConfig: Optional[VpcConfig]
    StoppingCondition: Optional[StoppingCondition]
    CreationTime: Optional[Timestamp]
    TrainingStartTime: Optional[Timestamp]
    TrainingEndTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    SecondaryStatusTransitions: Optional[SecondaryStatusTransitions]
    FinalMetricDataList: Optional[FinalMetricDataList]
    EnableNetworkIsolation: Optional[Boolean]
    EnableInterContainerTrafficEncryption: Optional[Boolean]
    EnableManagedSpotTraining: Optional[Boolean]
    CheckpointConfig: Optional[CheckpointConfig]
    TrainingTimeInSeconds: Optional[TrainingTimeInSeconds]
    BillableTimeInSeconds: Optional[BillableTimeInSeconds]
    DebugHookConfig: Optional[DebugHookConfig]
    ExperimentConfig: Optional[ExperimentConfig]
    DebugRuleConfigurations: Optional[DebugRuleConfigurations]
    TensorBoardOutputConfig: Optional[TensorBoardOutputConfig]
    DebugRuleEvaluationStatuses: Optional[DebugRuleEvaluationStatuses]
    Environment: Optional[TrainingEnvironmentMap]
    RetryStrategy: Optional[RetryStrategy]
    Tags: Optional[TagList]


class TrialComponentSourceDetail(TypedDict, total=False):
    SourceArn: Optional[TrialComponentSourceArn]
    TrainingJob: Optional[TrainingJob]
    ProcessingJob: Optional[ProcessingJob]
    TransformJob: Optional[TransformJob]


class TrialComponent(TypedDict, total=False):
    TrialComponentName: Optional[ExperimentEntityName]
    DisplayName: Optional[ExperimentEntityName]
    TrialComponentArn: Optional[TrialComponentArn]
    Source: Optional[TrialComponentSource]
    Status: Optional[TrialComponentStatus]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    Parameters: Optional[TrialComponentParameters]
    InputArtifacts: Optional[TrialComponentArtifacts]
    OutputArtifacts: Optional[TrialComponentArtifacts]
    Metrics: Optional[TrialComponentMetricSummaries]
    MetadataProperties: Optional[MetadataProperties]
    SourceDetail: Optional[TrialComponentSourceDetail]
    LineageGroupArn: Optional[LineageGroupArn]
    Tags: Optional[TagList]
    Parents: Optional[Parents]


class TrialComponentSimpleSummary(TypedDict, total=False):
    TrialComponentName: Optional[ExperimentEntityName]
    TrialComponentArn: Optional[TrialComponentArn]
    TrialComponentSource: Optional[TrialComponentSource]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]


TrialComponentSimpleSummaries = List[TrialComponentSimpleSummary]


class Trial(TypedDict, total=False):
    TrialName: Optional[ExperimentEntityName]
    TrialArn: Optional[TrialArn]
    DisplayName: Optional[ExperimentEntityName]
    ExperimentName: Optional[ExperimentEntityName]
    Source: Optional[TrialSource]
    CreationTime: Optional[Timestamp]
    CreatedBy: Optional[UserContext]
    LastModifiedTime: Optional[Timestamp]
    LastModifiedBy: Optional[UserContext]
    MetadataProperties: Optional[MetadataProperties]
    Tags: Optional[TagList]
    TrialComponentSummaries: Optional[TrialComponentSimpleSummaries]


class SearchRecord(TypedDict, total=False):
    TrainingJob: Optional[TrainingJob]
    Experiment: Optional[Experiment]
    Trial: Optional[Trial]
    TrialComponent: Optional[TrialComponent]
    Endpoint: Optional[Endpoint]
    ModelPackage: Optional[ModelPackage]
    ModelPackageGroup: Optional[ModelPackageGroup]
    Pipeline: Optional[Pipeline]
    PipelineExecution: Optional[PipelineExecution]
    FeatureGroup: Optional[FeatureGroup]
    Project: Optional[Project]


class SearchRequest(ServiceRequest):
    Resource: ResourceType
    SearchExpression: Optional[SearchExpression]
    SortBy: Optional[ResourcePropertyName]
    SortOrder: Optional[SearchSortOrder]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


SearchResultsList = List[SearchRecord]


class SearchResponse(TypedDict, total=False):
    Results: Optional[SearchResultsList]
    NextToken: Optional[NextToken]


class SendPipelineExecutionStepFailureRequest(ServiceRequest):
    CallbackToken: CallbackToken
    FailureReason: Optional[String256]
    ClientRequestToken: Optional[IdempotencyToken]


class SendPipelineExecutionStepFailureResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class SendPipelineExecutionStepSuccessRequest(ServiceRequest):
    CallbackToken: CallbackToken
    OutputParameters: Optional[OutputParameterList]
    ClientRequestToken: Optional[IdempotencyToken]


class SendPipelineExecutionStepSuccessResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class ServiceCatalogProvisioningUpdateDetails(TypedDict, total=False):
    ProvisioningArtifactId: Optional[ServiceCatalogEntityId]
    ProvisioningParameters: Optional[ProvisioningParameters]


class StartMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName


class StartNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName


class StartPipelineExecutionRequest(ServiceRequest):
    PipelineName: PipelineName
    PipelineExecutionDisplayName: Optional[PipelineExecutionName]
    PipelineParameters: Optional[ParameterList]
    PipelineExecutionDescription: Optional[PipelineExecutionDescription]
    ClientRequestToken: IdempotencyToken
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class StartPipelineExecutionResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class StopAutoMLJobRequest(ServiceRequest):
    AutoMLJobName: AutoMLJobName


class StopCompilationJobRequest(ServiceRequest):
    CompilationJobName: EntityName


class StopEdgePackagingJobRequest(ServiceRequest):
    EdgePackagingJobName: EntityName


class StopHyperParameterTuningJobRequest(ServiceRequest):
    HyperParameterTuningJobName: HyperParameterTuningJobName


class StopInferenceRecommendationsJobRequest(ServiceRequest):
    JobName: RecommendationJobName


class StopLabelingJobRequest(ServiceRequest):
    LabelingJobName: LabelingJobName


class StopMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName


class StopNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName


class StopPipelineExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn
    ClientRequestToken: IdempotencyToken


class StopPipelineExecutionResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class StopProcessingJobRequest(ServiceRequest):
    ProcessingJobName: ProcessingJobName


class StopTrainingJobRequest(ServiceRequest):
    TrainingJobName: TrainingJobName


class StopTransformJobRequest(ServiceRequest):
    TransformJobName: TransformJobName


class UpdateActionRequest(ServiceRequest):
    ActionName: ExperimentEntityName
    Description: Optional[ExperimentDescription]
    Status: Optional[ActionStatus]
    Properties: Optional[LineageEntityParameters]
    PropertiesToRemove: Optional[ListLineageEntityParameterKey]


class UpdateActionResponse(TypedDict, total=False):
    ActionArn: Optional[ActionArn]


class UpdateAppImageConfigRequest(ServiceRequest):
    AppImageConfigName: AppImageConfigName
    KernelGatewayImageConfig: Optional[KernelGatewayImageConfig]


class UpdateAppImageConfigResponse(TypedDict, total=False):
    AppImageConfigArn: Optional[AppImageConfigArn]


class UpdateArtifactRequest(ServiceRequest):
    ArtifactArn: ArtifactArn
    ArtifactName: Optional[ExperimentEntityName]
    Properties: Optional[LineageEntityParameters]
    PropertiesToRemove: Optional[ListLineageEntityParameterKey]


class UpdateArtifactResponse(TypedDict, total=False):
    ArtifactArn: Optional[ArtifactArn]


class UpdateCodeRepositoryInput(ServiceRequest):
    CodeRepositoryName: EntityName
    GitConfig: Optional[GitConfigForUpdate]


class UpdateCodeRepositoryOutput(TypedDict, total=False):
    CodeRepositoryArn: CodeRepositoryArn


class UpdateContextRequest(ServiceRequest):
    ContextName: ExperimentEntityName
    Description: Optional[ExperimentDescription]
    Properties: Optional[LineageEntityParameters]
    PropertiesToRemove: Optional[ListLineageEntityParameterKey]


class UpdateContextResponse(TypedDict, total=False):
    ContextArn: Optional[ContextArn]


class UpdateDeviceFleetRequest(ServiceRequest):
    DeviceFleetName: EntityName
    RoleArn: Optional[RoleArn]
    Description: Optional[DeviceFleetDescription]
    OutputConfig: EdgeOutputConfig
    EnableIotRoleAlias: Optional[EnableIotRoleAlias]


class UpdateDevicesRequest(ServiceRequest):
    DeviceFleetName: EntityName
    Devices: Devices


class UpdateDomainRequest(ServiceRequest):
    DomainId: DomainId
    DefaultUserSettings: Optional[UserSettings]
    DomainSettingsForUpdate: Optional[DomainSettingsForUpdate]


class UpdateDomainResponse(TypedDict, total=False):
    DomainArn: Optional[DomainArn]


class VariantProperty(TypedDict, total=False):
    VariantPropertyType: VariantPropertyType


VariantPropertyList = List[VariantProperty]


class UpdateEndpointInput(ServiceRequest):
    EndpointName: EndpointName
    EndpointConfigName: EndpointConfigName
    RetainAllVariantProperties: Optional[Boolean]
    ExcludeRetainedVariantProperties: Optional[VariantPropertyList]
    DeploymentConfig: Optional[DeploymentConfig]
    RetainDeploymentConfig: Optional[Boolean]


class UpdateEndpointOutput(TypedDict, total=False):
    EndpointArn: EndpointArn


class UpdateEndpointWeightsAndCapacitiesInput(ServiceRequest):
    EndpointName: EndpointName
    DesiredWeightsAndCapacities: DesiredWeightAndCapacityList


class UpdateEndpointWeightsAndCapacitiesOutput(TypedDict, total=False):
    EndpointArn: EndpointArn


class UpdateExperimentRequest(ServiceRequest):
    ExperimentName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]
    Description: Optional[ExperimentDescription]


class UpdateExperimentResponse(TypedDict, total=False):
    ExperimentArn: Optional[ExperimentArn]


class UpdateImageRequest(ServiceRequest):
    DeleteProperties: Optional[ImageDeletePropertyList]
    Description: Optional[ImageDescription]
    DisplayName: Optional[ImageDisplayName]
    ImageName: ImageName
    RoleArn: Optional[RoleArn]


class UpdateImageResponse(TypedDict, total=False):
    ImageArn: Optional[ImageArn]


class UpdateModelPackageInput(ServiceRequest):
    ModelPackageArn: ModelPackageArn
    ModelApprovalStatus: Optional[ModelApprovalStatus]
    ApprovalDescription: Optional[ApprovalDescription]
    CustomerMetadataProperties: Optional[CustomerMetadataMap]
    CustomerMetadataPropertiesToRemove: Optional[CustomerMetadataKeyList]
    AdditionalInferenceSpecificationsToAdd: Optional[AdditionalInferenceSpecifications]


class UpdateModelPackageOutput(TypedDict, total=False):
    ModelPackageArn: ModelPackageArn


class UpdateMonitoringScheduleRequest(ServiceRequest):
    MonitoringScheduleName: MonitoringScheduleName
    MonitoringScheduleConfig: MonitoringScheduleConfig


class UpdateMonitoringScheduleResponse(TypedDict, total=False):
    MonitoringScheduleArn: MonitoringScheduleArn


class UpdateNotebookInstanceInput(ServiceRequest):
    NotebookInstanceName: NotebookInstanceName
    InstanceType: Optional[InstanceType]
    RoleArn: Optional[RoleArn]
    LifecycleConfigName: Optional[NotebookInstanceLifecycleConfigName]
    DisassociateLifecycleConfig: Optional[DisassociateNotebookInstanceLifecycleConfig]
    VolumeSizeInGB: Optional[NotebookInstanceVolumeSizeInGB]
    DefaultCodeRepository: Optional[CodeRepositoryNameOrUrl]
    AdditionalCodeRepositories: Optional[AdditionalCodeRepositoryNamesOrUrls]
    AcceleratorTypes: Optional[NotebookInstanceAcceleratorTypes]
    DisassociateAcceleratorTypes: Optional[DisassociateNotebookInstanceAcceleratorTypes]
    DisassociateDefaultCodeRepository: Optional[DisassociateDefaultCodeRepository]
    DisassociateAdditionalCodeRepositories: Optional[DisassociateAdditionalCodeRepositories]
    RootAccess: Optional[RootAccess]


class UpdateNotebookInstanceLifecycleConfigInput(ServiceRequest):
    NotebookInstanceLifecycleConfigName: NotebookInstanceLifecycleConfigName
    OnCreate: Optional[NotebookInstanceLifecycleConfigList]
    OnStart: Optional[NotebookInstanceLifecycleConfigList]


class UpdateNotebookInstanceLifecycleConfigOutput(TypedDict, total=False):
    pass


class UpdateNotebookInstanceOutput(TypedDict, total=False):
    pass


class UpdatePipelineExecutionRequest(ServiceRequest):
    PipelineExecutionArn: PipelineExecutionArn
    PipelineExecutionDescription: Optional[PipelineExecutionDescription]
    PipelineExecutionDisplayName: Optional[PipelineExecutionName]
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class UpdatePipelineExecutionResponse(TypedDict, total=False):
    PipelineExecutionArn: Optional[PipelineExecutionArn]


class UpdatePipelineRequest(ServiceRequest):
    PipelineName: PipelineName
    PipelineDisplayName: Optional[PipelineName]
    PipelineDefinition: Optional[PipelineDefinition]
    PipelineDefinitionS3Location: Optional[PipelineDefinitionS3Location]
    PipelineDescription: Optional[PipelineDescription]
    RoleArn: Optional[RoleArn]
    ParallelismConfiguration: Optional[ParallelismConfiguration]


class UpdatePipelineResponse(TypedDict, total=False):
    PipelineArn: Optional[PipelineArn]


class UpdateProjectInput(ServiceRequest):
    ProjectName: ProjectEntityName
    ProjectDescription: Optional[EntityDescription]
    ServiceCatalogProvisioningUpdateDetails: Optional[ServiceCatalogProvisioningUpdateDetails]
    Tags: Optional[TagList]


class UpdateProjectOutput(TypedDict, total=False):
    ProjectArn: ProjectArn


class UpdateTrainingJobRequest(ServiceRequest):
    TrainingJobName: TrainingJobName
    ProfilerConfig: Optional[ProfilerConfigForUpdate]
    ProfilerRuleConfigurations: Optional[ProfilerRuleConfigurations]


class UpdateTrainingJobResponse(TypedDict, total=False):
    TrainingJobArn: TrainingJobArn


class UpdateTrialComponentRequest(ServiceRequest):
    TrialComponentName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]
    Status: Optional[TrialComponentStatus]
    StartTime: Optional[Timestamp]
    EndTime: Optional[Timestamp]
    Parameters: Optional[TrialComponentParameters]
    ParametersToRemove: Optional[ListTrialComponentKey256]
    InputArtifacts: Optional[TrialComponentArtifacts]
    InputArtifactsToRemove: Optional[ListTrialComponentKey256]
    OutputArtifacts: Optional[TrialComponentArtifacts]
    OutputArtifactsToRemove: Optional[ListTrialComponentKey256]


class UpdateTrialComponentResponse(TypedDict, total=False):
    TrialComponentArn: Optional[TrialComponentArn]


class UpdateTrialRequest(ServiceRequest):
    TrialName: ExperimentEntityName
    DisplayName: Optional[ExperimentEntityName]


class UpdateTrialResponse(TypedDict, total=False):
    TrialArn: Optional[TrialArn]


class UpdateUserProfileRequest(ServiceRequest):
    DomainId: DomainId
    UserProfileName: UserProfileName
    UserSettings: Optional[UserSettings]


class UpdateUserProfileResponse(TypedDict, total=False):
    UserProfileArn: Optional[UserProfileArn]


class UpdateWorkforceRequest(ServiceRequest):
    WorkforceName: WorkforceName
    SourceIpConfig: Optional[SourceIpConfig]
    OidcConfig: Optional[OidcConfig]


class UpdateWorkforceResponse(TypedDict, total=False):
    Workforce: Workforce


class UpdateWorkteamRequest(ServiceRequest):
    WorkteamName: WorkteamName
    MemberDefinitions: Optional[MemberDefinitions]
    Description: Optional[String200]
    NotificationConfiguration: Optional[NotificationConfiguration]


class UpdateWorkteamResponse(TypedDict, total=False):
    Workteam: Workteam


class SagemakerApi:

    service = "sagemaker"
    version = "2017-07-24"

    @handler("AddAssociation")
    def add_association(
        self,
        context: RequestContext,
        source_arn: AssociationEntityArn,
        destination_arn: AssociationEntityArn,
        association_type: AssociationEdgeType = None,
    ) -> AddAssociationResponse:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagList
    ) -> AddTagsOutput:
        raise NotImplementedError

    @handler("AssociateTrialComponent")
    def associate_trial_component(
        self,
        context: RequestContext,
        trial_component_name: ExperimentEntityName,
        trial_name: ExperimentEntityName,
    ) -> AssociateTrialComponentResponse:
        raise NotImplementedError

    @handler("BatchDescribeModelPackage")
    def batch_describe_model_package(
        self, context: RequestContext, model_package_arn_list: ModelPackageArnList
    ) -> BatchDescribeModelPackageOutput:
        raise NotImplementedError

    @handler("CreateAction")
    def create_action(
        self,
        context: RequestContext,
        action_name: ExperimentEntityName,
        source: ActionSource,
        action_type: String256,
        description: ExperimentDescription = None,
        status: ActionStatus = None,
        properties: LineageEntityParameters = None,
        metadata_properties: MetadataProperties = None,
        tags: TagList = None,
    ) -> CreateActionResponse:
        raise NotImplementedError

    @handler("CreateAlgorithm")
    def create_algorithm(
        self,
        context: RequestContext,
        algorithm_name: EntityName,
        training_specification: TrainingSpecification,
        algorithm_description: EntityDescription = None,
        inference_specification: InferenceSpecification = None,
        validation_specification: AlgorithmValidationSpecification = None,
        certify_for_marketplace: CertifyForMarketplace = None,
        tags: TagList = None,
    ) -> CreateAlgorithmOutput:
        raise NotImplementedError

    @handler("CreateApp")
    def create_app(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        app_type: AppType,
        app_name: AppName,
        tags: TagList = None,
        resource_spec: ResourceSpec = None,
    ) -> CreateAppResponse:
        raise NotImplementedError

    @handler("CreateAppImageConfig")
    def create_app_image_config(
        self,
        context: RequestContext,
        app_image_config_name: AppImageConfigName,
        tags: TagList = None,
        kernel_gateway_image_config: KernelGatewayImageConfig = None,
    ) -> CreateAppImageConfigResponse:
        raise NotImplementedError

    @handler("CreateArtifact")
    def create_artifact(
        self,
        context: RequestContext,
        source: ArtifactSource,
        artifact_type: String256,
        artifact_name: ExperimentEntityName = None,
        properties: LineageEntityParameters = None,
        metadata_properties: MetadataProperties = None,
        tags: TagList = None,
    ) -> CreateArtifactResponse:
        raise NotImplementedError

    @handler("CreateAutoMLJob")
    def create_auto_ml_job(
        self,
        context: RequestContext,
        auto_ml_job_name: AutoMLJobName,
        input_data_config: AutoMLInputDataConfig,
        output_data_config: AutoMLOutputDataConfig,
        role_arn: RoleArn,
        problem_type: ProblemType = None,
        auto_ml_job_objective: AutoMLJobObjective = None,
        auto_ml_job_config: AutoMLJobConfig = None,
        generate_candidate_definitions_only: GenerateCandidateDefinitionsOnly = None,
        tags: TagList = None,
        model_deploy_config: ModelDeployConfig = None,
    ) -> CreateAutoMLJobResponse:
        raise NotImplementedError

    @handler("CreateCodeRepository")
    def create_code_repository(
        self,
        context: RequestContext,
        code_repository_name: EntityName,
        git_config: GitConfig,
        tags: TagList = None,
    ) -> CreateCodeRepositoryOutput:
        raise NotImplementedError

    @handler("CreateCompilationJob")
    def create_compilation_job(
        self,
        context: RequestContext,
        compilation_job_name: EntityName,
        role_arn: RoleArn,
        output_config: OutputConfig,
        stopping_condition: StoppingCondition,
        model_package_version_arn: ModelPackageArn = None,
        input_config: InputConfig = None,
        vpc_config: NeoVpcConfig = None,
        tags: TagList = None,
    ) -> CreateCompilationJobResponse:
        raise NotImplementedError

    @handler("CreateContext")
    def create_context(
        self,
        context: RequestContext,
        context_name: ExperimentEntityName,
        source: ContextSource,
        context_type: String256,
        description: ExperimentDescription = None,
        properties: LineageEntityParameters = None,
        tags: TagList = None,
    ) -> CreateContextResponse:
        raise NotImplementedError

    @handler("CreateDataQualityJobDefinition")
    def create_data_quality_job_definition(
        self,
        context: RequestContext,
        job_definition_name: MonitoringJobDefinitionName,
        data_quality_app_specification: DataQualityAppSpecification,
        data_quality_job_input: DataQualityJobInput,
        data_quality_job_output_config: MonitoringOutputConfig,
        job_resources: MonitoringResources,
        role_arn: RoleArn,
        data_quality_baseline_config: DataQualityBaselineConfig = None,
        network_config: MonitoringNetworkConfig = None,
        stopping_condition: MonitoringStoppingCondition = None,
        tags: TagList = None,
    ) -> CreateDataQualityJobDefinitionResponse:
        raise NotImplementedError

    @handler("CreateDeviceFleet")
    def create_device_fleet(
        self,
        context: RequestContext,
        device_fleet_name: EntityName,
        output_config: EdgeOutputConfig,
        role_arn: RoleArn = None,
        description: DeviceFleetDescription = None,
        tags: TagList = None,
        enable_iot_role_alias: EnableIotRoleAlias = None,
    ) -> None:
        raise NotImplementedError

    @handler("CreateDomain")
    def create_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        auth_mode: AuthMode,
        default_user_settings: UserSettings,
        subnet_ids: Subnets,
        vpc_id: VpcId,
        tags: TagList = None,
        app_network_access_type: AppNetworkAccessType = None,
        home_efs_file_system_kms_key_id: KmsKeyId = None,
        kms_key_id: KmsKeyId = None,
        app_security_group_management: AppSecurityGroupManagement = None,
        domain_settings: DomainSettings = None,
    ) -> CreateDomainResponse:
        raise NotImplementedError

    @handler("CreateEdgePackagingJob")
    def create_edge_packaging_job(
        self,
        context: RequestContext,
        edge_packaging_job_name: EntityName,
        compilation_job_name: EntityName,
        model_name: EntityName,
        model_version: EdgeVersion,
        role_arn: RoleArn,
        output_config: EdgeOutputConfig,
        resource_key: KmsKeyId = None,
        tags: TagList = None,
    ) -> None:
        raise NotImplementedError

    @handler("CreateEndpoint")
    def create_endpoint(
        self,
        context: RequestContext,
        endpoint_name: EndpointName,
        endpoint_config_name: EndpointConfigName,
        deployment_config: DeploymentConfig = None,
        tags: TagList = None,
    ) -> CreateEndpointOutput:
        raise NotImplementedError

    @handler("CreateEndpointConfig")
    def create_endpoint_config(
        self,
        context: RequestContext,
        endpoint_config_name: EndpointConfigName,
        production_variants: ProductionVariantList,
        data_capture_config: DataCaptureConfig = None,
        tags: TagList = None,
        kms_key_id: KmsKeyId = None,
        async_inference_config: AsyncInferenceConfig = None,
    ) -> CreateEndpointConfigOutput:
        raise NotImplementedError

    @handler("CreateExperiment")
    def create_experiment(
        self,
        context: RequestContext,
        experiment_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
        description: ExperimentDescription = None,
        tags: TagList = None,
    ) -> CreateExperimentResponse:
        raise NotImplementedError

    @handler("CreateFeatureGroup")
    def create_feature_group(
        self,
        context: RequestContext,
        feature_group_name: FeatureGroupName,
        record_identifier_feature_name: FeatureName,
        event_time_feature_name: FeatureName,
        feature_definitions: FeatureDefinitions,
        online_store_config: OnlineStoreConfig = None,
        offline_store_config: OfflineStoreConfig = None,
        role_arn: RoleArn = None,
        description: Description = None,
        tags: TagList = None,
    ) -> CreateFeatureGroupResponse:
        raise NotImplementedError

    @handler("CreateFlowDefinition")
    def create_flow_definition(
        self,
        context: RequestContext,
        flow_definition_name: FlowDefinitionName,
        human_loop_config: HumanLoopConfig,
        output_config: FlowDefinitionOutputConfig,
        role_arn: RoleArn,
        human_loop_request_source: HumanLoopRequestSource = None,
        human_loop_activation_config: HumanLoopActivationConfig = None,
        tags: TagList = None,
    ) -> CreateFlowDefinitionResponse:
        raise NotImplementedError

    @handler("CreateHumanTaskUi")
    def create_human_task_ui(
        self,
        context: RequestContext,
        human_task_ui_name: HumanTaskUiName,
        ui_template: UiTemplate,
        tags: TagList = None,
    ) -> CreateHumanTaskUiResponse:
        raise NotImplementedError

    @handler("CreateHyperParameterTuningJob")
    def create_hyper_parameter_tuning_job(
        self,
        context: RequestContext,
        hyper_parameter_tuning_job_name: HyperParameterTuningJobName,
        hyper_parameter_tuning_job_config: HyperParameterTuningJobConfig,
        training_job_definition: HyperParameterTrainingJobDefinition = None,
        training_job_definitions: HyperParameterTrainingJobDefinitions = None,
        warm_start_config: HyperParameterTuningJobWarmStartConfig = None,
        tags: TagList = None,
    ) -> CreateHyperParameterTuningJobResponse:
        raise NotImplementedError

    @handler("CreateImage")
    def create_image(
        self,
        context: RequestContext,
        image_name: ImageName,
        role_arn: RoleArn,
        description: ImageDescription = None,
        display_name: ImageDisplayName = None,
        tags: TagList = None,
    ) -> CreateImageResponse:
        raise NotImplementedError

    @handler("CreateImageVersion")
    def create_image_version(
        self,
        context: RequestContext,
        base_image: ImageBaseImage,
        client_token: ClientToken,
        image_name: ImageName,
    ) -> CreateImageVersionResponse:
        raise NotImplementedError

    @handler("CreateInferenceRecommendationsJob")
    def create_inference_recommendations_job(
        self,
        context: RequestContext,
        job_name: RecommendationJobName,
        job_type: RecommendationJobType,
        role_arn: RoleArn,
        input_config: RecommendationJobInputConfig,
        job_description: RecommendationJobDescription = None,
        stopping_conditions: RecommendationJobStoppingConditions = None,
        tags: TagList = None,
    ) -> CreateInferenceRecommendationsJobResponse:
        raise NotImplementedError

    @handler("CreateLabelingJob")
    def create_labeling_job(
        self,
        context: RequestContext,
        labeling_job_name: LabelingJobName,
        label_attribute_name: LabelAttributeName,
        input_config: LabelingJobInputConfig,
        output_config: LabelingJobOutputConfig,
        role_arn: RoleArn,
        human_task_config: HumanTaskConfig,
        label_category_config_s3_uri: S3Uri = None,
        stopping_conditions: LabelingJobStoppingConditions = None,
        labeling_job_algorithms_config: LabelingJobAlgorithmsConfig = None,
        tags: TagList = None,
    ) -> CreateLabelingJobResponse:
        raise NotImplementedError

    @handler("CreateModel")
    def create_model(
        self,
        context: RequestContext,
        model_name: ModelName,
        execution_role_arn: RoleArn,
        primary_container: ContainerDefinition = None,
        containers: ContainerDefinitionList = None,
        inference_execution_config: InferenceExecutionConfig = None,
        tags: TagList = None,
        vpc_config: VpcConfig = None,
        enable_network_isolation: Boolean = None,
    ) -> CreateModelOutput:
        raise NotImplementedError

    @handler("CreateModelBiasJobDefinition")
    def create_model_bias_job_definition(
        self,
        context: RequestContext,
        job_definition_name: MonitoringJobDefinitionName,
        model_bias_app_specification: ModelBiasAppSpecification,
        model_bias_job_input: ModelBiasJobInput,
        model_bias_job_output_config: MonitoringOutputConfig,
        job_resources: MonitoringResources,
        role_arn: RoleArn,
        model_bias_baseline_config: ModelBiasBaselineConfig = None,
        network_config: MonitoringNetworkConfig = None,
        stopping_condition: MonitoringStoppingCondition = None,
        tags: TagList = None,
    ) -> CreateModelBiasJobDefinitionResponse:
        raise NotImplementedError

    @handler("CreateModelExplainabilityJobDefinition")
    def create_model_explainability_job_definition(
        self,
        context: RequestContext,
        job_definition_name: MonitoringJobDefinitionName,
        model_explainability_app_specification: ModelExplainabilityAppSpecification,
        model_explainability_job_input: ModelExplainabilityJobInput,
        model_explainability_job_output_config: MonitoringOutputConfig,
        job_resources: MonitoringResources,
        role_arn: RoleArn,
        model_explainability_baseline_config: ModelExplainabilityBaselineConfig = None,
        network_config: MonitoringNetworkConfig = None,
        stopping_condition: MonitoringStoppingCondition = None,
        tags: TagList = None,
    ) -> CreateModelExplainabilityJobDefinitionResponse:
        raise NotImplementedError

    @handler("CreateModelPackage")
    def create_model_package(
        self,
        context: RequestContext,
        model_package_name: EntityName = None,
        model_package_group_name: ArnOrName = None,
        model_package_description: EntityDescription = None,
        inference_specification: InferenceSpecification = None,
        validation_specification: ModelPackageValidationSpecification = None,
        source_algorithm_specification: SourceAlgorithmSpecification = None,
        certify_for_marketplace: CertifyForMarketplace = None,
        tags: TagList = None,
        model_approval_status: ModelApprovalStatus = None,
        metadata_properties: MetadataProperties = None,
        model_metrics: ModelMetrics = None,
        client_token: ClientToken = None,
        customer_metadata_properties: CustomerMetadataMap = None,
        drift_check_baselines: DriftCheckBaselines = None,
        domain: String = None,
        task: String = None,
        sample_payload_url: S3Uri = None,
        additional_inference_specifications: AdditionalInferenceSpecifications = None,
    ) -> CreateModelPackageOutput:
        raise NotImplementedError

    @handler("CreateModelPackageGroup")
    def create_model_package_group(
        self,
        context: RequestContext,
        model_package_group_name: EntityName,
        model_package_group_description: EntityDescription = None,
        tags: TagList = None,
    ) -> CreateModelPackageGroupOutput:
        raise NotImplementedError

    @handler("CreateModelQualityJobDefinition")
    def create_model_quality_job_definition(
        self,
        context: RequestContext,
        job_definition_name: MonitoringJobDefinitionName,
        model_quality_app_specification: ModelQualityAppSpecification,
        model_quality_job_input: ModelQualityJobInput,
        model_quality_job_output_config: MonitoringOutputConfig,
        job_resources: MonitoringResources,
        role_arn: RoleArn,
        model_quality_baseline_config: ModelQualityBaselineConfig = None,
        network_config: MonitoringNetworkConfig = None,
        stopping_condition: MonitoringStoppingCondition = None,
        tags: TagList = None,
    ) -> CreateModelQualityJobDefinitionResponse:
        raise NotImplementedError

    @handler("CreateMonitoringSchedule")
    def create_monitoring_schedule(
        self,
        context: RequestContext,
        monitoring_schedule_name: MonitoringScheduleName,
        monitoring_schedule_config: MonitoringScheduleConfig,
        tags: TagList = None,
    ) -> CreateMonitoringScheduleResponse:
        raise NotImplementedError

    @handler("CreateNotebookInstance")
    def create_notebook_instance(
        self,
        context: RequestContext,
        notebook_instance_name: NotebookInstanceName,
        instance_type: InstanceType,
        role_arn: RoleArn,
        subnet_id: SubnetId = None,
        security_group_ids: SecurityGroupIds = None,
        kms_key_id: KmsKeyId = None,
        tags: TagList = None,
        lifecycle_config_name: NotebookInstanceLifecycleConfigName = None,
        direct_internet_access: DirectInternetAccess = None,
        volume_size_in_gb: NotebookInstanceVolumeSizeInGB = None,
        accelerator_types: NotebookInstanceAcceleratorTypes = None,
        default_code_repository: CodeRepositoryNameOrUrl = None,
        additional_code_repositories: AdditionalCodeRepositoryNamesOrUrls = None,
        root_access: RootAccess = None,
        platform_identifier: PlatformIdentifier = None,
    ) -> CreateNotebookInstanceOutput:
        raise NotImplementedError

    @handler("CreateNotebookInstanceLifecycleConfig")
    def create_notebook_instance_lifecycle_config(
        self,
        context: RequestContext,
        notebook_instance_lifecycle_config_name: NotebookInstanceLifecycleConfigName,
        on_create: NotebookInstanceLifecycleConfigList = None,
        on_start: NotebookInstanceLifecycleConfigList = None,
    ) -> CreateNotebookInstanceLifecycleConfigOutput:
        raise NotImplementedError

    @handler("CreatePipeline")
    def create_pipeline(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        client_request_token: IdempotencyToken,
        role_arn: RoleArn,
        pipeline_display_name: PipelineName = None,
        pipeline_definition: PipelineDefinition = None,
        pipeline_definition_s3_location: PipelineDefinitionS3Location = None,
        pipeline_description: PipelineDescription = None,
        tags: TagList = None,
        parallelism_configuration: ParallelismConfiguration = None,
    ) -> CreatePipelineResponse:
        raise NotImplementedError

    @handler("CreatePresignedDomainUrl")
    def create_presigned_domain_url(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        session_expiration_duration_in_seconds: SessionExpirationDurationInSeconds = None,
        expires_in_seconds: ExpiresInSeconds = None,
    ) -> CreatePresignedDomainUrlResponse:
        raise NotImplementedError

    @handler("CreatePresignedNotebookInstanceUrl")
    def create_presigned_notebook_instance_url(
        self,
        context: RequestContext,
        notebook_instance_name: NotebookInstanceName,
        session_expiration_duration_in_seconds: SessionExpirationDurationInSeconds = None,
    ) -> CreatePresignedNotebookInstanceUrlOutput:
        raise NotImplementedError

    @handler("CreateProcessingJob")
    def create_processing_job(
        self,
        context: RequestContext,
        processing_job_name: ProcessingJobName,
        processing_resources: ProcessingResources,
        app_specification: AppSpecification,
        role_arn: RoleArn,
        processing_inputs: ProcessingInputs = None,
        processing_output_config: ProcessingOutputConfig = None,
        stopping_condition: ProcessingStoppingCondition = None,
        environment: ProcessingEnvironmentMap = None,
        network_config: NetworkConfig = None,
        tags: TagList = None,
        experiment_config: ExperimentConfig = None,
    ) -> CreateProcessingJobResponse:
        raise NotImplementedError

    @handler("CreateProject")
    def create_project(
        self,
        context: RequestContext,
        project_name: ProjectEntityName,
        service_catalog_provisioning_details: ServiceCatalogProvisioningDetails,
        project_description: EntityDescription = None,
        tags: TagList = None,
    ) -> CreateProjectOutput:
        raise NotImplementedError

    @handler("CreateStudioLifecycleConfig")
    def create_studio_lifecycle_config(
        self,
        context: RequestContext,
        studio_lifecycle_config_name: StudioLifecycleConfigName,
        studio_lifecycle_config_content: StudioLifecycleConfigContent,
        studio_lifecycle_config_app_type: StudioLifecycleConfigAppType,
        tags: TagList = None,
    ) -> CreateStudioLifecycleConfigResponse:
        raise NotImplementedError

    @handler("CreateTrainingJob")
    def create_training_job(
        self,
        context: RequestContext,
        training_job_name: TrainingJobName,
        algorithm_specification: AlgorithmSpecification,
        role_arn: RoleArn,
        output_data_config: OutputDataConfig,
        resource_config: ResourceConfig,
        stopping_condition: StoppingCondition,
        hyper_parameters: HyperParameters = None,
        input_data_config: InputDataConfig = None,
        vpc_config: VpcConfig = None,
        tags: TagList = None,
        enable_network_isolation: Boolean = None,
        enable_inter_container_traffic_encryption: Boolean = None,
        enable_managed_spot_training: Boolean = None,
        checkpoint_config: CheckpointConfig = None,
        debug_hook_config: DebugHookConfig = None,
        debug_rule_configurations: DebugRuleConfigurations = None,
        tensor_board_output_config: TensorBoardOutputConfig = None,
        experiment_config: ExperimentConfig = None,
        profiler_config: ProfilerConfig = None,
        profiler_rule_configurations: ProfilerRuleConfigurations = None,
        environment: TrainingEnvironmentMap = None,
        retry_strategy: RetryStrategy = None,
    ) -> CreateTrainingJobResponse:
        raise NotImplementedError

    @handler("CreateTransformJob")
    def create_transform_job(
        self,
        context: RequestContext,
        transform_job_name: TransformJobName,
        model_name: ModelName,
        transform_input: TransformInput,
        transform_output: TransformOutput,
        transform_resources: TransformResources,
        max_concurrent_transforms: MaxConcurrentTransforms = None,
        model_client_config: ModelClientConfig = None,
        max_payload_in_mb: MaxPayloadInMB = None,
        batch_strategy: BatchStrategy = None,
        environment: TransformEnvironmentMap = None,
        data_processing: DataProcessing = None,
        tags: TagList = None,
        experiment_config: ExperimentConfig = None,
    ) -> CreateTransformJobResponse:
        raise NotImplementedError

    @handler("CreateTrial")
    def create_trial(
        self,
        context: RequestContext,
        trial_name: ExperimentEntityName,
        experiment_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
        metadata_properties: MetadataProperties = None,
        tags: TagList = None,
    ) -> CreateTrialResponse:
        raise NotImplementedError

    @handler("CreateTrialComponent")
    def create_trial_component(
        self,
        context: RequestContext,
        trial_component_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
        status: TrialComponentStatus = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        parameters: TrialComponentParameters = None,
        input_artifacts: TrialComponentArtifacts = None,
        output_artifacts: TrialComponentArtifacts = None,
        metadata_properties: MetadataProperties = None,
        tags: TagList = None,
    ) -> CreateTrialComponentResponse:
        raise NotImplementedError

    @handler("CreateUserProfile")
    def create_user_profile(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        single_sign_on_user_identifier: SingleSignOnUserIdentifier = None,
        single_sign_on_user_value: String256 = None,
        tags: TagList = None,
        user_settings: UserSettings = None,
    ) -> CreateUserProfileResponse:
        raise NotImplementedError

    @handler("CreateWorkforce")
    def create_workforce(
        self,
        context: RequestContext,
        workforce_name: WorkforceName,
        cognito_config: CognitoConfig = None,
        oidc_config: OidcConfig = None,
        source_ip_config: SourceIpConfig = None,
        tags: TagList = None,
    ) -> CreateWorkforceResponse:
        raise NotImplementedError

    @handler("CreateWorkteam")
    def create_workteam(
        self,
        context: RequestContext,
        workteam_name: WorkteamName,
        member_definitions: MemberDefinitions,
        description: String200,
        workforce_name: WorkforceName = None,
        notification_configuration: NotificationConfiguration = None,
        tags: TagList = None,
    ) -> CreateWorkteamResponse:
        raise NotImplementedError

    @handler("DeleteAction")
    def delete_action(
        self, context: RequestContext, action_name: ExperimentEntityName
    ) -> DeleteActionResponse:
        raise NotImplementedError

    @handler("DeleteAlgorithm")
    def delete_algorithm(self, context: RequestContext, algorithm_name: EntityName) -> None:
        raise NotImplementedError

    @handler("DeleteApp")
    def delete_app(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        app_type: AppType,
        app_name: AppName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAppImageConfig")
    def delete_app_image_config(
        self, context: RequestContext, app_image_config_name: AppImageConfigName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteArtifact")
    def delete_artifact(
        self,
        context: RequestContext,
        artifact_arn: ArtifactArn = None,
        source: ArtifactSource = None,
    ) -> DeleteArtifactResponse:
        raise NotImplementedError

    @handler("DeleteAssociation")
    def delete_association(
        self,
        context: RequestContext,
        source_arn: AssociationEntityArn,
        destination_arn: AssociationEntityArn,
    ) -> DeleteAssociationResponse:
        raise NotImplementedError

    @handler("DeleteCodeRepository")
    def delete_code_repository(
        self, context: RequestContext, code_repository_name: EntityName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteContext")
    def delete_context(
        self, context: RequestContext, context_name: ExperimentEntityName
    ) -> DeleteContextResponse:
        raise NotImplementedError

    @handler("DeleteDataQualityJobDefinition")
    def delete_data_quality_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeviceFleet")
    def delete_device_fleet(self, context: RequestContext, device_fleet_name: EntityName) -> None:
        raise NotImplementedError

    @handler("DeleteDomain")
    def delete_domain(
        self, context: RequestContext, domain_id: DomainId, retention_policy: RetentionPolicy = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEndpoint")
    def delete_endpoint(self, context: RequestContext, endpoint_name: EndpointName) -> None:
        raise NotImplementedError

    @handler("DeleteEndpointConfig")
    def delete_endpoint_config(
        self, context: RequestContext, endpoint_config_name: EndpointConfigName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteExperiment")
    def delete_experiment(
        self, context: RequestContext, experiment_name: ExperimentEntityName
    ) -> DeleteExperimentResponse:
        raise NotImplementedError

    @handler("DeleteFeatureGroup")
    def delete_feature_group(
        self, context: RequestContext, feature_group_name: FeatureGroupName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFlowDefinition")
    def delete_flow_definition(
        self, context: RequestContext, flow_definition_name: FlowDefinitionName
    ) -> DeleteFlowDefinitionResponse:
        raise NotImplementedError

    @handler("DeleteHumanTaskUi")
    def delete_human_task_ui(
        self, context: RequestContext, human_task_ui_name: HumanTaskUiName
    ) -> DeleteHumanTaskUiResponse:
        raise NotImplementedError

    @handler("DeleteImage")
    def delete_image(self, context: RequestContext, image_name: ImageName) -> DeleteImageResponse:
        raise NotImplementedError

    @handler("DeleteImageVersion")
    def delete_image_version(
        self, context: RequestContext, image_name: ImageName, version: ImageVersionNumber
    ) -> DeleteImageVersionResponse:
        raise NotImplementedError

    @handler("DeleteModel")
    def delete_model(self, context: RequestContext, model_name: ModelName) -> None:
        raise NotImplementedError

    @handler("DeleteModelBiasJobDefinition")
    def delete_model_bias_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModelExplainabilityJobDefinition")
    def delete_model_explainability_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModelPackage")
    def delete_model_package(
        self, context: RequestContext, model_package_name: VersionedArnOrName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModelPackageGroup")
    def delete_model_package_group(
        self, context: RequestContext, model_package_group_name: ArnOrName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModelPackageGroupPolicy")
    def delete_model_package_group_policy(
        self, context: RequestContext, model_package_group_name: EntityName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModelQualityJobDefinition")
    def delete_model_quality_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMonitoringSchedule")
    def delete_monitoring_schedule(
        self, context: RequestContext, monitoring_schedule_name: MonitoringScheduleName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteNotebookInstance")
    def delete_notebook_instance(
        self, context: RequestContext, notebook_instance_name: NotebookInstanceName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteNotebookInstanceLifecycleConfig")
    def delete_notebook_instance_lifecycle_config(
        self,
        context: RequestContext,
        notebook_instance_lifecycle_config_name: NotebookInstanceLifecycleConfigName,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePipeline")
    def delete_pipeline(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        client_request_token: IdempotencyToken,
    ) -> DeletePipelineResponse:
        raise NotImplementedError

    @handler("DeleteProject")
    def delete_project(self, context: RequestContext, project_name: ProjectEntityName) -> None:
        raise NotImplementedError

    @handler("DeleteStudioLifecycleConfig")
    def delete_studio_lifecycle_config(
        self, context: RequestContext, studio_lifecycle_config_name: StudioLifecycleConfigName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> DeleteTagsOutput:
        raise NotImplementedError

    @handler("DeleteTrial")
    def delete_trial(
        self, context: RequestContext, trial_name: ExperimentEntityName
    ) -> DeleteTrialResponse:
        raise NotImplementedError

    @handler("DeleteTrialComponent")
    def delete_trial_component(
        self, context: RequestContext, trial_component_name: ExperimentEntityName
    ) -> DeleteTrialComponentResponse:
        raise NotImplementedError

    @handler("DeleteUserProfile")
    def delete_user_profile(
        self, context: RequestContext, domain_id: DomainId, user_profile_name: UserProfileName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteWorkforce")
    def delete_workforce(
        self, context: RequestContext, workforce_name: WorkforceName
    ) -> DeleteWorkforceResponse:
        raise NotImplementedError

    @handler("DeleteWorkteam")
    def delete_workteam(
        self, context: RequestContext, workteam_name: WorkteamName
    ) -> DeleteWorkteamResponse:
        raise NotImplementedError

    @handler("DeregisterDevices")
    def deregister_devices(
        self, context: RequestContext, device_fleet_name: EntityName, device_names: DeviceNames
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAction")
    def describe_action(
        self, context: RequestContext, action_name: ExperimentEntityName
    ) -> DescribeActionResponse:
        raise NotImplementedError

    @handler("DescribeAlgorithm")
    def describe_algorithm(
        self, context: RequestContext, algorithm_name: ArnOrName
    ) -> DescribeAlgorithmOutput:
        raise NotImplementedError

    @handler("DescribeApp")
    def describe_app(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        app_type: AppType,
        app_name: AppName,
    ) -> DescribeAppResponse:
        raise NotImplementedError

    @handler("DescribeAppImageConfig")
    def describe_app_image_config(
        self, context: RequestContext, app_image_config_name: AppImageConfigName
    ) -> DescribeAppImageConfigResponse:
        raise NotImplementedError

    @handler("DescribeArtifact")
    def describe_artifact(
        self, context: RequestContext, artifact_arn: ArtifactArn
    ) -> DescribeArtifactResponse:
        raise NotImplementedError

    @handler("DescribeAutoMLJob")
    def describe_auto_ml_job(
        self, context: RequestContext, auto_ml_job_name: AutoMLJobName
    ) -> DescribeAutoMLJobResponse:
        raise NotImplementedError

    @handler("DescribeCodeRepository")
    def describe_code_repository(
        self, context: RequestContext, code_repository_name: EntityName
    ) -> DescribeCodeRepositoryOutput:
        raise NotImplementedError

    @handler("DescribeCompilationJob")
    def describe_compilation_job(
        self, context: RequestContext, compilation_job_name: EntityName
    ) -> DescribeCompilationJobResponse:
        raise NotImplementedError

    @handler("DescribeContext")
    def describe_context(
        self, context: RequestContext, context_name: ExperimentEntityNameOrArn
    ) -> DescribeContextResponse:
        raise NotImplementedError

    @handler("DescribeDataQualityJobDefinition")
    def describe_data_quality_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> DescribeDataQualityJobDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeDevice")
    def describe_device(
        self,
        context: RequestContext,
        device_name: EntityName,
        device_fleet_name: EntityName,
        next_token: NextToken = None,
    ) -> DescribeDeviceResponse:
        raise NotImplementedError

    @handler("DescribeDeviceFleet")
    def describe_device_fleet(
        self, context: RequestContext, device_fleet_name: EntityName
    ) -> DescribeDeviceFleetResponse:
        raise NotImplementedError

    @handler("DescribeDomain")
    def describe_domain(
        self, context: RequestContext, domain_id: DomainId
    ) -> DescribeDomainResponse:
        raise NotImplementedError

    @handler("DescribeEdgePackagingJob")
    def describe_edge_packaging_job(
        self, context: RequestContext, edge_packaging_job_name: EntityName
    ) -> DescribeEdgePackagingJobResponse:
        raise NotImplementedError

    @handler("DescribeEndpoint")
    def describe_endpoint(
        self, context: RequestContext, endpoint_name: EndpointName
    ) -> DescribeEndpointOutput:
        raise NotImplementedError

    @handler("DescribeEndpointConfig")
    def describe_endpoint_config(
        self, context: RequestContext, endpoint_config_name: EndpointConfigName
    ) -> DescribeEndpointConfigOutput:
        raise NotImplementedError

    @handler("DescribeExperiment")
    def describe_experiment(
        self, context: RequestContext, experiment_name: ExperimentEntityName
    ) -> DescribeExperimentResponse:
        raise NotImplementedError

    @handler("DescribeFeatureGroup")
    def describe_feature_group(
        self,
        context: RequestContext,
        feature_group_name: FeatureGroupName,
        next_token: NextToken = None,
    ) -> DescribeFeatureGroupResponse:
        raise NotImplementedError

    @handler("DescribeFlowDefinition")
    def describe_flow_definition(
        self, context: RequestContext, flow_definition_name: FlowDefinitionName
    ) -> DescribeFlowDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeHumanTaskUi")
    def describe_human_task_ui(
        self, context: RequestContext, human_task_ui_name: HumanTaskUiName
    ) -> DescribeHumanTaskUiResponse:
        raise NotImplementedError

    @handler("DescribeHyperParameterTuningJob")
    def describe_hyper_parameter_tuning_job(
        self, context: RequestContext, hyper_parameter_tuning_job_name: HyperParameterTuningJobName
    ) -> DescribeHyperParameterTuningJobResponse:
        raise NotImplementedError

    @handler("DescribeImage")
    def describe_image(
        self, context: RequestContext, image_name: ImageName
    ) -> DescribeImageResponse:
        raise NotImplementedError

    @handler("DescribeImageVersion")
    def describe_image_version(
        self, context: RequestContext, image_name: ImageName, version: ImageVersionNumber = None
    ) -> DescribeImageVersionResponse:
        raise NotImplementedError

    @handler("DescribeInferenceRecommendationsJob")
    def describe_inference_recommendations_job(
        self, context: RequestContext, job_name: RecommendationJobName
    ) -> DescribeInferenceRecommendationsJobResponse:
        raise NotImplementedError

    @handler("DescribeLabelingJob")
    def describe_labeling_job(
        self, context: RequestContext, labeling_job_name: LabelingJobName
    ) -> DescribeLabelingJobResponse:
        raise NotImplementedError

    @handler("DescribeLineageGroup")
    def describe_lineage_group(
        self, context: RequestContext, lineage_group_name: ExperimentEntityName
    ) -> DescribeLineageGroupResponse:
        raise NotImplementedError

    @handler("DescribeModel")
    def describe_model(self, context: RequestContext, model_name: ModelName) -> DescribeModelOutput:
        raise NotImplementedError

    @handler("DescribeModelBiasJobDefinition")
    def describe_model_bias_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> DescribeModelBiasJobDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeModelExplainabilityJobDefinition")
    def describe_model_explainability_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> DescribeModelExplainabilityJobDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeModelPackage")
    def describe_model_package(
        self, context: RequestContext, model_package_name: VersionedArnOrName
    ) -> DescribeModelPackageOutput:
        raise NotImplementedError

    @handler("DescribeModelPackageGroup")
    def describe_model_package_group(
        self, context: RequestContext, model_package_group_name: ArnOrName
    ) -> DescribeModelPackageGroupOutput:
        raise NotImplementedError

    @handler("DescribeModelQualityJobDefinition")
    def describe_model_quality_job_definition(
        self, context: RequestContext, job_definition_name: MonitoringJobDefinitionName
    ) -> DescribeModelQualityJobDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeMonitoringSchedule")
    def describe_monitoring_schedule(
        self, context: RequestContext, monitoring_schedule_name: MonitoringScheduleName
    ) -> DescribeMonitoringScheduleResponse:
        raise NotImplementedError

    @handler("DescribeNotebookInstance")
    def describe_notebook_instance(
        self, context: RequestContext, notebook_instance_name: NotebookInstanceName
    ) -> DescribeNotebookInstanceOutput:
        raise NotImplementedError

    @handler("DescribeNotebookInstanceLifecycleConfig")
    def describe_notebook_instance_lifecycle_config(
        self,
        context: RequestContext,
        notebook_instance_lifecycle_config_name: NotebookInstanceLifecycleConfigName,
    ) -> DescribeNotebookInstanceLifecycleConfigOutput:
        raise NotImplementedError

    @handler("DescribePipeline")
    def describe_pipeline(
        self, context: RequestContext, pipeline_name: PipelineName
    ) -> DescribePipelineResponse:
        raise NotImplementedError

    @handler("DescribePipelineDefinitionForExecution")
    def describe_pipeline_definition_for_execution(
        self, context: RequestContext, pipeline_execution_arn: PipelineExecutionArn
    ) -> DescribePipelineDefinitionForExecutionResponse:
        raise NotImplementedError

    @handler("DescribePipelineExecution")
    def describe_pipeline_execution(
        self, context: RequestContext, pipeline_execution_arn: PipelineExecutionArn
    ) -> DescribePipelineExecutionResponse:
        raise NotImplementedError

    @handler("DescribeProcessingJob")
    def describe_processing_job(
        self, context: RequestContext, processing_job_name: ProcessingJobName
    ) -> DescribeProcessingJobResponse:
        raise NotImplementedError

    @handler("DescribeProject")
    def describe_project(
        self, context: RequestContext, project_name: ProjectEntityName
    ) -> DescribeProjectOutput:
        raise NotImplementedError

    @handler("DescribeStudioLifecycleConfig")
    def describe_studio_lifecycle_config(
        self, context: RequestContext, studio_lifecycle_config_name: StudioLifecycleConfigName
    ) -> DescribeStudioLifecycleConfigResponse:
        raise NotImplementedError

    @handler("DescribeSubscribedWorkteam")
    def describe_subscribed_workteam(
        self, context: RequestContext, workteam_arn: WorkteamArn
    ) -> DescribeSubscribedWorkteamResponse:
        raise NotImplementedError

    @handler("DescribeTrainingJob")
    def describe_training_job(
        self, context: RequestContext, training_job_name: TrainingJobName
    ) -> DescribeTrainingJobResponse:
        raise NotImplementedError

    @handler("DescribeTransformJob")
    def describe_transform_job(
        self, context: RequestContext, transform_job_name: TransformJobName
    ) -> DescribeTransformJobResponse:
        raise NotImplementedError

    @handler("DescribeTrial")
    def describe_trial(
        self, context: RequestContext, trial_name: ExperimentEntityName
    ) -> DescribeTrialResponse:
        raise NotImplementedError

    @handler("DescribeTrialComponent")
    def describe_trial_component(
        self, context: RequestContext, trial_component_name: ExperimentEntityNameOrArn
    ) -> DescribeTrialComponentResponse:
        raise NotImplementedError

    @handler("DescribeUserProfile")
    def describe_user_profile(
        self, context: RequestContext, domain_id: DomainId, user_profile_name: UserProfileName
    ) -> DescribeUserProfileResponse:
        raise NotImplementedError

    @handler("DescribeWorkforce")
    def describe_workforce(
        self, context: RequestContext, workforce_name: WorkforceName
    ) -> DescribeWorkforceResponse:
        raise NotImplementedError

    @handler("DescribeWorkteam")
    def describe_workteam(
        self, context: RequestContext, workteam_name: WorkteamName
    ) -> DescribeWorkteamResponse:
        raise NotImplementedError

    @handler("DisableSagemakerServicecatalogPortfolio")
    def disable_sagemaker_servicecatalog_portfolio(
        self,
        context: RequestContext,
    ) -> DisableSagemakerServicecatalogPortfolioOutput:
        raise NotImplementedError

    @handler("DisassociateTrialComponent")
    def disassociate_trial_component(
        self,
        context: RequestContext,
        trial_component_name: ExperimentEntityName,
        trial_name: ExperimentEntityName,
    ) -> DisassociateTrialComponentResponse:
        raise NotImplementedError

    @handler("EnableSagemakerServicecatalogPortfolio")
    def enable_sagemaker_servicecatalog_portfolio(
        self,
        context: RequestContext,
    ) -> EnableSagemakerServicecatalogPortfolioOutput:
        raise NotImplementedError

    @handler("GetDeviceFleetReport")
    def get_device_fleet_report(
        self, context: RequestContext, device_fleet_name: EntityName
    ) -> GetDeviceFleetReportResponse:
        raise NotImplementedError

    @handler("GetLineageGroupPolicy")
    def get_lineage_group_policy(
        self, context: RequestContext, lineage_group_name: LineageGroupNameOrArn
    ) -> GetLineageGroupPolicyResponse:
        raise NotImplementedError

    @handler("GetModelPackageGroupPolicy")
    def get_model_package_group_policy(
        self, context: RequestContext, model_package_group_name: EntityName
    ) -> GetModelPackageGroupPolicyOutput:
        raise NotImplementedError

    @handler("GetSagemakerServicecatalogPortfolioStatus")
    def get_sagemaker_servicecatalog_portfolio_status(
        self,
        context: RequestContext,
    ) -> GetSagemakerServicecatalogPortfolioStatusOutput:
        raise NotImplementedError

    @handler("GetSearchSuggestions")
    def get_search_suggestions(
        self,
        context: RequestContext,
        resource: ResourceType,
        suggestion_query: SuggestionQuery = None,
    ) -> GetSearchSuggestionsResponse:
        raise NotImplementedError

    @handler("ListActions")
    def list_actions(
        self,
        context: RequestContext,
        source_uri: SourceUri = None,
        action_type: String256 = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortActionsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListActionsResponse:
        raise NotImplementedError

    @handler("ListAlgorithms")
    def list_algorithms(
        self,
        context: RequestContext,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        next_token: NextToken = None,
        sort_by: AlgorithmSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListAlgorithmsOutput:
        raise NotImplementedError

    @handler("ListAppImageConfigs")
    def list_app_image_configs(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        name_contains: AppImageConfigName = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
        modified_time_before: Timestamp = None,
        modified_time_after: Timestamp = None,
        sort_by: AppImageConfigSortKey = None,
        sort_order: SortOrder = None,
    ) -> ListAppImageConfigsResponse:
        raise NotImplementedError

    @handler("ListApps")
    def list_apps(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_order: SortOrder = None,
        sort_by: AppSortKey = None,
        domain_id_equals: DomainId = None,
        user_profile_name_equals: UserProfileName = None,
    ) -> ListAppsResponse:
        raise NotImplementedError

    @handler("ListArtifacts")
    def list_artifacts(
        self,
        context: RequestContext,
        source_uri: SourceUri = None,
        artifact_type: String256 = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortArtifactsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListArtifactsResponse:
        raise NotImplementedError

    @handler("ListAssociations")
    def list_associations(
        self,
        context: RequestContext,
        source_arn: AssociationEntityArn = None,
        destination_arn: AssociationEntityArn = None,
        source_type: String256 = None,
        destination_type: String256 = None,
        association_type: AssociationEdgeType = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortAssociationsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAssociationsResponse:
        raise NotImplementedError

    @handler("ListAutoMLJobs")
    def list_auto_ml_jobs(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: AutoMLNameContains = None,
        status_equals: AutoMLJobStatus = None,
        sort_order: AutoMLSortOrder = None,
        sort_by: AutoMLSortBy = None,
        max_results: AutoMLMaxResults = None,
        next_token: NextToken = None,
    ) -> ListAutoMLJobsResponse:
        raise NotImplementedError

    @handler("ListCandidatesForAutoMLJob")
    def list_candidates_for_auto_ml_job(
        self,
        context: RequestContext,
        auto_ml_job_name: AutoMLJobName,
        status_equals: CandidateStatus = None,
        candidate_name_equals: CandidateName = None,
        sort_order: AutoMLSortOrder = None,
        sort_by: CandidateSortBy = None,
        max_results: AutoMLMaxResults = None,
        next_token: NextToken = None,
    ) -> ListCandidatesForAutoMLJobResponse:
        raise NotImplementedError

    @handler("ListCodeRepositories")
    def list_code_repositories(
        self,
        context: RequestContext,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        max_results: MaxResults = None,
        name_contains: CodeRepositoryNameContains = None,
        next_token: NextToken = None,
        sort_by: CodeRepositorySortBy = None,
        sort_order: CodeRepositorySortOrder = None,
    ) -> ListCodeRepositoriesOutput:
        raise NotImplementedError

    @handler("ListCompilationJobs")
    def list_compilation_jobs(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        last_modified_time_after: LastModifiedTime = None,
        last_modified_time_before: LastModifiedTime = None,
        name_contains: NameContains = None,
        status_equals: CompilationJobStatus = None,
        sort_by: ListCompilationJobsSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListCompilationJobsResponse:
        raise NotImplementedError

    @handler("ListContexts")
    def list_contexts(
        self,
        context: RequestContext,
        source_uri: SourceUri = None,
        context_type: String256 = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortContextsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListContextsResponse:
        raise NotImplementedError

    @handler("ListDataQualityJobDefinitions")
    def list_data_quality_job_definitions(
        self,
        context: RequestContext,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringJobDefinitionSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListDataQualityJobDefinitionsResponse:
        raise NotImplementedError

    @handler("ListDeviceFleets")
    def list_device_fleets(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: ListMaxResults = None,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: NameContains = None,
        sort_by: ListDeviceFleetsSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListDeviceFleetsResponse:
        raise NotImplementedError

    @handler("ListDevices")
    def list_devices(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: ListMaxResults = None,
        latest_heartbeat_after: Timestamp = None,
        model_name: EntityName = None,
        device_fleet_name: EntityName = None,
    ) -> ListDevicesResponse:
        raise NotImplementedError

    @handler("ListDomains")
    def list_domains(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDomainsResponse:
        raise NotImplementedError

    @handler("ListEdgePackagingJobs")
    def list_edge_packaging_jobs(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: ListMaxResults = None,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: NameContains = None,
        model_name_contains: NameContains = None,
        status_equals: EdgePackagingJobStatus = None,
        sort_by: ListEdgePackagingJobsSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListEdgePackagingJobsResponse:
        raise NotImplementedError

    @handler("ListEndpointConfigs")
    def list_endpoint_configs(
        self,
        context: RequestContext,
        sort_by: EndpointConfigSortKey = None,
        sort_order: OrderKey = None,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
        name_contains: EndpointConfigNameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListEndpointConfigsOutput:
        raise NotImplementedError

    @handler("ListEndpoints")
    def list_endpoints(
        self,
        context: RequestContext,
        sort_by: EndpointSortKey = None,
        sort_order: OrderKey = None,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
        name_contains: EndpointNameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        status_equals: EndpointStatus = None,
    ) -> ListEndpointsOutput:
        raise NotImplementedError

    @handler("ListExperiments")
    def list_experiments(
        self,
        context: RequestContext,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortExperimentsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListExperimentsResponse:
        raise NotImplementedError

    @handler("ListFeatureGroups")
    def list_feature_groups(
        self,
        context: RequestContext,
        name_contains: FeatureGroupNameContains = None,
        feature_group_status_equals: FeatureGroupStatus = None,
        offline_store_status_equals: OfflineStoreStatusValue = None,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        sort_order: FeatureGroupSortOrder = None,
        sort_by: FeatureGroupSortBy = None,
        max_results: FeatureGroupMaxResults = None,
        next_token: NextToken = None,
    ) -> ListFeatureGroupsResponse:
        raise NotImplementedError

    @handler("ListFlowDefinitions")
    def list_flow_definitions(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListFlowDefinitionsResponse:
        raise NotImplementedError

    @handler("ListHumanTaskUis")
    def list_human_task_uis(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListHumanTaskUisResponse:
        raise NotImplementedError

    @handler("ListHyperParameterTuningJobs")
    def list_hyper_parameter_tuning_jobs(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_by: HyperParameterTuningJobSortByOptions = None,
        sort_order: SortOrder = None,
        name_contains: NameContains = None,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        status_equals: HyperParameterTuningJobStatus = None,
    ) -> ListHyperParameterTuningJobsResponse:
        raise NotImplementedError

    @handler("ListImageVersions")
    def list_image_versions(
        self,
        context: RequestContext,
        image_name: ImageName,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        sort_by: ImageVersionSortBy = None,
        sort_order: ImageVersionSortOrder = None,
    ) -> ListImageVersionsResponse:
        raise NotImplementedError

    @handler("ListImages")
    def list_images(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        max_results: MaxResults = None,
        name_contains: ImageNameContains = None,
        next_token: NextToken = None,
        sort_by: ImageSortBy = None,
        sort_order: ImageSortOrder = None,
    ) -> ListImagesResponse:
        raise NotImplementedError

    @handler("ListInferenceRecommendationsJobs")
    def list_inference_recommendations_jobs(
        self,
        context: RequestContext,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        last_modified_time_after: LastModifiedTime = None,
        last_modified_time_before: LastModifiedTime = None,
        name_contains: NameContains = None,
        status_equals: RecommendationJobStatus = None,
        sort_by: ListInferenceRecommendationsJobsSortBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListInferenceRecommendationsJobsResponse:
        raise NotImplementedError

    @handler("ListLabelingJobs")
    def list_labeling_jobs(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        name_contains: NameContains = None,
        sort_by: SortBy = None,
        sort_order: SortOrder = None,
        status_equals: LabelingJobStatus = None,
    ) -> ListLabelingJobsResponse:
        raise NotImplementedError

    @handler("ListLabelingJobsForWorkteam")
    def list_labeling_jobs_for_workteam(
        self,
        context: RequestContext,
        workteam_arn: WorkteamArn,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        job_reference_code_contains: JobReferenceCodeContains = None,
        sort_by: ListLabelingJobsForWorkteamSortByOptions = None,
        sort_order: SortOrder = None,
    ) -> ListLabelingJobsForWorkteamResponse:
        raise NotImplementedError

    @handler("ListLineageGroups")
    def list_lineage_groups(
        self,
        context: RequestContext,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortLineageGroupsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListLineageGroupsResponse:
        raise NotImplementedError

    @handler("ListModelBiasJobDefinitions")
    def list_model_bias_job_definitions(
        self,
        context: RequestContext,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringJobDefinitionSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListModelBiasJobDefinitionsResponse:
        raise NotImplementedError

    @handler("ListModelExplainabilityJobDefinitions")
    def list_model_explainability_job_definitions(
        self,
        context: RequestContext,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringJobDefinitionSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListModelExplainabilityJobDefinitionsResponse:
        raise NotImplementedError

    @handler("ListModelMetadata")
    def list_model_metadata(
        self,
        context: RequestContext,
        search_expression: ModelMetadataSearchExpression = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListModelMetadataResponse:
        raise NotImplementedError

    @handler("ListModelPackageGroups")
    def list_model_package_groups(
        self,
        context: RequestContext,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        next_token: NextToken = None,
        sort_by: ModelPackageGroupSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListModelPackageGroupsOutput:
        raise NotImplementedError

    @handler("ListModelPackages")
    def list_model_packages(
        self,
        context: RequestContext,
        creation_time_after: CreationTime = None,
        creation_time_before: CreationTime = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        model_approval_status: ModelApprovalStatus = None,
        model_package_group_name: ArnOrName = None,
        model_package_type: ModelPackageType = None,
        next_token: NextToken = None,
        sort_by: ModelPackageSortBy = None,
        sort_order: SortOrder = None,
    ) -> ListModelPackagesOutput:
        raise NotImplementedError

    @handler("ListModelQualityJobDefinitions")
    def list_model_quality_job_definitions(
        self,
        context: RequestContext,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringJobDefinitionSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListModelQualityJobDefinitionsResponse:
        raise NotImplementedError

    @handler("ListModels")
    def list_models(
        self,
        context: RequestContext,
        sort_by: ModelSortKey = None,
        sort_order: OrderKey = None,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
        name_contains: ModelNameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
    ) -> ListModelsOutput:
        raise NotImplementedError

    @handler("ListMonitoringExecutions")
    def list_monitoring_executions(
        self,
        context: RequestContext,
        monitoring_schedule_name: MonitoringScheduleName = None,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringExecutionSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        scheduled_time_before: Timestamp = None,
        scheduled_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        status_equals: ExecutionStatus = None,
        monitoring_job_definition_name: MonitoringJobDefinitionName = None,
        monitoring_type_equals: MonitoringType = None,
    ) -> ListMonitoringExecutionsResponse:
        raise NotImplementedError

    @handler("ListMonitoringSchedules")
    def list_monitoring_schedules(
        self,
        context: RequestContext,
        endpoint_name: EndpointName = None,
        sort_by: MonitoringScheduleSortKey = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: NameContains = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        status_equals: ScheduleStatus = None,
        monitoring_job_definition_name: MonitoringJobDefinitionName = None,
        monitoring_type_equals: MonitoringType = None,
    ) -> ListMonitoringSchedulesResponse:
        raise NotImplementedError

    @handler("ListNotebookInstanceLifecycleConfigs")
    def list_notebook_instance_lifecycle_configs(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_by: NotebookInstanceLifecycleConfigSortKey = None,
        sort_order: NotebookInstanceLifecycleConfigSortOrder = None,
        name_contains: NotebookInstanceLifecycleConfigNameContains = None,
        creation_time_before: CreationTime = None,
        creation_time_after: CreationTime = None,
        last_modified_time_before: LastModifiedTime = None,
        last_modified_time_after: LastModifiedTime = None,
    ) -> ListNotebookInstanceLifecycleConfigsOutput:
        raise NotImplementedError

    @handler("ListNotebookInstances")
    def list_notebook_instances(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_by: NotebookInstanceSortKey = None,
        sort_order: NotebookInstanceSortOrder = None,
        name_contains: NotebookInstanceNameContains = None,
        creation_time_before: CreationTime = None,
        creation_time_after: CreationTime = None,
        last_modified_time_before: LastModifiedTime = None,
        last_modified_time_after: LastModifiedTime = None,
        status_equals: NotebookInstanceStatus = None,
        notebook_instance_lifecycle_config_name_contains: NotebookInstanceLifecycleConfigName = None,
        default_code_repository_contains: CodeRepositoryContains = None,
        additional_code_repository_equals: CodeRepositoryNameOrUrl = None,
    ) -> ListNotebookInstancesOutput:
        raise NotImplementedError

    @handler("ListPipelineExecutionSteps")
    def list_pipeline_execution_steps(
        self,
        context: RequestContext,
        pipeline_execution_arn: PipelineExecutionArn = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_order: SortOrder = None,
    ) -> ListPipelineExecutionStepsResponse:
        raise NotImplementedError

    @handler("ListPipelineExecutions")
    def list_pipeline_executions(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortPipelineExecutionsBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPipelineExecutionsResponse:
        raise NotImplementedError

    @handler("ListPipelineParametersForExecution")
    def list_pipeline_parameters_for_execution(
        self,
        context: RequestContext,
        pipeline_execution_arn: PipelineExecutionArn,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPipelineParametersForExecutionResponse:
        raise NotImplementedError

    @handler("ListPipelines")
    def list_pipelines(
        self,
        context: RequestContext,
        pipeline_name_prefix: PipelineName = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortPipelinesBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPipelinesResponse:
        raise NotImplementedError

    @handler("ListProcessingJobs")
    def list_processing_jobs(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: String = None,
        status_equals: ProcessingJobStatus = None,
        sort_by: SortBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListProcessingJobsResponse:
        raise NotImplementedError

    @handler("ListProjects")
    def list_projects(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        max_results: MaxResults = None,
        name_contains: ProjectEntityName = None,
        next_token: NextToken = None,
        sort_by: ProjectSortBy = None,
        sort_order: ProjectSortOrder = None,
    ) -> ListProjectsOutput:
        raise NotImplementedError

    @handler("ListStudioLifecycleConfigs")
    def list_studio_lifecycle_configs(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        name_contains: StudioLifecycleConfigName = None,
        app_type_equals: StudioLifecycleConfigAppType = None,
        creation_time_before: Timestamp = None,
        creation_time_after: Timestamp = None,
        modified_time_before: Timestamp = None,
        modified_time_after: Timestamp = None,
        sort_by: StudioLifecycleConfigSortKey = None,
        sort_order: SortOrder = None,
    ) -> ListStudioLifecycleConfigsResponse:
        raise NotImplementedError

    @handler("ListSubscribedWorkteams")
    def list_subscribed_workteams(
        self,
        context: RequestContext,
        name_contains: WorkteamName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListSubscribedWorkteamsResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(
        self,
        context: RequestContext,
        resource_arn: ResourceArn,
        next_token: NextToken = None,
        max_results: ListTagsMaxResults = None,
    ) -> ListTagsOutput:
        raise NotImplementedError

    @handler("ListTrainingJobs")
    def list_training_jobs(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: NameContains = None,
        status_equals: TrainingJobStatus = None,
        sort_by: SortBy = None,
        sort_order: SortOrder = None,
    ) -> ListTrainingJobsResponse:
        raise NotImplementedError

    @handler("ListTrainingJobsForHyperParameterTuningJob")
    def list_training_jobs_for_hyper_parameter_tuning_job(
        self,
        context: RequestContext,
        hyper_parameter_tuning_job_name: HyperParameterTuningJobName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        status_equals: TrainingJobStatus = None,
        sort_by: TrainingJobSortByOptions = None,
        sort_order: SortOrder = None,
    ) -> ListTrainingJobsForHyperParameterTuningJobResponse:
        raise NotImplementedError

    @handler("ListTransformJobs")
    def list_transform_jobs(
        self,
        context: RequestContext,
        creation_time_after: Timestamp = None,
        creation_time_before: Timestamp = None,
        last_modified_time_after: Timestamp = None,
        last_modified_time_before: Timestamp = None,
        name_contains: NameContains = None,
        status_equals: TransformJobStatus = None,
        sort_by: SortBy = None,
        sort_order: SortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTransformJobsResponse:
        raise NotImplementedError

    @handler("ListTrialComponents")
    def list_trial_components(
        self,
        context: RequestContext,
        experiment_name: ExperimentEntityName = None,
        trial_name: ExperimentEntityName = None,
        source_arn: String256 = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortTrialComponentsBy = None,
        sort_order: SortOrder = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListTrialComponentsResponse:
        raise NotImplementedError

    @handler("ListTrials")
    def list_trials(
        self,
        context: RequestContext,
        experiment_name: ExperimentEntityName = None,
        trial_component_name: ExperimentEntityName = None,
        created_after: Timestamp = None,
        created_before: Timestamp = None,
        sort_by: SortTrialsBy = None,
        sort_order: SortOrder = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListTrialsResponse:
        raise NotImplementedError

    @handler("ListUserProfiles")
    def list_user_profiles(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        sort_order: SortOrder = None,
        sort_by: UserProfileSortKey = None,
        domain_id_equals: DomainId = None,
        user_profile_name_contains: UserProfileName = None,
    ) -> ListUserProfilesResponse:
        raise NotImplementedError

    @handler("ListWorkforces")
    def list_workforces(
        self,
        context: RequestContext,
        sort_by: ListWorkforcesSortByOptions = None,
        sort_order: SortOrder = None,
        name_contains: WorkforceName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListWorkforcesResponse:
        raise NotImplementedError

    @handler("ListWorkteams")
    def list_workteams(
        self,
        context: RequestContext,
        sort_by: ListWorkteamsSortByOptions = None,
        sort_order: SortOrder = None,
        name_contains: WorkteamName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListWorkteamsResponse:
        raise NotImplementedError

    @handler("PutModelPackageGroupPolicy")
    def put_model_package_group_policy(
        self,
        context: RequestContext,
        model_package_group_name: EntityName,
        resource_policy: PolicyString,
    ) -> PutModelPackageGroupPolicyOutput:
        raise NotImplementedError

    @handler("QueryLineage")
    def query_lineage(
        self,
        context: RequestContext,
        start_arns: QueryLineageStartArns,
        direction: Direction = None,
        include_edges: Boolean = None,
        filters: QueryFilters = None,
        max_depth: QueryLineageMaxDepth = None,
        max_results: QueryLineageMaxResults = None,
        next_token: String8192 = None,
    ) -> QueryLineageResponse:
        raise NotImplementedError

    @handler("RegisterDevices")
    def register_devices(
        self,
        context: RequestContext,
        device_fleet_name: EntityName,
        devices: Devices,
        tags: TagList = None,
    ) -> None:
        raise NotImplementedError

    @handler("RenderUiTemplate")
    def render_ui_template(
        self,
        context: RequestContext,
        task: RenderableTask,
        role_arn: RoleArn,
        ui_template: UiTemplate = None,
        human_task_ui_arn: HumanTaskUiArn = None,
    ) -> RenderUiTemplateResponse:
        raise NotImplementedError

    @handler("RetryPipelineExecution")
    def retry_pipeline_execution(
        self,
        context: RequestContext,
        pipeline_execution_arn: PipelineExecutionArn,
        client_request_token: IdempotencyToken,
        parallelism_configuration: ParallelismConfiguration = None,
    ) -> RetryPipelineExecutionResponse:
        raise NotImplementedError

    @handler("Search")
    def search(
        self,
        context: RequestContext,
        resource: ResourceType,
        search_expression: SearchExpression = None,
        sort_by: ResourcePropertyName = None,
        sort_order: SearchSortOrder = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> SearchResponse:
        raise NotImplementedError

    @handler("SendPipelineExecutionStepFailure")
    def send_pipeline_execution_step_failure(
        self,
        context: RequestContext,
        callback_token: CallbackToken,
        failure_reason: String256 = None,
        client_request_token: IdempotencyToken = None,
    ) -> SendPipelineExecutionStepFailureResponse:
        raise NotImplementedError

    @handler("SendPipelineExecutionStepSuccess")
    def send_pipeline_execution_step_success(
        self,
        context: RequestContext,
        callback_token: CallbackToken,
        output_parameters: OutputParameterList = None,
        client_request_token: IdempotencyToken = None,
    ) -> SendPipelineExecutionStepSuccessResponse:
        raise NotImplementedError

    @handler("StartMonitoringSchedule")
    def start_monitoring_schedule(
        self, context: RequestContext, monitoring_schedule_name: MonitoringScheduleName
    ) -> None:
        raise NotImplementedError

    @handler("StartNotebookInstance")
    def start_notebook_instance(
        self, context: RequestContext, notebook_instance_name: NotebookInstanceName
    ) -> None:
        raise NotImplementedError

    @handler("StartPipelineExecution")
    def start_pipeline_execution(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        client_request_token: IdempotencyToken,
        pipeline_execution_display_name: PipelineExecutionName = None,
        pipeline_parameters: ParameterList = None,
        pipeline_execution_description: PipelineExecutionDescription = None,
        parallelism_configuration: ParallelismConfiguration = None,
    ) -> StartPipelineExecutionResponse:
        raise NotImplementedError

    @handler("StopAutoMLJob")
    def stop_auto_ml_job(self, context: RequestContext, auto_ml_job_name: AutoMLJobName) -> None:
        raise NotImplementedError

    @handler("StopCompilationJob")
    def stop_compilation_job(
        self, context: RequestContext, compilation_job_name: EntityName
    ) -> None:
        raise NotImplementedError

    @handler("StopEdgePackagingJob")
    def stop_edge_packaging_job(
        self, context: RequestContext, edge_packaging_job_name: EntityName
    ) -> None:
        raise NotImplementedError

    @handler("StopHyperParameterTuningJob")
    def stop_hyper_parameter_tuning_job(
        self, context: RequestContext, hyper_parameter_tuning_job_name: HyperParameterTuningJobName
    ) -> None:
        raise NotImplementedError

    @handler("StopInferenceRecommendationsJob")
    def stop_inference_recommendations_job(
        self, context: RequestContext, job_name: RecommendationJobName
    ) -> None:
        raise NotImplementedError

    @handler("StopLabelingJob")
    def stop_labeling_job(
        self, context: RequestContext, labeling_job_name: LabelingJobName
    ) -> None:
        raise NotImplementedError

    @handler("StopMonitoringSchedule")
    def stop_monitoring_schedule(
        self, context: RequestContext, monitoring_schedule_name: MonitoringScheduleName
    ) -> None:
        raise NotImplementedError

    @handler("StopNotebookInstance")
    def stop_notebook_instance(
        self, context: RequestContext, notebook_instance_name: NotebookInstanceName
    ) -> None:
        raise NotImplementedError

    @handler("StopPipelineExecution")
    def stop_pipeline_execution(
        self,
        context: RequestContext,
        pipeline_execution_arn: PipelineExecutionArn,
        client_request_token: IdempotencyToken,
    ) -> StopPipelineExecutionResponse:
        raise NotImplementedError

    @handler("StopProcessingJob")
    def stop_processing_job(
        self, context: RequestContext, processing_job_name: ProcessingJobName
    ) -> None:
        raise NotImplementedError

    @handler("StopTrainingJob")
    def stop_training_job(
        self, context: RequestContext, training_job_name: TrainingJobName
    ) -> None:
        raise NotImplementedError

    @handler("StopTransformJob")
    def stop_transform_job(
        self, context: RequestContext, transform_job_name: TransformJobName
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAction")
    def update_action(
        self,
        context: RequestContext,
        action_name: ExperimentEntityName,
        description: ExperimentDescription = None,
        status: ActionStatus = None,
        properties: LineageEntityParameters = None,
        properties_to_remove: ListLineageEntityParameterKey = None,
    ) -> UpdateActionResponse:
        raise NotImplementedError

    @handler("UpdateAppImageConfig")
    def update_app_image_config(
        self,
        context: RequestContext,
        app_image_config_name: AppImageConfigName,
        kernel_gateway_image_config: KernelGatewayImageConfig = None,
    ) -> UpdateAppImageConfigResponse:
        raise NotImplementedError

    @handler("UpdateArtifact")
    def update_artifact(
        self,
        context: RequestContext,
        artifact_arn: ArtifactArn,
        artifact_name: ExperimentEntityName = None,
        properties: LineageEntityParameters = None,
        properties_to_remove: ListLineageEntityParameterKey = None,
    ) -> UpdateArtifactResponse:
        raise NotImplementedError

    @handler("UpdateCodeRepository")
    def update_code_repository(
        self,
        context: RequestContext,
        code_repository_name: EntityName,
        git_config: GitConfigForUpdate = None,
    ) -> UpdateCodeRepositoryOutput:
        raise NotImplementedError

    @handler("UpdateContext")
    def update_context(
        self,
        context: RequestContext,
        context_name: ExperimentEntityName,
        description: ExperimentDescription = None,
        properties: LineageEntityParameters = None,
        properties_to_remove: ListLineageEntityParameterKey = None,
    ) -> UpdateContextResponse:
        raise NotImplementedError

    @handler("UpdateDeviceFleet")
    def update_device_fleet(
        self,
        context: RequestContext,
        device_fleet_name: EntityName,
        output_config: EdgeOutputConfig,
        role_arn: RoleArn = None,
        description: DeviceFleetDescription = None,
        enable_iot_role_alias: EnableIotRoleAlias = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDevices")
    def update_devices(
        self, context: RequestContext, device_fleet_name: EntityName, devices: Devices
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDomain")
    def update_domain(
        self,
        context: RequestContext,
        domain_id: DomainId,
        default_user_settings: UserSettings = None,
        domain_settings_for_update: DomainSettingsForUpdate = None,
    ) -> UpdateDomainResponse:
        raise NotImplementedError

    @handler("UpdateEndpoint")
    def update_endpoint(
        self,
        context: RequestContext,
        endpoint_name: EndpointName,
        endpoint_config_name: EndpointConfigName,
        retain_all_variant_properties: Boolean = None,
        exclude_retained_variant_properties: VariantPropertyList = None,
        deployment_config: DeploymentConfig = None,
        retain_deployment_config: Boolean = None,
    ) -> UpdateEndpointOutput:
        raise NotImplementedError

    @handler("UpdateEndpointWeightsAndCapacities")
    def update_endpoint_weights_and_capacities(
        self,
        context: RequestContext,
        endpoint_name: EndpointName,
        desired_weights_and_capacities: DesiredWeightAndCapacityList,
    ) -> UpdateEndpointWeightsAndCapacitiesOutput:
        raise NotImplementedError

    @handler("UpdateExperiment")
    def update_experiment(
        self,
        context: RequestContext,
        experiment_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
        description: ExperimentDescription = None,
    ) -> UpdateExperimentResponse:
        raise NotImplementedError

    @handler("UpdateImage")
    def update_image(
        self,
        context: RequestContext,
        image_name: ImageName,
        delete_properties: ImageDeletePropertyList = None,
        description: ImageDescription = None,
        display_name: ImageDisplayName = None,
        role_arn: RoleArn = None,
    ) -> UpdateImageResponse:
        raise NotImplementedError

    @handler("UpdateModelPackage")
    def update_model_package(
        self,
        context: RequestContext,
        model_package_arn: ModelPackageArn,
        model_approval_status: ModelApprovalStatus = None,
        approval_description: ApprovalDescription = None,
        customer_metadata_properties: CustomerMetadataMap = None,
        customer_metadata_properties_to_remove: CustomerMetadataKeyList = None,
        additional_inference_specifications_to_add: AdditionalInferenceSpecifications = None,
    ) -> UpdateModelPackageOutput:
        raise NotImplementedError

    @handler("UpdateMonitoringSchedule")
    def update_monitoring_schedule(
        self,
        context: RequestContext,
        monitoring_schedule_name: MonitoringScheduleName,
        monitoring_schedule_config: MonitoringScheduleConfig,
    ) -> UpdateMonitoringScheduleResponse:
        raise NotImplementedError

    @handler("UpdateNotebookInstance")
    def update_notebook_instance(
        self,
        context: RequestContext,
        notebook_instance_name: NotebookInstanceName,
        instance_type: InstanceType = None,
        role_arn: RoleArn = None,
        lifecycle_config_name: NotebookInstanceLifecycleConfigName = None,
        disassociate_lifecycle_config: DisassociateNotebookInstanceLifecycleConfig = None,
        volume_size_in_gb: NotebookInstanceVolumeSizeInGB = None,
        default_code_repository: CodeRepositoryNameOrUrl = None,
        additional_code_repositories: AdditionalCodeRepositoryNamesOrUrls = None,
        accelerator_types: NotebookInstanceAcceleratorTypes = None,
        disassociate_accelerator_types: DisassociateNotebookInstanceAcceleratorTypes = None,
        disassociate_default_code_repository: DisassociateDefaultCodeRepository = None,
        disassociate_additional_code_repositories: DisassociateAdditionalCodeRepositories = None,
        root_access: RootAccess = None,
    ) -> UpdateNotebookInstanceOutput:
        raise NotImplementedError

    @handler("UpdateNotebookInstanceLifecycleConfig")
    def update_notebook_instance_lifecycle_config(
        self,
        context: RequestContext,
        notebook_instance_lifecycle_config_name: NotebookInstanceLifecycleConfigName,
        on_create: NotebookInstanceLifecycleConfigList = None,
        on_start: NotebookInstanceLifecycleConfigList = None,
    ) -> UpdateNotebookInstanceLifecycleConfigOutput:
        raise NotImplementedError

    @handler("UpdatePipeline")
    def update_pipeline(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        pipeline_display_name: PipelineName = None,
        pipeline_definition: PipelineDefinition = None,
        pipeline_definition_s3_location: PipelineDefinitionS3Location = None,
        pipeline_description: PipelineDescription = None,
        role_arn: RoleArn = None,
        parallelism_configuration: ParallelismConfiguration = None,
    ) -> UpdatePipelineResponse:
        raise NotImplementedError

    @handler("UpdatePipelineExecution")
    def update_pipeline_execution(
        self,
        context: RequestContext,
        pipeline_execution_arn: PipelineExecutionArn,
        pipeline_execution_description: PipelineExecutionDescription = None,
        pipeline_execution_display_name: PipelineExecutionName = None,
        parallelism_configuration: ParallelismConfiguration = None,
    ) -> UpdatePipelineExecutionResponse:
        raise NotImplementedError

    @handler("UpdateProject")
    def update_project(
        self,
        context: RequestContext,
        project_name: ProjectEntityName,
        project_description: EntityDescription = None,
        service_catalog_provisioning_update_details: ServiceCatalogProvisioningUpdateDetails = None,
        tags: TagList = None,
    ) -> UpdateProjectOutput:
        raise NotImplementedError

    @handler("UpdateTrainingJob")
    def update_training_job(
        self,
        context: RequestContext,
        training_job_name: TrainingJobName,
        profiler_config: ProfilerConfigForUpdate = None,
        profiler_rule_configurations: ProfilerRuleConfigurations = None,
    ) -> UpdateTrainingJobResponse:
        raise NotImplementedError

    @handler("UpdateTrial")
    def update_trial(
        self,
        context: RequestContext,
        trial_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
    ) -> UpdateTrialResponse:
        raise NotImplementedError

    @handler("UpdateTrialComponent")
    def update_trial_component(
        self,
        context: RequestContext,
        trial_component_name: ExperimentEntityName,
        display_name: ExperimentEntityName = None,
        status: TrialComponentStatus = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        parameters: TrialComponentParameters = None,
        parameters_to_remove: ListTrialComponentKey256 = None,
        input_artifacts: TrialComponentArtifacts = None,
        input_artifacts_to_remove: ListTrialComponentKey256 = None,
        output_artifacts: TrialComponentArtifacts = None,
        output_artifacts_to_remove: ListTrialComponentKey256 = None,
    ) -> UpdateTrialComponentResponse:
        raise NotImplementedError

    @handler("UpdateUserProfile")
    def update_user_profile(
        self,
        context: RequestContext,
        domain_id: DomainId,
        user_profile_name: UserProfileName,
        user_settings: UserSettings = None,
    ) -> UpdateUserProfileResponse:
        raise NotImplementedError

    @handler("UpdateWorkforce")
    def update_workforce(
        self,
        context: RequestContext,
        workforce_name: WorkforceName,
        source_ip_config: SourceIpConfig = None,
        oidc_config: OidcConfig = None,
    ) -> UpdateWorkforceResponse:
        raise NotImplementedError

    @handler("UpdateWorkteam")
    def update_workteam(
        self,
        context: RequestContext,
        workteam_name: WorkteamName,
        member_definitions: MemberDefinitions = None,
        description: String200 = None,
        notification_configuration: NotificationConfiguration = None,
    ) -> UpdateWorkteamResponse:
        raise NotImplementedError
