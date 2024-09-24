from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
ArnOrJsonPath = str
ArnOrUrl = str
BatchArraySize = int
BatchRetryAttempts = int
Boolean = bool
CapacityProvider = str
CapacityProviderStrategyItemBase = int
CapacityProviderStrategyItemWeight = int
CloudwatchLogGroupArn = str
Database = str
DbUser = str
DimensionName = str
DimensionValue = str
EndpointString = str
EphemeralStorageSize = int
ErrorMessage = str
EventBridgeDetailType = str
EventBridgeEndpointId = str
EventBridgeEventSource = str
EventPattern = str
FirehoseArn = str
HeaderKey = str
HeaderValue = str
InputTemplate = str
Integer = int
JsonPath = str
KafkaTopicName = str
KinesisPartitionKey = str
KmsKeyIdentifier = str
LimitMax10 = int
LimitMax100 = int
LimitMax10000 = int
LimitMin1 = int
LogStreamName = str
MQBrokerQueueName = str
MaximumBatchingWindowInSeconds = int
MaximumRecordAgeInSeconds = int
MaximumRetryAttemptsESM = int
MeasureName = str
MeasureValue = str
MessageDeduplicationId = str
MessageGroupId = str
MultiMeasureAttributeName = str
MultiMeasureName = str
NextToken = str
OptionalArn = str
PathParameter = str
PipeArn = str
PipeDescription = str
PipeName = str
PipeStateReason = str
PlacementConstraintExpression = str
PlacementStrategyField = str
QueryStringKey = str
QueryStringValue = str
ReferenceId = str
ResourceArn = str
RoleArn = str
S3LogDestinationParametersBucketNameString = str
S3LogDestinationParametersBucketOwnerString = str
S3LogDestinationParametersPrefixString = str
SageMakerPipelineParameterName = str
SageMakerPipelineParameterValue = str
SecretManagerArn = str
SecretManagerArnOrJsonPath = str
SecurityGroup = str
SecurityGroupId = str
Sql = str
StatementName = str
String = str
Subnet = str
SubnetId = str
TagKey = str
TagValue = str
TimeValue = str
TimestampFormat = str
URI = str
VersionValue = str


class AssignPublicIp(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class BatchJobDependencyType(StrEnum):
    N_TO_N = "N_TO_N"
    SEQUENTIAL = "SEQUENTIAL"


class BatchResourceRequirementType(StrEnum):
    GPU = "GPU"
    MEMORY = "MEMORY"
    VCPU = "VCPU"


class DimensionValueType(StrEnum):
    VARCHAR = "VARCHAR"


class DynamoDBStreamStartPosition(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"


class EcsEnvironmentFileType(StrEnum):
    s3 = "s3"


class EcsResourceRequirementType(StrEnum):
    GPU = "GPU"
    InferenceAccelerator = "InferenceAccelerator"


class EpochTimeUnit(StrEnum):
    MILLISECONDS = "MILLISECONDS"
    SECONDS = "SECONDS"
    MICROSECONDS = "MICROSECONDS"
    NANOSECONDS = "NANOSECONDS"


class IncludeExecutionDataOption(StrEnum):
    ALL = "ALL"


class KinesisStreamStartPosition(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"


class LaunchType(StrEnum):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class LogLevel(StrEnum):
    OFF = "OFF"
    ERROR = "ERROR"
    INFO = "INFO"
    TRACE = "TRACE"


class MSKStartPosition(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"


class MeasureValueType(StrEnum):
    DOUBLE = "DOUBLE"
    BIGINT = "BIGINT"
    VARCHAR = "VARCHAR"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"


class OnPartialBatchItemFailureStreams(StrEnum):
    AUTOMATIC_BISECT = "AUTOMATIC_BISECT"


class PipeState(StrEnum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    STARTING = "STARTING"
    STOPPING = "STOPPING"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATE_FAILED = "UPDATE_FAILED"
    START_FAILED = "START_FAILED"
    STOP_FAILED = "STOP_FAILED"
    DELETE_FAILED = "DELETE_FAILED"
    CREATE_ROLLBACK_FAILED = "CREATE_ROLLBACK_FAILED"
    DELETE_ROLLBACK_FAILED = "DELETE_ROLLBACK_FAILED"
    UPDATE_ROLLBACK_FAILED = "UPDATE_ROLLBACK_FAILED"


class PipeTargetInvocationType(StrEnum):
    REQUEST_RESPONSE = "REQUEST_RESPONSE"
    FIRE_AND_FORGET = "FIRE_AND_FORGET"


class PlacementConstraintType(StrEnum):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(StrEnum):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PropagateTags(StrEnum):
    TASK_DEFINITION = "TASK_DEFINITION"


class RequestedPipeState(StrEnum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"


class RequestedPipeStateDescribeResponse(StrEnum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    DELETED = "DELETED"


class S3OutputFormat(StrEnum):
    json = "json"
    plain = "plain"
    w3c = "w3c"


class SelfManagedKafkaStartPosition(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"


class TimeFieldType(StrEnum):
    EPOCH = "EPOCH"
    TIMESTAMP_FORMAT = "TIMESTAMP_FORMAT"


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = True
    status_code: int = 409
    resourceId: String
    resourceType: String


class InternalException(ServiceException):
    code: str = "InternalException"
    sender_fault: bool = False
    status_code: int = 500
    retryAfterSeconds: Optional[Integer]


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = True
    status_code: int = 402
    resourceId: String
    resourceType: String
    serviceCode: String
    quotaCode: String


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = True
    status_code: int = 429
    serviceCode: Optional[String]
    quotaCode: Optional[String]
    retryAfterSeconds: Optional[Integer]


class ValidationExceptionField(TypedDict, total=False):
    name: String
    message: ErrorMessage


ValidationExceptionFieldList = List[ValidationExceptionField]


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400
    fieldList: Optional[ValidationExceptionFieldList]


SecurityGroups = List[SecurityGroup]
Subnets = List[Subnet]


class AwsVpcConfiguration(TypedDict, total=False):
    Subnets: Subnets
    SecurityGroups: Optional[SecurityGroups]
    AssignPublicIp: Optional[AssignPublicIp]


class BatchArrayProperties(TypedDict, total=False):
    Size: Optional[BatchArraySize]


class BatchResourceRequirement(TypedDict, total=False):
    Type: BatchResourceRequirementType
    Value: String


BatchResourceRequirementsList = List[BatchResourceRequirement]


class BatchEnvironmentVariable(TypedDict, total=False):
    Name: Optional[String]
    Value: Optional[String]


BatchEnvironmentVariableList = List[BatchEnvironmentVariable]
StringList = List[String]


class BatchContainerOverrides(TypedDict, total=False):
    Command: Optional[StringList]
    Environment: Optional[BatchEnvironmentVariableList]
    InstanceType: Optional[String]
    ResourceRequirements: Optional[BatchResourceRequirementsList]


class BatchJobDependency(TypedDict, total=False):
    JobId: Optional[String]
    Type: Optional[BatchJobDependencyType]


BatchDependsOn = List[BatchJobDependency]
BatchParametersMap = Dict[String, String]


class BatchRetryStrategy(TypedDict, total=False):
    Attempts: Optional[BatchRetryAttempts]


class CapacityProviderStrategyItem(TypedDict, total=False):
    capacityProvider: CapacityProvider
    weight: Optional[CapacityProviderStrategyItemWeight]
    base: Optional[CapacityProviderStrategyItemBase]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]


class CloudwatchLogsLogDestination(TypedDict, total=False):
    LogGroupArn: Optional[CloudwatchLogGroupArn]


class CloudwatchLogsLogDestinationParameters(TypedDict, total=False):
    LogGroupArn: CloudwatchLogGroupArn


IncludeExecutionData = List[IncludeExecutionDataOption]


class FirehoseLogDestinationParameters(TypedDict, total=False):
    DeliveryStreamArn: FirehoseArn


class S3LogDestinationParameters(TypedDict, total=False):
    BucketName: S3LogDestinationParametersBucketNameString
    BucketOwner: S3LogDestinationParametersBucketOwnerString
    OutputFormat: Optional[S3OutputFormat]
    Prefix: Optional[S3LogDestinationParametersPrefixString]


class PipeLogConfigurationParameters(TypedDict, total=False):
    S3LogDestination: Optional[S3LogDestinationParameters]
    FirehoseLogDestination: Optional[FirehoseLogDestinationParameters]
    CloudwatchLogsLogDestination: Optional[CloudwatchLogsLogDestinationParameters]
    Level: LogLevel
    IncludeExecutionData: Optional[IncludeExecutionData]


TagMap = Dict[TagKey, TagValue]


class MultiMeasureAttributeMapping(TypedDict, total=False):
    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MultiMeasureAttributeName: MultiMeasureAttributeName


MultiMeasureAttributeMappings = List[MultiMeasureAttributeMapping]


class MultiMeasureMapping(TypedDict, total=False):
    MultiMeasureName: MultiMeasureName
    MultiMeasureAttributeMappings: MultiMeasureAttributeMappings


MultiMeasureMappings = List[MultiMeasureMapping]


class SingleMeasureMapping(TypedDict, total=False):
    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MeasureName: MeasureName


SingleMeasureMappings = List[SingleMeasureMapping]


class DimensionMapping(TypedDict, total=False):
    DimensionValue: DimensionValue
    DimensionValueType: DimensionValueType
    DimensionName: DimensionName


DimensionMappings = List[DimensionMapping]


class PipeTargetTimestreamParameters(TypedDict, total=False):
    TimeValue: TimeValue
    EpochTimeUnit: Optional[EpochTimeUnit]
    TimeFieldType: Optional[TimeFieldType]
    TimestampFormat: Optional[TimestampFormat]
    VersionValue: VersionValue
    DimensionMappings: DimensionMappings
    SingleMeasureMappings: Optional[SingleMeasureMappings]
    MultiMeasureMappings: Optional[MultiMeasureMappings]


class PipeTargetCloudWatchLogsParameters(TypedDict, total=False):
    LogStreamName: Optional[LogStreamName]
    Timestamp: Optional[JsonPath]


EventBridgeEventResourceList = List[ArnOrJsonPath]


class PipeTargetEventBridgeEventBusParameters(TypedDict, total=False):
    EndpointId: Optional[EventBridgeEndpointId]
    DetailType: Optional[EventBridgeDetailType]
    Source: Optional[EventBridgeEventSource]
    Resources: Optional[EventBridgeEventResourceList]
    Time: Optional[JsonPath]


class SageMakerPipelineParameter(TypedDict, total=False):
    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = List[SageMakerPipelineParameter]


class PipeTargetSageMakerPipelineParameters(TypedDict, total=False):
    PipelineParameterList: Optional[SageMakerPipelineParameterList]


Sqls = List[Sql]


class PipeTargetRedshiftDataParameters(TypedDict, total=False):
    SecretManagerArn: Optional[SecretManagerArnOrJsonPath]
    Database: Database
    DbUser: Optional[DbUser]
    StatementName: Optional[StatementName]
    WithEvent: Optional[Boolean]
    Sqls: Sqls


QueryStringParametersMap = Dict[QueryStringKey, QueryStringValue]
HeaderParametersMap = Dict[HeaderKey, HeaderValue]
PathParameterList = List[PathParameter]


class PipeTargetHttpParameters(TypedDict, total=False):
    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


class PipeTargetSqsQueueParameters(TypedDict, total=False):
    MessageGroupId: Optional[MessageGroupId]
    MessageDeduplicationId: Optional[MessageDeduplicationId]


class PipeTargetBatchJobParameters(TypedDict, total=False):
    JobDefinition: String
    JobName: String
    ArrayProperties: Optional[BatchArrayProperties]
    RetryStrategy: Optional[BatchRetryStrategy]
    ContainerOverrides: Optional[BatchContainerOverrides]
    DependsOn: Optional[BatchDependsOn]
    Parameters: Optional[BatchParametersMap]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class EcsInferenceAcceleratorOverride(TypedDict, total=False):
    deviceName: Optional[String]
    deviceType: Optional[String]


EcsInferenceAcceleratorOverrideList = List[EcsInferenceAcceleratorOverride]


class EcsEphemeralStorage(TypedDict, total=False):
    sizeInGiB: EphemeralStorageSize


EcsResourceRequirement = TypedDict(
    "EcsResourceRequirement",
    {
        "type": EcsResourceRequirementType,
        "value": String,
    },
    total=False,
)
EcsResourceRequirementsList = List[EcsResourceRequirement]
EcsEnvironmentFile = TypedDict(
    "EcsEnvironmentFile",
    {
        "type": EcsEnvironmentFileType,
        "value": String,
    },
    total=False,
)
EcsEnvironmentFileList = List[EcsEnvironmentFile]


class EcsEnvironmentVariable(TypedDict, total=False):
    name: Optional[String]
    value: Optional[String]


EcsEnvironmentVariableList = List[EcsEnvironmentVariable]


class EcsContainerOverride(TypedDict, total=False):
    Command: Optional[StringList]
    Cpu: Optional[Integer]
    Environment: Optional[EcsEnvironmentVariableList]
    EnvironmentFiles: Optional[EcsEnvironmentFileList]
    Memory: Optional[Integer]
    MemoryReservation: Optional[Integer]
    Name: Optional[String]
    ResourceRequirements: Optional[EcsResourceRequirementsList]


EcsContainerOverrideList = List[EcsContainerOverride]


class EcsTaskOverride(TypedDict, total=False):
    ContainerOverrides: Optional[EcsContainerOverrideList]
    Cpu: Optional[String]
    EphemeralStorage: Optional[EcsEphemeralStorage]
    ExecutionRoleArn: Optional[ArnOrJsonPath]
    InferenceAcceleratorOverrides: Optional[EcsInferenceAcceleratorOverrideList]
    Memory: Optional[String]
    TaskRoleArn: Optional[ArnOrJsonPath]


PlacementStrategy = TypedDict(
    "PlacementStrategy",
    {
        "type": Optional[PlacementStrategyType],
        "field": Optional[PlacementStrategyField],
    },
    total=False,
)
PlacementStrategies = List[PlacementStrategy]
PlacementConstraint = TypedDict(
    "PlacementConstraint",
    {
        "type": Optional[PlacementConstraintType],
        "expression": Optional[PlacementConstraintExpression],
    },
    total=False,
)
PlacementConstraints = List[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: Optional[AwsVpcConfiguration]


class PipeTargetEcsTaskParameters(TypedDict, total=False):
    TaskDefinitionArn: ArnOrJsonPath
    TaskCount: Optional[LimitMin1]
    LaunchType: Optional[LaunchType]
    NetworkConfiguration: Optional[NetworkConfiguration]
    PlatformVersion: Optional[String]
    Group: Optional[String]
    CapacityProviderStrategy: Optional[CapacityProviderStrategy]
    EnableECSManagedTags: Optional[Boolean]
    EnableExecuteCommand: Optional[Boolean]
    PlacementConstraints: Optional[PlacementConstraints]
    PlacementStrategy: Optional[PlacementStrategies]
    PropagateTags: Optional[PropagateTags]
    ReferenceId: Optional[ReferenceId]
    Overrides: Optional[EcsTaskOverride]
    Tags: Optional[TagList]


class PipeTargetKinesisStreamParameters(TypedDict, total=False):
    PartitionKey: KinesisPartitionKey


class PipeTargetStateMachineParameters(TypedDict, total=False):
    InvocationType: Optional[PipeTargetInvocationType]


class PipeTargetLambdaFunctionParameters(TypedDict, total=False):
    InvocationType: Optional[PipeTargetInvocationType]


class PipeTargetParameters(TypedDict, total=False):
    InputTemplate: Optional[InputTemplate]
    LambdaFunctionParameters: Optional[PipeTargetLambdaFunctionParameters]
    StepFunctionStateMachineParameters: Optional[PipeTargetStateMachineParameters]
    KinesisStreamParameters: Optional[PipeTargetKinesisStreamParameters]
    EcsTaskParameters: Optional[PipeTargetEcsTaskParameters]
    BatchJobParameters: Optional[PipeTargetBatchJobParameters]
    SqsQueueParameters: Optional[PipeTargetSqsQueueParameters]
    HttpParameters: Optional[PipeTargetHttpParameters]
    RedshiftDataParameters: Optional[PipeTargetRedshiftDataParameters]
    SageMakerPipelineParameters: Optional[PipeTargetSageMakerPipelineParameters]
    EventBridgeEventBusParameters: Optional[PipeTargetEventBridgeEventBusParameters]
    CloudWatchLogsParameters: Optional[PipeTargetCloudWatchLogsParameters]
    TimestreamParameters: Optional[PipeTargetTimestreamParameters]


class PipeEnrichmentHttpParameters(TypedDict, total=False):
    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


class PipeEnrichmentParameters(TypedDict, total=False):
    InputTemplate: Optional[InputTemplate]
    HttpParameters: Optional[PipeEnrichmentHttpParameters]


SecurityGroupIds = List[SecurityGroupId]
SubnetIds = List[SubnetId]


class SelfManagedKafkaAccessConfigurationVpc(TypedDict, total=False):
    Subnets: Optional[SubnetIds]
    SecurityGroup: Optional[SecurityGroupIds]


class SelfManagedKafkaAccessConfigurationCredentials(TypedDict, total=False):
    BasicAuth: Optional[SecretManagerArn]
    SaslScram512Auth: Optional[SecretManagerArn]
    SaslScram256Auth: Optional[SecretManagerArn]
    ClientCertificateTlsAuth: Optional[SecretManagerArn]


KafkaBootstrapServers = List[EndpointString]


class PipeSourceSelfManagedKafkaParameters(TypedDict, total=False):
    TopicName: KafkaTopicName
    StartingPosition: Optional[SelfManagedKafkaStartPosition]
    AdditionalBootstrapServers: Optional[KafkaBootstrapServers]
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ConsumerGroupID: Optional[URI]
    Credentials: Optional[SelfManagedKafkaAccessConfigurationCredentials]
    ServerRootCaCertificate: Optional[SecretManagerArn]
    Vpc: Optional[SelfManagedKafkaAccessConfigurationVpc]


class MSKAccessCredentials(TypedDict, total=False):
    SaslScram512Auth: Optional[SecretManagerArn]
    ClientCertificateTlsAuth: Optional[SecretManagerArn]


class PipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    TopicName: KafkaTopicName
    StartingPosition: Optional[MSKStartPosition]
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ConsumerGroupID: Optional[URI]
    Credentials: Optional[MSKAccessCredentials]


class MQBrokerAccessCredentials(TypedDict, total=False):
    BasicAuth: Optional[SecretManagerArn]


class PipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    VirtualHost: Optional[URI]
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class PipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class PipeSourceSqsQueueParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class DeadLetterConfig(TypedDict, total=False):
    Arn: Optional[Arn]


class PipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]
    StartingPosition: DynamoDBStreamStartPosition


Timestamp = datetime


class PipeSourceKinesisStreamParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]
    StartingPosition: KinesisStreamStartPosition
    StartingPositionTimestamp: Optional[Timestamp]


class Filter(TypedDict, total=False):
    Pattern: Optional[EventPattern]


FilterList = List[Filter]


class FilterCriteria(TypedDict, total=False):
    Filters: Optional[FilterList]


class PipeSourceParameters(TypedDict, total=False):
    FilterCriteria: Optional[FilterCriteria]
    KinesisStreamParameters: Optional[PipeSourceKinesisStreamParameters]
    DynamoDBStreamParameters: Optional[PipeSourceDynamoDBStreamParameters]
    SqsQueueParameters: Optional[PipeSourceSqsQueueParameters]
    ActiveMQBrokerParameters: Optional[PipeSourceActiveMQBrokerParameters]
    RabbitMQBrokerParameters: Optional[PipeSourceRabbitMQBrokerParameters]
    ManagedStreamingKafkaParameters: Optional[PipeSourceManagedStreamingKafkaParameters]
    SelfManagedKafkaParameters: Optional[PipeSourceSelfManagedKafkaParameters]


class CreatePipeRequest(ServiceRequest):
    Name: PipeName
    Description: Optional[PipeDescription]
    DesiredState: Optional[RequestedPipeState]
    Source: ArnOrUrl
    SourceParameters: Optional[PipeSourceParameters]
    Enrichment: Optional[OptionalArn]
    EnrichmentParameters: Optional[PipeEnrichmentParameters]
    Target: Arn
    TargetParameters: Optional[PipeTargetParameters]
    RoleArn: RoleArn
    Tags: Optional[TagMap]
    LogConfiguration: Optional[PipeLogConfigurationParameters]
    KmsKeyIdentifier: Optional[KmsKeyIdentifier]


class CreatePipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class DeletePipeRequest(ServiceRequest):
    Name: PipeName


class DeletePipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    DesiredState: Optional[RequestedPipeStateDescribeResponse]
    CurrentState: Optional[PipeState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class DescribePipeRequest(ServiceRequest):
    Name: PipeName


class FirehoseLogDestination(TypedDict, total=False):
    DeliveryStreamArn: Optional[FirehoseArn]


class S3LogDestination(TypedDict, total=False):
    BucketName: Optional[String]
    Prefix: Optional[String]
    BucketOwner: Optional[String]
    OutputFormat: Optional[S3OutputFormat]


class PipeLogConfiguration(TypedDict, total=False):
    S3LogDestination: Optional[S3LogDestination]
    FirehoseLogDestination: Optional[FirehoseLogDestination]
    CloudwatchLogsLogDestination: Optional[CloudwatchLogsLogDestination]
    Level: Optional[LogLevel]
    IncludeExecutionData: Optional[IncludeExecutionData]


class DescribePipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    Description: Optional[PipeDescription]
    DesiredState: Optional[RequestedPipeStateDescribeResponse]
    CurrentState: Optional[PipeState]
    StateReason: Optional[PipeStateReason]
    Source: Optional[ArnOrUrl]
    SourceParameters: Optional[PipeSourceParameters]
    Enrichment: Optional[OptionalArn]
    EnrichmentParameters: Optional[PipeEnrichmentParameters]
    Target: Optional[Arn]
    TargetParameters: Optional[PipeTargetParameters]
    RoleArn: Optional[RoleArn]
    Tags: Optional[TagMap]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LogConfiguration: Optional[PipeLogConfiguration]
    KmsKeyIdentifier: Optional[KmsKeyIdentifier]


class ListPipesRequest(ServiceRequest):
    NamePrefix: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    SourcePrefix: Optional[ResourceArn]
    TargetPrefix: Optional[ResourceArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class Pipe(TypedDict, total=False):
    Name: Optional[PipeName]
    Arn: Optional[PipeArn]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    StateReason: Optional[PipeStateReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    Source: Optional[ArnOrUrl]
    Target: Optional[Arn]
    Enrichment: Optional[OptionalArn]


PipeList = List[Pipe]


class ListPipesResponse(TypedDict, total=False):
    Pipes: Optional[PipeList]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: PipeArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagMap]


class StartPipeRequest(ServiceRequest):
    Name: PipeName


class StartPipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class StopPipeRequest(ServiceRequest):
    Name: PipeName


class StopPipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: PipeArn
    tags: TagMap


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: PipeArn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdatePipeSourceSelfManagedKafkaParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    Credentials: Optional[SelfManagedKafkaAccessConfigurationCredentials]
    ServerRootCaCertificate: Optional[SecretManagerArn]
    Vpc: Optional[SelfManagedKafkaAccessConfigurationVpc]


class UpdatePipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    Credentials: Optional[MSKAccessCredentials]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceSqsQueueParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]


class UpdatePipeSourceKinesisStreamParameters(TypedDict, total=False):
    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]


class UpdatePipeSourceParameters(TypedDict, total=False):
    FilterCriteria: Optional[FilterCriteria]
    KinesisStreamParameters: Optional[UpdatePipeSourceKinesisStreamParameters]
    DynamoDBStreamParameters: Optional[UpdatePipeSourceDynamoDBStreamParameters]
    SqsQueueParameters: Optional[UpdatePipeSourceSqsQueueParameters]
    ActiveMQBrokerParameters: Optional[UpdatePipeSourceActiveMQBrokerParameters]
    RabbitMQBrokerParameters: Optional[UpdatePipeSourceRabbitMQBrokerParameters]
    ManagedStreamingKafkaParameters: Optional[UpdatePipeSourceManagedStreamingKafkaParameters]
    SelfManagedKafkaParameters: Optional[UpdatePipeSourceSelfManagedKafkaParameters]


class UpdatePipeRequest(ServiceRequest):
    Name: PipeName
    Description: Optional[PipeDescription]
    DesiredState: Optional[RequestedPipeState]
    SourceParameters: Optional[UpdatePipeSourceParameters]
    Enrichment: Optional[OptionalArn]
    EnrichmentParameters: Optional[PipeEnrichmentParameters]
    Target: Optional[Arn]
    TargetParameters: Optional[PipeTargetParameters]
    RoleArn: RoleArn
    LogConfiguration: Optional[PipeLogConfigurationParameters]
    KmsKeyIdentifier: Optional[KmsKeyIdentifier]


class UpdatePipeResponse(TypedDict, total=False):
    Arn: Optional[PipeArn]
    Name: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class PipesApi:
    service = "pipes"
    version = "2015-10-07"

    @handler("CreatePipe")
    def create_pipe(
        self,
        context: RequestContext,
        name: PipeName,
        source: ArnOrUrl,
        target: Arn,
        role_arn: RoleArn,
        description: PipeDescription = None,
        desired_state: RequestedPipeState = None,
        source_parameters: PipeSourceParameters = None,
        enrichment: OptionalArn = None,
        enrichment_parameters: PipeEnrichmentParameters = None,
        target_parameters: PipeTargetParameters = None,
        tags: TagMap = None,
        log_configuration: PipeLogConfigurationParameters = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> CreatePipeResponse:
        raise NotImplementedError

    @handler("DeletePipe")
    def delete_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> DeletePipeResponse:
        raise NotImplementedError

    @handler("DescribePipe")
    def describe_pipe(
        self, context: RequestContext, name: PipeName, **kwargs
    ) -> DescribePipeResponse:
        raise NotImplementedError

    @handler("ListPipes")
    def list_pipes(
        self,
        context: RequestContext,
        name_prefix: PipeName = None,
        desired_state: RequestedPipeState = None,
        current_state: PipeState = None,
        source_prefix: ResourceArn = None,
        target_prefix: ResourceArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListPipesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: PipeArn, **kwargs
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("StartPipe")
    def start_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> StartPipeResponse:
        raise NotImplementedError

    @handler("StopPipe")
    def stop_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> StopPipeResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: PipeArn, tags: TagMap, **kwargs
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: PipeArn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdatePipe")
    def update_pipe(
        self,
        context: RequestContext,
        name: PipeName,
        role_arn: RoleArn,
        description: PipeDescription = None,
        desired_state: RequestedPipeState = None,
        source_parameters: UpdatePipeSourceParameters = None,
        enrichment: OptionalArn = None,
        enrichment_parameters: PipeEnrichmentParameters = None,
        target: Arn = None,
        target_parameters: PipeTargetParameters = None,
        log_configuration: PipeLogConfigurationParameters = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> UpdatePipeResponse:
        raise NotImplementedError
