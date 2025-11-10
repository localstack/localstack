from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
    retryAfterSeconds: Integer | None


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
    serviceCode: String | None
    quotaCode: String | None
    retryAfterSeconds: Integer | None


class ValidationExceptionField(TypedDict, total=False):
    name: String
    message: ErrorMessage


ValidationExceptionFieldList = list[ValidationExceptionField]


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400
    fieldList: ValidationExceptionFieldList | None


SecurityGroups = list[SecurityGroup]
Subnets = list[Subnet]


class AwsVpcConfiguration(TypedDict, total=False):
    Subnets: Subnets
    SecurityGroups: SecurityGroups | None
    AssignPublicIp: AssignPublicIp | None


class BatchArrayProperties(TypedDict, total=False):
    Size: BatchArraySize | None


class BatchResourceRequirement(TypedDict, total=False):
    Type: BatchResourceRequirementType
    Value: String


BatchResourceRequirementsList = list[BatchResourceRequirement]


class BatchEnvironmentVariable(TypedDict, total=False):
    Name: String | None
    Value: String | None


BatchEnvironmentVariableList = list[BatchEnvironmentVariable]
StringList = list[String]


class BatchContainerOverrides(TypedDict, total=False):
    Command: StringList | None
    Environment: BatchEnvironmentVariableList | None
    InstanceType: String | None
    ResourceRequirements: BatchResourceRequirementsList | None


class BatchJobDependency(TypedDict, total=False):
    JobId: String | None
    Type: BatchJobDependencyType | None


BatchDependsOn = list[BatchJobDependency]
BatchParametersMap = dict[String, String]


class BatchRetryStrategy(TypedDict, total=False):
    Attempts: BatchRetryAttempts | None


class CapacityProviderStrategyItem(TypedDict, total=False):
    capacityProvider: CapacityProvider
    weight: CapacityProviderStrategyItemWeight | None
    base: CapacityProviderStrategyItemBase | None


CapacityProviderStrategy = list[CapacityProviderStrategyItem]


class CloudwatchLogsLogDestination(TypedDict, total=False):
    LogGroupArn: CloudwatchLogGroupArn | None


class CloudwatchLogsLogDestinationParameters(TypedDict, total=False):
    LogGroupArn: CloudwatchLogGroupArn


IncludeExecutionData = list[IncludeExecutionDataOption]


class FirehoseLogDestinationParameters(TypedDict, total=False):
    DeliveryStreamArn: FirehoseArn


class S3LogDestinationParameters(TypedDict, total=False):
    BucketName: S3LogDestinationParametersBucketNameString
    BucketOwner: S3LogDestinationParametersBucketOwnerString
    OutputFormat: S3OutputFormat | None
    Prefix: S3LogDestinationParametersPrefixString | None


class PipeLogConfigurationParameters(TypedDict, total=False):
    S3LogDestination: S3LogDestinationParameters | None
    FirehoseLogDestination: FirehoseLogDestinationParameters | None
    CloudwatchLogsLogDestination: CloudwatchLogsLogDestinationParameters | None
    Level: LogLevel
    IncludeExecutionData: IncludeExecutionData | None


TagMap = dict[TagKey, TagValue]


class MultiMeasureAttributeMapping(TypedDict, total=False):
    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MultiMeasureAttributeName: MultiMeasureAttributeName


MultiMeasureAttributeMappings = list[MultiMeasureAttributeMapping]


class MultiMeasureMapping(TypedDict, total=False):
    MultiMeasureName: MultiMeasureName
    MultiMeasureAttributeMappings: MultiMeasureAttributeMappings


MultiMeasureMappings = list[MultiMeasureMapping]


class SingleMeasureMapping(TypedDict, total=False):
    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MeasureName: MeasureName


SingleMeasureMappings = list[SingleMeasureMapping]


class DimensionMapping(TypedDict, total=False):
    DimensionValue: DimensionValue
    DimensionValueType: DimensionValueType
    DimensionName: DimensionName


DimensionMappings = list[DimensionMapping]


class PipeTargetTimestreamParameters(TypedDict, total=False):
    TimeValue: TimeValue
    EpochTimeUnit: EpochTimeUnit | None
    TimeFieldType: TimeFieldType | None
    TimestampFormat: TimestampFormat | None
    VersionValue: VersionValue
    DimensionMappings: DimensionMappings
    SingleMeasureMappings: SingleMeasureMappings | None
    MultiMeasureMappings: MultiMeasureMappings | None


class PipeTargetCloudWatchLogsParameters(TypedDict, total=False):
    LogStreamName: LogStreamName | None
    Timestamp: JsonPath | None


EventBridgeEventResourceList = list[ArnOrJsonPath]


class PipeTargetEventBridgeEventBusParameters(TypedDict, total=False):
    EndpointId: EventBridgeEndpointId | None
    DetailType: EventBridgeDetailType | None
    Source: EventBridgeEventSource | None
    Resources: EventBridgeEventResourceList | None
    Time: JsonPath | None


class SageMakerPipelineParameter(TypedDict, total=False):
    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = list[SageMakerPipelineParameter]


class PipeTargetSageMakerPipelineParameters(TypedDict, total=False):
    PipelineParameterList: SageMakerPipelineParameterList | None


Sqls = list[Sql]


class PipeTargetRedshiftDataParameters(TypedDict, total=False):
    SecretManagerArn: SecretManagerArnOrJsonPath | None
    Database: Database
    DbUser: DbUser | None
    StatementName: StatementName | None
    WithEvent: Boolean | None
    Sqls: Sqls


QueryStringParametersMap = dict[QueryStringKey, QueryStringValue]
HeaderParametersMap = dict[HeaderKey, HeaderValue]
PathParameterList = list[PathParameter]


class PipeTargetHttpParameters(TypedDict, total=False):
    PathParameterValues: PathParameterList | None
    HeaderParameters: HeaderParametersMap | None
    QueryStringParameters: QueryStringParametersMap | None


class PipeTargetSqsQueueParameters(TypedDict, total=False):
    MessageGroupId: MessageGroupId | None
    MessageDeduplicationId: MessageDeduplicationId | None


class PipeTargetBatchJobParameters(TypedDict, total=False):
    JobDefinition: String
    JobName: String
    ArrayProperties: BatchArrayProperties | None
    RetryStrategy: BatchRetryStrategy | None
    ContainerOverrides: BatchContainerOverrides | None
    DependsOn: BatchDependsOn | None
    Parameters: BatchParametersMap | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class EcsInferenceAcceleratorOverride(TypedDict, total=False):
    deviceName: String | None
    deviceType: String | None


EcsInferenceAcceleratorOverrideList = list[EcsInferenceAcceleratorOverride]


class EcsEphemeralStorage(TypedDict, total=False):
    sizeInGiB: EphemeralStorageSize


class EcsResourceRequirement(TypedDict, total=False):
    type: EcsResourceRequirementType
    value: String


EcsResourceRequirementsList = list[EcsResourceRequirement]


class EcsEnvironmentFile(TypedDict, total=False):
    type: EcsEnvironmentFileType
    value: String


EcsEnvironmentFileList = list[EcsEnvironmentFile]


class EcsEnvironmentVariable(TypedDict, total=False):
    name: String | None
    value: String | None


EcsEnvironmentVariableList = list[EcsEnvironmentVariable]


class EcsContainerOverride(TypedDict, total=False):
    Command: StringList | None
    Cpu: Integer | None
    Environment: EcsEnvironmentVariableList | None
    EnvironmentFiles: EcsEnvironmentFileList | None
    Memory: Integer | None
    MemoryReservation: Integer | None
    Name: String | None
    ResourceRequirements: EcsResourceRequirementsList | None


EcsContainerOverrideList = list[EcsContainerOverride]


class EcsTaskOverride(TypedDict, total=False):
    ContainerOverrides: EcsContainerOverrideList | None
    Cpu: String | None
    EphemeralStorage: EcsEphemeralStorage | None
    ExecutionRoleArn: ArnOrJsonPath | None
    InferenceAcceleratorOverrides: EcsInferenceAcceleratorOverrideList | None
    Memory: String | None
    TaskRoleArn: ArnOrJsonPath | None


class PlacementStrategy(TypedDict, total=False):
    type: PlacementStrategyType | None
    field: PlacementStrategyField | None


PlacementStrategies = list[PlacementStrategy]


class PlacementConstraint(TypedDict, total=False):
    type: PlacementConstraintType | None
    expression: PlacementConstraintExpression | None


PlacementConstraints = list[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: AwsVpcConfiguration | None


class PipeTargetEcsTaskParameters(TypedDict, total=False):
    TaskDefinitionArn: ArnOrJsonPath
    TaskCount: LimitMin1 | None
    LaunchType: LaunchType | None
    NetworkConfiguration: NetworkConfiguration | None
    PlatformVersion: String | None
    Group: String | None
    CapacityProviderStrategy: CapacityProviderStrategy | None
    EnableECSManagedTags: Boolean | None
    EnableExecuteCommand: Boolean | None
    PlacementConstraints: PlacementConstraints | None
    PlacementStrategy: PlacementStrategies | None
    PropagateTags: PropagateTags | None
    ReferenceId: ReferenceId | None
    Overrides: EcsTaskOverride | None
    Tags: TagList | None


class PipeTargetKinesisStreamParameters(TypedDict, total=False):
    PartitionKey: KinesisPartitionKey


class PipeTargetStateMachineParameters(TypedDict, total=False):
    InvocationType: PipeTargetInvocationType | None


class PipeTargetLambdaFunctionParameters(TypedDict, total=False):
    InvocationType: PipeTargetInvocationType | None


class PipeTargetParameters(TypedDict, total=False):
    InputTemplate: InputTemplate | None
    LambdaFunctionParameters: PipeTargetLambdaFunctionParameters | None
    StepFunctionStateMachineParameters: PipeTargetStateMachineParameters | None
    KinesisStreamParameters: PipeTargetKinesisStreamParameters | None
    EcsTaskParameters: PipeTargetEcsTaskParameters | None
    BatchJobParameters: PipeTargetBatchJobParameters | None
    SqsQueueParameters: PipeTargetSqsQueueParameters | None
    HttpParameters: PipeTargetHttpParameters | None
    RedshiftDataParameters: PipeTargetRedshiftDataParameters | None
    SageMakerPipelineParameters: PipeTargetSageMakerPipelineParameters | None
    EventBridgeEventBusParameters: PipeTargetEventBridgeEventBusParameters | None
    CloudWatchLogsParameters: PipeTargetCloudWatchLogsParameters | None
    TimestreamParameters: PipeTargetTimestreamParameters | None


class PipeEnrichmentHttpParameters(TypedDict, total=False):
    PathParameterValues: PathParameterList | None
    HeaderParameters: HeaderParametersMap | None
    QueryStringParameters: QueryStringParametersMap | None


class PipeEnrichmentParameters(TypedDict, total=False):
    InputTemplate: InputTemplate | None
    HttpParameters: PipeEnrichmentHttpParameters | None


SecurityGroupIds = list[SecurityGroupId]
SubnetIds = list[SubnetId]


class SelfManagedKafkaAccessConfigurationVpc(TypedDict, total=False):
    Subnets: SubnetIds | None
    SecurityGroup: SecurityGroupIds | None


class SelfManagedKafkaAccessConfigurationCredentials(TypedDict, total=False):
    BasicAuth: SecretManagerArn | None
    SaslScram512Auth: SecretManagerArn | None
    SaslScram256Auth: SecretManagerArn | None
    ClientCertificateTlsAuth: SecretManagerArn | None


KafkaBootstrapServers = list[EndpointString]


class PipeSourceSelfManagedKafkaParameters(TypedDict, total=False):
    TopicName: KafkaTopicName
    StartingPosition: SelfManagedKafkaStartPosition | None
    AdditionalBootstrapServers: KafkaBootstrapServers | None
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    ConsumerGroupID: URI | None
    Credentials: SelfManagedKafkaAccessConfigurationCredentials | None
    ServerRootCaCertificate: SecretManagerArn | None
    Vpc: SelfManagedKafkaAccessConfigurationVpc | None


class MSKAccessCredentials(TypedDict, total=False):
    SaslScram512Auth: SecretManagerArn | None
    ClientCertificateTlsAuth: SecretManagerArn | None


class PipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    TopicName: KafkaTopicName
    StartingPosition: MSKStartPosition | None
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    ConsumerGroupID: URI | None
    Credentials: MSKAccessCredentials | None


class MQBrokerAccessCredentials(TypedDict, total=False):
    BasicAuth: SecretManagerArn | None


class PipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    VirtualHost: URI | None
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class PipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class PipeSourceSqsQueueParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class DeadLetterConfig(TypedDict, total=False):
    Arn: Arn | None


class PipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    DeadLetterConfig: DeadLetterConfig | None
    OnPartialBatchItemFailure: OnPartialBatchItemFailureStreams | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    MaximumRetryAttempts: MaximumRetryAttemptsESM | None
    ParallelizationFactor: LimitMax10 | None
    StartingPosition: DynamoDBStreamStartPosition


Timestamp = datetime


class PipeSourceKinesisStreamParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    DeadLetterConfig: DeadLetterConfig | None
    OnPartialBatchItemFailure: OnPartialBatchItemFailureStreams | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    MaximumRetryAttempts: MaximumRetryAttemptsESM | None
    ParallelizationFactor: LimitMax10 | None
    StartingPosition: KinesisStreamStartPosition
    StartingPositionTimestamp: Timestamp | None


class Filter(TypedDict, total=False):
    Pattern: EventPattern | None


FilterList = list[Filter]


class FilterCriteria(TypedDict, total=False):
    Filters: FilterList | None


class PipeSourceParameters(TypedDict, total=False):
    FilterCriteria: FilterCriteria | None
    KinesisStreamParameters: PipeSourceKinesisStreamParameters | None
    DynamoDBStreamParameters: PipeSourceDynamoDBStreamParameters | None
    SqsQueueParameters: PipeSourceSqsQueueParameters | None
    ActiveMQBrokerParameters: PipeSourceActiveMQBrokerParameters | None
    RabbitMQBrokerParameters: PipeSourceRabbitMQBrokerParameters | None
    ManagedStreamingKafkaParameters: PipeSourceManagedStreamingKafkaParameters | None
    SelfManagedKafkaParameters: PipeSourceSelfManagedKafkaParameters | None


class CreatePipeRequest(ServiceRequest):
    Name: PipeName
    Description: PipeDescription | None
    DesiredState: RequestedPipeState | None
    Source: ArnOrUrl
    SourceParameters: PipeSourceParameters | None
    Enrichment: OptionalArn | None
    EnrichmentParameters: PipeEnrichmentParameters | None
    Target: Arn
    TargetParameters: PipeTargetParameters | None
    RoleArn: RoleArn
    Tags: TagMap | None
    LogConfiguration: PipeLogConfigurationParameters | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class CreatePipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class DeletePipeRequest(ServiceRequest):
    Name: PipeName


class DeletePipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    DesiredState: RequestedPipeStateDescribeResponse | None
    CurrentState: PipeState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class DescribePipeRequest(ServiceRequest):
    Name: PipeName


class FirehoseLogDestination(TypedDict, total=False):
    DeliveryStreamArn: FirehoseArn | None


class S3LogDestination(TypedDict, total=False):
    BucketName: String | None
    Prefix: String | None
    BucketOwner: String | None
    OutputFormat: S3OutputFormat | None


class PipeLogConfiguration(TypedDict, total=False):
    S3LogDestination: S3LogDestination | None
    FirehoseLogDestination: FirehoseLogDestination | None
    CloudwatchLogsLogDestination: CloudwatchLogsLogDestination | None
    Level: LogLevel | None
    IncludeExecutionData: IncludeExecutionData | None


class DescribePipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    Description: PipeDescription | None
    DesiredState: RequestedPipeStateDescribeResponse | None
    CurrentState: PipeState | None
    StateReason: PipeStateReason | None
    Source: ArnOrUrl | None
    SourceParameters: PipeSourceParameters | None
    Enrichment: OptionalArn | None
    EnrichmentParameters: PipeEnrichmentParameters | None
    Target: Arn | None
    TargetParameters: PipeTargetParameters | None
    RoleArn: RoleArn | None
    Tags: TagMap | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LogConfiguration: PipeLogConfiguration | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class ListPipesRequest(ServiceRequest):
    NamePrefix: PipeName | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    SourcePrefix: ResourceArn | None
    TargetPrefix: ResourceArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class Pipe(TypedDict, total=False):
    Name: PipeName | None
    Arn: PipeArn | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    StateReason: PipeStateReason | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    Source: ArnOrUrl | None
    Target: Arn | None
    Enrichment: OptionalArn | None


PipeList = list[Pipe]


class ListPipesResponse(TypedDict, total=False):
    Pipes: PipeList | None
    NextToken: NextToken | None


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: PipeArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: TagMap | None


class StartPipeRequest(ServiceRequest):
    Name: PipeName


class StartPipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class StopPipeRequest(ServiceRequest):
    Name: PipeName


class StopPipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


TagKeyList = list[TagKey]


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
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    Credentials: SelfManagedKafkaAccessConfigurationCredentials | None
    ServerRootCaCertificate: SecretManagerArn | None
    Vpc: SelfManagedKafkaAccessConfigurationVpc | None


class UpdatePipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    Credentials: MSKAccessCredentials | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class UpdatePipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class UpdatePipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    Credentials: MQBrokerAccessCredentials
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class UpdatePipeSourceSqsQueueParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None


class UpdatePipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    DeadLetterConfig: DeadLetterConfig | None
    OnPartialBatchItemFailure: OnPartialBatchItemFailureStreams | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    MaximumRetryAttempts: MaximumRetryAttemptsESM | None
    ParallelizationFactor: LimitMax10 | None


class UpdatePipeSourceKinesisStreamParameters(TypedDict, total=False):
    BatchSize: LimitMax10000 | None
    DeadLetterConfig: DeadLetterConfig | None
    OnPartialBatchItemFailure: OnPartialBatchItemFailureStreams | None
    MaximumBatchingWindowInSeconds: MaximumBatchingWindowInSeconds | None
    MaximumRecordAgeInSeconds: MaximumRecordAgeInSeconds | None
    MaximumRetryAttempts: MaximumRetryAttemptsESM | None
    ParallelizationFactor: LimitMax10 | None


class UpdatePipeSourceParameters(TypedDict, total=False):
    FilterCriteria: FilterCriteria | None
    KinesisStreamParameters: UpdatePipeSourceKinesisStreamParameters | None
    DynamoDBStreamParameters: UpdatePipeSourceDynamoDBStreamParameters | None
    SqsQueueParameters: UpdatePipeSourceSqsQueueParameters | None
    ActiveMQBrokerParameters: UpdatePipeSourceActiveMQBrokerParameters | None
    RabbitMQBrokerParameters: UpdatePipeSourceRabbitMQBrokerParameters | None
    ManagedStreamingKafkaParameters: UpdatePipeSourceManagedStreamingKafkaParameters | None
    SelfManagedKafkaParameters: UpdatePipeSourceSelfManagedKafkaParameters | None


class UpdatePipeRequest(ServiceRequest):
    Name: PipeName
    Description: PipeDescription | None
    DesiredState: RequestedPipeState | None
    SourceParameters: UpdatePipeSourceParameters | None
    Enrichment: OptionalArn | None
    EnrichmentParameters: PipeEnrichmentParameters | None
    Target: Arn | None
    TargetParameters: PipeTargetParameters | None
    RoleArn: RoleArn
    LogConfiguration: PipeLogConfigurationParameters | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class UpdatePipeResponse(TypedDict, total=False):
    Arn: PipeArn | None
    Name: PipeName | None
    DesiredState: RequestedPipeState | None
    CurrentState: PipeState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class PipesApi:
    service: str = "pipes"
    version: str = "2015-10-07"

    @handler("CreatePipe")
    def create_pipe(
        self,
        context: RequestContext,
        name: PipeName,
        source: ArnOrUrl,
        target: Arn,
        role_arn: RoleArn,
        description: PipeDescription | None = None,
        desired_state: RequestedPipeState | None = None,
        source_parameters: PipeSourceParameters | None = None,
        enrichment: OptionalArn | None = None,
        enrichment_parameters: PipeEnrichmentParameters | None = None,
        target_parameters: PipeTargetParameters | None = None,
        tags: TagMap | None = None,
        log_configuration: PipeLogConfigurationParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
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
        name_prefix: PipeName | None = None,
        desired_state: RequestedPipeState | None = None,
        current_state: PipeState | None = None,
        source_prefix: ResourceArn | None = None,
        target_prefix: ResourceArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
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
        description: PipeDescription | None = None,
        desired_state: RequestedPipeState | None = None,
        source_parameters: UpdatePipeSourceParameters | None = None,
        enrichment: OptionalArn | None = None,
        enrichment_parameters: PipeEnrichmentParameters | None = None,
        target: Arn | None = None,
        target_parameters: PipeTargetParameters | None = None,
        log_configuration: PipeLogConfigurationParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> UpdatePipeResponse:
        raise NotImplementedError
