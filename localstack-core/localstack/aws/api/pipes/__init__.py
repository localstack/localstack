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
    """An action you attempted resulted in an exception."""

    code: str = "ConflictException"
    sender_fault: bool = True
    status_code: int = 409
    resourceId: String
    resourceType: String


class InternalException(ServiceException):
    """This exception occurs due to unexpected causes."""

    code: str = "InternalException"
    sender_fault: bool = False
    status_code: int = 500
    retryAfterSeconds: Optional[Integer]


class NotFoundException(ServiceException):
    """An entity that you specified does not exist."""

    code: str = "NotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class ServiceQuotaExceededException(ServiceException):
    """A quota has been exceeded."""

    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = True
    status_code: int = 402
    resourceId: String
    resourceType: String
    serviceCode: String
    quotaCode: String


class ThrottlingException(ServiceException):
    """An action was throttled."""

    code: str = "ThrottlingException"
    sender_fault: bool = True
    status_code: int = 429
    serviceCode: Optional[String]
    quotaCode: Optional[String]
    retryAfterSeconds: Optional[Integer]


class ValidationExceptionField(TypedDict, total=False):
    """Indicates that an error has occurred while performing a validate
    operation.
    """

    name: String
    message: ErrorMessage


ValidationExceptionFieldList = List[ValidationExceptionField]


class ValidationException(ServiceException):
    """Indicates that an error has occurred while performing a validate
    operation.
    """

    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400
    fieldList: Optional[ValidationExceptionFieldList]


SecurityGroups = List[SecurityGroup]
Subnets = List[Subnet]


class AwsVpcConfiguration(TypedDict, total=False):
    """This structure specifies the VPC subnets and security groups for the
    task, and whether a public IP address is to be used. This structure is
    relevant only for ECS tasks that use the ``awsvpc`` network mode.
    """

    Subnets: Subnets
    SecurityGroups: Optional[SecurityGroups]
    AssignPublicIp: Optional[AssignPublicIp]


class BatchArrayProperties(TypedDict, total=False):
    """The array properties for the submitted job, such as the size of the
    array. The array size can be between 2 and 10,000. If you specify array
    properties for a job, it becomes an array job. This parameter is used
    only if the target is an Batch job.
    """

    Size: Optional[BatchArraySize]


class BatchResourceRequirement(TypedDict, total=False):
    """The type and amount of a resource to assign to a container. The
    supported resources include ``GPU``, ``MEMORY``, and ``VCPU``.
    """

    Type: BatchResourceRequirementType
    Value: String


BatchResourceRequirementsList = List[BatchResourceRequirement]


class BatchEnvironmentVariable(TypedDict, total=False):
    """The environment variables to send to the container. You can add new
    environment variables, which are added to the container at launch, or
    you can override the existing environment variables from the Docker
    image or the task definition.

    Environment variables cannot start with "``Batch``". This naming
    convention is reserved for variables that Batch sets.
    """

    Name: Optional[String]
    Value: Optional[String]


BatchEnvironmentVariableList = List[BatchEnvironmentVariable]
StringList = List[String]


class BatchContainerOverrides(TypedDict, total=False):
    """The overrides that are sent to a container."""

    Command: Optional[StringList]
    Environment: Optional[BatchEnvironmentVariableList]
    InstanceType: Optional[String]
    ResourceRequirements: Optional[BatchResourceRequirementsList]


class BatchJobDependency(TypedDict, total=False):
    """An object that represents an Batch job dependency."""

    JobId: Optional[String]
    Type: Optional[BatchJobDependencyType]


BatchDependsOn = List[BatchJobDependency]
BatchParametersMap = Dict[String, String]


class BatchRetryStrategy(TypedDict, total=False):
    """The retry strategy that's associated with a job. For more information,
    see `Automated job
    retries <https://docs.aws.amazon.com/batch/latest/userguide/job_retries.html>`__
    in the *Batch User Guide*.
    """

    Attempts: Optional[BatchRetryAttempts]


class CapacityProviderStrategyItem(TypedDict, total=False):
    """The details of a capacity provider strategy. To learn more, see
    `CapacityProviderStrategyItem <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CapacityProviderStrategyItem.html>`__
    in the Amazon ECS API Reference.
    """

    capacityProvider: CapacityProvider
    weight: Optional[CapacityProviderStrategyItemWeight]
    base: Optional[CapacityProviderStrategyItemBase]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]


class CloudwatchLogsLogDestination(TypedDict, total=False):
    """The Amazon CloudWatch Logs logging configuration settings for the pipe."""

    LogGroupArn: Optional[CloudwatchLogGroupArn]


class CloudwatchLogsLogDestinationParameters(TypedDict, total=False):
    """The Amazon CloudWatch Logs logging configuration settings for the pipe."""

    LogGroupArn: CloudwatchLogGroupArn


IncludeExecutionData = List[IncludeExecutionDataOption]


class FirehoseLogDestinationParameters(TypedDict, total=False):
    """The Amazon Data Firehose logging configuration settings for the pipe."""

    DeliveryStreamArn: FirehoseArn


class S3LogDestinationParameters(TypedDict, total=False):
    """The Amazon S3 logging configuration settings for the pipe."""

    BucketName: S3LogDestinationParametersBucketNameString
    BucketOwner: S3LogDestinationParametersBucketOwnerString
    OutputFormat: Optional[S3OutputFormat]
    Prefix: Optional[S3LogDestinationParametersPrefixString]


class PipeLogConfigurationParameters(TypedDict, total=False):
    """Specifies the logging configuration settings for the pipe.

    When you call ``UpdatePipe``, EventBridge updates the fields in the
    ``PipeLogConfigurationParameters`` object atomically as one and
    overrides existing values. This is by design. If you don't specify an
    optional field in any of the Amazon Web Services service parameters
    objects (``CloudwatchLogsLogDestinationParameters``,
    ``FirehoseLogDestinationParameters``, or
    ``S3LogDestinationParameters``), EventBridge sets that field to its
    system-default value during the update.

    For example, suppose when you created the pipe you specified a Firehose
    stream log destination. You then update the pipe to add an Amazon S3 log
    destination. In addition to specifying the
    ``S3LogDestinationParameters`` for the new log destination, you must
    also specify the fields in the ``FirehoseLogDestinationParameters``
    object in order to retain the Firehose stream log destination.

    For more information on generating pipe log records, see `Log
    EventBridge Pipes <eventbridge/latest/userguide/eb-pipes-logs.html>`__
    in the *Amazon EventBridge User Guide*.
    """

    S3LogDestination: Optional[S3LogDestinationParameters]
    FirehoseLogDestination: Optional[FirehoseLogDestinationParameters]
    CloudwatchLogsLogDestination: Optional[CloudwatchLogsLogDestinationParameters]
    Level: LogLevel
    IncludeExecutionData: Optional[IncludeExecutionData]


TagMap = Dict[TagKey, TagValue]


class MultiMeasureAttributeMapping(TypedDict, total=False):
    """A mapping of a source event data field to a measure in a Timestream for
    LiveAnalytics record.
    """

    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MultiMeasureAttributeName: MultiMeasureAttributeName


MultiMeasureAttributeMappings = List[MultiMeasureAttributeMapping]


class MultiMeasureMapping(TypedDict, total=False):
    """Maps multiple measures from the source event to the same Timestream for
    LiveAnalytics record.

    For more information, see `Amazon Timestream for LiveAnalytics
    concepts <https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html>`__
    """

    MultiMeasureName: MultiMeasureName
    MultiMeasureAttributeMappings: MultiMeasureAttributeMappings


MultiMeasureMappings = List[MultiMeasureMapping]


class SingleMeasureMapping(TypedDict, total=False):
    """Maps a single source data field to a single record in the specified
    Timestream for LiveAnalytics table.

    For more information, see `Amazon Timestream for LiveAnalytics
    concepts <https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html>`__
    """

    MeasureValue: MeasureValue
    MeasureValueType: MeasureValueType
    MeasureName: MeasureName


SingleMeasureMappings = List[SingleMeasureMapping]


class DimensionMapping(TypedDict, total=False):
    """Maps source data to a dimension in the target Timestream for
    LiveAnalytics table.

    For more information, see `Amazon Timestream for LiveAnalytics
    concepts <https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html>`__
    """

    DimensionValue: DimensionValue
    DimensionValueType: DimensionValueType
    DimensionName: DimensionName


DimensionMappings = List[DimensionMapping]


class PipeTargetTimestreamParameters(TypedDict, total=False):
    """The parameters for using a Timestream for LiveAnalytics table as a
    target.
    """

    TimeValue: TimeValue
    EpochTimeUnit: Optional[EpochTimeUnit]
    TimeFieldType: Optional[TimeFieldType]
    TimestampFormat: Optional[TimestampFormat]
    VersionValue: VersionValue
    DimensionMappings: DimensionMappings
    SingleMeasureMappings: Optional[SingleMeasureMappings]
    MultiMeasureMappings: Optional[MultiMeasureMappings]


class PipeTargetCloudWatchLogsParameters(TypedDict, total=False):
    """The parameters for using an CloudWatch Logs log stream as a target."""

    LogStreamName: Optional[LogStreamName]
    Timestamp: Optional[JsonPath]


EventBridgeEventResourceList = List[ArnOrJsonPath]


class PipeTargetEventBridgeEventBusParameters(TypedDict, total=False):
    """The parameters for using an EventBridge event bus as a target."""

    EndpointId: Optional[EventBridgeEndpointId]
    DetailType: Optional[EventBridgeDetailType]
    Source: Optional[EventBridgeEventSource]
    Resources: Optional[EventBridgeEventResourceList]
    Time: Optional[JsonPath]


class SageMakerPipelineParameter(TypedDict, total=False):
    """Name/Value pair of a parameter to start execution of a SageMaker Model
    Building Pipeline.
    """

    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = List[SageMakerPipelineParameter]


class PipeTargetSageMakerPipelineParameters(TypedDict, total=False):
    """The parameters for using a SageMaker pipeline as a target."""

    PipelineParameterList: Optional[SageMakerPipelineParameterList]


Sqls = List[Sql]


class PipeTargetRedshiftDataParameters(TypedDict, total=False):
    """These are custom parameters to be used when the target is a Amazon
    Redshift cluster to invoke the Amazon Redshift Data API
    BatchExecuteStatement.
    """

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
    """These are custom parameter to be used when the target is an API Gateway
    REST APIs or EventBridge ApiDestinations.
    """

    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


class PipeTargetSqsQueueParameters(TypedDict, total=False):
    """The parameters for using a Amazon SQS stream as a target."""

    MessageGroupId: Optional[MessageGroupId]
    MessageDeduplicationId: Optional[MessageDeduplicationId]


class PipeTargetBatchJobParameters(TypedDict, total=False):
    """The parameters for using an Batch job as a target."""

    JobDefinition: String
    JobName: String
    ArrayProperties: Optional[BatchArrayProperties]
    RetryStrategy: Optional[BatchRetryStrategy]
    ContainerOverrides: Optional[BatchContainerOverrides]
    DependsOn: Optional[BatchDependsOn]
    Parameters: Optional[BatchParametersMap]


class Tag(TypedDict, total=False):
    """A key-value pair associated with an Amazon Web Services resource. In
    EventBridge, rules and event buses support tagging.
    """

    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class EcsInferenceAcceleratorOverride(TypedDict, total=False):
    """Details on an Elastic Inference accelerator task override. This
    parameter is used to override the Elastic Inference accelerator
    specified in the task definition. For more information, see `Working
    with Amazon Elastic Inference on Amazon
    ECS <https://docs.aws.amazon.com/AmazonECS/latest/userguide/ecs-inference.html>`__
    in the *Amazon Elastic Container Service Developer Guide*.
    """

    deviceName: Optional[String]
    deviceType: Optional[String]


EcsInferenceAcceleratorOverrideList = List[EcsInferenceAcceleratorOverride]


class EcsEphemeralStorage(TypedDict, total=False):
    """The amount of ephemeral storage to allocate for the task. This parameter
    is used to expand the total amount of ephemeral storage available,
    beyond the default amount, for tasks hosted on Fargate. For more
    information, see `Fargate task
    storage <https://docs.aws.amazon.com/AmazonECS/latest/userguide/using_data_volumes.html>`__
    in the *Amazon ECS User Guide for Fargate*.

    This parameter is only supported for tasks hosted on Fargate using Linux
    platform version ``1.4.0`` or later. This parameter is not supported for
    Windows containers on Fargate.
    """

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
    """The environment variables to send to the container. You can add new
    environment variables, which are added to the container at launch, or
    you can override the existing environment variables from the Docker
    image or the task definition. You must also specify a container name.
    """

    name: Optional[String]
    value: Optional[String]


EcsEnvironmentVariableList = List[EcsEnvironmentVariable]


class EcsContainerOverride(TypedDict, total=False):
    """The overrides that are sent to a container. An empty container override
    can be passed in. An example of an empty container override is
    ``{"containerOverrides": [ ] }``. If a non-empty container override is
    specified, the ``name`` parameter must be included.
    """

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
    """The overrides that are associated with a task."""

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
    """This structure specifies the network configuration for an Amazon ECS
    task.
    """

    awsvpcConfiguration: Optional[AwsVpcConfiguration]


class PipeTargetEcsTaskParameters(TypedDict, total=False):
    """The parameters for using an Amazon ECS task as a target."""

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
    """The parameters for using a Kinesis stream as a target."""

    PartitionKey: KinesisPartitionKey


class PipeTargetStateMachineParameters(TypedDict, total=False):
    """The parameters for using a Step Functions state machine as a target."""

    InvocationType: Optional[PipeTargetInvocationType]


class PipeTargetLambdaFunctionParameters(TypedDict, total=False):
    """The parameters for using a Lambda function as a target."""

    InvocationType: Optional[PipeTargetInvocationType]


class PipeTargetParameters(TypedDict, total=False):
    """The parameters required to set up a target for your pipe.

    For more information about pipe target parameters, including how to use
    dynamic path parameters, see `Target
    parameters <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-target.html>`__
    in the *Amazon EventBridge User Guide*.
    """

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
    """These are custom parameter to be used when the target is an API Gateway
    REST APIs or EventBridge ApiDestinations. In the latter case, these are
    merged with any InvocationParameters specified on the Connection, with
    any values from the Connection taking precedence.
    """

    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


class PipeEnrichmentParameters(TypedDict, total=False):
    """The parameters required to set up enrichment on your pipe."""

    InputTemplate: Optional[InputTemplate]
    HttpParameters: Optional[PipeEnrichmentHttpParameters]


SecurityGroupIds = List[SecurityGroupId]
SubnetIds = List[SubnetId]


class SelfManagedKafkaAccessConfigurationVpc(TypedDict, total=False):
    """This structure specifies the VPC subnets and security groups for the
    stream, and whether a public IP address is to be used.
    """

    Subnets: Optional[SubnetIds]
    SecurityGroup: Optional[SecurityGroupIds]


class SelfManagedKafkaAccessConfigurationCredentials(TypedDict, total=False):
    """The Secrets Manager secret that stores your stream credentials."""

    BasicAuth: Optional[SecretManagerArn]
    SaslScram512Auth: Optional[SecretManagerArn]
    SaslScram256Auth: Optional[SecretManagerArn]
    ClientCertificateTlsAuth: Optional[SecretManagerArn]


KafkaBootstrapServers = List[EndpointString]


class PipeSourceSelfManagedKafkaParameters(TypedDict, total=False):
    """The parameters for using a self-managed Apache Kafka stream as a source.

    A *self managed* cluster refers to any Apache Kafka cluster not hosted
    by Amazon Web Services. This includes both clusters you manage yourself,
    as well as those hosted by a third-party provider, such as `Confluent
    Cloud <https://www.confluent.io/>`__,
    `CloudKarafka <https://www.cloudkarafka.com/>`__, or
    `Redpanda <https://redpanda.com/>`__. For more information, see `Apache
    Kafka streams as a
    source <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kafka.html>`__
    in the *Amazon EventBridge User Guide*.
    """

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
    """The Secrets Manager secret that stores your stream credentials."""

    SaslScram512Auth: Optional[SecretManagerArn]
    ClientCertificateTlsAuth: Optional[SecretManagerArn]


class PipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    """The parameters for using an MSK stream as a source."""

    TopicName: KafkaTopicName
    StartingPosition: Optional[MSKStartPosition]
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    ConsumerGroupID: Optional[URI]
    Credentials: Optional[MSKAccessCredentials]


class MQBrokerAccessCredentials(TypedDict, total=False):
    """The Secrets Manager secret that stores your broker credentials."""

    BasicAuth: Optional[SecretManagerArn]


class PipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    """The parameters for using a Rabbit MQ broker as a source."""

    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    VirtualHost: Optional[URI]
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class PipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    """The parameters for using an Active MQ broker as a source."""

    Credentials: MQBrokerAccessCredentials
    QueueName: MQBrokerQueueName
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class PipeSourceSqsQueueParameters(TypedDict, total=False):
    """The parameters for using a Amazon SQS stream as a source."""

    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class DeadLetterConfig(TypedDict, total=False):
    """A ``DeadLetterConfig`` object that contains information about a
    dead-letter queue configuration.
    """

    Arn: Optional[Arn]


class PipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    """The parameters for using a DynamoDB stream as a source."""

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
    """The parameters for using a Kinesis stream as a source."""

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
    """Filter events using an event pattern. For more information, see `Events
    and Event
    Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`__
    in the *Amazon EventBridge User Guide*.
    """

    Pattern: Optional[EventPattern]


FilterList = List[Filter]


class FilterCriteria(TypedDict, total=False):
    """The collection of event patterns used to filter events.

    To remove a filter, specify a ``FilterCriteria`` object with an empty
    array of ``Filter`` objects.

    For more information, see `Events and Event
    Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`__
    in the *Amazon EventBridge User Guide*.
    """

    Filters: Optional[FilterList]


class PipeSourceParameters(TypedDict, total=False):
    """The parameters required to set up a source for your pipe."""

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
    """The Amazon Data Firehose logging configuration settings for the pipe."""

    DeliveryStreamArn: Optional[FirehoseArn]


class S3LogDestination(TypedDict, total=False):
    """The Amazon S3 logging configuration settings for the pipe."""

    BucketName: Optional[String]
    Prefix: Optional[String]
    BucketOwner: Optional[String]
    OutputFormat: Optional[S3OutputFormat]


class PipeLogConfiguration(TypedDict, total=False):
    """The logging configuration settings for the pipe."""

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


class ListPipesRequest(ServiceRequest):
    NamePrefix: Optional[PipeName]
    DesiredState: Optional[RequestedPipeState]
    CurrentState: Optional[PipeState]
    SourcePrefix: Optional[ResourceArn]
    TargetPrefix: Optional[ResourceArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class Pipe(TypedDict, total=False):
    """An object that represents a pipe. Amazon EventBridgePipes connect event
    sources to targets and reduces the need for specialized knowledge and
    integration code.
    """

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
    """The parameters for using a self-managed Apache Kafka stream as a source.

    A *self managed* cluster refers to any Apache Kafka cluster not hosted
    by Amazon Web Services. This includes both clusters you manage yourself,
    as well as those hosted by a third-party provider, such as `Confluent
    Cloud <https://www.confluent.io/>`__,
    `CloudKarafka <https://www.cloudkarafka.com/>`__, or
    `Redpanda <https://redpanda.com/>`__. For more information, see `Apache
    Kafka streams as a
    source <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kafka.html>`__
    in the *Amazon EventBridge User Guide*.
    """

    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    Credentials: Optional[SelfManagedKafkaAccessConfigurationCredentials]
    ServerRootCaCertificate: Optional[SecretManagerArn]
    Vpc: Optional[SelfManagedKafkaAccessConfigurationVpc]


class UpdatePipeSourceManagedStreamingKafkaParameters(TypedDict, total=False):
    """The parameters for using an MSK stream as a source."""

    BatchSize: Optional[LimitMax10000]
    Credentials: Optional[MSKAccessCredentials]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceRabbitMQBrokerParameters(TypedDict, total=False):
    """The parameters for using a Rabbit MQ broker as a source."""

    Credentials: MQBrokerAccessCredentials
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceActiveMQBrokerParameters(TypedDict, total=False):
    """The parameters for using an Active MQ broker as a source."""

    Credentials: MQBrokerAccessCredentials
    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceSqsQueueParameters(TypedDict, total=False):
    """The parameters for using a Amazon SQS stream as a source."""

    BatchSize: Optional[LimitMax10000]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]


class UpdatePipeSourceDynamoDBStreamParameters(TypedDict, total=False):
    """The parameters for using a DynamoDB stream as a source."""

    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]


class UpdatePipeSourceKinesisStreamParameters(TypedDict, total=False):
    """The parameters for using a Kinesis stream as a source."""

    BatchSize: Optional[LimitMax10000]
    DeadLetterConfig: Optional[DeadLetterConfig]
    OnPartialBatchItemFailure: Optional[OnPartialBatchItemFailureStreams]
    MaximumBatchingWindowInSeconds: Optional[MaximumBatchingWindowInSeconds]
    MaximumRecordAgeInSeconds: Optional[MaximumRecordAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttemptsESM]
    ParallelizationFactor: Optional[LimitMax10]


class UpdatePipeSourceParameters(TypedDict, total=False):
    """The parameters required to set up a source for your pipe."""

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
        **kwargs,
    ) -> CreatePipeResponse:
        """Create a pipe. Amazon EventBridge Pipes connect event sources to targets
        and reduces the need for specialized knowledge and integration code.

        :param name: The name of the pipe.
        :param source: The ARN of the source resource.
        :param target: The ARN of the target resource.
        :param role_arn: The ARN of the role that allows the pipe to send data to the target.
        :param description: A description of the pipe.
        :param desired_state: The state the pipe should be in.
        :param source_parameters: The parameters required to set up a source for your pipe.
        :param enrichment: The ARN of the enrichment resource.
        :param enrichment_parameters: The parameters required to set up enrichment on your pipe.
        :param target_parameters: The parameters required to set up a target for your pipe.
        :param tags: The list of key-value pairs to associate with the pipe.
        :param log_configuration: The logging configuration settings for the pipe.
        :returns: CreatePipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        :raises ConflictException:
        :raises ServiceQuotaExceededException:
        """
        raise NotImplementedError

    @handler("DeletePipe")
    def delete_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> DeletePipeResponse:
        """Delete an existing pipe. For more information about pipes, see `Amazon
        EventBridge
        Pipes <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html>`__
        in the Amazon EventBridge User Guide.

        :param name: The name of the pipe.
        :returns: DeletePipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("DescribePipe")
    def describe_pipe(
        self, context: RequestContext, name: PipeName, **kwargs
    ) -> DescribePipeResponse:
        """Get the information about an existing pipe. For more information about
        pipes, see `Amazon EventBridge
        Pipes <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html>`__
        in the Amazon EventBridge User Guide.

        :param name: The name of the pipe.
        :returns: DescribePipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        """
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
        """Get the pipes associated with this account. For more information about
        pipes, see `Amazon EventBridge
        Pipes <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html>`__
        in the Amazon EventBridge User Guide.

        :param name_prefix: A value that will return a subset of the pipes associated with this
        account.
        :param desired_state: The state the pipe should be in.
        :param current_state: The state the pipe is in.
        :param source_prefix: The prefix matching the pipe source.
        :param target_prefix: The prefix matching the pipe target.
        :param next_token: If ``nextToken`` is returned, there are more results available.
        :param limit: The maximum number of pipes to include in the response.
        :returns: ListPipesResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: PipeArn, **kwargs
    ) -> ListTagsForResourceResponse:
        """Displays the tags associated with a pipe.

        :param resource_arn: The ARN of the pipe for which you want to view tags.
        :returns: ListTagsForResourceResponse
        :raises InternalException:
        :raises ValidationException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("StartPipe")
    def start_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> StartPipeResponse:
        """Start an existing pipe.

        :param name: The name of the pipe.
        :returns: StartPipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("StopPipe")
    def stop_pipe(self, context: RequestContext, name: PipeName, **kwargs) -> StopPipeResponse:
        """Stop an existing pipe.

        :param name: The name of the pipe.
        :returns: StopPipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: PipeArn, tags: TagMap, **kwargs
    ) -> TagResourceResponse:
        """Assigns one or more tags (key-value pairs) to the specified pipe. Tags
        can help you organize and categorize your resources. You can also use
        them to scope user permissions by granting a user permission to access
        or change only resources with certain tag values.

        Tags don't have any semantic meaning to Amazon Web Services and are
        interpreted strictly as strings of characters.

        You can use the ``TagResource`` action with a pipe that already has
        tags. If you specify a new tag key, this tag is appended to the list of
        tags associated with the pipe. If you specify a tag key that is already
        associated with the pipe, the new tag value that you specify replaces
        the previous value for that tag.

        You can associate as many as 50 tags with a pipe.

        :param resource_arn: The ARN of the pipe.
        :param tags: The list of key-value pairs associated with the pipe.
        :returns: TagResourceResponse
        :raises InternalException:
        :raises ValidationException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: PipeArn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        """Removes one or more tags from the specified pipes.

        :param resource_arn: The ARN of the pipe.
        :param tag_keys: The list of tag keys to remove from the pipe.
        :returns: UntagResourceResponse
        :raises InternalException:
        :raises ValidationException:
        :raises NotFoundException:
        """
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
        **kwargs,
    ) -> UpdatePipeResponse:
        """Update an existing pipe. When you call ``UpdatePipe``, EventBridge only
        the updates fields you have specified in the request; the rest remain
        unchanged. The exception to this is if you modify any Amazon Web
        Services-service specific fields in the ``SourceParameters``,
        ``EnrichmentParameters``, or ``TargetParameters`` objects. For example,
        ``DynamoDBStreamParameters`` or ``EventBridgeEventBusParameters``.
        EventBridge updates the fields in these objects atomically as one and
        overrides existing values. This is by design, and means that if you
        don't specify an optional field in one of these ``Parameters`` objects,
        EventBridge sets that field to its system-default value during the
        update.

        For more information about pipes, see `Amazon EventBridge
        Pipes <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html>`__
        in the Amazon EventBridge User Guide.

        :param name: The name of the pipe.
        :param role_arn: The ARN of the role that allows the pipe to send data to the target.
        :param description: A description of the pipe.
        :param desired_state: The state the pipe should be in.
        :param source_parameters: The parameters required to set up a source for your pipe.
        :param enrichment: The ARN of the enrichment resource.
        :param enrichment_parameters: The parameters required to set up enrichment on your pipe.
        :param target: The ARN of the target resource.
        :param target_parameters: The parameters required to set up a target for your pipe.
        :param log_configuration: The logging configuration settings for the pipe.
        :returns: UpdatePipeResponse
        :raises InternalException:
        :raises ValidationException:
        :raises ThrottlingException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError
