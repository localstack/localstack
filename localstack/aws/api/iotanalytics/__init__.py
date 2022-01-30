import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ActivityBatchSize = int
ActivityName = str
AttributeName = str
BucketKeyExpression = str
BucketName = str
ChannelArn = str
ChannelName = str
ColumnDataType = str
ColumnName = str
DatasetActionName = str
DatasetArn = str
DatasetContentVersion = str
DatasetName = str
DatastoreArn = str
DatastoreName = str
DoubleValue = float
EntryName = str
ErrorCode = str
ErrorMessage = str
FilterExpression = str
GlueDatabaseName = str
GlueTableName = str
Image = str
IncludeStatisticsFlag = bool
IotEventsInputName = str
LambdaName = str
LateDataRuleName = str
LogResult = str
LoggingEnabled = bool
MathExpression = str
MaxMessages = int
MaxResults = int
MaxVersions = int
MessageId = str
NextToken = str
OffsetSeconds = int
OutputFileName = str
PartitionAttributeName = str
PipelineArn = str
PipelineName = str
PresignedURI = str
Reason = str
ReprocessingId = str
ResourceArn = str
RetentionPeriodInDays = int
RoleArn = str
S3KeyPrefix = str
S3PathChannelMessage = str
ScheduleExpression = str
SessionTimeoutInMinutes = int
SizeInBytes = float
SqlQuery = str
StringValue = str
TagKey = str
TagValue = str
TimeExpression = str
TimestampFormat = str
UnlimitedRetentionPeriod = bool
UnlimitedVersioning = bool
VariableName = str
VolumeSizeInGB = int
errorMessage = str
resourceArn = str
resourceId = str


class ChannelStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class ComputeType(str):
    ACU_1 = "ACU_1"
    ACU_2 = "ACU_2"


class DatasetActionType(str):
    QUERY = "QUERY"
    CONTAINER = "CONTAINER"


class DatasetContentState(str):
    CREATING = "CREATING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class DatasetStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class DatastoreStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class FileFormatType(str):
    JSON = "JSON"
    PARQUET = "PARQUET"


class LoggingLevel(str):
    ERROR = "ERROR"


class ReprocessingStatus(str):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class InternalFailureException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class LimitExceededException(ServiceException):
    message: Optional[errorMessage]


class ResourceAlreadyExistsException(ServiceException):
    message: Optional[errorMessage]
    resourceId: Optional[resourceId]
    resourceArn: Optional[resourceArn]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]


AttributeNameMapping = Dict[AttributeName, AttributeName]


class AddAttributesActivity(TypedDict, total=False):
    name: ActivityName
    attributes: AttributeNameMapping
    next: Optional[ActivityName]


AttributeNames = List[AttributeName]


class BatchPutMessageErrorEntry(TypedDict, total=False):
    messageId: Optional[MessageId]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchPutMessageErrorEntries = List[BatchPutMessageErrorEntry]
MessagePayload = bytes


class Message(TypedDict, total=False):
    messageId: MessageId
    payload: MessagePayload


Messages = List[Message]


class BatchPutMessageRequest(ServiceRequest):
    channelName: ChannelName
    messages: Messages


class BatchPutMessageResponse(TypedDict, total=False):
    batchPutMessageErrorEntries: Optional[BatchPutMessageErrorEntries]


class CancelPipelineReprocessingRequest(ServiceRequest):
    pipelineName: PipelineName
    reprocessingId: ReprocessingId


class CancelPipelineReprocessingResponse(TypedDict, total=False):
    pass


Timestamp = datetime


class RetentionPeriod(TypedDict, total=False):
    unlimited: Optional[UnlimitedRetentionPeriod]
    numberOfDays: Optional[RetentionPeriodInDays]


class CustomerManagedChannelS3Storage(TypedDict, total=False):
    bucket: BucketName
    keyPrefix: Optional[S3KeyPrefix]
    roleArn: RoleArn


class ServiceManagedChannelS3Storage(TypedDict, total=False):
    pass


class ChannelStorage(TypedDict, total=False):
    serviceManagedS3: Optional[ServiceManagedChannelS3Storage]
    customerManagedS3: Optional[CustomerManagedChannelS3Storage]


class Channel(TypedDict, total=False):
    name: Optional[ChannelName]
    storage: Optional[ChannelStorage]
    arn: Optional[ChannelArn]
    status: Optional[ChannelStatus]
    retentionPeriod: Optional[RetentionPeriod]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    lastMessageArrivalTime: Optional[Timestamp]


class ChannelActivity(TypedDict, total=False):
    name: ActivityName
    channelName: ChannelName
    next: Optional[ActivityName]


S3PathChannelMessages = List[S3PathChannelMessage]


class ChannelMessages(TypedDict, total=False):
    s3Paths: Optional[S3PathChannelMessages]


class EstimatedResourceSize(TypedDict, total=False):
    estimatedSizeInBytes: Optional[SizeInBytes]
    estimatedOn: Optional[Timestamp]


class ChannelStatistics(TypedDict, total=False):
    size: Optional[EstimatedResourceSize]


class CustomerManagedChannelS3StorageSummary(TypedDict, total=False):
    bucket: Optional[BucketName]
    keyPrefix: Optional[S3KeyPrefix]
    roleArn: Optional[RoleArn]


class ServiceManagedChannelS3StorageSummary(TypedDict, total=False):
    pass


class ChannelStorageSummary(TypedDict, total=False):
    serviceManagedS3: Optional[ServiceManagedChannelS3StorageSummary]
    customerManagedS3: Optional[CustomerManagedChannelS3StorageSummary]


class ChannelSummary(TypedDict, total=False):
    channelName: Optional[ChannelName]
    channelStorage: Optional[ChannelStorageSummary]
    status: Optional[ChannelStatus]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    lastMessageArrivalTime: Optional[Timestamp]


ChannelSummaries = List[ChannelSummary]
Column = TypedDict(
    "Column",
    {
        "name": ColumnName,
        "type": ColumnDataType,
    },
    total=False,
)
Columns = List[Column]


class OutputFileUriValue(TypedDict, total=False):
    fileName: OutputFileName


class DatasetContentVersionValue(TypedDict, total=False):
    datasetName: DatasetName


class Variable(TypedDict, total=False):
    name: VariableName
    stringValue: Optional[StringValue]
    doubleValue: Optional[DoubleValue]
    datasetContentVersionValue: Optional[DatasetContentVersionValue]
    outputFileUriValue: Optional[OutputFileUriValue]


Variables = List[Variable]


class ResourceConfiguration(TypedDict, total=False):
    computeType: ComputeType
    volumeSizeInGB: VolumeSizeInGB


class ContainerDatasetAction(TypedDict, total=False):
    image: Image
    executionRoleArn: RoleArn
    resourceConfiguration: ResourceConfiguration
    variables: Optional[Variables]


class Tag(TypedDict, total=False):
    key: TagKey
    value: TagValue


TagList = List[Tag]


class CreateChannelRequest(ServiceRequest):
    channelName: ChannelName
    channelStorage: Optional[ChannelStorage]
    retentionPeriod: Optional[RetentionPeriod]
    tags: Optional[TagList]


class CreateChannelResponse(TypedDict, total=False):
    channelName: Optional[ChannelName]
    channelArn: Optional[ChannelArn]
    retentionPeriod: Optional[RetentionPeriod]


class CreateDatasetContentRequest(ServiceRequest):
    datasetName: DatasetName
    versionId: Optional[DatasetContentVersion]


class CreateDatasetContentResponse(TypedDict, total=False):
    versionId: Optional[DatasetContentVersion]


class DeltaTimeSessionWindowConfiguration(TypedDict, total=False):
    timeoutInMinutes: SessionTimeoutInMinutes


class LateDataRuleConfiguration(TypedDict, total=False):
    deltaTimeSessionWindowConfiguration: Optional[DeltaTimeSessionWindowConfiguration]


class LateDataRule(TypedDict, total=False):
    ruleName: Optional[LateDataRuleName]
    ruleConfiguration: LateDataRuleConfiguration


LateDataRules = List[LateDataRule]


class VersioningConfiguration(TypedDict, total=False):
    unlimited: Optional[UnlimitedVersioning]
    maxVersions: Optional[MaxVersions]


class GlueConfiguration(TypedDict, total=False):
    tableName: GlueTableName
    databaseName: GlueDatabaseName


class S3DestinationConfiguration(TypedDict, total=False):
    bucket: BucketName
    key: BucketKeyExpression
    glueConfiguration: Optional[GlueConfiguration]
    roleArn: RoleArn


class IotEventsDestinationConfiguration(TypedDict, total=False):
    inputName: IotEventsInputName
    roleArn: RoleArn


class DatasetContentDeliveryDestination(TypedDict, total=False):
    iotEventsDestinationConfiguration: Optional[IotEventsDestinationConfiguration]
    s3DestinationConfiguration: Optional[S3DestinationConfiguration]


class DatasetContentDeliveryRule(TypedDict, total=False):
    entryName: Optional[EntryName]
    destination: DatasetContentDeliveryDestination


DatasetContentDeliveryRules = List[DatasetContentDeliveryRule]


class TriggeringDataset(TypedDict, total=False):
    name: DatasetName


class Schedule(TypedDict, total=False):
    expression: Optional[ScheduleExpression]


class DatasetTrigger(TypedDict, total=False):
    schedule: Optional[Schedule]
    dataset: Optional[TriggeringDataset]


DatasetTriggers = List[DatasetTrigger]


class DeltaTime(TypedDict, total=False):
    offsetSeconds: OffsetSeconds
    timeExpression: TimeExpression


class QueryFilter(TypedDict, total=False):
    deltaTime: Optional[DeltaTime]


QueryFilters = List[QueryFilter]


class SqlQueryDatasetAction(TypedDict, total=False):
    sqlQuery: SqlQuery
    filters: Optional[QueryFilters]


class DatasetAction(TypedDict, total=False):
    actionName: Optional[DatasetActionName]
    queryAction: Optional[SqlQueryDatasetAction]
    containerAction: Optional[ContainerDatasetAction]


DatasetActions = List[DatasetAction]


class CreateDatasetRequest(ServiceRequest):
    datasetName: DatasetName
    actions: DatasetActions
    triggers: Optional[DatasetTriggers]
    contentDeliveryRules: Optional[DatasetContentDeliveryRules]
    retentionPeriod: Optional[RetentionPeriod]
    versioningConfiguration: Optional[VersioningConfiguration]
    tags: Optional[TagList]
    lateDataRules: Optional[LateDataRules]


class CreateDatasetResponse(TypedDict, total=False):
    datasetName: Optional[DatasetName]
    datasetArn: Optional[DatasetArn]
    retentionPeriod: Optional[RetentionPeriod]


class TimestampPartition(TypedDict, total=False):
    attributeName: PartitionAttributeName
    timestampFormat: Optional[TimestampFormat]


class Partition(TypedDict, total=False):
    attributeName: PartitionAttributeName


class DatastorePartition(TypedDict, total=False):
    attributePartition: Optional[Partition]
    timestampPartition: Optional[TimestampPartition]


Partitions = List[DatastorePartition]


class DatastorePartitions(TypedDict, total=False):
    partitions: Optional[Partitions]


class SchemaDefinition(TypedDict, total=False):
    columns: Optional[Columns]


class ParquetConfiguration(TypedDict, total=False):
    schemaDefinition: Optional[SchemaDefinition]


class JsonConfiguration(TypedDict, total=False):
    pass


class FileFormatConfiguration(TypedDict, total=False):
    jsonConfiguration: Optional[JsonConfiguration]
    parquetConfiguration: Optional[ParquetConfiguration]


class IotSiteWiseCustomerManagedDatastoreS3Storage(TypedDict, total=False):
    bucket: BucketName
    keyPrefix: Optional[S3KeyPrefix]


class DatastoreIotSiteWiseMultiLayerStorage(TypedDict, total=False):
    customerManagedS3Storage: IotSiteWiseCustomerManagedDatastoreS3Storage


class CustomerManagedDatastoreS3Storage(TypedDict, total=False):
    bucket: BucketName
    keyPrefix: Optional[S3KeyPrefix]
    roleArn: RoleArn


class ServiceManagedDatastoreS3Storage(TypedDict, total=False):
    pass


class DatastoreStorage(TypedDict, total=False):
    serviceManagedS3: Optional[ServiceManagedDatastoreS3Storage]
    customerManagedS3: Optional[CustomerManagedDatastoreS3Storage]
    iotSiteWiseMultiLayerStorage: Optional[DatastoreIotSiteWiseMultiLayerStorage]


class CreateDatastoreRequest(ServiceRequest):
    datastoreName: DatastoreName
    datastoreStorage: Optional[DatastoreStorage]
    retentionPeriod: Optional[RetentionPeriod]
    tags: Optional[TagList]
    fileFormatConfiguration: Optional[FileFormatConfiguration]
    datastorePartitions: Optional[DatastorePartitions]


class CreateDatastoreResponse(TypedDict, total=False):
    datastoreName: Optional[DatastoreName]
    datastoreArn: Optional[DatastoreArn]
    retentionPeriod: Optional[RetentionPeriod]


class DeviceShadowEnrichActivity(TypedDict, total=False):
    name: ActivityName
    attribute: AttributeName
    thingName: AttributeName
    roleArn: RoleArn
    next: Optional[ActivityName]


class DeviceRegistryEnrichActivity(TypedDict, total=False):
    name: ActivityName
    attribute: AttributeName
    thingName: AttributeName
    roleArn: RoleArn
    next: Optional[ActivityName]


class MathActivity(TypedDict, total=False):
    name: ActivityName
    attribute: AttributeName
    math: MathExpression
    next: Optional[ActivityName]


class FilterActivity(TypedDict, total=False):
    name: ActivityName
    filter: FilterExpression
    next: Optional[ActivityName]


class SelectAttributesActivity(TypedDict, total=False):
    name: ActivityName
    attributes: AttributeNames
    next: Optional[ActivityName]


class RemoveAttributesActivity(TypedDict, total=False):
    name: ActivityName
    attributes: AttributeNames
    next: Optional[ActivityName]


class DatastoreActivity(TypedDict, total=False):
    name: ActivityName
    datastoreName: DatastoreName


class LambdaActivity(TypedDict, total=False):
    name: ActivityName
    lambdaName: LambdaName
    batchSize: ActivityBatchSize
    next: Optional[ActivityName]


PipelineActivity = TypedDict(
    "PipelineActivity",
    {
        "channel": Optional[ChannelActivity],
        "lambda": Optional[LambdaActivity],
        "datastore": Optional[DatastoreActivity],
        "addAttributes": Optional[AddAttributesActivity],
        "removeAttributes": Optional[RemoveAttributesActivity],
        "selectAttributes": Optional[SelectAttributesActivity],
        "filter": Optional[FilterActivity],
        "math": Optional[MathActivity],
        "deviceRegistryEnrich": Optional[DeviceRegistryEnrichActivity],
        "deviceShadowEnrich": Optional[DeviceShadowEnrichActivity],
    },
    total=False,
)
PipelineActivities = List[PipelineActivity]


class CreatePipelineRequest(ServiceRequest):
    pipelineName: PipelineName
    pipelineActivities: PipelineActivities
    tags: Optional[TagList]


class CreatePipelineResponse(TypedDict, total=False):
    pipelineName: Optional[PipelineName]
    pipelineArn: Optional[PipelineArn]


class CustomerManagedDatastoreS3StorageSummary(TypedDict, total=False):
    bucket: Optional[BucketName]
    keyPrefix: Optional[S3KeyPrefix]
    roleArn: Optional[RoleArn]


class Dataset(TypedDict, total=False):
    name: Optional[DatasetName]
    arn: Optional[DatasetArn]
    actions: Optional[DatasetActions]
    triggers: Optional[DatasetTriggers]
    contentDeliveryRules: Optional[DatasetContentDeliveryRules]
    status: Optional[DatasetStatus]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    retentionPeriod: Optional[RetentionPeriod]
    versioningConfiguration: Optional[VersioningConfiguration]
    lateDataRules: Optional[LateDataRules]


class DatasetActionSummary(TypedDict, total=False):
    actionName: Optional[DatasetActionName]
    actionType: Optional[DatasetActionType]


DatasetActionSummaries = List[DatasetActionSummary]


class DatasetContentStatus(TypedDict, total=False):
    state: Optional[DatasetContentState]
    reason: Optional[Reason]


class DatasetContentSummary(TypedDict, total=False):
    version: Optional[DatasetContentVersion]
    status: Optional[DatasetContentStatus]
    creationTime: Optional[Timestamp]
    scheduleTime: Optional[Timestamp]
    completionTime: Optional[Timestamp]


DatasetContentSummaries = List[DatasetContentSummary]


class DatasetEntry(TypedDict, total=False):
    entryName: Optional[EntryName]
    dataURI: Optional[PresignedURI]


DatasetEntries = List[DatasetEntry]


class DatasetSummary(TypedDict, total=False):
    datasetName: Optional[DatasetName]
    status: Optional[DatasetStatus]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    triggers: Optional[DatasetTriggers]
    actions: Optional[DatasetActionSummaries]


DatasetSummaries = List[DatasetSummary]


class Datastore(TypedDict, total=False):
    name: Optional[DatastoreName]
    storage: Optional[DatastoreStorage]
    arn: Optional[DatastoreArn]
    status: Optional[DatastoreStatus]
    retentionPeriod: Optional[RetentionPeriod]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    lastMessageArrivalTime: Optional[Timestamp]
    fileFormatConfiguration: Optional[FileFormatConfiguration]
    datastorePartitions: Optional[DatastorePartitions]


class IotSiteWiseCustomerManagedDatastoreS3StorageSummary(TypedDict, total=False):
    bucket: Optional[BucketName]
    keyPrefix: Optional[S3KeyPrefix]


class DatastoreIotSiteWiseMultiLayerStorageSummary(TypedDict, total=False):
    customerManagedS3Storage: Optional[IotSiteWiseCustomerManagedDatastoreS3StorageSummary]


class DatastoreStatistics(TypedDict, total=False):
    size: Optional[EstimatedResourceSize]


class ServiceManagedDatastoreS3StorageSummary(TypedDict, total=False):
    pass


class DatastoreStorageSummary(TypedDict, total=False):
    serviceManagedS3: Optional[ServiceManagedDatastoreS3StorageSummary]
    customerManagedS3: Optional[CustomerManagedDatastoreS3StorageSummary]
    iotSiteWiseMultiLayerStorage: Optional[DatastoreIotSiteWiseMultiLayerStorageSummary]


class DatastoreSummary(TypedDict, total=False):
    datastoreName: Optional[DatastoreName]
    datastoreStorage: Optional[DatastoreStorageSummary]
    status: Optional[DatastoreStatus]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    lastMessageArrivalTime: Optional[Timestamp]
    fileFormatType: Optional[FileFormatType]
    datastorePartitions: Optional[DatastorePartitions]


DatastoreSummaries = List[DatastoreSummary]


class DeleteChannelRequest(ServiceRequest):
    channelName: ChannelName


class DeleteDatasetContentRequest(ServiceRequest):
    datasetName: DatasetName
    versionId: Optional[DatasetContentVersion]


class DeleteDatasetRequest(ServiceRequest):
    datasetName: DatasetName


class DeleteDatastoreRequest(ServiceRequest):
    datastoreName: DatastoreName


class DeletePipelineRequest(ServiceRequest):
    pipelineName: PipelineName


class DescribeChannelRequest(ServiceRequest):
    channelName: ChannelName
    includeStatistics: Optional[IncludeStatisticsFlag]


class DescribeChannelResponse(TypedDict, total=False):
    channel: Optional[Channel]
    statistics: Optional[ChannelStatistics]


class DescribeDatasetRequest(ServiceRequest):
    datasetName: DatasetName


class DescribeDatasetResponse(TypedDict, total=False):
    dataset: Optional[Dataset]


class DescribeDatastoreRequest(ServiceRequest):
    datastoreName: DatastoreName
    includeStatistics: Optional[IncludeStatisticsFlag]


class DescribeDatastoreResponse(TypedDict, total=False):
    datastore: Optional[Datastore]
    statistics: Optional[DatastoreStatistics]


class DescribeLoggingOptionsRequest(ServiceRequest):
    pass


class LoggingOptions(TypedDict, total=False):
    roleArn: RoleArn
    level: LoggingLevel
    enabled: LoggingEnabled


class DescribeLoggingOptionsResponse(TypedDict, total=False):
    loggingOptions: Optional[LoggingOptions]


class DescribePipelineRequest(ServiceRequest):
    pipelineName: PipelineName


class ReprocessingSummary(TypedDict, total=False):
    id: Optional[ReprocessingId]
    status: Optional[ReprocessingStatus]
    creationTime: Optional[Timestamp]


ReprocessingSummaries = List[ReprocessingSummary]


class Pipeline(TypedDict, total=False):
    name: Optional[PipelineName]
    arn: Optional[PipelineArn]
    activities: Optional[PipelineActivities]
    reprocessingSummaries: Optional[ReprocessingSummaries]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


class DescribePipelineResponse(TypedDict, total=False):
    pipeline: Optional[Pipeline]


EndTime = datetime


class GetDatasetContentRequest(ServiceRequest):
    datasetName: DatasetName
    versionId: Optional[DatasetContentVersion]


class GetDatasetContentResponse(TypedDict, total=False):
    entries: Optional[DatasetEntries]
    timestamp: Optional[Timestamp]
    status: Optional[DatasetContentStatus]


class ListChannelsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListChannelsResponse(TypedDict, total=False):
    channelSummaries: Optional[ChannelSummaries]
    nextToken: Optional[NextToken]


class ListDatasetContentsRequest(ServiceRequest):
    datasetName: DatasetName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    scheduledOnOrAfter: Optional[Timestamp]
    scheduledBefore: Optional[Timestamp]


class ListDatasetContentsResponse(TypedDict, total=False):
    datasetContentSummaries: Optional[DatasetContentSummaries]
    nextToken: Optional[NextToken]


class ListDatasetsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDatasetsResponse(TypedDict, total=False):
    datasetSummaries: Optional[DatasetSummaries]
    nextToken: Optional[NextToken]


class ListDatastoresRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDatastoresResponse(TypedDict, total=False):
    datastoreSummaries: Optional[DatastoreSummaries]
    nextToken: Optional[NextToken]


class ListPipelinesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class PipelineSummary(TypedDict, total=False):
    pipelineName: Optional[PipelineName]
    reprocessingSummaries: Optional[ReprocessingSummaries]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


PipelineSummaries = List[PipelineSummary]


class ListPipelinesResponse(TypedDict, total=False):
    pipelineSummaries: Optional[PipelineSummaries]
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: ResourceArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagList]


MessagePayloads = List[MessagePayload]


class PutLoggingOptionsRequest(ServiceRequest):
    loggingOptions: LoggingOptions


class RunPipelineActivityRequest(ServiceRequest):
    pipelineActivity: PipelineActivity
    payloads: MessagePayloads


class RunPipelineActivityResponse(TypedDict, total=False):
    payloads: Optional[MessagePayloads]
    logResult: Optional[LogResult]


StartTime = datetime


class SampleChannelDataRequest(ServiceRequest):
    channelName: ChannelName
    maxMessages: Optional[MaxMessages]
    startTime: Optional[StartTime]
    endTime: Optional[EndTime]


class SampleChannelDataResponse(TypedDict, total=False):
    payloads: Optional[MessagePayloads]


class StartPipelineReprocessingRequest(ServiceRequest):
    pipelineName: PipelineName
    startTime: Optional[StartTime]
    endTime: Optional[EndTime]
    channelMessages: Optional[ChannelMessages]


class StartPipelineReprocessingResponse(TypedDict, total=False):
    reprocessingId: Optional[ReprocessingId]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateChannelRequest(ServiceRequest):
    channelName: ChannelName
    channelStorage: Optional[ChannelStorage]
    retentionPeriod: Optional[RetentionPeriod]


class UpdateDatasetRequest(ServiceRequest):
    datasetName: DatasetName
    actions: DatasetActions
    triggers: Optional[DatasetTriggers]
    contentDeliveryRules: Optional[DatasetContentDeliveryRules]
    retentionPeriod: Optional[RetentionPeriod]
    versioningConfiguration: Optional[VersioningConfiguration]
    lateDataRules: Optional[LateDataRules]


class UpdateDatastoreRequest(ServiceRequest):
    datastoreName: DatastoreName
    retentionPeriod: Optional[RetentionPeriod]
    datastoreStorage: Optional[DatastoreStorage]
    fileFormatConfiguration: Optional[FileFormatConfiguration]


class UpdatePipelineRequest(ServiceRequest):
    pipelineName: PipelineName
    pipelineActivities: PipelineActivities


class IotanalyticsApi:

    service = "iotanalytics"
    version = "2017-11-27"

    @handler("BatchPutMessage")
    def batch_put_message(
        self, context: RequestContext, channel_name: ChannelName, messages: Messages
    ) -> BatchPutMessageResponse:
        raise NotImplementedError

    @handler("CancelPipelineReprocessing")
    def cancel_pipeline_reprocessing(
        self, context: RequestContext, pipeline_name: PipelineName, reprocessing_id: ReprocessingId
    ) -> CancelPipelineReprocessingResponse:
        raise NotImplementedError

    @handler("CreateChannel")
    def create_channel(
        self,
        context: RequestContext,
        channel_name: ChannelName,
        channel_storage: ChannelStorage = None,
        retention_period: RetentionPeriod = None,
        tags: TagList = None,
    ) -> CreateChannelResponse:
        raise NotImplementedError

    @handler("CreateDataset")
    def create_dataset(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        actions: DatasetActions,
        triggers: DatasetTriggers = None,
        content_delivery_rules: DatasetContentDeliveryRules = None,
        retention_period: RetentionPeriod = None,
        versioning_configuration: VersioningConfiguration = None,
        tags: TagList = None,
        late_data_rules: LateDataRules = None,
    ) -> CreateDatasetResponse:
        raise NotImplementedError

    @handler("CreateDatasetContent")
    def create_dataset_content(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        version_id: DatasetContentVersion = None,
    ) -> CreateDatasetContentResponse:
        raise NotImplementedError

    @handler("CreateDatastore")
    def create_datastore(
        self,
        context: RequestContext,
        datastore_name: DatastoreName,
        datastore_storage: DatastoreStorage = None,
        retention_period: RetentionPeriod = None,
        tags: TagList = None,
        file_format_configuration: FileFormatConfiguration = None,
        datastore_partitions: DatastorePartitions = None,
    ) -> CreateDatastoreResponse:
        raise NotImplementedError

    @handler("CreatePipeline")
    def create_pipeline(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        pipeline_activities: PipelineActivities,
        tags: TagList = None,
    ) -> CreatePipelineResponse:
        raise NotImplementedError

    @handler("DeleteChannel")
    def delete_channel(self, context: RequestContext, channel_name: ChannelName) -> None:
        raise NotImplementedError

    @handler("DeleteDataset")
    def delete_dataset(self, context: RequestContext, dataset_name: DatasetName) -> None:
        raise NotImplementedError

    @handler("DeleteDatasetContent")
    def delete_dataset_content(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        version_id: DatasetContentVersion = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDatastore")
    def delete_datastore(self, context: RequestContext, datastore_name: DatastoreName) -> None:
        raise NotImplementedError

    @handler("DeletePipeline")
    def delete_pipeline(self, context: RequestContext, pipeline_name: PipelineName) -> None:
        raise NotImplementedError

    @handler("DescribeChannel")
    def describe_channel(
        self,
        context: RequestContext,
        channel_name: ChannelName,
        include_statistics: IncludeStatisticsFlag = None,
    ) -> DescribeChannelResponse:
        raise NotImplementedError

    @handler("DescribeDataset")
    def describe_dataset(
        self, context: RequestContext, dataset_name: DatasetName
    ) -> DescribeDatasetResponse:
        raise NotImplementedError

    @handler("DescribeDatastore")
    def describe_datastore(
        self,
        context: RequestContext,
        datastore_name: DatastoreName,
        include_statistics: IncludeStatisticsFlag = None,
    ) -> DescribeDatastoreResponse:
        raise NotImplementedError

    @handler("DescribeLoggingOptions")
    def describe_logging_options(
        self,
        context: RequestContext,
    ) -> DescribeLoggingOptionsResponse:
        raise NotImplementedError

    @handler("DescribePipeline")
    def describe_pipeline(
        self, context: RequestContext, pipeline_name: PipelineName
    ) -> DescribePipelineResponse:
        raise NotImplementedError

    @handler("GetDatasetContent")
    def get_dataset_content(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        version_id: DatasetContentVersion = None,
    ) -> GetDatasetContentResponse:
        raise NotImplementedError

    @handler("ListChannels")
    def list_channels(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListChannelsResponse:
        raise NotImplementedError

    @handler("ListDatasetContents")
    def list_dataset_contents(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        scheduled_on_or_after: Timestamp = None,
        scheduled_before: Timestamp = None,
    ) -> ListDatasetContentsResponse:
        raise NotImplementedError

    @handler("ListDatasets")
    def list_datasets(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDatasetsResponse:
        raise NotImplementedError

    @handler("ListDatastores")
    def list_datastores(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDatastoresResponse:
        raise NotImplementedError

    @handler("ListPipelines")
    def list_pipelines(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListPipelinesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutLoggingOptions")
    def put_logging_options(self, context: RequestContext, logging_options: LoggingOptions) -> None:
        raise NotImplementedError

    @handler("RunPipelineActivity")
    def run_pipeline_activity(
        self,
        context: RequestContext,
        pipeline_activity: PipelineActivity,
        payloads: MessagePayloads,
    ) -> RunPipelineActivityResponse:
        raise NotImplementedError

    @handler("SampleChannelData")
    def sample_channel_data(
        self,
        context: RequestContext,
        channel_name: ChannelName,
        max_messages: MaxMessages = None,
        start_time: StartTime = None,
        end_time: EndTime = None,
    ) -> SampleChannelDataResponse:
        raise NotImplementedError

    @handler("StartPipelineReprocessing")
    def start_pipeline_reprocessing(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        start_time: StartTime = None,
        end_time: EndTime = None,
        channel_messages: ChannelMessages = None,
    ) -> StartPipelineReprocessingResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateChannel")
    def update_channel(
        self,
        context: RequestContext,
        channel_name: ChannelName,
        channel_storage: ChannelStorage = None,
        retention_period: RetentionPeriod = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDataset")
    def update_dataset(
        self,
        context: RequestContext,
        dataset_name: DatasetName,
        actions: DatasetActions,
        triggers: DatasetTriggers = None,
        content_delivery_rules: DatasetContentDeliveryRules = None,
        retention_period: RetentionPeriod = None,
        versioning_configuration: VersioningConfiguration = None,
        late_data_rules: LateDataRules = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDatastore")
    def update_datastore(
        self,
        context: RequestContext,
        datastore_name: DatastoreName,
        retention_period: RetentionPeriod = None,
        datastore_storage: DatastoreStorage = None,
        file_format_configuration: FileFormatConfiguration = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePipeline")
    def update_pipeline(
        self,
        context: RequestContext,
        pipeline_name: PipelineName,
        pipeline_activities: PipelineActivities,
    ) -> None:
        raise NotImplementedError
