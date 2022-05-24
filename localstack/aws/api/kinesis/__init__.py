import sys
from datetime import datetime
from typing import Dict, Iterator, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

BooleanObject = bool
ConsumerARN = str
ConsumerCountObject = int
ConsumerName = str
DescribeStreamInputLimit = int
ErrorCode = str
ErrorMessage = str
GetRecordsInputLimit = int
HashKey = str
KeyId = str
ListShardsInputLimit = int
ListStreamConsumersInputLimit = int
ListStreamsInputLimit = int
ListTagsForStreamInputLimit = int
NextToken = str
OnDemandStreamCountLimitObject = int
OnDemandStreamCountObject = int
PartitionKey = str
PositiveIntegerObject = int
RetentionPeriodHours = int
SequenceNumber = str
ShardCountObject = int
ShardId = str
ShardIterator = str
StreamARN = str
StreamName = str
TagKey = str
TagValue = str


class ConsumerStatus(str):
    CREATING = "CREATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"


class EncryptionType(str):
    NONE = "NONE"
    KMS = "KMS"


class MetricsName(str):
    IncomingBytes = "IncomingBytes"
    IncomingRecords = "IncomingRecords"
    OutgoingBytes = "OutgoingBytes"
    OutgoingRecords = "OutgoingRecords"
    WriteProvisionedThroughputExceeded = "WriteProvisionedThroughputExceeded"
    ReadProvisionedThroughputExceeded = "ReadProvisionedThroughputExceeded"
    IteratorAgeMilliseconds = "IteratorAgeMilliseconds"
    ALL = "ALL"


class ScalingType(str):
    UNIFORM_SCALING = "UNIFORM_SCALING"


class ShardFilterType(str):
    AFTER_SHARD_ID = "AFTER_SHARD_ID"
    AT_TRIM_HORIZON = "AT_TRIM_HORIZON"
    FROM_TRIM_HORIZON = "FROM_TRIM_HORIZON"
    AT_LATEST = "AT_LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"
    FROM_TIMESTAMP = "FROM_TIMESTAMP"


class ShardIteratorType(str):
    AT_SEQUENCE_NUMBER = "AT_SEQUENCE_NUMBER"
    AFTER_SEQUENCE_NUMBER = "AFTER_SEQUENCE_NUMBER"
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"


class StreamMode(str):
    PROVISIONED = "PROVISIONED"
    ON_DEMAND = "ON_DEMAND"


class StreamStatus(str):
    CREATING = "CREATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"
    UPDATING = "UPDATING"


class ExpiredIteratorException(ServiceException):
    message: Optional[ErrorMessage]


class ExpiredNextTokenException(ServiceException):
    message: Optional[ErrorMessage]


class InternalFailureException(ServiceException):
    message: Optional[ErrorMessage]


class InvalidArgumentException(ServiceException):
    message: Optional[ErrorMessage]


class KMSAccessDeniedException(ServiceException):
    message: Optional[ErrorMessage]


class KMSDisabledException(ServiceException):
    message: Optional[ErrorMessage]


class KMSInvalidStateException(ServiceException):
    message: Optional[ErrorMessage]


class KMSNotFoundException(ServiceException):
    message: Optional[ErrorMessage]


class KMSOptInRequired(ServiceException):
    message: Optional[ErrorMessage]


class KMSThrottlingException(ServiceException):
    message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    message: Optional[ErrorMessage]


class ProvisionedThroughputExceededException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceInUseException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[ErrorMessage]


class ValidationException(ServiceException):
    message: Optional[ErrorMessage]


TagMap = Dict[TagKey, TagValue]


class AddTagsToStreamInput(ServiceRequest):
    StreamName: StreamName
    Tags: TagMap


class HashKeyRange(TypedDict, total=False):
    StartingHashKey: HashKey
    EndingHashKey: HashKey


ShardIdList = List[ShardId]


class ChildShard(TypedDict, total=False):
    ShardId: ShardId
    ParentShards: ShardIdList
    HashKeyRange: HashKeyRange


ChildShardList = List[ChildShard]
Timestamp = datetime


class Consumer(TypedDict, total=False):
    ConsumerName: ConsumerName
    ConsumerARN: ConsumerARN
    ConsumerStatus: ConsumerStatus
    ConsumerCreationTimestamp: Timestamp


class ConsumerDescription(TypedDict, total=False):
    ConsumerName: ConsumerName
    ConsumerARN: ConsumerARN
    ConsumerStatus: ConsumerStatus
    ConsumerCreationTimestamp: Timestamp
    StreamARN: StreamARN


ConsumerList = List[Consumer]


class StreamModeDetails(TypedDict, total=False):
    StreamMode: StreamMode


class CreateStreamInput(ServiceRequest):
    StreamName: StreamName
    ShardCount: Optional[PositiveIntegerObject]
    StreamModeDetails: Optional[StreamModeDetails]


Data = bytes


class DecreaseStreamRetentionPeriodInput(ServiceRequest):
    StreamName: StreamName
    RetentionPeriodHours: RetentionPeriodHours


class DeleteStreamInput(ServiceRequest):
    StreamName: StreamName
    EnforceConsumerDeletion: Optional[BooleanObject]


class DeregisterStreamConsumerInput(ServiceRequest):
    StreamARN: Optional[StreamARN]
    ConsumerName: Optional[ConsumerName]
    ConsumerARN: Optional[ConsumerARN]


class DescribeLimitsInput(ServiceRequest):
    pass


class DescribeLimitsOutput(TypedDict, total=False):
    ShardLimit: ShardCountObject
    OpenShardCount: ShardCountObject
    OnDemandStreamCount: OnDemandStreamCountObject
    OnDemandStreamCountLimit: OnDemandStreamCountLimitObject


class DescribeStreamConsumerInput(ServiceRequest):
    StreamARN: Optional[StreamARN]
    ConsumerName: Optional[ConsumerName]
    ConsumerARN: Optional[ConsumerARN]


class DescribeStreamConsumerOutput(TypedDict, total=False):
    ConsumerDescription: ConsumerDescription


class DescribeStreamInput(ServiceRequest):
    StreamName: StreamName
    Limit: Optional[DescribeStreamInputLimit]
    ExclusiveStartShardId: Optional[ShardId]


MetricsNameList = List[MetricsName]


class EnhancedMetrics(TypedDict, total=False):
    ShardLevelMetrics: Optional[MetricsNameList]


EnhancedMonitoringList = List[EnhancedMetrics]


class SequenceNumberRange(TypedDict, total=False):
    StartingSequenceNumber: SequenceNumber
    EndingSequenceNumber: Optional[SequenceNumber]


class Shard(TypedDict, total=False):
    ShardId: ShardId
    ParentShardId: Optional[ShardId]
    AdjacentParentShardId: Optional[ShardId]
    HashKeyRange: HashKeyRange
    SequenceNumberRange: SequenceNumberRange


ShardList = List[Shard]


class StreamDescription(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: Optional[StreamModeDetails]
    Shards: ShardList
    HasMoreShards: BooleanObject
    RetentionPeriodHours: RetentionPeriodHours
    StreamCreationTimestamp: Timestamp
    EnhancedMonitoring: EnhancedMonitoringList
    EncryptionType: Optional[EncryptionType]
    KeyId: Optional[KeyId]


class DescribeStreamOutput(TypedDict, total=False):
    StreamDescription: StreamDescription


class DescribeStreamSummaryInput(ServiceRequest):
    StreamName: StreamName


class StreamDescriptionSummary(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: Optional[StreamModeDetails]
    RetentionPeriodHours: RetentionPeriodHours
    StreamCreationTimestamp: Timestamp
    EnhancedMonitoring: EnhancedMonitoringList
    EncryptionType: Optional[EncryptionType]
    KeyId: Optional[KeyId]
    OpenShardCount: ShardCountObject
    ConsumerCount: Optional[ConsumerCountObject]


class DescribeStreamSummaryOutput(TypedDict, total=False):
    StreamDescriptionSummary: StreamDescriptionSummary


class DisableEnhancedMonitoringInput(ServiceRequest):
    StreamName: StreamName
    ShardLevelMetrics: MetricsNameList


class EnableEnhancedMonitoringInput(ServiceRequest):
    StreamName: StreamName
    ShardLevelMetrics: MetricsNameList


class EnhancedMonitoringOutput(TypedDict, total=False):
    StreamName: Optional[StreamName]
    CurrentShardLevelMetrics: Optional[MetricsNameList]
    DesiredShardLevelMetrics: Optional[MetricsNameList]


class GetRecordsInput(ServiceRequest):
    ShardIterator: ShardIterator
    Limit: Optional[GetRecordsInputLimit]


MillisBehindLatest = int


class Record(TypedDict, total=False):
    SequenceNumber: SequenceNumber
    ApproximateArrivalTimestamp: Optional[Timestamp]
    Data: Data
    PartitionKey: PartitionKey
    EncryptionType: Optional[EncryptionType]


RecordList = List[Record]


class GetRecordsOutput(TypedDict, total=False):
    Records: RecordList
    NextShardIterator: Optional[ShardIterator]
    MillisBehindLatest: Optional[MillisBehindLatest]
    ChildShards: Optional[ChildShardList]


class GetShardIteratorInput(ServiceRequest):
    StreamName: StreamName
    ShardId: ShardId
    ShardIteratorType: ShardIteratorType
    StartingSequenceNumber: Optional[SequenceNumber]
    Timestamp: Optional[Timestamp]


class GetShardIteratorOutput(TypedDict, total=False):
    ShardIterator: Optional[ShardIterator]


class IncreaseStreamRetentionPeriodInput(ServiceRequest):
    StreamName: StreamName
    RetentionPeriodHours: RetentionPeriodHours


class ShardFilter(TypedDict, total=False):
    Type: ShardFilterType
    ShardId: Optional[ShardId]
    Timestamp: Optional[Timestamp]


class ListShardsInput(ServiceRequest):
    StreamName: Optional[StreamName]
    NextToken: Optional[NextToken]
    ExclusiveStartShardId: Optional[ShardId]
    MaxResults: Optional[ListShardsInputLimit]
    StreamCreationTimestamp: Optional[Timestamp]
    ShardFilter: Optional[ShardFilter]


class ListShardsOutput(TypedDict, total=False):
    Shards: Optional[ShardList]
    NextToken: Optional[NextToken]


class ListStreamConsumersInput(ServiceRequest):
    StreamARN: StreamARN
    NextToken: Optional[NextToken]
    MaxResults: Optional[ListStreamConsumersInputLimit]
    StreamCreationTimestamp: Optional[Timestamp]


class ListStreamConsumersOutput(TypedDict, total=False):
    Consumers: Optional[ConsumerList]
    NextToken: Optional[NextToken]


class ListStreamsInput(ServiceRequest):
    Limit: Optional[ListStreamsInputLimit]
    ExclusiveStartStreamName: Optional[StreamName]


StreamNameList = List[StreamName]


class ListStreamsOutput(TypedDict, total=False):
    StreamNames: StreamNameList
    HasMoreStreams: BooleanObject


class ListTagsForStreamInput(ServiceRequest):
    StreamName: StreamName
    ExclusiveStartTagKey: Optional[TagKey]
    Limit: Optional[ListTagsForStreamInputLimit]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class ListTagsForStreamOutput(TypedDict, total=False):
    Tags: TagList
    HasMoreTags: BooleanObject


class MergeShardsInput(ServiceRequest):
    StreamName: StreamName
    ShardToMerge: ShardId
    AdjacentShardToMerge: ShardId


class PutRecordInput(ServiceRequest):
    StreamName: StreamName
    Data: Data
    PartitionKey: PartitionKey
    ExplicitHashKey: Optional[HashKey]
    SequenceNumberForOrdering: Optional[SequenceNumber]


class PutRecordOutput(TypedDict, total=False):
    ShardId: ShardId
    SequenceNumber: SequenceNumber
    EncryptionType: Optional[EncryptionType]


class PutRecordsRequestEntry(TypedDict, total=False):
    Data: Data
    ExplicitHashKey: Optional[HashKey]
    PartitionKey: PartitionKey


PutRecordsRequestEntryList = List[PutRecordsRequestEntry]


class PutRecordsInput(ServiceRequest):
    Records: PutRecordsRequestEntryList
    StreamName: StreamName


class PutRecordsResultEntry(TypedDict, total=False):
    SequenceNumber: Optional[SequenceNumber]
    ShardId: Optional[ShardId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutRecordsResultEntryList = List[PutRecordsResultEntry]


class PutRecordsOutput(TypedDict, total=False):
    FailedRecordCount: Optional[PositiveIntegerObject]
    Records: PutRecordsResultEntryList
    EncryptionType: Optional[EncryptionType]


class RegisterStreamConsumerInput(ServiceRequest):
    StreamARN: StreamARN
    ConsumerName: ConsumerName


class RegisterStreamConsumerOutput(TypedDict, total=False):
    Consumer: Consumer


TagKeyList = List[TagKey]


class RemoveTagsFromStreamInput(ServiceRequest):
    StreamName: StreamName
    TagKeys: TagKeyList


class SplitShardInput(ServiceRequest):
    StreamName: StreamName
    ShardToSplit: ShardId
    NewStartingHashKey: HashKey


class StartStreamEncryptionInput(ServiceRequest):
    StreamName: StreamName
    EncryptionType: EncryptionType
    KeyId: KeyId


class StartingPosition(TypedDict, total=False):
    Type: ShardIteratorType
    SequenceNumber: Optional[SequenceNumber]
    Timestamp: Optional[Timestamp]


class StopStreamEncryptionInput(ServiceRequest):
    StreamName: StreamName
    EncryptionType: EncryptionType
    KeyId: KeyId


class SubscribeToShardEvent(TypedDict, total=False):
    Records: RecordList
    ContinuationSequenceNumber: SequenceNumber
    MillisBehindLatest: MillisBehindLatest
    ChildShards: Optional[ChildShardList]


class SubscribeToShardEventStream(TypedDict, total=False):
    SubscribeToShardEvent: SubscribeToShardEvent
    ResourceNotFoundException: Optional[ResourceNotFoundException]
    ResourceInUseException: Optional[ResourceInUseException]
    KMSDisabledException: Optional[KMSDisabledException]
    KMSInvalidStateException: Optional[KMSInvalidStateException]
    KMSAccessDeniedException: Optional[KMSAccessDeniedException]
    KMSNotFoundException: Optional[KMSNotFoundException]
    KMSOptInRequired: Optional[KMSOptInRequired]
    KMSThrottlingException: Optional[KMSThrottlingException]
    InternalFailureException: Optional[InternalFailureException]


class SubscribeToShardInput(ServiceRequest):
    ConsumerARN: ConsumerARN
    ShardId: ShardId
    StartingPosition: StartingPosition


class SubscribeToShardOutput(TypedDict, total=False):
    EventStream: Iterator[SubscribeToShardEventStream]


class UpdateShardCountInput(ServiceRequest):
    StreamName: StreamName
    TargetShardCount: PositiveIntegerObject
    ScalingType: ScalingType


class UpdateShardCountOutput(TypedDict, total=False):
    StreamName: Optional[StreamName]
    CurrentShardCount: Optional[PositiveIntegerObject]
    TargetShardCount: Optional[PositiveIntegerObject]


class UpdateStreamModeInput(ServiceRequest):
    StreamARN: StreamARN
    StreamModeDetails: StreamModeDetails


class KinesisApi:

    service = "kinesis"
    version = "2013-12-02"

    @handler("AddTagsToStream")
    def add_tags_to_stream(
        self, context: RequestContext, stream_name: StreamName, tags: TagMap
    ) -> None:
        raise NotImplementedError

    @handler("CreateStream")
    def create_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_count: PositiveIntegerObject = None,
        stream_mode_details: StreamModeDetails = None,
    ) -> None:
        raise NotImplementedError

    @handler("DecreaseStreamRetentionPeriod")
    def decrease_stream_retention_period(
        self,
        context: RequestContext,
        stream_name: StreamName,
        retention_period_hours: RetentionPeriodHours,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStream")
    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        enforce_consumer_deletion: BooleanObject = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeregisterStreamConsumer")
    def deregister_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = None,
        consumer_name: ConsumerName = None,
        consumer_arn: ConsumerARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeLimits")
    def describe_limits(
        self,
        context: RequestContext,
    ) -> DescribeLimitsOutput:
        raise NotImplementedError

    @handler("DescribeStream")
    def describe_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        limit: DescribeStreamInputLimit = None,
        exclusive_start_shard_id: ShardId = None,
    ) -> DescribeStreamOutput:
        raise NotImplementedError

    @handler("DescribeStreamConsumer")
    def describe_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = None,
        consumer_name: ConsumerName = None,
        consumer_arn: ConsumerARN = None,
    ) -> DescribeStreamConsumerOutput:
        raise NotImplementedError

    @handler("DescribeStreamSummary")
    def describe_stream_summary(
        self, context: RequestContext, stream_name: StreamName
    ) -> DescribeStreamSummaryOutput:
        raise NotImplementedError

    @handler("DisableEnhancedMonitoring")
    def disable_enhanced_monitoring(
        self, context: RequestContext, stream_name: StreamName, shard_level_metrics: MetricsNameList
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("EnableEnhancedMonitoring")
    def enable_enhanced_monitoring(
        self, context: RequestContext, stream_name: StreamName, shard_level_metrics: MetricsNameList
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("GetRecords")
    def get_records(
        self,
        context: RequestContext,
        shard_iterator: ShardIterator,
        limit: GetRecordsInputLimit = None,
    ) -> GetRecordsOutput:
        raise NotImplementedError

    @handler("GetShardIterator")
    def get_shard_iterator(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        starting_sequence_number: SequenceNumber = None,
        timestamp: Timestamp = None,
    ) -> GetShardIteratorOutput:
        raise NotImplementedError

    @handler("IncreaseStreamRetentionPeriod")
    def increase_stream_retention_period(
        self,
        context: RequestContext,
        stream_name: StreamName,
        retention_period_hours: RetentionPeriodHours,
    ) -> None:
        raise NotImplementedError

    @handler("ListShards")
    def list_shards(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        next_token: NextToken = None,
        exclusive_start_shard_id: ShardId = None,
        max_results: ListShardsInputLimit = None,
        stream_creation_timestamp: Timestamp = None,
        shard_filter: ShardFilter = None,
    ) -> ListShardsOutput:
        raise NotImplementedError

    @handler("ListStreamConsumers")
    def list_stream_consumers(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        next_token: NextToken = None,
        max_results: ListStreamConsumersInputLimit = None,
        stream_creation_timestamp: Timestamp = None,
    ) -> ListStreamConsumersOutput:
        raise NotImplementedError

    @handler("ListStreams")
    def list_streams(
        self,
        context: RequestContext,
        limit: ListStreamsInputLimit = None,
        exclusive_start_stream_name: StreamName = None,
    ) -> ListStreamsOutput:
        raise NotImplementedError

    @handler("ListTagsForStream")
    def list_tags_for_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForStreamInputLimit = None,
    ) -> ListTagsForStreamOutput:
        raise NotImplementedError

    @handler("MergeShards")
    def merge_shards(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_to_merge: ShardId,
        adjacent_shard_to_merge: ShardId,
    ) -> None:
        raise NotImplementedError

    @handler("PutRecord")
    def put_record(
        self,
        context: RequestContext,
        stream_name: StreamName,
        data: Data,
        partition_key: PartitionKey,
        explicit_hash_key: HashKey = None,
        sequence_number_for_ordering: SequenceNumber = None,
    ) -> PutRecordOutput:
        raise NotImplementedError

    @handler("PutRecords")
    def put_records(
        self, context: RequestContext, records: PutRecordsRequestEntryList, stream_name: StreamName
    ) -> PutRecordsOutput:
        raise NotImplementedError

    @handler("RegisterStreamConsumer")
    def register_stream_consumer(
        self, context: RequestContext, stream_arn: StreamARN, consumer_name: ConsumerName
    ) -> RegisterStreamConsumerOutput:
        raise NotImplementedError

    @handler("RemoveTagsFromStream")
    def remove_tags_from_stream(
        self, context: RequestContext, stream_name: StreamName, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("SplitShard")
    def split_shard(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_to_split: ShardId,
        new_starting_hash_key: HashKey,
    ) -> None:
        raise NotImplementedError

    @handler("StartStreamEncryption")
    def start_stream_encryption(
        self,
        context: RequestContext,
        stream_name: StreamName,
        encryption_type: EncryptionType,
        key_id: KeyId,
    ) -> None:
        raise NotImplementedError

    @handler("StopStreamEncryption")
    def stop_stream_encryption(
        self,
        context: RequestContext,
        stream_name: StreamName,
        encryption_type: EncryptionType,
        key_id: KeyId,
    ) -> None:
        raise NotImplementedError

    @handler("SubscribeToShard")
    def subscribe_to_shard(
        self,
        context: RequestContext,
        consumer_arn: ConsumerARN,
        shard_id: ShardId,
        starting_position: StartingPosition,
    ) -> SubscribeToShardOutput:
        raise NotImplementedError

    @handler("UpdateShardCount")
    def update_shard_count(
        self,
        context: RequestContext,
        stream_name: StreamName,
        target_shard_count: PositiveIntegerObject,
        scaling_type: ScalingType,
    ) -> UpdateShardCountOutput:
        raise NotImplementedError

    @handler("UpdateStreamMode")
    def update_stream_mode(
        self, context: RequestContext, stream_arn: StreamARN, stream_mode_details: StreamModeDetails
    ) -> None:
        raise NotImplementedError
