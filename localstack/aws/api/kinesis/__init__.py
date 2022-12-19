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


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class ExpiredIteratorException(ServiceException):
    code: str = "ExpiredIteratorException"
    sender_fault: bool = False
    status_code: int = 400


class ExpiredNextTokenException(ServiceException):
    code: str = "ExpiredNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InternalFailureException(ServiceException):
    code: str = "InternalFailureException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArgumentException(ServiceException):
    code: str = "InvalidArgumentException"
    sender_fault: bool = False
    status_code: int = 400


class KMSAccessDeniedException(ServiceException):
    code: str = "KMSAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class KMSDisabledException(ServiceException):
    code: str = "KMSDisabledException"
    sender_fault: bool = False
    status_code: int = 400


class KMSInvalidStateException(ServiceException):
    code: str = "KMSInvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class KMSNotFoundException(ServiceException):
    code: str = "KMSNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class KMSOptInRequired(ServiceException):
    code: str = "KMSOptInRequired"
    sender_fault: bool = False
    status_code: int = 400


class KMSThrottlingException(ServiceException):
    code: str = "KMSThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ProvisionedThroughputExceededException(ServiceException):
    code: str = "ProvisionedThroughputExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


TagMap = Dict[TagKey, TagValue]


class AddTagsToStreamInput(ServiceRequest):
    StreamName: Optional[StreamName]
    Tags: TagMap
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    RetentionPeriodHours: RetentionPeriodHours
    StreamARN: Optional[StreamARN]


class DeleteStreamInput(ServiceRequest):
    StreamName: Optional[StreamName]
    EnforceConsumerDeletion: Optional[BooleanObject]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    Limit: Optional[DescribeStreamInputLimit]
    ExclusiveStartShardId: Optional[ShardId]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    ShardLevelMetrics: MetricsNameList
    StreamARN: Optional[StreamARN]


class EnableEnhancedMonitoringInput(ServiceRequest):
    StreamName: Optional[StreamName]
    ShardLevelMetrics: MetricsNameList
    StreamARN: Optional[StreamARN]


class EnhancedMonitoringOutput(TypedDict, total=False):
    StreamName: Optional[StreamName]
    CurrentShardLevelMetrics: Optional[MetricsNameList]
    DesiredShardLevelMetrics: Optional[MetricsNameList]
    StreamARN: Optional[StreamARN]


class GetRecordsInput(ServiceRequest):
    ShardIterator: ShardIterator
    Limit: Optional[GetRecordsInputLimit]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    ShardId: ShardId
    ShardIteratorType: ShardIteratorType
    StartingSequenceNumber: Optional[SequenceNumber]
    Timestamp: Optional[Timestamp]
    StreamARN: Optional[StreamARN]


class GetShardIteratorOutput(TypedDict, total=False):
    ShardIterator: Optional[ShardIterator]


class IncreaseStreamRetentionPeriodInput(ServiceRequest):
    StreamName: Optional[StreamName]
    RetentionPeriodHours: RetentionPeriodHours
    StreamARN: Optional[StreamARN]


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
    StreamARN: Optional[StreamARN]


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
    NextToken: Optional[NextToken]


class StreamSummary(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: Optional[StreamModeDetails]
    StreamCreationTimestamp: Optional[Timestamp]


StreamSummaryList = List[StreamSummary]
StreamNameList = List[StreamName]


class ListStreamsOutput(TypedDict, total=False):
    StreamNames: StreamNameList
    HasMoreStreams: BooleanObject
    NextToken: Optional[NextToken]
    StreamSummaries: Optional[StreamSummaryList]


class ListTagsForStreamInput(ServiceRequest):
    StreamName: Optional[StreamName]
    ExclusiveStartTagKey: Optional[TagKey]
    Limit: Optional[ListTagsForStreamInputLimit]
    StreamARN: Optional[StreamARN]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class ListTagsForStreamOutput(TypedDict, total=False):
    Tags: TagList
    HasMoreTags: BooleanObject


class MergeShardsInput(ServiceRequest):
    StreamName: Optional[StreamName]
    ShardToMerge: ShardId
    AdjacentShardToMerge: ShardId
    StreamARN: Optional[StreamARN]


class PutRecordInput(ServiceRequest):
    StreamName: Optional[StreamName]
    Data: Data
    PartitionKey: PartitionKey
    ExplicitHashKey: Optional[HashKey]
    SequenceNumberForOrdering: Optional[SequenceNumber]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    TagKeys: TagKeyList
    StreamARN: Optional[StreamARN]


class SplitShardInput(ServiceRequest):
    StreamName: Optional[StreamName]
    ShardToSplit: ShardId
    NewStartingHashKey: HashKey
    StreamARN: Optional[StreamARN]


class StartStreamEncryptionInput(ServiceRequest):
    StreamName: Optional[StreamName]
    EncryptionType: EncryptionType
    KeyId: KeyId
    StreamARN: Optional[StreamARN]


class StartingPosition(TypedDict, total=False):
    Type: ShardIteratorType
    SequenceNumber: Optional[SequenceNumber]
    Timestamp: Optional[Timestamp]


class StopStreamEncryptionInput(ServiceRequest):
    StreamName: Optional[StreamName]
    EncryptionType: EncryptionType
    KeyId: KeyId
    StreamARN: Optional[StreamARN]


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
    StreamName: Optional[StreamName]
    TargetShardCount: PositiveIntegerObject
    ScalingType: ScalingType
    StreamARN: Optional[StreamARN]


class UpdateShardCountOutput(TypedDict, total=False):
    StreamName: Optional[StreamName]
    CurrentShardCount: Optional[PositiveIntegerObject]
    TargetShardCount: Optional[PositiveIntegerObject]
    StreamARN: Optional[StreamARN]


class UpdateStreamModeInput(ServiceRequest):
    StreamARN: StreamARN
    StreamModeDetails: StreamModeDetails


class KinesisApi:

    service = "kinesis"
    version = "2013-12-02"

    @handler("AddTagsToStream")
    def add_tags_to_stream(
        self,
        context: RequestContext,
        tags: TagMap,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
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
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStream")
    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        enforce_consumer_deletion: BooleanObject = None,
        stream_arn: StreamARN = None,
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
        stream_name: StreamName = None,
        limit: DescribeStreamInputLimit = None,
        exclusive_start_shard_id: ShardId = None,
        stream_arn: StreamARN = None,
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
        self, context: RequestContext, stream_name: StreamName = None, stream_arn: StreamARN = None
    ) -> DescribeStreamSummaryOutput:
        raise NotImplementedError

    @handler("DisableEnhancedMonitoring")
    def disable_enhanced_monitoring(
        self,
        context: RequestContext,
        shard_level_metrics: MetricsNameList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("EnableEnhancedMonitoring")
    def enable_enhanced_monitoring(
        self,
        context: RequestContext,
        shard_level_metrics: MetricsNameList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("GetRecords")
    def get_records(
        self,
        context: RequestContext,
        shard_iterator: ShardIterator,
        limit: GetRecordsInputLimit = None,
        stream_arn: StreamARN = None,
    ) -> GetRecordsOutput:
        raise NotImplementedError

    @handler("GetShardIterator")
    def get_shard_iterator(
        self,
        context: RequestContext,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        stream_name: StreamName = None,
        starting_sequence_number: SequenceNumber = None,
        timestamp: Timestamp = None,
        stream_arn: StreamARN = None,
    ) -> GetShardIteratorOutput:
        raise NotImplementedError

    @handler("IncreaseStreamRetentionPeriod")
    def increase_stream_retention_period(
        self,
        context: RequestContext,
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
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
        stream_arn: StreamARN = None,
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
        next_token: NextToken = None,
    ) -> ListStreamsOutput:
        raise NotImplementedError

    @handler("ListTagsForStream")
    def list_tags_for_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForStreamInputLimit = None,
        stream_arn: StreamARN = None,
    ) -> ListTagsForStreamOutput:
        raise NotImplementedError

    @handler("MergeShards")
    def merge_shards(
        self,
        context: RequestContext,
        shard_to_merge: ShardId,
        adjacent_shard_to_merge: ShardId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutRecord")
    def put_record(
        self,
        context: RequestContext,
        data: Data,
        partition_key: PartitionKey,
        stream_name: StreamName = None,
        explicit_hash_key: HashKey = None,
        sequence_number_for_ordering: SequenceNumber = None,
        stream_arn: StreamARN = None,
    ) -> PutRecordOutput:
        raise NotImplementedError

    @handler("PutRecords")
    def put_records(
        self,
        context: RequestContext,
        records: PutRecordsRequestEntryList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> PutRecordsOutput:
        raise NotImplementedError

    @handler("RegisterStreamConsumer")
    def register_stream_consumer(
        self, context: RequestContext, stream_arn: StreamARN, consumer_name: ConsumerName
    ) -> RegisterStreamConsumerOutput:
        raise NotImplementedError

    @handler("RemoveTagsFromStream")
    def remove_tags_from_stream(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("SplitShard")
    def split_shard(
        self,
        context: RequestContext,
        shard_to_split: ShardId,
        new_starting_hash_key: HashKey,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("StartStreamEncryption")
    def start_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> None:
        raise NotImplementedError

    @handler("StopStreamEncryption")
    def stop_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
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
        target_shard_count: PositiveIntegerObject,
        scaling_type: ScalingType,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
    ) -> UpdateShardCountOutput:
        raise NotImplementedError

    @handler("UpdateStreamMode")
    def update_stream_mode(
        self, context: RequestContext, stream_arn: StreamARN, stream_mode_details: StreamModeDetails
    ) -> None:
        raise NotImplementedError
