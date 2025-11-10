from collections.abc import Iterator
from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
MaxRecordSizeInKiB = int
NaturalIntegerObject = int
NextToken = str
OnDemandStreamCountLimitObject = int
OnDemandStreamCountObject = int
PartitionKey = str
Policy = str
PositiveIntegerObject = int
ResourceARN = str
RetentionPeriodHours = int
SequenceNumber = str
ShardCountObject = int
ShardId = str
ShardIterator = str
StreamARN = str
StreamName = str
TagKey = str
TagValue = str


class ConsumerStatus(StrEnum):
    CREATING = "CREATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"


class EncryptionType(StrEnum):
    NONE = "NONE"
    KMS = "KMS"


class MetricsName(StrEnum):
    IncomingBytes = "IncomingBytes"
    IncomingRecords = "IncomingRecords"
    OutgoingBytes = "OutgoingBytes"
    OutgoingRecords = "OutgoingRecords"
    WriteProvisionedThroughputExceeded = "WriteProvisionedThroughputExceeded"
    ReadProvisionedThroughputExceeded = "ReadProvisionedThroughputExceeded"
    IteratorAgeMilliseconds = "IteratorAgeMilliseconds"
    ALL = "ALL"


class MinimumThroughputBillingCommitmentInputStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class MinimumThroughputBillingCommitmentOutputStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ENABLED_UNTIL_EARLIEST_ALLOWED_END = "ENABLED_UNTIL_EARLIEST_ALLOWED_END"


class ScalingType(StrEnum):
    UNIFORM_SCALING = "UNIFORM_SCALING"


class ShardFilterType(StrEnum):
    AFTER_SHARD_ID = "AFTER_SHARD_ID"
    AT_TRIM_HORIZON = "AT_TRIM_HORIZON"
    FROM_TRIM_HORIZON = "FROM_TRIM_HORIZON"
    AT_LATEST = "AT_LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"
    FROM_TIMESTAMP = "FROM_TIMESTAMP"


class ShardIteratorType(StrEnum):
    AT_SEQUENCE_NUMBER = "AT_SEQUENCE_NUMBER"
    AFTER_SEQUENCE_NUMBER = "AFTER_SEQUENCE_NUMBER"
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_TIMESTAMP = "AT_TIMESTAMP"


class StreamMode(StrEnum):
    PROVISIONED = "PROVISIONED"
    ON_DEMAND = "ON_DEMAND"


class StreamStatus(StrEnum):
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


TagMap = dict[TagKey, TagValue]


class AddTagsToStreamInput(ServiceRequest):
    StreamName: StreamName | None
    Tags: TagMap
    StreamARN: StreamARN | None


class HashKeyRange(TypedDict, total=False):
    StartingHashKey: HashKey
    EndingHashKey: HashKey


ShardIdList = list[ShardId]


class ChildShard(TypedDict, total=False):
    ShardId: ShardId
    ParentShards: ShardIdList
    HashKeyRange: HashKeyRange


ChildShardList = list[ChildShard]
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


ConsumerList = list[Consumer]


class StreamModeDetails(TypedDict, total=False):
    StreamMode: StreamMode


class CreateStreamInput(ServiceRequest):
    StreamName: StreamName
    ShardCount: PositiveIntegerObject | None
    StreamModeDetails: StreamModeDetails | None
    Tags: TagMap | None
    WarmThroughputMiBps: NaturalIntegerObject | None
    MaxRecordSizeInKiB: MaxRecordSizeInKiB | None


Data = bytes


class DecreaseStreamRetentionPeriodInput(ServiceRequest):
    StreamName: StreamName | None
    RetentionPeriodHours: RetentionPeriodHours
    StreamARN: StreamARN | None


class DeleteResourcePolicyInput(ServiceRequest):
    ResourceARN: ResourceARN


class DeleteStreamInput(ServiceRequest):
    StreamName: StreamName | None
    EnforceConsumerDeletion: BooleanObject | None
    StreamARN: StreamARN | None


class DeregisterStreamConsumerInput(ServiceRequest):
    StreamARN: StreamARN | None
    ConsumerName: ConsumerName | None
    ConsumerARN: ConsumerARN | None


class DescribeAccountSettingsInput(ServiceRequest):
    pass


class MinimumThroughputBillingCommitmentOutput(TypedDict, total=False):
    Status: MinimumThroughputBillingCommitmentOutputStatus
    StartedAt: Timestamp | None
    EndedAt: Timestamp | None
    EarliestAllowedEndAt: Timestamp | None


class DescribeAccountSettingsOutput(TypedDict, total=False):
    MinimumThroughputBillingCommitment: MinimumThroughputBillingCommitmentOutput | None


class DescribeLimitsInput(ServiceRequest):
    pass


class DescribeLimitsOutput(TypedDict, total=False):
    ShardLimit: ShardCountObject
    OpenShardCount: ShardCountObject
    OnDemandStreamCount: OnDemandStreamCountObject
    OnDemandStreamCountLimit: OnDemandStreamCountLimitObject


class DescribeStreamConsumerInput(ServiceRequest):
    StreamARN: StreamARN | None
    ConsumerName: ConsumerName | None
    ConsumerARN: ConsumerARN | None


class DescribeStreamConsumerOutput(TypedDict, total=False):
    ConsumerDescription: ConsumerDescription


class DescribeStreamInput(ServiceRequest):
    StreamName: StreamName | None
    Limit: DescribeStreamInputLimit | None
    ExclusiveStartShardId: ShardId | None
    StreamARN: StreamARN | None


MetricsNameList = list[MetricsName]


class EnhancedMetrics(TypedDict, total=False):
    ShardLevelMetrics: MetricsNameList | None


EnhancedMonitoringList = list[EnhancedMetrics]


class SequenceNumberRange(TypedDict, total=False):
    StartingSequenceNumber: SequenceNumber
    EndingSequenceNumber: SequenceNumber | None


class Shard(TypedDict, total=False):
    ShardId: ShardId
    ParentShardId: ShardId | None
    AdjacentParentShardId: ShardId | None
    HashKeyRange: HashKeyRange
    SequenceNumberRange: SequenceNumberRange


ShardList = list[Shard]


class StreamDescription(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: StreamModeDetails | None
    Shards: ShardList
    HasMoreShards: BooleanObject
    RetentionPeriodHours: RetentionPeriodHours
    StreamCreationTimestamp: Timestamp
    EnhancedMonitoring: EnhancedMonitoringList
    EncryptionType: EncryptionType | None
    KeyId: KeyId | None


class DescribeStreamOutput(TypedDict, total=False):
    StreamDescription: StreamDescription


class DescribeStreamSummaryInput(ServiceRequest):
    StreamName: StreamName | None
    StreamARN: StreamARN | None


class WarmThroughputObject(TypedDict, total=False):
    TargetMiBps: NaturalIntegerObject | None
    CurrentMiBps: NaturalIntegerObject | None


class StreamDescriptionSummary(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: StreamModeDetails | None
    RetentionPeriodHours: RetentionPeriodHours
    StreamCreationTimestamp: Timestamp
    EnhancedMonitoring: EnhancedMonitoringList
    EncryptionType: EncryptionType | None
    KeyId: KeyId | None
    OpenShardCount: ShardCountObject
    ConsumerCount: ConsumerCountObject | None
    WarmThroughput: WarmThroughputObject | None
    MaxRecordSizeInKiB: MaxRecordSizeInKiB | None


class DescribeStreamSummaryOutput(TypedDict, total=False):
    StreamDescriptionSummary: StreamDescriptionSummary


class DisableEnhancedMonitoringInput(ServiceRequest):
    StreamName: StreamName | None
    ShardLevelMetrics: MetricsNameList
    StreamARN: StreamARN | None


class EnableEnhancedMonitoringInput(ServiceRequest):
    StreamName: StreamName | None
    ShardLevelMetrics: MetricsNameList
    StreamARN: StreamARN | None


class EnhancedMonitoringOutput(TypedDict, total=False):
    StreamName: StreamName | None
    CurrentShardLevelMetrics: MetricsNameList | None
    DesiredShardLevelMetrics: MetricsNameList | None
    StreamARN: StreamARN | None


class GetRecordsInput(ServiceRequest):
    ShardIterator: ShardIterator
    Limit: GetRecordsInputLimit | None
    StreamARN: StreamARN | None


MillisBehindLatest = int


class Record(TypedDict, total=False):
    SequenceNumber: SequenceNumber
    ApproximateArrivalTimestamp: Timestamp | None
    Data: Data
    PartitionKey: PartitionKey
    EncryptionType: EncryptionType | None


RecordList = list[Record]


class GetRecordsOutput(TypedDict, total=False):
    Records: RecordList
    NextShardIterator: ShardIterator | None
    MillisBehindLatest: MillisBehindLatest | None
    ChildShards: ChildShardList | None


class GetResourcePolicyInput(ServiceRequest):
    ResourceARN: ResourceARN


class GetResourcePolicyOutput(TypedDict, total=False):
    Policy: Policy


class GetShardIteratorInput(ServiceRequest):
    StreamName: StreamName | None
    ShardId: ShardId
    ShardIteratorType: ShardIteratorType
    StartingSequenceNumber: SequenceNumber | None
    Timestamp: Timestamp | None
    StreamARN: StreamARN | None


class GetShardIteratorOutput(TypedDict, total=False):
    ShardIterator: ShardIterator | None


class IncreaseStreamRetentionPeriodInput(ServiceRequest):
    StreamName: StreamName | None
    RetentionPeriodHours: RetentionPeriodHours
    StreamARN: StreamARN | None


class ShardFilter(TypedDict, total=False):
    Type: ShardFilterType
    ShardId: ShardId | None
    Timestamp: Timestamp | None


class ListShardsInput(ServiceRequest):
    StreamName: StreamName | None
    NextToken: NextToken | None
    ExclusiveStartShardId: ShardId | None
    MaxResults: ListShardsInputLimit | None
    StreamCreationTimestamp: Timestamp | None
    ShardFilter: ShardFilter | None
    StreamARN: StreamARN | None


class ListShardsOutput(TypedDict, total=False):
    Shards: ShardList | None
    NextToken: NextToken | None


class ListStreamConsumersInput(ServiceRequest):
    StreamARN: StreamARN
    NextToken: NextToken | None
    MaxResults: ListStreamConsumersInputLimit | None
    StreamCreationTimestamp: Timestamp | None


class ListStreamConsumersOutput(TypedDict, total=False):
    Consumers: ConsumerList | None
    NextToken: NextToken | None


class ListStreamsInput(ServiceRequest):
    Limit: ListStreamsInputLimit | None
    ExclusiveStartStreamName: StreamName | None
    NextToken: NextToken | None


class StreamSummary(TypedDict, total=False):
    StreamName: StreamName
    StreamARN: StreamARN
    StreamStatus: StreamStatus
    StreamModeDetails: StreamModeDetails | None
    StreamCreationTimestamp: Timestamp | None


StreamSummaryList = list[StreamSummary]
StreamNameList = list[StreamName]


class ListStreamsOutput(TypedDict, total=False):
    StreamNames: StreamNameList
    HasMoreStreams: BooleanObject
    NextToken: NextToken | None
    StreamSummaries: StreamSummaryList | None


class ListTagsForResourceInput(ServiceRequest):
    ResourceARN: ResourceARN


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue | None


TagList = list[Tag]


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: TagList | None


class ListTagsForStreamInput(ServiceRequest):
    StreamName: StreamName | None
    ExclusiveStartTagKey: TagKey | None
    Limit: ListTagsForStreamInputLimit | None
    StreamARN: StreamARN | None


class ListTagsForStreamOutput(TypedDict, total=False):
    Tags: TagList
    HasMoreTags: BooleanObject


class MergeShardsInput(ServiceRequest):
    StreamName: StreamName | None
    ShardToMerge: ShardId
    AdjacentShardToMerge: ShardId
    StreamARN: StreamARN | None


class MinimumThroughputBillingCommitmentInput(TypedDict, total=False):
    Status: MinimumThroughputBillingCommitmentInputStatus


class PutRecordInput(ServiceRequest):
    StreamName: StreamName | None
    Data: Data
    PartitionKey: PartitionKey
    ExplicitHashKey: HashKey | None
    SequenceNumberForOrdering: SequenceNumber | None
    StreamARN: StreamARN | None


class PutRecordOutput(TypedDict, total=False):
    ShardId: ShardId
    SequenceNumber: SequenceNumber
    EncryptionType: EncryptionType | None


class PutRecordsRequestEntry(TypedDict, total=False):
    Data: Data
    ExplicitHashKey: HashKey | None
    PartitionKey: PartitionKey


PutRecordsRequestEntryList = list[PutRecordsRequestEntry]


class PutRecordsInput(ServiceRequest):
    Records: PutRecordsRequestEntryList
    StreamName: StreamName | None
    StreamARN: StreamARN | None


class PutRecordsResultEntry(TypedDict, total=False):
    SequenceNumber: SequenceNumber | None
    ShardId: ShardId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


PutRecordsResultEntryList = list[PutRecordsResultEntry]


class PutRecordsOutput(TypedDict, total=False):
    FailedRecordCount: PositiveIntegerObject | None
    Records: PutRecordsResultEntryList
    EncryptionType: EncryptionType | None


class PutResourcePolicyInput(ServiceRequest):
    ResourceARN: ResourceARN
    Policy: Policy


class RegisterStreamConsumerInput(ServiceRequest):
    StreamARN: StreamARN
    ConsumerName: ConsumerName
    Tags: TagMap | None


class RegisterStreamConsumerOutput(TypedDict, total=False):
    Consumer: Consumer


TagKeyList = list[TagKey]


class RemoveTagsFromStreamInput(ServiceRequest):
    StreamName: StreamName | None
    TagKeys: TagKeyList
    StreamARN: StreamARN | None


class SplitShardInput(ServiceRequest):
    StreamName: StreamName | None
    ShardToSplit: ShardId
    NewStartingHashKey: HashKey
    StreamARN: StreamARN | None


class StartStreamEncryptionInput(ServiceRequest):
    StreamName: StreamName | None
    EncryptionType: EncryptionType
    KeyId: KeyId
    StreamARN: StreamARN | None


class StartingPosition(TypedDict, total=False):
    Type: ShardIteratorType
    SequenceNumber: SequenceNumber | None
    Timestamp: Timestamp | None


class StopStreamEncryptionInput(ServiceRequest):
    StreamName: StreamName | None
    EncryptionType: EncryptionType
    KeyId: KeyId
    StreamARN: StreamARN | None


class SubscribeToShardEvent(TypedDict, total=False):
    Records: RecordList
    ContinuationSequenceNumber: SequenceNumber
    MillisBehindLatest: MillisBehindLatest
    ChildShards: ChildShardList | None


class SubscribeToShardEventStream(TypedDict, total=False):
    SubscribeToShardEvent: SubscribeToShardEvent
    ResourceNotFoundException: ResourceNotFoundException | None
    ResourceInUseException: ResourceInUseException | None
    KMSDisabledException: KMSDisabledException | None
    KMSInvalidStateException: KMSInvalidStateException | None
    KMSAccessDeniedException: KMSAccessDeniedException | None
    KMSNotFoundException: KMSNotFoundException | None
    KMSOptInRequired: KMSOptInRequired | None
    KMSThrottlingException: KMSThrottlingException | None
    InternalFailureException: InternalFailureException | None


class SubscribeToShardInput(ServiceRequest):
    ConsumerARN: ConsumerARN
    ShardId: ShardId
    StartingPosition: StartingPosition


class SubscribeToShardOutput(TypedDict, total=False):
    EventStream: Iterator[SubscribeToShardEventStream]


class TagResourceInput(ServiceRequest):
    Tags: TagMap
    ResourceARN: ResourceARN


class UntagResourceInput(ServiceRequest):
    TagKeys: TagKeyList
    ResourceARN: ResourceARN


class UpdateAccountSettingsInput(ServiceRequest):
    MinimumThroughputBillingCommitment: MinimumThroughputBillingCommitmentInput


class UpdateAccountSettingsOutput(TypedDict, total=False):
    MinimumThroughputBillingCommitment: MinimumThroughputBillingCommitmentOutput | None


class UpdateMaxRecordSizeInput(ServiceRequest):
    StreamARN: StreamARN | None
    MaxRecordSizeInKiB: MaxRecordSizeInKiB


class UpdateShardCountInput(ServiceRequest):
    StreamName: StreamName | None
    TargetShardCount: PositiveIntegerObject
    ScalingType: ScalingType
    StreamARN: StreamARN | None


class UpdateShardCountOutput(TypedDict, total=False):
    StreamName: StreamName | None
    CurrentShardCount: PositiveIntegerObject | None
    TargetShardCount: PositiveIntegerObject | None
    StreamARN: StreamARN | None


class UpdateStreamModeInput(ServiceRequest):
    StreamARN: StreamARN
    StreamModeDetails: StreamModeDetails
    WarmThroughputMiBps: NaturalIntegerObject | None


class UpdateStreamWarmThroughputInput(ServiceRequest):
    StreamARN: StreamARN | None
    StreamName: StreamName | None
    WarmThroughputMiBps: NaturalIntegerObject


class UpdateStreamWarmThroughputOutput(TypedDict, total=False):
    StreamARN: StreamARN | None
    StreamName: StreamName | None
    WarmThroughput: WarmThroughputObject | None


class KinesisApi:
    service: str = "kinesis"
    version: str = "2013-12-02"

    @handler("AddTagsToStream")
    def add_tags_to_stream(
        self,
        context: RequestContext,
        tags: TagMap,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateStream")
    def create_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_count: PositiveIntegerObject | None = None,
        stream_mode_details: StreamModeDetails | None = None,
        tags: TagMap | None = None,
        warm_throughput_mi_bps: NaturalIntegerObject | None = None,
        max_record_size_in_ki_b: MaxRecordSizeInKiB | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DecreaseStreamRetentionPeriod")
    def decrease_stream_retention_period(
        self,
        context: RequestContext,
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStream")
    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName | None = None,
        enforce_consumer_deletion: BooleanObject | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeregisterStreamConsumer")
    def deregister_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN | None = None,
        consumer_name: ConsumerName | None = None,
        consumer_arn: ConsumerARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAccountSettings")
    def describe_account_settings(
        self, context: RequestContext, **kwargs
    ) -> DescribeAccountSettingsOutput:
        raise NotImplementedError

    @handler("DescribeLimits")
    def describe_limits(self, context: RequestContext, **kwargs) -> DescribeLimitsOutput:
        raise NotImplementedError

    @handler("DescribeStream")
    def describe_stream(
        self,
        context: RequestContext,
        stream_name: StreamName | None = None,
        limit: DescribeStreamInputLimit | None = None,
        exclusive_start_shard_id: ShardId | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> DescribeStreamOutput:
        raise NotImplementedError

    @handler("DescribeStreamConsumer")
    def describe_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN | None = None,
        consumer_name: ConsumerName | None = None,
        consumer_arn: ConsumerARN | None = None,
        **kwargs,
    ) -> DescribeStreamConsumerOutput:
        raise NotImplementedError

    @handler("DescribeStreamSummary")
    def describe_stream_summary(
        self,
        context: RequestContext,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> DescribeStreamSummaryOutput:
        raise NotImplementedError

    @handler("DisableEnhancedMonitoring")
    def disable_enhanced_monitoring(
        self,
        context: RequestContext,
        shard_level_metrics: MetricsNameList,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("EnableEnhancedMonitoring")
    def enable_enhanced_monitoring(
        self,
        context: RequestContext,
        shard_level_metrics: MetricsNameList,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> EnhancedMonitoringOutput:
        raise NotImplementedError

    @handler("GetRecords")
    def get_records(
        self,
        context: RequestContext,
        shard_iterator: ShardIterator,
        limit: GetRecordsInputLimit | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> GetRecordsOutput:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, **kwargs
    ) -> GetResourcePolicyOutput:
        raise NotImplementedError

    @handler("GetShardIterator")
    def get_shard_iterator(
        self,
        context: RequestContext,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        stream_name: StreamName | None = None,
        starting_sequence_number: SequenceNumber | None = None,
        timestamp: Timestamp | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> GetShardIteratorOutput:
        raise NotImplementedError

    @handler("IncreaseStreamRetentionPeriod")
    def increase_stream_retention_period(
        self,
        context: RequestContext,
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ListShards")
    def list_shards(
        self,
        context: RequestContext,
        stream_name: StreamName | None = None,
        next_token: NextToken | None = None,
        exclusive_start_shard_id: ShardId | None = None,
        max_results: ListShardsInputLimit | None = None,
        stream_creation_timestamp: Timestamp | None = None,
        shard_filter: ShardFilter | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> ListShardsOutput:
        raise NotImplementedError

    @handler("ListStreamConsumers")
    def list_stream_consumers(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        next_token: NextToken | None = None,
        max_results: ListStreamConsumersInputLimit | None = None,
        stream_creation_timestamp: Timestamp | None = None,
        **kwargs,
    ) -> ListStreamConsumersOutput:
        raise NotImplementedError

    @handler("ListStreams")
    def list_streams(
        self,
        context: RequestContext,
        limit: ListStreamsInputLimit | None = None,
        exclusive_start_stream_name: StreamName | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListStreamsOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceARN, **kwargs
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("ListTagsForStream")
    def list_tags_for_stream(
        self,
        context: RequestContext,
        stream_name: StreamName | None = None,
        exclusive_start_tag_key: TagKey | None = None,
        limit: ListTagsForStreamInputLimit | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> ListTagsForStreamOutput:
        raise NotImplementedError

    @handler("MergeShards")
    def merge_shards(
        self,
        context: RequestContext,
        shard_to_merge: ShardId,
        adjacent_shard_to_merge: ShardId,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRecord")
    def put_record(
        self,
        context: RequestContext,
        data: Data,
        partition_key: PartitionKey,
        stream_name: StreamName | None = None,
        explicit_hash_key: HashKey | None = None,
        sequence_number_for_ordering: SequenceNumber | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> PutRecordOutput:
        raise NotImplementedError

    @handler("PutRecords")
    def put_records(
        self,
        context: RequestContext,
        records: PutRecordsRequestEntryList,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> PutRecordsOutput:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, policy: Policy, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RegisterStreamConsumer")
    def register_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        consumer_name: ConsumerName,
        tags: TagMap | None = None,
        **kwargs,
    ) -> RegisterStreamConsumerOutput:
        raise NotImplementedError

    @handler("RemoveTagsFromStream")
    def remove_tags_from_stream(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SplitShard")
    def split_shard(
        self,
        context: RequestContext,
        shard_to_split: ShardId,
        new_starting_hash_key: HashKey,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StartStreamEncryption")
    def start_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StopStreamEncryption")
    def stop_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SubscribeToShard")
    def subscribe_to_shard(
        self,
        context: RequestContext,
        consumer_arn: ConsumerARN,
        shard_id: ShardId,
        starting_position: StartingPosition,
        **kwargs,
    ) -> SubscribeToShardOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, tags: TagMap, resource_arn: ResourceARN, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, tag_keys: TagKeyList, resource_arn: ResourceARN, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAccountSettings")
    def update_account_settings(
        self,
        context: RequestContext,
        minimum_throughput_billing_commitment: MinimumThroughputBillingCommitmentInput,
        **kwargs,
    ) -> UpdateAccountSettingsOutput:
        raise NotImplementedError

    @handler("UpdateMaxRecordSize")
    def update_max_record_size(
        self,
        context: RequestContext,
        max_record_size_in_ki_b: MaxRecordSizeInKiB,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateShardCount")
    def update_shard_count(
        self,
        context: RequestContext,
        target_shard_count: PositiveIntegerObject,
        scaling_type: ScalingType,
        stream_name: StreamName | None = None,
        stream_arn: StreamARN | None = None,
        **kwargs,
    ) -> UpdateShardCountOutput:
        raise NotImplementedError

    @handler("UpdateStreamMode")
    def update_stream_mode(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        stream_mode_details: StreamModeDetails,
        warm_throughput_mi_bps: NaturalIntegerObject | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateStreamWarmThroughput")
    def update_stream_warm_throughput(
        self,
        context: RequestContext,
        warm_throughput_mi_bps: NaturalIntegerObject,
        stream_arn: StreamARN | None = None,
        stream_name: StreamName | None = None,
        **kwargs,
    ) -> UpdateStreamWarmThroughputOutput:
        raise NotImplementedError
