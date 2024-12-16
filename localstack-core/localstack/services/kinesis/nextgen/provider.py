from localstack.aws.api import RequestContext
from localstack.aws.api.kinesis import (
    BooleanObject,
    ConsumerARN,
    ConsumerName,
    Data,
    DescribeStreamConsumerOutput,
    DescribeStreamInputLimit,
    DescribeStreamOutput,
    DescribeStreamSummaryOutput,
    EncryptionType,
    GetRecordsInputLimit,
    GetRecordsOutput,
    GetResourcePolicyOutput,
    HashKey,
    KeyId,
    KinesisApi,
    ListShardsInputLimit,
    ListShardsOutput,
    ListStreamConsumersInputLimit,
    ListStreamConsumersOutput,
    ListStreamsInputLimit,
    ListStreamsOutput,
    ListTagsForStreamInputLimit,
    ListTagsForStreamOutput,
    NextToken,
    PartitionKey,
    Policy,
    PositiveIntegerObject,
    PutRecordOutput,
    PutRecordsOutput,
    PutRecordsRequestEntryList,
    RegisterStreamConsumerOutput,
    ResourceARN,
    RetentionPeriodHours,
    ScalingType,
    SequenceNumber,
    ShardFilter,
    ShardId,
    ShardIterator,
    StartingPosition,
    StreamARN,
    StreamModeDetails,
    StreamName,
    SubscribeToShardOutput,
    TagKey,
    TagKeyList,
    TagMap,
    Timestamp,
    UpdateShardCountOutput,
)


class KinesisProvider(KinesisApi):
    #
    # Streams CRUD
    #

    def create_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_count: PositiveIntegerObject = None,
        stream_mode_details: StreamModeDetails = None,
        tags: TagMap = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def describe_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        limit: DescribeStreamInputLimit = None,
        exclusive_start_shard_id: ShardId = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> DescribeStreamOutput:
        raise NotImplementedError

    def describe_stream_summary(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> DescribeStreamSummaryOutput:
        raise NotImplementedError

    def list_streams(
        self,
        context: RequestContext,
        limit: ListStreamsInputLimit = None,
        exclusive_start_stream_name: StreamName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListStreamsOutput:
        raise NotImplementedError

    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        enforce_consumer_deletion: BooleanObject = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    #
    # Stream modes
    #

    def update_stream_mode(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        stream_mode_details: StreamModeDetails,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    #
    # Stream retention
    #

    def increase_stream_retention_period(
        self,
        context: RequestContext,
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def decrease_stream_retention_period(
        self,
        context: RequestContext,
        retention_period_hours: RetentionPeriodHours,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    #
    # Stream tagging
    #

    def add_tags_to_stream(
        self,
        context: RequestContext,
        tags: TagMap,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def list_tags_for_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForStreamInputLimit = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> ListTagsForStreamOutput:
        raise NotImplementedError

    def remove_tags_from_stream(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    #
    # Shards CRUD
    #

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
        **kwargs,
    ) -> ListShardsOutput:
        raise NotImplementedError

    def merge_shards(
        self,
        context: RequestContext,
        shard_to_merge: ShardId,
        adjacent_shard_to_merge: ShardId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def split_shard(
        self,
        context: RequestContext,
        shard_to_split: ShardId,
        new_starting_hash_key: HashKey,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def update_shard_count(
        self,
        context: RequestContext,
        target_shard_count: PositiveIntegerObject,
        scaling_type: ScalingType,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> UpdateShardCountOutput:
        raise NotImplementedError

    #
    # Records
    #

    def get_records(
        self,
        context: RequestContext,
        shard_iterator: ShardIterator,
        limit: GetRecordsInputLimit = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> GetRecordsOutput:
        raise NotImplementedError

    def put_record(
        self,
        context: RequestContext,
        data: Data,
        partition_key: PartitionKey,
        stream_name: StreamName = None,
        explicit_hash_key: HashKey = None,
        sequence_number_for_ordering: SequenceNumber = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> PutRecordOutput:
        raise NotImplementedError

    def put_records(
        self,
        context: RequestContext,
        records: PutRecordsRequestEntryList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> PutRecordsOutput:
        raise NotImplementedError

    #
    # Stream consumers
    #

    def register_stream_consumer(
        self, context: RequestContext, stream_arn: StreamARN, consumer_name: ConsumerName, **kwargs
    ) -> RegisterStreamConsumerOutput:
        raise NotImplementedError

    def describe_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = None,
        consumer_name: ConsumerName = None,
        consumer_arn: ConsumerARN = None,
        **kwargs,
    ) -> DescribeStreamConsumerOutput:
        raise NotImplementedError

    def list_stream_consumers(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        next_token: NextToken = None,
        max_results: ListStreamConsumersInputLimit = None,
        stream_creation_timestamp: Timestamp = None,
        **kwargs,
    ) -> ListStreamConsumersOutput:
        raise NotImplementedError

    def deregister_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = None,
        consumer_name: ConsumerName = None,
        consumer_arn: ConsumerARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def subscribe_to_shard(
        self,
        context: RequestContext,
        consumer_arn: ConsumerARN,
        shard_id: ShardId,
        starting_position: StartingPosition,
        **kwargs,
    ) -> SubscribeToShardOutput:
        raise NotImplementedError

    #
    # Encryption
    #

    def start_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    def stop_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    #
    # Resource Policies
    #

    def get_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, **kwargs
    ) -> GetResourcePolicyOutput:
        raise NotImplementedError

    def put_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, policy: Policy, **kwargs
    ) -> None:
        raise NotImplementedError

    def delete_resource_policy(
        self, context: RequestContext, resource_arn: ResourceARN, **kwargs
    ) -> None:
        raise NotImplementedError
