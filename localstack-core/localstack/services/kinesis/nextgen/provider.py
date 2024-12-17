from typing import Tuple

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
    InvalidArgumentException,
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
    ResourceNotFoundException,
    RetentionPeriodHours,
    ScalingType,
    SequenceNumber,
    ShardFilter,
    ShardId,
    ShardIterator,
    StartingPosition,
    StreamARN,
    StreamMode,
    StreamModeDetails,
    StreamName,
    StreamStatus,
    StreamSummary,
    SubscribeToShardOutput,
    TagKey,
    TagKeyList,
    TagMap,
    Timestamp,
    UpdateShardCountOutput,
)
from localstack.services.kinesis.nextgen.models import Stream, kinesis_stores
from localstack.utils.aws.arns import parse_arn
from localstack.utils.tagging import convert_to_taglist


class KinesisProvider(KinesisApi):
    @staticmethod
    def _get_stream(account_id: str, region_name: str, name: str) -> Stream:
        store = kinesis_stores[account_id][region_name]

        if name not in store.streams:
            raise ResourceNotFoundException("TODO")  # TODO

        return store.streams.get(name)

    @staticmethod
    def _resolve_stream(
        context: RequestContext, arn: str | None, name: str | None
    ) -> Tuple[str, str, str]:
        # TODO: consider invoking from _get_stream()
        if arn is None and name is None:
            raise InvalidArgumentException("TODO")  # TODO

        if arn:
            arn_data = parse_arn(arn)
            return (
                arn_data["account"],
                arn_data["region"],
                arn_data["resource"].removeprefix("stream/"),
            )

        return context.account_id, context.region, name

    @staticmethod
    def _validate_stream_mode(stream_mode_details: StreamModeDetails | None) -> str:
        stream_mode_details = stream_mode_details or {}
        mode = stream_mode_details.get("StreamMode") or StreamMode.ON_DEMAND
        if mode not in StreamMode.__members__:
            raise InvalidArgumentException("TODO")  # TODO
        return mode

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
        store = kinesis_stores[context.account_id][context.region]

        if stream_name in store.streams:
            raise InvalidArgumentException("TODO")  # TODO

        # TODO: for provisioned mode, shard count is required

        mode = self._validate_stream_mode(stream_mode_details)

        stream = Stream(
            account_id=context.account_id,
            region_name=context.region,
            name=stream_name,
            mode=mode,
            shard_count=shard_count,
        )

        store.streams[stream_name] = stream

        if tags:
            tag_list = convert_to_taglist(tags)
            store.TAGS.tag_resource(stream.arn, tag_list)

    def describe_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        limit: DescribeStreamInputLimit = None,
        exclusive_start_shard_id: ShardId = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> DescribeStreamOutput:
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))

        # TODO: obey exclusive_start_shard_id

        return DescribeStreamOutput(
            StreamName=stream_name,
            StreamARN=stream_arn,
            StreamCreationTimestamp=stream.created_timestamp,
            StreamModeDetails=StreamModeDetails(StreamMode=stream.mode),
            StreamStatus=StreamStatus.ACTIVE,
            RetentionPeriodHours=stream.retention_period,
            HasMoreShards=False,
            Shards=[],
        )

    def describe_stream_summary(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> DescribeStreamSummaryOutput:
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))

        return DescribeStreamSummaryOutput(
            StreamName=stream_name,
            StreamARN=stream_arn,
            StreamCreationTimestamp=stream.created_timestamp,
            StreamModeDetails=StreamModeDetails(StreamMode=stream.mode),
            StreamStatus=StreamStatus.ACTIVE,
            RetentionPeriodHours=stream.retention_period,
        )

    def list_streams(
        self,
        context: RequestContext,
        limit: ListStreamsInputLimit = None,
        exclusive_start_stream_name: StreamName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListStreamsOutput:
        store = kinesis_stores[context.account_id][context.region]

        summaries = []
        for stream in store.streams.values():
            summaries.append(
                StreamSummary(
                    StreamName=stream.name,
                    StreamARN=stream.arn,
                    StreamStatus=StreamStatus.ACTIVE,
                    StreamModeDetails=StreamModeDetails(StreamMode=stream.mode),
                    StreamCreationTimestamp=stream.created_timestamp,
                )
            )

        return ListStreamsOutput(
            HasMoreStreams=False,
            StreamNames=store.streams.keys(),
            StreamSummaries=summaries,
        )

    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        enforce_consumer_deletion: BooleanObject = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        # Check if the stream exists
        self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))

        # TODO: if enforce_consumer_deletion is set, raise ResourceInUseException if consumers are registered

        del kinesis_stores[context.account_id][context.region].streams[stream_name]

    def update_stream_mode(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        stream_mode_details: StreamModeDetails,
        **kwargs,
    ) -> None:
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, None))

        stream.mode = self._validate_stream_mode(stream_mode_details)

    #
    # Stream Retention
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
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))
        tag_list = convert_to_taglist(tags)
        store = kinesis_stores[context.account_id][context.region]
        store.TAGS.tag_resource(stream.arn, tag_list)

    def list_tags_for_stream(
        self,
        context: RequestContext,
        stream_name: StreamName = None,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForStreamInputLimit = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> ListTagsForStreamOutput:
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))
        store = kinesis_stores[context.account_id][context.region]
        tag_list = store.TAGS.list_tags_for_resource(stream.arn)["Tags"]
        return ListTagsForStreamOutput(
            Tags=tag_list,
            HasMoreTags=False,
        )

    def remove_tags_from_stream(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        stream = self._get_stream(*self._resolve_stream(context, stream_arn, stream_name))
        store = kinesis_stores[context.account_id][context.region]
        store.TAGS.untag_resource(stream.arn, tag_keys)

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
    # Enhanced Fan Out
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
        # When encryption is enabled on AWS Kinesis, only the stream data at rest is encrypted.
        # In this implementation, this is just treated as a no-op. Future work could involve checking key validity.
        pass

    def stop_stream_encryption(
        self,
        context: RequestContext,
        encryption_type: EncryptionType,
        key_id: KeyId,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        **kwargs,
    ) -> None:
        pass

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
