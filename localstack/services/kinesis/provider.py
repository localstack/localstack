import logging
import time
from collections import defaultdict
from datetime import datetime
from random import random
from typing import Dict, List, Set

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.kinesis import (
    BooleanObject,
    Consumer,
    ConsumerARN,
    ConsumerDescription,
    ConsumerName,
    ConsumerStatus,
    Data,
    DescribeStreamConsumerOutput,
    EnhancedMonitoringOutput,
    HashKey,
    KinesisApi,
    ListStreamConsumersInputLimit,
    ListStreamConsumersOutput,
    MetricsName,
    MetricsNameList,
    NextToken,
    PartitionKey,
    PositiveIntegerObject,
    ProvisionedThroughputExceededException,
    PutRecordsOutput,
    PutRecordsRequestEntryList,
    PutRecordsResultEntry,
    RegisterStreamConsumerOutput,
    ResourceInUseException,
    ResourceNotFoundException,
    ScalingType,
    SequenceNumber,
    ShardId,
    StartingPosition,
    StreamARN,
    StreamModeDetails,
    StreamName,
    SubscribeToShardEvent,
    SubscribeToShardEventStream,
    SubscribeToShardOutput,
    Timestamp,
    UpdateShardCountOutput,
)
from localstack.aws.forwarder import HttpFallbackDispatcher
from localstack.aws.proxy import AwsApiListener
from localstack.constants import LOCALHOST
from localstack.services.generic_proxy import RegionBackend
from localstack.services.kinesis.kinesis_starter import check_kinesis, start_kinesis
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

# TODO ASF: Check if we need to implement CBOR encoding in the serializer!
# TODO ASF: Set "X-Amzn-Errortype" (HEADER_AMZN_ERROR_TYPE) on responses
# TODO ASF: Rewrite responses
#           - Region in content of responses
#           - Record rewriting:
#             - SDKv2: Transform timestamps to int?
#             - Remove double quotes for JSON responses
#             - Convert base64 encoded data back to bytes for the cbor encoding


class KinesisApiListener(AwsApiListener):
    def __init__(self, provider=None):
        provider = provider or KinesisProvider()
        self.provider = provider
        super().__init__("kinesis", HttpFallbackDispatcher(provider, provider.get_forward_url))


class KinesisBackend(RegionBackend):
    def __init__(self):
        # list of stream consumer details
        self.stream_consumers: List[ConsumerDescription] = []
        # maps stream name to list of enhanced monitoring metrics
        self.enhanced_metrics: Dict[StreamName, Set[MetricsName]] = defaultdict(set)


def find_stream_for_consumer(consumer_arn):
    kinesis = aws_stack.connect_to_service("kinesis")
    for stream_name in kinesis.list_streams()["StreamNames"]:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        for cons in kinesis.list_stream_consumers(StreamARN=stream_arn)["Consumers"]:
            if cons["ConsumerARN"] == consumer_arn:
                return stream_name
    raise Exception("Unable to find stream for stream consumer %s" % consumer_arn)


def find_consumer(consumer_arn="", consumer_name="", stream_arn=""):
    stream_consumers = KinesisBackend.get().stream_consumers
    for consumer in stream_consumers:
        if consumer_arn and consumer_arn == consumer.get("ConsumerARN"):
            return consumer
        elif consumer_name == consumer.get("ConsumerName") and stream_arn == consumer.get(
            "StreamARN"
        ):
            return consumer


class KinesisProvider(KinesisApi, ServiceLifecycleHook):
    def __init__(self):
        self._server = None

    def on_before_start(self):
        self._server = start_kinesis()
        check_kinesis()

    def get_forward_url(self):
        """Return the URL of the backend Kinesis server to forward requests to"""
        return f"http://{LOCALHOST}:{self._server.port}"

    def subscribe_to_shard(
        self,
        context: RequestContext,
        consumer_arn: ConsumerARN,
        shard_id: ShardId,
        starting_position: StartingPosition,
    ) -> SubscribeToShardOutput:
        kinesis = aws_stack.connect_to_service("kinesis")
        stream_name = find_stream_for_consumer(consumer_arn)
        iter_type = starting_position["Type"]
        kwargs = {}
        starting_sequence_number = starting_position.get("SequenceNumber") or "0"
        if iter_type in ["AT_SEQUENCE_NUMBER", "AFTER_SEQUENCE_NUMBER"]:
            kwargs["StartingSequenceNumber"] = starting_sequence_number
        elif iter_type in ["AT_TIMESTAMP"]:
            # or value is just an example timestamp from aws docs
            timestamp = starting_position.get("Timestamp") or 1459799926.480
            kwargs["Timestamp"] = timestamp
        initial_shard_iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType=iter_type, **kwargs
        )["ShardIterator"]

        def event_generator():
            shard_iterator = initial_shard_iterator
            last_sequence_number = starting_sequence_number
            # TODO: find better way to run loop up to max 5 minutes (until connection terminates)!
            for i in range(5 * 60):
                try:
                    result = kinesis.get_records(ShardIterator=shard_iterator)
                except Exception as e:
                    if "ResourceNotFoundException" in str(e):
                        LOG.debug(
                            'Kinesis stream "%s" has been deleted, closing shard subscriber',
                            stream_name,
                        )
                        return
                    raise
                shard_iterator = result.get("NextShardIterator")
                records = result.get("Records", [])
                if not records:
                    time.sleep(1)
                    continue

                yield SubscribeToShardEventStream(
                    SubscribeToShardEvent=SubscribeToShardEvent(
                        Records=records,
                        ContinuationSequenceNumber=str(last_sequence_number),
                        MillisBehindLatest=0,
                        ChildShards=[],
                    )
                )

        return SubscribeToShardOutput(EventStream=event_generator())

    def put_record(
        self,
        context: RequestContext,
        stream_name: StreamName,
        data: Data,
        partition_key: PartitionKey,
        explicit_hash_key: HashKey = None,
        sequence_number_for_ordering: SequenceNumber = None,
    ):
        if random() < config.KINESIS_ERROR_PROBABILITY:
            raise ProvisionedThroughputExceededException(
                "Rate exceeded for shard X in stream Y under account Z."
            )
        # If "we were lucky" and the error probability didn't hit, we raise a NotImplementedError in order to
        # trigger the fallback to kinesis-mock or kinesalite
        raise NotImplementedError

    def put_records(
        self, context: RequestContext, records: PutRecordsRequestEntryList, stream_name: StreamName
    ) -> PutRecordsOutput:
        if random() < config.KINESIS_ERROR_PROBABILITY:
            records_count = len(records) if records is not None else 0
            records = [
                PutRecordsResultEntry(
                    ErrorCode="ProvisionedThroughputExceededException",
                    ErrorMessage="Rate exceeded for shard X in stream Y under account Z.",
                )
            ] * records_count
            return PutRecordsOutput(FailedRecordCount=1, Records=records)
        # If "we were lucky" and the error probability didn't hit, we raise a NotImplementedError in order to
        # trigger the fallback to kinesis-mock or kinesalite
        raise NotImplementedError

    def register_stream_consumer(
        self, context: RequestContext, stream_arn: StreamARN, consumer_name: ConsumerName
    ) -> RegisterStreamConsumerOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            prev_consumer = find_consumer(stream_arn=stream_arn, consumer_name=consumer_name)
            if prev_consumer:
                raise ResourceInUseException(
                    f"Consumer {prev_consumer['ConsumerARN']} already exists"
                )
            consumer = Consumer(
                ConsumerName=consumer_name,
                ConsumerStatus=ConsumerStatus.ACTIVE,
                ConsumerARN=f"{stream_arn}/consumer/{consumer_name}",
                ConsumerCreationTimestamp=datetime.now(),
            )
            consumer_description = ConsumerDescription(**consumer)
            consumer_description["StreamARN"] = stream_arn
            KinesisBackend.get().stream_consumers.append(consumer_description)
            return RegisterStreamConsumerOutput(Consumer=consumer)

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def deregister_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = "",
        consumer_name: ConsumerName = "",
        consumer_arn: ConsumerARN = "",
    ) -> None:
        if config.KINESIS_PROVIDER == "kinesalite":

            def consumer_filter(consumer: ConsumerDescription):
                return not (
                    consumer.get("ConsumerARN") == consumer_arn
                    or (
                        consumer.get("StreamARN") == stream_arn
                        and consumer.get("ConsumerName") == consumer_name
                    )
                )

            region = KinesisBackend.get()
            region.stream_consumers = list(filter(consumer_filter, region.stream_consumers))
            return None

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def list_stream_consumers(
        self,
        context: RequestContext,
        stream_arn: StreamARN,
        next_token: NextToken = None,
        max_results: ListStreamConsumersInputLimit = None,
        stream_creation_timestamp: Timestamp = None,
    ) -> ListStreamConsumersOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            stream_consumers = KinesisBackend.get().stream_consumers
            consumers: List[Consumer] = []
            for consumer_description in stream_consumers:
                consumer = Consumer(
                    ConsumerARN=consumer_description["ConsumerARN"],
                    ConsumerCreationTimestamp=consumer_description["ConsumerCreationTimestamp"],
                    ConsumerName=consumer_description["ConsumerName"],
                    ConsumerStatus=consumer_description["ConsumerStatus"],
                )
                consumers.append(consumer)
            return ListStreamConsumersOutput(Consumers=consumers)

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def describe_stream_consumer(
        self,
        context: RequestContext,
        stream_arn: StreamARN = None,
        consumer_name: ConsumerName = None,
        consumer_arn: ConsumerARN = None,
    ) -> DescribeStreamConsumerOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            consumer_to_locate = find_consumer(consumer_arn, consumer_name, stream_arn)
            if not consumer_to_locate:
                raise ResourceNotFoundException(
                    f"Consumer {consumer_arn or consumer_name} not found."
                )
            return DescribeStreamConsumerOutput(ConsumerDescription=consumer_to_locate)

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def enable_enhanced_monitoring(
        self, context: RequestContext, stream_name: StreamName, shard_level_metrics: MetricsNameList
    ) -> EnhancedMonitoringOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            stream_metrics = KinesisBackend.get().enhanced_metrics[stream_name]
            stream_metrics.update(shard_level_metrics)
            stream_metrics_list = list(stream_metrics)
            return EnhancedMonitoringOutput(
                StreamName=stream_name,
                CurrentShardLevelMetrics=stream_metrics_list,
                DesiredShardLevelMetrics=stream_metrics_list,
            )

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def disable_enhanced_monitoring(
        self, context: RequestContext, stream_name: StreamName, shard_level_metrics: MetricsNameList
    ) -> EnhancedMonitoringOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            region = KinesisBackend.get()
            region.enhanced_metrics[stream_name] = region.enhanced_metrics[stream_name] - set(
                shard_level_metrics
            )
            stream_metrics_list = list(region.enhanced_metrics[stream_name])
            return EnhancedMonitoringOutput(
                StreamName=stream_name,
                CurrentShardLevelMetrics=stream_metrics_list,
                DesiredShardLevelMetrics=stream_metrics_list,
            )

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def update_shard_count(
        self,
        context: RequestContext,
        stream_name: StreamName,
        target_shard_count: PositiveIntegerObject,
        scaling_type: ScalingType,
    ) -> UpdateShardCountOutput:
        if config.KINESIS_PROVIDER == "kinesalite":
            # Currently, kinesalite - which backs the Kinesis implementation for localstack - does
            # not support UpdateShardCount: https://github.com/mhart/kinesalite/issues/61
            # Terraform makes the call to UpdateShardCount when it
            # applies Kinesis resources. A Terraform run fails when this is not present.
            # This code just returns a successful response, bypassing the 400 response that kinesalite would return.
            return UpdateShardCountOutput(
                CurrentShardCount=1,
                StreamName=stream_name,
                TargetShardCount=target_shard_count,
            )

        # If kinesis-mock is used, we forward the request through the fallback by raising a NotImplementedError
        raise NotImplementedError

    def create_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        shard_count: PositiveIntegerObject = None,
        stream_mode_details: StreamModeDetails = None,
    ) -> None:
        payload = {"n": event_publisher.get_hash(stream_name), "s": shard_count}
        event_publisher.fire_event(event_publisher.EVENT_KINESIS_CREATE_STREAM, payload=payload)

        # After the event is logged, the request is forwarded to the fallback by raising a NotImplementedError
        raise NotImplementedError

    def delete_stream(
        self,
        context: RequestContext,
        stream_name: StreamName,
        enforce_consumer_deletion: BooleanObject = None,
    ) -> None:
        payload = {"n": event_publisher.get_hash(stream_name)}
        event_publisher.fire_event(event_publisher.EVENT_KINESIS_DELETE_STREAM, payload=payload)

        # After the event is logged, the request is forwarded to the fallback by raising a NotImplementedError
        raise NotImplementedError
