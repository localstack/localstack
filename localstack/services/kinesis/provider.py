import logging
import time
from datetime import datetime
from random import random
from typing import List

import localstack.services.kinesis.kinesis_starter as starter
from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext
from localstack.aws.api.kinesis import (
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
    StreamName,
    SubscribeToShardEvent,
    SubscribeToShardEventStream,
    SubscribeToShardOutput,
    Timestamp,
    UpdateShardCountOutput,
)
from localstack.constants import LOCALHOST
from localstack.services.kinesis.models import KinesisStore, kinesis_stores
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)
MAX_SUBSCRIPTION_SECONDS = 300


def find_stream_for_consumer(consumer_arn):
    kinesis = aws_stack.connect_to_service("kinesis")
    for stream_name in kinesis.list_streams()["StreamNames"]:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        for cons in kinesis.list_stream_consumers(StreamARN=stream_arn)["Consumers"]:
            if cons["ConsumerARN"] == consumer_arn:
                return stream_name
    raise Exception("Unable to find stream for stream consumer %s" % consumer_arn)


def find_consumer(consumer_arn="", consumer_name="", stream_arn=""):
    store = KinesisProvider.get_store()
    for consumer in store.stream_consumers:
        if consumer_arn and consumer_arn == consumer.get("ConsumerARN"):
            return consumer
        elif consumer_name == consumer.get("ConsumerName") and stream_arn == consumer.get(
            "StreamARN"
        ):
            return consumer


class KinesisProvider(KinesisApi, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> KinesisStore:
        return kinesis_stores[get_aws_account_id()][aws_stack.get_region()]

    def on_before_start(self):
        starter.start_kinesis()
        starter.check_kinesis()

    def get_forward_url(self):
        """Return the URL of the backend Kinesis server to forward requests to"""
        return f"http://{LOCALHOST}:{starter.get_server().port}"

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

            maximum_duration_subscription_timestamp = now_utc() + MAX_SUBSCRIPTION_SECONDS

            while now_utc() < maximum_duration_subscription_timestamp:
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
                    # On AWS there is *at least* 1 event every 5 seconds
                    # but this is not possible in this structure.
                    # In order to avoid a 5-second blocking call, we make the compromise of 3 seconds.
                    time.sleep(3)

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
            store = self.get_store()
            store.stream_consumers.append(consumer_description)
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
        # TODO remove this method when deleting kinesalite support
        if config.KINESIS_PROVIDER == "kinesalite":

            def consumer_filter(consumer: ConsumerDescription):
                return not (
                    consumer.get("ConsumerARN") == consumer_arn
                    or (
                        consumer.get("StreamARN") == stream_arn
                        and consumer.get("ConsumerName") == consumer_name
                    )
                )

            store = self.get_store()
            store.stream_consumers = list(filter(consumer_filter, store.stream_consumers))
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
        # TODO remove this method when deleting kinesalite support
        if config.KINESIS_PROVIDER == "kinesalite":
            store = self.get_store()
            consumers: List[Consumer] = []
            for consumer_description in store.stream_consumers:
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
        # TODO remove this method when deleting kinesalite support
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
        # TODO remove this method when deleting kinesalite support
        if config.KINESIS_PROVIDER == "kinesalite":
            store = self.get_store()
            stream_metrics = store.enhanced_metrics[stream_name]
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
        # TODO remove this method when deleting kinesalite support
        if config.KINESIS_PROVIDER == "kinesalite":
            store = self.get_store()
            store.enhanced_metrics[stream_name] = store.enhanced_metrics[stream_name] - set(
                shard_level_metrics
            )
            stream_metrics_list = list(store.enhanced_metrics[stream_name])
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
        # TODO remove this method when deleting kinesalite support
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
