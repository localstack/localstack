import json
import logging
from abc import abstractmethod
from datetime import datetime
from typing import Iterator

from botocore.client import BaseClient

from localstack.aws.api.pipes import (
    OnPartialBatchItemFailureStreams,
)
from localstack.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
    PartialBatchFailureError,
)
from localstack.services.lambda_.event_source_mapping.pipe_utils import (
    format_time_iso_8601_z,
    get_current_time,
    get_datetime_from_timestamp,
    get_internal_client,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import Poller
from localstack.services.lambda_.event_source_mapping.pollers.sqs_poller import get_queue_url
from localstack.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)


# TODO: fix this poller to support resharding
#   https://docs.aws.amazon.com/streams/latest/dev/kinesis-using-sdk-java-resharding.html
class StreamPoller(Poller):
    # Mapping of shard id => shard iterator
    shards: dict[str, str]
    # Iterator for round-robin polling from different shards because a batch cannot contain events from different shards
    # This is a workaround for not handling shards in parallel.
    iterator_over_shards: Iterator[tuple[str, str]] | None

    # The ARN of the processor (e.g., Pipe ARN)
    partner_resource_arn: str | None

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
        partner_resource_arn: str | None = None,
    ):
        super().__init__(source_arn, source_parameters, source_client, processor)
        self.partner_resource_arn: str = partner_resource_arn
        self.shards: dict[str, str] = {}
        self.iterator_over_shards: Iterator[str, str] | None = None

    @abstractmethod
    def transform_into_events(self, records: list[dict], shard_id) -> list[dict]:
        pass

    @property
    @abstractmethod
    def stream_parameters(self) -> dict:
        pass

    def poll_events(self):
        """Generalized poller for streams such as Kinesis or DynamoDB
        Examples of Kinesis consumers:
        * StackOverflow: https://stackoverflow.com/a/22403036/6875981
        * AWS Sample: https://github.com/aws-samples/kinesis-poster-worker/blob/master/worker.py
        Examples of DynamoDB consumers:
        * Blogpost: https://www.tecracer.com/blog/2022/05/getting-a-near-real-time-view-of-a-dynamodb-stream-with-python.html
        """
        # TODO: consider potential shard iterator timeout after 300 seconds (likely not relevant with short-polling):
        #   https://docs.aws.amazon.com/streams/latest/dev/troubleshooting-consumers.html#shard-iterator-expires-unexpectedly
        #  Does this happen if no records are received for 300 seconds?
        if not self.shards:
            self.shards = self.initialize_shards()

        # TODO: improve efficiency because this currently limits the throughput to at most batch size per poll interval
        # Handle shards round-robin. Re-initialize current shard iterator once all shards are handled.
        if self.iterator_over_shards is None:
            self.iterator_over_shards = iter(self.shards.items())

        current_shard_tuple = next(self.iterator_over_shards, None)
        if current_shard_tuple:
            # TODO: the functionality and control flow below is too complex and should be refactored
            abort_condition = None
            shard_id, shard_iterator = current_shard_tuple
            # TODO: implement MaximumBatchingWindowInSeconds flush condition
            get_records_response = self.source_client.get_records(
                # TODO: double-check cross-account behavior (region should be fine)
                # StreamARN=self.source_arn,  # differs for DynamoDB but optional
                ShardIterator=shard_iterator,
                Limit=self.stream_parameters["BatchSize"],
            )
            records = get_records_response["Records"]
            polled_events = self.transform_into_events(records, shard_id)
            # Check MaximumRecordAgeInSeconds
            if maximum_record_age_in_seconds := self.stream_parameters.get(
                "MaximumRecordAgeInSeconds"
            ):
                arrival_timestamp_of_last_event = polled_events[-1]["approximateArrivalTimestamp"]
                now = get_current_time().timestamp()
                record_age_in_seconds = now - arrival_timestamp_of_last_event
                if record_age_in_seconds > maximum_record_age_in_seconds:
                    abort_condition = "RecordAgeExpired"
            matching_events = self.filter_events(polled_events)
            # Don't trigger upon empty events
            if len(matching_events) == 0:
                # Update shard iterator upon if no records match the filter
                self.shards[shard_id] = get_records_response["NextShardIterator"]
                return
            events = self.add_source_metadata(matching_events)
            LOG.debug(
                "Polled %d events from %s in shard %s", len(events), self.source_arn, shard_id
            )
            # TODO: A retry should probably re-trigger fetching the record from the stream again?!
            #  -> This could be tested by setting a high retry number, using a long pipe execution, and a relatively
            #  short record expiration age at the source. Check what happens if the record expires at the source.
            #  A potential implementation could use checkpointing based on the iterator position (within shard scope)
            # TODO: handle partial batch failure (see poller.py:parse_batch_item_failures)
            # TODO: think about how to avoid starvation of other shards if one shard runs into infinite retries
            attempts = 0
            while not abort_condition and not self.max_retries_exceeded(attempts):
                try:
                    self.processor.process_events_batch(events)
                    # Update shard iterator upon successful pipe execution
                    self.shards[shard_id] = get_records_response["NextShardIterator"]
                    return
                except PartialBatchFailureError:
                    # TODO: add tests for partial batch failure scenarios
                    if (
                        self.stream_parameters["OnPartialBatchItemFailure"]
                        == OnPartialBatchItemFailureStreams.AUTOMATIC_BISECT
                    ):
                        # TODO: implement and test splitting batches in half until batch size 1
                        #  https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_PipeSourceKinesisStreamParameters.html
                        LOG.warning(
                            "AUTOMATIC_BISECT upon partial batch item failure is not yet implemented. Retrying the entire batch."
                        )

                    # let entire batch fail (ideally raise BatchFailureError)
                    LOG.debug(
                        f"Attempt {attempts} failed while processing {self.partner_resource_arn} with events: {events}"
                    )
                    attempts += 1
                    # Retry polling until the record expires at the source
                    if self.stream_parameters.get("MaximumRetryAttempts", -1) == -1:
                        return
                except Exception:
                    LOG.debug(
                        f"Attempt {attempts} failed while processing {self.partner_resource_arn} with events: {events}"
                    )
                    attempts += 1
                    # Retry polling until the record expires at the source
                    if self.stream_parameters.get("MaximumRetryAttempts", -1) == -1:
                        return

            # Send failed events to potential DLQ
            abort_condition = abort_condition or "RetryAttemptsExhausted"
            context = {
                "condition": abort_condition,
                "partnerResourceArn": self.partner_resource_arn,
            }
            self.send_events_to_dlq(events, context=context)
            # Update shard iterator upon failure once the events are sent to the DLQ
            self.shards[shard_id] = get_records_response["NextShardIterator"]
        else:
            # Set current shard iterator to None to re-start round-robin at the first shard
            self.iterator_over_shards = None

    @abstractmethod
    def initialize_shards(self) -> dict[str, str]:
        """Returns a shard dict mapping from shard id -> shard iterator
        The implementations for Kinesis and DynamoDB are similar but differ in various ways:
        * Kinesis uses "StreamARN" and DynamoDB uses "StreamArn" as source parameter
        * Kinesis uses "StreamStatus.ACTIVE" and DynamoDB uses "StreamStatus.ENABLED"
        * Only Kinesis supports the additional StartingPosition called "AT_TIMESTAMP" using "StartingPositionTimestamp"
        """
        pass

    def send_events_to_dlq(self, events, context) -> None:
        dlq_arn = self.stream_parameters.get("DeadLetterConfig", {}).get("Arn")
        if dlq_arn:
            # Create DLQ event
            first_record = events[0]
            first_record_arrival = get_datetime_from_timestamp(
                first_record["approximateArrivalTimestamp"]
            )
            last_record = events[-1]
            last_record_arrival = get_datetime_from_timestamp(
                last_record["approximateArrivalTimestamp"]
            )
            shard_id = first_record["eventID"].split(":")[0]
            dlq_event = {
                "context": context,
                "KinesisBatchInfo": {
                    "approximateArrivalOfFirstRecord": format_time_iso_8601_z(first_record_arrival),
                    "approximateArrivalOfLastRecord": format_time_iso_8601_z(last_record_arrival),
                    "batchSize": len(events),
                    "endSequenceNumber": last_record["sequenceNumber"],
                    "shardId": shard_id,
                    "startSequenceNumber": first_record["sequenceNumber"],
                    "streamArn": self.source_arn,
                },
                "timestamp": format_time_iso_8601_z(datetime.utcnow()),
                "version": "1.0",
            }
            # Send DLQ event to DLQ target
            parsed_arn = parse_arn(dlq_arn)
            service = parsed_arn["service"]
            # TODO: use a sender instance here, likely inject via DI into poller (what if it updates?)
            if service == "sqs":
                # TODO: inject and cache SQS client using proper IAM role (supports cross-account operations)
                sqs_client = get_internal_client(dlq_arn)
                # TODO: check if the DLQ exists
                dlq_url = get_queue_url(dlq_arn)
                # TODO: validate no FIFO queue because they are unsupported
                sqs_client.send_message(QueueUrl=dlq_url, MessageBody=json.dumps(dlq_event))
            else:
                # TODO: implement sns DLQ
                LOG.warning("Unsupported DLQ service %s", service)

    def max_retries_exceeded(self, attempts: int) -> bool:
        maximum_retry_attempts = self.stream_parameters.get("MaximumRetryAttempts", -1)
        # Infinite retries until the source expires
        if maximum_retry_attempts == -1:
            return False
        return attempts > maximum_retry_attempts
