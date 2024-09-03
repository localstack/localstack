import json
import logging
from abc import abstractmethod
from datetime import datetime
from typing import Iterator

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from localstack.aws.api.pipes import (
    OnPartialBatchItemFailureStreams,
)
from localstack.services.lambda_.event_source_mapping.event_processor import (
    CustomerInvocationError,
    EventProcessor,
    PartialBatchFailureError,
    PipeInternalError,
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
        self.partner_resource_arn = partner_resource_arn
        self.shards = {}
        self.iterator_over_shards = None

    @abstractmethod
    def transform_into_events(self, records: list[dict], shard_id) -> list[dict]:
        pass

    @property
    @abstractmethod
    def stream_parameters(self) -> dict:
        pass

    @abstractmethod
    def initialize_shards(self) -> dict[str, str]:
        """Returns a shard dict mapping from shard id -> shard iterator
        The implementations for Kinesis and DynamoDB are similar but differ in various ways:
        * Kinesis uses "StreamARN" and DynamoDB uses "StreamArn" as source parameter
        * Kinesis uses "StreamStatus.ACTIVE" and DynamoDB uses "StreamStatus.ENABLED"
        * Only Kinesis supports the additional StartingPosition called "AT_TIMESTAMP" using "StartingPositionTimestamp"
        """
        pass

    @abstractmethod
    def stream_arn_param(self) -> dict:
        """Returns a dict of the correct key/value pair for the stream arn used in GetRecords.
        Either StreamARN for Kinesis or {} for DynamoDB (unsupported)"""
        pass

    @abstractmethod
    def failure_payload_details_field_name(self) -> str:
        pass

    @abstractmethod
    def get_approximate_arrival_time(self, record: dict) -> float:
        pass

    @abstractmethod
    def get_sequence_number(self, record: dict) -> str:
        pass

    def pre_filter(self, events: list[dict]) -> list[dict]:
        return events

    def post_filter(self, events: list[dict]) -> list[dict]:
        return events

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
            try:
                self.poll_events_from_shard(*current_shard_tuple)
            # TODO: implement exponential back-off for errors in general
            except PipeInternalError:
                # TODO: standardize logging
                # Ignore and wait for the next polling interval, which will do retry
                pass
        else:
            # Set current shard iterator to None to re-start round-robin at the first shard
            self.iterator_over_shards = None

    def poll_events_from_shard(self, shard_id: str, shard_iterator: str):
        abort_condition = None
        get_records_response = self.get_records(shard_iterator)
        records = get_records_response["Records"]
        polled_events = self.transform_into_events(records, shard_id)
        # Check MaximumRecordAgeInSeconds
        if maximum_record_age_in_seconds := self.stream_parameters.get("MaximumRecordAgeInSeconds"):
            arrival_timestamp_of_last_event = polled_events[-1]["approximateArrivalTimestamp"]
            now = get_current_time().timestamp()
            record_age_in_seconds = now - arrival_timestamp_of_last_event
            if record_age_in_seconds > maximum_record_age_in_seconds:
                abort_condition = "RecordAgeExpired"

        # TODO: implement format detection behavior (e.g., for JSON body):
        #  https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
        #  Check whether we need poller-specific filter-preprocessing here without modifying the actual event!
        # convert to json for filtering (HACK for fixing parity with v1 and getting regression tests passing)
        # localstack.services.lambda_.event_source_listeners.kinesis_event_source_listener.KinesisEventSourceListener._filter_records
        # TODO: explore better abstraction for the entire filtering, including the set_data and get_data remapping
        #  We need better clarify which transformations happen before and after filtering -> fix missing test coverage
        parsed_events = self.pre_filter(polled_events)
        # TODO: advance iterator past matching events!
        #  We need to checkpoint the sequence number for each shard and then advance the shard iterator using
        #  GetShardIterator with a given sequence number
        #  https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
        #  Failing to do so kinda blocks the stream resulting in very high latency.
        matching_events = self.filter_events(parsed_events)
        matching_events_post_filter = self.post_filter(matching_events)

        # TODO: implement MaximumBatchingWindowInSeconds flush condition (before or after filter?)
        # Don't trigger upon empty events
        if len(matching_events_post_filter) == 0:
            # Update shard iterator if no records match the filter
            self.shards[shard_id] = get_records_response["NextShardIterator"]
            return
        events = self.add_source_metadata(matching_events_post_filter)
        LOG.debug("Polled %d events from %s in shard %s", len(events), self.source_arn, shard_id)
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
                # Update shard iterator if execution is successful
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
                    # TODO: handle iterator expired scenario
                    return
            except Exception:
                LOG.warning(
                    f"Attempt {attempts} failed unexpectedly while processing {self.partner_resource_arn} with events: {events}"
                )
                attempts += 1
                # Retry polling until the record expires at the source
                if self.stream_parameters.get("MaximumRetryAttempts", -1) == -1:
                    # TODO: handle iterator expired scenario
                    return

        # Send failed events to potential DLQ
        abort_condition = abort_condition or "RetryAttemptsExhausted"
        # TODO: fix format for ESM using `requestContext` and `responseContext` (which requires info from the Lambda sender!) instead
        context = {
            "context": {
                "condition": abort_condition,
                "partnerResourceArn": self.partner_resource_arn,
            }
        }
        self.send_events_to_dlq(events, context=context)
        # Update shard iterator if the execution failed but the events are sent to a DLQ
        self.shards[shard_id] = get_records_response["NextShardIterator"]

    def get_records(self, shard_iterator: str) -> dict:
        """Returns a GetRecordsOutput from the GetRecords endpoint of streaming services such as Kinesis or DynamoDB"""
        try:
            get_records_response = self.source_client.get_records(
                # TODO: add test for cross-account scenario
                # Differs for Kinesis and DynamoDB but required for cross-account scenario
                **self.stream_arn_param(),
                ShardIterator=shard_iterator,
                Limit=self.stream_parameters["BatchSize"],
            )
            return get_records_response
        # TODO: test iterator expired with conditional error scenario (requires failure destinations)
        except self.source_client.exceptions.ExpiredIteratorException as e:
            LOG.debug(
                "Shard iterator %s expired for stream %s, re-initializing shards",
                shard_iterator,
                self.source_arn,
            )
            # TODO: test TRIM_HORIZON and AT_TIMESTAMP scenarios for this case. We don't want to start from scratch and
            #  might need to think about checkpointing here.
            self.shards = self.initialize_shards()
            raise PipeInternalError from e
        except ClientError as e:
            if "AccessDeniedException" in str(e):
                LOG.warning(
                    "Insufficient permissions to get records from stream %s: %s",
                    self.source_arn,
                    e,
                )
                raise CustomerInvocationError from e
            elif "ResourceNotFoundException" in str(e):
                LOG.warning(
                    "Source stream %s does not exist: %s",
                    self.source_arn,
                    e,
                )
                raise CustomerInvocationError from e
            else:
                LOG.debug("ClientError during get_records for stream %s: %s", self.source_arn, e)
                raise PipeInternalError from e

    def send_events_to_dlq(self, events, context) -> None:
        dlq_arn = self.stream_parameters.get("DeadLetterConfig", {}).get("Arn")
        if dlq_arn:
            dlq_event = self.create_dlq_event(events, context)
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

    def create_dlq_event(self, events: list[dict], context: dict) -> dict:
        first_record = events[0]
        first_record_arrival = get_datetime_from_timestamp(
            self.get_approximate_arrival_time(first_record)
        )

        last_record = events[-1]
        last_record_arrival = get_datetime_from_timestamp(
            self.get_approximate_arrival_time(last_record)
        )
        shard_id = first_record["eventID"].split(":")[0]
        return {
            **context,
            self.failure_payload_details_field_name(): {
                "approximateArrivalOfFirstRecord": format_time_iso_8601_z(first_record_arrival),
                "approximateArrivalOfLastRecord": format_time_iso_8601_z(last_record_arrival),
                "batchSize": len(events),
                "endSequenceNumber": self.get_sequence_number(last_record),
                "shardId": shard_id,
                "startSequenceNumber": self.get_sequence_number(first_record),
                "streamArn": self.source_arn,
            },
            "timestamp": format_time_iso_8601_z(datetime.utcnow()),
            "version": "1.0",
        }

    def max_retries_exceeded(self, attempts: int) -> bool:
        maximum_retry_attempts = self.stream_parameters.get("MaximumRetryAttempts", -1)
        # Infinite retries until the source expires
        if maximum_retry_attempts == -1:
            return False
        return attempts > maximum_retry_attempts
