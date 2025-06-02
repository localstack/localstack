import json
import logging
import threading
from abc import abstractmethod
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime
from typing import Iterator

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from localstack.aws.api.pipes import (
    OnPartialBatchItemFailureStreams,
)
from localstack.services.lambda_.event_source_mapping.event_processor import (
    BatchFailureError,
    CustomerInvocationError,
    EventProcessor,
    PartialBatchFailureError,
    PipeInternalError,
)
from localstack.services.lambda_.event_source_mapping.pipe_utils import (
    get_current_time,
    get_datetime_from_timestamp,
    get_internal_client,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import (
    EmptyPollResultsException,
    Poller,
    get_batch_item_failures,
)
from localstack.services.lambda_.event_source_mapping.pollers.sqs_poller import get_queue_url
from localstack.services.lambda_.event_source_mapping.senders.sender_utils import (
    batched,
)
from localstack.utils.aws.arns import parse_arn, s3_bucket_name
from localstack.utils.backoff import ExponentialBackoff
from localstack.utils.batch_policy import Batcher
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)


# TODO: fix this poller to support resharding
#   https://docs.aws.amazon.com/streams/latest/dev/kinesis-using-sdk-java-resharding.html
class StreamPoller(Poller):
    # Mapping of shard id => shard iterator
    # TODO: This mapping approach needs to be re-worked to instead store last processed sequence number.
    shards: dict[str, str]
    # Iterator for round-robin polling from different shards because a batch cannot contain events from different shards
    # This is a workaround for not handling shards in parallel.
    iterator_over_shards: Iterator[tuple[str, str]] | None
    # ESM UUID is needed in failure processing to form s3 failure destination object key
    esm_uuid: str | None

    # The ARN of the processor (e.g., Pipe ARN)
    partner_resource_arn: str | None

    # Used for backing-off between retries and breaking the retry loop
    _is_shutdown: threading.Event

    # Collects and flushes a batch of records based on a batching policy
    shard_batcher: dict[str, Batcher[dict]]

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
        partner_resource_arn: str | None = None,
        esm_uuid: str | None = None,
        shards: dict[str, str] | None = None,
    ):
        super().__init__(source_arn, source_parameters, source_client, processor)
        self.partner_resource_arn = partner_resource_arn
        self.esm_uuid = esm_uuid
        self.shards = shards if shards is not None else {}
        self.iterator_over_shards = None

        self._is_shutdown = threading.Event()

        self.shard_batcher = defaultdict(
            lambda: Batcher(
                max_count=self.stream_parameters.get("BatchSize", 100),
                max_window=self.stream_parameters.get("MaximumBatchingWindowInSeconds", 0),
            )
        )

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
    def format_datetime(self, time: datetime) -> str:
        """Formats a datetime in the correct format for DynamoDB (with ms) or Kinesis (without ms)"""
        pass

    @abstractmethod
    def get_sequence_number(self, record: dict) -> str:
        pass

    def close(self):
        self._is_shutdown.set()

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

        if not self.shards:
            LOG.debug("No shards found for %s.", self.source_arn)
            raise EmptyPollResultsException(service=self.event_source(), source_arn=self.source_arn)
        else:
            # Remove all shard batchers without corresponding shards
            for shard_id in self.shard_batcher.keys() - self.shards.keys():
                self.shard_batcher.pop(shard_id, None)

        # TODO: improve efficiency because this currently limits the throughput to at most batch size per poll interval
        # Handle shards round-robin. Re-initialize current shard iterator once all shards are handled.
        if self.iterator_over_shards is None:
            self.iterator_over_shards = iter(self.shards.items())

        current_shard_tuple = next(self.iterator_over_shards, None)
        if not current_shard_tuple:
            self.iterator_over_shards = iter(self.shards.items())
            current_shard_tuple = next(self.iterator_over_shards, None)

        # TODO Better handling when shards are initialised and the iterator returns nothing
        if not current_shard_tuple:
            raise PipeInternalError(
                "Failed to retrieve any shards for stream polling despite initialization."
            )

        try:
            self.poll_events_from_shard(*current_shard_tuple)
        except PipeInternalError:
            # TODO: standardize logging
            # Ignore and wait for the next polling interval, which will do retry
            pass

    def poll_events_from_shard(self, shard_id: str, shard_iterator: str):
        get_records_response = self.get_records(shard_iterator)
        records: list[dict] = get_records_response.get("Records", [])
        if not (next_shard_iterator := get_records_response.get("NextShardIterator")):
            # If the next shard iterator is None, we can assume the shard is closed or
            # has expired on the DynamoDB Local server, hence we should re-initialize.
            self.shards = self.initialize_shards()
        else:
            # We should always be storing the next_shard_iterator value, otherwise we risk an iterator expiring
            # and all records being re-processed.
            self.shards[shard_id] = next_shard_iterator

        # We cannot reliably back-off when no records found since an iterator
        # may have to move multiple times until records are returned.
        # See https://docs.aws.amazon.com/streams/latest/dev/troubleshooting-consumers.html#getrecords-returns-empty
        # However, we still need to check if batcher should be triggered due to time-based batching.
        should_flush = self.shard_batcher[shard_id].add(records)
        if not should_flush:
            return

        # Retrieve and drain all events in batcher
        collected_records = self.shard_batcher[shard_id].flush()
        # If there is overflow (i.e 1k BatchSize and 1.2K returned in flush), further split up the batch.
        for batch in batched(collected_records, self.stream_parameters.get("BatchSize")):
            # This could potentially lead to data loss if forward_events_to_target raises an exception after a flush
            # which would otherwise be solved with checkpointing.
            # TODO: Implement checkpointing, leasing, etc. from https://docs.aws.amazon.com/streams/latest/dev/kcl-concepts.html
            self.forward_events_to_target(shard_id, batch)

    def forward_events_to_target(self, shard_id, records):
        polled_events = self.transform_into_events(records, shard_id)
        abort_condition = None
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
            return

        events = self.add_source_metadata(matching_events_post_filter)
        LOG.debug("Polled %d events from %s in shard %s", len(events), self.source_arn, shard_id)
        #  -> This could be tested by setting a high retry number, using a long pipe execution, and a relatively
        #  short record expiration age at the source. Check what happens if the record expires at the source.
        #  A potential implementation could use checkpointing based on the iterator position (within shard scope)
        # TODO: handle partial batch failure (see poller.py:parse_batch_item_failures)
        # TODO: think about how to avoid starvation of other shards if one shard runs into infinite retries
        attempts = 0
        discarded_events_for_dlq = []
        error_payload = {}

        max_retries = self.stream_parameters.get("MaximumRetryAttempts", -1)
        max_record_age = max(
            self.stream_parameters.get("MaximumRecordAgeInSeconds", -1), 0
        )  # Disable check if -1
        # NOTE: max_retries == 0 means exponential backoff is disabled
        boff = ExponentialBackoff(max_retries=max_retries)
        while not abort_condition and events and not self._is_shutdown.is_set():
            if self.max_retries_exceeded(attempts):
                abort_condition = "RetryAttemptsExhausted"
                break

            if max_record_age:
                events, expired_events = self.bisect_events_by_record_age(max_record_age, events)
                if expired_events:
                    discarded_events_for_dlq.extend(expired_events)
                    continue

            try:
                if attempts > 0:
                    # TODO: Should we always backoff (with jitter) before processing since we may not want multiple pollers
                    # all starting up and polling simultaneously
                    # For example: 500 persisted ESMs starting up and requesting concurrently could flood gateway
                    self._is_shutdown.wait(boff.next_backoff())

                self.processor.process_events_batch(events)
                boff.reset()
                # We may need to send on data to a DLQ so break the processing loop and proceed if invocation successful.
                break
            except PartialBatchFailureError as ex:
                # TODO: add tests for partial batch failure scenarios
                if (
                    self.stream_parameters.get("OnPartialBatchItemFailure")
                    == OnPartialBatchItemFailureStreams.AUTOMATIC_BISECT
                ):
                    # TODO: implement and test splitting batches in half until batch size 1
                    #  https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_PipeSourceKinesisStreamParameters.html
                    LOG.warning(
                        "AUTOMATIC_BISECT upon partial batch item failure is not yet implemented. Retrying the entire batch."
                    )
                error_payload = ex.error

                # Extract all sequence numbers from events in batch. This allows us to fail the whole batch if
                # an unknown itemidentifier is returned.
                batch_sequence_numbers = {
                    self.get_sequence_number(event) for event in matching_events
                }

                # If the batchItemFailures array contains multiple items, Lambda uses the record with the lowest sequence number as the checkpoint.
                # Lambda then retries all records starting from that checkpoint.
                failed_sequence_ids: list[int] | None = get_batch_item_failures(
                    ex.partial_failure_payload, batch_sequence_numbers
                )

                # If None is returned, consider the entire batch a failure.
                if failed_sequence_ids is None:
                    continue

                # This shouldn't be possible since a PartialBatchFailureError was raised
                if len(failed_sequence_ids) == 0:
                    assert failed_sequence_ids, (
                        "Invalid state encountered: PartialBatchFailureError raised but no batch item failures found."
                    )

                lowest_sequence_id: str = min(failed_sequence_ids, key=int)

                # Discard all successful events and re-process from sequence number of failed event
                _, events = self.bisect_events(lowest_sequence_id, events)
            except BatchFailureError as ex:
                error_payload = ex.error

                # FIXME partner_resource_arn is not defined in ESM
                LOG.debug(
                    "Attempt %d failed while processing %s with events: %s",
                    attempts,
                    self.partner_resource_arn or self.source_arn,
                    events,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
            except Exception:
                # FIXME partner_resource_arn is not defined in ESM
                LOG.error(
                    "Attempt %d failed with unexpected error while processing %s with events: %s",
                    attempts,
                    self.partner_resource_arn or self.source_arn,
                    events,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
            finally:
                # Retry polling until the record expires at the source
                attempts += 1

        if discarded_events_for_dlq:
            abort_condition = "RecordAgeExceeded"
            error_payload = {}
            events = discarded_events_for_dlq

        # Send failed events to potential DLQ
        if abort_condition:
            failure_context = self.processor.generate_event_failure_context(
                abort_condition=abort_condition,
                error=error_payload,
                attempts_count=attempts,
                partner_resource_arn=self.partner_resource_arn,
            )
            self.send_events_to_dlq(shard_id, events, context=failure_context)

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
                # FIXME: The 'Invalid ShardId in ShardIterator' error is returned by DynamoDB-local. Unsure when/why this is returned.
                if "Invalid ShardId in ShardIterator" in str(e):
                    LOG.warning(
                        "Invalid ShardId in ShardIterator for %s. Re-initializing shards.",
                        self.source_arn,
                    )
                    self.shards = self.initialize_shards()
                else:
                    LOG.warning(
                        "Source stream %s does not exist: %s",
                        self.source_arn,
                        e,
                    )
                    raise CustomerInvocationError from e
            elif "TrimmedDataAccessException" in str(e):
                LOG.debug(
                    "Attempted to iterate over trimmed record or expired shard iterator %s for stream %s, re-initializing shards",
                    shard_iterator,
                    self.source_arn,
                )
                self.shards = self.initialize_shards()
            else:
                LOG.debug("ClientError during get_records for stream %s: %s", self.source_arn, e)
            raise PipeInternalError from e

    def send_events_to_dlq(self, shard_id, events, context) -> None:
        dlq_arn = self.stream_parameters.get("DeadLetterConfig", {}).get("Arn")
        if dlq_arn:
            failure_timstamp = get_current_time()
            dlq_event = self.create_dlq_event(shard_id, events, context, failure_timstamp)
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
            elif service == "sns":
                sns_client = get_internal_client(dlq_arn)
                sns_client.publish(TopicArn=dlq_arn, Message=json.dumps(dlq_event))
            elif service == "s3":
                s3_client = get_internal_client(dlq_arn)
                dlq_event_with_payload = {
                    **dlq_event,
                    "payload": {
                        "Records": events,
                    },
                }
                s3_client.put_object(
                    Bucket=s3_bucket_name(dlq_arn),
                    Key=get_failure_s3_object_key(self.esm_uuid, shard_id, failure_timstamp),
                    Body=json.dumps(dlq_event_with_payload),
                )
            else:
                LOG.warning("Unsupported DLQ service %s", service)

    def create_dlq_event(
        self, shard_id: str, events: list[dict], context: dict, failure_timestamp: datetime
    ) -> dict:
        first_record = events[0]
        first_record_arrival = get_datetime_from_timestamp(
            self.get_approximate_arrival_time(first_record)
        )

        last_record = events[-1]
        last_record_arrival = get_datetime_from_timestamp(
            self.get_approximate_arrival_time(last_record)
        )
        return {
            **context,
            self.failure_payload_details_field_name(): {
                "approximateArrivalOfFirstRecord": self.format_datetime(first_record_arrival),
                "approximateArrivalOfLastRecord": self.format_datetime(last_record_arrival),
                "batchSize": len(events),
                "endSequenceNumber": self.get_sequence_number(last_record),
                "shardId": shard_id,
                "startSequenceNumber": self.get_sequence_number(first_record),
                "streamArn": self.source_arn,
            },
            "timestamp": failure_timestamp.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "version": "1.0",
        }

    def max_retries_exceeded(self, attempts: int) -> bool:
        maximum_retry_attempts = self.stream_parameters.get("MaximumRetryAttempts", -1)
        # Infinite retries until the source expires
        if maximum_retry_attempts == -1:
            return False
        return attempts > maximum_retry_attempts

    def bisect_events(
        self, sequence_number: str, events: list[dict]
    ) -> tuple[list[dict], list[dict]]:
        """Splits list of events in two, where a sequence number equals a passed parameter `sequence_number`.
        This is used for:
          - `ReportBatchItemFailures`: Discarding events in a batch following a failure when is set.
          - `BisectBatchOnFunctionError`: Used to split a failed batch in two when doing a retry (not implemented)."""
        for i, event in enumerate(events):
            if self.get_sequence_number(event) == sequence_number:
                return events[:i], events[i:]

        return events, []

    def bisect_events_by_record_age(
        self, maximum_record_age: int, events: list[dict]
    ) -> tuple[list[dict], list[dict]]:
        """Splits events into [valid_events], [expired_events] based on record age.
        Where:
          - Events with age < maximum_record_age are valid.
          - Events with age >= maximum_record_age are expired."""
        cutoff_timestamp = get_current_time().timestamp() - maximum_record_age
        index = bisect_left(events, cutoff_timestamp, key=self.get_approximate_arrival_time)
        return events[index:], events[:index]


def get_failure_s3_object_key(esm_uuid: str, shard_id: str, failure_datetime: datetime) -> str:
    """
    From https://docs.aws.amazon.com/lambda/latest/dg/kinesis-on-failure-destination.html:

    The S3 object containing the invocation record uses the following naming convention:
    aws/lambda/<ESM-UUID>/<shardID>/YYYY/MM/DD/YYYY-MM-DDTHH.MM.SS-<Random UUID>

    :return: Key for s3 object that invocation failure record will be put to
    """
    timestamp = failure_datetime.strftime("%Y-%m-%dT%H.%M.%S")
    year_month_day = failure_datetime.strftime("%Y/%m/%d")
    random_uuid = long_uid()
    return f"aws/lambda/{esm_uuid}/{shard_id}/{year_month_day}/{timestamp}-{random_uuid}"
