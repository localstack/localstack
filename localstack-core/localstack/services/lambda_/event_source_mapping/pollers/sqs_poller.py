import json
import logging
from collections import defaultdict
from functools import cached_property

from botocore.client import BaseClient

from localstack.aws.api.pipes import PipeSourceSqsQueueParameters
from localstack.aws.api.sqs import MessageSystemAttributeName
from localstack.config import internal_service_url
from localstack.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
    PartialBatchFailureError,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import (
    EmptyPollResultsException,
    Poller,
    parse_batch_item_failures,
)
from localstack.services.lambda_.event_source_mapping.senders.sender_utils import (
    batched,
)
from localstack.services.sqs.constants import (
    HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT,
    HEADER_LOCALSTACK_SQS_OVERRIDE_WAIT_TIME_SECONDS,
)
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import first_char_to_lower

LOG = logging.getLogger(__name__)

DEFAULT_MAX_RECEIVE_COUNT = 10
# See https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html
DEFAULT_MAX_WAIT_TIME_SECONDS = 20


class SqsPoller(Poller):
    queue_url: str

    batch_size: int
    maximum_batching_window: int

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
    ):
        super().__init__(source_arn, source_parameters, source_client, processor)
        self.queue_url = get_queue_url(self.source_arn)

        self.batch_size = self.sqs_queue_parameters.get("BatchSize", DEFAULT_MAX_RECEIVE_COUNT)
        # HACK: When the MaximumBatchingWindowInSeconds is not set, just default to short-polling.
        # While set in ESM (via the config factory) setting this param as a default in Pipes causes
        # parity issues with a retrieved config since no default value is returned.
        self.maximum_batching_window = self.sqs_queue_parameters.get(
            "MaximumBatchingWindowInSeconds", 0
        )

        self._register_client_hooks()

    @property
    def sqs_queue_parameters(self) -> PipeSourceSqsQueueParameters:
        # TODO: De-couple Poller configuration params from ESM/Pipes specific config (i.e PipeSourceSqsQueueParameters)
        return self.source_parameters["SqsQueueParameters"]

    @cached_property
    def is_fifo_queue(self) -> bool:
        # Alternative heuristic: self.queue_url.endswith(".fifo"), but we need the call to get_queue_attributes for IAM
        return self.get_queue_attributes().get("FifoQueue", "false").lower() == "true"

    def _register_client_hooks(self):
        event_system = self.source_client.meta.events

        def handle_message_count_override(params, context, **kwargs):
            requested_count = params.pop("sqs_override_max_message_count", None)
            if not requested_count or requested_count <= DEFAULT_MAX_RECEIVE_COUNT:
                return

            context[HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT] = str(requested_count)

        def handle_message_wait_time_seconds_override(params, context, **kwargs):
            requested_wait = params.pop("sqs_override_wait_time_seconds", None)
            if not requested_wait or requested_wait <= DEFAULT_MAX_WAIT_TIME_SECONDS:
                return

            context[HEADER_LOCALSTACK_SQS_OVERRIDE_WAIT_TIME_SECONDS] = str(requested_wait)

        def handle_inject_headers(params, context, **kwargs):
            if override_message_count := context.pop(
                HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT, None
            ):
                params["headers"][HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT] = (
                    override_message_count
                )

            if override_wait_time := context.pop(
                HEADER_LOCALSTACK_SQS_OVERRIDE_WAIT_TIME_SECONDS, None
            ):
                params["headers"][HEADER_LOCALSTACK_SQS_OVERRIDE_WAIT_TIME_SECONDS] = (
                    override_wait_time
                )

        event_system.register(
            "provide-client-params.sqs.ReceiveMessage", handle_message_count_override
        )
        event_system.register(
            "provide-client-params.sqs.ReceiveMessage", handle_message_wait_time_seconds_override
        )
        # Since we delete SQS messages after processing, this allows us to remove up to 10K entries at a time.
        event_system.register(
            "provide-client-params.sqs.DeleteMessageBatch", handle_message_count_override
        )

        event_system.register("before-call.sqs.ReceiveMessage", handle_inject_headers)
        event_system.register("before-call.sqs.DeleteMessageBatch", handle_inject_headers)

    def get_queue_attributes(self) -> dict:
        """The API call to sqs:GetQueueAttributes is required for IAM policy streamsing."""
        get_queue_attributes_response = self.source_client.get_queue_attributes(
            QueueUrl=self.queue_url,
            AttributeNames=["FifoQueue"],
        )
        return get_queue_attributes_response.get("Attributes", {})

    def event_source(self) -> str:
        return "aws:sqs"

    def poll_events(self) -> None:
        # In order to improve performance, we've adopted long-polling for the SQS poll operation `ReceiveMessage` [1].
        # * Our LS-internal optimizations leverage custom boto-headers to set larger batch sizes and longer wait times than what the AWS API allows [2].
        # * Higher batch collection durations and no. of records retrieved per request mean fewer calls to the LocalStack gateway [3] when polling an event-source [4].
        # * LocalStack shutdown works because the LocalStack gateway shuts down and terminates the open connection.
        # * Provider lifecycle hooks have been added to ensure blocking long-poll calls are gracefully interrupted and returned.
        #
        # Pros (+) / Cons (-):
        # + Alleviates pressure on the gateway since each `ReceiveMessage` call only returns once we reach the desired `BatchSize` or the `WaitTimeSeconds` elapses.
        # + Matches the AWS behavior also using long-polling
        # - Blocks a LocalStack gateway thread (default 1k) for every open connection, which could lead to resource contention if used at scale.
        #
        # Refs / Notes:
        # [1] Amazon SQS short and long polling: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html
        # [2] PR (2025-02): https://github.com/localstack/localstack/pull/12002
        # [3] Note: Under high volumes of requests, the LocalStack gateway becomes a major performance bottleneck.
        # [4] ESM blog mentioning long-polling: https://aws.amazon.com/de/blogs/aws/aws-lambda-adds-amazon-simple-queue-service-to-supported-event-sources/

        # TODO: Handle exceptions differently i.e QueueNotExist or ConnectionFailed should retry with backoff
        response = self.source_client.receive_message(
            QueueUrl=self.queue_url,
            MaxNumberOfMessages=min(self.batch_size, DEFAULT_MAX_RECEIVE_COUNT),
            WaitTimeSeconds=min(self.maximum_batching_window, DEFAULT_MAX_WAIT_TIME_SECONDS),
            MessageAttributeNames=["All"],
            MessageSystemAttributeNames=[MessageSystemAttributeName.All],
            # Override how many messages we can receive per call
            sqs_override_max_message_count=self.batch_size,
            # Override how long to wait until batching conditions are met
            sqs_override_wait_time_seconds=self.maximum_batching_window,
        )

        messages = response.get("Messages", [])
        if not messages:
            raise EmptyPollResultsException(service="sqs", source_arn=self.source_arn)

        LOG.debug("Polled %d events from %s", len(messages), self.source_arn)
        # TODO: implement invocation payload size quota
        # NOTE: Split up a batch into mini-batches of up to 2.5K records each. This is to prevent exceeding the 6MB size-limit
        # imposed on payloads sent to a Lambda as well as LocalStack Lambdas failing to handle large payloads efficiently.
        # See https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html#invocation-eventsourcemapping-batching
        for message_batch in batched(messages, 2500):
            if len(message_batch) < len(messages):
                LOG.debug(
                    "Splitting events from %s into mini-batch (%d/%d)",
                    self.source_arn,
                    len(message_batch),
                    len(messages),
                )
            try:
                if self.is_fifo_queue:
                    # TODO: think about starvation behavior because once failing message could block other groups
                    fifo_groups = split_by_message_group_id(message_batch)
                    for fifo_group_messages in fifo_groups.values():
                        self.handle_messages(fifo_group_messages)
                else:
                    self.handle_messages(message_batch)

            # TODO: unify exception handling across pollers: should we catch and raise?
            except Exception as e:
                # TODO: improve error messages (produce same failure and design better error messages)
                LOG.warning(
                    "Polling or batch processing failed: %s",
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

    def handle_messages(self, messages):
        polled_events = transform_into_events(messages)
        # Filtering: matching vs. discarded (i.e., not matching filter criteria)
        # TODO: implement format detection behavior (e.g., for JSON body):
        #  https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html#pipes-filter-sqs
        #  Check whether we need poller-specific filter-preprocessing here without modifying the actual event!
        # convert to json for filtering (HACK for fixing parity with v1 and getting regression tests passing)
        for event in polled_events:
            try:
                event["body"] = json.loads(event["body"])
            except json.JSONDecodeError:
                LOG.debug(
                    "Unable to convert event body '%s' to json... Event might be dropped.",
                    event["body"],
                )
        matching_events = self.filter_events(polled_events)
        # convert them back (HACK for fixing parity with v1 and getting regression tests passing)
        for event in matching_events:
            event["body"] = (
                json.dumps(event["body"]) if not isinstance(event["body"], str) else event["body"]
            )

        all_message_ids = {message["MessageId"] for message in messages}
        matching_message_ids = {event["messageId"] for event in matching_events}
        discarded_message_ids = all_message_ids.difference(matching_message_ids)
        # Delete discarded events immediately:
        # https://lucvandonkersgoed.com/2022/01/20/the-9-ways-an-sqs-message-can-be-deleted/#7-event-source-mappings-with-filters
        self.delete_messages(messages, discarded_message_ids)

        # Don't trigger upon empty events
        if len(matching_events) == 0:
            return
        # Enrich events with metadata after filtering
        enriched_events = self.add_source_metadata(matching_events)

        # Invoke the processor (e.g., Pipe, ESM) and handle partial batch failures
        try:
            self.processor.process_events_batch(enriched_events)
            successful_message_ids = all_message_ids
        except PartialBatchFailureError as e:
            failed_message_ids = parse_batch_item_failures(
                e.partial_failure_payload, matching_message_ids
            )
            successful_message_ids = matching_message_ids.difference(failed_message_ids)

        # Only delete messages that are processed successfully as described here:
        # https://docs.aws.amazon.com/en_gb/lambda/latest/dg/with-sqs.html
        # When Lambda reads a batch, the messages stay in the queue but are hidden for the length of the queue's
        # visibility timeout. If your function successfully processes the batch, Lambda deletes the messages
        # from the queue. By default, if your function encounters an error while processing a batch,
        # all messages in that batch become visible in the queue again. For this reason, your function code must
        # be able to process the same message multiple times without unintended side effects.
        # Troubleshooting: https://repost.aws/knowledge-center/lambda-sqs-report-batch-item-failures
        # For FIFO queues, AWS also deletes successfully sent messages. Therefore, the AWS docs recommends:
        # "If you're using this feature with a FIFO queue, your function should stop processing messages after the first
        # failure and return all failed and unprocessed messages in batchItemFailures. This helps preserve the ordering
        # of messages in your queue."
        # Following this recommendation could result in the unsolved side effect that valid messages are continuously
        # placed in the same batch as failing messages:
        # * https://stackoverflow.com/questions/78694079/how-to-stop-fifo-sqs-messages-from-being-placed-in-a-batch-with-failing-messages
        # * https://stackoverflow.com/questions/76912394/can-i-report-only-messages-from-failing-group-id-in-reportbatchitemfailures-resp

        # TODO: Test blocking failure behavior for FIFO queues to guarantee strict ordering
        #  -> might require some checkpointing or retry control on the poller side?!
        # The poller should only proceed processing FIFO queues after having retried failing messages:
        # "If your pipe returns an error, the pipe attempts all retries on the affected messages before EventBridge
        # receives additional messages from the same group."
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-sqs.html
        self.delete_messages(messages, successful_message_ids)

    def delete_messages(self, messages: list[dict], message_ids_to_delete: set):
        """Delete SQS `messages` from the source queue that match a MessageId within `message_ids_to_delete`"""
        # TODO: unclear how (partial) failures for deleting are handled, retry or fail batch? Hard to test against AWS
        if len(message_ids_to_delete) > 0:
            entries = [
                {"Id": str(count), "ReceiptHandle": message["ReceiptHandle"]}
                for count, message in enumerate(messages)
                if message["MessageId"] in message_ids_to_delete
            ]

            self.source_client.delete_message_batch(
                QueueUrl=self.queue_url,
                Entries=entries,
                # Override how many messages can be deleted at once
                sqs_override_max_message_count=self.batch_size,
            )


def split_by_message_group_id(messages) -> defaultdict[str, list[dict]]:
    """Splitting SQS messages by MessageGroupId to ensure strict ordering for FIFO queues"""
    fifo_groups = defaultdict(list)
    for message in messages:
        message_group_id = message["Attributes"]["MessageGroupId"]
        fifo_groups[message_group_id].append(message)
    return fifo_groups


def transform_into_events(messages: list[dict]) -> list[dict]:
    events = []
    for message in messages:
        # TODO: consolidate with SQS event source listener:
        #  localstack.services.lambda_.event_source_listeners.sqs_event_source_listener.SQSEventSourceListener._send_event_to_lambda
        message_attrs = message_attributes_to_lower(message.get("MessageAttributes"))
        event = {
            # Original SQS message attributes
            "messageId": message["MessageId"],
            "receiptHandle": message["ReceiptHandle"],
            # TODO: test with empty body
            # TODO: implement heuristic based on content type: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html#pipes-filter-sqs
            "body": message.get("Body", "MessageBody"),
            "attributes": message.get("Attributes", {}),
            "messageAttributes": message_attrs,
            # TODO: test with empty body
            "md5OfBody": message.get("MD5OfBody") or message.get("MD5OfMessageBody"),
        }
        # TODO: test Pipe with message attributes (only covered by Lambda ESM SQS test so far)
        if md5_of_message_attributes := message.get("MD5OfMessageAttributes"):
            event["md5OfMessageAttributes"] = md5_of_message_attributes
        events.append(event)
    return events


def get_queue_url(queue_arn: str) -> str:
    # TODO: consolidate this method with localstack.services.sqs.models.SqsQueue.url
    # * Do we need to support different endpoint strategies?
    # * If so, how can we achieve this without having a request context
    host_url = internal_service_url()
    host = host_url.rstrip("/")
    parsed_arn = parse_arn(queue_arn)
    account_id = parsed_arn["account"]
    name = parsed_arn["resource"]
    return f"{host}/{account_id}/{name}"


def message_attributes_to_lower(message_attrs):
    """Convert message attribute details (first characters) to lower case (e.g., stringValue, dataType)."""
    message_attrs = message_attrs or {}
    for _, attr in message_attrs.items():
        if not isinstance(attr, dict):
            continue
        for key, value in dict(attr).items():
            attr[first_char_to_lower(key)] = attr.pop(key)
    return message_attrs
