import json
import logging
import time
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
    Poller,
    parse_batch_item_failures,
)
from localstack.services.lambda_.event_source_mapping.senders.sender_utils import (
    batched,
    batched_by_size,
)
from localstack.services.sqs.constants import HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import first_char_to_lower

LOG = logging.getLogger(__name__)

DEFAULT_MAX_RECEIVE_COUNT = 10


class SqsPoller(Poller):
    queue_url: str

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
    ):
        super().__init__(source_arn, source_parameters, source_client, processor)
        self.queue_url = get_queue_url(self.source_arn)
        self._register_client_hooks()

    @property
    def sqs_queue_parameters(self) -> PipeSourceSqsQueueParameters:
        return self.source_parameters["SqsQueueParameters"]

    @cached_property
    def is_fifo_queue(self) -> bool:
        # Alternative heuristic: self.queue_url.endswith(".fifo"), but we need the call to get_queue_attributes for IAM
        return self.get_queue_attributes().get("FifoQueue", "false").lower() == "true"

    def _register_client_hooks(self):
        event_system = self.source_client.meta.events

        def _handle_receive_message_override(params, context, **kwargs):
            requested_count = params.get("MaxNumberOfMessages")
            if not requested_count or requested_count <= DEFAULT_MAX_RECEIVE_COUNT:
                return

            # Allow overide parameter to be greater than default and less than maximum batch size.
            # Useful for getting remaining records less than the batch size. i.e we need 100 records but BatchSize is 1k.
            override = min(requested_count, self.sqs_queue_parameters["BatchSize"])
            context[HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT] = str(override)

        def _handle_delete_batch_override(params, context, **kwargs):
            requested_count = len(params.get("Entries", []))
            if not requested_count or requested_count <= DEFAULT_MAX_RECEIVE_COUNT:
                return

            override = min(requested_count, self.sqs_queue_parameters["BatchSize"])
            context[HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT] = str(override)

        def _handler_inject_header(params, context, **kwargs):
            if override := context.pop(HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT, None):
                params["headers"][HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT] = override

        event_system.register(
            "provide-client-params.sqs.ReceiveMessage", _handle_receive_message_override
        )
        # Since we delete SQS messages after processing, this allows us to remove up to 10K entries at a time.
        event_system.register(
            "provide-client-params.sqs.DeleteMessageBatch", _handle_delete_batch_override
        )
        event_system.register("before-call.sqs.*", _handler_inject_header)

    def get_queue_attributes(self) -> dict:
        """The API call to sqs:GetQueueAttributes is required for IAM policy streamsing."""
        get_queue_attributes_response = self.source_client.get_queue_attributes(
            QueueUrl=self.queue_url,
            AttributeNames=["FifoQueue"],
        )
        return get_queue_attributes_response.get("Attributes", {})

    def event_source(self) -> str:
        return "aws:sqs"

    def collect_messages(self, max_batch_size=10, max_batch_window=0, **kwargs) -> list[dict]:
        # TODO: Set to max_batch_size when override message count changes are merged.
        messages_per_receive = min(DEFAULT_MAX_RECEIVE_COUNT, max_batch_size)

        # Number of messages we want to receive per ReceiveMessage operation.
        def receive_message(num_messages: int = messages_per_receive):
            response = self.source_client.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=num_messages,
                MessageAttributeNames=["All"],
                MessageSystemAttributeNames=[MessageSystemAttributeName.All],
            )
            return response.get("Messages", [])

        batch = []
        start_collection_t = time.monotonic()
        while len(batch) < max_batch_size:
            # Adjust request size if we're close to max_batch_size
            if (remaining := max_batch_size - len(batch)) < messages_per_receive:
                messages_per_receive = remaining

            try:
                messages = receive_message(messages_per_receive)
            except Exception as e:
                # If an exception is raised here, break the loop and return whatever
                # has been collected early.
                # TODO: Handle exceptions differently i.e QueueNotExist or ConnectionFailed should retry with backoff
                LOG.warning(
                    "Polling SQS queue %s failed: %s",
                    self.source_arn,
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                break

            if messages:
                batch.extend(messages)

            time_elapsed = time.monotonic() - start_collection_t
            if time_elapsed >= max_batch_window or len(batch) >= max_batch_size:
                return batch

            # 1. Naive approach: jitter iterations between 2 values i.e [0.02-0.002]
            # 2. Ideal rate of sending: limit the SQS iterations to adhere to some rate-limit i.e 50/s
            # 3. Rate limit on gateway?
            # 4. Long-polling on the SQS provider

        return batch

    def poll_events(self) -> None:
        # SQS pipe source: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-sqs.html
        # "The 9 Ways an SQS Message can be Deleted": https://lucvandonkersgoed.com/2022/01/20/the-9-ways-an-sqs-message-can-be-deleted/
        # TODO: implement invocation payload size quota
        # TODO: consider long-polling vs. short-polling trade-off. AWS uses long-polling:
        #  https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-sqs.html#pipes-sqs-scaling
        collected_messages = self.collect_messages(
            max_batch_size=self.sqs_queue_parameters["BatchSize"],
            max_batch_window=self.sqs_queue_parameters["MaximumBatchingWindowInSeconds"],
        )

        # NOTE: If the collection of messages exceeds the 6MB size-limit imposed on payloads sent to a Lambda,
        # split into chunks of up to 6MB each.
        # See https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html#invocation-eventsourcemapping-batching
        for messages in batched_by_size(collected_messages, 5e6):
            LOG.debug("Polled %d events from %s", len(messages), self.source_arn)
            try:
                if self.is_fifo_queue:
                    # TODO: think about starvation behavior because once failing message could block other groups
                    fifo_groups = split_by_message_group_id(messages)
                    for fifo_group_messages in fifo_groups.values():
                        self.handle_messages(fifo_group_messages)
                else:
                    self.handle_messages(messages)

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
            batch_size = self.sqs_queue_parameters.get("BatchSize", DEFAULT_MAX_RECEIVE_COUNT)
            for batched_entries in batched(entries, batch_size):
                self.source_client.delete_message_batch(
                    QueueUrl=self.queue_url, Entries=batched_entries
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
