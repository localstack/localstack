import logging
from collections import defaultdict
from functools import cached_property

from botocore.client import BaseClient

from localstack.aws.api.pipes import PipeSourceSqsQueueParameters
from localstack.config import internal_service_url
from localstack.services.lambda_.event_source_listeners.utils import message_attributes_to_lower
from localstack.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
    PartialBatchFailureError,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import (
    Poller,
    parse_batch_item_failures,
)
from localstack.utils.aws.arns import parse_arn

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

    @property
    def sqs_queue_parameters(self) -> PipeSourceSqsQueueParameters:
        return self.source_parameters["SqsQueueParameters"]

    @cached_property
    def is_fifo_queue(self) -> bool:
        # Alternative heuristic: self.queue_url.endswith(".fifo"), but we need the call to get_queue_attributes for IAM
        return self.get_queue_attributes().get("FifoQueue") == "true"

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
        # SQS pipe source: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-sqs.html
        # "The 9 Ways an SQS Message can be Deleted": https://lucvandonkersgoed.com/2022/01/20/the-9-ways-an-sqs-message-can-be-deleted/
        # TODO: implement batch window expires based on MaximumBatchingWindowInSeconds
        # TODO: implement invocation payload size quota
        # TODO: consider long-polling vs. short-polling trade-off. AWS uses long-polling:
        #  https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-sqs.html#pipes-sqs-scaling
        response = self.source_client.receive_message(
            QueueUrl=self.queue_url,
            MaxNumberOfMessages=self.sqs_queue_parameters["BatchSize"],
            AttributeNames=["All"],
        )
        if messages := response.get("Messages"):
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
        matching_events = self.filter_events(polled_events)
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
            self.source_client.delete_message_batch(QueueUrl=self.queue_url, Entries=entries)


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
        # TODO: test with message attributes
        if "MD5OfMessageAttributes" in message:
            event["md5OfMessageAttributes"] = message["md5OfMessageAttributes"]
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
