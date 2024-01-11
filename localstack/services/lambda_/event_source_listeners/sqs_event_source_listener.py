import json
import logging
import time
from typing import Dict, List, Optional

from localstack import config
from localstack.aws.api.lambda_ import InvocationType
from localstack.services.lambda_.event_source_listeners.adapters import (
    EventSourceAdapter,
)
from localstack.services.lambda_.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.lambda_.event_source_listeners.lambda_legacy import LegacyInvocationResult
from localstack.services.lambda_.event_source_listeners.utils import (
    filter_stream_records,
    message_attributes_to_lower,
)
from localstack.utils.aws import arns
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class SQSEventSourceListener(EventSourceListener):
    # SQS listener thread settings
    SQS_LISTENER_THREAD: Dict = {}
    SQS_POLL_INTERVAL_SEC: float = config.LAMBDA_SQS_EVENT_SOURCE_MAPPING_INTERVAL_SEC

    _invoke_adapter: EventSourceAdapter

    @staticmethod
    def source_type():
        return "sqs"

    def start(self, invoke_adapter: Optional[EventSourceAdapter] = None):
        self._invoke_adapter = invoke_adapter
        if self._invoke_adapter is None:
            LOG.error("Invoke adapter needs to be set for new Lambda provider. Aborting.")
            raise Exception("Invoke adapter not set ")

        if self.SQS_LISTENER_THREAD:
            return

        LOG.debug("Starting SQS message polling thread for Lambda API")
        self.SQS_LISTENER_THREAD["_thread_"] = thread = FuncThread(
            self._listener_loop, name="sqs-event-source-listener"
        )
        thread.start()

    def get_matching_event_sources(self) -> List[Dict]:
        return self._invoke_adapter.get_event_sources(source_arn=r".*:sqs:.*")

    def _listener_loop(self, *args):
        while True:
            try:
                sources = self.get_matching_event_sources()
                if not sources:
                    # Temporarily disable polling if no event sources are configured
                    # anymore. The loop will get restarted next time a message
                    # arrives and if an event source is configured.
                    self.SQS_LISTENER_THREAD.pop("_thread_")
                    return

                for source in sources:
                    queue_arn = source["EventSourceArn"]
                    region_name = extract_region_from_arn(queue_arn)

                    sqs_client = self._get_client(
                        function_arn=source["FunctionArn"], region_name=region_name
                    )
                    batch_size = max(min(source.get("BatchSize", 1), 10), 1)

                    try:
                        queue_url = arns.sqs_queue_url_for_arn(queue_arn)
                        result = sqs_client.receive_message(
                            QueueUrl=queue_url,
                            AttributeNames=["All"],
                            MessageAttributeNames=["All"],
                            MaxNumberOfMessages=batch_size,
                        )
                        messages = result.get("Messages")
                        if not messages:
                            continue

                        self._process_messages_for_event_source(source, messages)

                    except Exception as e:
                        if "NonExistentQueue" not in str(e):
                            # TODO: remove event source if queue does no longer exist?
                            LOG.debug(
                                "Unable to poll SQS messages for queue %s: %s",
                                queue_arn,
                                e,
                                exc_info=True,
                            )

            except Exception as e:
                LOG.debug(e)
            finally:
                time.sleep(self.SQS_POLL_INTERVAL_SEC)

    def _process_messages_for_event_source(self, source, messages) -> None:
        lambda_arn = source["FunctionArn"]
        queue_arn = source["EventSourceArn"]
        # https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#services-sqs-batchfailurereporting
        report_partial_failures = "ReportBatchItemFailures" in source.get(
            "FunctionResponseTypes", []
        )
        region_name = extract_region_from_arn(queue_arn)
        queue_url = arns.sqs_queue_url_for_arn(queue_arn)
        LOG.debug("Sending event from event source %s to Lambda %s", queue_arn, lambda_arn)
        self._send_event_to_lambda(
            queue_arn,
            queue_url,
            lambda_arn,
            messages,
            region=region_name,
            report_partial_failures=report_partial_failures,
        )

    def _get_client(self, function_arn: str, region_name: str):
        return self._invoke_adapter.get_client_factory(
            function_arn=function_arn, region_name=region_name
        ).sqs.request_metadata(source_arn=function_arn)

    def _get_lambda_event_filters_for_arn(self, function_arn: str, queue_arn: str):
        result = []
        sources = self._invoke_adapter.get_event_sources(queue_arn)
        filtered_sources = [s for s in sources if s["FunctionArn"] == function_arn]

        for fs in filtered_sources:
            fc = fs.get("FilterCriteria")
            if fc:
                result.append(fc)
        return result

    def _send_event_to_lambda(
        self, queue_arn, queue_url, lambda_arn, messages, region, report_partial_failures=False
    ) -> None:
        records = []

        def delete_messages(result: LegacyInvocationResult, func_arn, event, error=None, **kwargs):
            if error:
                # Skip deleting messages from the queue in case of processing errors. We'll pick them up and retry
                # next time they become visible in the queue. Redrive policies will be handled automatically by SQS
                # on the next polling attempt.
                # Even if ReportBatchItemFailures is set, the entire batch fails if an error is raised.
                return

            region_name = extract_region_from_arn(queue_arn)
            sqs_client = self._get_client(function_arn=lambda_arn, region_name=region_name)

            if report_partial_failures:
                valid_message_ids = [r["messageId"] for r in records]
                # collect messages to delete (= the ones that were processed successfully)
                try:
                    if messages_to_keep := parse_batch_item_failures(
                        result, valid_message_ids=valid_message_ids
                    ):
                        # unless there is an exception or the parse result is empty, only delete those messages that
                        # are not part of the partial failure report.
                        messages_to_delete = [
                            message_id
                            for message_id in valid_message_ids
                            if message_id not in messages_to_keep
                        ]
                    else:
                        # otherwise delete all messages
                        messages_to_delete = valid_message_ids

                    LOG.debug(
                        "Lambda partial SQS batch failure report: ok=%s, failed=%s",
                        messages_to_delete,
                        messages_to_keep,
                    )
                except Exception as e:
                    LOG.error(
                        "Error while parsing batchItemFailures from lambda response %s: %s. "
                        "Treating the batch as complete failure.",
                        result.result,
                        e,
                    )
                    return

                entries = [
                    {"Id": r["messageId"], "ReceiptHandle": r["receiptHandle"]}
                    for r in records
                    if r["messageId"] in messages_to_delete
                ]

            else:
                entries = [
                    {"Id": r["messageId"], "ReceiptHandle": r["receiptHandle"]} for r in records
                ]

            try:
                sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)
            except Exception as e:
                LOG.info(
                    "Unable to delete Lambda events from SQS queue "
                    + "(please check SQS visibility timeout settings): %s - %s" % (entries, e)
                )

        for msg in messages:
            message_attrs = message_attributes_to_lower(msg.get("MessageAttributes"))
            record = {
                "body": msg.get("Body", "MessageBody"),
                "receiptHandle": msg.get("ReceiptHandle"),
                "md5OfBody": msg.get("MD5OfBody") or msg.get("MD5OfMessageBody"),
                "eventSourceARN": queue_arn,
                "eventSource": "aws:sqs",
                "awsRegion": region,
                "messageId": msg["MessageId"],
                "attributes": msg.get("Attributes", {}),
                "messageAttributes": message_attrs,
            }

            if md5OfMessageAttributes := msg.get("MD5OfMessageAttributes"):
                record["md5OfMessageAttributes"] = md5OfMessageAttributes

            records.append(record)

        event_filter_criterias = self._get_lambda_event_filters_for_arn(lambda_arn, queue_arn)
        if len(event_filter_criterias) > 0:
            # convert to json for filtering
            for record in records:
                try:
                    record["body"] = json.loads(record["body"])
                except json.JSONDecodeError:
                    LOG.warning(
                        f"Unable to convert record '{record['body']}' to json... Record might be dropped."
                    )
            records = filter_stream_records(records, event_filter_criterias)
            # convert them back
            for record in records:
                record["body"] = (
                    json.dumps(record["body"])
                    if not isinstance(record["body"], str)
                    else record["body"]
                )

        # all messages were filtered out
        if not len(records) > 0:
            return

        event = {"Records": records}

        self._invoke_adapter.invoke(
            function_arn=lambda_arn,
            context={},
            payload=event,
            invocation_type=InvocationType.RequestResponse,
            callback=delete_messages,
        )


def parse_batch_item_failures(
    result: LegacyInvocationResult, valid_message_ids: List[str]
) -> List[str]:
    """
    Parses a lambda responses as a partial batch failure response, that looks something like this::

        {
          "batchItemFailures": [
                {
                    "itemIdentifier": "id2"
                },
                {
                    "itemIdentifier": "id4"
                }
            ]
        }

    If the response returns an empty list, then the batch should be considered as a complete success. If an exception
    is raised, the batch should be considered a complete failure.

    See https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html#services-sqs-batchfailurereporting

    :param result: the lambda invocation result
    :param valid_message_ids: the list of valid message ids in the batch
    :raises KeyError: if the itemIdentifier value is missing or not in the batch
    :raises Exception: any other exception related to parsing (e.g., JSON parser error)
    :return: a list of message IDs that are part of a failure and should not be deleted from the queue
    """
    if not result or not result.result:
        return []

    if isinstance(result.result, dict):
        partial_batch_failure = result.result
    else:
        partial_batch_failure = json.loads(result.result)

    if not partial_batch_failure:
        return []

    batch_item_failures = partial_batch_failure.get("batchItemFailures")

    if not batch_item_failures:
        return []

    messages_to_keep = []
    for item in batch_item_failures:
        if "itemIdentifier" not in item:
            raise KeyError(f"missing itemIdentifier in batchItemFailure record {item}")

        item_identifier = item["itemIdentifier"]

        if item_identifier not in valid_message_ids:
            raise KeyError(f"itemIdentifier '{item_identifier}' not in the batch")

        messages_to_keep.append(item_identifier)

    return messages_to_keep
