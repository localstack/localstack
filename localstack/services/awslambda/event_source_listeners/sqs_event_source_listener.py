import logging
import time
from typing import Dict, List

from localstack.services.awslambda import lambda_executors
from localstack.services.awslambda.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.awslambda.lambda_api import (
    get_event_sources,
    message_attributes_to_lower,
    run_lambda,
)
from localstack.services.awslambda.lambda_executors import InvocationResult
from localstack.utils.aws import aws_stack
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class SQSEventSourceListener(EventSourceListener):
    # SQS listener thread settings
    SQS_LISTENER_THREAD: Dict = {}
    SQS_POLL_INTERVAL_SEC: float = 1

    @staticmethod
    def source_type():
        return "sqs"

    def start(self):
        if self.SQS_LISTENER_THREAD:
            return

        LOG.debug("Starting SQS message polling thread for Lambda API")
        self.SQS_LISTENER_THREAD["_thread_"] = thread = FuncThread(self._listener_loop)
        thread.start()

    def get_matching_event_sources(self) -> List[Dict]:
        return get_event_sources(source_arn=r".*:sqs:.*")

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
                    region_name = queue_arn.split(":")[3]
                    sqs_client = aws_stack.connect_to_service("sqs", region_name=region_name)
                    batch_size = max(min(source.get("BatchSize", 1), 10), 1)

                    try:
                        queue_url = aws_stack.sqs_queue_url_for_arn(queue_arn)
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
                            LOG.debug("Unable to poll SQS messages for queue %s: %s", queue_arn, e)

            except Exception:
                pass
            finally:
                time.sleep(self.SQS_POLL_INTERVAL_SEC)

    def _process_messages_for_event_source(self, source, messages):
        lambda_arn = source["FunctionArn"]
        queue_arn = source["EventSourceArn"]
        region_name = queue_arn.split(":")[3]
        queue_url = aws_stack.sqs_queue_url_for_arn(queue_arn)
        LOG.debug("Sending event from event source %s to Lambda %s", queue_arn, lambda_arn)
        res = self._send_event_to_lambda(
            queue_arn,
            queue_url,
            lambda_arn,
            messages,
            region=region_name,
        )
        return res

    def _send_event_to_lambda(self, queue_arn, queue_url, lambda_arn, messages, region) -> bool:
        def delete_messages(result, func_arn, event, error=None, **kwargs):
            if error:
                # Skip deleting messages from the queue in case of processing errors. We'll pick them up and retry
                # next time they become visible in the queue. Redrive policies will be handled automatically by SQS
                # on the next polling attempt.
                return

            region_name = queue_arn.split(":")[3]
            sqs_client = aws_stack.connect_to_service("sqs", region_name=region_name)
            entries = [
                {"Id": r["receiptHandle"], "ReceiptHandle": r["receiptHandle"]} for r in records
            ]
            try:
                sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)
            except Exception as e:
                LOG.info(
                    "Unable to delete Lambda events from SQS queue "
                    + "(please check SQS visibility timeout settings): %s - %s" % (entries, e)
                )

        records = []
        for msg in messages:
            message_attrs = message_attributes_to_lower(msg.get("MessageAttributes"))
            record = {
                "body": msg.get("Body", "MessageBody"),
                "receiptHandle": msg.get("ReceiptHandle"),
                "md5OfBody": msg.get("MD5OfBody") or msg.get("MD5OfMessageBody"),
                "eventSourceARN": queue_arn,
                "eventSource": lambda_executors.EVENT_SOURCE_SQS,
                "awsRegion": region,
                "messageId": msg["MessageId"],
                "attributes": msg.get("Attributes", {}),
                "messageAttributes": message_attrs,
            }

            if md5OfMessageAttributes := msg.get("MD5OfMessageAttributes"):
                record["md5OfMessageAttributes"] = md5OfMessageAttributes

            records.append(record)

        event = {"Records": records}

        res = run_lambda(
            func_arn=lambda_arn,
            event=event,
            context={},
            asynchronous=True,
            callback=delete_messages,
        )
        if isinstance(res, InvocationResult):
            status_code = getattr(res.result, "status_code", 0)
            if status_code >= 400:
                return False
        return True
