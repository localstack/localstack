import logging
import threading
from typing import Iterable

from localstack import config
from localstack.aws.api.sqs import (
    AttributeNameList,
    CreateQueueResult,
    GetQueueAttributesResult,
    Integer,
    Message,
    MessageAttributeNameList,
    MessageBodyAttributeMap,
    MessageBodySystemAttributeMap,
    MessageSystemAttributeName,
    QueueAttributeMap,
    ReceiveMessageResult,
    SendMessageResult,
    String,
    TagMap,
)
from localstack.services.sqs.models import SqsQueue, StandardQueue
from localstack.services.sqs.provider import (
    QueueUpdateWorker,
    _create_message_attribute_hash,
    to_sqs_api_message,
)
from localstack.services.sqs.utils import generate_message_id
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import md5
from localstack.utils.time import now

LOG = logging.getLogger(__name__)


class EventQueueUpdateWorker(QueueUpdateWorker):
    """
    Regularly re-queues inflight and delayed messages whose visibility timeout has expired or delay deadline has been
    reached.
    """

    def __init__(self) -> None:
        super().__init__()
        self.queues = []

    def add_queue(self, queue: SqsQueue):
        self.queues.append(queue)

    def remove_queue(self, queue: SqsQueue):
        self.queues.remove(queue)

    def iter_queues(self) -> Iterable[SqsQueue]:
        return iter(self.queues)


class QueueManager:
    queues: dict[str, StandardQueue]
    queue_lock: threading.RLock
    queue_update_worker: EventQueueUpdateWorker

    def __init__(self):
        self.queues = {}
        # lock for handling queue lifecycle and avoiding duplicates
        self.queue_lock = threading.RLock()
        self.queue_update_worker = EventQueueUpdateWorker()

    def start(self):
        self.queue_update_worker.start()

    def stop(self):
        self.queue_update_worker.stop()

    def get_queue(self, queue_name: str):
        if queue_name not in self.queues:
            raise ValueError("Queue not available")
        return self.queues[queue_name]

    def create_queue(self, queue_name: str) -> SqsQueue:
        """
        Creates a queue.
        :param queue_name: Queue name, has to be unique
        :return: Queue Object
        """
        with self.queue_lock:
            if queue_name in self.queues:
                return self.queues[queue_name]

            queue = StandardQueue(
                name=queue_name,
                region="us-east-1",
                account_id=config.INTERNAL_RESOURCE_ACCOUNT,
            )
            self.queues[queue_name] = queue
            self.queue_update_worker.add_queue(queue)
        return queue

    def delete_queue(self, queue_name: str) -> None:
        with self.queue_lock:
            if queue_name not in self.queues:
                raise ValueError(f"Queue '{queue_name}' not available")

            queue = self.queues.pop(queue_name)
            self.queue_update_worker.remove_queue(queue)


class FakeSqsClient:
    def __init__(self, queue_manager: QueueManager):
        self.queue_manager = queue_manager

    def create_queue(
        self, QueueName: String, Attributes: QueueAttributeMap = None, tags: TagMap = None
    ) -> CreateQueueResult:
        self.queue_manager.create_queue(queue_name=QueueName)
        return {"QueueUrl": QueueName}

    def delete_queue(self, QueueUrl: String) -> None:
        self.queue_manager.delete_queue(queue_name=QueueUrl)

    def get_queue_attributes(
        self, QueueUrl: String, AttributeNames: AttributeNameList = None
    ) -> GetQueueAttributesResult:
        queue = self.queue_manager.get_queue(queue_name=QueueUrl)
        result = queue.get_queue_attributes(AttributeNames)
        return {"Attributes": result}

    def purge_queue(self, QueueUrl: String) -> None:
        queue = self.queue_manager.get_queue(queue_name=QueueUrl)
        queue.clear()

    def receive_message(
        self,
        QueueUrl: String,
        AttributeNames: AttributeNameList = None,
        MessageAttributeNames: MessageAttributeNameList = None,
        MaxNumberOfMessages: Integer = None,
        VisibilityTimeout: Integer = None,
        WaitTimeSeconds: Integer = None,
        ReceiveRequestAttemptId: String = None,
    ) -> ReceiveMessageResult:
        queue = self.queue_manager.get_queue(queue_name=QueueUrl)
        num = MaxNumberOfMessages or 1
        result = queue.receive(
            num_messages=num,
            visibility_timeout=VisibilityTimeout,
            wait_time_seconds=WaitTimeSeconds,
        )

        messages = []
        for i, standard_message in enumerate(result.successful):
            message = to_sqs_api_message(standard_message, AttributeNames, MessageAttributeNames)
            message["ReceiptHandle"] = result.receipt_handles[i]
            messages.append(message)

        return {"Messages": messages if messages else None}

    def delete_message(self, QueueUrl: String, ReceiptHandle: String) -> None:
        queue = self.queue_manager.get_queue(queue_name=QueueUrl)
        queue.remove(ReceiptHandle)

    def _create_message_attributes(
        self,
        message_system_attributes: MessageBodySystemAttributeMap = None,
    ) -> dict[str, str]:
        result = {
            MessageSystemAttributeName.SenderId: config.INTERNAL_RESOURCE_ACCOUNT,  # not the account ID in AWS
            MessageSystemAttributeName.SentTimestamp: str(now(millis=True)),
        }

        if message_system_attributes is not None:
            for attr in message_system_attributes:
                result[attr] = message_system_attributes[attr]["StringValue"]

        return result

    def send_message(
        self,
        QueueUrl: String,
        MessageBody: String,
        DelaySeconds: Integer = None,
        MessageAttributes: MessageBodyAttributeMap = None,
        MessageSystemAttributes: MessageBodySystemAttributeMap = None,
        MessageDeduplicationId: String = None,
        MessageGroupId: String = None,
    ) -> SendMessageResult:
        queue = self.queue_manager.get_queue(queue_name=QueueUrl)

        message = Message(
            MessageId=generate_message_id(),
            MD5OfBody=md5(MessageBody),
            Body=MessageBody,
            Attributes=self._create_message_attributes(MessageSystemAttributes),
            MD5OfMessageAttributes=_create_message_attribute_hash(MessageAttributes),
            MessageAttributes=MessageAttributes,
        )
        queue_item = queue.put(
            message=message,
            message_deduplication_id=MessageDeduplicationId,
            message_group_id=MessageGroupId,
            delay_seconds=int(DelaySeconds) if DelaySeconds is not None else None,
        )
        message = queue_item.message
        return {
            "MessageId": message["MessageId"],
            "MD5OfMessageBody": message["MD5OfBody"],
            "MD5OfMessageAttributes": message.get("MD5OfMessageAttributes"),
            "SequenceNumber": queue_item.sequence_number,
            "MD5OfMessageSystemAttributes": _create_message_attribute_hash(MessageSystemAttributes),
        }


@singleton_factory
def get_fake_sqs_client():
    queue_manager = QueueManager()
    queue_manager.start()
    return FakeSqsClient(queue_manager)
