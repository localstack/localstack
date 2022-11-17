import copy
import hashlib
import heapq
import inspect
import logging
import re
import threading
import time
from queue import PriorityQueue
from typing import Dict, NamedTuple, Optional, Set

from localstack import config, constants
from localstack.aws.api import RequestContext
from localstack.aws.api.sqs import (
    InvalidAttributeName,
    Message,
    MessageNotInflight,
    MessageSystemAttributeName,
    QueueAttributeMap,
    QueueAttributeName,
    ReceiptHandleIsInvalid,
    TagMap,
)
from localstack.config import external_service_url
from localstack.services.sqs import constants as sqs_constants
from localstack.services.sqs.exceptions import (
    InvalidAttributeValue,
    InvalidParameterValue,
    MissingParameter,
)
from localstack.services.sqs.utils import (
    decode_receipt_handle,
    encode_receipt_handle,
    global_message_sequence,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.time import now

LOG = logging.getLogger(__name__)


class SqsMessage:
    message: Message
    created: float
    visibility_timeout: int
    receive_times: int
    delay_seconds: Optional[int]
    receipt_handles: Set[str]
    last_received: Optional[float]
    first_received: Optional[float]
    visibility_deadline: Optional[float]
    deleted: bool
    priority: float
    message_deduplication_id: str
    message_group_id: str
    sequence_number: str

    def __init__(
        self,
        priority: float,
        message: Message,
        message_deduplication_id: str = None,
        message_group_id: str = None,
        sequence_number: str = None,
    ) -> None:
        self.created = time.time()
        self.message = message
        self.receive_times = 0
        self.receipt_handles = set()

        self.delay_seconds = None
        self.last_received = None
        self.first_received = None
        self.deleted = False
        self.priority = priority
        self.sequence_number = sequence_number

        attributes = {}
        if message_group_id is not None:
            attributes["MessageGroupId"] = message_group_id
        if message_deduplication_id is not None:
            attributes["MessageDeduplicationId"] = message_deduplication_id
        if sequence_number is not None:
            attributes["SequenceNumber"] = sequence_number

        if self.message.get("Attributes"):
            self.message["Attributes"].update(attributes)
        else:
            self.message["Attributes"] = attributes

    @property
    def message_group_id(self) -> Optional[str]:
        return self.message["Attributes"].get("MessageGroupId")

    @property
    def message_deduplication_id(self) -> Optional[str]:
        return self.message["Attributes"].get("MessageDeduplicationId")

    def set_last_received(self, timestamp: float):
        """
        Sets the last received timestamp of the message to the given value, and updates the visibility deadline
        accordingly.

        :param timestamp: the last time the message was received
        """
        self.last_received = timestamp
        self.visibility_deadline = timestamp + self.visibility_timeout

    def update_visibility_timeout(self, timeout: int):
        """
        Sets the visibility timeout of the message to the given value, and updates the visibility deadline accordingly.

        :param timeout: the timeout value in seconds
        """
        self.visibility_timeout = timeout
        self.visibility_deadline = time.time() + timeout

    @property
    def is_visible(self) -> bool:
        """
        Returns false if the message has a visibility deadline that is in the future.

        :return: whether the message is visibile or not.
        """
        if self.visibility_deadline is None:
            return True
        if time.time() >= self.visibility_deadline:
            return True

        return False

    @property
    def is_delayed(self) -> bool:
        if self.delay_seconds is None:
            return False
        return time.time() <= self.created + self.delay_seconds

    def __gt__(self, other):
        return self.priority > other.priority

    def __ge__(self, other):
        return self.priority >= other.priority

    def __lt__(self, other):
        return self.priority < other.priority

    def __le__(self, other):
        return self.priority <= other.priority

    def __eq__(self, other):
        return self.message["MessageId"] == other.message["MessageId"]

    def __hash__(self):
        return self.message["MessageId"].__hash__()


class Permission(NamedTuple):
    # TODO: just a placeholder for real policies
    label: str
    account_id: str
    action: str


class SqsQueue:
    name: str
    region: str
    account_id: str

    attributes: QueueAttributeMap
    tags: TagMap
    permissions: Set[Permission]

    purge_in_progress: bool
    purge_timestamp: Optional[float]

    visible: PriorityQueue
    delayed: Set[SqsMessage]
    inflight: Set[SqsMessage]
    receipts: Dict[str, SqsMessage]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        self.name = name
        self.region = region
        self.account_id = account_id

        self._assert_queue_name(name)
        self.tags = tags or {}

        self.visible = PriorityQueue()
        self.delayed = set()
        self.inflight = set()
        self.receipts = {}

        self.attributes = self.default_attributes()
        if attributes:
            self.attributes.update(attributes)

        self.purge_in_progress = False
        self.purge_timestamp = None

        self.permissions = set()
        self.mutex = threading.RLock()

    def default_attributes(self) -> QueueAttributeMap:
        return {
            QueueAttributeName.ApproximateNumberOfMessages: lambda: self.approx_number_of_messages,
            QueueAttributeName.ApproximateNumberOfMessagesNotVisible: lambda: self.approx_number_of_messages_not_visible,
            QueueAttributeName.ApproximateNumberOfMessagesDelayed: lambda: self.approx_number_of_messages_delayed,
            QueueAttributeName.CreatedTimestamp: str(now()),
            QueueAttributeName.DelaySeconds: "0",
            QueueAttributeName.LastModifiedTimestamp: str(now()),
            QueueAttributeName.MaximumMessageSize: str(sqs_constants.DEFAULT_MAXIMUM_MESSAGE_SIZE),
            QueueAttributeName.MessageRetentionPeriod: "345600",
            QueueAttributeName.QueueArn: self.arn,
            QueueAttributeName.ReceiveMessageWaitTimeSeconds: "0",
            QueueAttributeName.VisibilityTimeout: "30",
            QueueAttributeName.SqsManagedSseEnabled: "false",
        }

    def update_delay_seconds(self, value: int):
        """
        For standard queues, the per-queue delay setting is not retroactive—changing the setting doesn't affect the delay of messages already in the queue.
        For FIFO queues, the per-queue delay setting is retroactive—changing the setting affects the delay of messages already in the queue.

        https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-delay-queues.html

        :param value: the number of seconds
        """
        self.attributes[QueueAttributeName.DelaySeconds] = str(value)

    def update_last_modified(self, timestamp: int = None):
        if timestamp is None:
            timestamp = now()

        self.attributes[QueueAttributeName.LastModifiedTimestamp] = str(timestamp)

    @property
    def arn(self) -> str:
        return f"arn:aws:sqs:{self.region}:{self.account_id}:{self.name}"

    def url(self, context: RequestContext) -> str:
        """Return queue URL using either SQS_PORT_EXTERNAL (if configured), the SQS_ENDPOINT_STRATEGY (if configured)
        or based on the 'Host' request header"""

        host_url = context.request.host_url

        if config.SQS_ENDPOINT_STRATEGY == "domain":
            # queue.localhost.localstack.cloud:4566/000000000000/my-queue (us-east-1)
            # or us-east-2.queue.localhost.localstack.cloud:4566/000000000000/my-queue
            region = "" if self.region == "us-east-1" else self.region + "."
            scheme = context.request.scheme
            host_url = f"{scheme}://{region}queue.{constants.LOCALHOST_HOSTNAME}:{config.EDGE_PORT}"
        elif config.SQS_ENDPOINT_STRATEGY == "path":
            # https?://localhost:4566/queue/us-east-1/00000000000/my-queue (us-east-1)
            host_url = f"{context.request.host_url}/queue/{self.region}"
        else:
            if config.SQS_PORT_EXTERNAL:
                host_url = external_service_url("sqs")

        return "{host}/{account_id}/{name}".format(
            host=host_url.rstrip("/"),
            account_id=self.account_id,
            name=self.name,
        )

    @property
    def visibility_timeout(self) -> int:
        return int(self.attributes[QueueAttributeName.VisibilityTimeout])

    @property
    def delay_seconds(self) -> int:
        return int(self.attributes[QueueAttributeName.DelaySeconds])

    @property
    def wait_time_seconds(self) -> int:
        return int(self.attributes[QueueAttributeName.ReceiveMessageWaitTimeSeconds])

    @property
    def maximum_message_size(self):
        return int(self.attributes[QueueAttributeName.MaximumMessageSize])

    @property
    def approx_number_of_messages(self):
        return self.visible._qsize()

    @property
    def approx_number_of_messages_not_visible(self):
        return len(self.inflight)

    @property
    def approx_number_of_messages_delayed(self):
        return len(self.delayed)

    def validate_receipt_handle(self, receipt_handle: str):
        if self.arn != decode_receipt_handle(receipt_handle):
            raise ReceiptHandleIsInvalid(
                f'The input receipt handle "{receipt_handle}" is not a valid receipt handle.'
            )

    def update_visibility_timeout(self, receipt_handle: str, visibility_timeout: int):
        with self.mutex:
            self.validate_receipt_handle(receipt_handle)

            if receipt_handle not in self.receipts:
                raise InvalidParameterValue(
                    f"Value {receipt_handle} for parameter ReceiptHandle is invalid. Reason: Message does not exist "
                    f"or is not available for visibility timeout change."
                )

            standard_message = self.receipts[receipt_handle]

            if standard_message not in self.inflight:
                raise MessageNotInflight()

            standard_message.update_visibility_timeout(visibility_timeout)

            if visibility_timeout == 0:
                LOG.info(
                    "terminating the visibility timeout of %s",
                    standard_message.message["MessageId"],
                )
                # Terminating the visibility timeout for a message
                # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html#terminating-message-visibility-timeout
                self.inflight.remove(standard_message)
                self.visible.put_nowait(standard_message)

    def remove(self, receipt_handle: str):
        with self.mutex:
            self.validate_receipt_handle(receipt_handle)

            if receipt_handle not in self.receipts:
                LOG.debug(
                    "no in-flight message found for receipt handle %s in queue %s",
                    receipt_handle,
                    self.arn,
                )
                return

            standard_message = self.receipts[receipt_handle]
            standard_message.deleted = True
            LOG.debug(
                "deleting message %s from queue %s",
                standard_message.message["MessageId"],
                self.arn,
            )

            # remove all handles
            for handle in standard_message.receipt_handles:
                del self.receipts[handle]
            standard_message.receipt_handles.clear()

            # remove in-flight message
            try:
                self.inflight.remove(standard_message)
            except KeyError:
                # this means the message was re-queued in the meantime
                # TODO: remove this message from the visible queue if it exists: a message can be removed with an old
                #  receipt handle that was issued before the message was put back in the visible queue.
                self.visible.queue.remove(standard_message)
                heapq.heapify(self.visible.queue)

    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
        delay_seconds: int = None,
    ) -> SqsMessage:
        raise NotImplementedError

    def get(self, block=True, timeout=None, visibility_timeout: int = None) -> SqsMessage:
        start = time.time()
        while True:
            standard_message: SqsMessage = self.visible.get(block=block, timeout=timeout)
            LOG.debug(
                "de-queued message %s from %s", standard_message.message["MessageId"], self.arn
            )

            with self.mutex:
                if standard_message.deleted:
                    # TODO: check what the behavior of AWS is here. should we return a deleted message?
                    timeout -= time.time() - start
                    if timeout < 0:
                        timeout = 0
                    continue

                # update message attributes
                standard_message.visibility_timeout = (
                    self.visibility_timeout if visibility_timeout is None else visibility_timeout
                )
                standard_message.receive_times += 1
                standard_message.set_last_received(time.time())
                if standard_message.first_received is None:
                    standard_message.first_received = standard_message.last_received

                # create and manage receipt handle
                receipt_handle = self.create_receipt_handle(standard_message)
                standard_message.receipt_handles.add(receipt_handle)
                self.receipts[receipt_handle] = standard_message

                if standard_message.visibility_timeout == 0:
                    self.visible.put_nowait(standard_message)
                else:
                    self.inflight.add(standard_message)

            # prepare message for receiver
            copied_message = copy.deepcopy(standard_message)
            copied_message.message["Attributes"][
                MessageSystemAttributeName.ApproximateReceiveCount
            ] = str(standard_message.receive_times)
            copied_message.message["Attributes"][
                MessageSystemAttributeName.ApproximateFirstReceiveTimestamp
            ] = str(int(standard_message.first_received * 1000))
            copied_message.message["ReceiptHandle"] = receipt_handle

            return copied_message

    def clear(self):
        """
        Calls clear on all internal datastructures that hold messages and data related to them.
        """
        with self.mutex:
            self.visible.queue.clear()
            self.inflight.clear()
            self.delayed.clear()
            self.receipts.clear()

    def create_receipt_handle(self, message: SqsMessage) -> str:
        return encode_receipt_handle(self.arn, message)

    def requeue_inflight_messages(self):
        if not self.inflight:
            return

        with self.mutex:
            messages = [message for message in self.inflight if message.is_visible]
            for standard_message in messages:
                LOG.debug(
                    "re-queueing inflight messages %s into queue %s",
                    standard_message.message["MessageId"],
                    self.arn,
                )
                self.inflight.remove(standard_message)
                self.visible.put_nowait(standard_message)

    def enqueue_delayed_messages(self):
        if not self.delayed:
            return

        with self.mutex:
            messages = [message for message in self.delayed if not message.is_delayed]
            for standard_message in messages:
                LOG.debug(
                    "enqueueing delayed messages %s into queue %s",
                    standard_message.message["MessageId"],
                    self.arn,
                )
                self.delayed.remove(standard_message)
                self.visible.put_nowait(standard_message)

    def _assert_queue_name(self, name):
        if not re.match(r"^[a-zA-Z0-9_-]{1,80}$", name):
            raise InvalidParameterValue(
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
            )

    def validate_queue_attributes(self, attributes):
        valid = [
            k[1]
            for k in inspect.getmembers(QueueAttributeName)
            if k not in sqs_constants.INTERNAL_QUEUE_ATTRIBUTES
        ]
        del valid[valid.index(QueueAttributeName.FifoQueue)]

        for k in attributes.keys():
            if k not in valid:
                raise InvalidAttributeName(f"Unknown Attribute {k}.")


class StandardQueue(SqsQueue):
    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
        delay_seconds: int = None,
    ):
        if message_deduplication_id:
            raise InvalidParameterValue(
                f"Value {message_deduplication_id} for parameter MessageDeduplicationId is invalid. Reason: The "
                f"request includes a parameter that is not valid for this queue type. "
            )
        if message_group_id:
            raise InvalidParameterValue(
                f"Value {message_group_id} for parameter MessageGroupId is invalid. Reason: The request includes a "
                f"parameter that is not valid for this queue type. "
            )

        standard_message = SqsMessage(time.time(), message)

        if visibility_timeout is not None:
            standard_message.visibility_timeout = visibility_timeout
        else:
            # use the attribute from the queue
            standard_message.visibility_timeout = self.visibility_timeout

        if delay_seconds is not None:
            standard_message.delay_seconds = delay_seconds
        else:
            standard_message.delay_seconds = self.delay_seconds

        if standard_message.is_delayed:
            self.delayed.add(standard_message)
        else:
            self.visible.put_nowait(standard_message)

        return standard_message


class FifoQueue(SqsQueue):
    deduplication: Dict[str, Dict[str, SqsMessage]]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        super().__init__(name, region, account_id, attributes, tags)
        self.deduplication = {}

    def default_attributes(self) -> QueueAttributeMap:
        return {
            **super().default_attributes(),
            QueueAttributeName.ContentBasedDeduplication: "false",
            QueueAttributeName.DeduplicationScope: "queue",
            QueueAttributeName.FifoThroughputLimit: "perQueue",
        }

    def update_delay_seconds(self, value: int):
        super(FifoQueue, self).update_delay_seconds(value)
        for message in self.delayed:
            message.delay_seconds = value

    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
        delay_seconds: int = None,
    ):
        if delay_seconds:
            # in fifo queues, delay is only applied on queue level. However, explicitly setting delay_seconds=0 is valid
            raise InvalidParameterValue(
                f"Value {delay_seconds} for parameter DelaySeconds is invalid. Reason: The request include parameter "
                f"that is not valid for this queue type."
            )

        if not message_group_id:
            raise MissingParameter("The request must contain the parameter MessageGroupId.")
        dedup_id = message_deduplication_id
        content_based_deduplication = (
            "true"
            == (self.attributes.get(QueueAttributeName.ContentBasedDeduplication, "false")).lower()
        )
        if not dedup_id and content_based_deduplication:
            dedup_id = hashlib.sha256(message.get("Body").encode("utf-8")).hexdigest()
        if not dedup_id:
            raise InvalidParameterValue(
                "The Queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided "
                "explicitly "
            )

        fifo_message = SqsMessage(
            time.time(),
            message,
            message_deduplication_id=dedup_id,
            message_group_id=message_group_id,
            sequence_number=str(self.next_sequence_number()),
        )
        if visibility_timeout is not None:
            fifo_message.visibility_timeout = visibility_timeout
        else:
            # use the attribute from the queue
            fifo_message.visibility_timeout = self.visibility_timeout

        if delay_seconds is not None:
            fifo_message.delay_seconds = delay_seconds
        else:
            fifo_message.delay_seconds = self.delay_seconds

        original_message = None
        original_message_group = self.deduplication.get(message_group_id)
        if original_message_group:
            original_message = original_message_group.get(dedup_id)

        if (
            original_message
            and not original_message.deleted
            and original_message.priority + sqs_constants.DEDUPLICATION_INTERVAL_IN_SEC
            > fifo_message.priority
        ):
            message["MessageId"] = original_message.message["MessageId"]
        else:
            if fifo_message.is_delayed:
                self.delayed.add(fifo_message)
            else:
                self.visible.put_nowait(fifo_message)

            if not original_message_group:
                self.deduplication[message_group_id] = {}
            self.deduplication[message_group_id][dedup_id] = fifo_message

        return fifo_message

    def _assert_queue_name(self, name):
        if not name.endswith(".fifo"):
            raise InvalidParameterValue(
                "The name of a FIFO queue can only include alphanumeric characters, hyphens, or underscores, "
                "must end with .fifo suffix and be 1 to 80 in length"
            )
        # The .fifo suffix counts towards the 80-character queue name quota.
        queue_name = name[:-5] + "_fifo"
        super()._assert_queue_name(queue_name)

    def validate_queue_attributes(self, attributes):
        valid = [
            k[1]
            for k in inspect.getmembers(QueueAttributeName)
            if k not in sqs_constants.INTERNAL_QUEUE_ATTRIBUTES
        ]
        for k in attributes.keys():
            if k not in valid:
                raise InvalidAttributeName(f"Unknown Attribute {k}.")
        # Special Cases
        fifo = attributes.get(QueueAttributeName.FifoQueue)
        if fifo and fifo.lower() != "true":
            raise InvalidAttributeValue(
                "Invalid value for the parameter FifoQueue. Reason: Modifying queue type is not supported."
            )

    def next_sequence_number(self):
        return next(global_message_sequence())


class SqsStore(BaseStore):
    queues: Dict[str, SqsQueue] = LocalAttribute(default=dict)

    deleted: Dict[str, float] = LocalAttribute(default=dict)

    def expire_deleted(self):
        for k in list(self.deleted.keys()):
            if self.deleted[k] <= (time.time() - sqs_constants.RECENTLY_DELETED_TIMEOUT):
                del self.deleted[k]


sqs_stores = AccountRegionBundle("sqs", SqsStore)
