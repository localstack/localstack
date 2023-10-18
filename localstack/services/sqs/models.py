import hashlib
import heapq
import inspect
import json
import logging
import re
import threading
import time
from queue import Empty, PriorityQueue, Queue
from typing import Dict, Optional, Set

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.sqs import (
    InvalidAttributeName,
    Message,
    MessageNotInflight,
    QueueAttributeMap,
    QueueAttributeName,
    ReceiptHandleIsInvalid,
    TagMap,
)
from localstack.config import get_protocol
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
    is_message_deduplication_id_required,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.time import now
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

ReceiptHandle = str


class SqsMessage:
    message: Message
    created: float
    visibility_timeout: int
    receive_count: int
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
        self.receive_count = 0
        self.receipt_handles = set()

        self.delay_seconds = None
        self.last_received = None
        self.first_received = None
        self.visibility_deadline = None
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

    @property
    def message_id(self):
        return self.message["MessageId"]

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
        return self.message_id == other.message_id

    def __hash__(self):
        return self.message_id.__hash__()

    def __repr__(self):
        return f"SqsMessage(id={self.message_id},group={self.message_group_id})"


class ReceiveMessageResult:
    """
    Object to communicate the result of a "receive messages" operation between the SqsProvider and
    the underlying datastructure holding the messages.
    """

    successful: list[SqsMessage]
    """The messages that were successfully received from the queue"""

    receipt_handles: list[str]
    """The array index position in ``successful`` and ``receipt_handles`` need to be the same (this
    assumption is needed when assembling the result in `SqsProvider.receive_message`)"""

    dead_letter_messages: list[SqsMessage]
    """All messages that were received more than maxReceiveCount in the redrive policy (if any)"""

    def __init__(self):
        self.successful = []
        self.receipt_handles = []
        self.dead_letter_messages = []


class SqsQueue:
    name: str
    region: str
    account_id: str

    attributes: QueueAttributeMap
    tags: TagMap

    purge_in_progress: bool
    purge_timestamp: Optional[float]

    delayed: Set[SqsMessage]
    inflight: Set[SqsMessage]
    receipts: Dict[str, SqsMessage]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        self.name = name
        self.region = region
        self.account_id = account_id

        self._assert_queue_name(name)
        self.tags = tags or {}

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
            QueueAttributeName.SqsManagedSseEnabled: "true",
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

        scheme = context.request.scheme
        host_definition = localstack_host()

        if config.SQS_ENDPOINT_STRATEGY == "standard":
            # Region is always part of the queue URL
            # sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/my-queue
            scheme = context.request.scheme
            host_definition = localstack_host(use_localhost_cloud=True)
            host_url = f"{scheme}://sqs.{self.region}.{host_definition.host_and_port()}"

        elif config.SQS_ENDPOINT_STRATEGY == "domain":
            # Legacy style
            # queue.localhost.localstack.cloud:4566/000000000000/my-queue (us-east-1)
            # or us-east-2.queue.localhost.localstack.cloud:4566/000000000000/my-queue
            region = "" if self.region == "us-east-1" else self.region + "."

            host_url = f"{scheme}://{region}queue.{host_definition.host_and_port()}"
        elif config.SQS_ENDPOINT_STRATEGY == "path":
            # https?://localhost:4566/queue/us-east-1/00000000000/my-queue (us-east-1)
            host_url = f"{scheme}://{host_definition.host}/queue/{self.region}"
        else:
            host_url = f"{scheme}://{host_definition.host}"
            if config.SQS_PORT_EXTERNAL:
                host_definition = localstack_host(custom_port=config.SQS_PORT_EXTERNAL)
                host_url = f"{get_protocol()}://{host_definition.host_and_port()}"

        return "{host}/{account_id}/{name}".format(
            host=host_url.rstrip("/"),
            account_id=self.account_id,
            name=self.name,
        )

    @property
    def redrive_policy(self) -> Optional[dict]:
        if policy_document := self.attributes.get(QueueAttributeName.RedrivePolicy):
            return json.loads(policy_document)
        return None

    @property
    def max_receive_count(self) -> Optional[int]:
        """
        Returns the maxReceiveCount attribute of the redrive policy. If no redrive policy is set, then it
        returns None.
        """
        if redrive_policy := self.redrive_policy:
            return int(redrive_policy["maxReceiveCount"])
        return None

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
    def maximum_message_size(self) -> int:
        return int(self.attributes[QueueAttributeName.MaximumMessageSize])

    @property
    def approx_number_of_messages(self) -> int:
        raise NotImplementedError

    @property
    def approx_number_of_messages_not_visible(self) -> int:
        return len(self.inflight)

    @property
    def approx_number_of_messages_delayed(self) -> int:
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
                self._put_message(standard_message)

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

            # remove all handles associated with this message
            for handle in standard_message.receipt_handles:
                del self.receipts[handle]
            standard_message.receipt_handles.clear()

            self._on_remove_message(standard_message)

    def _on_remove_message(self, message: SqsMessage):
        """Hook for queue-specific logic executed when a message is removed."""
        pass

    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
        delay_seconds: int = None,
    ) -> SqsMessage:
        raise NotImplementedError

    def receive(
        self,
        num_messages: int = 1,
        wait_time_seconds: int = None,
        visibility_timeout: int = None,
    ) -> ReceiveMessageResult:
        """
        Receive ``num_messages`` from the queue, and wait at max ``wait_time_seconds``. If a visibility
        timeout is given, also change the visibility timeout of all received messages accordingly.

        :param num_messages: the number of messages you want to get from the underlying queue
        :param wait_time_seconds: the number of seconds you want to wait
        :param visibility_timeout: an optional new visibility timeout
        :return: a ReceiveMessageResult object that contains the result of the operation
        """
        raise NotImplementedError

    def clear(self):
        """
        Calls clear on all internal datastructures that hold messages and data related to them.
        """
        with self.mutex:
            self.inflight.clear()
            self.delayed.clear()
            self.receipts.clear()

    def _put_message(self, message: SqsMessage):
        """Low-level put operation to put messages into a queue and modify visibilities accordingly."""
        raise NotImplementedError

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
                    standard_message,
                    self.arn,
                )
                self.inflight.remove(standard_message)
                self._put_message(standard_message)

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
                self._put_message(standard_message)

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

    def add_permission(self, label: str, actions: list[str], account_ids: list[str]) -> None:
        """
        Create / append to a policy for usage with the add_permission api call

        :param actions: List of actions to be included in the policy, without the SQS: prefix
        :param account_ids: List of account ids to be included in the policy
        :param label: Permission label
        """
        statement = {
            "Sid": label,
            "Effect": "Allow",
            "Principal": {
                "AWS": [f"arn:aws:iam::{account_id}:root" for account_id in account_ids]
                if len(account_ids) > 1
                else f"arn:aws:iam::{account_ids[0]}:root"
            },
            "Action": [f"SQS:{action}" for action in actions]
            if len(actions) > 1
            else f"SQS:{actions[0]}",
            "Resource": self.arn,
        }
        if policy := self.attributes.get(QueueAttributeName.Policy):
            policy = json.loads(policy)
            policy.setdefault("Statement", [])
        else:
            policy = {
                "Version": "2008-10-17",
                "Id": f"{self.arn}/SQSDefaultPolicy",
                "Statement": [],
            }
        policy.setdefault("Statement", [])
        existing_statement_ids = [statement.get("Sid") for statement in policy["Statement"]]
        if label in existing_statement_ids:
            raise InvalidParameterValue(
                f"Value {label} for parameter Label is invalid. Reason: Already exists."
            )
        policy["Statement"].append(statement)
        self.attributes[QueueAttributeName.Policy] = json.dumps(policy)

    def remove_permission(self, label: str) -> None:
        """
        Delete a policy statement for usage of the remove_permission call

        :param label: Permission label
        """
        if policy := self.attributes.get(QueueAttributeName.Policy):
            policy = json.loads(policy)
            # this should not be necessary, but we can upload custom policies, so it's better to be safe
            policy.setdefault("Statement", [])
        else:
            policy = {
                "Version": "2008-10-17",
                "Id": f"{self.arn}/SQSDefaultPolicy",
                "Statement": [],
            }
        existing_statement_ids = [statement.get("Sid") for statement in policy["Statement"]]
        if label not in existing_statement_ids:
            raise InvalidParameterValue(
                f"Value {label} for parameter Label is invalid. Reason: can't find label."
            )
        policy["Statement"] = [
            statement for statement in policy["Statement"] if statement.get("Sid") != label
        ]
        if policy["Statement"]:
            self.attributes[QueueAttributeName.Policy] = json.dumps(policy)
        else:
            del self.attributes[QueueAttributeName.Policy]


class StandardQueue(SqsQueue):
    visible: PriorityQueue
    inflight: Set[SqsMessage]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        super().__init__(name, region, account_id, attributes, tags)
        self.visible = PriorityQueue()

    def clear(self):
        with self.mutex:
            super().clear()
            self.visible.queue.clear()

    @property
    def approx_number_of_messages(self):
        return self.visible.qsize()

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
            self._put_message(standard_message)

        return standard_message

    def _put_message(self, message: SqsMessage):
        self.visible.put_nowait(message)

    def receive(
        self,
        num_messages: int = 1,
        wait_time_seconds: int = None,
        visibility_timeout: int = None,
    ) -> ReceiveMessageResult:
        result = ReceiveMessageResult()

        max_receive_count = self.max_receive_count
        visibility_timeout = (
            self.visibility_timeout if visibility_timeout is None else visibility_timeout
        )

        block = True if wait_time_seconds else False
        timeout = wait_time_seconds or 0
        start = time.time()

        # collect messages
        while True:
            try:
                message = self.visible.get(block=block, timeout=timeout)
            except Empty:
                break
            # setting block to false guarantees that, if we've already waited before, we don't wait the
            # full time again in the next iteration if max_number_of_messages is set but there are no more
            # messages in the queue. see https://github.com/localstack/localstack/issues/5824
            block = False

            timeout -= time.time() - start
            if timeout < 0:
                timeout = 0

            if message.deleted:
                # filter messages that were deleted with an expired receipt handle after they have been
                # re-queued. this can only happen due to a race with `remove`.
                continue

            # update message attributes
            message.receive_count += 1
            message.update_visibility_timeout(visibility_timeout)
            message.set_last_received(time.time())
            if message.first_received is None:
                message.first_received = message.last_received

            LOG.debug("de-queued message %s from %s", message, self.arn)
            if max_receive_count and message.receive_count > max_receive_count:
                # the message needs to move to the DLQ
                LOG.debug(
                    "message %s has been received %d times, marking it for DLQ",
                    message,
                    message.receive_count,
                )
                result.dead_letter_messages.append(message)
            else:
                result.successful.append(message)

                # now we can return
                if len(result.successful) == num_messages:
                    break

        # now process the successful result messages: create receipt handles and manage visibility.
        for message in result.successful:
            # manage receipt handle
            receipt_handle = self.create_receipt_handle(message)
            message.receipt_handles.add(receipt_handle)
            self.receipts[receipt_handle] = message
            result.receipt_handles.append(receipt_handle)

            # manage message visibility
            if message.visibility_timeout == 0:
                self.visible.put_nowait(message)
            else:
                self.inflight.add(message)

        return result

    def _on_remove_message(self, message: SqsMessage):
        try:
            self.inflight.remove(message)
        except KeyError:
            # this likely means the message was removed with an expired receipt handle unfortunately this
            # means we need to scan the queue for the element and remove it from there, and then re-heapify
            # the queue
            self.visible.queue.remove(message)
            heapq.heapify(self.visible.queue)


class MessageGroup:
    message_group_id: str
    messages: list[SqsMessage]

    def __init__(self, message_group_id: str):
        self.message_group_id = message_group_id
        self.messages = []

    def empty(self) -> bool:
        return not self.messages

    def size(self) -> int:
        return len(self.messages)

    def pop(self) -> SqsMessage:
        return heapq.heappop(self.messages)

    def push(self, message: SqsMessage):
        heapq.heappush(self.messages, message)

    def __eq__(self, other):
        return self.message_group_id == other.message_group_id

    def __hash__(self):
        return self.message_group_id.__hash__()

    def __repr__(self):
        return f"MessageGroup(id={self.message_group_id}, size={len(self.messages)})"


class FifoQueue(SqsQueue):
    """
    A FIFO queue behaves differently than a default queue. Most behavior has to be implemented separately.

    See https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html

    TODO: raise exceptions when trying to remove a message with an expired receipt handle
    """

    deduplication: Dict[str, SqsMessage]
    message_groups: dict[str, MessageGroup]
    inflight_groups: set[MessageGroup]
    message_group_queue: Queue

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        super().__init__(name, region, account_id, attributes, tags)
        self.deduplication = {}

        self.message_groups = {}
        self.inflight_groups = set()
        self.message_group_queue = Queue()

    @property
    def approx_number_of_messages(self):
        n = 0
        for message_group in self.message_groups.values():
            n += len(message_group.messages)
        return n

    def get_message_group(self, message_group_id: str) -> MessageGroup:
        """
        Thread safe lazy factory for MessageGroup objects.

        :param message_group_id: the message group ID
        :return: a new or existing MessageGroup object
        """
        with self.mutex:
            if message_group_id not in self.message_groups:
                # a newly created message group is added to the queue immediately
                message_group = self.message_groups[message_group_id] = MessageGroup(
                    message_group_id
                )
                self.message_group_queue.put_nowait(message_group)

            return self.message_groups.get(message_group_id)

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

    def remove(self, receipt_handle: str):
        self.validate_receipt_handle(receipt_handle)
        decode_receipt_handle(receipt_handle)

        super().remove(receipt_handle)

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
        content_based_deduplication = not is_message_deduplication_id_required(self)
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

        original_message = self.deduplication.get(dedup_id)

        if (
            original_message
            and original_message.priority + sqs_constants.DEDUPLICATION_INTERVAL_IN_SEC
            > fifo_message.priority
        ):
            message["MessageId"] = original_message.message["MessageId"]
        else:
            if fifo_message.is_delayed:
                self.delayed.add(fifo_message)
            else:
                self._put_message(fifo_message)

            self.deduplication[dedup_id] = fifo_message

        return fifo_message

    def _put_message(self, message: SqsMessage):
        """Once a message becomes visible in a FIFO queue, its message group also becomes visible."""
        message_group = self.get_message_group(message.message_group_id)

        with self.mutex:
            # put the message into the group
            message_group.push(message)

            # if a message becomes visible in the queue, that message's group becomes visible also
            if message_group in self.inflight_groups:
                self.inflight_groups.remove(message_group)
                self.message_group_queue.put_nowait(message_group)

    def receive(
        self,
        num_messages: int = 1,
        wait_time_seconds: int = None,
        visibility_timeout: int = None,
    ) -> ReceiveMessageResult:
        """
        Receive logic for FIFO queues is different from standard queues. See
        https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-understanding-logic.html.

        When receiving messages from a FIFO queue with multiple message group IDs, SQS first attempts to
        return as many messages with the same message group ID as possible. This allows other consumers to
        process messages with a different message group ID. When you receive a message with a message group
        ID, no more messages for the same message group ID are returned unless you delete the message, or it
        becomes visible.
        """
        result = ReceiveMessageResult()

        max_receive_count = self.max_receive_count
        visibility_timeout = (
            self.visibility_timeout if visibility_timeout is None else visibility_timeout
        )

        block = True if wait_time_seconds else False
        timeout = wait_time_seconds or 0
        start = time.time()

        received_groups: Set[MessageGroup] = set()

        # collect messages over potentially multiple groups
        while True:
            try:
                group: MessageGroup = self.message_group_queue.get(block=block, timeout=timeout)
            except Empty:
                break

            self.inflight_groups.add(group)

            if group.empty():
                # this can be the case if all messages in the group are still invisible
                # TODO: it should be blocking until at least one message is in the queue, but we don't
                #  want to block the group
                timeout -= time.time() - start
                if timeout < 0:
                    timeout = 0
                continue

            received_groups.add(group)

            block = False

            # we lock the queue while accessing the groups to not get into races with re-queueing/deleting
            with self.mutex:
                # collect messages from the group until a continue/break condition is met
                while True:
                    try:
                        message = group.pop()
                    except IndexError:
                        break

                    if message.deleted:
                        # this means the message was deleted with a receipt handle after its visibility
                        # timeout expired and the messages was re-queued in the meantime.
                        continue

                    # update message attributes
                    message.receive_count += 1
                    message.update_visibility_timeout(visibility_timeout)
                    message.set_last_received(time.time())
                    if message.first_received is None:
                        message.first_received = message.last_received

                    LOG.debug("de-queued message %s from fifo queue %s", message, self.arn)
                    if max_receive_count and message.receive_count > max_receive_count:
                        # the message needs to move to the DLQ
                        LOG.debug(
                            "message %s has been received %d times, marking it for DLQ",
                            message,
                            message.receive_count,
                        )
                        result.dead_letter_messages.append(message)
                    else:
                        result.successful.append(message)

                        # now we can break the inner loop
                        if len(result.successful) == num_messages:
                            break

                # but we also need to check the condition to return from the outer loop
                if len(result.successful) == num_messages:
                    break

        # now process the successful result messages: create receipt handles and manage visibility.
        # we use the mutex again because we are modifying the group
        with self.mutex:
            for message in result.successful:
                # manage receipt handle
                receipt_handle = self.create_receipt_handle(message)
                message.receipt_handles.add(receipt_handle)
                self.receipts[receipt_handle] = message
                result.receipt_handles.append(receipt_handle)

                # manage message visibility
                if message.visibility_timeout == 0:
                    self._put_message(message)
                else:
                    self.inflight.add(message)

        return result

    def _on_remove_message(self, message: SqsMessage):
        # if a message is deleted from the queue, the message's group can become visible again
        message_group = self.get_message_group(message.message_group_id)

        with self.mutex:
            try:
                self.inflight.remove(message)
            except KeyError:
                # in FIFO queues, this should not happen, as expired receipt handles cannot be used to
                # delete a message.
                pass

            if message_group in self.inflight_groups:
                # it becomes visible again only if there are no other in flight messages in that group
                for message in self.inflight:
                    if message.message_group_id == message_group.message_group_id:
                        return

                self.inflight_groups.remove(message_group)
                self.message_group_queue.put_nowait(message_group)

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

    def clear(self):
        with self.mutex:
            super().clear()
            self.message_groups.clear()
            self.inflight_groups.clear()
            self.message_group_queue.queue.clear()
            self.deduplication.clear()


class SqsStore(BaseStore):
    queues: Dict[str, SqsQueue] = LocalAttribute(default=dict)

    deleted: Dict[str, float] = LocalAttribute(default=dict)

    def expire_deleted(self):
        for k in list(self.deleted.keys()):
            if self.deleted[k] <= (time.time() - sqs_constants.RECENTLY_DELETED_TIMEOUT):
                del self.deleted[k]


sqs_stores = AccountRegionBundle("sqs", SqsStore)
