import base64
import copy
import hashlib
import heapq
import inspect
import json
import logging
import random
import re
import string
import threading
import time
from queue import Empty, PriorityQueue
from typing import Dict, List, NamedTuple, Optional, Set

from moto.sqs.models import BINARY_TYPE_FIELD_INDEX, STRING_TYPE_FIELD_INDEX
from moto.sqs.models import Message as MotoMessage

from localstack import config, constants
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sqs import (
    ActionNameList,
    AttributeNameList,
    AWSAccountIdList,
    BatchEntryIdsNotDistinct,
    BatchResultErrorEntry,
    BoxedInteger,
    ChangeMessageVisibilityBatchRequestEntryList,
    ChangeMessageVisibilityBatchResult,
    CreateQueueResult,
    DeleteMessageBatchRequestEntryList,
    DeleteMessageBatchResult,
    DeleteMessageBatchResultEntry,
    EmptyBatchRequest,
    GetQueueAttributesResult,
    GetQueueUrlResult,
    Integer,
    InvalidAttributeName,
    InvalidMessageContents,
    ListQueuesResult,
    ListQueueTagsResult,
    Message,
    MessageAttributeNameList,
    MessageBodyAttributeMap,
    MessageBodySystemAttributeMap,
    MessageNotInflight,
    MessageSystemAttributeName,
    PurgeQueueInProgress,
    QueueAttributeMap,
    QueueAttributeName,
    QueueDoesNotExist,
    ReceiptHandleIsInvalid,
    ReceiveMessageResult,
    SendMessageBatchRequestEntryList,
    SendMessageBatchResult,
    SendMessageBatchResultEntry,
    SendMessageResult,
    SqsApi,
    String,
    TagKeyList,
    TagMap,
    Token,
)
from localstack.aws.spec import load_service
from localstack.config import external_service_url
from localstack.services.generic_proxy import RegionBackend
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.aws_stack import parse_arn
from localstack.utils.common import long_uid, md5, now, start_thread
from localstack.utils.run import FuncThread

LOG = logging.getLogger(__name__)

# Valid unicode values: #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
MSG_CONTENT_REGEX = "^[\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]*$"

# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
# While not documented, umlauts seem to be allowed
ATTR_NAME_CHAR_REGEX = "^[\u00C0-\u017Fa-zA-Z0-9_.-]*$"
ATTR_NAME_PREFIX_SUFFIX_REGEX = r"^(?!(aws\.|amazon\.|\.)).*(?<!\.)$"
ATTR_TYPE_REGEX = "^(String|Number|Binary).*$"
FIFO_MSG_REGEX = "^[0-9a-zA-z!\"#$%&'()*+,./:;<=>?@[\\]^_`{|}~-]*$"

DEDUPLICATION_INTERVAL_IN_SEC = 5 * 60


class InvalidParameterValue(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidParameterValue", message, 400, True)


class InvalidAttributeValue(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidAttributeValue", message, 400, True)


class MissingParameter(CommonServiceException):
    def __init__(self, message):
        super().__init__("MissingParameter", message, 400, True)


def generate_message_id():
    return long_uid()


def assert_queue_name(queue_name: str, fifo: bool = False):
    if queue_name.endswith(".fifo"):
        if not fifo:
            # Standard queues with .fifo suffix are not allowed
            raise InvalidParameterValue(
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
            )
        # The .fifo suffix counts towards the 80-character queue name quota.
        queue_name = queue_name[:-5] + "_fifo"

    # slashes are actually not allowed, but we've allowed it explicitly in localstack
    if not re.match(r"^[a-zA-Z0-9/_-]{1,80}$", queue_name):
        raise InvalidParameterValue(
            "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
        )


def check_message_content(message_body: str):
    error = "Invalid characters found. Valid unicode characters are #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF"

    if not re.match(MSG_CONTENT_REGEX, message_body):
        raise InvalidMessageContents(error)


def encode_receipt_handle(queue_arn, message: "SqsMessage") -> str:
    # http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/ImportantIdentifiers.html#ImportantIdentifiers-receipt-handles
    # encode the queue arn in the receipt handle, so we can later check if it belongs to the queue
    # but also add some randomness s.t. the generated receipt handles look like the ones from AWS
    handle = f"{long_uid()} {queue_arn} {message.message.get('MessageId')} {message.last_received}"
    encoded = base64.b64encode(handle.encode("utf-8"))
    return encoded.decode("utf-8")


def decode_receipt_handle(receipt_handle: str) -> str:
    try:
        handle = base64.b64decode(receipt_handle).decode("utf-8")
        _, queue_arn, message_id, last_received = handle.split(" ")
        parse_arn(queue_arn)  # raises a ValueError if it is not an arn
        return queue_arn
    except (IndexError, ValueError):
        raise ReceiptHandleIsInvalid(
            f'The input receipt handle "{receipt_handle}" is not a valid receipt handle.'
        )


class Permission(NamedTuple):
    # TODO: just a placeholder for real policies
    label: str
    account_id: str
    action: str


class SqsMessage:
    message: Message
    visibility_timeout: int
    receive_times: int
    receipt_handles: Set[str]
    deleted: bool
    priority: float
    message_deduplication_id: str
    message_group_id: str

    def __init__(
        self,
        priority: float,
        message: Message,
        message_deduplication_id: str = None,
        message_group_id: str = None,
    ) -> None:
        self.message = message
        self.receive_times = 0
        self.receipt_handles = set()

        self.last_received = None
        self.first_received = None
        self.deleted = False
        self.priority = priority

        attributes = {}
        if message_group_id is not None:
            attributes["MessageGroupId"] = message_group_id
        if message_deduplication_id is not None:
            attributes["MessageDeduplicationId"] = message_deduplication_id

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
    def is_visible(self):
        if self.last_received is None:
            return True
        if time.time() >= (self.last_received + self.visibility_timeout):
            return True

        return False

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


class SqsQueue:
    name: str
    region: str
    account_id: str

    attributes: QueueAttributeMap
    tags: TagMap
    permissions: Set[Permission]

    purge_in_progress: bool

    visible: PriorityQueue
    inflight: Set[SqsMessage]
    receipts: Dict[str, SqsMessage]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        self.name = name
        self.region = region
        self.account_id = account_id

        self._assert_queue_name(name)
        self.tags = tags or {}

        self.visible = PriorityQueue()
        self.inflight = set()
        self.receipts = {}

        self.attributes = self.default_attributes()
        if attributes:
            self.attributes.update(attributes)

        self.purge_in_progress = False
        self.permissions = set()
        self.mutex = threading.RLock()

    def default_attributes(self) -> QueueAttributeMap:
        return {
            QueueAttributeName.ApproximateNumberOfMessages: self.visible._qsize,
            QueueAttributeName.ApproximateNumberOfMessagesNotVisible: lambda: len(self.inflight),
            QueueAttributeName.ApproximateNumberOfMessagesDelayed: "0",  # FIXME: this should also be callable
            QueueAttributeName.CreatedTimestamp: str(now()),
            QueueAttributeName.DelaySeconds: "0",
            QueueAttributeName.LastModifiedTimestamp: str(now()),
            QueueAttributeName.MaximumMessageSize: "262144",
            QueueAttributeName.MessageRetentionPeriod: "345600",
            QueueAttributeName.QueueArn: self.arn,
            QueueAttributeName.ReceiveMessageWaitTimeSeconds: "0",
            QueueAttributeName.VisibilityTimeout: "30",
        }

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
            # localhost:4566/queue/us-east-1/00000000000/my-queue (us-east-1)
            host_url = f"{context.request.host}/queue/{self.region}"
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
    def wait_time_seconds(self) -> int:
        return int(self.attributes[QueueAttributeName.ReceiveMessageWaitTimeSeconds])

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

            standard_message.visibility_timeout = visibility_timeout

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
                pass

    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
    ):
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
                standard_message.last_received = time.time()
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
            ] = standard_message.first_received
            copied_message.message["ReceiptHandle"] = receipt_handle

            return copied_message

    def create_receipt_handle(self, message: SqsMessage) -> str:
        return encode_receipt_handle(self.arn, message)

    def requeue_inflight_messages(self):
        if not self.inflight:
            return

        with self.mutex:
            messages = list(self.inflight)
            for standard_message in messages:
                if standard_message.is_visible:
                    LOG.debug(
                        "re-queueing inflight messages %s into queue %s",
                        standard_message.message["MessageId"],
                        self.arn,
                    )
                    self.inflight.remove(standard_message)
                    self.visible.put_nowait(standard_message)

    def _assert_queue_name(self, name):
        if not re.match(r"^[a-zA-Z0-9_-]{1,80}$", name):
            raise InvalidParameterValue(
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
            )

    def validate_queue_attributes(self, attributes):
        valid = [k[1] for k in inspect.getmembers(QueueAttributeName)]
        del valid[valid.index(QueueAttributeName.FifoQueue)]

        for k in attributes.keys():
            if k not in valid:
                raise InvalidAttributeName(f"Unknown Attribute {k}")

    def generate_sequence_number(self):
        return None


class StandardQueue(SqsQueue):
    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
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

        self.visible.put_nowait(standard_message)


class FifoQueue(SqsQueue):
    visible: PriorityQueue
    inflight: Set[SqsMessage]
    receipts: Dict[str, SqsMessage]
    deduplication: Dict[str, Dict[str, SqsMessage]]

    def __init__(self, name: str, region: str, account_id: str, attributes=None, tags=None) -> None:
        super().__init__(name, region, account_id, attributes, tags)
        self.deduplication = {}

    def put(
        self,
        message: Message,
        visibility_timeout: int = None,
        message_deduplication_id: str = None,
        message_group_id: str = None,
    ):

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

        qm = SqsMessage(
            time.time(),
            message,
            message_deduplication_id=dedup_id,
            message_group_id=message_group_id,
        )
        if visibility_timeout is not None:
            qm.visibility_timeout = visibility_timeout
        else:
            # use the attribute from the queue
            qm.visibility_timeout = self.visibility_timeout
        original_message = None
        original_message_group = self.deduplication.get(message_group_id)
        if original_message_group:
            original_message = original_message_group.get(dedup_id)
        if (
            original_message
            and not original_message.deleted
            and original_message.priority + DEDUPLICATION_INTERVAL_IN_SEC > qm.priority
        ):
            message["MessageId"] = original_message.message["MessageId"]
        else:
            self.visible.put_nowait(qm)
            if not original_message_group:
                self.deduplication[message_group_id] = {}
            self.deduplication[message_group_id][message_deduplication_id] = qm

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
        valid = [k[1] for k in inspect.getmembers(QueueAttributeName)]

        for k in attributes.keys():
            if k not in valid:
                raise InvalidAttributeName(f"Unknown Attribute {k}")
        # Special Cases
        fifo = attributes.get(QueueAttributeName.FifoQueue)
        if fifo and fifo.lower() != "true":
            raise InvalidAttributeValue(
                "Invalid value for the parameter FifoQueue. Reason: Modifying queue type is not supported."
            )

    # TODO: If we ever actually need to do something with this number, it needs to be part of
    #   SQSMessage. This means changing all *put*() signatures to return the saved message.
    def generate_sequence_number(self):
        return _create_mock_sequence_number()


class InflightUpdateWorker:
    """
    Regularly re-queues inflight messages whose visibility timeout has expired.

    FIXME: very crude implementation. it would be better to have event-driven communication.
    """

    def __init__(self) -> None:
        super().__init__()
        self.running = False
        self.thread: Optional[FuncThread] = None

    def start(self):
        if self.thread:
            return

        def _run(*_args):
            self.running = True
            self.run()

        self.thread = start_thread(_run)

    def stop(self):
        if self.thread:
            self.thread.stop()

        self.running = False
        self.thread = None

    def run(self):
        while self.running:
            time.sleep(1)
            for region in SqsBackend.regions().keys():
                backend = SqsBackend.get(region)
                for queue in backend.queues.values():
                    queue.requeue_inflight_messages()


def check_attributes(message_attributes: MessageBodyAttributeMap):
    if not message_attributes:
        return
    for attribute_name in message_attributes:
        if len(attribute_name) >= 256:
            raise InvalidParameterValue(
                "Message (user) attribute names must be shorter than 256 Bytes"
            )
        if not re.match(ATTR_NAME_CHAR_REGEX, attribute_name.lower()):
            raise InvalidParameterValue(
                "Message (user) attributes name can only contain upper and lower score characters, digits, periods, "
                "hyphens and underscores. "
            )
        if not re.match(ATTR_NAME_PREFIX_SUFFIX_REGEX, attribute_name.lower()):
            raise InvalidParameterValue(
                "You can't use message attribute names beginning with 'AWS.' or 'Amazon.'. "
                "These strings are reserved for internal use. Additionally, they cannot start or end with '.'."
            )

        attribute = message_attributes[attribute_name]
        attribute_type = attribute.get("DataType")
        if not attribute_type:
            raise InvalidParameterValue("Missing required parameter DataType")
        if not re.match(ATTR_TYPE_REGEX, attribute_type):
            raise InvalidParameterValue(
                f"Type for parameter MessageAttributes.Attribute_name.DataType must be prefixed"
                f'with "String", "Binary", or "Number", but was: {attribute_type}'
            )
        if len(attribute_type) >= 256:
            raise InvalidParameterValue(
                "Message (user) attribute types must be shorter than 256 Bytes"
            )

        if attribute_type == "String":
            try:
                attribute_value = attribute.get("StringValue")

                if not attribute_value:
                    raise InvalidParameterValue(
                        f"Message (user) attribute '{attribute_name}' must contain a non-empty value of type 'String'."
                    )

                check_message_content(attribute_value)
            except InvalidMessageContents as e:
                # AWS throws a different exception here
                raise InvalidParameterValue(e.args[0])


def check_fifo_id(fifo_id):
    if not fifo_id:
        return
    if len(fifo_id) >= 128:
        raise InvalidParameterValue(
            "Message deduplication ID and group ID must be shorter than 128 bytes"
        )
    if not re.match(FIFO_MSG_REGEX, fifo_id):
        raise InvalidParameterValue(
            "Invalid characters found. Deduplication ID and group ID can only contain"
            "alphanumeric characters as well as TODO"
        )


class SqsBackend(RegionBackend):
    queues: Dict[str, SqsQueue]

    def __init__(self):
        self.queues = {}


class SqsProvider(SqsApi, ServiceLifecycleHook):
    """
    LocalStack SQS Provider.

    LIMITATIONS:
        - Pagination of results (NextToken)
        - Delivery guarantees
        - The region is not encoded in the queue URL
    """

    queues: Dict[str, SqsQueue]

    def __init__(self) -> None:
        super().__init__()
        self._mutex = threading.RLock()
        self._inflight_worker = InflightUpdateWorker()

    def on_before_start(self):
        self._inflight_worker.start()

    def on_before_stop(self):
        self._inflight_worker.stop()

    def _require_queue(self, context: RequestContext, name: str) -> SqsQueue:
        """
        Returns the queue for the given name, or raises QueueDoesNotExist if it does not exist.

        :param: context: the request context
        :param name: the name to look for
        :returns: the queue
        :raises QueueDoesNotExist: if the queue does not exist
        """
        backend = SqsBackend.get(context.region)

        with self._mutex:
            if name not in backend.queues.keys():
                raise QueueDoesNotExist("The specified queue does not exist for this wsdl version.")

            return backend.queues[name]

    def _require_queue_by_arn(self, context: RequestContext, queue_arn: str) -> SqsQueue:
        arn = parse_arn(queue_arn)
        return self._require_queue(context, arn["resource"])

    def _resolve_queue(
        self,
        context: RequestContext,
        queue_name: Optional[str] = None,
        queue_url: Optional[str] = None,
    ) -> SqsQueue:
        """
        Determines the name of the queue from available information (request context, queue URL) to return the respective queue,
        or raises QueueDoesNotExist if it does not exist.

        :param context: the request context, used for getting region and account_id, and optionally the queue_url
        :param queue_name: the queue name (if this is set, then this will be used for the key)
        :param queue_url: the queue url (if name is not set, this will be used to determine the queue name)
        :returns: the queue
        :raises QueueDoesNotExist: if the queue does not exist
        """
        name = resolve_queue_name(context, queue_name, queue_url)
        return self._require_queue(context, name)

    def create_queue(
        self,
        context: RequestContext,
        queue_name: String,
        attributes: QueueAttributeMap = None,
        tags: TagMap = None,
    ) -> CreateQueueResult:
        fifo = attributes and (
            attributes.get(QueueAttributeName.FifoQueue, "false").lower() == "true"
        )

        # Special Case TODO: why is an emtpy policy passed at all? same in set_queue_attributes
        if attributes and attributes.get(QueueAttributeName.Policy) == "":
            del attributes[QueueAttributeName.Policy]

        backend = SqsBackend.get(context.region)

        if queue_name in backend.queues:
            # FIXME #5938: should raise `QueueNameExists` if queue exists with different attributes
            queue = backend.queues[queue_name]
            return CreateQueueResult(QueueUrl=queue.url(context))
        if fifo:
            queue = FifoQueue(queue_name, context.region, context.account_id, attributes, tags)
        else:
            queue = StandardQueue(queue_name, context.region, context.account_id, attributes, tags)

        LOG.debug("creating queue key=%s attributes=%s tags=%s", queue_name, attributes, tags)

        with self._mutex:
            backend.queues[queue_name] = queue

        return CreateQueueResult(QueueUrl=queue.url(context))

    def get_queue_url(
        self, context: RequestContext, queue_name: String, queue_owner_aws_account_id: String = None
    ) -> GetQueueUrlResult:
        backend = SqsBackend.get(context.region)
        if queue_name not in backend.queues.keys():
            raise QueueDoesNotExist("The specified queue does not exist for this wsdl version.")

        queue = backend.queues[queue_name]

        return GetQueueUrlResult(QueueUrl=queue.url(context))

    def list_queues(
        self,
        context: RequestContext,
        queue_name_prefix: String = None,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListQueuesResult:
        backend = SqsBackend.get(context.region)

        if queue_name_prefix:
            urls = [
                queue.url(context)
                for queue in backend.queues.values()
                if queue.name.startswith(queue_name_prefix)
            ]
        else:
            urls = [queue.url(context) for queue in backend.queues.values()]

        if max_results:
            # FIXME: also need to solve pagination with stateful iterators: If the total number of items available is
            #  more than the value specified, a NextToken is provided in the command's output. To resume pagination,
            #  provide the NextToken value in the starting-token argument of a subsequent command. Do not use the
            #  NextToken response element directly outside of the AWS CLI.
            urls = urls[:max_results]

        return ListQueuesResult(QueueUrls=urls)

    def change_message_visibility(
        self,
        context: RequestContext,
        queue_url: String,
        receipt_handle: String,
        visibility_timeout: Integer,
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)
        queue.update_visibility_timeout(receipt_handle, visibility_timeout)

    def change_message_visibility_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: ChangeMessageVisibilityBatchRequestEntryList,
    ) -> ChangeMessageVisibilityBatchResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        self._assert_batch(entries)

        successful = []
        failed = []

        with queue.mutex:
            for entry in entries:
                try:
                    queue.update_visibility_timeout(
                        entry["ReceiptHandle"], entry["VisibilityTimeout"]
                    )
                    successful.append({"Id": entry["Id"]})
                except Exception as e:
                    failed.append(
                        BatchResultErrorEntry(
                            Id=entry["Id"],
                            SenderFault=False,
                            Code=e.__class__.__name__,
                            Message=str(e),
                        )
                    )

        return ChangeMessageVisibilityBatchResult(
            Successful=successful,
            Failed=failed,
        )

    def delete_queue(self, context: RequestContext, queue_url: String) -> None:
        backend = SqsBackend.get(context.region)

        with self._mutex:
            queue = self._resolve_queue(context, queue_url=queue_url)
            del backend.queues[queue.name]

    def get_queue_attributes(
        self, context: RequestContext, queue_url: String, attribute_names: AttributeNameList = None
    ) -> GetQueueAttributesResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        if not attribute_names:
            return GetQueueAttributesResult(Attributes={})

        if QueueAttributeName.All in attribute_names:
            # return GetQueueAttributesResult(Attributes=queue.attributes)
            attribute_names = queue.attributes.keys()

        result: Dict[QueueAttributeName, str] = {}

        for attr in attribute_names:
            try:
                getattr(QueueAttributeName, attr)
            except AttributeError:
                raise InvalidAttributeName(f"Unknown Attribute {attr}.")

            if callable(queue.attributes.get(attr)):
                func = queue.attributes.get(attr)
                result[attr] = func()
            else:
                result[attr] = queue.attributes.get(attr)

        return GetQueueAttributesResult(Attributes=result)

    def send_message(
        self,
        context: RequestContext,
        queue_url: String,
        message_body: String,
        delay_seconds: Integer = None,
        message_attributes: MessageBodyAttributeMap = None,
        message_system_attributes: MessageBodySystemAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
    ) -> SendMessageResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        message = self._put_message(
            queue,
            context,
            message_body,
            delay_seconds,
            message_attributes,
            message_system_attributes,
            message_deduplication_id,
            message_group_id,
        )
        return SendMessageResult(
            MessageId=message["MessageId"],
            MD5OfMessageBody=message["MD5OfBody"],
            MD5OfMessageAttributes=message.get("MD5OfMessageAttributes"),
            SequenceNumber=queue.generate_sequence_number(),
            MD5OfMessageSystemAttributes=_create_message_attribute_hash(message_system_attributes),
        )

    def send_message_batch(
        self, context: RequestContext, queue_url: String, entries: SendMessageBatchRequestEntryList
    ) -> SendMessageBatchResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        self._assert_batch(entries)

        successful = []
        failed = []

        with queue.mutex:
            for entry in entries:
                try:
                    message = self._put_message(
                        queue,
                        context,
                        message_body=entry.get("MessageBody"),
                        delay_seconds=entry.get("DelaySeconds"),
                        message_attributes=entry.get("MessageAttributes"),
                        message_system_attributes=entry.get("MessageSystemAttributes"),
                        message_deduplication_id=entry.get("MessageDeduplicationId"),
                        message_group_id=entry.get("MessageGroupId"),
                    )

                    successful.append(
                        SendMessageBatchResultEntry(
                            Id=entry["Id"],
                            MessageId=message.get("MessageId"),
                            MD5OfMessageBody=message.get("MD5OfBody"),
                            MD5OfMessageAttributes=message.get("MD5OfMessageAttributes"),
                            MD5OfMessageSystemAttributes=_create_message_attribute_hash(
                                message.get("message_system_attributes")
                            ),
                            SequenceNumber=queue.generate_sequence_number(),
                        )
                    )
                except Exception as e:
                    failed.append(
                        BatchResultErrorEntry(
                            Id=entry["Id"],
                            SenderFault=False,
                            Code=e.__class__.__name__,
                            Message=str(e),
                        )
                    )

        return SendMessageBatchResult(
            Successful=successful,
            Failed=failed,
        )

    def _put_message(
        self,
        queue: SqsQueue,
        context: RequestContext,
        message_body: String,
        delay_seconds: Integer = None,
        message_attributes: MessageBodyAttributeMap = None,
        message_system_attributes: MessageBodySystemAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
    ) -> Message:
        check_message_content(message_body)
        check_attributes(message_attributes)
        check_attributes(message_system_attributes)
        check_fifo_id(message_deduplication_id)
        check_fifo_id(message_group_id)

        message: Message = Message(
            MessageId=generate_message_id(),
            MD5OfBody=md5(message_body),
            Body=message_body,
            Attributes=self._create_message_attributes(context, message_system_attributes),
            MD5OfMessageAttributes=_create_message_attribute_hash(message_attributes),
            MessageAttributes=message_attributes,
        )
        delay_seconds = delay_seconds or queue.attributes.get(QueueAttributeName.DelaySeconds, "0")

        if int(delay_seconds):
            # FIXME: this is a pretty bad implementation (one thread per message...). polling on a priority queue
            #  would probably be better. We also need access to delayed messages for the
            #  ApproximateNumberrOfDelayedMessages attribute.
            threading.Timer(
                int(delay_seconds),
                queue.put,
                args=(message, message_deduplication_id, message_group_id),
            ).start()
        else:
            queue.put(
                message=message,
                message_deduplication_id=message_deduplication_id,
                message_group_id=message_group_id,
            )

        return message

    def receive_message(
        self,
        context: RequestContext,
        queue_url: String,
        attribute_names: AttributeNameList = None,
        message_attribute_names: MessageAttributeNameList = None,
        max_number_of_messages: Integer = None,
        visibility_timeout: Integer = None,
        wait_time_seconds: Integer = None,
        receive_request_attempt_id: String = None,
    ) -> ReceiveMessageResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        if wait_time_seconds is None:
            wait_time_seconds = queue.wait_time_seconds

        num = max_number_of_messages or 1
        block = True if wait_time_seconds else False
        # collect messages
        messages = []

        # we chose to always return the maximum possible number of messages, even though AWS will typically return
        # fewer messages than requested on small queues. at some point we could maybe change this to randomly sample
        # between 1 and max_number_of_messages.
        # see https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
        while num:
            try:
                standard_message = queue.get(
                    block=block, timeout=wait_time_seconds, visibility_timeout=visibility_timeout
                )
                msg = standard_message.message
            except Empty:
                break

            # setting block to false guarantees that, if we've already waited before, we don't wait the full time
            # again in the next iteration if max_number_of_messages is set but there are no more messages in the
            # queue. see https://github.com/localstack/localstack/issues/5824
            block = False

            moved_to_dlq = False
            if (
                queue.attributes
                and queue.attributes.get(QueueAttributeName.RedrivePolicy) is not None
            ):
                moved_to_dlq = self._dead_letter_check(queue, standard_message, context)
            if moved_to_dlq:
                continue

            msg = copy.deepcopy(msg)
            message_filter_attributes(msg, attribute_names)
            message_filter_message_attributes(msg, message_attribute_names)

            if msg.get("MessageAttributes"):
                msg["MD5OfMessageAttributes"] = _create_message_attribute_hash(
                    msg["MessageAttributes"]
                )
            else:
                # delete the value that was computed when creating the message
                msg.pop("MD5OfMessageAttributes")

            # add message to result
            messages.append(msg)
            num -= 1

        # TODO: how does receiving behave if the queue was deleted in the meantime?
        return ReceiveMessageResult(Messages=messages)

    def _dead_letter_check(
        self, queue: SqsQueue, std_m: SqsMessage, context: RequestContext
    ) -> bool:
        redrive_policy = json.loads(queue.attributes.get(QueueAttributeName.RedrivePolicy))
        # TODO: include the names of the dictionary sub - attributes in the autogenerated code?
        max_receive_count = redrive_policy["maxReceiveCount"]
        if std_m.receive_times > max_receive_count:
            dead_letter_target_arn = redrive_policy["deadLetterTargetArn"]
            dl_queue = self._require_queue_by_arn(context, dead_letter_target_arn)
            # TODO: this needs to be atomic?
            dead_message = std_m.message
            dl_queue.put(
                message=dead_message,
                message_deduplication_id=std_m.message_deduplication_id,
                message_group_id=std_m.message_group_id,
            )
            queue.remove(std_m.message["ReceiptHandle"])
            return True
        else:
            return False

    def delete_message(
        self, context: RequestContext, queue_url: String, receipt_handle: String
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)
        queue.remove(receipt_handle)

    def delete_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: DeleteMessageBatchRequestEntryList,
    ) -> DeleteMessageBatchResult:
        queue = self._resolve_queue(context, queue_url=queue_url)
        self._assert_batch(entries)

        successful = []
        failed = []

        with queue.mutex:
            for entry in entries:
                try:
                    queue.remove(entry["ReceiptHandle"])
                    successful.append(DeleteMessageBatchResultEntry(Id=entry["Id"]))
                except Exception as e:
                    failed.append(
                        BatchResultErrorEntry(
                            Id=entry["Id"],
                            SenderFault=False,
                            Code=e.__class__.__name__,
                            Message=str(e),
                        )
                    )

        return DeleteMessageBatchResult(
            Successful=successful,
            Failed=failed,
        )

    def purge_queue(self, context: RequestContext, queue_url: String) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        with self._mutex:
            # FIXME: use queue-specific locks
            if queue.purge_in_progress:
                raise PurgeQueueInProgress()
            queue.purge_in_progress = True

        # TODO: how do other methods behave when purge is in progress?

        try:
            while True:
                queue.visible.get_nowait()
        except Empty:
            return
        finally:
            queue.purge_in_progress = False

    def set_queue_attributes(
        self, context: RequestContext, queue_url: String, attributes: QueueAttributeMap
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        if not attributes:
            return

        queue.validate_queue_attributes(attributes)

        for k, v in attributes.items():
            queue.attributes[k] = v

        # Special cases
        if queue.attributes.get(QueueAttributeName.Policy) == "":
            del queue.attributes[QueueAttributeName.Policy]

        redrive_policy = queue.attributes.get(QueueAttributeName.RedrivePolicy)
        if redrive_policy:
            _redrive_policy = json.loads(redrive_policy)
            dl_target_arn = _redrive_policy.get("deadLetterTargetArn")
            max_receive_count = _redrive_policy.get("maxReceiveCount")
            # TODO: use the actual AWS responses
            if not dl_target_arn:
                raise InvalidParameterValue(
                    "The required parameter 'deadLetterTargetArn' is missing"
                )
            if not max_receive_count:
                raise InvalidParameterValue("The required parameter 'maxReceiveCount' is missing")
            try:
                max_receive_count = int(max_receive_count)
                valid_count = 1 <= max_receive_count <= 1000
            except ValueError:
                valid_count = False
            if not valid_count:
                raise InvalidParameterValue(
                    f"Value {redrive_policy} for parameter RedrivePolicy is invalid. Reason: Invalid value for "
                    f"maxReceiveCount: {max_receive_count}, valid values are from 1 to 1000 both inclusive. "
                )

    def tag_queue(self, context: RequestContext, queue_url: String, tags: TagMap) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        if not tags:
            return

        for k, v in tags.items():
            queue.tags[k] = v

    def list_queue_tags(self, context: RequestContext, queue_url: String) -> ListQueueTagsResult:
        queue = self._resolve_queue(context, queue_url=queue_url)
        return ListQueueTagsResult(Tags=queue.tags)

    def untag_queue(self, context: RequestContext, queue_url: String, tag_keys: TagKeyList) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        for k in tag_keys:
            if k in queue.tags:
                del queue.tags[k]

    def add_permission(
        self,
        context: RequestContext,
        queue_url: String,
        label: String,
        aws_account_ids: AWSAccountIdList,
        actions: ActionNameList,
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        self._validate_actions(actions)

        for account_id in aws_account_ids:
            for action in actions:
                queue.permissions.add(Permission(label, account_id, action))

    def remove_permission(self, context: RequestContext, queue_url: String, label: String) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        candidates = [p for p in queue.permissions if p.label == label]
        if candidates:
            queue.permissions.remove(candidates[0])

    def _create_message_attributes(
        self,
        context: RequestContext,
        message_system_attributes: MessageBodySystemAttributeMap = None,
    ) -> Dict[MessageSystemAttributeName, str]:
        result: Dict[MessageSystemAttributeName, str] = {
            MessageSystemAttributeName.SenderId: context.account_id,  # not the account ID in AWS
            MessageSystemAttributeName.SentTimestamp: str(now()),
        }

        if message_system_attributes is not None:
            for attr in message_system_attributes:
                result[attr] = message_system_attributes[attr]["StringValue"]

        return result

    def _validate_queue_attributes(self, attributes: QueueAttributeMap):
        valid = [k[1] for k in inspect.getmembers(QueueAttributeName)]

        for k in attributes.keys():
            if k not in valid:
                raise InvalidAttributeName("Unknown Attribute %s" % k)

    def _validate_actions(self, actions: ActionNameList):
        service = load_service(service=self.service, version=self.version)
        # FIXME: this is a bit of a heuristic as it will also include actions like "ListQueues" which is not
        #  associated with an action on a queue
        valid = list(service.operation_names)
        valid.append("*")

        for action in actions:
            if action not in valid:
                raise InvalidParameterValue(
                    f"Value SQS:{action} for parameter ActionName is invalid. Reason: Please refer to the appropriate "
                    "WSDL for a list of valid actions. "
                )

    def _assert_batch(self, batch: List):
        if not batch:
            raise EmptyBatchRequest
        visited = set()
        for entry in batch:
            # TODO: InvalidBatchEntryId
            if entry["Id"] in visited:
                raise BatchEntryIdsNotDistinct()
            else:
                visited.add(entry["Id"])


def _create_mock_sequence_number():
    return "".join(random.choice(string.digits) for _ in range(20))


# Method from moto's attribute_md5 of moto/sqs/models.py, separated from the Message Object
def _create_message_attribute_hash(message_attributes) -> Optional[str]:
    # To avoid the need to check for dict conformity everytime we invoke this function
    if not isinstance(message_attributes, dict):
        return
    hash = hashlib.md5()

    for attrName in sorted(message_attributes.keys()):
        attr_value = message_attributes[attrName]
        # Encode name
        MotoMessage.update_binary_length_and_value(hash, MotoMessage.utf8(attrName))
        # Encode data type
        MotoMessage.update_binary_length_and_value(hash, MotoMessage.utf8(attr_value["DataType"]))
        # Encode transport type and value
        if attr_value.get("StringValue"):
            hash.update(bytearray([STRING_TYPE_FIELD_INDEX]))
            MotoMessage.update_binary_length_and_value(
                hash, MotoMessage.utf8(attr_value.get("StringValue"))
            )
        elif attr_value.get("BinaryValue"):
            hash.update(bytearray([BINARY_TYPE_FIELD_INDEX]))
            decoded_binary_value = base64.b64decode(attr_value.get("BinaryValue"))
            MotoMessage.update_binary_length_and_value(hash, decoded_binary_value)
        # string_list_value, binary_list_value type is not implemented, reserved for the future use.
        # See https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_MessageAttributeValue.html
    return hash.hexdigest()


def get_queue_name_from_url(queue_url: str) -> str:
    return queue_url.rstrip("/").split("/")[-1]


def resolve_queue_name(
    context: RequestContext, queue_name: Optional[str] = None, queue_url: Optional[str] = None
) -> str:
    """
    Resolves a queue name from the given information.

    :param context: the request context, used for getting region and account_id, and optionally the queue_url
    :param queue_name: the queue name (if this is set, then this will be used for the key)
    :param queue_url: the queue url (if name is not set, this will be used to determine the queue name)
    :return: the queue name describing the queue being requested
    """
    if not queue_name:
        if queue_url:
            queue_name = get_queue_name_from_url(queue_url)
        else:
            queue_name = get_queue_name_from_url(context.request.base_url)

    return queue_name


def message_filter_attributes(message: Message, names: Optional[AttributeNameList]):
    """
    Utility function filter from the given message (in-place) the system attributes from the given list. It will
    apply all rules according to:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.receive_message.

    :param message: The message to filter (it will be modified)
    :param names: the attributes names/filters
    """
    if "Attributes" not in message:
        return

    if not names:
        del message["Attributes"]
        return

    if "All" in names:
        return

    for k in list(message["Attributes"].keys()):
        if k not in names:
            del message["Attributes"][k]


def message_filter_message_attributes(message: Message, names: Optional[MessageAttributeNameList]):
    """
    Utility function filter from the given message (in-place) the message attributes from the given list. It will
    apply all rules according to:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.receive_message.

    :param message: The message to filter (it will be modified)
    :param names: the attributes names/filters (can be 'All', '.*', or prefix filters like 'Foo.*')
    """
    if not message.get("MessageAttributes"):
        return

    if not names:
        del message["MessageAttributes"]
        return

    if "All" in names or ".*" in names:
        return

    attributes = message["MessageAttributes"]
    matched = []

    keys = [name for name in names if ".*" not in name]
    prefixes = [name.split(".*")[0] for name in names if ".*" in name]

    # match prefix filters
    for k in attributes:
        if k in keys:
            matched.append(k)
            continue

        for prefix in prefixes:
            if k.startswith(prefix):
                matched.append(k)
            break

    message["MessageAttributes"] = {k: attributes[k] for k in matched}
