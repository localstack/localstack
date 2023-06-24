import copy
import hashlib
import json
import logging
import re
import threading
import time
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from moto.sqs.models import BINARY_TYPE_FIELD_INDEX, STRING_TYPE_FIELD_INDEX
from moto.sqs.models import Message as MotoMessage

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, ServiceException
from localstack.aws.api.sqs import (
    ActionNameList,
    AttributeNameList,
    AWSAccountIdList,
    BatchEntryIdsNotDistinct,
    BatchRequestTooLong,
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
    InvalidBatchEntryId,
    InvalidMessageContents,
    ListDeadLetterSourceQueuesResult,
    ListQueuesResult,
    ListQueueTagsResult,
    Message,
    MessageAttributeNameList,
    MessageBodyAttributeMap,
    MessageBodySystemAttributeMap,
    MessageSystemAttributeName,
    PurgeQueueInProgress,
    QueueAttributeMap,
    QueueAttributeName,
    QueueDeletedRecently,
    QueueDoesNotExist,
    QueueNameExists,
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
    TooManyEntriesInBatchRequest,
)
from localstack.aws.protocol.serializer import aws_response_serializer, create_serializer
from localstack.aws.spec import load_service
from localstack.config import SQS_DISABLE_MAX_NUMBER_OF_MESSAGE_LIMIT
from localstack.http import Request, route
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sqs import constants as sqs_constants
from localstack.services.sqs.exceptions import InvalidParameterValue
from localstack.services.sqs.models import (
    FifoQueue,
    SqsMessage,
    SqsQueue,
    SqsStore,
    StandardQueue,
    sqs_stores,
)
from localstack.services.sqs.utils import generate_message_id, parse_queue_url
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import parse_arn
from localstack.utils.aws.request_context import extract_region_from_headers
from localstack.utils.cloudwatch.cloudwatch_util import publish_sqs_metric
from localstack.utils.run import FuncThread
from localstack.utils.scheduler import Scheduler
from localstack.utils.strings import md5
from localstack.utils.threads import start_thread
from localstack.utils.time import now

LOG = logging.getLogger(__name__)

MAX_NUMBER_OF_MESSAGES = 10
_STORE_LOCK = threading.RLock()


class InvalidAddress(ServiceException):
    code = "InvalidAddress"
    message = "The address https://queue.amazonaws.com/ is not valid for this endpoint."
    sender_fault = True
    status_code = 404


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


def check_message_size(
    message_body: str, message_attributes: MessageBodyAttributeMap, max_message_size: int
):
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
    error = "One or more parameters are invalid. "
    error += f"Reason: Message must be shorter than {max_message_size} bytes."

    if (
        _message_body_size(message_body) + _message_attributes_size(message_attributes)
        > max_message_size
    ):
        raise InvalidParameterValue(error)


def _message_body_size(body: str):
    return _bytesize(body)


def _message_attributes_size(attributes: MessageBodyAttributeMap):
    if not attributes:
        return 0
    message_attributes_keys_size = sum(_bytesize(k) for k in attributes.keys())
    message_attributes_values_size = sum(
        sum(_bytesize(v) for v in attr.values()) for attr in attributes.values()
    )
    return message_attributes_keys_size + message_attributes_values_size


def _bytesize(value: str | bytes):
    # must encode as utf8 to get correct bytes with len
    return len(value.encode("utf8")) if isinstance(value, str) else len(value)


def check_message_content(message_body: str):
    error = "Invalid characters found. Valid unicode characters are #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF"

    if not re.match(sqs_constants.MSG_CONTENT_REGEX, message_body):
        raise InvalidMessageContents(error)


class CloudwatchDispatcher:
    """
    Dispatches SQS metrics for specific api-calls using a ThreadPool
    """

    def __init__(self, num_thread: int = 3):
        self.executor = ThreadPoolExecutor(
            num_thread, thread_name_prefix="sqs-metrics-cloudwatch-dispatcher"
        )

    def shutdown(self):
        self.executor.shutdown(wait=False)

    def dispatch_sqs_metric(
        self, region: str, queue_name: str, metric: str, value: float = 1, unit: str = "Count"
    ):
        """
        Publishes a metric to Cloudwatch using a Threadpool
        :param region The region that should be used for Cloudwatch client
        :param queue_name The name of the queue that the metric belongs to
        :param metric The name of the metric
        :param value The value for that metric, default 1
        :param unit The unit for the value, default "Count"
        """
        self.executor.submit(
            publish_sqs_metric,
            region=region,
            queue_name=queue_name,
            metric=metric,
            value=value,
            unit=unit,
        )

    def dispatch_metric_message_sent(self, queue: SqsQueue, message_body_size: int):
        """
        Sends metric 'NumberOfMessagesSent' and 'SentMessageSize' to Cloudwatch
        :param queue The Queue for which the metric will be send
        :param message_body_size the size of the message in bytes
        """
        self.dispatch_sqs_metric(
            region=queue.region, queue_name=queue.name, metric="NumberOfMessagesSent"
        )
        self.dispatch_sqs_metric(
            region=queue.region,
            queue_name=queue.name,
            metric="SentMessageSize",
            value=message_body_size,
            unit="Bytes",
        )

    def dispatch_metric_message_deleted(self, queue: SqsQueue, deleted: int = 1):
        """
        Sends metric 'NumberOfMessagesDeleted' to Cloudwatch
        :param queue The Queue for which the metric will be sent
        :param deleted The number of messages that were successfully deleted, default: 1
        """
        self.dispatch_sqs_metric(
            region=queue.region,
            queue_name=queue.name,
            metric="NumberOfMessagesDeleted",
            value=deleted,
        )

    def dispatch_metric_received(self, queue: SqsQueue, received: int):
        """
        Sends metric 'NumberOfMessagesReceived' (if received > 0), or 'NumberOfEmptyReceives' to Cloudwatch
        :param queue The Queue for which the metric will be send
        :param received The number of messages that have been received
        """
        if received > 0:
            self.dispatch_sqs_metric(
                region=queue.region,
                queue_name=queue.name,
                metric="NumberOfMessagesReceived",
                value=received,
            )
        else:
            self.dispatch_sqs_metric(
                region=queue.region, queue_name=queue.name, metric="NumberOfEmptyReceives"
            )


class CloudwatchPublishWorker:
    """
    Regularly publish metrics data about approximate messages to Cloudwatch.
    Includes: ApproximateNumberOfMessagesVisible, ApproximateNumberOfMessagesNotVisible
        and ApproximateNumberOfMessagesDelayed
    """

    def __init__(self) -> None:
        super().__init__()
        self.scheduler = Scheduler()
        self.thread: Optional[FuncThread] = None

    def publish_approximate_cloudwatch_metrics(self):
        for account_id, region_bundle in sqs_stores.items():
            for region, store in region_bundle.items():
                for queue in store.queues.values():
                    self.publish_approximate_metrics_for_queue_to_cloudwatch(queue)

    def publish_approximate_metrics_for_queue_to_cloudwatch(self, queue):
        """Publishes the metrics for ApproximateNumberOfMessagesVisible, ApproximateNumberOfMessagesNotVisible
        and ApproximateNumberOfMessagesDelayed to CloudWatch"""
        # TODO ApproximateAgeOfOldestMessage is missing
        #  https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html
        publish_sqs_metric(
            region=queue.region,
            queue_name=queue.name,
            metric="ApproximateNumberOfMessagesVisible",
            value=queue.approx_number_of_messages,
        )
        publish_sqs_metric(
            region=queue.region,
            queue_name=queue.name,
            metric="ApproximateNumberOfMessagesNotVisible",
            value=queue.approx_number_of_messages_not_visible,
        )
        publish_sqs_metric(
            region=queue.region,
            queue_name=queue.name,
            metric="ApproximateNumberOfMessagesDelayed",
            value=queue.approx_number_of_messages_delayed,
        )

    def start(self):
        if self.thread:
            return

        self.scheduler = Scheduler()
        self.scheduler.schedule(
            self.publish_approximate_cloudwatch_metrics,
            period=config.SQS_CLOUDWATCH_METRICS_REPORT_INTERVAL,
        )

        def _run(*_args):
            self.scheduler.run()

        self.thread = start_thread(_run, name="sqs-approx-metrics-cloudwatch-publisher")

    def stop(self):
        if self.scheduler:
            self.scheduler.close()

        if self.thread:
            self.thread.stop()

        self.thread = None
        self.scheduler = None


class QueueUpdateWorker:
    """
    Regularly re-queues inflight and delayed messages whose visibility timeout has expired or delay deadline has been
    reached.
    """

    def __init__(self) -> None:
        super().__init__()
        self.scheduler = Scheduler()
        self.thread: Optional[FuncThread] = None
        self.mutex = threading.RLock()

    def do_update_all_queues(self):
        for account_id, region_bundle in sqs_stores.items():
            for region, store in region_bundle.items():
                for queue in store.queues.values():
                    try:
                        queue.requeue_inflight_messages()
                    except Exception:
                        LOG.exception("error re-queueing inflight messages")

                    try:
                        queue.enqueue_delayed_messages()
                    except Exception:
                        LOG.exception("error enqueueing delayed messages")

    def start(self):
        with self.mutex:
            if self.thread:
                return

            self.scheduler = Scheduler()
            self.scheduler.schedule(self.do_update_all_queues, period=1)

            def _run(*_args):
                self.scheduler.run()

            self.thread = start_thread(_run, name="sqs-queue-update-worker")

    def stop(self):
        with self.mutex:
            if self.scheduler:
                self.scheduler.close()

            if self.thread:
                self.thread.stop()

            self.thread = None
            self.scheduler = None


def check_attributes(message_attributes: MessageBodyAttributeMap):
    if not message_attributes:
        return
    for attribute_name in message_attributes:
        if len(attribute_name) >= 256:
            raise InvalidParameterValue(
                "Message (user) attribute names must be shorter than 256 Bytes"
            )
        if not re.match(sqs_constants.ATTR_NAME_CHAR_REGEX, attribute_name.lower()):
            raise InvalidParameterValue(
                "Message (user) attributes name can only contain upper and lower score characters, digits, periods, "
                "hyphens and underscores. "
            )
        if not re.match(sqs_constants.ATTR_NAME_PREFIX_SUFFIX_REGEX, attribute_name.lower()):
            raise InvalidParameterValue(
                "You can't use message attribute names beginning with 'AWS.' or 'Amazon.'. "
                "These strings are reserved for internal use. Additionally, they cannot start or end with '.'."
            )

        attribute = message_attributes[attribute_name]
        attribute_type = attribute.get("DataType")
        if not attribute_type:
            raise InvalidParameterValue("Missing required parameter DataType")
        if not re.match(sqs_constants.ATTR_TYPE_REGEX, attribute_type):
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
    if not re.match(sqs_constants.FIFO_MSG_REGEX, fifo_id):
        raise InvalidParameterValue(
            "Invalid characters found. Deduplication ID and group ID can only contain"
            "alphanumeric characters as well as TODO"
        )


class SqsDeveloperEndpoints:
    """
    A set of SQS developer tool endpoints:

    - ``/_aws/sqs/messages``: list SQS messages without side effects, compatible with ``ReceiveMessage``.
    """

    def __init__(self, stores=None):
        self.stores = stores or sqs_stores
        self.service = load_service("sqs")
        self.serializer = create_serializer(self.service)

    @route("/_aws/sqs/messages")
    @aws_response_serializer("sqs", "ReceiveMessage")
    def list_messages(self, request: Request) -> ReceiveMessageResult:
        """
        This endpoint expects a ``QueueUrl`` request parameter (either as query arg or form parameter), similar to
        the ``ReceiveMessage`` operation. It will parse the Queue URL generated by one of the SQS endpoint strategies.
        """
        if "Action" in request.values and request.values["Action"] != "ReceiveMessage":
            raise CommonServiceException(
                "InvalidRequest", "This endpoint only accepts ReceiveMessage calls"
            )

        if not request.values.get("QueueUrl"):
            raise QueueDoesNotExist()

        try:
            account_id, region, queue_name = parse_queue_url(request.values["QueueUrl"])
        except ValueError:
            LOG.exception("Error while parsing Queue URL from request values: %s", request.values)
            raise InvalidAddress()

        if not region:
            region = extract_region_from_headers(request.headers)

        return self._get_and_serialize_messages(request, region, account_id, queue_name)

    @route("/_aws/sqs/messages/<region>/<account_id>/<queue_name>")
    @aws_response_serializer("sqs", "ReceiveMessage")
    def list_messages_for_queue_url(
        self, request: Request, region: str, account_id: str, queue_name: str
    ) -> ReceiveMessageResult:
        """
        This endpoint extracts the region, account_id, and queue_name directly from the URL rather than requiring the
        QueueUrl as parameter.
        """
        if "Action" in request.values and request.values["Action"] != "ReceiveMessage":
            raise CommonServiceException(
                "InvalidRequest", "This endpoint only accepts ReceiveMessage calls"
            )

        return self._get_and_serialize_messages(request, region, account_id, queue_name)

    def _get_and_serialize_messages(
        self, request: Request, region: str, account_id: str, queue_name: str
    ) -> ReceiveMessageResult:
        try:
            store = self.stores[account_id or get_aws_account_id()][
                region or aws_stack.get_region()
            ]
            queue = store.queues[queue_name]
        except KeyError:
            LOG.info(
                "no queue named %s in region %s and account %s", queue_name, region, account_id
            )
            raise QueueDoesNotExist()

        messages = self._collect_visible_messages(queue)
        return ReceiveMessageResult(Messages=messages)

    def _collect_visible_messages(self, queue: SqsQueue) -> List[Message]:
        """
        Retrieves from a given SqsQueue all visible messages without causing any side effects (not setting any
        receive timestamps, receive counts, or visibility state).

        :param queue: the queue
        :return: a list of messages
        """
        receipt_handle = "SQS/BACKDOOR/ACCESS"  # dummy receipt handle

        sqs_messages: List[SqsMessage] = []

        if isinstance(queue, StandardQueue):
            sqs_messages.extend(queue.visible.queue)
        elif isinstance(queue, FifoQueue):
            for message_group in queue.message_groups.values():
                for sqs_message in message_group.messages:
                    sqs_messages.append(sqs_message)
        else:
            raise ValueError(f"unknown queue type {type(queue)}")

        messages = []

        for sqs_message in sqs_messages:
            message: Message = to_sqs_api_message(sqs_message, QueueAttributeName.All, ["All"])
            messages.append(message)
            message["ReceiptHandle"] = receipt_handle

        return messages


class SqsProvider(SqsApi, ServiceLifecycleHook):
    """
    LocalStack SQS Provider.

    LIMITATIONS:
        - Pagination of results (NextToken)
        - Delivery guarantees
        - The region is not encoded in the queue URL

    CROSS-ACCOUNT ACCESS:
    LocalStack permits cross-account access for all operations. However, AWS
    disallows the same for following operations:
        - AddPermission
        - CreateQueue
        - DeleteQueue
        - ListQueues
        - ListQueueTags
        - RemovePermission
        - SetQueueAttributes
        - TagQueue
        - UntagQueue
    """

    queues: Dict[str, SqsQueue]

    def __init__(self) -> None:
        super().__init__()
        self._queue_update_worker = QueueUpdateWorker()
        self._router_rules = []
        self._init_cloudwatch_metrics_reporting()

    @staticmethod
    def get_store(account_id: str = None, region: str = None) -> SqsStore:
        return sqs_stores[account_id or get_aws_account_id()][region or aws_stack.get_region()]

    def on_before_start(self):
        self._router_rules = ROUTER.add(SqsDeveloperEndpoints())
        self._queue_update_worker.start()
        self._start_cloudwatch_metrics_reporting()

    def on_before_stop(self):
        for rule in self._router_rules:
            ROUTER.remove_rule(rule)

        self._queue_update_worker.stop()
        self._stop_cloudwatch_metrics_reporting()

    @staticmethod
    def _require_queue(account_id: str, region_name: str, name: str) -> SqsQueue:
        """
        Returns the queue for the given name, or raises QueueDoesNotExist if it does not exist.

        :param: context: the request context
        :param name: the name to look for
        :returns: the queue
        :raises QueueDoesNotExist: if the queue does not exist
        """
        store = SqsProvider.get_store(account_id, region_name)
        with _STORE_LOCK:
            if name not in store.queues.keys():
                raise QueueDoesNotExist("The specified queue does not exist for this wsdl version.")

            return store.queues[name]

    def _require_queue_by_arn(self, context: RequestContext, queue_arn: str) -> SqsQueue:
        arn = parse_arn(queue_arn)
        return self._require_queue(arn["account"], arn["region"], arn["resource"])

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
        account_id, region_name, name = resolve_queue_location(context, queue_name, queue_url)
        return self._require_queue(account_id, region_name or context.region, name)

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

        store = self.get_store(context.account_id, context.region)

        with _STORE_LOCK:
            if queue_name in store.queues:
                queue = store.queues[queue_name]

                if attributes:
                    # if attributes are set, then we check whether the existing attributes match the passed ones
                    queue.validate_queue_attributes(attributes)
                    for k, v in attributes.items():
                        if queue.attributes.get(k) != v:
                            LOG.debug(
                                "queue attribute values %s for queue %s do not match %s (existing) != %s (new)",
                                k,
                                queue_name,
                                queue.attributes.get(k),
                                v,
                            )
                            raise QueueNameExists(
                                f"A queue already exists with the same name and a different value for attribute {k}"
                            )

                return CreateQueueResult(QueueUrl=queue.url(context))

            if config.SQS_DELAY_RECENTLY_DELETED:
                deleted = store.deleted.get(queue_name)
                if deleted and deleted > (time.time() - sqs_constants.RECENTLY_DELETED_TIMEOUT):
                    raise QueueDeletedRecently(
                        "You must wait 60 seconds after deleting a queue before you can create "
                        "another with the same name."
                    )
            store.expire_deleted()

            # create the appropriate queue
            if fifo:
                queue = FifoQueue(queue_name, context.region, context.account_id, attributes, tags)
            else:
                queue = StandardQueue(
                    queue_name, context.region, context.account_id, attributes, tags
                )

            LOG.debug("creating queue key=%s attributes=%s tags=%s", queue_name, attributes, tags)

            store.queues[queue_name] = queue

        return CreateQueueResult(QueueUrl=queue.url(context))

    def get_queue_url(
        self, context: RequestContext, queue_name: String, queue_owner_aws_account_id: String = None
    ) -> GetQueueUrlResult:
        store = self.get_store(queue_owner_aws_account_id or context.account_id, context.region)
        if queue_name not in store.queues.keys():
            raise QueueDoesNotExist("The specified queue does not exist for this wsdl version.")

        queue = store.queues[queue_name]

        return GetQueueUrlResult(QueueUrl=queue.url(context))

    def list_queues(
        self,
        context: RequestContext,
        queue_name_prefix: String = None,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListQueuesResult:
        store = self.get_store(context.account_id, context.region)

        if queue_name_prefix:
            urls = [
                queue.url(context)
                for queue in store.queues.values()
                if queue.name.startswith(queue_name_prefix)
            ]
        else:
            urls = [queue.url(context) for queue in store.queues.values()]

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
        account_id, region, name = parse_queue_url(queue_url)
        if region is None:
            region = context.region

        if account_id != context.account_id:
            LOG.warning(
                "Attempting a cross-account DeleteQueue operation (account from context: %s, account from queue url: %s, which is not allowed in AWS",
                account_id,
                context.account_id,
            )

        with _STORE_LOCK:
            store = self.get_store(account_id, region)
            queue = self._resolve_queue(context, queue_url=queue_url)
            LOG.debug(
                "deleting queue name=%s, region=%s, account=%s",
                queue.name,
                queue.region,
                queue.account_id,
            )
            del store.queues[queue.name]
            store.deleted[queue.name] = time.time()

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

        # Have to check the message size here, rather than in _put_message
        # to avoid multiple calls for batch messages.
        check_message_size(message_body, message_attributes, queue.maximum_message_size)

        queue_item = self._put_message(
            queue,
            context,
            message_body,
            delay_seconds,
            message_attributes,
            message_system_attributes,
            message_deduplication_id,
            message_group_id,
        )
        message = queue_item.message
        return SendMessageResult(
            MessageId=message["MessageId"],
            MD5OfMessageBody=message["MD5OfBody"],
            MD5OfMessageAttributes=message.get("MD5OfMessageAttributes"),
            SequenceNumber=queue_item.sequence_number,
            MD5OfMessageSystemAttributes=_create_message_attribute_hash(message_system_attributes),
        )

    def send_message_batch(
        self, context: RequestContext, queue_url: String, entries: SendMessageBatchRequestEntryList
    ) -> SendMessageBatchResult:
        queue = self._resolve_queue(context, queue_url=queue_url)

        self._assert_batch(entries)
        # check the total batch size first and raise BatchRequestTooLong id > DEFAULT_MAXIMUM_MESSAGE_SIZE.
        # This is checked before any messages in the batch are sent.  Raising the exception here should
        # cause error response, rather than batching error results and returning
        self._assert_valid_batch_size(entries, sqs_constants.DEFAULT_MAXIMUM_MESSAGE_SIZE)

        successful = []
        failed = []

        with queue.mutex:
            for entry in entries:
                try:
                    queue_item = self._put_message(
                        queue,
                        context,
                        message_body=entry.get("MessageBody"),
                        delay_seconds=entry.get("DelaySeconds"),
                        message_attributes=entry.get("MessageAttributes"),
                        message_system_attributes=entry.get("MessageSystemAttributes"),
                        message_deduplication_id=entry.get("MessageDeduplicationId"),
                        message_group_id=entry.get("MessageGroupId"),
                    )
                    message = queue_item.message

                    successful.append(
                        SendMessageBatchResultEntry(
                            Id=entry["Id"],
                            MessageId=message.get("MessageId"),
                            MD5OfMessageBody=message.get("MD5OfBody"),
                            MD5OfMessageAttributes=message.get("MD5OfMessageAttributes"),
                            MD5OfMessageSystemAttributes=_create_message_attribute_hash(
                                message.get("message_system_attributes")
                            ),
                            SequenceNumber=queue_item.sequence_number,
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
    ) -> SqsMessage:
        check_message_content(message_body)
        check_attributes(message_attributes)
        check_attributes(message_system_attributes)
        check_fifo_id(message_deduplication_id)
        check_fifo_id(message_group_id)

        message = Message(
            MessageId=generate_message_id(),
            MD5OfBody=md5(message_body),
            Body=message_body,
            Attributes=self._create_message_attributes(context, message_system_attributes),
            MD5OfMessageAttributes=_create_message_attribute_hash(message_attributes),
            MessageAttributes=message_attributes,
        )
        if self._cloudwatch_dispatcher:
            self._cloudwatch_dispatcher.dispatch_metric_message_sent(
                queue=queue, message_body_size=len(message_body.encode("utf-8"))
            )

        return queue.put(
            message=message,
            message_deduplication_id=message_deduplication_id,
            message_group_id=message_group_id,
            delay_seconds=int(delay_seconds) if delay_seconds is not None else None,
        )

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

        # backdoor to get all messages
        if num == -1:
            num = queue.approx_number_of_messages
        elif (
            num < 1 or num > MAX_NUMBER_OF_MESSAGES
        ) and not SQS_DISABLE_MAX_NUMBER_OF_MESSAGE_LIMIT:
            raise InvalidParameterValue(
                f"Value {num} for parameter MaxNumberOfMessages is invalid. "
                f"Reason: Must be between 1 and 10, if provided."
            )

        # we chose to always return the maximum possible number of messages, even though AWS will typically return
        # fewer messages than requested on small queues. at some point we could maybe change this to randomly sample
        # between 1 and max_number_of_messages.
        # see https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
        result = queue.receive(num, wait_time_seconds, visibility_timeout)

        # process dead letter messages
        if result.dead_letter_messages:
            dead_letter_target_arn = queue.redrive_policy["deadLetterTargetArn"]
            dl_queue = self._require_queue_by_arn(context, dead_letter_target_arn)
            # TODO: does this need to be atomic?
            for standard_message in result.dead_letter_messages:
                message = to_sqs_api_message(
                    standard_message, attribute_names, message_attribute_names
                )
                dl_queue.put(
                    message=message,
                    message_deduplication_id=standard_message.message_deduplication_id,
                    message_group_id=standard_message.message_group_id,
                )

        # prepare result
        messages = []
        for i, standard_message in enumerate(result.successful):
            message = to_sqs_api_message(standard_message, attribute_names, message_attribute_names)
            message["ReceiptHandle"] = result.receipt_handles[i]
            messages.append(message)

        if self._cloudwatch_dispatcher:
            self._cloudwatch_dispatcher.dispatch_metric_received(queue, received=len(messages))

        # TODO: how does receiving behave if the queue was deleted in the meantime?
        return ReceiveMessageResult(Messages=messages)

    def list_dead_letter_source_queues(
        self,
        context: RequestContext,
        queue_url: String,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListDeadLetterSourceQueuesResult:
        urls = []
        store = self.get_store(context.account_id, context.region)
        dead_letter_queue = self._resolve_queue(context, queue_url=queue_url)
        for queue in store.queues.values():
            policy = queue.attributes.get(QueueAttributeName.RedrivePolicy)
            if policy:
                policy = json.loads(policy)
                dlq_arn = policy.get("deadLetterTargetArn")
                if dlq_arn == dead_letter_queue.arn:
                    urls.append(queue.url(context))
        return ListDeadLetterSourceQueuesResult(queueUrls=urls)

    def delete_message(
        self, context: RequestContext, queue_url: String, receipt_handle: String
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)
        queue.remove(receipt_handle)
        if self._cloudwatch_dispatcher:
            self._cloudwatch_dispatcher.dispatch_metric_message_deleted(queue)

    def delete_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: DeleteMessageBatchRequestEntryList,
    ) -> DeleteMessageBatchResult:
        queue = self._resolve_queue(context, queue_url=queue_url)
        self._assert_batch(entries)
        self._assert_valid_message_ids(entries)

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
        if self._cloudwatch_dispatcher:
            self._cloudwatch_dispatcher.dispatch_metric_message_deleted(
                queue, deleted=len(successful)
            )

        return DeleteMessageBatchResult(
            Successful=successful,
            Failed=failed,
        )

    def purge_queue(self, context: RequestContext, queue_url: String) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        with queue.mutex:
            if config.SQS_DELAY_PURGE_RETRY:
                if queue.purge_timestamp and (queue.purge_timestamp + 60) > time.time():
                    raise PurgeQueueInProgress(
                        f"Only one PurgeQueue operation on {queue.name} is allowed every 60 seconds."
                    )
            queue.purge_timestamp = time.time()
            queue.clear()

    def set_queue_attributes(
        self, context: RequestContext, queue_url: String, attributes: QueueAttributeMap
    ) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        if not attributes:
            return

        queue.validate_queue_attributes(attributes)

        for k, v in attributes.items():
            if k in sqs_constants.INTERNAL_QUEUE_ATTRIBUTES:
                raise InvalidAttributeName(f"Unknown Attribute {k}.")
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
            if max_receive_count is None:
                raise InvalidParameterValue("The required parameter 'maxReceiveCount' is missing")
            try:
                max_receive_count = int(max_receive_count)
                valid_count = 1 <= max_receive_count <= 1000
            except ValueError:
                valid_count = False
            if not valid_count:
                raise InvalidParameterValue(
                    f"Value {redrive_policy} for parameter RedrivePolicy is invalid. Reason: Invalid value for "
                    f"maxReceiveCount: {max_receive_count}, valid values are from 1 to 1000 both inclusive."
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

        queue.add_permission(label=label, actions=actions, account_ids=aws_account_ids)

    def remove_permission(self, context: RequestContext, queue_url: String, label: String) -> None:
        queue = self._resolve_queue(context, queue_url=queue_url)

        queue.remove_permission(label=label)

    def _create_message_attributes(
        self,
        context: RequestContext,
        message_system_attributes: MessageBodySystemAttributeMap = None,
    ) -> Dict[MessageSystemAttributeName, str]:
        result: Dict[MessageSystemAttributeName, str] = {
            MessageSystemAttributeName.SenderId: context.account_id,  # not the account ID in AWS
            MessageSystemAttributeName.SentTimestamp: str(now(millis=True)),
        }

        if message_system_attributes is not None:
            for attr in message_system_attributes:
                result[attr] = message_system_attributes[attr]["StringValue"]

        return result

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

    def _assert_batch(self, batch: List) -> None:
        if not batch:
            raise EmptyBatchRequest
        if batch and (no_entries := len(batch)) > MAX_NUMBER_OF_MESSAGES:
            raise TooManyEntriesInBatchRequest(
                f"Maximum number of entries per request are {MAX_NUMBER_OF_MESSAGES}. You have sent {no_entries}."
            )
        visited = set()
        for entry in batch:
            entry_id = entry["Id"]
            if not re.search(r"^[\w-]+$", entry_id) or len(entry_id) > 80:
                raise InvalidBatchEntryId(
                    "A batch entry id can only contain alphanumeric characters, hyphens and underscores. "
                    "It can be at most 80 letters long."
                )
            if entry_id in visited:
                raise BatchEntryIdsNotDistinct()
            else:
                visited.add(entry_id)

    def _assert_valid_batch_size(self, batch: List, max_message_size: int):
        batch_message_size = sum(
            _message_body_size(entry.get("MessageBody"))
            + _message_attributes_size(entry.get("MessageAttributes"))
            for entry in batch
        )
        if batch_message_size > max_message_size:
            error = f"Batch requests cannot be longer than {max_message_size} bytes."
            error += f" You have sent {batch_message_size} bytes."
            raise BatchRequestTooLong(error)

    def _assert_valid_message_ids(self, batch: List):
        batch_id_regex = r"^[\w-]{1,80}$"
        for message in batch:
            if not re.match(batch_id_regex, message.get("Id", "")):
                raise InvalidBatchEntryId(
                    "A batch entry id can only contain alphanumeric characters, "
                    "hyphens and underscores. It can be at most 80 letters long."
                )

    def _init_cloudwatch_metrics_reporting(self):
        self._cloudwatch_publish_worker = (
            None if config.SQS_DISABLE_CLOUDWATCH_METRICS else CloudwatchPublishWorker()
        )
        self._cloudwatch_dispatcher = (
            None if config.SQS_DISABLE_CLOUDWATCH_METRICS else CloudwatchDispatcher()
        )

    def _start_cloudwatch_metrics_reporting(self):
        if not config.SQS_DISABLE_CLOUDWATCH_METRICS:
            self._cloudwatch_publish_worker.start()

    def _stop_cloudwatch_metrics_reporting(self):
        if not config.SQS_DISABLE_CLOUDWATCH_METRICS:
            self._cloudwatch_publish_worker.stop()
            self._cloudwatch_dispatcher.shutdown()


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
            decoded_binary_value = attr_value.get("BinaryValue")
            MotoMessage.update_binary_length_and_value(hash, decoded_binary_value)
        # string_list_value, binary_list_value type is not implemented, reserved for the future use.
        # See https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_MessageAttributeValue.html
    return hash.hexdigest()


def resolve_queue_location(
    context: RequestContext, queue_name: Optional[str] = None, queue_url: Optional[str] = None
) -> Tuple[str, Optional[str], str]:
    """
    Resolves a queue location from the given information.

    :param context: the request context, used for getting region and account_id, and optionally the queue_url
    :param queue_name: the queue name (if this is set, then this will be used for the key)
    :param queue_url: the queue url (if name is not set, this will be used to determine the queue name)
    :return: tuple of account id, region and queue_name
    """
    if not queue_name:
        try:
            if queue_url:
                return parse_queue_url(queue_url)
            else:
                return parse_queue_url(context.request.base_url)
        except ValueError:
            # should work if queue name is passed in QueueUrl
            return context.account_id, context.region, queue_url

    return context.account_id, context.region, queue_name


def to_sqs_api_message(
    standard_message: SqsMessage,
    attribute_names: AttributeNameList = None,
    message_attribute_names: MessageAttributeNameList = None,
) -> Message:
    """
    Utility function to convert an SQS message from LocalStack's internal representation to the AWS API
    concept 'Message', which is the format returned by the ``ReceiveMessage`` operation.

    :param standard_message: A LocalStack SQS message
    :param attribute_names: the attribute name list to filter
    :param message_attribute_names: the message attribute names to filter
    :return: a copy of the original Message with updated message attributes and MD5 attribute hash sums
    """
    # prepare message for receiver
    message = copy.deepcopy(standard_message.message)

    # update system attributes of the message copy
    message["Attributes"][MessageSystemAttributeName.ApproximateReceiveCount] = str(
        (standard_message.receive_count or 0)
    )
    message["Attributes"][MessageSystemAttributeName.ApproximateFirstReceiveTimestamp] = str(
        int((standard_message.first_received or 0) * 1000)
    )

    # filter attributes for receiver
    message_filter_attributes(message, attribute_names)
    message_filter_message_attributes(message, message_attribute_names)
    if message.get("MessageAttributes"):
        message["MD5OfMessageAttributes"] = _create_message_attribute_hash(
            message["MessageAttributes"]
        )
    else:
        # delete the value that was computed when creating the message
        message.pop("MD5OfMessageAttributes", None)
    return message


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
