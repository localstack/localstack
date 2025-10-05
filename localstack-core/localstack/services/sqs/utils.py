import base64
import hashlib
import itertools
import json
import re
import struct
import time
from typing import Any, Literal, NamedTuple
from urllib.parse import urlparse

from localstack.aws.api.sqs import (
    AttributeNameList,
    Message,
    MessageAttributeNameList,
    QueueAttributeName,
    ReceiptHandleIsInvalid,
)
from localstack.services.sqs.constants import (
    DOMAIN_STRATEGY_URL_REGEX,
    LEGACY_STRATEGY_URL_REGEX,
    PATH_STRATEGY_URL_REGEX,
    STANDARD_STRATEGY_URL_REGEX,
)
from localstack.utils.aws.arns import parse_arn
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import base64_decode, long_uid, to_bytes, to_str

STANDARD_ENDPOINT = re.compile(STANDARD_STRATEGY_URL_REGEX)
DOMAIN_ENDPOINT = re.compile(DOMAIN_STRATEGY_URL_REGEX)
PATH_ENDPOINT = re.compile(PATH_STRATEGY_URL_REGEX)
LEGACY_ENDPOINT = re.compile(LEGACY_STRATEGY_URL_REGEX)

STRING_TYPE_FIELD_INDEX = 1
BINARY_TYPE_FIELD_INDEX = 2
STRING_LIST_TYPE_FIELD_INDEX = 3
BINARY_LIST_TYPE_FIELD_INDEX = 4


def is_sqs_queue_url(url: str) -> bool:
    return any(
        [
            STANDARD_ENDPOINT.search(url),
            DOMAIN_ENDPOINT.search(url),
            PATH_ENDPOINT.search(url),
            LEGACY_ENDPOINT.search(url),
        ]
    )


def guess_endpoint_strategy_and_host(
    host: str,
) -> tuple[Literal["standard", "domain", "path"], str]:
    """
    This method is used for the dynamic endpoint strategy. It heuristically determines a tuple where the first
    element is the endpoint strategy, and the second is the part of the host after the endpoint prefix and region.
    For instance:

      * ``sqs.us-east-1.localhost.localstack.cloud`` -> ``standard, localhost.localstack.cloud``
      * ``queue.localhost.localstack.cloud:4566`` -> ``domain, localhost.localstack.cloud:4566``
      * ``us-east-2.queue.amazonaws.com`` -> ``domain, amazonaws.com``
      * ``localhost:4566`` -> ``path, localhost:443``
      * ``amazonaws.com`` -> ``path, amazonaws.com``

    :param host: the original host in the request
    :return: endpoint strategy, host segment
    """
    components = host.split(".")

    if host.startswith("sqs."):
        return "standard", ".".join(components[2:])

    if host.startswith("queue."):
        return "domain", ".".join(components[1:])

    if len(components) > 2 and components[1] == "queue":
        return "domain", ".".join(components[2:])

    return "path", host


def is_message_deduplication_id_required(queue):
    content_based_deduplication_disabled = (
        "false"
        == (queue.attributes.get(QueueAttributeName.ContentBasedDeduplication, "false")).lower()
    )
    return is_fifo_queue(queue) and content_based_deduplication_disabled


def is_fifo_queue(queue):
    return "true" == queue.attributes.get(QueueAttributeName.FifoQueue, "false").lower()


def parse_queue_url(queue_url: str) -> tuple[str, str | None, str]:
    """
    Parses an SQS Queue URL and returns a triple of account_id, region and queue_name.

    :param queue_url: the queue URL
    :return: account_id, region (may be None), queue_name
    """
    url = urlparse(queue_url.rstrip("/"))
    path_parts = url.path.lstrip("/").split("/")
    domain_parts = url.netloc.split(".")

    if len(path_parts) != 2 and len(path_parts) != 4:
        raise ValueError(f"Not a valid queue URL: {queue_url}")

    account_id, queue_name = path_parts[-2:]

    if len(path_parts) == 4:
        if path_parts[0] != "queue":
            raise ValueError(f"Not a valid queue URL: {queue_url}")
        # SQS_ENDPOINT_STRATEGY == "path"
        region = path_parts[1]
    elif url.netloc.startswith("sqs."):
        # SQS_ENDPOINT_STRATEGY == "standard"
        region = domain_parts[1]
    elif ".queue." in url.netloc:
        if domain_parts[1] != "queue":
            # .queue. should be on second position after the region
            raise ValueError(f"Not a valid queue URL: {queue_url}")
        # SQS_ENDPOINT_STRATEGY == "domain"
        region = domain_parts[0]
    elif url.netloc.startswith("queue"):
        # SQS_ENDPOINT_STRATEGY == "domain" (with default region)
        region = "us-east-1"
    else:
        region = None

    return account_id, region, queue_name


class ReceiptHandleInformation(NamedTuple):
    identifier: str
    queue_arn: str
    message_id: str
    last_received: str


def extract_receipt_handle_info(receipt_handle: str) -> ReceiptHandleInformation:
    try:
        handle = base64.b64decode(receipt_handle).decode("utf-8")
        parts = handle.split(" ")
        if len(parts) != 4:
            raise ValueError(f'The input receipt handle "{receipt_handle}" is incomplete.')
        parse_arn(parts[1])
        return ReceiptHandleInformation(*parts)
    except (IndexError, ValueError) as e:
        raise ReceiptHandleIsInvalid(
            f'The input receipt handle "{receipt_handle}" is not a valid receipt handle.'
        ) from e


def encode_receipt_handle(queue_arn, message) -> str:
    # http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/ImportantIdentifiers.html#ImportantIdentifiers-receipt-handles
    # encode the queue arn in the receipt handle, so we can later check if it belongs to the queue
    # but also add some randomness s.t. the generated receipt handles look like the ones from AWS
    handle = f"{long_uid()} {queue_arn} {message.message.get('MessageId')} {message.last_received}"
    encoded = base64.b64encode(handle.encode("utf-8"))
    return encoded.decode("utf-8")


def encode_move_task_handle(task_id: str, source_arn: str) -> str:
    """
    Move task handles are base64 encoded JSON dictionaries containing the task id and the source arn.

    :param task_id: the move task id
    :param source_arn: the source queue arn
    :return: a string of a base64 encoded json doc
    """
    doc = f'{{"taskId":"{task_id}","sourceArn":"{source_arn}"}}'
    return to_str(base64.b64encode(to_bytes(doc)))


def decode_move_task_handle(handle: str | bytes) -> tuple[str, str]:
    """
    Inverse operation of ``encode_move_task_handle``.

    :param handle: the base64 encoded task handle
    :return: a tuple of task_id and source_arn
    :raises ValueError: if the handle is not encoded correctly or does not contain the necessary fields
    """
    doc = json.loads(base64_decode(handle))
    if "taskId" not in doc:
        raise ValueError("taskId not found in handle")
    if "sourceArn" not in doc:
        raise ValueError("sourceArn not found in handle")
    return doc["taskId"], doc["sourceArn"]


@singleton_factory
def global_message_sequence():
    # creates a 20-digit number used as the start for the global sequence
    start = int(time.time()) << 33
    # itertools.count is thread safe over the GIL since its getAndIncrement operation is a single python bytecode op
    return itertools.count(start)


def generate_message_id():
    return long_uid()


def message_filter_attributes(message: Message, names: AttributeNameList | None):
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

    if QueueAttributeName.All in names:
        return

    for k in list(message["Attributes"].keys()):
        if k not in names:
            del message["Attributes"][k]


def message_filter_message_attributes(message: Message, names: MessageAttributeNameList | None):
    """
    Utility function filter from the given message (in-place) the message attributes from the given list. It will
    apply all rules according to:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.receive_message.

    :param message: The message to filter (it will be modified)
    :param names: the attributes names/filters (can be 'All', '.*', '*' or prefix filters like 'Foo.*')
    """
    if not message.get("MessageAttributes"):
        return

    if not names:
        del message["MessageAttributes"]
        return

    if "All" in names or ".*" in names or "*" in names:
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
    if matched:
        message["MessageAttributes"] = {k: attributes[k] for k in matched}
    else:
        message.pop("MessageAttributes")


def _utf8(value: Any) -> bytes:  # type: ignore[misc]
    if isinstance(value, str):
        return value.encode("utf-8")
    return value


def _update_binary_length_and_value(md5: Any, value: bytes) -> None:  # type: ignore[misc]
    length_bytes = struct.pack("!I".encode("ascii"), len(value))
    md5.update(length_bytes)
    md5.update(value)


def create_message_attribute_hash(message_attributes) -> str | None:
    """
    Method from moto's attribute_md5 of moto/sqs/models.py, separated from the Message Object.
    """
    # To avoid the need to check for dict conformity everytime we invoke this function
    if not isinstance(message_attributes, dict):
        return

    hash = hashlib.md5()

    for attrName in sorted(message_attributes.keys()):
        attr_value = message_attributes[attrName]
        # Encode name
        _update_binary_length_and_value(hash, _utf8(attrName))
        # Encode data type
        _update_binary_length_and_value(hash, _utf8(attr_value["DataType"]))
        # Encode transport type and value
        if attr_value.get("StringValue"):
            hash.update(bytearray([STRING_TYPE_FIELD_INDEX]))
            _update_binary_length_and_value(hash, _utf8(attr_value.get("StringValue")))
        elif attr_value.get("BinaryValue"):
            hash.update(bytearray([BINARY_TYPE_FIELD_INDEX]))
            decoded_binary_value = attr_value.get("BinaryValue")
            _update_binary_length_and_value(hash, decoded_binary_value)
        # string_list_value, binary_list_value type is not implemented, reserved for the future use.
        # See https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_MessageAttributeValue.html
    return hash.hexdigest()
