import base64
import itertools
import json
import re
import time
from typing import Literal, NamedTuple, Optional, Tuple
from urllib.parse import urlparse

from localstack.aws.api.sqs import QueueAttributeName, ReceiptHandleIsInvalid
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
) -> Tuple[Literal["standard", "domain", "path"], str]:
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


def parse_queue_url(queue_url: str) -> Tuple[str, Optional[str], str]:
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


def token_generator(item: str) -> str:
    base64_bytes = base64.b64encode(item.encode("utf-8"))
    next_token = base64_bytes.decode("utf-8")
    return next_token
