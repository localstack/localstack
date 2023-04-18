import base64
import itertools
import re
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

from moto.sqs.exceptions import MessageAttributesInvalid
from moto.sqs.models import TRANSPORT_TYPE_ENCODINGS, Message

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.sqs import ReceiptHandleIsInvalid
from localstack.utils.aws.arns import parse_arn
from localstack.utils.common import clone
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import long_uid
from localstack.utils.urls import path_from_url


def is_sqs_queue_url(url):
    path = path_from_url(url).partition("?")[0]
    return re.match(r"^/(queue|%s)/[a-zA-Z0-9_-]+(.fifo)?$" % get_aws_account_id(), path)


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


def parse_message_attributes(
    querystring, key="MessageAttribute", base="", value_namespace="Value."
):
    message_attributes = {}
    index = 1
    while True:
        # Loop through looking for message attributes
        name_key = base + "{0}.{1}.Name".format(key, index)
        name = querystring.get(name_key)
        if not name:
            # Found all attributes
            break

        data_type_key = base + "{0}.{1}.{2}DataType".format(key, index, value_namespace)
        data_type = querystring.get(data_type_key)
        if not data_type:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' must contain non-empty message attribute value.".format(
                    name[0]
                )
            )

        data_type_parts = data_type[0].split(".")
        if data_type_parts[0] not in [
            "String",
            "Binary",
            "Number",
        ]:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String.".format(
                    name[0]
                )
            )

        type_prefix = "String"
        if data_type_parts[0] == "Binary":
            type_prefix = "Binary"

        value_key = base + "{0}.{1}.{2}{3}Value".format(key, index, value_namespace, type_prefix)
        value = querystring.get(value_key)
        if not value:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' must contain non-empty message attribute value for message attribute type '{1}'.".format(
                    name[0], data_type[0]
                )
            )

        message_attributes[name[0]] = {
            "data_type": data_type[0],
            type_prefix.lower() + "_value": value[0],
        }

        index += 1

    return message_attributes


def get_message_attributes_md5(req_data):
    req_data = clone(req_data)
    orig_types = {}
    for key, entry in dict(req_data).items():
        # Fix an issue in moto where data types like 'Number.java.lang.Integer' are
        # not supported: Keep track of the original data type, and temporarily change
        # it to the short form (e.g., 'Number'), before changing it back again.
        if key.endswith("DataType"):
            parts = entry.split(".")
            if len(parts) > 2:
                short_type_name = parts[0]
                full_type_name = entry
                attr_num = key.split(".")[1]
                attr_name = req_data["MessageAttribute.%s.Name" % attr_num]
                orig_types[attr_name] = full_type_name
                req_data[key] = [short_type_name]
                if full_type_name not in TRANSPORT_TYPE_ENCODINGS:
                    TRANSPORT_TYPE_ENCODINGS[full_type_name] = TRANSPORT_TYPE_ENCODINGS[
                        short_type_name
                    ]

    # moto parse_message_attributes(..) expects params to be passed as dict of lists
    req_data_lists = {k: [v] for k, v in req_data.items()}
    moto_message = Message("dummy_msg_id", "dummy_body")
    moto_message.message_attributes = parse_message_attributes(req_data_lists)
    for key, data_type in orig_types.items():
        moto_message.message_attributes[key]["data_type"] = data_type
    message_attr_hash = moto_message.attribute_md5

    return message_attr_hash


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


def encode_receipt_handle(queue_arn, message) -> str:
    # http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/ImportantIdentifiers.html#ImportantIdentifiers-receipt-handles
    # encode the queue arn in the receipt handle, so we can later check if it belongs to the queue
    # but also add some randomness s.t. the generated receipt handles look like the ones from AWS
    handle = f"{long_uid()} {queue_arn} {message.message.get('MessageId')} {message.last_received}"
    encoded = base64.b64encode(handle.encode("utf-8"))
    return encoded.decode("utf-8")


@singleton_factory
def global_message_sequence():
    # creates a 20-digit number used as the start for the global sequence
    start = int(time.time()) << 33
    # itertools.count is thread safe over the GIL since its getAndIncrement operation is a single python bytecode op
    return itertools.count(start)


def generate_message_id():
    return long_uid()
