import pytest

import localstack.services.sqs.exceptions
import localstack.services.sqs.models
from localstack.aws.api.sqs import Message
from localstack.services.sqs import provider
from localstack.services.sqs.constants import DEFAULT_MAXIMUM_MESSAGE_SIZE
from localstack.services.sqs.utils import get_message_attributes_md5
from localstack.utils.common import convert_to_printable_chars


def test_sqs_message_attrs_md5():
    msg_attrs = {
        "MessageAttribute.1.Name": "timestamp",
        "MessageAttribute.1.Value.StringValue": "1493147359900",
        "MessageAttribute.1.Value.DataType": "Number",
    }
    md5 = get_message_attributes_md5(msg_attrs)
    assert md5 == "235c5c510d26fb653d073faed50ae77c"


def test_convert_non_printable_chars():
    string = "invalid characters - %s %s %s" % (chr(8), chr(11), chr(12))
    result = convert_to_printable_chars(string)
    assert result == "invalid characters -   "
    result = convert_to_printable_chars({"foo": [string]})
    assert result == {"foo": ["invalid characters -   "]}

    string = "valid characters - %s %s %s %s" % (chr(9), chr(10), chr(13), chr(32))
    result = convert_to_printable_chars(string)
    assert result == string


def test_compare_sqs_message_attrs_md5():
    msg_attrs_listener = {
        "MessageAttribute.1.Name": "timestamp",
        "MessageAttribute.1.Value.StringValue": "1493147359900",
        "MessageAttribute.1.Value.DataType": "Number",
    }
    md5_listener = get_message_attributes_md5(msg_attrs_listener)
    msg_attrs_provider = {"timestamp": {"StringValue": "1493147359900", "DataType": "Number"}}
    md5_provider = provider._create_message_attribute_hash(msg_attrs_provider)
    assert md5_provider == md5_listener


def test_handle_string_max_receive_count_in_dead_letter_check():
    # fmt: off
    policy = {"RedrivePolicy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:DeadLetterQueue\",\"maxReceiveCount\": \"5\" }"}
    # fmt: on
    queue = localstack.services.sqs.models.SqsQueue("TestQueue", "us-east-1", "123456789", policy)
    sqs_message = localstack.services.sqs.models.SqsMessage(Message(), {})
    result = provider.SqsProvider()._dead_letter_check(queue, sqs_message, None)
    assert result is False


def test_except_check_message_size():
    message_body = "".join(("a" for _ in range(DEFAULT_MAXIMUM_MESSAGE_SIZE + 1)))
    with pytest.raises(localstack.services.sqs.exceptions.InvalidParameterValue):
        provider.check_message_size(message_body, DEFAULT_MAXIMUM_MESSAGE_SIZE)


def test_check_message_size():
    message_body = "a"
    provider.check_message_size(message_body, DEFAULT_MAXIMUM_MESSAGE_SIZE)
