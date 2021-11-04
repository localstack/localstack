import os

import pytest
from localstack.utils.common import short_uid

#os.environ['TEST_TARGET'] = 'AWS_CLOUD'


def test_invalid_receipt_handle_should_return_error_message_issue_3619(sqs_client, sqs_create_queue):
    queue_name = "queue_3619_"+short_uid()
    queue_url = sqs_create_queue(QueueName=queue_name)
    with pytest.raises(Exception) as e:
        sqs_client.change_message_visibility(QueueUrl=queue_url, ReceiptHandle="INVALID", VisibilityTimeout=60)
    e.match('(invalid|not a valid)')  # returned messages are slightly different but both exist


def test_message_with_attributes_should_be_enqueued_issue_3737(sqs_client, sqs_create_queue):
    queue_name = "queue_3737_"+short_uid()
    queue_url = sqs_create_queue(QueueName=queue_name)
    assert queue_url.endswith(queue_name)

    message_body = "test"
    timestamp_attribute = {'DataType': 'Number', 'StringValue': '1614717034367'}
    message_attributes = {'timestamp': timestamp_attribute}
    response_send = \
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_body, MessageAttributes=message_attributes)
    response_receive = sqs_client.receive_message(QueueUrl=queue_url)
    assert response_receive['Messages'][0]['MessageId'] == response_send['MessageId']


def test_batch_send_with_invalid_char_should_succeed_issue_4135(sqs_client, sqs_create_queue):
    queue_name = "queue_4135_" + short_uid()
    queue_url = sqs_create_queue(QueueName=queue_name)

    batch = []
    for i in range(0, 8):
        batch.append({'Id': str(i), 'MessageBody': str(i)})
    batch.append({'Id': '9', 'MessageBody': "\x01"})
    result_send = sqs_client.send_message_batch(QueueUrl=queue_url, Entries=batch)
    assert len(result_send['Failed']) == 1

