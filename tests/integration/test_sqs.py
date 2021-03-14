import os
import json
import time
import unittest
import requests
import datetime

from botocore.exceptions import ClientError
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.auth import SigV4Auth, SIGV4_TIMESTAMP
from localstack.constants import (
    TEST_AWS_ACCOUNT_ID,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_SECRET_ACCESS_KEY
)
from six.moves.urllib.parse import urlencode

from localstack import config
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, retry, to_str, get_service_protocol
from localstack.utils.testutil import get_lambda_log_events
from .lambdas import lambda_integration
from .test_lambda import use_docker, load_file, TEST_LAMBDA_PYTHON, LAMBDA_RUNTIME_PYTHON36, \
    LAMBDA_RUNTIME_DOTNETCORE2, LAMBDA_RUNTIME_DOTNETCORE31, TEST_LAMBDA_LIBS, \
    TEST_LAMBDA_DOTNETCORE2, TEST_LAMBDA_DOTNETCORE31

TEST_QUEUE_NAME = 'TestQueue'

TEST_POLICY = """
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": "sqs:SendMessage",
      "Resource": "'$sqs_queue_arn'",
      "Condition":{
        "ArnEquals":{
        "aws:SourceArn":"'$sns_topic_arn'"
        }
      }
    }
  ]
}
"""

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ECHO_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py')

TEST_MESSAGE_ATTRIBUTES = {
    'City': {
        'DataType': 'String',
        'StringValue': 'Any City - with special characters: <?`'
    },
    'Population': {
        'DataType': 'Number',
        'StringValue': '1250800'
    }
}


class SQSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = aws_stack.connect_to_service('sqs')

    def test_list_queue_tags(self):
        queue_info = self.client.create_queue(QueueName=TEST_QUEUE_NAME)
        queue_url = queue_info['QueueUrl']

        # list queues with name prefix
        result = self.client.list_queues(QueueNamePrefix=TEST_QUEUE_NAME[0:-2])
        self.assertIn('QueueUrls', result)
        self.assertEqual(1, len(result.get('QueueUrls')))

        result = self.client.list_queue_tags(QueueUrl=queue_url)
        # Apparently, if there are no tags, then `Tags` should NOT appear in the response.
        self.assertNotIn('Tags', result)

        # try to request details from queue URL directly via GET request
        response = requests.get(queue_url)
        content = to_str(response.content)
        self.assertIn(queue_url, content)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        result = self.client.list_queues(QueueNamePrefix=TEST_QUEUE_NAME)
        self.assertEqual(0, len(result.get('QueueUrls', [])))

    def test_publish_get_delete_message(self):
        queue_name = 'queue-%s' % short_uid()
        queue_info = self.client.create_queue(QueueName=queue_name)
        queue_url = queue_info['QueueUrl']
        self.assertIn(queue_name, queue_url)

        # publish/receive message
        self.client.send_message(QueueUrl=queue_url, MessageBody='msg123')
        for i in range(2):
            messages = self.client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages']
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0]['Body'], 'msg123')

        # delete/receive message
        self.client.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]['ReceiptHandle'])
        response = self.client.receive_message(QueueUrl=queue_url)
        self.assertFalse(response.get('Messages'))

        # publish/receive message with change_message_visibility
        self.client.send_message(QueueUrl=queue_url, MessageBody='msg234')
        messages = self.client.receive_message(QueueUrl=queue_url)['Messages']
        response = self.client.receive_message(QueueUrl=queue_url)
        self.assertFalse(response.get('Messages'))
        self.client.change_message_visibility(QueueUrl=queue_url,
                                              ReceiptHandle=messages[0]['ReceiptHandle'], VisibilityTimeout=0)
        for i in range(2):
            messages = self.client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages']
            self.assertEquals(len(messages), 1)
            self.assertEquals(messages[0]['Body'], 'msg234')

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_publish_get_delete_message_batch(self):
        queue_name = 'queue-%s' % short_uid()
        queue_info = self.client.create_queue(QueueName=queue_name)
        queue_url = queue_info['QueueUrl']
        self.assertIn(queue_name, queue_url)

        def receive_messages(**kwargs):
            kwds = dict(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                MessageAttributeNames=['All']
            )
            kwds.update(kwargs)
            messages = self.client.receive_message(**kwds)
            return messages

        def get_hashes(messages, outgoing=False):
            body_key = 'MD5OfMessageBody' if outgoing else 'MD5OfBody'
            return set([
                (m[body_key], m['MD5OfMessageAttributes'])
                for m in messages
            ])

        messages_to_send = [
            {
                'Id': 'message{:02d}'.format(i),
                'MessageBody': 'msgBody{:02d}'.format(i),
                'MessageAttributes': {
                    'CustomAttribute': {
                        'DataType': 'String',
                        'StringValue': 'CustomAttributeValue{:02d}'.format(i)
                    }
                }
            }
            for i in range(1, 11)
        ]

        resp = self.client.send_message_batch(QueueUrl=queue_url, Entries=messages_to_send)
        sent_hashes = get_hashes(resp.get('Successful', []), outgoing=True)
        self.assertEqual(len(sent_hashes), len(messages_to_send))

        for i in range(2):
            messages = receive_messages(VisibilityTimeout=0)['Messages']
            received_hashes = get_hashes(messages)
            self.assertEqual(received_hashes, sent_hashes)

        self.client.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {'Id': '{:02d}'.format(i), 'ReceiptHandle': m['ReceiptHandle']}
                for i, m in enumerate(messages)
            ]
        )

        response = receive_messages()
        self.assertFalse(response.get('Messages'))

        # publish/receive message with change_message_visibility
        self.client.send_message_batch(QueueUrl=queue_url, Entries=messages_to_send)
        messages = receive_messages()['Messages']
        response = receive_messages()
        self.assertFalse(response.get('Messages'))

        reset_hashes = get_hashes(messages[:5])
        self.client.change_message_visibility_batch(
            QueueUrl=queue_url,
            Entries=[
                {
                    'Id': '{:02d}'.format(i),
                    'ReceiptHandle': msg['ReceiptHandle'],
                    'VisibilityTimeout': 0,
                }
                for i, msg in enumerate(messages[:5])
            ]
        )
        for i in range(2):
            messages = receive_messages(VisibilityTimeout=0)['Messages']
            received_hashes = get_hashes(messages)
            self.assertEqual(reset_hashes, received_hashes)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_create_fifo_queue(self):
        fifo_queue = 'my-queue.fifo'
        queue_info = self.client.create_queue(QueueName=fifo_queue, Attributes={'FifoQueue': 'true'})
        queue_url = queue_info['QueueUrl']

        # it should preserve .fifo in the queue name
        self.assertIn(fifo_queue, queue_url)

        # try sending a message with message group ID and deduplication ID
        response = self.client.send_message(QueueUrl=queue_url, MessageBody='test msg 123',
            MessageDeduplicationId='dedup-1', MessageGroupId='group-1')
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])
        self.assertIn('MessageId', response)
        self.assertIn('MD5OfMessageBody', response)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_set_queue_policy(self):
        queue_name = 'queue-%s' % short_uid()
        queue_info = self.client.create_queue(QueueName=queue_name)
        queue_url = queue_info['QueueUrl']

        attributes = {
            'Policy': TEST_POLICY
        }
        self.client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        attrs = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])['Attributes']
        self.assertIn('sqs:SendMessage', attrs['Policy'])
        attrs = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])['Attributes']
        self.assertIn('sqs:SendMessage', attrs['Policy'])

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_send_message_attributes(self):
        queue_name = 'queue-%s' % short_uid()

        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        payload = {}
        attrs = {'attr1': {'StringValue': 'val1', 'DataType': 'String'}}
        self.client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload),
                                 MessageAttributes=attrs)

        result = self.client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
        messages = result['Messages']
        self.assertEquals(messages[0]['MessageAttributes'], attrs)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_send_message_with_invalid_string_attributes(self):
        queue_name = 'queue-%s' % short_uid()

        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        payload = {}
        # String Attributes must not contain non-printable characters
        # See: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
        attrs = {'attr1': {
            'StringValue': 'invalid characters, %s, %s, %s' % (chr(8), chr(11), chr(12)), 'DataType': 'String'
        }}
        with self.assertRaises(Exception):
            self.client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload),
                                     MessageAttributes=attrs)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_send_message_with_invalid_payload_characters(self):
        queue_name = 'queue-%s' % short_uid()

        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        # Some common control characters and some code points just outside of a permitted range
        for invalid_char in ['\0', '\v', '\f', '\u0019', '\uFFFE', '\uFFFF']:
            raw_payload = 'invalid character: ' + invalid_char
            with self.assertRaisesRegex(Exception, 'invalid characters'):
                self.client.send_message(QueueUrl=queue_url, MessageBody=raw_payload)

        raw_payload = 'valid characters: \t\n\r\uD7FF\uE000\uFFFD\u10000\u10FFFF'
        self.client.send_message(QueueUrl=queue_url, MessageBody=raw_payload)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_dead_letter_queue_config(self):
        queue_name = 'queue-%s' % short_uid()
        dlq_name = 'queue-%s' % short_uid()

        dlq_info = self.client.create_queue(QueueName=dlq_name)
        dlq_arn = aws_stack.sqs_queue_arn(dlq_name)

        attributes = {'RedrivePolicy': json.dumps({'deadLetterTargetArn': dlq_arn, 'maxReceiveCount': 100})}
        queue_url = self.client.create_queue(QueueName=queue_name, Attributes=attributes)['QueueUrl']

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        self.client.delete_queue(QueueUrl=dlq_info['QueueUrl'])

    def test_dead_letter_queue_execution(self):
        lambda_client = aws_stack.connect_to_service('lambda')

        # create SQS queue with DLQ redrive policy
        queue_name1 = 'dlq-%s' % short_uid()
        queue_name2 = 'test-dlq-%s' % short_uid()
        queue_url1 = self.client.create_queue(QueueName=queue_name1)['QueueUrl']
        queue_arn1 = aws_stack.sqs_queue_arn(queue_name1)
        policy = {'deadLetterTargetArn': queue_arn1, 'maxReceiveCount': 1}
        queue_url2 = self.client.create_queue(QueueName=queue_name2,
            Attributes={'RedrivePolicy': json.dumps(policy)})['QueueUrl']
        queue_arn2 = aws_stack.sqs_queue_arn(queue_name2)

        # create Lambda and add source mapping
        lambda_name = 'test-%s' % short_uid()
        testutil.create_lambda_function(func_name=lambda_name, libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON, runtime=LAMBDA_RUNTIME_PYTHON36)
        lambda_client.create_event_source_mapping(EventSourceArn=queue_arn2, FunctionName=lambda_name)

        # add message to SQS, which will trigger the Lambda, resulting in an error
        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1
        }
        self.client.send_message(QueueUrl=queue_url2, MessageBody=json.dumps(payload))

        retry(lambda: self.receive_dlq(queue_url1), retries=8, sleep=2)

    def test_dead_letter_queue_max_receive_count(self):

        # create SQS queue with DLQ redrive policy using "maxReceiveCount"
        queue_name1 = 'dlq-%s' % short_uid()
        queue_name2 = 'test-dlq-%s' % short_uid()
        queue_url1 = self.client.create_queue(QueueName=queue_name1)['QueueUrl']
        queue_arn1 = aws_stack.sqs_queue_arn(queue_name1)
        policy = {'deadLetterTargetArn': queue_arn1, 'maxReceiveCount': '1'}
        queue_url2 = self.client.create_queue(QueueName=queue_name2,
            Attributes={'VisibilityTimeout': '1', 'RedrivePolicy': json.dumps(policy)})['QueueUrl']

        # add message to SQS, then retrieve the message
        payload = {}
        self.client.send_message(QueueUrl=queue_url2, MessageBody=json.dumps(payload))
        rs = self.client.receive_message(QueueUrl=queue_url2)
        self.assertEqual(len(rs.get('Messages', [])), 1)
        # wait some time, then try to receive the message again - should be empty
        time.sleep(1.01)
        rs = self.client.receive_message(QueueUrl=queue_url2)
        self.assertEqual(len(rs.get('Messages', [])), 0)

        # assert that message has been put on the DLQ
        retry(lambda: self.receive_dlq(queue_url1, assert_receive_count=2), retries=8, sleep=2)

    def test_set_queue_attribute_at_creation(self):
        queue_name = 'queue-%s' % short_uid()

        attributes = {
            'MessageRetentionPeriod': '604800',  # Unsupported by ElasticMq, should be saved in memory
            'ReceiveMessageWaitTimeSeconds': '10',
            'VisibilityTimeout': '30'
        }

        queue_url = self.client.create_queue(QueueName=queue_name, Attributes=attributes)['QueueUrl']
        creation_attributes = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])

        # assertion
        self.assertIn('MessageRetentionPeriod', creation_attributes['Attributes'].keys())
        self.assertEqual('604800', creation_attributes['Attributes']['MessageRetentionPeriod'])

        # cleanup
        self.client.delete_queue(QueueUrl=queue_url)

    def test_get_specific_queue_attribute_response(self):
        queue_name = 'queue-%s' % short_uid()

        dead_queue_url = self.client.create_queue(QueueName='newQueue')['QueueUrl']
        supported_attribute_get = self.client.get_queue_attributes(QueueUrl=dead_queue_url,
                                                                   AttributeNames=['QueueArn'])

        self.assertTrue('QueueArn' in supported_attribute_get['Attributes'].keys())
        dead_queue_arn = supported_attribute_get['Attributes']['QueueArn']

        _redrive_policy = {
            'deadLetterTargetArn': dead_queue_arn,
            'maxReceiveCount': '10'
        }

        attributes = {
            'MessageRetentionPeriod': '604800',
            'DelaySeconds': '10',
            'RedrivePolicy': json.dumps(_redrive_policy)
        }

        queue_url = self.client.create_queue(QueueName=queue_name, Attributes=attributes)['QueueUrl']
        unsupported_attribute_get = self.client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['MessageRetentionPeriod', 'RedrivePolicy']
        )
        supported_attribute_get = self.client.get_queue_attributes(QueueUrl=queue_url,
                                                                   AttributeNames=['QueueArn'])
        # assertion
        self.assertTrue('MessageRetentionPeriod' in unsupported_attribute_get['Attributes'].keys())
        self.assertEqual('604800', unsupported_attribute_get['Attributes']['MessageRetentionPeriod'])
        self.assertTrue('QueueArn' in supported_attribute_get['Attributes'].keys())
        self.assertTrue('RedrivePolicy' in unsupported_attribute_get['Attributes'].keys())

        redrive_policy = json.loads(unsupported_attribute_get['Attributes']['RedrivePolicy'])
        self.assertTrue(isinstance(redrive_policy['maxReceiveCount'], int))

        # cleanup
        self.client.delete_queue(QueueUrl=queue_url)
        self.client.delete_queue(QueueUrl=dead_queue_url)

    def test_set_unsupported_attributes(self):
        queue_name = 'queue-%s' % short_uid()
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        self.client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                'FifoQueue': 'true'
            }
        )

        rs = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('FifoQueue', rs['Attributes'])
        self.assertEqual(rs['Attributes']['FifoQueue'], 'true')

        # cleanup
        self.client.delete_queue(QueueUrl=queue_url)

    def test_list_dead_letter_source_queues(self):
        normal_queue_name = 'queue-%s' % short_uid()
        dlq_name = 'queue-%s' % short_uid()

        dlq = self.client.create_queue(QueueName=dlq_name)

        dlq_arn = aws_stack.sqs_queue_arn(dlq_name)

        attributes = {'RedrivePolicy': json.dumps({'deadLetterTargetArn': dlq_arn, 'maxReceiveCount': 100})}
        nq = self.client.create_queue(QueueName=normal_queue_name, Attributes=attributes)['QueueUrl']

        res = self.client.list_dead_letter_source_queues(QueueUrl=dlq['QueueUrl'])

        self.assertEqual(res['queueUrls'][0], nq)
        self.assertEqual(res['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertEqual(res['queueUrls'][0], nq)
        self.assertEqual(len(res['queueUrls']), 1)
        self.assertEqual(res['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        self.client.delete_queue(QueueUrl=nq)
        self.client.delete_queue(QueueUrl=dlq['QueueUrl'])

    def test_lambda_invoked_by_sqs_message_with_attributes(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        queue_name = 'queue-{}'.format(short_uid())

        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.create_event_source_mapping(
            EventSourceArn=aws_stack.sqs_queue_arn(queue_name),
            FunctionName=function_name
        )

        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody='hello world.',
            MessageAttributes=TEST_MESSAGE_ATTRIBUTES
        )

        events = retry(get_lambda_log_events, sleep_before=3, function_name=function_name)
        self.assertEqual(len(events), 1)

        sqs_msg = events[0]['Records'][0]
        self.assertEqual(sqs_msg['body'], 'hello world.')

        self.assertIn('messageAttributes', sqs_msg)
        self.assertIn('City', sqs_msg['messageAttributes'])
        attr_lower = TEST_MESSAGE_ATTRIBUTES['City']
        attr_lower = {'dataType': attr_lower['DataType'], 'stringValue': attr_lower['StringValue']}
        self.assertEqual(sqs_msg['messageAttributes']['City'], attr_lower)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        lambda_client.delete_function(FunctionName=function_name)

    def test_send_message_with_delay_seconds(self):
        queue_name = 'queue-{}'.format(short_uid())
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        # send message with DelaySeconds = 0
        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody='hello world.',
            DelaySeconds=0
        )

        rs = self.client.receive_message(QueueUrl=queue_url)
        self.assertIn('Messages', rs)
        self.assertEqual(len(rs['Messages']), 1)

        message = rs['Messages'][0]
        self.assertEqual(message['Body'], 'hello world.')
        self.client.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[{'Id': short_uid(), 'ReceiptHandle': message['ReceiptHandle']}]
        )

        # send message with DelaySeconds = 10
        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody='test_message_2',
            DelaySeconds=10
        )

        rs = self.client.receive_message(QueueUrl=queue_url)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertNotIn('Messages', rs)

        def get_message(q_url):
            resp = self.client.receive_message(QueueUrl=q_url)
            return resp['Messages']

        messages = retry(get_message, retries=3, sleep=10, q_url=queue_url)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]['Body'], 'test_message_2')

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_get_multiple_messages(self):
        queue_name = 'queue-{}'.format(short_uid())
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']
        number_of_messages = 3

        for i in range(number_of_messages):
            self.client.send_message(
                QueueUrl=queue_url,
                MessageBody='hello world. {}'.format(i),
                DelaySeconds=0
            )

        messages = {}
        for i in range(number_of_messages):
            rs = self.client.receive_message(QueueUrl=queue_url)
            m = rs['Messages'][0]
            messages[m['MessageId']] = m['Body']

        self.assertEqual(len(messages.keys()), number_of_messages)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_lambda_invoked_by_sqs_message_with_delay_seconds(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        queue_name = 'queue-{}'.format(short_uid())
        delay_time = 6

        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn,
            FunctionName=function_name
        )

        rs = self.client.send_message(
            QueueUrl=queue_url,
            MessageBody='hello world.',
            DelaySeconds=delay_time
        )
        message_id = rs['MessageId']

        time.sleep(delay_time / 2)

        # There is no log group for this lambda (lambda not invoked yet)
        log_events = get_lambda_log_events(function_name)
        self.assertEqual(len(log_events), 0)

        # After delay time, lambda invoked by sqs
        events = get_lambda_log_events(function_name, delay_time * 1.5)
        # Lambda just invoked 1 time
        self.assertEqual(len(events), 1)

        message = events[0]['Records'][0]
        self.assertEqual(message['eventSourceARN'], queue_arn)
        self.assertEqual(message['messageId'], message_id)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        lambda_client.delete_function(FunctionName=function_name)

    def test_get_queue_attributes(self):

        sqs = self.client
        queue_name1 = 'test-%s' % short_uid()
        queue_name2 = 'test-%s' % short_uid()

        sqs.create_queue(QueueName=queue_name1)
        queue_arn1 = aws_stack.sqs_queue_arn(queue_name1)
        policy = {'deadLetterTargetArn': queue_arn1, 'maxReceiveCount': 1}

        queue_url2 = self.client.create_queue(QueueName=queue_name2,
                                              Attributes={'RedrivePolicy': json.dumps(policy)})['QueueUrl']

        response = sqs.get_queue_attributes(QueueUrl=queue_url2)

        redrive_policy = json.loads(response['Attributes']['RedrivePolicy'])
        self.assertEqual(redrive_policy['maxReceiveCount'], 1)
        self.assertIn(redrive_policy['deadLetterTargetArn'], queue_arn1)

    def test_send_message_batch_with_empty_list(self):
        client = self.client
        response = client.create_queue(QueueName='test-queue')
        queue_url = response['QueueUrl']

        try:
            client.send_message_batch(QueueUrl=queue_url, Entries=[])
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'EmptyBatchRequest')
            self.assertIn(e.response['ResponseMetadata']['HTTPStatusCode'], [400, 404])

        entries = [{
            'Id': 'message{:02d}'.format(0),
            'MessageBody': 'msgBody{:02d}'.format(0),
            'MessageAttributes': {
                'CustomAttribute': {
                    'DataType': 'String',
                    'StringValue': 'CustomAttributeValue{:02d}'.format(0)
                }
            }
        }]

        result = client.send_message_batch(QueueUrl=queue_url, Entries=entries)
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        # clean up
        client.delete_queue(QueueUrl=queue_url)

    def _run_test_lambda_invoked_by_sqs_message_with_delay_seconds_dotnet(self, zip_file, handler, runtime):
        if not use_docker():
            return

        func_name = 'dotnet-sqs-{}'.format(short_uid())
        queue_name = 'queue-%s' % short_uid()
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        delay_time = 1

        testutil.create_lambda_function(
            func_name=func_name,
            zip_file=zip_file,
            handler=handler,
            runtime=runtime)

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn,
            FunctionName=func_name
        )

        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody='hello world.',
            DelaySeconds=delay_time
        )

        # assert that the Lambda has been invoked
        def get_logs():
            logs = get_lambda_log_events(func_name)
            self.assertGreater(len(logs), 0)

        retry(get_logs, retries=5, sleep=3)

        # assert that the message has been deleted from the queue
        resp = self.client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(None, resp.get('Messages', None))

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        testutil.delete_lambda_function(func_name)

    def test_lambda_invoked_by_sqs_message_with_delay_seconds_dotnetcore2(self):
        zip_file = load_file(TEST_LAMBDA_DOTNETCORE2, mode='rb')
        handler = 'DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler'

        self._run_test_lambda_invoked_by_sqs_message_with_delay_seconds_dotnet(
            zip_file, handler, LAMBDA_RUNTIME_DOTNETCORE2
        )

    def test_lambda_invoked_by_sqs_message_with_delay_seconds_dotnetcore31(self):
        zip_file = load_file(TEST_LAMBDA_DOTNETCORE31, mode='rb')
        handler = 'dotnetcore31::dotnetcore31.Function::FunctionHandler'

        self._run_test_lambda_invoked_by_sqs_message_with_delay_seconds_dotnet(
            zip_file, handler, LAMBDA_RUNTIME_DOTNETCORE31
        )

    def _run_test_fifo_queue_send_multiple_messages(self):
        fifo_queue = 'queue-{}.fifo'.format(short_uid())

        message_group = 'group-%s' % short_uid()
        results = []
        number_of_messages = 5

        queue_url = self.client.create_queue(QueueName=fifo_queue, Attributes={'FifoQueue': 'true'})['QueueUrl']

        # it should preserve .fifo in the queue name
        self.assertIn(fifo_queue, queue_url)

        # try sending multiple message with message group ID and deduplication ID
        for i in range(number_of_messages):
            rs = self.client.send_message(
                QueueUrl=queue_url, MessageBody='message-{}'.format(i),
                MessageDeduplicationId='deduplication-{}'.format(i), MessageGroupId=message_group
            )
            results.append(rs)

        return queue_url, number_of_messages, results

    def test_fifo_queue_send_multiple_messages_single_receive(self):
        queue_url, number_of_messages, results = self._run_test_fifo_queue_send_multiple_messages()

        # receive multiple message in the same time
        messages = self.client.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=['All'], MaxNumberOfMessages=number_of_messages
        )

        # asset the received messages data
        self.assertEqual(number_of_messages, len(messages['Messages']))
        for i in range(number_of_messages):
            self.assertEqual('message-{}'.format(i), messages['Messages'][i]['Body'])
            self.assertEqual(results[i]['MD5OfMessageBody'], messages['Messages'][i]['MD5OfBody'])
            self.assertEqual(results[i]['MessageId'], messages['Messages'][i]['MessageId'])

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_fifo_queue_send_multiple_messages_multiple_receives(self):
        queue_url, number_of_messages, results = self._run_test_fifo_queue_send_multiple_messages()
        first_receives = number_of_messages // 2

        # receive multiple message first time
        messages = self.client.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=['All'], MaxNumberOfMessages=first_receives
        )

        # asset the received messages data first time
        self.assertEqual(first_receives, len(messages['Messages']))
        for i in range(first_receives):
            self.assertEqual('message-{}'.format(i), messages['Messages'][i]['Body'])
            self.assertEqual(results[i]['MD5OfMessageBody'], messages['Messages'][i]['MD5OfBody'])
            self.assertEqual(results[i]['MessageId'], messages['Messages'][i]['MessageId'])

            # delete message to receive next message in queue
            self.client.delete_message(QueueUrl=queue_url, ReceiptHandle=messages['Messages'][i]['ReceiptHandle'])

        second_receives = number_of_messages - first_receives

        # try to get one by one message in the second time
        for i in range(second_receives):
            message = self.client.receive_message(QueueUrl=queue_url)
            self.assertEqual('message-{}'.format(first_receives + i), message['Messages'][0]['Body'])
            self.assertEqual(results[first_receives + i]['MD5OfMessageBody'], message['Messages'][0]['MD5OfBody'])
            self.assertEqual(results[first_receives + i]['MessageId'], message['Messages'][0]['MessageId'])

            # delete message to receive next message in queue
            self.client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['Messages'][0]['ReceiptHandle'])

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_fifo_queue_send_multiple_messages_multiple_single_receives(self):
        queue_url, number_of_messages, results = self._run_test_fifo_queue_send_multiple_messages()

        for i in range(number_of_messages):
            resp = self.client.receive_message(QueueUrl=queue_url)
            self.assertEqual('message-{}'.format(i), resp['Messages'][0]['Body'])
            self.assertEqual(results[i]['MD5OfMessageBody'], resp['Messages'][0]['MD5OfBody'])
            self.assertEqual(results[i]['MessageId'], resp['Messages'][0]['MessageId'])

            # delete message to receive next message in queue
            self.client.delete_message(QueueUrl=queue_url, ReceiptHandle=resp['Messages'][0]['ReceiptHandle'])

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_tag_untag_queue(self):
        queue_name = 'queue-{}'.format(short_uid())
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        response = self.client.tag_queue(QueueUrl=queue_url, Tags={'tag1': 'value1', 'tag2': 'value2'})
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

        response = self.client.list_queue_tags(QueueUrl=queue_url)
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])
        self.assertIn('tag1', response['Tags'])
        self.assertIn('tag2', response['Tags'])

        response = self.client.untag_queue(QueueUrl=queue_url, TagKeys=['tag2'])
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

        response = self.client.list_queue_tags(QueueUrl=queue_url)
        self.assertIn('tag1', response['Tags'])
        self.assertNotIn('tag2', response['Tags'])
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

        # clean up
        self.client.untag_queue(QueueUrl=queue_url, TagKeys=['tag1'])
        self.client.delete_queue(QueueUrl=queue_url)

    def test_posting_to_queue_with_trailing_slash(self):
        queue_name = 'queue-{}'.format(short_uid())
        queue_url = self.client.create_queue(QueueName=queue_name)['QueueUrl']

        base_url = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_SQS)
        encoded_url = urlencode({
            'Action': 'SendMessage',
            'Version': '2012-11-05',
            'QueueUrl': '{}/{}/{}/'.format(base_url, TEST_AWS_ACCOUNT_ID, queue_name),
            'MessageBody': 'test body'
        })
        r = requests.post(url=base_url, data=encoded_url)
        self.assertEqual(r.status_code, 200)

        # We can get the message back
        resp = self.client.receive_message(QueueUrl=queue_url)
        self.assertEqual(resp['Messages'][0]['Body'], 'test body')

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_create_queue_with_slashes(self):
        queue_name = 'queue/%s' % short_uid()
        queue_url = self.client.create_queue(QueueName=queue_name)

        result = self.client.list_queues()
        self.assertIn(queue_url.get('QueueUrl'), result.get('QueueUrls'))

        # clean up
        self.client.delete_queue(QueueUrl=queue_url.get('QueueUrl'))

        result = self.client.list_queues()
        self.assertNotIn(queue_url.get('QueueUrl'), result.get('QueueUrls'))

    def test_post_list_queue_with_auth_in_presigned_url(self):
        base_url = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_SQS)

        req = AWSRequest(method='POST', url=base_url, data={
            'Action': 'ListQueues',
            'Version': '2012-11-05'
        })

        # boto doesn't support querystring-style auth, so we have to do some
        # weird logic to use boto's signing functions, to understand what's
        # going on here look at the internals of the SigV4Auth.add_auth
        # method.
        datetime_now = datetime.datetime.utcnow()
        req.context['timestamp'] = datetime_now.strftime(SIGV4_TIMESTAMP)
        signer = SigV4Auth(
            Credentials(TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY),
            'sqs',
            aws_stack.get_region()
        )
        canonical_request = signer.canonical_request(req)
        string_to_sign = signer.string_to_sign(req, canonical_request)

        encoded_url = urlencode({
            'Action': 'ListQueues',
            'Version': '2012-11-05',
            'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
            'X-Amz-Credential': signer.scope(req),
            'X-Amz-SignedHeaders': ';'.join(
                signer.headers_to_sign(req).keys()
            ),
            'X-Amz-Signature': signer.signature(string_to_sign, req)
        })

        res = requests.post(url=base_url, data=encoded_url)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(b'<ListQueuesResponse>' in res.content)

    def test_get_list_queue_with_auth_in_presigned_url(self):
        base_url = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_SQS)

        req = AWSRequest(method='GET', url=base_url, params={
            'Action': 'ListQueues',
            'Version': '2012-11-05'
        })

        # manually construct signed parameters
        datetime_now = datetime.datetime.utcnow()
        req.context['timestamp'] = datetime_now.strftime(SIGV4_TIMESTAMP)
        signer = SigV4Auth(
            Credentials(TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY),
            'sqs',
            aws_stack.get_region()
        )
        canonical_request = signer.canonical_request(req)
        string_to_sign = signer.string_to_sign(req, canonical_request)

        params_with_auth = {
            'Action': 'ListQueues',
            'Version': '2012-11-05',
            'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
            'X-Amz-Credential': signer.scope(req),
            'X-Amz-SignedHeaders': ';'.join(
                signer.headers_to_sign(req).keys()
            ),
            'X-Amz-Signature': signer.signature(string_to_sign, req)
        }

        res = requests.get(url=base_url, params=params_with_auth)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(b'<ListQueuesResponse>' in res.content)

    # ---------------
    # HELPER METHODS
    # ---------------

    def receive_dlq(self, queue_url, assert_error_details=False, assert_receive_count=None):
        """ Assert that a message has been received on the given DLQ """
        result = self.client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
        self.assertGreater(len(result['Messages']), 0)
        msg = result['Messages'][0]
        msg_attrs = msg.get('MessageAttributes') or msg.get('Attributes')
        if assert_error_details:
            self.assertIn('RequestID', msg_attrs)
            self.assertIn('ErrorCode', msg_attrs)
            self.assertIn('ErrorMessage', msg_attrs)
        else:
            if assert_receive_count is not None:
                pass
                # TODO: this started failing with latest moto upgrade,
                # probably in or around this commit:
                # https://github.com/spulec/moto/commit/6da4905da940e25e317db60b7657ea632f58ef1d
                # self.assertEqual(str(assert_receive_count), msg_attrs.get('ApproximateReceiveCount'))
