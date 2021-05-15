# -*- coding: utf-8 -*-

import json
import os
import requests
import time
import unittest
from botocore.exceptions import ClientError
from localstack import config
from localstack.utils import testutil
from localstack.config import external_service_url
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    to_str, get_free_tcp_port, retry, wait_for_port_open, get_service_protocol, short_uid
)
from localstack.utils.testutil import check_expected_lambda_log_events_length
from localstack.services.infra import start_proxy
from localstack.services.generic_proxy import ProxyListener
from localstack.services.sns.sns_listener import SNSBackend
from .lambdas import lambda_integration
from .test_lambda import TEST_LAMBDA_PYTHON, LAMBDA_RUNTIME_PYTHON36, TEST_LAMBDA_LIBS
from localstack.services.install import SQS_BACKEND_IMPL

TEST_TOPIC_NAME = 'TestTopic_snsTest'
TEST_QUEUE_NAME = 'TestQueue_snsTest'
TEST_QUEUE_DLQ_NAME = 'TestQueue_DLQ_snsTest'
TEST_TOPIC_NAME_2 = 'topic-test-2'

PUBLICATION_TIMEOUT = .500
PUBLICATION_RETRIES = 4

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ECHO_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py')


class SNSTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sqs_client = aws_stack.connect_to_service('sqs')
        cls.sns_client = aws_stack.connect_to_service('sns')
        cls.topic_arn = cls.sns_client.create_topic(Name=TEST_TOPIC_NAME)['TopicArn']
        cls.queue_url = cls.sqs_client.create_queue(QueueName=TEST_QUEUE_NAME)['QueueUrl']
        cls.dlq_url = cls.sqs_client.create_queue(QueueName=TEST_QUEUE_DLQ_NAME)['QueueUrl']

    @classmethod
    def tearDownClass(cls):
        cls.sqs_client.delete_queue(QueueUrl=cls.queue_url)
        cls.sqs_client.delete_queue(QueueUrl=cls.dlq_url)
        cls.sns_client.delete_topic(TopicArn=cls.topic_arn)

    def test_publish_unicode_chars(self):
        # connect an SNS topic to a new SQS queue
        _, queue_arn, queue_url = self._create_queue()
        self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol='sqs', Endpoint=queue_arn)

        # publish message to SNS, receive it from SQS, assert that messages are equal
        message = u'ö§a1"_!?,. £$-'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message)

        def check_message():
            msgs = self.sqs_client.receive_message(QueueUrl=queue_url)
            msg_received = msgs['Messages'][0]
            msg_received = json.loads(to_str(msg_received['Body']))
            msg_received = msg_received['Message']
            self.assertEqual(message, msg_received)
        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_subscribe_http_endpoint(self):
        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        wait_for_port_open(local_port)
        queue_arn = '%s://localhost:%s' % (get_service_protocol(), local_port)
        self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol='http', Endpoint=queue_arn)

        def received():
            self.assertEqual(records[0][0]['Type'], 'SubscriptionConfirmation')
            self.assertEqual(records[0][1]['x-amz-sns-message-type'], 'SubscriptionConfirmation')

            token = records[0][0]['Token']
            subscribe_url = records[0][0]['SubscribeURL']

            self.assertEqual(subscribe_url, '%s/?Action=ConfirmSubscription&TopicArn=%s&Token=%s' % (
                external_service_url('sns'), self.topic_arn, token))

            self.assertIn('Signature', records[0][0])
            self.assertIn('SigningCertURL', records[0][0])

        retry(received, retries=5, sleep=1)
        proxy.stop()

    def test_attribute_raw_subscribe(self):
        # create SNS topic and connect it to an SQS queue
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME)
        self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol='sqs',
            Endpoint=queue_arn,
            Attributes={'RawMessageDelivery': 'true'}
        )

        # fetch subscription information
        subscription_list = self.sns_client.list_subscriptions()

        subscription_arn = ''
        for subscription in subscription_list['Subscriptions']:
            if subscription['TopicArn'] == self.topic_arn:
                subscription_arn = subscription['SubscriptionArn']
        actual_attributes = self.sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn)['Attributes']

        # assert the attributes are well set
        self.assertTrue(actual_attributes['RawMessageDelivery'])

        # publish message to SNS, receive it from SQS, assert that messages are equal and that they are Raw
        message = u'This is a test message'
        binary_attribute = b'\x02\x03\x04'
        # extending this test case to test support for binary message attribute data
        # https://github.com/localstack/localstack/issues/2432
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'store': {'DataType': 'Binary', 'BinaryValue': binary_attribute}})

        def check_message():
            msgs = self.sqs_client.receive_message(QueueUrl=self.queue_url, MessageAttributeNames=['All'])
            msg_received = msgs['Messages'][0]

            self.assertEqual(message, msg_received['Body'])
            self.assertEqual(binary_attribute, msg_received['MessageAttributes']['store']['BinaryValue'])

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_filter_policy(self):
        # connect SNS topic to an SQS queue
        queue_name, queue_arn, queue_url = self._create_queue()

        filter_policy = {'attr1': [{'numeric': ['>', 0, '<=', 100]}]}
        self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol='sqs',
            Endpoint=queue_arn,
            Attributes={
                'FilterPolicy': json.dumps(filter_policy)
            }
        )

        # get number of messages
        num_msgs_0 = len(self.sqs_client.receive_message(QueueUrl=queue_url).get('Messages', []))

        # publish message that satisfies the filter policy, assert that message is received
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
            MessageAttributes={'attr1': {'DataType': 'Number', 'StringValue': '99'}})

        def check_message():
            num_msgs_1 = len(self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages'])
            self.assertEqual(num_msgs_1, num_msgs_0 + 1)
            return num_msgs_1
        num_msgs_1 = retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
            MessageAttributes={'attr1': {'DataType': 'Number', 'StringValue': '111'}})

        def check_message2():
            num_msgs_2 = len(self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages'])
            self.assertEqual(num_msgs_2, num_msgs_1)
            return num_msgs_2
        retry(check_message2, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_exists_filter_policy(self):
        # connect SNS topic to an SQS queue
        queue_name, queue_arn, queue_url = self._create_queue()
        filter_policy = {'store': [{'exists': True}]}

        def do_subscribe(self, filter_policy, queue_arn):
            self.sns_client.subscribe(
                TopicArn=self.topic_arn,
                Protocol='sqs',
                Endpoint=queue_arn,
                Attributes={
                    'FilterPolicy': json.dumps(filter_policy)
                }
            )
        do_subscribe(self, filter_policy, queue_arn)

        # get number of messages
        num_msgs_0 = len(self.sqs_client.receive_message(QueueUrl=queue_url).get('Messages', []))

        # publish message that satisfies the filter policy, assert that message is received
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'store': {'DataType': 'Number', 'StringValue': '99'},
                                                   'def': {'DataType': 'Number', 'StringValue': '99'}})

        def check_message1():
            num_msgs_1 = len(self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages'])
            self.assertEqual(num_msgs_1, num_msgs_0 + 1)
            return num_msgs_1
        num_msgs_1 = retry(check_message1, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'attr1': {'DataType': 'Number', 'StringValue': '111'}})

        def check_message2():
            num_msgs_2 = len(self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages'])
            self.assertEqual(num_msgs_2, num_msgs_1)
            return num_msgs_2
        retry(check_message2, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # test with exist operator set to false.
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME)
        filter_policy = {'store': [{'exists': False}]}
        do_subscribe(self, filter_policy, queue_arn)
        # get number of messages
        num_msgs_0 = len(self.sqs_client.receive_message(QueueUrl=self.queue_url).get('Messages', []))

        # publish message with the attribute and see if its getting filtered.
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'store': {'DataType': 'Number', 'StringValue': '99'},
                                                   'def': {'DataType': 'Number', 'StringValue': '99'}})

        def check_message():
            num_msgs_1 = len(self.sqs_client.receive_message(QueueUrl=self.queue_url,
                                                         VisibilityTimeout=0).get('Messages', []))
            self.assertEqual(num_msgs_1, num_msgs_0)
            return num_msgs_1

        num_msgs_1 = retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that without the attribute and see if its getting filtered.
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'attr1': {'DataType': 'Number', 'StringValue': '111'}})

        def check_message3():
            num_msgs_2 = len(self.sqs_client.receive_message(QueueUrl=self.queue_url,
                                                             VisibilityTimeout=0).get('Messages', []))
            self.assertEqual(num_msgs_2, num_msgs_1)
            return num_msgs_2

        retry(check_message3, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_subscribe_sqs_queue(self):
        _, queue_arn, queue_url = self._create_queue()

        # publish message
        subscription = self._publish_sns_message_with_attrs(queue_arn, 'sqs')

        # assert that message is received
        def check_message():
            messages = self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages']
            self.assertEqual(json.loads(messages[0]['Body'])['MessageAttributes']['attr1']['Value'], '99.12')
        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self.sns_client.unsubscribe(SubscriptionArn=subscription['SubscriptionArn'])

    def test_subscribe_platform_endpoint(self):
        sns = self.sns_client
        sns_backend = SNSBackend.get()
        app_arn = sns.create_platform_application(Name='app1', Platform='p1', Attributes={})['PlatformApplicationArn']
        platform_arn = sns.create_platform_endpoint(PlatformApplicationArn=app_arn, Token='token_1')['EndpointArn']
        subscription = self._publish_sns_message_with_attrs(platform_arn, 'application')

        # assert that message has been received
        def check_message():
            self.assertGreater(len(sns_backend.platform_endpoint_messages[platform_arn]), 0)
        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        sns.unsubscribe(SubscriptionArn=subscription['SubscriptionArn'])
        sns.delete_endpoint(EndpointArn=platform_arn)
        sns.delete_platform_application(PlatformApplicationArn=app_arn)

    def _publish_sns_message_with_attrs(self, endpoint_arn, protocol):
        # create subscription with filter policy
        filter_policy = {'attr1': [{'numeric': ['>', 0, '<=', 100]}]}
        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol=protocol,
            Endpoint=endpoint_arn,
            Attributes={
                'FilterPolicy': json.dumps(filter_policy)
            }
        )
        # publish message that satisfies the filter policy
        message = u'This is a test message'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message,
                                MessageAttributes={'attr1': {'DataType': 'Number', 'StringValue': '99.12'}})
        time.sleep(PUBLICATION_TIMEOUT)
        return subscription

    def test_unknown_topic_publish(self):
        fake_arn = 'arn:aws:sns:us-east-1:123456789012:i_dont_exist'
        message = u'This is a test message'
        try:
            self.sns_client.publish(TopicArn=fake_arn, Message=message)
            self.fail('This call should not be successful as the topic does not exist')
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NotFound')
            self.assertEqual(e.response['Error']['Message'], 'Topic does not exist')
            self.assertEqual(e.response['ResponseMetadata']['HTTPStatusCode'], 404)

    def test_publish_sms(self):
        response = self.sns_client.publish(PhoneNumber='+33000000000', Message='This is a SMS')
        self.assertTrue('MessageId' in response)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_publish_target(self):
        response = self.sns_client.publish(
            TargetArn='arn:aws:sns:us-east-1:000000000000:endpoint/APNS/abcdef/0f7d5971-aa8b-4bd5-b585-0826e9f93a66',
            Message='This is a push notification')
        self.assertTrue('MessageId' in response)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_tags(self):
        self.sns_client.tag_resource(
            ResourceArn=self.topic_arn,
            Tags=[
                {
                    'Key': '123',
                    'Value': 'abc'
                },
                {
                    'Key': '456',
                    'Value': 'def'
                },
                {
                    'Key': '456',
                    'Value': 'def'
                }
            ]
        )

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        distinct_tags = [tag for idx, tag in enumerate(tags['Tags']) if tag not in tags['Tags'][:idx]]
        # test for duplicate tags
        self.assertEqual(len(tags['Tags']), len(distinct_tags))
        self.assertEqual(len(tags['Tags']), 2)
        self.assertEqual(tags['Tags'][0]['Key'], '123')
        self.assertEqual(tags['Tags'][0]['Value'], 'abc')
        self.assertEqual(tags['Tags'][1]['Key'], '456')
        self.assertEqual(tags['Tags'][1]['Value'], 'def')

        self.sns_client.untag_resource(
            ResourceArn=self.topic_arn,
            TagKeys=['123']
        )

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        self.assertEqual(len(tags['Tags']), 1)
        self.assertEqual(tags['Tags'][0]['Key'], '456')
        self.assertEqual(tags['Tags'][0]['Value'], 'def')

        self.sns_client.tag_resource(
            ResourceArn=self.topic_arn,
            Tags=[
                {
                    'Key': '456',
                    'Value': 'pqr'
                }
            ]
        )

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        self.assertEqual(len(tags['Tags']), 1)
        self.assertEqual(tags['Tags'][0]['Key'], '456')
        self.assertEqual(tags['Tags'][0]['Value'], 'pqr')

    def test_topic_subscription(self):
        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol='email',
            Endpoint='localstack@yopmail.com'
        )
        sns_backend = SNSBackend.get()

        def check_subscription():
            subscription_arn = subscription['SubscriptionArn']
            subscription_obj = sns_backend.subscription_status[subscription_arn]
            self.assertEqual(subscription_obj['Status'], 'Not Subscribed')

            _token = subscription_obj['Token']
            self.sns_client.confirm_subscription(
                TopicArn=self.topic_arn,
                Token=_token
            )
            self.assertEqual(subscription_obj['Status'], 'Subscribed')
        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_dead_letter_queue(self):
        lambda_name = 'test-%s' % short_uid()
        lambda_arn = aws_stack.lambda_function_arn(lambda_name)
        topic_name = 'test-%s' % short_uid()
        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']
        queue_name = 'test-%s' % short_uid()
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        testutil.create_lambda_function(func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON, libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36, DeadLetterConfig={'TargetArn': queue_arn})
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='lambda', Endpoint=lambda_arn)

        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }
        self.sns_client.publish(TopicArn=topic_arn, Message=json.dumps(payload))

        def receive_dlq():
            result = self.sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
            msg_attrs = result['Messages'][0]['MessageAttributes']
            self.assertGreater(len(result['Messages']), 0)
            self.assertIn('RequestID', msg_attrs)
            self.assertIn('ErrorCode', msg_attrs)
            self.assertIn('ErrorMessage', msg_attrs)
        retry(receive_dlq, retries=8, sleep=2)

    def unsubscribe_all_from_sns(self):
        for subscription_arn in self.sns_client.list_subscriptions()['Subscriptions']:
            self.sns_client.unsubscribe(SubscriptionArn=subscription_arn['SubscriptionArn'])

    def test_redrive_policy_http_subscription(self):
        self.unsubscribe_all_from_sns()

        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        wait_for_port_open(local_port)
        http_endpoint = '%s://localhost:%s' % (get_service_protocol(), local_port)

        subscription = self.sns_client.subscribe(TopicArn=self.topic_arn,
            Protocol='http', Endpoint=http_endpoint)
        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription['SubscriptionArn'],
            AttributeName='RedrivePolicy',
            AttributeValue=json.dumps({'deadLetterTargetArn': aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)})
        )

        proxy.stop()
        # for some reason, it takes a long time to stop the proxy thread -> TODO investigate
        time.sleep(5)

        self.sns_client.publish(TopicArn=self.topic_arn, Message=json.dumps({'message': 'test_redrive_policy'}))

        def receive_dlq():
            result = self.sqs_client.receive_message(QueueUrl=self.dlq_url, MessageAttributeNames=['All'])
            self.assertGreater(len(result['Messages']), 0)
            self.assertEqual(
                json.loads(json.loads(result['Messages'][0]['Body'])['Message'][0])['message'],
                'test_redrive_policy'
            )
        retry(receive_dlq, retries=7, sleep=2.5)

    def test_redrive_policy_lambda_subscription(self):
        self.unsubscribe_all_from_sns()

        lambda_name = 'test-%s' % short_uid()
        lambda_arn = aws_stack.lambda_function_arn(lambda_name)

        testutil.create_lambda_function(func_name=lambda_name, libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON, runtime=LAMBDA_RUNTIME_PYTHON36)

        subscription = self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol='lambda', Endpoint=lambda_arn)

        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription['SubscriptionArn'],
            AttributeName='RedrivePolicy',
            AttributeValue=json.dumps({'deadLetterTargetArn': aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)})
        )
        testutil.delete_lambda_function(lambda_name)

        self.sns_client.publish(TopicArn=self.topic_arn, Message=json.dumps({'message': 'test_redrive_policy'}))

        def receive_dlq():
            result = self.sqs_client.receive_message(QueueUrl=self.dlq_url, MessageAttributeNames=['All'])
            self.assertGreater(len(result['Messages']), 0)
            self.assertEqual(
                json.loads(json.loads(result['Messages'][0]['Body'])['Message'][0])['message'],
                'test_redrive_policy'
            )

        retry(receive_dlq, retries=10, sleep=2)

    def test_redrive_policy_queue_subscription(self):
        self.unsubscribe_all_from_sns()

        topic_arn = self.sns_client.create_topic(Name='topic-%s' % short_uid())['TopicArn']
        invalid_queue_arn = aws_stack.sqs_queue_arn('invalid_queue')
        # subscribe with an invalid queue ARN, to trigger event on DLQ below
        subscription = self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=invalid_queue_arn)

        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription['SubscriptionArn'],
            AttributeName='RedrivePolicy',
            AttributeValue=json.dumps({'deadLetterTargetArn': aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)})
        )

        self.sns_client.publish(TopicArn=topic_arn, Message=json.dumps({'message': 'test_redrive_policy'}))

        def receive_dlq():
            result = self.sqs_client.receive_message(QueueUrl=self.dlq_url, MessageAttributeNames=['All'])
            self.assertGreater(len(result['Messages']), 0)
            self.assertEqual(
                json.loads(json.loads(result['Messages'][0]['Body'])['Message'][0])['message'],
                'test_redrive_policy'
            )

        retry(receive_dlq, retries=10, sleep=2)

    def test_publish_with_empty_subject(self):
        topic_arn = self.sns_client.create_topic(Name=TEST_TOPIC_NAME_2)['TopicArn']

        # Publish without subject
        rs = self.sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps({'message': 'test_publish'})
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        try:
            # Publish with empty subject
            self.sns_client.publish(
                TopicArn=topic_arn,
                Subject='',
                Message=json.dumps({'message': 'test_publish'})
            )
            self.fail('This call should not be successful as the subject is empty')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidParameter')

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)

    def test_create_topic_test_arn(self):
        response = self.sns_client.create_topic(Name=TEST_TOPIC_NAME)
        topic_arn_params = response['TopicArn'].split(':')
        self.assertEqual(topic_arn_params[4], TEST_AWS_ACCOUNT_ID)
        self.assertEqual(topic_arn_params[5], TEST_TOPIC_NAME)

    def test_publish_message_by_target_arn(self):
        self.unsubscribe_all_from_sns()

        topic_name = 'queue-{}'.format(short_uid())
        func_name = 'lambda-%s' % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=func_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )
        lambda_arn = aws_stack.lambda_function_arn(func_name)

        subscription_arn = self.sns_client.subscribe(
            TopicArn=topic_arn, Protocol='lambda', Endpoint=lambda_arn
        )['SubscriptionArn']

        self.sns_client.publish(
            TopicArn=topic_arn,
            Message='test_message_1',
            Subject='test subject'
        )

        # Lambda invoked 1 time
        events = retry(check_expected_lambda_log_events_length, retries=3,
                       sleep=1, function_name=func_name, expected_length=1)

        message = events[0]['Records'][0]
        self.assertEqual(message['EventSubscriptionArn'], subscription_arn)

        self.sns_client.publish(
            TargetArn=topic_arn,
            Message='test_message_2',
            Subject='test subject'
        )

        events = retry(check_expected_lambda_log_events_length, retries=3,
                       sleep=1, function_name=func_name, expected_length=2)
        # Lambda invoked 1 more time
        self.assertEqual(len(events), 2)

        for event in events:
            message = event['Records'][0]
            self.assertEqual(message['EventSubscriptionArn'], subscription_arn)

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.delete_function(FunctionName=func_name)

    def test_publish_message_after_subscribe_topic(self):
        self.unsubscribe_all_from_sns()

        topic_name = 'queue-{}'.format(short_uid())
        queue_name = 'test-%s' % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        rs = self.sns_client.publish(
            TopicArn=topic_arn,
            Subject='test subject',
            Message='test_message_1'
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_arn)

        message_subject = 'sqs subject'
        message_body = 'test_message_2'

        rs = self.sns_client.publish(
            TopicArn=topic_arn,
            Subject=message_subject,
            Message=message_body
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        message_id = rs['MessageId']

        def get_message(q_url):
            resp = self.sqs_client.receive_message(QueueUrl=q_url)
            return json.loads(resp['Messages'][0]['Body'])

        message = retry(get_message, retries=3, sleep=2, q_url=queue_url)
        self.assertEqual(message['MessageId'], message_id)
        self.assertEqual(message['Subject'], message_subject)
        self.assertEqual(message['Message'], message_body)

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_create_duplicate_topic_with_different_tags(self):
        topic_name = 'test-%s' % short_uid()
        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']

        with self.assertRaises(ClientError) as ctx:
            self.sns_client.create_topic(Name=topic_name, Tags=[{'Key': '456', 'Value': 'pqr'}])
            self.fail('This call should not be successful as the topic already exists with different tags')

        e = ctx.exception
        self.assertEqual(e.response['Error']['Code'], 'InvalidParameter')
        self.assertEqual(e.response['Error']['Message'], 'Topic already exists with different tags')
        self.assertEqual(e.response['ResponseMetadata']['HTTPStatusCode'], 400)

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)

    def test_create_duplicate_topic_check_idempotentness(self):
        topic_name = 'test-%s' % short_uid()
        tags = [{'Key': 'a', 'Value': '1'}, {'Key': 'b', 'Value': '2'}]
        kwargs = [{'Tags': tags},  # to create topic with two tags
            {'Tags': tags},  # to create the same topic again with same tags
            {'Tags': [tags[0]]},  # to create the same topic again with one of the tags from above
            {'Tags': []}  # to create the same topic again with no tags
        ]
        responses = []
        for arg in kwargs:
            responses.append(self.sns_client.create_topic(Name=topic_name, **arg))
        # assert TopicArn is returned by all the above create_topic calls
        for i in range(len(responses)):
            self.assertIn('TopicArn', responses[i])
        # clean up
        self.sns_client.delete_topic(TopicArn=responses[0]['TopicArn'])

    def test_create_platform_endpoint_check_idempotentness(self):
        response = self.sns_client.create_platform_application(
            Name='test-%s' % short_uid(), Platform='GCM', Attributes={'PlatformCredential': '123'}
        )
        kwargs_list = [{'Token': 'test1', 'CustomUserData': 'test-data'},
            {'Token': 'test1', 'CustomUserData': 'test-data'},
            {'Token': 'test1'}, {'Token': 'test1'}
        ]
        platform_arn = response['PlatformApplicationArn']
        responses = []
        for kwargs in kwargs_list:
            responses.append(self.sns_client.create_platform_endpoint(PlatformApplicationArn=platform_arn,
                **kwargs))
        # Assert endpointarn is returned in every call create platform call
        for i in range(len(responses)):
            self.assertIn('EndpointArn', responses[i])
        endpoint_arn = responses[0]['EndpointArn']
        # clean up
        self.sns_client.delete_endpoint(EndpointArn=endpoint_arn)
        self.sns_client.delete_platform_application(PlatformApplicationArn=platform_arn)

    def test_publish_by_path_parameters(self):
        topic_name = 'topic-{}'.format(short_uid())
        queue_name = 'queue-{}'.format(short_uid())

        message = 'test message {}'.format(short_uid())
        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']

        base_url = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_SNS)
        path = 'Action=Publish&Version=2010-03-31&TopicArn={}&Message={}'.format(topic_arn, message)

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_arn)

        r = requests.post(
            url='{}/?{}'.format(base_url, path),
            headers=aws_stack.mock_aws_request_headers('sns')
        )
        self.assertEqual(r.status_code, 200)

        def get_notification(q_url):
            resp = self.sqs_client.receive_message(QueueUrl=q_url)
            return json.loads(resp['Messages'][0]['Body'])

        notification = retry(get_notification, retries=3, sleep=2, q_url=queue_url)
        self.assertEqual(notification['TopicArn'], topic_arn)
        self.assertEqual(notification['Message'], message)

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_multiple_subscriptions_http_endpoint(self):
        self.unsubscribe_all_from_sns()

        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 429

        number_of_subscriptions = 4
        records = []
        proxies = []

        for _ in range(number_of_subscriptions):
            local_port = get_free_tcp_port()
            proxies.append(start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener()))
            wait_for_port_open(local_port)
            http_endpoint = '%s://localhost:%s' % (get_service_protocol(), local_port)
            self.sns_client.subscribe(TopicArn=self.topic_arn,
                                      Protocol='http', Endpoint=http_endpoint)

        # fetch subscription information
        subscription_list = self.sns_client.list_subscriptions()
        self.assertEqual(subscription_list['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(len(subscription_list['Subscriptions']), number_of_subscriptions)

        self.assertEqual(number_of_subscriptions, len(records))

        for proxy in proxies:
            proxy.stop()

    def _create_queue(self):
        queue_name = 'queue-%s' % short_uid()
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        return queue_name, queue_arn, queue_url

    def test_publish_sms_endpoint(self):
        def check_messages():
            sns_backend = SNSBackend.get()
            self.assertEqual(len(list_of_contacts), len(sns_backend.sms_messages))

        list_of_contacts = [
            '+10123456789',
            '+10000000000',
            '+19876543210'
        ]
        message = 'Good news everyone!'
        # Add SMS Subscribers
        for number in list_of_contacts:
            self.sns_client.subscribe(
                TopicArn=self.topic_arn,
                Protocol='sms',
                Endpoint=number
            )
        # Publish a message.
        self.sns_client.publish(Message=message, TopicArn=self.topic_arn)
        retry(check_messages, retries=3, sleep=0.5)

    def test_publish_sqs_from_sns(self):
        topic = self.sns_client.create_topic(Name='test_topic3')
        topic_arn = topic['TopicArn']
        test_queue = self.sqs_client.create_queue(QueueName='test_queue3')

        queue_url = test_queue['QueueUrl']
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_url)
        self.sns_client.publish(TargetArn=topic_arn, Message='Test msg')

        response = self.sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=['SentTimestamp'],
            MaxNumberOfMessages=1,
            MessageAttributeNames=['All'],
            VisibilityTimeout=2,
            WaitTimeSeconds=2,
        )
        self.assertEqual(len(response['Messages']), 1)

    def add_xray_header(self, request, **kwargs):
        request.headers['X-Amzn-Trace-Id'] = \
            'Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1'

    def test_publish_sqs_from_sns_with_xray_propagation(self):
        if SQS_BACKEND_IMPL != 'elasticmq':
            return

        self.sns_client.meta.events.register('before-send.sns.Publish', self.add_xray_header)

        topic = self.sns_client.create_topic(Name='test_topic4')
        topic_arn = topic['TopicArn']
        test_queue = self.sqs_client.create_queue(QueueName='test_queue4')

        queue_url = test_queue['QueueUrl']
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_url)
        self.sns_client.publish(TargetArn=topic_arn, Message='X-Ray propagation test msg')

        response = self.sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=['SentTimestamp', 'AWSTraceHeader'],
            MaxNumberOfMessages=1,
            MessageAttributeNames=['All'],
            VisibilityTimeout=2,
            WaitTimeSeconds=2,
        )

        self.assertEqual(len(response['Messages']), 1)
        message = response['Messages'][0]
        self.assertTrue('Attributes' in message)
        self.assertTrue('AWSTraceHeader' in message['Attributes'])
        self.assertEqual(message['Attributes']['AWSTraceHeader'],
                         'Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1')

    def test_create_topic_after_delete_with_new_tags(self):
        topic_name = 'test-%s' % short_uid()
        topic = self.sns_client.create_topic(Name=topic_name, Tags=[{'Key': 'Name', 'Value': 'pqr'}])
        self.sns_client.delete_topic(TopicArn=topic['TopicArn'])

        topic1 = self.sns_client.create_topic(Name=topic_name, Tags=[{'Key': 'Name', 'Value': 'abc'}])
        self.assertEqual(topic['TopicArn'], topic1['TopicArn'])

        # cleanup
        self.sns_client.delete_topic(TopicArn=topic1['TopicArn'])

    def test_not_found_error_on_get_subscription_attributes(self):
        topic_name = 'queue-{}'.format(short_uid())
        queue_name = 'test-%s' % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']
        queue = self.sqs_client.create_queue(QueueName=queue_name)

        queue_url = queue['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        subscription = self.sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_arn)

        subscription_attributes = self.sns_client.get_subscription_attributes(
            SubscriptionArn=subscription['SubscriptionArn'])

        self.assertEqual(subscription_attributes.get('Attributes').get('SubscriptionArn'),
                         subscription['SubscriptionArn'])

        self.sns_client.unsubscribe(SubscriptionArn=subscription['SubscriptionArn'])

        with self.assertRaises(ClientError) as ctx:
            self.sns_client.get_subscription_attributes(
                SubscriptionArn=subscription['SubscriptionArn'])

        self.assertEqual(ctx.exception.response['Error']['Code'], 'NotFound')
        self.assertEqual(ctx.exception.response['ResponseMetadata']['HTTPStatusCode'], 404)

        # cleanup
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)
