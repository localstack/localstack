# -*- coding: utf-8 -*-

import json
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str


TEST_TOPIC_NAME = 'TestTopic_snsTest'
TEST_QUEUE_NAME = 'TestQueue_snsTest'


class SNSTest(unittest.TestCase):

    def test_publish_unicode_chars(self):
        sqs_client = aws_stack.connect_to_service('sqs')
        sns_client = aws_stack.connect_to_service('sns')

        # create SNS topic and connect it to an SQS queue
        topic = sns_client.create_topic(Name=TEST_TOPIC_NAME)
        queue = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME)
        topic_arn = topic['TopicArn']
        queue_url = queue['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME)
        sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_arn)

        # publish message to SNS, receive it from SQS, assert that messages are equal
        message = u'ö§a1"_!?,. £$-'
        sns_client.publish(TopicArn=topic_arn, Message=message)
        msgs = sqs_client.receive_message(QueueUrl=queue_url)
        msg_received = msgs['Messages'][0]
        msg_received = json.loads(to_str(msg_received['Body']))
        msg_received = msg_received['Message']
        self.assertEqual(message, msg_received)
