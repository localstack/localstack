import json
import unittest

from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, load_file, retry
from .lambdas import lambda_integration
from .test_lambda import TEST_LAMBDA_PYTHON, LAMBDA_RUNTIME_PYTHON36, TEST_LAMBDA_LIBS

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


class SQSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = aws_stack.connect_to_service('sqs')

    def test_list_queue_tags(self):
        # Since this API call is not implemented in ElasticMQ, we're mocking it
        # and letting it return an empty response
        queue_info = self.client.create_queue(QueueName=TEST_QUEUE_NAME)
        queue_url = queue_info['QueueUrl']
        result = self.client.list_queue_tags(QueueUrl=queue_url)

        # Apparently, if there are no tags, then `Tags` should NOT appear in the response.
        self.assertNotIn('Tags', result)

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)

    def test_publish_get_delete_message(self):
        queue_name = 'queue-%s' % short_uid()
        queue_info = self.client.create_queue(QueueName=queue_name)
        queue_url = queue_info['QueueUrl']
        self.assertIn(queue_name, queue_url)

        # publish/receive message
        self.client.send_message(QueueUrl=queue_url, MessageBody='msg123')
        for i in range(2):
            messages = self.client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)['Messages']
            self.assertEquals(len(messages), 1)
            self.assertEquals(messages[0]['Body'], 'msg123')

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

    def test_create_fifo_queue(self):
        fifo_queue = 'my-queue.fifo'
        queue_info = self.client.create_queue(QueueName=fifo_queue, Attributes={'FifoQueue': 'true'})
        queue_url = queue_info['QueueUrl']

        # it should preserve .fifo in the queue name
        self.assertIn(fifo_queue, queue_url)

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
        queue_name1 = 'test-%s' % short_uid()
        queue_name2 = 'test-%s' % short_uid()
        queue_url1 = self.client.create_queue(QueueName=queue_name1)['QueueUrl']
        queue_arn1 = aws_stack.sqs_queue_arn(queue_name1)
        policy = {'deadLetterTargetArn': queue_arn1, 'maxReceiveCount': 1}
        queue_url2 = self.client.create_queue(QueueName=queue_name2,
                                              Attributes={'RedrivePolicy': json.dumps(policy)})['QueueUrl']
        queue_arn2 = aws_stack.sqs_queue_arn(queue_name2)

        # create Lambda and add source mapping
        lambda_name = 'test-%s' % short_uid()
        zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON),
                                                  get_content=True, libs=TEST_LAMBDA_LIBS,
                                                  runtime=LAMBDA_RUNTIME_PYTHON36)
        testutil.create_lambda_function(func_name=lambda_name, zip_file=zip_file,
                                        runtime=LAMBDA_RUNTIME_PYTHON36)
        lambda_client.create_event_source_mapping(EventSourceArn=queue_arn2, FunctionName=lambda_name)

        # add message to SQS, which will trigger the Lambda, resulting in an error
        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1
        }
        self.client.send_message(QueueUrl=queue_url2, MessageBody=json.dumps(payload))

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = self.client.receive_message(QueueUrl=queue_url1, MessageAttributeNames=['All'])
            self.assertGreater(len(result['Messages']), 0)
            msg_attrs = result['Messages'][0]['MessageAttributes']
            self.assertIn('RequestID', msg_attrs)
            self.assertIn('ErrorCode', msg_attrs)
            self.assertIn('ErrorMessage', msg_attrs)

        retry(receive_dlq, retries=8, sleep=2)

    def test_set_queue_attribute_at_creation(self):
        queue_name = 'queue-%s' % short_uid()

        attributes = {
            'MessageRetentionPeriod': '604800',  # This one is unsupported by ElasticMq and should be saved in memory
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
