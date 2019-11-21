import json
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


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
        res = self.client.list_queue_tags(QueueUrl=queue_url)

        # Apparently, if there are no tags, then `Tags` should NOT appear in the response.
        assert 'Tags' not in res

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

        # delete/receive message
        self.client.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]['ReceiptHandle'])
        response = self.client.receive_message(QueueUrl=queue_url)
        self.assertFalse(response.get('Messages'))

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

    def test_dead_letter_queue(self):
        queue_name = 'queue-%s' % short_uid()
        dlq_name = 'queue-%s' % short_uid()

        dlq_info = self.client.create_queue(QueueName=dlq_name)
        dlq_arn = aws_stack.sqs_queue_arn(dlq_name)

        attributes = {'RedrivePolicy': json.dumps({'deadLetterTargetArn': dlq_arn, 'maxReceiveCount': 100})}
        queue_info = self.client.create_queue(QueueName=queue_name, Attributes=attributes)
        queue_url = queue_info['QueueUrl']

        # clean up
        self.client.delete_queue(QueueUrl=queue_url)
        self.client.delete_queue(QueueUrl=dlq_info['QueueUrl'])
