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

    def test_create_fifo_queue(self):
        fifo_queue = 'my-queue.fifo'
        queue_info = self.client.create_queue(QueueName=fifo_queue, Attributes={'FifoQueue': 'true'})
        queue_url = queue_info['QueueUrl']

        # it should preserve .fifo in the queue name
        self.assertIn(fifo_queue, queue_url)

    def test_set_queue_policy(self):
        fifo_queue = 'queue-%s' % short_uid()
        queue_info = self.client.create_queue(QueueName=fifo_queue)
        queue_url = queue_info['QueueUrl']

        attributes = {
            'Policy': TEST_POLICY
        }
        self.client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        attrs = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])['Attributes']
        self.assertIn('sqs:SendMessage', attrs['Policy'])
        attrs = self.client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])['Attributes']
        self.assertIn('sqs:SendMessage', attrs['Policy'])
