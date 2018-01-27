import unittest
from localstack.utils.aws import aws_stack


TEST_QUEUE_NAME = 'TestQueue'


class SQSTest(unittest.TestCase):
    def test_list_queue_tags(self):
        # Since this API call is not implemented in ElasticMQ, we're mocking it
        # and letting it return an empty response
        sqs_client = aws_stack.connect_to_service('sqs')
        queue_info = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME)
        queue_url = queue_info['QueueUrl']
        res = sqs_client.list_queue_tags(QueueUrl=queue_url)

        # Apparently, if there are no tags, then `Tags` should NOT appear in the response.
        assert 'Tags' not in res
