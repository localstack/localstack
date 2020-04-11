import unittest
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, get_service_protocol
from localstack.utils.bootstrap import is_api_enabled


class TestEdgeAPI(unittest.TestCase):

    def test_invoke_apis_via_edge(self):
        edge_url = '%s://localhost:%s' % (get_service_protocol(), config.EDGE_PORT)

        if is_api_enabled('s3'):
            self._invoke_s3_via_edge(edge_url)
        if is_api_enabled('kinesis'):
            self._invoke_kinesis_via_edge(edge_url)
        if is_api_enabled('dynamodbstreams'):
            self._invoke_dynamodbstreams_via_edge(edge_url)
        if is_api_enabled('firehose'):
            self._invoke_firehose_via_edge(edge_url)
        if is_api_enabled('stepfunctions'):
            self._invoke_stepfunctions_via_edge(edge_url)

    def _invoke_kinesis_via_edge(self, edge_url):
        client = aws_stack.connect_to_service('kinesis', endpoint_url=edge_url)
        result = client.list_streams()
        self.assertIn('StreamNames', result)

    def _invoke_dynamodbstreams_via_edge(self, edge_url):
        client = aws_stack.connect_to_service('dynamodbstreams', endpoint_url=edge_url)
        result = client.list_streams()
        self.assertIn('Streams', result)

    def _invoke_firehose_via_edge(self, edge_url):
        client = aws_stack.connect_to_service('firehose', endpoint_url=edge_url)
        result = client.list_delivery_streams()
        self.assertIn('DeliveryStreamNames', result)

    def _invoke_stepfunctions_via_edge(self, edge_url):
        client = aws_stack.connect_to_service('stepfunctions', endpoint_url=edge_url)
        result = client.list_state_machines()
        self.assertIn('stateMachines', result)

    def _invoke_s3_via_edge(self, edge_url):
        client = aws_stack.connect_to_service('s3', endpoint_url=edge_url)
        bucket_name = 'edge-%s' % short_uid()

        client.create_bucket(Bucket=bucket_name)
        result = client.head_bucket(Bucket=bucket_name)
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        client.delete_bucket(Bucket=bucket_name)
