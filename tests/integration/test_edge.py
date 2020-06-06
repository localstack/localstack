import io
import unittest
import requests
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, get_service_protocol, to_str
from localstack.utils.bootstrap import is_api_enabled


class TestEdgeAPI(unittest.TestCase):

    def test_invoke_apis_via_edge(self):
        edge_port = config.EDGE_PORT_HTTP or config.EDGE_PORT
        edge_url = '%s://localhost:%s' % (get_service_protocol(), edge_port)

        if is_api_enabled('s3'):
            self._invoke_s3_via_edge(edge_url)
            self._invoke_s3_via_edge_multipart_form(edge_url)
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

        bucket_name = 'edge-%s' % short_uid()
        object_name = 'testobject'
        bucket_url = '%s/%s' % (edge_url, bucket_name)
        result = requests.put(bucket_url)
        self.assertEqual(result.status_code, 200)
        result = client.head_bucket(Bucket=bucket_name)
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        result = requests.post(bucket_url, data='key=%s&file=file_content_123' % object_name, headers=headers)
        self.assertEqual(result.status_code, 204)
        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        self.assertEqual('file_content_123', to_str(result.getvalue()))

    def _invoke_s3_via_edge_multipart_form(self, edge_url):
        client = aws_stack.connect_to_service('s3', endpoint_url=edge_url)
        bucket_name = 'edge-%s' % short_uid()
        object_name = 'testobject'
        object_data = b'testdata'

        client.create_bucket(Bucket=bucket_name)
        presigned_post = client.generate_presigned_post(bucket_name, object_name)

        files = {'file': object_data}
        r = requests.post(presigned_post['url'], data=presigned_post['fields'], files=files)
        self.assertEqual(r.status_code, 204)

        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        self.assertEqual(to_str(object_data), to_str(result.getvalue()))

        client.delete_object(Bucket=bucket_name, Key=object_name)
        client.delete_bucket(Bucket=bucket_name)
