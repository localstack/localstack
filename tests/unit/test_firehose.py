import unittest
import json

from localstack.services.firehose import firehose_api
from localstack.utils.common import short_uid, retry, get_free_tcp_port
from localstack.services.infra import start_proxy
from localstack.services.generic_proxy import ProxyListener

TEST_STREAM_NAME_1 = 'firehose_test_' + short_uid()
TEST_STREAM_NAME_2 = 'firehose_test_' + short_uid()
TEST_TAG_1 = {'Key': 'MyTag', 'Value': 'TestValue'}
TEST_TAG_2 = {'Key': 'AnotherTag', 'Value': 'AnotherValue'}
TEST_TAGS = [TEST_TAG_1, TEST_TAG_2]


class FirehoseApiTest(unittest.TestCase):

    def setUp(self):
        firehose_api.create_stream(TEST_STREAM_NAME_1, tags=TEST_TAGS)

    def tearDown(self):
        firehose_api.delete_stream(TEST_STREAM_NAME_1)

    def test_delivery_stream_tags(self):
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1)
        self.assertEquals(TEST_TAGS, result['Tags'])
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1, exclusive_start_tag_key='MyTag')
        self.assertEquals([TEST_TAG_2], result['Tags'])
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1, limit=1)
        self.assertEquals([TEST_TAG_1], result['Tags'])
        self.assertEquals(True, result['HasMore'])

    def test_stream_with_httpendpoint_destination(self):
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                data_received = dict(json.loads(data.decode('utf-8')))
                records.append(data_received)
        local_port = get_free_tcp_port()
        records = []
        http_destination = {'EndpointConfiguration': {'Url': f'http://localhost:{local_port}'}}
        http_destination_update = {
            'EndpointConfiguration': {
                'Url': f'http://localhost:{local_port}',
                'Name': 'test_update'
            }
        }
        # create stream
        stream = firehose_api.create_stream(TEST_STREAM_NAME_2, tags=TEST_TAGS, http_destination=http_destination)
        destination_description = stream['Destinations'][0]['HttpEndpointDestinationDescription']
        self.assertEquals(1, len(stream['Destinations']))
        self.assertEquals(f'http://localhost:{local_port}', destination_description['EndpointConfiguration']['Url'])
        # update stream destination
        destination_id = stream['Destinations'][0]['DestinationId']
        updated_stream_destination = firehose_api.update_destination(TEST_STREAM_NAME_2, destination_id,
             http_update=http_destination_update)
        destination_description = updated_stream_destination['HttpEndpointDestinationDescription']
        self.assertEquals('test_update', destination_description['EndpointConfiguration']['Name'])
        # put record to stream
        start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        firehose_api.put_record(TEST_STREAM_NAME_2, {'Data': 'SGVsbG8gd29ybGQ='})
        # wait for the result to arrive with proper content
        retry(lambda: self.assertEquals('SGVsbG8gd29ybGQ=', records[0]['records'][0]['data']), retries=5, sleep=1)
        # delete stream
        stream = firehose_api.delete_stream(TEST_STREAM_NAME_2)
        self.assertEquals({}, stream)
