import unittest
import json

from localstack.services.firehose import firehose_api
from localstack.utils.common import short_uid
from localstack.services.infra import start_proxy
from localstack.services.generic_proxy import ProxyListener

TEST_STREAM_NAME_1 = 'firehose_test_' + short_uid()
TEST_STREAM_NAME_2 = 'firehose_test_' + short_uid()
TEST_TAG_1 = {'Key': 'MyTag', 'Value': 'TestValue'}
TEST_TAG_2 = {'Key': 'AnotherTag', 'Value': 'AnotherValue'}
TEST_TAGS = [TEST_TAG_1, TEST_TAG_2]
HTTP_DESTINATION = {'EndpointConfiguration': {'Url': 'http://localhost:5000'}}
HTTP_DESTINATION_UPDATE = {'EndpointConfiguration': {'Name': 'test_update'}}


class FirehoseApiTest(unittest.TestCase):

    def setUp(self):
        firehose_api.create_stream(TEST_STREAM_NAME_1, tags=TEST_TAGS)
        firehose_api.create_stream(TEST_STREAM_NAME_2, tags=TEST_TAGS, http_destination=HTTP_DESTINATION)

    def tearDown(self):
        firehose_api.delete_stream(TEST_STREAM_NAME_1)
        firehose_api.delete_stream(TEST_STREAM_NAME_2)

    def test_delivery_stream_tags(self):
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1)
        self.assertEquals(TEST_TAGS, result['Tags'])
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1, exclusive_start_tag_key='MyTag')
        self.assertEquals([TEST_TAG_2], result['Tags'])
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME_1, limit=1)
        self.assertEquals([TEST_TAG_1], result['Tags'])
        self.assertEquals(True, result['HasMore'])

    def test_create_stream_with_HttpEndpointDestination(self):
        stream = firehose_api.get_stream(TEST_STREAM_NAME_2)
        destination_description = stream['Destinations'][0]['HttpEndpointDestinationDescription']
        self.assertEquals(1, len(stream['Destinations']))
        self.assertEquals('http://localhost:5000',
        destination_description['EndpointConfiguration']['Url'])

    def test_update_stream_HttpEndpointDestination(self):
        stream = firehose_api.get_stream(TEST_STREAM_NAME_2)
        destination_id = stream['Destinations'][0]['DestinationId']
        updated_stream_destination = firehose_api.update_destination(TEST_STREAM_NAME_2, destination_id,
             http_update=HTTP_DESTINATION_UPDATE)
        destination_description = updated_stream_destination['HttpEndpointDestinationDescription']
        self.assertEquals('test_update',
            destination_description['EndpointConfiguration']['Name'])

    def test_put_record_to_HttpEndpointDestination(self):
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                data_received = dict(json.loads(data.decode('utf-8')))
                self.assertEquals('SGVsbG8gd29ybGQ=', data_received['records'][0]['data'])
        start_proxy(5000, backend_url=None, update_listener=MyUpdateListener())
        firehose_api.put_record(TEST_STREAM_NAME_2, {'Data': 'SGVsbG8gd29ybGQ='})
