import unittest
import json
import base64

from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import (short_uid, get_free_tcp_port, wait_for_port_open, get_service_protocol,
    retry, to_bytes, to_str)
from localstack.services.infra import start_proxy
from localstack.services.generic_proxy import ProxyListener

TEST_STREAM_NAME = 'firehose_test_' + short_uid()


class FirehoseTest(unittest.TestCase):
    def test_firehose_http(self):
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                data_received = dict(json.loads(data.decode('utf-8')))
                records.append(data_received)
                return 200
        firehose = aws_stack.connect_to_service('firehose')
        local_port = get_free_tcp_port()
        endpoint = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, local_port)
        records = []
        http_destination_update = {
            'EndpointConfiguration': {
                'Url': endpoint,
                'Name': 'test_update'
            }
        }
        http_destination = {
            'EndpointConfiguration': {
                'Url': endpoint
            },
            'S3BackupMode': 'FailedDataOnly',
            'S3Configuration': {
                'RoleARN': 'arn:.*',
                'BucketARN': 'arn:.*',
                'Prefix': '',
                'ErrorOutputPrefix': '',
                'BufferingHints': {
                    'SizeInMBs': 1,
                    'IntervalInSeconds': 60
                }
            }
        }

        # start proxy server
        start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        wait_for_port_open(local_port)

        # create firehose stream with http destination
        stream = firehose.create_delivery_stream(DeliveryStreamName=TEST_STREAM_NAME,
            HttpEndpointDestinationConfiguration=http_destination)
        self.assertTrue(stream)
        stream_description = firehose.describe_delivery_stream(DeliveryStreamName=TEST_STREAM_NAME)
        stream_description = stream_description['DeliveryStreamDescription']
        destination_description = stream_description['Destinations'][0]['HttpEndpointDestinationDescription']
        self.assertEquals(1, len(stream_description['Destinations']))
        self.assertEquals(f'http://localhost:{local_port}', destination_description['EndpointConfiguration']['Url'])

        # put record
        firehose.put_record(DeliveryStreamName=TEST_STREAM_NAME, Record={'Data': 'Hello World!'})
        record_received = to_str(base64.b64decode(to_bytes(records[0]['records'][0]['data'])))
        # wait for the result to arrive with proper content
        retry(lambda: self.assertEquals('Hello World!', record_received), retries=5, sleep=1)

        # update stream destination
        destination_id = stream_description['Destinations'][0]['DestinationId']
        version_id = stream_description['VersionId']
        firehose.update_destination(DeliveryStreamName=TEST_STREAM_NAME, DestinationId=destination_id,
            CurrentDeliveryStreamVersionId=version_id, HttpEndpointDestinationUpdate=http_destination_update)
        stream_description = firehose.describe_delivery_stream(DeliveryStreamName=TEST_STREAM_NAME)
        stream_description = stream_description['DeliveryStreamDescription']
        destination_description = stream_description['Destinations'][0]['HttpEndpointDestinationDescription']
        self.assertEquals('test_update', destination_description['EndpointConfiguration']['Name'])

        # delete stream
        stream = firehose.delete_delivery_stream(DeliveryStreamName=TEST_STREAM_NAME)
        self.assertEquals(200, stream['ResponseMetadata']['HTTPStatusCode'])
