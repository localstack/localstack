import logging
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid
from localstack.utils.kinesis import kinesis_connector


class TestKinesisServer(unittest.TestCase):

    def test_stream_consumers(self):
        client = aws_stack.connect_to_service('kinesis')
        stream_name = 'test-%s' % short_uid()
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)

        def assert_consumers(count):
            consumers = client.list_stream_consumers(StreamARN=stream_arn).get('Consumers')
            self.assertEqual(len(consumers), count)
            return consumers

        # create stream and assert 0 consumers
        client.create_stream(StreamName=stream_name, ShardCount=1)
        assert_consumers(0)

        # create consumer and assert 1 consumer
        consumer_name = 'cons1'
        client.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        consumers = assert_consumers(1)
        self.assertEqual(consumers[0]['ConsumerName'], consumer_name)
        self.assertIn('/%s' % consumer_name, consumers[0]['ConsumerARN'])

        # delete non-existing consumer and assert 1 consumer
        client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName='_invalid_')
        assert_consumers(1)

        # delete existing consumer and assert 0 remaining consumers
        client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        assert_consumers(0)


class TestKinesisPythonClient(unittest.TestCase):

    def test_run_kcl(self):
        result = []

        def process_records(records):
            result.extend(records)

        # start Kinesis client
        stream_name = 'test-foobar'
        aws_stack.create_kinesis_stream(stream_name, delete=True)
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            kcl_log_level=logging.INFO,
            wait_until_started=True)

        kinesis = aws_stack.connect_to_service('kinesis')

        stream_summary = kinesis.describe_stream_summary(StreamName=stream_name)
        self.assertEqual(stream_summary['StreamDescriptionSummary']['OpenShardCount'], 1)

        num_events_kinesis = 10
        kinesis.put_records(Records=[
            {
                'Data': '{}',
                'PartitionKey': 'test_%s' % i
            } for i in range(0, num_events_kinesis)
        ], StreamName=stream_name)

        def check_events():
            self.assertEqual(len(result), num_events_kinesis)

        retry(check_events, retries=4, sleep=2)
