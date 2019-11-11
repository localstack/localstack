import logging
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry
from localstack.utils.kinesis import kinesis_connector


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
