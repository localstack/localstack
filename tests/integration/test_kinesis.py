import base64
import logging
import unittest
import re
from time import sleep
from datetime import datetime
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid
from localstack.utils.kinesis import kinesis_connector


class TestKinesis(unittest.TestCase):

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
        sleep(1)
        assert_consumers(0)

        # create consumer and assert 1 consumer
        consumer_name = 'cons1'
        response = client.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        sleep(1)
        self.assertEqual(response['Consumer']['ConsumerName'], consumer_name)
        # boto3 converts the timestamp to datetime
        self.assertTrue(isinstance(response['Consumer']['ConsumerCreationTimestamp'], datetime))
        consumers = assert_consumers(1)
        consumer_arn = consumers[0]['ConsumerARN']
        self.assertEqual(consumers[0]['ConsumerName'], consumer_name)
        self.assertIn('/%s' % consumer_name, consumer_arn)
        self.assertTrue(isinstance(consumers[0]['ConsumerCreationTimestamp'], datetime))

        # lookup stream consumer by describe calls, assert response
        consumer_description_by_arn = client.describe_stream_consumer(
            StreamARN=stream_arn,
            ConsumerARN=consumer_arn)['ConsumerDescription']
        self.assertEqual(consumer_description_by_arn['ConsumerName'], consumer_name)
        self.assertEqual(consumer_description_by_arn['ConsumerARN'], consumer_arn)
        self.assertEqual(consumer_description_by_arn['StreamARN'], stream_arn)
        self.assertEqual(consumer_description_by_arn['ConsumerStatus'], 'ACTIVE')
        self.assertTrue(isinstance(consumer_description_by_arn['ConsumerCreationTimestamp'], datetime))
        consumer_description_by_name = client.describe_stream_consumer(
            StreamARN=stream_arn,
            ConsumerName=consumer_name)['ConsumerDescription']
        self.assertEqual(consumer_description_by_arn, consumer_description_by_name)

        # delete existing consumer and assert 0 remaining consumers
        client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        sleep(1)
        assert_consumers(0)

        # clean up
        client.delete_stream(StreamName=stream_name)

    def test_subscribe_to_shard(self):
        client = aws_stack.connect_to_service('kinesis')
        stream_name = 'test-%s' % short_uid()
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)

        # create stream and consumer
        result = client.create_stream(StreamName=stream_name, ShardCount=1)
        sleep(1)
        result = client.register_stream_consumer(StreamARN=stream_arn, ConsumerName='c1')['Consumer']
        sleep(1)

        # subscribe to shard
        response = client.describe_stream(StreamName=stream_name)
        shard_id = response.get('StreamDescription').get('Shards')[0].get('ShardId')
        result = client.subscribe_to_shard(ConsumerARN=result['ConsumerARN'],
            ShardId=shard_id, StartingPosition={'Type': 'TRIM_HORIZON'})
        stream = result['EventStream']

        # put records
        num_records = 5
        msg = b'Hello world'
        msg_b64 = base64.b64encode(msg)
        for i in range(num_records):
            client.put_records(StreamName=stream_name, Records=[{'Data': msg_b64, 'PartitionKey': '1'}])

        # assert results
        results = []
        for entry in stream:
            records = entry['SubscribeToShardEvent']['Records']
            continuation_sequence_number = entry['SubscribeToShardEvent']['ContinuationSequenceNumber']
            # https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShardEvent.html
            self.assertIsNotNone(re.fullmatch('^0|([1-9][0-9]{0,128})$', continuation_sequence_number))
            results.extend(records)
            if len(results) >= num_records:
                break

        # assert results
        self.assertEqual(len(results), num_records)
        for record in results:
            self.assertEqual(record['Data'], msg)

        # clean up
        client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName='c1')
        client.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)

    def test_subscribe_to_shard_with_sequence_number_as_iterator(self):
        client = aws_stack.connect_to_service('kinesis')
        stream_name = 'test-%s' % short_uid()
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)

        # create stream and consumer
        result = client.create_stream(StreamName=stream_name, ShardCount=1)
        sleep(1)
        result = client.register_stream_consumer(StreamARN=stream_arn, ConsumerName='c1')['Consumer']
        sleep(1)
        # get starting sequence number
        response = client.describe_stream(StreamName=stream_name)
        sequence_number = response.get('StreamDescription').get('Shards')[0].get('SequenceNumberRange'). \
            get('StartingSequenceNumber')
        # subscribe to shard with iterator type as AT_SEQUENCE_NUMBER
        response = client.describe_stream(StreamName=stream_name)
        shard_id = response.get('StreamDescription').get('Shards')[0].get('ShardId')
        result = client.subscribe_to_shard(ConsumerARN=result['ConsumerARN'],
            ShardId=shard_id, StartingPosition={'Type': 'AT_SEQUENCE_NUMBER',
            'SequenceNumber': sequence_number})
        stream = result['EventStream']
        # put records
        num_records = 5
        for i in range(num_records):
            client.put_records(StreamName=stream_name, Records=[{'Data': 'SGVsbG8gd29ybGQ=', 'PartitionKey': '1'}])

        results = []
        for entry in stream:
            records = entry['SubscribeToShardEvent']['Records']
            results.extend(records)
            if len(results) >= num_records:
                break

        # assert results
        self.assertEqual(len(results), num_records)
        for record in results:
            self.assertEqual(record['Data'], b'Hello world')

        # clean up
        client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName='c1')
        client.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)

    def test_get_records(self):
        client = aws_stack.connect_to_service('kinesis')
        stream_name = 'test-%s' % short_uid()

        client.create_stream(StreamName=stream_name, ShardCount=1)
        sleep(2)
        client.put_records(StreamName=stream_name, Records=[{'Data': 'SGVsbG8gd29ybGQ=', 'PartitionKey': '1'}])

        response = client.describe_stream(StreamName=stream_name)

        sequence_number = response.get('StreamDescription').get('Shards')[0].get('SequenceNumberRange'). \
            get('StartingSequenceNumber')

        shard_id = response.get('StreamDescription').get('Shards')[0].get('ShardId')

        response = client.get_shard_iterator(StreamName=stream_name, ShardId=shard_id,
                                             ShardIteratorType='AT_SEQUENCE_NUMBER',
                                             StartingSequenceNumber=sequence_number)

        response = client.get_records(ShardIterator=response.get('ShardIterator'))
        self.assertEqual(len(response.get('Records')), 1)
        self.assertIn('Data', response.get('Records')[0])

        # clean up
        client.delete_stream(StreamName=stream_name)


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
