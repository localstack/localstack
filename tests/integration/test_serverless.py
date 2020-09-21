import os
import json
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import run


class TestServerless(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base_dir = os.path.join(os.path.dirname(__file__), 'serverless')

        if not os.path.exists(os.path.join(base_dir, 'node_modules')):
            # install dependencies
            run('cd %s; npm install' % base_dir)

        # deploy serverless app
        run('cd %s; npm run serverless -- --region=%s' % (base_dir, aws_stack.get_region()))

    def test_event_rules_deployed(self):
        events = aws_stack.connect_to_service('events')
        rules = events.list_rules()['Rules']
        rule = ([r for r in rules if r['Name'] == 'sls-test-cf-event'] or [None])[0]
        self.assertTrue(rule)
        self.assertIn('Arn', rule)
        pattern = json.loads(rule['EventPattern'])
        self.assertEqual(pattern['source'], ['aws.cloudformation'])
        self.assertIn('detail-type', pattern)

    def test_dynamodb_stream_handler_deployed(self):
        function_name = 'sls-test-local-dynamodbStreamHandler'
        table_name = 'Test'

        lambda_client = aws_stack.connect_to_service('lambda')
        dynamodb_client = aws_stack.connect_to_service('dynamodb')

        resp = lambda_client.list_functions()
        function = [fn for fn in resp['Functions'] if fn['FunctionName'] == function_name][0]
        self.assertEqual(function['Handler'], 'handler.processItem')

        resp = lambda_client.list_event_source_mappings(
            FunctionName=function_name,
        )
        events = resp['EventSourceMappings']
        self.assertEqual(len(events), 1)
        event_source_arn = events[0]['EventSourceArn']

        resp = dynamodb_client.describe_table(
            TableName=table_name
        )
        latest_stream_arn = resp['Table']['LatestStreamArn'].replace(resp['Table']['LatestStreamLabel'], 'latest')
        self.assertEqual(latest_stream_arn, event_source_arn)

    def test_kinesis_stream_handler_deployed(self):
        function_name = 'sls-test-local-kinesisStreamHandler'
        stream_name = 'KinesisTestStream'

        lambda_client = aws_stack.connect_to_service('lambda')
        kinesis_client = aws_stack.connect_to_service('kinesis')

        resp = lambda_client.list_functions()
        function = [fn for fn in resp['Functions'] if fn['FunctionName'] == function_name][0]
        self.assertEqual(function['Handler'], 'handler.processKinesis')

        resp = lambda_client.list_event_source_mappings(
            FunctionName=function_name,
        )
        events = resp['EventSourceMappings']
        self.assertEqual(len(events), 1)
        event_source_arn = events[0]['EventSourceArn']

        resp = kinesis_client.describe_stream(
            StreamName=stream_name
        )
        self.assertEqual(resp['StreamDescription']['StreamARN'], event_source_arn)
