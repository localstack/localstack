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

        # list apigateway before sls deployment
        apigw_client = aws_stack.connect_to_service('apigateway')
        apis = apigw_client.get_rest_apis()['items']
        cls.api_ids = [api['id'] for api in apis]

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

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        mappings = resp['EventSourceMappings']
        self.assertEqual(len(mappings), 1)
        event_source_arn = mappings[0]['EventSourceArn']

        resp = kinesis_client.describe_stream(StreamName=stream_name)
        self.assertEqual(resp['StreamDescription']['StreamARN'], event_source_arn)

    def test_queue_handler_deployed(self):
        function_name = 'sls-test-local-queueHandler'
        queue_name = 'sls-test-local-CreateQueue'

        lambda_client = aws_stack.connect_to_service('lambda')

        resp = lambda_client.list_functions()
        function = [fn for fn in resp['Functions'] if fn['FunctionName'] == function_name][0]
        self.assertEqual(function['Handler'], 'src/sqs.create')

        resp = lambda_client.list_event_source_mappings(
            FunctionName=function_name,
        )
        events = resp['EventSourceMappings']
        self.assertEqual(len(events), 1)
        event_source_arn = events[0]['EventSourceArn']

        self.assertEqual(aws_stack.sqs_queue_arn(queue_name), event_source_arn)

    def test_apigateway_deployed(self):
        function_name = 'sls-test-local-router'

        lambda_client = aws_stack.connect_to_service('lambda')

        resp = lambda_client.list_functions()
        function = [fn for fn in resp['Functions'] if fn['FunctionName'] == function_name][0]
        self.assertEqual(function['Handler'], 'src/http.router')

        apigw_client = aws_stack.connect_to_service('apigateway')
        apis = apigw_client.get_rest_apis()['items']
        api_ids = [api['id'] for api in apis if api['id'] not in self.api_ids]
        self.assertEqual(len(api_ids), 1)

        resources = apigw_client.get_resources(restApiId=api_ids[0])['items']
        proxy_resources = [res for res in resources if res['path'] == '/{proxy+}']
        self.assertEqual(len(proxy_resources), 1)

        proxy_resource = proxy_resources[0]
        for method in ['DELETE', 'OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'HEAD']:
            self.assertIn(method, proxy_resource['resourceMethods'])
            resource_method = proxy_resource['resourceMethods'][method]
            self.assertIn(aws_stack.lambda_function_arn(function_name), resource_method['methodIntegration']['uri'])
