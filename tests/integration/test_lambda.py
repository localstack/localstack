import re
import os
import json
import shutil
import time
import unittest
import six
import base64
from botocore.exceptions import ClientError
from io import BytesIO
from localstack import config
from localstack.constants import LOCALSTACK_MAVEN_VERSION, LOCALSTACK_ROOT_FOLDER, LAMBDA_TEST_ROLE
from localstack.services.awslambda.lambda_executors import LAMBDA_RUNTIME_PYTHON37, LAMBDA_RUNTIME_NODEJS12X
from localstack.utils import testutil
from localstack.utils.testutil import (
    get_lambda_log_events, check_expected_lambda_log_events_length,
    create_lambda_archive
)
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    unzip, new_tmp_dir, short_uid, load_file, to_str, mkdir, download,
    run_safe, get_free_tcp_port, get_service_protocol, retry, to_bytes
)
from localstack.services.infra import start_proxy
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.services.generic_proxy import ProxyListener
from localstack.services.awslambda.lambda_api import (
    LAMBDA_RUNTIME_DOTNETCORE2, LAMBDA_RUNTIME_DOTNETCORE31, LAMBDA_RUNTIME_RUBY25, LAMBDA_RUNTIME_PYTHON27,
    use_docker, LAMBDA_RUNTIME_PYTHON36, LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_NODEJS810, LAMBDA_RUNTIME_PROVIDED, BATCH_SIZE_RANGES, INVALID_PARAMETER_VALUE_EXCEPTION,
    LAMBDA_DEFAULT_HANDLER)
from .lambdas import lambda_integration

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py')
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py')
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_python3.py')
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.js')
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.rb')
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, 'lambdas', 'dotnetcore2', 'dotnetcore2.zip')
TEST_LAMBDA_DOTNETCORE31 = os.path.join(THIS_FOLDER, 'lambdas', 'dotnetcore31', 'dotnetcore31.zip')
TEST_LAMBDA_CUSTOM_RUNTIME = os.path.join(THIS_FOLDER, 'lambdas', 'custom-runtime')
TEST_LAMBDA_JAVA = os.path.join(LOCALSTACK_ROOT_FOLDER, 'localstack', 'infra', 'localstack-utils-tests.jar')
TEST_LAMBDA_JAVA_WITH_LIB = os.path.join(THIS_FOLDER, 'lambdas', 'java', 'lambda-function-with-lib-0.0.1.jar')
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_environment.py')
TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE1 = os.path.join(THIS_FOLDER, 'lambdas', 'python3', 'lambda1', 'lambda1.zip')
TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE2 = os.path.join(THIS_FOLDER, 'lambdas', 'python3', 'lambda2', 'lambda2.zip')

TEST_LAMBDA_NAME_PY = 'test_lambda_py'
TEST_LAMBDA_NAME_PY3 = 'test_lambda_py3'
TEST_LAMBDA_NAME_JS = 'test_lambda_js'
TEST_LAMBDA_NAME_RUBY = 'test_lambda_ruby'
TEST_LAMBDA_NAME_DOTNETCORE2 = 'test_lambda_dotnetcore2'
TEST_LAMBDA_NAME_DOTNETCORE31 = 'test_lambda_dotnetcore31'
TEST_LAMBDA_NAME_CUSTOM_RUNTIME = 'test_lambda_custom_runtime'
TEST_LAMBDA_NAME_JAVA = 'test_lambda_java'
TEST_LAMBDA_NAME_JAVA_STREAM = 'test_lambda_java_stream'
TEST_LAMBDA_NAME_JAVA_SERIALIZABLE = 'test_lambda_java_serializable'
TEST_LAMBDA_NAME_ENV = 'test_lambda_env'

TEST_LAMBDA_ECHO_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py')
TEST_LAMBDA_SEND_MESSAGE_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_send_message.py')
TEST_LAMBDA_PUT_ITEM_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_put_item.py')
TEST_LAMBDA_START_EXECUTION_FILE = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_start_execution.py')

TEST_LAMBDA_FUNCTION_PREFIX = 'lambda-function'
TEST_SNS_TOPIC_NAME = 'sns-topic-1'

MAVEN_BASE_URL = 'https://repo.maven.apache.org/maven2'

TEST_LAMBDA_JAR_URL = '{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar'.format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_BASE_URL, name='localstack-utils')

TEST_LAMBDA_LIBS = [
    'localstack', 'localstack_client', 'requests', 'psutil', 'urllib3', 'chardet', 'certifi', 'idna', 'pip', 'dns'
]


def _run_forward_to_fallback_url(url, num_requests=3):
    lambda_client = aws_stack.connect_to_service('lambda')
    config.LAMBDA_FALLBACK_URL = url
    try:
        for i in range(num_requests):
            lambda_client.invoke(FunctionName='non-existing-lambda-%s' % i,
                                 Payload=b'{}', InvocationType='RequestResponse')
    finally:
        config.LAMBDA_FALLBACK_URL = ''


class LambdaTestBase(unittest.TestCase):
    def test_create_lambda_function(self):
        func_name = 'lambda_func-{}'.format(short_uid())
        kms_key_arn = 'arn:aws:kms:us-east-1:000000000000:key11'
        vpc_config = {
            'SubnetIds': ['subnet-123456789'],
            'SecurityGroupIds': ['sg-123456789']
        }
        tags = {
            'env': 'testing'
        }

        kwargs = {
            'FunctionName': func_name,
            'Runtime': LAMBDA_RUNTIME_PYTHON37,
            'Handler': LAMBDA_DEFAULT_HANDLER,
            'Role': LAMBDA_TEST_ROLE,
            'KMSKeyArn': kms_key_arn,
            'Code': {
                'ZipFile': create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
            },
            'Timeout': 3,
            'VpcConfig': vpc_config,
            'Tags': tags
        }

        client = aws_stack.connect_to_service('lambda')
        client.create_function(**kwargs)

        rs = client.get_function(
            FunctionName=func_name
        )

        self.assertEqual(rs['Configuration'].get('KMSKeyArn', ''), kms_key_arn)
        self.assertEqual(rs['Configuration'].get('VpcConfig', {}), vpc_config)
        self.assertEqual(rs['Tags'], tags)

        client.delete_function(FunctionName=func_name)

    def check_lambda_logs(self, func_name, expected_lines=[]):
        log_events = LambdaTestBase.get_lambda_logs(func_name)
        log_messages = [e['message'] for e in log_events]
        for line in expected_lines:
            if '.*' in line:
                found = [re.match(line, m) for m in log_messages]
                if any(found):
                    continue
            self.assertIn(line, log_messages)

    @staticmethod
    def get_lambda_logs(func_name):
        logs_client = aws_stack.connect_to_service('logs')
        log_group_name = '/aws/lambda/%s' % func_name
        streams = logs_client.describe_log_streams(logGroupName=log_group_name)['logStreams']
        streams = sorted(streams, key=lambda x: x['creationTime'], reverse=True)
        log_events = logs_client.get_log_events(
            logGroupName=log_group_name, logStreamName=streams[0]['logStreamName'])['events']
        return log_events


class TestLambdaBaseFeatures(unittest.TestCase):
    def test_forward_to_fallback_url_dynamodb(self):
        db_table = 'lambda-records'
        ddb_client = aws_stack.connect_to_service('dynamodb')

        def num_items():
            return len((run_safe(ddb_client.scan, TableName=db_table) or {'Items': []})['Items'])

        items_before = num_items()
        _run_forward_to_fallback_url('dynamodb://%s' % db_table)
        items_after = num_items()
        self.assertEqual(items_after, items_before + 3)

    def test_forward_to_fallback_url_http(self):
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append({'data': data, 'headers': headers})
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())

        items_before = len(records)
        _run_forward_to_fallback_url('%s://localhost:%s' % (get_service_protocol(), local_port))
        items_after = len(records)
        for record in records:
            self.assertIn('non-existing-lambda', record['headers']['lambda-function-name'])

        self.assertEqual(items_after, items_before + 3)
        proxy.stop()

    def test_adding_fallback_function_name_in_headers(self):
        lambda_client = aws_stack.connect_to_service('lambda')
        ddb_client = aws_stack.connect_to_service('dynamodb')

        db_table = 'lambda-records'
        config.LAMBDA_FALLBACK_URL = 'dynamodb://%s' % db_table

        lambda_client.invoke(FunctionName='non-existing-lambda',
                             Payload=b'{}', InvocationType='RequestResponse')

        result = run_safe(ddb_client.scan, TableName=db_table)
        self.assertEqual(result['Items'][0]['function_name']['S'], 'non-existing-lambda')

    def test_dead_letter_queue(self):
        sqs_client = aws_stack.connect_to_service('sqs')
        lambda_client = aws_stack.connect_to_service('lambda')

        # create DLQ and Lambda function
        queue_name = 'test-%s' % short_uid()
        lambda_name = 'test-%s' % short_uid()
        queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON, func_name=lambda_name, libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36, DeadLetterConfig={'TargetArn': queue_arn}
        )

        # invoke Lambda, triggering an error
        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1
        }
        lambda_client.invoke(FunctionName=lambda_name,
                             Payload=json.dumps(payload), InvocationType='Event')

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
            self.assertGreater(len(result['Messages']), 0)
            msg_attrs = result['Messages'][0]['MessageAttributes']
            self.assertIn('RequestID', msg_attrs)
            self.assertIn('ErrorCode', msg_attrs)
            self.assertIn('ErrorMessage', msg_attrs)

        retry(receive_dlq, retries=8, sleep=2)

        # update DLQ config
        lambda_client.update_function_configuration(FunctionName=lambda_name, DeadLetterConfig={})
        # invoke Lambda again, assert that status code is 200 and error details contained in the payload
        result = lambda_client.invoke(FunctionName=lambda_name, Payload=json.dumps(payload))
        payload = json.loads(to_str(result['Payload'].read()))
        self.assertEqual(200, result['StatusCode'])
        self.assertEqual('Unhandled', result['FunctionError'])
        self.assertEqual('$LATEST', result['ExecutedVersion'])
        self.assertIn('Test exception', payload['errorMessage'])
        self.assertEqual('Exception', payload['errorType'])
        self.assertEqual(list, type(payload['stackTrace']))

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url)
        lambda_client.delete_function(FunctionName=lambda_name)

    def test_add_lambda_permission(self):
        iam_client = aws_stack.connect_to_service('iam')
        lambda_client = aws_stack.connect_to_service('lambda')

        # create lambda permission
        action = 'lambda:InvokeFunction'
        sid = 's3'
        resp = lambda_client.add_permission(FunctionName=TEST_LAMBDA_NAME_PY, Action=action,
                                            StatementId=sid, Principal='s3.amazonaws.com',
                                            SourceArn=aws_stack.s3_bucket_arn('test-bucket'))
        self.assertIn('Statement', resp)
        # fetch lambda policy
        policy = lambda_client.get_policy(FunctionName=TEST_LAMBDA_NAME_PY)['Policy']
        self.assertIsInstance(policy, six.string_types)
        policy = json.loads(to_str(policy))
        self.assertEqual(policy['Statement'][0]['Action'], action)
        self.assertEqual(policy['Statement'][0]['Sid'], sid)
        self.assertEqual(policy['Statement'][0]['Resource'], lambda_api.func_arn(TEST_LAMBDA_NAME_PY))
        # fetch IAM policy
        policies = iam_client.list_policies(Scope='Local', MaxItems=500)['Policies']
        matching = [p for p in policies if p['PolicyName'] == 'lambda_policy_%s_%s' % (TEST_LAMBDA_NAME_PY, sid)]
        self.assertEqual(len(matching), 1)
        self.assertIn(':policy/', matching[0]['Arn'])

        # remove permission that we just added
        resp = lambda_client.remove_permission(FunctionName=TEST_LAMBDA_NAME_PY,
                                               StatementId=resp['Statement'], Qualifier='qual1', RevisionId='r1')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_lambda_asynchronous_invocations(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        lambda_client = aws_stack.connect_to_service('lambda')

        # adding event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=123,
            MaximumEventAgeInSeconds=123,
            DestinationConfig={
                'OnSuccess': {
                    'Destination': function_name
                },
                'OnFailure': {
                    'Destination': function_name
                }
            }
        )

        destination_config = {
            'OnSuccess': {
                'Destination': function_name
            },
            'OnFailure': {
                'Destination': function_name
            }
        }

        # checking for parameter configuration
        self.assertEqual(response['MaximumRetryAttempts'], 123)
        self.assertEqual(response['MaximumEventAgeInSeconds'], 123)
        self.assertEqual(response['DestinationConfig'], destination_config)

        # over writing event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=123,
            DestinationConfig={
                'OnSuccess': {
                    'Destination': function_name
                },
                'OnFailure': {
                    'Destination': function_name
                }
            }
        )

        # checking if 'MaximumEventAgeInSeconds' is removed
        self.assertNotIn('MaximumEventAgeInSeconds', response)

        # updating event invoke config
        response = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=111,
        )

        # checking for updated and existing configuration
        self.assertEqual(response['MaximumRetryAttempts'], 111)
        self.assertEqual(response['DestinationConfig'], destination_config)

        # clean up
        response = lambda_client.delete_function_event_invoke_config(
            FunctionName=function_name)
        lambda_client.delete_function(FunctionName=function_name)

    def test_event_source_mapping_default_batch_size(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        queue_name_1 = 'queue-{}-1'.format(short_uid())
        queue_name_2 = 'queue-{}-2'.format(short_uid())
        ddb_table = 'ddb_table-{}'.format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        lambda_client = aws_stack.connect_to_service('lambda')

        sqs_client = aws_stack.connect_to_service('sqs')
        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)['QueueUrl']
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        rs = lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn_1,
            FunctionName=function_name
        )
        self.assertEqual(rs['BatchSize'], BATCH_SIZE_RANGES['sqs'][0])

        uuid = rs['UUID']

        try:
            # Update batch size with invalid value
            lambda_client.update_event_source_mapping(
                UUID=uuid,
                FunctionName=function_name,
                BatchSize=BATCH_SIZE_RANGES['sqs'][1] + 1
            )
            self.fail('This call should not be successful as the batch size > MAX_BATCH_SIZE')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], INVALID_PARAMETER_VALUE_EXCEPTION)

        queue_url_2 = sqs_client.create_queue(QueueName=queue_name_2)['QueueUrl']
        queue_arn_2 = aws_stack.sqs_queue_arn(queue_name_2)

        try:
            # Create event source mapping with invalid batch size value
            lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_2,
                FunctionName=function_name,
                BatchSize=BATCH_SIZE_RANGES['sqs'][1] + 1
            )
            self.fail('This call should not be successful as the batch size > MAX_BATCH_SIZE')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], INVALID_PARAMETER_VALUE_EXCEPTION)

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key='id')['TableDescription']['TableArn']
        rs = lambda_client.create_event_source_mapping(
            EventSourceArn=table_arn,
            FunctionName=function_name
        )
        self.assertEqual(rs['BatchSize'], BATCH_SIZE_RANGES['dynamodb'][0])

        # clean up
        dynamodb_client = aws_stack.connect_to_service('dynamodb')
        dynamodb_client.delete_table(TableName=ddb_table)
        sqs_client.delete_queue(QueueUrl=queue_url_1)
        sqs_client.delete_queue(QueueUrl=queue_url_2)
        lambda_client.delete_function(FunctionName=function_name)

    def test_disabled_event_source_mapping_with_dynamodb(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        ddb_table = 'ddb_table-{}'.format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key='id')['TableDescription']['TableArn']

        lambda_client = aws_stack.connect_to_service('lambda')

        rs = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=table_arn
        )
        uuid = rs['UUID']

        dynamodb = aws_stack.connect_to_resource('dynamodb')
        table = dynamodb.Table(ddb_table)

        items = [
            {'id': short_uid(), 'data': 'data1'},
            {'id': short_uid(), 'data': 'data2'}
        ]

        table.put_item(Item=items[0])
        events = get_lambda_log_events(function_name)

        # lambda was invoked 1 time
        self.assertEqual(len(events[0]['Records']), 1)

        # disable event source mapping
        lambda_client.update_event_source_mapping(
            UUID=uuid,
            Enabled=False
        )

        table.put_item(Item=items[1])
        events = get_lambda_log_events(function_name)

        # lambda no longer invoked, still have 1 event
        self.assertEqual(len(events[0]['Records']), 1)

        # clean up
        dynamodb_client = aws_stack.connect_to_service('dynamodb')
        dynamodb_client.delete_table(TableName=ddb_table)

        lambda_client.delete_function(FunctionName=function_name)

    def test_deletion_event_source_mapping_with_dynamodb(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        ddb_table = 'ddb_table-{}'.format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key='id')['TableDescription']['TableArn']
        lambda_client = aws_stack.connect_to_service('lambda')

        lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=table_arn
        )

        dynamodb_client = aws_stack.connect_to_service('dynamodb')
        dynamodb_client.delete_table(TableName=ddb_table)

        result = lambda_client.list_event_source_mappings(EventSourceArn=table_arn)
        self.assertEqual(len(result['EventSourceMappings']), 0)
        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    def test_event_source_mapping_with_sqs(self):
        lambda_client = aws_stack.connect_to_service('lambda')
        sqs_client = aws_stack.connect_to_service('sqs')

        function_name = 'lambda_func-{}'.format(short_uid())
        queue_name_1 = 'queue-{}-1'.format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)['QueueUrl']
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn_1,
            FunctionName=function_name
        )

        sqs_client.send_message(QueueUrl=queue_url_1, MessageBody=json.dumps({'foo': 'bar'}))
        events = retry(get_lambda_log_events, sleep_before=3, function_name=function_name)

        # lambda was invoked 1 time
        self.assertEqual(len(events[0]['Records']), 1)

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url_1)
        lambda_client.delete_function(FunctionName=function_name)

    def test_create_kinesis_event_source_mapping(self):
        function_name = 'lambda_func-{}'.format(short_uid())
        stream_name = 'test-foobar'

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        arn = aws_stack.kinesis_stream_arn(stream_name, account_id='000000000000')

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.create_event_source_mapping(
            EventSourceArn=arn,
            FunctionName=function_name
        )

        stream_name = 'test-foobar'
        aws_stack.create_kinesis_stream(stream_name, delete=True)
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
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

        events = get_lambda_log_events(function_name)
        self.assertEqual(len(events[0]['Records']), 10)

        self.assertIn('eventID', events[0]['Records'][0])
        self.assertIn('eventSourceARN', events[0]['Records'][0])
        self.assertIn('eventSource', events[0]['Records'][0])
        self.assertIn('eventVersion', events[0]['Records'][0])
        self.assertIn('eventName', events[0]['Records'][0])
        self.assertIn('invokeIdentityArn', events[0]['Records'][0])
        self.assertIn('awsRegion', events[0]['Records'][0])
        self.assertIn('kinesis', events[0]['Records'][0])


class TestPythonRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')
        cls.s3_client = aws_stack.connect_to_service('s3')
        cls.sns_client = aws_stack.connect_to_service('sns')

        Util.create_function(TEST_LAMBDA_PYTHON, TEST_LAMBDA_NAME_PY,
                             runtime=LAMBDA_RUNTIME_PYTHON27, libs=TEST_LAMBDA_LIBS)

    @classmethod
    def tearDownClass(cls):
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_PY)

    def test_invocation_type_not_set(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_PY, Payload=b'{}')
        result_data = json.loads(result['Payload'].read())

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(result_data['event'], json.loads('{}'))

    def test_invocation_type_request_response(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_PY,
            Payload=b'{}', InvocationType='RequestResponse'
        )
        result_data = result['Payload'].read()
        result_data = json.loads(to_str(result_data))

        self.assertEqual(result['StatusCode'], 200)
        self.assertIsInstance(result_data, dict)

    def test_invocation_type_event(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_PY,
            Payload=b'{}', InvocationType='Event')

        self.assertEqual(result['StatusCode'], 202)

    def test_invocation_type_dry_run(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_PY, Payload=b'{}',
            InvocationType='DryRun')

        self.assertEqual(result['StatusCode'], 204)

    def test_lambda_environment(self):
        vars = {'Hello': 'World'}
        testutil.create_lambda_function(handler_file=TEST_LAMBDA_ENV, libs=TEST_LAMBDA_LIBS,
                                        func_name=TEST_LAMBDA_NAME_ENV, runtime=LAMBDA_RUNTIME_PYTHON27, envvars=vars)

        # invoke function and assert result contains env vars
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_ENV, Payload=b'{}')
        result_data = result['Payload']
        self.assertEqual(result['StatusCode'], 200)
        self.assertDictEqual(json.load(result_data), vars)

        # get function config and assert result contains env vars
        result = self.lambda_client.get_function_configuration(
            FunctionName=TEST_LAMBDA_NAME_ENV)
        self.assertEqual(result['Environment'], {'Variables': vars})

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_ENV)

    def test_invocation_with_qualifier(self):
        lambda_name = 'test_lambda_%s' % short_uid()
        bucket_name = 'test-bucket-lambda2'
        bucket_key = 'test_lambda.zip'

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True,
            libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.upload_fileobj(
            BytesIO(zip_file), bucket_name, bucket_key)

        # create lambda function
        response = self.lambda_client.create_function(
            FunctionName=lambda_name, Handler='handler.handler',
            Runtime=lambda_api.LAMBDA_RUNTIME_PYTHON27, Role='r1',
            Code={
                'S3Bucket': bucket_name,
                'S3Key': bucket_key
            },
            Publish=True
        )

        self.assertIn('Version', response)

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = self.lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=data_before,
            Qualifier=response['Version']
        )
        data_after = json.loads(result['Payload'].read())
        self.assertEqual(json.loads(to_str(data_before)), data_after['event'])

        context = data_after['context']
        self.assertEqual(response['Version'], context['function_version'])
        self.assertEqual(lambda_name, context['function_name'])

        # assert that logs are present
        expected = ['Lambda log message - print function']
        if use_docker():
            # Note that during regular test execution, nosetests captures the output from
            # the logging module - hence we can only expect this when running in Docker
            expected.append('.*Lambda log message - logging module')
        self.check_lambda_logs(lambda_name, expected_lines=expected)

        # clean up
        testutil.delete_lambda_function(lambda_name)

    def test_upload_lambda_from_s3(self):
        lambda_name = 'test_lambda_%s' % short_uid()
        bucket_name = 'test-bucket-lambda'
        bucket_key = 'test_lambda.zip'

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True,
            libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.upload_fileobj(
            BytesIO(zip_file), bucket_name, bucket_key)

        # create lambda function
        self.lambda_client.create_function(
            FunctionName=lambda_name, Handler='handler.handler',
            Runtime=lambda_api.LAMBDA_RUNTIME_PYTHON27, Role='r1',
            Code={
                'S3Bucket': bucket_name,
                'S3Key': bucket_key
            }
        )

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = self.lambda_client.invoke(
            FunctionName=lambda_name, Payload=data_before)
        data_after = json.loads(result['Payload'].read())
        self.assertEqual(json.loads(to_str(data_before)), data_after['event'])

        context = data_after['context']
        self.assertEqual('$LATEST', context['function_version'])
        self.assertEqual(lambda_name, context['function_name'])

        # clean up
        testutil.delete_lambda_function(lambda_name)

    def test_python_lambda_running_in_docker(self):
        if not use_docker():
            return

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON3, libs=TEST_LAMBDA_LIBS,
            func_name=TEST_LAMBDA_NAME_PY3, runtime=LAMBDA_RUNTIME_PYTHON36)

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_PY3, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_PY3)

    def test_handler_in_submodule(self):
        func_name = 'lambda-%s' % short_uid()
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True,
            libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON36,
            file_name='abc/def/main.py')
        testutil.create_lambda_function(func_name=func_name, zip_file=zip_file,
                                        handler='abc.def.main.handler', runtime=LAMBDA_RUNTIME_PYTHON36)

        # invoke function and assert result
        result = self.lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
        result_data = json.loads(result['Payload'].read())
        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(result_data['event'], json.loads('{}'))

    def test_python3_runtime_multiple_create_with_conflicting_module(self):
        original_do_use_docker = lambda_api.DO_USE_DOCKER
        try:
            # always use the local runner
            lambda_api.DO_USE_DOCKER = False

            python3_with_settings1 = load_file(TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE1, mode='rb')
            python3_with_settings2 = load_file(TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE2, mode='rb')

            lambda_name1 = 'test1-%s' % short_uid()
            testutil.create_lambda_function(func_name=lambda_name1,
                                            zip_file=python3_with_settings1,
                                            runtime=LAMBDA_RUNTIME_PYTHON36,
                                            handler='handler1.handler')

            lambda_name2 = 'test2-%s' % short_uid()
            testutil.create_lambda_function(func_name=lambda_name2,
                                            zip_file=python3_with_settings2,
                                            runtime=LAMBDA_RUNTIME_PYTHON36,
                                            handler='handler2.handler')

            result1 = self.lambda_client.invoke(FunctionName=lambda_name1, Payload=b'{}')
            result_data1 = result1['Payload'].read()

            result2 = self.lambda_client.invoke(FunctionName=lambda_name2, Payload=b'{}')
            result_data2 = result2['Payload'].read()

            self.assertEqual(result1['StatusCode'], 200)
            self.assertIn('setting1', to_str(result_data1))

            self.assertEqual(result2['StatusCode'], 200)
            self.assertIn('setting2', to_str(result_data2))

            # clean up
            testutil.delete_lambda_function(lambda_name1)
            testutil.delete_lambda_function(lambda_name2)
        finally:
            lambda_api.DO_USE_DOCKER = original_do_use_docker

    def test_lambda_subscribe_sns_topic(self):
        function_name = '{}-{}'.format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())

        testutil.create_lambda_function(handler_file=TEST_LAMBDA_ECHO_FILE,
                                        func_name=function_name, runtime=LAMBDA_RUNTIME_PYTHON36)

        topic = self.sns_client.create_topic(Name=TEST_SNS_TOPIC_NAME)
        topic_arn = topic['TopicArn']

        self.sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol='lambda',
            Endpoint=lambda_api.func_arn(function_name),
        )

        subject = '[Subject] Test subject'
        message = 'Hello world.'
        self.sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )

        events = retry(check_expected_lambda_log_events_length, retries=3,
                       sleep=1, function_name=function_name, expected_length=1)
        notification = events[0]['Records'][0]['Sns']

        self.assertIn('Subject', notification)
        self.assertEqual(notification['Subject'], subject)

    def test_lambda_send_message_to_sqs(self):
        function_name = '{}-{}'.format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())
        queue_name = 'lambda-queue-{}'.format(short_uid())

        sqs_client = aws_stack.connect_to_service('sqs')

        testutil.create_lambda_function(handler_file=TEST_LAMBDA_SEND_MESSAGE_FILE,
                                        func_name=function_name,
                                        runtime=LAMBDA_RUNTIME_PYTHON36)

        queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']

        event = {
            'message': 'message-from-test-lambda-{}'.format(short_uid()),
            'queue_name': queue_name,
            'region_name': config.DEFAULT_REGION
        }

        self.lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps(event)
        )

        # assert that message has been received on the Queue
        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=['All'])
            self.assertGreater(len(rs['Messages']), 0)
            return rs['Messages'][0]

        message = retry(receive_message, retries=3, sleep=2)
        self.assertEqual(message['Body'], event['message'])

        # clean up
        testutil.delete_lambda_function(function_name)
        sqs_client.delete_queue(QueueUrl=queue_url)

    def test_lambda_put_item_to_dynamodb(self):
        table_name = 'ddb-table-{}'.format(short_uid())
        function_name = '{}-{}'.format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())

        aws_stack.create_dynamodb_table(table_name, partition_key='id')

        testutil.create_lambda_function(handler_file=TEST_LAMBDA_PUT_ITEM_FILE,
                                        func_name=function_name,
                                        runtime=LAMBDA_RUNTIME_PYTHON36)

        data = {
            short_uid(): 'data-{}'.format(i)
            for i in range(3)
        }

        event = {
            'table_name': table_name,
            'region_name': config.DEFAULT_REGION,
            'items': [{'id': k, 'data': v} for k, v in data.items()]
        }

        self.lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps(event)
        )

        dynamodb = aws_stack.connect_to_resource('dynamodb')
        rs = dynamodb.Table(table_name).scan()
        items = rs['Items']

        self.assertEqual(len(items), len(data.keys()))
        for item in items:
            self.assertEqual(data[item['id']], item['data'])

        # clean up
        testutil.delete_lambda_function(function_name)

        dynamodb_client = aws_stack.connect_to_service('dynamodb')
        dynamodb_client.delete_table(TableName=table_name)

    def test_lambda_start_stepfunctions_execution(self):
        function_name = '{}-{}'.format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())
        resource_lambda_name = '{}-{}'.format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())
        state_machine_name = 'state-machine-{}'.format(short_uid())

        testutil.create_lambda_function(handler_file=TEST_LAMBDA_START_EXECUTION_FILE,
                                        func_name=function_name,
                                        runtime=LAMBDA_RUNTIME_PYTHON36)

        testutil.create_lambda_function(handler_file=TEST_LAMBDA_ECHO_FILE,
                                        func_name=resource_lambda_name,
                                        runtime=LAMBDA_RUNTIME_PYTHON36)

        state_machine_def = {
            'StartAt': 'step1',
            'States': {
                'step1': {
                    'Type': 'Task',
                    'Resource': aws_stack.lambda_function_arn(resource_lambda_name),
                    'ResultPath': '$.result_value',
                    'End': True
                }
            }
        }

        sfn_client = aws_stack.connect_to_service('stepfunctions')
        rs = sfn_client.create_state_machine(
            name=state_machine_name,
            definition=json.dumps(state_machine_def),
            roleArn=aws_stack.role_arn('sfn_role')
        )
        sm_arn = rs['stateMachineArn']

        self.lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps({
                'state_machine_arn': sm_arn,
                'region_name': config.DEFAULT_REGION,
                'input': {}
            })
        )
        time.sleep(1)

        rs = sfn_client.list_executions(
            stateMachineArn=sm_arn
        )

        # assert that state machine get executed 1 time
        self.assertEqual(
            len([ex for ex in rs['executions'] if ex['stateMachineArn'] == sm_arn]),
            1
        )

        # clean up
        testutil.delete_lambda_function(function_name)
        testutil.delete_lambda_function(resource_lambda_name)

        # clean up
        sfn_client.delete_state_machine(stateMachineArn=sm_arn)

    def create_multiple_lambda_permissions(self):
        iam_client = aws_stack.connect_to_service('iam')
        lambda_client = aws_stack.connect_to_service('lambda')
        role_name = 'role-{}'.format(short_uid())
        assume_policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'sts:AssumeRole',
                    'Principal': {'Service': 'lambda.amazonaws.com'}
                }
            ]
        }

        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document)
        )

        Util.create_function('testLambda', TEST_LAMBDA_NAME_PY,
                             runtime=LAMBDA_RUNTIME_PYTHON37, libs=TEST_LAMBDA_LIBS)

        action = 'lambda:InvokeFunction'
        sid = 'logs'
        resp = lambda_client.add_permission(FunctionName='testLambda', Action=action,
                                            StatementId=sid, Principal='logs.amazonaws.com')
        self.assertIn('Statement', resp)

        sid = 'kinesis'
        resp = lambda_client.add_permission(FunctionName='testLambda', Action=action,
                                            StatementId=sid, Principal='kinesis.amazonaws.com')

        self.assertIn('Statement', resp)
        # delete lambda
        testutil.delete_lambda_function(TEST_LAMBDA_PYTHON)


class TestNodeJSRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_nodejs_lambda_running_in_docker(self):
        if not use_docker():
            return

        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JS,
            handler_file=TEST_LAMBDA_NODEJS,
            handler='lambda_integration.handler',
            runtime=LAMBDA_RUNTIME_NODEJS810
        )
        ctx = {'custom': {'foo': 'bar'},
               'client': {'snap': ['crackle', 'pop']},
               'env': {'fizz': 'buzz'}}

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JS, Payload=b'{}',
            ClientContext=to_str(base64.b64encode(to_bytes(json.dumps(ctx)))))

        result_data = result['Payload'].read()
        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(json.loads(json.loads(result_data)['context']['clientContext']).
                         get('custom').get('foo'), 'bar')

        # assert that logs are present
        expected = ['.*Node.js Lambda handler executing.']
        self.check_lambda_logs(TEST_LAMBDA_NAME_JS, expected_lines=expected)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JS)

    def test_invoke_nodejs_lambda(self):
        if not use_docker():
            return

        handler_file = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_handler.js')
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JS,
            zip_file=testutil.create_zip_file(handler_file, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS12X,
            handler='lambda_handler.handler'
        )

        rs = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JS,
            Payload=json.dumps({
                'event_type': 'test_lambda'
            })
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        events = get_lambda_log_events(TEST_LAMBDA_NAME_JS)
        self.assertGreater(len(events), 0)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JS)


class TestCustomRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_nodejs_lambda_running_in_docker(self):
        if not use_docker():
            return

        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_CUSTOM_RUNTIME,
            handler_file=TEST_LAMBDA_CUSTOM_RUNTIME,
            handler='function.handler',
            runtime=LAMBDA_RUNTIME_PROVIDED
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_CUSTOM_RUNTIME,
            Payload=b'{"text":"bar with \'quotes\\""}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(
            to_str(result_data).strip(),
            """Echoing request: '{"text": "bar with \'quotes\\""}'""")

        # assert that logs are present
        expected = ['.*Custom Runtime Lambda handler executing.']
        self.check_lambda_logs(
            TEST_LAMBDA_NAME_CUSTOM_RUNTIME, expected_lines=expected)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_CUSTOM_RUNTIME)


class TestDotNetCoreRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')
        cls.zip_file_content2 = load_file(TEST_LAMBDA_DOTNETCORE2, mode='rb')
        cls.zip_file_content31 = load_file(TEST_LAMBDA_DOTNETCORE31, mode='rb')

    def __run_test(self, func_name, zip_file, handler, runtime, expected_lines):
        if not use_docker():
            return

        testutil.create_lambda_function(
            func_name=func_name,
            zip_file=zip_file,
            handler=handler,
            runtime=runtime)
        result = self.lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')
        # TODO make lambda log checks more resilient to various formats
        # self.check_lambda_logs(func_name, expected_lines=expected_lines)

        testutil.delete_lambda_function(func_name)

    def test_dotnetcore2_lambda_running_in_docker(self):
        self.__run_test(
            func_name=TEST_LAMBDA_NAME_DOTNETCORE2,
            zip_file=self.zip_file_content2,
            handler='DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler',
            runtime=LAMBDA_RUNTIME_DOTNETCORE2,
            expected_lines=['Running .NET Core 2.0 Lambda'])

    def test_dotnetcore31_lambda_running_in_docker(self):
        self.__run_test(
            func_name=TEST_LAMBDA_NAME_DOTNETCORE31,
            zip_file=self.zip_file_content31,
            handler='dotnetcore31::dotnetcore31.Function::FunctionHandler',
            runtime=LAMBDA_RUNTIME_DOTNETCORE31,
            expected_lines=['Running .NET Core 3.1 Lambda'])


class TestRubyRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_ruby_lambda_running_in_docker(self):
        if not use_docker():
            return

        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_RUBY,
            handler_file=TEST_LAMBDA_RUBY,
            handler='lambda_integration.handler',
            runtime=LAMBDA_RUNTIME_RUBY25
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_RUBY, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_RUBY)


class TestJavaRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

        # deploy lambda - Java
        if not os.path.exists(TEST_LAMBDA_JAVA):
            mkdir(os.path.dirname(TEST_LAMBDA_JAVA))
            download(TEST_LAMBDA_JAR_URL, TEST_LAMBDA_JAVA)

        # Lambda supports single JAR deployments without the zip,
        # so we upload the JAR directly.
        cls.test_java_jar = load_file(TEST_LAMBDA_JAVA, mode='rb')
        cls.test_java_zip = testutil.create_zip_file(TEST_LAMBDA_JAVA, get_content=True)
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JAVA,
            zip_file=cls.test_java_jar,
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.LambdaHandler'
        )

        # deploy lambda - Java with stream handler
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JAVA_STREAM,
            zip_file=cls.test_java_jar,
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.LambdaStreamHandler'
        )

        # deploy lambda - Java with serializable input object
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JAVA_SERIALIZABLE,
            zip_file=cls.test_java_zip,
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.SerializedInputLambdaHandler'
        )

    @classmethod
    def tearDownClass(cls):
        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA_STREAM)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA_SERIALIZABLE)

    def test_java_runtime(self):
        self.assertIsNotNone(self.test_java_jar)

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('LinkedHashMap', to_str(result_data))

    def test_java_runtime_with_lib(self):
        java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode='rb')

        # create ZIP file from JAR file
        jar_dir = new_tmp_dir()
        zip_dir = new_tmp_dir()
        unzip(TEST_LAMBDA_JAVA_WITH_LIB, jar_dir)
        shutil.move(os.path.join(jar_dir, 'lib'), os.path.join(zip_dir, 'lib'))
        jar_without_libs_file = testutil.create_zip_file(jar_dir)
        shutil.copy(jar_without_libs_file, os.path.join(zip_dir, 'lib', 'lambda.jar'))
        java_zip_with_lib = testutil.create_zip_file(zip_dir, get_content=True)

        for archive in [java_jar_with_lib, java_zip_with_lib]:
            lambda_name = 'test-%s' % short_uid()
            testutil.create_lambda_function(func_name=lambda_name,
                                            zip_file=archive, runtime=LAMBDA_RUNTIME_JAVA8,
                                            handler='cloud.localstack.sample.LambdaHandlerWithLib')

            result = self.lambda_client.invoke(FunctionName=lambda_name, Payload=b'{"echo":"echo"}')
            result_data = result['Payload'].read()

            self.assertEqual(result['StatusCode'], 200)
            self.assertIn('echo', to_str(result_data))
            # clean up
            testutil.delete_lambda_function(lambda_name)

    def test_sns_event(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, InvocationType='Event',
            Payload=b'{"Records": [{"Sns": {"Message": "{}"}}]}')

        self.assertEqual(result['StatusCode'], 202)

    def test_ddb_event(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, InvocationType='Event',
            Payload=b'{"Records": [{"dynamodb": {"Message": "{}"}}]}')

        self.assertEqual(result['StatusCode'], 202)

    def test_kinesis_invocation(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA,
            Payload=b'{"Records": [{"Kinesis": {"Data": "data", "PartitionKey": "partition"}}]}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('KinesisEvent', to_str(result_data))

    def test_kinesis_event(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, InvocationType='Event',
            Payload=b'{"Records": [{"Kinesis": {"Data": "data", "PartitionKey": "partition"}}]}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 202)
        self.assertEqual(to_str(result_data).strip(), '')

    def test_stream_handler(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA_STREAM, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

    def test_serializable_input_object(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA_SERIALIZABLE,
            Payload=b'{"bucket": "test_bucket", "key": "test_key"}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertDictEqual(
            json.loads(to_str(result_data)),
            {'validated': True, 'bucket': 'test_bucket', 'key': 'test_key'}
        )

    def test_trigger_java_lambda_through_sns(self):
        topic_name = 'topic-%s' % short_uid()
        function_name = 'func-%s' % short_uid()
        bucket_name = 'bucket-%s' % short_uid()
        key = 'key-%s' % short_uid()

        sns_client = aws_stack.connect_to_service('sns')
        topic_arn = sns_client.create_topic(Name=topic_name)['TopicArn']

        s3_client = aws_stack.connect_to_service('s3')

        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'TopicConfigurations': [
                    {
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*']
                    }
                ]
            }
        )

        testutil.create_lambda_function(
            func_name=function_name,
            zip_file=load_file(TEST_LAMBDA_JAVA, mode='rb'),
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.LambdaHandler'
        )

        sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol='lambda',
            Endpoint=aws_stack.lambda_function_arn(function_name)
        )

        s3_client.put_object(Bucket=bucket_name, Key=key, Body='something')
        time.sleep(2)

        # We got an event that confirm lambda invoked
        retry(function=check_expected_lambda_log_events_length,
              expected_length=1, retries=3, sleep=1,
              function_name=function_name)

        # clean up
        sns_client.delete_topic(TopicArn=topic_arn)
        testutil.delete_lambda_function(function_name)

        s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': key}]})
        s3_client.delete_bucket(Bucket=bucket_name)


class TestDockerBehaviour(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_prime_and_destroy_containers(self):
        # run these tests only for the "reuse containers" Lambda executor
        if not isinstance(lambda_api.LAMBDA_EXECUTOR,
                          lambda_executors.LambdaExecutorReuseContainers):
            return

        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = 'test_prime_and_destroy_containers'
        func_arn = lambda_api.func_arn(func_name)

        # make sure existing containers are gone
        executor.cleanup()
        self.assertEqual(len(executor.get_all_container_names()), 0)

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name, handler_file=TEST_LAMBDA_ENV, libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27, envvars={'Hello': 'World'})

        self.assertEqual(len(executor.get_all_container_names()), 0)
        self.assertDictEqual(executor.function_invoke_times, {})

        # invoke a few times.
        durations = []
        num_iterations = 3

        for i in range(0, num_iterations + 1):
            prev_invoke_time = None
            if i > 0:
                prev_invoke_time = executor.function_invoke_times[func_arn]

            start_time = time.time()
            self.lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
            duration = time.time() - start_time

            self.assertEqual(len(executor.get_all_container_names()), 1)

            # ensure the last invoke time is being updated properly.
            if i > 0:
                self.assertGreater(executor.function_invoke_times[func_arn], prev_invoke_time)
            else:
                self.assertGreater(executor.function_invoke_times[func_arn], 0)

            durations.append(duration)

        # the first call would have created the container. subsequent calls would reuse and be faster.
        for i in range(1, num_iterations + 1):
            self.assertLess(durations[i], durations[0])

        status = executor.get_docker_container_status(func_arn)
        self.assertEqual(status, 1)

        container_network = executor.get_docker_container_network(func_arn)
        self.assertEqual(container_network, 'default')

        executor.cleanup()
        status = executor.get_docker_container_status(func_arn)
        self.assertEqual(status, 0)

        self.assertEqual(len(executor.get_all_container_names()), 0)

        # clean up
        testutil.delete_lambda_function(func_name)

    def test_docker_command_for_separate_container_lambda_executor(self):
        # run these tests only for the "separate containers" Lambda executor
        if not isinstance(lambda_api.LAMBDA_EXECUTOR,
                          lambda_executors.LambdaExecutorSeparateContainers):
            return

        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = 'test_docker_command_for_separate_container_lambda_executor'
        func_arn = lambda_api.func_arn(func_name)

        handler = 'handler'
        lambda_cwd = '/app/lambda'
        network = 'compose_network'

        config.LAMBDA_DOCKER_NETWORK = network

        cmd = executor.prepare_execution(func_arn, {}, LAMBDA_RUNTIME_NODEJS810, '', handler, lambda_cwd)

        expected = 'docker run -v "%s":/var/task   --network="%s"  --rm "lambci/lambda:%s" "%s"' % (
            lambda_cwd, network, LAMBDA_RUNTIME_NODEJS810, handler)

        self.assertIn(('--network="%s"' % network), cmd, 'cmd=%s expected=%s' % (cmd, expected))

        config.LAMBDA_DOCKER_NETWORK = ''

    def test_destroy_idle_containers(self):
        # run these tests only for the "reuse containers" Lambda executor
        if not isinstance(lambda_api.LAMBDA_EXECUTOR,
                          lambda_executors.LambdaExecutorReuseContainers):
            return

        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = 'test_destroy_idle_containers'
        func_arn = lambda_api.func_arn(func_name)

        # make sure existing containers are gone
        executor.destroy_existing_docker_containers()
        self.assertEqual(len(executor.get_all_container_names()), 0)

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name, handler_file=TEST_LAMBDA_ENV, libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27, envvars={'Hello': 'World'})

        self.assertEqual(len(executor.get_all_container_names()), 0)

        self.lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
        self.assertEqual(len(executor.get_all_container_names()), 1)

        # try to destroy idle containers.
        executor.idle_container_destroyer()
        self.assertEqual(len(executor.get_all_container_names()), 1)

        # simulate an idle container
        executor.function_invoke_times[func_arn] = time.time() - lambda_executors.MAX_CONTAINER_IDLE_TIME_MS
        executor.idle_container_destroyer()
        self.assertEqual(len(executor.get_all_container_names()), 0)

        # clean up
        testutil.delete_lambda_function(func_name)


class Util(object):
    @classmethod
    def create_function(cls, file, name, runtime=None, libs=None):
        runtime = runtime or LAMBDA_RUNTIME_PYTHON27
        testutil.create_lambda_function(
            func_name=name, handler_file=file, libs=TEST_LAMBDA_LIBS, runtime=runtime)
