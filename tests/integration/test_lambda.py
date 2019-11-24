import re
import os
import json
import time
import unittest
import six
from io import BytesIO
from localstack import config
from localstack.constants import LOCALSTACK_ROOT_FOLDER, LOCALSTACK_MAVEN_VERSION
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    short_uid, load_file, to_str, mkdir, download, run_safe, get_free_tcp_port, get_service_protocol)
from localstack.services.infra import start_proxy
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.services.generic_proxy import ProxyListener
from localstack.services.awslambda.lambda_api import (
    LAMBDA_RUNTIME_DOTNETCORE2, LAMBDA_RUNTIME_RUBY25, LAMBDA_RUNTIME_PYTHON27,
    use_docker, LAMBDA_RUNTIME_PYTHON36, LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_NODEJS810, LAMBDA_RUNTIME_CUSTOM_RUNTIME
)

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py')
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_python3.py')
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.js')
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.rb')
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, 'lambdas', 'dotnetcore2', 'dotnetcore2.zip')
TEST_LAMBDA_CUSTOM_RUNTIME = os.path.join(THIS_FOLDER, 'lambdas', 'custom-runtime')
TEST_LAMBDA_JAVA = os.path.join(LOCALSTACK_ROOT_FOLDER, 'localstack', 'infra', 'localstack-utils-tests.jar')
TEST_LAMBDA_JAVA_WITH_LIB = os.path.join(THIS_FOLDER, 'lambdas', 'java', 'lambda-function-with-lib-0.0.1.jar')
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_environment.py')

TEST_LAMBDA_NAME_PY = 'test_lambda_py'
TEST_LAMBDA_NAME_PY3 = 'test_lambda_py3'
TEST_LAMBDA_NAME_JS = 'test_lambda_js'
TEST_LAMBDA_NAME_RUBY = 'test_lambda_ruby'
TEST_LAMBDA_NAME_DOTNETCORE2 = 'test_lambda_dotnetcore2'
TEST_LAMBDA_NAME_CUSTOM_RUNTIME = 'test_lambda_custom_runtime'
TEST_LAMBDA_NAME_JAVA = 'test_lambda_java'
TEST_LAMBDA_NAME_JAVA_STREAM = 'test_lambda_java_stream'
TEST_LAMBDA_NAME_JAVA_SERIALIZABLE = 'test_lambda_java_serializable'
TEST_LAMBDA_NAME_JAVA_WITH_LIB = 'test_lambda_java_with_lib'
TEST_LAMBDA_NAME_ENV = 'test_lambda_env'

MAVEN_BASE_URL = 'https://repo.maven.apache.org/maven2'
TEST_LAMBDA_JAR_URL = ('{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar').format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_BASE_URL, name='localstack-utils')

TEST_LAMBDA_LIBS = ['localstack', 'localstack_client', 'requests',
    'psutil', 'urllib3', 'chardet', 'certifi', 'idna', 'pip', 'dns']


class LambdaTestBase(unittest.TestCase):

    def check_lambda_logs(self, func_name, expected_lines=[]):
        logs_client = aws_stack.connect_to_service('logs')
        log_group_name = '/aws/lambda/%s' % func_name
        streams = logs_client.describe_log_streams(logGroupName=log_group_name)['logStreams']
        streams = sorted(streams, key=lambda x: x['creationTime'], reverse=True)
        log_events = logs_client.get_log_events(
            logGroupName=log_group_name, logStreamName=streams[0]['logStreamName'])['events']
        log_messages = [e['message'] for e in log_events]
        for line in expected_lines:
            if '.*' in line:
                found = [re.match(line, m) for m in log_messages]
                if any(found):
                    continue
            self.assertIn(line, log_messages)


class TestLambdaBaseFeatures(unittest.TestCase):

    def test_forward_to_fallback_url_dynamodb(self):
        db_table = 'lambda-records'
        ddb_client = aws_stack.connect_to_service('dynamodb')

        def num_items():
            return len((run_safe(ddb_client.scan, TableName=db_table) or {'Items': []})['Items'])

        items_before = num_items()
        self._run_forward_to_fallback_url('dynamodb://%s' % db_table)
        items_after = num_items()
        self.assertEqual(items_after, items_before + 3)

    def test_forward_to_fallback_url_http(self):
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append(data)
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())

        items_before = len(records)
        self._run_forward_to_fallback_url('%s://localhost:%s' % (get_service_protocol(), local_port))
        items_after = len(records)
        self.assertEqual(items_after, items_before + 3)
        proxy.stop()

    def _run_forward_to_fallback_url(self, url, num_requests=3):
        lambda_client = aws_stack.connect_to_service('lambda')
        config.LAMBDA_FALLBACK_URL = url
        try:
            for i in range(num_requests):
                lambda_client.invoke(FunctionName='non-existing-lambda-%s' % i,
                    Payload=b'{}', InvocationType='RequestResponse')
        finally:
            config.LAMBDA_FALLBACK_URL = ''

    def test_add_lambda_permission(self):
        iam_client = aws_stack.connect_to_service('iam')
        lambda_client = aws_stack.connect_to_service('lambda')

        # create lambda permission
        action = 'lambda:InvokeFunction'
        resp = lambda_client.add_permission(FunctionName=TEST_LAMBDA_NAME_PY, Action=action,
            StatementId='s3', Principal='s3.amazonaws.com', SourceArn=aws_stack.s3_bucket_arn('test-bucket'))
        self.assertIn('Statement', resp)
        # fetch lambda policy
        policy = lambda_client.get_policy(FunctionName=TEST_LAMBDA_NAME_PY)['Policy']
        self.assertIsInstance(policy, six.string_types)
        policy = json.loads(to_str(policy))
        self.assertEqual(policy['Statement'][0]['Action'], action)
        self.assertEqual(policy['Statement'][0]['Resource'], lambda_api.func_arn(TEST_LAMBDA_NAME_PY))
        # fetch IAM policy
        policies = iam_client.list_policies(Scope='Local', MaxItems=500)['Policies']
        matching = [p for p in policies if p['PolicyName'] == 'lambda_policy_%s' % TEST_LAMBDA_NAME_PY]
        self.assertEqual(len(matching), 1)
        self.assertIn(':policy/', matching[0]['Arn'])

        # remove permission that we just added
        resp = lambda_client.remove_permission(FunctionName=TEST_LAMBDA_NAME_PY,
            StatementId=resp['Statement'], Qualifier='qual1', RevisionId='r1')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)


class TestPythonRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')
        cls.s3_client = aws_stack.connect_to_service('s3')

        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_PY,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )

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
            Payload=b'{}', InvocationType='RequestResponse')
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
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_ENV), get_content=True,
            libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_ENV, zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27, envvars=vars)

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
        bucket_name = 'test_bucket_lambda2'
        bucket_key = 'test_lambda.zip'

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
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
        bucket_name = 'test_bucket_lambda'
        bucket_key = 'test_lambda.zip'

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
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

        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON3),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_PY3,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

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


class TestNodeJSRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_nodejs_lambda_running_in_docker(self):
        if not use_docker():
            return

        zip_file = testutil.create_zip_file(
            TEST_LAMBDA_NODEJS, get_content=True)
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JS,
            zip_file=zip_file,
            handler='lambda_integration.handler',
            runtime=LAMBDA_RUNTIME_NODEJS810
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JS, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

        # assert that logs are present
        expected = ['.*Node.js Lambda handler executing.']
        self.check_lambda_logs(TEST_LAMBDA_NAME_JS, expected_lines=expected)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JS)


class TestCustomRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_nodejs_lambda_running_in_docker(self):
        if not use_docker():
            return

        zip_file = testutil.create_zip_file(
            TEST_LAMBDA_CUSTOM_RUNTIME, get_content=True)
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_CUSTOM_RUNTIME,
            zip_file=zip_file,
            handler='function.handler',
            runtime=LAMBDA_RUNTIME_CUSTOM_RUNTIME
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

        # lambda .NET Core 2.0 is already a zip
        zip_file = TEST_LAMBDA_DOTNETCORE2
        cls.zip_file_content = None
        with open(zip_file, 'rb') as file_obj:
            cls.zip_file_content = file_obj.read()

    def test_dotnet_lambda_running_in_docker(self):
        if not use_docker():
            return

        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_DOTNETCORE2,
            zip_file=self.zip_file_content,
            handler='DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler',
            runtime=LAMBDA_RUNTIME_DOTNETCORE2
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_DOTNETCORE2, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

        # assert that logs are present
        expected = ['Running .NET Core 2.0 Lambda']
        self.check_lambda_logs(TEST_LAMBDA_NAME_DOTNETCORE2, expected_lines=expected)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_DOTNETCORE2)


class TestRubyRuntimes(LambdaTestBase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')

    def test_ruby_lambda_running_in_docker(self):
        if not use_docker():
            return

        zip_file = testutil.create_zip_file(
            TEST_LAMBDA_RUBY, get_content=True)
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_RUBY,
            zip_file=zip_file,
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

        # upload the JAR directly
        cls.test_java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode='rb')
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_JAVA_WITH_LIB,
            zip_file=cls.test_java_jar_with_lib,
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.LambdaHandlerWithLib'
        )

    @classmethod
    def tearDownClass(cls):
        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA_STREAM)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA_SERIALIZABLE)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_JAVA_WITH_LIB)

    def test_java_runtime(self):
        self.assertIsNotNone(self.test_java_jar)

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('LinkedHashMap', to_str(result_data))

    def test_java_runtime_with_lib(self):
        self.assertIsNotNone(self.test_java_jar_with_lib)

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA_WITH_LIB, Payload=b'{"echo":"echo"}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('echo', to_str(result_data))

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
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_ENV),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=func_name,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27,
            envvars={'Hello': 'World'}
        )

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
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_ENV),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=func_name,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27,
            envvars={'Hello': 'World'}
        )

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
