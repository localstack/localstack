import re
import os
import json
import time
import unittest
from io import BytesIO
from localstack import config
from localstack.constants import LOCALSTACK_ROOT_FOLDER, LOCALSTACK_MAVEN_VERSION
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, load_file, to_str, mkdir, download
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.services.awslambda.lambda_api import (
    LAMBDA_RUNTIME_NODEJS, LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_RUBY25, LAMBDA_RUNTIME_PYTHON27,
    LAMBDA_RUNTIME_PYTHON36, LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_NODEJS810, use_docker
)

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py')
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_python3.py')
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.js')
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.rb')
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, 'lambdas', 'dotnetcore2', 'dotnetcore2.zip')
TEST_LAMBDA_JAVA = os.path.join(LOCALSTACK_ROOT_FOLDER, 'localstack', 'infra', 'localstack-utils-tests.jar')
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_environment.py')

TEST_LAMBDA_NAME_PY = 'test_lambda_py'
TEST_LAMBDA_NAME_PY3 = 'test_lambda_py3'
TEST_LAMBDA_NAME_JS = 'test_lambda_js'
TEST_LAMBDA_NAME_RUBY = 'test_lambda_ruby'
TEST_LAMBDA_NAME_DOTNETCORE2 = 'test_lambda_dotnetcore2'
TEST_LAMBDA_NAME_JAVA = 'test_lambda_java'
TEST_LAMBDA_NAME_JAVA_STREAM = 'test_lambda_java_stream'
TEST_LAMBDA_NAME_JAVA_SERIALIZABLE = 'test_lambda_java_serializable'
TEST_LAMBDA_NAME_ENV = 'test_lambda_env'

MAVEN_BASE_URL = 'https://repo.maven.apache.org/maven2'
TEST_LAMBDA_JAR_URL = ('{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar').format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_BASE_URL, name='localstack-utils')

TEST_LAMBDA_LIBS = ['localstack', 'localstack_client', 'requests', 'psutil', 'urllib3', 'chardet', 'certifi', 'idna']


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
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_PY)

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
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_ENV),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_ENV,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27,
            envvars={'Hello': 'World'}
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_ENV, Payload=b'{}')
        result_data = result['Payload']

        self.assertEqual(result['StatusCode'], 200)
        self.assertDictEqual(json.load(result_data), {'Hello': 'World'})

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
        data_before = b'{"foo": "bar"}'
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
        data_before = b'{"foo": "bar"}'
        result = self.lambda_client.invoke(
            FunctionName=lambda_name, Payload=data_before)
        data_after = json.loads(result['Payload'].read())
        self.assertEqual(json.loads(to_str(data_before)), data_after['event'])

        context = data_after['context']
        self.assertEqual('$LATEST', context['function_version'])
        self.assertEqual(lambda_name, context['function_name'])

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
            runtime=LAMBDA_RUNTIME_NODEJS
        )
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JS, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertEqual(to_str(result_data).strip(), '{}')

        # assert that logs are present
        expected = ['.*Node.js Lambda handler executing.']
        self.check_lambda_logs(TEST_LAMBDA_NAME_JS, expected_lines=expected)


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
            zip_file=cls.test_java_jar,
            runtime=LAMBDA_RUNTIME_JAVA8,
            handler='cloud.localstack.sample.SerializedInputLambdaHandler'
        )

    def test_java_runtime(self):
        self.assertIsNotNone(self.test_java_jar)

        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA, Payload=b'{}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('LinkedHashMap', to_str(result_data))

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

    def test_kinesis_event(self):
        result = self.lambda_client.invoke(
            FunctionName=TEST_LAMBDA_NAME_JAVA,
            Payload=b'{"Records": [{"Kinesis": {"Data": "data", "PartitionKey": "partition"}}]}')
        result_data = result['Payload'].read()

        self.assertEqual(result['StatusCode'], 200)
        self.assertIn('KinesisEvent', to_str(result_data))

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
        executor.function_invoke_times[func_arn] = time.time() - 610
        executor.idle_container_destroyer()
        self.assertEqual(len(executor.get_all_container_names()), 0)
