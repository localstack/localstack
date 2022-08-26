import base64
import json
import logging
import os
import re
import shutil
import time
from io import BytesIO

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda.lambda_api import use_docker
from localstack.services.install import GO_RUNTIME_VERSION, download_and_extract, TEST_LAMBDA_JAVA, \
    INSTALL_PATH_LOCALSTACK_FAT_JAR
from localstack.utils import testutil
from localstack.utils.archives import unzip
from localstack.utils.files import load_file, mkdir, cp_r, save_file, new_tmp_dir
from localstack.utils.functions import run_safe
from localstack.utils.platform import get_os, get_arch
from localstack.utils.strings import short_uid, to_str, to_bytes
from localstack.utils.sync import retry, poll_condition
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_CUSTOM_RUNTIME
from localstack.utils.testutil import get_lambda_log_events, check_expected_lambda_log_events_length, \
    create_lambda_archive
from tests.integration.awslambda.test_lambda import read_streams, TEST_LAMBDA_INTEGRATION_NODEJS, \
    TEST_LAMBDA_NODEJS, TEST_LAMBDA_NODEJS_ES6, TEST_LAMBDA_RUBY, TEST_LAMBDA_DOTNETCORE31, TEST_LAMBDA_DOTNET6, \
    TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS, TEST_LAMBDA_PYTHON, TEST_LAMBDA_LIBS, TEST_LAMBDA_SEND_MESSAGE_FILE, \
    TEST_LAMBDA_PUT_ITEM_FILE, TEST_LAMBDA_START_EXECUTION_FILE, TEST_LAMBDA_PYTHON_ECHO, TEST_LAMBDA_PYTHON_VERSION, \
    TEST_LAMBDA_PYTHON_UNHANDLED_ERROR, TEST_LAMBDA_ENV, TEST_LAMBDA_JAVA_WITH_LIB, TEST_GOLANG_LAMBDA_URL_TEMPLATE, \
    THIS_FOLDER
from localstack.testing.aws.lambda_utils import is_old_provider

PYTHON_TEST_RUNTIMES = (
    [
        Runtime.python3_9,
        Runtime.python3_7,
        Runtime.python3_8,
        Runtime.python3_9,
    ]
    if use_docker()
    else [Runtime.python3_9]
)
NODE_TEST_RUNTIMES = (
    [
        Runtime.nodejs12X,
        Runtime.nodejs14X,
        Runtime.nodejs16X
    ]
    if use_docker()
    else [Runtime.nodejs16X]
)
JAVA_TEST_RUNTIMES = (
    [
        Runtime.java8,
        Runtime.java8_al2,
        Runtime.java11,
    ]
    if use_docker()
    else [Runtime.java11]
)


PROVIDED_TEST_RUNTIMES = [
    Runtime.provided,
    # TODO remove skip once we use correct images
    pytest.param(
        Runtime.provided_al2,
        marks=pytest.mark.skipif(
            is_old_provider(), reason="curl missing in provided.al2 lambci image"
        ),
    ),
]


parametrize_python_runtimes = pytest.mark.parametrize("runtime", PYTHON_TEST_RUNTIMES)
parametrize_node_runtimes = pytest.mark.parametrize("runtime", NODE_TEST_RUNTIMES)
parametrize_java_runtimes = pytest.mark.parametrize("runtime", JAVA_TEST_RUNTIMES)


class TestNodeJSRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker nodejs runtimes not applicable if run locally"
    )
    @parametrize_node_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_nodejs_lambda_with_context(
        self, lambda_client, create_lambda_function, runtime, check_lambda_logs, snapshot
    ):
        """Test context of nodejs lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_INTEGRATION_NODEJS,
            handler="lambda_integration.handler",
            runtime=runtime,
        )
        snapshot.match("creation", creation_response)
        ctx = {
            "custom": {"foo": "bar"},
            "client": {"snap": ["crackle", "pop"]},
            "env": {"fizz": "buzz"},
        }

        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
            ClientContext=to_str(base64.b64encode(to_bytes(json.dumps(ctx)))),
        )
        result = read_streams(result)
        snapshot.match("invocation", result)

        result_data = result["Payload"]
        assert 200 == result["StatusCode"]
        client_context = json.loads(result_data)["context"]["clientContext"]
        # TODO in the old provider, for some reason this is necessary. That is invalid behavior
        if is_old_provider():
            client_context = json.loads(client_context)
        assert "bar" == client_context.get("custom").get("foo")

        # assert that logs are present
        expected = [".*Node.js Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=15)

    @parametrize_node_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_invoke_nodejs_lambda(
        self, lambda_client, create_lambda_function, runtime, logs_client, snapshot
    ):
        """Test simple nodejs lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=runtime,
            handler="lambda_handler.handler",
        )
        snapshot.match("creation-result", result)

        rs = lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps({"event_type": "test_lambda"}),
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invocation-result", rs)

        payload = rs["Payload"]
        response = json.loads(payload)
        assert "response from localstack lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) > 0

        retry(assert_events, retries=10)

    @pytest.mark.parametrize("runtime", (Runtime.nodejs14X, Runtime.nodejs16X))
    @pytest.mark.skip_snapshot_verify
    @pytest.mark.skipif(
        not use_docker(), reason="ES6 support is only guaranteed when using the docker executor"
    )
    def test_invoke_nodejs_es6_lambda(
        self, lambda_client, create_lambda_function, logs_client, snapshot, runtime
    ):
        """Test simple nodejs lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS_ES6, get_content=True),
            runtime=runtime,
            handler="lambda_handler_es6.handler",
        )
        snapshot.match("creation-result", result)

        rs = lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps({"event_type": "test_lambda"}),
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invocation-result", rs)

        payload = rs["Payload"]
        response = json.loads(payload)
        assert "response from localstack lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) > 0

        retry(assert_events, retries=10)

    @parametrize_node_runtimes
    @pytest.mark.skip_snapshot_verify(
        paths=["$..LogResult", "$..Payload.headers", "$..Payload.isBase64Encoded"]
    )
    def test_invoke_nodejs_lambda_with_payload_containing_quotes(
        self, lambda_client, create_lambda_function, runtime, logs_client, snapshot
    ):
        """Test nodejs invocation of payload with quotes"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=runtime,
            handler="lambda_handler.handler",
        )

        test_string = "test_string' with some quotes"
        body = f'{{"test_var": "{test_string}"}}'
        rs = lambda_client.invoke(
            FunctionName=function_name,
            Payload=body,
        )

        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invoke-result", rs)
        response = json.loads(rs["Payload"])
        assert "response from localstack lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) > 0
            assert test_string in str(events[0])

        retry(assert_events, retries=10)


class TestGolangRuntimes:
    @pytest.mark.skip_snapshot_verify
    @pytest.mark.skip_offline
    def test_golang_lambda(self, lambda_client, tmp_path, create_lambda_function, snapshot):
        """Test simple golang lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # fetch platform-specific example handler
        url = TEST_GOLANG_LAMBDA_URL_TEMPLATE.format(
            version=GO_RUNTIME_VERSION,
            os=get_os(),
            arch=get_arch(),
        )
        handler = tmp_path / "go-handler"
        download_and_extract(url, handler)

        # create function
        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=handler,
            handler="handler",
            runtime=Runtime.go1_x,
        )
        snapshot.match("create-result", create_result)

        # invoke
        result = lambda_client.invoke(
            FunctionName=func_name, Payload=json.dumps({"name": "pytest"})
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]
        assert result["StatusCode"] == 200
        assert result_data.strip() == '"Hello pytest!"'


class TestRubyRuntimes:
    @pytest.mark.skipif(not use_docker(), reason="ruby runtimes not supported in local invocation")
    @pytest.mark.skip_snapshot_verify
    def test_ruby_lambda_running_in_docker(self, lambda_client, create_lambda_function, snapshot):
        """Test simple ruby lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_RUBY,
            handler="lambda_integration.handler",
            runtime=Runtime.ruby2_7,
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "{}" == to_str(result_data).strip()


class TestDotNetCoreRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Dotnet functions only supported with docker executor"
    )
    @pytest.mark.parametrize(
        "zip_file,handler,runtime,expected_lines",
        [
            (
                TEST_LAMBDA_DOTNETCORE31,
                "dotnetcore31::dotnetcore31.Function::FunctionHandler",
                Runtime.dotnetcore3_1,
                ["Running .NET Core 3.1 Lambda"],
            ),
            (
                TEST_LAMBDA_DOTNET6,
                "dotnet6::dotnet6.Function::FunctionHandler",
                Runtime.dotnet6,
                ["Running .NET 6 Lambda"],
            ),
        ],
        ids=["dotnetcore3.1", "dotnet6"],
    )
    @pytest.mark.skip_snapshot_verify
    def test_dotnet_lambda(
        self,
        zip_file,
        handler,
        runtime,
        expected_lines,
        lambda_client,
        create_lambda_function,
        snapshot,
    ):
        """Test simple dotnet lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"

        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=load_file(zip_file, mode="rb"),
            handler=handler,
            runtime=runtime,
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "{}" == result_data.strip()
        # ODO make lambda log checks more resilient to various formats
        # self.check_lambda_logs(func_name, expected_lines=expected_lines)


class TestJavaRuntimes:
    @pytest.fixture(scope="class")
    def test_java_jar(self) -> bytes:
        # The TEST_LAMBDA_JAVA jar file is downloaded with `make init-testlibs`.
        java_file = load_file(TEST_LAMBDA_JAVA, mode="rb")
        if not java_file:
            raise Exception(
                f"Test dependency {TEST_LAMBDA_JAVA} not found."
                "Please make sure to run 'make init-testlibs' to ensure the file is available."
            )
        return java_file

    @pytest.fixture(scope="class")
    def test_java_zip(self, tmpdir_factory, test_java_jar) -> bytes:
        tmpdir = tmpdir_factory.mktemp("tmp-java-zip")
        zip_lib_dir = os.path.join(tmpdir, "lib")
        zip_jar_path = os.path.join(zip_lib_dir, "test.lambda.jar")
        mkdir(zip_lib_dir)
        cp_r(
            INSTALL_PATH_LOCALSTACK_FAT_JAR,
            os.path.join(zip_lib_dir, "executor.lambda.jar"),
        )
        save_file(zip_jar_path, test_java_jar)
        return testutil.create_zip_file(tmpdir, get_content=True)

    @pytest.fixture(
        params=JAVA_TEST_RUNTIMES,
    )
    def simple_java_lambda(self, create_lambda_function, test_java_zip, request):
        function_name = f"java-test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=request.param,
            handler="cloud.localstack.sample.LambdaHandler",
        )
        return function_name

    @pytest.mark.skip_snapshot_verify(
        paths=["$..invoke-result.LogResult", "$..invoke-result.Payload"]
    )
    def test_java_runtime(self, lambda_client, simple_java_lambda, snapshot):
        """Tests a simple java lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            Payload=b'{"echo":"echo"}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        # TODO: find out why the assertion below does not work in Travis-CI! (seems to work locally)
        assert "LinkedHashMap" in to_str(result_data)
        assert result_data is not None

    @pytest.mark.skip_snapshot_verify(
        paths=["$..invoke-result.LogResult", "$..invoke-result.Payload"]
    )
    def test_java_runtime_with_large_payload(
        self, lambda_client, simple_java_lambda, caplog, snapshot
    ):
        """Tests a invocation against a java lambda with a 5MB payload"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        payload = {"test": "test123456" * 100 * 1000 * 5}  # 5MB payload
        payload = to_bytes(json.dumps(payload))

        result = lambda_client.invoke(FunctionName=simple_java_lambda, Payload=payload)
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "LinkedHashMap" in result_data
        assert result_data is not None

    @pytest.mark.skip_snapshot_verify
    def test_java_runtime_with_lib(self, lambda_client, create_lambda_function, snapshot):
        """Test lambda creation/invocation with different deployment package types (jar, zip, zip-with-gradle)"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode="rb")

        # create ZIP file from JAR file
        jar_dir = new_tmp_dir()
        zip_dir = new_tmp_dir()
        unzip(TEST_LAMBDA_JAVA_WITH_LIB, jar_dir)
        zip_lib_dir = os.path.join(zip_dir, "lib")
        shutil.move(os.path.join(jar_dir, "lib"), zip_lib_dir)
        jar_without_libs_file = testutil.create_zip_file(jar_dir)
        shutil.copy(jar_without_libs_file, os.path.join(zip_lib_dir, "lambda.jar"))
        java_zip_with_lib = testutil.create_zip_file(zip_dir, get_content=True)

        java_zip_with_lib_gradle = load_file(
            os.path.join(
                THIS_FOLDER,
                "functions/java/lambda_echo/build/distributions/lambda-function-built-by-gradle.zip"
            ),
            mode="rb",
        )

        for archive_desc, archive in [
            ("jar-with-lib", java_jar_with_lib),
            ("zip-with-lib", java_zip_with_lib),
            ("zip-with-lib-gradle", java_zip_with_lib_gradle),
        ]:
            lambda_name = f"test-function-{short_uid()}"
            create_result = create_lambda_function(
                func_name=lambda_name,
                zip_file=archive,
                runtime=Runtime.java11,
                handler="cloud.localstack.sample.LambdaHandlerWithLib",
            )
            snapshot.match(f"create-result-{archive_desc}", create_result)

            result = lambda_client.invoke(FunctionName=lambda_name, Payload=b'{"echo":"echo"}')
            result = read_streams(result)
            snapshot.match(f"invoke-result-{archive_desc}", result)
            result_data = result["Payload"]

            assert 200 == result["StatusCode"]
            assert "echo" in to_str(result_data)

    def test_sns_event(self, lambda_client, simple_java_lambda):
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=b'{"Records": [{"Sns": {"Message": "{}"}}]}',
        )

        assert 202 == result["StatusCode"]

    def test_ddb_event(self, lambda_client, simple_java_lambda):
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=b'{"Records": [{"dynamodb": {"Message": "{}"}}]}',
        )

        assert 202 == result["StatusCode"]

    @parametrize_java_runtimes
    def test_kinesis_invocation(
        self, lambda_client, create_lambda_function, test_java_zip, runtime
    ):
        payload = (
            b'{"Records": [{'
            b'"kinesis": {"data": "dGVzdA==", "partitionKey": "partition"},'
            b'"eventID": "shardId-000000000001:12345678901234567890123456789012345678901234567890",'
            b'"eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test"}]}'
        )
        # deploy lambda - Java with Kinesis input object
        function_name = f"test-lambda-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.KinesisLambdaHandler",
        )
        result = lambda_client.invoke(FunctionName=function_name, Payload=payload)
        result_data = result["Payload"].read()

        assert 200 == result["StatusCode"]
        assert '"test "' == to_str(result_data).strip()

    def test_kinesis_event(self, lambda_client, simple_java_lambda):
        payload = (
            b'{"Records": [{'
            b'"kinesis": {"data": "dGVzdA==", "partitionKey": "partition"},'
            b'"eventID": "shardId-000000000001:12345678901234567890123456789012345678901234567890",'
            b'"eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test"}]}'
        )
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=payload,
        )
        result_data = result["Payload"].read()

        assert 202 == result["StatusCode"]
        assert "" == to_str(result_data).strip()

    @parametrize_java_runtimes
    def test_stream_handler(self, lambda_client, create_lambda_function, test_java_jar, runtime):
        function_name = f"test-lambda-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_jar,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.LambdaStreamHandler",
        )
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"echo":"echo"}',
        )
        result_data = result["Payload"].read()

        assert 200 == result["StatusCode"]
        assert "{}" == to_str(result_data).strip()

    @parametrize_java_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_serializable_input_object(
        self, lambda_client, create_lambda_function, test_java_zip, runtime, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # deploy lambda - Java with serializable input object
        function_name = f"test-lambda-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.SerializedInputLambdaHandler",
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"bucket": "test_bucket", "key": "test_key"}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert json.loads(result_data) == {
            "validated": True,
            "bucket": "test_bucket",
            "key": "test_key",
        }

    @pytest.mark.skip_snapshot_verify
    def test_trigger_java_lambda_through_sns(
        self,
        lambda_client,
        s3_client,
        sns_client,
        sns_subscription,
        simple_java_lambda,
        s3_bucket,
        sns_create_topic,
        logs_client,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("Sid"))

        topic_name = f"topic-{short_uid()}"
        key = f"key-{short_uid()}"
        function_name = simple_java_lambda
        function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function", function_result)
        function_arn = function_result["Configuration"]["FunctionArn"]
        permission_id = f"test-statement-{short_uid()}"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        s3_sns_policy = f"""{{
            "Version": "2012-10-17",
            "Id": "example-ID",
            "Statement": [
                {{
                    "Sid": "Example SNS topic policy",
                    "Effect": "Allow",
                    "Principal": {{
                        "Service": "s3.amazonaws.com"
                    }},
                    "Action": [
                        "SNS:Publish"
                    ],
                    "Resource": "{topic_arn}",
                    "Condition": {{
                        "ArnLike": {{
                            "aws:SourceArn": "arn:aws:s3:*:*:{s3_bucket}"
                        }}
                    }}
                }}
            ]
        }}
        """
        sns_client.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="Policy", AttributeValue=s3_sns_policy
        )

        s3_client.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "TopicConfigurations": [{"TopicArn": topic_arn, "Events": ["s3:ObjectCreated:*"]}]
            },
        )

        add_permission_response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )

        snapshot.match("add-permission", add_permission_response)

        sns_subscription(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=function_arn,
        )

        events_before = (
            run_safe(
                get_lambda_log_events,
                function_name,
                regex_filter="Records",
                logs_client=logs_client,
            )
            or []
        )

        s3_client.put_object(Bucket=s3_bucket, Key=key, Body="something")

        # We got an event that confirm lambda invoked
        retry(
            function=check_expected_lambda_log_events_length,
            retries=30,
            sleep=1,
            expected_length=len(events_before) + 1,
            function_name=function_name,
            regex_filter="Records",
            logs_client=logs_client,
        )

        # clean up
        s3_client.delete_objects(Bucket=s3_bucket, Delete={"Objects": [{"Key": key}]})

    @pytest.mark.parametrize(
        "handler,expected_result",
        [
            (
                "cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom::handleRequestCustom",
                "CUSTOM",
            ),
            ("cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom", "INTERFACE"),
            (
                "cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom::handleRequest",
                "INTERFACE",
            ),
        ],
    )
    # this test is only compiled against java 11
    @pytest.mark.skip_snapshot_verify
    def test_java_custom_handler_method_specification(
        self,
        lambda_client,
        create_lambda_function,
        handler,
        expected_result,
        check_lambda_logs,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        java_handler_multiple_handlers = load_file(TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS, mode="rb")
        expected = ['.*"echo": "echo".*']

        function_name = f"lambda_handler_test_{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=java_handler_multiple_handlers,
            runtime=Runtime.java11,
            handler=handler,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=function_name, Payload=b'{"echo":"echo"}')
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert expected_result == result_data.strip('"\n ')

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=20)


class TestPythonRuntimes:
    @pytest.fixture(
        params=PYTHON_TEST_RUNTIMES,
    )
    def python_function_name(self, request, lambda_client, create_lambda_function):
        function_name = f"python-test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
            runtime=request.param,
        )
        return function_name

    @pytest.mark.skip_snapshot_verify(
        paths=["$..Payload.context.memory_limit_in_mb", "$..logs.logs"]
    )
    def test_invocation_type_not_set(self, lambda_client, python_function_name, snapshot):
        """Test invocation of a lambda with no invocation type set, but LogType="Tail""" ""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(
            snapshot.transform.key_value("LogResult", reference_replacement=False)
        )

        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", LogType="Tail"
        )
        result = read_streams(result)
        snapshot.match("invoke", result)
        result_data = json.loads(result["Payload"])

        # assert response details
        assert 200 == result["StatusCode"]
        assert {} == result_data["event"]

        # assert that logs are contained in response
        logs = result.get("LogResult", "")
        logs = to_str(base64.b64decode(to_str(logs)))
        snapshot.add_transformer(
            snapshot.transform.regex(
                re.compile(r"Duration: \d+(\.\d{2})? ms"), "Duration: <duration> ms"
            )
        )
        snapshot.add_transformer(
            snapshot.transform.regex(re.compile(r"Used: \d+ MB"), "Used: <memory> MB")
        )
        snapshot.match("logs", {"logs": logs})
        assert "START" in logs
        assert "Lambda log message" in logs
        assert "END" in logs
        assert "REPORT" in logs

    @pytest.mark.skip_snapshot_verify(
        paths=["$..LogResult", "$..Payload.context.memory_limit_in_mb"]
    )
    def test_invocation_type_request_response(self, lambda_client, python_function_name, snapshot):
        """Test invocation with InvocationType RequestResponse explicitely set"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        result = lambda_client.invoke(
            FunctionName=python_function_name,
            Payload=b"{}",
            InvocationType="RequestResponse",
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]
        result_data = json.loads(result_data)
        assert "application/json" == result["ResponseMetadata"]["HTTPHeaders"]["content-type"]
        assert 200 == result["StatusCode"]
        assert isinstance(result_data, dict)

    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult", "$..ExecutedVersion"])
    def test_invocation_type_event(self, lambda_client, python_function_name, snapshot):
        """Check invocation response for type event"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", InvocationType="Event"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 202 == result["StatusCode"]

    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult", "$..ExecutedVersion"])
    def test_invocation_type_dry_run(self, lambda_client, python_function_name, snapshot):
        """Check invocation response for type dryrun"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", InvocationType="DryRun"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 204 == result["StatusCode"]

    @parametrize_python_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_lambda_environment(self, lambda_client, create_lambda_function, runtime, snapshot):
        """Tests invoking a lambda function with environment variables set on creation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"env-test-function-{short_uid()}"
        env_vars = {"Hello": "World"}
        creation_result = create_lambda_function(
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            func_name=function_name,
            envvars=env_vars,
            runtime=runtime,
        )
        snapshot.match("creation-result", creation_result)

        # invoke function and assert result contains env vars
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invocation-result", result)
        result_data = result["Payload"]
        assert 200 == result["StatusCode"]
        assert json.loads(result_data) == env_vars

        # get function config and assert result contains env vars
        result = lambda_client.get_function_configuration(FunctionName=function_name)
        snapshot.match("get-configuration-result", result)
        assert result["Environment"] == {"Variables": env_vars}

    @parametrize_python_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_invocation_with_qualifier(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        runtime,
        check_lambda_logs,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
    ):
        """Tests invocation of python lambda with a given qualifier"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True, libs=TEST_LAMBDA_LIBS, runtime=runtime
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Role=lambda_su_role,
            Publish=True,
            Handler="handler.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", response)

        assert "Version" in response
        qualifier = response["Version"]

        wait_until_lambda_ready(function_name=function_name, qualifier=qualifier)

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = lambda_client.invoke(
            FunctionName=function_name, Payload=data_before, Qualifier=qualifier
        )
        result = read_streams(result)
        snapshot.match("invocation-response", result)
        data_after = json.loads(result["Payload"])
        assert json.loads(to_str(data_before)) == data_after["event"]

        context = data_after["context"]
        assert response["Version"] == context["function_version"]
        assert context.get("aws_request_id")
        assert function_name == context["function_name"]
        assert f"/aws/lambda/{function_name}" == context["log_group_name"]
        assert context.get("log_stream_name")
        assert context.get("memory_limit_in_mb")

        # assert that logs are present
        expected = [".*Lambda log message - print function.*"]
        if use_docker():
            # Note that during regular test execution, nosetests captures the output from
            # the logging module - hence we can only expect this when running in Docker
            expected.append(".*Lambda log message - logging module.*")

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=10)
        lambda_client.delete_function(FunctionName=function_name)

    @parametrize_python_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_upload_lambda_from_s3(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        runtime,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
    ):
        """Test invocation of a python lambda with its deployment package uploaded to s3"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True, libs=TEST_LAMBDA_LIBS, runtime=runtime
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        create_response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", create_response)

        wait_until_lambda_ready(function_name=function_name)

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = lambda_client.invoke(FunctionName=function_name, Payload=data_before)
        result = read_streams(result)
        snapshot.match("invocation-response", result)
        data_after = json.loads(result["Payload"])
        assert json.loads(to_str(data_before)) == data_after["event"]

        context = data_after["context"]
        assert "$LATEST" == context["function_version"]
        assert function_name == context["function_name"]

        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    @parametrize_python_runtimes
    def test_handler_in_submodule(self, lambda_client, create_lambda_function, runtime):
        """Test invocation of a lambda handler which resides in a submodule (= not root module)"""
        function_name = f"test-function-{short_uid()}"
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=runtime,
            file_name="localstack_package/def/main.py",
        )
        create_lambda_function(
            func_name=function_name,
            zip_file=zip_file,
            handler="localstack_package.def.main.handler",
            runtime=runtime,
        )

        # invoke function and assert result
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result_data = json.loads(result["Payload"].read())
        assert 200 == result["StatusCode"]
        assert json.loads("{}") == result_data["event"]

    @parametrize_python_runtimes
    def test_lambda_send_message_to_sqs(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        runtime,
        lambda_su_role,
    ):
        """Send sqs message to sqs queue inside python lambda"""
        function_name = f"test-function-{short_uid()}"
        queue_name = f"lambda-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        create_lambda_function(
            handler_file=TEST_LAMBDA_SEND_MESSAGE_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        event = {
            "message": f"message-from-test-lambda-{short_uid()}",
            "queue_name": queue_name,
            "region_name": sqs_client.meta.region_name,
        }

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        # assert that message has been received on the Queue
        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            return rs["Messages"][0]

        message = retry(receive_message, retries=15, sleep=2)
        assert event["message"] == message["Body"]

    @parametrize_python_runtimes
    def test_lambda_put_item_to_dynamodb(
        self,
        lambda_client,
        create_lambda_function,
        dynamodb_create_table,
        runtime,
        dynamodb_resource,
        lambda_su_role,
        dynamodb_client,
    ):
        """Put item into dynamodb from python lambda"""
        table_name = f"ddb-table-{short_uid()}"
        function_name = f"test-function-{short_uid()}"

        dynamodb_create_table(table_name=table_name, partition_key="id")

        create_lambda_function(
            handler_file=TEST_LAMBDA_PUT_ITEM_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        data = {short_uid(): f"data-{i}" for i in range(3)}

        event = {
            "table_name": table_name,
            "region_name": dynamodb_client.meta.region_name,
            "items": [{"id": k, "data": v} for k, v in data.items()],
        }

        def wait_for_table_created():
            return (
                dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"]
                == "ACTIVE"
            )

        assert poll_condition(wait_for_table_created, timeout=30)

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        rs = dynamodb_resource.Table(table_name).scan()

        items = rs["Items"]

        assert len(items) == len(data.keys())
        for item in items:
            assert data[item["id"]] == item["data"]

    @parametrize_python_runtimes
    def test_lambda_start_stepfunctions_execution(
        self, lambda_client, stepfunctions_client, create_lambda_function, runtime, lambda_su_role
    ):
        """Start stepfunctions machine execution from lambda"""
        function_name = f"test-function-{short_uid()}"
        resource_lambda_name = f"test-resource-{short_uid()}"
        state_machine_name = f"state-machine-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_START_EXECUTION_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        resource_lambda_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=resource_lambda_name,
            runtime=runtime,
            role=lambda_su_role,
        )["CreateFunctionResponse"]["FunctionArn"]

        state_machine_def = {
            "StartAt": "step1",
            "States": {
                "step1": {
                    "Type": "Task",
                    "Resource": resource_lambda_arn,
                    "ResultPath": "$.result_value",
                    "End": True,
                }
            },
        }

        rs = stepfunctions_client.create_state_machine(
            name=state_machine_name,
            definition=json.dumps(state_machine_def),
            roleArn=lambda_su_role,
        )
        sm_arn = rs["stateMachineArn"]

        try:
            lambda_client.invoke(
                FunctionName=function_name,
                Payload=json.dumps(
                    {
                        "state_machine_arn": sm_arn,
                        "region_name": stepfunctions_client.meta.region_name,
                        "input": {},
                    }
                ),
            )
            time.sleep(1)

            rs = stepfunctions_client.list_executions(stateMachineArn=sm_arn)

            # assert that state machine get executed 1 time
            assert 1 == len([ex for ex in rs["executions"] if ex["stateMachineArn"] == sm_arn])

        finally:
            # clean up
            stepfunctions_client.delete_state_machine(stateMachineArn=sm_arn)

    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    def test_python_runtime_correct_versions(self, lambda_client, create_lambda_function, runtime):
        """Test different versions of python runtimes to report back the correct python version"""
        function_name = f"test_python_executor_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_VERSION,
            runtime=runtime,
        )
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
        )
        result = json.loads(to_str(result["Payload"].read()))
        assert result["version"] == runtime

    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    @pytest.mark.skip_snapshot_verify
    def test_python_runtime_unhandled_errors(
        self, lambda_client, create_lambda_function, runtime, snapshot
    ):
        """Test unhandled errors during python lambda invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"test_python_executor_{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=runtime,
        )
        snapshot.match("creation_response", creation_response)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
        )
        result = read_streams(result)
        snapshot.match("invocation_response", result)
        assert result["StatusCode"] == 200
        assert result["ExecutedVersion"] == "$LATEST"
        assert result["FunctionError"] == "Unhandled"
        payload = json.loads(result["Payload"])
        assert payload["errorType"] == "CustomException"
        assert payload["errorMessage"] == "some error occurred"
        assert "stackTrace" in payload

        if (
            runtime == "python3.9" and not is_old_provider()
        ):  # TODO: remove this after the legacy provider is gone
            assert "requestId" in payload
        else:
            assert "requestId" not in payload


class TestCustomRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker provided runtimes not applicable if run locally"
    )
    @pytest.mark.parametrize(
        "runtime",
        PROVIDED_TEST_RUNTIMES,
    )
    @pytest.mark.skip_snapshot_verify
    def test_provided_runtimes(
        self, lambda_client, create_lambda_function, runtime, check_lambda_logs, snapshot
    ):
        """Test simple provided lambda (with curl as RIC) invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_CUSTOM_RUNTIME,
            handler="function.handler",
            runtime=runtime,
        )
        snapshot.match("create-result", result)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"text": "bar with \'quotes\\""}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        result_data = result_data.strip()
        # jsonify in pro (re-)formats the event json so we allow both versions here
        assert result_data in (
            """Echoing request: '{"text": "bar with \'quotes\\""}'""",
            """Echoing request: '{"text":"bar with \'quotes\\""}'""",
        )

        # assert that logs are present
        expected = [".*Custom Runtime Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=20)

