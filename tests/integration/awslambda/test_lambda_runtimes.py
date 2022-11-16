import json
import os
import shutil
from typing import List

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.constants import LOCALSTACK_MAVEN_VERSION, MAVEN_REPO_URL
from localstack.packages import DownloadInstaller, Package, PackageInstaller
from localstack.services.awslambda.lambda_api import use_docker
from localstack.services.awslambda.packages import lambda_java_libs_package
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.utils import testutil
from localstack.utils.archives import unzip
from localstack.utils.files import cp_r, load_file, mkdir, new_tmp_dir, save_file
from localstack.utils.functions import run_safe
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events
from tests.integration.awslambda.test_lambda import (
    JAVA_TEST_RUNTIMES,
    NODE_TEST_RUNTIMES,
    PYTHON_TEST_RUNTIMES,
    TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS,
    TEST_LAMBDA_JAVA_WITH_LIB,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS_ES6,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
    TEST_LAMBDA_PYTHON_VERSION,
    THIS_FOLDER,
    read_streams,
)

# Java Test Jar Download (used for tests)
TEST_LAMBDA_JAR_URL_TEMPLATE = "{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar"


class LambdaJavaTestlibsPackage(Package):
    def __init__(self):
        super().__init__("JavaLambdaTestlibs", LOCALSTACK_MAVEN_VERSION)

    def get_versions(self) -> List[str]:
        return [LOCALSTACK_MAVEN_VERSION]

    def _get_installer(self, version: str) -> PackageInstaller:
        return LambdaJavaTestlibsPackageInstaller(version)


class LambdaJavaTestlibsPackageInstaller(DownloadInstaller):
    def __init__(self, version):
        super().__init__("lambda-java-testlibs", version)

    def _get_download_url(self) -> str:
        return TEST_LAMBDA_JAR_URL_TEMPLATE.format(
            version=self.version, url=MAVEN_REPO_URL, name="localstack-utils"
        )


lambda_java_testlibs_package = LambdaJavaTestlibsPackage()

parametrize_python_runtimes = pytest.mark.parametrize("runtime", PYTHON_TEST_RUNTIMES)
parametrize_node_runtimes = pytest.mark.parametrize("runtime", NODE_TEST_RUNTIMES)
parametrize_java_runtimes = pytest.mark.parametrize("runtime", JAVA_TEST_RUNTIMES)


@pytest.fixture(autouse=True)
def add_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(snapshot.transform.key_value("CodeSha256", "<code-sha-256>"))


# some more common ones that usually don't work in the old provider
pytestmark = pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=[
        # "$..Architectures",
        "$..EphemeralStorage",
        "$..LastUpdateStatus",
        "$..MemorySize",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
        "$..VpcConfig",
        "$..LogResult",
        # "$..CodeSigningConfig",
        "$..Environment",  # missing
        "$..HTTPStatusCode",  # 201 vs 200
        "$..Layers",
    ],
)


class TestNodeJSRuntimes:
    @pytest.mark.parametrize("runtime", (Runtime.nodejs14_x, Runtime.nodejs16_x))
    @pytest.mark.skipif(
        is_old_provider() and not use_docker(),
        reason="ES6 support is only guaranteed when using the docker executor",
    )
    @pytest.mark.aws_validated
    def test_invoke_nodejs_es6_lambda(
        self, lambda_client, create_lambda_function, logs_client, snapshot, runtime
    ):
        """Test simple nodejs lambda invocation"""

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


class TestJavaRuntimes:
    @pytest.fixture(scope="class")
    def test_java_jar(self) -> bytes:
        lambda_java_testlibs_package.install()
        java_file = load_file(
            lambda_java_testlibs_package.get_installer().get_executable_path(), mode="rb"
        )
        return java_file

    @pytest.fixture(scope="class")
    def test_java_zip(self, tmpdir_factory, test_java_jar) -> bytes:
        tmpdir = tmpdir_factory.mktemp("tmp-java-zip")
        zip_lib_dir = os.path.join(tmpdir, "lib")
        zip_jar_path = os.path.join(zip_lib_dir, "test.lambda.jar")
        mkdir(zip_lib_dir)
        installer = lambda_java_libs_package.get_installer()
        installer.install()
        java_lib_dir = installer.get_executable_path()
        cp_r(
            java_lib_dir,
            os.path.join(zip_lib_dir, "executor.lambda.jar"),
        )
        save_file(zip_jar_path, test_java_jar)
        return testutil.create_zip_file(tmpdir, get_content=True)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Payload"]
    )  # newline at end
    @pytest.mark.aws_validated
    def test_java_runtime_with_lib(self, lambda_client, create_lambda_function, snapshot):
        """Test lambda creation/invocation with different deployment package types (jar, zip, zip-with-gradle)"""

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
                "functions/java/lambda_echo/build/distributions/lambda-function-built-by-gradle.zip",
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

    @parametrize_java_runtimes
    @pytest.mark.aws_validated
    def test_stream_handler(
        self, lambda_client, create_lambda_function, test_java_jar, runtime, snapshot
    ):
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
        snapshot.match("invoke_result", result)

    @parametrize_java_runtimes
    @pytest.mark.aws_validated
    def test_serializable_input_object(
        self, lambda_client, create_lambda_function, test_java_zip, runtime, snapshot
    ):
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
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Payload"]
    )  # newline at end
    @pytest.mark.aws_validated
    # this test is only compiled against java 11
    def test_java_custom_handler_method_specification(
        self,
        lambda_client,
        create_lambda_function,
        handler,
        expected_result,
        check_lambda_logs,
        snapshot,
    ):
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

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Code.RepositoryType", "$..Tags"]
    )
    # TODO maybe snapshot payload as well
    def test_java_lambda_subscribe_sns_topic(
        self,
        lambda_client,
        s3_client,
        sns_client,
        sns_subscription,
        s3_bucket,
        sns_create_topic,
        logs_client,
        snapshot,
        create_lambda_function,
        test_java_zip,
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("Sid"))
        function_name = f"java-test-function-{short_uid()}"
        topic_name = f"topic-{short_uid()}"
        key = f"key-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=Runtime.java11,
            handler="cloud.localstack.sample.LambdaHandler",
        )
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


class TestPythonRuntimes:
    @parametrize_python_runtimes
    @pytest.mark.aws_validated
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

    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    @pytest.mark.aws_validated
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

    # TODO remove once new error test is in place
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..Payload.requestId"])
    @pytest.mark.aws_validated
    def test_python_runtime_unhandled_errors(
        self, lambda_client, create_lambda_function, runtime, snapshot
    ):
        """Test unhandled errors during python lambda invocation"""
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
