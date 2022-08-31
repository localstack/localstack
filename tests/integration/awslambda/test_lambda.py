import json
import logging
import os
from typing import Dict, TypeVar

import pytest
from botocore.response import StreamingBody

from localstack.aws.api.lambda_ import Runtime
from localstack.utils import testutil
from localstack.utils.common import load_file, retry, safe_requests, short_uid, to_bytes, to_str
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.testutil import create_lambda_archive

LOG = logging.getLogger(__name__)
FUNCTION_MAX_UNZIPPED_SIZE = 262144000


# TODO: find a better way to manage these handler files
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_python_version.py")
TEST_LAMBDA_PYTHON_UNHANDLED_ERROR = os.path.join(
    THIS_FOLDER, "functions/lambda_unhandled_error.py"
)
TEST_LAMBDA_AWS_PROXY = os.path.join(THIS_FOLDER, "functions/lambda_aws_proxy.py")
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, "functions/lambda_python3.py")
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
TEST_LAMBDA_NODEJS_ES6 = os.path.join(THIS_FOLDER, "functions/lambda_handler_es6.mjs")
TEST_LAMBDA_HELLO_WORLD = os.path.join(THIS_FOLDER, "functions/lambda_hello_world.py")
TEST_LAMBDA_NODEJS_APIGW_INTEGRATION = os.path.join(THIS_FOLDER, "functions/apigw_integration.js")
TEST_LAMBDA_NODEJS_APIGW_502 = os.path.join(THIS_FOLDER, "functions/apigw_502.js")
TEST_LAMBDA_GOLANG_ZIP = os.path.join(THIS_FOLDER, "functions/golang/handler.zip")
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, "functions/lambda_integration.rb")
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, "functions/dotnetcore2/dotnetcore2.zip")
TEST_LAMBDA_DOTNETCORE31 = os.path.join(THIS_FOLDER, "functions/dotnetcore31/dotnetcore31.zip")
TEST_LAMBDA_DOTNET6 = os.path.join(THIS_FOLDER, "functions/dotnet6/dotnet6.zip")
TEST_LAMBDA_CUSTOM_RUNTIME = os.path.join(THIS_FOLDER, "functions/custom-runtime")
TEST_LAMBDA_HTTP_RUST = os.path.join(THIS_FOLDER, "functions/rust-lambda/function.zip")
TEST_LAMBDA_JAVA_WITH_LIB = os.path.join(
    THIS_FOLDER, "functions/java/lambda_echo/lambda-function-with-lib-0.0.1.jar"
)
TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS = os.path.join(
    THIS_FOLDER,
    "functions",
    "java",
    "lambda_multiple_handlers",
    "build",
    "distributions",
    "lambda-function-with-multiple-handlers.zip",
)
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, "functions/lambda_environment.py")

TEST_LAMBDA_SEND_MESSAGE_FILE = os.path.join(THIS_FOLDER, "functions/lambda_send_message.py")
TEST_LAMBDA_PUT_ITEM_FILE = os.path.join(THIS_FOLDER, "functions/lambda_put_item.py")
TEST_LAMBDA_START_EXECUTION_FILE = os.path.join(THIS_FOLDER, "functions/lambda_start_execution.py")
TEST_LAMBDA_URL = os.path.join(THIS_FOLDER, "functions/lambda_url.js")
TEST_LAMBDA_CACHE_NODEJS = os.path.join(THIS_FOLDER, "functions", "lambda_cache.js")
TEST_LAMBDA_CACHE_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_cache.py")
TEST_LAMBDA_TIMEOUT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_timeout.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_introspect.py")

TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"


TEST_LAMBDA_LIBS = [
    "requests",
    "psutil",
    "urllib3",
    "chardet",
    "certifi",
    "idna",
    "pip",
    "dns",
]

T = TypeVar("T")


def read_streams(payload: T) -> T:
    new_payload = {}
    for k, v in payload.items():
        if isinstance(v, Dict):
            new_payload[k] = read_streams(v)
        elif isinstance(v, StreamingBody):
            new_payload[k] = to_str(v.read())
        else:
            new_payload[k] = v
    return new_payload


class TestLambdaBaseFeatures:
    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult"])
    def test_large_payloads(self, caplog, lambda_client, create_lambda_function, snapshot):
        """Testing large payloads sent to lambda functions (~5MB)"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        payload = {"test": "test123456" * 100 * 1000 * 5}  # 5MB payload
        payload_bytes = to_bytes(json.dumps(payload))
        result = lambda_client.invoke(FunctionName=function_name, Payload=payload_bytes)
        result = read_streams(result)
        snapshot.match("invocation_response", result)
        assert 200 == result["ResponseMetadata"]["HTTPStatusCode"]
        result_data = result["Payload"]
        result_data = json.loads(to_str(result_data))
        assert payload == result_data

    # TODO
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify  # skipped - the diff is too big
    @pytest.mark.skipif(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="Lambda function state pending for small lambdas not supported on localstack",
    )
    def test_function_state(self, lambda_client, lambda_su_role, snapshot):
        """Tests if a lambda starts in state "Pending" but moves to "Active" at some point"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        # necessary due to changing zip timestamps. We might need a reproducible archive method for this
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        try:

            def create_function():
                return lambda_client.create_function(
                    FunctionName=function_name,
                    Runtime="python3.9",
                    Handler="handler.handler",
                    Role=lambda_su_role,
                    Code={"ZipFile": zip_file},
                )

            response = retry(create_function, sleep=3, retries=5)

            snapshot.match("create-fn-response", response)
            assert response["State"] == "Pending"

            # lambda has to get active at some point
            def _check_lambda_state():
                response = lambda_client.get_function(FunctionName=function_name)
                assert response["Configuration"]["State"] == "Active"
                return response

            response = retry(_check_lambda_state)
            snapshot.match("get-fn-response", response)
        finally:
            try:
                lambda_client.delete_function(FunctionName=function_name)
            except Exception:
                LOG.debug("Unable to delete function %s", function_name)


class TestLambdaBehavior:
    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (
                TEST_LAMBDA_CACHE_NODEJS,
                Runtime.nodejs12_x,
            ),  # TODO: can we do some kind of nested parametrize here?
            (TEST_LAMBDA_CACHE_PYTHON, Runtime.python3_8),
        ],
        ids=["nodejs", "python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda caching not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_cache_local(
        self, lambda_client, create_lambda_function, lambda_fn, lambda_runtime
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
        )

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 0

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 1

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda timeouts not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 2}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200

        log_group_name = f"/aws/lambda/{func_name}"
        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.skip_snapshot_verify
    def test_lambda_no_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 1}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200
        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def _assert_log_output():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]
            return any(["starting wait" in e["message"] for e in log_events]) and any(
                ["done waiting" in e["message"] for e in log_events]
            )

        wait_until(_assert_log_output, strategy="linear")


# features
class TestLambdaURL:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..context",
            "$..event.headers.x-forwarded-proto",
            "$..event.headers.x-forwarded-for",
            "$..event.headers.x-forwarded-port",
            "$..event.headers.x-amzn-lambda-forwarded-client-ip",
            "$..event.headers.x-amzn-lambda-forwarded-host",
            "$..event.headers.x-amzn-lambda-proxy-auth",
            "$..event.headers.x-amzn-lambda-proxying-cell",
            "$..event.headers.x-amzn-trace-id",
        ]
    )
    def test_lambda_url_invocation(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestId", "uuid", reference_replacement=False),
                snapshot.transform.key_value(
                    "FunctionUrl", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.http.sourceIp",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-forwarded-for", "ip-address", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-client-ip",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-host",
                    "lambda-url",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.host", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.apiId", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainName", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainPrefix", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.time", "readable-date", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.timeEpoch",
                    "epoch-milliseconds",
                    reference_replacement=False,
                ),
            ]
        )

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_url.handler",
        )

        url_config = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )

        snapshot.match("add_permission", permissions_response)

        url = url_config["FunctionUrl"]
        url += "custom_path/extend?test_param=test_value"

        result = safe_requests.post(
            url, data=b"{'key':'value'}", headers={"User-Agent": "python-requests/testing"}
        )

        assert result.status_code == 200
        snapshot.match("lambda_url_invocation", json.loads(result.content))

        result = safe_requests.post(url, data="text", headers={"Content-Type": "text/plain"})
        event = json.loads(result.content)["event"]
        assert event["body"] == "text"
        assert event["isBase64Encoded"] is False

        result = safe_requests.post(url)
        event = json.loads(result.content)["event"]
        assert "Body" not in event
        assert event["isBase64Encoded"] is False


@pytest.mark.skip_snapshot_verify
@pytest.mark.aws_validated
class TestLambdaFeatures:
    def test_basic_invoke(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # predefined names
        fn_name = f"ls-fn-{short_uid()}"
        fn_name_2 = f"ls-fn-{short_uid()}"

        # infra setup (& validations)
        with open(os.path.join(os.path.dirname(__file__), "functions/echo.zip"), "rb") as f:
            response = create_lambda_function_aws(
                FunctionName=fn_name,
                Handler="index.handler",
                Code={"ZipFile": f.read()},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
            snapshot.match("lambda_create_fn", response)

        with open(os.path.join(os.path.dirname(__file__), "functions/echo.zip"), "rb") as f:
            response = create_lambda_function_aws(
                FunctionName=fn_name_2,
                Handler="index.handler",
                Code={"ZipFile": f.read()},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
            snapshot.match("lambda_create_fn_2", response)

        get_fn_result = lambda_client.get_function(FunctionName=fn_name)

        snapshot.match("lambda_get_fn", get_fn_result)

        get_fn_result_2 = lambda_client.get_function(FunctionName=fn_name_2)
        snapshot.match("lambda_get_fn_2", get_fn_result_2)

        invoke_result = lambda_client.invoke(FunctionName=fn_name, Payload=bytes("{}", "utf-8"))
        snapshot.match("lambda_invoke_result", invoke_result)
