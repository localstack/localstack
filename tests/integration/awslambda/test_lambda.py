import base64
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Dict, TypeVar

import pytest
from botocore.response import StreamingBody

from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda.lambda_api import use_docker
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    is_old_provider,
    update_done,
)
from localstack.testing.aws.util import create_client_with_keys
from localstack.testing.pytest.snapshot import is_aws
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.testing.snapshots.transformer_utility import PATTERN_UUID
from localstack.utils import testutil
from localstack.utils.files import load_file
from localstack.utils.http import safe_requests
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry, wait_until
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
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
TEST_LAMBDA_NODEJS_ES6 = os.path.join(THIS_FOLDER, "functions/lambda_handler_es6.mjs")
TEST_LAMBDA_NODEJS_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.js")
TEST_LAMBDA_HELLO_WORLD = os.path.join(THIS_FOLDER, "functions/lambda_hello_world.py")
TEST_LAMBDA_NODEJS_APIGW_INTEGRATION = os.path.join(THIS_FOLDER, "functions/apigw_integration.js")
TEST_LAMBDA_NODEJS_APIGW_502 = os.path.join(THIS_FOLDER, "functions/apigw_502.js")
TEST_LAMBDA_GOLANG_ZIP = os.path.join(THIS_FOLDER, "functions/golang/handler.zip")
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, "functions/lambda_integration.rb")
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
TEST_LAMBDA_CACHE_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_cache.js")
TEST_LAMBDA_CACHE_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_cache.py")
TEST_LAMBDA_TIMEOUT_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_timeout.py")
TEST_LAMBDA_SLEEP_ENVIRONMENT = os.path.join(THIS_FOLDER, "functions/lambda_sleep_environment.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_introspect.py")
TEST_LAMBDA_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_version.py")

TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"

PYTHON_TEST_RUNTIMES = (
    [
        Runtime.python3_7,
        Runtime.python3_8,
        Runtime.python3_9,
    ]
    if not is_old_provider() or use_docker()
    else [Runtime.python3_9]
)
NODE_TEST_RUNTIMES = (
    [Runtime.nodejs12_x, Runtime.nodejs14_x, Runtime.nodejs16_x]
    if not is_old_provider() or use_docker()
    else [Runtime.nodejs16_x]
)
JAVA_TEST_RUNTIMES = (
    [
        Runtime.java8,
        Runtime.java8_al2,
        Runtime.java11,
    ]
    if not is_old_provider() or use_docker()
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


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        snapshot.transform.key_value("CodeSha256", reference_replacement=False)
    )


# some more common ones that usually don't work in the old provider
if is_old_provider():
    pytestmark = pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Architectures",
            "$..EphemeralStorage",
            "$..LastUpdateStatus",
            "$..MemorySize",
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
            "$..VpcConfig",
            "$..CodeSigningConfig",
            "$..Environment",  # missing
            "$..HTTPStatusCode",  # 201 vs 200
            "$..Layers",
        ],
    )
else:
    pytestmark = pytest.mark.skip_snapshot_verify(
        paths=[
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
            "$..CodeSize",
            "$..LastUpdateStatus",
            "$..LastUpdateStatusReason",
            "$..LastUpdateStatusReasonCode",
        ],
    )


class TestLambdaBaseFeatures:
    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult"])
    @pytest.mark.aws_validated
    def test_large_payloads(self, caplog, lambda_client, create_lambda_function, snapshot):
        """Testing large payloads sent to lambda functions (~5MB)"""
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        large_value = "test123456" * 100 * 1000 * 5
        snapshot.add_transformer(snapshot.transform.regex(large_value, "<large-value>"))
        payload = {"test": large_value}  # 5MB payload
        result = lambda_client.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        snapshot.match("invocation_response", result)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Tags",
            "$..Configuration.RevisionId",
            "$..Code.RepositoryType",
            "$..CodeSize",  # CI reports different code size here,
            "$..Layers",  # PRO
        ],
    )
    @pytest.mark.aws_validated
    def test_function_state(
        self, lambda_client, lambda_su_role, snapshot, create_lambda_function_aws
    ):
        """Tests if a lambda starts in state "Pending" but moves to "Active" at some point"""

        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        # create_response is the original create call response, even though the fixture waits until it's not pending
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"ZipFile": zip_file},
        )
        snapshot.match("create-fn-response", create_response)

        response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-fn-response", response)

    @pytest.mark.skipif(
        is_old_provider(), reason="Credential injection not supported in old provider"
    )
    @pytest.mark.aws_validated
    def test_lambda_different_iam_keys_environment(
        self, lambda_client, lambda_su_role, create_lambda_function, snapshot, sts_client
    ):
        """
        In this test we want to check if multiple lambda environments (= instances of hot functions) have
        different AWS access keys
        """
        function_name = f"fn-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_SLEEP_ENVIRONMENT,
            runtime=Runtime.python3_8,
            role=lambda_su_role,
        )
        snapshot.match("create-result", create_result)

        # invoke two versions in two threads at the same time so environments won't be reused really quick
        def _invoke_lambda(*args):
            result = lambda_client.invoke(
                FunctionName=function_name, Payload=to_bytes(json.dumps({"sleep": 2}))
            )
            return json.loads(to_str(result["Payload"].read()))["environment"]

        def _transform_to_key_dict(env: Dict[str, str]):
            return {
                "AccessKeyId": env["AWS_ACCESS_KEY_ID"],
                "SecretAccessKey": env["AWS_SECRET_ACCESS_KEY"],
                "SessionToken": env["AWS_SESSION_TOKEN"],
            }

        def _assert_invocations():
            with ThreadPoolExecutor(2) as executor:
                results = list(executor.map(_invoke_lambda, range(2)))
            assert len(results) == 2
            assert (
                results[0]["AWS_LAMBDA_LOG_STREAM_NAME"] != results[1]["AWS_LAMBDA_LOG_STREAM_NAME"]
            ), "Environments identical for both invocations"
            # if we got different environments, those should differ as well
            assert (
                results[0]["AWS_ACCESS_KEY_ID"] != results[1]["AWS_ACCESS_KEY_ID"]
            ), "Access Key IDs have to differ"
            assert (
                results[0]["AWS_SECRET_ACCESS_KEY"] != results[1]["AWS_SECRET_ACCESS_KEY"]
            ), "Secret Access keys have to differ"
            assert (
                results[0]["AWS_SESSION_TOKEN"] != results[1]["AWS_SESSION_TOKEN"]
            ), "Session tokens have to differ"
            # check if the access keys match the same role, and the role matches the one provided
            # since a lot of asserts are based on the structure of the arns, snapshots are not too nice here, so manual
            keys_1 = _transform_to_key_dict(results[0])
            keys_2 = _transform_to_key_dict(results[1])
            sts_client_1 = create_client_with_keys("sts", keys=keys_1)
            sts_client_2 = create_client_with_keys("sts", keys=keys_2)
            identity_1 = sts_client_1.get_caller_identity()
            identity_2 = sts_client_2.get_caller_identity()
            assert identity_1["Arn"] == identity_2["Arn"]
            role_part = (
                identity_1["Arn"]
                .replace("sts", "iam")
                .replace("assumed-role", "role")
                .rpartition("/")
            )
            assert lambda_su_role == role_part[0]
            assert function_name == role_part[2]
            assert identity_1["Account"] == identity_2["Account"]
            assert identity_1["UserId"] == identity_2["UserId"]
            assert function_name == identity_1["UserId"].partition(":")[2]

        retry(_assert_invocations)


class TestLambdaBehavior:
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Payload", "$..LogResult"]
    )
    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_CACHE_NODEJS, Runtime.nodejs12_x),
            (TEST_LAMBDA_CACHE_PYTHON, Runtime.python3_8),
        ],
        ids=["nodejs", "python"],
    )
    @pytest.mark.aws_validated
    def test_lambda_cache_local(
        self, lambda_client, create_lambda_function, lambda_fn, lambda_runtime, snapshot
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
        )

        first_invoke_result = lambda_client.invoke(FunctionName=func_name)
        snapshot.match("first_invoke_result", first_invoke_result)

        second_invoke_result = lambda_client.invoke(FunctionName=func_name)
        snapshot.match("second_invoke_result", second_invoke_result)

    @pytest.mark.skipif(is_old_provider(), reason="old provider")
    @pytest.mark.aws_validated
    @pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
    def test_lambda_invoke_with_timeout(
        self,
        lambda_client,
        create_lambda_function,
        logs_client,
        snapshot,
    ):
        regex = re.compile(r".*\s(?P<uuid>[-a-z0-9]+) Task timed out after \d.\d+ seconds")
        snapshot.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: regex.search(v).group("uuid") if k == "errorMessage" else None,
                "<timeout_error_msg>",
                replace_reference=False,
            )
        )

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_TIMEOUT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 2}))
        snapshot.match("invoke-result", result)

        log_group_name = f"/aws/lambda/{func_name}"
        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            # TODO: this part is a bit flaky, at least locally with old provider
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Payload", "$..LogResult", "$..Layers"]
    )
    @pytest.mark.aws_validated
    def test_lambda_invoke_no_timeout(
        self,
        lambda_client,
        create_lambda_function,
        logs_client,
        snapshot,
    ):
        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_TIMEOUT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 1}))
        snapshot.match("invoke-result", result)
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


@pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
class TestLambdaURL:
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
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
        ],
    )
    @pytest.mark.aws_validated
    def test_lambda_url_invocation(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestId", reference_replacement=False),
                snapshot.transform.key_value("FunctionUrl", reference_replacement=False),
                snapshot.transform.jsonpath(
                    "$..headers.x-forwarded-for", "ip-address", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..headers.x-amzn-trace-id", "x-amzn-trace-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..headers.x-amzn-lambda-forwarded-client-ip",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..headers.x-amzn-lambda-forwarded-host",
                    "forwarded-host",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.http.sourceIp",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..headers.host", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.apiId", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.domainName", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.domainPrefix", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.time", "readable-date", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..requestContext.timeEpoch",
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


class TestLambdaFeatures:
    @pytest.fixture(
        params=[("python3.9", TEST_LAMBDA_PYTHON_ECHO), ("nodejs16.x", TEST_LAMBDA_NODEJS_ECHO)],
        ids=["python3.9", "nodejs16.x"],
    )
    def invocation_echo_lambda(self, create_lambda_function, request):
        function_name = f"echo-func-{short_uid()}"
        runtime, handler = request.param
        creation_result = create_lambda_function(
            handler_file=handler,
            func_name=function_name,
            runtime=runtime,
        )
        return creation_result["CreateFunctionResponse"]["FunctionArn"]

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..Payload.context.memory_limit_in_mb", "$..logs.logs"]
    )
    # TODO remove, currently missing init duration in REPORT
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: not is_old_provider(), paths=["$..logs.logs"]
    )
    @pytest.mark.aws_validated
    def test_invocation_with_logs(self, lambda_client, snapshot, invocation_echo_lambda):
        """Test invocation of a lambda with no invocation type set, but LogType="Tail""" ""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))
        snapshot.add_transformer(
            snapshot.transform.key_value("LogResult", reference_replacement=False)
        )

        result = lambda_client.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", LogType="Tail"
        )
        snapshot.match("invoke", result)

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
        assert "{}" in logs
        assert "END" in logs
        assert "REPORT" in logs

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..LogResult", "$..Payload.context.memory_limit_in_mb"]
    )
    @pytest.mark.aws_validated
    def test_invocation_type_request_response(
        self, lambda_client, snapshot, invocation_echo_lambda
    ):
        """Test invocation with InvocationType RequestResponse explicitly set"""
        result = lambda_client.invoke(
            FunctionName=invocation_echo_lambda,
            Payload=b"{}",
            InvocationType="RequestResponse",
        )
        snapshot.match("invoke-result", result)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..LogResult", "$..ExecutedVersion"]
    )
    @pytest.mark.aws_validated
    def test_invocation_type_event(self, lambda_client, snapshot, invocation_echo_lambda):
        """Check invocation response for type event"""
        result = lambda_client.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", InvocationType="Event"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 202 == result["StatusCode"]

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..LogResult", "$..ExecutedVersion"]
    )
    @pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
    @pytest.mark.aws_validated
    def test_invocation_type_dry_run(self, lambda_client, snapshot, invocation_echo_lambda):
        """Check invocation response for type dryrun"""
        result = lambda_client.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", InvocationType="DryRun"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 204 == result["StatusCode"]

    @pytest.mark.skip(reason="Not yet implemented")
    @pytest.mark.aws_validated
    def test_invocation_type_event_error(
        self, lambda_client, create_lambda_function, logs_client, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))

        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime="python3.9",
        )
        snapshot.match("creation_response", creation_response)
        invocation_response = lambda_client.invoke(
            FunctionName=function_name, Payload=b"{}", InvocationType="Event"
        )
        snapshot.match("invocation_response", invocation_response)

        # check logs if lambda was executed twice
        log_group_name = f"/aws/lambda/{function_name}"

        def assert_events():
            ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
            log_stream_name = ls_result["logStreams"][0]["logStreamName"]
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert len([e["message"] for e in log_events if e["message"].startswith("START")]) == 2
            assert len([e["message"] for e in log_events if e["message"].startswith("REPORT")]) == 2
            return log_events

        events = retry(assert_events, retries=120, sleep=2)
        snapshot.match("log_events", events)
        # check if both request ids are identical, since snapshots currently do not support reference replacement for regexes
        start_messages = [e["message"] for e in events if e["message"].startswith("START")]
        uuids = [PATTERN_UUID.search(message).group(0) for message in start_messages]
        assert len(uuids) == 2
        assert uuids[0] == uuids[1]

    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_invocation_with_qualifier(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        check_lambda_logs,
        lambda_su_role,
        wait_until_lambda_ready,
        create_lambda_function_aws,
        snapshot,
    ):
        """Tests invocation of python lambda with a given qualifier"""
        snapshot.add_transformer(snapshot.transform.key_value("LogResult"))

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=Runtime.python3_9,
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Role=lambda_su_role,
            Publish=True,
            Handler="handler.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", response)
        qualifier = response["Version"]

        # invoke lambda function
        invoke_result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"foo": "bar with \'quotes\\""}',
            Qualifier=qualifier,
            LogType="Tail",
        )
        log_result = invoke_result["LogResult"]
        raw_logs = to_str(base64.b64decode(to_str(log_result)))
        log_lines = raw_logs.splitlines()
        snapshot.match(
            "log_result",
            {"log_result": [line for line in log_lines if not line.startswith("REPORT")]},
        )
        snapshot.match("invocation-response", invoke_result)

    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_upload_lambda_from_s3(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
        create_lambda_function_aws,
    ):
        """Test invocation of a python lambda with its deployment package uploaded to s3"""
        snapshot.add_transformer(snapshot.transform.s3_api())

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=Runtime.python3_9,
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", create_response)

        # invoke lambda function
        result = lambda_client.invoke(
            FunctionName=function_name, Payload=b'{"foo": "bar with \'quotes\\""}'
        )
        snapshot.match("invocation-response", result)

    @pytest.mark.skipif(
        is_old_provider() and not use_docker(),
        reason="Test for docker nodejs runtimes not applicable if run locally",
    )
    @pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_lambda_with_context(
        self, lambda_client, create_lambda_function, check_lambda_logs, snapshot
    ):
        """Test context of nodejs lambda invocation"""
        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_INTEGRATION_NODEJS,
            handler="lambda_integration.handler",
            runtime=Runtime.nodejs16_x,
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


@pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaConcurrency:
    @pytest.mark.aws_validated
    def test_lambda_concurrency_block(self, snapshot, create_lambda_function, lambda_client):
        """
        Tests an edge case where reserved concurrency is equal to the sum of all provisioned concurrencies for a function.
        In this case we can't call $LATEST anymore since there's no "free"/unclaimed concurrency left to execute the function with
        """
        # function
        func_name = f"fn-concurrency-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
        )

        # reserved concurrency
        v1_result = lambda_client.publish_version(FunctionName=func_name)
        snapshot.match("v1_result", v1_result)
        v1 = v1_result["Version"]

        # assert version is available(!)
        lambda_client.get_waiter(waiter_name="function_active_v2").wait(
            FunctionName=func_name, Qualifier=v1
        )

        # Reserved concurrency works on the whole function
        reserved_concurrency_result = lambda_client.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("reserved_concurrency_result", reserved_concurrency_result)

        # verify we can call $LATEST
        invoke_latest_before_block = lambda_client.invoke(
            FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_latest_before_block", invoke_latest_before_block)

        # Provisioned concurrency works on individual version/aliases, but *not* on $LATEST
        provisioned_concurrency_result = lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1, ProvisionedConcurrentExecutions=1
        )
        snapshot.match("provisioned_concurrency_result", provisioned_concurrency_result)

        assert wait_until(concurrency_update_done(lambda_client, func_name, v1))

        # verify we can't call $LATEST anymore
        with pytest.raises(lambda_client.exceptions.TooManyRequestsException) as e:
            lambda_client.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_first_exc", e.value.response)

        # but we can call the version with provisioned cocurrency
        invoke_v1_after_block = lambda_client.invoke(
            FunctionName=func_name, Qualifier=v1, Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_v1_after_block", invoke_v1_after_block)

        # verify we can't call $LATEST again
        with pytest.raises(lambda_client.exceptions.TooManyRequestsException) as e:
            lambda_client.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_second_exc", e.value.response)

    @pytest.mark.skipif(condition=is_aws(), reason="very slow (only execute when needed)")
    @pytest.mark.aws_validated
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, lambda_client, logs_client, create_lambda_function, snapshot
    ):
        """
        create fn ⇒ publish version ⇒ create alias for version ⇒ put concurrency on alias
        ⇒ new version with change ⇒ change alias to new version ⇒ concurrency moves with alias? same behavior for calls to alias/version?
        """

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        snapshot.match("get-function-configuration", fn)

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)

        get_function_configuration = lambda_client.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", get_function_configuration)

        lambda_client.get_waiter("function_updated_v2").wait(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )

        # There's no ProvisionedConcurrencyConfiguration yet
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = lambda_client.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_before_provisioned", get_function_result)
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, alias_name))
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        lambda_client.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(lambda_client, func_name))
        lambda_conf = lambda_client.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = lambda_client.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = lambda_client.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(lambda_client, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"
        assert (
            get_invoke_init_type(lambda_client, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(
            lambda_client.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        snapshot.match("provisioned_concurrency_notfound", e.value.response)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaVersions:
    @pytest.mark.aws_validated
    def test_lambda_versions_with_code_changes(
        self, lambda_client, lambda_su_role, create_lambda_function_aws, snapshot
    ):
        waiter = lambda_client.get_waiter("function_updated_v2")
        function_name = f"fn-{short_uid()}"
        zip_file_v1 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version1", get_content=True
        )
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="handler.handler",
            Code={"ZipFile": zip_file_v1},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)
        first_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        update_lambda_response = lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        invocation_result_latest = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        snapshot.match("invocation_result_latest", invocation_result_latest)
        invocation_result_v1 = lambda_client.invoke(
            FunctionName=function_name, Qualifier=first_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v1", invocation_result_v1)
        second_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        invocation_result_v2 = lambda_client.invoke(
            FunctionName=function_name, Qualifier=second_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v2", invocation_result_v2)
        zip_file_v3 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version3", get_content=True
        )
        update_lambda_response_with_publish = lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v3, Publish=True
        )
        snapshot.match("update_lambda_response_with_publish", update_lambda_response_with_publish)
        waiter.wait(
            FunctionName=function_name, Qualifier=update_lambda_response_with_publish["Version"]
        )
        invocation_result_v3 = lambda_client.invoke(
            FunctionName=function_name,
            Qualifier=update_lambda_response_with_publish["Version"],
            Payload=b"{}",
        )
        snapshot.match("invocation_result_v3", invocation_result_v3)
        invocation_result_latest_end = lambda_client.invoke(
            FunctionName=function_name, Payload=b"{}"
        )
        snapshot.match("invocation_result_latest_end", invocation_result_latest_end)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaAliases:
    @pytest.mark.aws_validated
    def test_lambda_alias_moving(
        self, lambda_client, lambda_su_role, create_lambda_function_aws, snapshot
    ):
        """Check if alias only moves after it is updated"""
        waiter = lambda_client.get_waiter("function_updated_v2")
        function_name = f"fn-{short_uid()}"
        zip_file_v1 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version1", get_content=True
        )
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="handler.handler",
            Code={"ZipFile": zip_file_v1},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)
        first_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=first_publish_response["Version"])
        # create alias
        create_alias_response = lambda_client.create_alias(
            FunctionName=function_name,
            FunctionVersion=first_publish_response["Version"],
            Name="alias1",
        )
        snapshot.match("create_alias_response", create_alias_response)
        invocation_result_qualifier_v1 = lambda_client.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1", invocation_result_qualifier_v1)
        invocation_result_qualifier_v1_arn = lambda_client.invoke(
            FunctionName=create_alias_response["AliasArn"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1_arn", invocation_result_qualifier_v1_arn)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        # update lambda code
        update_lambda_response = lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        # check if alias is still first version
        invocation_result_qualifier_v1_after_update = lambda_client.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_update",
            invocation_result_qualifier_v1_after_update,
        )
        # publish to 2
        second_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # check if invoke still targets 1
        invocation_result_qualifier_v1_after_publish = lambda_client.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_publish",
            invocation_result_qualifier_v1_after_publish,
        )
        # move alias to 2
        update_alias_response = lambda_client.update_alias(
            FunctionName=function_name,
            Name=create_alias_response["Name"],
            FunctionVersion=second_publish_response["Version"],
        )
        snapshot.match("update_alias_response", update_alias_response)
        # check if alias moved to 2
        invocation_result_qualifier_v2 = lambda_client.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v2", invocation_result_qualifier_v2)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.invoke(
                FunctionName=function_name, Qualifier="non-existent-alias", Payload=b"{}"
            )
        snapshot.match("invocation_exc_not_existent", e.value.response)

    @pytest.mark.aws_validated
    def test_alias_routingconfig(
        self, lambda_client, lambda_su_role, create_lambda_function_aws, snapshot
    ):
        waiter = lambda_client.get_waiter("function_updated_v2")
        function_name = f"fn-{short_uid()}"
        zip_file_v1 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version1", get_content=True
        )
        create_function_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="handler.handler",
            Code={"ZipFile": zip_file_v1},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Description="First version :)",
            Publish=True,
        )
        waiter.wait(FunctionName=function_name)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        # update lambda code
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=zip_file_v2)
        waiter.wait(FunctionName=function_name)

        second_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # create alias
        create_alias_response = lambda_client.create_alias(
            FunctionName=function_name,
            FunctionVersion=create_function_response["Version"],
            Name="alias1",
            RoutingConfig={"AdditionalVersionWeights": {second_publish_response["Version"]: 0.5}},
        )
        snapshot.match("create_alias_response", create_alias_response)
        retries = 0
        max_retries = 20
        versions_hit = set()
        while len(versions_hit) < 2 and retries < max_retries:
            invoke_response = lambda_client.invoke(
                FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
            )
            payload = json.loads(to_str(invoke_response["Payload"].read()))
            versions_hit.add(payload["version_from_ctx"])
            retries += 1
        assert len(versions_hit) == 2, f"Did not hit both versions after {max_retries} retries"
