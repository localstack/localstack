import base64
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Dict, TypeVar

import pytest
from botocore.response import StreamingBody

from localstack import config
from localstack.aws.api.lambda_ import Architecture, Runtime
from localstack.services.awslambda.lambda_api import use_docker
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    is_old_local_executor,
    is_old_provider,
    update_done,
)
from localstack.testing.aws.util import create_client_with_keys, is_aws_cloud
from localstack.testing.pytest.snapshot import is_aws
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.testing.snapshots.transformer_utility import PATTERN_UUID
from localstack.utils import files, platform, testutil
from localstack.utils.files import load_file
from localstack.utils.http import safe_requests
from localstack.utils.platform import get_arch, is_arm_compatible, standardized_arch
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry, wait_until
from localstack.utils.testutil import create_lambda_archive

LOG = logging.getLogger(__name__)
FUNCTION_MAX_UNZIPPED_SIZE = 262144000


# TODO: find a better way to manage these handler files
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_ECHO_ZIP = os.path.join(THIS_FOLDER, "functions/echo.zip")
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
TEST_LAMBDA_TIMEOUT_ENV_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_timeout_env.py")
TEST_LAMBDA_SLEEP_ENVIRONMENT = os.path.join(THIS_FOLDER, "functions/lambda_sleep_environment.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_introspect.py")
TEST_LAMBDA_ULIMITS = os.path.join(THIS_FOLDER, "functions/lambda_ulimits.py")
TEST_LAMBDA_INVOCATION_TYPE = os.path.join(THIS_FOLDER, "functions/lambda_invocation_type.py")
TEST_LAMBDA_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_version.py")
TEST_LAMBDA_CONTEXT_REQID = os.path.join(THIS_FOLDER, "functions/lambda_context.py")

TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"

PYTHON_TEST_RUNTIMES = (
    [
        Runtime.python3_7,
        Runtime.python3_8,
        Runtime.python3_9,
        Runtime.python3_10,
    ]
    if (not is_old_provider() or use_docker()) and get_arch() != "arm64"
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
    if (not is_old_provider() or use_docker()) and get_arch() != "arm64"
    else [Runtime.java11]
)

TEST_LAMBDA_LIBS = [
    "requests",
    "psutil",
    "urllib3",
    "charset_normalizer",
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
pytestmark = pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
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
        "$..SnapStart",
    ],
)


class TestLambdaBaseFeatures:
    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult"])
    @pytest.mark.aws_validated
    def test_large_payloads(self, caplog, create_lambda_function, snapshot, aws_client):
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
        result = aws_client.awslambda.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        snapshot.match("invocation_response", result)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Tags",
            "$..Configuration.RevisionId",
            "$..Code.RepositoryType",
            "$..Layers",  # PRO
            "$..RuntimeVersionConfig",
        ],
    )
    @pytest.mark.aws_validated
    def test_function_state(self, lambda_su_role, snapshot, create_lambda_function_aws, aws_client):
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

        response = aws_client.awslambda.get_function(FunctionName=function_name)
        snapshot.match("get-fn-response", response)

    @pytest.mark.skipif(
        is_old_provider(), reason="Credential injection not supported in old provider"
    )
    @pytest.mark.aws_validated
    def test_lambda_different_iam_keys_environment(
        self, lambda_su_role, create_lambda_function, snapshot, aws_client
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
            result = aws_client.awslambda.invoke(
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
        condition=is_old_provider,
        paths=[
            # empty dict is interpreted as string and fails upon event parsing
            "$..FunctionError",
            "$..LogResult",
            "$..Payload.errorMessage",
            "$..Payload.errorType",
            "$..Payload.event",
            "$..Payload.platform_machine",
            "$..Payload.platform_system",
            "$..Payload.stackTrace",
            "$..Payload.paths",
            "$..Payload.pwd",
            "$..Payload.user_login_name",
            "$..Payload.user_whoami",
        ],
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            # fixable by setting /tmp permissions to 700
            "$..Payload.paths._tmp_mode",
            # requires creating a new user `slicer` and chown /var/task
            "$..Payload.paths._var_task_gid",
            "$..Payload.paths._var_task_owner",
            "$..Payload.paths._var_task_uid",
        ],
    )
    # TODO: fix arch compatibility detection for supported emulations
    @pytest.mark.skipif(get_arch() == "arm64", reason="Cannot inspect x86 runtime on arm")
    @pytest.mark.aws_validated
    def test_runtime_introspection_x86(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_x86_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            timeout=9,
            Architectures=[Architecture.x86_64],
        )

        invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_x86_introspection", invoke_result)

    @pytest.mark.skipif(is_old_provider(), reason="unsupported in old provider")
    @pytest.mark.skipif(
        not is_arm_compatible() and not is_aws(),
        reason="ARM architecture not supported on this host",
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            # fixable by setting /tmp permissions to 700
            "$..Payload.paths._tmp_mode",
            # requires creating a new user `slicer` and chown /var/task
            "$..Payload.paths._var_task_gid",
            "$..Payload.paths._var_task_owner",
            "$..Payload.paths._var_task_uid",
        ],
    )
    @pytest.mark.aws_validated
    def test_runtime_introspection_arm(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_arm_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            timeout=9,
            Architectures=[Architecture.arm64],
        )

        invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_arm_introspection", invoke_result)

    @pytest.mark.skipif(
        is_old_local_executor(),
        reason="Monkey-patching of Docker flags is not applicable because no new container is spawned",
    )
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..LogResult"])
    @pytest.mark.aws_validated
    def test_runtime_ulimits(self, create_lambda_function, snapshot, monkeypatch, aws_client):
        """We consider ulimits parity as opt-in because development environments could hit these limits unlike in
        optimized production deployments."""
        monkeypatch.setattr(
            config,
            "LAMBDA_DOCKER_FLAGS",
            "--ulimit nofile=1024:1024 --ulimit nproc=735:735 --ulimit core=-1:-1 --ulimit stack=8388608:-1",
        )

        func_name = f"test_lambda_ulimits_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ULIMITS,
            runtime=Runtime.python3_9,
        )

        invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_ulimits", invoke_result)

    @pytest.mark.skipif(is_old_provider(), reason="unsupported in old provider")
    @pytest.mark.skipif(
        is_old_local_executor(),
        reason="Monkey-patching of Docker flags is not applicable because no new container is spawned",
    )
    @pytest.mark.only_localstack
    def test_ignore_architecture(self, create_lambda_function, snapshot, monkeypatch, aws_client):
        """Test configuration to ignore lambda architecture by creating a lambda with non-native architecture."""
        monkeypatch.setattr(config, "LAMBDA_IGNORE_ARCHITECTURE", True)

        # Assumes that LocalStack runs on native Docker host architecture
        # This assumption could be violated when using remote Lambda executors
        native_arch = platform.get_arch()
        non_native_architecture = (
            Architecture.x86_64 if native_arch == "arm64" else Architecture.arm64
        )
        func_name = f"test_lambda_arch_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            Architectures=[non_native_architecture],
        )

        invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        payload = json.loads(to_str(invoke_result["Payload"].read()))
        lambda_arch = standardized_arch(payload.get("platform_machine"))
        assert lambda_arch == native_arch

    @pytest.mark.skipif(is_old_provider(), reason="unsupported in old provider")
    @pytest.mark.skip  # TODO remove once is_arch_compatible checks work properly
    @pytest.mark.aws_validated
    def test_mixed_architecture(self, create_lambda_function, aws_client):
        """Test emulation and interaction of lambda functions with different architectures.
        Limitation: only works on ARM hosts that support x86 emulation.
        """
        func_name = f"test_lambda_x86_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            Architectures=[Architecture.x86_64],
        )

        invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        assert "FunctionError" not in invoke_result
        payload = json.loads(invoke_result["Payload"].read())
        assert payload.get("platform_machine") == "x86_64"

        func_name_arm = f"test_lambda_arm_{short_uid()}"
        create_lambda_function(
            func_name=func_name_arm,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            Architectures=[Architecture.arm64],
        )

        invoke_result_arm = aws_client.awslambda.invoke(FunctionName=func_name_arm)
        assert "FunctionError" not in invoke_result_arm
        payload_arm = json.loads(invoke_result_arm["Payload"].read())
        assert payload_arm.get("platform_machine") == "aarch64"

        v1_result = aws_client.awslambda.publish_version(FunctionName=func_name)
        v1 = v1_result["Version"]

        # assert version is available(!)
        aws_client.awslambda.get_waiter(waiter_name="function_active_v2").wait(
            FunctionName=func_name, Qualifier=v1
        )

        arm_v1_result = aws_client.awslambda.publish_version(FunctionName=func_name_arm)
        arm_v1 = arm_v1_result["Version"]

        # assert version is available(!)
        aws_client.awslambda.get_waiter(waiter_name="function_active_v2").wait(
            FunctionName=func_name_arm, Qualifier=arm_v1
        )

        invoke_result_2 = aws_client.awslambda.invoke(FunctionName=func_name, Qualifier=v1)
        assert "FunctionError" not in invoke_result_2
        payload_2 = json.loads(invoke_result_2["Payload"].read())
        assert payload_2.get("platform_machine") == "x86_64"

        invoke_result_arm_2 = aws_client.awslambda.invoke(
            FunctionName=func_name_arm, Qualifier=arm_v1
        )
        assert "FunctionError" not in invoke_result_arm_2
        payload_arm_2 = json.loads(invoke_result_arm_2["Payload"].read())
        assert payload_arm_2.get("platform_machine") == "aarch64"

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
        self, create_lambda_function, lambda_fn, lambda_runtime, snapshot, aws_client
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=aws_client.awslambda,
        )

        first_invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("first_invoke_result", first_invoke_result)

        second_invoke_result = aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("second_invoke_result", second_invoke_result)

    @pytest.mark.skipif(is_old_provider(), reason="old provider")
    @pytest.mark.aws_validated
    def test_lambda_invoke_with_timeout(self, create_lambda_function, snapshot, aws_client):
        # Snapshot generation could be flaky against AWS with a small timeout margin (e.g., 1.02 instead of 1.00)
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
            client=aws_client.awslambda,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"wait": 2})
        )
        snapshot.match("invoke-result", result)

        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = aws_client.logs.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            # TODO: this part is a bit flaky, at least locally with old provider
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Payload",
            "$..LogResult",
            "$..Layers",
            "$..CreateFunctionResponse.RuntimeVersionConfig",
        ],
    )
    @pytest.mark.aws_validated
    def test_lambda_invoke_no_timeout(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_TIMEOUT_PYTHON,
            runtime=Runtime.python3_8,
            client=aws_client.awslambda,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"wait": 1})
        )
        snapshot.match("invoke-result", result)
        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def _assert_log_output():
            log_events = aws_client.logs.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]
            return any(["starting wait" in e["message"] for e in log_events]) and any(
                ["done waiting" in e["message"] for e in log_events]
            )

        wait_until(_assert_log_output, strategy="linear")

    @pytest.mark.skipif(is_old_provider(), reason="old provider")
    @pytest.mark.xfail(reason="Currently flaky in CI")
    @pytest.mark.aws_validated
    def test_lambda_invoke_timed_out_environment_reuse(
        self, create_lambda_function, snapshot, aws_client
    ):
        """Test checking if a timeout leads to a new environment with a new filesystem (and lost /tmp) or not"""
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
            handler_file=TEST_LAMBDA_TIMEOUT_ENV_PYTHON,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
            timeout=1,
        )
        snapshot.match("create-result", create_result)
        file_content = "some-content"
        set_number = 42

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"write-file": file_content})
        )
        snapshot.match("invoke-result-file-write", result)
        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-file": True})
        )
        snapshot.match("invoke-result-file-read", result)
        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"set-number": set_number})
        )
        snapshot.match("invoke-result-set-number", result)
        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-number": True})
        )
        snapshot.match("invoke-result-read-number", result)
        # file is written, let's let the function timeout and check if it is still there

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"sleep": 2})
        )
        snapshot.match("invoke-result-timed-out", result)
        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = aws_client.logs.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            # TODO: this part is a bit flaky, at least locally with old provider
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

        # check if, for the next normal invocation, the file is still there:
        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-file": True})
        )
        snapshot.match("invoke-result-file-read-after-timeout", result)
        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-number": True})
        )
        snapshot.match("invoke-result-read-number-after-timeout", result)


URL_HANDLER_CODE = """
def handler(event, ctx):
    return <<returnvalue>>
"""


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
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..event.headers.x-forwarded-proto",
        "$..event.headers.x-forwarded-port",
        "$..event.headers.x-amzn-trace-id",
    ],
)
class TestLambdaURL:
    # TODO: add more tests

    @pytest.mark.parametrize(
        "returnvalue",
        [
            '{"hello": "world"}',
            '{"statusCode": 200, "body": "body123"}',
            '{"statusCode": 200, "body": "{\\"hello\\": \\"world\\"}"}',
            '["hello", 3, True]',
            '"hello"',
            "3",
            "3.1",
            "True",
        ],
        ids=[
            "dict",
            "http-response",
            "http-response-json",
            "list-mixed",
            "string",
            "integer",
            "float",
            "boolean",
        ],
    )
    @pytest.mark.skipif(condition=is_old_provider(), reason="broken/not-implemented")
    @pytest.mark.aws_validated
    def test_lambda_url_invocation(self, create_lambda_function, snapshot, returnvalue, aws_client):
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "FunctionUrl", "<function-url>", reference_replacement=False
            )
        )

        function_name = f"test-function-{short_uid()}"

        handler_file = files.new_tmp_file()
        handler_code = URL_HANDLER_CODE.replace("<<returnvalue>>", returnvalue)
        files.save_file(handler_file, handler_code)

        create_lambda_function(
            func_name=function_name,
            handler_file=handler_file,
            runtime=Runtime.python3_9,
        )

        url_config = aws_client.awslambda.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.awslambda.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        snapshot.match("add_permission", permissions_response)

        url = f"{url_config['FunctionUrl']}custom_path/extend?test_param=test_value"
        result = safe_requests.post(url, data=b"{'key':'value'}")
        snapshot.match(
            "lambda_url_invocation",
            {
                "statuscode": result.status_code,
                "headers": {
                    "Content-Type": result.headers["Content-Type"],
                    "Content-Length": result.headers["Content-Length"],
                },
                "content": to_str(result.content),
            },
        )

    @pytest.mark.aws_validated
    def test_lambda_url_echo_invoke(self, create_lambda_function, snapshot, aws_client):
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "FunctionUrl", "<function-url>", reference_replacement=False
            )
        )
        function_name = f"test-fnurl-echo-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs16_x,
            handler="lambda_url.handler",
        )

        url_config = aws_client.awslambda.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.awslambda.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        snapshot.match("add_permission", permissions_response)

        url = f"{url_config['FunctionUrl']}custom_path/extend?test_param=test_value"

        # TODO: add more cases
        result = safe_requests.post(url, data="text", headers={"Content-Type": "text/plain"})
        assert result.status_code == 200
        event = json.loads(result.content)["event"]
        assert event["body"] == "text"
        assert event["isBase64Encoded"] is False

        result = safe_requests.post(url)
        event = json.loads(result.content)["event"]
        assert "Body" not in event
        assert event["isBase64Encoded"] is False

    @pytest.mark.aws_validated
    @pytest.mark.skipif(condition=is_old_provider(), reason="broken/not-implemented")
    def test_lambda_url_invocation_exception(self, create_lambda_function, snapshot, aws_client):
        # TODO: extend tests
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", reference_replacement=False)
        )
        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=Runtime.python3_9,
        )
        get_fn_result = aws_client.awslambda.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        url_config = aws_client.awslambda.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.awslambda.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        snapshot.match("add_permission", permissions_response)

        url = url_config["FunctionUrl"]

        result = safe_requests.post(
            url, data=b"{}", headers={"User-Agent": "python-requests/testing"}
        )
        assert to_str(result.content) == "Internal Server Error"
        assert result.status_code == 502


@pytest.mark.skip(reason="Not yet implemented")
class TestLambdaPermissions:
    @pytest.mark.aws_validated
    def test_lambda_permission_url_invocation(self, create_lambda_function, snapshot, aws_client):

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs18_x,
            handler="lambda_url.handler",
        )
        url_config = aws_client.awslambda.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        # Intentionally missing add_permission for invoking lambda function

        url = url_config["FunctionUrl"]
        result = safe_requests.post(url, data="text", headers={"Content-Type": "text/plain"})
        assert result.status_code == 403
        snapshot.match("lambda_url_invocation_missing_permission", result.text)


class TestLambdaFeatures:
    @pytest.fixture(
        params=[
            ("nodejs16.x", TEST_LAMBDA_NODEJS_ECHO),
            ("python3.10", TEST_LAMBDA_PYTHON_ECHO),
        ],
        ids=["nodejs16.x", "python3.10"],
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
    def test_invocation_with_logs(self, snapshot, invocation_echo_lambda, aws_client):
        """Test invocation of a lambda with no invocation type set, but LogType="Tail""" ""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))
        snapshot.add_transformer(
            snapshot.transform.key_value("LogResult", reference_replacement=False)
        )

        result = aws_client.awslambda.invoke(
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
    def test_invocation_type_request_response(self, snapshot, invocation_echo_lambda, aws_client):
        """Test invocation with InvocationType RequestResponse explicitly set"""
        result = aws_client.awslambda.invoke(
            FunctionName=invocation_echo_lambda,
            Payload=b"{}",
            InvocationType="RequestResponse",
        )
        snapshot.match("invoke-result", result)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..LogResult", "$..ExecutedVersion"]
    )
    @pytest.mark.aws_validated
    def test_invocation_type_event(self, snapshot, invocation_echo_lambda, aws_client):
        """Check invocation response for type event"""
        result = aws_client.awslambda.invoke(
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
    def test_invocation_type_dry_run(self, snapshot, invocation_echo_lambda, aws_client):
        """Check invocation response for type dryrun"""
        result = aws_client.awslambda.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", InvocationType="DryRun"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 204 == result["StatusCode"]

    @pytest.mark.skip(reason="Not yet implemented")
    @pytest.mark.aws_validated
    def test_invocation_type_event_error(self, create_lambda_function, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))

        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=Runtime.python3_10,
        )
        snapshot.match("creation_response", creation_response)
        invocation_response = aws_client.awslambda.invoke(
            FunctionName=function_name, Payload=b"{}", InvocationType="Event"
        )
        snapshot.match("invocation_response", invocation_response)

        # check logs if lambda was executed twice
        log_group_name = f"/aws/lambda/{function_name}"

        def assert_events():
            ls_result = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
            log_stream_name = ls_result["logStreams"][0]["logStreamName"]
            log_events = aws_client.logs.get_log_events(
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
        s3_bucket,
        check_lambda_logs,
        lambda_su_role,
        wait_until_lambda_ready,
        create_lambda_function_aws,
        snapshot,
        aws_client,
    ):
        """Tests invocation of python lambda with a given qualifier"""
        snapshot.add_transformer(snapshot.transform.key_value("LogResult"))

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            runtime=Runtime.python3_10,
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_10,
            Role=lambda_su_role,
            Publish=True,
            Handler="handler.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", response)
        qualifier = response["Version"]

        # invoke lambda function
        invoke_result = aws_client.awslambda.invoke(
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
        s3_bucket,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
        create_lambda_function_aws,
        aws_client,
    ):
        """Test invocation of a python lambda with its deployment package uploaded to s3"""
        snapshot.add_transformer(snapshot.transform.s3_api())

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            runtime=Runtime.python3_10,
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_10,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", create_response)

        # invoke lambda function
        result = aws_client.awslambda.invoke(
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
        self, create_lambda_function, check_lambda_logs, snapshot, aws_client
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

        result = aws_client.awslambda.invoke(
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


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaConcurrency:
    @pytest.mark.aws_validated
    def test_lambda_concurrency_crud(self, snapshot, create_lambda_function, aws_client):
        func_name = f"fn-concurrency-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
        )

        default_concurrency_result = aws_client.awslambda.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_default", default_concurrency_result)

        # 0 should always succeed independent of the UnreservedConcurrentExecution limits
        reserved_concurrency_result = aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=0
        )
        snapshot.match("put_function_concurrency", reserved_concurrency_result)

        updated_concurrency_result = aws_client.awslambda.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_updated", updated_concurrency_result)
        assert updated_concurrency_result["ReservedConcurrentExecutions"] == 0

        aws_client.awslambda.delete_function_concurrency(FunctionName=func_name)

        deleted_concurrency_result = aws_client.awslambda.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_deleted", deleted_concurrency_result)

    @pytest.mark.skip(reason="Requires prefer-provisioned feature")
    @pytest.mark.aws_validated
    def test_lambda_concurrency_block(self, snapshot, create_lambda_function, aws_client):
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
        v1_result = aws_client.awslambda.publish_version(FunctionName=func_name)
        snapshot.match("v1_result", v1_result)
        v1 = v1_result["Version"]

        # assert version is available(!)
        aws_client.awslambda.get_waiter(waiter_name="function_active_v2").wait(
            FunctionName=func_name, Qualifier=v1
        )

        # Reserved concurrency works on the whole function
        reserved_concurrency_result = aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("reserved_concurrency_result", reserved_concurrency_result)

        # verify we can call $LATEST
        invoke_latest_before_block = aws_client.awslambda.invoke(
            FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_latest_before_block", invoke_latest_before_block)

        # Provisioned concurrency works on individual version/aliases, but *not* on $LATEST
        provisioned_concurrency_result = aws_client.awslambda.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1, ProvisionedConcurrentExecutions=1
        )
        snapshot.match("provisioned_concurrency_result", provisioned_concurrency_result)

        assert wait_until(concurrency_update_done(aws_client.awslambda, func_name, v1))

        # verify we can't call $LATEST anymore
        with pytest.raises(aws_client.awslambda.exceptions.TooManyRequestsException) as e:
            aws_client.awslambda.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_first_exc", e.value.response)

        # but we can call the version with provisioned concurrency
        invoke_v1_after_block = aws_client.awslambda.invoke(
            FunctionName=func_name, Qualifier=v1, Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_v1_after_block", invoke_v1_after_block)

        # verify we can't call $LATEST again
        with pytest.raises(aws_client.awslambda.exceptions.TooManyRequestsException) as e:
            aws_client.awslambda.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_second_exc", e.value.response)

    @pytest.mark.skipif(not is_old_provider(), reason="Not yet implemented")
    @pytest.mark.skipif(condition=is_aws(), reason="very slow (only execute when needed)")
    @pytest.mark.aws_validated
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, create_lambda_function, snapshot, aws_client
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
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_8,
            client=aws_client.awslambda,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = aws_client.awslambda.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("get-function-configuration", fn)

        first_ver = aws_client.awslambda.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)

        get_function_configuration = aws_client.awslambda.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", get_function_configuration)

        aws_client.awslambda.get_waiter("function_updated_v2").wait(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )

        # There's no ProvisionedConcurrencyConfiguration yet
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, first_ver["Version"])
            == "on-demand"
        )

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = aws_client.awslambda.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        get_function_result = aws_client.awslambda.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_before_provisioned", get_function_result)
        aws_client.awslambda.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(aws_client.awslambda, func_name, alias_name))
        get_function_result = aws_client.awslambda.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, alias_name)
            == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        aws_client.awslambda.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(aws_client.awslambda, func_name))
        lambda_conf = aws_client.awslambda.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = aws_client.awslambda.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = aws_client.awslambda.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = aws_client.awslambda.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(aws_client.awslambda, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, first_ver["Version"])
            == "on-demand"
        )
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(aws_client.awslambda, func_name, alias_name)
            == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(
            aws_client.awslambda.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            aws_client.awslambda.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        snapshot.match("provisioned_concurrency_notfound", e.value.response)

    @pytest.mark.aws_validated
    def test_provisioned_concurrency(self, create_lambda_function, snapshot, aws_client):
        """
        TODO: what happens with running invocations in provisioned environments when the provisioned concurrency is deleted?
        TODO: are the previous provisioned environments not available for new invocations anymore?
        TODO: lambda_client.delete_provisioned_concurrency_config()

        Findings (mostly through manual testing, observing, changing the test here and doing semi-manual runs)
        - execution environments are provisioned nearly in parallel (we had *ONE*  case where it first spawned 19/20)
        - it generates 2x provisioned concurrency cloudwatch logstreams with only INIT_START
        - updates while IN_PROGRESS are allowed and overwrite the previous config
        """
        func_name = f"test_lambda_{short_uid()}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
        )

        v1 = aws_client.awslambda.publish_version(FunctionName=func_name)

        put_provisioned = aws_client.awslambda.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=5
        )
        snapshot.match("put_provisioned_5", put_provisioned)

        get_provisioned_prewait = aws_client.awslambda.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_prewait", get_provisioned_prewait)
        assert wait_until(concurrency_update_done(aws_client.awslambda, func_name, v1["Version"]))
        get_provisioned_postwait = aws_client.awslambda.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_postwait", get_provisioned_postwait)

        invoke_result1 = aws_client.awslambda.invoke(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        result1 = json.loads(to_str(invoke_result1["Payload"].read()))
        assert result1 == "provisioned-concurrency"

        invoke_result2 = aws_client.awslambda.invoke(FunctionName=func_name, Qualifier="$LATEST")
        result2 = json.loads(to_str(invoke_result2["Payload"].read()))
        assert result2 == "on-demand"

    @pytest.mark.aws_validated
    def test_reserved_concurrency_async_queue(
        self, create_lambda_function, snapshot, sqs_create_queue, aws_client
    ):
        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
            timeout=20,
        )

        fn = aws_client.awslambda.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("fn", fn)
        fn_arn = fn["FunctionArn"]

        # sequential execution
        put_fn_concurrency = aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_fn_concurrency", put_fn_concurrency)

        aws_client.awslambda.invoke(
            FunctionName=fn_arn, InvocationType="Event", Payload=json.dumps({"wait": 10})
        )
        aws_client.awslambda.invoke(
            FunctionName=fn_arn, InvocationType="Event", Payload=json.dumps({"wait": 10})
        )

        time.sleep(4)  # make sure one is already in the "queue" and one is being executed

        with pytest.raises(aws_client.awslambda.exceptions.TooManyRequestsException) as e:
            aws_client.awslambda.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")
        snapshot.match("too_many_requests_exc", e.value.response)

        with pytest.raises(aws_client.awslambda.exceptions.InvalidParameterValueException) as e:
            aws_client.awslambda.put_function_concurrency(
                FunctionName=fn_arn, ReservedConcurrentExecutions=2
            )
        snapshot.match("put_function_concurrency_qualified_arn_exc", e.value.response)

        aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=2
        )
        aws_client.awslambda.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")

        def assert_events():
            log_events = aws_client.logs.filter_log_events(
                logGroupName=f"/aws/lambda/{func_name}",
            )["events"]
            assert len([e["message"] for e in log_events if e["message"].startswith("REPORT")]) == 3

        retry(assert_events, retries=120, sleep=2)

        # TODO: snapshot logs & request ID for correlation after request id gets propagated
        #  https://github.com/localstack/localstack/pull/7874

    @pytest.mark.aws_validated
    def test_reserved_concurrency(
        self, create_lambda_function, snapshot, sqs_create_queue, aws_client
    ):
        snapshot.add_transformer(
            snapshot.transform.key_value("MD5OfBody", "<md5-of-body>", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "ReceiptHandle", "receipt-handle", reference_replacement=True
            )
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("SenderId", "<sender-id>", reference_replacement=False)
        )
        func_name = f"test_lambda_{short_uid()}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
            timeout=20,
        )

        fn = aws_client.awslambda.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("fn", fn)
        fn_arn = fn["FunctionArn"]

        # block execution by setting reserved concurrency to 0
        put_reserved = aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=0
        )
        snapshot.match("put_reserved", put_reserved)

        with pytest.raises(aws_client.awslambda.exceptions.TooManyRequestsException) as e:
            aws_client.awslambda.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")
        snapshot.match("exc_no_cap_requestresponse", e.value.response)

        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        put_event_invoke_conf = aws_client.awslambda.put_function_event_invoke_config(
            FunctionName=func_name,
            MaximumRetryAttempts=0,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        snapshot.match("put_event_invoke_conf", put_event_invoke_conf)

        time.sleep(3)  # just to be sure

        invoke_result = aws_client.awslambda.invoke(FunctionName=fn_arn, InvocationType="Event")
        snapshot.match("invoke_result", invoke_result)

        def get_msg_from_queue():
            msgs = aws_client.sqs.receive_message(
                QueueUrl=queue_url, AttributeNames=["All"], WaitTimeSeconds=5
            )
            return msgs["Messages"][0]

        msg = retry(get_msg_from_queue, retries=10, sleep=2)
        snapshot.match("msg", msg)

    @pytest.mark.aws_validated
    def test_reserved_provisioned_overlap(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_{short_uid()}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
        )

        v1 = aws_client.awslambda.publish_version(FunctionName=func_name)

        put_provisioned = aws_client.awslambda.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=2
        )
        snapshot.match("put_provisioned_5", put_provisioned)

        get_provisioned_prewait = aws_client.awslambda.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_prewait", get_provisioned_prewait)
        assert wait_until(concurrency_update_done(aws_client.awslambda, func_name, v1["Version"]))
        get_provisioned_postwait = aws_client.awslambda.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_postwait", get_provisioned_postwait)

        with pytest.raises(aws_client.awslambda.exceptions.InvalidParameterValueException) as e:
            aws_client.awslambda.put_function_concurrency(
                FunctionName=func_name, ReservedConcurrentExecutions=1
            )
        snapshot.match("reserved_lower_than_provisioned_exc", e.value.response)
        aws_client.awslambda.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=2
        )
        get_concurrency = aws_client.awslambda.get_function_concurrency(FunctionName=func_name)
        snapshot.match("get_concurrency", get_concurrency)

        # absolute limit, this means there is no free function execution for any invoke that doesn't have provisioned concurrency (!)
        with pytest.raises(aws_client.awslambda.exceptions.TooManyRequestsException) as e:
            aws_client.awslambda.invoke(FunctionName=func_name)
        snapshot.match("reserved_equals_provisioned_latest_invoke_exc", e.value.response)

        # passes since the version has a provisioned concurrency config set
        # TODO: re-add this when implementing it in version manager
        # invoke_result1 = lambda_client.invoke(FunctionName=func_name, Qualifier=v1["Version"])
        # result1 = json.loads(to_str(invoke_result1["Payload"].read()))
        # assert result1 == "provisioned-concurrency"

        # try to add a new provisioned concurrency config to another qualifier on the same function
        update_func_config = aws_client.awslambda.update_function_configuration(
            FunctionName=func_name, Timeout=15
        )
        snapshot.match("update_func_config", update_func_config)
        aws_client.awslambda.get_waiter("function_updated_v2").wait(FunctionName=func_name)

        v2 = aws_client.awslambda.publish_version(FunctionName=func_name)
        assert v1["Version"] != v2["Version"]
        # doesn't work because the reserved function concurrency is 2 and we already have a total provisioned sum of 2
        with pytest.raises(aws_client.awslambda.exceptions.InvalidParameterValueException) as e:
            aws_client.awslambda.put_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=v2["Version"], ProvisionedConcurrentExecutions=1
            )
        snapshot.match("reserved_equals_provisioned_another_provisioned_exc", e.value.response)

        # updating the provisioned concurrency config of v1 to 3 (from 2) should also not work
        with pytest.raises(aws_client.awslambda.exceptions.InvalidParameterValueException) as e:
            aws_client.awslambda.put_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=3
            )
        snapshot.match("reserved_equals_provisioned_increase_provisioned_exc", e.value.response)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaVersions:
    @pytest.mark.aws_validated
    def test_lambda_versions_with_code_changes(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        waiter = aws_client.awslambda.get_waiter("function_updated_v2")
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
        first_publish_response = aws_client.awslambda.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        update_lambda_response = aws_client.awslambda.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        invocation_result_latest = aws_client.awslambda.invoke(
            FunctionName=function_name, Payload=b"{}"
        )
        snapshot.match("invocation_result_latest", invocation_result_latest)
        invocation_result_v1 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=first_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v1", invocation_result_v1)
        second_publish_response = aws_client.awslambda.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        invocation_result_v2 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=second_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v2", invocation_result_v2)
        zip_file_v3 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version3", get_content=True
        )
        update_lambda_response_with_publish = aws_client.awslambda.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v3, Publish=True
        )
        snapshot.match("update_lambda_response_with_publish", update_lambda_response_with_publish)
        waiter.wait(
            FunctionName=function_name, Qualifier=update_lambda_response_with_publish["Version"]
        )
        invocation_result_v3 = aws_client.awslambda.invoke(
            FunctionName=function_name,
            Qualifier=update_lambda_response_with_publish["Version"],
            Payload=b"{}",
        )
        snapshot.match("invocation_result_v3", invocation_result_v3)
        invocation_result_latest_end = aws_client.awslambda.invoke(
            FunctionName=function_name, Payload=b"{}"
        )
        snapshot.match("invocation_result_latest_end", invocation_result_latest_end)
        invocation_result_v2 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=second_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v2_end", invocation_result_v2)
        invocation_result_v1 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=first_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v1_end", invocation_result_v1)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaAliases:
    @pytest.mark.aws_validated
    def test_lambda_alias_moving(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        """Check if alias only moves after it is updated"""
        waiter = aws_client.awslambda.get_waiter("function_updated_v2")
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
        first_publish_response = aws_client.awslambda.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=first_publish_response["Version"])
        # create alias
        create_alias_response = aws_client.awslambda.create_alias(
            FunctionName=function_name,
            FunctionVersion=first_publish_response["Version"],
            Name="alias1",
        )
        snapshot.match("create_alias_response", create_alias_response)
        invocation_result_qualifier_v1 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1", invocation_result_qualifier_v1)
        invocation_result_qualifier_v1_arn = aws_client.awslambda.invoke(
            FunctionName=create_alias_response["AliasArn"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1_arn", invocation_result_qualifier_v1_arn)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        # update lambda code
        update_lambda_response = aws_client.awslambda.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        # check if alias is still first version
        invocation_result_qualifier_v1_after_update = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_update",
            invocation_result_qualifier_v1_after_update,
        )
        # publish to 2
        second_publish_response = aws_client.awslambda.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # check if invoke still targets 1
        invocation_result_qualifier_v1_after_publish = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_publish",
            invocation_result_qualifier_v1_after_publish,
        )
        # move alias to 2
        update_alias_response = aws_client.awslambda.update_alias(
            FunctionName=function_name,
            Name=create_alias_response["Name"],
            FunctionVersion=second_publish_response["Version"],
        )
        snapshot.match("update_alias_response", update_alias_response)
        # check if alias moved to 2
        invocation_result_qualifier_v2 = aws_client.awslambda.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v2", invocation_result_qualifier_v2)
        with pytest.raises(aws_client.awslambda.exceptions.ResourceNotFoundException) as e:
            aws_client.awslambda.invoke(
                FunctionName=function_name, Qualifier="non-existent-alias", Payload=b"{}"
            )
        snapshot.match("invocation_exc_not_existent", e.value.response)

    @pytest.mark.aws_validated
    def test_alias_routingconfig(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        waiter = aws_client.awslambda.get_waiter("function_updated_v2")
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
        aws_client.awslambda.update_function_code(FunctionName=function_name, ZipFile=zip_file_v2)
        waiter.wait(FunctionName=function_name)

        second_publish_response = aws_client.awslambda.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # create alias
        create_alias_response = aws_client.awslambda.create_alias(
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
            invoke_response = aws_client.awslambda.invoke(
                FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
            )
            payload = json.loads(to_str(invoke_response["Payload"].read()))
            versions_hit.add(payload["version_from_ctx"])
            retries += 1
        assert len(versions_hit) == 2, f"Did not hit both versions after {max_retries} retries"


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestRequestIdHandling:
    @pytest.mark.aws_validated
    def test_request_id_format(self, aws_client):
        r = aws_client.awslambda.list_functions()
        request_id = r["ResponseMetadata"]["RequestId"]
        assert re.match(
            r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", request_id
        )

    @pytest.mark.aws_validated
    def test_request_id_invoke(self, aws_client, create_lambda_function, snapshot):
        func_name = f"test_lambda_{short_uid()}"
        log_group_name = f"/aws/lambda/{func_name}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
        )

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_result", result)
        snapshot.add_transformer(
            snapshot.transform.regex(result["ResponseMetadata"]["RequestId"], "<request-id>")
        )

        def fetch_logs():
            log_events_result = aws_client.logs.filter_log_events(logGroupName=log_group_name)
            assert any(["REPORT" in e["message"] for e in log_events_result["events"]])
            return log_events_result

        log_events = retry(fetch_logs, retries=10, sleep=2)
        end_log_entries = [
            e["message"].rstrip() for e in log_events["events"] if e["message"].startswith("END")
        ]
        snapshot.match("end_log_entries", end_log_entries)

    @pytest.mark.aws_validated
    def test_request_id_invoke_url(self, aws_client, create_lambda_function, snapshot):
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "FunctionUrl", "<function-url>", reference_replacement=False
            )
        )

        fn_name = f"test-url-fn{short_uid()}"
        log_group_name = f"/aws/lambda/{fn_name}"

        handler_file = files.new_tmp_file()
        handler_code = URL_HANDLER_CODE.replace("<<returnvalue>>", "'hi'")
        files.save_file(handler_file, handler_code)

        create_lambda_function(
            func_name=fn_name,
            handler_file=handler_file,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
        )

        url_config = aws_client.awslambda.create_function_url_config(
            FunctionName=fn_name,
            AuthType="NONE",
        )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.awslambda.add_permission(
            FunctionName=fn_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        snapshot.match("add_permission", permissions_response)

        url = f"{url_config['FunctionUrl']}custom_path/extend?test_param=test_value"
        result = safe_requests.post(url, data=b"{'key':'value'}")
        snapshot.match(
            "lambda_url_invocation",
            {
                "statuscode": result.status_code,
                "headers": {"x-amzn-RequestId": result.headers.get("x-amzn-RequestId")},
                "content": to_str(result.content),
            },
        )

        def fetch_logs():
            log_events_result = aws_client.logs.filter_log_events(logGroupName=log_group_name)
            assert any(["REPORT" in e["message"] for e in log_events_result["events"]])
            return log_events_result

        log_events = retry(fetch_logs, retries=10, sleep=2)
        # TODO: AWS appends a "\n" so we need to trim here. Should explore this more
        end_log_entries = [
            e["message"].rstrip() for e in log_events["events"] if e["message"].startswith("END")
        ]
        snapshot.match("end_log_entries", end_log_entries)

    @pytest.mark.aws_validated
    def test_request_id_async_invoke_with_retry(
        self, aws_client, create_lambda_function, monkeypatch, snapshot
    ):
        snapshot.add_transformer(
            snapshot.transform.key_value("eventId", "<event-id>", reference_replacement=False)
        )
        test_delay_base = 60
        if not is_aws_cloud():
            test_delay_base = 5
            monkeypatch.setattr(config, "LAMBDA_RETRY_BASE_DELAY_SECONDS", test_delay_base)

        func_name = f"test_lambda_{short_uid()}"
        log_group_name = f"/aws/lambda/{func_name}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_CONTEXT_REQID,
            runtime=Runtime.python3_9,
            client=aws_client.awslambda,
        )

        aws_client.awslambda.put_function_event_invoke_config(
            FunctionName=func_name, MaximumRetryAttempts=1
        )
        aws_client.awslambda.get_waiter("function_updated_v2").wait(FunctionName=func_name)

        result = aws_client.awslambda.invoke(
            FunctionName=func_name, InvocationType="Event", Payload=json.dumps({"fail": 1})
        )
        snapshot.match("invoke_result", result)

        request_id = result["ResponseMetadata"]["RequestId"]
        snapshot.add_transformer(snapshot.transform.regex(request_id, "<request-id>"))

        time.sleep(test_delay_base * 2)

        log_events = aws_client.logs.filter_log_events(logGroupName=log_group_name)
        report_messages = [e for e in log_events["events"] if "REPORT" in e["message"]]
        assert len(report_messages) == 2
        assert all([request_id in rm["message"] for rm in report_messages])
        end_messages = [
            e["message"].rstrip() for e in log_events["events"] if "END" in e["message"]
        ]
        snapshot.match("end_messages", end_messages)
