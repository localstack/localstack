"""Tests for Lambda behavior and implicit functionality.
Everything related to API operations goes into test_lambda_api.py instead."""

import base64
import json
import logging
import os
import random
import re
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Dict, TypeVar

import pytest
import requests
from botocore.config import Config
from botocore.response import StreamingBody
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack import config
from localstack.aws.api.lambda_ import Architecture, InvokeMode, Runtime
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.services.lambda_.runtimes import RUNTIMES_AGGREGATED
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    update_done,
)
from localstack.testing.aws.util import create_client_with_keys, is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import PATTERN_UUID
from localstack.utils import files, platform, testutil
from localstack.utils.aws import arns
from localstack.utils.aws.arns import lambda_function_name
from localstack.utils.files import load_file
from localstack.utils.http import safe_requests
from localstack.utils.platform import Arch, standardized_arch
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry, wait_until
from localstack.utils.testutil import create_lambda_archive
from tests.aws.services.lambda_.utils import get_s3_keys

LOG = logging.getLogger(__name__)

# TODO: find a better way to manage these handler files
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_ECHO_JSON_BODY = os.path.join(THIS_FOLDER, "functions/lambda_echo_json_body.py")
TEST_LAMBDA_PYTHON_ECHO_STATUS_CODE = os.path.join(
    THIS_FOLDER, "functions/lambda_echo_status_code.py"
)
TEST_LAMBDA_PYTHON_REQUEST_ID = os.path.join(THIS_FOLDER, "functions/lambda_request_id.py")
TEST_LAMBDA_PYTHON_ECHO_VERSION_ENV = os.path.join(
    THIS_FOLDER, "functions/lambda_echo_version_env.py"
)
TEST_LAMBDA_PYTHON_ROLE = os.path.join(THIS_FOLDER, "functions/lambda_role.py")
TEST_LAMBDA_MAPPING_RESPONSES = os.path.join(THIS_FOLDER, "functions/lambda_mapping_responses.py")
TEST_LAMBDA_PYTHON_SELECT_PATTERN = os.path.join(THIS_FOLDER, "functions/lambda_select_pattern.py")
TEST_LAMBDA_PYTHON_ECHO_ZIP = os.path.join(THIS_FOLDER, "functions/echo.zip")
TEST_LAMBDA_PYTHON_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_python_version.py")
TEST_LAMBDA_PYTHON_UNHANDLED_ERROR = os.path.join(
    THIS_FOLDER, "functions/lambda_unhandled_error.py"
)
TEST_LAMBDA_PYTHON_RUNTIME_ERROR = os.path.join(THIS_FOLDER, "functions/lambda_runtime_error.py")
TEST_LAMBDA_PYTHON_RUNTIME_EXIT = os.path.join(THIS_FOLDER, "functions/lambda_runtime_exit.py")
TEST_LAMBDA_PYTHON_RUNTIME_EXIT_SEGFAULT = os.path.join(
    THIS_FOLDER, "functions/lambda_runtime_exit_segfault.py"
)
TEST_LAMBDA_PYTHON_HANDLER_ERROR = os.path.join(THIS_FOLDER, "functions/lambda_handler_error.py")
TEST_LAMBDA_PYTHON_HANDLER_EXIT = os.path.join(THIS_FOLDER, "functions/lambda_handler_exit.py")
TEST_LAMBDA_AWS_PROXY = os.path.join(THIS_FOLDER, "functions/lambda_aws_proxy.py")
TEST_LAMBDA_AWS_PROXY_FORMAT = os.path.join(THIS_FOLDER, "functions/lambda_aws_proxy_format.py")
TEST_LAMBDA_PYTHON_S3_INTEGRATION = os.path.join(THIS_FOLDER, "functions/lambda_s3_integration.py")
TEST_LAMBDA_PYTHON_S3_INTEGRATION_FUNCTION_VERSION = os.path.join(
    THIS_FOLDER, "functions/lambda_s3_integration_function_version.py"
)
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
TEST_LAMBDA_NODEJS_ES6 = os.path.join(THIS_FOLDER, "functions/lambda_handler_es6.mjs")
TEST_LAMBDA_NODEJS_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.js")
TEST_LAMBDA_NODEJS_APIGW_INTEGRATION = os.path.join(THIS_FOLDER, "functions/apigw_integration.js")
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
TEST_LAMBDA_PROCESS_INSPECTION = os.path.join(THIS_FOLDER, "functions/lambda_process_inspection.py")
TEST_LAMBDA_CUSTOM_RESPONSE_SIZE = os.path.join(THIS_FOLDER, "functions/lambda_response_size.py")
TEST_LAMBDA_PYTHON_MULTIPLE_HANDLERS = os.path.join(
    THIS_FOLDER, "functions/lambda_multiple_handlers.py"
)

PYTHON_TEST_RUNTIMES = RUNTIMES_AGGREGATED["python"]
NODE_TEST_RUNTIMES = RUNTIMES_AGGREGATED["nodejs"]
JAVA_TEST_RUNTIMES = RUNTIMES_AGGREGATED["java"]

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


def check_concurrency_quota(aws_client: ServiceLevelClientFactory, min_concurrent_executions: int):
    account_settings = aws_client.lambda_.get_account_settings()
    concurrent_executions = account_settings["AccountLimit"]["ConcurrentExecutions"]
    if concurrent_executions < min_concurrent_executions:
        pytest.skip(
            "Account limit for Lambda ConcurrentExecutions is too low:"
            f" ({concurrent_executions}/{min_concurrent_executions})."
            " Request a quota increase on AWS: https://console.aws.amazon.com/servicequotas/home"
        )
    else:
        unreserved_concurrent_executions = account_settings["AccountLimit"][
            "UnreservedConcurrentExecutions"
        ]
        if unreserved_concurrent_executions < min_concurrent_executions:
            LOG.warning(
                "Insufficient UnreservedConcurrentExecutions available for this test. "
                "Ensure that no other tests use any reserved or provisioned concurrency."
            )


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        snapshot.transform.key_value("CodeSha256", reference_replacement=False)
    )


class TestLambdaBaseFeatures:
    @markers.snapshot.skip_snapshot_verify(paths=["$..LogResult"])
    @markers.aws.validated
    def test_large_payloads(self, caplog, create_lambda_function, aws_client):
        """Testing large payloads sent to lambda functions (~5MB)"""
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        large_value = "test123456" * 100 * 1000 * 5
        payload = {"test": large_value}  # 5MB payload
        result = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        # do not use snapshots here - loading 5MB json takes ~14 sec
        assert "FunctionError" not in result
        assert payload == json.load(result["Payload"])

    @markers.aws.validated
    def test_lambda_large_response(self, caplog, create_lambda_function, aws_client):
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_response-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_CUSTOM_RESPONSE_SIZE,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        response_size = 6 * 1024 * 1024  # actually + 100 is the upper limit
        payload = {"bytenum": response_size}  # 6MB response size
        result = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        assert "FunctionError" not in result
        assert "a" * response_size == json.load(result["Payload"])

    @markers.aws.validated
    def test_lambda_too_large_response(self, create_lambda_function, aws_client, snapshot):
        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_CUSTOM_RESPONSE_SIZE,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        response_size = 7 * 1024 * 1024  # 7MB response size (i.e. over 6MB limit)
        payload = {"bytenum": response_size}
        result = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        snapshot.match("invoke_result", result)

        # second invoke to make sure we didn't break further invocations
        result2 = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        snapshot.match("invoke_result_2", result2)

        # check that our manual log/print statement ends up in CW
        def _check_print_in_logs():
            log_events = (
                aws_client.logs.get_paginator("filter_log_events")
                .paginate(logGroupName=f"/aws/lambda/{function_name}")
                .build_full_result()
            )
            assert any("generating bytes" in e["message"] for e in log_events["events"])

        retry(_check_print_in_logs, retries=10)

    @markers.aws.only_localstack
    def test_lambda_too_large_response_but_with_custom_limit(
        self, caplog, create_lambda_function, aws_client, monkeypatch
    ):
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)
        monkeypatch.setattr(
            config, "LAMBDA_LIMITS_MAX_FUNCTION_PAYLOAD_SIZE_BYTES", str(7 * 1024 * 1024 + 100)
        )

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_CUSTOM_RESPONSE_SIZE,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        response_size = 7 * 1024 * 1024  # 7MB response size (i.e. over 6MB limit)
        payload = {"bytenum": response_size}
        result = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=to_bytes(json.dumps(payload))
        )
        assert "a" * response_size == json.load(result["Payload"])

    @markers.aws.validated
    def test_function_state(self, lambda_su_role, snapshot, create_lambda_function_aws, aws_client):
        """Tests if a lambda starts in state "Pending" but moves to "Active" at some point"""

        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        # create_response is the original create call response, even though the fixture waits until it's not pending
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_12,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"ZipFile": zip_file},
        )
        snapshot.match("create-fn-response", create_response)

        response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-fn-response", response)

    @pytest.mark.parametrize("function_name_length", [1, 2])
    @markers.aws.validated
    def test_assume_role(
        self, create_lambda_function, aws_client, snapshot, function_name_length, account_id
    ):
        """Motivated by a GitHub issue where a single-character function name fails to start upon invocation
        due to an invalid role ARN: https://github.com/localstack/localstack/issues/9016
        Notice that the assumed role depends on the length of the function name because single-character functions
        are suffixed with "@lambda_function". Examples:
        # 1: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-c33a16ee/u@lambda_function
        # 2: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-8ca8c35a/zz
        # 60: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-edc0e63c/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn
        # 64: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-ebed06d4/GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG
        # 65: fails due to validation constraint
        Unknown whether the 8-character hexadecimal number suffix after "lambda-autogenerated-" follows any pattern.
        """
        lambda_autogen_role = "(?<=lambda-autogenerated-)([0-9a-f]{8})"
        # avoid any other transformers possible registering reference replacements (especially resource transformer)
        snapshot.transformers.clear()
        snapshot.add_transformer(
            [
                snapshot.transform.regex(account_id, "1" * 12),
                snapshot.transform.regex(lambda_autogen_role, "<lambda-autogenerated-role-prefix>"),
                snapshot.transform.regex(r'(?<=/)[a-zA-Z]{1,2}(?="|@)', "<function-name>"),
            ]
        )

        # Generate single-character name (matching [a-z]/i)
        random_letter = random.choice(string.ascii_letters)
        function_name = str(random_letter * function_name_length)

        create_result = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ROLE,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        # Example: arn:aws:iam::111111111111:role/lambda-autogenerated-d5da4d52
        create_role_resource = arns.extract_resource_from_arn(
            create_result["CreateFunctionResponse"]["Role"]
        )

        invoke_result = aws_client.lambda_.invoke(FunctionName=function_name)
        payload = json.load(invoke_result["Payload"])
        snapshot.match("invoke-result-assumed-role-arn", payload["Arn"])

        # Example: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-c33a16ee/f@lambda_function
        # Example: arn:aws:sts::111111111111:assumed-role/lambda-autogenerated-c33a16ee/fn
        assume_role_resource = arns.extract_resource_from_arn(payload["Arn"])
        assert (
            create_role_resource.split("/")[1] == assume_role_resource.split("/")[1]
        ), "role name upon create_function does not match the assumed role name upon Lambda invocation"

        # The resource transformer masks the naming policy and does not support role prefixes.
        # Therefore, we need test the special case of a one-character function name separately.
        if function_name_length == 1:
            assert assume_role_resource.split("/")[-1] == f"{function_name}@lambda_function"
        else:
            assert assume_role_resource.split("/")[-1] == function_name

    @markers.aws.validated
    def test_lambda_different_iam_keys_environment(
        self, lambda_su_role, create_lambda_function, snapshot, aws_client, region_name
    ):
        """
        In this test we want to check if multiple lambda environments (= instances of hot functions) have
        different AWS access keys
        """
        function_name = f"fn-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_SLEEP_ENVIRONMENT,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        snapshot.match("create-result", create_result)

        # invoke two versions in two threads at the same time so environments won't be reused really quick
        def _invoke_lambda(*args):
            result = aws_client.lambda_.invoke(
                FunctionName=function_name, Payload=to_bytes(json.dumps({"sleep": 2}))
            )
            return json.load(result["Payload"])["environment"]

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
            sts_client_1 = create_client_with_keys("sts", keys=keys_1, region_name=region_name)
            sts_client_2 = create_client_with_keys("sts", keys=keys_2, region_name=region_name)
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # requires creating a new user `slicer` and chown /var/task
            "$..Payload.paths._var_task_gid",
            "$..Payload.paths._var_task_owner",
            "$..Payload.paths._var_task_uid",
        ],
    )
    @markers.aws.validated
    @markers.only_on_amd64
    def test_runtime_introspection_x86(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_x86_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_12,
            timeout=9,
            Architectures=[Architecture.x86_64],
        )

        invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_x86_introspection", invoke_result)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # requires creating a new user `slicer` and chown /var/task
            "$..Payload.paths._var_task_gid",
            "$..Payload.paths._var_task_owner",
            "$..Payload.paths._var_task_uid",
        ],
    )
    @markers.aws.validated
    @markers.only_on_arm64
    def test_runtime_introspection_arm(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_arm_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_12,
            timeout=9,
            Architectures=[Architecture.arm64],
        )

        invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_arm_introspection", invoke_result)

    @markers.aws.validated
    def test_runtime_ulimits(self, create_lambda_function, snapshot, monkeypatch, aws_client):
        """We consider ulimits parity as opt-in because development environments could hit these limits unlike in
        optimized production deployments."""
        monkeypatch.setattr(
            config,
            "LAMBDA_DOCKER_FLAGS",
            "--ulimit nofile=1024:1024 --ulimit nproc=742:742 --ulimit core=-1:-1 --ulimit stack=8388608:-1 --ulimit memlock=65536:65536",
        )

        func_name = f"test_lambda_ulimits_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ULIMITS,
            runtime=Runtime.python3_12,
        )

        invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_runtime_ulimits", invoke_result)

    @markers.aws.only_localstack
    def test_ignore_architecture(self, create_lambda_function, monkeypatch, aws_client):
        """Test configuration to ignore lambda architecture by creating a lambda with non-native architecture."""
        monkeypatch.setattr(config, "LAMBDA_IGNORE_ARCHITECTURE", True)

        # Assumes that LocalStack runs on native Docker host architecture
        # This assumption could be violated when using remote Lambda executors
        native_arch = platform.get_arch()
        non_native_architecture = (
            Architecture.x86_64 if native_arch == Arch.arm64 else Architecture.arm64
        )
        func_name = f"test_lambda_arch_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_12,
            Architectures=[non_native_architecture],
        )

        invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        payload = json.load(invoke_result["Payload"])
        lambda_arch = standardized_arch(payload.get("platform_machine"))
        assert lambda_arch == native_arch

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..RuntimeVersionConfig.RuntimeVersionArn",
        ]
    )
    @markers.aws.validated
    # Special case requiring both architectures
    @markers.only_on_amd64
    @markers.only_on_arm64
    def test_mixed_architecture(self, create_lambda_function, aws_client, snapshot):
        """Test emulation of a lambda function changing architectures.
        Limitation: only works on hosts that support both ARM and AMD64 architectures.
        """
        func_name = f"test_lambda_mixed_arch_{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_INTROSPECT_PYTHON), get_content=True)
        create_function_response = create_lambda_function(
            func_name=func_name,
            zip_file=zip_file,
            runtime=Runtime.python3_12,
            Architectures=[Architecture.x86_64],
        )
        snapshot.match("create_function_response", create_function_response)

        invoke_result_x86 = aws_client.lambda_.invoke(FunctionName=func_name)
        assert "FunctionError" not in invoke_result_x86
        payload = json.load(invoke_result_x86["Payload"])
        assert payload.get("platform_machine") == "x86_64"

        update_function_code_response = aws_client.lambda_.update_function_code(
            FunctionName=func_name, ZipFile=zip_file, Architectures=[Architecture.arm64]
        )
        snapshot.match("update_function_code_response", update_function_code_response)
        aws_client.lambda_.get_waiter(waiter_name="function_updated_v2").wait(
            FunctionName=func_name
        )

        invoke_result_arm = aws_client.lambda_.invoke(FunctionName=func_name)
        assert "FunctionError" not in invoke_result_arm
        payload_arm = json.load(invoke_result_arm["Payload"])
        assert payload_arm.get("platform_machine") == "aarch64"

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_CACHE_NODEJS, Runtime.nodejs20_x),
            (TEST_LAMBDA_CACHE_PYTHON, Runtime.python3_12),
        ],
        ids=["nodejs", "python"],
    )
    @markers.aws.validated
    def test_lambda_cache_local(
        self, create_lambda_function, lambda_fn, lambda_runtime, snapshot, aws_client
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=aws_client.lambda_,
        )

        first_invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("first_invoke_result", first_invoke_result)

        second_invoke_result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("second_invoke_result", second_invoke_result)

    @markers.aws.validated
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
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 2}))
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

            assert any("starting wait" in e["message"] for e in log_events)
            # TODO: this part is a bit flaky, at least locally with old provider
            assert not any("done waiting" in e["message"] for e in log_events)

        retry(assert_events, retries=15)

    @markers.aws.validated
    def test_lambda_invoke_no_timeout(self, create_lambda_function, snapshot, aws_client):
        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_TIMEOUT_PYTHON,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 1}))
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
            return any("starting wait" in e["message"] for e in log_events) and any(
                "done waiting" in e["message"] for e in log_events
            )

        wait_until(_assert_log_output, strategy="linear")

    @pytest.mark.skip(reason="Currently flaky in CI")
    @markers.aws.validated
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
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=1,
        )
        snapshot.match("create-result", create_result)
        file_content = "some-content"
        set_number = 42

        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"write-file": file_content})
        )
        snapshot.match("invoke-result-file-write", result)
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-file": True})
        )
        snapshot.match("invoke-result-file-read", result)
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"set-number": set_number})
        )
        snapshot.match("invoke-result-set-number", result)
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-number": True})
        )
        snapshot.match("invoke-result-read-number", result)
        # file is written, let's let the function timeout and check if it is still there

        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=json.dumps({"sleep": 2}))
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

            assert any("starting wait" in e["message"] for e in log_events)
            # TODO: this part is a bit flaky, at least locally with old provider
            assert not any("done waiting" in e["message"] for e in log_events)

        retry(assert_events, retries=15)

        # check if, for the next normal invocation, the file is still there:
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-file": True})
        )
        snapshot.match("invoke-result-file-read-after-timeout", result)
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"read-number": True})
        )
        snapshot.match("invoke-result-read-number-after-timeout", result)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # not set directly on init in lambda, but only on runtime processes
            "$..Payload.environment.AWS_ACCESS_KEY_ID",
            "$..Payload.environment.AWS_SECRET_ACCESS_KEY",
            "$..Payload.environment.AWS_SESSION_TOKEN",
            "$..Payload.environment.AWS_XRAY_DAEMON_ADDRESS",
            # variables set by default in the image/docker
            "$..Payload.environment.HOME",
            "$..Payload.environment.HOSTNAME",
            # LocalStack specific variables
            "$..Payload.environment.AWS_ENDPOINT_URL",
            "$..Payload.environment.AWS_LAMBDA_FUNCTION_TIMEOUT",
            "$..Payload.environment.EDGE_PORT",
            "$..Payload.environment.LOCALSTACK_FUNCTION_ACCOUNT_ID",
            "$..Payload.environment.LOCALSTACK_HOSTNAME",
            "$..Payload.environment.LOCALSTACK_INIT_LOG_LEVEL",
            "$..Payload.environment.LOCALSTACK_RUNTIME_ENDPOINT",
            "$..Payload.environment.LOCALSTACK_RUNTIME_ID",
            "$..Payload.environment.LOCALSTACK_USER",
            "$..Payload.environment.LOCALSTACK_POST_INVOKE_WAIT_MS",
            "$..Payload.environment.LOCALSTACK_MAX_PAYLOAD_SIZE",
            "$..Payload.environment.LOCALSTACK_CHMOD_PATHS",
            # internal AWS lambda functionality
            "$..Payload.environment._AWS_XRAY_DAEMON_ADDRESS",
            "$..Payload.environment._LAMBDA_CONSOLE_SOCKET",
            "$..Payload.environment._LAMBDA_CONTROL_SOCKET",
            "$..Payload.environment._LAMBDA_DIRECT_INVOKE_SOCKET",
            "$..Payload.environment._LAMBDA_LOG_FD",
            "$..Payload.environment._LAMBDA_RUNTIME_LOAD_TIME",
            "$..Payload.environment._LAMBDA_SB_ID",
            "$..Payload.environment._LAMBDA_SHARED_MEM_FD",
            "$..Payload.environment._LAMBDA_TELEMETRY_API_PASSPHRASE",
            "$..Payload.environment._X_AMZN_TRACE_ID",
        ]
    )
    def test_lambda_init_environment(
        self, aws_client, create_lambda_function, snapshot, monkeypatch
    ):
        if not is_aws_cloud():
            # needed to be able to read /proc/1/environ
            monkeypatch.setattr(config, "LAMBDA_INIT_USER", "root")
        func_name = f"test_lambda_{short_uid()}"
        # The file descriptors might change, and might have to be added to the transformers at some point
        snapshot.add_transformer(
            [
                snapshot.transform.key_value(
                    "_LAMBDA_TELEMETRY_API_PASSPHRASE", "telemetry-passphrase"
                ),
                snapshot.transform.key_value("AWS_LAMBDA_LOG_STREAM_NAME", "log-stream-name"),
                snapshot.transform.key_value("_X_AMZN_TRACE_ID", "xray-trace-id"),
                snapshot.transform.key_value("_LAMBDA_RUNTIME_LOAD_TIME", "runtime-load-time"),
            ]
        )
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PROCESS_INSPECTION,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )
        snapshot.match("create-result", create_result)

        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=json.dumps({"pid": 1}))
        snapshot.match("lambda-init-inspection", result)


URL_HANDLER_CODE = """
def handler(event, ctx):
    return <<returnvalue>>
"""


@markers.snapshot.skip_snapshot_verify(
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
    @markers.aws.validated
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
            runtime=Runtime.python3_12,
        )

        url_config = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.lambda_.add_permission(
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

    @pytest.mark.parametrize(
        "invoke_mode",
        [None, InvokeMode.BUFFERED, InvokeMode.RESPONSE_STREAM],
    )
    @markers.aws.validated
    def test_lambda_url_echo_invoke(
        self, create_lambda_function, snapshot, aws_client, invoke_mode
    ):
        if invoke_mode == "RESPONSE_STREAM" and not is_aws_cloud():
            pytest.skip(
                "'RESPONSE_STREAM should invoke the lambda using InvokeWithResponseStream, "
                "but this is not implemented on LS yet. '"
            )

        snapshot.add_transformer(
            snapshot.transform.key_value(
                "FunctionUrl", "<function-url>", reference_replacement=False
            )
        )
        function_name = f"test-fnurl-echo-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs20_x,
            handler="lambda_url.handler",
        )

        if invoke_mode:
            url_config = aws_client.lambda_.create_function_url_config(
                FunctionName=function_name, AuthType="NONE", InvokeMode=invoke_mode
            )
        else:
            url_config = aws_client.lambda_.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.lambda_.add_permission(
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

        if invoke_mode != "RESPONSE_STREAM":
            event = json.loads(result.content)["event"]
            assert event["body"] == "text"
            assert event["isBase64Encoded"] is False

            result = safe_requests.post(url)
            event = json.loads(result.content)["event"]

        else:
            response_chunks = []
            for chunk in result.iter_content(chunk_size=1024):
                if chunk:  # Filter out keep-alive new chunks
                    response_chunks.append(chunk.decode("utf-8"))

            # Join the chunks to form the complete response string
            complete_response = "".join(response_chunks)

            response_json = json.loads(complete_response)
            event = json.loads(response_json["body"])["event"]
            # TODO the chunk-event actually contains a key "body": "text" - not sure if we need more/other validation here
            # but it's not implemented in LS anyhow yet

        assert "Body" not in event
        assert event["isBase64Encoded"] is False

    @markers.aws.validated
    def test_lambda_url_headers_and_status(self, create_lambda_function, aws_client):
        function_name = f"test-fnurl-echo-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_PYTHON_ECHO_JSON_BODY, get_content=True),
            runtime=Runtime.python3_12,
            handler="lambda_echo_json_body.handler",
        )
        url_config = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )

        url = f"{url_config['FunctionUrl']}custom_path/extend?test_param=test_value"

        event = {
            "statusCode": 201,
            "headers": {
                "Content-Type": "application/json",
                "My-Custom-Header": "Custom Value",
            },
            "body": json.dumps({"message": "hello-world"}),
            "isBase64Encoded": False,
        }
        result = requests.post(url, json=event)
        assert result.json() == {"message": "hello-world"}
        assert result.status_code == 201
        assert "my-custom-header" in result.headers
        assert result.headers["my-custom-header"] == "Custom Value"

        # try with string status code
        event = {
            "statusCode": "418",
            "body": "i'm a teapot",
            "isBase64Encoded": False,
        }
        result = requests.post(url, json=event)
        assert result.text == "i'm a teapot"
        assert result.status_code == 418

    @markers.aws.validated
    def test_lambda_update_function_url_config(self, create_lambda_function, snapshot, aws_client):
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "FunctionUrl", "<function-url>", reference_replacement=False
            )
        )
        function_name = f"test-fnurl-echo-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs20_x,
            handler="lambda_url.handler",
        )

        url_config = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name, AuthType="NONE", InvokeMode=InvokeMode.BUFFERED
        )
        snapshot.match("create_lambda_url_config", url_config)

        get_url_config = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config", get_url_config)

        modify_config = aws_client.lambda_.update_function_url_config(
            FunctionName=function_name, InvokeMode="RESPONSE_STREAM"
        )
        snapshot.match("modify_lambda_url_config", modify_config)

        get_url_config = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config_2", get_url_config)

        # test if this removes the invoke-mode from the function
        modify_config = aws_client.lambda_.update_function_url_config(
            FunctionName=function_name,
        )
        snapshot.match("modify_lambda_url_config_none", modify_config)

        get_url_config = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config_3", get_url_config)

    @markers.aws.validated
    def test_lambda_url_invocation_exception(self, create_lambda_function, snapshot, aws_client):
        # TODO: extend tests
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", reference_replacement=False)
        )
        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=Runtime.python3_12,
        )
        get_fn_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        url_config = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.lambda_.add_permission(
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

    @markers.aws.validated
    def test_lambda_url_invalid_invoke_mode(self, create_lambda_function, snapshot, aws_client):
        function_name = f"test-fn-echo-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO_JSON_BODY,
            runtime=Runtime.python3_12,
            handler="lambda_echo_json_body.handler",
        )

        with pytest.raises(Exception) as e:
            aws_client.lambda_.create_function_url_config(
                FunctionName=function_name, AuthType="NONE", InvokeMode="UNKNOWN"
            )
        snapshot.match("invoke_function_invalid_invoke_type", e.value.response)

    @markers.aws.validated
    def test_lambda_url_non_existing_url(self):
        lambda_url_subdomain = "0123456789abcdefghijklmnopqrstuv.lambda-url.us-east-1"

        if is_aws_cloud():
            url = f"https://{lambda_url_subdomain}.on.aws"
        else:
            url = config.external_service_url(subdomains=lambda_url_subdomain)

        response = requests.get(url)
        assert response.text == '{"Message":null}'
        assert response.status_code == 403
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["x-amzn-ErrorType"] == "AccessDeniedException"

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..headers.domain",  # TODO: LS Lambda should populate this value for AWS parity
            "$..headers.x-forwarded-for",
            "$..headers.x-amzn-trace-id",
            "$..origin",  # TODO: LS Lambda should populate this value for AWS parity
        ]
    )
    @markers.aws.validated
    def test_lambda_url_echo_http_fixture_default(
        self, create_echo_http_server, snapshot, aws_client
    ):
        key_value_transform = [
            "domain",
            "origin",
            "x-amzn-tls-cipher-suite",
            "x-amzn-tls-version",
            "x-amzn-trace-id",
            "x-forwarded-for",
            "x-forwarded-port",
            "x-forwarded-proto",
        ]
        for key in key_value_transform:
            snapshot.add_transformer(snapshot.transform.key_value(key))
        echo_url = create_echo_http_server()
        response = requests.post(
            url=echo_url + "/path/1?q=query",
            headers={
                "content-type": "application/json",
                "ExTrA-HeadErs": "With WeiRd CapS",
                "user-agent": "test/echo",
            },
            json={"foo": "bar"},
        )
        snapshot.match("url_response", response.json())

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..content.headers.domain",  # TODO: LS Lambda should populate this value for AWS parity
            "$..origin",  # TODO: LS Lambda should populate this value for AWS parity
        ]
    )
    @markers.aws.validated
    def test_lambda_url_echo_http_fixture_trim_x_headers(
        self, create_echo_http_server, snapshot, aws_client
    ):
        snapshot.add_transformer(snapshot.transform.key_value("domain"))
        snapshot.add_transformer(snapshot.transform.key_value("origin"))
        echo_url = create_echo_http_server(trim_x_headers=True)
        response = requests.post(
            url=echo_url + "/path/1?q=query",
            headers={
                "content-type": "application/json",
                "ExTrA-HeadErs": "With WeiRd CapS",
                "user-agent": "test/echo",
            },
            json={"foo": "bar"},
        )
        snapshot.match("url_response", response.json())

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..origin",  # FIXME: LS does not populate the value
        ]
    )
    def test_lambda_url_form_payload(self, create_echo_http_server, snapshot, aws_client):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("domain"),
                snapshot.transform.key_value("origin"),
            ]
        )
        echo_server_url = create_echo_http_server(trim_x_headers=True)
        # multipart body
        body = (
            b"\r\n--4efd159eae0c4f4e125a5a509e073d85\r\n"
            b'Content-Disposition: form-data; name="formfield"\r\n\r\n'
            b"not a file, just a field"
            b"\r\n--4efd159eae0c4f4e125a5a509e073d85\r\n"
            b'Content-Disposition: form-data; name="foo"; filename="foo"\r\n'
            b"Content-Type: text/plain;\r\n\r\n"
            b"bar"
            b"\r\n\r\n--4efd159eae0c4f4e125a5a509e073d85--\r\n"
        )
        response = requests.post(
            url=f"{echo_server_url}/test/value",
            headers={
                "Content-Type": "multipart/form-data; boundary=4efd159eae0c4f4e125a5a509e073d85",
                "User-Agent": "python/test-request",
            },
            data=body,
            verify=False,
        )
        assert response.status_code == 200
        response_json = response.json()
        snapshot.match("url_response", response_json)

        form_data = base64.b64decode(response_json["data"])
        assert form_data == body


@pytest.mark.skipif(not is_aws_cloud(), reason="Not yet implemented")
class TestLambdaPermissions:
    @markers.aws.validated
    def test_lambda_permission_url_invocation(self, create_lambda_function, snapshot, aws_client):
        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs20_x,
            handler="lambda_url.handler",
        )
        url_config = aws_client.lambda_.create_function_url_config(
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

    # TODO remove, currently missing init duration in REPORT
    @markers.snapshot.skip_snapshot_verify(paths=["$..logs.logs"])
    @markers.aws.validated
    def test_invocation_with_logs(self, snapshot, invocation_echo_lambda, aws_client):
        """Test invocation of a lambda with no invocation type set, but LogType="Tail""" ""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))
        snapshot.add_transformer(
            snapshot.transform.key_value("LogResult", reference_replacement=False)
        )

        result = aws_client.lambda_.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", LogType="Tail"
        )
        snapshot.match("invoke", result)

        # assert that logs are contained in response
        logs = result.get("LogResult", "")
        logs = to_str(base64.b64decode(to_str(logs)))
        snapshot.add_transformer(snapshot.transform.lambda_report_logs())
        snapshot.match("logs", {"logs": logs.splitlines(keepends=True)})
        assert "START" in logs
        assert "{}" in logs
        assert "END" in logs
        assert "REPORT" in logs

    @markers.aws.validated
    def test_invoke_exceptions(self, aws_client, snapshot):
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.invoke(FunctionName="doesnotexist")
        snapshot.match("invoke_function_doesnotexist", e.value.response)

    @markers.aws.validated
    def test_invocation_type_request_response(self, snapshot, invocation_echo_lambda, aws_client):
        """Test invocation with InvocationType RequestResponse explicitly set"""
        result = aws_client.lambda_.invoke(
            FunctionName=invocation_echo_lambda,
            Payload=b"{}",
            InvocationType="RequestResponse",
        )
        snapshot.match("invoke-result", result)

    @markers.aws.validated
    def test_invocation_type_event(
        self, snapshot, invocation_echo_lambda, aws_client, check_lambda_logs
    ):
        """Check invocation response for type event"""
        function_arn = invocation_echo_lambda
        function_name = lambda_function_name(invocation_echo_lambda)
        result = aws_client.lambda_.invoke(
            FunctionName=function_arn, Payload=b"{}", InvocationType="Event"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 202 == result["StatusCode"]

        # Assert that the function gets invoked by checking the logs.
        # This also ensures that we wait until the invocation is done before deleting the function.
        expected = [".*{}"]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=15)

    # TODO: implement for new provider (was tested in old provider)
    @pytest.mark.skip(reason="Not yet implemented")
    @markers.aws.validated
    def test_invocation_type_dry_run(self, snapshot, invocation_echo_lambda, aws_client):
        """Check invocation response for type dryrun"""
        result = aws_client.lambda_.invoke(
            FunctionName=invocation_echo_lambda, Payload=b"{}", InvocationType="DryRun"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 204 == result["StatusCode"]

    @pytest.mark.skip(reason="Not yet implemented")
    @markers.aws.validated
    def test_invocation_type_event_error(self, create_lambda_function, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<request-id>"))

        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=Runtime.python3_12,
        )
        snapshot.match("creation_response", creation_response)
        invocation_response = aws_client.lambda_.invoke(
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
        # TODO: fix transformers for numbers etc or selectively match log events
        snapshot.match("log_events", events)
        # check if both request ids are identical, since snapshots currently do not support reference replacement for regexes
        start_messages = [e["message"] for e in events if e["message"].startswith("START")]
        uuids = [PATTERN_UUID.search(message).group(0) for message in start_messages]
        assert len(uuids) == 2
        assert uuids[0] == uuids[1]

    @markers.aws.validated
    def test_invocation_with_qualifier(
        self,
        s3_bucket,
        lambda_su_role,
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
            runtime=Runtime.python3_12,
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_12,
            Role=lambda_su_role,
            Publish=True,
            Handler="handler.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", response)
        qualifier = response["Version"]

        # invoke lambda function
        invoke_result = aws_client.lambda_.invoke(
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

    @markers.aws.validated
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
            runtime=Runtime.python3_12,
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Runtime=Runtime.python3_12,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", create_response)

        # invoke lambda function
        result = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=b'{"foo": "bar with \'quotes\\""}'
        )
        snapshot.match("invocation-response", result)

    # TODO: implement in new provider (was tested in old provider)
    @pytest.mark.skip(reason="Not yet implemented")
    @markers.aws.validated
    def test_lambda_with_context(
        self, create_lambda_function, check_lambda_logs, snapshot, aws_client
    ):
        """Test context of nodejs lambda invocation"""
        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_INTEGRATION_NODEJS,
            handler="lambda_integration.handler",
            runtime=Runtime.nodejs20_x,
        )
        snapshot.match("creation", creation_response)
        ctx = {
            "custom": {"foo": "bar"},
            "client": {"snap": ["crackle", "pop"]},
            "env": {"fizz": "buzz"},
        }

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
            Payload=b"{}",
            ClientContext=to_str(base64.b64encode(to_bytes(json.dumps(ctx)))),
        )
        result = read_streams(result)
        snapshot.match("invocation", result)

        result_data = result["Payload"]
        assert 200 == result["StatusCode"]
        client_context = json.loads(result_data)["context"]["clientContext"]
        assert "bar" == client_context.get("custom").get("foo")

        # assert that logs are present
        expected = [".*Node.js Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=15)


class TestLambdaErrors:
    @markers.aws.validated
    def test_lambda_runtime_error(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that raises an exception during runtime startup."""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_RUNTIME_ERROR,
            handler="lambda_runtime_error.handler",
            runtime=Runtime.python3_12,
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @pytest.mark.skipif(
        not is_aws_cloud(), reason="Not yet supported. Need to report exit in Lambda init binary."
    )
    @markers.aws.validated
    def test_lambda_runtime_exit(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that exits during runtime startup."""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_RUNTIME_EXIT,
            handler="lambda_runtime_exit.handler",
            runtime=Runtime.python3_12,
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @pytest.mark.skipif(
        not is_aws_cloud(), reason="Not yet supported. Need to report exit in Lambda init binary."
    )
    @markers.aws.validated
    def test_lambda_runtime_exit_segfault(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that exits during runtime startup with a segmentation fault."""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_RUNTIME_EXIT_SEGFAULT,
            handler="lambda_runtime_exit_segfault.handler",
            runtime=Runtime.python3_12,
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @markers.aws.validated
    def test_lambda_handler_error(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that raises an exception in the handler."""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_HANDLER_ERROR,
            handler="lambda_handler_error.handler",
            runtime=Runtime.python3_12,
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @pytest.mark.skipif(
        not is_aws_cloud(), reason="Not yet supported. Need to report exit in Lambda init binary."
    )
    @markers.aws.validated
    def test_lambda_handler_exit(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that exits in the handler."""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_HANDLER_EXIT,
            handler="lambda_handler_exit.handler",
            runtime=Runtime.python3_12,
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @pytest.mark.skipif(
        not is_aws_cloud(), reason="Not yet supported. Need to raise error in Lambda init binary."
    )
    @markers.aws.validated
    def test_lambda_runtime_wrapper_not_found(self, aws_client, create_lambda_function, snapshot):
        """Test Lambda that points to a non-existing Lambda wrapper"""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
            envvars={"AWS_LAMBDA_EXEC_WRAPPER": "/idontexist.sh"},
        )

        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
        )
        snapshot.match("invocation_error", result)

    @markers.aws.only_localstack(
        reason="Can only induce Lambda-internal Docker error in LocalStack"
    )
    def test_lambda_runtime_startup_timeout(
        self, aws_client_factory, create_lambda_function, monkeypatch
    ):
        """Test Lambda that times out during runtime startup"""
        monkeypatch.setattr(
            config, "LAMBDA_DOCKER_FLAGS", "-e LOCALSTACK_RUNTIME_ENDPOINT=http://somehost.invalid"
        )
        monkeypatch.setattr(config, "LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT", 2)

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
        )

        client_config = Config(
            retries={"max_attempts": 0},
        )
        no_retry_lambda_client = aws_client_factory.get_client("lambda", config=client_config)
        with pytest.raises(no_retry_lambda_client.exceptions.ServiceException) as e:
            no_retry_lambda_client.invoke(
                FunctionName=function_name,
            )
        assert e.match(
            r"An error occurred \(ServiceException\) when calling the Invoke operation \(reached max "
            r"retries: \d\): Internal error while executing lambda"
        )

    @markers.aws.only_localstack(
        reason="Can only induce Lambda-internal Docker error in LocalStack"
    )
    def test_lambda_runtime_startup_error(
        self, aws_client_factory, create_lambda_function, monkeypatch
    ):
        """Test Lambda that errors during runtime startup"""
        monkeypatch.setattr(config, "LAMBDA_DOCKER_FLAGS", "invalid_flags")

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
        )

        client_config = Config(
            retries={"max_attempts": 0},
        )
        no_retry_lambda_client = aws_client_factory.get_client("lambda", config=client_config)
        with pytest.raises(no_retry_lambda_client.exceptions.ServiceException) as e:
            no_retry_lambda_client.invoke(
                FunctionName=function_name,
            )
        assert e.match(
            r"An error occurred \(ServiceException\) when calling the Invoke operation \(reached max "
            r"retries: \d\): Internal error while executing lambda"
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
    @pytest.mark.parametrize(
        ["label", "payload"],
        [
            # Body taken from AWS CLI v2 call:
            # aws lambda invoke --debug --function-name localstack-lambda-url-example \
            #   --payload '{"body": "{\"num1\": \"10\", \"num2\": \"10\"}" }' output.txt
            ("body", b"n\x87r\x9e\xe9\xb5\xd7I\xee\x9bmt"),
            # Body taken from AWS CLI v2 call:
            # aws lambda invoke --debug --function-name localstack-lambda-url-example \
            #   --payload '{"message": "hello" }' output.txt
            ("message", b"\x99\xeb,j\x07\xa1zYh"),
        ],
    )
    def test_lambda_invoke_payload_encoding_error(
        self, aws_client_factory, create_lambda_function, snapshot, label, payload
    ):
        """Test Lambda invoke with invalid encoding error.
        This happens when using the AWS CLI v2 with an inline --payload '{"input": "my-input"}' without specifying
        the flag --cli-binary-format raw-in-base64-out because base64 is the new default in v2. See AWS docs:
        https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-options.html
        """
        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
        )

        client_config = Config(
            retries={"max_attempts": 0},
        )
        no_retry_lambda_client = aws_client_factory.get_client("lambda", config=client_config)
        with pytest.raises(no_retry_lambda_client.exceptions.InvalidRequestContentException) as e:
            no_retry_lambda_client.invoke(FunctionName=function_name, Payload=payload)
        snapshot.match(f"invoke_function_invalid_payload_{label}", e.value.response)


class TestLambdaCleanup:
    @pytest.mark.skip(
        reason="Not yet handled properly. Currently raises an InvalidStatusException."
    )
    @markers.aws.validated
    def test_delete_lambda_during_sync_invoke(self, aws_client, create_lambda_function, snapshot):
        """Test deleting a Lambda during a synchronous invocation.

        Unlike AWS, we will throw an error and clean up all containers to avoid dangling containers.
        """
        func_name = f"func-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_SLEEP_ENVIRONMENT,
            runtime=Runtime.python3_12,
            Timeout=30,
        )

        # Warm up the Lambda
        invoke_result_1 = aws_client.lambda_.invoke(
            FunctionName=func_name,
            Payload=json.dumps({"sleep": 0}),
            InvocationType="RequestResponse",
        )
        assert invoke_result_1["StatusCode"] == 200
        assert "FunctionError" not in invoke_result_1

        # Simultaneously invoke and delete the Lambda function
        errored = False

        def _invoke_function():
            nonlocal errored
            try:
                invoke_result_2 = aws_client.lambda_.invoke(
                    FunctionName=func_name,
                    Payload=json.dumps({"sleep": 20}),
                    InvocationType="RequestResponse",
                )
                assert invoke_result_2["StatusCode"] == 200
                assert "FunctionError" not in invoke_result_2
            except Exception:
                LOG.exception("Invoke failed")
                errored = True

        thread = threading.Thread(target=_invoke_function)
        thread.start()

        # Ensure that the invoke has been sent before deleting the function
        time.sleep(5)
        delete_result = aws_client.lambda_.delete_function(FunctionName=func_name)
        snapshot.match("delete-result", delete_result)

        thread.join()

        assert not errored

    @markers.aws.validated
    def test_recreate_function(
        self, aws_client, create_lambda_function, check_lambda_logs, snapshot
    ):
        """Recreating a function with the same name should not cause any resource cleanup issues or namespace collisions
        Reproduces a GitHub issue: https://github.com/localstack/localstack/issues/10280"""
        function_name = f"test-function-{short_uid()}"
        create_function_response_one = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
        )
        snapshot.match("create_function_response_one", create_function_response_one)

        aws_client.lambda_.delete_function(FunctionName=function_name)

        # Immediately re-create the same function
        create_function_response_two = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            handler="lambda_echo.handler",
            runtime=Runtime.python3_12,
        )
        snapshot.match("create_function_response_two", create_function_response_two)

        # Validate that async invokes still work
        invoke_response = aws_client.lambda_.invoke(
            FunctionName=function_name,
            InvocationType="Event",
        )
        invoke_response = read_streams(invoke_response)
        assert 202 == invoke_response["StatusCode"]

        # Assert that the function gets invoked by checking the logs.
        # This also ensures that we wait until the invocation is done before deleting the function.
        expected = [".*{}"]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=15)


class TestLambdaMultiAccounts:
    @pytest.fixture
    def primary_client(self, aws_client):
        return aws_client.lambda_

    @pytest.fixture
    def secondary_client(self, secondary_aws_client):
        return secondary_aws_client.lambda_

    @pytest.fixture
    def created_lambda_arn(self, create_lambda_function, primary_client, secondary_account_id):
        # Operations related to functions.
        # See: https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html#permissions-resource-xaccountinvoke
        #
        # - Invoke
        # - GetFunction
        # - GetFunctionConfiguration
        # - UpdateFunctionCode
        # - DeleteFunction
        # - PublishVersion
        # - ListVersionsByFunction
        # - CreateAlias
        # - GetAlias
        # - ListAliases
        # - UpdateAlias
        # - DeleteAlias
        # - GetPolicy
        # - PutFunctionConcurrency
        # - DeleteFunctionConcurrency
        # - ListTags
        # - TagResource
        # - UntagResource

        func_name = f"func-{short_uid()}"
        func_arn = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]["FunctionArn"]

        statement_id = f"stm-{short_uid()}"
        primary_client.add_permission(
            FunctionName=func_name,
            StatementId=statement_id,
            Principal=secondary_account_id,
            Action="lambda:*",
        )
        return func_arn

    @pytest.fixture
    def created_layer_arn(
        self, primary_client, create_lambda_function, dummylayer, secondary_account_id
    ):
        # As of 2024-02, AWS restricts the input for adding resource-based policy to layer versions via AddLayerVersionPermission.
        # Only 'lambda:GetLayerVersion' is accepted for Action.
        # https://github.com/boto/botocore/blob/cf7b8449643187670620ab699596ca785e3ec889/botocore/data/lambda/2015-03-31/service-2.json#L3906-L3909
        # This appears to have been the case at least since 2021-06.
        # Furthermore this contradicts with what its docs on valid IAM actions for layer versions:
        # https://docs.aws.amazon.com/lambda/latest/dg/lambda-api-permissions-ref.html#permissions-resources-layers

        # Operations related to Lambda layers supported by cross account
        # - GetLayerVersion
        # - GetLayerVersionByArn

        # Operations not supported by lambda layer cross account
        # - ListLayerVersions
        # - DeleteLayerVersion
        # - AddLayerVersionPermission
        # - GetLayerVersionPolicy
        # - RemoveLayerVersionPermission

        layer_name = f"layer-{short_uid()}"
        layer_arn = primary_client.publish_layer_version(
            LayerName=layer_name, Content={"ZipFile": dummylayer}
        )["LayerArn"]

        layer_statement_id = f"stm-{short_uid()}"
        primary_client.add_layer_version_permission(
            LayerName=layer_arn,
            StatementId=layer_statement_id,
            Principal=secondary_account_id,
            Action="lambda:GetLayerVersion",
            VersionNumber=1,
        )

        return layer_arn

    @markers.aws.validated
    def test_get_lambda_layer(self, secondary_client, created_layer_arn):
        secondary_client.get_layer_version(LayerName=created_layer_arn, VersionNumber=1)
        secondary_client.get_layer_version_by_arn(Arn=created_layer_arn + ":1")

    @markers.aws.validated
    def test_get_function(self, secondary_client, created_lambda_arn):
        secondary_client.get_function(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_get_function_configuration(self, secondary_client, created_lambda_arn):
        secondary_client.get_function_configuration(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_list_versions_by_function(self, secondary_client, created_lambda_arn):
        secondary_client.get_function_configuration(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_function_concurrency(self, secondary_client, created_lambda_arn):
        secondary_client.put_function_concurrency(
            FunctionName=created_lambda_arn, ReservedConcurrentExecutions=1
        )
        secondary_client.delete_function_concurrency(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_function_alias(self, secondary_client, created_lambda_arn):
        alias_name = f"alias-{short_uid()}"
        secondary_client.create_alias(
            FunctionName=created_lambda_arn, FunctionVersion="$LATEST", Name=alias_name
        )

        secondary_client.get_alias(FunctionName=created_lambda_arn, Name=alias_name)

        alias_description = f"alias-description-{short_uid()}"
        secondary_client.update_alias(
            FunctionName=created_lambda_arn, Name=alias_name, Description=alias_description
        )

        resp = secondary_client.list_aliases(FunctionName=created_lambda_arn)
        assert len(resp["Aliases"]) == 1
        assert resp["Aliases"][0]["Description"] == alias_description

        secondary_client.delete_alias(FunctionName=created_lambda_arn, Name=alias_name)

    @markers.aws.validated
    def test_function_tags(self, secondary_client, created_lambda_arn):
        tags = {"foo": "bar"}
        secondary_client.tag_resource(Resource=created_lambda_arn, Tags=tags)
        assert secondary_client.list_tags(Resource=created_lambda_arn)["Tags"] == tags
        secondary_client.untag_resource(Resource=created_lambda_arn, TagKeys=["lorem"])

    @markers.aws.validated
    def test_function_invocation(self, secondary_client, created_lambda_arn):
        secondary_client.invoke(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_publish_version(self, secondary_client, created_lambda_arn):
        secondary_client.publish_version(FunctionName=created_lambda_arn)

    @markers.aws.validated
    def test_delete_function(self, secondary_client, created_lambda_arn):
        secondary_client.delete_function(FunctionName=created_lambda_arn)


class TestLambdaConcurrency:
    @markers.aws.validated
    def test_lambda_concurrency_crud(self, snapshot, create_lambda_function, aws_client):
        func_name = f"fn-concurrency-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
        )

        default_concurrency_result = aws_client.lambda_.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_default", default_concurrency_result)

        # 0 should always succeed independent of the UnreservedConcurrentExecution limits
        reserved_concurrency_result = aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=0
        )
        snapshot.match("put_function_concurrency", reserved_concurrency_result)

        updated_concurrency_result = aws_client.lambda_.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_updated", updated_concurrency_result)
        assert updated_concurrency_result["ReservedConcurrentExecutions"] == 0

        aws_client.lambda_.delete_function_concurrency(FunctionName=func_name)

        deleted_concurrency_result = aws_client.lambda_.get_function_concurrency(
            FunctionName=func_name
        )
        snapshot.match("get_function_concurrency_deleted", deleted_concurrency_result)

    @markers.aws.validated
    def test_lambda_concurrency_block(self, snapshot, create_lambda_function, aws_client):
        """
        Tests an edge case where reserved concurrency is equal to the sum of all provisioned concurrencies for a function.
        In this case we can't call $LATEST anymore since there's no "free"/unclaimed concurrency left to execute the function with
        """
        min_concurrent_executions = 10 + 2  # reserved concurrency + provisioned concurrency
        check_concurrency_quota(aws_client, min_concurrent_executions)

        # function
        func_name = f"fn-concurrency-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
        )

        # reserved concurrency
        v1_result = aws_client.lambda_.publish_version(FunctionName=func_name)
        snapshot.match("v1_result", v1_result)
        v1 = v1_result["Version"]

        # assert version is available(!)
        aws_client.lambda_.get_waiter(waiter_name="function_active_v2").wait(
            FunctionName=func_name, Qualifier=v1
        )

        # Reserved concurrency works on the whole function
        reserved_concurrency_result = aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("reserved_concurrency_result", reserved_concurrency_result)

        # verify we can call $LATEST
        invoke_latest_before_block = aws_client.lambda_.invoke(
            FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_latest_before_block", invoke_latest_before_block)

        # Provisioned concurrency works on individual version/aliases, but *not* on $LATEST
        provisioned_concurrency_result = aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1, ProvisionedConcurrentExecutions=1
        )
        snapshot.match("provisioned_concurrency_result", provisioned_concurrency_result)

        assert wait_until(concurrency_update_done(aws_client.lambda_, func_name, v1))

        # verify we can't call $LATEST anymore
        with pytest.raises(aws_client.lambda_.exceptions.TooManyRequestsException) as e:
            aws_client.lambda_.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_first_exc", e.value.response)

        # but we can call the version with provisioned concurrency
        invoke_v1_after_block = aws_client.lambda_.invoke(
            FunctionName=func_name, Qualifier=v1, Payload=json.dumps({"hello": "world"})
        )
        snapshot.match("invoke_v1_after_block", invoke_v1_after_block)

        # verify we can't call $LATEST again
        with pytest.raises(aws_client.lambda_.exceptions.TooManyRequestsException) as e:
            aws_client.lambda_.invoke(
                FunctionName=func_name, Qualifier="$LATEST", Payload=json.dumps({"hello": "world"})
            )
        snapshot.match("invoke_latest_second_exc", e.value.response)

    @pytest.mark.skip(reason="Not yet implemented")
    @pytest.mark.skipif(condition=is_aws_cloud(), reason="very slow (only execute when needed)")
    @markers.aws.validated
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, create_lambda_function, snapshot, aws_client
    ):
        """
        create fn ⇒ publish version ⇒ create alias for version ⇒ put concurrency on alias
        ⇒ new version with change ⇒ change alias to new version ⇒ concurrency moves with alias? same behavior for calls to alias/version?
        """

        # TODO: validate once implemented
        min_concurrent_executions = 10 + 2  # for alias and version
        check_concurrency_quota(aws_client, min_concurrent_executions)

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = aws_client.lambda_.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("get-function-configuration", fn)

        first_ver = aws_client.lambda_.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)

        get_function_configuration = aws_client.lambda_.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", get_function_configuration)

        aws_client.lambda_.get_waiter("function_updated_v2").wait(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )

        # There's no ProvisionedConcurrencyConfiguration yet
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, first_ver["Version"]) == "on-demand"
        )

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = aws_client.lambda_.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        get_function_result = aws_client.lambda_.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_before_provisioned", get_function_result)
        aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(aws_client.lambda_, func_name, alias_name))
        get_function_result = aws_client.lambda_.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, alias_name)
            == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        aws_client.lambda_.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(aws_client.lambda_, func_name))
        lambda_conf = aws_client.lambda_.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = aws_client.lambda_.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = aws_client.lambda_.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(aws_client.lambda_, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, first_ver["Version"]) == "on-demand"
        )
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(aws_client.lambda_, func_name, alias_name)
            == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(
            aws_client.lambda_.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            aws_client.lambda_.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        snapshot.match("provisioned_concurrency_notfound", e.value.response)

    @markers.aws.validated
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
        min_concurrent_executions = 10 + 5
        check_concurrency_quota(aws_client, min_concurrent_executions)

        func_name = f"test_lambda_{short_uid()}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        v1 = aws_client.lambda_.publish_version(FunctionName=func_name)

        put_provisioned = aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=5
        )
        snapshot.match("put_provisioned_5", put_provisioned)

        get_provisioned_prewait = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )

        # TODO: test invoke before provisioned concurrency actually updated
        # maybe repeated executions to see when we get the provisioned invocation type

        snapshot.match("get_provisioned_prewait", get_provisioned_prewait)
        assert wait_until(concurrency_update_done(aws_client.lambda_, func_name, v1["Version"]))
        get_provisioned_postwait = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_postwait", get_provisioned_postwait)

        invoke_result1 = aws_client.lambda_.invoke(FunctionName=func_name, Qualifier=v1["Version"])
        result1 = json.load(invoke_result1["Payload"])
        assert result1 == "provisioned-concurrency"

        invoke_result2 = aws_client.lambda_.invoke(FunctionName=func_name, Qualifier="$LATEST")
        result2 = json.load(invoke_result2["Payload"])
        assert result2 == "on-demand"

    @markers.aws.validated
    def test_lambda_provisioned_concurrency_scheduling(
        self, snapshot, create_lambda_function, aws_client
    ):
        min_concurrent_executions = 10 + 1
        check_concurrency_quota(aws_client, min_concurrent_executions)

        """Tests that invokes should be scheduled to provisioned-concurrency instances rather than on-demand
        if-and-only-if free provisioned concurrency is available."""
        func_name = f"fn-concurrency-{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_12,
            timeout=10,
        )

        v1 = aws_client.lambda_.publish_version(FunctionName=func_name)

        aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(aws_client.lambda_, func_name, v1["Version"]))

        get_provisioned_postwait = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_postwait", get_provisioned_postwait)

        # Schedule Lambda to provisioned concurrency instead of launching a new on-demand instance
        invoke_result = aws_client.lambda_.invoke(
            FunctionName=func_name,
            Qualifier=v1["Version"],
        )
        result = json.load(invoke_result["Payload"])
        assert result == "provisioned-concurrency"

        # Send two simultaneous invokes
        errored = False

        def _invoke_lambda():
            nonlocal errored
            try:
                invoke_result1 = aws_client.lambda_.invoke(
                    FunctionName=func_name,
                    Qualifier=v1["Version"],
                    Payload=json.dumps({"wait": 6}),
                )
                result1 = json.load(invoke_result1["Payload"])
                assert result1 == "provisioned-concurrency"
            except Exception:
                LOG.exception("Invoking Lambda failed")
                errored = True

        thread = threading.Thread(target=_invoke_lambda)
        thread.start()

        # Ensure the first provisioned-concurrency invoke is running before sending the second on-demand invoke
        time.sleep(2)

        # Invoke while the first invoke is still running
        invoke_result2 = aws_client.lambda_.invoke(
            FunctionName=func_name,
            Qualifier=v1["Version"],
        )
        result2 = json.load(invoke_result2["Payload"])
        assert result2 == "on-demand"

        # Wait for the first invoker thread
        thread.join()
        assert not errored

    @markers.aws.validated
    @pytest.mark.skip(reason="flaky")
    def test_reserved_concurrency_async_queue(self, create_lambda_function, snapshot, aws_client):
        min_concurrent_executions = 10 + 3
        check_concurrency_quota(aws_client, min_concurrent_executions)

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=20,
        )

        fn = aws_client.lambda_.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("fn", fn)
        fn_arn = fn["FunctionArn"]

        # configure reserved concurrency for sequential execution
        put_fn_concurrency = aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_fn_concurrency", put_fn_concurrency)

        # warm up the Lambda function to mitigate flakiness due to cold start
        aws_client.lambda_.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")

        # simultaneously queue two event invocations
        # The first event invoke gets executed immediately
        aws_client.lambda_.invoke(
            FunctionName=fn_arn, InvocationType="Event", Payload=json.dumps({"wait": 15})
        )
        # The second event invoke gets throttled and re-scheduled with an internal retry
        aws_client.lambda_.invoke(
            FunctionName=fn_arn, InvocationType="Event", Payload=json.dumps({"wait": 10})
        )

        # Ensure one event invocation is being executed and the other one is in the queue.
        time.sleep(5)

        # Synchronous invocations raise an exception because insufficient reserved concurrency is available
        with pytest.raises(aws_client.lambda_.exceptions.TooManyRequestsException) as e:
            aws_client.lambda_.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")
        snapshot.match("too_many_requests_exc", e.value.response)

        # ReservedConcurrentExecutions=2 is insufficient because the throttled async event invoke might be
        # re-scheduled before the synchronous invoke while the first async invoke is still running.
        aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=3
        )
        aws_client.lambda_.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")

        def assert_events():
            log_events = aws_client.logs.filter_log_events(
                logGroupName=f"/aws/lambda/{func_name}",
            )["events"]
            invocation_count = len(
                [event["message"] for event in log_events if event["message"].startswith("REPORT")]
            )
            assert invocation_count == 4

        retry(assert_events, retries=120, sleep=2)

        # TODO: snapshot logs & request ID for correlation after request id gets propagated
        #  https://github.com/localstack/localstack/pull/7874

    @markers.snapshot.skip_snapshot_verify(paths=["$..Attributes.AWSTraceHeader"])
    @markers.aws.validated
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
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=20,
        )

        fn = aws_client.lambda_.get_function_configuration(
            FunctionName=func_name, Qualifier="$LATEST"
        )
        snapshot.match("fn", fn)
        fn_arn = fn["FunctionArn"]

        # block execution by setting reserved concurrency to 0
        put_reserved = aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=0
        )
        snapshot.match("put_reserved", put_reserved)

        with pytest.raises(aws_client.lambda_.exceptions.TooManyRequestsException) as e:
            aws_client.lambda_.invoke(FunctionName=fn_arn, InvocationType="RequestResponse")
        snapshot.match("exc_no_cap_requestresponse", e.value.response)

        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        put_event_invoke_conf = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=func_name,
            MaximumRetryAttempts=0,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        snapshot.match("put_event_invoke_conf", put_event_invoke_conf)

        time.sleep(3)  # just to be sure the event invoke config is active

        invoke_result = aws_client.lambda_.invoke(FunctionName=fn_arn, InvocationType="Event")
        snapshot.match("invoke_result", invoke_result)

        def get_msg_from_queue():
            msgs = aws_client.sqs.receive_message(
                QueueUrl=queue_url, AttributeNames=["All"], WaitTimeSeconds=5
            )
            return msgs["Messages"][0]

        msg = retry(get_msg_from_queue, retries=10, sleep=2)
        snapshot.match("msg", msg)

    @markers.aws.validated
    def test_reserved_provisioned_overlap(self, create_lambda_function, snapshot, aws_client):
        min_concurrent_executions = 10 + 4  # provisioned concurrency (2) + reserved concurrency (2)
        check_concurrency_quota(aws_client, min_concurrent_executions)

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INVOCATION_TYPE,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        v1 = aws_client.lambda_.publish_version(FunctionName=func_name)

        put_provisioned = aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=2
        )
        snapshot.match("put_provisioned_5", put_provisioned)

        get_provisioned_prewait = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_prewait", get_provisioned_prewait)
        assert wait_until(concurrency_update_done(aws_client.lambda_, func_name, v1["Version"]))
        get_provisioned_postwait = aws_client.lambda_.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=v1["Version"]
        )
        snapshot.match("get_provisioned_postwait", get_provisioned_postwait)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.put_function_concurrency(
                FunctionName=func_name, ReservedConcurrentExecutions=1
            )
        snapshot.match("reserved_lower_than_provisioned_exc", e.value.response)
        aws_client.lambda_.put_function_concurrency(
            FunctionName=func_name, ReservedConcurrentExecutions=2
        )
        get_concurrency = aws_client.lambda_.get_function_concurrency(FunctionName=func_name)
        snapshot.match("get_concurrency", get_concurrency)

        # absolute limit, this means there is no free function execution for any invoke that doesn't have provisioned concurrency (!)
        with pytest.raises(aws_client.lambda_.exceptions.TooManyRequestsException) as e:
            aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("reserved_equals_provisioned_latest_invoke_exc", e.value.response)

        # passes since the version has a provisioned concurrency config set
        invoke_result1 = aws_client.lambda_.invoke(FunctionName=func_name, Qualifier=v1["Version"])
        result1 = json.load(invoke_result1["Payload"])
        assert result1 == "provisioned-concurrency"

        # try to add a new provisioned concurrency config to another qualifier on the same function
        update_func_config = aws_client.lambda_.update_function_configuration(
            FunctionName=func_name, Timeout=15
        )
        snapshot.match("update_func_config", update_func_config)
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=func_name)

        v2 = aws_client.lambda_.publish_version(FunctionName=func_name)
        assert v1["Version"] != v2["Version"]
        # doesn't work because the reserved function concurrency is 2 and we already have a total provisioned sum of 2
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.put_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=v2["Version"], ProvisionedConcurrentExecutions=1
            )
        snapshot.match("reserved_equals_provisioned_another_provisioned_exc", e.value.response)

        # updating the provisioned concurrency config of v1 to 3 (from 2) should also not work
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.put_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=v1["Version"], ProvisionedConcurrentExecutions=3
            )
        snapshot.match("reserved_equals_provisioned_increase_provisioned_exc", e.value.response)


class TestLambdaVersions:
    @markers.aws.validated
    def test_lambda_versions_with_code_changes(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
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
            Runtime=Runtime.python3_12,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)
        first_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        update_lambda_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        invocation_result_latest = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=b"{}"
        )
        snapshot.match("invocation_result_latest", invocation_result_latest)
        invocation_result_v1 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=first_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v1", invocation_result_v1)
        second_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        invocation_result_v2 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=second_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v2", invocation_result_v2)
        zip_file_v3 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version3", get_content=True
        )
        update_lambda_response_with_publish = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v3, Publish=True
        )
        snapshot.match("update_lambda_response_with_publish", update_lambda_response_with_publish)
        waiter.wait(
            FunctionName=function_name, Qualifier=update_lambda_response_with_publish["Version"]
        )
        invocation_result_v3 = aws_client.lambda_.invoke(
            FunctionName=function_name,
            Qualifier=update_lambda_response_with_publish["Version"],
            Payload=b"{}",
        )
        snapshot.match("invocation_result_v3", invocation_result_v3)
        invocation_result_latest_end = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=b"{}"
        )
        snapshot.match("invocation_result_latest_end", invocation_result_latest_end)
        invocation_result_v2 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=second_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v2_end", invocation_result_v2)
        invocation_result_v1 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=first_publish_response["Version"], Payload=b"{}"
        )
        snapshot.match("invocation_result_v1_end", invocation_result_v1)

    @markers.aws.validated
    def test_lambda_handler_update(self, aws_client, create_lambda_function, snapshot):
        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            # handler.handler by convention
            handler_file=TEST_LAMBDA_PYTHON_MULTIPLE_HANDLERS,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        invoke_result_handler_one = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_result_handler_one", invoke_result_handler_one)

        update_function_configuration_result = aws_client.lambda_.update_function_configuration(
            FunctionName=func_name, Handler="handler.handler_two"
        )
        snapshot.match("update_function_configuration_result", update_function_configuration_result)
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=func_name)

        get_function_result = aws_client.lambda_.get_function(FunctionName=func_name)
        snapshot.match("get_function_result", get_function_result)

        invoke_result_handler_two = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_result_handler_two", invoke_result_handler_two)

        publish_version_result = aws_client.lambda_.publish_version(FunctionName=func_name)
        waiter.wait(FunctionName=func_name, Qualifier=publish_version_result["Version"])

        invoke_result_handler_two_postpublish = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match(
            "invoke_result_handler_two_postpublish", invoke_result_handler_two_postpublish
        )

    # TODO: Fix this test by not stopping running invokes for function updates of $LATEST
    @pytest.mark.skip(
        reason="""Fails with 'Internal error while executing lambda' because
                  the current implementation stops all running invokes upon update."""
    )
    @markers.aws.validated
    def test_function_update_during_invoke(self, aws_client, create_lambda_function, snapshot):
        function_name = f"test-function-{short_uid()}"
        environment_v1 = {"Variables": {"FUNCTION_VARIANT": "variant-1"}}
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION_FUNCTION_VERSION,
            runtime=Runtime.python3_12,
            Environment=environment_v1,
        )

        errored = False

        def _update_function():
            nonlocal errored
            try:
                # Make it very likely that the invocation is being processed because the incoming invocation acquires
                # an invocation lease quickly.
                time.sleep(5)

                environment_v2 = environment_v1.copy()
                environment_v2["Variables"]["FUNCTION_VARIANT"] = "variant-2"
                aws_client.lambda_.update_function_configuration(
                    FunctionName=function_name, Environment=environment_v2
                )
                waiter = aws_client.lambda_.get_waiter("function_updated_v2")
                waiter.wait(FunctionName=function_name)

                payload = {"request_prefix": "2-post-update"}
                invoke_response_after = aws_client.lambda_.invoke(
                    FunctionName=function_name,
                    Payload=json.dumps(payload),
                )
                assert invoke_response_after["StatusCode"] == 200
                payload = json.load(invoke_response_after["Payload"])
                assert payload["function_variant"] == "variant-2"
                assert payload["function_version"] == "$LATEST"
            except Exception:
                LOG.exception(f"Updating lambda function {function_name} failed.")
                errored = True

        # Start thread with upcoming function update (slightly delayed)
        thread = threading.Thread(target=_update_function)
        thread.start()

        # Start an invocation with a sleep
        payload = {"request_prefix": "1-sleep", "sleep_seconds": 20}
        invoke_response_before = aws_client.lambda_.invoke(
            FunctionName=function_name,
            Payload=json.dumps(payload),
        )
        snapshot.match("invoke_response_before", invoke_response_before)

        thread.join()
        assert not errored

    # TODO: Fix first invoke getting retried and ending up being executed against the new variant because the
    #  update stops the running function version. We should let running executions finish for $LATEST in this case.
    # MAYBE: consider validating whether a code update behaves differently than a configuration update
    @markers.aws.validated
    def test_async_invoke_queue_upon_function_update(
        self, aws_client, create_lambda_function, s3_create_bucket, snapshot
    ):
        """Test what happens with queued async invokes (i.e., event invokes) when updating a function.
        We are using a combination of reserved concurrency and sleeps to design this test case predictable.
        Observation: If we don't wait after sending the first invoke, some queued invokes can still be handled by an
        old variant in some non-deterministic way.
        """
        # HACK: workaround to ignore `$..async_invoke_history_sorted[0]` because indices don't work in the ignore list
        snapshot.add_transformer(
            snapshot.transform.regex("01-sleep--variant-2", "01-sleep--variant-1")
        )
        bucket_name = f"lambda-target-bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)

        function_name = f"test-function-{short_uid()}"
        environment_v1 = {
            "Variables": {"S3_BUCKET_NAME": bucket_name, "FUNCTION_VARIANT": "variant-1"}
        }
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION_FUNCTION_VERSION,
            runtime=Runtime.python3_12,
            Environment=environment_v1,
        )
        # Add reserved concurrency limits the throughput and makes it easier to cause event invokes to queue up.
        reserved_concurrency_response = aws_client.lambda_.put_function_concurrency(
            FunctionName=function_name,
            ReservedConcurrentExecutions=1,
        )
        assert reserved_concurrency_response["ResponseMetadata"]["HTTPStatusCode"] == 200

        payload = {"request_prefix": f"{1:02}-sleep", "sleep_seconds": 22}
        aws_client.lambda_.invoke(
            FunctionName=function_name,
            InvocationType="Event",
            Payload=json.dumps(payload),
        )
        # Make it very likely that the invocation is being processed because the Lambda poller should pick up queued
        # async invokes quickly using long polling.
        time.sleep(2)

        # Send async invocation, which should queue up before we update the function
        num_invocations_before = 9
        for index in range(num_invocations_before):
            payload = {"request_prefix": f"{index + 2:02}-before"}
            aws_client.lambda_.invoke(
                FunctionName=function_name,
                InvocationType="Event",
                Payload=json.dumps(payload),
            )

        # Update the function variant while still having invokes in the async invoke queue
        environment_v2 = environment_v1.copy()
        environment_v2["Variables"]["FUNCTION_VARIANT"] = "variant-2"
        aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Environment=environment_v2
        )
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        # Send further async invocations after the update succeeded
        num_invocations_after = 5
        for index in range(num_invocations_after):
            payload = {"request_prefix": f"{index + num_invocations_before + 2:02}-after"}
            aws_client.lambda_.invoke(
                FunctionName=function_name,
                InvocationType="Event",
                Payload=json.dumps(payload),
            )

        # +1 for the first sleep invocation
        total_invocations = 1 + num_invocations_before + num_invocations_after

        def assert_s3_objects():
            s3_keys_output = get_s3_keys(aws_client, bucket_name)
            assert len(s3_keys_output) >= total_invocations
            return s3_keys_output

        s3_keys = retry(assert_s3_objects, retries=20, sleep=5)
        s3_keys_sorted = sorted(s3_keys)
        snapshot.match("async_invoke_history_sorted", s3_keys_sorted)


# TODO: test if routing is static for a single invocation:
#  Do retries for an event invoke, take the same "path" for every retry?
class TestLambdaAliases:
    @markers.aws.validated
    def test_lambda_alias_moving(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        """Check if alias only moves after it is updated"""
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
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
            Runtime=Runtime.python3_12,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)
        first_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=first_publish_response["Version"])
        # create alias
        create_alias_response = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            FunctionVersion=first_publish_response["Version"],
            Name="alias1",
        )
        snapshot.match("create_alias_response", create_alias_response)
        invocation_result_qualifier_v1 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1", invocation_result_qualifier_v1)
        invocation_result_qualifier_v1_arn = aws_client.lambda_.invoke(
            FunctionName=create_alias_response["AliasArn"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v1_arn", invocation_result_qualifier_v1_arn)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        # update lambda code
        update_lambda_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_v2
        )
        snapshot.match("update_lambda_response", update_lambda_response)
        waiter.wait(FunctionName=function_name)
        # check if alias is still first version
        invocation_result_qualifier_v1_after_update = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_update",
            invocation_result_qualifier_v1_after_update,
        )
        # publish to 2
        second_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # check if invoke still targets 1
        invocation_result_qualifier_v1_after_publish = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match(
            "invocation_result_qualifier_v1_after_publish",
            invocation_result_qualifier_v1_after_publish,
        )
        # move alias to 2
        update_alias_response = aws_client.lambda_.update_alias(
            FunctionName=function_name,
            Name=create_alias_response["Name"],
            FunctionVersion=second_publish_response["Version"],
        )
        snapshot.match("update_alias_response", update_alias_response)
        # check if alias moved to 2
        invocation_result_qualifier_v2 = aws_client.lambda_.invoke(
            FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
        )
        snapshot.match("invocation_result_qualifier_v2", invocation_result_qualifier_v2)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.invoke(
                FunctionName=function_name, Qualifier="non-existent-alias", Payload=b"{}"
            )
        snapshot.match("invocation_exc_not_existent", e.value.response)

    @markers.aws.validated
    def test_alias_routingconfig(
        self, lambda_su_role, create_lambda_function_aws, snapshot, aws_client
    ):
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
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
            Runtime=Runtime.python3_12,
            Description="First version :)",
            Publish=True,
        )
        waiter.wait(FunctionName=function_name)
        zip_file_v2 = create_lambda_archive(
            load_file(TEST_LAMBDA_VERSION) % "version2", get_content=True
        )
        # update lambda code
        aws_client.lambda_.update_function_code(FunctionName=function_name, ZipFile=zip_file_v2)
        waiter.wait(FunctionName=function_name)

        second_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Second version description :)"
        )
        waiter.wait(FunctionName=function_name, Qualifier=second_publish_response["Version"])
        # create alias
        create_alias_response = aws_client.lambda_.create_alias(
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
            invoke_response = aws_client.lambda_.invoke(
                FunctionName=function_name, Qualifier=create_alias_response["Name"], Payload=b"{}"
            )
            payload = json.load(invoke_response["Payload"])
            versions_hit.add(payload["version_from_ctx"])
            retries += 1
        assert len(versions_hit) == 2, f"Did not hit both versions after {max_retries} retries"


class TestRequestIdHandling:
    @markers.aws.validated
    def test_request_id_format(self, aws_client):
        r = aws_client.lambda_.list_functions()
        request_id = r["ResponseMetadata"]["RequestId"]
        assert re.match(
            r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", request_id
        )

    # TODO remove, currently missing init duration in REPORT
    @markers.snapshot.skip_snapshot_verify(paths=["$..logs"])
    @markers.aws.validated
    def test_request_id_invoke(self, aws_client, create_lambda_function, snapshot):
        """Test that the request_id within the Lambda context matches with CloudWatch logs."""
        func_name = f"test_lambda_{short_uid()}"
        log_group_name = f"/aws/lambda/{func_name}"

        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_PYTHON_REQUEST_ID,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        result = aws_client.lambda_.invoke(FunctionName=func_name)
        snapshot.match("invoke_result", result)
        snapshot.add_transformer(
            snapshot.transform.regex(result["ResponseMetadata"]["RequestId"], "<request-id>")
        )

        def fetch_logs():
            log_events_result = aws_client.logs.filter_log_events(logGroupName=log_group_name)
            assert any("REPORT" in e["message"] for e in log_events_result["events"])
            return log_events_result

        log_events = retry(fetch_logs, retries=10, sleep=2)
        log_entries = [
            line["message"].rstrip()
            for line in log_events["events"]
            if "RequestId" in line["message"]
        ]
        snapshot.match("log_entries", {"logs": log_entries})
        snapshot.add_transformer(snapshot.transform.lambda_report_logs())

    @markers.aws.validated
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
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        url_config = aws_client.lambda_.create_function_url_config(
            FunctionName=fn_name,
            AuthType="NONE",
        )
        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = aws_client.lambda_.add_permission(
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
            assert any("REPORT" in e["message"] for e in log_events_result["events"])
            return log_events_result

        log_events = retry(fetch_logs, retries=10, sleep=2)
        # TODO: AWS appends a "\n" so we need to trim here. Should explore this more
        end_log_entries = [
            e["message"].rstrip() for e in log_events["events"] if e["message"].startswith("END")
        ]
        snapshot.match("end_log_entries", end_log_entries)

    @markers.aws.validated
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
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
        )

        aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=func_name, MaximumRetryAttempts=1
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=func_name)

        result = aws_client.lambda_.invoke(
            FunctionName=func_name, InvocationType="Event", Payload=json.dumps({"fail": 1})
        )
        snapshot.match("invoke_result", result)

        request_id = result["ResponseMetadata"]["RequestId"]
        snapshot.add_transformer(snapshot.transform.regex(request_id, "<request-id>"))

        time.sleep(test_delay_base * 2)

        log_events = aws_client.logs.filter_log_events(logGroupName=log_group_name)
        report_messages = [e for e in log_events["events"] if "REPORT" in e["message"]]
        assert len(report_messages) == 2
        assert all(request_id in rm["message"] for rm in report_messages)
        end_messages = [
            e["message"].rstrip() for e in log_events["events"] if "END" in e["message"]
        ]
        snapshot.match("end_messages", end_messages)
