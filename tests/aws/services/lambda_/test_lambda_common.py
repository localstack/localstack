"""Lambda scenario tests for different runtimes (i.e., multiruntime tests).

Directly correlates to the structure found in tests.aws.lambda_.functions.common
Each scenario has the following folder structure: ./common/<scenario>/runtime/
Runtime can either be directly one of the supported runtimes (e.g. in case of version specific compilation instructions)
or one of the keys in RUNTIMES_AGGREGATED. To selectively execute runtimes, use the runtimes parameter of multiruntime.
Example: runtimes=[Runtime.go1_x]
"""
import json
import logging
import time
import zipfile

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.services.lambda_.runtimes import TESTED_RUNTIMES
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.utils.files import cp_r
from localstack.utils.platform import Arch, get_arch
from localstack.utils.strings import short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("AWS_ACCESS_KEY_ID", "aws-access-key-id"),
            snapshot.transform.key_value("AWS_SECRET_ACCESS_KEY", "aws-secret-access-key"),
            snapshot.transform.key_value("AWS_SESSION_TOKEN", "aws-session-token"),
            snapshot.transform.key_value("_X_AMZN_TRACE_ID", "x-amzn-trace-id"),
            # go lambdas only
            snapshot.transform.key_value(
                "_LAMBDA_SERVER_PORT", "<lambda-server-port>", reference_replacement=False
            ),
            # workaround for integer values
            KeyValueBasedTransformer(
                lambda k, v: str(v) if k == "remaining_time_in_millis" else None,
                "<remaining-time-in-millis>",
                replace_reference=False,
            ),
            snapshot.transform.key_value("deadline", "deadline"),
        ]
    )


# TODO: remove this once all non-arm compatible runtimes are deprecated by the end of 2023
RUNTIMES_SKIP_ARM = [
    Runtime.python3_7,
    Runtime.java8,
    Runtime.go1_x,
    Runtime.provided,
    # TODO: debug and fix ARM builds in CI (works locally on ARM mac)
    Runtime.java8_al2,
    Runtime.java11,
    Runtime.java17,
    Runtime.java21,
    Runtime.dotnet6,
    # test_echo_invoke works but test_introspection_invoke and test_uncaught_exception_invoke fail in CI
    Runtime.provided_al2,
    Runtime.provided_al2023,
]

arm_compatible_runtimes = list(set(TESTED_RUNTIMES) - set(RUNTIMES_SKIP_ARM))
runtimes = arm_compatible_runtimes if get_arch() == Arch.arm64 else TESTED_RUNTIMES


@markers.lambda_runtime_update
class TestLambdaRuntimesCommon:
    # TODO: refactor builds:
    #   * Create a generic parametrizable Makefile per runtime (possibly with an option to provide a specific one)

    @markers.aws.validated
    @markers.multiruntime(scenario="echo", runtimes=runtimes)
    def test_echo_invoke(self, multiruntime_lambda, aws_client):
        # provided lambdas take a little longer for large payloads, hence timeout to 5s
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024, Timeout=5)

        def _invoke_with_payload(payload):
            invoke_result = aws_client.lambda_.invoke(
                FunctionName=create_function_result["FunctionName"],
                Payload=to_bytes(json.dumps(payload)),
            )

            assert invoke_result["StatusCode"] == 200
            assert json.loads(invoke_result["Payload"].read()) == payload
            assert not invoke_result.get("FunctionError")

        # simple payload
        payload = {"hello": "world"}
        _invoke_with_payload(payload)
        # payload with quotes and other special characters
        payload = {"hello": "'\" some other ''\"\" quotes, a emoji 🥳 and some brackets {[}}[([]))"}
        _invoke_with_payload(payload)

        # large payload (5MB+)
        payload = {"hello": "obi wan!" * 128 * 1024 * 5}
        _invoke_with_payload(payload)

        # test non json invocations
        # boolean value
        payload = True
        _invoke_with_payload(payload)
        payload = False
        _invoke_with_payload(payload)
        # None value
        payload = None
        _invoke_with_payload(payload)
        # array value
        payload = [1, 2]
        _invoke_with_payload(payload)
        # number value
        payload = 1
        _invoke_with_payload(payload)
        # no payload at all
        invoke_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"]
        )
        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == {}
        assert not invoke_result.get("FunctionError")

    # skip snapshots of LS specific env variables
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # LocalStack API
            "$..environment.LOCALSTACK_HOSTNAME",
            "$..environment.EDGE_PORT",
            "$..environment.AWS_ENDPOINT_URL",
            # TODO: unset RIE API vars in RIE
            "$..environment.AWS_LAMBDA_FUNCTION_TIMEOUT",
            # AWS SDK container credentials:
            # https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
            "$..environment.AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "$..environment.AWS_CONTAINER_CREDENTIALS_FULL_URI",
            # TODO: xray
            "$..environment.AWS_XRAY_CONTEXT_MISSING",
            "$..environment.AWS_XRAY_DAEMON_ADDRESS",
            "$..environment._AWS_XRAY_DAEMON_ADDRESS",
            "$..environment._AWS_XRAY_DAEMON_PORT",
            "$..environment._X_AMZN_TRACE_ID",
            # Specific runtimes
            # TODO: Only nodejs18.x: AWS=/etc/pki/tls/certs/ca-bundle.crt LS=var/runtime/ca-cert.pem
            "$..environment.NODE_EXTRA_CA_CERTS",
            "$..environment._LAMBDA_TELEMETRY_LOG_FD",  # Only java8, dotnetcore3.1, dotnet6, go1.x
            "$..environment.AWS_EXECUTION_ENV",  # Only rust runtime
            "$..environment.LD_LIBRARY_PATH",  # Only rust runtime (additional /var/lang/bin)
            "$..environment.PATH",  # Only rust runtime (additional /var/lang/bin)
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
            "$..environment.LC_CTYPE",  # Only python3.11 (part of a broken image rollout, likely rolled back)
        ]
    )
    @markers.aws.validated
    @markers.multiruntime(scenario="introspection", runtimes=runtimes)
    def test_introspection_invoke(self, multiruntime_lambda, snapshot, aws_client):
        create_function_result = multiruntime_lambda.create_function(
            MemorySize=1024, Environment={"Variables": {"TEST_KEY": "TEST_VAL"}}
        )
        snapshot.match("create_function_result", create_function_result)

        # simple payload
        invoke_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b'{"simple": "payload"}',
        )

        assert invoke_result["StatusCode"] == 200
        invocation_result_payload = to_str(invoke_result["Payload"].read())
        invocation_result_payload = json.loads(invocation_result_payload)
        assert "environment" in invocation_result_payload
        assert "ctx" in invocation_result_payload
        assert "packages" in invocation_result_payload
        snapshot.match("invocation_result_payload", invocation_result_payload)

        # Check again with a qualified arn as function name
        invoke_result_qualified = aws_client.lambda_.invoke(
            FunctionName=f"{create_function_result['FunctionArn']}:$LATEST",
            Payload=b'{"simple": "payload"}',
        )

        assert invoke_result["StatusCode"] == 200
        invocation_result_payload_qualified = to_str(invoke_result_qualified["Payload"].read())
        invocation_result_payload_qualified = json.loads(invocation_result_payload_qualified)
        snapshot.match("invocation_result_payload_qualified", invocation_result_payload_qualified)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
        ]
    )
    @markers.aws.validated
    @markers.multiruntime(scenario="uncaughtexception", runtimes=runtimes)
    def test_uncaught_exception_invoke(self, multiruntime_lambda, snapshot, aws_client):
        # unfortunately the stack trace is quite unreliable and changes when AWS updates the runtime transparently
        # since the stack trace contains references to internal runtime code.
        snapshot.add_transformer(
            snapshot.transform.key_value("stackTrace", "<stack-trace>", reference_replacement=False)
        )
        # for nodejs
        snapshot.add_transformer(
            snapshot.transform.key_value("trace", "<stack-trace>", reference_replacement=False)
        )
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024)
        snapshot.match("create_function_result", create_function_result)

        # simple payload
        invocation_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b'{"error_msg": "some_error_msg"}',
        )
        assert "FunctionError" in invocation_result
        snapshot.match("error_result", invocation_result)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
        ]
    )
    @markers.aws.validated
    # Only works for >=al2 runtimes, except for any provided runtimes
    # Source: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
    @markers.multiruntime(
        scenario="introspection",
        runtimes=list(
            set(TESTED_RUNTIMES)
            - set(RUNTIMES_SKIP_ARM)
            - {Runtime.provided_al2, Runtime.provided_al2023}
        ),
    )
    def test_runtime_wrapper_invoke(self, multiruntime_lambda, snapshot, tmp_path, aws_client):
        # copy and modify zip file, pretty dirty hack to reuse scenario and reduce CI test runtime
        modified_zip = str(tmp_path / f"temp-zip-{short_uid()}.zip")
        cp_r(multiruntime_lambda.zip_file_path, modified_zip)
        test_value = f"test-value-{short_uid()}"
        env_wrapper = f"""#!/bin/bash
          export WRAPPER_VAR={test_value}
          exec "$@"
        """
        with zipfile.ZipFile(modified_zip, mode="a") as zip_file:
            info = zipfile.ZipInfo("environment_wrapper")
            info.date_time = time.localtime()
            info.external_attr = 0o100755 << 16
            zip_file.writestr(info, env_wrapper)

        # use new zipfile for file upload
        multiruntime_lambda.zip_file_path = modified_zip
        create_function_result = multiruntime_lambda.create_function(
            MemorySize=1024,
            Environment={"Variables": {"AWS_LAMBDA_EXEC_WRAPPER": "/var/task/environment_wrapper"}},
        )
        snapshot.match("create_function_result", create_function_result)

        # simple payload
        invoke_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b'{"simple": "payload"}',
        )

        assert invoke_result["StatusCode"] == 200
        invocation_result_payload = to_str(invoke_result["Payload"].read())
        invocation_result_payload = json.loads(invocation_result_payload)
        assert "environment" in invocation_result_payload
        assert "ctx" in invocation_result_payload
        assert "packages" in invocation_result_payload
        assert invocation_result_payload["environment"]["WRAPPER_VAR"] == test_value


class TestLambdaCallingLocalstack:
    """=> Keep these tests synchronized with `test_lambda_endpoint_injection.py` in ext!"""

    # TODO: remove this once all non-arm compatible runtimes are deprecated by the end of 2023
    #  and the ARM builds are fixed for the CI.
    # These temporary runtime selections are only relevant for test_manual_endpoint_injection
    x86_runtimes = [
        "dotnet6",
        "go",
        # java17 and java21 do not ship the AWS SDK v1 anymore.
        # Therefore, we create a specific directory and bundle the SDK v1 separately because the SDK v2 does not
        # support DISABLE_CERT_CHECKING_SYSTEM_PROPERTY anymore.
        "java",
        # nodejs18.x and nodejs20.x do not ship the AWS SDK v1 anymore.
        # Therefore, we create a specific directory and use the SDK v2 instead.
        "nodejs",
        "python",
        "ruby",
    ]

    # ARM-compatible runtimes for the endpointinjection scenario
    arm_runtimes = [
        # TODO: debug and fix ARM builds in CI (works locally on ARM mac)
        # "dotnet6",
        # "java8.al2",
        # "java11",
        # "java17",
        # "java21",
        "nodejs",
        "python3.8",
        "python3.9",
        "python3.10",
        "python3.11",
        "python3.12",
        "ruby",
    ]

    @markers.multiruntime(
        scenario="endpointinjection",
        runtimes=arm_runtimes if get_arch() == Arch.arm64 else x86_runtimes,
    )
    @markers.aws.validated
    def test_manual_endpoint_injection(self, multiruntime_lambda, tmp_path, aws_client):
        """Test calling SQS from Lambda using manual AWS SDK client configuration via AWS_ENDPOINT_URL.
        This must work for all runtimes.
        The code might differ depending on the SDK version shipped with the Lambda runtime.
        This test is designed to be AWS-compatible using minimal code changes to configure the endpoint url for LS.
        """

        create_function_result = multiruntime_lambda.create_function(MemorySize=1024, Timeout=15)

        invocation_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
        )
        assert "FunctionError" not in invocation_result
