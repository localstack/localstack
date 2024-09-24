"""Testing different runtimes focusing on common functionality that should work across all runtimes (e.g., echo invoke).
Internally, these tests are also known as multiruntime tests.

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
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack.services.lambda_.runtimes import RUNTIMES_AGGREGATED, TESTED_RUNTIMES
from localstack.testing.pytest import markers
from localstack.utils.files import cp_r
from localstack.utils.strings import short_uid, to_bytes

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
            # Works in LocalStack locally but the hash changes in CI and every time at AWS (except for Java runtimes)
            snapshot.transform.key_value(
                "CodeSha256", value_replacement="<code-sha256>", reference_replacement=False
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


@markers.lambda_runtime_update
class TestLambdaRuntimesCommon:
    # TODO: refactor builds by creating a generic parametrizable Makefile per runtime (possibly with an option to
    #  provide a specific one). This might be doable by including another Makefile:
    #  https://www.gnu.org/software/make/manual/make.html#Include

    @markers.aws.validated
    @markers.multiruntime(scenario="echo")
    def test_echo_invoke(self, multiruntime_lambda, aws_client):
        # provided lambdas take a little longer for large payloads, hence timeout to 5s
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024, Timeout=5)

        def _invoke_with_payload(payload):
            invoke_result = aws_client.lambda_.invoke(
                FunctionName=create_function_result["FunctionName"],
                Payload=to_bytes(json.dumps(payload)),
            )

            assert invoke_result["StatusCode"] == 200
            assert json.load(invoke_result["Payload"]) == payload
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
        assert json.load(invoke_result["Payload"]) == {}
        assert not invoke_result.get("FunctionError")

    # skip snapshots of LS specific env variables
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: implement logging config
            "$..LoggingConfig",
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
            "$..environment.LC_CTYPE",  # Only python3.11 (part of a broken image rollout, likely rolled back)
            # Newer Nodejs images explicitly disable a temporary performance workaround for Nodejs 20 on certain hosts:
            # https://nodejs.org/api/cli.html#uv_use_io_uringvalue
            # https://techfindings.net/archives/6469
            "$..environment.UV_USE_IO_URING",  # Only Nodejs runtimes
            # Only Dotnet8
            "$..environment.DOTNET_CLI_TELEMETRY_OPTOUT",
            "$..environment.DOTNET_NOLOGO",
            "$..environment.DOTNET_RUNNING_IN_CONTAINER",
            "$..environment.DOTNET_VERSION",
        ]
    )
    @markers.aws.validated
    @markers.multiruntime(scenario="introspection")
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
        invocation_result_payload = json.load(invoke_result["Payload"])
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
        invocation_result_payload_qualified = json.load(invoke_result_qualified["Payload"])
        snapshot.match("invocation_result_payload_qualified", invocation_result_payload_qualified)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: implement logging config
            "$..LoggingConfig",
        ]
    )
    @markers.aws.validated
    @markers.multiruntime(scenario="uncaughtexception")
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
            # TODO: implement logging config
            "$..LoggingConfig",
        ]
    )
    @markers.aws.validated
    # Only works for >=al2 runtimes, except for any provided runtimes
    # Does NOT work for provided runtimes
    # Source: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
    @markers.multiruntime(
        scenario="introspection",
        runtimes=list(set(TESTED_RUNTIMES) - set(RUNTIMES_AGGREGATED.get("provided"))),
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
        invocation_result_payload = json.load(invoke_result["Payload"])
        assert "environment" in invocation_result_payload
        assert "ctx" in invocation_result_payload
        assert "packages" in invocation_result_payload
        assert invocation_result_payload["environment"]["WRAPPER_VAR"] == test_value


@markers.lambda_runtime_update
class TestLambdaCallingLocalstack:
    """=> Keep these tests synchronized with `test_lambda_endpoint_injection.py` in ext!"""

    @markers.multiruntime(
        scenario="endpointinjection",
        runtimes=list(set(TESTED_RUNTIMES) - set(RUNTIMES_AGGREGATED.get("provided"))),
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
