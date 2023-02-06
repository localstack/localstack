import json
import logging
import os
import time
import zipfile

import pytest

from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.utils.files import cp_r
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


@pytest.mark.skipif(
    condition=is_old_provider(),
    reason="Local executor does not support the majority of the runtimes",
)
class TestLambdaRuntimesCommon:
    """
    Directly correlates to the structure found in tests.integration.awslambda.functions.common

    each scenario has the following folder structure

    ./common/<scenario>/runtime/

    runtime can either be directly one of the supported runtimes (e.g. in case of version specific compilation instructions) or one of the keys in RUNTIMES_AGGREGATED

    """

    @pytest.mark.multiruntime(scenario="echo")
    def test_echo_invoke(self, lambda_client, multiruntime_lambda):
        # provided lambdas take a little longer for large payloads, hence timeout to 5s
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024, Timeout=5)

        def _invoke_with_payload(payload):
            invoke_result = lambda_client.invoke(
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
        invoke_result = lambda_client.invoke(FunctionName=create_function_result["FunctionName"])
        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == {}
        assert not invoke_result.get("FunctionError")

    # skip snapshots of LS specific env variables / xray variables
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..environment.AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "$..environment.AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "$..environment.AWS_ENDPOINT_URL",
            "$..environment.AWS_LAMBDA_FUNCTION_TIMEOUT",
            "$..environment.AWS_XRAY_CONTEXT_MISSING",
            "$..environment.AWS_XRAY_DAEMON_ADDRESS",
            "$..environment.EDGE_PORT",
            "$..environment.HOME",
            "$..environment.HOSTNAME",
            "$..environment.LOCALSTACK_HOSTNAME",
            "$..environment.LOCALSTACK_RUNTIME_ENDPOINT",
            "$..environment.LOCALSTACK_RUNTIME_ID",
            "$..environment.RUNTIME_ROOT",
            "$..environment.TASK_ROOT",
            "$..environment._AWS_XRAY_DAEMON_ADDRESS",
            "$..environment._AWS_XRAY_DAEMON_PORT",
            "$..environment._LAMBDA_TELEMETRY_LOG_FD",  # Only java8, dotnetcore3.1, dotnet6, go1.x
            "$..environment._X_AMZN_TRACE_ID",
            "$..environment.AWS_EXECUTION_ENV",  # Only rust runtime
            "$..environment.LD_LIBRARY_PATH",  # Only rust runtime (additional /var/lang/bin)
            "$..environment.PATH",  # Only rust runtime (additional /var/lang/bin)
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
        ]
    )
    @pytest.mark.multiruntime(scenario="introspection")
    def test_introspection_invoke(self, lambda_client, multiruntime_lambda, snapshot):
        create_function_result = multiruntime_lambda.create_function(
            MemorySize=1024, Environment={"Variables": {"TEST_KEY": "TEST_VAL"}}
        )
        snapshot.match("create_function_result", create_function_result)

        # simple payload
        invoke_result = lambda_client.invoke(
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
        invoke_result_qualified = lambda_client.invoke(
            FunctionName=f"{create_function_result['FunctionArn']}:$LATEST",
            Payload=b'{"simple": "payload"}',
        )

        assert invoke_result["StatusCode"] == 200
        invocation_result_payload_qualified = to_str(invoke_result_qualified["Payload"].read())
        invocation_result_payload_qualified = json.loads(invocation_result_payload_qualified)
        snapshot.match("invocation_result_payload_qualified", invocation_result_payload_qualified)

    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
        ]
    )
    @pytest.mark.multiruntime(scenario="uncaughtexception")
    def test_uncaught_exception_invoke(self, lambda_client, multiruntime_lambda, snapshot):
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
        invocation_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b'{"error_msg": "some_error_msg"}',
        )
        assert "FunctionError" in invocation_result
        snapshot.match("error_result", invocation_result)

    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
            "$..SnapStart",  # FIXME needs to be added to CreateFunction + all snapshots regenerated
        ]
    )
    # this does only work on al2 lambdas, except provided.al2.
    # Source: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
    @pytest.mark.multiruntime(
        scenario="introspection",
        runtimes=["nodejs"],
        # runtimes=["nodejs", "python3.8", "python3.9", "java8.al2", "java11", "dotnet", "ruby"],
    )
    def test_runtime_wrapper_invoke(self, lambda_client, multiruntime_lambda, snapshot, tmp_path):
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
        invoke_result = lambda_client.invoke(
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


@pytest.mark.whitebox
@pytest.mark.skipif(
    condition=is_old_provider(),
    reason="Local executor does not support the majority of the runtimes",
)
class TestLambdaCallingLocalstack:
    @pytest.mark.multiruntime(
        scenario="endpointinjection",
        runtimes=[
            "nodejs",
            "python",
            "ruby",
            "java8.al2",
            "java11",
            "go1.x",  # TODO: does not yet support transparent endpoint injection
            "dotnet6",  # TODO: does not yet support transparent endpoint injection
            "dotnetcore3.1",  # TODO: does not yet support transparent endpoint injection
        ],
    )
    def test_calling_localstack_from_lambda(self, lambda_client, multiruntime_lambda, tmp_path):
        pro_enabled = "LOCALSTACK_API_KEY" in os.environ

        if pro_enabled and multiruntime_lambda.runtime in ["go1.x", "dotnet6", "dotnetcore3.1"]:
            pytest.skip(
                f"Runtime ({multiruntime_lambda.runtime}) does not support transparent endpoint injection yet. Skipping"
            )

        create_function_result = multiruntime_lambda.create_function(
            MemorySize=1024,
            Environment={"Variables": {"CONFIGURE_CLIENT": "0" if pro_enabled else "1"}},
        )

        invocation_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b"{}",
        )
        assert "FunctionError" not in invocation_result
