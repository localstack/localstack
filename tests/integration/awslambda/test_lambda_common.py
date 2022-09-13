import json
import logging

import pytest

from localstack.utils.strings import to_bytes, to_str

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())


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

        # simple payload
        payload = {"hello": "world"}
        invoke_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=to_bytes(json.dumps(payload)),
        )

        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == payload

        # payload with quotes and other special characters
        payload = {"hello": "'\" some other ''\"\" quotes, a emoji 🥳 and some brackets {[}}[([]))"}
        invoke_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=to_bytes(json.dumps(payload)),
        )

        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == payload

        # large payload (5MB+)
        payload = {"hello": "obi wan!" * 128 * 1024 * 5}
        invoke_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=to_bytes(json.dumps(payload)),
        )

        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == payload

    @pytest.mark.multiruntime(
        scenario="introspection",
        runtimes=["python", "nodejs", "ruby", "java", "go", "dotnet", "custom"],
    )
    def test_introspection_invoke(self, lambda_client, multiruntime_lambda, snapshot):
        # provided lambdas take a little longer for large payloads, hence timeout to 5s
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
