import json
import logging

import pytest

LOG = logging.getLogger(__name__)


class TestLambdaRuntimesCommon:
    """
    Directly correlates to the structure found in tests.integration.awslambda.functions.common

    each scenario has the following folder structure

    ./common/<scenario>/runtime/

    runtime can either be directly one of the supported runtimes (e.g. in case of version specific compilation instructions) or one of the keys in RUNTIMES_AGGREGATED

    """

    @pytest.mark.multiruntime(scenario="echo")
    def test_echo_invoke(self, lambda_client, multiruntime_lambda):
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024)
        invoke_result = lambda_client.invoke(
            FunctionName=create_function_result["FunctionName"], Payload=b'{"hello":"world"}'
        )

        assert invoke_result["StatusCode"] == 200
        assert json.loads(invoke_result["Payload"].read()) == {"hello": "world"}
