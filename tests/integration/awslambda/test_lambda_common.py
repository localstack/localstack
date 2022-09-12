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

    def test_something_random(self, lambda_client):
        ...

    # mixed
    @pytest.mark.multiruntime(scenario="echo", runtimes=["python", "ruby", "nodejs12.x"])
    def test_echo_some(self, lambda_client, multiruntime_lambda):
        multiruntime_lambda.create_function()

    # mixed
    @pytest.mark.multiruntime(scenario="echo", runtimes=["python"])
    def test_echo_invoke(self, lambda_client, multiruntime_lambda, snapshot):
        create_function_result = multiruntime_lambda.create_function()
        lambda_client.invoke(FunctionName=create_function_result["FunctionName"], Payload=b"{}")
