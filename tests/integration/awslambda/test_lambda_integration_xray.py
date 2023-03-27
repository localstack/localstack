import json
import os
import time

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.utils.strings import short_uid, to_str

TEST_LAMBDA_XRAY_TRACEID = os.path.join(
    os.path.dirname(__file__), "./functions/xray_tracing_traceid.py"
)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
@pytest.mark.parametrize("tracing_mode", ["Active", "PassThrough"])
@pytest.mark.aws_validated
def test_traceid_outside_handler(
    lambda_client, create_lambda_function, lambda_su_role, tracing_mode
):
    fn_name = f"test-xray-traceid-fn-{short_uid()}"

    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_XRAY_TRACEID,
        runtime=Runtime.python3_9,
        role=lambda_su_role,
        TracingConfig={"Mode": tracing_mode},
    )

    invoke_result_1 = lambda_client.invoke(FunctionName=fn_name)
    parsed_result_1 = json.loads(to_str(invoke_result_1["Payload"].read()))
    time.sleep(1)  # to guarantee sampling on AWS
    invoke_result_2 = lambda_client.invoke(FunctionName=fn_name)
    parsed_result_2 = json.loads(to_str(invoke_result_2["Payload"].read()))

    assert parsed_result_1["trace_id_outside_handler"] == "None"
    assert parsed_result_2["trace_id_outside_handler"] == "None"
    assert parsed_result_1["trace_id_inside_handler"] != parsed_result_2["trace_id_inside_handler"]
