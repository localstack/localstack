import json
import os
import time

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

TEST_LAMBDA_XRAY_TRACEID = os.path.join(
    os.path.dirname(__file__), "functions/xray_tracing_traceid.py"
)


@pytest.mark.parametrize("tracing_mode", ["Active", "PassThrough"])
@markers.aws.validated
def test_traceid_outside_handler(create_lambda_function, lambda_su_role, tracing_mode, aws_client):
    fn_name = f"test-xray-traceid-fn-{short_uid()}"

    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_XRAY_TRACEID,
        runtime=Runtime.python3_12,
        role=lambda_su_role,
        TracingConfig={"Mode": tracing_mode},
    )

    invoke_result_1 = aws_client.lambda_.invoke(FunctionName=fn_name)
    parsed_result_1 = json.load(invoke_result_1["Payload"])
    time.sleep(1)  # to guarantee sampling on AWS
    invoke_result_2 = aws_client.lambda_.invoke(FunctionName=fn_name)
    parsed_result_2 = json.load(invoke_result_2["Payload"])

    assert parsed_result_1["trace_id_outside_handler"] == "None"
    assert parsed_result_2["trace_id_outside_handler"] == "None"
    assert parsed_result_1["trace_id_inside_handler"] != parsed_result_2["trace_id_inside_handler"]
