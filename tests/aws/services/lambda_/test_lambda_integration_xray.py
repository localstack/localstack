import json
import os
import time

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.xray.trace_header import TraceHeader

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


@markers.aws.validated
def test_xray_trace_propagation(
    create_lambda_function, lambda_su_role, snapshot, aws_client, cleanups
):
    """Test trace header parsing and propagation from an incoming Lambda invoke request into a Lambda invocation.
    This test should work independently of the TracingConfig: PassThrough (default) vs. Active
    https://stackoverflow.com/questions/50077890/aws-sam-x-ray-tracing-active-vs-passthrough
    """
    fn_name = f"test-xray-trace-propagation-fn-{short_uid()}"

    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_XRAY_TRACEID,
        runtime=Runtime.python3_12,
    )

    # add boto hook
    root_trace_id = "1-3152b799-8954dae64eda91bc9a23a7e8"
    xray_trace_header = TraceHeader(root=root_trace_id, parent="7fa8c0f79203be72", sampled=1)

    def add_xray_header(request, **kwargs):
        request.headers["X-Amzn-Trace-Id"] = xray_trace_header.to_header_str()

    event_name = "before-send.lambda.*"
    aws_client.lambda_.meta.events.register(event_name, add_xray_header)
    # make sure the hook gets cleaned up after the test
    cleanups.append(lambda: aws_client.lambda_.meta.events.unregister(event_name, add_xray_header))

    result = aws_client.lambda_.invoke(FunctionName=fn_name)
    payload = json.load(result["Payload"])
    actual_root_trace_id = TraceHeader.from_header_str(payload["trace_id_inside_handler"]).root
    assert actual_root_trace_id == root_trace_id

    # TODO: lineage field missing in LocalStack and xray trace header transformers needed for snapshotting
    # snapshot.match("trace-header", payload["envs"]["_X_AMZN_TRACE_ID"])
