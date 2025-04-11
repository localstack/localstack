import json
import time

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from localstack.utils.xray.trace_header import TraceHeader
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_AWS_PROXY_FORMAT

APIGATEWAY_ASSUME_ROLE_POLICY = {
    "Statement": {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {"Service": "apigateway.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}
import re

import pytest

from localstack.testing.aws.util import is_aws_cloud
from tests.aws.services.events.helper_functions import is_old_provider
from tests.aws.services.events.test_events import TEST_EVENT_DETAIL, TEST_EVENT_PATTERN
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_XRAY_TRACEID

# currently only API Gateway v2 and Lambda support X-Ray tracing


@markers.aws.validated
@pytest.mark.skipif(
    condition=is_old_provider(),
    reason="not supported by the old provider",
)
def test_xray_trace_propagation_events_api_gateway(
    aws_client,
    create_role_with_policy,
    create_lambda_function,
    create_rest_apigw,
    events_create_event_bus,
    events_put_rule,
    region_name,
    cleanups,
    account_id,
):
    # create lambda
    function_name = f"test-function-{short_uid()}"
    function_arn = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY_FORMAT,
        handler="lambda_aws_proxy_format.handler",
        runtime=Runtime.python3_12,
    )["CreateFunctionResponse"]["FunctionArn"]

    # create api gateway with lambda integration
    # create rest api
    api_id, api_name, root_id = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Test Integration with EventBridge X-Ray",
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="test"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
    )

    # Lambda AWS_PROXY integration
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region_name}:lambda:path/2015-03-31/functions/{function_arn}/invocations",
    )

    # Give permission to API Gateway to invoke Lambda
    source_arn = f"arn:aws:execute-api:{region_name}:{account_id}:{api_id}/*/POST/test"
    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"sid-{short_uid()}",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    stage_name = "test"
    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    # Create event bus
    event_bus_name = f"test-bus-{short_uid()}"
    events_create_event_bus(Name=event_bus_name)

    # Create rule
    rule_name = f"test-rule-{short_uid()}"
    event_pattern = {"source": ["test.source"], "detail-type": ["test.detail.type"]}
    events_put_rule(
        Name=rule_name,
        EventBusName=event_bus_name,
        EventPattern=json.dumps(event_pattern),
    )

    # Create an IAM Role for EventBridge to invoke API Gateway
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    role_name, role_arn = create_role_with_policy(
        effect="Allow",
        actions="execute-api:Invoke",
        assume_policy_doc=json.dumps(assume_role_policy_document),
        resource=source_arn,
        attach=False,  # Since we're using put_role_policy, not attach_role_policy
    )

    # Allow some time for IAM role propagation (only needed in AWS)
    if is_aws_cloud():
        time.sleep(10)

    # Add the API Gateway as a target with the RoleArn
    target_id = f"target-{short_uid()}"
    api_target_arn = (
        f"arn:aws:execute-api:{region_name}:{account_id}:{api_id}/{stage_name}/POST/test"
    )
    put_targets_response = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=event_bus_name,
        Targets=[
            {
                "Id": target_id,
                "Arn": api_target_arn,
                "RoleArn": role_arn,
                "Input": json.dumps({"message": "Hello from EventBridge"}),
                "RetryPolicy": {"MaximumRetryAttempts": 0},
            }
        ],
    )
    assert put_targets_response["FailedEntryCount"] == 0

    ######
    # Test
    ######
    # Enable X-Ray tracing for the aws_client
    trace_id = "1-67f4141f-e1cd7672871da115129f8b19"
    parent_id = "d0ee9531727135a0"
    xray_trace_header = TraceHeader(root=trace_id, parent=parent_id, sampled=1)

    def add_xray_header(request, **kwargs):
        request.headers["X-Amzn-Trace-Id"] = xray_trace_header.to_header_str()

    event_name = "before-send.events.*"
    aws_client.events.meta.events.register(event_name, add_xray_header)

    # make sure the hook gets cleaned up after the test
    cleanups.append(lambda: aws_client.events.meta.events.unregister(event_name, add_xray_header))

    event_entry = {
        "EventBusName": event_bus_name,
        "Source": "test.source",
        "DetailType": "test.detail.type",
        "Detail": json.dumps({"message": "Hello from EventBridge"}),
    }
    put_events_response = aws_client.events.put_events(Entries=[event_entry])
    assert put_events_response["FailedEntryCount"] == 0

    # Verify the Lambda invocation
    events = retry(
        check_expected_lambda_log_events_length,
        retries=10,
        sleep=10,
        sleep_before=10 if is_aws_cloud() else 1,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )

    # TODO how to assert X-Ray trace ID correct propagation from eventbridge to api gateway if no X-Ray trace id is present in the event

    lambda_trace_header = events[0]["headers"].get("X-Amzn-Trace-Id")
    assert lambda_trace_header is not None
    lambda_trace_id = re.search(r"Root=([^;]+)", lambda_trace_header).group(1)
    assert lambda_trace_id == trace_id


@markers.aws.validated
@pytest.mark.skipif(
    condition=is_old_provider(),
    reason="not supported by the old provider",
)
def test_xray_trace_propagation_events_lambda(
    create_lambda_function,
    events_create_event_bus,
    events_put_rule,
    cleanups,
    aws_client,
):
    function_name = f"lambda-func-{short_uid()}"
    create_lambda_response = create_lambda_function(
        handler_file=TEST_LAMBDA_XRAY_TRACEID,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )
    lambda_function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

    bus_name = f"bus-{short_uid()}"
    events_create_event_bus(Name=bus_name)

    rule_name = f"rule-{short_uid()}"
    rule_arn = events_put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )["RuleArn"]

    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"{rule_name}-Event",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    target_id = f"target-{short_uid()}"
    aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": lambda_function_arn}],
    )

    # Enable X-Ray tracing for the aws_client
    trace_id = "1-67f4141f-e1cd7672871da115129f8b19"
    parent_id = "d0ee9531727135a0"
    xray_trace_header = TraceHeader(root=trace_id, parent=parent_id, sampled=1)

    def add_xray_header(request, **kwargs):
        request.headers["X-Amzn-Trace-Id"] = xray_trace_header.to_header_str()

    event_name = "before-send.events.*"
    aws_client.events.meta.events.register(event_name, add_xray_header)
    # make sure the hook gets cleaned up after the test
    cleanups.append(lambda: aws_client.events.meta.events.unregister(event_name, add_xray_header))

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(TEST_EVENT_DETAIL),
            }
        ]
    )

    # Verify the Lambda invocation
    events = retry(
        check_expected_lambda_log_events_length,
        retries=10,
        sleep=10,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )

    # TODO how to assert X-Ray trace ID correct propagation from eventbridge to api lambda if no X-Ray trace id is present in the event

    lambda_trace_header = events[0]["trace_id_inside_handler"]
    assert lambda_trace_header is not None
    lambda_trace_id = re.search(r"Root=([^;]+)", lambda_trace_header).group(1)
    assert lambda_trace_id == trace_id


@markers.aws.validated
@pytest.mark.parametrize(
    "bus_combination", [("default", "custom"), ("custom", "custom"), ("custom", "default")]
)
@pytest.mark.skipif(
    condition=is_old_provider(),
    reason="not supported by the old provider",
)
def test_xray_trace_propagation_events_events(
    bus_combination,
    create_lambda_function,
    events_create_event_bus,
    create_role_event_bus_source_to_bus_target,
    region_name,
    account_id,
    events_put_rule,
    cleanups,
    aws_client,
):
    """
    Event Bridge Bus Source to Event Bridge Bus Target to Lambda for asserting X-Ray trace propagation
    """
    # Create event buses
    bus_source, bus_target = bus_combination
    if bus_source == "default":
        bus_name_source = "default"
    if bus_source == "custom":
        bus_name_source = f"test-event-bus-source-{short_uid()}"
        events_create_event_bus(Name=bus_name_source)
    if bus_target == "default":
        bus_name_target = "default"
        bus_arn_target = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
    if bus_target == "custom":
        bus_name_target = f"test-event-bus-target-{short_uid()}"
        bus_arn_target = events_create_event_bus(Name=bus_name_target)["EventBusArn"]

    # Create permission for event bus source to send events to event bus target
    role_arn_bus_source_to_bus_target = create_role_event_bus_source_to_bus_target()

    if is_aws_cloud():
        time.sleep(10)  # required for role propagation

    # Permission for event bus target to receive events from event bus source
    aws_client.events.put_permission(
        StatementId=f"TargetEventBusAccessPermission{short_uid()}",
        EventBusName=bus_name_target,
        Action="events:PutEvents",
        Principal="*",
    )

    # Create rule source event bus to target
    rule_name_source_to_target = f"test-rule-source-to-target-{short_uid()}"
    events_put_rule(
        Name=rule_name_source_to_target,
        EventBusName=bus_name_source,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )

    # Add target event bus as target
    target_id_event_bus_target = f"test-target-source-events-{short_uid()}"
    aws_client.events.put_targets(
        Rule=rule_name_source_to_target,
        EventBusName=bus_name_source,
        Targets=[
            {
                "Id": target_id_event_bus_target,
                "Arn": bus_arn_target,
                "RoleArn": role_arn_bus_source_to_bus_target,
            }
        ],
    )

    # Create Lambda function
    function_name = f"lambda-func-{short_uid()}"
    create_lambda_response = create_lambda_function(
        handler_file=TEST_LAMBDA_XRAY_TRACEID,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )
    lambda_function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

    # Connect Event Bus Target to Lambda
    rule_name_lambda = f"rule-{short_uid()}"
    rule_arn_lambda = events_put_rule(
        Name=rule_name_lambda,
        EventBusName=bus_name_target,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )["RuleArn"]

    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"{rule_name_lambda}-Event",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn_lambda,
    )

    target_id_lambda = f"target-{short_uid()}"
    aws_client.events.put_targets(
        Rule=rule_name_lambda,
        EventBusName=bus_name_target,
        Targets=[{"Id": target_id_lambda, "Arn": lambda_function_arn}],
    )

    ######
    # Test
    ######

    # Enable X-Ray tracing for the aws_client
    trace_id = "1-67f4141f-e1cd7672871da115129f8b19"
    parent_id = "d0ee9531727135a0"
    xray_trace_header = TraceHeader(root=trace_id, parent=parent_id, sampled=1)

    def add_xray_header(request, **kwargs):
        request.headers["X-Amzn-Trace-Id"] = xray_trace_header.to_header_str()

    event_name = "before-send.events.*"
    aws_client.events.meta.events.register(event_name, add_xray_header)
    # make sure the hook gets cleaned up after the test
    cleanups.append(lambda: aws_client.events.meta.events.unregister(event_name, add_xray_header))

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name_source,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(TEST_EVENT_DETAIL),
            }
        ]
    )

    # Verify the Lambda invocation
    events = retry(
        check_expected_lambda_log_events_length,
        retries=10,
        sleep=10,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )

    # TODO how to assert X-Ray trace ID correct propagation from eventbridge to eventbridge lambda if no X-Ray trace id is present in the event

    lambda_trace_header = events[0]["trace_id_inside_handler"]
    assert lambda_trace_header is not None
    lambda_trace_id = re.search(r"Root=([^;]+)", lambda_trace_header).group(1)
    assert lambda_trace_id == trace_id
