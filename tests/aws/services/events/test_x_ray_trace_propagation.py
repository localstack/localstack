import json

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length

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
from aws_xray_sdk.core import patch, xray_recorder

from localstack.testing.aws.util import is_aws_cloud
from tests.aws.services.events.helper_functions import is_old_provider
from tests.aws.services.events.test_events import TEST_EVENT_DETAIL, TEST_EVENT_PATTERN
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO, TEST_LAMBDA_XRAY_TRACEID

# currently only API Gateway v2 and Lambda support X-Ray tracing


@markers.aws.unknown
@pytest.mark.skipif(
    condition=is_old_provider() and not is_aws_cloud(),
    reason="not supported by the old provider",
)
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: those headers are sent by Events via the SDK, we should at least populate X-Amz-Source-Account
        #  and X-Amz-Source-Arn
        "$..headers.amz-sdk-invocation-id",
        "$..headers.amz-sdk-request",
        "$..headers.amz-sdk-retry",
        "$..headers.X-Amz-Security-Token",
        "$..headers.X-Amz-Source-Account",
        "$..headers.X-Amz-Source-Arn",
        # seems like this one can vary in casing between runs?
        "$..headers.x-amz-date",
        "$..headers.X-Amz-Date",
        # those headers are missing in API Gateway
        "$..headers.CloudFront-Forwarded-Proto",
        "$..headers.CloudFront-Is-Desktop-Viewer",
        "$..headers.CloudFront-Is-Mobile-Viewer",
        "$..headers.CloudFront-Is-SmartTV-Viewer",
        "$..headers.CloudFront-Is-Tablet-Viewer",
        "$..headers.CloudFront-Viewer-ASN",
        "$..headers.CloudFront-Viewer-Country",
        "$..headers.X-Amz-Cf-Id",
        "$..headers.Via",
        # sent by `requests` library by default
        "$..headers.Accept-Encoding",
        "$..headers.Accept",
        "$..headers.Host",
        "$..multiValueHeaders.Host",
        "$..requestContext.apiId",
        "$..requestContext.domainName",
        "$..requestContext.domainPrefix",
        "$..requestContext.requestTime",
        "$..requestContext.requestTimeEpoch",
        "$..requestContext.resourceId",
        "$..headers.x-localstack-edge",
        "$..headers.Connection",
        "$..headers.Content-Length",
        "$..headers.accept-encoding",
        "$..headers.accept",
        "$..headers.X-Forwarded-Port",
        "$..headers.X-Forwarded-Proto",
        "$..pathParameters",
        "$..requestContext.authorizer",
        "$..requestContext.deploymentId",
        "$..requestContext.extendedRequestId",
        "$..requestContext.identity",
        "$..requestContext.requestId",
        "$..stageVariables",
    ],
)
def test_xray_trace_propagation_events_api_gateway(
    aws_client,
    create_role_with_policy,
    create_lambda_function,
    create_rest_apigw,
    events_create_event_bus,
    events_put_rule,
    region_name,
    account_id,
    snapshot,
):
    # create lambda
    function_name = f"test-function-{short_uid()}"
    function_arn = create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )["CreateFunctionResponse"]["FunctionArn"]

    # create api gateway with lambda integration
    # create rest api
    api_id, api_name, root = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Integration test API",
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root, pathPart="{proxy+}"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
    )

    # create role with policy
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    # Lambda AWS_PROXY integration
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{function_arn}/invocations",
        credentials=role_arn,
    )

    stage_name = "test-api-stage-name"
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
    source_arn = f"arn:aws:execute-api:{region_name}:{account_id}:{api_id}/*/POST/test"
    role_name, role_arn = create_role_with_policy(
        effect="Allow",
        actions="execute-api:Invoke",
        assume_policy_doc=json.dumps(assume_role_policy_document),
        resource=source_arn,
        attach=False,  # Since we're using put_role_policy, not attach_role_policy
    )

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
    events_client = aws_client.events

    # Enable X-Ray tracing for the aws_client
    segment = xray_recorder.begin_segment(name="put_events")
    trace_id = segment.trace_id
    libraries = ["botocore"]
    patch(libraries)

    event_entry = {
        "EventBusName": event_bus_name,
        "Source": "test.source",
        "DetailType": "test.detail.type",
        "Detail": json.dumps({"message": "Hello from EventBridge"}),
    }
    put_events_response = events_client.put_events(Entries=[event_entry])
    snapshot.match("put_events_response", put_events_response)
    assert put_events_response["FailedEntryCount"] == 0

    # Verify the Lambda invocation
    events = retry(
        check_expected_lambda_log_events_length,
        retries=10,
        sleep=10,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )

    # TODO how to assert X-Ray trace ID correct propagation from eventbridge to api gateway

    lambda_trace_header = events[0]["headers"].get("X-Amzn-Trace-Id")
    assert lambda_trace_header is not None
    lambda_trace_id = re.search(r"Root=([^;]+)", lambda_trace_header).group(1)
    assert lambda_trace_id == trace_id

    snapshot.add_transformer(
        snapshot.transform.regex(lambda_trace_id, "trace_id_root"),
    )

    snapshot.match("lambda_logs", events)


@markers.aws.unknown
@pytest.mark.skipif(
    condition=is_old_provider() and not is_aws_cloud(),
    reason="not supported by the old provider",
)
def test_xray_trace_propagation_events_lambda(
    create_lambda_function,
    events_create_event_bus,
    events_put_rule,
    aws_client,
    snapshot,
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
    segment = xray_recorder.begin_segment(name="put_events")
    trace_id = segment.trace_id
    libraries = ["botocore"]
    patch(libraries)

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

    # TODO how to assert X-Ray trace ID correct propagation from eventbridge to api gateway

    lambda_trace_header = events[0]["trace_id_inside_handler"]
    assert lambda_trace_header is not None
    lambda_trace_id = re.search(r"Root=([^;]+)", lambda_trace_header).group(1)
    assert lambda_trace_id == trace_id

    snapshot.add_transformer(
        snapshot.transform.regex(lambda_trace_id, "trace_id_root"),
    )

    snapshot.match("lambda_logs", events)
