import json

from localstack import config
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
import pytest

from localstack.testing.aws.util import is_aws_cloud
from tests.aws.services.events.helper_functions import is_old_provider
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
)


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
    ]
)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not config.APIGW_NEXT_GEN_PROVIDER,
    paths=[
        # parity issue from previous APIGW implementation
        "$..headers.x-localstack-edge",
        "$..headers.Connection",
        "$..headers.Content-Length",
        "$..headers.accept-encoding",
        "$..headers.accept",
        "$..headers.X-Amzn-Trace-Id",
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
    events_put_targets,
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
    event_entry = {
        "EventBusName": event_bus_name,
        "Source": "test.source",
        "DetailType": "test.detail.type",
        "Detail": json.dumps({"message": "Hello from EventBridge"}),
    }
    put_events_response = aws_client.events.put_events(Entries=[event_entry])
    snapshot.match("put_events_response", put_events_response)
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
    snapshot.match("lambda_logs", events)
    # TODO assert that the X-Ray trace ID is present in the logs
    # TODO how to assert X-Ray trace ID correct propagation


# def test_xray_trace_propagation_events_lambda():
