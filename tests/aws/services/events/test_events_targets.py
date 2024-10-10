"""Tests for integrations between AWS EventBridge and other AWS services.
Tests are separated in different classes for each target service.
Classes are ordered alphabetically."""

import json
import time

import aws_cdk as cdk
import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from tests.aws.scenario.kinesis_firehose.conftest import get_all_expected_messages_from_s3
from tests.aws.services.events.helper_functions import is_old_provider, sqs_collect_messages
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN
from tests.aws.services.firehose.helper_functions import get_firehose_iam_documents
from tests.aws.services.kinesis.helper_functions import get_shard_iterator
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_AWS_PROXY_FORMAT,
    TEST_LAMBDA_PYTHON_ECHO,
)


# TODO:
#  Add tests for the following services:
#   - API Gateway (community)
#   - CloudWatch Logs (community)
#  These tests should go into LocalStack Pro:
#   - AppSync (pro)
#   - Batch (pro)
#   - Container (pro)
#   - Redshift (pro)
#   - Sagemaker (pro)
class TestEventsTargetApiGateway:
    @markers.aws.validated
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
    def test_put_events_with_target_api_gateway(
        self,
        create_lambda_function,
        create_rest_apigw,
        events_create_event_bus,
        events_put_rule,
        aws_client,
        snapshot,
        create_role_with_policy,
        region_name,
        account_id,
    ):
        snapshot.add_transformers_list(
            [
                *snapshot.transform.lambda_api(),
                *snapshot.transform.apigateway_api(),
                *snapshot.transform.apigateway_proxy_event(),
                snapshot.transform.key_value("CodeSha256"),
                snapshot.transform.key_value("EventId", reference_replacement=False),
                snapshot.transform.key_value(
                    "multiValueHeaders",
                    value_replacement="<multiValueHeaders>",
                    reference_replacement=False,
                ),
                snapshot.transform.key_value("apiId"),
                snapshot.transform.key_value("amz-sdk-request"),
                snapshot.transform.key_value("amz-sdk-retry"),
                snapshot.transform.key_value("X-Amz-Date"),
                snapshot.transform.key_value("x-amz-date"),
                # Events use the Java SDK to forward the event, and the User-Agent reflects that
                snapshot.transform.key_value("User-Agent"),
                snapshot.transform.key_value("X-Forwarded-For", reference_replacement=False),
                snapshot.transform.key_value("X-Forwarded-Port", reference_replacement=False),
                snapshot.transform.key_value("X-Forwarded-Proto", reference_replacement=False),
            ]
        )
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("X-Amz-Security-Token", reference_replacement=False),
                snapshot.transform.key_value("domainName"),
                snapshot.transform.key_value("amz-sdk-invocation-id", reference_replacement=False),
                snapshot.transform.key_value("CloudFront-Viewer-ASN", reference_replacement=False),
                snapshot.transform.key_value(
                    "CloudFront-Viewer-Country", reference_replacement=False
                ),
            ],
            priority=-2,
        )

        # Step a: Create a Lambda function with a unique name using the existing fixture
        function_name = f"test-lambda-{short_uid()}"

        # Create the Lambda function with the correct handler
        create_lambda_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_AWS_PROXY_FORMAT,
            handler="lambda_aws_proxy_format.handler",
            runtime=Runtime.python3_12,
        )
        lambda_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]
        snapshot.match("create_lambda_response", create_lambda_response)

        # Step b: Set up an API Gateway
        api_id, _, root_id = create_rest_apigw(
            name=f"test-api-${short_uid()}",
            description="Test Integration with EventBridge",
        )

        # Create a resource under the root
        resource_response = aws_client.apigateway.create_resource(
            restApiId=api_id,
            parentId=root_id,
            pathPart="test",
        )
        resource_id = resource_response["id"]

        # Set up POST method
        aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="NONE",
        )

        # Define source_arn
        source_arn = f"arn:aws:execute-api:{region_name}:{account_id}:{api_id}/*/POST/test"

        # Integrate the method with the Lambda function
        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            type="AWS_PROXY",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        )

        # Give permission to API Gateway to invoke Lambda
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=f"sid-{short_uid()}",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )

        # Deploy the API to a 'test' stage
        stage_name = "test"
        deployment = aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
        )
        snapshot.match("deployment_response", deployment)

        # Step c: Create a new event bus
        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_response = events_create_event_bus(Name=event_bus_name)
        snapshot.match("event_bus_response", event_bus_response)

        # Step d: Create a rule on this bus
        rule_name = f"test-rule-{short_uid()}"
        event_pattern = {"source": ["test.source"], "detail-type": ["test.detail.type"]}
        rule_response = events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(event_pattern),
        )
        snapshot.match("rule_response", rule_response)

        # Step e: Create an IAM Role for EventBridge to invoke API Gateway
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

        # Step f: Add the API Gateway as a target with the RoleArn
        target_id = f"target-{short_uid()}"
        api_target_arn = (
            f"arn:aws:execute-api:{region_name}:{account_id}:{api_id}/{stage_name}/POST/test"
        )

        # TODO: test path parameters, headers and query strings
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
        snapshot.match("put_targets_response", put_targets_response)
        assert put_targets_response["FailedEntryCount"] == 0

        # Step g: Send an event to EventBridge
        event_entry = {
            "EventBusName": event_bus_name,
            "Source": "test.source",
            "DetailType": "test.detail.type",
            "Detail": json.dumps({"message": "Hello from EventBridge"}),
        }
        put_events_response = aws_client.events.put_events(Entries=[event_entry])
        snapshot.match("put_events_response", put_events_response)
        assert put_events_response["FailedEntryCount"] == 0

        # Step h: Verify the Lambda invocation
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


class TestEventsTargetEvents:
    # cross region and cross account event bus to event buss tests are in test_events_cross_account_region.py

    @markers.aws.validated
    @pytest.mark.parametrize(
        "bus_combination", [("default", "custom"), ("custom", "custom"), ("custom", "default")]
    )
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_put_events_with_target_events(
        self,
        bus_combination,
        events_create_event_bus,
        region_name,
        account_id,
        events_put_rule,
        create_role_event_bus_source_to_bus_target,
        create_sqs_events_target,
        aws_client,
        snapshot,
    ):
        # Create event buses
        bus_source, bus_target = bus_combination
        if bus_source == "default":
            event_bus_name_source = "default"
        if bus_source == "custom":
            event_bus_name_source = f"test-event-bus-source-{short_uid()}"
            events_create_event_bus(Name=event_bus_name_source)
        if bus_target == "default":
            event_bus_name_target = "default"
            event_bus_arn_target = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if bus_target == "custom":
            event_bus_name_target = f"test-event-bus-target-{short_uid()}"
            event_bus_arn_target = events_create_event_bus(Name=event_bus_name_target)[
                "EventBusArn"
            ]

        # Create permission for event bus source to send events to event bus target
        role_arn_bus_source_to_bus_target = create_role_event_bus_source_to_bus_target()

        if is_aws_cloud():
            time.sleep(10)  # required for role propagation

        # Permission for event bus target to receive events from event bus source
        aws_client.events.put_permission(
            StatementId=f"TargetEventBusAccessPermission{short_uid()}",
            EventBusName=event_bus_name_target,
            Action="events:PutEvents",
            Principal="*",
        )

        # Create rule source event bus to target
        rule_name_source_to_target = f"test-rule-source-to-target-{short_uid()}"
        events_put_rule(
            Name=rule_name_source_to_target,
            EventBusName=event_bus_name_source,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        # Add target event bus as target
        target_id_event_bus_target = f"test-target-source-events-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name_source_to_target,
            EventBusName=event_bus_name_source,
            Targets=[
                {
                    "Id": target_id_event_bus_target,
                    "Arn": event_bus_arn_target,
                    "RoleArn": role_arn_bus_source_to_bus_target,
                }
            ],
        )

        # Setup sqs target for target event bus
        rule_name_target_to_sqs = f"test-rule-target-{short_uid()}"
        events_put_rule(
            Name=rule_name_target_to_sqs,
            EventBusName=event_bus_name_target,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        queue_url, queue_arn = create_sqs_events_target()
        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name_target_to_sqs,
            EventBusName=event_bus_arn_target,
            Targets=[
                {"Id": target_id, "Arn": queue_arn},
            ],
        )

        ######
        # Test
        ######

        # Put events into primary event bus
        aws_client.events.put_events(
            Entries=[
                {
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                    "EventBusName": event_bus_name_source,
                }
            ],
        )

        # Collect messages from primary queue
        messages = sqs_collect_messages(
            aws_client, queue_url, expected_events_count=1, wait_time=1, retries=5
        )
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
            ],
        )
        snapshot.match("messages", messages)


class TestEventsTargetFirehose:
    @markers.aws.validated
    def test_put_events_with_target_firehose(
        self,
        aws_client,
        create_iam_role_with_policy,
        s3_bucket,
        firehose_create_delivery_stream,
        events_create_event_bus,
        events_put_rule,
        s3_empty_bucket,
        snapshot,
    ):
        # create firehose target bucket
        bucket_arn = arns.s3_bucket_arn(s3_bucket)

        # Create access policy for firehose
        role_policy, policy_document = get_firehose_iam_documents(bucket_arn, "*")

        firehose_delivery_stream_to_s3_role_arn = create_iam_role_with_policy(
            RoleDefinition=role_policy, PolicyDefinition=policy_document
        )

        if is_aws_cloud():
            time.sleep(10)  # AWS IAM propagation delay

        # create firehose delivery stream to s3
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        s3_prefix = "testeventdata"

        delivery_stream_arn = firehose_create_delivery_stream(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "BucketARN": bucket_arn,
                "RoleARN": firehose_delivery_stream_to_s3_role_arn,
                "Prefix": s3_prefix,
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 1},
            },
        )["DeliveryStreamARN"]

        # Create event bus, rule and target
        event_bus_name = f"test-bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)

        rule_name = f"rule-{short_uid()}"
        events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        # Create IAM role event bridge bus to firehose delivery stream
        assume_role_policy_document_bus_to_firehose = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        policy_document_bus_to_firehose = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": delivery_stream_arn,
                }
            ],
        }

        event_bridge_bus_to_firehose_role_arn = create_iam_role_with_policy(
            RoleDefinition=assume_role_policy_document_bus_to_firehose,
            PolicyDefinition=policy_document_bus_to_firehose,
        )

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": delivery_stream_arn,
                    "RoleArn": event_bridge_bus_to_firehose_role_arn,
                }
            ],
        )

        if is_aws_cloud():
            time.sleep(
                30
            )  # not clear yet why but firehose needs time to receive events event though status is ACTIVE

        for _ in range(10):
            aws_client.events.put_events(
                Entries=[
                    {
                        "EventBusName": event_bus_name,
                        "Source": TEST_EVENT_PATTERN["source"][0],
                        "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                        "Detail": json.dumps(EVENT_DETAIL),
                    }
                ]
            )

        ######
        # Test
        ######

        if is_aws_cloud():
            sleep = 10
            retries = 30
        else:
            sleep = 1
            retries = 5

        bucket_data = get_all_expected_messages_from_s3(
            aws_client,
            s3_bucket,
            expected_message_count=10,
            sleep=sleep,
            retries=retries,
        )
        snapshot.match("s3", bucket_data)

        # empty and delete bucket
        s3_empty_bucket(s3_bucket)
        aws_client.s3.delete_bucket(Bucket=s3_bucket)


class TestEventsTargetKinesis:
    @markers.aws.validated
    def test_put_events_with_target_kinesis(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        create_iam_role_with_policy,
        aws_client,
        events_create_event_bus,
        events_put_rule,
        snapshot,
    ):
        # Create a Kinesis stream
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        # Create IAM role event bridge bus to kinesis stream
        assume_role_policy_document_bus_to_kinesis = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        policy_document_bus_to_kinesis = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                    "Resource": stream_arn,
                }
            ],
        }
        event_bridge_bus_to_kinesis_role_arn = create_iam_role_with_policy(
            RoleDefinition=assume_role_policy_document_bus_to_kinesis,
            PolicyDefinition=policy_document_bus_to_kinesis,
        )

        # Create an event bus
        event_bus_name = f"bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)

        rule_name = f"rule-{short_uid()}"
        events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": stream_arn,
                    "RoleArn": event_bridge_bus_to_kinesis_role_arn,
                    "KinesisParameters": {"PartitionKeyPath": "$.detail-type"},
                }
            ],
        )

        if is_aws_cloud():
            time.sleep(
                30
            )  # cold start of connection event bus to kinesis takes some time until messages can be sent

        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": event_bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        shard_iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        response = aws_client.kinesis.get_records(ShardIterator=shard_iterator)

        assert len(response["Records"]) == 1

        data = response["Records"][0]["Data"].decode("utf-8")

        snapshot.match("response", data)


class TestEventsTargetLambda:
    @markers.aws.validated
    def test_put_events_with_target_lambda(
        self,
        create_lambda_function,
        events_create_event_bus,
        events_put_rule,
        aws_client,
        snapshot,
    ):
        function_name = f"lambda-func-{short_uid()}"
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
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

        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        # Get lambda's log events
        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            logs_client=aws_client.logs,
        )

        snapshot.match("events", events)

    @markers.aws.validated
    def test_put_events_with_target_lambda_list_entry(
        self, create_lambda_function, events_create_event_bus, events_put_rule, aws_client, snapshot
    ):
        function_name = f"lambda-func-{short_uid()}"
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        lambda_function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

        event_pattern = {"detail": {"payload": {"automations": {"id": [{"exists": True}]}}}}

        bus_name = f"bus-{short_uid()}"
        events_create_event_bus(Name=bus_name)

        rule_name = f"rule-{short_uid()}"
        rule_arn = events_put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(event_pattern),
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

        event_detail = {
            "payload": {
                "userId": 10,
                "businessId": 3,
                "channelId": 6,
                "card": {"foo": "bar"},
                "targetEntity": True,
                "entityAuditTrailEvent": {"foo": "bar"},
                "automations": [
                    {
                        "id": "123",
                        "actions": [
                            {
                                "id": "321",
                                "type": "SEND_NOTIFICATION",
                                "settings": {
                                    "message": "",
                                    "recipientEmails": [],
                                    "subject": "",
                                    "type": "SEND_NOTIFICATION",
                                },
                            }
                        ],
                    }
                ],
            }
        }
        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(event_detail),
                }
            ]
        )

        # Get lambda's log events
        events = retry(
            check_expected_lambda_log_events_length,
            retries=15,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            logs_client=aws_client.logs,
        )
        snapshot.match("events", events)

    @markers.aws.validated
    def test_put_events_with_target_lambda_list_entries_partial_match(
        self,
        create_lambda_function,
        events_create_event_bus,
        events_put_rule,
        aws_client,
        snapshot,
    ):
        function_name = f"lambda-func-{short_uid()}"
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )
        lambda_function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

        event_pattern = {"detail": {"payload": {"automations": {"id": [{"exists": True}]}}}}

        bus_name = f"test-bus-{short_uid()}"
        events_create_event_bus(Name=bus_name)

        rule_name = f"rule-{short_uid()}"
        rule_arn = events_put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(event_pattern),
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

        event_detail_partial_match = {
            "payload": {
                "userId": 10,
                "businessId": 3,
                "channelId": 6,
                "card": {"foo": "bar"},
                "targetEntity": True,
                "entityAuditTrailEvent": {"foo": "bar"},
                "automations": [
                    {"foo": "bar"},
                    {
                        "id": "123",
                        "actions": [
                            {
                                "id": "321",
                                "type": "SEND_NOTIFICATION",
                                "settings": {
                                    "message": "",
                                    "recipientEmails": [],
                                    "subject": "",
                                    "type": "SEND_NOTIFICATION",
                                },
                            }
                        ],
                    },
                    {"bar": "foo"},
                ],
            }
        }
        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(event_detail_partial_match),
                },
            ]
        )

        # Get lambda's log events
        events = retry(
            check_expected_lambda_log_events_length,
            retries=15,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            logs_client=aws_client.logs,
        )
        snapshot.match("events", events)


class TestEventsTargetSns:
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    @pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
    def test_put_events_with_target_sns(
        self,
        monkeypatch,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_create_topic,
        sns_subscription,
        events_create_event_bus,
        events_put_rule,
        aws_client,
        snapshot,
        strategy,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        # Create sqs queue and give sns permission to send messages
        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)
        policy = {
            "Version": "2012-10-17",
            "Id": f"sqs-sns-{short_uid()}",
            "Statement": [
                {
                    "Sid": f"SendMessage-{short_uid()}",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                }
            ],
        }
        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
        )

        # Create sns topic and subscribe it to sqs queue
        topic_name = f"test-topic-{short_uid()}"
        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        # Enable event bridge to push to sns
        policy = {
            "Version": "2012-10-17",
            "Id": f"sns-eventbridge-{short_uid()}",
            "Statement": [
                {
                    "Sid": f"SendMessage-{short_uid()}",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sns:Publish",
                    "Resource": topic_arn,
                }
            ],
        }
        aws_client.sns.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
        )

        # Create event bus, rule and target
        event_bus_name = f"test-bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)

        rule_name = f"test-rule-{short_uid()}"
        events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[{"Id": target_id, "Arn": topic_arn}],
        )

        # Test
        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": event_bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        messages = sqs_collect_messages(aws_client, queue_url, expected_events_count=1)

        body = json.loads(messages[0]["Body"])
        message_id = json.loads(body["Message"])["id"]
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
                snapshot.transform.key_value("Signature", reference_replacement=False),
                snapshot.transform.key_value("SigningCertURL", reference_replacement=False),
                snapshot.transform.key_value("UnsubscribeURL", reference_replacement=False),
                snapshot.transform.regex(topic_arn, "topic-arn"),
                snapshot.transform.regex(message_id, "message-id"),
            ]
        )
        snapshot.match("messages", messages)


class TestEventsTargetSqs:
    @markers.aws.validated
    def test_put_events_with_target_sqs(self, put_events_with_filter_to_sqs, snapshot):
        entries = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
        message = put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN,
            entries_asserts=[(entries, True)],
        )
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
            ],
        )
        snapshot.match("message", message)

    @markers.aws.validated
    def test_put_events_with_target_sqs_event_detail_match(
        self, put_events_with_filter_to_sqs, snapshot
    ):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps({"EventType": "1"}),
            }
        ]
        entries2 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps({"EventType": "2"}),
            }
        ]
        entries_asserts = [(entries1, True), (entries2, False)]
        messages = put_events_with_filter_to_sqs(
            pattern={"detail": {"EventType": ["0", "1"]}},
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
            ],
        )
        snapshot.match("messages", messages)


class TestEventsTargetStepFunctions:
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_put_events_with_target_statefunction_machine(self, infrastructure_setup, aws_client):
        infra = infrastructure_setup(namespace="EventsTests")
        stack_name = "stack-events-target-stepfunctions"
        stack = cdk.Stack(infra.cdk_app, stack_name=stack_name)

        bus_name = "MyEventBus"
        bus = cdk.aws_events.EventBus(stack, "MyEventBus", event_bus_name=bus_name)

        queue = cdk.aws_sqs.Queue(stack, "MyQueue", queue_name="MyQueue")

        send_to_sqs_task = cdk.aws_stepfunctions_tasks.SqsSendMessage(
            stack,
            "SendToQueue",
            queue=queue,
            message_body=cdk.aws_stepfunctions.TaskInput.from_object(
                {"message": cdk.aws_stepfunctions.JsonPath.entire_payload}
            ),
        )

        state_machine = cdk.aws_stepfunctions.StateMachine(
            stack,
            "MyStateMachine",
            definition=send_to_sqs_task,
            state_machine_name="MyStateMachine",
        )

        detail_type = "myDetailType"
        rule = cdk.aws_events.Rule(
            stack,
            "MyRule",
            event_bus=bus,
            event_pattern=cdk.aws_events.EventPattern(detail_type=[detail_type]),
        )

        rule.add_target(cdk.aws_events_targets.SfnStateMachine(state_machine))

        cdk.CfnOutput(stack, "MachineArn", value=state_machine.state_machine_arn)
        cdk.CfnOutput(stack, "QueueUrl", value=queue.queue_url)

        with infra.provisioner() as prov:
            outputs = prov.get_stack_outputs(stack_name=stack_name)

            entries = [
                {
                    "Source": "com.sample.resource",
                    "DetailType": detail_type,
                    "Detail": json.dumps({"Key1": "Value"}),
                    "EventBusName": bus_name,
                }
                for i in range(5)
            ]
            put_events = aws_client.events.put_events(Entries=entries)

            state_machine_arn = outputs["MachineArn"]

            def _assert_executions():
                executions = (
                    aws_client.stepfunctions.get_paginator("list_executions")
                    .paginate(stateMachineArn=state_machine_arn)
                    .build_full_result()
                )
                assert len(executions["executions"]) > 0

                matched_executions = [
                    e
                    for e in executions["executions"]
                    if e["name"].startswith(put_events["Entries"][0]["EventId"])
                ]
                assert len(matched_executions) > 0

            retry_config = {
                "retries": (20 if is_aws_cloud() else 5),
                "sleep": (2 if is_aws_cloud() else 1),
                "sleep_before": (2 if is_aws_cloud() else 0),
            }
            retry(_assert_executions, **retry_config)

            messages = []
            queue_url = outputs["QueueUrl"]

            def _assert_messages():
                queue_msgs = aws_client.sqs.receive_message(QueueUrl=queue_url)
                for msg in queue_msgs.get("Messages", []):
                    messages.append(msg)

                assert len(messages) > 0

            retry(_assert_messages, **retry_config)
