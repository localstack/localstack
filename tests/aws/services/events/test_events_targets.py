"""Tests for integrations between AWS EventBridge and other AWS services."""

import json
import time

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from tests.aws.scenario.kinesis_firehose.conftest import get_all_expected_messages_from_s3
from tests.aws.services.events.helper_functions import (
    assert_valid_event,
    is_v2_provider,
    sqs_collect_messages,
)
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN
from tests.aws.services.firehose.helper_functions import get_firehose_iam_documents
from tests.aws.services.kinesis.helper_functions import get_shard_iterator
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO

# class TestEventTargetApiGateway:
#     # TODO add test once API Gateway is supported

# class TestEventTargetAppSync:
#     # TODO add test once AppSync is supported

# class TestEventTargetBatch:
#     # TODO add test once Batch is supported

# class TestEventTargetContainer:
#     # TODO add test once Container is supported


class TestEventTargetEvents:
    # cross region and cross account event bus to event buss tests are in test_events_cross_account_region.py

    @markers.aws.validated
    @pytest.mark.parametrize(
        "bus_combination", [("default", "custom"), ("custom", "custom"), ("custom", "default")]
    )
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


class TestEventTargetFirehose:
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


class TestEventTargetKinesis:
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


class TestEventTargetLambda:
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
            runtime=Runtime.python3_9,
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

        bus_name = f"bus-{short_uid()}"
        events_create_event_bus(Name=bus_name)

        rule_name = f"rule-{short_uid()}"
        bus_name = f"bus-{short_uid()}"
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


# class TestEventsTargetLogs:
#     # TODO add test once Logs is supported

# class TestEventTargetRedshift:
#     # TODO add test once Redshift is supported


# class TestEventTargetSagemaker:
#     # TODO add test once Sagemaker is supported


class TestEventTargetSns:
    @markers.aws.needs_fixing
    @pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
    def test_put_events_with_target_sns(
        self,
        monkeypatch,
        sns_subscription,
        aws_client,
        clean_up,
        strategy,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_name = "test-%s" % short_uid()
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        topic_name = "topic-{}".format(short_uid())
        topic_arn = aws_client.sns.create_topic(Name=topic_name)["TopicArn"]

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        aws_client.events.create_event_bus(Name=bus_name)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": topic_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

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

        messages = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"]).get("Message")
        assert_valid_event(actual_event)
        assert json.loads(actual_event).get("detail") == EVENT_DETAIL

        # clean up
        aws_client.sns.delete_topic(TopicArn=topic_arn)
        clean_up(
            bus_name=bus_name,
            rule_name=rule_name,
            target_ids=target_id,
            queue_url=queue_url,
        )


class TestEventTargetSqs:
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

    @markers.aws.unknown
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_events_with_target_sqs_new_region(self, aws_client_factory):
        events_client = aws_client_factory(region_name="eu-west-1").events
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_client_factory(region_name="eu-west-1").sqs
        sqs_client.create_queue(QueueName=queue_name)
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        events_client.create_event_bus(Name=bus_name)

        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        response = events_client.put_events(
            Entries=[
                {
                    "Source": "com.mycompany.myapp",
                    "Detail": '{ "key1": "value1", "key": "value2" }',
                    "Resources": [],
                    "DetailType": "myDetailType",
                }
            ]
        )
        assert "Entries" in response
        assert len(response.get("Entries")) == 1
        assert "EventId" in response.get("Entries")[0]

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


class TestEventTargetStepFunctions:
    @markers.aws.validated
    def test_put_events_target_state_machine(self, aws_client):
        # TODO add test
        pass


class TestEventTargetSystemsManager:
    @markers.aws.needs_fixing  # TODO: Reason add permission and correct policies
    @pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
    def test_trigger_event_on_systems_manager_change(
        self, monkeypatch, aws_client, clean_up, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())

        # create queue
        queue_name = "queue-{}".format(short_uid())
        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        # put rule listening on SSM changes
        ssm_prefix = "/test/local/"
        aws_client.events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(
                {
                    "detail": {
                        "name": [{"prefix": ssm_prefix}],
                        "operation": [
                            "Create",
                            "Update",
                            "Delete",
                            "LabelParameterVersion",
                        ],
                    },
                    "detail-type": ["Parameter Store Change"],
                    "source": ["aws.ssm"],
                }
            ),
            State="ENABLED",
            Description="Trigger on SSM parameter changes",
        )

        # put target
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        param_suffix = short_uid()

        # change SSM param to trigger event
        aws_client.ssm.put_parameter(
            Name=f"{ssm_prefix}/test-{param_suffix}", Value="value1", Type="String"
        )

        def assert_message():
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            result = resp.get("Messages")
            body = json.loads(result[0]["Body"])
            assert body == {
                "name": f"/test/local/test-{param_suffix}",
                "operation": "Create",
            }

        # assert that message has been received
        retry(assert_message, retries=7, sleep=0.3)

        # clean up
        clean_up(rule_name=rule_name, target_ids=target_id)
