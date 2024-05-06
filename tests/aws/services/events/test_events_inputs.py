"""Tests for input path and input transformer in AWS EventBridge."""

import json

import pytest

from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from tests.aws.services.events.conftest import sqs_collect_messages
from tests.aws.services.events.helper_functions import is_v2_provider
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN


class TestEventsInputPath:
    @markers.aws.validated
    def test_put_events_with_input_path(self, put_events_with_filter_to_sqs, snapshot):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
        entries_asserts = [(entries1, True)]
        messages = put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("message", messages)

    @markers.aws.validated
    def test_put_events_with_input_path_nested(self, put_events_with_filter_to_sqs, snapshot):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
        entries_asserts = [(entries1, True)]
        messages = put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN,
            entries_asserts=entries_asserts,
            input_path="$.detail.payload",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("message", messages)

    @markers.aws.unknown
    def test_put_events_with_input_path_multiple(self, aws_client, clean_up):
        queue_name = "queue-{}".format(short_uid())
        queue_name_1 = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        target_id_1 = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        queue_url_1 = aws_client.sqs.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = arns.sqs_queue_arn(queue_name_1, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        aws_client.events.create_event_bus(Name=bus_name)

        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
                {
                    "Id": target_id_1,
                    "Arn": queue_arn_1,
                },
            ],
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

        messages = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == EVENT_DETAIL

        messages = sqs_collect_messages(aws_client, queue_url_1, min_events=1, retries=3)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")).get("detail") == EVENT_DETAIL

        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": "dummySource",
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        messages = sqs_collect_messages(aws_client, queue_url, min_events=0, retries=1, wait_time=3)
        assert messages == []

        # clean up
        clean_up(
            bus_name=bus_name,
            rule_name=rule_name,
            target_ids=[target_id, target_id_1],
            queue_url=queue_url,
        )


class TestEventsInputTransformers:
    @markers.aws.validated
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_events_with_input_transformation_to_sqs(
        self, put_events_with_filter_to_sqs, snapshot
    ):
        pattern = {"detail-type": ["customerCreated"]}
        event_detail = {"command": "display-message", "payload": "baz"}
        entries = [
            {
                "Source": "com.mycompany.myapp",
                "DetailType": "customerCreated",
                "Detail": json.dumps(event_detail),
            }
        ]
        entries_asserts = [(entries, True)]

        # input transformer with all keys in template present in message
        input_path_map = {
            "detail-type": "$.detail-type",
            "timestamp": "$.time",
            "command": "$.detail.command",
        }
        input_template = '"Event of <detail-type> type, at time <timestamp>, info extracted from detail <command>"'
        input_transformer_match_all = {
            "InputPathsMap": input_path_map,
            "InputTemplate": input_template,
        }
        messages_match_all = put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_transformer=input_transformer_match_all,
        )

        # input transformer with keys in template missing from message
        input_path_map_missing_key = {
            "detail-type": "$.detail-type",
            "timestamp": "$.time",
            "command": "$.detail.notinmessage",
        }
        input_transformer_not_match_all = {
            "InputPathsMap": input_path_map_missing_key,
            "InputTemplate": input_template,
        }
        messages_not_match_all = put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_transformer=input_transformer_not_match_all,
        )

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("custom-variables-match-all", messages_match_all)
        snapshot.match("custom-variables-not-match-all", messages_not_match_all)
