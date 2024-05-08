"""Tests for input path and input transformer in AWS EventBridge."""

import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.conftest import sqs_collect_messages
from tests.aws.services.events.helper_functions import is_v2_provider
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN

EVENT_DETAIL_DUPLICATED_KEY = {
    "command": "update-account",
    "payload": {"acc_id": "0a787ecb-4015", "payload": {"message": "baz", "id": "123"}},
}


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
    @pytest.mark.parametrize("event_detail", [EVENT_DETAIL, EVENT_DETAIL_DUPLICATED_KEY])
    def test_put_events_with_input_path_nested(
        self, event_detail, put_events_with_filter_to_sqs, snapshot
    ):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(event_detail),
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

    @markers.aws.validated
    def test_put_events_with_input_path_max_level_depth(
        self, put_events_with_filter_to_sqs, snapshot
    ):
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
            input_path="$.detail.payload.sf_id",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("message", messages)

    @markers.aws.validated
    def test_put_events_with_input_path_multiple_targets(
        self,
        aws_client,
        create_sqs_events_target,
        events_create_event_bus,
        events_put_rule,
        snapshot,
    ):
        # prepare target queues
        queue_url_1, queue_arn_1 = create_sqs_events_target()
        queue_url_2, queue_arn_2 = create_sqs_events_target()

        bus_name = f"test-bus-{short_uid()}"
        events_create_event_bus(Name=bus_name)

        rule_name = f"test-rule-{short_uid()}"
        events_put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        target_id_1 = f"target-{short_uid()}"
        target_id_2 = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": target_id_1, "Arn": queue_arn_1, "InputPath": "$.detail"},
                {"Id": target_id_2, "Arn": queue_arn_2},
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

        messages_queue_1 = sqs_collect_messages(aws_client, queue_url_1, min_events=1, retries=3)
        messages_queue_2 = sqs_collect_messages(aws_client, queue_url_2, min_events=1, retries=3)

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("message-queue-1", messages_queue_1)
        snapshot.match("message-queue-2", messages_queue_2)


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
