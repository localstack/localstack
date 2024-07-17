import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import json5
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from tests.aws.services.events.helper_functions import (
    sqs_collect_messages,
)

THIS_FOLDER: str = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_DIR = os.path.join(THIS_FOLDER, "event_pattern_templates")
COMPLEX_MULTI_KEY_EVENT_PATTERN = os.path.join(
    REQUEST_TEMPLATE_DIR, "complex_multi_key_event_pattern.json"
)
COMPLEX_MULTI_KEY_EVENT = os.path.join(REQUEST_TEMPLATE_DIR, "complex_multi_key_event.json")

SKIP_LABELS = [
    # Failing exception tests:
    "arrays_empty_EXC",
    "content_numeric_EXC",
    "content_numeric_operatorcasing_EXC",
    "content_numeric_syntax_EXC",
    "content_wildcard_complex_EXC",
    "int_nolist_EXC",
    "operator_case_sensitive_EXC",
    "string_nolist_EXC",
    # Failing tests:
    "complex_or",
    "content_anything_but_ignorecase",
    "content_anything_but_ignorecase_list",
    "content_anything_suffix",
    "content_exists_false",
    "content_ignorecase",
    "content_ignorecase_NEG",
    "content_ip_address",
    "content_numeric_and",
    "content_prefix_ignorecase",
    "content_suffix",
    "content_suffix_ignorecase",
    "content_wildcard_nonrepeating",
    "content_wildcard_repeating",
    "content_wildcard_simplified",
    "dot_joining_event",
    "dot_joining_pattern",
    "exists_dynamodb_NEG",
    "nested_json_NEG",
    "or-exists",
    "or-exists-parent",
]


def load_request_templates(directory_path: str) -> List[Tuple[dict, str]]:
    json5_files = list_files_with_suffix(directory_path, ".json5")
    return [load_request_template(file_path) for file_path in json5_files]


def load_request_template(file_path: str) -> Tuple[dict, str]:
    with open(file_path, "r") as df:
        template = json5.load(df)
    return template, Path(file_path).stem


def list_files_with_suffix(directory_path: str, suffix: str) -> List[str]:
    files = []
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename.endswith(suffix):
                absolute_filepath = os.path.join(root, filename)
                files.append(absolute_filepath)

    return files


request_template_tuples = load_request_templates(REQUEST_TEMPLATE_DIR)


class TestEventPattern:
    # TODO: extend these test cases based on the open source docs + tests: https://github.com/aws/event-ruler
    #  For example, "JSON Array Matching", "And and Or Relationship among fields with Ruler", rule validation,
    #  and exception handling.
    @pytest.mark.parametrize(
        "request_template,label",
        request_template_tuples,
        ids=[t[1] for t in request_template_tuples],
    )
    @markers.aws.validated
    def test_event_pattern(self, aws_client, snapshot, request_template, label):
        """This parametrized test handles three outcomes:
        a) MATCH (default): The EventPattern matches the Event yielding true as result.
        b) NO MATCH (_NEG suffix): The EventPattern does NOT match the Event yielding false as result.
        c) EXCEPTION (_EXC suffix): The EventPattern is invalid and raises an exception.
        """
        if label in SKIP_LABELS and not is_aws_cloud():
            pytest.skip("Not yet implemented")

        event = request_template["Event"]
        event_pattern = request_template["EventPattern"]

        if label.endswith("_EXC"):
            with pytest.raises(Exception) as e:
                aws_client.events.test_event_pattern(
                    Event=json.dumps(event),
                    EventPattern=json.dumps(event_pattern),
                )
            exception_info = {
                "exception_type": type(e.value),
                "exception_message": e.value.response,
            }
            snapshot.match(label, exception_info)
        else:
            response = aws_client.events.test_event_pattern(
                Event=json.dumps(event),
                EventPattern=json.dumps(event_pattern),
            )

            # Validate the test intention: The _NEG suffix indicates negative tests (i.e., a pattern not matching the event)
            if label.endswith("_NEG"):
                assert not response["Result"]
            else:
                assert response["Result"]

    @markers.aws.validated
    def test_event_pattern_with_multi_key(self, aws_client):
        """Test the special case of a duplicate JSON key separately because it requires working around the
        uniqueness constraints of the JSON5 library and Python dicts, which would already de-deduplicate the key "location".
        This example is based on the following AWS documentation:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-complex-example
        """

        with open(COMPLEX_MULTI_KEY_EVENT, "r") as event_file, open(
            COMPLEX_MULTI_KEY_EVENT_PATTERN, "r"
        ) as event_pattern_file:
            event = event_file.read()
            event_pattern = event_pattern_file.read()

            response = aws_client.events.test_event_pattern(
                Event=event,
                EventPattern=event_pattern,
            )
            assert response["Result"]

    @markers.aws.validated
    def test_event_pattern_with_escape_characters(self, aws_client):
        r"""Test the special case of using escape characters separately because it requires working around JSON escaping.
        Escape characters are explained in the AWS documentation:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-wildcard-matching
        * "The string \* represents the literal * character"
        * "The string \\ represents the literal \ character"
        """

        event = r'{"id": "1", "source": "test-source", "detail-type": "test-detail-type", "account": "123456789012", "region": "us-east-2", "time": "2022-07-13T13:48:01Z", "detail": {"escape_star": "*", "escape_backslash": "\\"}}'
        # TODO: devise better testing strategy for * because the wildcard matches everything and "\\*" does not match.
        event_pattern = r'{"detail": {"escape_star": ["*"], "escape_backslash": ["\\"]}}'

        response = aws_client.events.test_event_pattern(
            Event=event,
            EventPattern=event_pattern,
        )
        assert response["Result"]

    @markers.aws.validated
    def test_event_pattern_source(self, aws_client, snapshot, account_id, region_name):
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(
                {
                    "id": "1",
                    "source": "order",
                    "detail-type": "Test",
                    "account": account_id,
                    "region": region_name,
                    "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            ),
            EventPattern=json.dumps(
                {
                    "source": ["order"],
                    "detail-type": ["Test"],
                }
            ),
        )
        snapshot.match("eventbridge-test-event-pattern-response", response)

        # negative test, source is not matched
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(
                {
                    "id": "1",
                    "source": "order",
                    "detail-type": "Test",
                    "account": account_id,
                    "region": region_name,
                    "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            ),
            EventPattern=json.dumps(
                {
                    "source": ["shipment"],
                    "detail-type": ["Test"],
                }
            ),
        )
        snapshot.match("eventbridge-test-event-pattern-response-no-match", response)


class TestRuleWithPattern:
    @markers.aws.validated
    def test_put_events_with_rule_pattern_anything_but(
        self, put_events_with_filter_to_sqs, snapshot
    ):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
                snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
            ]
        )

        event_detail_match = {"command": "display-message", "payload": "baz"}
        event_detail_null = {"command": None, "payload": "baz"}
        event_detail_no_match = {"command": "no-message", "payload": "baz"}
        test_event_pattern_anything_but = {
            "source": ["core.update-account-command"],
            "detail-type": ["core.update-account-command"],
            "detail": {"command": [{"anything-but": ["no-message"]}]},
        }
        entries_match = [
            {
                "Source": test_event_pattern_anything_but["source"][0],
                "DetailType": test_event_pattern_anything_but["detail-type"][0],
                "Detail": json.dumps(event_detail_match),
            }
        ]
        entries_match_null = [
            {
                "Source": test_event_pattern_anything_but["source"][0],
                "DetailType": test_event_pattern_anything_but["detail-type"][0],
                "Detail": json.dumps(event_detail_null),
            }
        ]
        entries_no_match = [
            {
                "Source": test_event_pattern_anything_but["source"][0],
                "DetailType": test_event_pattern_anything_but["detail-type"][0],
                "Detail": json.dumps(event_detail_no_match),
            }
        ]

        entries_asserts = [
            (entries_match, True),
            (entries_match_null, True),
            (entries_no_match, False),
        ]

        messages = put_events_with_filter_to_sqs(
            pattern=test_event_pattern_anything_but,
            entries_asserts=entries_asserts,
        )
        snapshot.match("rule-anything-but", messages)

    @markers.aws.validated
    def test_put_events_with_rule_pattern_exists_true(
        self, put_events_with_filter_to_sqs, snapshot
    ):
        """
        Exists matching True condition: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-exists-matching
        """
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
                snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
            ]
        )

        event_detail_exists = {"key": "value", "payload": "baz"}
        event_detail_not_exists = {"no-key": "no-value", "payload": "baz"}
        event_patter_details = ["core.update-account-command"]
        test_event_pattern_exists = {
            "source": event_patter_details,
            "detail-type": event_patter_details,
            "detail": {"key": [{"exists": True}]},
        }
        entries_exists = [
            {
                "Source": test_event_pattern_exists["source"][0],
                "DetailType": test_event_pattern_exists["detail-type"][0],
                "Detail": json.dumps(event_detail_exists),
            }
        ]
        entries_not_exists = [
            {
                "Source": test_event_pattern_exists["source"][0],
                "DetailType": test_event_pattern_exists["detail-type"][0],
                "Detail": json.dumps(event_detail_not_exists),
            }
        ]
        entries_asserts = [
            (entries_exists, True),
            (entries_not_exists, False),
        ]

        messages = put_events_with_filter_to_sqs(
            pattern=test_event_pattern_exists,
            entries_asserts=entries_asserts,
        )
        snapshot.match("rule-exists-true", messages)

    @markers.aws.validated
    def test_put_events_with_rule_pattern_exists_false(
        self, put_events_with_filter_to_sqs, snapshot
    ):
        """
        Exists matching False condition: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-exists-matching
        """
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
                snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
            ]
        )

        event_detail_exists = {"key": "value", "payload": "baz"}
        event_detail_not_exists = {"no-key": "no-value", "payload": "baz"}
        event_patter_details = ["core.update-account-command"]
        test_event_pattern_not_exists = {
            "source": event_patter_details,
            "detail-type": event_patter_details,
            "detail": {"key": [{"exists": False}]},
        }
        entries_exists = [
            {
                "Source": test_event_pattern_not_exists["source"][0],
                "DetailType": test_event_pattern_not_exists["detail-type"][0],
                "Detail": json.dumps(event_detail_exists),
            }
        ]
        entries_not_exists = [
            {
                "Source": test_event_pattern_not_exists["source"][0],
                "DetailType": test_event_pattern_not_exists["detail-type"][0],
                "Detail": json.dumps(event_detail_not_exists),
            }
        ]
        entries_asserts_exists_false = [
            (entries_exists, False),
            (entries_not_exists, True),
        ]

        messages_not_exists = put_events_with_filter_to_sqs(
            pattern=test_event_pattern_not_exists,
            entries_asserts=entries_asserts_exists_false,
        )
        snapshot.match("rule-exists-false", messages_not_exists)

    @markers.aws.validated
    def test_put_event_with_content_base_rule_in_pattern(
        self,
        create_sqs_events_target,
        events_create_event_bus,
        events_put_rule,
        snapshot,
        aws_client,
    ):
        queue_url, queue_arn = create_sqs_events_target()

        # Create event bus
        event_bus_name = f"event-bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)

        # Put rule
        rule_name = f"rule-{short_uid()}"
        # EventBridge apparently converts some fields, for example: Source=>source, DetailType=>detail-type
        # but the actual pattern matching is case-sensitive by key!
        pattern = {
            "source": [{"exists": True}],
            "detail-type": [{"prefix": "core.app"}],
            "detail": {
                "description": ["this-is-event-details"],
                "amount": [200],
                "salary": [2000, 4000],
                "env": ["dev", "prod"],
                "user": ["user1", "user2", "user3"],
                "admins": ["skyli", {"prefix": "hey"}, {"prefix": "ad"}],
                "test1": [{"anything-but": 200}],
                "test2": [{"anything-but": "test2"}],
                "test3": [{"anything-but": ["test3", "test33"]}],
                "test4": [{"anything-but": {"prefix": "test4"}}],
                # TODO: unsupported in LocalStack
                # "ip": [{"cidr": "10.102.1.0/24"}],
                "num-test1": [{"numeric": ["<", 200]}],
                "num-test2": [{"numeric": ["<=", 200]}],
                "num-test3": [{"numeric": [">", 200]}],
                "num-test4": [{"numeric": [">=", 200]}],
                "num-test5": [{"numeric": [">=", 200, "<=", 500]}],
                "num-test6": [{"numeric": [">", 200, "<", 500]}],
                "num-test7": [{"numeric": [">=", 200, "<", 500]}],
            },
        }

        events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(pattern),
        )

        # Put target
        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        event = {
            "EventBusName": event_bus_name,
            "Source": "core.update-account-command",
            "DetailType": "core.app.backend",
            "Detail": json.dumps(
                {
                    "description": "this-is-event-details",
                    "amount": 200,
                    "salary": 2000,
                    "env": "prod",
                    "user": "user3",
                    "admins": "admin",
                    "test1": 300,
                    "test2": "test22",
                    "test3": "test333",
                    "test4": "this test4",
                    "ip": "10.102.1.100",
                    "num-test1": 100,
                    "num-test2": 200,
                    "num-test3": 300,
                    "num-test4": 200,
                    "num-test5": 500,
                    "num-test6": 300,
                    "num-test7": 300,
                }
            ),
        }

        aws_client.events.put_events(Entries=[event])

        messages = sqs_collect_messages(aws_client, queue_url, expected_events_count=1, retries=3)

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
                snapshot.transform.key_value("MessageId"),
            ]
        )
        snapshot.match("messages", messages)
