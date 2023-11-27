import pytest

from localstack.testing.snapshots import SnapshotSession
from localstack.testing.snapshots.report import _format_json_path
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer, SortingTransformer
from localstack.testing.snapshots.transformer_utility import (
    TransformerUtility,
    _resource_name_transformer,
)


class TestSnapshotManager:
    def test_simple_diff_nochange(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        sm.match("key_a", {"a": 3})
        sm._assert_all()

    def test_simple_diff_change(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        sm.match("key_a", {"a": 5})
        with pytest.raises(Exception) as ctx:
            sm._assert_all()
        ctx.match("Parity snapshot failed")

    def test_multiple_assertmatch_with_same_key_fail(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        sm.match("key_a", {"a": 3})
        with pytest.raises(Exception) as ctx:
            sm.match("key_a", {"a": 3})
        ctx.match("used multiple times in the same test scope")

    def test_context_replacement(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.add_transformer(
            KeyValueBasedTransformer(lambda k, v: v if k == "aaa" else None, replacement="A")
        )
        sm.recorded_state = {"key_a": {"aaa": "<A:1>", "bbb": "<A:1> hello"}}
        sm.match("key_a", {"aaa": "something", "bbb": "something hello"})
        sm._assert_all()

    def test_context_replacement_no_change(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.add_transformer(TransformerUtility.key_value("name"))
        sm.recorded_state = {"key_a": {"name": ""}}
        sm.match("key_a", {"name": ""})
        sm._assert_all()

    def test_match_order_reference_replacement(self):
        """tests if the reference-replacement works as expected, e.g., using alphabetical order of keys"""
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)

        sm.add_transformer(KeyValueBasedTransformer(_resource_name_transformer, "resource"))

        sm.recorded_state = {
            "subscription-attributes": {
                "Attributes": {
                    "ConfirmationWasAuthenticated": "true",
                    "Endpoint": "arn:aws:lambda:region:111111111111:function:<resource:1>",
                    "Owner": "111111111111",
                    "PendingConfirmation": "false",
                    "Protocol": "lambda",
                    "RawMessageDelivery": "false",
                    "RedrivePolicy": {
                        "deadLetterTargetArn": "arn:aws:sqs:region:111111111111:<resource:2>"
                    },
                    "SubscriptionArn": "arn:aws:sns:region:111111111111:<resource:4>:<resource:3>",
                    "TopicArn": "arn:aws:sns:region:111111111111:<resource:4>",
                },
                "ResponseMetadata": {"HTTPHeaders": {}, "HTTPStatusCode": 200},
            }
        }
        sm.match(
            "subscription-attributes",
            {
                "Attributes": {
                    "ConfirmationWasAuthenticated": "true",
                    "Owner": "111111111111",
                    "PendingConfirmation": "false",
                    "Protocol": "lambda",
                    "RawMessageDelivery": "false",
                    "RedrivePolicy": {
                        "deadLetterTargetArn": "arn:aws:sqs:region:111111111111:111112222233333"
                    },
                    "TopicArn": "arn:aws:sns:region:111111111111:rrrrrrrrrrrrrrrrr",
                    "SubscriptionArn": "arn:aws:sns:region:111111111111:rrrrrrrrrrrrrrrrr:azazazazazazazaza",
                    "Endpoint": "arn:aws:lambda:region:111111111111:function:aaaaabbbbb",
                },
                "ResponseMetadata": {"HTTPHeaders": {}, "HTTPStatusCode": 200},
            },
        )
        sm._assert_all()

    def test_reference_replacement_skip_outer_keys(self):
        """Test if the reference replacement properly skips the snapshot keys on the outermost level"""
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.add_transformer(TransformerUtility.key_value("name"))
        sm.recorded_state = {"key_a": {"name": "<name:1>"}}
        sm.match("key_a", {"name": "key"})
        sm._assert_all()

    def test_replacement_key_value(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.add_transformer(
            KeyValueBasedTransformer(
                # returns last two characters of value -> only this should be replaced
                lambda k, v: v[-2:] if k == "aaa" else None,
                replacement="A",
                replace_reference=False,
            )
        )
        sm.recorded_state = {
            "key_a": {"aaa": "hellA", "aab": "this is a test", "b": {"aaa": "another teA"}}
        }
        sm.match("key_a", {"aaa": "helloo", "aab": "this is a test", "b": {"aaa": "another test"}})
        sm._assert_all()

    def test_dot_in_skip_verification_path(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {
            "key_a": {"aaa": "hello", "aab": "this is a test", "b": {"a.aa": "another test"}}
        }
        sm.match(
            "key_a",
            {"aaa": "hello", "aab": "this is a test-fail", "b": {"a.aa": "another test-fail"}},
        )

        with pytest.raises(Exception) as ctx:  # asserts it fail without skipping
            sm._assert_all()
        ctx.match("Parity snapshot failed")

        skip_path = ["$..aab", "$..b.a.aa"]
        with pytest.raises(Exception) as ctx:  # asserts it fails if fields are not escaped
            sm._assert_all(skip_verification_paths=skip_path)
        ctx.match("Parity snapshot failed")

        skip_path_escaped = ["$..aab", "$..b.'a.aa'"]
        sm._assert_all(skip_verification_paths=skip_path_escaped)

    def test_non_homogeneous_list(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key1": [{"key2": "value1"}, "value2", 3]}
        sm.match("key1", [{"key2": "value1"}, "value2", 3])
        sm._assert_all()


def test_json_diff_format():
    path = ["Records", 1]
    assert _format_json_path(path) == '"$..Records"'
    path = ["Records", 1, 1, 1]
    assert _format_json_path(path) == '"$..Records"'
    path = ["Records", 1, "SomeKey"]
    assert _format_json_path(path) == '"$..Records..SomeKey"'
    path = ["Records", 1, 1, "SomeKey"]
    assert _format_json_path(path) == '"$..Records..SomeKey"'
    path = ["Records", 1, 1, 0, "SomeKey"]
    assert _format_json_path(path) == '"$..Records..SomeKey"'
    path = ["Records", "SomeKey"]
    assert _format_json_path(path) == '"$..Records.SomeKey"'
    path = []
    assert _format_json_path(path) == '"$.."'
    path = [1, 1, 0, "SomeKey"]
    assert _format_json_path(path) == '"$..SomeKey"'


def test_sorting_transformer():
    original_dict = {
        "a": {
            "b": [
                {"name": "c-123"},
                {"name": "a-123"},
                {"name": "b-123"},
            ]
        },
        "a2": {
            "b": [
                {"name": "b-123"},
                {"name": "a-123"},
                {"name": "c-123"},
            ]
        },
    }

    sorted_items = [
        {"name": "a-123"},
        {"name": "b-123"},
        {"name": "c-123"},
    ]

    transformer = SortingTransformer("b", lambda x: x["name"])
    transformed_dict = transformer.transform(original_dict)

    assert transformed_dict["a"]["b"] == sorted_items
    assert transformed_dict["a2"]["b"] == sorted_items
