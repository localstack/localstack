import pytest

from localstack.testing.snapshots import SnapshotSession
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.testing.snapshots.transformer_utility import _resource_name_transformer


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
