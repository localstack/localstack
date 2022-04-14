import re

import pytest

from localstack.utils.testing.snapshots import SnapshotSession


class TestSnapshotManager:
    def test_simple_diff_nochange(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        assert sm.match("key_a", {"a": 3})

    def test_simple_diff_change(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        assert not sm.match("key_a", {"a": 5})

    def test_multiple_assertmatch_with_same_key_fail(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": 3}}
        sm.match("key_a", {"a": 3})
        with pytest.raises(Exception) as ctx:
            sm.match("key_a", {"a": 3})
        ctx.match("used multiple times in the same test scope")

    def test_replacer_arn(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": "<arn>"}}
        assert sm.match(
            "key_a",
            {"a": "arn:aws:lambda:us-east-1:000000000000:function:localstack-testing-image-fn"},
        )

    def test_key_skip_defaults(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"SomethingName": "<name>"}}
        assert sm.match("key_a", {"SomethingName": "doesn't matter what's in here"})

    def test_key_skip_custom(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.skip_key(re.compile("Hello"), "Hallo")
        sm.recorded_state = {"key_a": {"Hello": "Hallo"}}
        assert sm.match("key_a", {"Hello": "doesn't matter what's in here"})

    def test_custom_replacer(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.register_replacement(re.compile("hello world!"), "<hello-world>")
        sm.recorded_state = {"key_a": {"a": "hello world", "b": "<hello-world>"}}
        assert sm.match("key_a", {"a": "hello world", "b": "hello world!"})

    def test_replacer_sqsurl(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": "<sqs-url>"}}
        assert sm.match(
            "key_a", {"a": "https://sqs.us-east-2.amazonaws.com/000000000000/test-topic-112233"}
        )
