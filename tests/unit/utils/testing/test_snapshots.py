import pytest

from localstack.testing.snapshots import SnapshotSession


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

    def test_replace_account_id(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.recorded_state = {"key_a": {"a": "<arn>"}}
        assert sm.match(
            "key_a",
            {"a": "arn:aws:lambda:us-east-1:000000000000:function:localstack-testing-image-fn"},
        )

    def test_custom_replacer(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        sm.replace_jsonpath_value("$..b", "hello world!")
        sm.recorded_state = {"key_a": {"a": "hello world", "b": "<hello-world>"}}
        assert sm.match("key_a", {"a": "hello world", "b": "hello world!"})
