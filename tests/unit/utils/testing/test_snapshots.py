import pytest

from localstack.testing.snapshots import SnapshotSession
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer


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
