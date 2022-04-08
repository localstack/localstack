import re

import pytest

from tests.integration.awslambda.conftest import SnapshotManager

# 1. needs to have context information across *MULTIPLE* diffs(!)
# 2.

# snapshot.match("k1", obj)
# snapshot.get("k1"),
# snapshot.match("k1")
# snapshot.assert_match("k1")
# snapshot.ignore_regex("")
# snapshot.ignore_path("")
# snapshot.ignore_types("")
# snapshot.disable_linking() # optional, default== linking
# snapshot.register_link("arn:aws.....", everywhere=True)
# snapshot.register_replacement(r"^clc-..asdfsfr$", "<clc>")


class TestSnapshotManager:
    def test_simple_diff_nochange(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"a": 3})
        sm.assert_match("key_a", {"a": 3})

    def test_simple_diff_change(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"a": 3})
        with pytest.raises(Exception):
            sm.assert_match("key_a", {"a": 5})

    def test_multiple_assertmatch_with_same_key_fail(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"a": 3})
        sm.assert_match("key_a", {"a": 3})
        with pytest.raises(Exception) as ctx:
            sm.assert_match("key_a", {"a": 3})
        ctx.match("used multiple times in the same test scope")

    def test_replacer_arn(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"a": "<arn>"})
        sm.assert_match(
            "key_a",
            {"a": "arn:aws:lambda:us-east-1:000000000000:function:localstack-testing-image-fn"},
        )

    def test_key_skip_defaults(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"SomethingName": "<name>"})
        sm.assert_match("key_a", {"SomethingName": "doesn't matter what's in here"})

    def test_key_skip_custom(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm.skip_key(re.compile("Hello"), "Hallo")
        sm._update("key_a", {"Hello": "Hallo"})
        sm.assert_match("key_a", {"Hello": "doesn't matter what's in here"})

    def test_custom_replacer(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm.register_replacement(re.compile("hello world!"), "<hello-world>")
        sm._update("key_a", {"a": "hello world", "b": "<hello-world>"})
        sm.assert_match("key_a", {"a": "hello world", "b": "hello world!"})

    def test_replacer_sqsurl(self):
        sm = SnapshotManager(scope_key="A", verify=True, file_path="", update=False)
        sm._update("key_a", {"a": "<sqs-url>"})
        sm.assert_match(
            "key_a", {"a": "https://sqs.us-east-2.amazonaws.com/000000000000/test-topic-112233"}
        )
