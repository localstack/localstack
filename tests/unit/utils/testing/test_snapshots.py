import json
import os

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

    def test_example(self):
        sm = SnapshotSession(scope_key="A", verify=True, file_path="", update=False)
        basepath = "/Users/stefanie/repos/localstack/tests/integration/sample-snapshots/1"
        for subdir, dirs, files in os.walk(basepath):
            for file in files:
                filepath_1 = subdir + os.sep + file
                filepath_2 = subdir.replace("1", "2") + os.sep + file
                # print(f"{filepath_1} - {filepath_2}")
                with open(filepath_1) as file1:
                    with open(filepath_2) as file2:
                        print(f"testing: {file}")
                        if file.endswith(".json"):
                            data1 = json.load(file1)
                            data2 = json.load(file2)
                        else:
                            data1 = {"fileContent": file1.readlines()}
                            data2 = {"fileContent": file2.readlines()}
                        sm.recorded_state = {file: data1}
                        assert sm.match(file, data2)
                        # assert data1 == data2
                        print(f"finished test for {file}")
