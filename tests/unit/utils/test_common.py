import os.path
import threading
import time
import unittest
from unittest.mock import MagicMock

import pytest

from localstack.utils.common import (
    FileListener,
    is_none_or_empty,
    poll_condition,
    run,
    synchronized,
)


class SynchronizedTest(unittest.TestCase):
    reallock = threading.RLock()
    mocklock = MagicMock(wraps=reallock)

    @synchronized(lock=mocklock)
    def locked(self):
        pass

    def test_synchronized_uses_with_enter_exit(self):
        self.locked()
        self.mocklock.__enter__.assert_called_with()
        self.mocklock.__exit__.assert_called_with(None, None, None)


@pytest.mark.parametrize(
    ["obj", "result"],
    [
        ("nonempty", False),
        ("", True),
        (None, True),
        ("   ", True),
    ],
)
def test_is_none_or_empty_strings(obj, result):
    assert is_none_or_empty(obj) == result


@pytest.mark.parametrize(
    ["obj", "result"],
    [
        ([], True),
        (None, True),
        ([1], False),
        (["1", "2"], False),
    ],
)
def test_is_none_or_empty_lists(obj, result):
    assert is_none_or_empty(obj) == result


def test_run_cmd_as_str_or_list():
    def _run(cmd):
        return run(cmd).strip()

    # Assert that commands can be specified as strings as well as lists.
    # (shell=True|False flag for subprocess.Popen() is properly managed by run(..) function)
    assert "foo bar 123" == _run("echo 'foo bar 123'")
    assert "foo bar 123" == _run("echo foo bar 123")
    assert "foo bar 123" == _run("  echo    foo    bar     123    ")
    assert "foo bar 123" == _run(["echo", "foo bar 123"])
    assert "foo bar 123" == _run(["echo", "foo", "bar", "123"])
    with pytest.raises(FileNotFoundError):
        _run(["echo 'foo bar 123'"])


@pytest.mark.parametrize("tail_engine", ["command", "tailer"])
class TestFileListener:
    def test_basic_usage(self, tail_engine, tmp_path):
        lines = list()

        file = tmp_path / "log.txt"
        file.touch()
        fd = open(file, "a")
        listener = FileListener(str(file), lines.append)
        listener.use_tail_command = tail_engine != "tailer"

        try:
            listener.start()
            assert listener.started.is_set()
            fd.write("hello" + os.linesep)
            fd.write("pytest" + os.linesep)
            fd.flush()

            assert poll_condition(lambda: len(lines) == 2, timeout=3), (
                "expected two lines to appear. %s" % lines
            )

            assert lines[0] == "hello"
            assert lines[1] == "pytest"
        finally:
            listener.close()

        try:
            fd.write("foobar" + os.linesep)
            time.sleep(0.5)
            assert len(lines) == 2, "expected listener.stop() to stop listening on new "
        finally:
            fd.close()

    def test_callback_exception_ignored(self, tail_engine, tmp_path):
        lines = list()

        def callback(line):
            if "throw" in line:
                raise ValueError("oh noes")

            lines.append(line)

        file = tmp_path / "log.txt"
        file.touch()
        fd = open(file, "a")
        listener = FileListener(str(file), callback)
        listener.use_tail_command = tail_engine != "tailer"

        try:
            listener.start()
            assert listener.started.is_set()
            fd.write("hello" + os.linesep)
            fd.flush()
            fd.write("throw" + os.linesep)
            fd.write("pytest" + os.linesep)
            fd.flush()

            assert poll_condition(lambda: len(lines) == 2, timeout=3), (
                "expected two lines to appear. %s" % lines
            )

            assert lines[0] == "hello"
            assert lines[1] == "pytest"
        finally:
            fd.close()
            listener.close()

    def test_open_missing_file(self, tail_engine):
        lines = list()

        listener = FileListener("/tmp/does/not/exist", lines.append)
        listener.use_tail_command = tail_engine != "tailer"

        with pytest.raises(FileNotFoundError):
            listener.start()
