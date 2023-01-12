import os.path
import re
import threading
import time
import unittest
from unittest.mock import MagicMock

import pytest
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from localstack.utils.collections import is_none_or_empty
from localstack.utils.crypto import (
    PEM_CERT_END,
    PEM_CERT_START,
    PEM_KEY_END_REGEX,
    PEM_KEY_START_REGEX,
    generate_ssl_cert,
)
from localstack.utils.files import load_file, new_tmp_file, rm_rf
from localstack.utils.http import download
from localstack.utils.json import FileMappedDocument
from localstack.utils.run import run
from localstack.utils.sync import poll_condition, synchronized
from localstack.utils.tail import FileListener


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
        lines = []

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
        lines = []

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
        lines = []

        listener = FileListener("/tmp/does/not/exist", lines.append)
        listener.use_tail_command = tail_engine != "tailer"

        with pytest.raises(FileNotFoundError):
            listener.start()


class TestFileMappedDocument:
    def test_load_without_file_succeeds(self, tmp_path):
        path = tmp_path / "doc.json"
        doc = FileMappedDocument(path)
        assert doc == {}

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "doc.json"
        doc = FileMappedDocument(path)

        doc["number"] = 42
        doc["nested"] = {"foo": "bar"}

        doc.save()

        doc = FileMappedDocument(path)
        doc.load()

        assert doc == {"number": 42, "nested": {"foo": "bar"}}

    def test_load_merges_content(self, tmp_path):
        path = tmp_path / "doc.json"
        # save state
        doc = FileMappedDocument(path)
        doc["number"] = 42
        doc["nested"] = {"foo": "bar"}
        doc.save()

        # save state from elsewhere
        doc1 = FileMappedDocument(path)
        doc1["another"] = 420
        doc1["nested"]["baz"] = "ed"
        doc1.save()

        # load state
        doc.load()
        assert doc == {"number": 42, "another": 420, "nested": {"foo": "bar", "baz": "ed"}}

    def test_load_with_directory_fails(self, tmp_path):
        path = tmp_path / "somedir"
        path.mkdir()

        with pytest.raises(IsADirectoryError):
            FileMappedDocument(path)

    def test_save_with_directory_fails(self, tmp_path):
        path = tmp_path / "somedir"
        doc = FileMappedDocument(path)

        path.mkdir()
        with pytest.raises(IsADirectoryError):
            doc.save()

    def test_save_sets_default_mod(self, tmp_path):
        path = tmp_path / "doc.json"
        doc = FileMappedDocument(path)
        doc.save()

        mode = path.stat().st_mode & 0o777
        assert oct(mode) == oct(0o664)

    def test_save_sets_mod(self, tmp_path):
        path = tmp_path / "doc.json"
        doc = FileMappedDocument(path, mode=0o600)
        doc.save()

        mode = path.stat().st_mode & 0o777
        assert oct(mode) == oct(0o600)

    def test_save_creates_directory(self, tmp_path):
        path = tmp_path / "some" / "dir" / "doc.json"
        assert not path.exists()

        doc = FileMappedDocument(path)
        doc.save()
        assert path.exists()


def test_generate_ssl_cert():
    def _assert(cert, key):
        # assert that file markers are in place
        assert PEM_CERT_START in cert
        assert PEM_CERT_END in cert
        assert re.match(PEM_KEY_START_REGEX, key.replace("\n", " "))
        assert re.match(rf".*{PEM_KEY_END_REGEX}", key.replace("\n", " "))

    # generate cert and get content directly
    cert = generate_ssl_cert()
    _assert(cert, cert)

    # generate cert to file and load content from there
    target_file, cert_file_name, key_file_name = generate_ssl_cert(
        target_file=new_tmp_file(), overwrite=True
    )
    _assert(load_file(cert_file_name), load_file(key_file_name))

    # clean up
    rm_rf(cert_file_name)
    rm_rf(key_file_name)


def test_download_with_timeout():
    def _handler(_: Request) -> Response:
        time.sleep(2)
        return Response(b"", status=200)

    tmp_file = new_tmp_file()
    # it seems this test is not properly cleaning up for other unit tests, this step is normally not necessary
    # we should use the fixture `httpserver` instead of HTTPServer directly
    with HTTPServer() as server:
        server.expect_request("/").respond_with_data(b"tmp_file", status=200)
        server.expect_request("/sleep").respond_with_handler(_handler)
        http_endpoint = server.url_for("/")

        download(http_endpoint, tmp_file)
        assert load_file(tmp_file) == "tmp_file"
        with pytest.raises(TimeoutError):
            download(f"{http_endpoint}/sleep", tmp_file, timeout=1)

    # clean up
    rm_rf(tmp_file)
