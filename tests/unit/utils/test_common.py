import re
import threading
import unittest
from unittest.mock import MagicMock

import pytest

from localstack.utils.collections import is_none_or_empty
from localstack.utils.crypto import (
    PEM_CERT_END,
    PEM_CERT_START,
    PEM_KEY_END_REGEX,
    PEM_KEY_START_REGEX,
    generate_ssl_cert,
)
from localstack.utils.files import load_file, new_tmp_file, rm_rf
from localstack.utils.json import FileMappedDocument
from localstack.utils.run import run
from localstack.utils.sync import synchronized


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
