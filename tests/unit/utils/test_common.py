import threading
import unittest
from unittest.mock import MagicMock

import pytest

from localstack.utils.common import is_none_or_empty, synchronized


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
