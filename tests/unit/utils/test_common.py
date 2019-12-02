import unittest
import threading
from unittest.mock import MagicMock
from localstack.utils.common import synchronized


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
