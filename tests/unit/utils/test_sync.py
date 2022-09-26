import threading

from localstack.utils.sync import SynchronizedDefaultDict


def test_synchronized_defaultdict():
    d = SynchronizedDefaultDict(int)

    d["a"] = 1
    d["b"] = 2

    assert d["a"] == 1
    assert d["b"] == 2
    assert d["c"] == 0

    d = SynchronizedDefaultDict(threading.RLock)

    with d["a"]:
        assert isinstance(d["a"], type(threading.RLock()))
