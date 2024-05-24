"""Concurrency synchronization utilities"""

import functools
import threading
import time
from collections import defaultdict
from typing import Callable, Literal, TypeVar


class ShortCircuitWaitException(Exception):
    """raise to immediately stop waiting, e.g. when an operation permanently failed"""

    pass


def wait_until(
    fn: Callable[[], bool],
    wait: float = 1.0,
    max_retries: int = 10,
    strategy: Literal["exponential", "static", "linear"] = "exponential",
    _retries: int = 1,
    _max_wait: float = 240,
) -> bool:
    """waits until a given condition is true, rechecking it periodically"""
    assert _retries > 0
    if max_retries < _retries:
        return False
    try:
        completed = fn()
    except ShortCircuitWaitException:
        return False
    except Exception:
        completed = False

    if completed:
        return True
    else:
        if wait > _max_wait:
            return False
        time.sleep(wait)
        next_wait = wait  # default: static
        if strategy == "linear":
            next_wait = (wait / _retries) * (_retries + 1)
        elif strategy == "exponential":
            next_wait = wait * 2
        return wait_until(fn, next_wait, max_retries, strategy, _retries + 1, _max_wait)


T = TypeVar("T")


def retry(function: Callable[..., T], retries=3, sleep=1.0, sleep_before=0, **kwargs) -> T:
    raise_error = None
    if sleep_before > 0:
        time.sleep(sleep_before)
    retries = int(retries)
    for i in range(0, retries + 1):
        try:
            return function(**kwargs)
        except Exception as error:
            raise_error = error
            time.sleep(sleep)
    raise raise_error


def poll_condition(condition, timeout: float = None, interval: float = 0.5) -> bool:
    """
    Poll evaluates the given condition until a truthy value is returned. It does this every `interval` seconds
    (0.5 by default), until the timeout (in seconds, if any) is reached.

    Poll returns True once `condition()` returns a truthy value, or False if the timeout is reached.
    """
    remaining = 0
    if timeout is not None:
        remaining = timeout

    while not condition():
        if timeout is not None:
            remaining -= interval

            if remaining <= 0:
                return False

        time.sleep(interval)

    return True


def synchronized(lock=None):
    """
    Synchronization decorator as described in
    http://blog.dscpl.com.au/2014/01/the-missing-synchronized-decorator.html.
    """

    def _decorator(wrapped):
        @functools.wraps(wrapped)
        def _wrapper(*args, **kwargs):
            with lock:
                return wrapped(*args, **kwargs)

        return _wrapper

    return _decorator


def sleep_forever():
    while True:
        time.sleep(1)


class SynchronizedDefaultDict(defaultdict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.RLock()

    def fromkeys(self, keys, value=None):
        with self._lock:
            return super().fromkeys(keys, value)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def __iter__(self):
        with self._lock:
            return super().__iter__()

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __str__(self):
        with self._lock:
            return super().__str__()
