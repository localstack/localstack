import sys
import time
from typing import Callable

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


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


def retry(function, retries=3, sleep=1.0, sleep_before=0, **kwargs):
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
