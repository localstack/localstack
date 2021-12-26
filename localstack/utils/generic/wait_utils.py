import time
from typing import Callable

from typing_extensions import Literal


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


class ShortCircuitWaitException(Exception):
    """raise to immediately stop waiting, e.g. when an operation permanently failed"""

    pass
