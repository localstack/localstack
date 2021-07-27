import time
from typing import Callable, Literal


def wait_until(
    fn: Callable[[], bool],
    wait: float = 1.0,
    max_retries: int = 10,
    strategy: Literal["exponential", "static", "linear"] = "exponential",
    _retries: int = 0,
    _max_wait: float = 120,
) -> None:
    """waits until a given condition is true, rechecking it periodically"""
    if max_retries < _retries:
        raise Exception("Too many retries!")
    completed = fn()
    if not completed:
        if wait > _max_wait:
            raise Exception("Maximum wait time reached")
        time.sleep(wait)
        next_wait = wait  # static
        if strategy == "linear":
            next_wait = (wait / _retries) * (_retries + 1)
        elif strategy == "exponential":
            next_wait = wait ** 2
        wait_until(fn, next_wait, max_retries, strategy, _retries + 1)
