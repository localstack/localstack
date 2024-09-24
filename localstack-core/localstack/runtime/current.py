"""This package gives access to the singleton ``LocalstackRuntime`` instance. This is the only global state
that should exist within localstack, which contains the singleton ``LocalstackRuntime`` which is currently
running."""

import threading
import typing

if typing.TYPE_CHECKING:
    # make sure we don't have any imports here at runtime, so it can be imported anywhere without conflicts
    from .runtime import LocalstackRuntime

_runtime: typing.Optional["LocalstackRuntime"] = None
"""The singleton LocalStack Runtime"""
_runtime_lock = threading.RLock()


def get_current_runtime() -> "LocalstackRuntime":
    with _runtime_lock:
        if not _runtime:
            raise ValueError("LocalStack runtime has not yet been set")
        return _runtime


def set_current_runtime(runtime: "LocalstackRuntime"):
    with _runtime_lock:
        global _runtime
        _runtime = runtime


def initialize_runtime() -> "LocalstackRuntime":
    from localstack.runtime import runtime

    with _runtime_lock:
        try:
            return get_current_runtime()
        except ValueError:
            pass
        rt = runtime.create_from_environment()
        set_current_runtime(rt)
        return rt
