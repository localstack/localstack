import abc
from typing import Any, Final


class TestStateMockedResponse(abc.ABC):
    pass


class TestStateResponseReturn(TestStateMockedResponse):
    payload: Final[Any]

    def __init__(self, payload: Any):
        self.payload = payload


class TestStateResponseThrow(TestStateMockedResponse):
    error: Final[str]
    cause: Final[str]

    def __init__(self, error: str, cause: str):
        self.error = error
        self.cause = cause
