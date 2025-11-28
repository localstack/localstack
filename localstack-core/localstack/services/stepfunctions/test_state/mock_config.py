import abc
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, create_model

from localstack.services.stepfunctions.asl.eval.states import (
    ExecutionData,
    StateData,
    StateMachineData,
    TaskData,
)


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


def _to_strict_model(name: str, source: type):
    type_map = {str: StrictStr, int: StrictInt}
    fields = {k: (type_map.get(v, v) | None, None) for k, v in source.__annotations__.items()}
    return create_model(name, __config__=ConfigDict(extra="forbid"), **fields)


TestStateContextObjectValidator: Final[type[BaseModel]] = create_model(
    "ContextValidator",
    __config__=ConfigDict(extra="forbid"),
    Execution=(_to_strict_model("Execution", ExecutionData) | None, None),
    State=(_to_strict_model("State", StateData) | None, None),
    StateMachine=(_to_strict_model("StateMachine", StateMachineData) | None, None),
    Task=(_to_strict_model("Task", TaskData) | None, None),
)
