import abc
from typing import Final

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, Timestamp


class ProgramState(abc.ABC): ...


class ProgramEnded(ProgramState):
    pass


class ProgramStopped(ProgramState):
    def __init__(self, stop_date: Timestamp, error: str | None, cause: str | None):
        super().__init__()
        self.stop_date: Timestamp = stop_date
        self.error: str | None = error
        self.cause: str | None = cause


class ProgramRunning(ProgramState):
    _next_state_name: str | None
    _next_field_name: str | None

    def __init__(self):
        super().__init__()
        self._next_state_name = None
        self._next_field_name = None

    @property
    def next_state_name(self) -> str:
        next_state_name = self._next_state_name
        if next_state_name is None:
            raise RuntimeError("Could not retrieve NextState from uninitialised ProgramState.")
        return next_state_name

    @next_state_name.setter
    def next_state_name(self, next_state_name) -> None:
        self._next_state_name = next_state_name
        self._next_field_name = None

    @property
    def next_field_name(self) -> str:
        return self._next_field_name

    @next_field_name.setter
    def next_field_name(self, next_field_name) -> None:
        next_state_name = self._next_state_name
        if next_state_name is None:
            raise RuntimeError("Could not set NextField from uninitialised ProgramState.")
        self._next_field_name = next_field_name


class ProgramError(ProgramState):
    error: Final[ExecutionFailedEventDetails | None]

    def __init__(self, error: ExecutionFailedEventDetails | None):
        super().__init__()
        self.error = error


class ProgramTimedOut(ProgramState):
    pass
