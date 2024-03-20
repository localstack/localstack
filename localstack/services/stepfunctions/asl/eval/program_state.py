import abc
from typing import Final, Optional

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, Timestamp


class ProgramState(abc.ABC): ...


class ProgramEnded(ProgramState):
    pass


class ProgramStopped(ProgramState):
    def __init__(self, stop_date: Timestamp, error: Optional[str], cause: Optional[str]):
        super().__init__()
        self.stop_date: Timestamp = stop_date
        self.error: Optional[str] = error
        self.cause: Optional[str] = cause


class ProgramRunning(ProgramState):
    def __init__(self):
        super().__init__()
        self._next_state_name: Optional[str] = None

    @property
    def next_state_name(self) -> str:
        next_state_name = self._next_state_name
        if next_state_name is None:
            raise RuntimeError("Could not retrieve NextState from uninitialised ProgramState.")
        return next_state_name

    @next_state_name.setter
    def next_state_name(self, next_state_name) -> None:
        if not self._validate_next_state_name(next_state_name):
            raise ValueError(f"No such NextState '{next_state_name}'.")
        self._next_state_name = next_state_name

    @staticmethod
    def _validate_next_state_name(next_state_name: Optional[str]) -> bool:
        # TODO.
        return bool(next_state_name)


class ProgramError(ProgramState):
    error: Final[Optional[ExecutionFailedEventDetails]]

    def __init__(self, error: Optional[ExecutionFailedEventDetails]):
        super().__init__()
        self.error = error


class ProgramTimedOut(ProgramState):
    pass
