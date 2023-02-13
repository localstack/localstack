from typing import Optional

from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState


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
