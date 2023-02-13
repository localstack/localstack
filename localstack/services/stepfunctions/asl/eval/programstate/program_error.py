from typing import Any

from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState


class ProgramError(ProgramState):
    def __init__(self, error: Any):
        super().__init__()
        self.error: Any = error
