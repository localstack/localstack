from typing import Final

from localstack.services.stepfunctions.asl.eval.program_state import ProgramState


class ProgramChoiceSelected(ProgramState):
    next_state_name: Final[str]

    def __init__(self, next_state_name: str):
        super().__init__()
        self.next_state_name = next_state_name
