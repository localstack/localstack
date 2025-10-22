from typing import Final

from localstack.services.stepfunctions.asl.eval.program_state import ProgramState


class ProgramChoiceSelected(ProgramState):
    next_state_name: Final[str]

    def __init__(self, next_state_name: str):
        super().__init__()
        self.next_state_name = next_state_name


class ProgramCaughtError(ProgramState):
    next_state_name: Final[str]
    error: Final[str]
    cause: Final[str]

    def __init__(self, next_state_name: str, error: str, cause: str):
        super().__init__()
        self.next_state_name = next_state_name
        self.error = error
        self.cause = cause


class ProgramRetriable(ProgramState):
    error: Final[str]
    cause: Final[str]

    def __init__(self, error: str, cause: str):
        super().__init__()
        self.error = error
        self.cause = cause
