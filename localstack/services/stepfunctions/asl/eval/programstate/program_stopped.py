from typing import Optional

from localstack.aws.api.stepfunctions import Timestamp
from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState


class ProgramStopped(ProgramState):
    def __init__(self, stop_date: Timestamp, error: Optional[str], cause: Optional[str]):
        super().__init__()
        self.stop_date: Timestamp = stop_date
        self.error: Optional[str] = error
        self.cause: Optional[str] = cause
