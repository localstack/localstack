from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails
from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState


class ProgramError(ProgramState):
    def __init__(self, error: ExecutionFailedEventDetails):
        super().__init__()
        self.error: ExecutionFailedEventDetails = error
