from collections import OrderedDict

from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachine


# TODO
class StepfunctionsBackend:
    def __init__(self):
        self.sm_by_arn: dict[str, StateMachine] = dict()
        self.execs_by_exec_arn: dict[str, Execution] = OrderedDict()
