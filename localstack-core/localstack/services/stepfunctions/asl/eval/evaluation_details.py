from typing import Any, Final, Optional

from localstack.aws.api.stepfunctions import Arn, Definition, LongArn, StateMachineType


class AWSExecutionDetails:
    account: Final[str]
    region: Final[str]
    role_arn: Final[str]

    def __init__(self, account: str, region: str, role_arn: str):
        self.account = account
        self.region = region
        self.role_arn = role_arn


class ExecutionDetails:
    arn: Final[LongArn]
    name: Final[str]
    role_arn: Final[Arn]
    inpt: Final[Optional[Any]]
    start_time: Final[str]

    def __init__(
        self, arn: LongArn, name: str, role_arn: Arn, inpt: Optional[Any], start_time: str
    ):
        self.arn = arn
        self.name = name
        self.role_arn = role_arn
        self.inpt = inpt
        self.start_time = start_time


class StateMachineDetails:
    arn: Final[Arn]
    name: Final[str]
    typ: Final[StateMachineType]
    definition: Final[Definition]

    def __init__(self, arn: Arn, name: str, typ: StateMachineType, definition: str):
        self.arn = arn
        self.name = name
        self.typ = typ
        self.definition = definition


class EvaluationDetails:
    aws_execution_details: Final[AWSExecutionDetails]
    execution_details: Final[ExecutionDetails]
    state_machine_details: Final[StateMachineDetails]

    def __init__(
        self,
        aws_execution_details: AWSExecutionDetails,
        execution_details: ExecutionDetails,
        state_machine_details: StateMachineDetails,
    ):
        self.aws_execution_details = aws_execution_details
        self.execution_details = execution_details
        self.state_machine_details = state_machine_details
