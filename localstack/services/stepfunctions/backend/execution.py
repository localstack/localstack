from __future__ import annotations

import datetime
import json
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    CloudWatchEventsExecutionDataDetails,
    DescribeExecutionOutput,
    ExecutionListItem,
    ExecutionStatus,
    GetExecutionHistoryOutput,
    HistoryEventList,
    InvalidName,
    SensitiveData,
    StartExecutionOutput,
    Timestamp,
    TraceHeader,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    Execution as ContextObjectExecution,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    StateMachine as ContextObjectStateMachine,
)
from localstack.services.stepfunctions.asl.eval.programstate.program_ended import ProgramEnded
from localstack.services.stepfunctions.asl.eval.programstate.program_error import ProgramError
from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState
from localstack.services.stepfunctions.asl.eval.programstate.program_stopped import ProgramStopped
from localstack.services.stepfunctions.backend.execution_worker import ExecutionWorker
from localstack.services.stepfunctions.backend.execution_worker_comm import ExecutionWorkerComm
from localstack.services.stepfunctions.backend.state_machine import StateMachine


class Execution:
    class BaseExecutionWorkerComm(ExecutionWorkerComm):
        def __init__(self, execution: Execution):
            self.execution: Execution = execution

        def terminated(self) -> None:
            exit_program_state: ProgramState = self.execution.exec_worker.env.program_state()
            self.execution.stop_date = datetime.datetime.now()
            self.execution.output = json.dumps(self.execution.exec_worker.env.inp)
            if isinstance(exit_program_state, ProgramEnded):
                self.execution.exec_status = ExecutionStatus.SUCCEEDED
            elif isinstance(exit_program_state, ProgramStopped):
                self.execution.exec_status = ExecutionStatus.ABORTED
            elif isinstance(exit_program_state, ProgramError):
                self.execution.exec_status = ExecutionStatus.FAILED
            else:
                raise RuntimeWarning(
                    f"Execution ended with unsupported ProgramState type '{type(exit_program_state)}'."
                )

    name: Final[str]
    role_arn: Final[Arn]
    exec_arn: Final[Arn]
    state_machine: Final[StateMachine]
    start_date: Final[Timestamp]
    input_data: Final[Optional[dict]]
    input_details: Final[Optional[CloudWatchEventsExecutionDataDetails]]
    trace_header: Final[Optional[TraceHeader]]

    exec_status: Optional[ExecutionStatus]
    stop_date: Optional[Timestamp]

    output: Optional[SensitiveData]
    output_details: Optional[CloudWatchEventsExecutionDataDetails]

    exec_worker: Optional[ExecutionWorker]

    def __init__(
        self,
        name: str,
        role_arn: Arn,
        exec_arn: Arn,
        state_machine: StateMachine,
        start_date: Timestamp,
        input_data: Optional[dict] = None,
        input_details: Optional[CloudWatchEventsExecutionDataDetails] = None,
        trace_header: Optional[TraceHeader] = None,
    ):
        self.name = name
        self.role_arn = role_arn
        self.exec_arn = exec_arn
        self.state_machine = state_machine
        self.start_date = start_date
        self.input_data = input_data
        self.input_details = input_details
        self.trace_header = trace_header
        self.exec_status = None
        self.stop_date = None
        self.output = None
        self.output_details = None
        self.exec_worker = None

    def to_start_output(self) -> StartExecutionOutput:
        return StartExecutionOutput(executionArn=self.exec_arn, startDate=self.start_date)

    def to_describe_output(self) -> DescribeExecutionOutput:
        return DescribeExecutionOutput(
            executionArn=self.exec_arn,
            stateMachineArn=self.state_machine.arn,
            name=self.state_machine.name,
            status=self.exec_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
            input=json.dumps(self.input_data),
            inputDetails=self.input_details,
            output=self.output,
            outputDetails=self.output_details,
            traceHeader=self.trace_header,
        )

    def to_execution_list_item(self) -> ExecutionListItem:
        return ExecutionListItem(
            executionArn=self.exec_arn,
            stateMachineArn=self.state_machine.arn,
            name=self.name,
            status=self.exec_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
        )

    def to_history_output(self) -> GetExecutionHistoryOutput:
        event_history: HistoryEventList = self.exec_worker.env.event_history.get_event_history()
        return GetExecutionHistoryOutput(events=event_history)

    def start(self) -> None:
        # TODO: checks exec_worker does not exists already?
        if self.exec_worker:
            raise InvalidName()  # TODO.

        self.exec_worker = ExecutionWorker(
            role_arn=self.role_arn,
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=Execution.BaseExecutionWorkerComm(self),
            context_object_init=ContextObjectInitData(
                Execution=ContextObjectExecution(
                    Id="TODO",
                    Input=self.input_data,
                    Name=self.state_machine.name,
                    RoleArn="TODO",
                    StartTime=self.start_date.time().isoformat(),
                ),
                StateMachine=ContextObjectStateMachine(
                    Id="TODO",
                    Name=self.state_machine.name,
                ),
            ),
        )
        self.exec_status = ExecutionStatus.RUNNING
        self.exec_worker.start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        exec_worker: Optional[ExecutionWorker] = self.exec_worker
        if not exec_worker:
            raise RuntimeError("No running executions.")
        exec_worker.stop(stop_date=stop_date, cause=cause, error=error)
