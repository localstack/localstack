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
from localstack.services.stepfunctions.backend.execution_worker import ExecutionWorker
from localstack.services.stepfunctions.backend.state_machine import StateMachine


class Execution:
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
        self.name: Final[str] = name
        self.role_arn: Final[Arn] = role_arn
        self.exec_arn: Final[Arn] = exec_arn
        self.state_machine: Final[StateMachine] = state_machine
        self.start_date: Final[Timestamp] = start_date
        self.input_data: Final[Optional[dict]] = input_data
        self.input_details: Final[Optional[CloudWatchEventsExecutionDataDetails]] = input_details
        self.trace_header: Final[Optional[TraceHeader]] = trace_header

        self.exec_status: Optional[ExecutionStatus] = None
        self.stop_date: Optional[Timestamp] = None

        self.output: Optional[SensitiveData] = None
        self.output_details: Optional[CloudWatchEventsExecutionDataDetails] = None

        self.exec_worker: Optional[ExecutionWorker] = None

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
        self.exec_status = ExecutionStatus.ABORTED  # TODO: what state?
        self.stop_date = stop_date
        exec_worker.stop(stop_date=stop_date, cause=cause, error=error)
