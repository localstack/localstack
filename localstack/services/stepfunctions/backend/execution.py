from __future__ import annotations

import datetime
from collections import OrderedDict
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    CloudWatchEventsExecutionDataDetails,
    DescribeExecutionOutput,
    EventId,
    ExecutionListItem,
    ExecutionStatus,
    ExecutionSucceededEventDetails,
    GetExecutionHistoryOutput,
    HistoryEvent,
    HistoryEventType,
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
from localstack.services.stepfunctions.backend.execution_event import ExecutionEvent
from localstack.services.stepfunctions.backend.execution_worker import (
    ExecutionWorker,
    ExecutionWorkerComm,
)
from localstack.services.stepfunctions.backend.state_machine import StateMachine


# TODO: add Event support.
class Execution:
    # TODO: see interface's todos.
    class BaseExecutionWorkerComm(ExecutionWorkerComm):
        def __init__(self, execution: Execution):
            self.execution: Execution = execution

        def succeed(self, result_data: Optional[SensitiveData]):
            # TODO: add support for output event details.
            self.execution.exec_status = ExecutionStatus.SUCCEEDED
            self.execution.output = result_data
            event = ExecutionEvent(
                timestamp=datetime.datetime.now(),
                event_type=HistoryEventType.ActivitySucceeded,
            )
            event.execution_succeeded_event_details = ExecutionSucceededEventDetails(
                output=result_data
            )
            self.execution.add_event(event)

    def __init__(
        self,
        exec_arn: Arn,
        state_machine: StateMachine,
        start_date: Timestamp,
        input_data: Optional[SensitiveData] = None,
        input_details: Optional[CloudWatchEventsExecutionDataDetails] = None,
        trace_header: Optional[TraceHeader] = None,
    ):
        self.exec_arn: Final[Arn] = exec_arn
        self.state_machine: Final[StateMachine] = state_machine
        self.start_date: Final[Timestamp] = start_date
        self.input_data: Final[Optional[SensitiveData]] = input_data
        self.input_details: Final[Optional[CloudWatchEventsExecutionDataDetails]] = input_details
        self.trace_header: Final[Optional[TraceHeader]] = trace_header

        self.exec_status: Optional[ExecutionStatus] = None  # TODO
        self.stop_date: Optional[Timestamp] = None

        self.output: Optional[SensitiveData] = None
        self.output_details: Optional[CloudWatchEventsExecutionDataDetails] = None

        self.exec_worker: Optional[ExecutionWorker] = None

        self._events: OrderedDict[EventId, ExecutionEvent] = OrderedDict()

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
            input=self.input_data,
            inputDetails=self.input_details,
            output=self.output,
            outputDetails=self.output_details,
            traceHeader=self.trace_header,
        )

    def to_execution_list_item(self) -> ExecutionListItem:
        return ExecutionListItem(
            executionArn=self.exec_arn,
            stateMachineArn=self.state_machine.arn,
            name=self.state_machine.name,
            status=self.exec_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
        )

    def to_history_output(self) -> GetExecutionHistoryOutput:
        events: list[HistoryEvent] = [event.to_history_event() for event in self._events.values()]
        return GetExecutionHistoryOutput(events=events)

    def start(self) -> None:
        # TODO: checks exec_worker does not exists already?
        if self.exec_worker:
            raise InvalidName()  # TODO.

        self.exec_worker = ExecutionWorker(
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

    def add_event(self, event: ExecutionEvent) -> None:
        # TODO: eventId workflow.
        event_id = len(self._events)
        event.event_id = event_id
        self._events[event_id] = event

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        # TODO: timeout to force timeout?
        exec_worker: Optional[ExecutionWorker] = self.exec_worker
        if not exec_worker:
            raise RuntimeError("No running executions.")
        self.exec_status = ExecutionStatus.ABORTED  # TODO: what state?
        self.stop_date = stop_date
        exec_worker.stop(stop_date=stop_date, cause=cause, error=error)
