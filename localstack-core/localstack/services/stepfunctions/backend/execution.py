from __future__ import annotations

import datetime
import json
import logging
from typing import Final, Optional

from localstack.aws.api.events import PutEventsRequestEntry
from localstack.aws.api.stepfunctions import (
    Arn,
    CloudWatchEventsExecutionDataDetails,
    DescribeExecutionOutput,
    DescribeStateMachineForExecutionOutput,
    ExecutionListItem,
    ExecutionStatus,
    GetExecutionHistoryOutput,
    HistoryEventList,
    InvalidName,
    SensitiveCause,
    SensitiveError,
    StartExecutionOutput,
    StartSyncExecutionOutput,
    StateMachineType,
    SyncExecutionStatus,
    Timestamp,
    TraceHeader,
)
from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.eval.aws_execution_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    Execution as ContextObjectExecution,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    StateMachine as ContextObjectStateMachine,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramEnded,
    ProgramError,
    ProgramState,
    ProgramStopped,
    ProgramTimedOut,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.execution_worker import (
    ExecutionWorker,
    SyncExecutionWorker,
)
from localstack.services.stepfunctions.backend.execution_worker_comm import (
    ExecutionWorkerCommunication,
)
from localstack.services.stepfunctions.backend.state_machine import (
    StateMachineInstance,
    StateMachineVersion,
)

LOG = logging.getLogger(__name__)


class BaseExecutionWorkerCommunication(ExecutionWorkerCommunication):
    execution: Final[Execution]

    def __init__(self, execution: Execution):
        self.execution = execution

    def _reflect_execution_status(self):
        exit_program_state: ProgramState = self.execution.exec_worker.env.program_state()
        self.execution.stop_date = datetime.datetime.now(tz=datetime.timezone.utc)
        if isinstance(exit_program_state, ProgramEnded):
            self.execution.exec_status = ExecutionStatus.SUCCEEDED
            self.execution.output = self.execution.exec_worker.env.inp
        elif isinstance(exit_program_state, ProgramStopped):
            self.execution.exec_status = ExecutionStatus.ABORTED
        elif isinstance(exit_program_state, ProgramError):
            self.execution.exec_status = ExecutionStatus.FAILED
            self.execution.error = exit_program_state.error.get("error")
            self.execution.cause = exit_program_state.error.get("cause")
        elif isinstance(exit_program_state, ProgramTimedOut):
            self.execution.exec_status = ExecutionStatus.TIMED_OUT
        else:
            raise RuntimeWarning(
                f"Execution ended with unsupported ProgramState type '{type(exit_program_state)}'."
            )

    def terminated(self) -> None:
        self._reflect_execution_status()
        self.execution.publish_execution_status_change_event()


class Execution:
    name: Final[str]
    sm_type: Final[StateMachineType]
    role_arn: Final[Arn]
    exec_arn: Final[Arn]

    account_id: str
    region_name: str

    state_machine: Final[StateMachineInstance]
    start_date: Final[Timestamp]
    input_data: Final[Optional[json]]
    input_details: Final[Optional[CloudWatchEventsExecutionDataDetails]]
    trace_header: Final[Optional[TraceHeader]]
    _cloud_watch_logging_session: Final[Optional[CloudWatchLoggingSession]]

    exec_status: Optional[ExecutionStatus]
    stop_date: Optional[Timestamp]

    output: Optional[json]
    output_details: Optional[CloudWatchEventsExecutionDataDetails]

    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]

    exec_worker: Optional[ExecutionWorker]

    _activity_store: dict[Arn, Activity]

    def __init__(
        self,
        name: str,
        sm_type: StateMachineType,
        role_arn: Arn,
        exec_arn: Arn,
        account_id: str,
        region_name: str,
        state_machine: StateMachineInstance,
        start_date: Timestamp,
        cloud_watch_logging_session: Optional[CloudWatchLoggingSession],
        activity_store: dict[Arn, Activity],
        input_data: Optional[json] = None,
        trace_header: Optional[TraceHeader] = None,
    ):
        self.name = name
        self.sm_type = sm_type
        self.role_arn = role_arn
        self.exec_arn = exec_arn
        self.account_id = account_id
        self.region_name = region_name
        self.state_machine = state_machine
        self.start_date = start_date
        self._cloud_watch_logging_session = cloud_watch_logging_session
        self.input_data = input_data
        self.input_details = CloudWatchEventsExecutionDataDetails(included=True)
        self.trace_header = trace_header
        self.exec_status = None
        self.stop_date = None
        self.output = None
        self.output_details = CloudWatchEventsExecutionDataDetails(included=True)
        self.exec_worker = None
        self.error = None
        self.cause = None
        self._activity_store = activity_store

    def _get_events_client(self):
        return connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).events

    def to_start_output(self) -> StartExecutionOutput:
        return StartExecutionOutput(executionArn=self.exec_arn, startDate=self.start_date)

    def to_describe_output(self) -> DescribeExecutionOutput:
        describe_output = DescribeExecutionOutput(
            executionArn=self.exec_arn,
            stateMachineArn=self.state_machine.arn,
            name=self.name,
            status=self.exec_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
            input=to_json_str(self.input_data, separators=(",", ":")),
            inputDetails=self.input_details,
            traceHeader=self.trace_header,
        )
        if describe_output["status"] == ExecutionStatus.SUCCEEDED:
            describe_output["output"] = to_json_str(self.output, separators=(",", ":"))
            describe_output["outputDetails"] = self.output_details
        if self.error is not None:
            describe_output["error"] = self.error
        if self.cause is not None:
            describe_output["cause"] = self.cause
        return describe_output

    def to_describe_state_machine_for_execution_output(
        self,
    ) -> DescribeStateMachineForExecutionOutput:
        state_machine: StateMachineInstance = self.state_machine
        state_machine_arn = (
            state_machine.source_arn
            if isinstance(state_machine, StateMachineVersion)
            else state_machine.arn
        )
        out = DescribeStateMachineForExecutionOutput(
            stateMachineArn=state_machine_arn,
            name=state_machine.name,
            definition=state_machine.definition,
            roleArn=self.role_arn,
            # The date and time the state machine associated with an execution was updated.
            updateDate=state_machine.create_date,
            loggingConfiguration=state_machine.logging_config,
        )
        revision_id = self.state_machine.revision_id
        if self.state_machine.revision_id:
            out["revisionId"] = revision_id
        return out

    def to_execution_list_item(self) -> ExecutionListItem:
        if isinstance(self.state_machine, StateMachineVersion):
            state_machine_arn = self.state_machine.source_arn
            state_machine_version_arn = self.state_machine.arn
        else:
            state_machine_arn = self.state_machine.arn
            state_machine_version_arn = None

        item = ExecutionListItem(
            executionArn=self.exec_arn,
            stateMachineArn=state_machine_arn,
            name=self.name,
            status=self.exec_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
        )
        if state_machine_version_arn is not None:
            item["stateMachineVersionArn"] = state_machine_version_arn
        return item

    def to_history_output(self) -> GetExecutionHistoryOutput:
        env = self.exec_worker.env
        event_history: HistoryEventList = list()
        if env is not None:
            # The execution has not started yet.
            event_history: HistoryEventList = env.event_manager.get_event_history()
        return GetExecutionHistoryOutput(events=event_history)

    @staticmethod
    def _to_serialized_date(timestamp: datetime.datetime) -> str:
        """See test in tests.aws.services.stepfunctions.v2.base.test_base.TestSnfBase.test_execution_dateformat"""
        return (
            f'{timestamp.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
        )

    def _get_start_execution_worker_comm(self) -> BaseExecutionWorkerCommunication:
        return BaseExecutionWorkerCommunication(self)

    def _get_start_context_object_init_data(self) -> ContextObjectInitData:
        return ContextObjectInitData(
            Execution=ContextObjectExecution(
                Id=self.exec_arn,
                Input=self.input_data,
                Name=self.name,
                RoleArn=self.role_arn,
                StartTime=self._to_serialized_date(self.start_date),
            ),
            StateMachine=ContextObjectStateMachine(
                Id=self.state_machine.arn,
                Name=self.state_machine.name,
            ),
        )

    def _get_start_aws_execution_details(self) -> AWSExecutionDetails:
        return AWSExecutionDetails(
            account=self.account_id, region=self.region_name, role_arn=self.role_arn
        )

    def _get_start_execution_worker(self) -> ExecutionWorker:
        return ExecutionWorker(
            execution_type=self.sm_type,
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=self._get_start_execution_worker_comm(),
            context_object_init=self._get_start_context_object_init_data(),
            aws_execution_details=self._get_start_aws_execution_details(),
            cloud_watch_logging_session=self._cloud_watch_logging_session,
            activity_store=self._activity_store,
        )

    def start(self) -> None:
        # TODO: checks exec_worker does not exists already?
        if self.exec_worker:
            raise InvalidName()  # TODO.
        self.exec_worker = self._get_start_execution_worker()
        self.exec_status = ExecutionStatus.RUNNING
        self.publish_execution_status_change_event()
        self.exec_worker.start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        exec_worker: Optional[ExecutionWorker] = self.exec_worker
        if exec_worker:
            exec_worker.stop(stop_date=stop_date, cause=cause, error=error)

    def publish_execution_status_change_event(self):
        input_value = (
            dict() if not self.input_data else to_json_str(self.input_data, separators=(",", ":"))
        )
        output_value = (
            None if self.output is None else to_json_str(self.output, separators=(",", ":"))
        )
        output_details = None if output_value is None else self.output_details
        entry = PutEventsRequestEntry(
            Source="aws.states",
            Resources=[self.exec_arn],
            DetailType="Step Functions Execution Status Change",
            Detail=to_json_str(
                # Note: this operation carries significant changes from a describe_execution request.
                DescribeExecutionOutput(
                    executionArn=self.exec_arn,
                    stateMachineArn=self.state_machine.arn,
                    stateMachineAliasArn=None,
                    stateMachineVersionArn=None,
                    name=self.name,
                    status=self.exec_status,
                    startDate=self.start_date,
                    stopDate=self.stop_date,
                    input=input_value,
                    inputDetails=self.input_details,
                    output=output_value,
                    outputDetails=output_details,
                    error=self.error,
                    cause=self.cause,
                )
            ),
        )
        try:
            self._get_events_client().put_events(Entries=[entry])
        except Exception:
            LOG.exception(
                "Unable to send notification of Entry='%s' for Step Function execution with Arn='%s' to EventBridge.",
                entry,
                self.exec_arn,
            )


class SyncExecutionWorkerCommunication(BaseExecutionWorkerCommunication):
    execution: Final[SyncExecution]

    def _reflect_execution_status(self) -> None:
        super()._reflect_execution_status()
        exit_status: ExecutionStatus = self.execution.exec_status
        if exit_status == ExecutionStatus.SUCCEEDED:
            self.execution.sync_execution_status = SyncExecutionStatus.SUCCEEDED
        elif exit_status == ExecutionStatus.TIMED_OUT:
            self.execution.sync_execution_status = SyncExecutionStatus.TIMED_OUT
        else:
            self.execution.sync_execution_status = SyncExecutionStatus.FAILED


class SyncExecution(Execution):
    sync_execution_status: Optional[SyncExecutionStatus] = None

    def _get_start_execution_worker(self) -> SyncExecutionWorker:
        return SyncExecutionWorker(
            execution_type=self.sm_type,
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=self._get_start_execution_worker_comm(),
            context_object_init=self._get_start_context_object_init_data(),
            aws_execution_details=self._get_start_aws_execution_details(),
            cloud_watch_logging_session=self._cloud_watch_logging_session,
            activity_store=self._activity_store,
        )

    def _get_start_execution_worker_comm(self) -> BaseExecutionWorkerCommunication:
        return SyncExecutionWorkerCommunication(self)

    def to_start_sync_execution_output(self) -> StartSyncExecutionOutput:
        start_output = StartSyncExecutionOutput(
            executionArn=self.exec_arn,
            stateMachineArn=self.state_machine.arn,
            name=self.name,
            status=self.sync_execution_status,
            startDate=self.start_date,
            stopDate=self.stop_date,
            input=to_json_str(self.input_data, separators=(",", ":")),
            inputDetails=self.input_details,
            traceHeader=self.trace_header,
        )
        if self.sync_execution_status == SyncExecutionStatus.SUCCEEDED:
            start_output["output"] = to_json_str(self.output, separators=(",", ":"))
        if self.output_details:
            start_output["outputDetails"] = self.output_details
        if self.error is not None:
            start_output["error"] = self.error
        if self.cause is not None:
            start_output["cause"] = self.cause
        return start_output
