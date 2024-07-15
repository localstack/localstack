from __future__ import annotations

import logging
import threading
from typing import Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    ExecutionStatus,
    InspectionLevel,
    StateMachineType,
    TestExecutionStatus,
    TestStateOutput,
    Timestamp,
)
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramEnded,
    ProgramError,
    ProgramState,
)
from localstack.services.stepfunctions.asl.eval.test_state.program_state import (
    ProgramChoiceSelected,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.execution import (
    BaseExecutionWorkerCommunication,
    Execution,
)
from localstack.services.stepfunctions.backend.state_machine import StateMachineInstance
from localstack.services.stepfunctions.backend.test_state.execution_worker import (
    TestStateExecutionWorker,
)

LOG = logging.getLogger(__name__)


class TestStateExecution(Execution):
    exec_worker: Optional[TestStateExecutionWorker]
    next_state: Optional[str]

    class TestCaseExecutionWorkerCommunication(BaseExecutionWorkerCommunication):
        _execution: TestStateExecution

        def terminated(self) -> None:
            exit_program_state: ProgramState = self.execution.exec_worker.env.program_state()
            if isinstance(exit_program_state, ProgramChoiceSelected):
                self.execution.exec_status = ExecutionStatus.SUCCEEDED
                self.execution.output = self.execution.exec_worker.env.inp
                self.execution.next_state = exit_program_state.next_state_name
            else:
                self._reflect_execution_status()

    def __init__(
        self,
        name: str,
        role_arn: Arn,
        exec_arn: Arn,
        account_id: str,
        region_name: str,
        state_machine: StateMachineInstance,
        start_date: Timestamp,
        activity_store: dict[Arn, Activity],
        input_data: Optional[dict] = None,
    ):
        super().__init__(
            name=name,
            sm_type=StateMachineType.STANDARD,
            role_arn=role_arn,
            exec_arn=exec_arn,
            account_id=account_id,
            region_name=region_name,
            state_machine=state_machine,
            start_date=start_date,
            activity_store=activity_store,
            input_data=input_data,
            cloud_watch_logging_session=None,
            trace_header=None,
        )
        self._execution_terminated_event = threading.Event()
        self.next_state = None

    def _get_start_execution_worker_comm(self) -> BaseExecutionWorkerCommunication:
        return self.TestCaseExecutionWorkerCommunication(self)

    def _get_start_execution_worker(self) -> TestStateExecutionWorker:
        return TestStateExecutionWorker(
            execution_type=StateMachineType.STANDARD,
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=self._get_start_execution_worker_comm(),
            context_object_init=self._get_start_context_object_init_data(),
            aws_execution_details=self._get_start_aws_execution_details(),
            cloud_watch_logging_session=None,
            activity_store=self._activity_store,
        )

    def publish_execution_status_change_event(self):
        # Do not publish execution status change events during test state execution.
        pass

    def to_test_state_output(self, inspection_level: InspectionLevel) -> TestStateOutput:
        exit_program_state: ProgramState = self.exec_worker.env.program_state()
        if isinstance(exit_program_state, ProgramEnded):
            output_str = to_json_str(self.output)
            test_state_output = TestStateOutput(
                status=TestExecutionStatus.SUCCEEDED, output=output_str
            )
        elif isinstance(exit_program_state, ProgramError):
            test_state_output = TestStateOutput(
                status=TestExecutionStatus.FAILED,
                error=exit_program_state.error["error"],
                cause=exit_program_state.error["cause"],
            )
        elif isinstance(exit_program_state, ProgramChoiceSelected):
            output_str = to_json_str(self.output)
            test_state_output = TestStateOutput(
                status=TestExecutionStatus.SUCCEEDED, nextState=self.next_state, output=output_str
            )
        else:
            # TODO: handle other statuses
            LOG.warning(
                f"Unsupported StateMachine exit type for TestState '{type(exit_program_state)}'"
            )
            output_str = to_json_str(self.output)
            test_state_output = TestStateOutput(
                status=TestExecutionStatus.FAILED, output=output_str
            )

        match inspection_level:
            case InspectionLevel.TRACE:
                test_state_output["inspectionData"] = self.exec_worker.env.inspection_data
            case InspectionLevel.DEBUG:
                test_state_output["inspectionData"] = self.exec_worker.env.inspection_data

        return test_state_output
