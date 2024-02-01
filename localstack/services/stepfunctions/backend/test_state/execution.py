from __future__ import annotations

import logging
import threading
from typing import Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    InspectionLevel,
    TestExecutionStatus,
    TestStateOutput,
    Timestamp,
)
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramEnded,
    ProgramError,
    ProgramState,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.execution import BaseExecutionWorkerComm, Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachineInstance
from localstack.services.stepfunctions.backend.test_state.execution_worker import (
    TestStateExecutionWorker,
)

LOG = logging.getLogger(__name__)

class TestStateExecution(Execution):
    exec_worker: Optional[TestStateExecutionWorker]

    class TestCaseExecutionWorkerComm(BaseExecutionWorkerComm):
        _execution: TestStateExecution

        def terminated(self) -> None:
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
        input_data: Optional[dict] = None,
    ):
        super().__init__(
            name,
            role_arn,
            exec_arn,
            account_id,
            region_name,
            state_machine,
            start_date,
            input_data,
            None,
        )
        self._execution_terminated_event = threading.Event()

    def _get_start_execution_worker_comm(self) -> BaseExecutionWorkerComm:
        return self.TestCaseExecutionWorkerComm(self)

    def _get_start_execution_worker(self) -> TestStateExecutionWorker:
        return TestStateExecutionWorker(
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=self._get_start_execution_worker_comm(),
            context_object_init=self._get_start_context_object_init_data(),
            aws_execution_details=self._get_start_aws_execution_details(),
        )

    def publish_execution_status_change_event(self):
        # Do not publish execution status change events during test state execution.
        pass

    def to_test_state_output(self, inspection_level: InspectionLevel) -> TestStateOutput:
        exit_program_state: ProgramState = self.exec_worker.env.program_state()
        if isinstance(exit_program_state, ProgramEnded):
            output_str = to_json_str(self.output)
            test_state_output = TestStateOutput(status=TestExecutionStatus.SUCCEEDED, output=output_str)
        elif isinstance(exit_program_state, ProgramError):
            test_state_output = TestStateOutput(status=TestExecutionStatus.FAILED, error=exit_program_state.error["error"], cause=exit_program_state.error["cause"])
        else:
            # TODO: handle other statuses
            LOG.warning(f"Unsupported StateMachine exit type for TestState '{type(exit_program_state)}'")
            output_str = to_json_str(self.output)
            test_state_output = TestStateOutput(status=TestExecutionStatus.FAILED, output=output_str)

        match inspection_level:
            case InspectionLevel.TRACE:
                test_state_output["inspectionData"] = self.exec_worker.env.inspection_data
            case InspectionLevel.DEBUG:
                test_state_output["inspectionData"] = self.exec_worker.env.inspection_data

        return test_state_output
