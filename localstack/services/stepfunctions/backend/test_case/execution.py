from __future__ import annotations

import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import Arn, TestStateOutput, Timestamp
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.execution import BaseExecutionWorkerComm, Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachineInstance
from localstack.services.stepfunctions.backend.test_case.execution_worker import (
    TestCaseExecutionWorker,
)


class TestCaseExecution(Execution):
    _TEST_CASE_EXECUTION_TIMEOUT_SECONDS: Final[int] = 300  # 5 minutes.

    _execution_terminated_event: Final[threading.Event]

    class TestCaseExecutionWorkerComm(BaseExecutionWorkerComm):
        _execution: TestCaseExecution

        def terminated(self) -> None:
            self._reflect_execution_status()
            self._execution._execution_terminated_event.set()

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

    def _get_start_execution_worker(self) -> TestCaseExecutionWorker:
        return TestCaseExecutionWorker(
            definition=self.state_machine.definition,
            input_data=self.input_data,
            exec_comm=self._get_start_execution_worker_comm(),
            context_object_init=self._get_start_context_object_init_data(),
            aws_execution_details=self._get_start_aws_execution_details(),
        )

    def start(self) -> None:
        super().start()
        self._execution_terminated_event.wait(timeout=self._TEST_CASE_EXECUTION_TIMEOUT_SECONDS)

    def publish_execution_status_change_event(self):
        # Do not publish execution status change events during test state execution.
        pass

    def to_test_state_output(self) -> TestStateOutput:
        return TestStateOutput(
            output=to_json_str(self.output),
        )
