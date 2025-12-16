import logging
from datetime import datetime

from localstack.aws.api.stepfunctions import Arn, ExecutionStatus
from localstack.services.stepfunctions.asl.eval.evaluation_details import EvaluationDetails
from localstack.services.stepfunctions.backend.execution import Execution, SyncExecution
from localstack.services.stepfunctions.backend.execution_worker import (
    ExecutionWorker,
    SyncExecutionWorker,
)

LOG = logging.getLogger(__name__)


class ExecutionWorkerManager:
    arn_to_execution_and_worker: dict[Arn, tuple[Execution, ExecutionWorker]]

    def __init__(self):
        self.arn_to_execution_and_worker = {}

    def create_execution_worker(self, execution: Execution) -> ExecutionWorker:
        match execution:
            case SyncExecution():
                worker = SyncExecutionWorker(
                    evaluation_details=EvaluationDetails(
                        aws_execution_details=execution._get_start_aws_execution_details(),
                        execution_details=execution.get_start_execution_details(),
                        state_machine_details=execution.get_start_state_machine_details(),
                    ),
                    exec_comm=execution._get_start_execution_worker_comm(),
                    cloud_watch_logging_session=execution._cloud_watch_logging_session,
                    activity_store=execution._activity_store,
                    local_mock_test_case=execution.local_mock_test_case,
                )
            case _:
                worker = ExecutionWorker(
                    evaluation_details=EvaluationDetails(
                        aws_execution_details=execution._get_start_aws_execution_details(),
                        execution_details=execution.get_start_execution_details(),
                        state_machine_details=execution.get_start_state_machine_details(),
                    ),
                    exec_comm=execution._get_start_execution_worker_comm(),
                    cloud_watch_logging_session=execution._cloud_watch_logging_session,
                    # TODO: This is not good would need to get removed
                    activity_store=execution._activity_store,
                    local_mock_test_case=execution.local_mock_test_case,
                )
        self.arn_to_execution_and_worker[execution.exec_arn] = (execution, worker)
        return worker

    def start_worker(self, arn: Arn) -> None:
        if not self.arn_to_execution_and_worker.get(arn):
            return None

        execution, worker = self.arn_to_execution_and_worker[arn]
        execution.exec_status = ExecutionStatus.RUNNING
        execution.publish_execution_status_change_event()
        return worker.start()

    def stop_worker(
        self, arn: Arn, stop_date: datetime, error: str | None = None, cause: str | None = None
    ) -> None:
        if not self.arn_to_execution_and_worker.get(arn):
            return None

        _, worker = self.arn_to_execution_and_worker[arn]
        if worker:
            worker.stop(stop_date=stop_date, cause=cause, error=error)
        return None
