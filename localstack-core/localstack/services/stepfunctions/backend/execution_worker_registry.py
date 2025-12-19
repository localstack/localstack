from localstack.aws.api.stepfunctions import Arn
from localstack.services.stepfunctions.backend.execution_worker import ExecutionWorker
from localstack.utils.objects import singleton_factory


class ExecutionWorkerRegistry:
    """
    This registry maintains a mapping from execution ARNs to their corresponding
    ExecutionWorker instances. We keep workers separated from Execution to properly separate data and runtime
    components.
    """

    worker: dict[Arn, ExecutionWorker]

    def __init__(self):
        self.worker = {}

    def register(self, exec_arn: Arn, worker: ExecutionWorker) -> None:
        self.worker[exec_arn] = worker

    def get(self, exec_arn: Arn) -> ExecutionWorker | None:
        return self.worker.get(exec_arn)


@singleton_factory
def get_execution_worker_registry() -> ExecutionWorkerRegistry:
    return ExecutionWorkerRegistry()
