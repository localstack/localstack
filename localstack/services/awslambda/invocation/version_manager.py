import dataclasses
import logging
import uuid
from concurrent.futures import Future
from datetime import datetime
from queue import Queue
from typing import Dict, Optional

from localstack.services.awslambda.invocation.lambda_service import FunctionVersion
from localstack.services.awslambda.invocation.runtime_executor import RuntimeExecutor

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class InvocationStorage:
    invocation_id: str
    result_future: Future
    retries: int
    payload: bytes
    client_context: str


@dataclasses.dataclass
class RunningInvocation:
    invocation: InvocationStorage
    start_time: datetime
    executor: RuntimeExecutor


class LambdaVersionManager:
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: FunctionVersion
    # mapping from invocation id to invocation storage
    running_invocations: Dict[str, RunningInvocation]
    running_executors: Dict[str, RuntimeExecutor]
    queued_invocations: Queue

    def __init__(self, function_arn: str, function_configuration: FunctionVersion):
        self.function_arn = function_arn
        self.function_configuration = function_configuration
        self.running_invocations = {}
        self.running_executors = {}
        self.queued_invocations = Queue()

    def init(self):
        # TODO initialized reserved concurrency
        pass

    def invoke(
        self,
        *,
        payload: Optional[bytes],
        client_context: Optional[str],
        invocation_type: Optional[str],
    ) -> Future:
        invocation = InvocationStorage(
            invocation_id=str(uuid.uuid4()),
            result_future=Future(),
            retries=1,
            payload=payload,
            client_context=client_context,
        )
        self.queued_invocations.put(invocation)
        return invocation.result_future

    def get_next_invocation(self, executor_id: str) -> InvocationStorage:
        """
        Get the next event queued for this version.
        This may block until an event is available
        :param executor_id ID of the executor requesting the event
        :return: Event & context
        """
        executor = self.running_executors.get(executor_id)
        if not executor:
            LOG.warning(
                "Executor '%s' is not available anymore. Skipping the event request...", executor_id
            )
            raise Exception("Executor not available")  # TODO proper exception handling

        # get invocation and wrap it
        invocation = self.queued_invocations.get()
        self.running_invocations[invocation.invocation_id] = RunningInvocation(
            invocation, datetime.now(), executor=executor
        )
        return invocation
