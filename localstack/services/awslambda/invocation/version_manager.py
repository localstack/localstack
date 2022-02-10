import dataclasses
import logging
import uuid
from concurrent.futures import Future
from datetime import datetime
from queue import Queue
from typing import TYPE_CHECKING, Dict, Optional

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import (
        FunctionVersion,
        LambdaRuntimeConfig,
    )

from localstack.services.awslambda.invocation.runtime_executor import RuntimeExecutor

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class InvocationStorage:
    invocation_id: str
    result_future: Future
    retries: int
    payload: Optional[bytes]
    client_context: Optional[str]


@dataclasses.dataclass
class RunningInvocation:
    invocation: InvocationStorage
    start_time: datetime
    executor: RuntimeExecutor


class LambdaVersionManager:
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: "FunctionVersion"
    # mapping from invocation id to invocation storage
    running_invocations: Dict[str, RunningInvocation]
    running_executors: Dict[str, RuntimeExecutor]
    queued_invocations: Queue
    reserved_concurrent_executions: int
    runtime_config: "LambdaRuntimeConfig"

    def __init__(
        self,
        function_arn: str,
        function_version: "FunctionVersion",
        runtime_config: "LambdaRuntimeConfig",
    ):
        self.function_arn = function_arn
        self.function_configuration = function_version
        self.runtime_config = runtime_config
        self.running_invocations = {}
        self.running_executors = {}
        self.queued_invocations = Queue()
        self.reserved_concurrent_executions = 0

    def init(self) -> None:
        # TODO initialize runners if applicable
        pass

    def update_reserved_concurrency_config(self, reserved_concurrent_executions: int) -> None:
        self.reserved_concurrent_executions = reserved_concurrent_executions

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
