import dataclasses
import logging
import uuid
from concurrent.futures import Future
from datetime import datetime
from queue import Queue
from typing import TYPE_CHECKING, Dict, Optional

from localstack.services.awslambda.invocation.executor_endpoint import (
    ExecutorEndpoint,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.runtime_handler import RuntimeEnvironment
from localstack.utils.common import get_free_tcp_port

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import (
        FunctionVersion,
        Invocation,
        LambdaRuntimeConfig,
    )


LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class InvocationStorage:
    invocation_id: str
    result_future: Future
    retries: int
    invocation: "Invocation"


@dataclasses.dataclass
class RunningInvocation:
    invocation: InvocationStorage
    start_time: datetime
    executor: RuntimeEnvironment


@dataclasses.dataclass
class InvocationResult:
    invocation_id: str
    payload: Optional[bytes]


@dataclasses.dataclass
class InvocationError:
    invocation_id: str
    payload: Optional[bytes]
    stacktrace: Optional[str]


class LambdaVersionManager(ServiceEndpoint):
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: "FunctionVersion"
    # mapping from invocation id to invocation storage
    running_invocations: Dict[str, RunningInvocation]
    available_environments: Dict[str, RuntimeEnvironment]
    queued_invocations: Queue
    reserved_concurrent_executions: int
    executor_endpoint: Optional[ExecutorEndpoint]

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
        self.available_environments = {}
        self.queued_invocations = Queue()
        self.reserved_concurrent_executions = 0

    def _build_executor_endpoint(self) -> ExecutorEndpoint:
        port = get_free_tcp_port()
        executor_endpoint = ExecutorEndpoint(port, service_endpoint=self)
        executor_endpoint.start()
        return executor_endpoint

    def init(self) -> None:
        self.executor_endpoint = self._build_executor_endpoint()

    def update_reserved_concurrency_config(self, reserved_concurrent_executions: int) -> None:
        self.reserved_concurrent_executions = reserved_concurrent_executions
        # TODO initialize/destroy runners if applicable

    def invoke(self, *, invocation: "Invocation") -> Future:
        invocation_storage = InvocationStorage(
            invocation_id=str(uuid.uuid4()),
            result_future=Future(),
            retries=1,
            invocation=invocation,
        )
        self.queued_invocations.put(invocation_storage)
        return invocation_storage.result_future

    def get_next_invocation(self, executor_id: str) -> InvocationStorage:
        """
        Get the next event queued for this version.
        This may block until an event is available
        :param executor_id ID of the executor requesting the event
        :return: Event & context
        """
        executor = self.available_environments.get(executor_id)
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

    def invocation_result(self, request_id: str, invocation_result: InvocationResult):
        pass

    def invocation_error(self, request_id: str, invocation_error: InvocationError):
        pass
