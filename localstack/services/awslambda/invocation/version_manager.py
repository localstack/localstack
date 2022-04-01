import dataclasses
import logging
import queue
import threading
import uuid
from concurrent.futures import Future
from datetime import datetime
from enum import Enum, auto
from queue import Queue
from threading import Thread
from typing import Dict, List, Optional, Union

from localstack.services.awslambda.invocation.lambda_models import (
    FunctionVersion,
    Invocation,
    InvocationError,
    InvocationLogs,
    InvocationResult,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.runtime_environment import (
    InvalidStatusException,
    RuntimeEnvironment,
    RuntimeStatus,
)
from localstack.services.awslambda.invocation.runtime_executor import (
    cleanup_version,
    prepare_version,
)
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs

LOG = logging.getLogger(__name__)


class ValueNameEnum(Enum):
    def __str__(self):
        return str(self.name)


class State(ValueNameEnum):
    Pending = auto()
    Active = auto()
    Inactive = auto()
    Failed = auto()


class StateReasonCode(ValueNameEnum):
    Idle = auto()
    Creating = auto()
    Restoring = auto()
    InsufficientRolePermissions = auto()
    InvalidConfiguration = auto()
    InternalError = auto()
    InvalidSecurityGroup = auto()
    ImageDeleted = auto()
    ImageAccessDenied = auto()
    InvalidImage = auto()


@dataclasses.dataclass(frozen=True)
class VersionState:
    state: State
    code: Optional[StateReasonCode] = None
    reason: Optional[str] = None


# InvocationResultFuture = Future[InvocationResult]
#
# from typing_extensions import Future


@dataclasses.dataclass(frozen=True)
class QueuedInvocation:
    invocation_id: str
    result_future: "Future[InvocationResult]"
    retries: int
    invocation: Invocation


@dataclasses.dataclass
class RunningInvocation:
    invocation: QueuedInvocation
    start_time: datetime
    executor: RuntimeEnvironment
    logs: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class LogItem:
    log_group: str
    log_stream: str
    logs: str


class ShutdownPill:
    pass


QUEUE_SHUTDOWN = ShutdownPill()


class LogHandler:
    log_queue: "Queue[Union[LogItem, ShutdownPill]]"
    _thread: Optional[Thread]
    _shutdown_event: threading.Event

    def __init__(self) -> None:
        self.log_queue = Queue()
        self._shutdown_event = threading.Event()
        self._thread = None

    def run_log_loop(self) -> None:
        while not self._shutdown_event.is_set():
            log_item = self.log_queue.get()
            if log_item is QUEUE_SHUTDOWN:
                return
            store_cloudwatch_logs(log_item.log_group, log_item.log_stream, log_item.logs)

    def start_subscriber(self) -> None:
        self._thread = Thread(target=self.run_log_loop)
        self._thread.start()

    def add_logs(self, log_item: LogItem) -> None:
        self.log_queue.put(log_item)

    def stop(self) -> None:
        self._shutdown_event.set()
        if self._thread:
            self.log_queue.put(QUEUE_SHUTDOWN)
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                LOG.error("Could not stop log subscriber in time")
            self._thread = None


class LambdaVersionManager(ServiceEndpoint):
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: FunctionVersion
    # mapping from invocation id to invocation storage
    running_invocations: Dict[str, RunningInvocation]
    # stack of available (ready to get invoked) environments
    available_environments: "queue.LifoQueue[Union[RuntimeEnvironment, ShutdownPill]]"
    # mapping environment id -> environment
    all_environments: Dict[str, RuntimeEnvironment]
    # queue of invocations to be executed
    queued_invocations: "Queue[Union[QueuedInvocation, ShutdownPill]]"
    provisioned_concurrent_executions: int
    invocation_thread: Optional[Thread]
    shutdown_event: threading.Event
    state: VersionState
    log_handler: LogHandler

    def __init__(
        self,
        function_arn: str,
        function_version: FunctionVersion,
    ):
        self.function_arn = function_arn
        self.function_version = function_version
        self.running_invocations = {}
        self.available_environments = queue.LifoQueue()
        self.all_environments = {}
        self.queued_invocations = Queue()
        self.provisioned_concurrent_executions = 0
        self.invocation_thread = None
        self.shutdown_event = threading.Event()
        self.state = VersionState(
            state=State.Pending, code=StateReasonCode.Creating, reason="Function starting up"
        )
        self.log_handler = LogHandler()

    def start(self) -> None:
        try:
            invocation_thread = Thread(target=self.invocation_loop)
            invocation_thread.start()
            self.invocation_thread = invocation_thread
            self.log_handler.start_subscriber()
            prepare_version(self.function_version)

            self.state = VersionState(state=State.Active)
            LOG.debug(f"Lambda '{self.function_arn}' changed to active")
        except Exception as e:
            self.state = VersionState(
                state=State.Failed,
                code=StateReasonCode.InternalError,
                reason=f"Error while creating lambda: {e}",
            )
            LOG.debug(
                f"Lambda '{self.function_arn}' changed to failed. Reason: %s", e, exc_info=True
            )

    def stop(self) -> None:
        LOG.debug("Stopping lambda version '%s'", self.function_arn)
        self.state = VersionState(
            state=State.Inactive, code=StateReasonCode.Idle, reason="Shutting down"
        )
        self.shutdown_event.set()
        self.queued_invocations.put(QUEUE_SHUTDOWN)
        self.available_environments.put(QUEUE_SHUTDOWN)
        if self.invocation_thread:
            try:
                self.invocation_thread.join(timeout=5.0)
                LOG.debug("Thread stopped '%s'", self.function_arn)
            except TimeoutError:
                LOG.warning("Thread did not stop after 5s '%s'", self.function_arn)
        for environment in list(self.all_environments.values()):
            self.stop_environment(environment)
        self.log_handler.stop()
        cleanup_version(self.function_version)

    def update_provisioned_concurrency_config(self, provisioned_concurrent_executions: int) -> None:
        self.provisioned_concurrent_executions = provisioned_concurrent_executions
        # TODO initialize/destroy runners if applicable

    def start_environment(self) -> RuntimeEnvironment:
        LOG.debug("Starting new environment")
        runtime_environment = RuntimeEnvironment(
            function_version=self.function_version,
            initialization_type="on-demand",
            service_endpoint=self,
        )
        self.all_environments[runtime_environment.id] = runtime_environment
        # TODO async?
        runtime_environment.start()

        return runtime_environment

    def stop_environment(self, environment: RuntimeEnvironment) -> None:
        try:
            environment.stop()
            self.all_environments.pop(environment.id)
        except Exception as e:
            LOG.debug(
                "Error while stopping environment for lambda %s, environment: %s, error: %s",
                self.function_arn,
                environment.id,
                e,
            )

    def count_environment_by_status(self, status: List[RuntimeStatus]) -> int:
        return len(
            [runtime for runtime in self.all_environments.values() if runtime.status in status]
        )

    def ready_environment_count(self) -> int:
        return self.count_environment_by_status([RuntimeStatus.READY])

    def active_environment_count(self) -> int:
        return self.count_environment_by_status(
            [RuntimeStatus.READY, RuntimeStatus.STARTING, RuntimeStatus.RUNNING]
        )

    def invocation_loop(self) -> None:
        while not self.shutdown_event.is_set():
            queued_invocation = self.queued_invocations.get()
            try:
                if self.shutdown_event.is_set() or queued_invocation is QUEUE_SHUTDOWN:
                    LOG.debug(
                        "Invocation loop for lambda %s stopped while waiting for invocations",
                        self.function_arn,
                    )
                    return
                LOG.debug("Got invocation event %s in loop", queued_invocation.invocation_id)
                # TODO refine environment startup logic
                if self.available_environments.empty() or self.active_environment_count() == 0:
                    self.start_environment()
                environment = None
                while not environment:
                    try:
                        environment = self.available_environments.get(timeout=1)
                        if environment is QUEUE_SHUTDOWN or self.shutdown_event.is_set():
                            LOG.debug(
                                "Invocation loop for lambda %s stopped while waiting for environments",
                                self.function_arn,
                            )
                            return
                        self.running_invocations[
                            queued_invocation.invocation_id
                        ] = RunningInvocation(
                            queued_invocation, datetime.now(), executor=environment
                        )
                        environment.invoke(invocation_event=queued_invocation)
                        LOG.debug("Invoke for request %s done", queued_invocation.invocation_id)
                    except queue.Empty:
                        if self.active_environment_count() == 0:
                            LOG.debug(
                                "Detected no active environments for version %s. Starting one...",
                                self.function_arn,
                            )
                            self.start_environment()
                            # TODO what to do with too much failed environments?
                    except InvalidStatusException:
                        LOG.debug(
                            "Retrieved environment %s in invalid state from queue. Trying the next...",
                            environment.id,
                        )
                        self.running_invocations.pop(queued_invocation.invocation_id, None)
            except Exception as e:
                queued_invocation.result_future.set_exception(e)

    def invoke(self, *, invocation: Invocation) -> "Future[InvocationResult]":
        invocation_storage = QueuedInvocation(
            invocation_id=str(uuid.uuid4()),
            result_future=Future(),
            retries=1,
            invocation=invocation,
        )
        self.queued_invocations.put(invocation_storage)

        return invocation_storage.result_future

    def set_environment_ready(self, executor_id: str) -> None:
        environment = self.all_environments.get(executor_id)
        if not environment:
            raise Exception(
                "Inconsistent state detected: Non existing environment '%s' reported error.",
                executor_id,
            )
        environment.set_ready()
        self.available_environments.put(environment)

    def set_environment_failed(self, executor_id: str) -> None:
        environment = self.all_environments.get(executor_id)
        if not environment:
            raise Exception(
                "Inconsistent state detected: Non existing environment '%s' reported error.",
                executor_id,
            )
        environment.errored()

    def store_logs(self, invocation_result: InvocationResult, executor: RuntimeEnvironment) -> None:
        if invocation_result.logs:
            log_item = LogItem(
                executor.get_log_group_name(),
                executor.get_log_stream_name(),
                invocation_result.logs,
            )
            self.log_handler.add_logs(log_item)
        else:
            LOG.warning(
                "Received no logs from invocation with id %s for lambda %s",
                invocation_result.invocation_id,
                self.function_arn,
            )

    def invocation_response(
        self, invoke_id: str, invocation_result: Union[InvocationResult, InvocationError]
    ) -> None:
        running_invocation = self.running_invocations.pop(invoke_id, None)

        if running_invocation is None:
            raise Exception(f"Cannot map invocation result {invoke_id} to invocation")

        if not invocation_result.logs:
            invocation_result.logs = running_invocation.logs
        executor = running_invocation.executor
        running_invocation.invocation.result_future.set_result(invocation_result)
        # mark executor available again
        executor.invocation_done()
        self.available_environments.put(executor)
        self.store_logs(invocation_result=invocation_result, executor=executor)

    # Service Endpoint implementation
    def invocation_result(self, invoke_id: str, invocation_result: InvocationResult) -> None:
        LOG.debug("Got invocation result for invocation '%s'", invoke_id)
        self.invocation_response(invoke_id=invoke_id, invocation_result=invocation_result)

    def invocation_error(self, invoke_id: str, invocation_error: InvocationError) -> None:
        LOG.debug("Got invocation error for invocation '%s'", invoke_id)
        self.invocation_response(invoke_id=invoke_id, invocation_result=invocation_error)

    def invocation_logs(self, invoke_id: str, invocation_logs: InvocationLogs) -> None:
        LOG.debug("Got logs for invocation '%s'", invoke_id)
        for log_line in invocation_logs.logs.splitlines():
            LOG.debug("> %s", log_line)
        running_invocation = self.running_invocations.get(invoke_id, None)
        if running_invocation is None:
            raise Exception(f"Cannot map invocation result {invoke_id} to invocation")
        running_invocation.logs = invocation_logs.logs

    def status_ready(self, executor_id: str) -> None:
        self.set_environment_ready(executor_id=executor_id)

    def status_error(self, executor_id: str) -> None:
        self.set_environment_failed(executor_id=executor_id)
