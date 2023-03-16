import concurrent.futures
import dataclasses
import json
import logging
import queue
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from queue import Queue
from typing import TYPE_CHECKING, Dict, List, Optional, Union

from localstack import config
from localstack.aws.api.lambda_ import (
    ProvisionedConcurrencyStatusEnum,
    ServiceException,
    State,
    StateReasonCode,
    TooManyRequestsException,
)
from localstack.services.awslambda.invocation.lambda_models import (
    Function,
    FunctionVersion,
    Invocation,
    InvocationError,
    InvocationLogs,
    InvocationResult,
    ProvisionedConcurrencyState,
    ServiceEndpoint,
    VersionState,
)
from localstack.services.awslambda.invocation.runtime_environment import (
    InvalidStatusException,
    RuntimeEnvironment,
    RuntimeStatus,
)
from localstack.services.awslambda.invocation.runtime_executor import get_runtime_executor
from localstack.services.awslambda.lambda_executors import InvocationException
from localstack.utils.aws import dead_letter_queue
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs
from localstack.utils.strings import to_str, truncate
from localstack.utils.threads import FuncThread, start_thread
from localstack.utils.time import timestamp_millis

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import LambdaService

LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class QueuedInvocation:
    invocation_id: str
    result_future: Future[InvocationResult] | None
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
    role_arn: str
    _thread: Optional[FuncThread]
    _shutdown_event: threading.Event

    def __init__(self, role_arn: str) -> None:
        self.role_arn = role_arn
        self.log_queue = Queue()
        self._shutdown_event = threading.Event()
        self._thread = None

    def run_log_loop(self, *args, **kwargs) -> None:
        # TODO: create client
        while not self._shutdown_event.is_set():
            log_item = self.log_queue.get()
            if log_item is QUEUE_SHUTDOWN:
                return
            store_cloudwatch_logs(log_item.log_group, log_item.log_stream, log_item.logs)

    def start_subscriber(self) -> None:
        self._thread = FuncThread(self.run_log_loop, name="log_handler")
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
    function: Function
    # mapping from invocation id to invocation storage
    running_invocations: Dict[str, RunningInvocation]
    # stack of available (ready to get invoked) environments
    available_environments: "queue.LifoQueue[Union[RuntimeEnvironment, ShutdownPill]]"
    # mapping environment id -> environment
    all_environments: Dict[str, RuntimeEnvironment]
    # queue of invocations to be executed
    queued_invocations: "Queue[Union[QueuedInvocation, ShutdownPill]]"
    invocation_thread: Optional[FuncThread]
    shutdown_event: threading.Event
    state: VersionState | None
    provisioned_state: ProvisionedConcurrencyState | None
    log_handler: LogHandler
    # TODO not sure about this backlink, maybe a callback is better?
    lambda_service: "LambdaService"

    destination_execution_pool: ThreadPoolExecutor

    def __init__(
        self,
        function_arn: str,
        function_version: FunctionVersion,
        function: Function,
        lambda_service: "LambdaService",
    ):
        self.function_arn = function_arn
        self.function_version = function_version
        self.function = function
        self.lambda_service = lambda_service
        self.log_handler = LogHandler(function_version.config.role)

        # invocation tracking
        self.running_invocations = {}
        self.queued_invocations = Queue()

        # execution environment tracking
        self.available_environments = queue.LifoQueue()
        self.all_environments = {}

        # async
        self.provisioning_thread = None
        self.provisioning_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-provisioning-{function_version.id.function_name}:{function_version.id.qualifier}"
        )
        self.execution_env_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-exenv-{function_version.id.function_name}:{function_version.id.qualifier}"
        )
        self.invocation_thread = None
        self.destination_execution_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-destination-processor-{function_version.id.function_name}"
        )
        self.shutdown_event = threading.Event()

        # async state
        self.provisioned_state = None
        self.state = None

    def start(self) -> None:
        try:
            invocation_thread = FuncThread(self.invocation_loop, name="invocation_loop")
            invocation_thread.start()
            self.invocation_thread = invocation_thread
            self.log_handler.start_subscriber()
            get_runtime_executor().prepare_version(self.function_version)

            # code and reason not set for success scenario because only failed states provide this field:
            # https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunctionConfiguration.html#SSS-GetFunctionConfiguration-response-LastUpdateStatusReasonCode
            self.state = VersionState(state=State.Active)
            LOG.debug(
                f"Lambda '{self.function_arn}' (id {self.function_version.config.internal_revision}) changed to active"
            )
        except Exception as e:
            self.state = VersionState(
                state=State.Failed,
                code=StateReasonCode.InternalError,
                reason=f"Error while creating lambda: {e}",
            )
            LOG.debug(
                f"Lambda '{self.function_arn}' changed to failed. Reason: %s", e, exc_info=True
            )
        finally:
            self.lambda_service.update_version_state(
                function_version=self.function_version, new_state=self.state
            )

    def stop(self) -> None:
        LOG.debug("Stopping lambda version '%s'", self.function_arn)
        self.state = VersionState(
            state=State.Inactive, code=StateReasonCode.Idle, reason="Shutting down"
        )
        self.shutdown_event.set()
        self.provisioning_pool.shutdown(wait=False, cancel_futures=True)
        self.destination_execution_pool.shutdown(wait=False, cancel_futures=True)

        self.queued_invocations.put(QUEUE_SHUTDOWN)
        self.available_environments.put(QUEUE_SHUTDOWN)

        futures_exenv_shutdown = []
        for environment in list(self.all_environments.values()):
            futures_exenv_shutdown.append(
                self.execution_env_pool.submit(self.stop_environment, environment)
            )
        if self.invocation_thread:
            try:
                self.invocation_thread.join(timeout=5.0)
                LOG.debug("Thread stopped '%s'", self.function_arn)
            except TimeoutError:
                LOG.warning("Thread did not stop after 5s '%s'", self.function_arn)

        concurrent.futures.wait(futures_exenv_shutdown, timeout=3)
        self.execution_env_pool.shutdown(wait=False, cancel_futures=True)
        self.log_handler.stop()
        get_runtime_executor().cleanup_version(self.function_version)

    def update_provisioned_concurrency_config(self, provisioned_concurrent_executions: int) -> None:
        """
        TODO: implement update while in progress (see test_provisioned_concurrency test)
        TODO: loop until diff == 0 and retry to remove/add diff environments
        TODO: alias routing & allocated
        TODO: ProvisionedConcurrencyStatusEnum.FAILED
        TODO: status reason

        :param provisioned_concurrent_executions: set to 0 to stop all provisioned environments
        """

        if self.provisioned_state == ProvisionedConcurrencyStatusEnum.IN_PROGRESS:
            raise ServiceException("Not working yet.")

        # create plan
        current_provisioned_environments = len(
            [
                e
                for e in self.all_environments.values()
                if e.initialization_type == "provisioned-concurrency"
            ]
        )
        target_provisioned_environments = provisioned_concurrent_executions
        diff = target_provisioned_environments - current_provisioned_environments

        def scale_environments(*args, **kwargs):
            futures = []
            if diff > 0:
                for _ in range(diff):
                    runtime_environment = RuntimeEnvironment(
                        function_version=self.function_version,
                        initialization_type="provisioned-concurrency",
                        service_endpoint=self,
                    )
                    self.all_environments[runtime_environment.id] = runtime_environment

                    def start_provisioning_env():
                        runtime_environment.start()
                        self.set_environment_ready(runtime_environment.id)

                    futures.append(self.provisioning_pool.submit(start_provisioning_env))

            elif diff < 0:
                provisioned_envs = [
                    e
                    for e in self.all_environments.values()
                    if e.initialization_type == "provisioned-concurrency"
                    and e.status != RuntimeStatus.RUNNING
                ]
                for e in provisioned_envs[: (diff * -1)]:
                    futures.append(self.provisioning_pool.submit(self.stop_environment, e))
            else:
                return  # NOOP

            concurrent.futures.wait(futures)

            if target_provisioned_environments == 0:
                self.provisioned_state = None
            else:
                self.provisioned_state.available = provisioned_concurrent_executions
                self.provisioned_state.allocated = provisioned_concurrent_executions
                self.provisioned_state.status = ProvisionedConcurrencyStatusEnum.READY

        self.provisioning_thread = start_thread(scale_environments)

    def start_environment(self):
        considered_envs = self.count_environment_by_status(
            [
                RuntimeStatus.INACTIVE,
                RuntimeStatus.READY,
                RuntimeStatus.STARTING,
                RuntimeStatus.RUNNING,
            ]
        )

        # TODO: invocation number instead of considered
        if (
            self.function.reserved_concurrent_executions is not None
            and considered_envs >= self.function.reserved_concurrent_executions
        ):
            return

        LOG.debug("Starting new environment")
        runtime_environment = RuntimeEnvironment(
            function_version=self.function_version,
            initialization_type="on-demand",
            service_endpoint=self,
        )
        self.all_environments[runtime_environment.id] = runtime_environment
        self.execution_env_pool.submit(runtime_environment.start)

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

    def invocation_loop(self, *args, **kwargs) -> None:
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
                # Assumption: Synchronous invoke should never end up in the invocation queue because we catch it earlier
                if self.function.reserved_concurrent_executions == 0:
                    # error...
                    self.destination_execution_pool.submit(
                        self.process_event_destinations,
                        invocation_result=InvocationError(
                            queued_invocation.invocation_id,
                            payload=None,
                            executed_version=None,
                            logs=None,
                        ),
                        queued_invocation=queued_invocation,
                        last_invoke_time=None,
                        original_payload=queued_invocation.invocation.payload,
                    )
                    continue

                # TODO refine environment startup logic
                if self.available_environments.empty() or self.active_environment_count() == 0:
                    self.start_environment()

                environment = None
                # TODO avoid infinite environment spawning retrying
                while not environment:
                    try:
                        environment = self.available_environments.get(timeout=1)
                        if environment is QUEUE_SHUTDOWN or self.shutdown_event.is_set():
                            LOG.debug(
                                "Invocation loop for lambda %s stopped while waiting for environments",
                                self.function_arn,
                            )
                            return

                        # TODO: untested assumption(!)
                        #   because provisioned concurrency affects the unreserved
                        if environment.initialization_type == "on-demand":
                            self.lambda_service.report_invocation_start(
                                self.function_version.id.unqualified_arn()
                            )

                        self.running_invocations[
                            queued_invocation.invocation_id
                        ] = RunningInvocation(
                            queued_invocation, datetime.now(), executor=environment
                        )

                        environment.invoke(invocation_event=queued_invocation)
                        LOG.debug("Invoke for request %s done", queued_invocation.invocation_id)
                    except queue.Empty:
                        # TODO if one environment threw an invalid status exception, we will get here potentially with
                        # another busy environment, and won't spawn a new one as there is one active here.
                        # We will be stuck in the loop until another becomes active without scaling.
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
                        if environment.initialization_type == "on-demand":
                            self.lambda_service.report_invocation_end(
                                self.function_version.id.unqualified_arn()
                            )
                        # try next environment
                        environment = None
            except Exception as e:
                # TODO: propagate unexpected errors
                LOG.debug(
                    "Unexpected exception in invocation loop for function version %s",
                    self.function_version.qualified_arn,
                    exc_info=True,
                )
                if queued_invocation.result_future:
                    queued_invocation.result_future.set_exception(e)

    def invoke(
        self, *, invocation: Invocation, current_retry: int = 0, invocation_id: str | None = None
    ) -> Future[InvocationResult] | None:
        future = Future() if invocation.invocation_type == "RequestResponse" else None
        if invocation_id is None:
            invocation_id = str(uuid.uuid4())
        if invocation.invocation_type == "RequestResponse":
            if (
                self.lambda_service.get_available_fn_concurrency(
                    self.function_version.id.unqualified_arn()
                )
                <= 0
            ):
                raise TooManyRequestsException(
                    "Rate Exceeded.",
                    Reason="ReservedFunctionConcurrentInvocationLimitExceeded",
                    Type="User",
                )

        invocation_storage = QueuedInvocation(
            invocation_id=invocation_id,
            result_future=future,
            retries=current_retry,
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

    def process_event_destinations(
        self,
        invocation_result: InvocationResult | InvocationError,
        queued_invocation: QueuedInvocation,
        last_invoke_time: Optional[datetime],
        original_payload: bytes,
    ) -> None:
        """TODO refactor"""
        LOG.debug("Got event invocation with id %s", invocation_result.invocation_id)

        # 1. Handle DLQ routing
        if (
            isinstance(invocation_result, InvocationError)
            and self.function_version.config.dead_letter_arn
        ):
            dead_letter_queue._send_to_dead_letter_queue(
                source_arn=self.function_arn,
                dlq_arn=self.function_version.config.dead_letter_arn,
                event=json.loads(to_str(original_payload)),
                error=InvocationException(
                    message="hi", result=to_str(invocation_result.payload)
                ),  # TODO: check message
            )

        # 2. Handle actual destination setup
        event_invoke_config = self.function.event_invoke_configs.get(
            self.function_version.id.qualifier
        )

        if event_invoke_config is None:
            return

        if isinstance(invocation_result, InvocationResult):
            LOG.debug("Handling success destination for %s", self.function_arn)
            success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
                "Destination"
            )
            if success_destination is None:
                return
            destination_payload = {
                "version": "1.0",
                "timestamp": timestamp_millis(),
                "requestContext": {
                    "requestId": invocation_result.invocation_id,
                    "functionArn": self.function_version.qualified_arn,
                    "condition": "Success",
                    "approximateInvokeCount": queued_invocation.retries + 1,
                },
                "requestPayload": json.loads(to_str(original_payload)),
                "responseContext": {
                    "statusCode": 200,
                    "executedVersion": self.function_version.id.qualifier,
                },
                "responsePayload": json.loads(to_str(invocation_result.payload or {})),
            }

            send_event_to_target(
                target_arn=event_invoke_config.destination_config["OnSuccess"]["Destination"],
                event=destination_payload,
            )

        elif isinstance(invocation_result, InvocationError):
            LOG.debug("Handling error destination for %s", self.function_arn)

            failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
                "Destination"
            )

            max_retry_attempts = event_invoke_config.maximum_retry_attempts
            previous_retry_attempts = queued_invocation.retries

            if self.function.reserved_concurrent_executions == 0:
                failure_cause = "ZeroReservedConcurrency"
                response_payload = None
                response_context = None
                approx_invoke_count = 0
            else:
                if max_retry_attempts > 0 and max_retry_attempts > previous_retry_attempts:
                    delay_queue_invoke_seconds = config.LAMBDA_RETRY_BASE_DELAY_SECONDS * (
                        previous_retry_attempts + 1
                    )

                    time_passed = datetime.now() - last_invoke_time
                    enough_time_for_retry = (
                        event_invoke_config.maximum_event_age_in_seconds
                        and time_passed.seconds + delay_queue_invoke_seconds
                        <= event_invoke_config.maximum_event_age_in_seconds
                    )

                    if (
                        event_invoke_config.maximum_event_age_in_seconds is None
                        or enough_time_for_retry
                    ):
                        time.sleep(delay_queue_invoke_seconds)
                        LOG.debug("Retrying lambda invocation for %s", self.function_arn)
                        self.invoke(
                            invocation=queued_invocation.invocation,
                            current_retry=previous_retry_attempts + 1,
                            invocation_id=queued_invocation.invocation_id,
                        )
                        return

                    failure_cause = "EventAgeExceeded"
                else:
                    failure_cause = "RetriesExhausted"

                response_payload = json.loads(to_str(invocation_result.payload))
                response_context = {
                    "statusCode": 200,
                    "executedVersion": self.function_version.id.qualifier,
                    "functionError": "Unhandled",
                }
                approx_invoke_count = previous_retry_attempts + 1

            if failure_destination is None:
                return

            destination_payload = {
                "version": "1.0",
                "timestamp": timestamp_millis(),
                "requestContext": {
                    "requestId": invocation_result.invocation_id,
                    "functionArn": self.function_version.qualified_arn,
                    "condition": failure_cause,
                    "approximateInvokeCount": approx_invoke_count,
                },
                "requestPayload": json.loads(to_str(original_payload)),
            }

            if response_context:
                destination_payload["responseContext"] = response_context
            if response_payload:
                destination_payload["responsePayload"] = response_payload

            send_event_to_target(
                target_arn=event_invoke_config.destination_config["OnFailure"]["Destination"],
                event=destination_payload,
            )
        else:
            raise ValueError("Unknown type for invocation result received.")

    def invocation_response(
        self, invoke_id: str, invocation_result: Union[InvocationResult, InvocationError]
    ) -> None:
        running_invocation = self.running_invocations.pop(invoke_id, None)

        if running_invocation is None:
            raise Exception(f"Cannot map invocation result {invoke_id} to invocation")

        if not invocation_result.logs:
            invocation_result.logs = running_invocation.logs
        invocation_result.executed_version = self.function_version.id.qualifier
        executor = running_invocation.executor

        if running_invocation.invocation.invocation.invocation_type == "RequestResponse":
            running_invocation.invocation.result_future.set_result(invocation_result)
        else:
            self.destination_execution_pool.submit(
                self.process_event_destinations,
                invocation_result=invocation_result,
                queued_invocation=running_invocation.invocation,
                last_invoke_time=running_invocation.invocation.invocation.invoke_time,
                original_payload=running_invocation.invocation.invocation.payload,
            )

        self.store_logs(invocation_result=invocation_result, executor=executor)

        # mark executor available again
        executor.invocation_done()
        self.available_environments.put(executor)
        if executor.initialization_type == "on-demand":
            self.lambda_service.report_invocation_end(self.function_version.id.unqualified_arn())

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
            LOG.debug("> %s", truncate(log_line, config.LAMBDA_TRUNCATE_STDOUT))
        running_invocation = self.running_invocations.get(invoke_id, None)
        if running_invocation is None:
            raise Exception(f"Cannot map invocation result {invoke_id} to invocation")
        running_invocation.logs = invocation_logs.logs

    def status_ready(self, executor_id: str) -> None:
        self.set_environment_ready(executor_id=executor_id)

    def status_error(self, executor_id: str) -> None:
        self.set_environment_failed(executor_id=executor_id)
