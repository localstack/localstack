import concurrent.futures
import dataclasses
import json
import logging
import queue
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from math import ceil
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
from localstack.aws.connect import connect_to
from localstack.services.lambda_.invocation.lambda_models import (
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
from localstack.services.lambda_.invocation.logs import LogHandler, LogItem
from localstack.services.lambda_.invocation.runtime_environment import (
    InvalidStatusException,
    RuntimeEnvironment,
    RuntimeStatus,
)
from localstack.services.lambda_.invocation.runtime_executor import get_runtime_executor
from localstack.services.lambda_.lambda_executors import InvocationException
from localstack.utils.aws import dead_letter_queue
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.cloudwatch.cloudwatch_util import publish_lambda_metric, store_cloudwatch_logs
from localstack.utils.strings import to_str, truncate
from localstack.utils.threads import FuncThread, start_thread
from localstack.utils.time import timestamp_millis

if TYPE_CHECKING:
    from localstack.services.lambda_.invocation.lambda_service import LambdaService

LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class QueuedInvocation:
    result_future: Future[InvocationResult] | None
    retries: int
    invocation: Invocation


@dataclasses.dataclass
class RunningInvocation:
    invocation: QueuedInvocation
    start_time: datetime
    executor: RuntimeEnvironment
    logs: Optional[str] = None


class ShutdownPill:
    pass


QUEUE_SHUTDOWN = ShutdownPill()


class LambdaVersionManager(ServiceEndpoint):
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: FunctionVersion
    function: Function

    # queue of invocations to be executed
    shutdown_event: threading.Event
    state: VersionState | None
    provisioned_state: ProvisionedConcurrencyState | None  # TODO: remove?
    log_handler: LogHandler
    # TODO not sure about this backlink, maybe a callback is better?
    lambda_service: "LambdaService"

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
        self.log_handler = LogHandler(function_version.config.role, function_version.id.region)

        # invocation tracking
        self.running_invocations = {}

        # async
        self.provisioning_thread = None
        self.provisioning_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-provisioning-{function_version.id.function_name}:{function_version.id.qualifier}"
        )
        self.shutdown_event = threading.Event()

        # async state
        self.provisioned_state = None
        self.state = None

    def start(self) -> None:
        new_state = None
        try:
            self.log_handler.start_subscriber()
            get_runtime_executor().prepare_version(self.function_version)  # TODO: make pluggable?

            # code and reason not set for success scenario because only failed states provide this field:
            # https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunctionConfiguration.html#SSS-GetFunctionConfiguration-response-LastUpdateStatusReasonCode
            new_state = VersionState(state=State.Active)
            LOG.debug(
                f"Changing Lambda '{self.function_arn}' (id {self.function_version.config.internal_revision}) to active"
            )
        except Exception as e:
            new_state = VersionState(
                state=State.Failed,
                code=StateReasonCode.InternalError,
                reason=f"Error while creating lambda: {e}",
            )
            LOG.debug(
                f"Changing Lambda '{self.function_arn}' to failed. Reason: %s", e, exc_info=True
            )
        finally:
            if new_state:
                self.lambda_service.update_version_state(
                    function_version=self.function_version, new_state=new_state
                )

    def stop(self) -> None:
        LOG.debug("Stopping lambda version '%s'", self.function_arn)
        self.state = VersionState(
            state=State.Inactive, code=StateReasonCode.Idle, reason="Shutting down"
        )
        self.shutdown_event.set()
        self.log_handler.stop()
        get_runtime_executor().cleanup_version(self.function_version)  # TODO: make pluggable?

    # TODO: move
    def update_provisioned_concurrency_config(
        self, provisioned_concurrent_executions: int
    ) -> Future[None]:
        """
        TODO: implement update while in progress (see test_provisioned_concurrency test)
        TODO: loop until diff == 0 and retry to remove/add diff environments
        TODO: alias routing & allocated
        TODO: ProvisionedConcurrencyStatusEnum.FAILED
        TODO: status reason

        :param provisioned_concurrent_executions: set to 0 to stop all provisioned environments
        """

        if (
            self.provisioned_state
            and self.provisioned_state.status == ProvisionedConcurrencyStatusEnum.IN_PROGRESS
        ):
            raise ServiceException(
                "Updating provisioned concurrency configuration while IN_PROGRESS is not supported yet."
            )

        if not self.provisioned_state:
            self.provisioned_state = ProvisionedConcurrencyState()

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
                    futures.append(self.provisioning_pool.submit(runtime_environment.start))

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
        return self.provisioning_thread.result_future

    # Extract environment handling

    def invoke(self, *, invocation: Invocation, current_retry: int = 0) -> InvocationResult:
        """
        0. check counter, get lease
        1. try to get an inactive (no active invoke) environment
        2.(allgood) send invoke to environment
        3. wait for invocation result
        4. return invocation result & release lease

        2.(nogood) fail fast fail hard

        """
        assert invocation.invocation_type == "RequestResponse"  # TODO: remove later

        with self.get_invocation_lease():  # TODO: do we need to pass more here?
            with self.assignment_service.get_environment() as execution_env:
                execution_env.invoke()
                # tracker = InvocationTracker()
                # future = tracker.register_invocation(invocation_id="blub")
                # return future.result(timeout=0.001)

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
                invocation_result.request_id,
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
        invocation_result.executed_version = self.function_version.id.qualifier
        self.store_logs(invocation_result=invocation_result, executor=executor)

    # Service Endpoint implementation
    # TODO: move
    def invocation_result(self, invoke_id: str, invocation_result: InvocationResult) -> None:
        LOG.debug("Got invocation result for invocation '%s'", invoke_id)
        start_thread(self.record_cw_metric_invocation)
        self.invocation_response(invoke_id=invoke_id, invocation_result=invocation_result)

    def invocation_error(self, invoke_id: str, invocation_error: InvocationError) -> None:
        LOG.debug("Got invocation error for invocation '%s'", invoke_id)
        start_thread(self.record_cw_metric_error)
        self.invocation_response(invoke_id=invoke_id, invocation_result=invocation_error)

    def invocation_logs(self, invoke_id: str, invocation_logs: InvocationLogs) -> None:
        LOG.debug("Got logs for invocation '%s'", invoke_id)
        for log_line in invocation_logs.logs.splitlines():
            LOG.debug("> %s", truncate(log_line, config.LAMBDA_TRUNCATE_STDOUT))
        running_invocation = self.running_invocations.get(invoke_id, None)
        if running_invocation is None:
            raise Exception(f"Cannot map invocation result {invoke_id} to invocation")
        running_invocation.logs = invocation_logs.logs
