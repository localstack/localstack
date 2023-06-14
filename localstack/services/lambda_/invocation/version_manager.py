import concurrent.futures
import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TYPE_CHECKING

from localstack import config
from localstack.aws.api.lambda_ import (
    ProvisionedConcurrencyStatusEnum,
    ServiceException,
    State,
    StateReasonCode,
)
from localstack.services.lambda_.invocation.assignment import AssignmentService
from localstack.services.lambda_.invocation.counting_service import CountingService
from localstack.services.lambda_.invocation.docker_runtime_executor import InitializationType
from localstack.services.lambda_.invocation.execution_environment import (
    ExecutionEnvironment,
    RuntimeStatus,
)
from localstack.services.lambda_.invocation.lambda_models import (
    Function,
    FunctionVersion,
    Invocation,
    InvocationResult,
    ProvisionedConcurrencyState,
    VersionState,
)
from localstack.services.lambda_.invocation.logs import LogHandler, LogItem
from localstack.services.lambda_.invocation.metrics import record_cw_metric_invocation
from localstack.services.lambda_.invocation.runtime_executor import get_runtime_executor
from localstack.utils.strings import truncate
from localstack.utils.threads import start_thread

if TYPE_CHECKING:
    from localstack.services.lambda_.invocation.lambda_service import LambdaService

LOG = logging.getLogger(__name__)


class ShutdownPill:
    pass


QUEUE_SHUTDOWN = ShutdownPill()


class LambdaVersionManager:
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
    counting_service: CountingService
    assignment_service: AssignmentService

    def __init__(
        self,
        function_arn: str,
        function_version: FunctionVersion,
        function: Function,
        lambda_service: "LambdaService",
        counting_service: CountingService,
        assignment_service: AssignmentService,
    ):
        self.function_arn = function_arn
        self.function_version = function_version
        self.function = function
        self.lambda_service = lambda_service
        self.counting_service = counting_service
        self.assignment_service = assignment_service
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
                    runtime_environment = ExecutionEnvironment(
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

    def invoke(self, *, invocation: Invocation) -> InvocationResult:
        """
        0. check counter, get lease
        1. try to get an inactive (no active invoke) environment
        2.(allgood) send invoke to environment
        3. wait for invocation result
        4. return invocation result & release lease

        2.(nogood) fail fast fail hard

        """
        assert invocation.invocation_type == "RequestResponse"  # TODO: remove later

        # lease should be specific for on-demand or provisioned, lease can return the type
        # TODO: try/catch handle case when no lease available
        with self.counting_service.get_invocation_lease() as provisioning_type:  # TODO: do we need to pass more here?
            # potential race condition when changing provisioned concurrency
            with self.get_environment(provisioning_type) as execution_env:
                invocation_result = execution_env.invoke(invocation)
                invocation_result.executed_version = self.function_version.id.qualifier
                self.store_logs(invocation_result=invocation_result, execution_env=execution_env)
        start_thread(
            lambda *args, **kwargs: record_cw_metric_invocation(
                function_name=self.function.function_name,
                region_name=self.function_version.id.region,
            )
        )
        LOG.debug("Got logs for invocation '%s'", invocation.request_id)
        for log_line in invocation_result.logs.splitlines():
            LOG.debug("> %s", truncate(log_line, config.LAMBDA_TRUNCATE_STDOUT))
        return invocation_result

    def get_environment(self, provisioning_type: InitializationType):
        return self.assignment_service.get_environment(self.function_version, provisioning_type)

    def store_logs(
        self, invocation_result: InvocationResult, execution_env: ExecutionEnvironment
    ) -> None:
        if invocation_result.logs:
            log_item = LogItem(
                execution_env.get_log_group_name(),
                execution_env.get_log_stream_name(),
                invocation_result.logs,
            )
            self.log_handler.add_logs(log_item)
        else:
            LOG.warning(
                "Received no logs from invocation with id %s for lambda %s",
                invocation_result.request_id,
                self.function_arn,
            )
