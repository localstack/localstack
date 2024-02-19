import concurrent.futures
import logging
import threading
import time
from concurrent.futures import Future
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
from localstack.services.lambda_.invocation.execution_environment import ExecutionEnvironment
from localstack.services.lambda_.invocation.executor_endpoint import StatusErrorException
from localstack.services.lambda_.invocation.lambda_models import (
    Function,
    FunctionVersion,
    Invocation,
    InvocationResult,
    ProvisionedConcurrencyState,
    VersionState,
)
from localstack.services.lambda_.invocation.logs import LogHandler, LogItem
from localstack.services.lambda_.invocation.metrics import (
    record_cw_metric_error,
    record_cw_metric_invocation,
)
from localstack.services.lambda_.invocation.runtime_executor import get_runtime_executor
from localstack.utils.strings import long_uid, truncate
from localstack.utils.threads import FuncThread, start_thread

if TYPE_CHECKING:
    from localstack.services.lambda_.invocation.lambda_service import LambdaService

LOG = logging.getLogger(__name__)


class LambdaVersionManager:
    # arn this Lambda Version manager manages
    function_arn: str
    function_version: FunctionVersion
    function: Function

    # Scale provisioned concurrency up and down
    provisioning_thread: FuncThread | None
    # Additional guard to prevent scheduling invocation on version during shutdown
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
        self.id = long_uid()
        self.function_arn = function_arn
        self.function_version = function_version
        self.function = function
        self.lambda_service = lambda_service
        self.counting_service = counting_service
        self.assignment_service = assignment_service
        self.log_handler = LogHandler(function_version.config.role, function_version.id.region)

        # async
        self.provisioning_thread = None
        self.shutdown_event = threading.Event()

        # async state
        self.provisioned_state = None
        self.provisioned_state_lock = threading.RLock()
        self.state = None

    def start(self) -> None:
        new_state = None
        try:
            self.log_handler.start_subscriber()
            time_before = time.perf_counter()
            get_runtime_executor().prepare_version(self.function_version)  # TODO: make pluggable?
            LOG.debug(
                "Version preparation of function %s took %0.2fms",
                self.function_version.qualified_arn,
                (time.perf_counter() - time_before) * 1000,
            )

            # code and reason not set for success scenario because only failed states provide this field:
            # https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunctionConfiguration.html#SSS-GetFunctionConfiguration-response-LastUpdateStatusReasonCode
            new_state = VersionState(state=State.Active)
            LOG.debug(
                f"Changing Lambda {self.function_arn} (id {self.function_version.config.internal_revision}) to active"
            )
        except Exception as e:
            new_state = VersionState(
                state=State.Failed,
                code=StateReasonCode.InternalError,
                reason=f"Error while creating lambda: {e}",
            )
            LOG.debug(
                f"Changing Lambda {self.function_arn} (id {self.function_version.config.internal_revision}) to "
                f"failed. Reason: %s",
                e,
                exc_info=True,
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
        self.assignment_service.stop_environments_for_version(self.id)
        get_runtime_executor().cleanup_version(self.function_version)  # TODO: make pluggable?

    def update_provisioned_concurrency_config(
        self, provisioned_concurrent_executions: int
    ) -> Future[None]:
        """
        TODO: implement update while in progress (see test_provisioned_concurrency test)
        TODO: loop until diff == 0 and retry to remove/add diff environments
        TODO: alias routing & allocated (i.e., the status while updating provisioned concurrency)
        TODO: ProvisionedConcurrencyStatusEnum.FAILED
        TODO: status reason

        :param provisioned_concurrent_executions: set to 0 to stop all provisioned environments
        """
        with self.provisioned_state_lock:
            # LocalStack limitation: cannot update provisioned concurrency while another update is in progress
            if (
                self.provisioned_state
                and self.provisioned_state.status == ProvisionedConcurrencyStatusEnum.IN_PROGRESS
            ):
                raise ServiceException(
                    "Updating provisioned concurrency configuration while IN_PROGRESS is not supported yet."
                )

            if not self.provisioned_state:
                self.provisioned_state = ProvisionedConcurrencyState()

        def scale_environments(*args, **kwargs) -> None:
            futures = self.assignment_service.scale_provisioned_concurrency(
                self.id, self.function_version, provisioned_concurrent_executions
            )

            concurrent.futures.wait(futures)

            with self.provisioned_state_lock:
                if provisioned_concurrent_executions == 0:
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
        synchronous invoke entrypoint

        0. check counter, get lease
        1. try to get an inactive (no active invoke) environment
        2.(allgood) send invoke to environment
        3. wait for invocation result
        4. return invocation result & release lease

        2.(nogood) fail fast fail hard

        """
        LOG.debug(
            "Got an invocation for function %s with request_id %s",
            self.function_arn,
            invocation.request_id,
        )
        if self.shutdown_event.is_set():
            message = f"Got an invocation with request_id {invocation.request_id} for a version shutting down"
            LOG.warning(message)
            raise ServiceException(message)

        with self.counting_service.get_invocation_lease(
            self.function, self.function_version
        ) as provisioning_type:
            # TODO: potential race condition when changing provisioned concurrency after getting the lease but before
            #   getting an an environment
            try:
                # Blocks and potentially creates a new execution environment for this invocation
                with self.assignment_service.get_environment(
                    self.id, self.function_version, provisioning_type
                ) as execution_env:
                    invocation_result = execution_env.invoke(invocation)
                    invocation_result.executed_version = self.function_version.id.qualifier
                    self.store_logs(
                        invocation_result=invocation_result, execution_env=execution_env
                    )
            except StatusErrorException as e:
                invocation_result = InvocationResult(
                    request_id="",
                    payload=e.payload,
                    is_error=True,
                    logs="",
                    executed_version=self.function_version.id.qualifier,
                )

        function_id = self.function_version.id
        # Record CloudWatch metrics in separate threads
        # MAYBE reuse threads rather than starting new threads upon every invocation
        if invocation_result.is_error:
            start_thread(
                lambda *args, **kwargs: record_cw_metric_error(
                    function_name=self.function.function_name,
                    account_id=self.function_version.id.account,
                    region_name=self.function_version.id.region,
                ),
                name=f"record-cloudwatch-metric-error-{function_id.function_name}:{function_id.qualifier}",
            )
        else:
            start_thread(
                lambda *args, **kwargs: record_cw_metric_invocation(
                    function_name=self.function.function_name,
                    account_id=self.function_version.id.account,
                    region_name=self.function_version.id.region,
                ),
                name=f"record-cloudwatch-metric-{function_id.function_name}:{function_id.qualifier}",
            )
        # TODO: consider using the same prefix logging as in error case for execution environment.
        #   possibly as separate named logger.
        LOG.debug("Got logs for invocation '%s'", invocation.request_id)
        for log_line in invocation_result.logs.splitlines():
            LOG.debug(
                "[%s-%s] %s",
                function_id.function_name,
                invocation.request_id,
                truncate(log_line, config.LAMBDA_TRUNCATE_STDOUT),
            )
        return invocation_result

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
