import logging
import random
import string
from datetime import date, datetime
from enum import Enum, auto
from threading import RLock, Timer
from typing import TYPE_CHECKING, Dict, Literal, Optional

from localstack import config
from localstack.services.awslambda.invocation.executor_endpoint import ServiceEndpoint
from localstack.services.awslambda.invocation.lambda_models import FunctionVersion
from localstack.services.awslambda.invocation.runtime_executor import RuntimeExecutor
from localstack.utils.strings import to_str

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.version_manager import QueuedInvocation

STARTUP_TIMEOUT_SEC = 10.0
HEX_CHARS = [str(num) for num in range(10)] + ["a", "b", "c", "d", "e", "f"]

LOG = logging.getLogger(__name__)


class RuntimeStatus(Enum):
    INACTIVE = auto()
    STARTING = auto()
    READY = auto()
    RUNNING = auto()
    FAILED = auto()
    STOPPED = auto()


InitializationType = Literal["on-demand", "provisioned-concurrency"]


class InvalidStatusException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


def generate_runtime_id() -> str:
    return "".join(random.choices(string.hexdigits[:16], k=32)).lower()


class RuntimeEnvironment:
    runtime_executor: RuntimeExecutor
    status_lock: RLock
    status: RuntimeStatus
    initialization_type: InitializationType
    last_returned: datetime
    startup_timer: Optional[Timer]

    def __init__(
        self,
        function_version: FunctionVersion,
        initialization_type: InitializationType,
        service_endpoint: ServiceEndpoint,
    ):
        self.id = generate_runtime_id()
        self.status = RuntimeStatus.INACTIVE
        self.status_lock = RLock()
        self.function_version = function_version
        self.initialization_type = initialization_type
        self.runtime_executor = RuntimeExecutor(
            self.id, function_version, service_endpoint=service_endpoint
        )
        self.last_returned = datetime.min
        self.startup_timer = None

    def get_log_group_name(self) -> str:
        return f"/aws/lambda/{self.function_version.id.function_name}"

    def get_log_stream_name(self) -> str:
        return f"{date.today():%Y/%m/%d}/[{self.function_version.qualifier}]{self.id}"

    def get_environment_variables(self) -> Dict[str, str]:
        """
        Returns the environment variable set for the runtime container
        :return: Dict of environment variables
        """
        env_vars = {
            # Runtime API specifics
            "LOCALSTACK_RUNTIME_ID": self.id,
            "LOCALSTACK_RUNTIME_ENDPOINT": f"http://{self.runtime_executor.get_endpoint_from_executor()}:{self.runtime_executor.executor_endpoint.port}",
            # General Lambda Environment Variables
            "AWS_LAMBDA_LOG_GROUP_NAME": self.get_log_group_name(),
            "AWS_LAMBDA_LOG_STREAM_NAME": self.get_log_stream_name(),
            "AWS_LAMBDA_FUNCTION_NAME": self.function_version.qualified_arn,  # TODO use name instead of arn
            "AWS_LAMBDA_FUNCTION_TIMEOUT": self.function_version.config.timeout,
            "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": self.function_version.config.memory_size,  # TODO use correct memory size
            "AWS_LAMBDA_FUNCTION_VERSION": self.function_version.qualifier,  # TODO use name instead of arn
            "AWS_DEFAULT_REGION": self.function_version.qualified_arn,  # TODO use region instead of arn
            "AWS_REGION": self.function_version.qualified_arn,  # TODO use region instead of arn
            "TASK_ROOT": "/var/task",  # TODO custom runtimes?
            "RUNTIME_ROOT": "/var/runtime",  # TODO custom runtimes?
            "AWS_LAMBDA_INITIALIZATION_TYPE": self.initialization_type,
            "TZ": ":UTC",  # TODO does this have to match local system time? format?
            # Access IDs for role TODO make dependent on role arn
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_SESSION_TOKEN": "test",
            # TODO xray
            # LocalStack endpoint specifics
            "LOCALSTACK_HOSTNAME": self.runtime_executor.get_endpoint_from_executor(),
            "EDGE_PORT": str(config.EDGE_PORT),
            "AWS_ENDPOINT_URL": f"http://{self.runtime_executor.get_endpoint_from_executor()}:{config.EDGE_PORT}",
        }
        if self.function_version.config.handler:
            env_vars["_HANDLER"] = self.function_version.config.handler
        if self.function_version.config.runtime:
            env_vars["AWS_EXECUTION_ENV"] = f"Aws_Lambda_{self.function_version.config.runtime}"
        env_vars.update(self.function_version.config.environment)
        return env_vars

    # Lifecycle methods
    def start(self) -> None:
        """
        Starting the runtime environment
        """
        with self.status_lock:
            if self.status != RuntimeStatus.INACTIVE:
                raise InvalidStatusException("Runtime Handler can only be started when inactive")
            self.status = RuntimeStatus.STARTING
            self.runtime_executor.start(self.get_environment_variables())
            self.startup_timer = Timer(STARTUP_TIMEOUT_SEC, self.timed_out)
            self.startup_timer.start()

    def stop(self) -> None:
        """
        Stopping the runtime environment
        """
        with self.status_lock:
            if self.status in [RuntimeStatus.INACTIVE, RuntimeStatus.STOPPED]:
                raise InvalidStatusException("Runtime Handler cannot be shutdown before started")
            self.runtime_executor.stop()
            self.status = RuntimeStatus.STOPPED

    # Status methods
    def set_ready(self) -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.STARTING:
                raise InvalidStatusException(
                    "Runtime Handler can only be set active while starting"
                )
            self.status = RuntimeStatus.READY
            if self.startup_timer:
                self.startup_timer.cancel()
                self.startup_timer = None

    def invocation_done(self) -> None:
        self.last_returned = datetime.now()
        with self.status_lock:
            if self.status != RuntimeStatus.RUNNING:
                raise InvalidStatusException("Runtime Handler can only be set ready while running")
            self.status = RuntimeStatus.READY

    def timed_out(self) -> None:
        LOG.debug(
            "Executor %s for function %s timed out during startup",
            self.id,
            self.function_version.qualified_arn,
        )
        self.startup_timer = None
        self.errored()

    def errored(self) -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.STARTING:
                raise InvalidStatusException("Runtime Handler can only error while starting")
            self.status = RuntimeStatus.FAILED
        if self.startup_timer:
            self.startup_timer.cancel()
        try:
            self.runtime_executor.stop()
        except Exception:
            LOG.debug("Unable to shutdown runtime handler '%s'", self.id)

    def invoke(self, invocation_event: "QueuedInvocation") -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.READY:
                raise InvalidStatusException("Invoke can only happen if status is ready")
            self.status = RuntimeStatus.RUNNING
        invoke_payload = {
            "invoke-id": invocation_event.invocation_id,
            "payload": to_str(invocation_event.invocation.payload),
        }
        self.runtime_executor.invoke(payload=invoke_payload)
