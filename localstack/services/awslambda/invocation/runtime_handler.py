import logging
from enum import Enum, auto
from threading import RLock
from typing import TYPE_CHECKING, Dict, Literal

import requests

from localstack import config
from localstack.services.awslambda.invocation.runtime_executor import RuntimeExecutor
from localstack.utils.common import short_uid, to_str

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.executor_endpoint import ExecutorEndpoint
    from localstack.services.awslambda.invocation.lambda_service import FunctionVersion
    from localstack.services.awslambda.invocation.version_manager import InvocationStorage

INVOCATION_PORT = 9563

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


class InvocationError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class RuntimeEnvironment:
    runtime_executor: RuntimeExecutor
    status_lock: RLock
    status: RuntimeStatus
    executor_endpoint: "ExecutorEndpoint"
    initialization_type: InitializationType
    last_returned: float

    def __init__(
        self,
        function_version: "FunctionVersion",
        executor_endpoint: "ExecutorEndpoint",
        initialization_type: InitializationType,
    ):
        self.id = short_uid()
        self.status = RuntimeStatus.INACTIVE
        self.status_lock = RLock()
        self.function_version = function_version
        self.executor_endpoint = executor_endpoint
        self.initialization_type = initialization_type
        self.runtime_executor = RuntimeExecutor(self.id, function_version.runtime)
        self.last_returned = -1

    def get_environment_variables(self) -> Dict[str, str]:
        """
        Returns the environment variable set for the runtime container
        :return: Dict of environment variables
        """
        env_vars = {
            # Runtime API specifics
            "LOCALSTACK_RUNTIME_ID": self.id,
            "LOCALSTACK_RUNTIME_ENDPOINT": f"http://{self.runtime_executor.get_endpoint_from_executor()}:{self.executor_endpoint.port}",
            "_HANDLER": self.function_version.handler,
            # General Lambda Environment Variables
            "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/",  # TODO correct value
            "AWS_LAMBDA_LOG_STREAM_NAME": "2022/13/32/...",  # TODO correct value
            "AWS_EXECUTION_ENV": f"Aws_Lambda_{self.function_version.runtime}",
            "AWS_LAMBDA_FUNCTION_NAME": self.function_version.qualified_arn,  # TODO use name instead of arn
            "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128",  # TODO use correct memory size
            "AWS_LAMBDA_FUNCTION_VERSION": self.function_version.qualified_arn,  # TODO use name instead of arn
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
        env_vars.update(self.function_version.environment)
        return env_vars

    # Lifecycle methods
    def start(self) -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.INACTIVE:
                raise InvalidStatusException("Runtime Handler can only be started when inactive")
            self.status = RuntimeStatus.READY
            self.runtime_executor.start(self.get_environment_variables(), self.function_version)
            # TODO start startup-timer to set timeout on starting phase

    def shutdown(self) -> None:
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

    def set_errored(self) -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.STARTING:
                raise InvalidStatusException("Runtime Handler can only error while starting")
            self.status = RuntimeStatus.FAILED

    def _invocation_url(self) -> str:
        return f"http://{self.runtime_executor.get_address()}:{INVOCATION_PORT}/invoke"

    def invoke(self, invocation_event: "InvocationStorage") -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.READY:
                raise InvalidStatusException("Invoke can only happen if status is ready")
            self.status = RuntimeStatus.RUNNING
        invoke_payload = {
            "invoke-id": invocation_event.invocation_id,
            "payload": to_str(invocation_event.invocation.payload),
        }
        LOG.debug("Sending invoke-payload '%s'", invoke_payload)
        response = requests.post(url=self._invocation_url(), json=invoke_payload)
        if not response.ok:
            raise InvocationError(
                f"Error while sending invocation {invoke_payload} to {self._invocation_url()}. Error Code: {response.status_code}"
            )
