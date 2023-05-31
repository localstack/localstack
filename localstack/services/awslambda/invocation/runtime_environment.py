import binascii
import logging
import os
import random
import string
import time
from datetime import date, datetime
from enum import Enum, auto
from threading import RLock, Timer
from typing import TYPE_CHECKING, Dict, Literal, Optional

from localstack import config
from localstack.aws.api.lambda_ import TracingMode
from localstack.aws.connect import connect_to
from localstack.services.awslambda.invocation.executor_endpoint import ServiceEndpoint
from localstack.services.awslambda.invocation.lambda_models import Credentials, FunctionVersion
from localstack.services.awslambda.invocation.runtime_executor import (
    RuntimeExecutor,
    get_runtime_executor,
)
from localstack.utils.strings import to_str

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.version_manager import QueuedInvocation

STARTUP_TIMEOUT_SEC = config.LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT
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


# TODO: add status callback
class RuntimeEnvironment:
    runtime_executor: RuntimeExecutor
    status_lock: RLock
    status: RuntimeStatus
    initialization_type: InitializationType
    last_returned: datetime
    startup_timer: Optional[Timer]
    keepalive_timer: Optional[Timer]

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
        self.runtime_executor = get_runtime_executor()(
            self.id, function_version, service_endpoint=service_endpoint
        )
        self.last_returned = datetime.min
        self.startup_timer = None
        self.keepalive_timer = Timer(0, lambda *args, **kwargs: None)

    def get_log_group_name(self) -> str:
        return f"/aws/lambda/{self.function_version.id.function_name}"

    def get_log_stream_name(self) -> str:
        return f"{date.today():%Y/%m/%d}/[{self.function_version.id.qualifier}]{self.id}"

    def get_environment_variables(self) -> Dict[str, str]:
        """
        Returns the environment variable set for the runtime container
        :return: Dict of environment variables
        """
        credentials = self.get_credentials()
        env_vars = {
            # 1) Public AWS defined runtime environment variables (in same order):
            # https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
            # a) Reserved environment variables
            # _HANDLER conditionally added below
            # TODO: _X_AMZN_TRACE_ID
            "AWS_DEFAULT_REGION": self.function_version.id.region,
            "AWS_REGION": self.function_version.id.region,
            # AWS_EXECUTION_ENV conditionally added below
            "AWS_LAMBDA_FUNCTION_NAME": self.function_version.id.function_name,
            "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": self.function_version.config.memory_size,
            "AWS_LAMBDA_FUNCTION_VERSION": self.function_version.id.qualifier,
            "AWS_LAMBDA_INITIALIZATION_TYPE": self.initialization_type,
            "AWS_LAMBDA_LOG_GROUP_NAME": self.get_log_group_name(),
            "AWS_LAMBDA_LOG_STREAM_NAME": self.get_log_stream_name(),
            # Access IDs for role
            "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
            "AWS_SESSION_TOKEN": credentials["SessionToken"],
            # AWS_LAMBDA_RUNTIME_API is set in the runtime interface emulator (RIE)
            "LAMBDA_TASK_ROOT": "/var/task",
            "LAMBDA_RUNTIME_DIR": "/var/runtime",
            # b) Unreserved environment variables
            # LANG
            # LD_LIBRARY_PATH
            # NODE_PATH
            # PYTHONPATH
            # GEM_PATH
            "AWS_XRAY_CONTEXT_MISSING": "LOG_ERROR",
            # TODO: allow configuration of xray address
            "AWS_XRAY_DAEMON_ADDRESS": "127.0.0.1:2000",
            # not 100% sure who sets these two
            # extensions are not supposed to have them in their envs => TODO: test if init removes them
            "_AWS_XRAY_DAEMON_PORT": "2000",
            "_AWS_XRAY_DAEMON_ADDRESS": "127.0.0.1",
            # AWS_LAMBDA_DOTNET_PREJIT
            "TZ": ":UTC",
            # 2) Public AWS RIE interface: https://github.com/aws/aws-lambda-runtime-interface-emulator
            "AWS_LAMBDA_FUNCTION_TIMEOUT": self.function_version.config.timeout,
            # 3) Public LocalStack endpoint
            "LOCALSTACK_HOSTNAME": self.runtime_executor.get_endpoint_from_executor(),
            "EDGE_PORT": str(config.EDGE_PORT),
            "AWS_ENDPOINT_URL": f"http://{self.runtime_executor.get_endpoint_from_executor()}:{config.EDGE_PORT}",
            # 4) Internal LocalStack runtime API
            "LOCALSTACK_RUNTIME_ID": self.id,
            "LOCALSTACK_RUNTIME_ENDPOINT": self.runtime_executor.get_runtime_endpoint(),
            # used by the init to spawn the x-ray daemon
            # LOCALSTACK_USER conditionally added below
        }
        # Conditionally added environment variables
        # config.handler is None for image lambdas and will be populated at runtime (e.g., by RIE)
        if self.function_version.config.handler:
            env_vars["_HANDLER"] = self.function_version.config.handler
        # Not defined for custom runtimes (e.g., provided, provided.al2)
        if self.function_version.config.runtime:
            env_vars["AWS_EXECUTION_ENV"] = f"Aws_Lambda_{self.function_version.config.runtime}"
        if self.function_version.config.environment:
            env_vars.update(self.function_version.config.environment)
        if config.LAMBDA_INIT_DEBUG:
            # Disable dropping privileges because it breaks debugging
            env_vars["LOCALSTACK_USER"] = ""
        if config.LAMBDA_INIT_USER:
            env_vars["LOCALSTACK_USER"] = config.LAMBDA_INIT_USER
        if config.DEBUG:
            env_vars["LOCALSTACK_INIT_LOG_LEVEL"] = "debug"
        if config.LAMBDA_INIT_POST_INVOKE_WAIT_MS:
            env_vars["LOCALSTACK_POST_INVOKE_WAIT_MS"] = int(config.LAMBDA_INIT_POST_INVOKE_WAIT_MS)
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
            try:
                self.runtime_executor.start(self.get_environment_variables())
            except Exception as e:
                LOG.warning(
                    "Failed to start runtime environment for ID=%s with: %s",
                    self.id,
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                self.errored()
                raise
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
            self.keepalive_timer.cancel()

    # Status methods
    def set_ready(self) -> None:
        with self.status_lock:
            if self.status != RuntimeStatus.STARTING:
                raise InvalidStatusException(
                    f"Runtime Handler can only be set active while starting. Current status: {self.status}"
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

            if self.initialization_type == "on-demand":
                self.keepalive_timer = Timer(
                    config.LAMBDA_KEEPALIVE_MS / 1000, self.keepalive_passed
                )
                self.keepalive_timer.start()

    def keepalive_passed(self) -> None:
        LOG.debug(
            "Executor %s for function %s hasn't received any invocations in a while. Stopping.",
            self.id,
            self.function_version.qualified_arn,
        )
        self.stop()

    def timed_out(self) -> None:
        LOG.warning(
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
            self.keepalive_timer.cancel()

        invoke_payload = {
            "invoke-id": invocation_event.invocation.request_id,  # TODO: rename to request-id
            "invoked-function-arn": invocation_event.invocation.invoked_arn,
            "payload": to_str(invocation_event.invocation.payload),
            "trace-id": self._generate_trace_header(),
        }
        self.runtime_executor.invoke(payload=invoke_payload)

    def get_credentials(self) -> Credentials:
        sts_client = connect_to().sts.request_metadata(service_principal="lambda")
        # TODO we should probably set a maximum alive duration for environments, due to the session expiration
        return sts_client.assume_role(
            RoleArn=self.function_version.config.role,
            RoleSessionName=self.function_version.id.function_name,
            DurationSeconds=43200,
        )["Credentials"]

    def _generate_trace_id(self):
        """https://docs.aws.amazon.com/xray/latest/devguide/xray-api-sendingdata.html#xray-api-traceids"""
        # TODO: add test for start time
        original_request_epoch = int(time.time())
        timestamp_hex = hex(original_request_epoch)[2:]
        version_number = "1"
        unique_id = binascii.hexlify(os.urandom(12)).decode("utf-8")
        return f"{version_number}-{timestamp_hex}-{unique_id}"

    def _generate_trace_header(self):
        """
        https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html

        "The sampling rate is 1 request per second and 5 percent of additional requests."

        Currently we implement a simpler, more predictable strategy.
        If TracingMode is "Active", we always sample the request. (Sampled=1)

        TODO: implement passive tracing
        TODO: use xray sdk here
        """
        if self.function_version.config.tracing_config_mode == TracingMode.Active:
            sampled = "1"
        else:
            sampled = "0"

        root_trace_id = self._generate_trace_id()

        parent = binascii.b2a_hex(os.urandom(8)).decode(
            "utf-8"
        )  # TODO: segment doesn't actually exist at the moment
        return f"Root={root_trace_id};Parent={parent};Sampled={sampled}"
