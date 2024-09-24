import dataclasses
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Type, TypedDict

from plux import PluginManager

from localstack import config
from localstack.services.lambda_.invocation.lambda_models import FunctionVersion, InvocationResult
from localstack.services.lambda_.invocation.plugins import RuntimeExecutorPlugin

LOG = logging.getLogger(__name__)


class RuntimeExecutor(ABC):
    id: str
    function_version: FunctionVersion

    def __init__(
        self,
        id: str,
        function_version: FunctionVersion,
    ) -> None:
        """
        Runtime executor class responsible for executing a runtime in specific environment

        :param id: ID string of the runtime executor
        :param function_version: Function version to be executed
        """
        self.id = id
        self.function_version = function_version

    @abstractmethod
    def start(self, env_vars: dict[str, str]) -> None:
        """
        Start the runtime executor with the given environment variables

        :param env_vars:
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Stop the runtime executor
        """
        pass

    @abstractmethod
    def get_address(self) -> str:
        """
        Get the address the runtime executor is available at for the LocalStack container.

        :return: IP address or hostname of the execution environment
        """
        pass

    @abstractmethod
    def get_endpoint_from_executor(self) -> str:
        """
        Get the address of LocalStack the runtime execution environment can communicate with LocalStack

        :return: IP address or hostname of LocalStack (from the view of the execution environment)
        """
        pass

    @abstractmethod
    def get_runtime_endpoint(self) -> str:
        """
        Gets the callback url of our executor endpoint

        :return: Base url of the callback, e.g. "http://123.123.123.123:4566/_localstack_lambda/ID1234" without trailing slash
        """
        pass

    @abstractmethod
    def invoke(self, payload: dict[str, str]) -> InvocationResult:
        """
        Send an invocation to the execution environment

        :param payload: Invocation payload
        """
        pass

    @abstractmethod
    def get_logs(self) -> str:
        """Get all logs of a given execution environment"""
        pass

    @classmethod
    @abstractmethod
    def prepare_version(cls, function_version: FunctionVersion) -> None:
        """
        Prepare a given function version to be executed.
        Includes all the preparation work necessary for execution, short of starting anything

        :param function_version: Function version to prepare
        """
        pass

    @classmethod
    @abstractmethod
    def cleanup_version(cls, function_version: FunctionVersion):
        """
        Cleanup the version preparation for the given version.
        Should cleanup preparation steps taken by prepare_version
        :param function_version:
        """
        pass

    @classmethod
    def validate_environment(cls) -> bool:
        """Validates the setup of the environment and provides an opportunity to log warnings.
        Returns False if an invalid environment is detected and True otherwise."""
        return True


class LambdaRuntimeException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


@dataclasses.dataclass
class LambdaPrebuildContext:
    docker_file_content: str
    context_path: Path
    function_version: FunctionVersion


class ChmodPath(TypedDict):
    path: str
    mode: str


EXECUTOR_PLUGIN_MANAGER: PluginManager[Type[RuntimeExecutor]] = PluginManager(
    RuntimeExecutorPlugin.namespace
)


def get_runtime_executor() -> Type[RuntimeExecutor]:
    plugin_name = config.LAMBDA_RUNTIME_EXECUTOR or "docker"
    if not EXECUTOR_PLUGIN_MANAGER.exists(plugin_name):
        LOG.warning(
            'Invalid specified plugin name %s. Falling back to "docker" runtime executor',
            plugin_name,
        )
        plugin_name = "docker"
    return EXECUTOR_PLUGIN_MANAGER.load(plugin_name).load()
