import logging
from abc import ABC, abstractmethod
from typing import Type

from plugin import PluginManager

from localstack import config
from localstack.aws.api.lambda_ import FunctionVersion
from localstack.services.awslambda.invocation.lambda_models import ServiceEndpoint
from localstack.services.awslambda.invocation.plugins import RuntimeExecutorPlugin

LOG = logging.getLogger(__name__)


class RuntimeExecutor(ABC):
    id: str
    function_version: FunctionVersion

    def __init__(
        self, id: str, function_version: FunctionVersion, service_endpoint: ServiceEndpoint
    ) -> None:
        """
        Runtime executor class responsible for executing a runtime in specific environment

        :param id: ID string of the runtime executor
        :param function_version: Function version to be executed
        :param service_endpoint: Service endpoint for execution related callbacks
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
    def invoke(self, payload: dict[str, str]) -> None:
        """
        Send an invocation to the execution environment

        :param payload: Invocation payload
        """
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
