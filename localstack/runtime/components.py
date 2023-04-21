"""
Core components of the runtime available as global singletons.
"""
from functools import cached_property
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from localstack.aws.app import LocalstackAwsGateway
    from localstack.services.plugins import ServicePluginManager

gateway: "LocalstackAwsGateway"
"""The Gateway processes incoming HTTP request and dispatches them to AWS services or internal resources"""

service_plugin_manager: "ServicePluginManager"
"""The plugin manager """


class RuntimeContainer:
    """
    Class that provides the core runtime components as singleton factories.
    """

    @cached_property
    def service_plugin_manager(self) -> "ServicePluginManager":
        # TODO: migrate creation here
        from localstack.services.plugins import SERVICE_PLUGINS

        return SERVICE_PLUGINS

    @cached_property
    def gateway(self) -> "LocalstackAwsGateway":
        from localstack.aws.app import LocalstackAwsGateway

        return LocalstackAwsGateway(self.service_plugin_manager)


_container = RuntimeContainer()


def __getattr__(name) -> Any:
    """
    Provides dynamic and lazy access to runtime components. Can be used like this::

        from localstack.runtime import components

        assert isinstance(components.gateway, LocalstackAwsGateway)

    or even::

        from localstack.runtime.components import gateway

        assert isinstance(gateway, LocalstackAwsGateway)

    :param name: the component to get
    :return: the component if it exists
    """
    return getattr(_container, name)
