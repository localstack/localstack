"""
This package contains code to define and manage the core components that make up a ``LocalstackRuntime``.
These include:
  - A ``Gateway``
  - A ``RuntimeServer`` as the main control loop
  - A ``ServiceManager`` to manage service plugins (TODO: once the Service concept has been generalized)
  - ... ?

Components can then be accessed via ``get_current_runtime()``.
"""

from functools import cached_property

from plux import Plugin, PluginManager
from rolo.gateway import Gateway

from .server.core import RuntimeServer, RuntimeServerPlugin


class Components(Plugin):
    """
    A Plugin that allows a specific localstack runtime implementation (aws, snowflake, ...) to expose its
    own component factory.
    """

    namespace = "localstack.runtime.components"

    @cached_property
    def gateway(self) -> Gateway:
        raise NotImplementedError

    @cached_property
    def runtime_server(self) -> RuntimeServer:
        raise NotImplementedError


class BaseComponents(Components):
    """
    A component base, which includes a ``RuntimeServer`` created from the config variable, and a default
    ServicePluginManager as ServiceManager.
    """

    @cached_property
    def runtime_server(self) -> RuntimeServer:
        from localstack import config

        # TODO: rename to RUNTIME_SERVER
        server_type = config.GATEWAY_SERVER

        plugins = PluginManager(RuntimeServerPlugin.namespace)

        if not plugins.exists(server_type):
            raise ValueError(f"Unknown gateway server type {server_type}")

        plugins.load(server_type)
        return plugins.get_container(server_type).load_value
