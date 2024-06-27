from abc import abstractmethod

from plux import Plugin, PluginManager

from localstack.http import Response
from localstack.utils.objects import singleton_factory

from ..api import RestApiInvocationContext


class RestApiIntegrationPlugin(Plugin):
    namespace = "localstack.services.apigateway.restapi.integrations"

    @abstractmethod
    def invoke(self, context: RestApiInvocationContext) -> Response:
        pass


class RestApiPluginManager(PluginManager[RestApiIntegrationPlugin]):
    def __init__(self):
        super().__init__(RestApiIntegrationPlugin.namespace)

    @staticmethod
    @singleton_factory
    def get() -> "RestApiPluginManager":
        """Returns a singleton instance of the manager."""
        return RestApiPluginManager()

    def get_plugin(self, integration_type: str) -> RestApiIntegrationPlugin | None:
        """
        Get the API Gateway REST API Integration plugin for the specific Integration Type.

        :param integration_type: Integration type the REST API Integration plugin will be returned for
        :return: RestApiIntegrationPlugin for the specified Integration Type, None if not existent.
        """
        try:
            return self.load(integration_type)
        except ValueError:
            return None
