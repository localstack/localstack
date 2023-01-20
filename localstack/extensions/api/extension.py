from plugin import Plugin

from .aws import CompositeHandler, CompositeResponseHandler
from .http import RouteHandler, Router


class BaseExtension(Plugin):
    """
    Base extension.
    """

    def load(self, *args, **kwargs):
        """
        Provided to plux to load the plugins. Do NOT overwrite! PluginManagers managing extensions expect the load method to return the Extension itself.

        :param args: load arguments
        :param kwargs: load keyword arguments
        :return: this extension object
        """
        self.on_extension_load(*args, **kwargs)
        return self

    def on_extension_load(self, *args, **kwargs):
        """
        Called when LocalStack loads the extension.
        """
        raise NotImplementedError


class Extension(BaseExtension):
    """
    An extension that is loaded into LocalStack dynamically.

    The method execution order of an extension is as follows:

    - on_extension_load
    - on_platform_start
    - update_gateway_routes
    - update_request_handlers
    - update_response_handlers
    - on_platform_ready
    """

    namespace = "localstack.extensions"

    def on_extension_load(self):
        """
        Called when LocalStack loads the extension.
        """
        pass

    def on_platform_start(self):
        """
        Called when LocalStack starts the main runtime.
        """
        pass

    def update_gateway_routes(self, router: Router[RouteHandler]):
        """
        Called with the Router attached to the LocalStack gateway. Overwrite this to add or update routes.

        :param router: the Router attached in the gateway
        """
        pass

    def update_request_handlers(self, handlers: CompositeHandler):
        """
        Called with the custom request handlers of the LocalStack gateway. Overwrite this to add or update handlers.

        :param handlers: custom request handlers of the gateway
        """
        pass

    def update_response_handlers(self, handlers: CompositeResponseHandler):
        """
        Called with the custom response handlers of the LocalStack gateway. Overwrite this to add or update handlers.

        :param handlers: custom response handlers of the gateway
        """
        pass

    def on_platform_ready(self):
        """
        Called when LocalStack is ready and the Ready marker has been printed.
        """
        pass

    def on_platform_shutdown(self):
        """
        Called when LocalStack is shutting down. Can be used to close any resources (threads, processes, sockets, etc.).
        """
        pass
