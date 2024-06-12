from plux import Plugin
from rolo.gateway import Gateway

from localstack import config


class RuntimeServer:
    """
    The main network IO loop of LocalStack. This could be twisted, hypercorn, or any other server
    implementation.
    """

    def register(
        self,
        gateway: Gateway,
        listen: list[config.HostAndPort],
        ssl_creds: tuple[str, str] | None = None,
    ):
        """
        Registers the Gateway and the port configuration into the server. Some servers like ``twisted`` or
        ``hypercorn`` support multiple calls to ``register``, allowing you to serve several Gateways
        through a single event loop.

        :param gateway: the gateway to serve
        :param listen: the host and port configuration
        :param ssl_creds: ssl credentials (certificate file path, key file path)
        """
        raise NotImplementedError

    def run(self):
        """
        Run the server and block the thread.
        """
        raise NotImplementedError

    def shutdown(self):
        """
        Shutdown the running server.
        """
        raise NotImplementedError


class RuntimeServerPlugin(Plugin):
    """
    Plugin that serves as a factory for specific ```RuntimeServer`` implementations.
    """

    namespace = "localstack.runtime.server"

    def load(self, *args, **kwargs) -> RuntimeServer:
        raise NotImplementedError
