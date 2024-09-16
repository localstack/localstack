from localstack.runtime.server.core import RuntimeServer, RuntimeServerPlugin


class TwistedRuntimeServerPlugin(RuntimeServerPlugin):
    name = "twisted"

    def load(self, *args, **kwargs) -> RuntimeServer:
        from .twisted import TwistedRuntimeServer

        return TwistedRuntimeServer()


class HypercornRuntimeServerPlugin(RuntimeServerPlugin):
    name = "hypercorn"

    def load(self, *args, **kwargs) -> RuntimeServer:
        from .hypercorn import HypercornRuntimeServer

        return HypercornRuntimeServer()
