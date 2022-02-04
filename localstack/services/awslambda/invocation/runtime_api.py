import logging

from flask import Flask

from localstack.utils.serving import Server

RUNTIME_API_PREFIX = "/2018-06-01/runtime"
LOG = logging.getLogger(__name__)

runtime_api = Flask("runtime_api")


class LambdaRuntimeAPI:
    @runtime_api.route(f"{RUNTIME_API_PREFIX}/invocation/next", methods=["GET"])
    def next_invocation(self):
        return 200, {}

    @runtime_api.route(f"{RUNTIME_API_PREFIX}/invocation/<req_id>/response", methods=["POST"])
    def invocation_response(self, req_id: str):
        return 202, ""

    @runtime_api.route(f"{RUNTIME_API_PREFIX}/init/error", methods=["POST"])
    def init_error(self):
        return {"invocation": "init_error"}

    @runtime_api.route(
        f"{RUNTIME_API_PREFIX}/invocation/<req_id>/error",
        methods=["POST"],
    )
    def invocation_error(self, req_id: str):
        return {"invocation": f"invocation_error to invocation {req_id}"}


class RuntimeAPIServer(Server):
    def __init__(self, port: int, host: str = "0.0.0.0"):
        super().__init__(port, host)

    def do_run(self):
        runtime_api.run(self.host, self.port)

    def do_shutdown(self):
        self._thread.stop()

    def cleanup(self):
        if not self.is_running():
            return
