import logging
from typing import TYPE_CHECKING

from flask import Flask
from flask.typing import ResponseReturnValue

from localstack.utils.serving import Server

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import LambdaService

RUNTIME_API_PREFIX = "/2018-06-01/runtime"
LOG = logging.getLogger(__name__)


class LambdaRuntimeAPI(Server):
    lambda_service: "LambdaService"

    def __init__(self, port: int, lambda_service: "LambdaService", host: str = "0.0.0.0") -> None:
        super().__init__(port, host)
        self.lambda_service = lambda_service

    def _create_runtime(self) -> Flask:
        runtime_api = Flask("runtime_api")

        @runtime_api.route(f"{RUNTIME_API_PREFIX}/invocation/next", methods=["GET"])
        def next_invocation() -> ResponseReturnValue:
            # TODO get proper parameters for below functions
            runtime_manager = self.lambda_service.get_lambda_version_manager("LAMBDA ARN")
            runtime_manager.get_next_invocation("executor ID")
            return 200, {}

        @runtime_api.route(f"{RUNTIME_API_PREFIX}/invocation/<req_id>/response", methods=["POST"])
        def invocation_response(req_id: str) -> ResponseReturnValue:
            return 202, ""

        @runtime_api.route(f"{RUNTIME_API_PREFIX}/init/error", methods=["POST"])
        def init_error() -> ResponseReturnValue:
            return {"invocation": "init_error"}

        @runtime_api.route(
            f"{RUNTIME_API_PREFIX}/invocation/<req_id>/error",
            methods=["POST"],
        )
        def invocation_error(req_id: str) -> ResponseReturnValue:
            return {"invocation": f"invocation_error to invocation {req_id}"}

        return runtime_api

    def do_run(self) -> None:
        runtime_api = self._create_runtime()
        LOG.debug("Running lambda runtime API on %s:%s", self.host, self.port)
        runtime_api.run(self.host, self.port)

    def do_shutdown(self) -> None:
        if self._thread:
            self._thread.stop()
