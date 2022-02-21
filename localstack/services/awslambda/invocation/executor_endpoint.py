import abc
import logging
from typing import TYPE_CHECKING

from flask import Flask
from flask.typing import ResponseReturnValue

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.version_manager import (
        InvocationError,
        InvocationResult,
    )
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class ServiceEndpoint(abc.ABC):
    def invocation_result(self, request_id: str, invocation_result: "InvocationResult"):
        raise NotImplementedError()

    def invocation_error(self, request_id: str, invocation_error: "InvocationError"):
        raise NotImplementedError()


class ExecutorEndpoint(Server):
    service_endpoint: ServiceEndpoint

    def __init__(self, port: int, service_endpoint: ServiceEndpoint, host: str = "0.0.0.0") -> None:
        super().__init__(port, host)
        self.service_endpoint = service_endpoint

    def _create_runtime(self) -> Flask:
        executor_endpoint = Flask(f"executor_endpoint_{self.port}")

        @executor_endpoint.route("/invocation/<req_id>/response", methods=["POST"])
        def invocation_response(req_id: str) -> ResponseReturnValue:
            return ""

        @executor_endpoint.route(
            "/invocation/<req_id>/error",
            methods=["POST"],
        )
        def invocation_error(req_id: str) -> ResponseReturnValue:
            return {"invocation": f"invocation_error to invocation {req_id}"}

        @executor_endpoint.route("/status/<runtime_id>/ready", methods=["POST"])
        def status_ready() -> ResponseReturnValue:
            return {"invocation": "init_error"}

        @executor_endpoint.route("/status/<runtime_id>/error", methods=["POST"])
        def status_error() -> ResponseReturnValue:
            return {"invocation": "init_error"}

        return executor_endpoint

    def do_run(self) -> None:
        runtime_api = self._create_runtime()
        LOG.debug("Running lambda runtime API on %s:%s", self.host, self.port)
        runtime_api.run(self.host, self.port)

    def do_shutdown(self) -> None:
        if self._thread:
            self._thread.stop()
