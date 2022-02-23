import abc
import dataclasses
import logging
from typing import Optional

from flask import Flask, request
from flask.typing import ResponseReturnValue

from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class InvocationResult:
    invocation_id: str
    payload: Optional[bytes]
    logs: Optional[bytes] = None


@dataclasses.dataclass
class InvocationError:
    invocation_id: str
    payload: Optional[bytes]


@dataclasses.dataclass
class InvocationLogs:
    invocation_id: str
    logs: Optional[bytes]


class ServiceEndpoint(abc.ABC):
    def invocation_result(self, invoke_id: str, invocation_result: InvocationResult) -> None:
        """
        Processes the result of an invocation
        :param invoke_id: Invocation Id
        :param invocation_result: Invocation Result
        """
        raise NotImplementedError()

    def invocation_error(self, invoke_id: str, invocation_error: InvocationError) -> None:
        """
        Processes an error during an invocation
        :param invoke_id: Invocation Id
        :param invocation_error: Invocation Error
        """
        raise NotImplementedError()

    def invocation_logs(self, invoke_id: str, invocation_logs: InvocationLogs) -> None:
        """
        Processes the logs of an invocation
        :param invoke_id: Invocation Id
        :param invocation_logs: Invocation logs
        """
        raise NotImplementedError()

    def status_ready(self, executor_id: str) -> None:
        raise NotImplementedError()

    def status_error(self, executor_id: str) -> None:
        raise NotImplementedError()


class ExecutorEndpoint(Server):
    service_endpoint: ServiceEndpoint

    def __init__(self, port: int, service_endpoint: ServiceEndpoint, host: str = "0.0.0.0") -> None:
        super().__init__(port, host)
        self.service_endpoint = service_endpoint

    def _create_endpoint(self) -> Flask:
        executor_endpoint = Flask(f"executor_endpoint_{self.port}")

        @executor_endpoint.route("/invocations/<req_id>/response", methods=["POST"])
        def invocation_response(req_id: str) -> ResponseReturnValue:
            result = InvocationResult(req_id, request.data)
            self.service_endpoint.invocation_result(invoke_id=req_id, invocation_result=result)
            return ""

        @executor_endpoint.route(
            "/invocations/<req_id>/error",
            methods=["POST"],
        )
        def invocation_error(req_id: str) -> ResponseReturnValue:
            LOG.debug("Got invocation error for %s", req_id)
            result = InvocationError(req_id, request.data)
            self.service_endpoint.invocation_error(invoke_id=req_id, invocation_error=result)
            return {"invocation": f"invocation_error to invocation {req_id}"}

        @executor_endpoint.route("/invocations/<invoke_id>/logs", methods=["POST"])
        def invocation_logs(invoke_id: str) -> ResponseReturnValue:
            logs = request.json
            logs["invocation_id"] = invoke_id
            logs = InvocationLogs(**logs)
            self.service_endpoint.invocation_logs(invoke_id=invoke_id, invocation_logs=logs)
            return ""

        @executor_endpoint.route("/status/<executor_id>/ready", methods=["POST"])
        def status_ready(executor_id: str) -> ResponseReturnValue:
            self.service_endpoint.status_ready(executor_id=executor_id)
            return {"invocation": "init_ready"}

        @executor_endpoint.route("/status/<executor_id>/error", methods=["POST"])
        def status_error(executor_id: str) -> ResponseReturnValue:
            self.service_endpoint.status_error(executor_id=executor_id)
            return {"invocation": "init_error"}

        return executor_endpoint

    def do_run(self) -> None:
        endpoint = self._create_endpoint()
        LOG.debug("Running executor endpoint API on %s:%s", self.host, self.port)
        endpoint.run(self.host, self.port)

    def do_shutdown(self) -> None:
        if self._thread:
            self._thread.stop()
