import logging
from http import HTTPStatus
from typing import Dict, Optional

import requests
from flask import Flask, Response, request
from flask.typing import ResponseReturnValue

from localstack.services.awslambda.invocation.lambda_models import (
    InvocationError,
    InvocationLogs,
    InvocationResult,
    ServiceEndpoint,
)
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)
INVOCATION_PORT = 9563


class InvokeSendError(Exception):
    def __init__(self, invocation_id: str, payload: Optional[bytes]):
        message = f"Error while trying to send invocation to RAPID for id {invocation_id}. Response: {payload}"
        super().__init__(message)


class ExecutorEndpoint(Server):
    service_endpoint: ServiceEndpoint
    port: Optional[str]

    def __init__(
        self,
        port: int,
        service_endpoint: ServiceEndpoint,
        host: str = "0.0.0.0",
        container_address: Optional[str] = None,
    ) -> None:
        super().__init__(port, host)
        self.service_endpoint = service_endpoint
        self.container_address = container_address

    def _create_endpoint(self) -> Flask:
        executor_endpoint = Flask(f"executor_endpoint_{self.port}")

        @executor_endpoint.route("/invocations/<req_id>/response", methods=["POST"])
        def invocation_response(req_id: str) -> ResponseReturnValue:
            result = InvocationResult(req_id, request.data)
            self.service_endpoint.invocation_result(invoke_id=req_id, invocation_result=result)
            return Response(status=HTTPStatus.ACCEPTED)

        @executor_endpoint.route(
            "/invocations/<req_id>/error",
            methods=["POST"],
        )
        def invocation_error(req_id: str) -> ResponseReturnValue:
            LOG.debug("Got invocation error for %s", req_id)
            result = InvocationError(req_id, request.data)
            self.service_endpoint.invocation_error(invoke_id=req_id, invocation_error=result)
            return Response(status=HTTPStatus.ACCEPTED)

        @executor_endpoint.route("/invocations/<invoke_id>/logs", methods=["POST"])
        def invocation_logs(invoke_id: str) -> ResponseReturnValue:
            logs = request.json
            if isinstance(logs, Dict):
                logs["invocation_id"] = invoke_id
                invocation_logs = InvocationLogs(**logs)
                self.service_endpoint.invocation_logs(
                    invoke_id=invoke_id, invocation_logs=invocation_logs
                )
            else:
                LOG.error("Invalid logs from RAPID! Logs: %s", logs)
                # TODO handle error in some way?
            return Response(status=HTTPStatus.ACCEPTED)

        @executor_endpoint.route("/status/<executor_id>/ready", methods=["POST"])
        def status_ready(executor_id: str) -> ResponseReturnValue:
            self.service_endpoint.status_ready(executor_id=executor_id)
            return Response(status=HTTPStatus.ACCEPTED)

        @executor_endpoint.route("/status/<executor_id>/error", methods=["POST"])
        def status_error(executor_id: str) -> ResponseReturnValue:
            self.service_endpoint.status_error(executor_id=executor_id)
            return Response(status=HTTPStatus.ACCEPTED)

        return executor_endpoint

    def do_run(self) -> None:
        endpoint = self._create_endpoint()
        LOG.debug("Running executor endpoint API on %s:%s", self.host, self.port)
        endpoint.run(self.host, self.port)

    def do_shutdown(self) -> None:
        if self._thread:
            self._thread.stop()

    def invoke(self, payload: Dict[str, str]) -> None:
        if not self.container_address:
            raise ValueError("Container address not set, but got an invoke.")
        invocation_url = f"http://{self.container_address}:{INVOCATION_PORT}/invoke"
        response = requests.post(url=invocation_url, json=payload)
        if not response.ok:
            raise InvokeSendError(
                f"Error while sending invocation {payload} to {invocation_url}. Error Code: {response.status_code}"
            )
