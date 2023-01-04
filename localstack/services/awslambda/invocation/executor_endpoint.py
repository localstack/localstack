import logging
from http import HTTPStatus
from typing import Dict, Optional

import requests
from werkzeug import Request
from werkzeug.routing import Rule

from localstack.http import Response, Router
from localstack.services.awslambda.invocation.lambda_models import (
    InvocationError,
    InvocationLogs,
    InvocationResult,
    ServiceEndpoint,
)
from localstack.services.edge import ROUTER

LOG = logging.getLogger(__name__)
INVOCATION_PORT = 9563

NAMESPACE = "/_localstack_lambda"


class InvokeSendError(Exception):
    def __init__(self, message):
        super().__init__(message)


class ExecutorEndpoint:
    service_endpoint: ServiceEndpoint
    container_address: str
    container_port: int
    rules: list[Rule]
    endpoint_id: str
    router: Router

    def __init__(
        self,
        endpoint_id: str,
        service_endpoint: ServiceEndpoint,
        container_address: Optional[str] = None,
        container_port: Optional[int] = INVOCATION_PORT,
    ) -> None:
        self.service_endpoint = service_endpoint
        self.container_address = container_address
        self.container_port = container_port
        self.rules = []
        self.endpoint_id = endpoint_id
        self.router = ROUTER

    def _create_endpoint(self, router: Router) -> list[Rule]:
        def invocation_response(request: Request, req_id: str) -> Response:
            result = InvocationResult(req_id, request.data)
            self.service_endpoint.invocation_result(invoke_id=req_id, invocation_result=result)
            return Response(status=HTTPStatus.ACCEPTED)

        def invocation_error(request: Request, req_id: str) -> Response:
            result = InvocationError(req_id, request.data)
            self.service_endpoint.invocation_error(invoke_id=req_id, invocation_error=result)
            return Response(status=HTTPStatus.ACCEPTED)

        def invocation_logs(request: Request, invoke_id: str) -> Response:
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

        def status_ready(request: Request, executor_id: str) -> Response:
            self.service_endpoint.status_ready(executor_id=executor_id)
            return Response(status=HTTPStatus.ACCEPTED)

        def status_error(request: Request, executor_id: str) -> Response:
            self.service_endpoint.status_error(executor_id=executor_id)
            return Response(status=HTTPStatus.ACCEPTED)

        return [
            router.add(
                f"{self.get_endpoint_prefix()}/invocations/<req_id>/response",
                endpoint=invocation_response,
                methods=["POST"],
            ),
            router.add(
                f"{self.get_endpoint_prefix()}/invocations/<req_id>/error",
                endpoint=invocation_error,
                methods=["POST"],
            ),
            router.add(
                f"{self.get_endpoint_prefix()}/invocations/<invoke_id>/logs",
                endpoint=invocation_logs,
                methods=["POST"],
            ),
            router.add(
                f"{self.get_endpoint_prefix()}/status/<executor_id>/ready",
                endpoint=status_ready,
                methods=["POST"],
            ),
            router.add(
                f"{self.get_endpoint_prefix()}/status/<executor_id>/error",
                endpoint=status_error,
                methods=["POST"],
            ),
        ]

    def get_endpoint_prefix(self):
        return f"{NAMESPACE}/{self.endpoint_id}"

    def start(self) -> None:
        self.rules = self._create_endpoint(self.router)

    def shutdown(self) -> None:
        for rule in self.rules:
            self.router.remove_rule(rule)

    def invoke(self, payload: Dict[str, str]) -> None:
        if not self.container_address:
            raise ValueError("Container address not set, but got an invoke.")
        invocation_url = f"http://{self.container_address}:{self.container_port}/invoke"
        response = requests.post(url=invocation_url, json=payload)
        if not response.ok:
            raise InvokeSendError(
                f"Error while sending invocation {payload} to {invocation_url}. Error Code: {response.status_code}"
            )
