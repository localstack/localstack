import logging
from concurrent.futures import CancelledError, Future
from http import HTTPStatus
from typing import Dict, Optional

import requests
from werkzeug import Request
from werkzeug.routing import Rule

from localstack.http import Response, Router
from localstack.services.edge import ROUTER
from localstack.services.lambda_.invocation.lambda_models import InvocationResult
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)
INVOCATION_PORT = 9563

NAMESPACE = "/_localstack_lambda"


class InvokeSendError(Exception):
    def __init__(self, message):
        super().__init__(message)


class StatusErrorException(Exception):
    payload: bytes

    def __init__(self, message, payload: bytes):
        super().__init__(message)
        self.payload = payload


class ShutdownDuringStartup(Exception):
    def __init__(self, message):
        super().__init__(message)


class ExecutorEndpoint:
    container_address: str
    container_port: int
    rules: list[Rule]
    endpoint_id: str
    router: Router
    startup_future: Future[bool] | None
    invocation_future: Future[InvocationResult] | None
    logs: str | None

    def __init__(
        self,
        endpoint_id: str,
        container_address: Optional[str] = None,
        container_port: Optional[int] = INVOCATION_PORT,
    ) -> None:
        self.container_address = container_address
        self.container_port = container_port
        self.rules = []
        self.endpoint_id = endpoint_id
        self.router = ROUTER
        self.startup_future = None
        self.invocation_future = None
        self.logs = None

    def _create_endpoint(self, router: Router) -> list[Rule]:
        def invocation_response(request: Request, req_id: str) -> Response:
            result = InvocationResult(req_id, request.data, is_error=False, logs=self.logs)
            self.invocation_future.set_result(result)
            return Response(status=HTTPStatus.ACCEPTED)

        def invocation_error(request: Request, req_id: str) -> Response:
            result = InvocationResult(req_id, request.data, is_error=True, logs=self.logs)
            self.invocation_future.set_result(result)
            return Response(status=HTTPStatus.ACCEPTED)

        def invocation_logs(request: Request, invoke_id: str) -> Response:
            logs = request.json
            if isinstance(logs, Dict):
                self.logs = logs["logs"]
            else:
                LOG.error("Invalid logs from RAPID! Logs: %s", logs)
            return Response(status=HTTPStatus.ACCEPTED)

        def status_ready(request: Request, executor_id: str) -> Response:
            self.startup_future.set_result(True)
            return Response(status=HTTPStatus.ACCEPTED)

        def status_error(request: Request, executor_id: str) -> Response:
            LOG.warning("Execution environment startup failed: %s", to_str(request.data))
            # TODO: debug Lambda runtime init to not send `runtime/init/error` twice
            if self.startup_future.done():
                return Response(status=HTTPStatus.BAD_REQUEST)
            self.startup_future.set_exception(
                StatusErrorException("Environment startup failed", payload=request.data)
            )
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
        self.startup_future = Future()

    def wait_for_startup(self):
        try:
            self.startup_future.result()
        except CancelledError as e:
            # Only happens if we shutdown the container during execution environment startup
            # Daniel: potential problem if we have a shutdown while we start the container (e.g., timeout) but wait_for_startup is not yet called
            raise ShutdownDuringStartup(
                "Executor environment shutdown during container startup"
            ) from e

    def shutdown(self) -> None:
        self.router.remove(self.rules)
        self.startup_future.cancel()
        if self.invocation_future:
            self.invocation_future.cancel()

    def invoke(self, payload: Dict[str, str]) -> InvocationResult:
        self.invocation_future = Future()
        self.logs = None
        if not self.container_address:
            raise ValueError("Container address not set, but got an invoke.")
        invocation_url = f"http://{self.container_address}:{self.container_port}/invoke"
        # disable proxies for internal requests
        proxies = {"http": "", "https": ""}
        response = requests.post(url=invocation_url, json=payload, proxies=proxies)
        if not response.ok:
            raise InvokeSendError(
                f"Error while sending invocation {payload} to {invocation_url}. Error Code: {response.status_code}"
            )
        # Do not wait longer for an invoke than the maximum lambda timeout plus a buffer
        # TODO: Can we really make this assumption for debugging?
        lambda_max_timeout_seconds = 900
        invoke_timeout_buffer_seconds = 5
        return self.invocation_future.result(
            timeout=lambda_max_timeout_seconds + invoke_timeout_buffer_seconds
        )
