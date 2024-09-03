import abc
import logging
from concurrent.futures import CancelledError, Future
from http import HTTPStatus
from typing import Dict, Optional

import requests
from werkzeug import Request

from localstack.http import Response, route
from localstack.services.edge import ROUTER
from localstack.services.lambda_.invocation.lambda_models import InvocationResult
from localstack.utils.lambda_debug_mode.lambda_debug_mode import (
    DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS,
    is_lambda_debug_mode,
)
from localstack.utils.objects import singleton_factory
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


class Endpoint(abc.ABC):
    @abc.abstractmethod
    def invocation_response(self, request: Request, req_id: str) -> Response:
        pass

    @abc.abstractmethod
    def invocation_error(self, request: Request, req_id: str) -> Response:
        pass

    @abc.abstractmethod
    def invocation_logs(self, request: Request, invoke_id: str) -> Response:
        pass

    @abc.abstractmethod
    def status_ready(self, request: Request, executor_id: str) -> Response:
        pass

    @abc.abstractmethod
    def status_error(self, request: Request, executor_id: str) -> Response:
        pass


class ExecutorRouter:
    endpoints: dict[str, Endpoint]

    def __init__(self):
        self.endpoints = {}

    def register_endpoint(self, executor_id: str, endpoint: Endpoint):
        self.endpoints[executor_id] = endpoint

    def unregister_endpoint(self, executor_id: str):
        self.endpoints.pop(executor_id)

    @route(f"{NAMESPACE}/<executor_id>/invocations/<req_id>/response", methods=["POST"])
    def invocation_response(self, request: Request, executor_id: str, req_id: str) -> Response:
        endpoint = self.endpoints[executor_id]
        return endpoint.invocation_response(request, req_id)

    @route(f"{NAMESPACE}/<executor_id>/invocations/<req_id>/error", methods=["POST"])
    def invocation_error(self, request: Request, executor_id: str, req_id: str) -> Response:
        endpoint = self.endpoints[executor_id]
        return endpoint.invocation_error(request, req_id)

    @route(f"{NAMESPACE}/<executor_id>/invocations/<invoke_id>/logs", methods=["POST"])
    def invocation_logs(self, request: Request, executor_id: str, invoke_id: str) -> Response:
        endpoint = self.endpoints[executor_id]
        return endpoint.invocation_logs(request, invoke_id)

    @route(f"{NAMESPACE}/<env_id>/status/<executor_id>/ready", methods=["POST"])
    def status_ready(self, request: Request, env_id: str, executor_id: str) -> Response:
        endpoint = self.endpoints[executor_id]
        return endpoint.status_ready(request, executor_id)

    @route(f"{NAMESPACE}/<env_id>/status/<executor_id>/error", methods=["POST"])
    def status_error(self, request: Request, env_id: str, executor_id: str) -> Response:
        endpoint = self.endpoints[executor_id]
        return endpoint.status_error(request, executor_id)


@singleton_factory
def executor_router():
    router = ExecutorRouter()
    ROUTER.add(router)
    return router


class ExecutorEndpoint(Endpoint):
    container_address: str
    container_port: int
    executor_id: str
    startup_future: Future[bool] | None
    invocation_future: Future[InvocationResult] | None
    logs: str | None

    def __init__(
        self,
        executor_id: str,
        container_address: Optional[str] = None,
        container_port: Optional[int] = INVOCATION_PORT,
    ) -> None:
        self.container_address = container_address
        self.container_port = container_port
        self.executor_id = executor_id
        self.startup_future = None
        self.invocation_future = None
        self.logs = None

    def invocation_response(self, request: Request, req_id: str) -> Response:
        result = InvocationResult(req_id, request.data, is_error=False, logs=self.logs)
        self.invocation_future.set_result(result)
        return Response(status=HTTPStatus.ACCEPTED)

    def invocation_error(self, request: Request, req_id: str) -> Response:
        result = InvocationResult(req_id, request.data, is_error=True, logs=self.logs)
        self.invocation_future.set_result(result)
        return Response(status=HTTPStatus.ACCEPTED)

    def invocation_logs(self, request: Request, invoke_id: str) -> Response:
        logs = request.json
        if isinstance(logs, Dict):
            self.logs = logs["logs"]
        else:
            LOG.error("Invalid logs from init! Logs: %s", logs)
        return Response(status=HTTPStatus.ACCEPTED)

    def status_ready(self, request: Request, executor_id: str) -> Response:
        self.startup_future.set_result(True)
        return Response(status=HTTPStatus.ACCEPTED)

    def status_error(self, request: Request, executor_id: str) -> Response:
        LOG.warning("Execution environment startup failed: %s", to_str(request.data))
        # TODO: debug Lambda runtime init to not send `runtime/init/error` twice
        if self.startup_future.done():
            return Response(status=HTTPStatus.BAD_REQUEST)
        self.startup_future.set_exception(
            StatusErrorException("Environment startup failed", payload=request.data)
        )
        return Response(status=HTTPStatus.ACCEPTED)

    def start(self) -> None:
        executor_router().register_endpoint(self.executor_id, self)
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

    def get_endpoint_prefix(self):
        return f"{NAMESPACE}/{self.executor_id}"

    def shutdown(self) -> None:
        executor_router().unregister_endpoint(self.executor_id)
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

        # Set a reference future awaiting limit to ensure this process eventually ends,
        # with timeout errors being handled by the lambda evaluator.
        # The following logic selects which maximum waiting time to consider depending
        # on whether the application is being debugged or not.
        # Note that if timeouts are enforced for the lambda function invoked at this endpoint
        # (this is needs to be configured in the Lambda Debug Mode Config file), the lambda
        # function will continue to enforce the expected timeouts.
        if is_lambda_debug_mode():
            # The value is set to a default high value to ensure eventual termination.
            timeout_seconds = DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS
        else:
            # Do not wait longer for an invoke than the maximum lambda timeout plus a buffer
            lambda_max_timeout_seconds = 900
            invoke_timeout_buffer_seconds = 5
            timeout_seconds = lambda_max_timeout_seconds + invoke_timeout_buffer_seconds
        return self.invocation_future.result(timeout=timeout_seconds)
