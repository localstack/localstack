import logging
import threading
from typing import Any, Optional

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.client import parse_response
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.http import Response
from localstack.utils.analytics.service_request_aggregator import (
    ServiceRequestAggregator,
    ServiceRequestInfo,
)
from localstack.utils.analytics.usage import UsageSetCounter

LOG = logging.getLogger(__name__)


class ServiceRequestCounter:
    aggregator: ServiceRequestAggregator

    def __init__(self, service_request_aggregator: ServiceRequestAggregator = None):
        self.aggregator = service_request_aggregator or ServiceRequestAggregator()
        self._mutex = threading.Lock()
        self._started = False

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if response is None or context.operation is None:
            return
        if config.DISABLE_EVENTS:
            return
        if context.is_internal_call:
            # don't count internal requests
            return

        # this condition will only be true only for the first call, so it makes sense to not acquire the lock every time
        if not self._started:
            with self._mutex:
                if not self._started:
                    self._started = True
                    self.aggregator.start()

        err_type = self._get_err_type(context, response) if response.status_code >= 400 else None
        service_name = context.operation.service_model.service_name
        operation_name = context.operation.name

        self.aggregator.add_request(
            ServiceRequestInfo(
                service_name,
                operation_name,
                response.status_code,
                err_type=err_type,
            )
        )

    def _get_err_type(self, context: RequestContext, response: Response) -> Optional[str]:
        """
        Attempts to re-use the existing service_response, or parse and return the error type from the response body,
        e.g. ``ResourceInUseException``.
        """
        try:
            if context.service_exception:
                return context.service_exception.code

            response = parse_response(context.operation, response)
            return response["Error"]["Code"]
        except Exception:
            if config.DEBUG_ANALYTICS:
                LOG.exception("error parsing error response")
            return None


class UsageCollectorFactory:
    _collector_registry: dict[str, Any] = {}
    """Registry for the different paths."""

    NAMESPACE_PREFIX = "agent:"
    """Namespace prefix to track usage of public endpoints (_localstack/ and _aws/)."""

    @classmethod
    def get_collector(cls, path: str):
        namespace = f"{cls.NAMESPACE_PREFIX}{path}"
        if namespace not in cls._collector_registry:
            cls._collector_registry[namespace] = UsageSetCounter(namespace)
        return cls._collector_registry[namespace]


class UserAgentCounter:
    """
    This handler collects User-Agents analytics for the LocalStack public endpoints (the ones with a _localstack or a
    _aws prefix).
    """

    def _record_usage(self, context: RequestContext) -> None:
        request_path = context.request.path
        user_agent = context.request.headers.get("User-Agent")
        if not request_path or not user_agent:
            return
        # Skip the endpoints for the new API Gateway implementation
        if "execute-api" in request_path:
            return
        # We only record the first segment in the path after the _internal/ or _aws/ prefix, as a path can have
        #   potentially an infinite number of parameters.
        recorded_path = request_path.split("/")[:2]
        if len(recorded_path) < 2:
            return
        recorded_path = "/".join(recorded_path)
        collector = UsageCollectorFactory.get_collector(recorded_path)
        collector.record(user_agent)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if config.DISABLE_EVENTS:
            return

        path = context.request.path
        if not (path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/")):
            return

        self._record_usage(context)
