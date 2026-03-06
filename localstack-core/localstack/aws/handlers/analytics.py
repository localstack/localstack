"""
This module provides a response handler that aggregates HTTP response data (service, operation, and status code)
and periodically emits relevant analytics events.

The `ServiceRequestCounter` class is used as a response handler in the AWS handler chain to collect
information about service requests, such as service name, operation name, and response status codes.
The collected data is then used to periodically report analytics events.

Key features and behaviors:
- Counts service-level requests (service, operation, status code).
- Periodically emits aggregated analytics events.
- Does not count internal requests (`context.is_internal_call`).
- Can be disabled via `config.DISABLE_EVENTS`.
- Provides error type parsing for failed requests (status code >= 400).
"""

import logging
import threading

from localstack import config
from localstack.aws.analytics.service_request_aggregator import (
    ServiceRequestAggregator,
    ServiceRequestInfo,
)
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.client import parse_response
from localstack.http import Response

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

    def _get_err_type(self, context: RequestContext, response: Response) -> str | None:
        """
        Attempts to re-use the existing service_response, or parse and return the error type from the response body,
        e.g. ``ResourceInUseException``.
        """
        try:
            if context.service_exception:
                return context.service_exception.code

            response = parse_response(context.operation, context.protocol, response)
            return response["Error"]["Code"]
        except Exception:
            if config.DEBUG_ANALYTICS:
                LOG.exception("error parsing error response")
            return None
