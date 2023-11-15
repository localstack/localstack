import logging
import threading
from typing import Optional

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.client import parse_response
from localstack.http import Response
from localstack.utils.analytics.service_request_aggregator import (
    ServiceRequestAggregator,
    ServiceRequestInfo,
)

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
