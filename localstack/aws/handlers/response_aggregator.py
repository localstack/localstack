import logging
import threading
from typing import Optional

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.analytics.response_aggregator import ResponseAggregator
from localstack.utils.aws.aws_responses import parse_response

LOG = logging.getLogger(__name__)


class ResponseAggregatorHandler:
    def __init__(self):
        self.aggregator = ResponseAggregator()
        self.aggregator_thread = None
        self._aggregator_mutex = threading.Lock()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if response is None or context.service is None or context.operation is None:
            return
        if config.DISABLE_EVENTS:
            return
        # this condition will only be true only for the first call, so it makes sense to not acquire the lock every time
        if self.aggregator_thread is None:
            with self._aggregator_mutex:
                if self.aggregator_thread is None:
                    self.aggregator_thread = self.aggregator.start_thread()

        err_type = self._get_err_type(context, response) if response.status_code >= 400 else None
        self.aggregator.add_response(
            context.service.service_name,
            context.operation.name,
            response.status_code,
            err_type=err_type,
        )

    def _get_err_type(self, context: RequestContext, response: Response) -> Optional[str]:
        """
        attempts to parse and return the error type from the response body, e.g. ResourceInUseException
        """
        try:
            parsed_response = parse_response(context, response)
            return parsed_response["Error"]["Code"]
        except Exception:
            LOG.exception("error parsing response")
            return None
