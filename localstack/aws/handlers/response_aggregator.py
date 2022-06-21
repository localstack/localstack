import json
import logging
import threading
import xml.etree.ElementTree as ET
from typing import Optional

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.analytics.response_aggregator import ResponseAggregator

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

        err_type = self._get_err_type(response) if response.status_code >= 400 else None
        self.aggregator.add_response(
            context.service.service_name,
            context.operation.name,
            response.status_code,
            err_type=err_type,
        )

    def _get_err_type(self, response: Response) -> Optional[str]:
        """
        makes a best effort to extract the exception name from the response payload
        """
        content_type = response.content_type
        try:
            if "json" in content_type:
                return json.loads(response.get_data(as_text=True))["__type"]
            elif "xml" in content_type:
                return ET.fromstring(response.get_data(as_text=True)).find("Code").text
            else:
                LOG.debug(f"unrecognized content type: '{content_type}'")
                return None
        except Exception:
            LOG.warning("unable to parse error type from response body")
            return None
