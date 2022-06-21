import atexit
import datetime
import logging
import threading
from collections import Counter, namedtuple
from typing import Any, Dict, Optional

from localstack import config
from localstack.utils import analytics
from localstack.utils.scheduler import Scheduler

LOG = logging.getLogger(__name__)
FLUSH_INTERVAL_SECS = 10


ResponseInfo = namedtuple("ResponseInfo", "service, operation, status_code, err_type")


class ResponseAggregator:
    """
    Collects HTTP response data, aggregates it into small batches, and periodically emits (flushes) it as an analytics event
    """

    def __init__(self):
        self.response_counter = Counter()
        self.period_start_time = datetime.datetime.utcnow()
        self.flush_scheduler = None
        self._flush_mutex = threading.Lock()

    def start_thread(self) -> threading.Thread:
        """
        Start a thread that periodically flushes HTTP response data aggregations as analytics events
        :returns: the thread containing the running flush scheduler
        """
        self.flush_scheduler = Scheduler()
        scheduler_thread = threading.Thread(target=self.flush_scheduler.run, daemon=True)
        scheduler_thread.start()
        self.flush_scheduler.schedule(func=self._flush, period=FLUSH_INTERVAL_SECS, fixed_rate=True)
        atexit.register(self._flush)
        return scheduler_thread

    def add_response(
        self, service_name: str, operation_name: str, response_code: int, err_type: Optional[str]
    ):
        """
        Add an HTTP response for aggregation and collection
        :param service_name: name of the service the request was aimed at, e.g. s3
        :param operation_name: name of the operation, e.g. CreateBucket
        :param response_code: HTTP status code of the response, e.g. 200
        """
        if config.DISABLE_EVENTS:
            return

        response_info = ResponseInfo(
            service=service_name,
            operation=operation_name,
            status_code=response_code,
            err_type=err_type,
        )
        with self._flush_mutex:
            self.response_counter[response_info] += 1

    def _get_analytics_payload(self) -> Dict[str, Any]:
        aggregations = []
        for resp, count in self.response_counter.items():
            resp_dict = resp._asdict()
            if resp_dict.get("err_type") is None:
                del resp_dict["err_type"]
            resp_dict["count"] = count
            aggregations.append(resp_dict)
        return {
            "period_start_time": self.period_start_time.isoformat() + "Z",
            "period_end_time": datetime.datetime.utcnow().isoformat() + "Z",
            "http_response_aggregations": aggregations,
        }

    def _flush(self):
        """
        Flushes the current batch of HTTP response data as an analytics event.
        This happens automatically in the background.
        """
        with self._flush_mutex:
            if len(self.response_counter) > 0:
                analytics_payload = self._get_analytics_payload()
                analytics.log.event("http_response_agg", analytics_payload)
                self.response_counter.clear()
        self.period_start_time = datetime.datetime.utcnow()
