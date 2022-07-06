import atexit
import datetime
import logging
import threading
from collections import Counter
from typing import Dict, List, NamedTuple, Optional

from localstack import config
from localstack.utils import analytics
from localstack.utils.scheduler import Scheduler

LOG = logging.getLogger(__name__)

DEFAULT_FLUSH_INTERVAL_SECS = 15
EVENT_NAME = "aws_request_agg"
OPTIONAL_FIELDS = ["err_type"]


class ServiceRequestInfo(NamedTuple):
    service: str
    operation: str
    status_code: int
    err_type: Optional[str] = None


class ServiceRequestAggregator:
    """
    Collects API call data, aggregates it into small batches, and periodically emits (flushes) it as an
    analytics event.
    """

    def __init__(self, flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECS):
        self.counter = Counter()
        self._flush_interval = flush_interval
        self._flush_scheduler = Scheduler()
        self._mutex = threading.RLock()
        self._period_start_time = datetime.datetime.utcnow()
        self._is_started = False
        self._is_shutdown = False

    def start(self):
        """
        Start a thread that periodically flushes HTTP response data aggregations as analytics events
        :returns: the thread containing the running flush scheduler
        """
        with self._mutex:
            if self._is_started:
                return
            self._is_started = True

            # schedule flush task
            self._flush_scheduler.schedule(
                func=self._flush, period=self._flush_interval, fixed_rate=True
            )

            # start thread
            _flush_scheduler_thread = threading.Thread(
                target=self._flush_scheduler.run, daemon=True
            )
            _flush_scheduler_thread.start()

            atexit.register(self.shutdown)

    def shutdown(self):
        with self._mutex:
            if not self._is_started:
                return
            if self._is_shutdown:
                return
            self._is_shutdown = True

            self._flush()
            self._flush_scheduler.close()
            atexit.unregister(self.shutdown)

    def add_request(self, request_info: ServiceRequestInfo):
        """
        Add an API call for aggregation and collection.

        :param request_info: information about the API call.
        """
        if config.DISABLE_EVENTS:
            return

        if self._is_shutdown:
            return

        with self._mutex:
            self.counter[request_info] += 1

    def _flush(self):
        """
        Flushes the current batch of HTTP response data as an analytics event.
        This happens automatically in the background.
        """
        with self._mutex:
            try:
                if len(self.counter) == 0:
                    return
                analytics_payload = self._create_analytics_payload()
                self._emit_payload(analytics_payload)
                self.counter.clear()
            finally:
                self._period_start_time = datetime.datetime.utcnow()

    def _create_analytics_payload(self):
        return {
            "period_start_time": self._period_start_time.isoformat() + "Z",
            "period_end_time": datetime.datetime.utcnow().isoformat() + "Z",
            "api_calls": self._aggregate_api_calls(self.counter),
        }

    def _aggregate_api_calls(self, counter) -> List:
        aggregations = []
        for api_call_info, count in counter.items():
            doc = api_call_info._asdict()
            for field in OPTIONAL_FIELDS:
                if doc.get(field) is None:
                    del doc[field]
            doc["count"] = count
            aggregations.append(doc)
        return aggregations

    def _emit_payload(self, analytics_payload: Dict):
        analytics.log.event(EVENT_NAME, analytics_payload)
