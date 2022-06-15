import atexit
import datetime
import logging
import threading
from collections import Counter, namedtuple
from typing import Any, Dict

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils import analytics
from localstack.utils.scheduler import Scheduler

LOG = logging.getLogger(__name__)
FLUSH_INTERVAL_SECS = 10


ResponseInfo = namedtuple("ResponseInfo", "service, operation, status_code")


class ResponseAggregator:
    def __init__(self):
        self.response_counter = Counter()
        self.period_start_time = datetime.datetime.utcnow()
        self.flush_scheduler = Scheduler()
        self.scheduler_thread = threading.Thread(target=self.flush_scheduler.run)
        self.scheduler_thread.start()
        self.flush_scheduler.schedule(func=self.flush, period=FLUSH_INTERVAL_SECS, fixed_rate=True)
        atexit.register(self.flush)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if response is None:
            return

        response_info = ResponseInfo(
            service=context.service.service_name,
            operation=context.operation.name,
            status_code=response.status_code,
        )
        self.response_counter[response_info] += 1

    def _get_analytics_payload(self) -> Dict[str, Any]:
        return {
            "period_start_time": self.period_start_time.isoformat() + "Z",
            "period_end_time": datetime.datetime.utcnow().isoformat() + "Z",
            "http_response_aggregations": [
                {**resp._asdict(), "count": count} for resp, count in self.response_counter.items()
            ],
        }

    def flush(self):
        if len(self.response_counter) > 0:
            analytics_payload = self._get_analytics_payload()
            analytics.log.event("http_response_agg", analytics_payload)
            self.response_counter.clear()
        self.period_start_time = datetime.datetime.utcnow()
