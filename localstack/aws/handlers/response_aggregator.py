import atexit
import dataclasses
import datetime
import json
import logging
import threading
from typing import Any, Dict

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils import analytics
from localstack.utils.scheduler import Scheduler

LOG = logging.getLogger(__name__)
FLUSH_INTERVAL_SECS = 10


@dataclasses.dataclass
class ResponseInfo:
    service: str
    operation: str
    status_code: int

    def to_string(self):
        return json.dumps(dataclasses.asdict(self), sort_keys=True)


class ResponseAggregator:
    def __init__(self):
        self.response_counts = {}
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
            context.service.service_name, context.operation.name, response.status_code
        ).to_string()
        if response_info in self.response_counts:
            self.response_counts[response_info] = self.response_counts[response_info] + 1
        else:
            self.response_counts[response_info] = 1

    def _get_analytics_payload(self) -> Dict[str, Any]:
        return {
            "period_start_time": self.period_start_time.isoformat() + "Z",
            "period_end_time": datetime.datetime.utcnow().isoformat() + "Z",
            "http_response_aggregations": [
                {**json.loads(resp), "count": count} for resp, count in self.response_counts.items()
            ],
        }

    def flush(self):
        if len(self.response_counts) > 0:
            analytics_payload = self._get_analytics_payload()
            analytics.log.event("http_response_agg", analytics_payload)
            self.response_counts = {}
        self.period_start_time = datetime.datetime.utcnow()
