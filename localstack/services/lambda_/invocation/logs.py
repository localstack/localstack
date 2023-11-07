import dataclasses
import logging
import threading
from queue import Queue
from typing import Optional, Union

from localstack.aws.connect import connect_to
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class ShutdownPill:
    pass


QUEUE_SHUTDOWN = ShutdownPill()


@dataclasses.dataclass(frozen=True)
class LogItem:
    log_group: str
    log_stream: str
    logs: str


class LogHandler:
    log_queue: "Queue[Union[LogItem, ShutdownPill]]"
    role_arn: str
    _thread: Optional[FuncThread]
    _shutdown_event: threading.Event

    def __init__(self, role_arn: str, region: str) -> None:
        self.role_arn = role_arn
        self.region = region
        self.log_queue = Queue()
        self._shutdown_event = threading.Event()
        self._thread = None

    def run_log_loop(self, *args, **kwargs) -> None:
        logs_client = connect_to.with_assumed_role(
            region_name=self.region,
            role_arn=self.role_arn,
            service_principal=ServicePrincipal.lambda_,
        ).logs
        while not self._shutdown_event.is_set():
            log_item = self.log_queue.get()
            if log_item is QUEUE_SHUTDOWN:
                return
            try:
                store_cloudwatch_logs(
                    logs_client, log_item.log_group, log_item.log_stream, log_item.logs
                )
            except Exception as e:
                LOG.warning(
                    "Error saving logs to group %s in region %s: %s",
                    log_item.log_group,
                    self.region,
                    e,
                )

    def start_subscriber(self) -> None:
        if not is_api_enabled("logs"):
            LOG.debug("Service 'logs' is disabled, not storing any logs for lambda executions")
            return
        self._thread = FuncThread(self.run_log_loop, name="log_handler")
        self._thread.start()

    def add_logs(self, log_item: LogItem) -> None:
        if not is_api_enabled("logs"):
            return
        self.log_queue.put(log_item)

    def stop(self) -> None:
        self._shutdown_event.set()
        if self._thread:
            self.log_queue.put(QUEUE_SHUTDOWN)
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                LOG.error("Could not stop log subscriber in time")
            self._thread = None
