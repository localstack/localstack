import json
import logging
import threading
from queue import Queue
from typing import List

from localstack import config
from localstack.constants import API_ENDPOINT

from .events import Event, EventHandler

LOG = logging.getLogger(__name__)


class Publisher:
    """
    A publisher takes a batch of events and publishes them to a destination.
    """

    def publish(self, events: List[Event]):
        ...


class JsonHttpPublisher(Publisher):
    """
    Publisher that serializes event batches as JSON and POSTs them to an HTTP endpoint.
    """

    default_endpoint: str = API_ENDPOINT.rstrip("/") + "/analytics"

    def __init__(self, endpoint=None):
        self.endpoint = endpoint or self.default_endpoint

    def publish(self, events: List[Event]):
        if not events:
            return

        docs = list()
        for event in events:
            try:
                docs.append(event.asdict())
            except Exception:
                if config.DEBUG_ANALYTICS:
                    LOG.exception("error while recording event %s", event)

                pass  # simply ignore events that aren't configured properly

        doc = json.dumps({"events": docs})
        # requests.post(self.endpoint, json=doc)
        print(f"requests.post({self.endpoint}, json={doc})")


class PublisherBuffer(EventHandler):
    """
    A PublisherBuffer is an EventHandler that collects events into a buffer until a flush condition is
    met, and then flushes the buffer to a Publisher. The condition is either a given buffer size or
    a time interval, whatever occurs first. The buffer is also flushed when the recorder is stopped
    via `cancel()`. Internally it uses a simple event-loop mechanism to multiplex commands on a
    single thread.
    """

    _cmd_flush = object()
    _cmd_stop = object()

    def __init__(self, publisher: Publisher, flush_size=100, flush_interval=10):
        self._publisher = publisher
        self._queue = Queue()
        self._command_queue = Queue()

        self.flush_size = flush_size
        self.flush_interval = flush_interval

    def handle(self, event: Event):
        self._queue.put_nowait(event)

        if self._queue.qsize() >= self.flush_size:
            self.flush()

    def flush(self):
        self._command_queue.put(self._cmd_flush)

    def cancel(self):
        self._command_queue.put(self._cmd_stop)

    def run(self, *_):
        while True:
            command = self._command_queue.get()

            if command is self._cmd_flush or command is self._cmd_stop:
                try:
                    self._do_flush()
                except Exception:
                    if config.DEBUG_ANALYTICS:
                        LOG.exception("error while flushing events")

            if command is self._cmd_stop:
                return

    def _do_flush(self):
        queue = self._queue
        events = list()

        for _ in range(min(self.flush_size, queue.qsize())):
            event = queue.get_nowait()
            events.append(event)

        if config.DEBUG_ANALYTICS:
            LOG.debug("collected %d events to publish", len(events))

        if events:
            self._publisher.publish(events)


def _create_main_handler() -> EventHandler:
    from localstack.utils.common import start_thread

    # TODO: use config
    recorder = PublisherBuffer(JsonHttpPublisher())
    start_thread(recorder.run)

    return recorder


_handler: EventHandler
_startup_mutex = threading.Lock()


def publish(event: Event):
    """
    Publish an event to the global analytics event publisher.
    """
    global _handler

    if config.DISABLE_EVENTS:
        if config.DEBUG_ANALYTICS:
            LOG.debug("skipping event %s", event)

    if not _handler:
        with _startup_mutex:
            if not _handler:
                _handler = _create_main_handler()

                if config.DEBUG_ANALYTICS:
                    LOG.debug("skipping event %s", event)

    try:
        _handler.handle(event)
    except Exception:
        if config.DEBUG_ANALYTICS:
            LOG.exception("error while recording event %s", event)
