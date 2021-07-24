import abc
import logging
import threading
import time
from queue import Queue
from typing import List

import requests

from localstack import config, constants
from localstack.constants import API_ENDPOINT
from localstack.utils.common import start_thread

from .events import Event, EventHandler
from .metadata import get_session_id

LOG = logging.getLogger(__name__)


class Publisher(abc.ABC):
    """
    A publisher takes a batch of events and publishes them to a destination.
    """

    def publish(self, events: List[Event]):
        raise NotImplementedError


class JsonHttpPublisher(Publisher):
    """
    Publisher that serializes event batches as JSON and POSTs them to an HTTP endpoint.
    """

    def __init__(self, endpoint):
        self.endpoint = endpoint
        # TODO: add compression to JsonHttpPublisher
        #  it would maybe be useful to compress analytics data, but it's unclear how that will
        #  affect performance and what the benefit is. need to measure first.

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

        # FIXME: fault tolerance/timeouts
        headers = self._create_headers()
        requests.post(self.endpoint, json={"events": docs}, headers=headers)

    def _create_headers(self):
        return {
            "User-Agent": "localstack/" + constants.VERSION,
            "Localstack-Session-ID": get_session_id(),
        }


class Printer(Publisher):
    """
    Publisher that prints serialized events to stdout.
    """

    def publish(self, events: List[Event]):
        for event in events:
            print(event.asdict())


class PublisherBuffer(EventHandler):
    """
    A PublisherBuffer is an EventHandler that collects events into a buffer until a flush condition is
    met, and then flushes the buffer to a Publisher. The condition is either a given buffer size or
    a time interval, whatever occurs first. The buffer is also flushed when the recorder is stopped
    via `cancel()`. Internally it uses a simple event-loop mechanism to multiplex commands on a
    single thread.
    """

    flush_size: int
    flush_interval: float

    _cmd_flush = object()
    _cmd_stop = object()

    # FIXME: figure out good default values
    def __init__(self, publisher: Publisher, flush_size: int = 50, flush_interval: float = 10):
        self._publisher = publisher
        self._queue = Queue()
        self._command_queue = Queue()

        self.flush_size = flush_size
        self.flush_interval = flush_interval

        self._last_flush = time.time()
        self._stopped = threading.Event()

    def handle(self, event: Event):
        self._queue.put_nowait(event)
        self.checked_flush()

    def cancel(self):
        if self._stopped.is_set():
            return

        self._stopped.set()
        self._command_queue.put(self._cmd_stop)

    def flush(self):
        self._command_queue.put(self._cmd_flush)
        self._last_flush = time.time()

    def checked_flush(self):
        """
        Runs flush only if a flush condition is met.
        """
        if self._queue.qsize() >= self.flush_size:
            self.flush()
            return
        if time.time() - self._last_flush >= self.flush_interval:
            self.flush()
            return

    def _run_flush_schedule(self, *_):
        while True:
            if self._stopped.wait(self.flush_interval):
                return
            self.checked_flush()

    def run(self, *_):
        flush_scheduler = start_thread(self._run_flush_schedule)

        try:
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
        finally:
            flush_scheduler.stop()

    def _do_flush(self):
        queue = self._queue
        events = list()

        for _ in range(queue.qsize()):
            event = queue.get_nowait()
            events.append(event)

        if config.DEBUG_ANALYTICS:
            LOG.debug("collected %d events to publish", len(events))

        if events:
            self._publisher.publish(events)


def _create_main_handler() -> EventHandler:
    # TODO: use config to create publisher
    endpoint = API_ENDPOINT.rstrip("/") + "/analytics"
    publisher = JsonHttpPublisher(endpoint)
    # publisher = Printer()

    recorder = PublisherBuffer(publisher)
    start_thread(recorder.run)

    return recorder


def _should_not_track():
    return config.DISABLE_EVENTS or config.is_env_true(constants.ENV_INTERNAL_TEST_RUN)


_handler: EventHandler = None
_startup_mutex = threading.Lock()


def publish(event: Event):
    """
    Publish an event to the global analytics event publisher.
    """
    global _handler

    if _should_not_track():
        if config.DEBUG_ANALYTICS:
            LOG.debug("skipping event %s", event)
        return

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
