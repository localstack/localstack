import abc
import atexit
import logging
import threading
import time
from queue import Queue
from typing import List, Optional

from localstack import config, constants
from localstack.utils.common import start_thread

from .client import AnalyticsClient
from .events import Event, EventHandler
from .metadata import get_client_metadata

LOG = logging.getLogger(__name__)


class Publisher(abc.ABC):
    """
    A publisher takes a batch of events and publishes them to a destination.
    """

    def publish(self, events: List[Event]):
        raise NotImplementedError


class AnalyticsClientPublisher(Publisher):
    client: AnalyticsClient

    def __init__(self, client: AnalyticsClient = None) -> None:
        super().__init__()
        self.client = client or AnalyticsClient()

    def publish(self, events: List[Event]):
        self.client.append_events(events)


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
    via `close()`. Internally it uses a simple event-loop mechanism to multiplex commands on a
    single thread.
    """

    flush_size: int
    flush_interval: float

    _cmd_flush = object()
    _cmd_stop = object()

    # FIXME: figure out good default values
    def __init__(self, publisher: Publisher, flush_size: int = 20, flush_interval: float = 10):
        self._publisher = publisher
        self._queue = Queue()
        self._command_queue = Queue()

        self.flush_size = flush_size
        self.flush_interval = flush_interval

        self._last_flush = time.time()
        self._stopping = threading.Event()
        self._stopped = threading.Event()

    def handle(self, event: Event):
        self._queue.put_nowait(event)
        self.checked_flush()

    def close(self):
        if self._stopping.is_set():
            return

        self._stopping.set()
        self._command_queue.put(self._cmd_stop)

    def close_sync(self, timeout: Optional[float] = None):
        self.close()
        return self._stopped.wait(timeout)

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
            if self._stopping.wait(self.flush_interval):
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
            self._stopped.set()
            flush_scheduler.stop()

    def _do_flush(self):
        queue = self._queue
        events = list()

        for _ in range(queue.qsize()):
            event = queue.get_nowait()
            events.append(event)

        if config.DEBUG_ANALYTICS:
            LOG.debug("collected %d events to publish", len(events))

        self._publisher.publish(events)


class GlobalAnalyticsBus(PublisherBuffer):
    def __init__(self, client: AnalyticsClient = None, flush_size=20, flush_interval=10) -> None:
        self._client = client or AnalyticsClient()
        self._publisher = AnalyticsClientPublisher(self._client)

        super().__init__(self._publisher, flush_size, flush_interval)

        self._started = False
        self._startup_mutex = threading.Lock()
        self._buffer_thread = None

        self.force_tracking = False  # allow class to ignore all other tracking config
        self.tracking_disabled = False  # disables tracking if global config would otherwise track

    @property
    def is_tracking_disabled(self):
        if self.force_tracking:
            return False

        # don't track if event tracking is disabled globally
        if config.DISABLE_EVENTS:
            return True
        # don't track for internal test runs (like integration tests)
        if config.is_env_true(constants.ENV_INTERNAL_TEST_RUN):
            return True
        if self.tracking_disabled:
            return True

        return False

    def handle(self, event: Event):
        """
        Publish an event to the global analytics event publisher.
        """
        if self.is_tracking_disabled:
            if config.DEBUG_ANALYTICS:
                LOG.debug("skipping event %s", event)
            return

        if not self._started:
            self._start()

        super().handle(event)

    def _start(self):
        with self._startup_mutex:
            if self._started:
                return
            self._started = True

            # TODO should do async retry here and queue events until decision has been made,
            #  otherwise first call to handle() may block
            try:
                response = self._client.start_session(get_client_metadata())
                LOG.info("session endpoint returned: %s", response)
            except Exception:
                if config.DEBUG_ANALYTICS:
                    LOG.exception("error while registering session")
                self.tracking_disabled = True
                return

            start_thread(self.run)

            def closer():
                self.close_sync(timeout=2)

            atexit.register(closer)
