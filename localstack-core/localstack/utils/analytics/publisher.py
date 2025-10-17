import abc
import atexit
import logging
import threading

from localstack import config
from localstack.utils.batching import AsyncBatcher
from localstack.utils.threads import FuncThread, start_thread, start_worker_thread

from .client import AnalyticsClient
from .events import Event, EventHandler
from .metadata import get_client_metadata

LOG = logging.getLogger(__name__)


class Publisher(abc.ABC):
    """
    A publisher takes a batch of events and publishes them to a destination.
    """

    def publish(self, events: list[Event]):
        raise NotImplementedError

    def close(self):
        pass


class AnalyticsClientPublisher(Publisher):
    client: AnalyticsClient

    def __init__(self, client: AnalyticsClient = None) -> None:
        super().__init__()
        self.client = client or AnalyticsClient()

    def publish(self, events: list[Event]):
        self.client.append_events(events)

    def close(self):
        self.client.close()


class Printer(Publisher):
    """
    Publisher that prints serialized events to stdout.
    """

    def publish(self, events: list[Event]):
        for event in events:
            print(event.asdict())


class GlobalAnalyticsBus(EventHandler):
    _batcher: AsyncBatcher[Event]
    _client: AnalyticsClient
    _worker_thread: FuncThread | None

    def __init__(self, client: AnalyticsClient = None, flush_size=20, flush_interval=10) -> None:
        self._client = client or AnalyticsClient()
        self._publisher = AnalyticsClientPublisher(self._client)
        self._batcher = AsyncBatcher(
            self._handle_batch,
            max_batch_size=flush_size,
            max_flush_interval=flush_interval,
        )

        self._started = False
        self._startup_mutex = threading.Lock()
        self._worker_thread = None

        self.force_tracking = False  # allow class to ignore all other tracking config
        self.tracking_disabled = False  # disables tracking if global config would otherwise track

    def _handle_batch(self, batch: list[Event]):
        """Method that satisfies the BatchHandler[Event] protocol and is passed to AsyncBatcher."""
        try:
            self._publisher.publish(batch)
        except Exception:
            # currently we're just dropping events if something goes wrong during publishing
            if config.DEBUG_ANALYTICS:
                LOG.exception("error while publishing analytics events")

    @property
    def is_tracking_disabled(self):
        if self.force_tracking:
            return False

        # don't track if event tracking is disabled globally
        if config.DISABLE_EVENTS:
            return True
        # don't track for internal test runs (like integration tests)
        if config.is_local_test_mode():
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
                LOG.debug("tracking disabled, skipping event %s", event)
            return

        if not self._started:
            # we make sure the batching worker is started
            self._start()

        self._batcher.add(event)

    def _start(self):
        with self._startup_mutex:
            if self._started:
                return
            self._started = True

            # startup has to run async, otherwise first call to handle() could block a long time.
            start_worker_thread(self._do_start_retry)

    def _do_start_retry(self, *_):
        # TODO: actually retry
        try:
            if config.DEBUG_ANALYTICS:
                LOG.debug("trying to register session with analytics backend")
            response = self._client.start_session(get_client_metadata())
            if config.DEBUG_ANALYTICS:
                LOG.debug("session endpoint returned: %s", response)

            if not response.track_events():
                if config.DEBUG_ANALYTICS:
                    LOG.debug("gracefully disabling analytics tracking")
                self.tracking_disabled = True

        except Exception:
            self.tracking_disabled = True
            if config.DEBUG_ANALYTICS:
                LOG.exception("error while registering session. disabling tracking")
            return

        self._worker_thread = start_thread(self._run, name="global-analytics-bus")

        # given the "Global" nature of this class, we register a global atexit hook to make sure all events are flushed
        # when localstack shuts down.
        def _do_close():
            self.close_sync(timeout=2)

        atexit.register(_do_close)

    def _run(self, *_):
        # main control loop, simply runs the batcher
        self._batcher.run()

    def close_sync(self, timeout=None):
        self._batcher.close()

        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
