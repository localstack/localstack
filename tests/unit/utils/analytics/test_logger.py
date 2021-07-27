from queue import Queue

import pytest

from localstack.utils.analytics.events import Event, EventHandler
from localstack.utils.analytics.logger import EventLogger
from localstack.utils.analytics.metadata import get_session_id


class EventCollector(EventHandler):
    def __init__(self):
        self.queue = Queue()

    def handle(self, event: Event):
        self.queue.put(event)

    def next(self, timeout=None) -> Event:
        block = timeout is not None
        return self.queue.get(block=block, timeout=timeout)


@pytest.fixture
def collector():
    return EventCollector()


def test_logger_uses_default_session_id(collector):
    log = EventLogger(collector)
    log.event("foo")

    assert log.session_id == get_session_id()
    assert collector.next().metadata.session_id == get_session_id()


def test_logger_can_overwrite_session_id(collector):
    log = EventLogger(collector, "420")
    log.event("foo")
    assert log.session_id == "420"
    assert collector.next().metadata.session_id == "420"


def test_hash_strings():
    h = EventLogger.hash("foobar")
    assert h
    assert h != "foobar"

    assert EventLogger.hash("foobar") == h, "hash should be deterministic"


def test_hash_numbers():
    h = EventLogger.hash(12)
    assert h
    assert len(h) > 2

    assert EventLogger.hash(12) == h, "hash should be deterministic"


def test_event_with_payload(collector):
    log = EventLogger(collector)

    log.event("foo", {"bar": "ed", "ans": 42})
    log.event("bar", {"foo": "zed", "ans": 420})

    e1 = collector.next()
    e2 = collector.next()

    assert e1.name == "foo"
    assert e2.name == "bar"

    assert e1.payload == {"bar": "ed", "ans": 42}
    assert e2.payload == {"foo": "zed", "ans": 420}


def test_event_with_kwargs_produces_dict_payload(collector):
    log = EventLogger(collector)

    log.event("foo", bar="ed", ans=42)
    log.event("bar", foo="zed", ans=420)

    e1 = collector.next()
    e2 = collector.next()

    assert e1.name == "foo"
    assert e2.name == "bar"

    assert e1.payload == {"bar": "ed", "ans": 42}
    assert e2.payload == {"foo": "zed", "ans": 420}


def test_event_with_kwargs_and_payload_raises_error(collector):
    log = EventLogger(collector)

    with pytest.raises(ValueError):
        log.event("foo", payload={}, foo=1)
