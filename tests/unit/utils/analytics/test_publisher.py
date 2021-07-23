import datetime
import threading
from queue import Queue
from typing import List

from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_session_id
from localstack.utils.analytics.publisher import JsonHttpPublisher, Publisher, PublisherBuffer


def test_publisher_buffer():
    calls = Queue()

    class QueuePublisher(Publisher):
        def publish(self, _events: List[Event]):
            calls.put(_events)

    buffer = PublisherBuffer(QueuePublisher(), flush_size=2, flush_interval=1000)

    t = threading.Thread(target=buffer.run)
    t.start()

    e1 = Event(EventMetadata(get_session_id(), str(datetime.datetime.now()), "foo"), {"nr": 1})
    e2 = Event(EventMetadata(get_session_id(), str(datetime.datetime.now()), "bar"), {"nr": 2})
    e3 = Event(EventMetadata(get_session_id(), str(datetime.datetime.now()), "edz"), {"nr": 3})

    buffer.handle(e1)
    buffer.handle(e2)
    buffer.handle(e3)

    c1 = calls.get(timeout=2)
    c2 = calls.get(timeout=2)

    assert len(c1) == 2
    assert len(c2) == 1

    assert c1[0] == e1
    assert c1[1] == e2
    assert c2[0] == e3

    buffer.cancel()
    t.join(10)


def test_json_http_publisher():
    publisher = JsonHttpPublisher()

    e1 = Event(
        EventMetadata(get_session_id(), str(datetime.datetime.now()), "foo"), {"some_payload": 1}
    )
    e2 = Event(
        EventMetadata(get_session_id(), str(datetime.datetime.now()), "bar"), {"some_payload": 2}
    )

    publisher.publish([e1, e2])
