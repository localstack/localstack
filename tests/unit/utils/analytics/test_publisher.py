import datetime
import json
import threading
from queue import Queue
from typing import List

from localstack import constants
from localstack.utils import testutil
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_session_id
from localstack.utils.analytics.publisher import JsonHttpPublisher, Publisher, PublisherBuffer


def new_event(payload=None) -> Event:
    return Event(
        EventMetadata(get_session_id(), str(datetime.datetime.now()), "test"),
        payload=payload,
    )


def test_publisher_buffer():
    calls = Queue()

    class QueuePublisher(Publisher):
        def publish(self, _events: List[Event]):
            calls.put(_events)

    buffer = PublisherBuffer(QueuePublisher(), flush_size=2, flush_interval=1000)

    t = threading.Thread(target=buffer.run)
    t.start()

    try:
        e1 = new_event()
        e2 = new_event()
        e3 = new_event()

        buffer.handle(e1)
        buffer.handle(e2)

        c1 = calls.get(timeout=2)
        assert len(c1) == 2

        buffer.handle(e3)  # should flush after cancel despite flush_size = 2
    finally:
        buffer.cancel()

    c2 = calls.get(timeout=2)
    assert len(c2) == 1

    assert c1[0] == e1
    assert c1[1] == e2
    assert c2[0] == e3

    t.join(10)


def test_publisher_buffer_interval():
    calls = Queue()

    class QueuePublisher(Publisher):
        def publish(self, _events: List[Event]):
            calls.put(_events)

    buffer = PublisherBuffer(QueuePublisher(), flush_size=10, flush_interval=1)

    t = threading.Thread(target=buffer.run)
    t.start()

    try:
        e1 = new_event()
        e2 = new_event()
        e3 = new_event()
        e4 = new_event()

        buffer.handle(e1)
        buffer.handle(e2)
        c1 = calls.get(timeout=2)

        buffer.handle(e3)
        buffer.handle(e4)
        c2 = calls.get(timeout=2)
    finally:
        buffer.cancel()

    assert len(c1) == 2
    assert len(c2) == 2
    t.join(10)


def test_json_http_publisher():
    request_data = Queue()

    def handler(request, data):
        request_data.put((request.__dict__, data))

    with testutil.http_server(handler) as url:
        publisher = JsonHttpPublisher(endpoint=f"{url}/analytics")

        e1 = new_event({"val": 1})
        e2 = new_event({"val": 2})
        e3 = new_event({"val": 3})

        publisher.publish([e1, e2])  # batch 1
        publisher.publish([e3])  # batch 2

        request1, data1 = request_data.get(timeout=2)
        request2, data2 = request_data.get(timeout=2)

    assert request_data.qsize() == 0

    # assert that http request/payload is correct
    assert request1["path"] == request2["path"] == "/analytics"

    doc1 = json.loads(data1)
    doc2 = json.loads(data2)
    assert isinstance(doc1["events"], list)
    assert len(doc1["events"]) == 2
    assert isinstance(doc2["events"], list)
    assert len(doc2["events"]) == 1

    # assert headers are set
    assert request1["headers"]["Localstack-Session-Id"] == get_session_id()
    assert request1["headers"]["User-Agent"] == f"localstack/{constants.VERSION}"

    # assert content is correct
    e1 = doc1["events"][0]
    e2 = doc1["events"][1]
    e3 = doc2["events"][0]

    assert e1["metadata"]["session_id"] == get_session_id()
    assert e2["metadata"]["session_id"] == get_session_id()
    assert e3["metadata"]["session_id"] == get_session_id()

    assert e1["metadata"]["event"] == "test"
    assert e2["metadata"]["event"] == "test"
    assert e3["metadata"]["event"] == "test"

    assert e1["payload"]["val"] == 1
    assert e2["payload"]["val"] == 2
    assert e3["payload"]["val"] == 3
