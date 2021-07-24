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
    request_data = Queue()

    def handler(request, data):
        request_data.put((request.__dict__, data))

    with testutil.http_server(handler) as url:
        publisher = JsonHttpPublisher(endpoint=f"{url}/analytics")

        e1 = Event(
            EventMetadata(get_session_id(), str(datetime.datetime.now()), "foo"),
            {"some_payload": 1},
        )
        e2 = Event(
            EventMetadata(get_session_id(), str(datetime.datetime.now()), "bar"),
            {"some_payload": 2},
        )
        e3 = Event(
            EventMetadata(get_session_id(), str(datetime.datetime.now()), "ed"), {"some_payload": 3}
        )

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

    assert e1["metadata"]["event"] == "foo"
    assert e2["metadata"]["event"] == "bar"
    assert e3["metadata"]["event"] == "ed"

    assert e1["payload"]["some_payload"] == 1
    assert e2["payload"]["some_payload"] == 2
    assert e3["payload"]["some_payload"] == 3
