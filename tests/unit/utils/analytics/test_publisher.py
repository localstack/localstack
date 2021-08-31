import datetime
import json
import threading
from queue import Queue
from typing import List

from localstack import config
from localstack.utils import testutil
from localstack.utils.analytics import GlobalAnalyticsBus
from localstack.utils.analytics.client import AnalyticsClient
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_session_id
from localstack.utils.analytics.publisher import Publisher, PublisherBuffer


def new_event(payload=None) -> Event:
    return Event(
        "test",
        EventMetadata(get_session_id(), str(datetime.datetime.now())),
        payload=payload,
    )


class TestPublisherBuffer:
    def test_basic(self):
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

            buffer.handle(e3)  # should flush after close despite flush_size = 2
        finally:
            buffer.close()

        c2 = calls.get(timeout=2)
        assert len(c2) == 1

        assert c1[0] == e1
        assert c1[1] == e2
        assert c2[0] == e3

        t.join(10)

    def test_interval(self):
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
            buffer.close()

        assert len(c1) == 2
        assert len(c2) == 2
        t.join(10)


class TestGlobalAnalyticsBus:
    def test(self):
        config.DEBUG_ANALYTICS = True
        http_requests = Queue()

        def handler(_request, _data):
            http_requests.put((_request.__dict__, _data))

            if _request.path == "/v0/session":
                return testutil.json_response({"track_events": True})

        with testutil.http_server(handler) as url:
            client = AnalyticsClient(url.lstrip("/") + "/v0")
            bus = GlobalAnalyticsBus(client=client, flush_size=2)
            bus.force_tracking = True

            assert http_requests.empty()

            bus.handle(new_event())

            # first event should trigger registration
            request, data = http_requests.get(timeout=5)
            assert request["path"] == "/v0/session"

            bus.handle(new_event())  # should flush here because of flush_size 2

            request, data = http_requests.get()
            assert request["path"] == "/v0/events"
            json_data = json.loads(data)
            assert len(json_data["events"]) == 2
