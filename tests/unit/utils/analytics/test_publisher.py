import datetime
import threading
from queue import Queue
from typing import List

import pytest

from localstack.utils.analytics import GlobalAnalyticsBus
from localstack.utils.analytics.client import AnalyticsClient
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_session_id
from localstack.utils.analytics.publisher import Publisher, PublisherBuffer
from localstack.utils.sync import retry


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
    def test(self, httpserver):
        httpserver.expect_request("/v0/session").respond_with_json({"track_events": True})
        httpserver.expect_request("/v0/events").respond_with_data(b"")

        client = AnalyticsClient(httpserver.url_for("/v0"))
        bus = GlobalAnalyticsBus(client=client, flush_size=2)
        bus.force_tracking = True

        assert not httpserver.log

        bus.handle(new_event())

        # first event should trigger registration
        request, response = retry(httpserver.log.pop, sleep=0.2, retries=10)
        assert request.path == "/v0/session"
        assert response.json["track_events"]
        assert not bus.tracking_disabled
        bus.handle(new_event())  # should flush here because of flush_size 2

        request, _ = retry(httpserver.log.pop, sleep=0.2, retries=10)
        assert request.path == "/v0/events"
        assert len(request.json["events"]) == 2

    @pytest.mark.parametrize("status_code", [200, 403])
    def test_with_track_events_disabled(self, httpserver, status_code):
        httpserver.expect_request("/v1/session").respond_with_json(
            {"track_events": False},
            status=status_code,
        )
        httpserver.expect_request("/v1/events").respond_with_data(b"")

        client = AnalyticsClient(httpserver.url_for("/v1"))
        bus = GlobalAnalyticsBus(client=client, flush_size=2)
        bus.force_tracking = True

        bus.handle(new_event())

        # first event should trigger registration
        request, response = retry(httpserver.log.pop, sleep=0.2, retries=10)
        assert request.path == "/v1/session"
        assert not response.json["track_events"]
        assert bus.tracking_disabled

    def test_with_session_error_response(self, httpserver):
        httpserver.expect_request("/v1/session").respond_with_data(b"oh noes", status=418)
        httpserver.expect_request("/v1/events").respond_with_data(b"")

        client = AnalyticsClient(httpserver.url_for("/v1"))
        bus = GlobalAnalyticsBus(client=client, flush_size=2)
        bus.force_tracking = True

        bus.handle(new_event())

        # first event should trigger registration
        request, response = retry(httpserver.log.pop, sleep=0.2, retries=10)
        assert request.path == "/v1/session"
        assert bus.tracking_disabled
