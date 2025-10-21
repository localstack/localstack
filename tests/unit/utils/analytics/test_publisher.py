import datetime

import pytest

from localstack.utils.analytics import GlobalAnalyticsBus
from localstack.utils.analytics.client import AnalyticsClient
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_session_id
from localstack.utils.sync import retry


def new_event(payload=None) -> Event:
    return Event(
        "test",
        EventMetadata(get_session_id(), str(datetime.datetime.now())),
        payload=payload,
    )


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
