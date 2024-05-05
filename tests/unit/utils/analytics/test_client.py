import datetime
from queue import Queue

from pytest_httpserver import HTTPServer

from localstack.constants import VERSION
from localstack.utils.analytics.client import AnalyticsClient
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_client_metadata, get_session_id
from localstack.utils.sync import poll_condition


def new_event(payload=None) -> Event:
    return Event(
        "test",
        EventMetadata(get_session_id(), str(datetime.datetime.now())),
        payload=payload,
    )


def test_append_events(httpserver: HTTPServer):
    request_data = Queue()

    httpserver.expect_request("/events").respond_with_data("", 200)

    client = AnalyticsClient(httpserver.url_for("/"))

    e1 = new_event({"val": 1})
    e2 = new_event({"val": 2})
    e3 = new_event({"val": 3})

    client.append_events([e1, e2])  # batch 1
    client.append_events([e3])  # batch 2

    assert poll_condition(lambda: len(httpserver.log) >= 2, 10)

    request1, _ = httpserver.log[0]
    request2, _ = httpserver.log[1]

    assert request_data.qsize() == 0

    # assert that http request/payload is correct
    assert request1.path == "/events"
    assert request2.path == "/events"

    doc1 = request1.get_json(force=True)
    doc2 = request2.get_json(force=True)
    assert isinstance(doc1["events"], list)
    assert len(doc1["events"]) == 2
    assert isinstance(doc2["events"], list)
    assert len(doc2["events"]) == 1

    # assert headers are set
    assert request1.headers["Localstack-Session-Id"] == get_session_id()
    assert request1.headers["User-Agent"] == f"localstack/{VERSION}"

    # assert content is correct
    e1 = doc1["events"][0]
    e2 = doc1["events"][1]
    e3 = doc2["events"][0]

    assert e1["name"] == "test"
    assert e2["name"] == "test"
    assert e3["name"] == "test"

    assert e1["metadata"]["session_id"] == get_session_id()
    assert e2["metadata"]["session_id"] == get_session_id()
    assert e3["metadata"]["session_id"] == get_session_id()

    assert e1["payload"]["val"] == 1
    assert e2["payload"]["val"] == 2
    assert e3["payload"]["val"] == 3


def test_start_session(httpserver):
    httpserver.expect_request("/session", method="POST").respond_with_json({"track_events": True})

    client = AnalyticsClient(httpserver.url_for("/"))
    response = client.start_session(get_client_metadata())

    assert response.track_events()
