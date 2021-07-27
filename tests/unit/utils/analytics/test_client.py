import datetime
import json
from queue import Queue

from localstack import constants
from localstack.utils import testutil
from localstack.utils.analytics.client import AnalyticsClient
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.metadata import get_client_metadata, get_session_id


def new_event(payload=None) -> Event:
    return Event(
        "test",
        EventMetadata(get_session_id(), str(datetime.datetime.now())),
        payload=payload,
    )


def test_append_events():
    request_data = Queue()

    def handler(request, data):
        request_data.put((request.__dict__, data))

    with testutil.http_server(handler) as url:
        client = AnalyticsClient(url)

        e1 = new_event({"val": 1})
        e2 = new_event({"val": 2})
        e3 = new_event({"val": 3})

        client.append_events([e1, e2])  # batch 1
        client.append_events([e3])  # batch 2

        request1, data1 = request_data.get(timeout=2)
        request2, data2 = request_data.get(timeout=2)

    assert request_data.qsize() == 0

    # assert that http request/payload is correct
    assert request1["path"] == request2["path"] == "/events"

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

    assert e1["name"] == "test"
    assert e2["name"] == "test"
    assert e3["name"] == "test"

    assert e1["metadata"]["session_id"] == get_session_id()
    assert e2["metadata"]["session_id"] == get_session_id()
    assert e3["metadata"]["session_id"] == get_session_id()

    assert e1["payload"]["val"] == 1
    assert e2["payload"]["val"] == 2
    assert e3["payload"]["val"] == 3


def test_start_session():
    request_data = Queue()

    def handler(request, data):
        request_data.put((request.__dict__, data))
        return testutil.json_response({"track_events": True})

    with testutil.http_server(handler) as url:
        client = AnalyticsClient(url)
        response = client.start_session(get_client_metadata())
        request, data = request_data.get(timeout=2)

    assert request["path"] == "/session"
    assert response.track_events()
