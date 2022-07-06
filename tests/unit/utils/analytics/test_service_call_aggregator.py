import time
from queue import Queue
from typing import List

import dateutil.parser
import pytest

from localstack.utils import analytics
from localstack.utils.analytics.events import Event
from localstack.utils.analytics.service_request_aggregator import (
    EVENT_NAME,
    ServiceRequestAggregator,
    ServiceRequestInfo,
)


def test_whitebox_create_analytics_payload():
    agg = ServiceRequestAggregator()

    agg.add_request(ServiceRequestInfo("test1", "test", 200, None))
    agg.add_request(ServiceRequestInfo("test1", "test", 200, None))
    agg.add_request(ServiceRequestInfo("test2", "test", 404, "ResourceNotFound"))
    agg.add_request(ServiceRequestInfo("test3", "test", 200, None))

    payload = agg._create_analytics_payload()

    aggregations = payload["api_calls"]
    assert len(aggregations) == 3

    period_start = dateutil.parser.isoparse(payload["period_start_time"])
    period_end = dateutil.parser.isoparse(payload["period_end_time"])
    assert period_end > period_start

    for record in aggregations:
        service = record["service"]
        if service == "test1":
            assert record["count"] == 2
            assert "err_type" not in record
        elif service == "test2":
            assert record["count"] == 1
            assert record["err_type"] == "ResourceNotFound"
        elif service == "test3":
            assert record["count"] == 1
            assert "err_type" not in record
        else:
            pytest.fail(f"unexpected service name in payload: '{service}'")


def test_whitebox_flush():
    flushed_payloads = Queue()

    def mock_emit_payload(_payload):
        flushed_payloads.put(_payload)

    agg = ServiceRequestAggregator(flush_interval=0.1)
    agg._emit_payload = mock_emit_payload

    agg.add_request(ServiceRequestInfo("test1", "test", 200))
    agg.add_request(ServiceRequestInfo("test1", "test", 200))

    assert len(agg.counter) == 1

    agg.start()

    payload = flushed_payloads.get(timeout=1)

    assert payload["api_calls"] == [
        {"count": 2, "operation": "test", "service": "test1", "status_code": 200}
    ]
    assert len(agg.counter) == 0


def test_integration(monkeypatch):
    events: List[Event] = []

    def _handle(_event: Event):
        events.append(_event)

    monkeypatch.setattr(analytics.log.handler, "handle", _handle)

    agg = ServiceRequestAggregator(flush_interval=1)

    agg.add_request(ServiceRequestInfo("s3", "ListBuckets", 200))
    agg.add_request(ServiceRequestInfo("s3", "CreateBucket", 200))
    agg.add_request(ServiceRequestInfo("s3", "HeadBucket", 200))
    agg.add_request(ServiceRequestInfo("s3", "HeadBucket", 200))

    agg.start()
    time.sleep(1.2)

    assert len(events) == 1, f"expected events to be flushed {events}"

    agg.add_request(ServiceRequestInfo("s3", "HeadBucket", 404))
    agg.add_request(ServiceRequestInfo("s3", "CreateBucket", 200))
    agg.add_request(ServiceRequestInfo("s3", "HeadBucket", 200))

    assert len(events) == 1, f"did not expect events to be flushed {events}"

    agg.shutdown()  # should flush

    assert len(events) == 2, f"expected events to be flushed {events}"

    event = events[0]
    assert event.name == EVENT_NAME
    calls = event.payload["api_calls"]
    assert {"count": 1, "operation": "ListBuckets", "service": "s3", "status_code": 200} in calls
    assert {"count": 1, "operation": "CreateBucket", "service": "s3", "status_code": 200} in calls
    assert {"count": 2, "operation": "HeadBucket", "service": "s3", "status_code": 200} in calls

    event = events[1]
    assert event.name == EVENT_NAME
    calls = event.payload["api_calls"]
    assert {"count": 1, "operation": "CreateBucket", "service": "s3", "status_code": 200} in calls
    assert {"count": 1, "operation": "HeadBucket", "service": "s3", "status_code": 200} in calls
    assert {"count": 1, "operation": "HeadBucket", "service": "s3", "status_code": 404} in calls
