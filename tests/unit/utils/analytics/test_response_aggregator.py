from queue import Queue

import dateutil.parser
import pytest

from localstack.utils.analytics import response_aggregator
from localstack.utils.analytics.event_publisher import get_hash


def test_get_analytics_payload():
    agg = response_aggregator.ResponseAggregator()

    agg.add_response("test1", "test", 200, None, None)
    agg.add_response("test1", "test", 200, None, None)
    agg.add_response("test2", "test", 404, "ResourceNotFound", None)
    agg.add_response("test3", "test", 200, None, "abc123")
    payload = agg._get_analytics_payload()
    aggregations = payload["operations"]
    assert len(aggregations) == 3
    period_start = dateutil.parser.isoparse(payload["period_start_time"])
    period_end = dateutil.parser.isoparse(payload["period_end_time"])
    assert period_end > period_start
    for record in payload["operations"]:
        service = record["service"]
        if service == "test1":
            assert record["count"] == 2
            assert "err_type" not in record
            assert "resource_id" not in record
        elif service == "test2":
            assert record["count"] == 1
            assert record["err_type"] == "ResourceNotFound"
            assert "resource_id" not in record
        elif service == "test3":
            assert record["count"] == 1
            assert "err_type" not in record
            assert record["resource_id"] == get_hash("abc123")
        else:
            pytest.fail(f"unexpected service name in payload: '{service}'")


def test_flush(monkeypatch):
    flushed_payloads = Queue()

    def mock_emit_payload(payload):
        flushed_payloads.put(payload)

    monkeypatch.setattr(response_aggregator, "FLUSH_INTERVAL_SECS", 0.1)

    agg = response_aggregator.ResponseAggregator()
    agg._emit_payload = mock_emit_payload

    agg.add_response("test1", "test", 200, None, None)
    agg.add_response("test1", "test", 200, None, None)

    assert len(agg.response_counter) == 1

    agg.start_thread()

    payload = flushed_payloads.get(timeout=1)

    assert payload
    assert payload["operations"] == [
        {"count": 2, "operation": "test", "service": "test1", "status_code": 200}
    ]
    assert len(agg.response_counter) == 0
