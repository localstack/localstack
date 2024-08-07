import datetime
import time

import pytest

from localstack.services.apigateway.next_gen.execute_api.helpers import (
    generate_trace_id,
    parse_trace_id,
)


def test_generate_trace_id():
    # See https://docs.aws.amazon.com/xray/latest/devguide/xray-api-sendingdata.html#xray-api-traceids for the format
    trace_id = generate_trace_id()
    version, hex_time, unique_id = trace_id.split("-")
    assert version == "1"
    trace_time = datetime.datetime.fromtimestamp(int(hex_time, 16), tz=datetime.UTC)
    now = time.time()
    assert now - 10 <= trace_time.timestamp() <= now
    assert len(unique_id) == 24


@pytest.mark.parametrize(
    "trace,expected",
    [
        (
            "Root=trace;Parent=parent;Sampled=0;lineage=lineage:0",
            {"Root": "trace", "Parent": "parent", "Sampled": "0", "Lineage": "lineage:0"},
        ),
        ("Root=trace", {"Root": "trace"}),
        ("Root=trace;Test", {"Root": "trace"}),
        ("Root=trace;Test=", {"Root": "trace", "Test": ""}),
        ("Root=trace;Test=value;", {"Root": "trace", "Test": "value"}),
    ],
)
def test_parse_trace_id(trace, expected):
    assert parse_trace_id(trace) == expected
