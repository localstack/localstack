import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import pytest
from _pytest.main import Session
from _pytest.nodes import Item

from localstack.aws.handlers.metric_handler import Metric, MetricHandler
from localstack.utils.strings import short_uid

BASE_PATH = os.path.join(os.path.dirname(__file__), "../../../target/metric_reports")
FNAME_RAW_DATA_CSV = os.path.join(
    BASE_PATH,
    f"metric-report-raw-data-{datetime.utcnow().strftime('%Y-%m-%d_%H:%M:%S')}-{short_uid()}.csv",
)


@pytest.hookimpl()
def pytest_sessionstart(session: "Session") -> None:
    Path(BASE_PATH).mkdir(parents=True, exist_ok=True)

    with open(FNAME_RAW_DATA_CSV, "w") as fd:
        writer = csv.writer(fd)
        writer.writerow(Metric.RAW_DATA_HEADER)


@pytest.hookimpl()
def pytest_runtest_teardown(item: "Item", nextitem: Optional["Item"]) -> None:
    node_id = item.nodeid
    xfail = False
    aws_validated = False
    snapshot = False

    for _ in item.iter_markers(name="xfail"):
        xfail = True
    for _ in item.iter_markers(name="aws_validated"):
        aws_validated = True
    if hasattr(item, "fixturenames") and "snapshot" in item.fixturenames:
        snapshot = True
    for metric in MetricHandler.metric_data:
        metric.xfail = xfail
        metric.aws_validated = aws_validated
        metric.snapshot = snapshot
        metric.node_id = node_id

    with open(FNAME_RAW_DATA_CSV, "a") as fd:
        writer = csv.writer(fd)
        writer.writerows(MetricHandler.metric_data)
        MetricHandler.metric_data.clear()
