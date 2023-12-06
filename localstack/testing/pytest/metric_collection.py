import csv
import os
import re
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
    f"metric-report-raw-data-{datetime.utcnow().strftime('%Y-%m-%d__%H_%M_%S')}-{short_uid()}.csv",
)


@pytest.hookimpl()
def pytest_sessionstart(session: "Session") -> None:
    Path(BASE_PATH).mkdir(parents=True, exist_ok=True)
    pattern = re.compile("--junitxml=(.*)\\.xml")
    if session.config.invocation_params:
        for ip in session.config.invocation_params.args:
            if m := pattern.match(ip):
                report_file_name = m.groups()[-1].split("/")[-1]
                global FNAME_RAW_DATA_CSV
                FNAME_RAW_DATA_CSV = os.path.join(
                    BASE_PATH,
                    f"metric-report-raw-data-{datetime.utcnow().strftime('%Y-%m-%d__%H_%M_%S')}-{report_file_name}.csv",
                )

    with open(FNAME_RAW_DATA_CSV, "w") as fd:
        writer = csv.writer(fd)
        writer.writerow(Metric.RAW_DATA_HEADER)


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item: "Item", nextitem: Optional["Item"]) -> None:
    node_id = item.nodeid
    xfail = False
    aws_validated = False
    snapshot = False
    skipped = ""

    for _ in item.iter_markers(name="xfail"):
        xfail = True
    for _ in item.iter_markers(name="aws_validated"):
        aws_validated = True
    if hasattr(item, "fixturenames") and "snapshot" in item.fixturenames:
        snapshot = True
        for sk in item.iter_markers(name="skip_snapshot_verify"):
            skipped = sk.kwargs.get("paths", "all")

    for metric in MetricHandler.metric_data:
        metric.xfail = xfail
        metric.aws_validated = aws_validated
        metric.snapshot = snapshot
        metric.node_id = node_id
        metric.snapshot_skipped_paths = skipped

    with open(FNAME_RAW_DATA_CSV, "a") as fd:
        writer = csv.writer(fd)
        writer.writerows(MetricHandler.metric_data)
        MetricHandler.metric_data.clear()
