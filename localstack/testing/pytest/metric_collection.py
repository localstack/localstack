import datetime
import json
import os
from typing import Optional

import pytest
from _pytest.main import Session
from _pytest.nodes import Item

from localstack import config
from localstack.aws.handlers.metric_collector import MetricCollector

BASE_PATH = os.path.join(os.path.dirname(__file__), "../../../target/metric_reports")

FNAME_RAW_DATA_CSV = os.path.join(
    BASE_PATH,
    "metric-report-raw-data.csv",
)


@pytest.hookimpl()
def pytest_sessionstart(session: "Session") -> None:
    from pathlib import Path

    Path(BASE_PATH).mkdir(parents=True, exist_ok=True)
    if config.is_collect_metrics_mode():

        with open(FNAME_RAW_DATA_CSV, "w") as fd:
            import csv

            header = [
                "service",
                "operation",
                "parameters",
                "response_code",
                "response",
                "exception",
                "test_node_id",
                "xfail",
                "origin",
            ]
            writer = csv.writer(fd)
            writer.writerow(header)


@pytest.hookimpl()
def pytest_sessionfinish(
    session,
    exitstatus,
) -> None:
    if config.is_collect_metrics_mode():
        dtime = datetime.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%s")
        fname = os.path.join(
            BASE_PATH,
            f"metric-report-{dtime}.json",
        )
        with open(fname, "w") as fd:
            fd.write(json.dumps(MetricCollector.metric_recorder_external, indent=2))

        fname = os.path.join(
            BASE_PATH,
            f"metric-report-internal-calls-{dtime}.json",
        )
        with open(fname, "w") as fd:
            fd.write(json.dumps(MetricCollector.metric_recorder_internal, indent=2))


@pytest.hookimpl()
def pytest_runtest_teardown(item: "Item", nextitem: Optional["Item"]) -> None:
    if config.is_collect_metrics_mode():
        with open(FNAME_RAW_DATA_CSV, "a") as fd:
            import csv

            writer = csv.writer(fd)
            writer.writerows(MetricCollector.data)
            MetricCollector.data.clear()


@pytest.hookimpl()
def pytest_runtest_call(item: "Item") -> None:
    MetricCollector.node_id = item.nodeid
    MetricCollector.xfail = False
    for _ in item.iter_markers(name="xfail"):
        MetricCollector.xfail = True
    # TODO only works if tests run sequentially
