import dataclasses
import datetime
import json
import os.path
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import requests

if TYPE_CHECKING:
    from _pytest.config import Config, PytestPluginManager
    from _pytest.config.argparsing import Parser


@dataclasses.dataclass
class MarkerReportEntry:
    node_id: str
    file_path: str
    markers: "list[str]"


@dataclasses.dataclass
class TinybirdReportRow:
    timestamp: str
    node_id: str
    project_name: str
    # code_owners: str  # comma separated
    file_path: str  # TODO: recreate data source at some point to remove this?
    service: str
    markers: str  # comma separated list
    aws_marker: str  # TODO: this is a bit redundant but easier for now to process
    commit_sha: str


@dataclasses.dataclass
class MarkerReport:
    prefix_filter: str
    entries: "list[MarkerReportEntry]" = dataclasses.field(default_factory=list)
    aggregated_report: "dict[str, int]" = dataclasses.field(default_factory=dict)

    def create_aggregated_report(self):
        for entry in self.entries:
            for marker in entry.markers:
                self.aggregated_report.setdefault(marker, 0)
                self.aggregated_report[marker] += 1


@pytest.hookimpl
def pytest_addoption(parser: "Parser", pluginmanager: "PytestPluginManager"):
    """
    Standard usage. Will create a report for all markers under ./target/marker-report-<date>.json
    $ python -m pytest tests/aws/ --marker-report

    Advanced usage. Will create a report for all markers under ./target2/marker-report-<date>.json
    $ python -m pytest tests/aws/ --marker-report --marker-report-path target2/

    Advanced usage. Only includes markers with `aws_` prefix in the report.
    $ python -m pytest tests/aws/ --marker-report --marker-report-prefix "aws_"
    """
    # TODO: --marker-report-* flags should imply --marker-report
    parser.addoption("--marker-report", action="store_true")
    parser.addoption("--marker-report-prefix", action="store")
    parser.addoption("--marker-report-path", action="store")
    parser.addoption("--marker-report-summary", action="store_true")
    parser.addoption("--marker-report-tinybird-upload", action="store_true")


def _get_svc_from_node_id(node_id: str) -> str:
    if node_id.startswith("tests/aws/services/"):
        parts = node_id.split("/")
        return parts[3]
    return ""


def _get_aws_marker_from_markers(markers: "list[str]") -> str:
    for marker in markers:
        if marker.startswith("aws_"):
            return marker
    return ""


@pytest.hookimpl
def pytest_collection_modifyitems(
    session: pytest.Session, config: "Config", items: "list[pytest.Item]"
) -> None:
    """Generate a report about the pytest markers used"""

    if not config.option.marker_report:
        return

    report = MarkerReport(prefix_filter=config.option.marker_report_prefix or "")

    # go through collected items to collect their markers
    for item in items:
        markers = set()
        for mark in item.iter_markers():
            if mark.name.startswith(report.prefix_filter):
                markers.add(mark.name)

        report_entry = MarkerReportEntry(
            node_id=item.nodeid, file_path=item.fspath.strpath, markers=list(markers)
        )
        report.entries.append(report_entry)

    report.create_aggregated_report()

    if config.option.marker_report_path:
        report_directory = Path(config.option.marker_report_path)
        if not report_directory.is_absolute():
            report_directory = config.rootpath / report_directory
        report_directory.mkdir(parents=True, exist_ok=True)
        report_path = report_directory / f"marker-report-{time.time_ns()}.json"

        with open(report_path, "w") as fd:
            json.dump(dataclasses.asdict(report), fd, indent=2, sort_keys=True)

    if config.option.marker_report_tinybird_upload:
        project_name = os.environ.get("MARKER_REPORT_PROJECT_NAME", "localstack")
        datasource_name = "pytest_markers__v0"
        token = os.environ.get("MARKER_REPORT_TINYBIRD_TOKEN")
        url = f"https://api.tinybird.co/v0/events?name={datasource_name}&token={token}"

        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        tinybird_data = [
            dataclasses.asdict(
                TinybirdReportRow(
                    timestamp=timestamp,
                    node_id=x.node_id,
                    project_name=project_name,
                    file_path=x.file_path,
                    service=_get_svc_from_node_id(x.node_id),
                    markers=",".join(sorted(x.markers)),
                    aws_marker=_get_aws_marker_from_markers(x.markers),
                    commit_sha=os.environ.get("MARKER_REPORT_COMMIT_SHA", ""),
                )
            )
            for x in report.entries
        ]

        data = "\n".join(json.dumps(x) for x in tinybird_data)

        response = requests.post(url, data=data, timeout=20)

        if response.status_code != 202:
            print(f"Error while uploading marker report to tinybird: {response.status_code}.")
        else:
            print("Successfully uploaded marker report to tinybird.")

    if config.option.marker_report_summary:
        print("\n=========================")
        print("MARKER REPORT (SUMMARY)")
        print("=========================")
        for k, v in report.aggregated_report.items():
            print(f"{k}: {v}")
        print("=========================\n")
