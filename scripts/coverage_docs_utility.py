import csv
import os
import sys
from pathlib import Path

from scripts.metric_aggregator import aggregate_recorded_raw_data

header = """
| Operation                              | Implemented | Tested |
|----------------------------------------|-------------|--------|
"""
yes_indicator = "✅"
no_indicator = "❌"


def create_metric_coverage_docs(file_name: str, metrics: dict, impl_details: dict, coverage: dict):
    if os.path.exists(file_name):
        os.remove(file_name)

    output = """---
title: "LocalStack Metric Coverage"
linkTitle: "LocalStack Metric Coverage"
weight: 100
description: >
  Overview of the implemented AWS APIs and integration test coverage in LocalStack
---
\n\n
"""
    for service in sorted(metrics.keys()):
        output += f"## {service} ##\n\n"
        if not impl_details.get(service):
            print(f"--------> Missing implementation details for service: {service}")
            continue
        output += f"API returns a response for {coverage[service]}% of the operations.\n"
        output += header
        del metrics[service]["service_attributes"]
        details = metrics[service]
        for operation in sorted(details.keys()):
            op_details = details[operation]
            implemented = yes_indicator if impl_details[service][operation] else no_indicator
            tested = yes_indicator if op_details.get("invoked", 0) > 0 else no_indicator

            output += (
                f"| {operation}{' '*(39-len(operation))}| {implemented}         | {tested}    |\n"
            )

        output += "\n\n"
        with open(file_name, "a") as fd:
            fd.write(f"{output}\n")
            output = ""


def main(path_to_implementation_details: str, path_to_raw_metrics: str):
    coverage = {}
    with open(
        f"{path_to_implementation_details}/implementation_coverage_aggregated.csv", mode="r"
    ) as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            coverage[row["service"]] = row["percentage"]

    impl_details = {}
    with open(
        f"{path_to_implementation_details}/implementation_coverage_full.csv", mode="r"
    ) as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            service = impl_details.setdefault(row["service"], {})
            service[row["operation"]] = True if row["is_implemented"] == "True" else False

    recorded_metrics = aggregate_recorded_raw_data(base_dir=path_to_raw_metrics)
    create_metric_coverage_docs(
        file_name=path_to_raw_metrics + "/metric-coverage.md",
        metrics=recorded_metrics,
        impl_details=impl_details,
        coverage=coverage,
    )


def print_usage():
    print("missing arguments")
    print(
        "usage: python coverage_docs_utility.py <dir-to-implementaiton-details> <dir-to-raw-csv-metric>"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print_usage()
    else:
        main(sys.argv[1], sys.argv[2])
