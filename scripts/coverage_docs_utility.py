import csv
import os
import sys
from pathlib import Path

from scripts.metric_aggregator import aggregate_recorded_raw_data

DOCS_HEADER = """---
title: "LocalStack Metric Coverage"
linkTitle: "LocalStack Metric Coverage"
weight: 100
description: >
  Overview of the implemented AWS APIs and integration test coverage in LocalStack
---
\n\n
"""


def create_simplified_metrics(metrics: dict, impl_details: dict):
    simplified_metric = {}
    for service in metrics:
        simplified_metric[service] = {}
        details = metrics[service]
        del metrics[service]["service_attributes"]
        for operation in sorted(details.keys()):
            op_details = details[operation]
            if impl_details[service].get(operation) is None:
                print(
                    f"------> WARNING: {service}.{operation} does not have implementation details"
                )
                continue
            simplified_metric[service][operation] = {
                "implemented": True if impl_details[service][operation] else False,
                "tested": True if op_details.get("invoked", 0) > 0 else False,
                "aws_validated": True if op_details["aws_validated"] else False,
                "snapshot": True if op_details["snapshot"] else False,
            }

    return simplified_metric


def create_metric_coverage_docs(file_name: str, metrics: dict, impl_details: dict):
    simplified_metrics = create_simplified_metrics(metrics, impl_details)

    if os.path.exists(file_name):
        os.remove(file_name)

    output = DOCS_HEADER
    header = """
| Operation                              | Implemented |
| -------------------------------------- | ----------: |
"""
    for service in sorted(simplified_metrics.keys()):
        output += f"## {service} ##\n\n"
        output += header
        details = simplified_metrics[service]

        # implemented_ops = {
        #     operation[0]: operation[1]
        #     for operation in details.items()
        #     if operation[1]["implemented"]
        # }
        # other_ops = {
        #     operation[0]: operation[1]
        #     for operation in details.items()
        #     if not operation[1]["implemented"]
        # }

        for operation in sorted(details.items(), key=lambda x: (x[1]["implemented"] < 1, x[0])):
            # print(f"{service}.{operation[0]}: {operation[1]['implemented']}")
            tested_indicator = "✨" if operation[1]["tested"] else ""
            trailing_spaces = 38 - len(operation[0]) - len(tested_indicator)
            implemented = "✅" if operation[1]["implemented"] else "-"
            output += f"| {operation[0]} {tested_indicator}{' ' * trailing_spaces}| {implemented}         |\n"

        output += "\n\n"
        with open(file_name, "a") as fd:
            fd.write(f"{output}\n")
            output = ""


def create_metric_coverage_docs_internal(
    file_name: str, metrics: dict, impl_details: dict, coverage: dict
):
    if os.path.exists(file_name):
        os.remove(file_name)

    output = DOCS_HEADER
    header = """
| Operation                              | Implemented | Tested |
|----------------------------------------|-------------|--------|
"""
    yes_indicator = "✅"
    no_indicator = "❌"
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
    # create_metric_coverage_docs(
    #     file_name=path_to_raw_metrics + "/metric-coverage.md",
    #     metrics=recorded_metrics,
    #     impl_details=impl_details,
    #     coverage=coverage,
    # )
    create_metric_coverage_docs(
        file_name=path_to_raw_metrics + "/metric-coverage.md",
        metrics=recorded_metrics,
        impl_details=impl_details,
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
