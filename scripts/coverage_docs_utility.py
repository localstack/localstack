import csv
import os
import sys
from pathlib import Path

from scripts.metric_aggregator import aggregate_recorded_raw_data

DOCS_HEADER = """---
title: "LocalStack Coverage"
linkTitle: "LocalStack Coverage"
weight: 100
description: >
  Overview of the implemented AWS APIs in LocalStack
aliases:
  - /localstack/coverage/
hide_readingtime: true
---
\n\n
"""

TABLE_HEADER = """
  <thead>
    <tr>
      <th>Operation</th>
      <th style="text-align:right">Implemented</th>
    </tr>
  </thead>"""


def create_simplified_metrics(metrics: dict, impl_details: dict):
    simplified_metric = {}
    for service in metrics:
        simplified_metric[service] = {}
        details = metrics[service]
        if "service_attributes" in metrics[service]:
            del metrics[service]["service_attributes"]
        for operation in sorted(details.keys()):
            op_details = details[operation]
            if impl_details.get(service, {}).get(operation) is None:
                print(
                    f"------> WARNING: {service}.{operation} does not have implementation details"
                )
                continue

            simplified_metric[service][operation] = {
                "implemented": impl_details[service][operation]["implemented"],
                "tested": True if op_details.get("invoked", 0) > 0 else False,
                "aws_validated": op_details["aws_validated"],
                "snapshot": op_details[
                    "snapshot"
                ],  # TODO also consider 'snapshot_skipped_paths' once we use this in docs
                "pro": impl_details[service][operation]["pro"],
            }

    return simplified_metric


def create_metric_coverage_docs(file_name: str, metrics: dict, impl_details: dict):
    simplified_metrics = create_simplified_metrics(metrics, impl_details)

    if os.path.exists(file_name):
        os.remove(file_name)

    output = DOCS_HEADER
    output += '<div class="coverage-report">\n\n'
    header = f"<table>{TABLE_HEADER}\n"
    for service in sorted(simplified_metrics.keys()):
        output += f"## {service} ##\n\n"
        output += header
        output += "  <tbody>\n"
        details = simplified_metrics[service]

        implemented_ops = {
            operation[0]: operation[1]
            for operation in details.items()
            if operation[1]["implemented"]
        }

        tested_indicator = ' <a href="#misc" title="covered by our integration test suite">✨</a>'
        for operation in sorted(implemented_ops.keys()):
            tested = ""
            pro_info = ""
            if implemented_ops.get(operation).get("tested"):
                tested = tested_indicator
            if implemented_ops.get(operation).get("pro"):
                pro_info = " (Pro) "
            output += (
                "    <tr>\n"
                f"      <td>{operation}{pro_info}{tested}</td>\n"
                '       <td style="text-align:right">✅</td>\n'
                "    </tr>\n"
            )
        output += "  </tbody>\n"
        other_ops = {
            operation[0]: operation[1]
            for operation in details.items()
            if not operation[1]["implemented"]
        }
        if other_ops:
            output += (
                "  <tbody>"
                "    <tr>\n"
                f"""      <td><a data-toggle="collapse" href=".{service.lower()}-notimplemented">Show missing</a></td>\n"""
                '      <td style="text-align:right"></td>\n'
                "    </tr>\n"
                "  </tbody>\n"
                f"""  <tbody class="collapse {service.lower()}-notimplemented"> """
            )
            for operation in sorted(other_ops.keys()):
                output += (
                    "    <tr>\n"
                    f"      <td>{operation}</td>\n"
                    '       <td style="text-align:right">-</td>\n'
                    "    </tr>\n"
                )
            output += "  </tbody>\n"

        # for operation in sorted(details.items(), key=lambda x: (x[1]["implemented"] < 1, x[0])):
        #     # print(f"{service}.{operation[0]}: {operation[1]['implemented']}")
        #     tested_indicator = "✨" if operation[1]["tested"] else ""
        #     trailing_spaces = 38 - len(operation[0]) - len(tested_indicator)
        #     implemented = "✅" if operation[1]["implemented"] else "-"
        #     output += f"| {operation[0]} {tested_indicator}{' ' * trailing_spaces}| {implemented}         |\n"

        output += " </table>\n\n"
        with open(file_name, "a") as fd:
            fd.write(f"{output}\n")
            output = ""

    with open(file_name, "a") as fd:
        fd.write(f"{output}\n")
        fd.write(
            "## Misc ##\n\n" "Endpoints marked with ✨ are covered by our integration test suite."
        )
        fd.write("\n\n</div>")


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
            if impl_details[service].get(operation) is None:
                print(
                    f"------> WARNING: {service}.{operation} does not have implementation details"
                )
                continue
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
    # coverage = {}
    # with open(
    #     f"{path_to_implementation_details}/implementation_coverage_aggregated.csv", mode="r"
    # ) as file:
    #     csv_reader = csv.DictReader(file)
    #     for row in csv_reader:
    #         coverage[row["service"]] = row["percentage"]

    impl_details = {}
    with open(
        f"{path_to_implementation_details}/community/implementation_coverage_full.csv", mode="r"
    ) as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            service = impl_details.setdefault(row["service"], {})
            service[row["operation"]] = {
                "implemented": True if row["is_implemented"] == "True" else False,
                "pro": False,
            }
    with open(
        f"{path_to_implementation_details}/pro/implementation_coverage_full.csv", mode="r"
    ) as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            service = impl_details.setdefault(row["service"], {})
            details = service.setdefault(row["operation"], {})
            service[row["operation"]] = details

            if "implemented" not in details and row["is_implemented"] == "False":
                # service only available in pro, operation not implemented
                details["implemented"] = False
                details["pro"] = True

            elif not details.get("implemented") and row["is_implemented"] == "True":
                # only override the pro-information if the operation is not already implemented by community
                details["implemented"] = True
                details["pro"] = True

    recorded_metrics = aggregate_recorded_raw_data(base_dir=path_to_raw_metrics)
    # create_metric_coverage_docs_internal(
    #     file_name=path_to_raw_metrics + "/metric-coverage_internal.md",
    #     metrics=recorded_metrics,
    #     impl_details=impl_details,
    #     coverage=coverage,
    # )
    create_metric_coverage_docs(
        file_name=path_to_raw_metrics + "/coverage.md",
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
