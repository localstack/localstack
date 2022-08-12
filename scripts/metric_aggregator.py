import copy
import csv
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Optional

from localstack.aws.handlers.metric_handler import Metric
from localstack.services.plugins import SERVICE_PLUGINS

LOG = logging.getLogger(__name__)

template_implemented_item = "- [X] "
template_not_implemented_item = "- [ ] "

template_implemented_html = '<input type="checkbox" disabled="disabled" checked="checked">'
template_not_implemented_html = '<input type="checkbox" disabled="disabled">'

SNAPSHOT = "📸"
SNAPSHOT_SKIP_VERIFY = "🚫"
AWS_VALIDATED = "✨"


def _generate_details_block_html(details_title, details):
    output = f"<li>  <details><summary>{details_title}</summary>\n\n"
    for e, count in details.items():
        if count > 0:
            output += f"  {template_implemented_html}{e}</input><br/>\n"
        else:
            output += f"  {template_not_implemented_html}{e}</input><br/>\n"
    output += "  </details></li>\n"
    return output


def create_simple_html_report(file_name, metrics):
    output = "<html><h1> Metric Collection Report of Integration Tests </h1>\n\n"
    output += "<div><b>Disclaimer</b>: naive calculation of test coverage - if operation is called at least once, it is considered as 'covered'.<br/>\n"
    output += "&#x2728;: aws_validated or using the snapshot fixture<br/>\n"
    output += "&#x1F4F8;: using the snapshot fixture without any skip_snapshot_verify<br/>\n"
    output += "&#x1F6AB;: using the snapshot fixture but uses skip_snapshot_verify<br/></div>\n"

    for service in sorted(metrics.keys()):
        output += f"<h1> {service} </h1>\n<div>\n"
        details = metrics[service]
        if not details["service_attributes"]["pro"]:
            output += "community<br/>\n"
        elif not details["service_attributes"]["community"]:
            output += "pro only<br/>\n"
        else:
            output += "community, and pro features<br/>\n"
        del metrics[service]["service_attributes"]
        output += "</div>\n"
        operation_counter = len(details)
        operation_tested = 0

        tmp = ""
        template_aws_validated = '<span title="AWS validated">&#x2728;</span>'
        template_snapshot_verified = '<span title="Snapshot verified">&#x1F4F8;</span>'
        template_snapshot_skipped = '<span title="Snapshot skipped">&#x1F6AB;</span>'

        for operation in sorted(details.keys()):
            op_details = details[operation]
            if op_details.get("invoked", 0) > 0:
                operation_tested += 1
                aws_validated = f"{template_aws_validated if op_details.get('aws_validated') or op_details.get('snapshot') else ''}"
                snapshot = f"{template_snapshot_verified if aws_validated and not op_details.get('snapshot_skipped_paths') else template_snapshot_skipped if aws_validated else ''}"
                tmp += f"<p>{template_implemented_html}{operation} {aws_validated} {snapshot}</input>\n"
            else:
                tmp += f"<p>{template_not_implemented_html}{operation}</input>\n"

            tmp += "<ul>"
            if op_details.get("parameters"):
                parameters = op_details.get("parameters")
                if parameters:
                    tmp += _generate_details_block_html("parameters  hit", parameters)
            if op_details.get("errors"):
                tmp += _generate_details_block_html("errors hit", op_details["errors"])
            tmp += "</ul>"
            tmp += "</p>"
        output += f"<p><details><summary>{operation_tested/operation_counter*100:.2f}% test coverage</summary>\n\n{tmp}\n</details></p>\n"

        with open(file_name, "a") as fd:
            fd.write(f"{output}\n")
            output = ""


def _generate_details_block(details_title: str, details: dict) -> str:
    output = f"  <details><summary>{details_title}</summary>\n\n"
    for e, count in details.items():
        if count > 0:
            output += f"  {template_implemented_item}{e}\n"
        else:
            output += f"  {template_not_implemented_item}{e}\n"
    output += "  </details>\n"
    return output


def create_readable_report(file_name: str, metrics: dict):
    output = "# Metric Collection Report of Integration Tests #\n\n"
    output += "**__Disclaimer__**: naive calculation of test coverage - if operation is called at least once, it is considered as 'covered'.\n"
    output += f"{AWS_VALIDATED}: aws_validated or using the snapshot fixture\n"
    output += f"{SNAPSHOT}: using the snapshot fixture without any skip_snapshot_verify\n"
    output += f"{AWS_VALIDATED}: using the snapshot fixture but uses skip_snapshot_verify\n"

    for service in sorted(metrics.keys()):
        output += f"## {service} ##\n"
        details = metrics[service]
        if not details["service_attributes"]["pro"]:
            output += "community\n"
        elif not details["service_attributes"]["community"]:
            output += "pro only\n"
        else:
            output += "community, and pro features\n"
        del metrics[service]["service_attributes"]

        operation_counter = len(details)
        operation_tested = 0

        tmp = ""
        for operation in sorted(details.keys()):
            op_details = details[operation]
            if op_details.get("invoked", 0) > 0:
                operation_tested += 1
                aws_validated = f"{AWS_VALIDATED if op_details.get('aws_validated') or op_details.get('snapshot') else ''}"
                snapshot = f"{SNAPSHOT if aws_validated and not op_details.get('snapshot_skipped_paths') else SNAPSHOT_SKIP_VERIFY if aws_validated else ''}"
                tmp += f"{template_implemented_item}{operation} {aws_validated} {snapshot}\n"
            else:
                tmp += f"{template_not_implemented_item}{operation}\n"
            if op_details.get("parameters"):
                parameters = op_details.get("parameters")
                if parameters:
                    tmp += _generate_details_block("parameters  hit", parameters)
            if op_details.get("errors"):
                tmp += _generate_details_block("errors hit", op_details["errors"])

        output += f"<details><summary>{operation_tested/operation_counter*100:.2f}% test coverage</summary>\n\n{tmp}\n</details>\n"

        with open(file_name, "a") as fd:
            fd.write(f"{output}\n")
            output = ""


def _init_service_metric_counter() -> Dict:
    metric_recorder = {}
    from localstack.aws.spec import load_service

    for s, provider in SERVICE_PLUGINS.api_provider_specs.items():
        try:
            print(f"found service {s}")
            service = load_service(s)
            ops = {}
            service_attributes = {"pro": "pro" in provider, "community": "default" in provider}
            ops["service_attributes"] = service_attributes
            for op in service.operation_names:
                attributes = {}
                attributes["invoked"] = 0
                attributes["aws_validated"] = False
                attributes["snapshot"] = False
                if hasattr(service.operation_model(op).input_shape, "members"):
                    params = {}
                    for n in service.operation_model(op).input_shape.members:
                        params[n] = 0
                    attributes["parameters"] = params
                if hasattr(service.operation_model(op), "error_shapes"):
                    exceptions = {}
                    for e in service.operation_model(op).error_shapes:
                        exceptions[e.name] = 0
                    attributes["errors"] = exceptions
                ops[op] = attributes

            metric_recorder[s] = ops
        except Exception:
            print(f"cannot load service '{s}'")
    return metric_recorder


def print_usage():
    print("missing argument: directory")
    print("usage: python metric_aggregator.py <dir-to-raw-csv-metric> [amd64|arch64]")


def write_json(file_name: str, metric_dict: dict):
    with open(file_name, "w") as fd:
        fd.write(json.dumps(metric_dict, indent=2, sort_keys=True))


def _print_diff(metric_recorder_internal, metric_recorder_external):
    for key, val in metric_recorder_internal.items():
        for subkey, val in val.items():
            if isinstance(val, dict) and val.get("invoked"):
                if val["invoked"] > 0 and not metric_recorder_external[key][subkey]["invoked"]:
                    print(f"found invocation mismatch: {key}.{subkey}")


def append_row_to_raw_collection(collection_raw_csv_file_name, row, arch):
    with open(collection_raw_csv_file_name, "a") as fd:
        writer = csv.writer(fd)
        row.append(arch)
        writer.writerow(row)


def aggregate_recorded_raw_data(
    base_dir: str, collection_raw_csv: Optional[str] = None, collect_for_arch: Optional[str] = ""
) -> dict:
    pathlist = Path(base_dir).rglob("metric-report-raw-data-*.csv")
    recorded = _init_service_metric_counter()
    for path in pathlist:
        print(f"checking {str(path)}")
        with open(path, "r") as csv_obj:
            csv_dict_reader = csv.reader(csv_obj)
            # skip the header
            next(csv_dict_reader)
            for row in csv_dict_reader:
                if collection_raw_csv:
                    arch = ""
                    if "arm64" in str(path):
                        arch = "arm64"
                    elif "amd64" in str(path):
                        arch = "amd64"
                    # only aggregate all if we did not set a specific target to collect
                    if not collect_for_arch:
                        append_row_to_raw_collection(collection_raw_csv, copy.deepcopy(row), arch)
                    elif collect_for_arch in str(path):
                        append_row_to_raw_collection(collection_raw_csv, copy.deepcopy(row), arch)
                metric: Metric = Metric(*row)
                if metric.xfail == "True":
                    print(f"test {metric.node_id} marked as xfail")
                    continue
                if collect_for_arch and collect_for_arch not in str(path):
                    continue

                service = recorded[metric.service]
                ops = service[metric.operation]

                errors = ops.setdefault("errors", {})
                if metric.exception:
                    exception = metric.exception
                    errors[exception] = ops.get(exception, 0) + 1
                elif int(metric.response_code) >= 300:
                    for expected_error in ops.get("errors", {}).keys():
                        if expected_error in metric.response_data:
                            # assume we have a match
                            errors[expected_error] += 1
                            LOG.warning(
                                f"Exception assumed for {metric.service}.{metric.operation}: code {metric.response_code}"
                            )
                            break

                ops["invoked"] += 1
                if metric.snapshot == "True":
                    ops["snapshot"] = True  # TODO snapshot currently includes also "skip_verify"
                    ops["snapshot_skipped_paths"] = metric.snapshot_skipped_paths or ""
                if metric.aws_validated == "True":
                    ops["aws_validated"] = True
                if not metric.parameters:
                    params = ops.setdefault("parameters", {})
                    params["_none_"] = params.get("_none_", 0) + 1
                else:
                    for p in metric.parameters.split(","):
                        ops["parameters"][p] += 1

                test_list = ops.setdefault("tests", [])
                if metric.node_id not in test_list:
                    test_list.append(metric.node_id)

    return recorded


def main():
    if not len(sys.argv) >= 2 or not Path(sys.argv[1]).is_dir():
        print_usage()
        return

    base_dir = sys.argv[1]
    collect_for_arch = ""
    if len(sys.argv) == 3:
        collect_for_arch = sys.argv[2]
        if collect_for_arch not in ("amd64", "arm64"):
            print_usage()
            return
        print(
            f"Set target to '{collect_for_arch}' - will only aggregate for these test results. Raw collection of all files.\n"
        )

    # TODO: removed splitting of internal/external recorded calls, as some pro tests use 'internals' to connect to service

    metrics_path = os.path.join(base_dir, "parity_metrics")
    Path(metrics_path).mkdir(parents=True, exist_ok=True)
    dtime = datetime.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%s")

    collection_raw_csv = os.path.join(metrics_path, f"raw-collected-data-{dtime}.csv")

    with open(collection_raw_csv, "w") as fd:
        writer = csv.writer(fd)
        header = Metric.RAW_DATA_HEADER.copy()
        header.append("arch")
        writer.writerow(header)

    recorded_metrics = aggregate_recorded_raw_data(base_dir, collection_raw_csv, collect_for_arch)

    write_json(
        os.path.join(
            metrics_path,
            f"metric-report-{dtime}{collect_for_arch}.json",
        ),
        recorded_metrics,
    )

    # filename = os.path.join(metrics_path, f"metric-report-{dtime}{collect_for_arch}.md")
    # create_readable_report(filename, recorded_metrics)
    filename = os.path.join(metrics_path, f"metric-report-{dtime}{collect_for_arch}.html")
    create_simple_html_report(filename, recorded_metrics)


if __name__ == "__main__":
    main()
