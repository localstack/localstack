import csv
import os
from pathlib import Path


def print_usage():
    print(
        """
    Helper script to an output report for the metrics coverage diff.

    Set the env `COVERAGE_DIR_ALL` which points to a folder containing metrics-raw-data reports for the initial tests.
    The env `COVERAGE_DIR_ACCEPTANCE` should point to the folder containing metrics-raw-data reports for the acceptance
    test suite (usually a subset of the initial tests).

    Use `OUTPUT_DIR` env to set the path where the report will be stored
    """
    )


def sort_dict_helper(d):
    if isinstance(d, dict):
        return {k: sort_dict_helper(v) for k, v in sorted(d.items())}
    else:
        return d


def create_initial_coverage(path_to_initial_metrics: str) -> dict:
    pathlist = Path(path_to_initial_metrics).rglob("*.csv")
    coverage = {}
    for path in pathlist:
        with open(path, "r") as csv_obj:
            csv_dict_reader = csv.DictReader(csv_obj)
            for metric in csv_dict_reader:
                service = metric.get("service")
                operation = metric.get("operation")
                response_code = metric.get("response_code")

                service_details = coverage.setdefault(service, {})
                operation_details = service_details.setdefault(operation, {})
                if response_code not in operation_details:
                    operation_details[response_code] = False
    return coverage


def mark_coverage_acceptance_test(
    path_to_acceptance_metrics: str, coverage_collection: dict
) -> dict:
    pathlist = Path(path_to_acceptance_metrics).rglob("*.csv")
    additional_tested = {}
    add_to_additional = False
    for path in pathlist:
        with open(path, "r") as csv_obj:
            csv_dict_reader = csv.DictReader(csv_obj)
            for metric in csv_dict_reader:
                service = metric.get("service")
                operation = metric.get("operation")
                response_code = metric.get("response_code")

                if service not in coverage_collection:
                    add_to_additional = True
                else:
                    service_details = coverage_collection[service]
                    if operation not in service_details:
                        add_to_additional = True
                    else:
                        operation_details = service_details.setdefault(operation, {})
                        if response_code not in operation_details:
                            add_to_additional = True
                        else:
                            operation_details[response_code] = True

                if add_to_additional:
                    service_details = additional_tested.setdefault(service, {})
                    operation_details = service_details.setdefault(operation, {})
                    if response_code not in operation_details:
                        operation_details[response_code] = True
                    add_to_additional = False

    return additional_tested


def create_readable_report(
    coverage_collection: dict, additional_tested_collection: dict, output_dir: str
):
    service_overview_coverage = """
    <table>
      <tr>
        <th style="text-align: left">Service</th>
        <th style="text-align: right">Coverage of Acceptance Tests Suite</th>
      </tr>
    """
    coverage_details = """
    <table>
      <tr>
        <th style="text-align: left">Service</th>
        <th style="text-align: left">Operation</th>
        <th>Return Code</th>
        <th>Covered By Acceptance Test</th>
      </tr>"""
    additional_test_details = ""
    coverage_collection = sort_dict_helper(coverage_collection)
    additional_tested_collection = sort_dict_helper(additional_tested_collection)
    for service, operations in coverage_collection.items():
        # count tested operations vs operations that are somehow covered with acceptance
        amount_ops = len(operations)
        covered_ops = len([op for op, details in operations.items() if any(details.values())])
        percentage_covered = 100 * covered_ops / amount_ops
        service_overview_coverage += "    <tr>\n"
        service_overview_coverage += f"    <td>{service}</td>\n"
        service_overview_coverage += (
            f"""    <td style="text-align: right">{percentage_covered:.2f}%</td>\n"""
        )
        service_overview_coverage += "    </tr>\n"

        for op_name, details in operations.items():
            for response_code, covered in details.items():
                coverage_details += "    <tr>\n"
                coverage_details += f"    <td>{service}</td>\n"
                coverage_details += f"    <td>{op_name}</td>\n"
                coverage_details += f"""    <td style="text-align: center">{response_code}</td>\n"""
                coverage_details += (
                    f"""    <td style="text-align: center">{'✅' if covered else '❌'}</td>\n"""
                )
                coverage_details += "    </tr>\n"
    if additional_tested_collection:
        additional_test_details = """<table>
      <tr>
        <th>Service</th>
        <th>Operation</th>
        <th>Return Code</th>
        <th>Covered By Acceptance Test</th>
      </tr>"""
        for service, operations in coverage_collection.items():
            for op_name, details in operations.items():
                for response_code, covered in details.items():
                    additional_test_details += "    <tr>\n"
                    additional_test_details += f"    <td>{service}</td>\n"
                    additional_test_details += f"    <td>{op_name}</td>\n"
                    additional_test_details += f"    <td>{response_code}</td>\n"
                    additional_test_details += f"    <td>{'✅' if covered else '❌'}</td>\n"
                    additional_test_details += "    </tr>\n"
        additional_test_details += "</table><br/>\n"
    service_overview_coverage += "</table><br/>\n"
    coverage_details += "</table><br/>\n"
    path = Path(output_dir)
    file_name = path.joinpath("report_metric_coverage.html")
    with open(file_name, "w") as fd:
        fd.write(
            """<!doctype html>
<html>
  <style>
    h1 {text-align: center;}
    h2 {text-align: center;}
    table {text-align: left;margin-left:auto;margin-right:auto;}
    p {text-align: center;}
    div {text-align: center;}
 </style>
<body>"""
        )
        fd.write("  <h1>Diff Report Metrics Coverage</h1>\n")
        fd.write("   <h2>Service Coverage</h2>\n")
        fd.write(
            "       <div><p>Assumption: the initial test suite is considered to have 100% coverage.</p>\n"
        )
        fd.write(f"<p>{service_overview_coverage}</p></div>\n")
        fd.write("   <h2>Coverage Details</h2>\n")
        fd.write(f"<div>{coverage_details}</div>")
        if additional_test_details:
            fd.write("    <h2>Additional Test Coverage</h2>\n")
            fd.write(
                "<div>     Note: this is probalby wrong usage of the script. It includes operations that have been covered with the acceptance tests only"
            )
            fd.write(f"<p>{additional_test_details}</p></div>\n")
        fd.write("</body></html")


def main():
    coverage_path_all = os.environ.get("COVERAGE_DIR_ALL")
    coverage_path_acceptance = os.environ.get("COVERAGE_DIR_ACCEPTANCE")
    output_dir = os.environ.get("OUTPUT_DIR")

    if not coverage_path_all or not coverage_path_acceptance or not output_dir:
        print_usage()
        return

    print(
        f"COVERAGE_DIR_ALL={coverage_path_all}, COVERAGE_DIR_ACCEPTANCE={coverage_path_acceptance}, OUTPUTDIR={output_dir}"
    )
    coverage_collection = create_initial_coverage(coverage_path_all)
    additional_tested = mark_coverage_acceptance_test(coverage_path_acceptance, coverage_collection)

    if additional_tested:
        print(
            "WARN: Found tests that are covered by acceptance tests, but haven't been covered by the initial tests"
        )

    create_readable_report(coverage_collection, additional_tested, output_dir)


if __name__ == "__main__":
    main()
