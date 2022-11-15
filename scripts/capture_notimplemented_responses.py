import csv
import json
import logging
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import TypedDict

import botocore.config
import requests
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from botocore.parsers import ResponseParserError
from rich.console import Console

from localstack.aws.mocking import generate_request
from localstack.aws.spec import ServiceCatalog
from localstack.utils.aws import aws_stack

logging.basicConfig(level=logging.INFO)
service_models = ServiceCatalog()

c = Console()

STATUS_TIMEOUT_ERROR = 901
STATUS_PARSING_ERROR = 902
STATUS_CONNECTION_ERROR = 903

# TODO: will only include available services
# generate with e.g. http http://localhost:4566/health | jq ".services | keys[]" | pbcopy
response = requests.get("http://localhost:4566/health").content.decode("utf-8")
latest_services_pro = [k for k in json.loads(response).get("services").keys()]

exclude_services = {"azure"}
latest_services_pro = [s for s in latest_services_pro if s not in exclude_services]
latest_services_pro.sort()


class RowEntry(TypedDict, total=False):
    service: str
    operation: str
    status_code: int
    error_code: str
    error_message: str
    is_implemented: bool


def simulate_call(service: str, op: str) -> RowEntry:
    """generates a mock request based on the service and operation model and sends it to the API"""
    client = aws_stack.create_external_boto_client(
        service,
        config=botocore.config.Config(
            parameter_validation=False,
            retries={"max_attempts": 0, "total_max_attempts": 1},
            connect_timeout=50,
            read_timeout=1,
            inject_host_prefix=False,
        ),
    )

    service_model = service_models.get(service)
    op_model = service_model.operation_model(op)
    parameters = generate_request(op_model)  # should be generate_parameters I guess

    result = RowEntry(service=service, operation=op, status_code=0)
    try:
        response = client._make_api_call(op, parameters)
        result["status_code"] = response["ResponseMetadata"]["HTTPStatusCode"]
    except ClientError as ce:
        result["status_code"] = ce.response["ResponseMetadata"]["HTTPStatusCode"]
        result["error_code"] = ce.response.get("Error", {}).get("Code", "Unknown?")
        result["error_message"] = ce.response.get("Error", {}).get("Message", "Unknown?")
    except (ReadTimeoutError, ConnectTimeoutError):
        logging.warning("Reached timeout. Assuming it is implemented.")
        result["status_code"] = STATUS_TIMEOUT_ERROR
    except EndpointConnectionError:
        # TODO: investigate further;for now assuming not implemented
        logging.warning("Connection failed. Assuming it is not implemented.")
        result["status_code"] = STATUS_CONNECTION_ERROR
    except ResponseParserError:
        # TODO: this is actually a bit tricky and might have to be handled on a service by service basis again
        logging.warning("Parsing issue. Assuming it isn't implemented.")
        result["status_code"] = STATUS_PARSING_ERROR
    except Exception as e:
        logging.exception(e)
    return result


def map_to_notimplemented(row: RowEntry) -> bool:
    """
    Some simple heuristics to check the API responses and classify them into implemented/notimplemented

    Ideally they all should behave the same way when receiving requests for not yet implemented endpoints
    (501 with a "not yet implemented" message)

    :param row: the RowEntry
    :return: True if we assume it is not implemented, False otherwise
    """
    if row["status_code"] in [STATUS_PARSING_ERROR]:
        # parsing issues are nearly always due to something not being implemented or activated
        return True
    if row["status_code"] in [STATUS_TIMEOUT_ERROR]:
        #  timeout issue, interpreted as implemented until there's a better heuristic
        return False
    if row["status_code"] == STATUS_CONNECTION_ERROR:
        # affected services:
        # lakeformation, GetQueryStat
        # lakeformation, GetQueryStatistics
        # lakeformation, GetWorkUnitResults
        # lakeformation, GetWorkUnits
        # lakeformation, StartQueryPlanning
        # servicediscovery, DiscoverInstances
        # stepfunctions, StartSyncExecution
        return True
    if (
        row["service"] == "cloudfront"
        and row["status_code"] == 500
        and row.get("error_code") == "500"
        and row.get("error_message", "").lower() == "internal server error"
    ):
        return True
    if row["service"] == "dynamodb" and row.get("error_code") == "UnknownOperationException":
        return True
    if row["service"] == "lambda" and row["status_code"] == 404 and row.get("error_code") == "404":
        return True
    if (
        row["service"]
        in [
            "route53",
            # "s3", -> for s3 404 not found is returned in some case when the bucket does not exist
            "s3control",
        ]
        and row["status_code"] == 404
        and row.get("error_code") == "404"
        and row.get("error_message") is not None
        and "not found" == row.get("error_message", "").lower()
    ):
        return True
    if (
        row["service"] in ["xray", "batch", "glacier", "resource-groups", "apigateway"]
        and row["status_code"] == 404
        and row.get("error_message") is not None
        and "The requested URL was not found on the server" in row.get("error_message")
    ):
        return True
    if (
        row["status_code"] == 501
        and row.get("error_message") is not None
        and "not yet implemented" in row.get("error_message", "")
    ):
        return True
    if row.get("error_message") is not None and "not yet implemented" in row.get(
        "error_message", ""
    ):
        return True
    if row["status_code"] == 501:
        return True
    if (
        row["status_code"] == 500
        and row.get("error_code") == "500"
        and not row.get("error_message")
    ):
        return True
    return False


def run_script(services: list[str], path: None):
    """send requests against all APIs"""
    print(
        f"writing results to '{path}implementation_coverage_full.csv' and '{path}implementation_coverage_aggregated.csv'..."
    )
    with (
        open(f"{path}implementation_coverage_full.csv", "w") as csvfile,
        open(f"{path}implementation_coverage_aggregated.csv", "w") as aggregatefile,
    ):
        full_w = csv.DictWriter(
            csvfile,
            fieldnames=[
                "service",
                "operation",
                "status_code",
                "error_code",
                "error_message",
                "is_implemented",
            ],
        )
        aggregated_w = csv.DictWriter(
            aggregatefile,
            fieldnames=["service", "operation", "implemented_count", "full_count", "percentage"],
        )

        full_w.writeheader()
        aggregated_w.writeheader()

        total_count = 0
        for service_name in services:
            service = service_models.get(service_name)
            for op_name in service.operation_names:
                total_count += 1

        time_start = time.perf_counter_ns()
        counter = 0
        responses = {}
        for service_name in services:
            c.print(f"\n=====  {service_name} =====")
            service = service_models.get(service_name)
            for op_name in service.operation_names:
                counter += 1
                c.print(
                    f"{100 * counter/total_count:3.1f}% | Calling endpoint {counter:4.0f}/{total_count}: {service_name}.{op_name}"
                )

                # here's the important part (the actual service call!)
                response = simulate_call(service_name, op_name)

                responses.setdefault(service_name, {})[op_name] = response
                is_implemented = str(not map_to_notimplemented(response))
                full_w.writerow(response | {"is_implemented": is_implemented})

            # calculate aggregate for service
            all_count = len(responses[service_name].values())
            implemented_count = len(
                [r for r in responses[service_name].values() if not map_to_notimplemented(r)]
            )
            implemented_percentage = implemented_count / all_count

            aggregated_w.writerow(
                {
                    "service": response["service"],
                    "operation": response["operation"],
                    "implemented_count": implemented_count,
                    "full_count": all_count,
                    "percentage": f"{implemented_percentage * 100:.1f}",
                }
            )
        time_end = time.perf_counter_ns()
        delta = timedelta(microseconds=(time_end - time_start) / 1000.0)
        c.print(f"\n\nDone.\nTotal time to completion: {delta}")


def calculate_percentages():
    aggregate = {}

    implemented_aggregate = {}
    aggregate_list = []

    with open("./output-notimplemented.csv", "r") as fd:
        reader = csv.DictReader(fd, fieldnames=["service", "operation", "implemented"])
        for line in reader:
            if line["implemented"] == "implemented":
                continue
            aggregate.setdefault(line["service"], {}).setdefault(line["operation"], line)

        for service in aggregate.keys():
            vals = aggregate[service].values()
            all_count = len(vals)
            implemented_count = len([v for v in vals if v["implemented"] == "True"])
            implemented_aggregate[service] = implemented_count / all_count
            aggregate_list.append(
                {
                    "service": service,
                    "count": all_count,
                    "implemented": implemented_count,
                    "percentage": implemented_count / all_count,
                }
            )

    aggregate_list.sort(key=lambda k: k["percentage"])

    with open("implementation_coverage_aggregated.csv", "w") as csv_fd:
        writer = csv.DictWriter(
            csv_fd, fieldnames=["service", "percentage", "implemented", "count"]
        )
        writer.writeheader()

        for agg in aggregate_list:
            agg["percentage"] = f"{agg['percentage'] * 100:.1f}"
            writer.writerow(agg)


# @click.command()
def main():
    path = "./"
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir():
        path = sys.argv[1]
        if not path.endswith("/"):
            path += "/"
    run_script(latest_services_pro, path=path)


if __name__ == "__main__":
    main()
