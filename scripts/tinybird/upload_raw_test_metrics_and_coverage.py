""" Uploading to Tinybird of the metrics collected for a CircleCI run

The upload includes:
 * Test Data Raw
 * Implemented/Not implemented Coverage (once for community, once for pro)

## Test Data Raw

Metric data that is collected during the integration test runs.

### Data Collection
All api calls are collected, and stored into a csv file.

- In *CircleCI*, we collect data for the `docker-test-arm64` and `docker-test-amd64` jobs. As both are divided into two test runs, and contain the same tests, we only merge the test results from `docker-test-arm64` runs. The output is stored as an artifact in the `report` step, and is called `parity_metrics/metric-report-raw-data-all-amd64[date-time].csv`
- In *Github*, the action `Integration Tests` collects the same data. The artifacts are stored as `parity-metric-ext-raw.zip` and contain a similar csv file.

### Data Structure
The following data is collected for each api call:

- *service:* the name of the service
- *operation*: the name of the operation
- *request_headers*: the headers are send with the request
- *parameters*: any parameters that were used for the operation, comma separated list; the value is not included
- *response_code*: the http response code that followed the request
- *response_data*: any data that was sent with the response
- *exception*: name of the exception, in case one was triggered for this request
- *origin*: indicates how the request was triggered, valid values are: `internal` and `external` . Internal means that the request was made from localstack, external means that it was triggered explicitly during the test.
- *test_node_id*: the id of the test, pattern: <filename::classname::testname>
- *xfail*: boolean string, indicates whether the test was marked with `xfail`
- *aws_validated*: boolean string, indicates whether the test was marked with `aws_validated`
- *snapshot*: boolean string, indicates whether the test was marked with `snapshot`
- *snapshot_skipped_paths*: comma separated list of any paths that are skipped for snapshot test

### Implemented/Not implemented Coverage
In CircleCI, we have two jobs that test for implemented/not implemented APIs for each service. One job is running for LocalStack Community version, the other one for LocalStack Pro.
We use an heuristic approach for the coverage, and the input for the parameters is non-deterministic, meaning that the classification of implemented/not implemented *could* change.
Currently, the coverage is used to generate the [docs coverage page](https://docs.localstack.cloud/references/coverage/), which is updated once a week.
In CircleCI, the `report` job stores the artifacts for `implementation_coverage_full.csv` (community and pro), and `implementation_coverage_aggregated.csv`.

### Data Structure
- *service:* name of the service
- *operation*: name of the operation
- *status_code*: status code returned for this call
- *error_code*: the error code or exception returned by this call
- *error_message*: detailed error message, if any was returned
- *is_implemented*: boolean, indicating if the operation is assumed to be implemented

### Relevant Data for Parity Dashboard

From the above data structure, the following information is sent to the parity dashboard:
*Test Data Raw* (tests_raw.datasource):
service, operation, parameters, response_code, origin, test_node_id, xfail, aws-alidated, snapshot, snapshot_skipped_paths*

*Coverage Data* (implementation_coverage.datasource):
service, operation, status_code, error_code, is_implemented*

Additionally, we add the following information:
- *build_id*: the workflow-id (for CircleCI)
- *timestamp*: a timestamp as string which will be the same for the CircleCI run
- *ls_source*: “community” for the CircleCI run, “pro” for the Github action

In order to get more metadata from the build, we also send some general information to tests_raw_builds.datasource:
- *build_id:* the workflow-id (for CircleCI)
- *timestamp:* a timestamp as string which will be the same for the CircleCI run
- *branch:* env value from *`CIRCLE_BRANCH`*
- *build_url:* env value from *`CIRCLE_BUILD_URL`*
- *pull_requests:* env value from *`CIRCLE_PULL_REQUESTS`*
- *build_num:* env value from *`CIRCLE_BUILD_NUM`*
- *workflow_id:* env value from *`CIRCLE_WORKFLOW_ID`*
"""

import csv
import datetime
import json
import os

import requests

DATA_TO_KEEP: list[str] = [
    "service",
    "operation",
    "parameters",
    "response_code",
    "origin",
    "test_node_id",
    "xfail",
    "aws_validated",
    "snapshot",
    "snapshot_skipped_paths",
]
CONVERT_TO_BOOL: list[str] = ["xfail", "aws_validated", "snapshot"]

DATA_SOURCE_RAW_TESTS = "tests_raw__v0"
DATA_SOURCE_RAW_BUILDS = "tests_raw_builds__v0"
DATA_SOURCE_IMPL_COVERAGAGE = "implementation_coverage__v0"


def convert_to_bool(input):
    return True if input.lower() == "true" else False


def send_data_to_tinybird(data: list[str], data_name: str):
    # print(f"example data:\n {data[0]}\n")
    token = os.environ.get("TINYBIRD_PARITY_ANALYTICS_TOKEN", "")
    if not token:
        print("missing ENV 'TINYBIRD_PARITY_ANALYTICS_TOKEN', no token defined. cannot send data")
        return

    data_to_send = "\n".join(data)
    r = requests.post(
        "https://api.tinybird.co/v0/events",
        params={
            "name": data_name,
            "token": token,
        },
        data=data_to_send,
    )
    print(f"sent data to tinybird, status code: {r.status_code}: {r.text}")


def send_metadata_for_build(build_id: str, timestamp: str):
    """
    sends the metadata for the build to tinybird

    SCHEMA >
    `build_id` String `json:$.build_id`,
    `timestamp` DateTime `json:$.timestamp`,
    `branch` String `json:$.branch`,
    `build_url` String `json:$.build_url`,
    `pull_requests` String `json:$.pull_requests`,
    `build_num` String `json:$.build_num`,
    `workflow_id` String `json:$.workflow_id`

    CircleCI env examples:
    CIRCLE_PULL_REQUESTS=https://github.com/localstack/localstack/pull/7324
    CIRCLE_BRANCH=coverage-tinybird
    CIRCLE_BUILD_NUM=78206
    CIRCLE_BUILD_URL=https://circleci.com/gh/localstack/localstack/78206
    CIRCLE_WORKFLOW_ID=b86a4bc4-bcd1-4170-94d6-4af66846c1c1
    """
    data = {
        "build_id": build_id,
        "timestamp": timestamp,
        "branch": os.environ.get("CIRCLE_BRANCH", ""),
        "build_url": os.environ.get("CIRCLE_BUILD_URL", ""),
        "pull_requests": os.environ.get("CIRCLE_PULL_REQUESTS", ""),
        "build_num": os.environ.get("CIRCLE_BUILD_NUM", ""),
        "workflow_id": os.environ.get("CIRCLE_WORKFLOW_ID", ""),
    }
    data_to_send = [json.dumps(data)]
    send_data_to_tinybird(data_to_send, data_name=DATA_SOURCE_RAW_BUILDS)


def send_metric_report(path: str, timestamp: str):
    """

    SCHEMA >
    `timestamp` DateTime `json:$.timestamp`,
    `ls_source` String `json:$.ls_source`,
    `test_node_id` String `json:$.test_node_id`,
    `operation` String `json:$.operation`,
    `origin` String `json:$.origin`,
    `parameters` String `json:$.parameters`,
    `response_code` String `json:$.response_code`,
    `service` String `json:$.service`,
    `snapshot` UInt8 `json:$.snapshot`,
    `snapshot_skipped_paths` String `json:$.snapshot_skipped_paths`,
    `aws_validated` UInt8 `json:$.aws_validated`,
    `xfail` UInt8 `json:$.xfail`,
    `build_id` String `json:$.build_id`
    """
    tmp: list[str] = []
    count: int = 0
    build_id = os.environ.get("CIRCLE_WORKFLOW_ID", "")
    send_metadata_for_build(build_id, timestamp)
    with open(path, "r") as csv_obj:
        reader_obj = csv.DictReader(csv_obj)
        data_to_remove = [field for field in reader_obj.fieldnames if field not in DATA_TO_KEEP]
        for row in reader_obj:
            count = count + 1

            # add timestamp, build_id, ls_source
            row["timestamp"] = timestamp
            row["build_id"] = build_id
            row["ls_source"] = "community"

            # remove data we are currently not interested in
            for field in data_to_remove:
                row.pop(field, None)

            # convert boolean values
            for convert in CONVERT_TO_BOOL:
                row[convert] = convert_to_bool(row[convert])

            tmp.append(json.dumps(row))
            if len(tmp) == 500:
                # send data in batches
                send_data_to_tinybird(tmp, data_name=DATA_SOURCE_RAW_TESTS)
                tmp.clear()

        if tmp:
            # send last batch
            send_data_to_tinybird(tmp, data_name=DATA_SOURCE_RAW_TESTS)

    print(f"---> processed {count} rows from community test coverage {path}")


def send_implemented_coverage(file: str, timestamp: str, type: str):
    """
    SCHEMA >
        `build_id` String `json:$.build_id`,
        `timestamp` DateTime `json:$.timestamp`,
        `ls_source` String `json:$.ls_source`,
        `operation` String `json:$.operation`,
        `service` String `json:$.service`,
        `status_code` Int32 `json:$.status_code`,
        `error_code` String `json:$.error_code`,
        `is_implemented` UInt8 `json:$.is_implemented`
    """
    tmp: list[str] = []
    count: int = 0

    with open(file, "r") as csv_obj:
        reader_obj = csv.DictReader(csv_obj)
        for row in reader_obj:
            count = count + 1
            # remove unnecessary data
            row.pop("error_message")

            # convert types
            row["is_implemented"] = convert_to_bool(row["is_implemented"])
            row["status_code"] = int(row["status_code"])

            # add timestamp and source
            row["timestamp"] = timestamp
            row["ls_source"] = type
            row["build_id"] = os.environ.get("CIRCLE_WORKFLOW_ID", "")

            tmp.append(json.dumps(row))
            if len(tmp) == 500:
                # send data in batches
                send_data_to_tinybird(tmp, data_name=DATA_SOURCE_IMPL_COVERAGAGE)
                tmp.clear()

        if tmp:
            # send last batch
            send_data_to_tinybird(tmp, data_name=DATA_SOURCE_IMPL_COVERAGAGE)
    print(f"---> processed {count} rows from {file} ({type})")


def main():
    token = os.environ.get("TINYBIRD_PARITY_ANALYTICS_TOKEN", "")
    metric_report = os.environ.get("METRIC_REPORT_PATH", "")
    community_impl_coverage = os.environ.get("COMMUNITY_IMPL_COV_PATH", "")
    pro_impl_coverage = os.environ.get("PRO_IMPL_COV_PATH", "")

    missing_info = (
        "missing data, please check the available ENVs that are required to run the script"
    )
    if not token:
        print(missing_info)
        print("missing TINYBIRD_PARITY_ANALYTICS_TOKEN")
        return
    if not metric_report:
        print(missing_info)
        print("missing METRIC_REPORT_PATH")
        return
    if not community_impl_coverage:
        print(missing_info)
        print("missing COMMUNITY_IMPL_COV_PATH")
        return
    if not pro_impl_coverage:
        print(missing_info)
        print("missing PRO_IMPL_COV_PATH")
        return
    # create one timestamp that will be used for all the data sent
    timestamp: str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    send_metric_report(metric_report, timestamp)
    send_implemented_coverage(community_impl_coverage, timestamp=timestamp, type="community")
    send_implemented_coverage(pro_impl_coverage, timestamp=timestamp, type="pro")


if __name__ == "__main__":
    main()
