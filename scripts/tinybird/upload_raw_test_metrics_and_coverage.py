"""Uploading to Tinybird of the metrics collected for a CircleCI run

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
- *build_id*: the workflow-id (for CircleCI) or run-id (for GitHub)
- *timestamp*: a timestamp as string which will be the same for the CircleCI run
- *ls_source*: “community” for the CircleCI run, “pro” for the Github action

In order to get more metadata from the build, we also send some general information to tests_raw_builds.datasource:
- *build_id:* the workflow-id (for CircleCI) or run-id (for GitHub)
- *timestamp:* a timestamp as string which will be the same for the CI run
- *branch:* env value from *`CIRCLE_BRANCH`* or *`GITHUB_HEAD_REF`* (only set for pull_requests) or *`GITHUB_REF_NAME`*
- *build_url:* env value from *`CIRCLE_BUILD_URL`* or *$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID*
- *pull_requests:* env value from *`CIRCLE_PULL_REQUESTS`* or *`GITHUB_REF`*
- *build_num:* env value from *`CIRCLE_BUILD_NUM`* (empty for GitHub, there seems to be no equivalent)
- *workflow_id:* env value from *`CIRCLE_WORKFLOW_ID`* or *`GITHUB_RUN_ID`*
"""

import csv
import datetime
import json
import os
from pathlib import Path

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

    GitHub env examples:
    GITHUB_REF=ref/heads/master or ref/pull/<pr_number>/merge (will be used for 'pull_requests')
    GITHUB_HEAD_REF=tinybird_data (used for 'branch', set only for pull_requests)
    GITHUB_REF_NAME=feature-branch-1 (will be used for 'branch' if GITHUB_HEAD_REF is not set)
    GITHUB_RUN_ID=1658821493 (will be used for 'workflow_id')

    workflow run's URL (will be used for 'build_url'):
    $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID

    could not find anything that corresponds to "build_num" (number of current job in CircleCI)
         -> leaving it blank for Github
    """
    # on GitHub the GITHUB_HEAD_REF is only set for pull_request, else we use the GITHUB_REF_NAME
    branch = (
        os.environ.get("CIRCLE_BRANCH", "")
        or os.environ.get("GITHUB_HEAD_REF", "")
        or os.environ.get("GITHUB_REF_NAME", "")
    )
    workflow_id = os.environ.get("CIRCLE_WORKFLOW_ID", "") or os.environ.get("GITHUB_RUN_ID", "")

    build_url = os.environ.get("CIRCLE_BUILD_URL", "")
    if not build_url and os.environ.get("GITHUB_SERVER_URL"):
        # construct the build-url for Github
        server = os.environ.get("GITHUB_SERVER_URL", "")
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        build_url = f"{server}/{repo}/actions/runs/{workflow_id}"

    pull_requests = os.environ.get("CIRCLE_PULL_REQUESTS", "") or os.environ.get("GITHUB_REF", "")
    build_num = os.environ.get(
        "CIRCLE_BUILD_NUM", ""
    )  # TODO could not find equivalent job-id ENV in github

    data = {
        "build_id": build_id,
        "timestamp": timestamp,
        "branch": branch,
        "build_url": build_url,
        "pull_requests": pull_requests,
        "build_num": build_num,
        "workflow_id": workflow_id,
    }
    data_to_send = [json.dumps(data)]
    send_data_to_tinybird(data_to_send, data_name=DATA_SOURCE_RAW_BUILDS)


def send_metric_report(metric_path: str, source_type: str, timestamp: str):
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
    build_id = os.environ.get("CIRCLE_WORKFLOW_ID", "") or os.environ.get("GITHUB_RUN_ID", "")
    send_metadata_for_build(build_id, timestamp)

    pathlist = Path(metric_path).rglob("metric-report-raw-data-*.csv")
    for path in pathlist:
        print(f"checking {str(path)}")
        with open(path, "r") as csv_obj:
            reader_obj = csv.DictReader(csv_obj)
            data_to_remove = [field for field in reader_obj.fieldnames if field not in DATA_TO_KEEP]
            for row in reader_obj:
                count = count + 1

                # add timestamp, build_id, ls_source
                row["timestamp"] = timestamp
                row["build_id"] = build_id
                row["ls_source"] = source_type

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
            tmp.clear()

    print(f"---> processed {count} rows from community test coverage {metric_path}")


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

    build_id = os.environ.get("CIRCLE_WORKFLOW_ID", "") or os.environ.get("GITHUB_RUN_ID", "")
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
            row["build_id"] = build_id

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
    metric_report_dir = os.environ.get("METRIC_REPORT_DIR_PATH", "")
    impl_coverage_file = os.environ.get("IMPLEMENTATION_COVERAGE_FILE", "")
    source_type = os.environ.get("SOURCE_TYPE", "")
    missing_info = (
        "missing data, please check the available ENVs that are required to run the script"
    )
    print(
        f"METRIC_REPORT_DIR_PATH={metric_report_dir}, IMPLEMENTATION_COVERAGE_FILE={impl_coverage_file}, "
        f"SOURCE_TYPE={source_type}"
    )
    if not metric_report_dir:
        print(missing_info)
        raise Exception("missing METRIC_REPORT_DIR_PATH")
    if not impl_coverage_file:
        print(missing_info)
        raise Exception("missing IMPLEMENTATION_COVERAGE_FILE")
    if not source_type:
        print(missing_info)
        raise Exception("missing SOURCE_TYPE")
    if not token:
        print(missing_info)
        raise Exception("missing TINYBIRD_PARITY_ANALYTICS_TOKEN")

    # create one timestamp that will be used for all the data sent
    timestamp: str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    send_metric_report(metric_report_dir, source_type=source_type, timestamp=timestamp)
    send_implemented_coverage(impl_coverage_file, timestamp=timestamp, type=source_type)


if __name__ == "__main__":
    main()
