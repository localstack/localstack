import csv
import datetime
import json
import os

# import requests

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


def convert_to_bool(input):
    return True if input.lower() == "true" else False


def send_data_to_tinybird(data: list[str], data_name: str, token: str):
    pass
    # data_to_send = "\n".join(data)
    # r = requests.post(
    #     "https://api.tinybird.co/v0/events",
    #     params={
    #         "name": data_name,
    #         "token": token,
    #     },
    #     data=data_to_send,
    # )
    # print(f"sent data to tinybird, status code: {r.status_code}:\n{r.text}\n")


def send_metric_report(path: str, timestamp: str, token: str):
    tmp: list[str] = []
    count: int = 0
    data_name = "events_example"  # TODO
    with open(path, "r") as csv_obj:
        reader_obj = csv.DictReader(csv_obj)
        data_to_remove = [field for field in reader_obj.fieldnames if field not in DATA_TO_KEEP]
        for row in reader_obj:
            count = count + 1
            # add timestamp
            row["timestamp"] = timestamp

            # remove data we are currently not interested in
            for field in data_to_remove:
                row.pop(field, None)

            # convert boolean values
            for convert in CONVERT_TO_BOOL:
                row[convert] = convert_to_bool(row[convert])

            tmp.append(json.dumps(row))
            if len(tmp) == 500:
                # send data in batches
                send_data_to_tinybird(tmp, data_name=data_name, token=token)
                tmp.clear()

        if tmp:
            # send last batch
            send_data_to_tinybird(tmp, data_name=data_name, token=token)

    print(f"---> processed {count} rows from community test coverage {path}")


def send_implemented_coverage(file: str, timestamp: str, type: str, token: str):
    tmp: list[str] = []
    count: int = 0
    data_name = "steffy_hackt"  # TODO
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
            row["source"] = type
            tmp.append(json.dumps(row))
            if len(tmp) == 500:
                # send data in batches
                send_data_to_tinybird(tmp, data_name=data_name, token=token)
                tmp.clear()

        if tmp:
            # send last batch
            send_data_to_tinybird(tmp, data_name=data_name, token=token)
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

    send_metric_report(metric_report, timestamp, token)
    send_implemented_coverage(
        community_impl_coverage, timestamp=timestamp, type="community", token=token
    )
    send_implemented_coverage(pro_impl_coverage, timestamp=timestamp, type="pro", token=token)


if __name__ == "__main__":
    main()
