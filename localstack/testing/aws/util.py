import json
import os
from os import path

from localstack.utils.aws import aws_stack


def is_aws_cloud() -> bool:
    return os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"


def get_lambda_logs(func_name, logs_client=None):
    logs_client = logs_client or aws_stack.create_external_boto_client("logs")
    log_group_name = f"/aws/lambda/{func_name}"
    streams = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    streams = sorted(streams, key=lambda x: x["creationTime"], reverse=True)
    log_events = logs_client.get_log_events(
        logGroupName=log_group_name, logStreamName=streams[0]["logStreamName"]
    )["events"]
    return log_events


def bucket_exists(client, bucket_name: str) -> bool:
    buckets = client.list_buckets()
    for bucket in buckets["Buckets"]:
        if bucket["Name"] == bucket_name:
            return True
    return False


def write_snapshot_samples(fn, svc, operation):
    for i in range(1, 3):
        response = fn()
        fname = path.join(
            path.dirname(__file__), "sample-snapshots", f"{svc}.{operation}.response.{i}.json"
        )
        with open(fname, "w") as fd:
            fd.write(json.dumps(response, indent=2, default=str))


def write_snapshot_samples_collect_stream(fn, field, svc, operation):
    for i in range(1, 3):
        response = fn()
        fname = path.join(
            path.dirname(__file__), "sample-snapshots", f"{svc}.{operation}.{field}.response.{i}"
        )
        with open(fname, "w+b") as fd:
            fd.write(response[field].read())
