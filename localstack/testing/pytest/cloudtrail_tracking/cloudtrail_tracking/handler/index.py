import json
import os
from datetime import datetime
from typing import Any, List

import boto3

S3_BUCKET = os.environ["BUCKET"]
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")


class Encoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle datetimes
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def get_client(service: str):
    if AWS_ENDPOINT_URL is not None:
        client = boto3.client(
            service,
            endpoint_url=AWS_ENDPOINT_URL,
            region_name="us-east-1",
        )
    else:
        client = boto3.client(service)

    return client


def fetch_events(role_arn: str, start_time: str, end_time: str) -> List[dict]:
    print(f"fetching cloudtrail events for role {role_arn} from {start_time=} to {end_time=}")
    client = get_client("cloudtrail")
    paginator = client.get_paginator("lookup_events")

    results = []
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
    ):
        for event in page["Events"]:
            cloudtrail_event = json.loads(event["CloudTrailEvent"])
            deploy_role = (
                cloudtrail_event.get("userIdentity", {})
                .get("sessionContext", {})
                .get("sessionIssuer", {})
                .get("arn")
            )
            if deploy_role == role_arn:
                results.append(cloudtrail_event)

    print(f"found {len(results)} events")

    # it's nice to have the events sorted
    results.sort(key=lambda e: e["eventTime"])
    return results


def compute_s3_key(test_name: str, start_time: str) -> str:
    key = f"{test_name}/{start_time}/events.json"
    print(f"saving results to s3://{S3_BUCKET}/{key}")
    return key


def save_to_s3(events: List[dict], s3_key: str) -> None:
    print("saving events to s3")
    body = json.dumps(events, cls=Encoder).encode("utf8")
    s3_client = get_client("s3")
    s3_client.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=body)


def handler(event, context):
    print(f"handler {event=}")

    test_name = event["test_name"]
    role_arn = event["role_arn"]
    start_time = event["start_time"]
    end_time = event["end_time"]

    events = fetch_events(role_arn, start_time, end_time)
    s3_key = compute_s3_key(test_name, start_time)
    save_to_s3(events, s3_key)

    print("done")
    return "ok"
