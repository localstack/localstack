import os
from typing import Dict

import boto3
from botocore.config import Config

from localstack import config
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


def create_client_with_keys(
    service: str,
    keys: Dict[str, str],
    region_name: str = None,
    client_config: Config = None,
):
    """
    Create a boto client with the given access key, targeted against LS per default, but to AWS if TEST_TARGET is set
    accordingly.

    :param service: Service to create the Client for
    :param keys: Access Keys
    :param region_name: Region for the client
    :param client_config:
    :return:
    """
    if not region_name and os.environ.get("TEST_TARGET") != "AWS_CLOUD":
        region_name = aws_stack.get_region()
    return boto3.client(
        service,
        region_name=region_name,
        aws_access_key_id=keys["AccessKeyId"],
        aws_secret_access_key=keys["SecretAccessKey"],
        aws_session_token=keys.get("SessionToken"),
        config=client_config,
        endpoint_url=config.get_edge_url()
        if os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        else None,
    )
