import functools
import os
from typing import Callable, Dict, TypeVar

import boto3
from botocore.awsrequest import AWSPreparedRequest, AWSResponse
from botocore.client import BaseClient
from botocore.compat import HTTPHeaders
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.forwarder import create_http_request
from localstack.aws.protocol.parser import create_parser
from localstack.aws.proxy import get_account_id_from_request
from localstack.aws.spec import load_service
from localstack.utils.aws import aws_stack
from localstack.utils.sync import poll_condition


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


def wait_for_user(keys):
    sts_client = create_client_with_keys(service="sts", keys=keys)

    def is_user_ready():
        try:
            sts_client.get_caller_identity()
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidClientTokenId":
                return False
            return True

    # wait until the given user is ready, takes AWS IAM a while...
    poll_condition(is_user_ready, interval=5, timeout=20)


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


def create_request_context(
    service_name: str, operation_name: str, region: str, aws_request: AWSPreparedRequest
) -> RequestContext:
    context = RequestContext()
    context.service = load_service(service_name)
    context.operation = context.service.operation_model(operation_name=operation_name)
    context.region = region
    if hasattr(aws_request.body, "read"):
        aws_request.body = aws_request.body.read()
    context.request = create_http_request(aws_request)
    parser = create_parser(context.service)
    _, instance = parser.parse(context.request)
    context.service_request = instance
    context.account_id = get_account_id_from_request(context.request)
    return context


class _RequestContextClient:
    _client: BaseClient

    def __init__(self, client: BaseClient):
        self._client = client

    def __getattr__(self, item):
        target = getattr(self._client, item)
        if not isinstance(target, Callable):
            return target

        @functools.wraps(target)
        def wrapper_method(*args, **kwargs):
            service_name = self._client.meta.service_model.service_name
            operation_name = self._client.meta.method_to_api_mapping[item]
            region = self._client.meta.region_name
            prepared_request = None

            def event_handler(request: AWSPreparedRequest, **_):
                nonlocal prepared_request
                prepared_request = request
                # we need to return an AWS Response here
                aws_response = AWSResponse(
                    url=request.url, status_code=200, headers=HTTPHeaders(), raw=None
                )
                aws_response._content = b""
                return aws_response

            self._client.meta.events.register(
                f"before-send.{service_name}.{operation_name}", handler=event_handler
            )
            try:
                target(*args, **kwargs)
            except Exception:
                pass
            self._client.meta.events.unregister(
                f"before-send.{service_name}.{operation_name}", handler=event_handler
            )

            return create_request_context(
                service_name=service_name,
                operation_name=operation_name,
                region=region,
                aws_request=prepared_request,
            )

        return wrapper_method


T = TypeVar("T", bound=BaseClient)


def RequestContextClient(client: T) -> T:
    return _RequestContextClient(client)  # noqa
