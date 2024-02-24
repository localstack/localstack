import functools
import os
from typing import Callable, Dict, TypeVar

import boto3
import botocore
from botocore.awsrequest import AWSPreparedRequest, AWSResponse
from botocore.client import BaseClient
from botocore.compat import HTTPHeaders
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.connect import (
    ClientFactory,
    ExternalAwsClientFactory,
    ExternalClientFactory,
    ServiceLevelClientFactory,
)
from localstack.aws.forwarder import create_http_request
from localstack.aws.protocol.parser import create_parser
from localstack.aws.spec import LOCALSTACK_BUILTIN_DATA_PATH, load_service
from localstack.constants import (
    SECONDARY_TEST_AWS_ACCESS_KEY_ID,
    SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_REGION_NAME,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.utils.aws.request_context import get_account_id_from_request
from localstack.utils.sync import poll_condition


def is_aws_cloud() -> bool:
    return os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"


def get_lambda_logs(func_name, logs_client):
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


def wait_for_user(keys, region_name: str):
    sts_client = create_client_with_keys(service="sts", keys=keys, region_name=region_name)

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
    region_name: str,
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
    return boto3.client(
        service,
        region_name=region_name,
        aws_access_key_id=keys["AccessKeyId"],
        aws_secret_access_key=keys["SecretAccessKey"],
        aws_session_token=keys.get("SessionToken"),
        config=client_config,
        endpoint_url=config.internal_service_url() if not is_aws_cloud() else None,
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


# Used for the aws_session, aws_client_factory and aws_client pytest fixtures
# Supports test executions against both LocalStack and production AWS

# TODO: Add the ability to use config profiles for primary and secondary clients
# See https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#using-a-configuration-file


def base_aws_session() -> boto3.Session:
    # When running against AWS, initial credentials must be read from environment or config file
    if is_aws_cloud():
        return boto3.Session()

    # Otherwise, when running against LS, use primary test credentials to start with
    # This set here in the session so that both `aws_client` and `aws_client_factory` can work without explicit creds.
    session = boto3.Session(
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    )
    # make sure we consider our custom data paths for legacy specs (like SQS query protocol)
    session._loader.search_paths.append(LOCALSTACK_BUILTIN_DATA_PATH)
    return session


def base_aws_client_factory(session: boto3.Session) -> ClientFactory:
    config = None
    if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS"):
        config = botocore.config.Config(
            connect_timeout=1_000,
            read_timeout=1_000,
            retries={"total_max_attempts": 1},
        )

    if is_aws_cloud():
        return ExternalAwsClientFactory(session=session, config=config)
    else:
        if not config:
            config = botocore.config.Config()

        # Prevent this fixture from using the region configured in system config
        config = config.merge(botocore.config.Config(region_name=TEST_AWS_REGION_NAME))
        return ExternalClientFactory(session=session, config=config)


def primary_testing_aws_client(client_factory: ClientFactory) -> ServiceLevelClientFactory:
    # Primary test credentials are already set in the boto3 session, so they're not set here again
    return client_factory()


def secondary_testing_aws_client(client_factory: ClientFactory) -> ServiceLevelClientFactory:
    # Setting secondary creds here, overriding the ones from the session
    return client_factory(
        aws_access_key_id=SECONDARY_TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
    )
