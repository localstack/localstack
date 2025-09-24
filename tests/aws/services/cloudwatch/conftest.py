import os
from typing import TYPE_CHECKING

import pytest
from botocore.parsers import create_parser
from botocore.serialize import create_serializer

from localstack.aws.spec import load_service
from localstack.testing.aws.util import is_aws_cloud

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient


def is_old_provider():
    return os.environ.get("PROVIDER_OVERRIDE_CLOUDWATCH") == "v1" and not is_aws_cloud()


@pytest.fixture(params=["query", "json", "smithy-rpc-v2-cbor"])
def aws_cloudwatch_client(aws_client, monkeypatch, request) -> "CloudWatchClient":
    protocol = request.param
    if is_old_provider() and protocol in ("json", "smithy-rpc-v2-cbor"):
        pytest.skip(f"Protocol '{protocol}' not supported in Moto")
    """
    Currently, there are no way to select which protocol to use when creating a Boto3 client for a service that supports
    multiple protocols, like CloudWatch.
    To avoid mutating clients by patching the client initialization logic, we can hardcode the parser and serializer
    used by the client instead.
    """
    # TODO: remove once Botocore countains the new CloudWatch spec
    #  for now, we need to also patch the botocore client to be sure it contains the updated service model via the
    #  json patch
    service_model = load_service("cloudwatch")

    # instantiate a client via our ExternalAwsClientFactory exposed via `aws_client` fixture
    cloudwatch_client_wrapper = aws_client.cloudwatch
    # this instance above is the `MetadataRequestInjector`, which wraps the actual client
    cloudwatch_client = cloudwatch_client_wrapper._client

    # the default client behavior is to include validation
    protocol_serializer = create_serializer(protocol)
    protocol_parser = create_parser(protocol)

    monkeypatch.setattr(cloudwatch_client.meta, "_service_model", service_model)
    monkeypatch.setattr(cloudwatch_client, "_serializer", protocol_serializer)
    monkeypatch.setattr(cloudwatch_client, "_response_parser", protocol_parser)
    monkeypatch.setattr(cloudwatch_client.meta.service_model, "resolved_protocol", protocol)

    # this is useful to know from the test itself which protocol is currently used
    monkeypatch.setattr(cloudwatch_client, "test_client_protocol", protocol, raising=False)

    yield cloudwatch_client
