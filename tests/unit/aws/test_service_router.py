from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Tuple
from urllib.parse import urlsplit

import pytest
from botocore.awsrequest import AWSRequest, create_request_object
from botocore.config import Config
from botocore.model import OperationModel, ServiceModel, Shape, StructureShape

from localstack.aws.protocol.service_router import determine_aws_service_name, get_service_catalog
from localstack.http import Request
from localstack.utils.aws import aws_stack
from localstack.utils.run import to_str


def _collect_operations() -> Tuple[ServiceModel, OperationModel]:
    """
    Collects all service<>operation combinations to test.
    """
    service_catalog = get_service_catalog()
    for service_name in service_catalog.service_names:
        service = service_catalog.get(service_name)
        for operation_name in service.operation_names:
            # FIXME try to support more and more services, get these exclusions down!
            # Exclude all operations for the following, currently _not_ supported services
            if service.service_name in [
                "chime",
                "chime-sdk-identity",
                "chime-sdk-media-pipelines",
                "chime-sdk-meetings",
                "chime-sdk-messaging",
                "connect",
                "connect-contact-lens",
                "greengrassv2",
                "iot1click",
                "iot1click-devices",
                "iot1click-projects",
                "kinesis-video-archived",
                "kinesis-video-archived-media",
                "kinesis-video-media",
                "kinesis-video-signaling",
                "kinesisvideo",
                "lex-models",
                "lex-runtime",
                "lexv2-models",
                "lexv2-runtime",
                "personalize",
                "personalize-events",
                "personalize-runtime",
                "pinpoint-sms-voice",
                "sagemaker-edge",
                "sagemaker-featurestore-runtime",
                "sms-voice",
                "sso",
                "sso-oidc",
            ]:
                yield pytest.param(
                    service,
                    service.operation_model(operation_name),
                    marks=pytest.mark.xfail(
                        reason=f"{service.service_name} is currently not supported by the service router"
                    ),
                )
            # Exclude services / operations which have ambiguities and where the service routing needs to resolve those
            elif (
                service.service_name in ["docdb", "neptune"]  # maps to rds
                or service.service_name in "timestream-write"  # maps to timestream-query
                or (
                    service.service_name == "sesv2"
                    and operation_name == "PutEmailIdentityDkimSigningAttributes"
                )
            ):
                yield pytest.param(
                    service,
                    service.operation_model(operation_name),
                    marks=pytest.mark.skip(
                        reason=f"{service.service_name} may differ due to ambiguities in the service specs"
                    ),
                )
            else:
                yield service, service.operation_model(operation_name)


@lru_cache
def _client(service: str):
    """Creates a boto client to create the request for a specific service."""
    config = Config(
        connect_timeout=1_000,
        read_timeout=1_000,
        retries={"total_max_attempts": 1},
        parameter_validation=False,
        user_agent="aws-cli/1.33.7",
    )
    return aws_stack.create_external_boto_client(service, config=config)


def _botocore_request_to_localstack_request(request_object: AWSRequest) -> Request:
    """Converts a botocore request (AWSRequest) to our HTTP framework's Request object based on Werkzeug."""
    split_url = urlsplit(request_object.url)
    path = split_url.path
    query_string = split_url.query
    body = request_object.body
    headers = request_object.headers
    return Request(
        method=request_object.method or "GET",
        path=path,
        query_string=to_str(query_string),
        headers=dict(headers),
        body=body,
        raw_path=path,
    )


# Simple dummy value mapping for the different shape types
_dummy_values = {
    "string": "dummy-value",
    "list": [],
    "integer": 0,
    "long": 0,
    "timestamp": datetime.now(),
}


def _create_dummy_request_args(operation_model: OperationModel) -> Dict:
    """Creates a dummy request param dict for the given operation."""
    input_shape: StructureShape = operation_model.input_shape
    if not input_shape:
        return {}
    result = {}
    for required_member in input_shape.required_members:
        required_shape: Shape = input_shape.members[required_member]
        location = required_shape.serialization.get("location")
        if location in ["uri", "querystring", "header", "headers"]:
            result[required_member] = _dummy_values[required_shape.type_name]
    return result


def _generate_test_name(param: Any):
    """Simple helper function to generate readable test names."""
    if isinstance(param, ServiceModel):
        return param.service_name
    elif isinstance(param, OperationModel):
        return param.name
    return param


@pytest.mark.parametrize(
    "service, operation",
    _collect_operations(),
    ids=_generate_test_name,
)
def test_service_router_works_for_every_service(
    service: ServiceModel, operation: OperationModel, caplog
):
    caplog.set_level("CRITICAL", "botocore")

    # Create a dummy request for the service router
    client = _client(service.service_name)
    request_context = {
        "client_region": client.meta.region_name,
        "client_config": client.meta.config,
        "has_streaming_input": operation.has_streaming_input,
        "auth_type": operation.auth_type,
    }
    request_args = _create_dummy_request_args(operation)
    request_dict = client._convert_to_request_dict(request_args, operation, request_context)
    request_object = create_request_object(request_dict)
    client._request_signer.sign(operation.name, request_object)
    request: Request = _botocore_request_to_localstack_request(request_object)

    # Execute the service router
    detected_service_name = determine_aws_service_name(request)

    # Make sure the detected service is the same as the one we generated the request for
    assert service.service_name == detected_service_name


def test_endpoint_prefix_based_routing():
    # TODO could be generalized using endpoint resolvers and replacing "amazonaws.com" with "localhost.localstack.cloud"
    detected_service_name = determine_aws_service_name(
        Request(method="GET", path="/", headers={"Host": "sqs.localhost.localstack.cloud"})
    )
    assert detected_service_name == "sqs"

    detected_service_name = determine_aws_service_name(
        Request(
            method="POST",
            path="/app-instances",
            headers={"Host": "identity-chime.localhost.localstack.cloud"},
        )
    )
    assert detected_service_name == "chime-sdk-identity"
