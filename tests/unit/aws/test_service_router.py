from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import pytest
from botocore.awsrequest import AWSRequest, create_request_object
from botocore.config import Config
from botocore.model import OperationModel, ServiceModel, Shape, StructureShape
from botocore.serialize import create_serializer

from localstack.aws.protocol.service_router import (
    ProtocolError,
    determine_aws_protocol,
    determine_aws_service_model,
    match_available_protocols,
)
from localstack.aws.spec import get_service_catalog
from localstack.http import Request
from localstack.utils.run import to_str


@pytest.fixture
def get_aws_client_for_protocol(aws_client_factory, monkeypatch):
    def _create_client(service_name: str, protocol: str):
        client = aws_client_factory.get_client(
            service_name,
            config=Config(
                connect_timeout=1_000,
                read_timeout=1_000,
                retries={"total_max_attempts": 1},
                parameter_validation=False,
                user_agent="aws-cli/1.33.7",
            ),
        )
        # TODO: we should come up with a better way to create a protocol-aware client
        protocol_serializer = create_serializer(protocol_name=protocol, include_validation=False)
        monkeypatch.setattr(client, "_serializer", protocol_serializer)
        return client

    yield _create_client


def _collect_operations() -> tuple[ServiceModel, OperationModel]:
    """
    Collects all service<>operation combinations to test.
    """
    service_catalog = get_service_catalog()
    for service_name in service_catalog.service_names:
        service = service_catalog.get(service_name)
        service_protocols = {service.protocol}
        if protocols := service.metadata.get("protocols"):
            service_protocols.update(protocols)

        for service_protocol in sorted(service_protocols):
            for operation_name in service.operation_names:
                # FIXME try to support more and more services, get these exclusions down!
                # Exclude all operations for the following, currently _not_ supported services
                if service.service_name in [
                    "bedrock-agent",
                    "bedrock-agentcore",
                    "bedrock-agentcore-control",
                    "bedrock-agent-runtime",
                    "bedrock-data-automation",
                    "bedrock-data-automation-runtime",
                    "chime",
                    "chime-sdk-identity",
                    "chime-sdk-media-pipelines",
                    "chime-sdk-meetings",
                    "chime-sdk-messaging",
                    "chime-sdk-voice",
                    "codecatalyst",
                    "connect",
                    "connect-contact-lens",
                    "connectcampaigns",
                    "connectcampaignsv2",
                    "greengrassv2",
                    "iot1click",
                    "iot1click-devices",
                    "iot1click-projects",
                    "ivs",
                    "ivs-realtime",
                    "kinesis-video-archived",
                    "kinesis-video-archived-media",
                    "kinesis-video-media",
                    "kinesis-video-signaling",
                    "kinesis-video-webrtc-storage",
                    "kinesisvideo",
                    "lex-models",
                    "lex-runtime",
                    "lexv2-models",
                    "lexv2-runtime",
                    "mailmanager",
                    "marketplace-catalog",
                    "marketplace-deployment",
                    "marketplace-reporting",
                    "personalize",
                    "personalize-events",
                    "personalize-runtime",
                    "pinpoint-sms-voice",
                    "qconnect",
                    "sagemaker-edge",
                    "sagemaker-featurestore-runtime",
                    "sagemaker-metrics",
                    "signin",
                    "sms-voice",
                    "sso",
                    "sso-oidc",
                    "wisdom",
                    "workdocs",
                ]:
                    yield pytest.param(
                        service,
                        service_protocol,
                        service.operation_model(operation_name),
                        marks=pytest.mark.skip(
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
                        service_protocol,
                        service.operation_model(operation_name),
                        marks=pytest.mark.skip(
                            reason=f"{service.service_name} may differ due to ambiguities in the service specs"
                        ),
                    )
                else:
                    yield service, service_protocol, service.operation_model(operation_name)


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
    "boolean": True,
}


def _create_dummy_request_args(operation_model: OperationModel) -> dict:
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
    "service, protocol, operation",
    _collect_operations(),
    ids=_generate_test_name,
)
def test_service_router_works_for_every_service(
    service: ServiceModel,
    protocol: str,
    operation: OperationModel,
    caplog,
    get_aws_client_for_protocol,
):
    caplog.set_level("CRITICAL", "botocore")

    # if we test the routing to the internalized sqs query, we want to use the service name "sqs-query" in order to
    # instruct botocore to load the internalized spec instead of the default (json)
    service_name = (
        "sqs-query"
        if service.service_name == "sqs" and protocol == "query"
        else service.service_name
    )

    # Create a dummy request for the service router
    client = get_aws_client_for_protocol(service_name, protocol)

    request_context = {
        "client_region": client.meta.region_name,
        "client_config": client.meta.config,
        "has_streaming_input": operation.has_streaming_input,
        "auth_type": operation.auth_type,
    }
    request_args = _create_dummy_request_args(operation)

    # pre-process the request args (some params are modified using botocore event handlers)
    request_args = client._emit_api_params(request_args, operation, request_context)
    # The endpoint URL is mandatory here, just set a dummy (doesn't _need_ to be localstack specific)
    request_dict = client._convert_to_request_dict(
        request_args, operation, "http://localhost.localstack.cloud", request_context
    )
    request_object = create_request_object(request_dict)
    client._request_signer.sign(operation.name, request_object)
    request: Request = _botocore_request_to_localstack_request(request_object)

    # Execute the service router
    detected_service_model = determine_aws_service_model(request)
    detected_service_protocol = determine_aws_protocol(request, detected_service_model)

    # Make sure the detected service and protocol are the same as the one we generated the request for
    assert detected_service_model.service_name == service.service_name
    assert detected_service_protocol == protocol


def test_endpoint_prefix_based_routing():
    # TODO could be generalized using endpoint resolvers and replacing "amazonaws.com" with "localhost.localstack.cloud"
    detected_service_model = determine_aws_service_model(
        Request(method="GET", path="/", headers={"Host": "kms.localhost.localstack.cloud"})
    )
    assert detected_service_model.service_name == "kms"

    detected_service_model = determine_aws_service_model(
        Request(
            method="POST",
            path="/app-instances",
            headers={"Host": "identity-chime.localhost.localstack.cloud"},
        )
    )
    assert detected_service_model.service_name == "chime-sdk-identity"


def test_endpoint_prefix_based_routing_s3_virtual_host():
    detected_service_model = determine_aws_service_model(
        Request(method="GET", path="/", headers={"Host": "pictures.s3.localhost.localstack.cloud"})
    )
    assert detected_service_model.service_name == "s3"

    detected_service_model = determine_aws_service_model(
        Request(
            method="POST",
            path="/app-instances",
            headers={"Host": "kms.s3.localhost.localstack.cloud"},
        )
    )
    assert detected_service_model.service_name == "s3"


def test_endpoint_prefix_based_routing_for_sqs():
    # test without content type
    detected_service_model = determine_aws_service_model(
        Request(method="GET", path="/", headers={"Host": "sqs.localhost.localstack.cloud"})
    )
    assert detected_service_model.service_name == "sqs"
    assert detected_service_model.protocol == "query"

    # test explicitly with JSON
    detected_service_model = determine_aws_service_model(
        Request(
            method="GET",
            path="/",
            headers={
                "Host": "sqs.localhost.localstack.cloud",
                "Content-Type": "application/x-amz-json-1.0",
            },
        )
    )
    assert detected_service_model.service_name == "sqs"
    assert detected_service_model.protocol == "json"


def test_multi_protocols_detection():
    rpc_v2_request = Request(
        method="POST",
        path="/service/ArcRegionSwitch/operation/ListPlans",
        headers={
            "Host": "localhost.localstack.cloud",
            "Smithy-Protocol": "rpc-v2-cbor",
            "Content-Type": "application/cbor",
        },
    )

    detected_service_model = determine_aws_service_model(rpc_v2_request)
    assert detected_service_model.service_name == "arc-region-switch"
    assert detected_service_model.protocol == "smithy-rpc-v2-cbor"

    detected_protocol = determine_aws_protocol(rpc_v2_request, detected_service_model)
    assert detected_protocol == "smithy-rpc-v2-cbor"

    # test explicitly with JSON
    json_request = Request(
        method="POST",
        path="/",
        headers={
            "Host": "localhost.localstack.cloud",
            "X-Amz-Target": "ArcRegionSwitch.ListPlans",
            "Content-Type": "application/x-amz-json-1.0",
        },
    )

    detected_service_model = determine_aws_service_model(json_request)
    assert detected_service_model.service_name == "arc-region-switch"
    # the default service model protocol is still RPC v2 CBOR
    assert detected_service_model.protocol == "smithy-rpc-v2-cbor"

    detected_protocol = determine_aws_protocol(json_request, detected_service_model)
    assert detected_protocol == "json"


def test_multi_protocols_detection_error():
    bad_request = Request(
        method="POST",
        path="/",
        headers={
            "Host": "localhost.localstack.cloud",
            "X-Amz-Target": "ArcRegionSwitch.ListPlans",
        },
    )

    detected_service_model = determine_aws_service_model(bad_request)
    assert detected_service_model.service_name == "arc-region-switch"
    # the default service model protocol is still RPC v2 CBOR
    assert detected_service_model.protocol == "smithy-rpc-v2-cbor"

    with pytest.raises(ProtocolError):
        determine_aws_protocol(bad_request, detected_service_model)


def test_query_protocol_detection_with_empty_body():
    sns_request = Request(
        method="POST",
        path="/",
        headers={
            "Host": "localhost.localstack.cloud",
        },
        query_string="Action=ConfirmSubscription&TopicArn=bad_arn&Token=token",
    )

    detected_service_model = determine_aws_service_model(sns_request)
    assert detected_service_model.service_name == "sns"
    assert detected_service_model.protocol == "query"

    # we set wrong protocol here just to verify we can match `query` even if we don't have the Content-Type
    assert match_available_protocols(sns_request, ["query", "json"])
