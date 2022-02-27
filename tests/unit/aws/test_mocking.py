import pytest
from botocore.parsers import create_parser as create_response_parser

from localstack.aws.mocking import generate_request, generate_response
from localstack.aws.protocol.request import guess_aws_service_name
from localstack.aws.protocol.serializer import create_serializer as create_response_serializer
from localstack.aws.spec import ServiceCatalog, load_service
from localstack.services.moto import create_aws_request_context

services = ServiceCatalog()


def collect_operations():
    for service in services.services.values():
        for op_name in service.operation_names:
            yield service.service_name, op_name


@pytest.mark.parametrize(
    "service, op",
    collect_operations(),
)
def test_request_generator(service, op):
    service = services.get(service)
    op = service.operation_model(op)

    parameters = generate_request(op)
    context = create_aws_request_context(service.service_name, op.name, parameters)

    assert context.request.path
    assert context.request.method
    assert context.request.headers


@pytest.mark.parametrize(
    "service, op",
    collect_operations(),
)
def test_response_generator(service, op):
    service = services.get(service)
    op = service.operation_model(op)
    serializer = create_response_serializer(service)

    parameters = generate_response(op)
    print(parameters)
    serialized_response = serializer.serialize_to_response(parameters, op)

    response_parser = create_response_parser(service.protocol)
    parsed_response = response_parser.parse(
        serialized_response.to_readonly_response_dict(),
        op.output_shape,
    )

    assert parsed_response


@pytest.mark.parametrize(
    "service, op",
    collect_operations(),
)
def test_guess_aws_service(service, op):
    service = load_service(service)
    op = service.operation_model(op)

    parameters = generate_request(op)

    try:
        url = f"http://{service.endpoint_prefix}.localhost.localstack.cloud"
        context = create_aws_request_context(
            service.service_name, op.name, parameters, endpoint_url=url
        )
    except Exception as e:
        pytest.xfail(f"generated request was invalid: {e}")
        return

    request = context.request

    assert (
        guess_aws_service_name(services, context.request) == service.service_name
    ), "incorrect service for request %s %s %s" % (request.method, request.path, request.headers)
