import re
from urllib.parse import urlencode

from localstack.aws.api import CommonServiceException
from localstack.aws.protocol.parser import OperationNotFoundParserError, create_parser
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.spec import load_service
from localstack.http import Request, Response
from localstack.services.edge import ROUTER
from localstack.utils.aws import aws_stack

_re_region = re.compile(r"^([a-z0-9-]+).queue")

service = load_service("sqs")
parser = create_parser(service)
serializer = create_serializer(service)


def handler(request: Request, account_id, queue_name):
    # extract region from endpoint host
    # see https://docs.aws.amazon.com/general/latest/gr/sqs-service.html

    matcher = _re_region.match(request.host)
    if matcher:
        region = matcher.group(1)
    else:
        region = "us-east-1"

    action = request.values.get("Action")
    if not action:
        return Response("<UnknownOperationException/>", 404)

    sqs = aws_stack.connect_to_service("sqs", region_name=region)

    # prepare aws request
    params = {"QueueUrl": request.base_url}
    params.update(request.values)
    body = urlencode(params)

    # TODO: unknownoperationexception
    try:
        operation, service_request = parser.parse(
            Request(request.method, headers=request.headers, body=body)
        )
    except OperationNotFoundParserError:
        error = CommonServiceException(
            "InvalidAction",
            message=f"The action {action} is not valid for this endpoint.",
            sender_fault=True,
        )
        return serializer.serialize_error_to_response(
            error, service.operation_model(service.operation_names[0])
        )

    boto_response = sqs._make_api_call(operation.name, service_request)
    status = boto_response["ResponseMetadata"]["HTTPStatusCode"]

    if status >= 301:
        error = boto_response["Error"]
        return serializer.serialize_error_to_response(
            CommonServiceException(
                code=error.get("Code", "UnknownError"),
                status_code=status,
                message=error.get("Message", ""),
            ),
            service.operation_model(operation),
        )

    # metadata = boto_response.pop("ResponseMetadata", {})
    return serializer.serialize_to_response(boto_response, operation)


ROUTER.add(
    '/<regex("[0-9]{12}"):account_id>/<regex("[a-zA-Z0-9_-]+(.fifo)?"):queue_name>',
    handler,
    methods=["POST", "GET"],
)
