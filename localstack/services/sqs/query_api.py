"""The SQS Query API allows using Queue URLs as endpoints for operations on that queue. See:
https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-making-api-requests.html. This is a
generic implementation that creates from Query API requests the respective AWS requests, and uses an aws_stack client
to make the request. """
from urllib.parse import urlencode

from localstack import config
from localstack.aws.api import CommonServiceException
from localstack.aws.protocol.parser import OperationNotFoundParserError, create_parser
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.spec import load_service
from localstack.http import Request, Response, Router, route
from localstack.http.dispatcher import Handler
from localstack.utils.aws import aws_stack

service = load_service("sqs")
parser = create_parser(service)
serializer = create_serializer(service)


@route(
    '/queue/<regex("[a-z0-9-]+"):region>/<regex("[0-9]{12}"):account_id>/<regex("[a-zA-Z0-9_-]+(.fifo)?"):queue_name>',
    methods=["POST", "GET"],
)
def path_strategy_handler(request: Request, region, account_id, queue_name):
    return handle_request(request, region)


@route(
    '/<regex("[0-9]{12}"):account_id>/<regex("[a-zA-Z0-9_-]+(.fifo)?"):queue_name>',
    host="sqs.<regex('([a-z0-9-]+)?'):region>.localstack.cloud<regex('(:[0-9]{2,5})?'):port>",
    methods=["POST", "GET"],
)
def domain_strategy_handler(request: Request, account_id, queue_name, region=None, port=None):
    """Uses the endpoint host to extract the region. See:
    https://docs.aws.amazon.com/general/latest/gr/sqs-service.html"""
    return handle_request(request, region)


@route(
    '/<regex("[0-9]{12}"):account_id>/<regex("[a-zA-Z0-9_-]+(.fifo)?"):queue_name>',
    methods=["POST", "GET"],
)
def legacy_handler(request: Request, account_id, queue_name) -> Response:
    # previously, Queue URLs were created as http://localhost:4566/000000000000/my-queue-name. Because the region is
    # ambiguous in this request, we fall back to the default region and hope for the best.
    return handle_request(request, config.DEFAULT_REGION)


def handle_request(request: Request, region: str) -> Response:
    action = request.values.get("Action")
    if not action:
        return Response("<UnknownOperationException/>", 404)

    sqs = aws_stack.connect_to_service("sqs", region_name=region)

    # prepare aws request
    params = {"QueueUrl": request.base_url}
    params.update(request.values)
    body = urlencode(params)

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
            # use a dummy operation to make the serializer work
            error,
            service.operation_model(service.operation_names[0]),
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
    if request.is_json:
        # TODO: the response should be sent as JSON response
        pass

    return serializer.serialize_to_response(boto_response, operation)


def register(router: Router[Handler]):
    router.add_route_endpoint(path_strategy_handler)
    router.add_route_endpoint(domain_strategy_handler)
    router.add_route_endpoint(legacy_handler)
