"""Utils to process AWS requests as a client."""
from botocore.model import OperationModel
from botocore.parsers import create_parser as create_response_parser
from werkzeug import Response

from localstack.aws.api import ServiceResponse


def parse_response(operation: OperationModel, response: Response) -> ServiceResponse:
    """
    Parses an HTTP response object into an AWS response object using botocore.

    :param operation: the operation of the original request
    :param response: the HTTP response object containing the response of the operation
    :return: a parsed dictionary as it is returned by botocore
    """
    response_dict = {  # this is what botocore.endpoint.convert_to_response_dict normally does
        "headers": dict(response.headers.items()),  # boto doesn't like werkzeug headers
        "status_code": response.status_code,
        "body": response.data,
        "context": {
            "operation_name": operation.name,
        },
    }

    parser = create_response_parser(operation.service_model.protocol)
    return parser.parse(response_dict, operation.output_shape)
