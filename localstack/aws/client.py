"""Utils to process AWS requests as a client."""
import io
import logging
from typing import Dict, Iterable, Optional

from botocore.model import OperationModel
from botocore.parsers import ResponseParser
from botocore.parsers import create_parser as create_response_parser
from werkzeug import Response

from localstack.aws.api import CommonServiceException, ServiceException, ServiceResponse

LOG = logging.getLogger(__name__)


class _ResponseStream(io.RawIOBase):
    """
    Wraps a Response and makes it available as a readable IO stream.

    Adapted from https://stackoverflow.com/a/20260030/804840
    """

    def __init__(self, response: Response):
        self.response = response
        self.iterator = response.iter_encoded()
        self._buf = None

    def readable(self):
        return True

    def readinto(self, b):
        try:
            upto = len(b)  # We're supposed to return at most this much
            chunk = self._buf or next(self.iterator)
            output, self._buf = chunk[:upto], chunk[upto:]
            b[: len(output)] = output
            return len(output)
        except StopIteration:
            return 0  # indicate EOF

    def __str__(self):
        length = self.response.content_length
        if length is None:
            length = "unknown"

        return f"StreamedBytes({length})"

    def __repr__(self):
        return self.__str__()


class _RawStream:
    """This is a compatibility adapter for the raw_stream attribute passed to botocore's EventStream."""

    def __init__(self, response: Response):
        self.response = response
        self.iterator = response.iter_encoded()

    def stream(self) -> Iterable[bytes]:
        return self.iterator

    def close(self):
        pass


def _add_modeled_error_fields(
    response_dict: Dict,
    parsed_response: Dict,
    operation_model: OperationModel,
    parser: ResponseParser,
):
    """
    This function adds additional error shape members (other than message, code, and type) to an already parsed error
    response dict.
    Port of botocore's Endpoint#_add_modeled_error_fields.
    """
    error_code = parsed_response.get("Error", {}).get("Code")
    if error_code is None:
        return
    service_model = operation_model.service_model
    error_shape = service_model.shape_for_error_code(error_code)
    if error_shape is None:
        return
    modeled_parse = parser.parse(response_dict, error_shape)
    parsed_response.update(modeled_parse)


def parse_response(
    operation: OperationModel, response: Response, include_response_metadata: bool = True
) -> ServiceResponse:
    """
    Parses an HTTP Response object into an AWS response object using botocore. It does this by adapting the
    procedure of ``botocore.endpoint.convert_to_response_dict`` to work with Werkzeug's server-side response object.

    :param operation: the operation of the original request
    :param response: the HTTP response object containing the response of the operation
    :param include_response_metadata: True if the ResponseMetadata (typical for boto response dicts) should be included
    :return: a parsed dictionary as it is returned by botocore
    """
    # this is what botocore.endpoint.convert_to_response_dict normally does
    response_dict = {
        "headers": dict(response.headers.items()),  # boto doesn't like werkzeug headers
        "status_code": response.status_code,
        "context": {
            "operation_name": operation.name,
        },
    }

    if response_dict["status_code"] >= 301:
        response_dict["body"] = response.data
    elif operation.has_event_stream_output:
        # TODO test this
        response_dict["body"] = _RawStream(response)
    elif operation.has_streaming_output:
        # for s3.GetObject for example, the Body attribute is actually a stream, not the raw bytes value
        response_dict["body"] = _ResponseStream(response)
    else:
        response_dict["body"] = response.data

    parser = create_response_parser(operation.service_model.protocol)
    parsed_response = parser.parse(response_dict, operation.output_shape)

    if response.status_code >= 301:
        # Add possible additional error shape members
        _add_modeled_error_fields(response_dict, parsed_response, operation, parser)

    if not include_response_metadata:
        parsed_response.pop("ResponseMetadata", None)

    return parsed_response


def parse_service_exception(
    response: Response, parsed_response: Dict
) -> Optional[ServiceException]:
    """
    Creates a ServiceException from a parsed response (one that botocore would return).
    It does not automatically raise the exception (see #raise_service_exception).
    :param response: Un-parsed response
    :param parsed_response: Parsed response
    :return: ServiceException or None (if it's not an error response)
    """
    if response.status_code < 301 or "Error" not in parsed_response:
        return None
    error = parsed_response["Error"]
    service_exception = CommonServiceException(
        code=error.get("Code", f"'{response.status_code}'"),
        status_code=response.status_code,
        message=error.get("Message", ""),
        sender_fault=error.get("Type") == "Sender",
    )
    # Add all additional fields in the parsed response as members of the exception
    for key, value in parsed_response.items():
        if key.lower() not in ["code", "message", "type"] and not hasattr(service_exception, key):
            setattr(service_exception, key, value)
    return service_exception


def raise_service_exception(response: Response, parsed_response: Dict) -> None:
    """
    Creates and raises a ServiceException from a parsed response (one that botocore would return).
    :param response: Un-parsed response
    :param parsed_response: Parsed response
    :raise ServiceException: If the response is an error response
    :return: None if the response is not an error response
    """
    if service_exception := parse_service_exception(response, parsed_response):
        raise service_exception
