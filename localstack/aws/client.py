"""Utils to process AWS requests as a client."""
import io
import logging
from typing import Iterable

from botocore.model import OperationModel
from botocore.parsers import create_parser as create_response_parser
from werkzeug import Response

from localstack.aws.api import ServiceResponse

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


def parse_response(operation: OperationModel, response: Response) -> ServiceResponse:
    """
    Parses an HTTP Response object into an AWS response object using botocore. It does this by adapting the
    procedure of ``botocore.endpoint.convert_to_response_dict`` to work with Werkzeug's server-side response object.

    :param operation: the operation of the original request
    :param response: the HTTP response object containing the response of the operation
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

    if response_dict["status_code"] >= 300:
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
    return parser.parse(response_dict, operation.output_shape)
