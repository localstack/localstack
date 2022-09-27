import pytest

from localstack.aws.api import ServiceException
from localstack.aws.client import _ResponseStream, parse_service_exception
from localstack.http import Response


def test_parse_service_exception():
    response = Response(status=400)
    parsed_response = {
        "Error": {
            "Code": "InvalidSubnetID.NotFound",
            "Message": "The subnet ID 'vpc-test' does not exist",
        }
    }
    exception = parse_service_exception(response, parsed_response)
    assert exception
    assert isinstance(exception, ServiceException)
    assert exception.code == "InvalidSubnetID.NotFound"
    assert exception.message == "The subnet ID 'vpc-test' does not exist"
    assert exception.status_code == 400
    assert not exception.sender_fault
    # Ensure that the parsed exception does not have the "Error" field from the botocore response dict
    assert not hasattr(exception, "Error")
    assert not hasattr(exception, "error")


class TestResponseStream:
    def test_read(self):
        response = Response(b"foobar")

        with _ResponseStream(response) as stream:
            assert stream.read(3) == b"foo"
            assert stream.read(3) == b"bar"

    def test_read_with_generator_response(self):
        def _gen():
            yield b"foo"
            yield b"bar"

        response = Response(_gen())

        with _ResponseStream(response) as stream:
            assert stream.read(2) == b"fo"
            # currently the response stream will not buffer across the next line
            assert stream.read(4) == b"o"
            assert stream.read(4) == b"bar"

    def test_as_iterator(self):
        def _gen():
            yield b"foo"
            yield b"bar"

        response = Response(_gen())

        with _ResponseStream(response) as stream:
            assert next(stream) == b"foo"
            assert next(stream) == b"bar"
            with pytest.raises(StopIteration):
                next(stream)
