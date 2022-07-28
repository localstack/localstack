from localstack.aws.api import ServiceException
from localstack.aws.client import parse_service_exception
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
