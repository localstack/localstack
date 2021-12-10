import json

import pytest
from requests.models import Response

from localstack.services.generic_proxy import PartitionAdjustingProxyListener
from localstack.utils.common import to_bytes, to_str

# Define the callables used to convert the payload to the appropriate encoding for the tests
byte_encoding = to_bytes
string_encoding = to_str


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
@pytest.mark.parametrize("origin_partition", ["aws", "aws-us-gov"])
def test_partition_adjustment_in_request(encoding, origin_partition):
    listener = PartitionAdjustingProxyListener()
    data = encoding(
        json.dumps(
            {
                "some-data-with-arn": f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
            }
        )
    )
    headers = {
        "some-header-with-arn": f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }
    result = listener.forward_request(
        method="POST",
        path=f"/?arn=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A&"
        f"arn2=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path2%2F%2A",
        data=data,
        headers=headers,
    )
    assert result.method == "POST"
    assert (
        result.path
        == "/?arn=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A&"
        "arn2=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path2%2F%2A"
    )
    assert result.data == encoding(
        json.dumps(
            {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
        )
    )
    assert result.headers == {
        "some-header-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
@pytest.mark.parametrize("origin_partition", ["aws", "aws-us-gov"])
def test_partition_adjustment_in_request_without_region_and_without_default_partition(
    encoding, origin_partition
):
    listener = PartitionAdjustingProxyListener()
    data = encoding(
        json.dumps({"some-data-with-arn": f"arn:{origin_partition}:iam::123456789012:ArnInData"})
    )
    headers = {"some-header-with-arn": f"arn:{origin_partition}:iam::123456789012:ArnInHeader"}
    result = listener.forward_request(
        method="POST",
        path=f"/?arn=arn%3A{origin_partition}%3Aiam%3A%3A123456789012%3AArnInPath&"
        f"arn2=arn%3A{origin_partition}%3Aiam%3A%3A123456789012%3AArnInPath2",
        data=data,
        headers=headers,
    )
    assert result.method == "POST"
    assert (
        result.path == "/?arn=arn%3Aaws%3Aiam%3A%3A123456789012%3AArnInPath&"
        "arn2=arn%3Aaws%3Aiam%3A%3A123456789012%3AArnInPath2"
    )
    assert result.data == encoding(
        json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
    )
    assert result.headers == {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_partition_adjustment_in_response(encoding):
    listener = PartitionAdjustingProxyListener()
    response = Response()
    response._content = encoding(
        json.dumps(
            {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
        )
    )
    response._status_code = 200
    response.headers = {
        "some-header-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }

    result = listener.return_response(
        method="POST", path="/", data="ignored", headers={}, response=response
    )

    assert result.status_code == response.status_code
    assert result.headers == {
        "some-header-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }
    assert result.content == encoding(
        json.dumps(
            {
                "some-data-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
            }
        )
    )


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_partition_adjustment_in_response_without_region_and_without_default_region(encoding):
    listener = PartitionAdjustingProxyListener()
    response = Response()
    response._content = encoding(
        json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
    )
    response._status_code = 200
    response.headers = {"some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"}

    result = listener.return_response(
        method="POST", path="/", data="ignored", headers={}, response=response
    )

    assert result.status_code == response.status_code
    assert result.headers == {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}
    assert result.content == encoding(
        json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
    )


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_partition_adjustment_in_response_without_region_and_with_default_region(
    encoding, switch_region
):
    with switch_region("us-gov-east-1"):
        listener = PartitionAdjustingProxyListener()
        response = Response()
        response._content = encoding(
            json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
        )
        response._status_code = 200
        response.headers = {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}

        result = listener.return_response(
            method="POST", path="/", data="ignored", headers={}, response=response
        )

        assert result.status_code == response.status_code
        assert result.headers == {
            "some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"
        }
        assert result.content == encoding(
            json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
        )
