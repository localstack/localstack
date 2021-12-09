import json

from requests.models import Response

from localstack.services.generic_proxy import PartitionAdjustingProxyListener


def test_partition_adjustment_in_request():
    listener = PartitionAdjustingProxyListener()
    data = json.dumps(
        {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
    )
    headers = {
        "some-header-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }
    result = listener.forward_request(
        method="POST",
        # TODO check if this is url encoded at this time
        path="/?arn=arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-path/*",
        # TODO check if this is binary encoded at this time
        data=data,
        headers=headers,
    )
    assert result.method == "POST"
    assert result.path == "/?arn=arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-path/*"
    assert result.data == json.dumps(
        {"some-data-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
    )
    assert result.headers == {
        "some-header-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    }


def test_partition_adjustment_in_request_without_region_and_without_default_partition():
    listener = PartitionAdjustingProxyListener()
    data = json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
    headers = {"some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"}
    result = listener.forward_request(
        method="POST",
        path="/?arn=arn:aws-us-gov:iam::123456789012:ArnInPath",
        data=data,
        headers=headers,
    )
    assert result.method == "POST"
    assert result.path == "/?arn=arn:aws:iam::123456789012:ArnInPath"
    assert result.data == json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
    assert result.headers == {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}


def test_partition_adjustment_in_request_without_region_and_with_default_region(switch_region):
    with switch_region("us-gov-east-1"):
        listener = PartitionAdjustingProxyListener()
        data = json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
        headers = {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}
        result = listener.forward_request(
            method="POST",
            path="/?arn=arn:aws:iam::123456789012:ArnInPath",
            data=data,
            headers=headers,
        )
        assert result.method == "POST"
        assert result.path == "/?arn=arn:aws-us-gov:iam::123456789012:ArnInPath"
        assert result.data == json.dumps(
            {"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"}
        )
        assert result.headers == {
            "some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"
        }


def test_partition_adjustment_in_response():
    listener = PartitionAdjustingProxyListener()
    response = Response()
    response._content = json.dumps(
        {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
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
    assert result.content == json.dumps(
        {"some-data-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
    )


def test_partition_adjustment_in_response_without_region_and_without_default_region():
    listener = PartitionAdjustingProxyListener()
    response = Response()
    response._content = json.dumps(
        {"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"}
    )
    response._status_code = 200
    response.headers = {"some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"}

    result = listener.return_response(
        method="POST", path="/", data="ignored", headers={}, response=response
    )

    assert result.status_code == response.status_code
    assert result.headers == {"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"}
    assert result.content == json.dumps(
        {"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"}
    )


def test_partition_adjustment_in_response_without_region_and_with_default_region(switch_region):
    with switch_region("us-gov-east-1"):
        listener = PartitionAdjustingProxyListener()
        response = Response()
        response._content = json.dumps(
            {"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"}
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
        assert result.content == json.dumps(
            {"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"}
        )
