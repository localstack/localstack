import base64
import hashlib
import json
from urllib.parse import urlencode

import pytest
from werkzeug.wrappers import Request as WerkzeugRequest

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.handlers.partition_rewriter import ArnPartitionRewriteHandler
from localstack.constants import INTERNAL_AWS_ACCESS_KEY_ID
from localstack.http import Request, Response
from localstack.http.request import get_full_raw_path, get_raw_path
from localstack.utils.aws.aws_stack import mock_aws_request_headers
from localstack.utils.common import to_bytes, to_str

# Define the callables used to convert the payload to the appropriate encoding for the tests
byte_encoding = to_bytes
string_encoding = to_str


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_no_arn_partition_rewriting_in_request(encoding):
    rewrite_handler = ArnPartitionRewriteHandler()
    data = encoding(json.dumps({"some-data-without-arn": "nothing to see here"}))
    headers = {"some-header-without-arn": "nothing to see here"}
    request = Request(
        method="POST",
        path="/",
        query_string="nothingtoseehere&somethingelse=something",
        body=data,
        headers=headers,
    )
    result = rewrite_handler.modify_request(request)
    assert result.method == "POST"
    assert result.full_path == "/?nothingtoseehere&somethingelse=something"
    # result for proxy will always be bytes
    assert result.data == to_bytes(json.dumps({"some-data-without-arn": "nothing to see here"}))
    assert result.headers["some-header-without-arn"] == "nothing to see here"


@pytest.mark.parametrize("internal_call", [True, False])
@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
@pytest.mark.parametrize("origin_partition", ["aws", "aws-us-gov"])
def test_arn_partition_rewriting_in_request(internal_call, encoding, origin_partition):
    rewrite_handler = ArnPartitionRewriteHandler()
    data = encoding(
        json.dumps(
            {
                "some-data-with-arn": f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
            }
        )
    )

    # if this test is parameterized to be an internal call, set the internal auth
    # incoming requests should be rewritten for both, internal and external requests (in contrast to the responses!)
    if internal_call:
        headers = mock_aws_request_headers(
            region_name=origin_partition,
            access_key=INTERNAL_AWS_ACCESS_KEY_ID,
            internal=True,
        )
    else:
        headers = {}

    headers[
        "some-header-with-arn"
    ] = f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-header/*"

    request = Request(
        method="POST",
        path=f"/arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A",
        query_string=f"arn=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query%2F%2A&"
        f"arn2=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query2%2F%2A",
        body=data,
        headers=headers,
    )
    result = rewrite_handler.modify_request(request)
    assert result.method == "POST"
    assert (
        get_full_raw_path(result)
        == "/arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A?arn=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query%2F%2A&"
        "arn2=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query2%2F%2A"
    )
    assert result.data == to_bytes(
        json.dumps(
            {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
        )
    )
    assert (
        result.headers["some-header-with-arn"]
        == "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    )


def test_arn_partition_rewriting_urlencoded_body():
    rewrite_handler = ArnPartitionRewriteHandler()
    data = {"some-data-with-arn": "arn:aws-us-gov:iam::000000000000:role/test-role"}

    # if this test is parameterized to be an internal call, set the internal auth
    # incoming requests should be rewritten for both, internal and external requests (in contrast to the responses!)
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}

    request = Request(
        method="POST",
        path="/",
        query_string="",
        body=urlencode(data),
        headers=headers,
    )
    result = rewrite_handler.modify_request(request)
    assert result.method == "POST"
    assert get_full_raw_path(result) == "/"
    assert result.form.to_dict() == {
        "some-data-with-arn": "arn:aws:iam::000000000000:role/test-role"
    }


def test_arn_partition_rewriting_contentmd5():
    rewrite_handler = ArnPartitionRewriteHandler()
    data = {"some-data-with-arn": "arn:aws-us-gov:iam::000000000000:role/test-role"}
    body = urlencode(data)
    original_md5 = base64.b64encode(hashlib.md5(body.encode("utf-8")).digest()).decode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Content-MD5": original_md5,
    }

    request = Request(
        method="POST",
        path="/",
        query_string="",
        body=body,
        headers=headers,
    )
    result = rewrite_handler.modify_request(request)
    data = result.get_data()
    assert result.method == "POST"
    assert get_full_raw_path(result) == "/"
    assert result.form.to_dict() == {
        "some-data-with-arn": "arn:aws:iam::000000000000:role/test-role"
    }
    assert "Content-MD5" in result.headers
    assert result.headers["Content-MD5"] != original_md5
    assert result.headers["Content-MD5"] == base64.b64encode(hashlib.md5(data).digest()).decode(
        "utf-8"
    )


def test_arn_partition_rewriting_url_encoding(httpserver, monkeypatch):
    path = "/query%3Aencoded%2Fpath/"

    def echo_path(_request: WerkzeugRequest) -> Response:
        response = Response()
        response.set_json(
            {
                "method": _request.method,
                "raw_path": get_raw_path(_request),
                "url": _request.url,
                "headers": dict(_request.headers),
            }
        )
        return response

    # httpserver matches on the URL-decoded path
    httpserver.expect_request("/query:encoded/path/").respond_with_handler(echo_path)

    def mock_get_edge_url() -> str:
        # Set the forwarding URL to the mock HTTP server
        return httpserver.url_for("/")

    monkeypatch.setattr(config, "get_edge_url", mock_get_edge_url)

    request = Request(
        method="POST",
        path=path,
        body=b"",
        headers={"Host": f"{httpserver.host}:{httpserver.port}"},
    )

    rewrite_handler = ArnPartitionRewriteHandler()
    chain = HandlerChain()
    chain.request_handlers.append(rewrite_handler)
    context = RequestContext()
    context.request = request
    chain.handle(context, Response())
    assert chain.terminated
    assert chain.response.json.get("raw_path") == path


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
@pytest.mark.parametrize("origin_partition", ["aws", "aws-us-gov"])
def test_arn_partition_rewriting_in_request_without_region_and_without_default_partition(
    encoding, origin_partition
):
    rewrite_handler = ArnPartitionRewriteHandler()
    data = encoding(
        json.dumps({"some-data-with-arn": f"arn:{origin_partition}:iam::123456789012:ArnInData"})
    )
    headers = {"some-header-with-arn": f"arn:{origin_partition}:iam::123456789012:ArnInHeader"}
    request = Request(
        method="POST",
        path="/",
        query_string=f"arn=arn%3A{origin_partition}%3Aiam%3A%3A123456789012%3AArnInPath&"
        f"arn2=arn%3A{origin_partition}%3Aiam%3A%3A123456789012%3AArnInPath2",
        body=data,
        headers=headers,
    )
    result = rewrite_handler.modify_request(request)
    assert result.method == "POST"
    assert (
        result.full_path == "/?arn=arn%3Aaws%3Aiam%3A%3A123456789012%3AArnInPath&"
        "arn2=arn%3Aaws%3Aiam%3A%3A123456789012%3AArnInPath2"
    )
    assert result.data == to_bytes(
        json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
    )
    assert result.headers["some-header-with-arn"] == "arn:aws:iam::123456789012:ArnInHeader"


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_arn_partition_rewriting_in_response(encoding):
    rewrite_handler = ArnPartitionRewriteHandler()
    response = Response(
        response=encoding(
            json.dumps(
                {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
            )
        ),
        status=200,
        headers={
            "some-header-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
        },
    )

    rewrite_handler.modify_response_revert(response, request_region="us-gov-west-1")

    assert response.status_code == response.status_code
    assert (
        response.headers["some-header-with-arn"]
        == "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
    )
    assert response.data == to_bytes(
        json.dumps(
            {
                "some-data-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
            }
        )
    )


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_arn_partition_rewriting_in_response_with_request_region(encoding):
    rewrite_handler = ArnPartitionRewriteHandler()
    response = Response(
        response=encoding(
            json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
        ),
        status=200,
        headers={"some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"},
    )
    rewrite_handler.modify_response_revert(response=response, request_region="us-gov-west-1")

    assert response.status_code == 200
    assert (
        response.headers["some-header-with-arn"] == "arn:aws-us-gov:iam::123456789012:ArnInHeader"
    )
    assert response.data == to_bytes(
        json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
    )


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_arn_partition_rewriting_in_response_without_region_and_without_default_region(
    encoding, switch_region
):
    with switch_region(None):
        rewrite_handler = ArnPartitionRewriteHandler()
        response = Response(
            response=encoding(
                json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
            ),
            status=200,
            headers={"some-header-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInHeader"},
        )
        rewrite_handler.modify_response_revert(response=response, request_region=None)

        assert response.status_code == 200
        assert response.headers["some-header-with-arn"] == "arn:aws:iam::123456789012:ArnInHeader"
        assert response.data == to_bytes(
            json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
        )


@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
def test_arn_partition_rewriting_in_response_without_region_and_with_default_region(
    encoding, switch_region
):
    with switch_region("us-gov-east-1"):
        rewrite_handler = ArnPartitionRewriteHandler()
        response = Response(
            response=encoding(
                json.dumps({"some-data-with-arn": "arn:aws:iam::123456789012:ArnInData"})
            ),
            status=200,
            headers={"some-header-with-arn": "arn:aws:iam::123456789012:ArnInHeader"},
        )
        rewrite_handler.modify_response_revert(response, request_region=None)

        assert response.status_code == response.status_code
        assert (
            response.headers["some-header-with-arn"]
            == "arn:aws-us-gov:iam::123456789012:ArnInHeader"
        )
        assert response.data == to_bytes(
            json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
        )


@pytest.mark.parametrize("internal_call", [True, False])
@pytest.mark.parametrize("encoding", [byte_encoding, string_encoding])
@pytest.mark.parametrize("origin_partition", ["aws", "aws-us-gov"])
def test_arn_partition_rewriting_in_request_and_response(
    internal_call, encoding, origin_partition, httpserver, monkeypatch
):
    handler_data = {}

    def echo(_request: WerkzeugRequest) -> Response:
        handler_data["received_request"] = _request
        response = Response()
        response.set_data(_request.data)
        response.headers = _request.headers
        handler_data["sent_request"] = response
        return response

    httpserver.expect_request("").respond_with_handler(echo)

    def mock_get_edge_url() -> str:
        # Set the forwarding URL to the mock HTTP server
        return httpserver.url_for("/")

    monkeypatch.setattr(config, "get_edge_url", mock_get_edge_url)
    data = encoding(
        json.dumps(
            {
                "some-data-with-arn": f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
            }
        )
    )

    # if this test is parameterized to be an internal call, set the internal auth
    # incoming requests should be rewritten for both, internal and external requests (in contrast to the responses!)
    if internal_call:
        headers = mock_aws_request_headers(
            region_name=origin_partition,
            access_key=INTERNAL_AWS_ACCESS_KEY_ID,
            internal=True,
        )
    else:
        headers = {"Host": f"{httpserver.host}:{httpserver.port}"}

    headers[
        "Arn-Header"
    ] = f"arn:{origin_partition}:apigateway:us-gov-west-1::/restapis/arn-in-header/*"

    request = Request(
        method="POST",
        path=f"/arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A",
        query_string=f"arn=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query%2F%2A&"
        f"arn2=arn%3A{origin_partition}%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query2%2F%2A",
        body=data,
        headers=headers,
    )
    rewrite_handler = ArnPartitionRewriteHandler()
    chain = HandlerChain()
    chain.request_handlers.append(rewrite_handler)
    context = RequestContext()
    context.request = request
    chain.handle(context, Response())
    if internal_call:
        assert not chain.terminated
        assert chain.response.data == b""
    else:
        # ensure that the backend system received the "internal" path, query, header, and data (partition is always "AWS")
        assert (
            get_raw_path(handler_data["received_request"])
            == "/arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-path%2F%2A"
        )
        assert (
            handler_data["received_request"].query_string
            == b"arn=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query%2F%2A&arn2=arn%3Aaws%3Aapigateway%3Aus-gov-west-1%3A%3A%2Frestapis%2Farn-in-query2%2F%2A"
        )
        assert (
            handler_data["received_request"].headers["Arn-Header"]
            == "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
        )
        assert handler_data["received_request"].data == to_bytes(
            json.dumps(
                {"some-data-with-arn": "arn:aws:apigateway:us-gov-west-1::/restapis/arn-in-body/*"}
            )
        )

        # ensure the client receives the "external" header, and data (partition is always the one which was sent)
        received_response = chain.response
        response_headers = received_response.headers
        assert (
            response_headers["Arn-Header"]
            == "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-header/*"
        )
        assert received_response.data == to_bytes(
            json.dumps(
                {
                    "some-data-with-arn": "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/arn-in-body/*"
                }
            )
        )
