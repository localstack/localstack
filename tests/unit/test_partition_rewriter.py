import json
from unittest import mock

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


def test_arn_partition_rewriting_url_encoding(httpserver, monkeypatch):
    path = "/query%3Aencoded%2Fpath/"

    def echo_path(request: WerkzeugRequest) -> Response:
        response = Response()
        response.set_json(
            {
                "method": request.method,
                "raw_path": get_raw_path(request),
                "url": request.url,
                "headers": dict(request.headers),
            }
        )
        return response

    httpserver.expect_request(path).respond_with_handler(echo_path)

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

    rewrite_handler.modify_response(response, request_region="us-gov-west-1")

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


def test_no_arn_partition_rewriting_in_internal_request():
    """Partitions should not be rewritten for _internal_ requests."""
    rewrite_handler = ArnPartitionRewriteHandler()
    request = Request(
        method="POST",
        path="/",
        body=b"",
        headers={},
    )
    handler2 = mock.MagicMock()
    # mimic an internal request
    request.headers.update(
        mock_aws_request_headers(
            region_name="us-gov-west-1",
            access_key=INTERNAL_AWS_ACCESS_KEY_ID,
            internal=True,
        )
    )
    chain = HandlerChain()
    chain.request_handlers.append(rewrite_handler)
    chain.request_handlers.append(handler2)
    context = RequestContext()
    context.request = request
    chain.handle(context, Response())
    assert not chain.terminated
    handler2.assert_called_once()


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
    rewrite_handler.modify_response(response=response, request_region="us-gov-west-1")

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
        rewrite_handler.modify_response(response=response, request_region=None)

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
        rewrite_handler.modify_response(response, request_region=None)

        assert response.status_code == response.status_code
        assert (
            response.headers["some-header-with-arn"]
            == "arn:aws-us-gov:iam::123456789012:ArnInHeader"
        )
        assert response.data == to_bytes(
            json.dumps({"some-data-with-arn": "arn:aws-us-gov:iam::123456789012:ArnInData"})
        )
