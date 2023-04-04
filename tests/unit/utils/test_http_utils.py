import time

import pytest
from pytest_httpserver import HTTPServer

from localstack.http import Request, Response
from localstack.utils.files import load_file, new_tmp_file, rm_rf
from localstack.utils.http import ACCEPT, add_query_params_to_url, canonicalize_headers, download


def test_canonicalize_headers():
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9," "*/*;q=0.8",
        "Accept-encoding": "gzip, deflate, br",
        "Accept-language": "en-GB,en;q=0.9",
        "Host": "c2m48evwfk.execute-api.eu-west-1.amazonaws.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 "
        "Safari/605.1.15",
        "X-Amzn-Trace-Id": "Root=1-61d0de53-5843d28d07bf39f63b105411",
        "X-Forwarded-For": "37.228.224.133",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https",
    }
    canonicals_headers = canonicalize_headers(headers)
    result_headers = {
        k: v for k, v in canonicals_headers.items() if not k.lower().startswith(ACCEPT)
    }
    expected_headers = {k: v for k, v in headers.items() if not k.lower().startswith(ACCEPT)}

    assert result_headers == expected_headers


def test_add_query_params_to_url():
    tt = [
        {
            "uri": "http://localhost.localstack.cloud",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud?param=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud?foo=bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud?foo=bar&param" "=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud/foo/bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud/foo/bar?param" "=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud/foo/bar?foo=bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud/foo/bar?foo=bar" "&param=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud?foo=bar",
            "query_params": {"foo": "bar"},
            "expected": "http://localhost.localstack.cloud?foo=bar",
        },
    ]

    for t in tt:
        result = add_query_params_to_url(t["uri"], t["query_params"])
        assert result == t["expected"]


def test_download_with_timeout():
    def _handler(_: Request) -> Response:
        time.sleep(2)
        return Response(b"", status=200)

    tmp_file = new_tmp_file()
    # it seems this test is not properly cleaning up for other unit tests, this step is normally not necessary
    # we should use the fixture `httpserver` instead of HTTPServer directly
    with HTTPServer() as server:
        server.expect_request("/").respond_with_data(b"tmp_file", status=200)
        server.expect_request("/sleep").respond_with_handler(_handler)
        http_endpoint = server.url_for("/")

        download(http_endpoint, tmp_file)
        assert load_file(tmp_file) == "tmp_file"
        with pytest.raises(TimeoutError):
            download(f"{http_endpoint}/sleep", tmp_file, timeout=1)

    # clean up
    rm_rf(tmp_file)


def test_download_with_headers(httpserver):
    test_headers = {
        "Authorization": "Beeearer Token Test Header",
        "Random-Header": "Another non-specified header",
    }

    # only match for the specific headers
    httpserver.expect_request("/", headers=test_headers).respond_with_data("OK")

    http_endpoint = httpserver.url_for("/")
    tmp_file = new_tmp_file()
    download(http_endpoint, tmp_file, request_headers=test_headers)
