import json
from typing import Tuple

import pytest
import requests
from pytest_httpserver import HTTPServer
from werkzeug import Request as WerkzeugRequest

from localstack.http import Request, Response, Router
from localstack.http.client import SimpleRequestsClient
from localstack.http.dispatcher import handler_dispatcher
from localstack.http.hypercorn import HypercornServer
from localstack.http.proxy import Proxy, ProxyHandler, forward


@pytest.fixture
def router_server(serve_asgi_adapter) -> Tuple[Router, HypercornServer]:
    """Creates a new Router with a handler dispatcher, serves it through a newly created ASGI server, and returns
    both the router and the server.
    """
    router = Router(dispatcher=handler_dispatcher())
    app = WerkzeugRequest.application(router.dispatch)
    return router, serve_asgi_adapter(app)


class TestPathForwarder:
    def test_get_with_path_rule(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        backend.expect_request("/").respond_with_data("ok/")
        backend.expect_request("/bar").respond_with_data("ok/bar")
        backend.expect_request("/bar/ed").respond_with_data("ok/bar/ed")

        router.add("/foo/<path:path>", ProxyHandler(backend.url_for("/")))

        response = requests.get(proxy.url + "/foo/bar")
        assert response.ok
        assert response.text == "ok/bar"

        response = requests.get(proxy.url + "/foo/bar/ed")
        assert response.ok
        assert response.text == "ok/bar/ed"

        response = requests.get(proxy.url)
        assert not response.ok

        response = requests.get(proxy.url + "/bar")
        assert not response.ok

        backend.check()

    def test_get_with_plain_rule(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        backend.expect_request("/").respond_with_data("ok")

        router.add("/foo", ProxyHandler(backend.url_for("/")))

        response = requests.get(proxy.url + "/foo")
        assert response.ok
        assert response.text == "ok"

        response = requests.get(proxy.url + "/foo/bar")
        assert not response.ok

    def test_get_with_different_base_url(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        backend.expect_request("/bar/ed").respond_with_data("ok/bar/ed")
        backend.expect_request("/bar/ed/baz").respond_with_data("ok/bar/ed/baz")

        router.add("/foo/<path:path>", ProxyHandler(backend.url_for("/bar")))

        response = requests.get(proxy.url + "/foo/ed")
        assert response.ok
        assert response.text == "ok/bar/ed"

        response = requests.get(proxy.url + "/foo/ed/baz")
        assert response.ok
        assert response.text == "ok/bar/ed/baz"

    def test_get_with_different_base_url_plain_rule(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        backend.expect_request("/bar").respond_with_data("ok/bar")
        backend.expect_request("/bar/").respond_with_data("ok/bar/")

        router.add("/foo", ProxyHandler(backend.url_for("/bar")))

        response = requests.get(proxy.url + "/foo")
        assert response.ok
        assert response.text == "ok/bar/"  # it's calling /bar/ because it's part of the root URL

    def test_xff_header(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        def _echo_headers(request):
            return Response(json.dumps(dict(request.headers)), mimetype="application/json")

        backend.expect_request("/echo").respond_with_handler(_echo_headers)

        router.add("/<path:path>", ProxyHandler(backend.url_for("/")))

        response = requests.get(proxy.url + "/echo")
        assert response.ok
        headers = response.json()
        assert headers["X-Forwarded-For"] == "127.0.0.1"

        # check that it appends remote address correctly if a header is already present
        response = requests.get(proxy.url + "/echo", headers={"X-Forwarded-For": "127.0.0.2"})
        assert response.ok
        headers = response.json()
        assert headers["X-Forwarded-For"] == "127.0.0.2, 127.0.0.1"

    def test_post_form_data_with_query_args(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        def _handler(request: WerkzeugRequest):
            data = {
                "args": request.args,
                "form": request.form,
            }
            return Response(json.dumps(data), mimetype="application/json")

        backend.expect_request("/form").respond_with_handler(_handler)

        router.add("/<path:path>", ProxyHandler(backend.url_for("/")))

        response = requests.post(
            proxy.url + "/form?q=yes",
            data={"foo": "bar", "baz": "ed"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.ok
        doc = response.json()
        assert doc == {"args": {"q": "yes"}, "form": {"foo": "bar", "baz": "ed"}}

    def test_path_encoding_preservation(self, router_server, httpserver: HTTPServer):
        router, proxy = router_server
        backend = httpserver

        def _handler(request: WerkzeugRequest):
            from localstack.http.request import get_raw_path

            data = {"path": get_raw_path(request), "query": request.query_string.decode("utf-8")}
            return Response(json.dumps(data), mimetype="application/json")

        backend.expect_request("").respond_with_handler(_handler)

        router.add("/<path:path>", ProxyHandler(backend.url_for("/")))

        response = requests.get(
            proxy.url
            + "/arn%3Aaws%3Aservice%3Aeu-west-1%3A000000000000%3Aroot-arn-path%2Fsub-arn-path%2F%2A/%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B?%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B=%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B",
        )
        assert response.ok
        doc = response.json()
        assert doc == {
            "path": "/arn%3Aaws%3Aservice%3Aeu-west-1%3A000000000000%3Aroot-arn-path%2Fsub-arn-path%2F%2A/%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B",
            "query": "%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B=%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B",
        }


class TestProxy:
    def test_proxy_with_custom_client(
        self, httpserver: HTTPServer, httpserver_echo_request_metadata
    ):
        """The Proxy class allows the injection of a custom HTTP client which can attach default headers to every
        request. this test verifies that this works through the proxy implementation."""
        httpserver.expect_request("/").respond_with_handler(httpserver_echo_request_metadata)

        with SimpleRequestsClient() as client:
            client.session.headers["X-My-Custom-Header"] = "hello world"

            proxy = Proxy(httpserver.url_for("/").lstrip("/"), client)

            request = Request(
                path="/",
                method="POST",
                body="foobar",
                remote_addr="127.0.0.10",
                headers={"Host": "127.0.0.1:80"},
            )

            response = proxy.request(request)

            assert "X-My-Custom-Header" in response.json["headers"]
            assert response.json["method"] == "POST"
            assert response.json["headers"]["X-My-Custom-Header"] == "hello world"
            assert response.json["headers"]["X-Forwarded-For"] == "127.0.0.10"
            assert response.json["headers"]["Host"] == "127.0.0.1:80"


@pytest.mark.parametrize("consume_data", [True, False])
def test_forward_files_and_form_data_proxy_consumes_data(
    consume_data, serve_asgi_adapter, tmp_path
):
    """Tests that, when the proxy consumes (or doesn't consume) the request object's data prior to forwarding,
    the request is forwarded correctly. not using httpserver here because it consumes werkzeug data incorrectly (it
    calls ``request.get_data()``)."""

    @WerkzeugRequest.application
    def _backend_handler(request: WerkzeugRequest):
        data = {
            "data": request.data.decode("utf-8"),
            "args": request.args,
            "form": request.form,
            "files": {
                name: storage.stream.read().decode("utf-8")
                for name, storage in request.files.items()
            },
        }
        return Response(json.dumps(data), mimetype="application/json")

    @WerkzeugRequest.application
    def _proxy_handler(request: WerkzeugRequest):
        # heuristic to check whether the stream has been consumed
        assert getattr(request, "_cached_data", None) is None, "data has already been cached"

        if consume_data:
            assert (
                not request.data
            )  # data should be empty because it is consumed by parsing form data

        return forward(request, forward_base_url=backend.url)

    backend = serve_asgi_adapter(_backend_handler)
    proxy = serve_asgi_adapter(_proxy_handler)

    tmp_file_1 = tmp_path / "temp_file_1.txt"
    tmp_file_1.write_text("1: hello\nworld")

    tmp_file_2 = tmp_path / "temp_file_2.txt"
    tmp_file_2.write_text("2: foobar")

    response = requests.post(
        proxy.url,
        params={"q": "yes"},
        data={"foo": "bar", "baz": "ed"},
        files={"upload_file_1": open(tmp_file_1, "rb"), "upload_file_2": open(tmp_file_2, "rb")},
    )
    assert response.ok
    doc = response.json()
    assert doc == {
        "data": "",
        "args": {"q": "yes"},
        "form": {"foo": "bar", "baz": "ed"},
        "files": {
            "upload_file_1": "1: hello\nworld",
            "upload_file_2": "2: foobar",
        },
    }
