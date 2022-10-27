import pytest

from localstack import config
from localstack.services.generic_proxy import UrlMatchingForwarder, get_cert_pem_file_path


class TestUrlMatchingForwarder:
    def test_matches_with_root_path_without_host(self):
        forwarder = UrlMatchingForwarder("/", "http://localhost")

        assert not forwarder.matches("", "")
        assert forwarder.matches("", "/")
        assert forwarder.matches("", "/fo")
        assert forwarder.matches("", "/foo")
        assert forwarder.matches("", "/foo/")
        assert forwarder.matches("", "/foo/bar")
        assert forwarder.matches("", "/fooo")
        assert forwarder.matches("example.com", "/")
        assert forwarder.matches("example.com", "/fo")
        assert forwarder.matches("example.com", "/foo")
        assert forwarder.matches("example.com", "/foo/")
        assert forwarder.matches("example.com", "/foo/bar")
        assert forwarder.matches("example.com", "/fooo")
        assert forwarder.matches("localhost", "/")
        assert forwarder.matches("localhost", "/fo")
        assert forwarder.matches("localhost", "/foo")
        assert forwarder.matches("localhost", "/foo/")
        assert forwarder.matches("localhost", "/foo/bar")
        assert forwarder.matches("localhost", "/fooo")
        assert forwarder.matches("localhost:8080", "/")
        assert forwarder.matches("localhost:8080", "/foo")
        assert forwarder.matches("localhost:8080", "/foo/bar")
        assert forwarder.matches("localhost", "/fooo")

    def test_matches_with_path_without_host(self):
        forwarder = UrlMatchingForwarder("/foo", "http://localhost")

        assert not forwarder.matches("", "")
        assert not forwarder.matches("", "/")
        assert not forwarder.matches("", "/fo")
        assert forwarder.matches("", "/foo")
        assert forwarder.matches("", "/foo/")
        assert forwarder.matches("", "/foo/bar")
        assert not forwarder.matches("", "/fooo")
        assert not forwarder.matches("example.com", "/")
        assert not forwarder.matches("example.com", "/fo")
        assert forwarder.matches("example.com", "/foo")
        assert forwarder.matches("example.com", "/foo/")
        assert forwarder.matches("example.com", "/foo/bar")
        assert not forwarder.matches("example.com", "/fooo")
        assert not forwarder.matches("localhost", "/")
        assert not forwarder.matches("localhost", "/fo")
        assert forwarder.matches("localhost", "/foo")
        assert forwarder.matches("localhost", "/foo/")
        assert forwarder.matches("localhost", "/foo/bar")
        assert not forwarder.matches("localhost", "/fooo")
        assert not forwarder.matches("localhost:8080", "/")
        assert forwarder.matches("localhost:8080", "/foo")
        assert forwarder.matches("localhost:8080", "/foo/bar")

    def test_matches_without_path_with_host(self):
        forwarder = UrlMatchingForwarder("http://example.com", "http://localhost")

        assert not forwarder.matches("", "")
        assert not forwarder.matches("", "/")
        assert not forwarder.matches("", "/fo")
        assert not forwarder.matches("", "/foo")
        assert not forwarder.matches("", "/foo/")
        assert not forwarder.matches("", "/foo/bar")
        assert not forwarder.matches("", "/fooo")
        assert forwarder.matches("example.com", "")
        assert forwarder.matches("example.com", "/")
        assert forwarder.matches("example.com", "/fo")
        assert forwarder.matches("example.com", "/foo")
        assert forwarder.matches("example.com", "/foo/")
        assert forwarder.matches("example.com", "/foo/bar")
        assert forwarder.matches("example.com", "/fooo")
        assert not forwarder.matches("localhost", "/")
        assert not forwarder.matches("localhost", "/fo")
        assert not forwarder.matches("localhost", "/foo")
        assert not forwarder.matches("localhost", "/foo/")
        assert not forwarder.matches("localhost", "/foo/bar")
        assert not forwarder.matches("localhost", "/fooo")
        assert not forwarder.matches("localhost:8080", "/")
        assert not forwarder.matches("localhost:8080", "/foo")
        assert not forwarder.matches("localhost:8080", "/foo/bar")

    def test_matches_with_path_with_host(self):
        forwarder = UrlMatchingForwarder("http://example.com/foo", "http://localhost")

        assert not forwarder.matches("", "")
        assert not forwarder.matches("", "/")
        assert not forwarder.matches("", "/fo")
        assert not forwarder.matches("", "/foo")
        assert not forwarder.matches("", "/foo/")
        assert not forwarder.matches("", "/foo/bar")
        assert not forwarder.matches("", "/fooo")
        assert not forwarder.matches("example.com", "")
        assert not forwarder.matches("example.com", "/")
        assert not forwarder.matches("example.com", "/fo")
        assert forwarder.matches("example.com", "/foo")
        assert forwarder.matches("example.com", "/foo/")
        assert forwarder.matches("example.com", "/foo/bar")
        assert not forwarder.matches("example.com", "/fooo")
        assert not forwarder.matches("localhost", "")
        assert not forwarder.matches("localhost", "/")
        assert not forwarder.matches("localhost", "/fo")
        assert not forwarder.matches("localhost", "/foo")
        assert not forwarder.matches("localhost", "/foo/")
        assert not forwarder.matches("localhost", "/foo/bar")
        assert not forwarder.matches("localhost", "/fooo")
        assert not forwarder.matches("localhost:8080", "/")
        assert not forwarder.matches("localhost:8080", "")
        assert not forwarder.matches("localhost:8080", "/foo")
        assert not forwarder.matches("localhost:8080", "/foo/bar")

    def test_matches_with_path_with_host_and_port(self):
        forwarder = UrlMatchingForwarder("http://localhost:8080/foo", "http://localhost")

        assert not forwarder.matches("", "")
        assert not forwarder.matches("", "/")
        assert not forwarder.matches("", "/fo")
        assert not forwarder.matches("", "/foo")
        assert not forwarder.matches("", "/foo/")
        assert not forwarder.matches("", "/foo/bar")
        assert not forwarder.matches("", "/fooo")
        assert not forwarder.matches("example.com", "")
        assert not forwarder.matches("example.com", "/")
        assert not forwarder.matches("example.com", "/fo")
        assert not forwarder.matches("example.com", "/foo")
        assert not forwarder.matches("example.com", "/foo/")
        assert not forwarder.matches("example.com", "/foo/bar")
        assert not forwarder.matches("example.com", "/fooo")
        assert not forwarder.matches("localhost", "")
        assert not forwarder.matches("localhost", "/")
        assert not forwarder.matches("localhost", "/fo")
        assert not forwarder.matches("localhost", "/foo")
        assert not forwarder.matches("localhost", "/foo/")
        assert not forwarder.matches("localhost", "/foo/bar")
        assert not forwarder.matches("localhost", "/fooo")
        assert not forwarder.matches("localhost:8080", "/")
        assert not forwarder.matches("localhost:8080", "")
        assert forwarder.matches("localhost:8080", "/foo")
        assert forwarder.matches("localhost:8080", "/foo/bar")

    def test_build_forward_url_with_host(self):
        forwarder = UrlMatchingForwarder("/", "http://localhost")

        def geturl(host, path):
            return forwarder.build_forward_url(host, path).geturl()

        assert geturl("", "/") == "http://localhost"
        assert geturl("", "/fo") == "http://localhost/fo"
        assert geturl("", "/foo") == "http://localhost/foo"
        assert geturl("", "/foo/") == "http://localhost/foo/"
        assert geturl("", "/foo/bar") == "http://localhost/foo/bar"
        assert geturl("", "/fooo") == "http://localhost/fooo"
        assert geturl("example.com", "/") == "http://localhost"
        assert geturl("example.com", "/fo") == "http://localhost/fo"
        assert geturl("example.com", "/foo") == "http://localhost/foo"
        assert geturl("example.com", "/foo/") == "http://localhost/foo/"
        assert geturl("example.com", "/foo/bar") == "http://localhost/foo/bar"
        assert geturl("example.com", "/fooo") == "http://localhost/fooo"
        assert geturl("localhost", "/") == "http://localhost"
        assert geturl("localhost", "/fo") == "http://localhost/fo"
        assert geturl("localhost", "/foo") == "http://localhost/foo"
        assert geturl("localhost", "/foo/") == "http://localhost/foo/"
        assert geturl("localhost", "/foo/bar") == "http://localhost/foo/bar"
        assert geturl("localhost", "/fooo") == "http://localhost/fooo"
        assert geturl("localhost:8080", "/") == "http://localhost"
        assert geturl("localhost:8080", "/foo") == "http://localhost/foo"
        assert geturl("localhost:8080", "/foo/bar") == "http://localhost/foo/bar"

    def test_build_forward_url_with_host_and_path(self):
        forwarder = UrlMatchingForwarder("/", "http://localhost/p")

        def geturl(host, path):
            return forwarder.build_forward_url(host, path).geturl()

        assert geturl("", "/") == "http://localhost/p"
        assert geturl("", "/fo") == "http://localhost/p/fo"
        assert geturl("", "/foo") == "http://localhost/p/foo"
        assert geturl("", "/foo/") == "http://localhost/p/foo/"
        assert geturl("", "/foo/bar") == "http://localhost/p/foo/bar"
        assert geturl("", "/fooo") == "http://localhost/p/fooo"
        assert geturl("example.com", "/") == "http://localhost/p"
        assert geturl("example.com", "/fo") == "http://localhost/p/fo"
        assert geturl("example.com", "/foo") == "http://localhost/p/foo"
        assert geturl("example.com", "/foo/") == "http://localhost/p/foo/"
        assert geturl("example.com", "/foo/bar") == "http://localhost/p/foo/bar"
        assert geturl("example.com", "/fooo") == "http://localhost/p/fooo"
        assert geturl("localhost", "/") == "http://localhost/p"
        assert geturl("localhost", "/fo") == "http://localhost/p/fo"
        assert geturl("localhost", "/foo") == "http://localhost/p/foo"
        assert geturl("localhost", "/foo/") == "http://localhost/p/foo/"
        assert geturl("localhost", "/foo/bar") == "http://localhost/p/foo/bar"
        assert geturl("localhost", "/fooo") == "http://localhost/p/fooo"
        assert geturl("localhost:8080", "/") == "http://localhost/p"
        assert geturl("localhost:8080", "/foo") == "http://localhost/p/foo"
        assert geturl("localhost:8080", "/foo/bar") == "http://localhost/p/foo/bar"

    def test_build_forward_url_with_host_and_trailing_path(self):
        forwarder = UrlMatchingForwarder("/", "http://localhost/p/")

        def geturl(host, path):
            return forwarder.build_forward_url(host, path).geturl()

        assert geturl("", "/") == "http://localhost/p/"
        assert geturl("", "/fo") == "http://localhost/p/fo"
        assert geturl("localhost", "/") == "http://localhost/p/"
        assert geturl("localhost", "/fo") == "http://localhost/p/fo"

    def test_build_forward_url_with_host_and_subpath(self):
        forwarder = UrlMatchingForwarder("/foo", "http://localhost:1234/oof")

        def geturl(host, path):
            return forwarder.build_forward_url(host, path).geturl()

        assert geturl("", "/foo") == "http://localhost:1234/oof"
        assert geturl("", "/foo/") == "http://localhost:1234/oof/"
        assert geturl("", "/foo/bar") == "http://localhost:1234/oof/bar"
        assert geturl("", "/foo/bar/") == "http://localhost:1234/oof/bar/"

    def test_build_forward_url_with_path(self):
        forwarder = UrlMatchingForwarder("/", "/p")

        def geturl(host, path):
            return forwarder.build_forward_url(host, path).geturl()

        assert geturl("", "/") == "/p"
        assert geturl("", "/fo") == "/p/fo"
        assert geturl("", "/foo") == "/p/foo"
        assert geturl("", "/foo/") == "/p/foo/"
        assert geturl("", "/foo/bar") == "/p/foo/bar"
        assert geturl("", "/fooo") == "/p/fooo"
        assert geturl("example.com", "/") == "example.com/p"
        assert geturl("example.com", "/fo") == "example.com/p/fo"
        assert geturl("example.com", "/foo") == "example.com/p/foo"
        assert geturl("example.com", "/foo/") == "example.com/p/foo/"
        assert geturl("example.com", "/foo/bar") == "example.com/p/foo/bar"
        assert geturl("example.com", "/fooo") == "example.com/p/fooo"
        assert geturl("localhost", "/") == "localhost/p"
        assert geturl("localhost", "/fo") == "localhost/p/fo"
        assert geturl("localhost", "/foo") == "localhost/p/foo"
        assert geturl("localhost", "/foo/") == "localhost/p/foo/"
        assert geturl("localhost", "/foo/bar") == "localhost/p/foo/bar"
        assert geturl("localhost", "/fooo") == "localhost/p/fooo"
        assert geturl("localhost:8080", "/") == "localhost:8080/p"
        assert geturl("localhost:8080", "/foo") == "localhost:8080/p/foo"
        assert geturl("localhost:8080", "/foo/bar") == "localhost:8080/p/foo/bar"

    def test_forward_request(self, httpserver):
        httpserver.expect_request("/baz", method="GET").respond_with_data("baz")
        forwarder = UrlMatchingForwarder("/foo", httpserver.url_for("/baz"))

        # not matching
        response = forwarder.forward_request("GET", "/fooo", "", {})
        assert response is True

        response = forwarder.forward_request("GET", "/foo", "", {})
        assert response is not True
        assert response.text == "baz"

        httpserver.expect_request("/baz/bar", method="GET").respond_with_data("baz/bar")
        response = forwarder.forward_request("GET", "/foo/bar", "", {})
        assert response is not True
        assert response.text == "baz/bar"

        httpserver.check()


def test_custom_ssl_cert_path_is_used(monkeypatch):
    monkeypatch.setattr(config, "CUSTOM_SSL_CERT_PATH", "/custom/path/server.cert.pem")
    assert get_cert_pem_file_path() == "/custom/path/server.cert.pem"


@pytest.mark.parametrize(
    "custom_ssl_cert_path_config",
    [None, ""],
)
def test_custom_ssl_cert_path_not_used_if_not_set(monkeypatch, custom_ssl_cert_path_config):
    monkeypatch.setattr(config, "CUSTOM_SSL_CERT_PATH", custom_ssl_cert_path_config)
    # the cache folder can differ for different environments, we only check the suffix
    assert get_cert_pem_file_path().endswith("/cache/server.test.pem")
