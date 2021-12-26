import pytest
import requests

from localstack.services.routing import (
    Request,
    ResourceRouter,
    ResourceRouterProxyListener,
    RoutingRule,
)
from localstack.utils.testutil import proxy_server


class TestRoutingRule:
    def test_matches_strict(self):
        rule = RoutingRule("/foo/bar")

        assert rule.matches(Request("GET", "/foo/bar", b"", {}))
        assert rule.matches(Request("GET", "/foo/bar/", b"", {}))
        assert rule.matches(Request("POST", "/foo/bar", b"", {}))

        assert not rule.matches(Request("GET", "/foo/ba", b"", {}))
        assert not rule.matches(Request("GET", "/foo/bare", b"", {}))
        assert not rule.matches(Request("GET", "/foo/bar/ed", b"", {}))
        assert not rule.matches(Request("GET", "/foo", b"", {}))

    def test_matches_with_query(self):
        rule = RoutingRule("/foo/bar")

        assert rule.matches(Request("GET", "/foo/bar?", b"", {}))
        assert rule.matches(Request("GET", "/foo/bar?help", b"", {}))
        assert rule.matches(Request("GET", "/foo/bar?help=me&ok", b"", {}))

    def test_matches_with_host(self):
        rule = RoutingRule("http://localhost:4566/foo/bar", match_host=True)

        assert rule.matches(Request("GET", "/foo/bar", b"", {"Host": "localhost:4566"}))
        assert not rule.matches(Request("GET", "/foo/bar", b"", {"Host": "localhost"}))
        assert not rule.matches(Request("GET", "/foo/bar", b"", {"Host": "example.com"}))
        assert not rule.matches(Request("GET", "/foo/bar", b"", {}))

    def test_matches_with_host_no_pattern_errors(self):
        rule = RoutingRule("/foo/bar", match_host=True)

        with pytest.raises(ValueError):
            rule.matches(Request("GET", "/foo/bar", b"", {}))


class TestResourceRouter:
    def test_dispatch_returns_no_route(self):
        router = ResourceRouter()
        assert router.dispatch(Request("GET", "/health", b"", {})) == ResourceRouter.NO_ROUTE

    def test_dispatch_to_correct_function(self):
        requests = []

        class TestResource:
            def on_get(self, req):
                requests.append(req)
                return "GET/OK"

            def on_post(self, req):
                requests.append(req)
                return "POST/OK"

        router = ResourceRouter()
        router.add_route("/health", TestResource())

        request = Request("GET", "/health", b"", {})
        assert router.dispatch(request) == "GET/OK"
        assert router.dispatch(request) == "GET/OK"
        assert len(requests) == 2
        assert requests[0] is request
        assert requests[1] is request

    def test_dispatch_with_suffix(self):
        class TestResource:
            def on_get_first(self, req):
                return "GET/OK"

            def on_post(self, req):
                return "POST/NOK"

            def on_post_second(self, req):
                return "POST/OK"

        router = ResourceRouter()
        resource = TestResource()
        router.add_route("/health/first", resource, suffix="first")
        router.add_route("/health/second", resource, suffix="second")

        assert router.dispatch(Request("GET", "/health/first", b"", {})) == "GET/OK"
        assert router.dispatch(Request("POST", "/health/first", b"", {})) == ResourceRouter.NO_ROUTE

        assert router.dispatch(Request("GET", "/health/second", b"", {})) == ResourceRouter.NO_ROUTE
        assert router.dispatch(Request("POST", "/health/second", b"", {})) == "POST/OK"

    def test_dispatch_to_non_existing_function_returns_no_route(self):
        class TestResource:
            def on_post(self, request):
                return "POST/OK"

        router = ResourceRouter()
        router.add_route("/health", TestResource())

        assert router.dispatch(Request("GET", "/health", b"", {})) == ResourceRouter.NO_ROUTE
        assert router.dispatch(Request("POST", "/health", b"", {})) == "POST/OK"


class TestResourceRouterProxyListener:
    def test_with_server(self):
        class TestResource:
            def on_get(self, request):
                return {"status": "ok"}

        router = ResourceRouter()
        router.add_route("/foo/bar", TestResource())

        with proxy_server(ResourceRouterProxyListener(router)) as url:
            response = requests.get(f"{url}/foo/bar")
            assert response.ok
            assert response.json() == {"status": "ok"}

            # test with query
            response = requests.get(f"{url}/foo/bar?hello=there")
            assert response.ok
            assert response.json() == {"status": "ok"}

            response = requests.get(f"{url}/foo")
            assert not response.ok
            assert response.status_code == 404

            response = requests.post(f"{url}/foo/bar")
            assert not response.ok
            assert response.status_code == 404
