import threading
from typing import List, Tuple

import pytest
import requests
import werkzeug
from werkzeug.exceptions import NotFound

from localstack.http import Request, Response, Router
from localstack.http.router import E, RequestArguments
from localstack.utils.common import get_free_tcp_port


def noop(*args, **kwargs):
    """Test dispatcher that does nothing"""
    return Response()


class RequestCollector:
    """Test dispatcher that collects requests into a list"""

    requests: List[Tuple[Request, E, RequestArguments]]

    def __init__(self) -> None:
        super().__init__()
        self.requests = []

    def __call__(self, request: Request, endpoint: E, args: RequestArguments) -> Response:
        self.requests.append((request, endpoint, args))
        return Response()


class TestRouter:
    # these are sanity check for the router and dispatching logic. since the matching is done by werkzeug's Map,
    # there is no need for thorough testing URL matching.

    def test_dispatch_raises_not_found(self):
        router = Router()
        router.add("/foobar", noop)
        with pytest.raises(NotFound):
            assert router.dispatch(Request("GET", "/foo"))

    def test_default_dispatcher_invokes_correct_endpoint(self):
        router = Router()

        def index(_: Request, args) -> Response:
            response = Response()
            response.set_json(args)
            return response

        def users(_: Request, args) -> Response:
            response = Response()
            response.set_json(args)
            return response

        router.add("/", index)
        router.add("/users/<int:user_id>", users)

        assert router.dispatch(Request("GET", "/")).json == {}
        assert router.dispatch(Request("GET", "/users/12")).json == {"user_id": 12}

    def test_dispatch_with_host_matching(self):
        router = Router()

        def ep_all(_: Request, args) -> Response:
            response = Response()
            response.set_json(dict(method="all", **args))
            return response

        def ep_index1(_: Request, args) -> Response:
            response = Response()
            response.set_json(dict(method="1", **args))
            return response

        def ep_index2(_: Request, args) -> Response:
            response = Response()
            response.set_json(dict(method="2", **args))
            return response

        router.add("/", ep_index1, host="localhost:<port>")
        router.add("/", ep_index2, host="localhost:12345")
        router.add("/all", ep_all, host="<host>")

        def invoke(path, server, port):
            return router.dispatch(Request("GET", path, server=(server, port))).json

        assert invoke("/", "localhost", 4566) == {"method": "1", "port": "4566"}
        assert invoke("/", "localhost", 12345) == {"method": "2"}
        assert invoke("/all", "127.0.0.1", None) == {"method": "all", "host": "127.0.0.1"}
        assert invoke("/all", "127.0.0.1", 12345) == {"method": "all", "host": "127.0.0.1:12345"}

        with pytest.raises(NotFound):
            invoke("/", "localstack.cloud", None)

    def test_custom_dispatcher(self):
        collector = RequestCollector()
        router = Router(dispatcher=collector)

        router.add("/", "index")
        router.add("/users/<int:id>", "users")

        router.dispatch(Request("GET", "/"))
        router.dispatch(Request("GET", "/users/12"))

        _, endpoint, args = collector.requests[0]
        assert endpoint == "index"
        assert args == {}

        _, endpoint, args = collector.requests[1]
        assert endpoint == "users"
        assert args == {"id": 12}

    def test_remove_rule(self):
        router = Router()

        def index(_: Request, args) -> Response:
            return Response(b"index")

        def users(_: Request, args) -> Response:
            return Response(b"users")

        rule0 = router.add("/", index)
        rule1 = router.add("/users/<int:user_id>", users)

        assert router.dispatch(Request("GET", "/")).data == b"index"
        assert router.dispatch(Request("GET", "/users/12")).data == b"users"

        router.remove_rule(rule1)

        assert router.dispatch(Request("GET", "/")).data == b"index"
        with pytest.raises(NotFound):
            assert router.dispatch(Request("GET", "/users/12"))

        router.remove_rule(rule0)
        with pytest.raises(NotFound):
            assert router.dispatch(Request("GET", "/"))
        with pytest.raises(NotFound):
            assert router.dispatch(Request("GET", "/users/12"))


class TestWsgiIntegration:
    def test_with_werkzeug(self):
        # setup up router
        router = Router()

        def index(_: Request, args) -> Response:
            return Response(b"index")

        def echo_json(request: Request, args) -> Response:
            response = Response()
            response.set_json(request.json)
            return response

        def users(_: Request, args) -> Response:
            response = Response()
            response.set_json(args)
            return response

        router.add("/", index)
        router.add("/users/<int:user_id>", users, host="<host>:<port>")
        router.add("/echo/", echo_json, methods=["POST"])

        # serve router through werkzeug
        @werkzeug.Request.application
        def app(request: werkzeug.Request) -> werkzeug.Response:
            return router.dispatch(request)

        host = "localhost"
        port = get_free_tcp_port()
        url = f"http://{host}:{port}"

        server = werkzeug.serving.make_server(host, port, app=app, threaded=True)
        t = threading.Thread(target=server.serve_forever)
        t.start()

        try:
            resp = requests.get(f"{url}/")
            assert resp.ok
            assert resp.content == b"index"

            resp = requests.get(f"{url}/users/123")
            assert resp.ok
            assert resp.json() == {"user_id": 123, "host": host, "port": str(port)}

            resp = requests.get(f"{url}/users")
            assert not resp.ok

            resp = requests.post(f"{url}/echo", json={"foo": "bar", "a": 420})
            assert resp.ok
            assert resp.json() == {"foo": "bar", "a": 420}
        finally:
            server.shutdown()
            t.join(timeout=10)
