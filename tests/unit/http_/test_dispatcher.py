from typing import Any, Dict

import pytest
from werkzeug.exceptions import MethodNotAllowed, NotFound

from localstack.http import Request, Response, Router
from localstack.http.dispatcher import handler_dispatcher, resource_dispatcher


class TestResourceDispatcher:
    def test_dispatch_to_correct_function(self):
        router = Router(dispatcher=resource_dispatcher(pass_response=False))

        requests = []

        class TestResource:
            def on_get(self, req):
                requests.append(req)
                return "GET/OK"

            def on_post(self, req):
                requests.append(req)
                return {"ok": "POST"}

            def on_head(self, req):
                requests.append(req)
                return "HEAD/OK"

        router.add("/_localstack/health", TestResource())

        request1 = Request("GET", "/_localstack/health")
        request2 = Request("POST", "/_localstack/health")
        request3 = Request("HEAD", "/_localstack/health")
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request2).json == {"ok": "POST"}
        assert router.dispatch(request3).get_data(True) == "HEAD/OK"
        assert len(requests) == 4
        assert requests[0] is request1
        assert requests[1] is request1
        assert requests[2] is request2
        assert requests[3] is request3

    def test_dispatch_to_non_existing_method_raises_exception(self):
        router = Router(dispatcher=resource_dispatcher(pass_response=False))

        class TestResource:
            def on_post(self, request):
                return "POST/OK"

        router.add("/_localstack/health", TestResource())

        with pytest.raises(MethodNotAllowed):
            assert router.dispatch(Request("GET", "/_localstack/health"))
        assert router.dispatch(Request("POST", "/_localstack/health")).get_data(True) == "POST/OK"

    def test_dispatcher_with_pass_response(self):
        router = Router(dispatcher=resource_dispatcher(pass_response=True))

        class TestResource:
            def on_get(self, req, resp: Response):
                resp.set_json({"message": "GET/OK"})

            def on_post(self, req, resp):
                resp.set_data("POST/OK")

        router.add("/_localstack/health", TestResource())
        assert router.dispatch(Request("GET", "/_localstack/health")).json == {"message": "GET/OK"}
        assert router.dispatch(Request("POST", "/_localstack/health")).get_data(True) == "POST/OK"


class TestHandlerDispatcher:
    def test_handler_dispatcher(self):
        router = Router(dispatcher=handler_dispatcher())

        def handler_foo(_request: Request) -> Response:
            return Response("ok")

        def handler_bar(_request: Request, bar, baz) -> Dict[str, any]:
            response = Response()
            response.set_json({"bar": bar, "baz": baz})
            return response

        router.add("/foo", handler_foo)
        router.add("/bar/<int:bar>/<baz>", handler_bar)

        assert router.dispatch(Request("GET", "/foo")).data == b"ok"
        assert router.dispatch(Request("GET", "/bar/420/ed")).json == {"bar": 420, "baz": "ed"}

        with pytest.raises(NotFound):
            assert router.dispatch(Request("GET", "/bar/asfg/ed"))

    def test_handler_dispatcher_invalid_signature(self):
        router = Router(dispatcher=handler_dispatcher())

        def handler(_request: Request, arg1) -> Response:  # invalid signature
            return Response("ok")

        router.add("/foo/<arg1>/<arg2>", handler)

        with pytest.raises(TypeError):
            router.dispatch(Request("GET", "/foo/a/b"))

    def test_handler_dispatcher_with_dict_return(self):
        router = Router(dispatcher=handler_dispatcher())

        def handler(_request: Request, arg1) -> Dict[str, Any]:
            return {"arg1": arg1, "hello": "there"}

        router.add("/foo/<arg1>", handler)
        assert router.dispatch(Request("GET", "/foo/a")).json == {"arg1": "a", "hello": "there"}

    def test_handler_dispatcher_with_text_return(self):
        router = Router(dispatcher=handler_dispatcher())

        def handler(_request: Request, arg1) -> str:
            return f"hello: {arg1}"

        router.add("/<arg1>", handler)
        assert router.dispatch(Request("GET", "/world")).data == b"hello: world"

    def test_handler_dispatcher_with_none_return(self):
        router = Router(dispatcher=handler_dispatcher())

        def handler(_request: Request):
            return None

        router.add("/", handler)
        assert router.dispatch(Request("GET", "/")).status_code == 200
