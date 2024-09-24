from typing import Any, Dict

import pytest
from werkzeug.exceptions import NotFound

from localstack.http import Request, Response, Router
from localstack.http.dispatcher import handler_dispatcher


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
