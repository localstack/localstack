import pytest
from werkzeug.exceptions import MethodNotAllowed

from localstack.http import Request, Response, Router
from localstack.http.dispatcher import resource_dispatcher


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

        router.add("/health", TestResource())

        request1 = Request("GET", "/health")
        request2 = Request("POST", "/health")
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request2).json == {"ok": "POST"}
        assert len(requests) == 3
        assert requests[0] is request1
        assert requests[1] is request1
        assert requests[2] is request2

    def test_dispatch_to_non_existing_method_raises_exception(self):
        router = Router(dispatcher=resource_dispatcher(pass_response=False))

        class TestResource:
            def on_post(self, request):
                return "POST/OK"

        router.add("/health", TestResource())

        with pytest.raises(MethodNotAllowed):
            assert router.dispatch(Request("GET", "/health"))
        assert router.dispatch(Request("POST", "/health")).get_data(True) == "POST/OK"

    def test_dispatcher_with_pass_response(self):
        router = Router(dispatcher=resource_dispatcher(pass_response=True))

        class TestResource:
            def on_get(self, req, resp: Response):
                resp.set_json({"message": "GET/OK"})

            def on_post(self, req, resp):
                resp.set_data("POST/OK")

        router.add("/health", TestResource())
        assert router.dispatch(Request("GET", "/health")).json == {"message": "GET/OK"}
        assert router.dispatch(Request("POST", "/health")).get_data(True) == "POST/OK"
