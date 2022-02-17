import requests

from localstack.http import Response, Router
from localstack.http.adapters import RouterListener
from localstack.utils.testutil import proxy_server


class TestRouterListener:
    def test_dispatching(self):
        def endpoint(request, args):
            resp = Response()
            resp.set_json({"args": args})
            return resp

        router = Router()
        router.add("/foo/<bar>", endpoint, methods=["GET"])

        with proxy_server(RouterListener(router, fall_through=False)) as url:
            response = requests.get(f"{url}/foo/ed")
            assert response.ok
            assert response.json() == {"args": {"bar": "ed"}}

            # test with query
            response = requests.get(f"{url}/foo/bar?hello=there")
            assert response.ok
            assert response.json() == {"args": {"bar": "bar"}}

            # test invalid endpoint
            response = requests.get(f"{url}/foo")
            assert not response.ok
            assert response.status_code == 404

            # test non-allowed method
            response = requests.post(f"{url}/foo/bar")
            assert not response.ok
            assert response.status_code == 405  # method not allowed
