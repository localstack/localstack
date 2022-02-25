"""Adapters and other utilities to use the HTTP framework together with the edge proxy. These tools facilitate the
migration from the edge proxy to the new HTTP framework, and will be removed in the future. """
from urllib.parse import urlsplit

from requests.models import Response as _RequestsResponse
from werkzeug.exceptions import NotFound

from localstack.services.generic_proxy import ProxyListener

from .request import Request
from .response import Response
from .router import Router


class ProxyListenerAdapter(ProxyListener):
    """
    A simple API adapter between 1) the edge proxy that uses the ``forward_request(method, path, data, headers)`` API
    to pass HTTP requests, and 2) the new HTTP framework, which uses werkzeug's ``Request`` and ``Response`` objects.
    """

    def request(self, request: Request) -> Response:
        raise NotImplementedError

    def forward_request(self, method, path, data, headers):
        split_url = urlsplit(path)
        request = Request(
            method=method,
            path=split_url.path,
            query_string=split_url.query,
            headers=headers,
            body=data,
        )

        response = self.request(request)

        return self.to_proxy_response(response)

    def to_proxy_response(self, response: Response):
        resp = _RequestsResponse()
        resp._content = response.get_data()
        resp.status_code = response.status_code
        resp.headers.update(response.headers)
        return resp


class RouterListener(ProxyListenerAdapter):
    """
    Serve a Router through an edge ProxyListener.
    """

    router: Router

    def __init__(self, router: Router, fall_through: bool = True):
        self.router = router
        self.fall_through = fall_through

    def forward_request(self, method, path, data, headers):
        try:
            return super().forward_request(method, path, data, headers)
        except NotFound:
            if self.fall_through:
                return True
            else:
                raise

    def request(self, request: Request) -> Response:
        return self.router.dispatch(request)
