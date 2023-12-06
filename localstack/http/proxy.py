from io import BytesIO
from typing import Mapping, Union
from urllib.parse import urlparse

from werkzeug import Request, Response
from werkzeug.datastructures import Headers
from werkzeug.test import EnvironBuilder

from .client import HttpClient, SimpleRequestsClient
from .request import get_raw_path, restore_payload, set_environment_headers


def forward(
    request: Request,
    forward_base_url: str,
    forward_path: str = None,
    headers: Union[Headers, Mapping[str, str]] = None,
) -> Response:
    """
    Convenience method that creates a new Proxy and immediately calls proxy.forward(...). See ``Proxy`` for more
    information.
    """
    with Proxy(forward_base_url=forward_base_url) as proxy:
        return proxy.forward(request, forward_path=forward_path, headers=headers)


class Proxy(HttpClient):
    preserve_host: bool

    def __init__(
        self, forward_base_url: str, client: HttpClient = None, preserve_host: bool = True
    ):
        """
        Creates a new HTTP Proxy which can be used to forward incoming requests according to the configuration.

        :param forward_base_url: the base url (backend) to forward the requests to.
        :param client: the HTTP Client used to make the requests
        :param preserve_host: True to ensure that the Host header of the incoming request is preserved.
                              If False, then the Host header will be set to the Host from the perspective of the Proxy.
        """
        self.forward_base_url = forward_base_url
        self.client = client or SimpleRequestsClient()
        self.preserve_host = preserve_host

    def request(self, request: Request, server: str | None = None) -> Response:
        """
        Compatibility with HttpClient interface. A call is equivalent to ``Proxy.forward(request, None, None)``.

        :param request: the request to proxy
        :param server: ignored for a proxy, since the server is already set by `forward_base_url`.
        :return: the proxied response
        """
        return self.forward(request)

    def forward(
        self,
        request: Request,
        forward_path: str = None,
        headers: Union[Headers, Mapping[str, str]] = None,
    ) -> Response:
        """
        Uses the client to forward the given request according to the proxy's configuration.

        :param request: the base request to forward (with the original URL and path data)
        :param forward_path: the path to forward the request to. if set, the original path will be replaced completely,
            otherwise the original path will be used
        :param headers: additional custom headers to send as part of the proxy request
        :return: the proxied response
        """
        headers = Headers(headers) if headers else Headers()

        if client_ip := request.remote_addr:
            if xff := request.headers.get("X-Forwarded-For"):
                headers["X-Forwarded-For"] = f"{xff}, {client_ip}"
            else:
                headers["X-Forwarded-For"] = f"{client_ip}"

        if forward_path is None:
            forward_path = get_raw_path(request)
        if forward_path:
            forward_path = "/" + forward_path.lstrip("/")

        proxy_request = _copy_request(request, self.forward_base_url, forward_path, headers)

        if self.preserve_host and "Host" in request.headers:
            proxy_request.headers["Host"] = request.headers["Host"]

        target = urlparse(self.forward_base_url)
        return self.client.request(proxy_request, server=f"{target.scheme}://{target.netloc}")

    def close(self):
        self.client.close()


class ProxyHandler:
    """
    A dispatcher Handler which can be used in a ``Router[Handler]`` that proxies incoming requests according to the
    configuration.

    The Handler is expected to be used together with a route that uses a ``path`` parameter named ``path`` in the URL.
    Fir example: if you want to forward all requests from ``/foobar/<path>`` to ``http://localhost:8080/v1/<path>``,
    you would do the following::

        router = Router(dispatcher=handler_dispatcher())
        router.add("/foobar/<path:path>", ProxyHandler("http://localhost:8080/v1")

    This is similar to the common nginx configuration where proxy_pass is a URI::

        location /foobar {
            proxy_pass http://localhost:8080/v1/;
        }
    """

    def __init__(self, forward_base_url: str, client: HttpClient = None):
        """
        Creates a new Proxy with the given ``forward_base_url`` (see ``Proxy``).

        :param forward_base_url: the base url (backend) to forward the requests to.
        :param client: the HTTP Client used to make the requests
        """
        self.proxy = Proxy(forward_base_url=forward_base_url, client=client)

    def __call__(self, request: Request, **kwargs) -> Response:
        return self.proxy.forward(request, forward_path=kwargs.get("path", ""))

    def close(self):
        self.proxy.close()


def _copy_request(
    request: Request,
    base_url: str = None,
    path: str = None,
    headers: Union[Headers, Mapping[str, str]] = None,
) -> Request:
    """
    Creates a new request from the given one that can be used to perform a proxy call.

    :param request: the original request
    :param base_url: the url to forward the request to (e.g., http://localhost:8080)
    :param path: the path to forward the request to (e.g., /foobar), if set to None, the original path will be used
    :param headers: optional headers to overwrite
    :return: a new request with slightly modified underlying environment but the same data stream
    """
    # ensure that the headers in the env are set on the environment
    # FIXME: we should preserve header casing like we do with the `asgi.headers` property in the  asgi/wsgi bridge to
    #  pass through the raw headers.
    set_environment_headers(request.environ, request.headers)
    builder = EnvironBuilder.from_environ(request.environ)

    if base_url:
        builder.base_url = base_url
        builder.headers["Host"] = builder.host

    if path is not None:
        builder.path = path

    if headers:
        builder.headers.update(headers)

    # FIXME: unfortunately, EnvironBuilder expects the input stream to be seekable, but we don't have that when using
    #  the asgi/wsgi bridge. we need a better way of dealing with IO!
    data = restore_payload(request)
    builder.input_stream = BytesIO(data)
    builder.content_length = len(data)
    # Since the payload is completely restored, the proxy forwarding is not streamed.
    # Therefore, we need to remove a potential "chunked" Transfer-Encoding
    if builder.headers.get("Transfer-Encoding", None) == "chunked":
        builder.headers.pop("Transfer-Encoding")

    new_request = builder.get_request()

    # explicitly set the path in the environment and in the newly created request
    if path is not None:
        new_request.environ["RAW_URI"] = path or "/"

    # copy headers s.t. they are no longer immutable (by default, EnvironHeaders are used)
    new_request.headers = Headers(new_request.headers)

    return new_request
