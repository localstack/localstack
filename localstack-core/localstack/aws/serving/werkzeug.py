import ssl
from typing import TYPE_CHECKING, Any, Optional, Tuple

from rolo.gateway import Gateway
from rolo.gateway.wsgi import WsgiGateway
from werkzeug import run_simple
from werkzeug.serving import WSGIRequestHandler

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment

from localstack import constants


def serve(
    gateway: Gateway,
    host: str = "localhost",
    port: int = constants.DEFAULT_PORT_EDGE,
    use_reloader: bool = True,
    ssl_creds: Optional[Tuple[Any, Any]] = None,
    **kwargs,
) -> None:
    """
    Serve a Gateway as a WSGI application through werkzeug. This is mostly for development purposes.

    :param gateway: the Gateway to serve
    :param host: the host to expose the server to
    :param port: the port to expose the server to
    :param use_reloader: whether to autoreload the server on changes
    :param kwargs: any other arguments that can be passed to `werkzeug.run_simple`
    """
    kwargs["threaded"] = kwargs.get("threaded", True)  # make sure requests don't block
    kwargs["ssl_context"] = ssl_creds
    kwargs.setdefault("request_handler", CustomWSGIRequestHandler)
    run_simple(host, port, WsgiGateway(gateway), use_reloader=use_reloader, **kwargs)


class CustomWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self) -> "WSGIEnvironment":
        environ = super().make_environ()

        # restore RAW_URI from the requestline will be something like ``GET //foo/?foo=bar%20ed HTTP/1.1``
        environ["RAW_URI"] = " ".join(self.requestline.split(" ")[1:-1])

        # restore raw headers for rolo
        environ["asgi.headers"] = [
            (k.encode("latin-1"), v.encode("latin-1")) for k, v in self.headers.raw_items()
        ]

        # the default WSGIRequestHandler does not understand our DuplexSocket, so it will always set https, which we
        # correct here
        try:
            is_ssl = isinstance(self.request, ssl.SSLSocket)
        except AttributeError:
            is_ssl = False
        environ["wsgi.url_scheme"] = "https" if is_ssl else "http"

        return environ
