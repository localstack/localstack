from werkzeug import run_simple

from ..gateway import Gateway
from .wsgi import WsgiGateway


def serve(gateway: Gateway, host="localhost", port=4566, use_reloader=True, **kwargs) -> None:
    """
    Serve a Gateway as a WSGI application through werkzeug. This is mostly for development purposes.

    :param gateway: the Gateway to serve
    :param host: the host to expose the server to
    :param port: the port to expose the server to
    :param use_reloader: whether to autoreload the server on changes
    :param kwargs: any other arguments that can be passed to `werkzeug.run_simple`
    """
    kwargs["threaded"] = kwargs.get("threaded", True)  # make sure requests don't block
    run_simple(host, port, WsgiGateway(gateway), use_reloader=use_reloader, **kwargs)
