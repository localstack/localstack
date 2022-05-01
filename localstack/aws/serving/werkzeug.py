from werkzeug import run_simple

from ..gateway import Gateway
from .wsgi import WsgiGateway


def serve(gateway: Gateway, host="localhost", port=4566, use_reloader=True, **kwargs):
    kwargs["threaded"] = kwargs.get("threaded", True)  # make sure requests don't block
    run_simple(host, port, WsgiGateway(gateway), use_reloader=use_reloader, **kwargs)
