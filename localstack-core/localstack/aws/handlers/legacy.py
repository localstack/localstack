"""Handlers for compatibility with legacy thread local storages."""

import logging

from localstack import config
from localstack.http import Response

from ..api import RequestContext
from ..chain import HandlerChain
from .routes import RouterHandler

LOG = logging.getLogger(__name__)


def set_close_connection_header(_chain: HandlerChain, context: RequestContext, response: Response):
    """This is a hack to work around performance issues with h11 and boto. See
    https://github.com/localstack/localstack/issues/6557"""
    if config.GATEWAY_SERVER != "hypercorn":
        return
    if conn := context.request.headers.get("Connection"):
        if conn.lower() == "keep-alive":
            # don't set Connection: close header if keep-alive is explicitly asked for
            return

    if "Connection" not in response.headers:
        response.headers["Connection"] = "close"


class EdgeRouterHandler(RouterHandler):
    def __init__(self, respond_not_found=False) -> None:
        from localstack.services.edge import ROUTER

        super().__init__(ROUTER, respond_not_found)
