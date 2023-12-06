import logging

from werkzeug.exceptions import NotFound

from localstack.http import Response, Router

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class RouterHandler(Handler):
    """
    Adapter to serve a Router as a Handler.
    """

    router: Router
    respond_not_found: bool

    def __init__(self, router: Router, respond_not_found: bool = False) -> None:
        self.router = router
        self.respond_not_found = respond_not_found

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        try:
            router_response = self.router.dispatch(context.request)
            response.update_from(router_response)
            chain.stop()
        except NotFound:
            if self.respond_not_found:
                chain.respond(404, "not found")
