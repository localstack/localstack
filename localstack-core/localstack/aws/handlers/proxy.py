from ...http import Response
from ...http.proxy import Proxy
from ..api import RequestContext
from ..chain import Handler, HandlerChain


class ProxyHandler(Handler):
    """
    Directly serves a localstack.http.proxy.Proxy as a HandlerChain Handler.
    This handler does not command the handler chain to stop or terminate.
    """

    proxy: Proxy

    def __init__(self, forward_base_url: str) -> None:
        self.proxy = Proxy(forward_base_url)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        proxy_response = self.proxy.forward(context.request)
        response.update_from(proxy_response)
