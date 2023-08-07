import logging

from localstack.http import Request, Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class CnameHostHeaderInjector(Handler):
    """
    This handler injects a `Host` header if the request host is a CNAME in Route53.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        context.region = self.get_region(context.request)

    @staticmethod
    def get_region(request: Request) -> str:
        from localstack.utils.aws.request_context import extract_region_from_headers

        return extract_region_from_headers(request.headers)
