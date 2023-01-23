from localstack.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..connect import LOCALSTACK_DATA_HEADER, load_dto


class DataEnricher(Handler):
    """
    This handler sets the internal call DTO in the request context.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if dto := context.request.headers.get(LOCALSTACK_DATA_HEADER):
            context.data = load_dto(dto)
