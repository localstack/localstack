from localstack.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..connect import INTERNAL_REQUEST_PARAMS_HEADER, load_dto


class InternalRequestParamEnricher(Handler):
    """
    This handler sets the internal call DTO in the request context.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if dto := context.request.headers.get(INTERNAL_REQUEST_PARAMS_HEADER):
            context.internal_request_params = load_dto(dto)
