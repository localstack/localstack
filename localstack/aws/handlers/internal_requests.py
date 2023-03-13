import logging
from types import MappingProxyType

from localstack.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..connect import INTERNAL_REQUEST_PARAMS_HEADER, load_dto

LOG = logging.getLogger(__name__)


class InternalRequestParamsEnricher(Handler):
    """
    This handler sets the internal call DTO in the request context.

    Important: This must be invoked after account and region enrichers because
    it may override them.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if header := context.request.headers.get(INTERNAL_REQUEST_PARAMS_HEADER):
            try:
                dto = MappingProxyType(load_dto(header))
            except Exception as e:
                LOG.error("Error loading request parameters '%s', Error: %s", header, e)
                return

            context.internal_request_params = dto
