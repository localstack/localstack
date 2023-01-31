import logging

from botocore.utils import InvalidArnException

from localstack.http import Response
from localstack.utils.aws.arns import extract_region_from_arn

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..connect import INTERNAL_REQUEST_PARAMS_HEADER, load_dto

LOG = logging.getLogger(__name__)


class InternalRequestParamsEnricher(Handler):
    """
    This handler sets the internal call DTO in the request context.

    Important: This must be invoked after `RegionContextEnricher` as it may
    override the `region_name`.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if dto := context.request.headers.get(INTERNAL_REQUEST_PARAMS_HEADER):
            context.internal_request_params = load_dto(dto)

            # Attention: region is overridden here
            if target_arn := dto.get("target_arn"):
                try:
                    context.region = extract_region_from_arn(target_arn)
                except InvalidArnException:
                    LOG.warning("Invalid target ARN in internal call DTO")
