import logging

from botocore.utils import InvalidArnException

from localstack.http import Response
from localstack.utils.aws.arns import parse_arn

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
            dto = load_dto(header)

            context.internal_request_params = dto

            # Attention: account and region may get overridden here
            if target_arn := dto.get("target_arn"):
                try:
                    arn_data = parse_arn(target_arn)
                    context.account_id = arn_data["account"]
                    context.region = arn_data["region"]
                except InvalidArnException:
                    LOG.warning("Invalid target ARN in internal call DTO")
