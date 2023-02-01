import logging
import re

from botocore.utils import InvalidArnException

from localstack.constants import AUTH_CREDENTIAL_REGEX
from localstack.http import Response
from localstack.utils.aws.arns import parse_arn

from ..accounts import set_aws_account_id
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

                    context.region = arn_data["region"]

                    context.account_id = arn_data["account"]
                    set_aws_account_id(context.account_id)

                except InvalidArnException:
                    LOG.warning("Invalid target ARN in internal call DTO")

            # Attn: account may get overridden here
            if target_account := dto.get("target_account"):
                # TODO@viren: Validate the account ID here?
                context.account_id = target_account

            # TODO@viren: Good idea to override the Auth header also?
            auth = context.request.headers.get("Authorization")

            context.request.headers["Authorization"] = re.sub(
                AUTH_CREDENTIAL_REGEX,
                rf"Credential={context.account_id}/\2/{context.region}/\4/",
                auth or "",
                flags=re.IGNORECASE,
            )
