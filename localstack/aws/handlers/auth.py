import logging

from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
)
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localstack.http import Response
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header
from localstack.utils.aws.request_context import mock_aws_request_headers

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class MissingAuthHeaderInjector(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # FIXME: this is needed for allowing access to resources via plain URLs where access is typically restricted (
        #  e.g., GET requests on S3 URLs or apigateway routes). this should probably be part of a general IAM middleware
        #  (that allows access to restricted resources by default)
        if not context.service:
            return

        api = context.service.service_name
        headers = context.request.headers

        if not headers.get("Authorization"):
            headers["Authorization"] = mock_aws_request_headers(
                api, aws_access_key_id="injectedaccesskey", region_name=AWS_REGION_US_EAST_1
            )["Authorization"]


class AccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Obtain the access key ID
        access_key_id = (
            extract_access_key_id_from_auth_header(context.request.headers)
            or DEFAULT_AWS_ACCOUNT_ID
        )

        # Obtain the account ID from access key ID
        context.account_id = get_account_id_from_access_key_id(access_key_id)

        # Make Moto use the same Account ID as LocalStack
        context.request.headers.add("x-moto-account-id", context.account_id)
