import logging

from localstack.aws.accounts import get_account_id_from_access_key_id, set_ctx_aws_access_key_id
from localstack.constants import HEADER_LOCALSTACK_ACCOUNT_ID, TEST_AWS_ACCESS_KEY_ID
from localstack.http import Response
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header

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
        from localstack.utils.aws import aws_stack

        api = context.service.service_name
        headers = context.request.headers

        if not headers.get("Authorization"):
            headers["Authorization"] = aws_stack.mock_aws_request_headers(api)["Authorization"]


class AccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)

        if not access_key_id:
            access_key_id = TEST_AWS_ACCESS_KEY_ID

        # Save the request access key ID in the current thread local storage
        set_ctx_aws_access_key_id(access_key_id)

        if account_id_from_header := context.request.headers.get(HEADER_LOCALSTACK_ACCOUNT_ID):
            context.account_id = account_id_from_header
        else:
            context.account_id = get_account_id_from_access_key_id(access_key_id)
