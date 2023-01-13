import logging

from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
    set_aws_access_key_id,
    set_aws_account_id,
)
from localstack.constants import (
    INTERNAL_AWS_ACCESS_KEY_ID,
    INTERNAL_AWS_ACCOUNT_ID,
    TEST_AWS_ACCESS_KEY_ID,
)
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
        # Obtain the access key ID and save it in the thread context
        access_key_id = (
            extract_access_key_id_from_auth_header(context.request.headers)
            or TEST_AWS_ACCESS_KEY_ID
        )
        set_aws_access_key_id(access_key_id)

        # Obtain the account ID and save it in the request context
        if access_key_id == INTERNAL_AWS_ACCESS_KEY_ID:
            # For internal calls, a special account ID is used for request context
            # Cross account calls don't have the same auth flows as user-originating calls
            # which means there is no true Account ID.
            # The invocations of `get_aws_account_id()` used to resolve the stores must not break.
            # We don't use the DEFAULT_AWS_ACCOUNT_ID either to help identify bugs.
            # If correctly implemented with CrossAccountAttribute and ARNs, the provider
            # will work with this internal AWS account ID.
            context.account_id = INTERNAL_AWS_ACCOUNT_ID
        else:
            context.account_id = get_account_id_from_access_key_id(access_key_id)

        # Save the same account ID in the thread context
        set_aws_account_id(context.account_id)

        # Make Moto use the same Account ID as LocalStack
        context.request.headers.add("x-moto-account-id", context.account_id)
