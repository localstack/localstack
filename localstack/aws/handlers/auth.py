import logging

from localstack.http import Response

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


class DefaultAccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # TODO: at some point we may want to get the account id from credentials (+ a user repository)
        from localstack import constants

        context.account_id = constants.TEST_AWS_ACCOUNT_ID
