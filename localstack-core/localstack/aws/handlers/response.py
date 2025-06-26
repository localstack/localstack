import logging

from localstack import config, constants
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)


class ResponseMetadataEnricher(Handler):
    """
    A handler that adds extra metadata to a Response.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Currently, we just add 'x-localstack' in response headers.
        response.headers[constants.HEADER_LOCALSTACK_IDENTIFIER] = "true"


@hooks.on_infra_start(should_load=config.LOCALSTACK_RESPONSE_HEADER_ENABLED)
def init_response_mutation_handler():
    from localstack.aws.handlers import run_custom_response_handlers

    # inject enricher into handler chain
    enricher = ResponseMetadataEnricher()
    run_custom_response_handlers.append(enricher)
