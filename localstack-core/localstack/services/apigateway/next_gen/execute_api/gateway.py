from rolo import Response
from rolo.gateway import Gateway

from . import handlers
from .context import RestApiInvocationContext


class RestApiGateway(Gateway):
    def __init__(self):
        super().__init__(context_class=RestApiInvocationContext)
        self.request_handlers.extend(
            [
                handlers.preprocess_request,
                handlers.method_request_handler,
                handlers.integration_request_handler,
                handlers.integration_handler,
                # temporary handler which executes everything for now
                handlers.global_temporary_handler,
            ]
        )
        self.response_handlers.extend(
            [
                handlers.integration_response_handler,
                handlers.method_response_handler,
                # add composite response handlers?
            ]
        )
        # TODO: we need the exception handler instead of serializing them
        self.exception_handlers.extend([])

    def process_with_context(self, context: RestApiInvocationContext, response: Response):
        chain = self.new_chain()
        chain.handle(context, response)
