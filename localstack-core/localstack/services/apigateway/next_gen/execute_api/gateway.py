from rolo import Response
from rolo.gateway import Gateway

from . import handlers
from .context import RestApiInvocationContext


class RestApiGateway(Gateway):
    """
    This class controls the main path of an API Gateway REST API. It contains the definitions of the different handlers
    to be called as part of the different steps of the invocation of the API.

    For now, you can extend the behavior of the invocation by adding handlers to the `preprocess_request`
    CompositeHandler.
    The documentation of this class will be extended as more behavior will be added to its handlers, as well as more
    ways to extend it.
    """

    def __init__(self):
        super().__init__(context_class=RestApiInvocationContext)
        self.request_handlers.extend(
            [
                handlers.parse_request,
                handlers.route_request,
                handlers.preprocess_request,
                handlers.method_request_handler,
                handlers.integration_request_handler,
                handlers.integration_handler,
                # temporary legacy which executes the legacy logic for now
                handlers.legacy_handler,
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
