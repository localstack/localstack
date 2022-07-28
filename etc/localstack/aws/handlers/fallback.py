"""Handlers for fallback logic, e.g., populating empty requests or defauling with default exceptions."""
import logging

from werkzeug.datastructures import Headers

from localstack.http import Response

from ..api import RequestContext
from ..chain import ExceptionHandler, Handler, HandlerChain

LOG = logging.getLogger(__name__)


class InternalFailureHandler(ExceptionHandler):
    """
    Exception handler that returns a generic error message if there was an exception and there is no response set yet.
    """

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: Response,
    ):
        if response.data:
            # response already set
            return

        LOG.debug("setting internal failure response for %s", exception)
        response.status_code = 500
        response.set_json(
            {
                "message": "Unexpected exception",
                "error": str(exception),
                "type": str(exception.__class__.__name__),
            }
        )


class EmptyResponseHandler(Handler):
    """
    Handler that creates a default response if the response in the context is empty.
    """

    status_code: int
    body: bytes
    headers: dict

    def __init__(self, status_code=404, body=None, headers=None):
        self.status_code = status_code
        self.body = body or b""
        self.headers = headers or Headers()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if self.is_empty_response(response):
            self.populate_default_response(response)

    def is_empty_response(self, response: Response):
        return response.status_code in [0, None] and not response.response

    def populate_default_response(self, response: Response):
        response.status_code = self.status_code
        response.data = self.body
        response.headers.update(self.headers)
