"""Handlers for fallback logic, e.g., populating empty requests or defauling with default exceptions."""

import logging

from rolo.gateway.handlers import EmptyResponseHandler
from werkzeug.exceptions import HTTPException

from localstack.http import Response

from ..api import RequestContext
from ..chain import ExceptionHandler, HandlerChain

__all__ = ["EmptyResponseHandler", "InternalFailureHandler"]

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

        if isinstance(exception, HTTPException):
            response.status_code = exception.code
            response.headers.update(exception.get_headers())
            response.set_json({"error": exception.name, "message": exception.description})
            return

        LOG.debug("setting internal failure response for %s", exception)
        response.status_code = 500
        response.set_json(
            {
                "error": "Unexpected exception",
                "message": str(exception),
                "type": str(exception.__class__.__name__),
            }
        )
