"""Handlers for logging."""
import logging

from localstack.aws.api import RequestContext, ServiceException
from localstack.aws.chain import ExceptionHandler, HandlerChain
from localstack.http import Response

LOG = logging.getLogger(__name__)


class ExceptionLogger(ExceptionHandler):
    """
    Logs exceptions into a logger.
    """

    def __init__(self, logger=None):
        self.logger = logger or LOG

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: Response,
    ):
        if isinstance(exception, ServiceException):
            # We do not want to log an error/stacktrace if the handler is working as expected, but chooses to throw
            # a service exception
            return
        if self.logger.isEnabledFor(level=logging.DEBUG):
            self.logger.exception("exception during call chain", exc_info=exception)
        else:
            self.logger.error("exception during call chain: %s", exception)


class ResponseLogger:
    def __call__(self, _: HandlerChain, context: RequestContext, response: Response):
        if context.operation:
            LOG.info(
                "%s %s.%s => %d",
                context.request.method,
                context.service.service_name,
                context.operation.name,
                response.status_code,
            )
        else:
            LOG.info(
                "%s %s => %d",
                context.request.method,
                context.request.path,
                response.status_code,
            )
