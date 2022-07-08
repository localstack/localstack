"""Handlers for logging."""
import logging

from localstack import config, constants
from localstack.aws.api import RequestContext, ServiceException
from localstack.aws.chain import ExceptionHandler, HandlerChain
from localstack.http import Response
from localstack.http.request import restore_payload
from localstack.utils.aws.aws_stack import is_internal_call_context

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
    def __init__(self, logger=None):
        self.logger = logger or LOG

    def __call__(self, _: HandlerChain, context: RequestContext, response: Response):
        if context.request.path == "/health":
            # special case so the health check doesn't spam the logs
            return

        # TODO: maybe it would be better to add an additional flag "LOG_INTERNAL_CALLS" instead of encoding it into
        #  the log level.
        is_internal_call = is_internal_call_context(context.request.headers)
        is_tracing_enabled = config.is_trace_logging_enabled()

        if is_internal_call:
            if not is_tracing_enabled:
                # only log internal calls when tracing is enabled
                return

            if config.LS_LOG == constants.LS_LOG_TRACE_INTERNAL:
                # trace internal calls only with "trace-internal"
                self._log_trace(context, response)
                return

            self._log_call(context, response)
            return

        if is_tracing_enabled:
            self._log_trace(context, response)
            return

        self._log_call(context, response)

    def _log_trace(self, context: RequestContext, response: Response):
        if context.operation:
            # log an AWS response
            if context.service_exception:
                self.logger.info(
                    "AWS %s.%s => %d (%s); %s(%s, headers=%s); %s('%s', headers=%s)",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                    context.service_exception.code,
                    # request
                    context.operation.input_shape.name
                    if context.operation.input_shape
                    else "Request",
                    context.service_request,
                    dict(context.request.headers),
                    # response
                    context.service_exception.code,
                    context.service_exception.message,
                    dict(response.headers),
                )
            else:
                self.logger.info(
                    "AWS %s.%s => %s; %s(%s, headers=%s); %s(%s, headers=%s)",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                    # request
                    context.operation.input_shape.name
                    if context.operation.input_shape
                    else "Request",
                    context.service_request,
                    dict(context.request.headers),
                    # response
                    context.operation.output_shape.name
                    if context.operation.output_shape
                    else "Response",
                    context.service_response,
                    dict(response.headers),
                )
        else:
            # log any other HTTP response
            msg = (
                "%s %s => %d\n"
                "--- HTTP REQUEST  ----------------------------\n%s%s\n"
                "--- HTTP RESPONSE ----------------------------\n%s%s"
            )
            self.logger.info(
                msg,
                context.request.method,
                context.request.path,
                response.status_code,
                context.request.headers,
                restore_payload(context.request),
                response.headers,
                response.data,
            )

        pass

    def _log_call(self, context: RequestContext, response: Response):
        if context.operation:
            # log an AWS response
            if context.service_exception:
                self.logger.info(
                    "AWS %s.%s => %d (%s)",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                    context.service_exception.code,
                )
            else:
                self.logger.info(
                    "AWS %s.%s => %s",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                )
        else:
            # log any other HTTP response
            self.logger.info(
                "%s %s => %d",
                context.request.method,
                context.request.path,
                response.status_code,
            )
