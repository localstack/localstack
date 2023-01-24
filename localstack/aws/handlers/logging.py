"""Handlers for logging."""
import functools
import logging
from functools import cached_property
from typing import Type

from werkzeug.datastructures import Headers

from localstack.aws.api import RequestContext, ServiceException
from localstack.aws.chain import ExceptionHandler, HandlerChain
from localstack.http import Response
from localstack.http.request import Request, restore_payload
from localstack.logging.format import AwsTraceLoggingFormatter, TraceLoggingFormatter
from localstack.logging.setup import create_default_handler
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
    def __call__(self, _: HandlerChain, context: RequestContext, response: Response):
        if context.request.path == "/health" or context.request.path == "/_localstack/health":
            # special case so the health check doesn't spam the logs
            return
        self._log(context, response)

    @cached_property
    def aws_logger(self):
        return self._prepare_logger(
            logging.getLogger("localstack.request.aws"), formatter=AwsTraceLoggingFormatter
        )

    @cached_property
    def http_logger(self):
        return self._prepare_logger(
            logging.getLogger("localstack.request.http"), formatter=TraceLoggingFormatter
        )

    @cached_property
    def internal_aws_logger(self):
        return self._prepare_logger(
            logging.getLogger("localstack.request.internal.aws"), formatter=AwsTraceLoggingFormatter
        )

    @cached_property
    def internal_http_logger(self):
        return self._prepare_logger(
            logging.getLogger("localstack.request.internal.http"), formatter=TraceLoggingFormatter
        )

    # make sure loggers are loaded after logging config is loaded
    def _prepare_logger(self, logger: logging.Logger, formatter: Type):
        if logger.isEnabledFor(logging.DEBUG):
            logger.propagate = False
            handler = create_default_handler(logger.level)
            handler.setFormatter(formatter())
            logger.addHandler(handler)
        return logger

    def _log_http_response(
        self,
        logger: logging.Logger,
        request: Request,
        response_status: int,
        response_headers: Headers,
        response_data,
    ):
        """
        Logs a given HTTP response on a given logger.
        The given response data is returned by this function, which allows the usage as a log interceptor for streamed
        response data.

        :param logger: HTTP logger to log the request onto
        :param request: HTTP request data (containing useful metadata like the HTTP method and path)
        :param response_status: HTTP status of the response to log
        :param response_headers: HTTP headers of the response to log
        :param response_data: HTTP body of the response to log
        :return: response data
        """
        logger.info(
            "%s %s => %d",
            request.method,
            request.path,
            response_status,
            extra={
                # request
                "input_type": "Request",
                "input": restore_payload(request),
                "request_headers": dict(request.headers),
                # response
                "output_type": "Response",
                "output": response_data,
                "response_headers": dict(response_headers),
            },
        )
        return response_data

    def _log(self, context: RequestContext, response: Response):
        aws_logger = self.aws_logger
        http_logger = self.http_logger
        is_internal_call = is_internal_call_context(context.request.headers)
        if is_internal_call:
            aws_logger = self.internal_aws_logger
            http_logger = self.internal_http_logger
        if context.operation:
            # log an AWS response
            if context.service_exception:
                aws_logger.info(
                    "AWS %s.%s => %d (%s)",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                    context.service_exception.code,
                    extra={
                        # request
                        "input_type": context.operation.input_shape.name
                        if context.operation.input_shape
                        else "Request",
                        "input": context.service_request,
                        "request_headers": dict(context.request.headers),
                        # response
                        "output_type": context.service_exception.code,
                        "output": context.service_exception.message,
                        "response_headers": dict(response.headers),
                    },
                )
            else:
                aws_logger.info(
                    "AWS %s.%s => %s",
                    context.service.service_name,
                    context.operation.name,
                    response.status_code,
                    extra={
                        # request
                        "input_type": context.operation.input_shape.name
                        if context.operation.input_shape
                        else "Request",
                        "input": context.service_request,
                        "request_headers": dict(context.request.headers),
                        # response
                        "output_type": context.operation.output_shape.name
                        if context.operation.output_shape
                        else "Response",
                        "output": context.service_response,
                        "response_headers": dict(response.headers),
                    },
                )
        else:
            # log any other HTTP response
            if hasattr(response.response, "__iter__"):
                # If the response is streamed, wrap the response data's iterator which logs all values when they are consumed
                log_partial = functools.partial(
                    self._log_http_response,
                    http_logger,
                    context.request,
                    response.status_code,
                    response.headers,
                )
                wrapped_response_iterator = map(log_partial, response.response)
                response.set_response(wrapped_response_iterator)
            else:
                # If the response is synchronous, we log the data directly
                self._log_http_response(
                    http_logger,
                    context.request,
                    response.status_code,
                    response.headers,
                    response.data,
                )
