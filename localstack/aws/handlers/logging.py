"""Handlers for logging."""
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


class _ResponseChunkLogger:
    # TODO also use this logger for other types (f.e. Kinesis' SubscribeToShard event streamed responses)
    def __init__(
        self,
        logger: logging.Logger,
        request: Request,
        response_status: int,
        response_headers: Headers,
        streaming: bool,
    ):
        """
        :param logger: HTTP logger to log the request onto
        :param request: HTTP request data (containing useful metadata like the HTTP method and path)
        :param response_status: HTTP status of the response to log
        :param response_headers: HTTP headers of the response to log
        :param streaming: true if this instance will be used to log streaming responses
        """
        self.logger = logger
        self.request = request
        self.response_status = response_status
        self.response_headers = response_headers
        self.streaming = streaming

    def __call__(
        self,
        response_data,
    ):
        """
        Logs a given HTTP response on a defined logger.
        The given response data is returned by this function, which allows the usage as a log interceptor for streamed
        response data.

        :param response_data: HTTP body of the response to log
        :return: response data
        """
        self.logger.info(
            "%s %s => %d",
            self.request.method,
            self.request.path,
            self.response_status,
            extra={
                # request
                "input_type": "Request",
                "input": restore_payload(self.request),
                "request_headers": dict(self.request.headers),
                # response
                "output_type": "Response",
                "output_streaming": self.streaming,
                "output": response_data,
                "response_headers": dict(self.response_headers),
            },
        )
        return response_data


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
                        "output_streaming": False,
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
                        "output_streaming": context.operation.has_event_stream_output,
                        "response_headers": dict(response.headers),
                    },
                )
        else:
            streaming = hasattr(response.response, "__iter__")
            response_chunk_logger = _ResponseChunkLogger(
                logger=http_logger,
                request=context.request,
                response_status=response.status_code,
                response_headers=response.headers,
                streaming=streaming,
            )
            wrapped_response_iterator = map(response_chunk_logger, response.response)
            response.set_response(wrapped_response_iterator)
