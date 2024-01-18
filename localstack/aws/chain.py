"""
The core concepts of the HandlerChain.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional

from werkzeug import Response

from ..utils.functions import call_safe
from .api import RequestContext

LOG = logging.getLogger(__name__)

Handler = Callable[["HandlerChain", RequestContext, Response], None]
"""The signature of request or response handler in the handler chain. Receives the HandlerChain, the
RequestContext, and the Response object to be populated."""

ExceptionHandler = Callable[["HandlerChain", Exception, RequestContext, Response], None]
"""The signature of an exception handler in the handler chain. Receives the HandlerChain, the exception that
was raised by the request handler, the RequestContext, and the Response object to be populated."""


class HandlerChain:
    """
    Implements a variant of the chain-of-responsibility pattern to process an incoming HTTP request. A handler
    chain consists of request handlers, response handlers, finalizers, and exception handlers. Each request
    should have its own HandlerChain instance, since the handler chain holds state for the handling of a
    request. A chain can be in three states that can be controlled by the handlers.

    * Running - the implicit state where all handlers are executed sequentially
    * Stopped - a handler has called ``chain.stop()``. This stops the execution of all request handlers, and
      proceeds immediately to executing the response handlers. Response handlers and finalizers will be run,
      even if the chain has been stopped.
    * Terminated - a handler has called ``chain.terminate()`. This stops the execution of all request
      handlers, and all response handlers, but runs the finalizers at the end.

    If an exception occurs during the execution of request handlers, the chain by default stops the chain,
    then runs each exception handler, and finally runs the response handlers. Exceptions that happen during
    the execution of response or exception handlers are logged but do not modify the control flow of the
    chain.
    """

    # handlers
    request_handlers: List[Handler]
    response_handlers: List[Handler]
    finalizers: List[Handler]
    exception_handlers: List[ExceptionHandler]

    # behavior configuration
    stop_on_error: bool = True
    """If set to true, the chain will implicitly stop if an error occurs in a request handler."""
    raise_on_error: bool = False
    """If set to true, an exception in the request handler will be re-raised by ``handle`` after the exception
    handlers have been called. """

    # internal state
    stopped: bool
    terminated: bool
    error: Optional[Exception]
    response: Optional[Response]
    context: Optional[RequestContext]

    def __init__(
        self,
        request_handlers: List[Handler] = None,
        response_handlers: List[Handler] = None,
        finalizers: List[Handler] = None,
        exception_handlers: List[ExceptionHandler] = None,
    ) -> None:
        super().__init__()
        self.request_handlers = request_handlers or list()
        self.response_handlers = response_handlers or list()
        self.exception_handlers = exception_handlers or list()
        self.finalizers = finalizers or list()

        self.stopped = False
        self.terminated = False
        self.finalized = False
        self.error = None
        self.response = None
        self.context = None

    def handle(self, context: RequestContext, response: Response):
        """
        Process the given request and populate the given response according to the handler chain control flow
        described in the ``HandlerChain`` class doc.

        :param context: the incoming request
        :param response: the response to be populated
        """
        self.context = context
        self.response = response

        try:
            for handler in self.request_handlers:
                try:
                    handler(self, self.context, response)
                except Exception as e:
                    # prepare the continuation behavior, but exception handlers could overwrite it
                    if self.raise_on_error:
                        self.error = e
                    if self.stop_on_error:
                        self.stopped = True

                    # call exception handlers safely
                    self._call_exception_handlers(e, response)

                # decide next step
                if self.error:
                    raise self.error
                if self.terminated:
                    return
                if self.stopped:
                    break

            # call response filters
            self._call_response_handlers(response)
        finally:
            if not self.finalized:
                self._call_finalizers(response)

    def respond(self, status_code: int = 200, payload: Any = None):
        """
        Convenience method for handlers to stop the chain and set the given status and payload to the
        current response object.

        :param status_code: the HTTP status code
        :param payload: the payload of the response
        """
        self.response.status_code = status_code
        if isinstance(payload, (list, dict)):
            self.response.set_json(payload)
        elif isinstance(payload, (str, bytes, bytearray)):
            self.response.data = payload
        elif payload is None and not self.response.response:
            self.response.response = []
        else:
            self.response.response = payload
        self.stop()

    def stop(self) -> None:
        """
        Stop the processing of the request handlers and proceed with response handlers.
        """
        self.stopped = True

    def terminate(self) -> None:
        """
        Terminate the handler chain, which skips response handlers.
        """
        self.terminated = True

    def throw(self, error: Exception) -> None:
        """
        Raises the given exception after the current request handler is done. This has no effect in response handlers.
        :param error: the exception to raise
        """
        self.error = error

    def _call_response_handlers(self, response):
        for handler in self.response_handlers:
            if self.terminated:
                return

            try:
                handler(self, self.context, response)
            except Exception as e:
                msg = "exception while running response handler"
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.exception(msg)
                else:
                    LOG.warning(msg + ": %s", e)

    def _call_finalizers(self, response):
        for handler in self.finalizers:
            try:
                handler(self, self.context, response)
            except Exception as e:
                msg = "exception while running request finalizer"
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.exception(msg)
                else:
                    LOG.warning(msg + ": %s", e)

    def _call_exception_handlers(self, e, response):
        for exception_handler in self.exception_handlers:
            try:
                exception_handler(self, e, self.context, response)
            except Exception as nested:
                # make sure we run all exception handlers
                msg = "exception while running exception handler"
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.exception(msg)
                else:
                    LOG.warning(msg + ": %s", nested)


class CompositeHandler(Handler):
    """
    A handler that sequentially invokes a list of Handlers, forming a stripped-down version of a handler
    chain.
    """

    handlers: List[Handler]

    def __init__(self, return_on_stop=True) -> None:
        """
        Creates a new composite handler with an empty handler list.

        TODO: build a proper chain nesting mechanism.

        :param return_on_stop: whether to respect chain.stopped
        """
        super().__init__()
        self.handlers = []
        self.return_on_stop = return_on_stop

    def append(self, handler: Handler) -> None:
        """
        Adds the given handler to the list of handlers.

        :param handler: the handler to add
        """
        self.handlers.append(handler)

    def remove(self, handler: Handler) -> None:
        """
        Remove the given handler from the list of handlers
        :param handler: the handler to remove
        """
        self.handlers.remove(handler)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        for handler in self.handlers:
            handler(chain, context, response)

            if chain.terminated:
                return
            if chain.stopped and self.return_on_stop:
                return


class CompositeExceptionHandler(ExceptionHandler):
    """
    A exception handler that sequentially invokes a list of ExceptionHandler instances, forming a
    stripped-down version of a handler chain for exception handlers.
    """

    handlers: List[ExceptionHandler]

    def __init__(self) -> None:
        """
        Creates a new composite exception handler with an empty handler list.
        """
        self.handlers = []

    def append(self, handler: ExceptionHandler) -> None:
        """
        Adds the given handler to the list of handlers.

        :param handler: the handler to add
        """
        self.handlers.append(handler)

    def remove(self, handler: ExceptionHandler) -> None:
        """
        Remove the given handler from the list of handlers
        :param handler: the handler to remove
        """
        self.handlers.remove(handler)

    def __call__(
        self, chain: HandlerChain, exception: Exception, context: RequestContext, response: Response
    ):
        for handler in self.handlers:
            try:
                handler(chain, exception, context, response)
            except Exception as nested:
                # make sure we run all exception handlers
                msg = "exception while running exception handler"
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.exception(msg)
                else:
                    LOG.warning(msg + ": %s", nested)


class CompositeResponseHandler(CompositeHandler):
    """
    A CompositeHandler that by default does not return on stop, meaning that all handlers in the composite
    will be executed, even if one of the handlers has called ``chain.stop()``. This mimics how response
    handlers are executed in the ``HandlerChain``.
    """

    def __init__(self) -> None:
        super().__init__(return_on_stop=False)


class CompositeFinalizer(CompositeResponseHandler):
    """
    A CompositeHandler that uses ``call_safe`` to invoke handlers, so every handler is always executed.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        for handler in self.handlers:
            call_safe(
                handler,
                args=(chain, context, response),
                exception_message="Error while running request finalizer",
            )
