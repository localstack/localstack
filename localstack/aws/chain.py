"""

"""
import logging
from typing import Callable, List, Optional

from localstack.aws.api import HttpResponse, RequestContext

LOG = logging.getLogger(__name__)

Handler = Callable[["HandlerChain", RequestContext, HttpResponse], None]
ExceptionHandler = Callable[["HandlerChain", Exception, RequestContext, HttpResponse], None]


class HandlerChain:
    # handlers
    request_handlers: List[Handler]
    exception_handlers: List[ExceptionHandler]

    # behavior configuration
    stop_on_error: bool = True
    raise_on_error: bool = False

    # state
    stopped: bool
    error: Optional[Exception]
    current: Handler

    def __init__(
        self, handlers: List[Handler] = None, exception_handlers: List[ExceptionHandler] = None
    ) -> None:
        super().__init__()
        self.request_handlers = handlers or list()
        self.exception_handlers = exception_handlers or list()

        self.stopped = False
        self.error = None

    def handle(self, context: RequestContext, response: HttpResponse):
        for handler in self.request_handlers:
            try:
                self.current = handler
                handler(self, context, response)
            except Exception as e:
                # prepare the continuation behavior, but exception handlers could overwrite it
                if self.raise_on_error:
                    self.error = e
                if self.stop_on_error:
                    self.stopped = True

                for exception_handler in self.exception_handlers:
                    try:
                        exception_handler(self, e, context, response)
                    except Exception as nested:
                        # make sure we run all exception handlers
                        msg = "exception while running exception handler"
                        if LOG.isEnabledFor(logging.DEBUG):
                            LOG.exception(msg)
                        else:
                            LOG.warning(msg + ": %s", nested)

            # decide next step
            if self.error:
                raise self.error

            if self.stopped:
                return

    def stop(self):
        self.stopped = True

    def throw(self, error: Exception):
        self.error = error


class HandlerChainAdapter(Handler):
    """
    Exposes a HandlerChain as a Handler. This provides a mechanism for nesting HandlerChains to create handler trees.
    """

    chain: HandlerChain

    def __init__(self, chain: HandlerChain):
        self.chain = chain

    def __call__(self, _: HandlerChain, context: RequestContext, response: HttpResponse):
        self.chain.handle(context, response)
