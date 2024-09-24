"""
The core concepts of the HandlerChain.
"""

from __future__ import annotations

import logging
from typing import Callable, Type

from rolo.gateway import (
    CompositeExceptionHandler,
    CompositeFinalizer,
    CompositeHandler,
    CompositeResponseHandler,
)
from rolo.gateway import HandlerChain as RoloHandlerChain
from werkzeug import Response

from .api import RequestContext

LOG = logging.getLogger(__name__)

Handler = Callable[["HandlerChain", RequestContext, Response], None]
"""The signature of request or response handler in the handler chain. Receives the HandlerChain, the
RequestContext, and the Response object to be populated."""

ExceptionHandler = Callable[["HandlerChain", Exception, RequestContext, Response], None]
"""The signature of an exception handler in the handler chain. Receives the HandlerChain, the exception that
was raised by the request handler, the RequestContext, and the Response object to be populated."""


HandlerChain: Type[RoloHandlerChain[RequestContext]] = RoloHandlerChain

__all__ = [
    "HandlerChain",
    "Handler",
    "ExceptionHandler",
    "CompositeHandler",
    "CompositeResponseHandler",
    "CompositeExceptionHandler",
    "CompositeFinalizer",
]
