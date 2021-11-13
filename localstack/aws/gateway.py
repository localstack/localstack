import logging
from typing import List

from .api import HttpRequest, HttpResponse, RequestContext
from .chain import ExceptionHandler, Handler, HandlerChain

LOG = logging.getLogger(__name__)


class Gateway:
    """
    A gateway creates new HandlerChain instances for each request and processes requests through them.
    """

    request_handlers: List[Handler]
    response_handlers: List[Handler]
    exception_handlers: List[ExceptionHandler]

    def __init__(self) -> None:
        super().__init__()
        self.request_handlers = list()
        self.response_handlers = list()
        self.exception_handlers = list()

    def new_chain(self, request: HttpRequest, response: HttpResponse) -> HandlerChain:
        return HandlerChain(self.request_handlers, self.response_handlers, self.exception_handlers)

    def process(self, request: HttpRequest, response: HttpResponse):
        chain = self.new_chain(request, response)

        context = RequestContext()
        context.request = request

        chain.handle(context, response)
