import logging
from typing import List

from localstack.http import Request, Response
from localstack.http.websocket import WebSocketRequest

from .api import RequestContext
from .chain import ExceptionHandler, Handler, HandlerChain

LOG = logging.getLogger(__name__)


class Gateway:
    """
    A gateway creates new HandlerChain instances for each request and processes requests through them.
    """

    request_handlers: List[Handler]
    response_handlers: List[Handler]
    finalizers: List[Handler]
    exception_handlers: List[ExceptionHandler]

    def __init__(self) -> None:
        super().__init__()
        self.request_handlers = list()
        self.response_handlers = list()
        self.finalizers = list()
        self.exception_handlers = list()

    def new_chain(self) -> HandlerChain:
        return HandlerChain(
            self.request_handlers,
            self.response_handlers,
            self.finalizers,
            self.exception_handlers,
        )

    def process(self, request: Request, response: Response):
        chain = self.new_chain()

        context = RequestContext()
        context.request = request

        chain.handle(context, response)

    def accept(self, request: WebSocketRequest):
        response = Response(status=101)
        self.process(request, response)

        # only send the populated response if the websocket hasn't already done so before
        if response.status_code != 101:
            if request.is_upgraded():
                return
            if request.is_rejected():
                return
            request.reject(response)
