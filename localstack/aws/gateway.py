import logging
from typing import List

from localstack.http import Request, Response
from localstack.http.asgi import ASGIWebsocket
from localstack.http.websocket import WebsocketRequest

from .api import RequestContext
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

    def new_chain(self) -> HandlerChain:
        return HandlerChain(self.request_handlers, self.response_handlers, self.exception_handlers)

    def process(self, request: Request, response: Response):
        chain = self.new_chain()

        context = RequestContext()
        context.request = request

        chain.handle(context, response)

    def accept(self, websocket: ASGIWebsocket):
        request = WebsocketRequest(websocket)
        with request:
            for line in request:
                print(line)

        request.handshake()
        request.respond()

        response = Response()
        self.process(request, response)

        if response.status_code not in [0, None]:
            if request.is_upgraded():
                raise "Cannot send response after connection has been upgraded"
        else:
            websocket.respond(
                response.status_code, response.headers.to_wsgi_list(), response.iter_encoded()
            )
