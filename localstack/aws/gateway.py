import logging
from typing import List

from localstack.http import Request, Response
from localstack.http.asgi import Websocket
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

    def accept(self, websocket: Websocket):
        request = WebsocketRequest(websocket)
        response = Response()
        self.process(request, response)

        if response.response:
            if response is not None:
                websocket.send(
                    {
                        "type": "websocket.http.response.start",
                        "status": response.status_code,
                        "headers": [],
                    }
                )
                for chunk in response.iter_encoded():
                    websocket.send(
                        {
                            "type": "websocket.http.response.body",
                            "body": chunk,
                            "more_body": True,
                        }
                    )
                websocket.send(
                    {
                        "type": "websocket.http.response.body",
                        "body": b"",
                        "more_body": False,
                    }
                )
