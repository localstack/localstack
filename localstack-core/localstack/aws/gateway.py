import typing as t

from rolo.gateway import Gateway as RoloGateway

from .chain import ExceptionHandler, Handler, RequestContext

__all__ = [
    "Gateway",
]


class Gateway(RoloGateway):
    def __init__(
        self,
        request_handlers: list[Handler] = None,
        response_handlers: list[Handler] = None,
        finalizers: list[Handler] = None,
        exception_handlers: list[ExceptionHandler] = None,
        context_class: t.Type[RequestContext] = None,
    ) -> None:
        super().__init__(
            request_handlers,
            response_handlers,
            finalizers,
            exception_handlers,
            context_class or RequestContext,
        )
