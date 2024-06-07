from typing import Callable, Type

from rolo import Response
from rolo.gateway.chain import HandlerChain as RoloHandlerChain

from .context import InvocationContext

ApiGatewayHandler = Callable[
    [RoloHandlerChain[InvocationContext], InvocationContext, Response], None
]

ApiGatewayHandlerChain: Type[RoloHandlerChain[InvocationContext]] = RoloHandlerChain
