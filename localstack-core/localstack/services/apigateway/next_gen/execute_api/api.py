from collections.abc import Callable

from rolo import Response
from rolo.gateway.chain import HandlerChain as RoloHandlerChain

from .context import RestApiInvocationContext

RestApiGatewayHandler = Callable[
    [RoloHandlerChain[RestApiInvocationContext], RestApiInvocationContext, Response], None
]

RestApiGatewayExceptionHandler = Callable[
    [RoloHandlerChain[RestApiInvocationContext], Exception, RestApiInvocationContext, Response],
    None,
]

RestApiGatewayHandlerChain: type[RoloHandlerChain[RestApiInvocationContext]] = RoloHandlerChain
