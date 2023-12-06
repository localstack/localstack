import json
from typing import Any, Dict, Protocol, Union

from werkzeug import Response as WerkzeugResponse

from localstack.utils.json import CustomEncoder

from .request import Request
from .response import Response
from .router import Dispatcher, RequestArguments

ResultValue = Union[
    WerkzeugResponse,
    str,
    bytes,
    Dict[str, Any],  # a JSON dict
]


def _populate_response(response: WerkzeugResponse, result: ResultValue):
    if result is None:
        return response

    elif isinstance(result, (str, bytes, bytearray)):
        response.data = result
    elif isinstance(result, dict):
        response.data = json.dumps(result, cls=CustomEncoder)
        response.mimetype = "application/json"
    else:
        raise ValueError("unhandled result type %s", type(result))

    return response


class Handler(Protocol):
    """
    A protocol used by a ``Router`` together with the dispatcher created with ``handler_dispatcher``. Endpoints added
    with this protocol take as first argument the HTTP request object, and then as keyword arguments the request
    parameters added in the rule. This makes it work very similar to flask routes.

    Example code could look like this::

        def my_route(request: Request, organization: str, repo: str):
            return {"something": "returned as json response"}

        router = Router(dispatcher=handler_dispatcher)
        router.add("/<organization>/<repo>", endpoint=my_route)

    """

    def __call__(self, request: Request, **kwargs) -> ResultValue:
        """
        Handle the given request.

        :param request: the HTTP request object
        :param kwargs: the url request parameters
        :return: a string or bytes value, a dict to create a json response, or a raw werkzeug Response object.
        """
        raise NotImplementedError


def handler_dispatcher() -> Dispatcher[Handler]:
    """
    Creates a Dispatcher that treats endpoints like callables of the ``Handler`` Protocol.

    :return: a new dispatcher
    """

    def _dispatch(request: Request, endpoint: Handler, args: RequestArguments) -> Response:
        result = endpoint(request, **args)
        if isinstance(result, WerkzeugResponse):
            return result
        response = Response()
        if result is not None:
            _populate_response(response, result)
        return response

    return _dispatch
