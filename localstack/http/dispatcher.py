import json
from typing import Any, Dict, Protocol, Union

from werkzeug import Response as WerkzeugResponse
from werkzeug.exceptions import MethodNotAllowed

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


def resource_dispatcher(pass_response: bool = False) -> Dispatcher:
    """
    A ``Dispatcher`` treats a Router endpoint like a REST resource, which dispatches the request further to the
    respective ``on_<http_verb>`` method. The following shows an example of how the pattern is used::

        class Foo:
            def on_get(self, request: Request):
                return {"ok": "GET it"}

            def on_post(self, request: Request):
                return {"ok": "it was POSTed"}

        router = Router(dispatcher=resource_dispatcher())
        router.add("/foo", Foo())

    Alternatively, if you create a dispatcher with pass_response=True then the dispatcher ignores the return value,
    but instead passes the response object. An implementation can look like this::

        class Foo:
            def on_get(self, request: Request, response: Response):
                response.set_json({"ok": "GET it"})

        router = Router(dispatcher=resource_dispatcher(pass_response=True))
        router.add("/foo", Foo())

    :param pass_response: whether to pass the response object to the resource
    :returns: a new Dispatcher
    """

    def _dispatch(request: Request, endpoint: object, args: RequestArguments) -> Response:
        fn_name = f"on_{request.method.lower()}"

        fn = getattr(endpoint, fn_name, None)

        if fn:
            if pass_response:
                response = Response()
                fn(request, response, **args)
            else:
                result = fn(request, **args)
                if isinstance(result, WerkzeugResponse):
                    return result
                response = Response()
                _populate_response(response, result)

            return response
        else:
            raise MethodNotAllowed()

    return _dispatch


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
