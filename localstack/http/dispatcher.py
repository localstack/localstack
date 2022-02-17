from typing import Any, Dict, Protocol, Union

from werkzeug.exceptions import MethodNotAllowed

from .request import Request
from .response import Response
from .router import Dispatcher, RequestArguments

ResultValue = Union[
    Response,
    str,
    bytes,
    Dict[str, Any],  # a JSON dict
]


def _populate_response(response: Response, result: ResultValue):
    if isinstance(result, dict):
        response.set_json(result)
    else:
        response.data = result
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
                if isinstance(result, Response):
                    return result
                response = Response()
                _populate_response(response, result)

            return response
        else:
            raise MethodNotAllowed()

    return _dispatch


class Handler(Protocol):
    def __call__(self, request: Request, **kwargs) -> ResultValue:
        pass


def handler_dispatcher() -> Dispatcher:
    """
    Creates a Dispatcher that treats endpoints like callables of the Handler Protocol.

    :return: a new dispatcher
    """

    def _dispatch(request: Request, endpoint: Handler, args: RequestArguments) -> Response:
        result = endpoint(request, **args)
        if isinstance(result, Response):
            return result
        response = Response()
        if result is not None:
            _populate_response(response, result)
        return response

    return _dispatch
