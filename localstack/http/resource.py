"""
This module enables the resource class pattern, where each respective ``on_<http_method>`` method of a class is
treated like an endpoint for the respective HTTP method. The following shows an example of how the pattern is used::

    class Foo:
        def on_get(self, request: Request):
            return {"ok": "GET it"}

        def on_post(self, request: Request):
            return {"ok": "it was POSTed"}


    router = Router(dispatcher=resource_dispatcher())
    router.add(Resource("/foo", Foo())
"""
from typing import Any, Iterable, Optional, Type

from werkzeug.routing import Map, Rule, RuleFactory

from .router import HTTP_METHODS, route


def resource(path: str, host: Optional[str] = None, **kwargs):
    """
    Class decorator that turns every method that follows the pattern ``on_<http-method>`` into a route,
    where the allowed method for that route is automatically set to the method specified in the function name. Example
    when using a Router with the ``handler_dispatcher``::

        @resource("/myresource/<resource_id>")
        class MyResource:
            def on_get(request: Request, resource_id: str) -> Response:
                return Response(f"GET called on {resource_id}")

            def on_post(request: Request, resource_id: str) -> Response:
                return Response(f"POST called on {resource_id}")

    This class can then be added to a router via ``router.add_route_endpoints(MyResource())``.

    Note that HEAD requests are automatically routed to ``on_get``. There is currently no way of specifying ``on_head``
    methods because of how werkzeug works. See https://werkzeug.palletsprojects.com/en/2.2.x/routing/

    :param path: the path pattern to match
    :param host: an optional host matching pattern. if not pattern is given, the rule matches any host
    :param kwargs: any other argument that can be passed to ``werkzeug.routing.Rule``
    :return: a class where each matching function is wrapped as a ``_RouteEndpoint``
    """
    allowed_names = [f"on_{method.lower()}" for method in HTTP_METHODS if method != "HEAD"]
    kwargs.pop("methods", None)

    def _wrapper(cls: Type):
        for name in allowed_names:
            member = getattr(cls, name, None)
            if member is None:
                continue

            http_method = name[3:].upper()
            setattr(cls, name, route(path, host, methods=[http_method], **kwargs)(member))

        return cls

    return _wrapper


class Resource(RuleFactory):
    """
    Exposes a given object that follows the "Resource" class pattern as a ``RuleFactory` that can then be added to a
    Router. Example use when using a Router with the ``handler_dispatcher``::

        class MyResource:
            def on_get(request: Request, resource_id: str) -> Response:
                return Response(f"GET called on {resource_id}")

            def on_post(request: Request, resource_id: str) -> Response:
                return Response(f"POST called on {resource_id}")

        router.add(Resource("/myresource/<resource_id>", MyResource()))
    """

    def __init__(self, path: str, obj: Any, host: Optional[str] = None, **kwargs):
        self.path = path
        self.obj = obj
        self.host = host
        self.kwargs = kwargs

    def get_rules(self, map: "Map") -> Iterable["Rule"]:
        allowed_names = [f"on_{method.lower()}" for method in HTTP_METHODS if method != "HEAD"]

        rules = []
        for name in allowed_names:
            member = getattr(self.obj, name, None)
            if member is None:
                continue

            http_method = name[3:].upper()
            rules.append(
                Rule(
                    self.path, endpoint=member, methods=[http_method], host=self.host, **self.kwargs
                )
            )
        return rules
