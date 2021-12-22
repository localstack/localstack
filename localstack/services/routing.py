import dataclasses
from typing import Any, List, Optional, Tuple
from urllib.parse import urlparse

from localstack.services.generic_proxy import ProxyListener
from localstack.services.messages import Request


@dataclasses.dataclass
class RoutingRule:
    uri_template: str
    is_pattern: bool = False
    method: str = None
    match_host: bool = False

    def url(self):
        return urlparse(self.uri_template)

    def matches(self, request: Request) -> bool:
        if self.method and self.method != request.method:
            return False

        if self.is_pattern:
            raise NotImplementedError

        url = self.url()
        host = request.host
        path = urlparse(request.path).path if "?" in request.path else request.path

        # TODO: consider matching default ports (80, 443 if scheme is https). Example: http://localhost:80 matches
        #  http://localhost) check host rule
        if self.match_host:
            if not url.netloc:
                raise ValueError("cannot match host without host pattern in URI template")

            if not host:
                return False
            elif host != url.netloc:
                return False

        # check path components
        if url.path == "/":
            if path.startswith("/"):
                return True

        path = path.rstrip("/")  # ignore trailing slashes
        base_path = url.path.rstrip("/")

        path_parts = path.split("/")
        base_path_parts = base_path.split("/")

        if len(base_path_parts) != len(path_parts):
            return False

        for i, component in enumerate(base_path_parts):
            if component != path_parts[i]:
                return False

        return True


class Dispatcher:
    """
    Dispatches a request to a resource by resolving on_post, on_get, etc ... methods of the resource,
    and then calling that method if it exists. Otherwise a ResourceRouter.NO_ROUTE is returned.
    """

    resource: Any
    suffix: str

    def __init__(self, resource: Any, suffix: str = None) -> None:
        super().__init__()
        self.resource = resource
        self.suffix = suffix

    def dispatch(self, request):
        fn_name = self.get_method_name(request)
        fn = getattr(self.resource, fn_name, None)
        if fn:
            return fn(request)
        else:
            return ResourceRouter.NO_ROUTE

    def get_method_name(self, request):
        if self.suffix:
            return f"on_{request.method.lower()}_{self.suffix}"
        else:
            return f"on_{request.method.lower()}"


class _NoRoute:
    def __repr__(self):
        return "no route"

    def __str__(self):
        return "no route"


class ResourceRouter:
    """
    Matches requests to routing rules and calls the respective dispatchers.
    """

    NO_ROUTE = _NoRoute()  # sentinel object to indicate that there is no route available

    routes: List[Tuple[RoutingRule, Dispatcher]]

    def __init__(self):
        self.routes = []

    def add_route(self, uri_template: str, resource: Any, suffix: str = None):
        """
        Adds a route to the given resource, where either on_<verb> or on_<verb>_<suffix> will be called.
        """
        # TODO: check if uri_template is a pattern and set is_pattern = True
        rule = RoutingRule(uri_template, False)
        self.add_routing_rule(rule, resource, suffix)

    def add_routing_rule(self, rule: RoutingRule, resource: Any, suffix: str = None):
        self.routes.append((rule, Dispatcher(resource, suffix)))

    def dispatch(self, request: Request):
        """
        Dispatches the request to a resource, or returns ResourceRouter.NO_ROUTE.
        """
        dispatcher = self.get_matching_route(request)

        if not dispatcher:
            return ResourceRouter.NO_ROUTE

        return dispatcher.dispatch(request)

    def get_matching_route(self, request: Request) -> Optional[Dispatcher]:
        for route, resource in self.routes:
            if route.matches(request):
                return resource

        return None


class ResourceRouterProxyListener(ProxyListener):
    """
    Adapter to serve a ResourceRouter through the generic proxy.
    """

    resources: ResourceRouter

    def __init__(self, resources: ResourceRouter) -> None:
        super().__init__()
        self.resources = resources

    def forward_request(self, method, path, data, headers):
        result = self.resources.dispatch(Request(method, path, data, headers))

        if result is ResourceRouter.NO_ROUTE:
            return 404

        return result
