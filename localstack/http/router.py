import threading
from typing import Any, Callable, Generic, Iterable, Mapping, Optional, Protocol, TypeVar

from werkzeug.routing import Map, Rule, RuleFactory

from localstack.utils.common import to_str

from .request import Request
from .response import Response

E = TypeVar("E")
RequestArguments = Mapping[str, Any]


class Dispatcher(Protocol):
    """
    A Dispatcher is called when a URL route matches a request. The dispatcher is responsible for appropriately
    creating a Response from the incoming Request and the matching endpoint.
    """

    def __call__(self, request: Request, endpoint: E, args: RequestArguments) -> Response:
        """
        Dispatch the HTTP Request.

        :param request: the incoming HTTP request
        :param endpoint: the endpoint that matched the URL rule
        :param args: the request arguments extracted from the URL rule
        :return: an HTTP Response
        """
        pass


def call_endpoint(
    request: Request,
    endpoint: Callable[[Request, RequestArguments], Response],
    args: RequestArguments,
) -> Response:
    """
    A Dispatcher that treats the matching endpoint as a callable and invokes it with the Request and request arguments.
    """
    return endpoint(request, args)


def _clone_map_without_rules(old: Map) -> Map:
    return Map(
        default_subdomain=old.default_subdomain,
        charset=old.charset,
        strict_slashes=old.strict_slashes,
        merge_slashes=old.merge_slashes,
        redirect_defaults=old.redirect_defaults,
        converters=old.converters,
        sort_parameters=old.sort_parameters,
        sort_key=old.sort_key,
        encoding_errors=old.encoding_errors,
        host_matching=old.host_matching,
    )


class Router(Generic[E]):
    """
    A Router is a wrapper around werkzeug's routing Map, that adds convenience methods and additional dispatching
    logic via the ``Dispatcher`` Protocol.
    """

    url_map: Map
    dispatcher: Dispatcher

    def __init__(self, dispatcher: Dispatcher = None):
        self.url_map = Map(host_matching=True, strict_slashes=False)
        self.dispatcher = dispatcher or call_endpoint
        self._mutex = threading.RLock()

    def add(
        self,
        path: str,
        endpoint: E,
        host: Optional[str] = None,
        methods: Optional[Iterable[str]] = None,
        **kwargs,
    ) -> Rule:
        """
        Adds a new Rule to the URL Map.

        :param path: the path pattern to match
        :param endpoint: the endpoint to invoke
        :param host: an optional host matching pattern. if not pattern is given, the rule matches any host
        :param methods: the allowed HTTP verbs for this rule
        :param kwargs: any other argument that can be passed to ``werkzeug.routing.Rule``
        :return:
        """
        if host is None and self.url_map.host_matching:
            # this creates a "match any" rule, and will put the value of the host
            # into the variable "__host__"
            host = "<__host__>"

        # the typing for endpoint is a str, but the doc states it can be any value,
        # however then the redirection URL building will not work
        rule = Rule(path, endpoint=endpoint, methods=methods, host=host, **kwargs)
        self.add_rule(rule)
        return rule

    def add_rule(self, rule: RuleFactory):
        with self._mutex:
            self.url_map.add(rule)

    def remove_rule(self, rule: Rule):
        """
        Removes a Rule from the Router.

        **Caveat**: This is an expensive operation. Removing rules from a URL Map is intentionally not supported by
        werkzeug due to issues with thread safety, see https://github.com/pallets/werkzeug/issues/796, and because
        using a lock in ``match`` would be too expensive. However, some services that use Routers for routing
        internal resources need to be able to remove rules when those resources are removed. So to remove rules we
        create a new Map without that rule. This will not prevent the rules from dispatching until the Map has been
        completely constructed.

        :param rule: the Rule to remove that was previously returned by ``add``.
        """
        with self._mutex:
            old = self.url_map
            if rule not in old._rules:
                raise KeyError("no such rule")

            new = _clone_map_without_rules(old)

            for r in old.iter_rules():
                if r == rule:
                    # this works even with copied rules because of the __eq__ implementation of Rule
                    continue
                new.add(r.empty())
            self.url_map = new

    def dispatch(self, request: Request) -> Response:
        """
        Does the entire dispatching roundtrip, from matching the request to endpoints, and then invoking the endpoint
        using the configured dispatcher of the router. For more information on the matching behavior,
        see ``werkzeug.routing.MapAdapter.match()``.

        :param request: the HTTP request
        :return: the HTTP response
        """
        matcher = self.url_map.bind(server_name=request.host)
        handler, args = matcher.match(
            request.path, method=request.method, query_args=to_str(request.query_string)
        )
        args.pop("__host__", None)
        return self.dispatcher(request, handler, args)
