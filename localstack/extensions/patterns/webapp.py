import typing as t

from rolo.proxy import ProxyHandler
from rolo.router import RuleAdapter, WithHost
from werkzeug.routing import Map, Rule, RuleFactory, Submount

from localstack import config


class _Server(t.Protocol):
    url: str


class ExtensionRoutesMixin:
    def __init__(self, name: str):
        self.name = name
        self.hostname_prefix = f"{name}."
        self.submount = f"/_extension/{name}"
        self.edge_url = config.external_service_url()


class ExtensionRoutes(RuleFactory, ExtensionRoutesMixin):
    name: str
    endpoint: t.Any

    def __init__(self, name: str, endpoint: t.Any):
        super().__init__(name)
        self.name = name
        self.endpoint = endpoint

    def get_rules(self, map: Map) -> t.Iterable[Rule]:
        endpoints = [RuleAdapter(self.endpoint)]
        yield from Submount(self.submount, endpoints).get_rules(map)
        yield from WithHost(f"{self.hostname_prefix}<__host__>", endpoints).get_rules(map)


class ExtensionProxyRoutes(RuleFactory, ExtensionRoutesMixin):
    name: str
    endpoint: t.Any

    def __init__(
        self, name: str, backend_url: str, proxy_configurator: t.Callable[[ProxyHandler], None]
    ):
        super().__init__(name)
        self.name = name
        self.backend_url = backend_url
        self.proxy_configurator = proxy_configurator

    def get_rules(self, map: Map) -> t.Iterable[Rule]:
        proxy = ProxyHandler(forward_base_url=self.backend_url + "/" + self.name)

        if self.proxy_configurator:
            self.proxy_configurator(proxy)

        endpoints = [
            RuleAdapter("/", proxy),
            RuleAdapter("/<path:path>", proxy),
        ]

        yield from Submount(self.submount, endpoints).get_rules(map)
        yield from WithHost(f"{self.hostname_prefix}<__host__>", endpoints).get_rules(map)
