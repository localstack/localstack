from typing import (
    Any,
    Mapping,
    TypeVar,
)

from rolo.routing import (
    PortConverter,
    RegexConverter,
    Router,
    RuleAdapter,
    RuleGroup,
    WithHost,
    route,
)
from rolo.routing.router import Dispatcher, call_endpoint

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE")

E = TypeVar("E")
RequestArguments = Mapping[str, Any]

__all__ = [
    "RequestArguments",
    "HTTP_METHODS",
    "RegexConverter",
    "PortConverter",
    "Dispatcher",
    "route",
    "call_endpoint",
    "Router",
    "RuleAdapter",
    "WithHost",
    "RuleGroup",
]
