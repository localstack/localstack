from typing import (
    Any,
    Mapping,
    TypeVar,
)

from rolo.router import (
    Dispatcher,
    PortConverter,
    RegexConverter,
    Router,
    RuleAdapter,
    RuleGroup,
    WithHost,
    call_endpoint,
    route,
)

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
